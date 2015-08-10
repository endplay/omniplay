#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>

#include <unordered_set>

#include "linkage_common.h"
#include "taint_interface/taint_creation.h"
#include "maputil.h"

#ifdef STATS
u_long map_merges = 0;
#endif

struct taint_entry {
    u_long p1;
    u_long p2;
};
struct taint_entry* merge_log;
#define OUTBUFSIZE 1000000
u_long outbuf[OUTBUFSIZE];
u_long outindex = 0;
int outfd;

static void flush_outbuf()
{
    long rc = write (outfd, outbuf, outindex*sizeof(u_long));
    if (rc != (long) (outindex*sizeof(u_long))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
	exit (rc);
    }
    outindex = 0;
}

static inline void print_value (u_long value) 
{
    if (outindex == OUTBUFSIZE) flush_outbuf();
    outbuf[outindex++] = value;
}


#define STACK_SIZE 1000000
u_long stack[STACK_SIZE];

static void map_iter (u_long value)
{
    std::unordered_set<u_long> seen_indices;
    struct taint_entry* pentry;
    u_long stack_depth = 0;

    pentry = &merge_log[value-0xe0000001];
#ifdef STATS
    map_merges++;
#endif
    //printf ("%lx -> %lx,%lx (%lu)\n", value, pentry->p1, pentry->p2, stack_depth);
    stack[stack_depth++] = pentry->p1;
    stack[stack_depth++] = pentry->p2;

    do {
	value = stack[--stack_depth];
	assert (stack_depth < STACK_SIZE);

	if (seen_indices.insert(value).second) {
    
	    if (value <= 0xe0000000) {
		print_value (value);
	    } else {
		pentry = &merge_log[value-0xe0000001];
#ifdef STATS
		map_merges++;
#endif
		//printf ("%lx -> %lx,%lx (%lu)\n", value, pentry->p1, pentry->p2, stack_depth);
		stack[stack_depth++] = pentry->p1;
		stack[stack_depth++] = pentry->p2;
	    }
	}
    } while (stack_depth);
}

int map_shmem (char* filename, int* pfd, u_long* pdatasize, u_long* pmapsize, char** pbuf)
{
    char shmemname[256];
    struct stat st, ost;
    u_long size, osize=0;
    int fd, ofd, rc;
    char* buf, *fbuf;

    ofd = open (filename, O_RDONLY, 0);
    if (ofd >= 0) {
	// This means that an overflow file was created - try to fit it in our address space
	rc = fstat(ofd, &ost);
	if (rc < 0) {
	    fprintf (stderr, "Unable to stat %s, rc=%d, errno=%d\n", filename, rc, errno);
	    return rc;
	}
	if (ost.st_size%4096) {
	    osize = ost.st_size + 4096-ost.st_size%4096;
	} else {
	    osize = ost.st_size;
	}
    }

    snprintf(shmemname, 256, "/node_nums_shm%s", filename);
    for (u_long i = 1; i < strlen(shmemname); i++) {
	if (shmemname[i] == '/') shmemname[i] = '.';
    }
    shmemname[strlen(shmemname)-10] = '\0';
    fd = shm_open (shmemname, O_RDONLY, 0);
    if (fd < 0) {
	fprintf (stderr, "Unable to open %s, rc=%d, errno=%d\n", shmemname, fd, errno);
	return fd;
    }
    rc = fstat(fd, &st);
    if (rc < 0) {
	fprintf (stderr, "Unable to stat %s, rc=%d, errno=%d\n", shmemname, rc, errno);
	return rc;
    }
    if (st.st_size%4096) {
	size = st.st_size + 4096-st.st_size%4096;
    } else {
	size = st.st_size;
    }

    if (ofd >= 0) {
	char* region;

	// First try to map contiguous redion
	region = (char *) mmap (NULL, size+osize, PROT_READ, MAP_PRIVATE|MAP_ANON, -1, 0);
	if (region == MAP_FAILED) {
	    fprintf (stderr, "Cannot map contiguous region of size %lu, errno=%d\n", size+osize, errno);
	    return -1;
	}
	munmap(region,size+osize);

	// Map shared memory to first portion
	buf = (char *) mmap (region, size, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
	    fprintf (stderr, "Cannot map shmem %s, errno=%d\n", shmemname, errno);
	    return -1;
	}
	// And overflow file to second portion
	fbuf = (char *) mmap (region+size, osize, PROT_READ, MAP_SHARED, ofd, 0);
	if (fbuf == MAP_FAILED) {
	    fprintf (stderr, "Cannot map file %s, errno=%d\n", shmemname, errno);
	    return -1;
	}
    } else {
	// No overflow
	buf = (char *) mmap (NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
	    fprintf (stderr, "Cannot map file %s, errno=%d\n", shmemname, errno);
	    return -1;
	}
    }

    // This is the last process to use the merge region
    // This will deallocate it  after we exit
    rc = shm_unlink (shmemname); 
    if (rc < 0) perror ("shmem_unlink");

    *pfd = fd;
    *pdatasize = st.st_size;
    *pmapsize = size;
    *pbuf = buf;

    return 0;
}


// Generate splice data:
// list of address for prior segment to track
static long map_before_segment (char* dirname)
{
    long rc;
    char* output_log, *plog;
    u_long ndatasize, odatasize, mergesize, mapsize, buf_size, value, i, zero = 0;
    char mergefile[256], outfile[256], map_name[256];
    int node_num_fd, mapfd;

    sprintf (mergefile, "%s/node_nums", dirname);
    sprintf (outfile, "%s/dataflow.result", dirname);

    rc = map_shmem (mergefile, &node_num_fd, &ndatasize, &mergesize, (char **) &merge_log);
    if (rc < 0) return rc;

    rc = map_file (outfile, &mapfd, &odatasize, &mapsize, &output_log);
    if (rc < 0) return rc;

    sprintf (map_name, "%s/map", dirname);
    outfd = open (map_name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outfd < 0) {
	fprintf (stderr, "map_inputs: cannot create splice file, errno=%d\n", errno);
	return -1;
    }

    plog = output_log;
    while (plog < output_log + odatasize) {
	plog += sizeof(struct taint_creation_info) + sizeof(u_long);
	buf_size = *((u_long *) plog);
	plog += sizeof(u_long);
	for (i = 0; i < buf_size; i++) {
	    plog += sizeof(u_long);
	    value = *((u_long *) plog);
	    plog += sizeof(u_long);
	    if (value) {
		if (value < 0xe0000001) {
		    print_value (value);
		} else {
		    map_iter (value);
		}
	    }
	    print_value(zero);
	}
    }

    flush_outbuf ();
    close (outfd);
#ifdef STATS
    printf ("map merges: %ld\n", map_merges);
#endif
    return 0;
}

int main (int argc, char* argv[]) 
{
    if (argc < 2) {
	fprintf (stderr, "format: mkmap <dirname>\n");
	return -1;
    }

    map_before_segment (argv[1]);

    return 0;
}
