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

//#define STATS

struct taint_entry {
    taint_t p1;
    taint_t p2;
};

std::unordered_set<taint_t> splice_addrs;
static struct taint_entry* merge_log;

#ifdef STATS
u_long merges = 0, zeros = 0, directs = 0, indirects = 0, inputs = 0;
#endif

#define STACK_SIZE 1000000
u_long stack[STACK_SIZE];

static inline void splice_iter(taint_t value)
{
    struct taint_entry* pentry;
    u_long stack_depth = 0;
    
    pentry = &merge_log[value-0xe0000001];
    //printf ("%lx -> %lx,%lx (%lu)\n", value, pentry->p1, pentry->p2, stack_depth);
#ifdef STATS
    merges++;
#endif
    stack[stack_depth++] = pentry->p1;
    stack[stack_depth++] = pentry->p2;

    do {
	value = stack[--stack_depth];
	assert (stack_depth < STACK_SIZE);

	if (splice_addrs.insert(value).second) {
	
	    if (value > 0xe0000000) {
		pentry = &merge_log[value-0xe0000001];
		//printf ("\t%lx -> %lx,%lx (%lu)\n", value, pentry->p1, pentry->p2, stack_depth);
#ifdef STATS
		merges++;
#endif
		stack[stack_depth++] = pentry->p1;
		stack[stack_depth++] = pentry->p2;
	    }
	}
    } while (stack_depth);
}
 
// Format of splice file is an unordered list of "addresses of interest"
static long print_addrs (char* dirname)
{
    char* buf;
    u_long* p;
    u_long rc, num_addrs = splice_addrs.size(), wsize;
    char splice_name[256];
    int fd;

    buf = (char *) malloc (num_addrs * sizeof(u_long));
    if (buf == NULL) {
	fprintf (stderr, "print_addrs: cannot allocate splice buffer of size %lu\n", num_addrs);
	return -1;
    }

    p = (u_long *) buf;
    for (auto iter = splice_addrs.begin(); iter != splice_addrs.end(); iter++) {
	if (*iter < 0xc0000001) {
	    *p = *iter;
	    p++;
	}
    }
    
    sprintf (splice_name, "%s/splice", dirname);
    fd = open (splice_name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) {
	fprintf (stderr, "print_addrs: cannot create splice file, errno=%d\n", errno);
	return -1;
    }

    wsize = (u_long) p - (u_long) buf;
    rc = write (fd, buf, wsize);
    if (rc != wsize) {
	fprintf (stderr, "print_addrs: cannot write splice file, rc=%ld, errno=%d, wsize %lu\n", rc, errno, wsize);
	return -1;
    }

    close (fd);
    free (buf);
    return 0;
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

    *pfd = fd;
    *pdatasize = st.st_size;
    if (ofd >= 0) *pdatasize += ost.st_size;
    *pmapsize = size;
    *pbuf = buf;

    return 0;
}

// Generate splice data:
// list of address for prior segment to track
static long splice_before_segment (char* dirname)
{
    long rc;
    char* output_log, *plog;
    taint_t value;
    u_long ndatasize, odatasize, mergesize, mapsize, buf_size, i;
    char mergefile[256], outfile[256];
    int node_num_fd, outfd;

    sprintf (mergefile, "%s/node_nums", dirname);
    sprintf (outfile, "%s/dataflow.result", dirname);

    rc = map_shmem (mergefile, &node_num_fd, &ndatasize, &mergesize, (char **) &merge_log);
    if (rc < 0) return rc;

    rc = map_file (outfile, &outfd, &odatasize, &mapsize, &output_log);
    if (rc < 0) return rc;

    plog = output_log;
    while (plog < output_log + odatasize) {
	plog += sizeof(struct taint_creation_info) + sizeof(u_long);
	buf_size = *((u_long *) plog);
	plog += sizeof(u_long);
	for (i = 0; i < buf_size; i++) {
	    plog += sizeof(u_long);
	    value = *((u_long *) plog);
	    plog += sizeof(taint_t);
	    if (value) {
		if (value < 0xc0000001) {
		    splice_addrs.insert(value);
#ifdef STATS
		    directs++;
#endif
		} else if (value >= 0xe0000001) {
#ifdef STATS
		    indirects++;
#endif
		    splice_iter(value);
#ifdef STATS
		} else {
		    inputs++;
#endif
		}
#ifdef STATS
	    } else {
	      zeros++;
#endif
	    }

	}
    }

    print_addrs (dirname);
#ifdef STATS
    printf ("splice zeros: %ld\n", zeros);
    printf ("splice directs: %ld\n", directs);
    printf ("splice inputs: %ld\n", inputs);
    printf ("splice indirects: %ld\n", indirects);
    printf ("splice merges: %ld\n", merges);
#endif

    return 0;
}

int main (int argc, char* argv[]) 
{
    if (argc < 2) {
	fprintf (stderr, "format: mksplice <dirname>\n");
	return -1;
    }

    splice_before_segment (argv[1]);

    return 0;
}
