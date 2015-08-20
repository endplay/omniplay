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
#include "xray_token.h"
#include "maputil.h"

//#define DEBUG 0x141fc
#ifdef DEBUG
FILE* debugfile;
#endif

//#define STATS

#ifdef STATS
u_long values = 0, directs = 0, indirects = 0, map_merges = 0;
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

u_long outubuf[OUTBUFSIZE];
u_long outuindex = 0;
int outufd;

u_long outrbuf[OUTBUFSIZE];
u_long outrindex = 0;
int outrfd;

int resolved_vals;
int unresolved_vals;
u_long output_token = 0;

int start_flag = 0;

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

static void flush_outubuf()
{
    long rc = write (outufd, outubuf, outuindex*sizeof(u_long));
    if (rc != (long) (outuindex*sizeof(u_long))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
	exit (rc);
    }
    outuindex = 0;
}

static inline void print_uvalue (u_long value) 
{
    if (outuindex == OUTBUFSIZE) flush_outubuf();
    outubuf[outuindex++] = value;
}

static void flush_outrbuf()
{
    long rc = write (outrfd, outrbuf, outrindex*sizeof(u_long));
    if (rc != (long) (outrindex*sizeof(u_long))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
	exit (rc);
    }
    outrindex = 0;
}

static inline void print_rvalue (u_long value) 
{
    if (outrindex == OUTBUFSIZE) flush_outrbuf();
    outrbuf[outrindex++] = value;
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
		if (value < 0xc0000000 && !start_flag) {
		    if (!unresolved_vals) {
			print_uvalue (output_token);
			unresolved_vals = 1;
		    }
		    print_uvalue (value);
#ifdef DEBUG
		    if (output_token == DEBUG) {
			fprintf (debugfile, "output %lx to unresolved value %lx (merge)\n", output_token, value);
		    }
#endif
		} else {
		    if (!resolved_vals) {
			print_rvalue (output_token);
			resolved_vals = 1;
		    }
		    if (start_flag) {
			print_rvalue (value);
#ifdef DEBUG
			if (output_token == DEBUG) {
			  fprintf (debugfile, "output %lx to resolved start input %lx (merge)\n", output_token, value);
			}
#endif
		    } else {
			print_rvalue (value-0xc0000000);
#ifdef DEBUG
			if (output_token == DEBUG) {
			    fprintf (debugfile, "output %lx to resolved input %lx (merge)\n", output_token, value-0xc0000000);
			}
#endif
		    }
		}
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

static void map_iter2 (u_long value)
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
    struct token token;
    long rc;
    char* output_log, *plog;
    u_long *ts_log;
    u_long tokens, ndatasize, odatasize, mergesize, mapsize, buf_size, value, i, zero = 0;
    char mergefile[256], outfile[256], tsfile[256], outrfile[256], outufile[256], map_name[256], tokfile[256];
    int node_num_fd, mapfd, tfd;
    struct stat st;

    sprintf (mergefile, "%s/node_nums", dirname);
    sprintf (outfile, "%s/dataflow.result", dirname);
    sprintf (tsfile, "%s/taint_structures", dirname);
    sprintf (tokfile, "%s/tokens", dirname);

    rc = map_shmem (mergefile, &node_num_fd, &ndatasize, &mergesize, (char **) &merge_log);
    if (rc < 0) return rc;

    rc = map_file (outfile, &mapfd, &odatasize, &mapsize, &output_log);
    if (rc < 0) return rc;

    sprintf (outufile, "%s/merge-outputs-unresolved", dirname);
    outufd = open (outufile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outufd < 0) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", outufile, errno);
	return -1;
    }
    sprintf (outrfile, "%s/merge-outputs-resolved", dirname);
    outrfd = open (outrfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outrfd < 0) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", outrfile, errno);
	return -1;
    }

#ifdef DEBUG
    char debugname[256];
    sprintf (debugname, "%s/mkmerge-debug", dirname);
    debugfile = fopen (debugname, "w");
    if (debugfile == NULL) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", debugname, errno);
	return -1;
    }
#endif

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
#ifdef STATS
		    directs++;
#endif
		    if (value < 0xc0000000 && !start_flag) {
			print_uvalue (output_token);
			print_uvalue (value);
			print_uvalue (zero);
#ifdef DEBUG
			if (output_token == DEBUG) {
			    fprintf (debugfile, "output %lx to unresolved addr %lx\n", output_token, value);
			}
#endif
			    
		    } else {
			print_rvalue (output_token);
			if (start_flag) {
			    print_rvalue (value);
#ifdef DEBUG
			    if (output_token == DEBUG) {
				fprintf (debugfile, "output %lx to resolved start input %lx\n", output_token, value);
			    }
#endif
			} else {
			    print_rvalue (value-0xc0000000);
#ifdef DEBUG
			    if (output_token == DEBUG) {
				fprintf (debugfile, "output %lx to resolved input %lx\n", output_token, value-0xc0000000);
			    }
#endif
			}
			print_rvalue (zero);
		    }
		} else {
#ifdef STATS
		    indirects++;
#endif
		    unresolved_vals = 0;
		    resolved_vals = 0;
		    map_iter (value);
		    if (unresolved_vals) print_uvalue(zero);
		    if (resolved_vals) print_rvalue(zero);
		}
	    }
	    output_token++;
#ifdef STATS
	    values++;
#endif
 	}
    }

    unmap_file (output_log, mapfd, mapsize);

    flush_outubuf ();
    close (outufd);
    flush_outrbuf ();
    close (outrfd);

#ifdef STATS
    printf ("outputs %s - values: %ld, directs: %ld, indirects: %ld, map merges: %ld\n", dirname, values, directs, indirects, map_merges);
#endif

    // Get number of tokens for this epoch
    tfd = open (tokfile, O_RDONLY);
    if (outfd < 0) {
	fprintf (stderr, "cannot open token file %s, rc=%d, errno=%d\n", tokfile, tfd, errno);
	return tfd;
    }
    
    rc = fstat (tfd, &st);
    if (rc < 0) {
	fprintf (stderr, "Unable to fstat token file %s, rc=%ld, errno=%d\n", tokfile, rc, errno);
	return rc;
    }

    if (st.st_size > 0) {
	rc = pread (tfd, &token, sizeof(token), st.st_size-sizeof(token));
	if (rc != sizeof(token)) {
	    fprintf (stderr, "Unable to read last token from file %s, rc=%ld, errno=%d\n", tokfile, rc, errno);
	    return rc;
	}
	
	tokens = token.token_num+token.size-1;
    } else {
	if (start_flag) {
	    tokens = 0;
	} else {
	    tokens = 0xc0000000;
	}
    }
    close (tfd);

    sprintf (map_name, "%s/merge-addrs", dirname);
    outfd = open (map_name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outfd < 0) {
	fprintf (stderr, "Cannot create merge-outputs file, errno=%d\n", errno);
	return -1;
    }

    rc = map_file (tsfile, &mapfd, &odatasize, &mapsize, (char **) &ts_log);
    if (rc < 0) return rc;

    print_value (output_token); // First entry is number of output tokens
    print_value (tokens);        // Second entry is number of input tokens
    for (i = 0; i < odatasize/(sizeof(u_long)*2); i++) {
	print_value (ts_log[2*i]); // addr
	value = ts_log[2*i+1];
	if (value) {
	    if (value < 0xe0000001) {
#ifdef STATS
		directs++;
#endif
		print_value (value);
	    } else {
#ifdef STATS
		indirects++;
#endif
		map_iter2 (value);
	    }
	}
#ifdef STATS
	values++;
#endif
	print_value(zero);
    }

    flush_outbuf ();
    close (outfd);

#ifdef STATS
    printf ("addrs %s - values: %ld, directs: %ld, indirects: %ld, map merges: %ld\n", dirname, values, directs, indirects, map_merges);
#endif
    return 0;
}

int main (int argc, char* argv[]) 
{
    if (argc < 2) {
	fprintf (stderr, "format: mkmap <dirname> [-s]\n");
	return -1;
    }

    if (argc == 3 && !strcmp(argv[2], "-s")) start_flag = 1;
    map_before_segment (argv[1]);

    return 0;
}
