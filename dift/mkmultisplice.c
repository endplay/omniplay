#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <glib-2.0/glib.h>

#include "linkage_common.h"
#include "taint_interface/taint_creation.h"
#include "maputil.h"

#define STATS

struct taint_entry {
    u_long p1;
    u_long p2;
};
#define NUM_MERGE_ENTRIES 134217728
#define MERGE_BLOCK_SIZE (NUM_MERGE_ENTRIES*sizeof(struct taint_entry))

#define INPUT_START 0xc0000001
#define MERGE_START 0xe0000001

static GHashTable* seen_addrs;
static GHashTable** splice_addrs;
static struct taint_entry* merge_log;
u_long block_start;

#ifdef STATS
static u_long merges = 0, earlier_block = 0, input = 0;
#endif

#define STACK_SIZE NUM_MERGE_ENTRIES
u_long stack[STACK_SIZE];

static void splice_iter(u_long value)
{
    struct taint_entry* pentry;
    u_long stack_depth = 0;
    int ndx;

    stack[stack_depth++] = value;

    do {
	value = stack[--stack_depth];

	if (value < INPUT_START) {
	    g_hash_table_add(splice_addrs[0], GUINT_TO_POINTER(value));
	} else if (value >= MERGE_START) {
	    if (value < block_start) {
		ndx = (value-MERGE_START)/MERGE_BLOCK_SIZE + 1;
		g_hash_table_add(splice_addrs[ndx], GUINT_TO_POINTER(value));
	    } else {
	      if (!g_hash_table_contains(seen_addrs, GUINT_TO_POINTER(value))) {
	
		g_hash_table_add(seen_addrs, GUINT_TO_POINTER(value));
		pentry = &merge_log[value-block_start];
#ifdef STATS
		merges++;
#endif
		//printf ("%lx -> %lx,%lx (%lu)\n", value, pentry->p1, pentry->p2, stack_depth);
		stack[stack_depth++] = pentry->p1;
		stack[stack_depth++] = pentry->p2;
	      }
	    }
	}
    } while (stack_depth > 0);
}

// Format of splice file is an unordered list of "addresses of interest"
static long print_addrs (char* dirname)
{
    GHashTableIter iter;
    gpointer key, value;
    char* buf;
    u_long* p;
    u_long rc, num_addrs = g_hash_table_size(splice_addrs[0]), wsize;
    char splice_name[256];
    int fd;

    buf = (char *) malloc (num_addrs * sizeof(u_long));
    if (buf == NULL) {
	fprintf (stderr, "print_addrs: cannot allocate splice buffer of size %lu\n", num_addrs);
	return -1;
    }

    g_hash_table_iter_init(&iter, splice_addrs[0]);
    p = (u_long *) buf;
    while (g_hash_table_iter_next(&iter, &key, &value)) {
	if (GPOINTER_TO_UINT(key) < 0xc0000001) {
	    *p = GPOINTER_TO_UINT(key);
	    p++;
	} else {
	    fprintf (stderr, "Should not see address %p in outputs", key);
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
    struct stat st;
    u_long size;
    int fd, rc, i;
    char* buf;

    snprintf(shmemname, 256, "/node_nums_shm%s", filename);
    for (i = 1; i < strlen(shmemname); i++) {
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

    buf = (char *) mmap (NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
	fprintf (stderr, "Cannot map file %s, errno=%d\n", shmemname, errno);
	return -1;
    }

    *pfd = fd;
    *pdatasize = st.st_size;
    *pmapsize = size;
    *pbuf = buf;

    return 0;
}

// Generate splice data:
// list of address for prior segment to track
static long splice_before_segment (char* dirname, int mfd, int blocks)
{
    long rc;
    char* output_log, *plog;
    u_long mdatasize, odatasize, mergesize, mapsize, buf_size, value, i;
    char mergefile[256], outfile[256];
    int outfd, blk, ndx;
    GHashTableIter iter;
    gpointer k, v;

    sprintf (mergefile, "%s/node_nums", dirname);
    sprintf (outfile, "%s/dataflow.result", dirname);

    rc = map_file (outfile, &outfd, &odatasize, &mapsize, &output_log);
    if (rc < 0) return rc;

    // Initialize hash tables
    seen_addrs = g_hash_table_new(g_direct_hash, g_direct_equal);
    splice_addrs = malloc(blocks*sizeof(GHashTable *));
    if (splice_addrs == NULL) {
	fprintf (stderr, "Cannot malloc splice_addrs array\n");
	return -1;
    }
    for (blk = 0; blk < blocks; blk++) {
	splice_addrs[blk] = g_hash_table_new(g_direct_hash, g_direct_equal);
    }

    for (blk = blocks-1; blk >= 0; blk--) {

	printf ("Doing block %d\n", blk);

	if (blk == 0) {
	    rc = map_shmem (mergefile, &mfd, &mdatasize, &mergesize, (char **) &merge_log);
	    if (rc < 0) return rc;
	} else {
	    merge_log = (struct taint_entry *) mmap (0, MERGE_BLOCK_SIZE, PROT_READ, MAP_SHARED, mfd, (blk-1)*MERGE_BLOCK_SIZE);
	    if (merge_log == MAP_FAILED) {
		fprintf (stderr, "Cannot map block %d of merge file, errno=%d\n", blk, errno);
		return -1;
	    }
	}
   
	block_start = MERGE_START+(blk*NUM_MERGE_ENTRIES);

	if (blk == blocks-1) {
	    // First iteration - read all entries from file
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
			if (value < INPUT_START) {
#ifdef STATS
			    input++;
#endif
			    g_hash_table_add(splice_addrs[0], GUINT_TO_POINTER(value));
			} else if (value >= MERGE_START) {
			    if (value < block_start) {
#ifdef STATS
				earlier_block++;
#endif
				ndx = (value-MERGE_START)/MERGE_BLOCK_SIZE + 1;
				g_hash_table_add(splice_addrs[ndx], GUINT_TO_POINTER(value));
			    } else {
				//printf ("value is %lx\n", value);
				splice_iter(value);
			    }
			}
		    }
		}
	    }
	} else {
	    printf ("size of block inputs: %d\n", g_hash_table_size(splice_addrs[blk+1]));
	    // Subsequent iterations - read from hash tables
	    g_hash_table_iter_init(&iter, splice_addrs[blk+1]);
	    while (g_hash_table_iter_next(&iter, &k, &v)) {	  
		// Should be in the correct range alredy
		//splice_recurse (GPOINTER_TO_UINT(k), 1);
		splice_iter(GPOINTER_TO_UINT(k));
	    }
	}
#ifdef STATS
	printf ("merges so far: %ld\n", merges);
#endif

	if (munmap (merge_log, MERGE_BLOCK_SIZE) < 0) {
	    fprintf (stderr, "Unable to munmap merge data, errno=%d\n", errno);
	}
    }
#ifdef STATS
    printf ("merges: %ld\n", merges);
    printf ("earlier block: %ld\n", earlier_block);
    printf ("input: %ld\n", input);
#endif

    print_addrs (dirname);

    return 0;
}

int main (int argc, char* argv[]) 
{
    char mergefile[256];
    struct stat st;
    int fd, rc, blocks;

    if (argc < 2) {
	fprintf (stderr, "format: mksplice <dirname>\n");
	return -1;
    }

    // Figure out how big the merge log is
    sprintf (mergefile, "%s/node_nums", argv[1]);
    fd = open (mergefile, O_RDONLY | O_LARGEFILE);
    if (fd >= 0) {

	rc = fstat(fd, &st);
	if (rc < 0) {
	    fprintf (stderr, "Unable to stat %s, rc=%d, errno=%d\n", mergefile, rc, errno);
	    return rc;
	}
	if (st.st_size % MERGE_BLOCK_SIZE) {
	    fprintf (stderr, "Merge file is of non-standard size %lu\n", st.st_size);
	}
	blocks = st.st_size / MERGE_BLOCK_SIZE + 1; 
    } else {
	blocks = 1;
    }
    printf ("Segments for multi-splice %d\n", blocks);

    splice_before_segment (argv[1], fd, blocks);

    return 0;
}
