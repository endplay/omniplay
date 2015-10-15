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

#include "../taint_interface/taint.h"
#include "../linkage_common.h"
#include "../taint_interface/taint_creation.h"
#include "../token.h"
#include "../maputil.h"

//#define DEBUG 0x1836
#ifdef DEBUG
FILE* debugfile;
#endif

//#define STATS

#ifdef STATS
unsigned long long values = 0, directs = 0, indirects = 0, map_merges = 0;
#endif

struct taint_entry {
    taint_t p1;
    taint_t p2;
};
struct taint_entry* merge_log;

#define OUTBUFSIZE 1000000
uint32_t outbuf[OUTBUFSIZE];
u_long outindex = 0;
int outfd;

uint32_t outubuf[OUTBUFSIZE];
u_long outuindex = 0;
int outufd;

uint32_t outrbuf[OUTBUFSIZE];
u_long outrindex = 0;
int outrfd;

bool resolved_vals;
bool unresolved_vals;

uint32_t output_token = 0;

bool start_flag = false;

static void flush_outbuf()
{
    long rc = write (outfd, outbuf, outindex*sizeof(uint32_t));
    if (rc != (long) (outindex*sizeof(uint32_t))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
	exit (rc);
    }
    outindex = 0;
}

static inline void print_value (uint32_t value) 
{
    if (outindex == OUTBUFSIZE) flush_outbuf();
    outbuf[outindex++] = value;
}

static void flush_outubuf()
{
    long rc = write (outufd, outubuf, outuindex*sizeof(uint32_t));
    if (rc != (long) (outuindex*sizeof(uint32_t))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
	exit (rc);
    }
    outuindex = 0;
}

static inline void print_uvalue (uint32_t value) 
{
    if (outuindex == OUTBUFSIZE) flush_outubuf();
    outubuf[outuindex++] = value;
}

static void flush_outrbuf()
{
    long rc = write (outrfd, outrbuf, outrindex*sizeof(uint32_t));
    if (rc != (long) (outrindex*sizeof(uint32_t))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
	exit (rc);
    }
    outrindex = 0;
}

static inline void print_rvalue (uint32_t value) 
{
    if (outrindex == OUTBUFSIZE) flush_outrbuf();
    outrbuf[outrindex++] = value;
}

#define STACK_SIZE 1000000
taint_t stack[STACK_SIZE];

static void map_iter (taint_t value)
{
    std::unordered_set<taint_t> seen_indices;
    struct taint_entry* pentry;
    u_long stack_depth = 0;

    pentry = &merge_log[value-0xe0000001];
#ifdef STATS
    map_merges++;
#endif
    //fprintf (debugfile, "%llx -> %llx,%llx (%lu)\n", value, pentry->p1, pentry->p2, stack_depth);
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
			unresolved_vals = true;
		    }
		    print_uvalue (value);
#ifdef DEBUG
		    if (output_token == DEBUG) {
			fprintf (debugfile, "output %lx to unresolved value %llx (merge)\n", output_token, value);
		    }
#endif
		} else {
		    if (!resolved_vals) {
			print_rvalue (output_token);
			resolved_vals = true;
		    }
		    if (start_flag) {
			print_rvalue (value);
#ifdef DEBUG
			if (output_token == DEBUG) {
			  fprintf (debugfile, "output %lx to resolved start input %llx (merge)\n", output_token, value);
			}
#endif
		    } else {
			print_rvalue (value-0xc0000000);
#ifdef DEBUG
			if (output_token == DEBUG) {
			    fprintf (debugfile, "output %lx to resolved input %llx (merge)\n", output_token, value-0xc0000000);
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

static void map_iter2 (taint_t value)
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

// Generate splice data:
// list of address for prior segment to track
static long map_before_segment (char* dirname)
{
    struct token token;
    long rc;
    char* output_log, *plog;
    taint_t *ts_log;
    uint32_t buf_size, tokens;
    u_long ndatasize, odatasize, mergesize, mapsize, i, zero = 0;
    taint_t value;
    char mergefile[256], outfile[256], tsfile[256], outrfile[256], outufile[256], map_name[256], tokfile[256];
    int node_num_fd, mapfd, tfd;
    struct stat st;

    sprintf (mergefile, "%s/node_nums", dirname);
    sprintf (outfile, "%s/dataflow.result", dirname);
    sprintf (tsfile, "%s/taint_structures", dirname);
    sprintf (tokfile, "%s/tokens", dirname);

    rc = map_file (mergefile, &node_num_fd, &ndatasize, &mergesize, (char **) &merge_log);
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
	plog += sizeof(struct taint_creation_info) + sizeof(uint32_t);
	buf_size = *((uint32_t *) plog);
	plog += sizeof(uint32_t);
	for (i = 0; i < buf_size; i++) {
	    plog += sizeof(uint32_t);
	    value = *((taint_t *) plog);
	    plog += sizeof(taint_t);
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
			    fprintf (debugfile, "output %lx to unresolved addr %llx\n", output_token, value);
			}
#endif
			    
		    } else {
			print_rvalue (output_token);
			if (start_flag) {
			    print_rvalue (value);
#ifdef DEBUG
			    if (output_token == DEBUG) {
				fprintf (debugfile, "output %lx to resolved start input %llx\n", output_token, value);
			    }
#endif
			} else {
			    print_rvalue (value-0xc0000000);
#ifdef DEBUG
			    if (output_token == DEBUG) {
				fprintf (debugfile, "output %lx to resolved input %llx\n", output_token, value-0xc0000000);
			    }
#endif
			}
			print_rvalue (zero);
		    }
		} else {
#ifdef STATS
		    indirects++;
#endif
		    unresolved_vals = false;
		    resolved_vals = false;
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
	printf ("tokens: %x sizeof(token) %lu\n", tokens, sizeof(token));
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

    print_value (output_token); // First entry is number of output tokens
    print_value (tokens);        // Second entry is number of input tokens

    rc = map_file (tsfile, &mapfd, &odatasize, &mapsize, (char **) &ts_log);
    if (rc < 0) {
	/* Sometimes there is no file for last epoch - this is OK */
	flush_outbuf ();
	close (outfd);
	return rc;
    }

    for (i = 0; i < odatasize/(sizeof(taint_t)*2); i++) {
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

    if (argc == 3 && !strcmp(argv[2], "-s")) start_flag = true;
    map_before_segment (argv[1]);

    return 0;
}
