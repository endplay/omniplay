#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <netdb.h>

#include <unordered_set>

#include "../taint_interface/taint.h"
#include "../linkage_common.h"
#include "../taint_interface/taint_creation.h"
#include "../token.h"
#include "../maputil.h"
#include "../taint_nw.h"

//#define DEBUG 0x1836
#ifdef DEBUG
FILE* debugfile;
#endif

//#define STATS

#ifdef STATS
unsigned long long values = 0, directs = 0, indirects = 0, map_merges = 0;
#endif

const u_long MERGE_SIZE  = 0x200000000; // 8GB max
const u_long OUTPUT_SIZE =  0x40000000; // 1GB max
const u_long TOKEN_SIZE =   0x10000000; // 256MB max
const u_long TS_SIZE =      0x40000000; // 1GB max

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

#ifdef DEBUG
static void dump_data (char* data, u_long size, char* dirname, const char* filename)
{
    char file[256];
    u_long bytes_written = 0;

    sprintf (file, "%s/%s", dirname, filename);
    int fd = open (file, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (fd < 0) {
	fprintf (stderr, "Cannot open %s\n", file);
	return;
    }

    while (bytes_written < size) {
	printf ("writing %ld bytes first %d to %s\n", size-bytes_written, *((uint32_t *) data+bytes_written), file);
	long rc = write (fd, data+bytes_written,size-bytes_written);
	if (rc <= 0) {
	    fprintf (stderr, "Cannot write %s\n", file);
	    return;
	}
	bytes_written += rc;
    }

    close (fd);
}
#endif

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

static long recv_taint_data (int s, char* buffer, u_long bufsize, uint32_t inputsize, u_long& ndx)
{
    uint32_t bytes_received = 0;
    while (bytes_received < inputsize) {
	long rc = read (s, buffer+ndx, inputsize-bytes_received);
	if (rc <= 0) {
	    fprintf (stderr, "recv_taint_data: received %ld, errno=%d\n", rc, errno);
	    break;
	}
	ndx += rc;
	bytes_received += rc;
    }
    return bytes_received;
}

// Generate splice data:
// list of address for prior segment to track
static long map_before_segment (char* dirname, int port)
{
    long rc;
    char* output_log, *token_log, *plog;
    taint_t *ts_log;
    uint32_t buf_size, tokens;
    u_long idatasize = 0, odatasize = 0, mdatasize = 0, adatasize = 0, i, zero = 0;
    taint_t value;
    char outrfile[256], outufile[256], map_name[256], outputfile[256], inputfile[256];
    int inputfd, outputfd;

    // Create mappings for inputs - we have to commit to a max size here
    token_log = (char *) mmap (NULL, TOKEN_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (token_log == MAP_FAILED) {
	fprintf (stderr, "Cannot map input data, errno=%d\n", errno);
	return -1;
    }

    output_log = (char *) mmap (NULL, OUTPUT_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (output_log == MAP_FAILED) {
	fprintf (stderr, "Cannot map output data, errno=%d\n", errno);
	return -1;
    }

    ts_log = (taint_t *) mmap (NULL, TS_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (ts_log == MAP_FAILED) {
	fprintf (stderr, "Cannot map addr data, errno=%d\n", errno);
	return -1;
    }

    merge_log = (taint_entry *) mmap (NULL, MERGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (merge_log == MAP_FAILED) {
	fprintf (stderr, "Cannot map merge log, errno=%d\n", errno);
	return -1;
    }

    // Set up output files 
    rc = mkdir(dirname, 0755);
    if (rc < 0) {
	fprintf (stderr, "Cannot create output dir %s, errno=%d\n", dirname, errno);
	return rc;
    }

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

    sprintf (map_name, "%s/merge-addrs", dirname);
    outfd = open (map_name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outfd < 0) {
	fprintf (stderr, "Cannot create merge-outputs file, errno=%d\n", errno);
	return -1;
    }

    sprintf (outputfile, "%s/dataflow.results", dirname);
    outputfd = open (outputfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outputfd < 0) {
	fprintf (stderr, "Cannot create dataflow.results file, errno=%d\n", errno);
	return -1;
    }

    sprintf (inputfile, "%s/tokens", dirname);
    inputfd = open (inputfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (inputfd < 0) {
	fprintf (stderr, "Cannot create tokens file, errno=%d\n", errno);
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

    // Initialize a socket to receive input data
    int c = socket (AF_INET, SOCK_STREAM, 0);
    if (c < 0) {
	fprintf (stderr, "Cannot create socket, errno=%d\n", errno);
	return c;
    }

    int on = 1;
    rc = setsockopt (c, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (rc < 0) {
	fprintf (stderr, "Cannot set socket option, errno=%d\n", errno);
	return rc;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    rc = bind (c, (struct sockaddr *) &addr, sizeof(addr));
    if (rc < 0) {
	fprintf (stderr, "Cannot bind socket, errno=%d\n", errno);
	return rc;
    }

    rc = listen (c, 5);
    if (rc < 0) {
	fprintf (stderr, "Cannot listen on socket, errno=%d\n", errno);
	return rc;
    }
    
    int s = accept (c, NULL, NULL);
    if (s < 0) {
	fprintf (stderr, "Cannot accept connection, errno=%d\n", errno);
	return s;
    }

    close (c);

    // Now receive the data into our memory buffers
    while (1) {
	
	// Receive header
	struct taint_data_header header;
	rc = read (s, &header, sizeof(header));
	if (rc == 0) break; // socket closed - no more data
	if (rc != sizeof(header)) {
	    printf ("Could not receive taint data header, rc=%ld\n", rc);
	    return -1;
	}
	
	// Receive data
	switch (header.type) {
	case TAINT_DATA_MERGE:
	    rc = recv_taint_data (s, (char *) merge_log, MERGE_SIZE, header.datasize, mdatasize);
	    break;
	case TAINT_DATA_OUTPUT:
	    rc = recv_taint_data (s, output_log, OUTPUT_SIZE, header.datasize, odatasize);
	    break;
	case TAINT_DATA_INPUT:
	    rc = recv_taint_data (s, token_log, TOKEN_SIZE, header.datasize, idatasize);
	    printf ("token log is %x\n", *((uint32_t *) token_log));
	    break;
	case TAINT_DATA_ADDR:
	    rc = recv_taint_data (s, (char *) ts_log, TS_SIZE, header.datasize, adatasize);
	    break;
	default:
	    fprintf (stderr, "Received unspecified taint header type %d\n", header.type);
	}
	if (rc != header.datasize) return -1;
    }
    
    printf ("Received %ld bytes of merge data\n", mdatasize);
    printf ("Received %ld bytes of output data\n", odatasize);
    printf ("Received %ld bytes of input data\n", idatasize);
    printf ("Received %ld bytes of addr data\n", adatasize);

#ifdef DEBUG
    dump_data ((char *) merge_log, mdatasize, dirname, "node_nums");
    dump_data (output_log, odatasize, dirname, "dataflow.results-debug");
    printf ("token log is %x\n", *((uint32_t *) token_log));
    dump_data (token_log, idatasize, dirname, "tokens-debug");
    dump_data ((char *) ts_log, adatasize, dirname, "taint_structures");
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

    flush_outubuf ();
    close (outufd);
    flush_outrbuf ();
    close (outrfd);

#ifdef STATS
    printf ("outputs %s - values: %ld, directs: %ld, indirects: %ld, map merges: %ld\n", dirname, values, directs, indirects, map_merges);
#endif

    // Get number of tokens for this epoch
    if (idatasize > 0) {
	struct token* ptoken = (struct token *) &token_log[idatasize-sizeof(struct token)];
	tokens = ptoken->token_num+ptoken->size-1;
	printf ("tokens: %x sizeof(token) %lu\n", tokens, sizeof(struct token));
    } else {
	if (start_flag) {
	    tokens = 0;
	} else {
	    tokens = 0xc0000000;
	}
    }

    print_value (output_token); // First entry is number of output tokens
    print_value (tokens);        // Second entry is number of input tokens

    for (i = 0; i < adatasize/(sizeof(taint_t)*2); i++) {
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

    // Need to persist the input and output token data
    u_long bytes_written = 0;
    while (bytes_written < idatasize) {
	rc = write (inputfd, token_log+bytes_written, idatasize-bytes_written);
	if (rc <= 0) {
	    fprintf (stderr, "Write of tokens data returns %ld\n", rc);
	    return -1;
	} 
	bytes_written += idatasize;
    }
    close (inputfd);

    char* optr = output_log;
    while ((u_long) optr < (u_long) output_log + odatasize) {
	rc = write (outputfd, optr, sizeof(struct taint_creation_info));
	if (rc != sizeof(struct taint_creation_info)) {
	    fprintf (stderr, "Write of output token returns %ld\n", rc);
	    return -1;
	} 
	optr += sizeof(struct taint_creation_info) + sizeof(uint32_t);
	buf_size = *((uint32_t *) optr);
	rc = write (outputfd, optr, sizeof(uint32_t));
	if (rc != sizeof(uint32_t)) {
	    fprintf (stderr, "Write of output size returns %ld\n", rc);
	    return -1;
	} 
	optr += sizeof(uint32_t) + buf_size*(sizeof(uint32_t)+sizeof(taint_t));
    }
    close (outputfd);

#ifdef STATS
    printf ("addrs %s - values: %ld, directs: %ld, indirects: %ld, map merges: %ld\n", dirname, values, directs, indirects, map_merges);
#endif
    return 0;
}

int main (int argc, char* argv[]) 
{
    if (argc < 2) {
	fprintf (stderr, "format: mkmap <dirname> <port> [-s]\n");
	return -1;
    }

    if (argc == 4 && !strcmp(argv[3], "-s")) start_flag = true;
    map_before_segment (argv[1], atoi(argv[2]));

    return 0;
}
