#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <pthread.h>
#include <netdb.h>

#include "linkage_common.h"
#include "taint_interface/taint_creation.h"
#include "xray_token.h"
#include "maputil.h"

#include <unordered_set>
#include <unordered_map>
#include <atomic>

using namespace std;

#include "../test/streamserver.h"


//#define DEBUG(x) ((x)==0x9808 || (x)==0x9808-0x21e || (x)==0x9808-0x24a6)
#define STATS

struct senddata {
    char*  host;
    short  port;
};

struct recvdata {
    short  port;
};

struct taint_entry {
    u_long p1;
    u_long p2;
};

#define STREAM_PORT 19765

#define OUTBUFSIZE 1000000

// Globals - mostly here for performance
unordered_map<u_long,unordered_set<u_long>*> resolved;
int                 outrfd;
u_long              outrindex;
u_long              outrbuf[OUTBUFSIZE];
struct taint_entry* merge_log;
struct taintq*      inputq;
u_long              can_read;
struct taintq*      outputq;
u_long              can_write;
int                 start_flag;
int                 finish_flag;

#ifdef DEBUG
FILE* debugfile;
#endif
#ifdef STATS
FILE* statsfile;
u_long merges = 0, directs = 0, indirects = 0, values = 0, output_merges;
u_long atokens = 0, passthrus = 0, aresolved = 0, aindirects = 0, avalues = 0, unmodified = 0;
struct timeval start_tv, output_done_tv, index_created_tv, address_done_tv, end_tv;

static long ms_diff (struct timeval tv1, struct timeval tv2)
{
    return ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000);
}
#endif

#define PRINT_UVALUE(val)						\
    {									\
	while (can_write == 0) {					\
	    usleep (100);						\
	    if (outputq->write_index >= outputq->read_index) {		\
		can_write = TAINTENTRIES - (outputq->write_index - outputq->read_index); \
	    } else {							\
		can_write = outputq->read_index - outputq->write_index; \
	    }								\
	}								\
	outputq->buffer[outputq->write_index] = (val);			\
	outputq->write_index++;						\
	if (outputq->write_index == TAINTENTRIES) outputq->write_index = 0; \
	can_write--;						\
    } 

#define PRINT_USENTINEL()			\
    {						\
	PRINT_UVALUE(0);			\
    }

// This will return a bogus value when the done flag is set and all entries are read
#define GET_UVALUE(val)							\
    {									\
	while (can_read == 0) {						\
	    usleep (100);						\
	    if (inputq->read_index > inputq->write_index) {		\
		can_read = TAINTENTRIES - (inputq->read_index - inputq->write_index); \
	    } else {							\
		can_read = inputq->write_index - inputq->read_index;	\
	    }								\
	}								\
	(val) = inputq->buffer[inputq->read_index];			\
	inputq->read_index++;						\
	if (inputq->read_index == TAINTENTRIES) inputq->read_index = 0; \
	can_read--;							\
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

#define PRINT_RVALUE(value)					\
    {								\
	if (outrindex == OUTBUFSIZE) flush_outrbuf();		\
	outrbuf[outrindex++] = (value);				\
    }

#define STACK_SIZE 1000000
u_long stack[STACK_SIZE];

static void map_iter (u_long value, u_long output_token, int& unresolved_vals, int& resolved_vals)
{
    unordered_set<u_long>* pset;

    auto iter = resolved.find(value);
    if (iter == resolved.end()) {
	unordered_set<u_long> seen_indices;
	struct taint_entry* pentry;
	u_long stack_depth = 0;
	
#ifdef STATS
	merges++;
#endif

	pset = new unordered_set<u_long>;
	resolved[value] = pset;
	
	pentry = &merge_log[value-0xe0000001];
	//printf ("%lx -> %lx,%lx (%lu)\n", value, pentry->p1, pentry->p2, stack_depth);
	stack[stack_depth++] = pentry->p1;
	stack[stack_depth++] = pentry->p2;
	
	do {
	    value = stack[--stack_depth];
	    assert (stack_depth < STACK_SIZE);
	    
	    if (value <= 0xe0000000) {
		pset->insert(value);
	    } else {
		if (seen_indices.insert(value).second) {
		    pentry = &merge_log[value-0xe0000001];
#ifdef STATS
		    merges++;
#endif
		    //printf ("%lx -> %lx,%lx (%lu)\n", value, pentry->p1, pentry->p2, stack_depth);
		    stack[stack_depth++] = pentry->p1;
		    stack[stack_depth++] = pentry->p2;
		}
	    }
	} while (stack_depth);
    } else {
	pset = iter->second;
    }

    for (auto iter2 = pset->begin(); iter2 != pset->end(); iter2++) {
	if (*iter2 < 0xc0000000 && !start_flag) {
	    if (!unresolved_vals) {
		PRINT_UVALUE(output_token);
		unresolved_vals = 1;
	    }
	    PRINT_UVALUE (*iter2);
#ifdef DEBUG
	    if (DEBUG(output_token)) {
		fprintf (debugfile, "cached: output %lx to unresolved value %lx (merge)\n", output_token, *iter2);
	    }
#endif
	} else {
	    if (!resolved_vals) {
		PRINT_RVALUE (output_token);
		resolved_vals = 1;
	    }
	    if (start_flag) {
		PRINT_RVALUE (*iter2);
#ifdef DEBUG
		if (DEBUG(output_token)) {
		    fprintf (debugfile, "cahced: output %lx to resolved start input %lx (merge)\n", output_token, *iter2);
		}
#endif
	    } else {
		PRINT_RVALUE (*iter2-0xc0000000);
#ifdef DEBUG
		if (DEBUG(output_token)) {
		    fprintf (debugfile, "cached: output %lx to resolved input %lx (merge)\n", output_token,*iter2-0xc0000000);
		}
#endif
	    }
	}
    }
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

// Process one epoch 
long stream_epoch (const char* dirname)
{
    long rc;
    char* output_log, *plog;
    u_long *ts_log;
    u_long ndatasize, odatasize, mergesize, mapsize, buf_size, value, otoken, i;
    char mergefile[256], outfile[256], tsfile[256], outrfile[256], addrfile[256], tokfile[256];
    int node_num_fd, mapfd;
    u_long output_token = 0;

    // First, resolve all outputs for this epoch
    sprintf (mergefile, "%s/node_nums", dirname);
    sprintf (outfile, "%s/dataflow.result", dirname);
    sprintf (outrfile, "%s/merge-outputs-resolved", dirname);
    sprintf (addrfile, "%s/merge-addrs", dirname);
    sprintf (tokfile, "%s/tokens", dirname);

#ifdef DEBUG
    char debugname[256];
    sprintf (debugname, "%s/stream-debug", dirname);
    debugfile = fopen (debugname, "w");
    if (debugfile == NULL) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", debugname, errno);
	return -1;
    }
#endif
#ifdef STATS
    gettimeofday(&start_tv, NULL);
#endif

    rc = map_shmem (mergefile, &node_num_fd, &ndatasize, &mergesize, (char **) &merge_log);
    if (rc < 0) return rc;

    rc = map_file (outfile, &mapfd, &odatasize, &mapsize, &output_log);
    if (rc < 0) return rc;

    outrfd = open (outrfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outrfd < 0) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", outrfile, errno);
	return outrfd;
    }
    outrindex = 0;

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
			PRINT_UVALUE (output_token);
			PRINT_UVALUE (value);
			PRINT_USENTINEL ();
#ifdef DEBUG
			if (DEBUG(output_token)) {
			    fprintf (debugfile, "output %lx to unresolved addr %lx\n", output_token, value);
			}
#endif
			    
		    } else {
			PRINT_RVALUE (output_token);
			if (start_flag) {
			    PRINT_RVALUE (value);
#ifdef DEBUG
			    if (DEBUG(output_token)) {
				fprintf (debugfile, "output %lx to resolved start input %lx\n", output_token, value);
			    }
#endif
			} else {
			    PRINT_RVALUE (value-0xc0000000);
#ifdef DEBUG
			    if (DEBUG(output_token)) {
				fprintf (debugfile, "output %lx to resolved input %lx\n", output_token, value-0xc0000000);
			    }
#endif
			}
			PRINT_RVALUE (0);
		    }
		} else {
#ifdef STATS
		    indirects++;
#endif
		    int unresolved_vals = 0, resolved_vals = 0;
		    map_iter (value, output_token, unresolved_vals, resolved_vals);
		    if (unresolved_vals) PRINT_USENTINEL();
		    if (resolved_vals) PRINT_RVALUE(0);
		}
	    }
	    output_token++;
#ifdef STATS
	    values++;
#endif
 	}
    }

    unmap_file (output_log, mapfd, mapsize);

#ifdef STATS
    gettimeofday(&output_done_tv, NULL);
    output_merges = merges;
    merges = 0;
#endif

    if (!finish_flag) {
	// Next, build index of output addresses
	unordered_map<u_long,u_long> address_map;
	
	sprintf (tsfile, "%s/taint_structures", dirname);
	rc = map_file (tsfile, &mapfd, &odatasize, &mapsize, (char **) &ts_log);
	if (rc < 0) return rc;
	
	for (i = 0; i < odatasize/(sizeof(u_long)*2); i++) {
	    address_map[ts_log[2*i]] = ts_log[2*i+1];
	}

#ifdef STATS
	gettimeofday(&index_created_tv, NULL);
#endif
	
	// Now, process input queue of later epoch outputs
	while (1) {
	    GET_UVALUE(otoken);
	    if (otoken == 0xffffffff) break;
#ifdef STATS
	    atokens++;
#endif
	    int unresolved_vals = 0, resolved_vals = 0;

	    GET_UVALUE(value);
	    while (value) {
#ifdef STATS
		avalues++;
#endif
		auto iter = address_map.find(value);
		if (iter == address_map.end()) {
		    if (!start_flag) {
#ifdef STATS
			passthrus++;
#endif
			// Not in this epoch - so pass through to next
			if (!unresolved_vals) {
			    PRINT_UVALUE(otoken+output_token);
			    unresolved_vals = 1;
			}
#ifdef DEBUG
			if (DEBUG(otoken+output_token) || DEBUG(otoken)) {
			    fprintf (debugfile, "output %lx(%lx/%lx) pass through value %lx\n", otoken+output_token, otoken, output_token, value);
			}
#endif
			PRINT_UVALUE(value);
		    }
		} else {
		    if (iter->second < 0xc0000000 && !start_flag) {
			if (iter->second) {
#ifdef STATS
			    unmodified++;
#endif
			    // Not in this epoch - so pass through to next
			    if (!unresolved_vals) {
				PRINT_UVALUE(otoken+output_token);
				unresolved_vals = 1;
			    }
#ifdef DEBUG
			    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
				fprintf (debugfile, "output %lx to unresolved value %lx via %lx\n", otoken+output_token, iter->second, value);
			    }
#endif
			    PRINT_UVALUE(iter->second);
			} // Else taint was cleared in this epoch
		    } else if (iter->second < 0xe0000001) {
			// Maps to input
#ifdef STATS
			aresolved++;
#endif
			if (!resolved_vals) {
			    PRINT_RVALUE(otoken+output_token);
			    resolved_vals = 1;
			}
			if (start_flag) {
#ifdef DEBUG
			    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
			      fprintf (debugfile, "output %lx to resolved value %lx via %lx\n", otoken+output_token, iter->second, value);
			    }
#endif
			    PRINT_RVALUE(iter->second);
			} else {
#ifdef DEBUG
			    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
			      fprintf (debugfile, "output %lx to resolved value %lx via %lx\n", otoken+output_token, iter->second-0xc0000000, value);
			    }
#endif
			    PRINT_RVALUE(iter->second-0xc0000000);
			}
		    } else {
			// Maps to merge
#ifdef STATS
			aindirects++;
#endif
#ifdef DEBUG
			if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
			    fprintf (debugfile, "output %lx to merge chain %lx\n", otoken+output_token, iter->second);
			}
#endif
			map_iter (iter->second, otoken+output_token, unresolved_vals, resolved_vals);
		    }
		}
		GET_UVALUE(value);
	    }
	    if (unresolved_vals) PRINT_USENTINEL();
	    if (resolved_vals) PRINT_RVALUE(0);
	}
#ifdef STATS
	gettimeofday(&address_done_tv, NULL);
#endif
    }
    if (!start_flag) PRINT_UVALUE(0xffffffff);

    flush_outrbuf ();
    close (outrfd);
    unmap_file ((char *) merge_log, node_num_fd, mergesize);

    int tfd = open (tokfile, O_RDONLY);
    if (tfd < 0) {
	fprintf (stderr, "cannot open token file %s, rc=%d, errno=%d\n", tokfile, tfd, errno);
	return tfd;
    }
    
    struct stat st;
    rc = fstat (tfd, &st);
    if (rc < 0) {
	fprintf (stderr, "Unable to fstat token file %s, rc=%ld, errno=%d\n", tokfile, rc, errno);
	return rc;
    }

    u_long tokens;
    if (st.st_size > 0) {
	struct token token;
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

    int afd = open(addrfile, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (afd < 0) {
	fprintf (stderr, "Cannot create address file %s, errno=%d\n", addrfile, errno);
	return afd;
    }
    rc = write (afd, &output_token, sizeof(output_token));
    if (rc != sizeof(output_token)) {
	fprintf (stderr, "Unable to write output token, rc=%ld, errno=%d\n", rc, errno);
	return rc;
    }
    rc = write (afd, &tokens, sizeof(tokens));
    if (rc != sizeof(tokens)) {
	fprintf (stderr, "Unable to write input token , rc=%ld, errno=%d\n", rc, errno);
	return rc;
    }
    close(afd);

#ifdef STATS
    gettimeofday(&end_tv, NULL);

    char statsname[256];
    sprintf (statsname, "%s/stream-stats", dirname);
    statsfile = fopen (statsname, "w");
    if (statsfile == NULL) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", statsname, errno);
	return -1;
    }

    fprintf (statsfile, "Total time:              %6ld ms\n", ms_diff (end_tv, start_tv));
    fprintf (statsfile, "Output processing time:  %6ld ms\n", ms_diff (output_done_tv, start_tv));
    if (!finish_flag) {
	fprintf (statsfile, "Index generation time:   %6ld ms\n", ms_diff (index_created_tv, output_done_tv));
	fprintf (statsfile, "Address processing time: %6ld ms\n", ms_diff (address_done_tv, index_created_tv));
	fprintf (statsfile, "Finish time:             %6ld ms\n", ms_diff (end_tv, address_done_tv));
    } else {
	fprintf (statsfile, "Finish time:             %6ld ms\n", ms_diff (end_tv, output_done_tv));
    }
    fprintf (statsfile, "\n");
    fprintf (statsfile, "Output directs %lu indirects %lu values %lu, merges %lu\n", directs, indirects, values, output_merges);
    if (!finish_flag) {
	fprintf (statsfile, "Address tokens %lu passthrus %lu resolved %lu, indirects %lu values %lu unmodified %lu, merges %lu\n", 
		 atokens, passthrus, aresolved, aindirects, avalues, unmodified, merges);
    }
    if (!start_flag) {
	u_long written = outputq->write_index;
	fprintf (statsfile, "Wrote %ld entries (%ld bytes)\n", written, written*sizeof(u_long)); 
    }
    fprintf (statsfile, "Unique indirects %d\n", resolved.size());
#endif

    return 0;
}

// Sending to another computer is implemented as separate thread to add asyncrhony
void* send_output_queue (void* arg)
{
    struct senddata* data = (struct senddata *) arg;
    struct sockaddr_in addr;
    struct hostent* hp;
    long rc;
    int s;

    // Establish a connection to receiving computer
    hp = gethostbyname (data->host);
    if (hp == NULL) {
	fprintf (stderr, "Invalid host %s, errno=%d\n", data->host, h_errno);
	return NULL;
    }

    s = socket (AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	fprintf (stderr, "Cannot create socket, errno=%d\n", errno);
	return NULL;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(data->port);
    memcpy (&addr.sin_addr, hp->h_addr, hp->h_length);

    // Receiver may not be started, so spin until connection is accepted
    do {
	rc = connect (s, (struct sockaddr *) &addr, sizeof(addr));
	if (rc < 0) {
	    fprintf (stderr, "Cannot connect, errno=%d\n", errno);
	    usleep (10000);
	}
    } while (rc < 0);

    // Listen on output queue and send over network
    while (1) {
	u_long can_send;
	u_long partial_bytes = 0;
	if (outputq->read_index > outputq->write_index) {			
	    can_send = TAINTENTRIES - outputq->read_index;
	} else {								
	    can_send = outputq->write_index - outputq->read_index;		
	}		
	if (can_send) {
	    can_send = can_send*sizeof(u_long)-partial_bytes; // Convert to bytes
	    rc = send (s, outputq->buffer + outputq->read_index, can_send, 0);
	    if (rc <= 0) {
		fprintf (stderr, "send returns %ld,errno=%d\n", rc, errno);
		break;
	    }
	    outputq->read_index += rc/sizeof(u_long);					       
	    if (rc%sizeof(u_long)) {
		partial_bytes += rc%sizeof(u_long);
		if (partial_bytes > sizeof(u_long)) {
		    outputq->read_index++;
		    partial_bytes -= sizeof(u_long);
		}
	    }
	    if (outputq->buffer[outputq->read_index-1] == 0xffffffff) break; // No more data to send
	} else {
	    usleep(100);
	}
    }

    close (s);
    return NULL;
}

void* recv_input_queue (void* arg)
{
    struct recvdata* data = (struct recvdata *) arg;
    struct sockaddr_in addr;
    long rc;
    int c, s;

    // Listen for incoming connection - should just be one so close listen socket after connection
    c = socket (AF_INET, SOCK_STREAM, 0);
    if (c < 0) {
	fprintf (stderr, "Cannot create socket, errno=%d\n", errno);
	return NULL;
    }

    int on = 1;
    rc = setsockopt (c, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (rc < 0) {
	fprintf (stderr, "Cannot set socket option, errno=%d\n", errno);
	return NULL;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(data->port);
    addr.sin_addr.s_addr = INADDR_ANY;

    printf ("Binding socket\n");
    rc = bind (c, (struct sockaddr *) &addr, sizeof(addr));
    if (rc < 0) {
	fprintf (stderr, "Cannot bind socket, errno=%d\n", errno);
	return NULL;
    }

    rc = listen (c, 5);
    if (rc < 0) {
	fprintf (stderr, "Cannot listen on socket, errno=%d\n", errno);
	return NULL;
    }
    
    s = accept (c, NULL, NULL);
    if (s < 0) {
	fprintf (stderr, "Cannot accept connection, errno=%d\n", errno);
	return NULL;
    }

    close (c);

    // Get data and put on the inputq
    while (1) {
	u_long can_recv;
	u_long partial_bytes = 0;
	if (inputq->write_index >= inputq->read_index) {			
	    can_recv = TAINTENTRIES - inputq->write_index;
	} else {								
	    can_recv = inputq->write_index - inputq->read_index;		
	}									
	if (can_recv) {
	    can_recv = can_recv*sizeof(u_long)-partial_bytes; // Convert to bytes
	    printf ("Receiving %lu bytes from inputq addr %p\n", can_recv*sizeof(u_long), inputq->buffer+inputq->write_index);
	    rc = recv (s, inputq->buffer + inputq->write_index, can_recv, 0);
	    if (rc < 0) {
		fprintf (stderr, "recv returns %ld,errno=%d\n", rc, errno);
		break;
	    } else if (rc == 0) {
		break; // Sender closed connection
	    }
	    inputq->write_index += rc/sizeof(u_long);					       
	    if (rc%sizeof(u_long)) {
		partial_bytes += rc%sizeof(u_long);
		if (partial_bytes > sizeof(u_long)) {
		    inputq->write_index++;
		    partial_bytes -= sizeof(u_long);
		}
	    }
	} else {
	    usleep(100);
	}
    }

    close (s);
    return NULL;
}

void format ()
{
    fprintf (stderr, "format: stream <dir> [-iq input_queue] [-oq output_queue] [-oh output_host] [-ih]\n");
    exit (0);
}

int main (int argc, char* argv[]) 
{
    char* input_queue = NULL;
    char* output_queue = NULL;
    char* output_host = NULL;
    bool input_host = false;
    pthread_t oh_tid, ih_tid;
    struct senddata sd;
    struct recvdata rd;
    long rc;

    if (argc < 2) format();

    for (int i = 0; i < argc; i++) {
	printf ("%s\n", argv[i]);
    }

    for (int i = 2; i < argc; i++) {
	if (!strcmp (argv[i], "-iq")) {
	    i++;
	    if (i < argc) {
		input_queue = argv[i];
	    } else {
		format();
	    }
	} else if (!strcmp (argv[i], "-oq")) {
	    i++;
	    if (i < argc) {
		output_queue = argv[i];
	    } else {
		format();
	    }
	} else if (!strcmp (argv[i], "-oh")) {
	    i++;
	    if (i < argc) {
		output_host = argv[i];
	    } else {
		format();
	    }
	} else if (!strcmp (argv[i], "-ih")) {
	    input_host = true;
	} else {
	    format();
	}
    }

    if (input_queue) {
	int iqfd = shm_open (input_queue, O_RDWR, 0);
	if (iqfd < 0) {
	    fprintf (stderr, "Cannot open input queue %s, errno=%d\n", input_queue, errno);
	    return -1;
	}
	inputq = (struct taintq *) mmap (NULL, TAINTQSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, iqfd, 0);
	if (inputq == MAP_FAILED) {
	    fprintf (stderr, "Cannot map input queue, errno=%d\n", errno);
	    return -1;
	}
	can_read = 0;
	finish_flag = 0;
    } else {
	inputq = NULL;
	finish_flag = 1;
    }

    if (output_queue) {
	int oqfd = shm_open (output_queue, O_RDWR, 0);
	if (oqfd < 0) {
	    fprintf (stderr, "Cannot open input queue %s, errno=%d\n", output_queue, errno);
	    return -1;
	}
	outputq = (struct taintq *) mmap (NULL, TAINTQSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, oqfd, 0);
	if (outputq == MAP_FAILED) {
	    fprintf (stderr, "Cannot map input queue, errno=%d\n", errno);
	    return -1;
	}
	can_write = 0;
	start_flag = 0;
    } else {
	outputq = NULL;
	start_flag = 1;
    }

    if (output_host) {
	sd.host = output_host;
	sd.port = STREAM_PORT;
	rc = pthread_create (&oh_tid, NULL, send_output_queue, &sd);
	if (rc < 0) {
	    fprintf (stderr, "Cannot create outputq thread\n");
	    return rc;
	}
    }

    if (input_host) {
	rd.port = STREAM_PORT;
	rc = pthread_create (&ih_tid, NULL, recv_input_queue, &rd);
	if (rc < 0) {
	    fprintf (stderr, "Cannot create inputq thread\n");
	    return rc;
	}
    }

    stream_epoch (argv[1]);
    
    if (output_host) pthread_join(oh_tid, NULL);
    if (input_host) pthread_join(ih_tid, NULL);

    return 0;
}
