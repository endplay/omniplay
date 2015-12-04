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

#include <unordered_set>
#include <unordered_map>
#include <atomic>
using namespace std;

#include "streamnw.h"
#include "../taint_interface/taint.h"
#include "../linkage_common.h"
#include "../taint_interface/taint_creation.h"
#include "../token.h"
#include "../taint_nw.h"
#include "../../test/streamserver.h"

//#define DEBUG(x) ((x)==0x1cec000 || (x)==0x0)
#define STATS

// Set up limits here - need to be less generate with 32-bit address space
#ifdef USE_NW
#ifdef BUILD_64
const u_long MERGE_SIZE  = 0x400000000; // 16GB max
const u_long OUTPUT_SIZE = 0x100000000; // 4GB max
#else
const u_long MERGE_SIZE  = 0x40000000; // 1GB max
const u_long OUTPUT_SIZE = 0x40000000; // 1GB max
#endif
const u_long TOKEN_SIZE =   0x10000000; // 256MB max
const u_long TS_SIZE =      0x40000000; // 1GB max
const u_long OUTBUFSIZE =   0x10000000; // 1GB size
#endif

#ifdef USE_SHMEM
const u_long OUTBUFSIZE =   0x2000000; // 128MB size
#ifdef BUILD_64
const u_long MAX_ADDRESS_MAP = 0; // No limit
#else
const u_long MAX_ADDRESS_MAP = 0x100000; // 16 MB
int afd;
#endif
#endif

#define TERM_VAL 0xffffffff // Sentinel for queue transmission

struct senddata {
    char*  host;
    short  port;
    bool   do_sequential;
};

struct recvdata {
    short  port;
    bool   do_sequential;
};

struct taint_entry {
    taint_t p1;
    taint_t p2;
};

#define STREAM_PORT 19765

// Globals - mostly here for performance
unordered_map<taint_t,unordered_set<uint32_t>*> resolved;
int                 outrfd;
uint32_t            outrindex = 0;
uint32_t            outrbuf[OUTBUFSIZE];
struct taint_entry* merge_log;
struct taintq*      inputq;
uint32_t            can_read, can_write;
struct taintq*      outputq;
bool                start_flag = false;
bool                finish_flag = false;

#ifdef DEBUG
FILE* debugfile;
#endif
#ifdef STATS
FILE* statsfile;
u_long merges = 0, directs = 0, indirects = 0, values = 0, idle = 0, output_merges;
u_long atokens = 0, passthrus = 0, aresolved = 0, aindirects = 0, avalues = 0, unmodified = 0, written = 0;
u_long prune_cnt = 0, simplify_cnt = 0;
u_long new_live_zeros = 0, new_live_inputs = 0, new_live_merges = 0, new_live_merge_zeros = 0, new_live_notlive = 0;
u_long live_set_size = 0, new_live_set_size = 0;
struct timeval start_tv, recv_done_tv, output_done_tv, index_created_tv, address_done_tv, end_tv;
struct timeval live_receive_done_tv, new_live_start_tv, live_done_tv, new_live_send_tv;

static long ms_diff (struct timeval tv1, struct timeval tv2)
{
    return ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000);
}
#endif

#ifdef STATS
#define IDLE					\
    {						\
	struct timeval tv1, tv2;		\
	gettimeofday(&tv1, NULL);		\
	usleep (100);				\
	gettimeofday(&tv2, NULL);		\
	idle += tv2.tv_usec - tv1.tv_usec;	\
	idle += (tv2.tv_sec - tv1.tv_sec)*1000000;	\
    }
#else
#define IDLE usleep (100);
#endif

#define PUT_QVALUE(val,q)						\
    {									\
	while (can_write == 0) {					\
	    IDLE;							\
	    if ((q)->write_index >= (q)->read_index) {			\
		can_write = TAINTENTRIES - ((q)->write_index - (q)->read_index); \
	    } else {							\
		can_write = (q)->read_index - (q)->write_index;		\
	    }								\
	}								\
	(q)->buffer[(q)->write_index] = (val);				\
	(q)->write_index++;						\
	if ((q)->write_index == TAINTENTRIES) (q)->write_index = 0;	\
	can_write--;							\
    } 


// This will return a bogus value when the done flag is set and all entries are read
#define GET_QVALUE(val,q)						\
    {									\
	while (can_read == 0) {						\
	    IDLE;							\
	    if ((q)->read_index > (q)->write_index) {			\
		can_read = TAINTENTRIES - ((q)->read_index - (q)->write_index); \
	    } else {							\
		can_read = (q)->write_index - (q)->read_index;		\
	    }								\
	}								\
	(val) = (q)->buffer[(q)->read_index];				\
	(q)->read_index++;						\
	if ((q)->read_index == TAINTENTRIES) (q)->read_index = 0;	\
	can_read--;							\
    }

#define DOWN_QSEM(q) sem_wait(&(q)->epoch_sem);
#define UP_QSEM(q) sem_post(&(q)->epoch_sem);

static void flush_outrbuf()
{
    long bytes_written = 0;
    long size = outrindex*sizeof(uint32_t);
    
    while (bytes_written < size) {
	long rc = write (outrfd, ((char *) outrbuf)+bytes_written, size-bytes_written);	
	if (rc <= 0) {
	    fprintf (stderr, "Canot write to resolved file, rc=%ld\n", rc);
	    exit (rc);
	}
	bytes_written += rc;
    }
    outrindex = 0;
}

#define PRINT_RVALUE(value)					\
    {								\
	if (outrindex == OUTBUFSIZE) flush_outrbuf();		\
	outrbuf[outrindex++] = (value);				\
    }

#define STACK_SIZE 1000000
taint_t stack[STACK_SIZE];

static int
init_socket (int port)
{
   int c = socket (AF_INET, SOCK_STREAM, 0);
    if (c < 0) {
	fprintf (stderr, "Cannot create socket, errno=%d\n", errno);
	return c;
    }

    int on = 1;
    long rc = setsockopt (c, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
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
    return s;
}

#ifdef USE_NW
static long recv_taint_data (int s, char* buffer, u_long bufsize, uint32_t inputsize, u_long& ndx)
{
    if (ndx+inputsize > bufsize) {
	fprintf (stderr, "recv_taint_data: buffer of %lu bytes too small\n", bufsize);
	return -1;
    }
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

static long
read_inputs (int port, char*& token_log, char*& output_log, taint_t*& ts_log, taint_entry*& merge_log,
	     u_long& mdatasize, u_long& odatasize, u_long& idatasize, u_long& adatasize)
{
    int rc;

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

    // Initialize a socket to receive input data
    int s = init_socket (port);

    // Now receive the data into our memory buffers
    while (1) {
	
	// Receive header
	struct taint_data_header header;
	int hbytes_received = 0;
	do {
	    rc = read (s, ((char *) (&header)) + hbytes_received, sizeof(header)-hbytes_received);
	    if (rc == 0) {
		if (hbytes_received) {
		    printf ("Partial header received, %d bytes\n", hbytes_received);
		    return -1;
		}
		close (s); // Socket closed - no more data
		return 0;
	    }
	    if (rc < 0) {
		printf ("Could not receive taint data header, rc=%d, errno=%d\n", rc, errno);
		return -1;
	    }
	    hbytes_received += rc;
	} while (hbytes_received != sizeof(header));

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
	    break;
	case TAINT_DATA_ADDR:
	    rc = recv_taint_data (s, (char *) ts_log, TS_SIZE, header.datasize, adatasize);
	    break;
	default:
	    fprintf (stderr, "Received unspecified taint header type %d\n", header.type);
	}
	if ((u_long) rc != header.datasize) return -1;
    }

    close (s);

    return 0;
}
#endif 
#ifdef USE_SHMEM

static void*
map_buffer (const char* prefix, const char* group_directory, u_long& datasize, u_long maxsize, int& fd)
{
    char filename[256];
    snprintf(filename, 256, "/%s_shm%s", prefix, group_directory);
    for (u_int i = 1; i < strlen(filename); i++) {
	if (filename[i] == '/') filename[i] = '.';
    }

    fd = shm_open(filename, O_RDWR, 0644);
    if (fd < 0) {
	fprintf(stderr, "could not open shmem %s, errno %d\n", filename, errno);
	return NULL;
    }

    struct stat64 st;
    int rc = fstat64 (fd, &st);
    if (rc < 0) {
	fprintf (stderr, "Cannot fstat shmem %s, rc=%d, errno=%d\n", filename, rc, errno);
	return NULL;
    }
    datasize = st.st_size;
    if (datasize == 0) return NULL;  // Some inputs may actually have no data

    int mapsize = datasize;
    if (maxsize) mapsize = maxsize;
    if (mapsize%4096) mapsize += (4096-mapsize%4096);
    void* ptr = mmap (NULL, mapsize, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
	fprintf (stderr, "Cannot map input data for %s, errno=%d\n", filename, errno);
	return NULL;
    }
    rc = shm_unlink (filename);
    if (rc < 0) {
	fprintf (stderr, "shm_unlink of %s failed, rc=%d, errno=%d\n", filename, rc, errno);
    }

    return ptr;
}

static long
read_inputs (int port, char*& token_log, char*& output_log, taint_t*& ts_log, taint_entry*& merge_log,
	     u_long& mdatasize, u_long& odatasize, u_long& idatasize, u_long& adatasize)
{
    // Initialize a socket to receive a little bit of input data
    int s = init_socket (port);

    // This will be sent after processing is completed 
    char group_directory[256];
    int rc = read (s, &group_directory, sizeof(group_directory));
    if (rc != sizeof(group_directory)) {
	fprintf (stderr, "read of group directory failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    int token_fd, output_fd, ts_fd, merge_fd;
    token_log = (char *) map_buffer ("tokens", group_directory, idatasize, 0, token_fd);
    output_log = (char *) map_buffer ("dataflow.results", group_directory, odatasize, 0, output_fd);
    ts_log = (taint_t *) map_buffer ("taint_structures", group_directory, adatasize, MAX_ADDRESS_MAP, ts_fd);
    merge_log = (taint_entry *) map_buffer ("node_nums", group_directory, mdatasize, 0, merge_fd);
#ifndef BUILD_64
    afd = ts_fd;
#endif
    printf ("%s: i %ld o %ld a %ld m %ld\n", group_directory, idatasize,
	    odatasize, adatasize, mdatasize);
    return 0;
}
#endif

static void map_iter (taint_t value, uint32_t output_token, bool& unresolved_vals, bool& resolved_vals)
{
    unordered_set<uint32_t>* pset;

    //auto iter = resolved.find(value);
    //if (iter == resolved.end()) {
	unordered_set<taint_t> seen_indices;
	struct taint_entry* pentry;
	uint32_t stack_depth = 0;
	
#ifdef STATS
	merges++;
#endif

	pset = new unordered_set<uint32_t>;
	//resolved[value] = pset;
	
	pentry = &merge_log[value-0xe0000001];
	// printf ("%llx -> %llx,%llx (%u)\n", value, pentry->p1, pentry->p2, stack_depth);
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
		    // printf ("%llx -> %llx,%llx (%u)\n", value, pentry->p1, pentry->p2, stack_depth);
		    stack[stack_depth++] = pentry->p1;
		    stack[stack_depth++] = pentry->p2;
		}
	    }
	} while (stack_depth);
	//} else {
	//pset = iter->second;
	//}

	pset->erase(0);
    for (auto iter2 = pset->begin(); iter2 != pset->end(); iter2++) {
	if (*iter2 < 0xc0000000 && !start_flag) {
	    if (!unresolved_vals) {
		PUT_QVALUE(output_token,outputq);
		unresolved_vals = true;
	    }
	    PUT_QVALUE (*iter2,outputq);
#ifdef DEBUG
	    if (DEBUG(output_token)) {
		fprintf (debugfile, "cached: output %x to unresolved value %x (merge)\n", output_token, *iter2);
	    }
#endif
	} else {
	    if (!resolved_vals) {
		PRINT_RVALUE (output_token);
		resolved_vals = true;
	    }
	    if (start_flag) {
		PRINT_RVALUE (*iter2);
#ifdef DEBUG
		if (DEBUG(output_token)) {
		    fprintf (debugfile, "cahced: output %x to resolved start input %x (merge)\n", output_token, *iter2);
		}
#endif
	    } else {
		PRINT_RVALUE (*iter2-0xc0000000);
#ifdef DEBUG
		if (DEBUG(output_token)) {
		    fprintf (debugfile, "cached: output %x to resolved input %x (merge)\n", output_token,*iter2-0xc0000000);
		}
#endif
	    }
	}
    }

    delete pset;
}

static long
build_address_map (unordered_map<taint_t,taint_t>& address_map, taint_t* ts_log, u_long adatasize)
{
#ifdef BUILD_64
    for (uint32_t i = 0; i < adatasize/(sizeof(taint_t)*2); i++) {
	address_map[ts_log[2*i]] = ts_log[2*i+1];
    }
#else
    // To conserve memory, only map a portion at a time since we are streaming this
    taint_t* p = (taint_t *) ts_log;
    long rc;
    for (uint32_t i = 0; i < adatasize/(sizeof(taint_t)*2); i++) {
	address_map[*p] = *(p+1);
	p += 2;

	if (i%(MAX_ADDRESS_MAP/(sizeof(taint_t)*2)) == MAX_ADDRESS_MAP/(sizeof(taint_t)*2)-1) {
	    rc = munmap (ts_log, MAX_ADDRESS_MAP);
	    if (rc < 0) {
		fprintf (stderr, "Cannot unmap address chunk\n");
	    }
	    
	    p = (taint_t *) mmap (ts_log, MAX_ADDRESS_MAP, PROT_READ|PROT_WRITE, MAP_SHARED, afd, (i+1)*(sizeof(taint_t)*2));
	    if (p == MAP_FAILED) {
		fprintf (stderr, "Cannot map address input chunk, errno=%d\n", errno);
		return -1;
	    }
	    ts_log = p;
	}
    }
    rc = munmap (ts_log, MAX_ADDRESS_MAP); // No longer needed
    if (rc < 0) {
	fprintf (stderr, "Cannot unmap last address chunk\n");
    }	    
    ts_log = NULL;
#endif

    return 0;
}

// Process one epoch 
long stream_epoch (const char* dirname, int port)
{
    long rc;
    char* output_log, *token_log, *plog;
    taint_t *ts_log, value;
    u_long idatasize = 0, odatasize = 0, mdatasize = 0, adatasize = 0;
    uint32_t buf_size, tokens, otoken, output_token = 0;
    char outrfile[256], outputfile[256], inputfile[256], addrsfile[256];
    int outputfd, inputfd, addrsfd;

    // First, resolve all outputs for this epoch
    rc = mkdir(dirname, 0755);
    if (rc < 0 && errno != EEXIST) {
	fprintf (stderr, "Cannot create output dir %s, errno=%d\n", dirname, errno);
	return rc;
    }

    sprintf (outrfile, "%s/merge-outputs-resolved", dirname);
    outrfd = open (outrfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outrfd < 0) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", outrfile, errno);
	return -1;
    }

    sprintf (outputfile, "%s/dataflow.results", dirname);
    outputfd = open (outputfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outputfd < 0) {
	fprintf (stderr, "Cannot create dataflow.results file, errno=%d\n", errno);
	return -1;
    }

    sprintf (addrsfile, "%s/merge-addrs", dirname);
    addrsfd = open (addrsfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (addrsfd < 0) {
	fprintf (stderr, "Cannot create merge-addrs file, errno=%d\n", errno);
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

    // Read inputs from DIFT engine
    rc = read_inputs (port, token_log, output_log, ts_log, merge_log,
		      mdatasize, odatasize, idatasize, adatasize);
    if (rc < 0) return rc;

#ifdef STATS
    gettimeofday(&recv_done_tv, NULL);
#endif

    plog = output_log;
    while ((u_long) plog < (u_long) output_log + odatasize) {
	plog += sizeof(struct taint_creation_info) + sizeof(uint32_t);
	buf_size = *((uint32_t *) plog);
	plog += sizeof(uint32_t);
	for (uint32_t i = 0; i < buf_size; i++) {
	    plog += sizeof(uint32_t);
	    value = *((taint_t *) plog);
	    plog += sizeof(taint_t);
	    if (value) {
		if (value < 0xe0000001) {
#ifdef STATS
		    directs++;
#endif
		    if (value < 0xc0000000 && !start_flag) {
			PUT_QVALUE (output_token,outputq);
			PUT_QVALUE (value,outputq);
			PUT_QVALUE (0,outputq);
#ifdef DEBUG
			if (DEBUG(output_token)) {
			    fprintf (debugfile, "output %x to unresolved addr %lx\n", output_token, (long) value);
			}
#endif
			    
		    } else {
			PRINT_RVALUE (output_token);
			if (start_flag) {
			    PRINT_RVALUE (value);
#ifdef DEBUG
			    if (DEBUG(output_token)) {
				fprintf (debugfile, "output %x to resolved start input %lx\n", output_token, (long) value);
			    }
#endif
			} else {
			    PRINT_RVALUE (value-0xc0000000);
#ifdef DEBUG
			    if (DEBUG(output_token)) {
				fprintf (debugfile, "output %x to resolved input %lx\n", output_token, (long) value-0xc0000000);
			    }
#endif
			}
			PRINT_RVALUE (0);
		    }
		} else {
#ifdef STATS
		    indirects++;
#endif
		    bool unresolved_vals = false, resolved_vals = false;
		    map_iter (value, output_token, unresolved_vals, resolved_vals);
		    if (unresolved_vals) PUT_QVALUE(0,outputq);
		    if (resolved_vals) PRINT_RVALUE(0);
		}
	    }
	    output_token++;
#ifdef STATS
	    values++;
#endif
 	}
    }

#ifdef STATS
    gettimeofday(&output_done_tv, NULL);
    output_merges = merges;
    merges = 0;
#endif
#ifdef DEBUG
    fprintf (debugfile, "output token is %x\n", output_token);
#endif

    if (!finish_flag) {
	// Next, build index of output addresses
	unordered_map<taint_t,taint_t> address_map;
	rc = build_address_map (address_map, ts_log, adatasize);
	if (rc < 0) return rc;

#ifdef STATS
	gettimeofday(&index_created_tv, NULL);
#endif
	
	// Now, process input queue of later epoch outputs
	while (1) {
	    GET_QVALUE(otoken, inputq);
	    if (otoken == TERM_VAL) break;
#ifdef STATS
	    atokens++;
#endif
	    bool unresolved_vals = false, resolved_vals = false;

	    GET_QVALUE(value, inputq);
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
			    PUT_QVALUE(otoken+output_token,outputq);
			    unresolved_vals = 1;
			}
#ifdef DEBUG
			if (DEBUG(otoken+output_token) || DEBUG(otoken)) {
			    fprintf (debugfile, "output %x(%x/%x) pass through value %lx\n", otoken+output_token, otoken, output_token, (long) value);
			}
#endif
			PUT_QVALUE(value,outputq);
		    }
		} else {
		    if (iter->second < 0xc0000000 && !start_flag) {
			if (iter->second) {
#ifdef STATS
			    unmodified++;
#endif
			    // Not in this epoch - so pass through to next
			    if (!unresolved_vals) {
				PUT_QVALUE(otoken+output_token,outputq);
				unresolved_vals = true;
			    }
#ifdef DEBUG
			    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
				fprintf (debugfile, "output %x to unresolved value %lx via %lx\n", otoken+output_token, (long) iter->second, (long) value);
			    }
#endif
			    PUT_QVALUE(iter->second,outputq);
			} // Else taint was cleared in this epoch
		    } else if (iter->second < 0xe0000001) {
			// Maps to input
#ifdef STATS
			aresolved++;
#endif
			if (!resolved_vals) {
			    PRINT_RVALUE(otoken+output_token);
			    resolved_vals = true;
			}
			if (start_flag) {
#ifdef DEBUG
			    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
				fprintf (debugfile, "output %x to resolved value %lx via %lx\n", otoken+output_token, (long) iter->second, (long) value);
			    }
#endif
			    PRINT_RVALUE(iter->second);
			} else {
#ifdef DEBUG
			    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
				fprintf (debugfile, "output %x to resolved value %lx via %lx\n", 
					 otoken+output_token, (long) iter->second-0xc0000000, (long) value);
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
			    fprintf (debugfile, "output %x to merge chain %lx via %lx\n", otoken+output_token, (long) iter->second, (long) value);
			}
#endif
			map_iter (iter->second, otoken+output_token, unresolved_vals, resolved_vals);
		    }
		}
		GET_QVALUE(value, inputq);
	    }
	    if (unresolved_vals) PUT_QVALUE(0,outputq);
	    if (resolved_vals) PRINT_RVALUE(0);
	}
#ifdef STATS
	gettimeofday(&address_done_tv, NULL);
#endif
    }
    if (!start_flag) PUT_QVALUE(TERM_VAL,outputq);

    flush_outrbuf ();
    close (outrfd);

    // Get number of tokens for this epoch
    if (idatasize > 0) {
	struct token* ptoken = (struct token *) &token_log[idatasize-sizeof(struct token)];
	tokens = ptoken->token_num+ptoken->size-1;
    } else {
	if (start_flag) {
	    tokens = 0;
	} else {
	    tokens = 0xc0000000;
	}
    }

    rc = write (addrsfd, &output_token, sizeof(output_token));
    if (rc != sizeof(output_token)) {
	fprintf (stderr, "Unable to write output token, rc=%ld, errno=%d\n", rc, errno);
	return rc;
    }
    rc = write (addrsfd, &tokens, sizeof(tokens));
    if (rc != sizeof(tokens)) {
	fprintf (stderr, "Unable to write input token , rc=%ld, errno=%d\n", rc, errno);
	return rc;
    }
    close(addrsfd);

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
    gettimeofday(&end_tv, NULL);

    char statsname[256];
    sprintf (statsname, "%s/stream-stats", dirname);
    statsfile = fopen (statsname, "w");
    if (statsfile == NULL) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", statsname, errno);
	return -1;
    }

    fprintf (statsfile, "Total time:              %6ld ms\n", ms_diff (end_tv, start_tv));
    fprintf (statsfile, "Receive time:            %6ld ms\n", ms_diff (recv_done_tv, start_tv));
    fprintf (statsfile, "Output processing time:  %6ld ms\n", ms_diff (output_done_tv, recv_done_tv));
    if (!finish_flag) {
	fprintf (statsfile, "Index generation time:   %6ld ms\n", ms_diff (index_created_tv, output_done_tv));
	fprintf (statsfile, "Address processing time: %6ld ms\n", ms_diff (address_done_tv, index_created_tv));
	fprintf (statsfile, "Finish time:             %6ld ms\n", ms_diff (end_tv, address_done_tv));
    } else {
	fprintf (statsfile, "Finish time:             %6ld ms\n", ms_diff (end_tv, output_done_tv));
    }
    fprintf (statsfile, "Idle                     %6lu ms\n", idle/1000);
    fprintf (statsfile, "\n");
    fprintf (statsfile, "Received %ld bytes of merge data\n", mdatasize);
    fprintf (statsfile, "Received %ld bytes of output data\n", odatasize);
    fprintf (statsfile, "Received %ld bytes of input data\n", idatasize);
    fprintf (statsfile, "Received %ld bytes of addr data\n", adatasize);
    fprintf (statsfile, "\n");
    fprintf (statsfile, "Output directs %lu indirects %lu values %lu, merges %lu\n", directs, indirects, values, output_merges);
    if (!finish_flag) {
	fprintf (statsfile, "Address tokens %lu passthrus %lu resolved %lu, indirects %lu values %lu unmodified %lu, merges %lu\n", 
		 atokens, passthrus, aresolved, aindirects, avalues, unmodified, merges);
    }
    if (!start_flag) {
	written = outputq->write_index;
	fprintf (statsfile, "Wrote %lu entries (%lu bytes)\n", written, written*sizeof(u_long)); 
    }
    fprintf (statsfile, "Unique indirects %ld\n", (long) resolved.size());
#endif

    return 0;
}

// Process one epoch for sequential forward strategy 
long seq_epoch (const char* dirname, int port)
{
    long rc;
    char* output_log, *token_log, *plog;
    taint_t *ts_log, value;
    u_long idatasize = 0, odatasize = 0, mdatasize = 0, adatasize = 0;
    uint32_t buf_size, tokens, otoken, output_token = 0;
    char outrfile[256], outputfile[256], inputfile[256], addrsfile[256];
    int outputfd, inputfd, addrsfd;

    // Set up output files
    rc = mkdir(dirname, 0755);
    if (rc < 0 && errno != EEXIST) {
	fprintf (stderr, "Cannot create output dir %s, errno=%d\n", dirname, errno);
	return rc;
    }

    sprintf (outrfile, "%s/merge-outputs-resolved", dirname);
    outrfd = open (outrfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outrfd < 0) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", outrfile, errno);
	return -1;
    }

    sprintf (outputfile, "%s/dataflow.results", dirname);
    outputfd = open (outputfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outputfd < 0) {
	fprintf (stderr, "Cannot create dataflow.results file, errno=%d\n", errno);
	return -1;
    }

    sprintf (addrsfile, "%s/merge-addrs", dirname);
    addrsfd = open (addrsfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (addrsfd < 0) {
	fprintf (stderr, "Cannot create merge-addrs file, errno=%d\n", errno);
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

    // Read inputs from DIFT engine
    rc = read_inputs (port, token_log, output_log, ts_log, merge_log,
		      mdatasize, odatasize, idatasize, adatasize);
    if (rc < 0) return rc;

#ifdef STATS
    gettimeofday(&recv_done_tv, NULL);
#endif

    unordered_set<uint32_t> live_set;
    unordered_set<uint32_t> new_live_set;

    if (!start_flag) {

	// Wait for preceding epoch to send list of live addresses
	uint32_t val;
	do {
	    GET_QVALUE(val, outputq);
	    if (val == TERM_VAL) break;
	    live_set.insert(val);
	    if (!finish_flag) new_live_set.insert(val);
	}  while (1);

#ifdef STATS
	live_set_size = live_set.size();
	gettimeofday(&live_receive_done_tv, NULL);
#endif
	// Wait on sender
	UP_QSEM (outputq);

	// Prune the merge log
	taint_entry* mptr = merge_log;
	while ((u_long) mptr < (u_long) merge_log + mdatasize) {
	    if (mptr->p1 < 0xc0000000) {
		if (live_set.count(mptr->p1) == 0) {
		    mptr->p1 = 0;
		} 
	    } else if (mptr->p1 > 0xe0000000) {
		taint_entry* pentry = &merge_log[mptr->p1-0xe0000001];
		if (pentry->p1 == 0) {
		    mptr->p1 = pentry->p2;
		} else if (pentry->p2 == 0) {
		    mptr->p1 = pentry->p1;
		}
	    }
	    if (mptr->p2 < 0xc0000000) {
		if (live_set.count(mptr->p2) == 0) {
		    mptr->p2 = 0;
		} 
	    } else if (mptr->p2 > 0xe0000000) {
		taint_entry* pentry = &merge_log[mptr->p2-0xe0000001];
		if (pentry->p1 == 0) {
		    mptr->p2 = pentry->p2;
		} else if (pentry->p2 == 0) {
		    mptr->p2 = pentry->p1;
		}
	    }
#ifdef STATS
	    if (mptr->p1 == 0 && mptr->p2 == 0) prune_cnt++;
	    else if (mptr->p1 == 0 || mptr->p2 == 0) simplify_cnt++;
#endif
	    mptr++;
	}
    }

    // Construct and send out new live set
    if (!finish_flag) {
#ifdef STATS
	gettimeofday(&new_live_start_tv, NULL);
#endif

	// Add live addresses
	taint_t* p = ts_log;
	for (uint32_t i = 0; i < adatasize/(sizeof(taint_t)*2); i++) {
	    taint_t addr = *p++;
	    taint_t val = *p++;
	    if (val == 0) {
		new_live_set.erase(addr);
#ifdef STATS
		new_live_zeros++;
#endif
	    } else if (val < 0xc0000000) {
		if (start_flag || live_set.count(val)) {
		    new_live_set.insert(addr);
#ifdef STATS
		    new_live_inputs++;
#endif
		} else {
#ifdef STATS
		    new_live_notlive++;
#endif
		}
	    } else if (val <= 0xe0000000) {
		new_live_set.insert(addr);
#ifdef STATS
		new_live_inputs++;
#endif
	    } else {
		taint_entry* pentry = &merge_log[val-0xe0000001];
		if (pentry->p1 || pentry->p2) {
		    new_live_set.insert(addr);
#ifdef STATS
		    new_live_merges++;
#endif
		} else {
		    new_live_set.erase(addr);
#ifdef STATS
		    new_live_merge_zeros++;
#endif
		}
	    }
#ifndef BUILD_64
	    // To conserve memory, only map a portion at a time since we are streaming this
	    if (i%(MAX_ADDRESS_MAP/(sizeof(taint_t)*2)) == MAX_ADDRESS_MAP/(sizeof(taint_t)*2)-1) {
		rc = munmap (ts_log, MAX_ADDRESS_MAP);
		if (rc < 0) {
		    fprintf (stderr, "Cannot unmap address chunk\n");
		}

		p = (taint_t *) mmap (ts_log, MAX_ADDRESS_MAP, PROT_READ|PROT_WRITE, MAP_SHARED, afd, (i+1)*(sizeof(taint_t)*2));
		if (p == MAP_FAILED) {
		    fprintf (stderr, "Cannot map address input chunk, errno=%d\n", errno);
		    return -1;
		}
		ts_log = p;
	    }
#endif
	}
#ifndef BUILD_64
	if (adatasize >= MAX_ADDRESS_MAP) {
	    rc = munmap (ts_log, MAX_ADDRESS_MAP);
	    if (rc < 0) {
		fprintf (stderr, "Cannot unmap last address chunk\n");
	    }
	    
	    taint_t* ts_log = (taint_t *) mmap (NULL, MAX_ADDRESS_MAP, PROT_READ|PROT_WRITE, MAP_SHARED, afd, 0);
	    if (ts_log == MAP_FAILED) {
		fprintf (stderr, "Cannot map address input chunk, errno=%d\n", errno);
		return -1;
	    }
	}
#endif

#ifdef STATS
	new_live_set_size = new_live_set.size();
	gettimeofday(&new_live_send_tv, NULL);
#endif
	for (auto iter = new_live_set.begin(); iter != new_live_set.end(); iter++) {
	    PUT_QVALUE(*iter,inputq);
	}
	PUT_QVALUE(TERM_VAL,inputq);

    }
    
    live_set.clear();
    new_live_set.clear();

#ifdef STATS
    gettimeofday(&live_done_tv, NULL);
#endif

    plog = output_log;
    while ((u_long) plog < (u_long) output_log + odatasize) {
	plog += sizeof(struct taint_creation_info) + sizeof(uint32_t);
	buf_size = *((uint32_t *) plog);
	plog += sizeof(uint32_t);
	for (uint32_t i = 0; i < buf_size; i++) {
	    plog += sizeof(uint32_t);
	    value = *((taint_t *) plog);
	    plog += sizeof(taint_t);
	    if (value) {
		if (value < 0xe0000001) {
#ifdef STATS
		    directs++;
#endif
		    if (value < 0xc0000000 && !start_flag) {
			PUT_QVALUE (output_token,outputq);
			PUT_QVALUE (value,outputq);
			PUT_QVALUE (0,outputq);
#ifdef DEBUG
			if (DEBUG(output_token)) {
			    fprintf (debugfile, "output %x to unresolved addr %lx\n", output_token, (long) value);
			}
#endif
			    
		    } else {
			PRINT_RVALUE (output_token);
			if (start_flag) {
			    PRINT_RVALUE (value);
#ifdef DEBUG
			    if (DEBUG(output_token)) {
				fprintf (debugfile, "output %x to resolved start input %lx\n", output_token, (long) value);
			    }
#endif
			} else {
			    PRINT_RVALUE (value-0xc0000000);
#ifdef DEBUG
			    if (DEBUG(output_token)) {
				fprintf (debugfile, "output %x to resolved input %lx\n", output_token, (long) value-0xc0000000);
			    }
#endif
			}
			PRINT_RVALUE (0);
		    }
		} else {
#ifdef STATS
		    indirects++;
#endif
#ifdef DEBUG
		    if (DEBUG(output_token)) {
			fprintf (debugfile, "output %x to merge log entry %lx\n", output_token, (long) value);
		    }
#endif
		    struct taint_entry* pentry = &merge_log[value-0xe0000001];
		    if (pentry->p1 || pentry->p2) {
			bool unresolved_vals = false, resolved_vals = false;
			map_iter (value, output_token, unresolved_vals, resolved_vals);
			if (unresolved_vals) PUT_QVALUE(0,outputq);
			if (resolved_vals) PRINT_RVALUE(0);
#ifdef DEBUG
		    } else if (DEBUG(output_token)) {
			fprintf (debugfile, "merge entry is zero - skip\n");
#endif
		    }
		}
	    }
	    output_token++;
#ifdef STATS
	    values++;
#endif
 	}
    }

#ifdef STATS
    gettimeofday(&output_done_tv, NULL);
    output_merges = merges;
    merges = 0;
#endif

    if (!finish_flag) {
	// Next, build index of output addresses
	unordered_map<taint_t,taint_t> address_map;
	rc = build_address_map (address_map, ts_log, adatasize);
	if (rc < 0) return rc;

#ifdef STATS
	gettimeofday(&index_created_tv, NULL);
#endif

	// Wait on sender
	DOWN_QSEM(inputq);

	// Now, process input queue of later epoch outputs
	while (1) {
	    GET_QVALUE(otoken, inputq);
	    if (otoken == TERM_VAL) break;
#ifdef STATS
	    atokens++;
#endif
	    bool unresolved_vals = false, resolved_vals = false;

	    GET_QVALUE(value, inputq);
#ifdef DEBUG
	    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
		fprintf (debugfile, "otoken %x to value %lx\n", otoken+output_token, (long) value);
	    }
#endif
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
			    PUT_QVALUE(otoken+output_token,outputq);
			    unresolved_vals = 1;
			}
#ifdef DEBUG
			if (DEBUG(otoken+output_token) || DEBUG(otoken)) {
			    fprintf (debugfile, "output %x(%x/%x) pass through value %lx\n", otoken+output_token, otoken, output_token, (long) value);
			}
#endif
			PUT_QVALUE(value,outputq);
		    }
		} else {
		    if (iter->second < 0xc0000000 && !start_flag) {
			if (iter->second) {
#ifdef STATS
			    unmodified++;
#endif
			    // Not in this epoch - so pass through to next
			    if (!unresolved_vals) {
				PUT_QVALUE(otoken+output_token,outputq);
				unresolved_vals = true;
			    }
#ifdef DEBUG
			    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
				fprintf (debugfile, "output %x to unresolved value %lx via %lx\n", otoken+output_token, (long) iter->second, (long) value);
			    }
#endif
			    PUT_QVALUE(iter->second,outputq);
			} // Else taint was cleared in this epoch
		    } else if (iter->second < 0xe0000001) {
			// Maps to input
#ifdef STATS
			aresolved++;
#endif
			if (!resolved_vals) {
			    PRINT_RVALUE(otoken+output_token);
			    resolved_vals = true;
			}
			if (start_flag) {
#ifdef DEBUG
			    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
				fprintf (debugfile, "output %x to resolved value %lx via %lx\n", otoken+output_token, (long) iter->second, (long) value);
			    }
#endif
			    PRINT_RVALUE(iter->second);
			} else {
#ifdef DEBUG
			    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
				fprintf (debugfile, "output %x to resolved value %lx via %lx\n", 
					 otoken+output_token, (long) iter->second-0xc0000000, (long) value);
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
			    fprintf (debugfile, "output %x to merge chain %lx via %lx\n", otoken+output_token, (long) iter->second, (long) value);
			}
#endif
			// This should happen a lot, so short-circuit
			struct taint_entry* pentry = &merge_log[iter->second-0xe0000001];
			if (pentry->p1 || pentry->p2) {
			    map_iter (iter->second, otoken+output_token, unresolved_vals, resolved_vals);
			}
		    }
		}
		GET_QVALUE(value, inputq);
	    }
	    if (unresolved_vals) PUT_QVALUE(0,outputq);
	    if (resolved_vals) PRINT_RVALUE(0);
	}
#ifdef STATS
	gettimeofday(&address_done_tv, NULL);
#endif
    }
    if (!start_flag) PUT_QVALUE(TERM_VAL,outputq)

    flush_outrbuf ();
    close (outrfd);

    // Get number of tokens for this epoch
    if (idatasize > 0) {
	struct token* ptoken = (struct token *) &token_log[idatasize-sizeof(struct token)];
	tokens = ptoken->token_num+ptoken->size-1;
    } else {
	if (start_flag) {
	    tokens = 0;
	} else {
	    tokens = 0xc0000000;
	}
    }

    rc = write (addrsfd, &output_token, sizeof(output_token));
    if (rc != sizeof(output_token)) {
	fprintf (stderr, "Unable to write output token, rc=%ld, errno=%d\n", rc, errno);
	return rc;
    }
    rc = write (addrsfd, &tokens, sizeof(tokens));
    if (rc != sizeof(tokens)) {
	fprintf (stderr, "Unable to write input token , rc=%ld, errno=%d\n", rc, errno);
	return rc;
    }
    close(addrsfd);

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
    gettimeofday(&end_tv, NULL);

    char statsname[256];
    sprintf (statsname, "%s/stream-stats", dirname);
    statsfile = fopen (statsname, "w");
    if (statsfile == NULL) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", statsname, errno);
	return -1;
    }

    fprintf (statsfile, "Total time:              %6ld ms\n", ms_diff (end_tv, start_tv));
    fprintf (statsfile, "Receive time:            %6ld ms\n", ms_diff (recv_done_tv, start_tv));
    if (!start_flag) {
	fprintf (statsfile, "Receive live set time:   %6ld ms\n", ms_diff (live_receive_done_tv, recv_done_tv));
	if (!finish_flag) {
	    fprintf (statsfile, "Prune live set time:     %6ld ms\n", ms_diff (new_live_start_tv, live_receive_done_tv));
	} else {
	    fprintf (statsfile, "Prune live set time:     %6ld ms\n", ms_diff (live_done_tv, live_receive_done_tv));
	}
    }
    if (!finish_flag) {
	fprintf (statsfile, "Make live set time:      %6ld ms\n", ms_diff (new_live_send_tv, new_live_start_tv));
	fprintf (statsfile, "Send live set time:      %6ld ms\n", ms_diff (live_done_tv, new_live_send_tv));
    }
    fprintf (statsfile, "Output processing time:  %6ld ms\n", ms_diff (output_done_tv, live_done_tv));
    if (!finish_flag) {
	fprintf (statsfile, "Index generation time:   %6ld ms\n", ms_diff (index_created_tv, output_done_tv));
	fprintf (statsfile, "Address processing time: %6ld ms\n", ms_diff (address_done_tv, index_created_tv));
	fprintf (statsfile, "Finish time:             %6ld ms\n", ms_diff (end_tv, address_done_tv));
    } else {
	fprintf (statsfile, "Finish time:             %6ld ms\n", ms_diff (end_tv, output_done_tv));
    }
    fprintf (statsfile, "Idle                     %6lu ms\n", idle/1000);
    fprintf (statsfile, "\n");
    fprintf (statsfile, "Received %ld bytes of merge data\n", mdatasize);
    fprintf (statsfile, "Received %ld bytes of output data\n", odatasize);
    fprintf (statsfile, "Received %ld bytes of input data\n", idatasize);
    fprintf (statsfile, "Received %ld bytes of addr data\n", adatasize);
    fprintf (statsfile, "\n");
    if (!start_flag) {
	fprintf (statsfile, "Received %ld values in live set\n", (long) live_set.size());
    }
    fprintf (statsfile, "Output directs %lu indirects %lu values %lu, merges %lu\n", directs, indirects, values, output_merges);
    if (!finish_flag) {
	fprintf (statsfile, "Pruned %ld simplified %ld unchanged %ld of %ld merge values using live set\n", 
		prune_cnt, simplify_cnt, mdatasize/sizeof(struct taint_entry)-prune_cnt-simplify_cnt,
		mdatasize/sizeof(struct taint_entry));
	fprintf (statsfile, "Address tokens %lu passthrus %lu resolved %lu, indirects %lu values %lu unmodified %lu, merges %lu\n", 
		 atokens, passthrus, aresolved, aindirects, avalues, unmodified, merges);
    }
    if (!start_flag) {
	fprintf (statsfile, "New live set has size %ld\n", (long) new_live_set.size());
	fprintf (statsfile, "zeros %lu, inputs %lu, merges %lu, merge_zeros %lu, not live %lu\n", new_live_zeros, 
		 new_live_inputs, new_live_merges, new_live_merge_zeros, new_live_notlive);
    }
    if (!start_flag) {
	written = outputq->write_index;
	fprintf (statsfile, "Wrote %lu entries (%lu bytes)\n", written, written*sizeof(u_long)); 
    }
    fprintf (statsfile, "Unique indirects %ld\n", (long) resolved.size());
#endif

    return 0;
}

int connect_output_queue (struct senddata* data) 
{
    struct sockaddr_in addr;
    struct hostent* hp;
    long rc;
    int s;

    // Establish a connection to receiving computer
    hp = gethostbyname (data->host);
    if (hp == NULL) {
	fprintf (stderr, "Invalid host %s, errno=%d\n", data->host, h_errno);
	return -1;
    }

    s = socket (AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	fprintf (stderr, "Cannot create socket, errno=%d\n", errno);
	return s;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(data->port);
    memcpy (&addr.sin_addr, hp->h_addr, hp->h_length);

    // Receiver may not be started, so spin until connection is accepted
    do {
	rc = connect (s, (struct sockaddr *) &addr, sizeof(addr));
	if (rc < 0) {
	    usleep (10000);
	}
    } while (rc < 0);

    return s;
}

int connect_input_queue (struct recvdata* data)
{
    struct sockaddr_in addr;
    long rc;
    int c, s;

    // Listen for incoming connection - should just be one so close listen socket after connection
    c = socket (AF_INET, SOCK_STREAM, 0);
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

    addr.sin_family = AF_INET;
    addr.sin_port = htons(data->port);
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
    
    s = accept (c, NULL, NULL);
    if (s < 0) {
	fprintf (stderr, "Cannot accept connection, errno=%d\n", errno);
	return s;
    }

    close (c);
    return s;
}

void send_stream (int s, struct taintq* q)
{
    // Listen on output queue and send over network
    while (1) {
	u_long can_send = 0;

	while (can_send == 0) {
	    usleep (100);
	    if (q->read_index > q->write_index) {			
		can_send = TAINTENTRIES - q->read_index;
	    } else {								
		can_send = q->write_index - q->read_index;		
	    }		
	}

	long rc = safe_write (s, q->buffer + q->read_index, can_send*sizeof(uint32_t));
	if (rc != (long)(can_send*sizeof(u_int32_t))) return; // Error sending the data

	q->read_index += can_send;
	if (q->buffer[(q->read_index-1)%TAINTENTRIES] == TERM_VAL) return; // No more data to send
    }
}

void recv_stream (int s, struct taintq* q)
{
    // Get data and put on the inputq
    while (1) {
	u_long can_recv;
	u_long partial_bytes = 0;
	if (q->write_index >= q->read_index) {			
	    can_recv = TAINTENTRIES - q->write_index;
	} else {								
	    can_recv = q->write_index - q->read_index;		
	}									
	if (can_recv) {
	    can_recv = can_recv*sizeof(u_long)-partial_bytes; // Convert to bytes
	    long rc = recv (s, q->buffer + q->write_index, can_recv, 0);
	    if (rc < 0) {
		fprintf (stderr, "recv returns %ld,errno=%d\n", rc, errno);
		break;
	    } else if (rc == 0) {
		break; // Sender closed connection
	    }
	    q->write_index += rc/sizeof(u_long);					       
	    if (rc%sizeof(u_long)) {
		partial_bytes += rc%sizeof(u_long);
		if (partial_bytes > sizeof(u_long)) {
		    q->write_index++;
		    partial_bytes -= sizeof(u_long);
		}
	    }
	    if (partial_bytes == 0 && q->buffer[(q->write_index-1)%TAINTENTRIES] == TERM_VAL) break; // Sender is done
	} else {
	    usleep(100);
	}
    }
}

// Sending to another computer is implemented as separate thread to add asyncrhony
void* send_output_queue (void* arg)
{
   struct senddata* data = (struct senddata *) arg;

   int s = connect_output_queue (data);
   if (s < 0) return NULL;

   if (data->do_sequential) {
       recv_stream (s, outputq); // First we read data from upstream
       DOWN_QSEM(outputq);
   }

   send_stream (s, outputq);
   close (s);
   return NULL;
}

void* recv_input_queue (void* arg)
{
    struct recvdata* data = (struct recvdata *) arg;

    int s = connect_input_queue (data);
    if (s < 0) return NULL;

    if (data->do_sequential) {
	send_stream (s, inputq); // First we send filters downstream	
	UP_QSEM(inputq);
    }

    recv_stream (s, inputq);
    close (s);
    return NULL;
}

void format ()
{
    fprintf (stderr, "format: stream <dir> <taint port> [-iq input_queue] [-oq output_queue] [-oh output_host] [-ih]\n");
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
    bool do_sequential = false;

    if (argc < 3) format();

    for (int i = 3; i < argc; i++) {
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
	} else if (!strcmp (argv[i], "-seq")) {
	    do_sequential = true;
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
	finish_flag = false;
    } else {
	inputq = NULL;
	finish_flag = true;
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
	start_flag = false;
    } else {
	outputq = NULL;
	start_flag = true;
    }

    if (output_host) {
	sd.host = output_host;
	sd.port = STREAM_PORT;
	sd.do_sequential = do_sequential;
	rc = pthread_create (&oh_tid, NULL, send_output_queue, &sd);
	if (rc < 0) {
	    fprintf (stderr, "Cannot create outputq thread\n");
	    return rc;
	}
    }

    if (input_host) {
	rd.port = STREAM_PORT;
	rd.do_sequential = do_sequential;
	rc = pthread_create (&ih_tid, NULL, recv_input_queue, &rd);
	if (rc < 0) {
	    fprintf (stderr, "Cannot create inputq thread\n");
	    return rc;
	}
    }

    if (do_sequential) {
	seq_epoch (argv[1], atoi(argv[2]));
    } else {
	stream_epoch (argv[1], atoi(argv[2]));
    }

    if (output_host) pthread_join(oh_tid, NULL);
    if (input_host) pthread_join(ih_tid, NULL);

    return 0;
}
