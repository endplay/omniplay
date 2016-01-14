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
#include <vector>
#include <atomic>
using namespace std;

#include "streamnw.h"
#include "../taint_interface/taint.h"
#include "../linkage_common.h"
#include "../taint_interface/taint_creation.h"
#include "../token.h"
#include "../taint_nw.h"
#include "../../test/streamserver.h"

//#define DEBUG(x) ((x)==0x5864 || (x)==0x5864-0x24a6 || (x) == 0x5864-0x24eb)
#define STATS

// Set up limits here - need to be less generate with 32-bit address space
#ifdef USE_NW
#ifdef BUILD_64
const u_long MERGE_SIZE  = 0x400000000; // 16GB max
const u_long OUTPUT_SIZE = 0x100000000; // 4GB max	//const u_long OUTPUT_SIZE = 0x800000000; // 32GB max
#else
const u_long MERGE_SIZE  = 0x10000000; // 1GB max
const u_long OUTPUT_SIZE = 0x10000000; // 1GB max
#endif
const u_long TOKEN_SIZE =   0x10000000; // 256MB max
const u_long TS_SIZE =      0x10000000; // 1GB max
const u_long OUTBUFSIZE =   0x10000000; // 1GB size
#endif

//this doesn't matter... but it won't make and I'm too lazy to actually fix it
#ifdef USE_NULL
const u_long OUTBUFSIZE =   0x2000000; // 128MB size
#endif

#ifdef USE_SHMEM 
const u_long OUTBUFSIZE =   0x2000000; // 128MB size
#ifdef BUILD_64
const u_long MAX_ADDRESS_MAP = 0; // No limit
#else
const u_long MAX_ADDRESS_MAP = 0x100000; // 16 MB
#endif
#endif



#define BUCKET_TERM_VAL 0xfffffffe // Sentinel for queue transmission
#define TERM_VAL        0xffffffff // Sentinel for queue transmission
#define QSTOP(val) (((val)&0xfffffffe)==0xfffffffe)
#define QEND(val) ((val)==TERM_VAL)


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

#define STACK_SIZE 1000000
typedef taint_t stacktype[STACK_SIZE];

// Globals - mostly here for performance/convenience
stacktype* astacks;

unordered_map<taint_t,unordered_set<uint32_t>*> resolved;
struct taint_entry* merge_log;

struct taintq_hdr*  outputq_hdr;
struct taintq_hdr*  inputq_hdr;
uint32_t*           outputq_buf;
uint32_t*           inputq_buf;
int                 oqfd = -1;
int                 iqfd = -1;

u_char              parallelize = 1;
bool                start_flag = false;
bool                finish_flag = false;

#ifdef DEBUG
FILE* debugfile;
#endif

#ifdef STATS
u_long merges = 0, directs = 0, indirects = 0, values = 0, quashed = 0, output_merges = 0;
u_long send_idle = 0, recv_idle = 0, live_set_send_idle = 0, live_set_recv_idle = 0, new_live_set_send_idle = 0, new_live_set_recv_idle = 0, output_send_idle = 0, output_recv_idle = 0;
u_long atokens = 0, passthrus = 0, aresolved = 0, aindirects = 0, unmodified = 0, written = 0;
u_long prune_cnt = 0, simplify_cnt = 0;
u_long new_live_no_changes = 0, new_live_zeros = 0, new_live_inputs = 0, new_live_merges = 0, new_live_merge_zeros = 0, new_live_notlive = 0;
u_long live_set_size = 0;
u_long values_sent = 0, values_rcvd = 0;
u_long prune_lookup = 0, prune_indirect = 0;
u_long total_address_ms = 0, longest_address_ms = 0, total_output_ms = 0, longest_output_ms = 0, total_new_live_set_ms = 0, longest_new_live_set_ms = 0, total_prune_1_ms = 0, longest_prune_1_ms = 0, total_prune_2_ms = 0;

struct timeval start_tv, recv_done_tv, finish_start_tv, end_tv;
struct timeval live_receive_start_tv = {0,0}, live_receive_end_tv = {0,0};
struct timeval prune_1_start_tv = {0,0}, prune_1_end_tv = {0,0};
struct timeval prune_2_start_tv = {0,0}, prune_2_end_tv = {0,0};
struct timeval send_wait_start_tv = {0,0}, send_wait_end_tv = {0,0};
struct timeval index_wait_start_tv = {0,0}, index_wait_end_tv = {0,0};
struct timeval output_start_tv = {0,0}, output_end_tv = {0,0};
struct timeval address_start_tv = {0,0}, address_end_tv = {0,0};
struct timeval new_live_start_tv = {0,0}, new_live_end_tv = {0,0}, live_done_tv = {0,0}, new_live_send_tv = {0,0};

static long ms_diff (struct timeval tv1, struct timeval tv2)
{
    return ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000);
}
#endif

char bucket_emptied[TAINTBUCKETS], bucket_filled[TAINTBUCKETS];
bool finished;
uint32_t next_read_index, next_write_index;

static void inline
bucket_write_init ()
{
    memset (bucket_filled, 0, sizeof(bucket_filled));
    finished = false;
    next_write_index = 0;
}

static void inline
bucket_read_init ()
{
    memset (bucket_emptied, 0, sizeof(bucket_emptied));
    next_read_index = 0;
}

static void inline 
bucket_init ()
{
    bucket_write_init();
    bucket_read_init();
}

static void inline 
bucket_push (uint32_t val, struct taintq_hdr* qh, uint32_t*& qb, int qfd, uint32_t& bucket_cnt, uint32_t& bucket_stop)
{
    if (bucket_cnt == bucket_stop) {
	// Get next bucket 
	pthread_mutex_lock(&(qh->lock));
	while ((next_write_index+1)%TAINTBUCKETS == qh->read_index) {
#ifdef STATS
	    struct timeval tv1, tv2;	       
	    gettimeofday(&tv1, NULL);	       
#endif
	    pthread_cond_wait(&(qh->full), &(qh->lock));
#ifdef STATS
	    gettimeofday(&tv2, NULL);		
	    send_idle += ms_diff (tv2,tv1);
#endif
	}
	bucket_cnt = next_write_index * TAINTBUCKETENTRIES;
	bucket_stop = bucket_cnt + TAINTBUCKETENTRIES;
	next_write_index = (next_write_index+1)%TAINTBUCKETS;
	pthread_mutex_unlock(&(qh->lock));
    } 
    qb[bucket_cnt++] = val;
    
    if (bucket_cnt == bucket_stop) {

	// This bucket is done
	pthread_mutex_lock(&(qh->lock));
	uint32_t bucket_index = (bucket_cnt-1)/TAINTBUCKETENTRIES;
	if (bucket_index == qh->write_index) {
	    // Mark this and any following emptied buckets as writable
	    qh->write_index = (qh->write_index+1)%TAINTBUCKETS;
	    while (bucket_filled[qh->write_index]) {
		bucket_filled[qh->write_index] = 0;
		qh->write_index = (qh->write_index+1)%TAINTBUCKETS;
	    }
	    pthread_cond_broadcast(&(qh->empty));
	} else {
	    bucket_filled[bucket_index] = 1;
	}
	pthread_mutex_unlock(&(qh->lock));
    }
}

// Pushes the bucket even if it is half-full - append sentinel to show this
static void inline bucket_term (struct taintq_hdr* qh, uint32_t*& qb, int qfd, uint32_t& bucket_cnt, uint32_t& bucket_stop)
{
    if (bucket_cnt == bucket_stop) return;  // Have not grabbed a bucket yet - so nothing to do
    if (bucket_cnt && QEND(qb[bucket_cnt-1])) {
	qb[bucket_stop-1] = TERM_VAL; // Mark last bucket for network processing
    }
    qb[bucket_cnt++] = BUCKET_TERM_VAL;  // Mark bucket as done
    bucket_stop = bucket_cnt;  // Force new bucket
    pthread_mutex_lock(&(qh->lock));
    uint32_t bucket_index = (bucket_cnt-1)/TAINTBUCKETENTRIES;
    if (bucket_index == qh->write_index) {
	// Mark this and any following emptied buckets as writable
	qh->write_index = (qh->write_index+1)%TAINTBUCKETS;
	while (bucket_filled[qh->write_index]) {
	    bucket_filled[qh->write_index] = 0;
	    qh->write_index = (qh->write_index+1)%TAINTBUCKETS;
	}
	pthread_cond_broadcast(&(qh->empty));
    } else {
	bucket_filled[bucket_index] = 1;
    }
    pthread_mutex_unlock(&(qh->lock));
}

static void inline 
bucket_pull (uint32_t& val, struct taintq_hdr* qh, uint32_t*& qb, int qfd, uint32_t& bucket_cnt, uint32_t& bucket_stop)
{
    do {
	if (bucket_cnt == bucket_stop) {
	    // Get next bucket 
	    pthread_mutex_lock(&(qh->lock));
	    while (qh->write_index == next_read_index && !finished) {
#ifdef STATS
		struct timeval tv1, tv2;	       
		gettimeofday(&tv1, NULL);	       
#endif
		pthread_cond_wait(&(qh->empty), &(qh->lock));
#ifdef STATS
		gettimeofday(&tv2, NULL);		
		recv_idle += ms_diff (tv2,tv1);
#endif
	    }
	    if (finished) {
		pthread_mutex_unlock(&(qh->lock));
		val = TERM_VAL;
		return;
	    }
	    bucket_cnt = next_read_index * TAINTBUCKETENTRIES;
	    bucket_stop = bucket_cnt + TAINTBUCKETENTRIES;
	    next_read_index = (next_read_index+1)%TAINTBUCKETS;
	    pthread_mutex_unlock(&(qh->lock));
	} 
	
	val = qb[bucket_cnt++];

	if (bucket_cnt == bucket_stop || QSTOP(val)) {
	    if (QEND(val)) {
		// No more data to come - let other threads know 
		pthread_mutex_lock(&(qh->lock));
		finished = true;
		pthread_cond_broadcast(&(qh->empty));
		pthread_mutex_unlock(&(qh->lock));
		return;
	    }

	    // This bucket is done
	    pthread_mutex_lock(&(qh->lock));
	    uint32_t bucket_index = (bucket_cnt-1)/TAINTBUCKETENTRIES;
	    if (bucket_index == qh->read_index) {
		// Mark this and any following emptied buckets as writable
		qh->read_index = (qh->read_index+1)%TAINTBUCKETS;
		while (bucket_emptied[qh->read_index]) {
		    bucket_emptied[qh->read_index] = 0;
		    qh->read_index = (qh->read_index+1)%TAINTBUCKETS;
		}
		pthread_cond_broadcast(&(qh->full));
	    } else {
		bucket_emptied[bucket_index] = 1;
	    }
	    pthread_mutex_unlock(&(qh->lock));
	    if (val == BUCKET_TERM_VAL) {
		bucket_stop = bucket_cnt; // Force new bucket
	    }
	}
    } while (val == BUCKET_TERM_VAL);
}

#define PUT_QVALUEB(val,q,qb,qfd,bc,bs) bucket_push (val,q,qb,qfd,bc,bs);
#define GET_QVALUEB(val,q,qb,qfd,bc,bs) bucket_pull (val,q,qb,qfd,bc,bs);

#define DOWN_QSEM(qh) sem_wait(&(qh)->epoch_sem);
#define UP_QSEM(qh) sem_post(&(qh)->epoch_sem);

/* The address map is constructed in a low-priority thread since it is not needed for a while */
struct build_map_data {
    unordered_map<taint_t,taint_t>* paddress_map;
    taint_t*                        ts_log;
    u_long                          adatasize;
};

static long
build_address_map (unordered_map<taint_t,taint_t>& address_map, taint_t* ts_log, u_long adatasize)
{
    for (uint32_t i = 0; i < adatasize/(sizeof(taint_t)*2); i++) {
	address_map[ts_log[2*i]] = ts_log[2*i+1];
    }
    return 0;
}

void*
build_address_map_entry (void* data)
{
    struct build_map_data* pbmd = (struct build_map_data *) data;
    build_address_map (*pbmd->paddress_map, pbmd->ts_log, pbmd->adatasize);
    delete pbmd;
    return NULL;
}

static pthread_t
spawn_map_thread (unordered_map<taint_t,taint_t>* paddress_map, taint_t* ts_log, u_long adatasize)
{
    pthread_t build_map_tid = 0;

    // Thread data
    build_map_data* bmd = new build_map_data;
    bmd->paddress_map = paddress_map;
    bmd->ts_log = ts_log;
    bmd->adatasize = adatasize;
    
    // Make low priority
    pthread_attr_t attr;
    pthread_attr_init (&attr);
    struct sched_param sp;
    sp.sched_priority = 19;
    if (pthread_attr_setschedparam(&attr, &sp) < 0) {
	fprintf (stderr, "pthread_attr_setschedparam failed, errno=%d\n", errno);
    }
    
    assert (pthread_create (&build_map_tid, NULL, build_address_map_entry, bmd) == 0);

    return build_map_tid;
}

int*       outrfds;
uint32_t** outptrs;
uint32_t** outstops;
uint32_t*  out_total_counts;
const u_long OUTENTRIES = 0x400000; // 16MB size
const u_long OUTBYTES = OUTENTRIES*sizeof(uint32_t);

static void 
output_init (const char* dirname)
{
    char outrfile[256];

    outrfds = new int[parallelize];
    outptrs = new uint32_t *[parallelize];
    outstops = new uint32_t *[parallelize];
    out_total_counts = new uint32_t[parallelize];

    // Open parallel output files and initalize memory
    for (int i = 0; i < parallelize; i++) {
	sprintf (outrfile, "%s/merge-outputs-resolved-%d", dirname, i);
	for (u_int i = 1; i < strlen(outrfile); i++) {
	    if (outrfile[i] == '/') outrfile[i] = '.';
	}
	outrfds[i] = shm_open (outrfile, O_CREAT | O_TRUNC | O_RDWR, 0644);
	if (outrfds[i] < 0) {
	    fprintf (stderr, "Cannot create %s, errno=%d\n", outrfile, errno);
	    assert (0);
	}
	long rc = ftruncate64 (outrfds[i], OUTBYTES);
	if (rc < 0) {
	    fprintf(stderr, "could not truncate ouput shmem %s, errno %d\n", outrfile, errno);
	    assert(0);
	}
	outptrs[i] = (uint32_t *) mmap (0, OUTBYTES, PROT_READ|PROT_WRITE, MAP_SHARED, outrfds[i], 0);
	if (outptrs[i] == MAP_FAILED) {
	    fprintf (stderr, "could not map merge buffer, errno=%d\n", errno);
	    assert (0);
	}
	outstops[i] = outptrs[i] + OUTENTRIES;
	out_total_counts[i] = 0;
    }
}

static void flush_outrbuf2(uint32_t*& outptr, uint32_t*& outstop)
{
    long rc;

    // Find out which mapping this belongs to
    int ndx = -1;
    for (int i = 0; i < parallelize; i++) {
	if (outstop == outstops[i]) {
	    ndx = i;
	    break;
	}
    }
    if (ndx < 0) {
	fprintf (stderr, "outstop is %p\n", outstop);
	for (int i = 0; i < parallelize; i++) {
	    fprintf (stderr, "outstop %d is %p\n", i, outstops[i]);
	}
	assert (0);
    }

    if (outptr == outstop) {
	if (munmap (outstops[ndx]-OUTBYTES, OUTBYTES) < 0) {
	    fprintf (stderr, "could not munmap out buffer, errno=%d\n", errno);
	    assert (0);
	}

	out_total_counts[ndx] += OUTBYTES;
	rc = ftruncate64 (outrfds[ndx], out_total_counts[ndx]+OUTBYTES);
	if (rc < 0) fprintf (stderr, "Truncation of output buffer returns %ld\n", rc);
	
	outptr = (taint_t *) mmap64 (0, OUTBYTES, PROT_READ|PROT_WRITE, MAP_SHARED, 
				     outrfds[ndx], out_total_counts[ndx]);
	if (outptr == MAP_FAILED) {
	    fprintf (stderr, "could not map dump buffer, errno=%d\n", errno);
	    assert (0);
	}
	outstop = outptr + OUTBYTES;
    } else {
	out_total_counts[ndx] += OUTBYTES - ((u_long) outstop - (u_long) outptr);
	rc = ftruncate64 (outrfds[ndx], out_total_counts[ndx]);
	if (rc < 0) fprintf (stderr, "Truncation of output buffer returns %ld\n", rc);
    }
}

static void flush_alloutbufs()
{
    for (int i = 0; i < parallelize; i++) {
	flush_outrbuf2(outptrs[i],outstops[i]);
    }
}

#define PRINT_RVALUE2(otoken,value,outptr,outstop)		\
    {								\
	if (outptr == outstop) flush_outrbuf2(outptr,outstop);	\
	*(outptr)++ = (otoken);					\
	*(outptr)++ = (value);					\
    }

static int
init_socket (int port)
{
    printf("stream: init_socket(%d)\n",port);
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
	fprintf (stderr, "recv_taint_data: buffer of %lu bytes too small, we need %lu\n", bufsize, ndx+inputsize);
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

static void
unlink_buffer (const char* prefix, const char* group_directory)
{
    char filename[256];
    snprintf(filename, 256, "/%s_shm%s", prefix, group_directory);
    for (u_int i = 1; i < strlen(filename); i++) {
	if (filename[i] == '/') filename[i] = '.';
    }

    long rc = shm_unlink (filename);
    if (rc < 0) {
	fprintf (stderr, "shm_unlink of %s failed, rc=%ld, errno=%d\n", filename, rc, errno);
    }
}

static void*
map_buffer (const char* prefix, const char* group_directory, u_long& datasize, u_long maxsize)
{
    char filename[256];
    snprintf(filename, 256, "/%s_shm%s", prefix, group_directory);
    for (u_int i = 1; i < strlen(filename); i++) {
	if (filename[i] == '/') filename[i] = '.';
    }

    int fd = shm_open(filename, O_RDWR, 0644);
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
    close (fd);
    unlink_buffer (prefix, group_directory);

    return ptr;
}

static long
setup_shmem (int port, char* group_directory)
{
    // Initialize a socket to receive a little bit of input data
    int s = init_socket (port);
    if (s < 0) {
	fprintf (stderr, "init socket reutrns %d\n", s);
	return s;
    }
    // This will be sent after processing is completed 
    int rc = safe_read (s, group_directory, 256);
    if (rc != 256) {
	fprintf (stderr, "Read of group directory failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    close (s);
    return 0;
}

static long
read_inputs (int port, char*& token_log, char*& output_log, taint_t*& ts_log, taint_entry*& merge_log,
	     u_long& mdatasize, u_long& odatasize, u_long& idatasize, u_long& adatasize)
{
    char group_directory[256];

    if (setup_shmem(port, group_directory) < 0) return -1;

    token_log = (char *) map_buffer ("tokens", group_directory, idatasize, 0);
    output_log = (char *) map_buffer ("dataflow.results", group_directory, odatasize, 0);
    ts_log = (taint_t *) map_buffer ("taint_structures", group_directory, adatasize, 0);
    merge_log = (taint_entry *) map_buffer ("node_nums", group_directory, mdatasize, 0);
    //printf ("%s: i %ld o %ld a %ld m %ld\n", group_directory, idatasize, odatasize, adatasize, mdatasize);
    return 0;
}
#endif

#ifdef STATS
static void map_iter_par (taint_t value, uint32_t output_token, taint_t* stack, uint32_t& bucket_cnt, uint32_t& bucket_stop, uint32_t*& resolvedptr, uint32_t*& resolvedstop, 
			  u_long& lvalues_sent, ulong& lmerges)
#else
static void map_iter_par (taint_t value, uint32_t output_token, taint_t* stack, uint32_t& bucket_cnt, uint32_t& bucket_stop, uint32_t*& resolvedptr, uint32_t*& resolvedstop)
#endif
{
    unordered_set<uint32_t> pset;
    unordered_set<taint_t> seen_indices;
    struct taint_entry* pentry;
    uint32_t stack_depth = 0;
	
#ifdef STATS
    merges++;
#endif

    pentry = &merge_log[value-0xe0000001];
    // printf ("%llx -> %llx,%llx (%u)\n", value, pentry->p1, pentry->p2, stack_depth);
    stack[stack_depth++] = pentry->p1;
    stack[stack_depth++] = pentry->p2;
    
    do {
	value = stack[--stack_depth];
	assert (stack_depth < STACK_SIZE);
	
	if (value <= 0xe0000000) {
	    pset.insert(value);
	} else {
	    if (seen_indices.insert(value).second) {
		pentry = &merge_log[value-0xe0000001];
#ifdef STATS
		lmerges++;
#endif
		stack[stack_depth++] = pentry->p1;
		stack[stack_depth++] = pentry->p2;
	    }
	}
    } while (stack_depth);

    pset.erase(0);
    for (auto iter2 = pset.begin(); iter2 != pset.end(); iter2++) {

	if (*iter2 < 0xc0000000 && !start_flag) {
	    PUT_QVALUEB (output_token,outputq_hdr,outputq_buf,oqfd, bucket_cnt, bucket_stop);
	    PUT_QVALUEB (*iter2,outputq_hdr,outputq_buf,oqfd,bucket_cnt, bucket_stop);
#ifdef STATS
	    lvalues_sent += 2;
#endif
#ifdef DEBUG
	    if (DEBUG(output_token)) {
		fprintf (debugfile, "output %x to unresolved value %x (merge)\n", output_token, *iter2);
	    }
#endif
	} else {
	    if (start_flag) {
		PRINT_RVALUE2 (output_token,*iter2,resolvedptr,resolvedstop);
#ifdef DEBUG
		if (DEBUG(output_token)) {
		    fprintf (debugfile, "output %x to resolved start input %x (merge)\n", output_token, *iter2);
		}
#endif
	    } else {
		PRINT_RVALUE2 (output_token,*iter2-0xc0000000,resolvedptr,resolvedstop);
#ifdef DEBUG
		if (DEBUG(output_token)) {
		    fprintf (debugfile, "output %x to resolved input %x (merge)\n", output_token,*iter2-0xc0000000);
		}
#endif
	    }
	}
    }
}

long setup_aggregation (const char* dirname, int& outputfd, int& inputfd, int& addrsfd)
{
    char outputfile[256], inputfile[256], addrsfile[256];
    
    astacks = new stacktype[parallelize];

    long rc = mkdir(dirname, 0755);
    if (rc < 0 && errno != EEXIST) {
	fprintf (stderr, "Cannot create output dir %s, errno=%d\n", dirname, errno);
	return rc;
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

    return 0;
}

struct output_par_data {
    pthread_t                tid;
    uint32_t                 output_token;
    char*                    plog;
    char*                    outstop;
    unordered_set<uint32_t>* plive_set;
    stacktype*               stack;
    uint32_t**               resolvedptr;
    uint32_t**               resolvedstop;
#ifdef STATS
    u_long                   ldirects;
    u_long                   lvalues_sent;
    u_long                   lquashed;
    u_long                   lindirects;
    u_long                   lvalues;
    u_long                   lmerges;
    struct timeval           tv_start;
    struct timeval           tv_end;
#endif
};

static void*
do_outputs_seq (void* pdata) 
{
    // Unpack arguments
    struct output_par_data* opdata = (struct output_par_data *) pdata;
    uint32_t  output_token = opdata->output_token;
    char*     plog = opdata->plog;
    char*     outstop = opdata->outstop;
    unordered_set<uint32_t>* plive_set = opdata->plive_set;
    stacktype* stack = opdata->stack;
    uint32_t*& resolvedptr = *opdata->resolvedptr;
    uint32_t*& resolvedstop = *opdata->resolvedstop;

    uint32_t wbucket_cnt = 0, wbucket_stop = 0;
#ifdef STATS
    u_long ldirects = 0, lvalues_sent = 0, lquashed = 0, lindirects = 0, lvalues = 0, lmerges = 0;
    gettimeofday(&opdata->tv_start, NULL);
#endif

    while (plog < outstop) {
	plog += sizeof(struct taint_creation_info) + sizeof(uint32_t);
	uint32_t buf_size = *((uint32_t *) plog);
	plog += sizeof(uint32_t);
	for (uint32_t i = 0; i < buf_size; i++) {
	    plog += sizeof(uint32_t);
	    taint_t value = *((taint_t *) plog);
	    plog += sizeof(taint_t);
	    if (value) {
		if (value < 0xe0000001) {
#ifdef STATS
		    ldirects++;
#endif
		    if (value < 0xc0000000 && !start_flag) {
			if (plive_set->count(value)) {
			    PUT_QVALUEB (output_token,outputq_hdr,outputq_buf,oqfd,wbucket_cnt, wbucket_stop);
			    PUT_QVALUEB (value,outputq_hdr,outputq_buf,oqfd, wbucket_cnt, wbucket_stop);
#ifdef STATS
			    lvalues_sent += 2;
#endif
#ifdef DEBUG
			    if (DEBUG(output_token)) {
				fprintf (debugfile, "output %x to unresolved addr %lx\n", output_token, (long) value);
			    }
#endif
#ifdef STATS
			} else {
			    lquashed++;
#endif
			}
		    } else {
			if (start_flag) {
			    PRINT_RVALUE2 (output_token,value,resolvedptr,resolvedstop);
#ifdef DEBUG
			    if (DEBUG(output_token)) {
				fprintf (debugfile, "output %x to resolved start input %lx\n", output_token, (long) value);
			    }
#endif
			} else {
			    PRINT_RVALUE2 (output_token,value-0xc0000000,resolvedptr,resolvedstop);
#ifdef DEBUG
			    if (DEBUG(output_token)) {
				fprintf (debugfile, "output %x to resolved input %lx\n", output_token, (long) value-0xc0000000);
			    }
#endif
			}
		    }
		} else {
#ifdef STATS
		    lindirects++;
#endif
#ifdef DEBUG
		    if (DEBUG(output_token)) {
			fprintf (debugfile, "output %x to merge log entry %lx\n", output_token, (long) value);
		    }
#endif
		    struct taint_entry* pentry = &merge_log[value-0xe0000001];
		    if (pentry->p1 || pentry->p2) {
#ifdef STATS
			map_iter_par (value, output_token, *stack, wbucket_cnt, wbucket_stop, resolvedptr, resolvedstop, lvalues_sent, lmerges);
#else
			map_iter_par (value, output_token, *stack, wbucket_cnt, wbucket_stop, resolvedptr, resolvedstop);
#endif
#ifdef DEBUG
		    } else if (DEBUG(output_token)) {
			fprintf (debugfile, "merge entry is zero - skip\n");
#endif
		    }
		}
	    }
	    output_token++;
#ifdef STATS
	    lvalues++;
#endif
 	}
    }

    opdata->output_token = output_token;

    // Flush out last addresses
    bucket_term(outputq_hdr,outputq_buf,oqfd,wbucket_cnt,wbucket_stop);

#ifdef STATS
    gettimeofday(&opdata->tv_end, NULL);
    opdata->ldirects = ldirects;
    opdata->lvalues_sent = lvalues_sent;
    opdata->lquashed = lquashed;
    opdata->lindirects = lindirects;
    opdata->lvalues = lvalues;
    opdata->lmerges = lmerges;
#endif

    return NULL;
}

static void*
do_outputs_stream (void* pdata) 
{
    // Unpack arguments
    struct output_par_data* opdata = (struct output_par_data *) pdata;
    uint32_t  output_token = opdata->output_token;
    char*     plog = opdata->plog;
    char*     outstop = opdata->outstop;
    stacktype* stack = opdata->stack;
    uint32_t*& resolvedptr = *opdata->resolvedptr;
    uint32_t*& resolvedstop = *opdata->resolvedstop;

    uint32_t wbucket_cnt = 0, wbucket_stop = 0;
#ifdef STATS
    u_long ldirects = 0, lvalues_sent = 0, lquashed = 0, lindirects = 0, lvalues = 0, lmerges = 0;
    gettimeofday(&opdata->tv_start, NULL);
#endif

    while (plog < outstop) {
	plog += sizeof(struct taint_creation_info) + sizeof(uint32_t);
	uint32_t buf_size = *((uint32_t *) plog);
	plog += sizeof(uint32_t);
	for (uint32_t i = 0; i < buf_size; i++) {
	    plog += sizeof(uint32_t);
	    taint_t value = *((taint_t *) plog);
	    plog += sizeof(taint_t);
	    if (value) {
		if (value < 0xe0000001) {
#ifdef STATS
		    ldirects++;
#endif
		    if (value < 0xc0000000 && !start_flag) {
			PUT_QVALUEB (output_token,outputq_hdr,outputq_buf,oqfd,wbucket_cnt, wbucket_stop);
			PUT_QVALUEB (value,outputq_hdr,outputq_buf,oqfd, wbucket_cnt, wbucket_stop);
#ifdef STATS
			lvalues_sent += 2;
#endif
#ifdef DEBUG
			if (DEBUG(output_token)) {
			    fprintf (debugfile, "output %x to unresolved addr %lx\n", output_token, (long) value);
			}
#endif
		    } else {
			if (start_flag) {
			    PRINT_RVALUE2 (output_token,value,resolvedptr,resolvedstop);
#ifdef DEBUG
			    if (DEBUG(output_token)) {
				fprintf (debugfile, "output %x to resolved start input %lx\n", output_token, (long) value);
			    }
#endif
			} else {
			    PRINT_RVALUE2 (output_token,value-0xc0000000,resolvedptr,resolvedstop);
#ifdef DEBUG
			    if (DEBUG(output_token)) {
				fprintf (debugfile, "output %x to resolved input %lx\n", output_token, (long) value-0xc0000000);
			    }
#endif
			}
		    }
		} else {
#ifdef STATS
		    lindirects++;
#endif
#ifdef DEBUG
		    if (DEBUG(output_token)) {
			fprintf (debugfile, "output %x to merge log entry %lx\n", output_token, (long) value);
		    }
#endif
		    struct taint_entry* pentry = &merge_log[value-0xe0000001];
		    if (pentry->p1 || pentry->p2) {
#ifdef STATS
			map_iter_par (value, output_token, *stack, wbucket_cnt, wbucket_stop, resolvedptr, resolvedstop, lvalues_sent, lmerges);
#else
			map_iter_par (value, output_token, *stack, wbucket_cnt, wbucket_stop, resolvedptr, resolvedstop);
#endif
#ifdef DEBUG
		    } else if (DEBUG(output_token)) {
			fprintf (debugfile, "merge entry is zero - skip\n");
#endif
		    }
		}
	    }
	    output_token++;
#ifdef STATS
	    lvalues++;
#endif
 	}
    }

    opdata->output_token = output_token;

    // Flush out last addresses
    bucket_term(outputq_hdr,outputq_buf,oqfd,wbucket_cnt,wbucket_stop);

#ifdef STATS
    gettimeofday(&opdata->tv_end, NULL);
    opdata->ldirects = ldirects;
    opdata->lvalues_sent = lvalues_sent;
    opdata->lquashed = lquashed;
    opdata->lindirects = lindirects;
    opdata->lvalues = lvalues;
    opdata->lmerges = lmerges;
#endif

    return NULL;
}

static uint32_t
process_outputs (char* plog, char* outstop, unordered_set<uint32_t>* plive_set, const char* dirname, void *(*do_outputs)(void *))
{
    struct output_par_data output_data[parallelize];
    uint32_t output_tokens = 0, last_output_tokens = 0;
    int ocnt = 0;

#ifdef STATS
    gettimeofday(&output_start_tv, NULL);
    send_idle = recv_idle = 0;
    merges = 0;
#endif

    output_init(dirname);

    if (plog != outstop) {

	// For the moment, we have to ge the correct output token value to start each epoch - I think
	// this info could be embedded in the file by the DIFT server with little cost
	char* p = plog;
	char* last = p;
	for (int i = 0; i < parallelize; i++) {
	    char* goal;
	    if (i == parallelize-1) {
		goal = outstop;
	    } else {
		goal = plog + (((u_long) outstop - (u_long) plog) * (i+1) / parallelize);
	    }
	    while (p < goal) {
		p += sizeof(struct taint_creation_info) + sizeof(uint32_t);
		uint32_t buf_size = *((uint32_t *) p);
		p += sizeof(uint32_t) + buf_size*(sizeof(uint32_t)+sizeof(taint_t));
		output_tokens += buf_size;
	    }
	    if (p > last) {
		output_data[ocnt].output_token = last_output_tokens;
		output_data[ocnt].plog = last;
		output_data[ocnt].outstop = p;
		output_data[ocnt].plive_set = plive_set;
		output_data[ocnt].stack = &astacks[ocnt];
		output_data[ocnt].resolvedptr = &outptrs[ocnt];
		output_data[ocnt].resolvedstop = &outstops[ocnt];
		ocnt++;
		last = p;
		last_output_tokens = output_tokens;
	    }
	}
	
	for (int i = 0; i < ocnt-1; i++) {
	    long rc = pthread_create (&output_data[i].tid, NULL, do_outputs, &output_data[i]);
	    if (rc < 0) {
		fprintf (stderr, "Cannot create output thread, rc=%ld\n", rc);
		assert (0);
	    }
	}
	
	(*do_outputs)(&output_data[ocnt-1]);
	
	for (int i = 0; i < ocnt-1; i++) {
	    long rc = pthread_join(output_data[i].tid, NULL);
	    if (rc < 0) fprintf (stderr, "Cannot join output thread, rc=%ld\n", rc); 
	}
    }

#ifdef STATS
    gettimeofday(&output_end_tv, NULL);
    output_merges = merges;
    output_send_idle = send_idle;
    output_recv_idle = recv_idle;
    for (int i = 0; i < ocnt; i++) {
	directs += output_data[i].ldirects;
	values_sent += output_data[i].lvalues_sent;
	quashed += output_data[i].lquashed;
	indirects += output_data[i].lindirects;
	values += output_data[i].lvalues;
	merges += output_data[i].lmerges;
	u_long ms = ms_diff(output_data[i].tv_end, output_data[i].tv_start);
	total_output_ms += ms;
	if (ms > longest_output_ms) longest_output_ms = ms;
    }
#endif
    
    return output_tokens;
}

struct address_par_data {
    pthread_t                       tid;
    uint32_t                        output_token;
    unordered_map<taint_t,taint_t>* paddress_map;
    stacktype*                      stack;
    uint32_t**                      resolvedptr;
    uint32_t**                      resolvedstop;
#ifdef STATS
    u_long                          lvalues_rcvd;
    u_long                          latokens;
    u_long                          lpassthrus;
    u_long                          lvalues_sent;
    u_long                          lunmodified;
    u_long                          laresolved;
    u_long                          laindirects;
    u_long                          lmerges;
    struct timeval                  tv_start;
    struct timeval                  tv_end;
#endif
};

static void* 
do_addresses (void* pdata)
{
    uint32_t otoken, value;
    uint32_t rbucket_cnt = 0, rbucket_stop = 0, wbucket_cnt = 0, wbucket_stop = 0;
    
    // Unpack arguments
    struct address_par_data* apdata = (struct address_par_data *) pdata;
    uint32_t  output_token = apdata->output_token;
    unordered_map<taint_t,taint_t>* paddress_map = apdata->paddress_map;
    stacktype* stack = apdata->stack;
    uint32_t*& resolvedptr = *apdata->resolvedptr;
    uint32_t*& resolvedstop = *apdata->resolvedstop;

#ifdef STATS
    u_long lvalues_rcvd = 0, latokens = 0, lpassthrus = 0, lvalues_sent = 0, lunmodified = 0, laresolved = 0, laindirects = 0, lmerges = 0;
    gettimeofday(&apdata->tv_start, NULL);
#endif

    // Now, process input queue of later epoch outputs
    while (1) {
	GET_QVALUEB(otoken, inputq_hdr, inputq_buf, iqfd, rbucket_cnt, rbucket_stop);
	if (otoken == TERM_VAL) break;
	GET_QVALUEB(value, inputq_hdr, inputq_buf, iqfd, rbucket_cnt, rbucket_stop);
#ifdef STATS
	latokens++;
	lvalues_rcvd += 2;
#endif
#ifdef DEBUG
	if (DEBUG(otoken+output_token)||DEBUG(otoken)||DEBUG(value)) {
	    fprintf (debugfile, "otoken %x(%x/%x) to value %lx\n", otoken+output_token, otoken, output_token, (long) value);
	}
#endif
	auto iter = paddress_map->find(value);
	if (iter == paddress_map->end()) {
#ifdef DEBUG
	    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
		fprintf (debugfile, "otoken %x(%x/%x) not found in map\n", otoken+output_token, otoken, output_token);
	    }
#endif
	    if (!start_flag) {
#ifdef STATS
		lpassthrus++;
#endif
		// Not in this epoch - so pass through to next
		PUT_QVALUEB(otoken+output_token,outputq_hdr,outputq_buf,oqfd,wbucket_cnt,wbucket_stop);
		PUT_QVALUEB(value,outputq_hdr,outputq_buf,oqfd,wbucket_cnt,wbucket_stop);
#ifdef STATS
		lvalues_sent += 2;
#endif
#ifdef DEBUG
		if (DEBUG(otoken+output_token) || DEBUG(otoken)) {
		    fprintf (debugfile, "output %x(%x/%x) pass through value %lx\n", otoken+output_token, otoken, output_token, 
			     (long) value);
		}
#endif
	    }
	} else {
#ifdef DEBUG
	    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
		fprintf (debugfile, "otoken %x(%x/%x) found in map: %x\n", otoken+output_token, otoken, output_token,
			 iter->second);
	    }
#endif
	    if (iter->second < 0xc0000000 && !start_flag) {
		if (iter->second) {
#ifdef STATS
		    lunmodified++;
#endif
		    // Not in this epoch - so pass through to next
		    PUT_QVALUEB(otoken+output_token,outputq_hdr,outputq_buf,oqfd,wbucket_cnt,wbucket_stop);
		    PUT_QVALUEB(iter->second,outputq_hdr,outputq_buf,oqfd,wbucket_cnt,wbucket_stop);
#ifdef STATS
		    lvalues_sent += 2;
#endif
#ifdef DEBUG
		    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
			fprintf (debugfile, "output %x to unresolved value %lx via %lx\n", otoken+output_token, (long) iter->second, (long) value);
		    }
#endif
#ifdef PARANOID
		} else {
		    fprintf (stderr, "value to cleared value\n");
#endif
		}
	    } else if (iter->second < 0xe0000001) {
		// Maps to input
#ifdef STATS
		laresolved++;
#endif
		if (start_flag) {
#ifdef DEBUG
		    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
			fprintf (debugfile, "output %x to resolved value %lx via %lx\n", otoken+output_token, (long) iter->second, (long) value);
		    }
#endif
		    PRINT_RVALUE2(otoken+output_token,iter->second,resolvedptr,resolvedstop);
		} else {
#ifdef DEBUG
		    if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
			fprintf (debugfile, "output %x to resolved value %lx via %lx\n", 
				 otoken+output_token, (long) iter->second-0xc0000000, (long) value);
		    }
#endif
		    PRINT_RVALUE2(otoken+output_token,iter->second-0xc0000000,resolvedptr,resolvedstop);
		}
	    } else {
		// Maps to merge
#ifdef STATS
		laindirects++;
#endif
#ifdef DEBUG
		if (DEBUG(otoken+output_token)||DEBUG(otoken)) {
		    fprintf (debugfile, "output %x to merge chain %lx via %lx\n", otoken+output_token, (long) iter->second, (long) value);
		}
#endif
#ifdef PARANOID
		struct taint_entry* pentry = &merge_log[iter->second-0xe0000001];
		if (pentry->p1 == 0 && pentry->p2 == 0) {
		    fprintf (stderr, "NULL merge entry\n");
		}
#endif
#ifdef STATS
		map_iter_par (iter->second, otoken+output_token, *stack, wbucket_cnt, wbucket_stop, resolvedptr, resolvedstop, lvalues_sent, lmerges);
#else
		map_iter_par (iter->second, otoken+output_token, *stack, wbucket_cnt, wbucket_stop, resolvedptr, resolvedstop);
#endif
	    }
	}
    }
    
    bucket_term(outputq_hdr,outputq_buf,oqfd,wbucket_cnt,wbucket_stop); // Flush partial bucket
    flush_outrbuf2 (resolvedptr, resolvedstop); // Finish file for this thread

#ifdef STATS
    gettimeofday(&apdata->tv_end, NULL);
    apdata->lvalues_rcvd = lvalues_rcvd;
    apdata->latokens = latokens;
    apdata->lpassthrus = lpassthrus;
    apdata->lvalues_sent = lvalues_sent;
    apdata->lunmodified = lunmodified;
    apdata->laresolved = laresolved;
    apdata->laindirects = laindirects;
    apdata->lmerges = lmerges;
#endif
    return NULL;
}

void process_addresses (uint32_t output_token, unordered_map<taint_t,taint_t>& address_map)
{
    struct address_par_data address_data[parallelize];
    int i;

#ifdef STATS
    gettimeofday(&address_start_tv, NULL);
    send_idle = recv_idle = 0;
    merges = 0;
#endif

    for (i = 0; i < parallelize-1; i++) {
	address_data[i].output_token = output_token;
	address_data[i].paddress_map = &address_map;
	address_data[i].stack = &astacks[i];
	address_data[i].resolvedptr = &outptrs[i];
	address_data[i].resolvedstop = &outstops[i];
	long rc = pthread_create (&address_data[i].tid, NULL, do_addresses, &address_data[i]);
	if (rc < 0) {
	    fprintf (stderr, "Cannot create address thread, rc=%ld\n", rc);
	    assert (0);
	}
    }

    address_data[i].output_token = output_token;
    address_data[i].paddress_map = &address_map;
    address_data[i].stack = &astacks[i];
    address_data[i].resolvedptr = &outptrs[i];
    address_data[i].resolvedstop = &outstops[i];
    do_addresses (&address_data[i]);

    for (i = 0; i < parallelize-1; i++) {
	long rc = pthread_join(address_data[i].tid, NULL);
	if (rc < 0) fprintf (stderr, "Cannot join address thread, rc=%ld\n", rc); 
    }

    if (!start_flag) {
	// Put end-of-data sentinel in queue
	uint32_t wbucket_cnt = 0, wbucket_stop = 0;
	PUT_QVALUEB(TERM_VAL,outputq_hdr,outputq_buf,oqfd,wbucket_cnt,wbucket_stop);
	bucket_term(outputq_hdr,outputq_buf,oqfd,wbucket_cnt,wbucket_stop);
    }
#ifdef STATS
    gettimeofday(&address_end_tv, NULL);
    for (i = 0; i < parallelize; i++) {
	values_rcvd += address_data[i].lvalues_rcvd;
	atokens += address_data[i].latokens;
	passthrus += address_data[i].lpassthrus;
	values_sent += address_data[i].lvalues_sent;
	unmodified += address_data[i].lunmodified;
	aresolved += address_data[i].laresolved;
	aindirects += address_data[i].laindirects;
	merges += address_data[i].lmerges;
	u_long ms = ms_diff(address_data[i].tv_end, address_data[i].tv_start);
	total_address_ms += ms;
	if (ms > longest_address_ms) longest_address_ms = ms;
    }
#endif
}

#ifdef STATS
static void
print_stats (const char* dirname, u_long mdatasize, u_long odatasize, u_long idatasize, u_long adatasize)
{
    char statsname[256];
    sprintf (statsname, "%s/stream-stats", dirname);

    FILE* statsfile = fopen (statsname, "w");
    if (statsfile == NULL) {
	fprintf (stderr, "Cannot create %s, errno=%d\n", statsname, errno);
	return;
    }

    fprintf (statsfile, "Total time:              %6ld ms\n", ms_diff (end_tv, start_tv));
    fprintf (statsfile, "Receive time:            %6ld ms\n", ms_diff (recv_done_tv, start_tv));
    fprintf (statsfile, "Receive live set time:   %6ld ms\n", ms_diff (live_receive_end_tv, live_receive_start_tv));
    fprintf (statsfile, "Prune live set time:     %6ld ms\n", ms_diff (prune_2_end_tv, prune_1_start_tv));
    fprintf (statsfile, "Make live set time:      %6ld ms\n", ms_diff (new_live_end_tv, new_live_start_tv));
    fprintf (statsfile, "Send live set wait time: %6ld ms\n", ms_diff (send_wait_end_tv, send_wait_start_tv));
    fprintf (statsfile, "Output processing time:  %6ld ms\n", ms_diff (output_end_tv, output_start_tv));
    fprintf (statsfile, "Index wait time:         %6ld ms\n", ms_diff (index_wait_end_tv, index_wait_start_tv));
    fprintf (statsfile, "Address processing time: %6ld ms\n", ms_diff (address_end_tv, address_start_tv));
    fprintf (statsfile, "Finish time:             %6ld ms\n", ms_diff (end_tv, finish_start_tv));

    fprintf (statsfile, "Total prune pass 1 time: %6ld ms longest thread %ld ms\n", total_prune_1_ms, longest_prune_1_ms);
    fprintf (statsfile, "Total prune pass 2 time: %6ld ms\n", total_prune_2_ms);
    fprintf (statsfile, "\n");

    fprintf (statsfile, "Total live set make time %ld ms longest thread %ld ms, send idle %ld recv idle %ld comp time %ld\n", 
	     total_new_live_set_ms, longest_new_live_set_ms, live_set_send_idle, live_set_recv_idle, 
	     total_new_live_set_ms - live_set_send_idle - live_set_recv_idle);
    fprintf (statsfile, "Total output time %ld ms longest thread %ld ms, send idle %ld recv idle %ld comp time %ld\n", 
	     total_output_ms, longest_output_ms, output_send_idle, output_recv_idle, total_output_ms - output_send_idle - output_recv_idle);
    fprintf (statsfile, "Total address time %ld ms longest thread %ld ms, send idle %ld recv idle %ld comp time %ld\n", 
	     total_address_ms, longest_address_ms, send_idle, recv_idle, total_address_ms - send_idle - recv_idle);
    fprintf (statsfile, "\n");

    fprintf (statsfile, "Received %ld bytes of merge data\n", mdatasize);
    fprintf (statsfile, "Received %ld bytes of output data\n", odatasize);
    fprintf (statsfile, "Received %ld bytes of input data\n", idatasize);
    fprintf (statsfile, "Received %ld bytes of addr data\n", adatasize);
    fprintf (statsfile, "\n");

    fprintf (statsfile, "Received %ld values in live set\n", (long) live_set_size);
    fprintf (statsfile, "Output directs %lu indirects %lu values %lu quashed %lu merges %lu\n", directs, indirects, values, quashed, output_merges);
    fprintf (statsfile, "Prune lookups %ld indirects %ld\n", prune_lookup, prune_indirect);
    fprintf (statsfile, "Pruned %ld simplified %ld unchanged %ld of %ld merge values using live set\n", 
	     prune_cnt, simplify_cnt, mdatasize/sizeof(struct taint_entry)-prune_cnt-simplify_cnt,
	     mdatasize/sizeof(struct taint_entry));
    fprintf (statsfile, "Address tokens %lu passthrus %lu resolved %lu, indirects %lu unmodified %lu, merges %lu\n", 
	     atokens, passthrus, aresolved, aindirects, unmodified, merges);
    fprintf (statsfile, "no changes %lu, zeros %lu, inputs %lu, merges %lu, merge_zeros %lu, not live %lu\n", 
	     new_live_no_changes, new_live_zeros, 
	     new_live_inputs, new_live_merges, new_live_merge_zeros, new_live_notlive);
    fprintf (statsfile, "Unique indirects %ld\n", (long) resolved.size());
    fprintf (statsfile, "Values rcvd %lu sent %lu\n", values_rcvd, values_sent);

    fclose (statsfile);
}
#endif

// Process one epoch 
long stream_epoch (const char* dirname, int port)
{
    long rc;
    char* output_log, *token_log;
    taint_t *ts_log;
    u_long idatasize = 0, odatasize = 0, mdatasize = 0, adatasize = 0;
    uint32_t buf_size, tokens, output_token = 0;
    int outputfd, inputfd, addrsfd;
    unordered_map<taint_t,taint_t> address_map;
    pthread_t build_map_tid = 0;

    rc = setup_aggregation (dirname, outputfd, inputfd, addrsfd);
    if (rc < 0) return rc;

    // Read inputs from DIFT engine
    rc = read_inputs (port, token_log, output_log, ts_log, merge_log,
		      mdatasize, odatasize, idatasize, adatasize);
    if (rc < 0) return rc;

#ifdef STATS
    gettimeofday(&recv_done_tv, NULL);
#endif

    if (!finish_flag) build_map_tid = spawn_map_thread (&address_map, ts_log, adatasize);

    bucket_init();
    output_token = process_outputs (output_log, output_log + odatasize, NULL, dirname, do_outputs_stream);

#ifdef DEBUG
    fprintf (debugfile, "output token is %x\n", output_token);
#endif

    if (!finish_flag) {

#ifdef STATS
	gettimeofday(&index_wait_start_tv, NULL);
#endif

	rc = pthread_join(build_map_tid, NULL);
	if (rc < 0) return rc;

#ifdef STATS
	gettimeofday(&index_wait_end_tv, NULL);
#endif
	
	process_addresses (output_token, address_map);

    } else if (!start_flag) {
	uint32_t write_cnt = 0, write_stop = 0;
	PUT_QVALUEB(TERM_VAL,outputq_hdr,outputq_buf,oqfd, write_cnt, write_stop);
	bucket_term (outputq_hdr,outputq_buf,oqfd, write_cnt, write_stop);
	flush_alloutbufs();
    } else {
	flush_alloutbufs();
    }

#ifdef STATS
    gettimeofday(&finish_start_tv, NULL);
#endif

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
    gettimeofday (&end_tv, NULL);
    print_stats (dirname, mdatasize, odatasize, idatasize, adatasize);

#endif

    return 0;
}

// This does live set lookups for a range of the merge log (this part is embarassingly parallel)
struct prune_pass_1 {
    pthread_t                tid;
    taint_entry*             mptr; 
    taint_entry*             mend; 
    unordered_set<uint32_t>* live_set;
#ifdef STATS
  struct timeval             start_tv;
  struct timeval             end_tv;
#endif
};

static void* 
prune_range_pass_1 (void* data)
{
    prune_pass_1* pp1 = (prune_pass_1 *) data;
    taint_entry* mptr = pp1->mptr;
    taint_entry* mend = pp1->mend;
    unordered_set<uint32_t>* live_set = pp1->live_set;

#ifdef STATS
    gettimeofday(&pp1->start_tv, NULL);
#endif
    while (mptr < mend) {
	if (mptr->p1 < 0xc0000000) {
	    if (live_set->count(mptr->p1) == 0) {
		mptr->p1 = 0;
	    } 
	}
	if (mptr->p2 < 0xc0000000) {
	    if (live_set->count(mptr->p2) == 0) {
		mptr->p2 = 0;
	    } 
	}
	mptr++;
    }
#ifdef STATS
    gettimeofday(&pp1->end_tv, NULL);
#endif

    return NULL;
}

// This is for the first pass or non-parallel version
static void 
prune_range_pass_both (taint_entry* mptr, taint_entry* mend, unordered_set<uint32_t>& live_set)
{
    while (mptr < mend) {
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

static void 
prune_merge_log (u_long mdatasize, unordered_set<uint32_t>& live_set) 
{
    u_long entries = mdatasize/sizeof(taint_entry);
    u_long incr = entries/parallelize;
    struct prune_pass_1 pp[parallelize];

#ifdef STATS
    gettimeofday(&prune_1_start_tv, NULL);
#endif

    for (int i = 0; i < parallelize; i++) {
	if (i == 0) {
	    pp[i].mptr = merge_log;
	} else {
	    pp[i].mptr = pp[i-1].mend;
	}
	if (i == parallelize-1) {
	    pp[i].mend = merge_log + entries;
	} else {
	    pp[i].mend = pp[i].mptr + incr;
	}
	pp[i].live_set = &live_set;
	if (i > 0) {	
	    long rc = pthread_create (&pp[i].tid, NULL, prune_range_pass_1, &pp[i]);
	    if (rc < 0) {
		fprintf (stderr, "Cannot create prune thread, rc=%ld\n", rc);
		assert (0);
	    }
	}
    }

    prune_range_pass_both(pp[0].mptr, pp[0].mend, live_set);

#ifdef STATS
    gettimeofday(&prune_1_end_tv, NULL);
    u_long ms = ms_diff(prune_1_end_tv, prune_1_start_tv);
    total_prune_1_ms = longest_prune_1_ms = ms;
#endif

    for (int i = 1; i < parallelize; i++) {
	long rc = pthread_join(pp[i].tid, NULL);
	if (rc < 0) fprintf (stderr, "Cannot join prune thread, rc=%ld\n", rc); 
#ifdef STATS
	u_long ms = ms_diff(pp[i].end_tv, pp[i].start_tv);
	total_prune_1_ms += ms;
	if (ms > longest_prune_1_ms) longest_prune_1_ms = ms;
	gettimeofday(&prune_2_start_tv, NULL);
#endif

	taint_entry* mptr = pp[i].mptr;
	while (mptr < pp[i].mend) {
	    if (mptr->p1 > 0xe0000000) {
		taint_entry* pentry = &merge_log[mptr->p1-0xe0000001];
		if (pentry->p1 == 0) {
		    mptr->p1 = pentry->p2;
		} else if (pentry->p2 == 0) {
		    mptr->p1 = pentry->p1;
		}
	    }
	    if (mptr->p2 > 0xe0000000) {
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
#ifdef STATS
	gettimeofday(&prune_2_end_tv, NULL);
	ms = ms_diff(prune_2_end_tv, prune_2_start_tv);
	total_prune_2_ms += ms;
#endif
    }
}

struct new_live_set_data {
    pthread_t                tid;
    taint_t*                 p;
    taint_t*                 pend;
    taint_t*                 pls;
    taint_t*                 plsend;
    unordered_set<uint32_t>* plive_set;
    vector<taint_t>          results;
#ifdef STATS
    u_long                   lno_changes;
    u_long                   lzeros;
    u_long                   linputs;
    u_long                   lnot_live;
    u_long                   lmerges;
    u_long                   lmerge_zeros;
    struct timeval           tv_start;
    struct timeval           tv_end;
#endif
};

void* 
do_new_live_set (void* data)
{
    // Unpack arguments
    new_live_set_data* pnlsd = (new_live_set_data *) data;
    taint_t* p = pnlsd->p;
    taint_t* pend = pnlsd->pend;
    taint_t* pls = pnlsd->pls;
    taint_t* plsend = pnlsd->plsend;
    unordered_set<uint32_t>* plive_set = pnlsd->plive_set;
    vector<taint_t>& results = pnlsd->results;

#ifdef STATS
    uint32_t lno_changes = 0, lzeros = 0, linputs = 0, lnot_live = 0, lmerges = 0, lmerge_zeros = 0;
    gettimeofday(&pnlsd->tv_start, NULL);
#endif

    while (p < pend && pls < plsend) {
	taint_t addr = *p;
	if (*pls < addr) {
	    // No change - so still in live set
	    results.push_back(*pls);
#ifdef STATS
	    lno_changes++;
#endif
	    pls++;
	} else {
	    taint_t val = *(p+1);
	    if (val == 0) {
		// Do nothing
#ifdef STATS
		lzeros++;
#endif
	    } else if (val < 0xc0000000) {
		if (start_flag || plive_set->count(val)) {
		    results.push_back(addr);
#ifdef STATS
		    linputs++;
#endif
		} else {
#ifdef STATS
		    lnot_live++;
#endif
		}
	    } else if (val <= 0xe0000000) {
		results.push_back(addr);
#ifdef STATS
		linputs++;
#endif
	    } else {
		taint_entry* pentry = &merge_log[val-0xe0000001];
		if (pentry->p1 || pentry->p2) {
		    results.push_back(addr);
#ifdef STATS
		    lmerges++;
#endif
		} else {
#ifdef STATS
		    lmerge_zeros++;
#endif
		}
	    }
	    p += 2;
	    if (addr == *pls) pls++;
	}
    }
    if (pls == plsend) {
	while (p < pend) {
	    taint_t addr = *p;
	    taint_t val = *(p+1);
	    if (val == 0) {
		// Do nothing
#ifdef STATS
		lzeros++;
#endif
	    } else if (val < 0xc0000000) {
		if (start_flag || plive_set->count(val)) {
		    results.push_back(addr);
#ifdef STATS
		    linputs++;
#endif
		} else {
#ifdef STATS
		    lnot_live++;
#endif
		}
	    } else if (val <= 0xe0000000) {
		results.push_back(addr);
#ifdef STATS
		linputs++;
#endif
	    } else {
		taint_entry* pentry = &merge_log[val-0xe0000001];
		if (pentry->p1 || pentry->p2) {
		    results.push_back(addr);
#ifdef STATS
		    lmerges++;
#endif
		} else {
#ifdef STATS
		    lmerge_zeros++;
#endif
		}
	    }
	    p += 2;
	}
    }
    if (p == pend) {
	while (pls < plsend) {
	    results.push_back(*pls);
	    pls++;
	}
    }

#ifdef STATS
    gettimeofday(&pnlsd->tv_end, NULL);
    pnlsd->lno_changes = lno_changes;
    pnlsd->lzeros = lzeros;
    pnlsd->linputs = linputs;
    pnlsd->lnot_live = lnot_live;
    pnlsd->lmerges = lmerges;
    pnlsd->lmerge_zeros = lmerge_zeros;
#endif
    return NULL;
}

static taint_t* find_split (taint_t* start, taint_t* end, taint_t val) 
{
    while (end > start) {
	u_long new_incr = (end - start) / 2;
	taint_t* mid = start + new_incr;
	if (*mid >= val) {
	    end = mid;
	} else {
	    start = mid+1;
	}
    }
    return end;
}

static void
make_new_live_set (taint_t* p, taint_t* pend, taint_t* pls, taint_t* plsend, unordered_set<uint32_t>& live_set)
{
    struct new_live_set_data new_live_set_data[parallelize];

#ifdef STATS
    gettimeofday(&new_live_start_tv, NULL);
    send_idle = recv_idle = 0;
#endif

    int ncnt = 0;
    u_long values = (pend - p)/2;
    u_long step = values/parallelize;
    if (step > 0) {
	taint_t* lastp = p;
	taint_t* lastpls = pls;
	for (int i = 0; i < parallelize; i++) {
	    
	    new_live_set_data[i].p = lastp;
	    if (i == parallelize-1) {
		new_live_set_data[i].pend = pend;
	    } else {
		lastp = new_live_set_data[i].pend = lastp + step*2;
	    }
	    new_live_set_data[i].pls = lastpls;
	    if (i == parallelize-1) {
		new_live_set_data[i].plsend = plsend;
	    } else {
		taint_t* split = find_split (lastpls, plsend, *lastp);
		lastpls = new_live_set_data[i].plsend = split;
	    }
	    new_live_set_data[i].plive_set = &live_set;
	}
	ncnt = parallelize;
    } else if (pend != p) {
	new_live_set_data[0].p = p;
	new_live_set_data[0].pend = pend;
	new_live_set_data[0].pls = pls;
	new_live_set_data[0].plsend = plsend;
	new_live_set_data[0].plive_set = &live_set;
	ncnt = 1;
    }
    for (int i = 0; i < ncnt-1; i++) {
	long rc = pthread_create (&new_live_set_data[i].tid, NULL, do_new_live_set, &new_live_set_data[i]);
	if (rc < 0) {
	    fprintf (stderr, "Cannot create output thread, rc=%ld\n", rc);
	    assert (0);
	}
    }

    if (ncnt) do_new_live_set(&new_live_set_data[ncnt-1]);

    // Write values in order
    uint32_t wbucket_cnt = 0, wbucket_stop = 0;
    for (int i = 0; i < ncnt; i++) {
	if (i < ncnt-1) {
	    long rc = pthread_join(new_live_set_data[i].tid, NULL);
	    if (rc < 0) fprintf (stderr, "Cannot join make live set thread, rc=%ld\n", rc); 
	}
	for (auto iter = new_live_set_data[i].results.begin(); iter != new_live_set_data[i].results.end(); iter++) {
	    PUT_QVALUEB(*iter,inputq_hdr,inputq_buf,iqfd,wbucket_cnt,wbucket_stop);
	}
    }

    // Write terminating value
    PUT_QVALUEB(TERM_VAL,inputq_hdr,inputq_buf,iqfd,wbucket_cnt,wbucket_stop);
    bucket_term(inputq_hdr,inputq_buf,iqfd,wbucket_cnt,wbucket_stop);

#ifdef STATS
    gettimeofday(&new_live_end_tv, NULL);
    new_live_set_send_idle = send_idle;
    new_live_set_recv_idle = recv_idle;

    for (int i = 0; i < ncnt; i++) {
	new_live_no_changes += new_live_set_data[i].lno_changes;
	new_live_zeros += new_live_set_data[i].lzeros;
	new_live_inputs += new_live_set_data[i].linputs;
	new_live_notlive += new_live_set_data[i].lnot_live;
	new_live_merges += new_live_set_data[i].lmerges;
	new_live_merge_zeros += new_live_set_data[i].lmerge_zeros;
	u_long ms = ms_diff(new_live_set_data[i].tv_end, new_live_set_data[i].tv_start);
	total_new_live_set_ms += ms;
	if (ms > longest_new_live_set_ms) longest_new_live_set_ms = ms;
    }
#endif
}

// Process one epoch for sequential forward strategy 
long seq_epoch (const char* dirname, int port)
{
    long rc;
    char* output_log, *token_log;
    taint_t *ts_log;
    u_long idatasize = 0, odatasize = 0, mdatasize = 0, adatasize = 0;
    uint32_t buf_size, tokens, output_token = 0;
    int outputfd, inputfd, addrsfd;
    unordered_set<uint32_t> live_set;
    unordered_map<taint_t,taint_t> address_map;
    pthread_t build_map_tid = 0;

    rc = setup_aggregation (dirname, outputfd, inputfd, addrsfd);
    if (rc < 0) return rc;

    // Read inputs from DIFT engine
    rc = read_inputs (port, token_log, output_log, ts_log, merge_log,
		      mdatasize, odatasize, idatasize, adatasize);
    if (rc < 0) return rc;

#ifdef STATS
    gettimeofday(&recv_done_tv, NULL);
#endif

    bucket_init();

    if (!finish_flag) build_map_tid = spawn_map_thread (&address_map, ts_log, adatasize);

    if (!start_flag) {

	// Wait for preceding epoch to send list of live addresses
#ifdef STATS
	gettimeofday(&live_receive_start_tv, NULL);
#endif
	uint32_t val;
	uint32_t rbucket_cnt = 0, rbucket_stop = 0;
	GET_QVALUEB(val, outputq_hdr, outputq_buf, oqfd, rbucket_cnt, rbucket_stop);
	while (val != TERM_VAL) {
	    live_set.insert(val);
	    GET_QVALUEB(val, outputq_hdr, outputq_buf, oqfd, rbucket_cnt, rbucket_stop);
	} 

#ifdef STATS
	gettimeofday(&live_receive_end_tv, NULL);
	live_set_size = live_set.size();
	live_set_send_idle = send_idle;
	live_set_recv_idle = recv_idle;
#endif
	// Prune the merge log
	prune_merge_log (mdatasize, live_set);
    }

    // Construct and send out new live set
    if (!finish_flag) {

	uint32_t* pls = outputq_buf;
	uint32_t* plsend = outputq_buf + live_set.size();
	if (live_set.size() > TAINTENTRIES) {
	    fprintf (stderr, "Oops: live set is %x\n", live_set.size());
	    return -1;
	}
	make_new_live_set(ts_log, ts_log + adatasize/sizeof(taint_t), pls, plsend, live_set);
    }
    
    if (!start_flag) {
	// Done reqding data in outputq - reset queue and wait on sender
	outputq_hdr->read_index = outputq_hdr->write_index = 0;
	UP_QSEM (outputq_hdr);
    }

#ifdef STATS
    gettimeofday(&live_done_tv, NULL);
#endif

    // Wait until live set has been completely read
    bucket_write_init();
    output_token = process_outputs (output_log, output_log + odatasize, &live_set, dirname, do_outputs_seq);

    if (!finish_flag) {

#ifdef STATS
	gettimeofday(&index_wait_start_tv, NULL);
#endif

	rc = pthread_join(build_map_tid, NULL);
	if (rc < 0) return rc;

#ifdef STATS
	gettimeofday(&index_wait_end_tv, NULL);
#endif

	if (!finish_flag) {
#ifdef STATS
	    gettimeofday(&send_wait_start_tv, NULL);
#endif	    
	    DOWN_QSEM(inputq_hdr);
#ifdef STATS
	    gettimeofday(&send_wait_end_tv, NULL);
#endif	    
	}
	bucket_read_init();
	process_addresses (output_token, address_map);

    } else if (!start_flag) {
	uint32_t write_cnt = 0, write_stop = 0;
	PUT_QVALUEB(TERM_VAL,outputq_hdr,outputq_buf,oqfd, write_cnt, write_stop);
	bucket_term (outputq_hdr,outputq_buf,oqfd, write_cnt, write_stop);
	flush_alloutbufs();
    } else {
	flush_alloutbufs();
    }

#ifdef STATS
    gettimeofday(&finish_start_tv, NULL);
#endif

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
    print_stats (dirname, mdatasize, odatasize, idatasize, adatasize);
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

void send_stream (int s, struct taintq_hdr* qh, uint32_t* qb)
{
    // Listen on output queue and send over network
    bool done = false;
    u_long bytes_sent = 0;
    while (!done) {

	pthread_mutex_lock(&(qh->lock));
	while (qh->read_index == qh->write_index) {
	    pthread_cond_wait(&(qh->empty), &(qh->lock));
	}
	pthread_mutex_unlock(&(qh->lock));

	long rc = safe_write (s, qb + (qh->read_index*TAINTBUCKETENTRIES), TAINTBUCKETSIZE);
	if (rc != (long)TAINTBUCKETSIZE) return; // Error sending the data

	bytes_sent += TAINTBUCKETENTRIES;

	if (qb[qh->read_index*TAINTBUCKETENTRIES+TAINTBUCKETENTRIES-1] == TERM_VAL) done = true;

	pthread_mutex_lock(&(qh->lock));
	qh->read_index = (qh->read_index+1)%TAINTBUCKETS;
	pthread_cond_signal(&(qh->full));
	pthread_mutex_unlock(&(qh->lock));
    }
}

void recv_stream (int s, struct taintq_hdr* qh, uint32_t* qb)
{
    // Get data and put on the inputq
    bool done = false;
    u_long bytes_rcvd = 0;
    while (!done) {

	// Receive a block at a time
	pthread_mutex_lock(&(qh->lock));
	while ((qh->write_index+1)%TAINTBUCKETS == qh->read_index) {
	    pthread_cond_wait(&(qh->full), &(qh->lock));
	}
	pthread_mutex_unlock(&(qh->lock));

	long rc = safe_read (s, qb + (qh->write_index*TAINTBUCKETENTRIES), TAINTBUCKETSIZE);
	if (rc != (long)TAINTBUCKETSIZE) return; // Error sending the data

	bytes_rcvd += TAINTBUCKETENTRIES;

	if (qb[qh->write_index*TAINTBUCKETENTRIES+TAINTBUCKETENTRIES-1] == TERM_VAL) done = true;

	pthread_mutex_lock(&(qh->lock));
	qh->write_index = (qh->write_index+1)%TAINTBUCKETS;
	pthread_cond_signal(&(qh->empty));
	pthread_mutex_unlock(&(qh->lock));
    }
}

int recv_input_queue (struct recvdata* data)
{
    int s = connect_input_queue (data);
    if (s < 0) return s;

    if (data->do_sequential) {
	send_stream (s, inputq_hdr, inputq_buf); // First we send filters downstream	
	inputq_hdr->read_index = inputq_hdr->write_index = 0;
	UP_QSEM(inputq_hdr);
    }

    recv_stream (s, inputq_hdr, inputq_buf);
    close (s);
    return 0;
}

// Sending to another computer is implemented as separate process to add asyncrhony
int send_output_queue (struct senddata* data)
{
   int s = connect_output_queue (data);
   if (s < 0) return s;

   if (data->do_sequential) {
       recv_stream (s, outputq_hdr, outputq_buf); // First we read data from upstream
       DOWN_QSEM(outputq_hdr);
   }

   send_stream (s, outputq_hdr, outputq_buf);
   close (s);
   return 0;
}

void format ()
{
    fprintf (stderr, "format: stream <dir> <taint port> [-iq input_queue_hdr input_queue] [-oq output_queue_hdr output_queue] [-par # of threads]\n");
    exit (0);
}

int main (int argc, char* argv[]) 
{
    char* input_queue_hdr = NULL;
    char* output_queue_hdr = NULL;
    char* input_queue = NULL;
    char* output_queue = NULL;
    char* output_host = NULL;
    bool input_host = false;
    struct senddata sd;
    struct recvdata rd;
    bool do_sequential = false;

    if (argc < 3) format();

    for (int i = 3; i < argc; i++) {
	if (!strcmp (argv[i], "-par")) {
	    i++;
	    if (i < argc) {
		parallelize = atoi(argv[i]);
	    } else {
		format();
	    }
	} else if (!strcmp (argv[i], "-iq")) {
	    i++;
	    if (i < argc) {
		input_queue_hdr = argv[i];
	    } else {
		format();
	    }
	    i++;
	    if (i < argc) {
		input_queue = argv[i];
	    } else {
		format();
	    }
	} else if (!strcmp (argv[i], "-oq")) {
	    i++;
	    if (i < argc) {
		output_queue_hdr = argv[i];
	    } else {
		format();
	    }
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

    if (output_host) {
	int oqhdrfd = shm_open (output_queue_hdr, O_RDWR, 0);
	if (oqhdrfd < 0) {
	    fprintf (stderr, "Cannot open output queue header %s, errno=%d\n", output_queue_hdr, errno);
	    return -1;
	}
	oqfd = shm_open (output_queue, O_RDWR, 0);
	if (oqfd < 0) {
	    fprintf (stderr, "Cannot open output queue %s, errno=%d\n", output_queue, errno);
	    return -1;
	}
	outputq_hdr = (struct taintq_hdr *) mmap (NULL, TAINTQHDRSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, oqhdrfd, 0);
	if (outputq_hdr == MAP_FAILED) {
	    fprintf (stderr, "Cannot map output queue header, errno=%d\n", errno);
	    return -1;
	}
	outputq_buf = (uint32_t *) mmap (NULL, TAINTQSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, oqfd, 0);
	if (outputq_buf == MAP_FAILED) {
	    fprintf (stderr, "Cannot map input queue, errno=%d\n", errno);
	    return -1;
	}
	sd.host = output_host;
	sd.port = STREAM_PORT;
	sd.do_sequential = do_sequential;
	return (send_output_queue (&sd));
    }

    if (input_host) {
	int iqhdrfd = shm_open (input_queue_hdr, O_RDWR, 0);
	if (iqhdrfd < 0) {
	    fprintf (stderr, "Cannot open input queue header %s, errno=%d\n", input_queue_hdr, errno);
	    return -1;
	}
	iqfd = shm_open (input_queue, O_RDWR, 0);
	if (iqfd < 0) {
	    fprintf (stderr, "Cannot open input queue %s, errno=%d\n", input_queue, errno);
	    return -1;
	}
	inputq_hdr = (struct taintq_hdr *) mmap (NULL, TAINTQHDRSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, iqhdrfd, 0);
	if (inputq_hdr == MAP_FAILED) {
	    fprintf (stderr, "Cannot map input queue header, errno=%d\n", errno);
	    return -1;
	}
	inputq_buf = (uint32_t *) mmap (NULL, TAINTQSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, iqfd, 0);
	if (inputq_buf == MAP_FAILED) {
	    fprintf (stderr, "Cannot map input queue, errno=%d\n", errno);
	    return -1;
	}
	rd.port = STREAM_PORT;
	rd.do_sequential = do_sequential;
	return recv_input_queue (&rd);
    }

    if (input_queue) {
	int iqhdrfd = shm_open (input_queue_hdr, O_RDWR, 0);
	if (iqhdrfd < 0) {
	    fprintf (stderr, "Cannot open input queue header %s, errno=%d\n", input_queue_hdr, errno);
	    return -1;
	}
	iqfd = shm_open (input_queue, O_RDWR, 0);
	if (iqfd < 0) {
	    fprintf (stderr, "Cannot open input queue %s, errno=%d\n", input_queue, errno);
	    return -1;
	}
	inputq_hdr = (struct taintq_hdr *) mmap (NULL, TAINTQHDRSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, iqhdrfd, 0);
	if (inputq_hdr == MAP_FAILED) {
	    fprintf (stderr, "Cannot map input queue header, errno=%d\n", errno);
	    return -1;
	}
	inputq_buf = (uint32_t *) mmap (NULL, TAINTQSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, iqfd, 0);
	if (inputq_buf == MAP_FAILED) {
	    fprintf (stderr, "Cannot map input queue, errno=%d\n", errno);
	    return -1;
	}
	finish_flag = false;
    } else {
	inputq_hdr = NULL;
	inputq_buf = NULL;
	finish_flag = true;
    }

    if (output_queue) {
	int oqhdrfd = shm_open (output_queue_hdr, O_RDWR, 0);
	if (oqhdrfd < 0) {
	    fprintf (stderr, "Cannot open output queue header %s, errno=%d\n", output_queue_hdr, errno);
	    return -1;
	}
	oqfd = shm_open (output_queue, O_RDWR, 0);
	if (oqfd < 0) {
	    fprintf (stderr, "Cannot open output queue %s, errno=%d\n", output_queue, errno);
	    return -1;
	}
	outputq_hdr = (struct taintq_hdr *) mmap (NULL, TAINTQHDRSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, oqhdrfd, 0);
	if (outputq_hdr == MAP_FAILED) {
	    fprintf (stderr, "Cannot map output queue header, errno=%d\n", errno);
	    return -1;
	}
	outputq_buf = (uint32_t *) mmap (NULL, TAINTQSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, oqfd, 0);
	if (outputq_buf == MAP_FAILED) {
	    fprintf (stderr, "Cannot map input queue, errno=%d\n", errno);
	    return -1;
	}
	start_flag = false;
    } else {
	outputq_hdr = NULL;
	outputq_buf = NULL;
	start_flag = true;
    }

    if (do_sequential) {
	seq_epoch (argv[1], atoi(argv[2]));
    } else {
	stream_epoch (argv[1], atoi(argv[2]));
    }

    return 0;
}
