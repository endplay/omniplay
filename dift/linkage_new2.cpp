#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <assert.h>
#include <sys/types.h>
#include <syscall.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sched.h>
#include <errno.h>
#include <stdint.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/net.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <map>
using namespace std;

#include "util.h" //why doesn't this fail? 
#include "list.h"
#include "linkage_common.h"
#include "taint_interface/taint_interface.h"
#include "taint_interface/taint_creation.h"
#include "xray_monitor.h"
#include "xray_token.h"
#include "xray_slab_alloc.h"
#include "trace_x.h"
#include "splice.h"
#include "taint_nw.h"

#if defined(USE_NW) || defined(USE_SHMEM)
int s = -1;
#endif

// List of available Linkage macros
// // DO NOT TURN THESE ON HERE. Turn these on in makefile.rules.
// #define COPY_ONLY                    // just copies
// #define LINKAGE_DATA                 // data flow
// #define LINKAGE_DATA_OFFSET
// #define LINKAGE_FPU
// #define LINKAGE_SYSCALL              // system call & libc function abstraction
// #define LINKAGE_CODE
#define LINKAGE_FDTRACK
// #define CTRL_FLOW                    // direct control flow
// #define ALT_PATH_EXPLORATION         // indirect control flow
// #define CONFAID

//#define LOGGING_ON
#define LOG_F log_f
//#define ERROR_PRINT fprintf
#define ERROR_PRINT(x,...);
#ifdef LOGGING_ON
#define LOG_PRINT(args...) \
{                           \
    fprintf(LOG_F, args);   \
    fflush(LOG_F);          \
}
/*
#define INSTRUMENT_PRINT(args...) \
{                                   \
    fprintf(args);                  \
    fflush(log_f);                  \
}
*/
 #define INSTRUMENT_PRINT(x,...);
 #define PRINTX fprintf
 #define SYSCALL_DEBUG fprintf
#else
 #define LOG_PRINT(x,...);
 #define INSTRUMENT_PRINT(x,...);
 #define SYSCALL_DEBUG(x,...);
 //#define SYSCALL_DEBUG fprintf
 #define PRINTX(x,...);
#endif
#define SPECIAL_REG(X) (X == LEVEL_BASE::REG_EBP || X == LEVEL_BASE::REG_ESP)

//#define USE_CODEFLUSH_TRACK
// Debug Macros
// #define TRACE_TAINT_OPS

//#define MMAP_INPUTS
//#define EXEC_INPUTS

//ARQUINN: added constant for copyfile
#define COPY_BUFFER_SIZE 1024

struct save_state {
    uint64_t rg_id; // for verification purposes, ask the kernel for these!
    int record_pid;
    unsigned long global_syscall_cnt;
    int syscall_cnt; // the per-thread count
    unsigned long open_file_cnt; 
};

/* Global state */
TLS_KEY tls_key; // Key for accessing TLS. 
int dev_fd; // File descriptor for the replay device
int get_record_pid(void);
#ifndef NO_FILE_OUTPUT
void init_logs(void);
#endif
struct thread_data* current_thread; // Always points to thread-local data (changed by kernel on context switch)
int first_thread = 1;
int child = 0;
char** main_prev_argv = 0;
char group_directory[256];
#ifndef NO_FILE_OUTPUT
FILE* log_f = NULL; // For debugging
#endif
unsigned long global_syscall_cnt = 0;
unsigned long open_file_cnt = FILENO_START; // 0 is stdin, 1 is exec args, 2 is env
struct xray_monitor* open_fds = NULL; // List of open fds
struct xray_monitor* open_socks = NULL; // list of open sockets
struct xray_monitor* open_x_fds = NULL; // list of open x sockets
FILE* filter_f = NULL;
int tokens_fd = -1;
int outfd = -1;
int trace_x = 0;
int xoutput_fd = -1;
#ifdef TRACE_TAINT_OPS
int trace_taint_outfd = -1;
#endif
unsigned long long inst_count = 0;
int filter_x = 0;
int filter_inputs = 0;
int print_all_opened_files = 0;
const char* filter_read_filename = NULL;
u_long segment_length = 0;
int splice_output = 0;
int all_output = 0;
const char* splice_semname = NULL;
const char* splice_input = NULL;
u_long num_merge_entries = 0x40000000/(sizeof(taint_t)*2);
u_long inst_cnt = 0;
map<pid_t,struct thread_data*> active_threads;
u_long* ppthread_log_clock = NULL;

//added for multi-process replay
const char* fork_flags = NULL;
int fork_flags_index = 0;

#ifdef OUTPUT_FILENAMES
FILE* filenames_f = NULL; // Mapping of all opened filenames
#endif


struct slab_alloc open_info_alloc;
struct slab_alloc thread_data_alloc;

KNOB<bool> KnobFilterInputs(KNOB_MODE_WRITEONCE,
    "pintool", "i", "",
    "filter input or not");
KNOB<string> KnobFilterInputFiles(KNOB_MODE_APPEND,
    "pintool", "f", "",
    "files to input filter on, only valid with -i on");
KNOB<string> KnobFilterInputPartFilename(KNOB_MODE_APPEND,
    "pintool", "e", "",
    "partial filename to filter input on, only valid with -i on");
KNOB<string> KnobFilterInputSyscalls(KNOB_MODE_APPEND,
    "pintool", "s", "",
    "syscalls to filter input on, only valid with -i on");
KNOB<string> KnobFilterInputRegex(KNOB_MODE_APPEND,
    "pintool", "r", "",
    "regex to filter input on, only valid with -i on");
KNOB<string> KnobFilterByteRange(KNOB_MODE_APPEND,
    "pintool", "b", "",
    "byte range to filter input on, only valid with -i on");
KNOB<string> KnobFilterReadFile(KNOB_MODE_WRITEONCE,
    "pintool", "rf", "",
    "filename of filter-file to get bytes to filter input on, only valid with -i on");
KNOB<int> KnobFilterOutputSyscall(KNOB_MODE_WRITEONCE,
    "pintool", "ofs", "",
    "if set, specific syscall for which to report output taint");
KNOB<bool> KnobTraceX(KNOB_MODE_WRITEONCE,
    "pintool", "x", "",
    "output taints to X");
KNOB<bool> KnobRecordOpenedFiles(KNOB_MODE_WRITEONCE,
    "pintool", "o", "",
    "print all opened files");
KNOB<unsigned int> KnobSegmentLength(KNOB_MODE_WRITEONCE,
    "pintool", "l", "",
    "segment length"); //FIXME: take into consideration offset of being attached later. Remember, this is to specify where to kill application.
KNOB<bool> KnobSpliceOutput(KNOB_MODE_WRITEONCE,
    "pintool", "so", "",
    "generate output splice file");
KNOB<bool> KnobAllOutput(KNOB_MODE_WRITEONCE,
    "pintool", "ao", "",
    "generate output file of changed taints");
KNOB<int> KnobMergeEntries(KNOB_MODE_WRITEONCE,
    "pintool", "me", "",
    "merge entries"); 
KNOB<string> KnobNWHostname(KNOB_MODE_WRITEONCE,
    "pintool", "host", "",
    "hostname for nw output");
KNOB<int> KnobNWPort(KNOB_MODE_WRITEONCE,
    "pintool", "port", "",
    "port for nw output");
KNOB<string> KnobForkFlags(KNOB_MODE_WRITEONCE,
    "pintool", "fork_flags", "",
    "flags for which way to go on each fork");


//FIXME: take into consideration offset of being attached later. Remember, this is to specify where to kill application.

// Specific output functions
// #define HEARTBLEED
#ifdef HEARTBLEED
int bad_memcpy_flag = 0;
int heartbleed_fd = -1;

void instrument_before_badmemcpy(void) {
    fprintf(stderr, "instrument bad heartbeat!\n");
    bad_memcpy_flag = 1;
}
#endif

//ARQUINN: added helper methods for copying tokens from the file
#ifdef USE_FILE
static void copy_file(int src, int dest) { 
    char buff[COPY_BUFFER_SIZE]; 
    int read_bytes, written_bytes,rc;

    rc = lseek(src,0, SEEK_SET);
    if(rc < 0) 
	fprintf(stderr, "There was an error using lseek rc %d, errno %d\n",rc,errno);

    while((read_bytes = read(src,buff,COPY_BUFFER_SIZE)) > 0) 
    {
	written_bytes = 0;
	while(written_bytes < read_bytes) { 
	    written_bytes += write(dest,buff,read_bytes - written_bytes);
	}
    }
    if(read_bytes < 0) { 
	fprintf(stderr, "There was an error reading file (int) rc %d, errno %d\n",read_bytes,errno);
    }
}
#ifdef OUTPUT_FILENAME
static void copy_file(FILE* src, FILE* dest) { 
    char buff[COPY_BUFFER_SIZE]; 
    int read_chars,written_chars, rc;

    rc = fseek(src,0, SEEK_SET);
    if(rc < 0) 
	fprintf(stderr, "There was an error using lseek rc %d, errno %d\n",rc,errno);

    while((read_chars = fread(buff,sizeof(char),COPY_BUFFER_SIZE,src)) > 0) 
    { 
	written_chars = 0;
	while(written_chars < read_chars) { 
	    written_chars += fwrite(buff,sizeof(char),read_chars-written_chars, dest);
	}
	fprintf(stderr, "\t wrote another %d bytes\n",written_chars);
    }
    if(read_chars < 0) { 
	fprintf(stderr, "There was an error reading file (FILE*) rc %d, errno %d\n",read_chars,errno);
    }
}
#endif
#endif


static int terminated = 0;
extern int dump_mem_taints (int fd);
extern int dump_reg_taints (int fd, taint_t* pregs);
extern int dump_mem_taints_start (int fd);
extern int dump_reg_taints_start (int fd, taint_t* pregs);
extern taint_t taint_num;

#ifdef TAINT_DEBUG
extern void print_taint_debug_reg (int tid, taint_t* pregs);
extern void print_taint_debug_mem ();
extern u_long debug_taint_cnt;
FILE* debug_f;
u_long taint_debug_inst = 0;
#endif

#ifdef TAINT_STATS
struct timeval begin_tv, end_tv;
u_long inst_instrumented = 0;
u_long traces_instrumented = 0;
uint64_t instrument_time = 0;
FILE* stats_f;
#endif

extern void write_token_finish (int fd);
extern void output_finish (int fd);

//In here we need to mess with stuff for if we are no longer following this process
static void dift_done ()
{    
    if (terminated) return;  // Only do this once
    terminated = 1;

    //fprintf (stderr, "starting dift_done\n");

#ifdef USE_FILE
    char taint_structures_file[256];
    snprintf(taint_structures_file, 256, "%s/taint_structures", group_directory);
    int taint_fd = open(taint_structures_file, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
    assert(taint_fd > 0);
#endif
#ifdef USE_SHMEM
    char taint_structures_file[256];
    snprintf(taint_structures_file, 256, "/taint_structures_shm%s", group_directory);
    for (u_int i = 1; i < strlen(taint_structures_file); i++) {
	if (taint_structures_file[i] == '/') taint_structures_file[i] = '.';
    }
    int taint_fd = shm_open(taint_structures_file, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (taint_fd < 0) {
	fprintf(stderr, "could not open taint shmem %s, errno %d\n", taint_structures_file, errno);
	assert(0);
    }
    if (all_output) {
	int rc = ftruncate64 (taint_fd, MAX_DUMP_SIZE);
	if (rc < 0) {
	    fprintf(stderr, "could not truncate shmem %s, errno %d\n", taint_structures_file, errno);
	    assert(0);
	}
    }
#endif
#ifdef USE_NW
    int taint_fd = s;
#endif

#ifndef USE_NULL    
    if (all_output) {
	if (splice_output) {
	    // Dump out the active registers in order of the record thread id
	    for (map<pid_t,struct thread_data*>::iterator iter = active_threads.begin(); 
		 iter != active_threads.end(); iter++) {
		//printf ("dumping record pid %d regs\n", iter->second->record_pid);
		dump_reg_taints(taint_fd, iter->second->shadow_reg_table);
	    }
	    dump_mem_taints(taint_fd);
	} else {
	    // Dump out the active registers in order of the record thread id
	    for (map<pid_t,struct thread_data*>::iterator iter = active_threads.begin(); 
		 iter != active_threads.end(); iter++) {
		dump_reg_taints_start(taint_fd, iter->second->shadow_reg_table);
	    }
	    dump_mem_taints_start(taint_fd);
	}
    }
#endif

    // Finish up output of other files
#ifdef USE_NW
    write_token_finish (s);
#endif
#ifdef USE_SHMEM
    //sential for not following
    if (tokens_fd != -99999 && outfd != -99999) { 
	write_token_finish (tokens_fd);
	output_finish (outfd);
    }
#endif

#ifdef TAINT_STATS
#ifndef USE_FILE
    if (tokens_fd != -99999 && outfd != -99999 && s != -99999) { 
#else
    if (tokens_fd != -99999 && outfd != -99999) { 
#endif
	gettimeofday(&end_tv, NULL);
	fprintf (stats_f, "Instructions instrumented: %ld\n", inst_instrumented);
	fprintf (stats_f, "Traces instrumented: %ld\n", traces_instrumented);
	fprintf (stats_f, "Instrument time: %lld us\n", instrument_time);
	fprintf (stats_f, "DIFT began at %ld.%06ld\n", begin_tv.tv_sec, begin_tv.tv_usec);
	fprintf (stats_f, "DIFT ended at %ld.%06ld\n", end_tv.tv_sec, end_tv.tv_usec);
	finish_and_print_taint_stats(stats_f);
	fclose (stats_f);
    }
#else
    finish_and_print_taint_stats(stdout);
#endif

#ifdef TAINT_DEBUG
    fclose (debug_f);
#endif

    printf("DIFT done at %ld\n", *ppthread_log_clock);

#ifdef USE_SHMEM
    // Send "done" message to aggregator
    if (s != -99999) {
	int rc = write (s, &group_directory, sizeof(group_directory));
	if (rc != sizeof(group_directory)) {
	    fprintf (stderr, "write of directory failed, rc=%d, errno=%d\n", rc, errno);
	}
    }
#endif
}

ADDRINT find_static_address(ADDRINT ip)
{
    PIN_LockClient();
    IMG img = IMG_FindByAddress(ip);
    if (!IMG_Valid(img)) return ip;
    ADDRINT offset = IMG_LoadOffset(img);
    PIN_UnlockClient();
    return ip - offset;
}

void print_static_address(FILE* fp, ADDRINT ip)
{
    const char* img_name = "--";
    ADDRINT static_ip = find_static_address(ip);
    PIN_LockClient();
    if (IMG_Valid(IMG_FindByAddress(ip))) {
        img_name = IMG_Name(IMG_FindByAddress(ip)).c_str();
    }
    fprintf(fp, "%#x %s\n", static_ip, img_name);
    PIN_UnlockClient();
}

static inline void increment_syscall_cnt (int syscall_num)
{
    // ignore pthread syscalls, or deterministic system calls that we don't log (e.g. 123, 186, 243, 244)
    if (!(syscall_num == 17 || syscall_num == 31 || syscall_num == 32 || 
	  syscall_num == 35 || syscall_num == 44 || syscall_num == 53 || 
	  syscall_num == 56 || syscall_num == 58 || syscall_num == 98 || 
	  syscall_num == 119 || syscall_num == 123 || syscall_num == 127 ||
	  syscall_num == 186 || syscall_num == 243 || syscall_num == 244)) {
        if (current_thread->ignore_flag) {
            if (!(*(int *)(current_thread->ignore_flag))) {
                global_syscall_cnt++;
                current_thread->syscall_cnt++;
            }
        } else {
            global_syscall_cnt++;
            current_thread->syscall_cnt++;
        }
#if 0
#ifdef TAINT_DEBUG
	fprintf (debug_f, "pid %d syscall %d global syscall cnt %lu num %d clock %ld\n", current_thread->record_pid, 
		 current_thread->syscall_cnt, global_syscall_cnt, syscall_num, *ppthread_log_clock);
#endif
#endif
    }
}

static void create_connect_info_name(char* connect_info_name, int domain,
				     struct connect_info* ci)
{
    assert(ci);
    if (domain == AF_UNIX) {
        memcpy(connect_info_name, ci->path, 108); // 108 is the magic number
    } else if (domain == AF_INET) {
        char address[256];
        if (!inet_ntop(AF_INET, &ci->sin_addr, address, 256)) {
            strcpy(connect_info_name, "UNKNOWN_SOCKET");
            return;
        }
        snprintf(connect_info_name, 256, "%s:%d", address, ci->port);
    } else if (domain == AF_INET6) {
        char address[256];
        if (!inet_ntop(AF_INET6, &ci->sin_addr6, address, 256)) {
            strcpy(connect_info_name, "UNKNOWN_SOCKET");
            return;
        }
        snprintf(connect_info_name, 256, "%s:%d", address, ci->port);
    } else {
        strcpy(connect_info_name, "UNKNOWN_SOCKET");
    }
}

static inline void sys_open_start(struct thread_data* tdata, char* filename, int flags)
{
    SYSCALL_DEBUG (stderr, "open_start: filename %s\n", filename);
    struct open_info* oi = (struct open_info *) get_slice(&open_info_alloc);
    strncpy(oi->name, filename, OPEN_PATH_LEN);
    oi->flags = flags;
    oi->fileno = open_file_cnt;
    open_file_cnt++;
    tdata->save_syscall_info = (void *) oi;
}

char* get_file_ext(char* filename){
    char* last = strrchr(filename, '/');
    char* dot;
    if (!last) {
        dot = strrchr(filename, '.');
    }
    else {
        dot = strrchr(last, '.');
    }
    if(!dot || dot == filename) {
        char* ret;
        ret = (char*) malloc(5 * sizeof(char));
	if (!ret) {
	    fprintf (stderr, "Unable to malloc file ext\n");
	    assert (0);
	}
        strcpy(ret, "none");
        return ret;
    }
    if (!strncmp(dot-2, "so", 2)) {
        strcpy(dot, "so");
        return dot;
    }
    return dot+1;
}

static inline void sys_open_stop(int rc)
{
    if (rc > 0) {
        struct open_info* oi = (struct open_info *) current_thread->save_syscall_info;
        monitor_add_fd(open_fds, rc, 0, current_thread->save_syscall_info);
	SYSCALL_DEBUG(stderr, "open: added fd %d\n", rc);
#ifdef OUTPUT_FILENAMES
        write_filename_mapping(filenames_f, oi->fileno, oi->name);
#endif

#ifdef LINKAGE_FDTRACK
        int cloexec = oi->flags | O_CLOEXEC;
        add_taint_fd(rc, cloexec);
#endif
    }
    SYSCALL_DEBUG (stderr, "open_stop: rc %d\n", rc);
    current_thread->save_syscall_info = NULL;
}

static inline void sys_close_start(struct thread_data* tdata, int fd)
{
    SYSCALL_DEBUG (stderr, "close_start:fd = %d\n", fd);
    tdata->save_syscall_info = (void *) fd;
}

static inline void sys_close_stop(int rc)
{
    int fd = (int) current_thread->save_syscall_info;
    // remove the fd from the list of open files
    if (!rc) {
        if (monitor_has_fd(open_fds, fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, fd);
            assert(oi);
            // free(oi);
            monitor_remove_fd(open_fds, fd);
	    SYSCALL_DEBUG (stderr, "close: remove fd %d\n", fd);
        } 
	if (monitor_has_fd(open_socks, fd)) {
		monitor_remove_fd(open_socks, fd);
		SYSCALL_DEBUG (stderr, "close: remove sock fd %d\n", fd);
	}
#ifdef LINKAGE_FDTRACK
        remove_taint_fd(fd);
#endif
    }
    current_thread->save_syscall_info = 0;
}

static inline void sys_read_start(struct thread_data* tdata, int fd, char* buf, int size)
{
    SYSCALL_DEBUG(stderr, "sys_read_start: fd = %d\n", fd);
    struct read_info* ri = &tdata->read_info_cache;
    ri->fd = fd;
    ri->buf = buf;
    tdata->save_syscall_info = (void *) ri;
}

static inline void sys_read_stop(int rc)
{
    int read_fileno = -1;
    struct read_info* ri = (struct read_info*) &current_thread->read_info_cache;

    if (rc > 0) {
        struct taint_creation_info tci;
        char* channel_name = (char *) "--";

        if (monitor_has_fd(open_fds, ri->fd)) {
            struct open_info* oi;
            oi = (struct open_info *)monitor_get_fd_data(open_fds, ri->fd);
            read_fileno = oi->fileno;
            channel_name = oi->name;
        } else if (monitor_has_fd(open_socks, ri->fd)) {
            struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, ri->fd);
	    if (si) {
		if (si->domain == AF_INET || si->domain == AF_INET6) {
		    channel_name = (char *) "inetsocket";
		    //fprintf (stderr, "Read inet rc %d from fd %d at clock %lu\n", rc, ri->fd, *ppthread_log_clock);
		} else {
		    channel_name = (char *) "recvsocket";
		}
	    } else {
		fprintf (stderr, "read from socket no si, rc=%d\n", rc);
	    }
        } else if(ri->fd == fileno(stdin)) {
            read_fileno = FILENO_STDIN;
        }

        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
        tci.offset = 0;
        tci.fileno = read_fileno;
        tci.data = 0;

        LOG_PRINT ("Create taints from buffer sized %d at location %#lx\n",
                        rc, (unsigned long) ri->buf);
        //fprintf(stderr, "inst_count = %lld\n", inst_count);
        create_taints_from_buffer(ri->buf, rc, &tci, tokens_fd, channel_name);
#ifdef LINKAGE_FDTRACK
        //fprintf(stderr, "read from fd %d\n", ri->fd);
        if (is_fd_tainted(ri->fd)) {
            taint_add_fd2mem((u_long) ri->buf, rc, ri->fd);
        }
#endif
    }

    memset(&current_thread->read_info_cache, 0, sizeof(struct read_info));
    current_thread->save_syscall_info = 0;
}

static inline void sys_pread_start(struct thread_data* tdata, int fd, char* buf, int size)
{
    SYSCALL_DEBUG(stderr, "pread fd = %d\n", fd);
    struct read_info* ri = &tdata->read_info_cache;
    ri->fd = fd;
    ri->buf = buf;
    tdata->save_syscall_info = (void *) ri;
}

static inline void sys_pread_stop(int rc)
{
    int read_fileno = -1;
    struct read_info* ri = (struct read_info*) &current_thread->read_info_cache;

    // If global_syscall_cnt == 0, then handled in previous epoch
    if (rc > 0) {
        struct taint_creation_info tci;
        char* channel_name = (char *) "--";

        if (monitor_has_fd(open_fds, ri->fd)) {
            struct open_info* oi;
            oi = (struct open_info *)monitor_get_fd_data(open_fds, ri->fd);
            read_fileno = oi->fileno;
            channel_name = oi->name;
        } else if(ri->fd == fileno(stdin)) {
            read_fileno = 0;
        }

        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
        tci.offset = 0;
        tci.fileno = read_fileno;
        tci.data = 0;

        LOG_PRINT ("Create taints from buffer sized %d at location %#lx\n",
                        rc, (unsigned long) ri->buf);
        create_taints_from_buffer(ri->buf, rc, &tci, tokens_fd, channel_name);
    }

    memset(&current_thread->read_info_cache, 0, sizeof(struct read_info));
    current_thread->save_syscall_info = 0;
}

#ifdef LINKAGE_FDTRACK
static void sys_select_start(struct thread_data* tdata, int nfds, fd_set* readfds, fd_set* writefds, 
			     fd_set* exceptfds, struct timeval* timeout)
{
    tdata->select_info_cache.nfds = nfds;
    tdata->select_info_cache.readfds = readfds;
    tdata->select_info_cache.writefds = writefds;
    tdata->select_info_cache.exceptfds = exceptfds;
    tdata->select_info_cache.timeout = timeout;
}

static void sys_select_stop(int rc)
{
    // If global_syscall_cnt == 0, then handled in previous epoch
    if (rc != -1) {
        // create a taint
        struct taint_creation_info tci;
        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
        tci.offset = 0;
        tci.fileno = FILENO_SELECT;
        tci.data = 0;
        tci.type = TOK_SELECT;

        create_fd_taints(current_thread->select_info_cache.nfds,
                current_thread->select_info_cache.readfds,
                &tci, tokens_fd);
    }
}
#endif

static void sys_mmap_start(struct thread_data* tdata, u_long addr, int len, int prot, int fd)
{
    struct mmap_info* mmi = &tdata->mmap_info_cache;
    mmi->addr = addr;
    mmi->length = len;
    mmi->prot = prot;
    mmi->fd = fd;
    tdata->save_syscall_info = (void *) mmi;
}

static void sys_mmap_stop(int rc)
{
    struct mmap_info* mmi = (struct mmap_info*) current_thread->save_syscall_info;
#ifdef MMAP_INPUTS
    // If global_syscall_cnt == 0, then handled in previous epoch
    if (rc != -1 && (mmi->fd != -1)) {
        fprintf(stderr, "mmap stop fd %d\n", mmi->fd);
        int read_fileno = -1;
        struct open_info* oi = NULL;
        char* channel_name = (char *) "--";

        if (monitor_has_fd(open_fds, mmi->fd)) {
            oi = (struct open_info *) monitor_get_fd_data(open_fds, mmi->fd);
            assert (oi);
            read_fileno = oi->fileno;
            channel_name = oi->name;
            fprintf(stderr, "mmap file name is %s, %d\n", channel_name, mmi->prot & PROT_EXEC);
        }
        if (!(mmi->prot & PROT_EXEC)) {
            struct taint_creation_info tci;
            tci.rg_id = current_thread->rg_id;
            tci.record_pid = current_thread->record_pid;
            tci.syscall_cnt = current_thread->syscall_cnt;
            tci.offset = 0;
            tci.fileno = read_fileno;
            tci.data = 0;

            fprintf(stderr, "mmap: call create taints from buffer %#lx, %d\n", (u_long) rc, mmi->length);
            create_taints_from_buffer ((void *) rc, mmi->length, &tci, tokens_fd,
                                        channel_name);
        } else {
            fprintf(stderr, "mmap is PROT_EXEC\n");
        }
    }
    current_thread->save_syscall_info = 0;
    SYSCALL_DEBUG (stderr, "sys_mmap_stop done\n");
#else
    // Need to at least clear these taints 
    clear_mem_taints (rc, mmi->length);
#endif
}

static inline void sys_write_start(struct thread_data* tdata, int fd, char* buf, int size)
{
    SYSCALL_DEBUG(stderr, "sys_write_start: fd = %d\n", fd);
    struct write_info* wi = &tdata->write_info_cache;
    wi->fd = fd;
    wi->buf = buf;
    tdata->save_syscall_info = (void *) wi;
}

static inline void sys_write_stop(int rc)
{
    struct write_info* wi = (struct write_info *) &current_thread->write_info_cache;
    int channel_fileno = -1;
    if (rc > 0) {
        struct taint_creation_info tci;
        SYSCALL_DEBUG (stderr, "write_stop: sucess write of size %d\n", rc);

        if (monitor_has_fd(open_fds, wi->fd)) {
            struct open_info* oi;
            oi = (struct open_info *) monitor_get_fd_data(open_fds, wi->fd);
            assert(oi);
            channel_fileno = oi->fileno;
        } else if (wi->fd == fileno(stdout)) {
            channel_fileno = FILENO_STDOUT;
        } else if (wi->fd == fileno(stderr)) {
            channel_fileno = FILENO_STDERR;
        } else if (wi->fd == fileno(stdin)) {
            channel_fileno = FILENO_STDIN;
        } else {
            channel_fileno = -1;
        }
        tci.type = 0;
        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
	if (!current_thread->syscall_in_progress) {
	    tci.syscall_cnt--; // Weird restart issue
	}
        tci.offset = 0;
        tci.fileno = channel_fileno;

        LOG_PRINT ("Output buffer result syscall %ld, %#lx\n", tci.syscall_cnt, (u_long) wi->buf);
        output_buffer_result (wi->buf, rc, &tci, outfd);
    }
}

static inline void sys_writev_start(struct thread_data* tdata, int fd, struct iovec* iov, int count)
{
    SYSCALL_DEBUG(stderr, "sys_writev_start: fd = %d\n", fd);
    struct writev_info* wvi;
    wvi = (struct writev_info *) &tdata->writev_info_cache;
    wvi->fd = fd;
    wvi->count = count;
    wvi->vi = iov;
    tdata->save_syscall_info = (void *) wvi;
}

static inline void sys_writev_stop(int rc)
{
    // If syscall cnt = 0, then write handled in previous epoch
    if (rc > 0) {
        struct taint_creation_info tci;
        struct writev_info* wvi = (struct writev_info *) &current_thread->writev_info_cache;
        int channel_fileno = -1;
        if (monitor_has_fd(open_fds, wvi->fd)) {
            struct open_info* oi;
            oi = (struct open_info *) monitor_get_fd_data(open_fds, wvi->fd);
            assert(oi);
            channel_fileno = oi->fileno;
        } if (monitor_has_fd(open_socks, wvi->fd)) {
            struct socket_info* si;
            si = (struct socket_info *) monitor_get_fd_data(open_socks, wvi->fd);
            channel_fileno = si->fileno;
        } else {
            channel_fileno = -1;
        }

        tci.type = 0;
        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
        tci.offset = 0;
        tci.fileno = channel_fileno;

        if (filter_x) {
            if (!monitor_has_fd(open_x_fds, wvi->fd)) {
                for (int i = 0; i < wvi->count; i++) {
                    struct iovec* vi = (wvi->vi + i);
                    output_buffer_result(vi->iov_base, vi->iov_len, &tci, outfd);
                    tci.offset += vi->iov_len;
                }
            }
        } else {
            for (int i = 0; i < wvi->count; i++) {
                struct iovec* vi = (wvi->vi + i);
                output_buffer_result(vi->iov_base, vi->iov_len, &tci, outfd);
                tci.offset += vi->iov_len;
            }
        }
    }
    memset(&current_thread->writev_info_cache, 0, sizeof(struct writev_info));
}

static void sys_socket_start (struct thread_data* tdata, int domain, int type, int protocol)
{
    struct socket_info* si = (struct socket_info*) malloc(sizeof(struct socket_info));
    if (si == NULL) {
	fprintf (stderr, "Unable to malloc socket info\n");
	assert (0);
    }
    si->call = SYS_SOCKET;
    si->domain = domain;
    si->type = type;
    si->protocol = protocol;
    si->fileno = -1; // will be set in connect/accept/bind
    si->ci = NULL;

    tdata->save_syscall_info = si;
}

static void sys_socket_stop(int rc)
{
    if (rc > 0) {
        struct socket_info* si = (struct socket_info *) current_thread->save_syscall_info;
        monitor_add_fd(open_socks, rc, 0, si);
        current_thread->save_syscall_info = NULL; // Giving si to the monitor
    }
}

static void sys_connect_start(thread_data* tdata, int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
    if (monitor_has_fd(open_socks, sockfd)) {
        struct socket_info* si = (struct socket_info*) monitor_get_fd_data(open_socks, sockfd);
        struct connect_info* ci = (struct connect_info *) malloc(sizeof(struct connect_info));
	if (ci == NULL) {
	    fprintf (stderr, "Unable to malloc connect_info\n");
	    assert (0);
	}
        memset(ci, 0, sizeof(struct connect_info));
        assert(si);

        ci->fd = sockfd;
        if (si->domain == AF_UNIX) {
            struct sockaddr_un* sun = (struct sockaddr_un*) addr;
            if (addr->sa_family == AF_UNIX) {
                memcpy(ci->path, sun->sun_path, 108); // apparently 108 is the magic number
            } else {
                //fprintf (stderr, "unknown sa_family %d is not AF_UNIX len is %d vs %d\n", addr->sa_family, addrlen, sizeof(struct sockaddr_un));
                memcpy(ci->path, "UNK", 4);
            }
        } else if (si->domain == AF_INET) {
            if (addr->sa_family == AF_INET || addrlen == sizeof(struct sockaddr_in)) {
                struct sockaddr_in* sin = (struct sockaddr_in*) addr;
                ci->port = htons(sin->sin_port);
                memcpy(&ci->sin_addr, &sin->sin_addr, sizeof(struct in_addr));
                //fprintf (stderr, "connect AF_INET port %d addr %x\n", ci->port, ci->sin_addr.s_addr);
            } else {
		//fprintf (stderr, "unknown sa_family %d is not AF_INET len is %d vs %d\n", addr->sa_family, addrlen, sizeof(struct sockaddr_in));
                ci->port = 0;
                memcpy(&ci->sin_addr, "UNK", 4);
            }
        } else if (si->domain == AF_INET6) {
            if (addr->sa_family == AF_INET6) {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*) addr;
                ci->port = htons(sin6->sin6_port);
                memcpy(&ci->sin_addr6, &sin6->sin6_addr, sizeof(struct in6_addr));
            } else {
                //fprintf (stderr, "unknown sa_family %d is not AF_INET6 len is %d vs %d\n", addr->sa_family, addrlen, sizeof(struct sockaddr_in6));
                ci->port = 0;
                memcpy(&ci->sin_addr6, "UNK", 4);
            }
        } else {
            fprintf(stderr, "unsupport socket family %d\n", si->domain);
            free(ci);
            return;
        }
        tdata->save_syscall_info = (void *) ci;
    }
}

static void sys_connect_stop(int rc)
{
    // successful connect
    if (!rc && current_thread->save_syscall_info) {
        struct connect_info* ci = (struct connect_info *) current_thread->save_syscall_info;
        struct socket_info* si = (struct socket_info *) monitor_get_fd_data(open_socks, ci->fd);
        char connect_info_name[256];
        if (!si) {
            fprintf(stderr, "could not find socket for connect %d\n", ci->fd);
            free(ci);
            current_thread->save_syscall_info = NULL;
            return;
        }
        //assert(si);
        if (filter_x) {
            if (si->domain == AF_UNIX) {
                char* c;
                c = ci->path;
                c += 1;
                if (strstr(ci->path, "tmp/.X11-unix/X") ||
                        strstr(c, "tmp/.X11-unix/X")) {
                    fprintf(stderr, "connect to X11, fd %d\n", ci->fd);
                    monitor_add_fd(open_x_fds, ci->fd, 0, 0);
                }
            } else if (si->domain == AF_INET) {
                struct in_addr ina;
                // X port is 6010, address is 127.0.0.1
                if (!inet_pton(AF_INET, "127.0.0.1", &ina)) { // create an address to check against
                    fprintf(stderr, "inet_pton failed?!\n");
                    assert(false);
                }
                fprintf(stderr, "connect to port %d\n", ci->port);
                if (ci->port == 6010 && ina.s_addr == ci->sin_addr.s_addr) {
                    monitor_add_fd(open_x_fds, ci->fd, 0, 0);
                    fprintf(stderr, "connect to X11 (over ssh forwarding)\n");
                }
            }
        }

        si->ci = ci;
        si->fileno = open_file_cnt;
        open_file_cnt++;
        create_connect_info_name(connect_info_name, si->domain, ci);
#ifdef OUTPUT_FILENAMES
        write_filename_mapping(filenames_f, si->fileno, connect_info_name);
#endif

        current_thread->save_syscall_info = NULL; // Socket_info owns this now
    }
}

static void sys_recv_start(thread_data* tdata, int fd, char* buf, int size) 
{
    // recv and read are similar so they can share the same info struct
    struct read_info* ri = (struct read_info*) &current_thread->read_info_cache;
    ri->fd = fd;
    ri->buf = buf;
    tdata->save_syscall_info = (void *) ri;
    LOG_PRINT ("recv on fd %d\n", fd);
}

static void sys_recv_stop(int rc) 
{
    struct read_info* ri = (struct read_info *) current_thread->save_syscall_info;
    LOG_PRINT ("Pid %d syscall recv returns %d\n", PIN_GetPid(), rc);
    SYSCALL_DEBUG (stderr, "Pid %d syscall recv returns %d\n", PIN_GetPid(), rc);

    // If syscall cnt = 0, then write handled in previous epoch
    if (rc > 0) {
        struct taint_creation_info tci;
        char* channel_name = (char *) "--";
        int read_fileno = -1;
        if(ri->fd == fileno(stdin)) {
            read_fileno = 0;
            channel_name = (char *) "stdin";
        } else if (monitor_has_fd(open_socks, ri->fd)) {
            struct socket_info* si;
            si = (struct socket_info *) monitor_get_fd_data(open_socks, ri->fd);
            read_fileno = si->fileno;
            // FIXME
	    if (si->domain == AF_INET || si->domain == AF_INET6) {
		channel_name = (char *) "inetsocket";
		//fprintf (stderr, "Recv inet rc %d from fd %d at clock %lu\n", rc, ri->fd, *ppthread_log_clock);
	    } else {
		channel_name = (char *) "recvsocket";
	    }
        }

        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
        tci.offset = 0;
        tci.fileno = read_fileno;
        tci.data = 0;

        LOG_PRINT ("Create taints from buffer sized %d at location %#lx\n",
                        rc, (unsigned long) ri->buf);
        create_taints_from_buffer(ri->buf, rc, &tci, tokens_fd, channel_name);

#ifdef LINKAGE_FDTRACK
        if (is_fd_tainted(ri->fd)) {
            taint_fd2mem((u_long) ri->buf, rc, ri->fd);
        }
#endif

    }
    SYSCALL_DEBUG (stderr, "recv_done\n");
    current_thread->save_syscall_info = 0;
}

static void sys_recvmsg_start(struct thread_data* tdata, int fd, struct msghdr* msg, int flags) 
{
    struct recvmsg_info* rmi;
    rmi = (struct recvmsg_info *) malloc(sizeof(struct recvmsg_info));
    if (rmi == NULL) {
	fprintf (stderr, "Unable to malloc recvmsg_info\n");
	assert (0);
    }
    rmi->fd = fd;
    rmi->msg = msg;
    rmi->flags = flags;

    tdata->save_syscall_info = (void *) rmi;
}

static void sys_recvmsg_stop(int rc) 
{
    struct recvmsg_info* rmi = (struct recvmsg_info *) current_thread->save_syscall_info;

    // If syscall cnt = 0, then write handled in previous epoch
    if (rc > 0) {
        struct taint_creation_info tci;
        char* channel_name = (char *) "recvmsgsocket";
        u_int i;
        int read_fileno = -1;
        if (monitor_has_fd(open_socks, rmi->fd)) {
            struct socket_info* si;
            si = (struct socket_info *) monitor_get_fd_data(open_socks, rmi->fd);
            read_fileno = si->fileno;
        } else {
            read_fileno = -1;
        }

        //fprintf (stderr, "rcvmsg_stop from channel: %s\n", channel_name);
        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
        tci.offset = 0;
        tci.fileno = read_fileno;
        tci.data = 0;

        for (i = 0; i < rmi->msg->msg_iovlen; i++) {
            struct iovec* vi = (rmi->msg->msg_iov + i);
            // TODO support filtering on certain sockets
            LOG_PRINT ("Create taints from buffer sized %d at location %#lx\n",
                        vi->iov_len, (unsigned long) vi->iov_base);
            create_taints_from_buffer(vi->iov_base, vi->iov_len, &tci, tokens_fd,
                                        channel_name);
            tci.offset += vi->iov_len;
        }
    }
    SYSCALL_DEBUG (stderr, "recvmsg_stop done\n");
    free(rmi);
}

static void sys_sendmsg_start(struct thread_data* tdata, int fd, struct msghdr* msg, int flags)
{
    struct sendmsg_info* smi;
    smi = (struct sendmsg_info *) malloc(sizeof(struct sendmsg_info));
    if (smi == NULL) {
	fprintf (stderr, "Unable to malloc sendmsg_info\n");
	assert (0);
    }
    smi->fd = fd;
    smi->msg = msg;
    smi->flags = flags;

    tdata->save_syscall_info = (void *) smi;
}

static void sys_sendmsg_stop(int rc)
{
    u_int i;
    struct sendmsg_info* smi = (struct sendmsg_info *) current_thread->save_syscall_info;
    int channel_fileno = -1;

    // If syscall cnt = 0, then write handled in previous epoch
    if (rc > 0) {
        struct taint_creation_info tci;
        SYSCALL_DEBUG (stderr, "sendmsg_stop: sucess sendmsg of size %d\n", rc);
        if (monitor_has_fd(open_socks, smi->fd)) {
            struct socket_info* si;
            si = (struct socket_info *) monitor_get_fd_data(open_socks, smi->fd);
            channel_fileno = si->fileno;
        } else {
            channel_fileno = -1;
        }

        tci.type = 0;
        tci.rg_id = current_thread->rg_id;
        tci.record_pid = current_thread->record_pid;
        tci.syscall_cnt = current_thread->syscall_cnt;
        tci.offset = 0;
        tci.fileno = channel_fileno;

        for (i = 0; i < smi->msg->msg_iovlen; i++) {
            struct iovec* vi = (smi->msg->msg_iov + i);
            output_buffer_result(vi->iov_base, vi->iov_len, &tci, outfd);
            tci.offset += vi->iov_len;
        }
    }
    SYSCALL_DEBUG (stderr, "sys_sendmsg_stop done\n");
    free(smi);
}

void syscall_start(struct thread_data* tdata, int sysnum, ADDRINT syscallarg0, ADDRINT syscallarg1,
		   ADDRINT syscallarg2, ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5)
{
    switch (sysnum) {
        case SYS_open:
            sys_open_start(tdata, (char *) syscallarg0, (int) syscallarg1);
            break;
        case SYS_close:
            sys_close_start(tdata, (int) syscallarg0); 
            break;
        case SYS_read:
	    sys_read_start(tdata, (int) syscallarg0, (char *) syscallarg1, (int) syscallarg2);
            break;
        case SYS_write:
        case SYS_pwrite64:
            sys_write_start(tdata, (int) syscallarg0, (char *) syscallarg1, (int) syscallarg2);
            break;
        case SYS_writev:
            sys_writev_start(tdata, (int) syscallarg0, (struct iovec *) syscallarg1, (int) syscallarg2);
            break;
        case SYS_pread64:
            sys_pread_start(tdata, (int) syscallarg0, (char *) syscallarg1, (int) syscallarg2);
            break;
#ifdef LINKAGE_FDTRACK
        case SYS_select:
        case 142:
            sys_select_start(tdata, (int) syscallarg0, (fd_set *) syscallarg1, (fd_set *) syscallarg2,
			     (fd_set *) syscallarg3, (struct timeval *) syscallarg4);
            break;
#endif
        case SYS_socketcall:
        {
            int call = (int) syscallarg0;
            unsigned long *args = (unsigned long *)syscallarg1;
            current_thread->socketcall = call;
            switch (call) {
                case SYS_SOCKET:
                    SYSCALL_DEBUG(stderr, "socket_start\n");
                    sys_socket_start(tdata, (int)args[0], (int)args[1], (int)args[2]);
                    break;
                case SYS_CONNECT:
                    SYSCALL_DEBUG(stderr, "connect_start\n");
                    sys_connect_start(tdata, (int)args[0], (struct sockaddr *)args[1], (socklen_t)args[2]);
                    break;
                case SYS_RECV:
                case SYS_RECVFROM:
                    SYSCALL_DEBUG(stderr, "recv_start\n");
                    sys_recv_start(tdata, (int)args[0], (char *)args[1], (int)args[2]);
                    break;
                case SYS_RECVMSG:
                    SYSCALL_DEBUG(stderr, "recvmsg_start\n");
                    sys_recvmsg_start(tdata, (int)args[0], (struct msghdr *)args[1], (int)args[2]);
                    break;
                case SYS_SENDMSG:
                    SYSCALL_DEBUG(stderr, "sendmsg_start\n");
                    sys_sendmsg_start(tdata, (int)args[0], (struct msghdr *)args[1], (int)args[2]);
                    break;
                default:
                    break;
            }
            break;
        }
        case SYS_mmap:
        case SYS_mmap2:
            sys_mmap_start(tdata, (u_long)syscallarg0, (int)syscallarg1, (int)syscallarg2, (int)syscallarg4);
            break;
    }
}

void syscall_end(int sysnum, ADDRINT ret_value)
{
    int rc = (int) ret_value;
    switch(sysnum) {
        case SYS_clone:
            SYSCALL_DEBUG(stderr, "%d clone done\n", PIN_GetPid());
            break;
        case SYS_open:
            sys_open_stop(rc);
            break;
        case SYS_close:
            sys_close_stop(rc);
            break;
        case SYS_read:
            sys_read_stop(rc);
            break;
        case SYS_write:
        case SYS_pwrite64:
            sys_write_stop(rc);
            break;
        case SYS_writev:
            sys_writev_stop(rc);
            break;
        case SYS_pread64:
            sys_pread_stop(rc);
            break;
#ifdef LINKAGE_FDTRACK
        case SYS_select:
        case 142:
            sys_select_stop(rc);
            break;
#endif
        case SYS_mmap:
        case SYS_mmap2:
            sys_mmap_stop(rc);
            break;
        case SYS_socketcall:
        {
            switch (current_thread->socketcall) {
                case SYS_SOCKET:
                    sys_socket_stop(rc);
                    break;
                case SYS_CONNECT:
                    sys_connect_stop(rc);
                    break;
                case SYS_RECV:
                case SYS_RECVFROM:
                    sys_recv_stop(rc);
                    break;
                case SYS_RECVMSG:
                    sys_recvmsg_stop(rc);
		    break;
                case SYS_SENDMSG:
                    sys_sendmsg_stop(rc);
                    break;
                default:
                    break;
            }
            current_thread->socketcall = 0;
            break;
        }
    }
}

// called before every application system call
void instrument_syscall(ADDRINT syscall_num, 
			ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2,
			ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5)
{   
    int sysnum = (int) syscall_num;

    // Because of Pin restart issues, this function alone has to use PIN thread-specific data
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    tdata->sysnum = sysnum;
    tdata->syscall_in_progress = true;
#ifdef TAINT_DEBUG
    fprintf (debug_f, "Thread %d sees sysnum %d in progress\n", tdata->record_pid, sysnum);
    if (current_thread != tdata) fprintf (debug_f, "current thread %d tdata %d\n", current_thread->record_pid, tdata->record_pid);
#endif

    if (sysnum == 31) {
	tdata->ignore_flag = (u_long) syscallarg1;
    }
    if (sysnum == 45 || sysnum == 91 || sysnum == 120 || sysnum == 125 || 
	sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
	check_clock_before_syscall (dev_fd, (int) syscall_num);
    }
    if (sysnum == 252) dift_done();

    if (segment_length && *ppthread_log_clock >= segment_length) {
	// Done with this replay - do exit stuff now because we may not get clean unwind
#ifdef TAINT_DEBUG
	fprintf (debug_f, "Pin terminating at Pid %d, entry to syscall %ld, term. clock %ld cur. clock %ld\n", PIN_GetPid(), global_syscall_cnt, segment_length, *ppthread_log_clock);
#endif
	dift_done ();
	try_to_exit(dev_fd, PIN_GetPid());
        PIN_ExitApplication(0);  //not working? 
    }
	
    syscall_start(tdata, sysnum, syscallarg0, syscallarg1, syscallarg2, 
		  syscallarg3, syscallarg4, syscallarg5);
    
    tdata->app_syscall = syscall_num;
}

void syscall_after (ADDRINT ip)
{
    if (current_thread->app_syscall == 999) {
	check_clock_after_syscall (dev_fd);
	current_thread->app_syscall = 0;  
    }
}

void instrument_syscall_ret(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    if (current_thread->app_syscall != 999) current_thread->app_syscall = 0;

    ADDRINT ret_value = PIN_GetSyscallReturn(ctxt, std);
    if (current_thread->sysnum == SYS_gettid) {
	// Pin "helpfully" changes the return value to the replay tid - change it back here
	//printf ("eax is %d changing to %d\n", PIN_GetContextReg (ctxt, LEVEL_BASE::REG_EAX), current_thread->record_pid);
	PIN_SetContextReg (ctxt, LEVEL_BASE::REG_EAX, current_thread->record_pid);
    }

    if (segment_length && *ppthread_log_clock > segment_length) {
#ifdef TAINT_DEBUG
	fprintf (debug_f, "Skip Pid %d, exit from syscall %ld due to termination, term. clock %ld cur. clock %ld\n", PIN_GetPid(), global_syscall_cnt, segment_length, *ppthread_log_clock);
#endif
    } else {
	syscall_end(current_thread->sysnum, ret_value);
    }

    if (!current_thread->syscall_in_progress) {
	/* Pin restart oddity: initial write will nondeterministically return twice (once with rc=0).
	   Just don't increment the global syscall cnt when this happens. */
	if (global_syscall_cnt == 0) {
	    if (current_thread->sysnum != SYS_write) {
#ifdef TAINT_DEBUG
		fprintf (debug_f, "First syscall %d not in progress and not write\n", current_thread->sysnum);
#endif
	    }
	} else {
#ifdef TAINT_DEBUG
	  fprintf (debug_f, "Syscall not in progress for global_syscall_cnt %ld sysnum %d thread %d\n", global_syscall_cnt, current_thread->sysnum, current_thread->record_pid);
	  struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
	  fprintf (debug_f, "tdata is %p current_thread is %p\n", tdata, current_thread);
#endif
	}
    } else {
	// reset the syscall number after returning from system call
	increment_syscall_cnt (current_thread->sysnum);
	current_thread->syscall_in_progress = false;
    }

    // The first syscall returns twice 
    if (global_syscall_cnt > 1) { 
	current_thread->sysnum = 0;
    }
}

void track_inst(INS ins, void* data) 
{
    if(INS_IsSyscall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_syscall),
                IARG_SYSCALL_NUMBER, 
                IARG_SYSARG_VALUE, 0, 
                IARG_SYSARG_VALUE, 1,
                IARG_SYSARG_VALUE, 2,
                IARG_SYSARG_VALUE, 3,
                IARG_SYSARG_VALUE, 4,
                IARG_SYSARG_VALUE, 5,
                IARG_END);
    }
}

#ifdef HEARTBLEED
void bad_memcpy(ADDRINT dst, ADDRINT src, ADDRINT len) {

    if (bad_memcpy_flag) {
        int rc;
        struct memcpy_header header;

        header.dst = dst;
        header.src = src;
        header.len = len;
        rc = write(heartbleed_fd, &header, sizeof(header));
        if (rc != sizeof(header)) {
            assert(0);
        }
        for (int i = 0; i < (int)len; i++) {
            taint_t* t;
            t = get_mem_taints(src + i, 1);
            if (t) {
                rc = write(heartbleed_fd, t, sizeof(taint_t));
                if (rc != sizeof(taint_t)) {
                    assert(0);
                }
            } else {
                taint_t value = 0;
                rc = write(heartbleed_fd, &value, sizeof(taint_t));
                if (rc != sizeof(taint_t)) {
                    assert(0);
                }
            }
        }
        bad_memcpy_flag = 0;
    }
}
#endif

/* Interpose on top this X function and check the taints for certain coordinates */
void trace_x_xputimage_start(ADDRINT dest_x, ADDRINT dest_y, ADDRINT w_ref, ADDRINT h_ref)
{
    PRINTX (stderr, "[TRACEX] xputimage (%d, %d)\n", (int) dest_x, (int) dest_y);
    // output x, y coords with taint
    output_xcoords(xoutput_fd, current_thread->syscall_cnt,
            (int) dest_x, (int) dest_y, w_ref);
    output_xcoords(xoutput_fd, current_thread->syscall_cnt,
            (int) dest_x, (int) dest_y, h_ref);
}

void trace_x_cairo_show_glyphs_start(ADDRINT cairo_context, ADDRINT array_glyphs, ADDRINT num_glyphs)
{
    int numglyphs = (int) num_glyphs;
    PRINTX (stderr, "[TRACEX] cairo_show_glyphs, num glyphs %d\n", (int) num_glyphs);
    // size of a glyph is 20
    for (int i = 0; i < numglyphs; i++) {
        for (unsigned j = 0; j < sizeof(cairo_glyph_t); j++) {
            u_long mem_loc = array_glyphs + (i * sizeof(cairo_glyph_t)) + j;
            output_xcoords(xoutput_fd, current_thread->syscall_cnt, -1, -1, mem_loc);
        }
    }
}

void trace_x_cairo_scaled_font_show_glyphs(ADDRINT array_glyphs, ADDRINT num_glyphs)
{
    int numglyphs = (int) num_glyphs;
    PRINTX (stderr, "[TRACEX] cairo_scaled_font_show_glyphs, num glyphs %d\n", (int) num_glyphs);
    // size of a glyph is 20
    for (int i = 0; i < numglyphs; i++) {
        for (int j = 0; j < 20; j++) {
            u_long mem_loc = array_glyphs + (i * 20) + j;
            output_xcoords(xoutput_fd, current_thread->syscall_cnt, -1, -1, mem_loc);
        }
    }
}

void trace_x_xrendercompositetext(ADDRINT dst_x, ADDRINT dst_y, ADDRINT ptr, ADDRINT len)
{
    PRINTX (stderr, "[TRACEX] xrendercompositetext (%d,%d)\n", (int) dst_x, (int) dst_y);
    for (int i = 0; i < (int)len; i++) {
        for (int j = 0; j < 16; j++) { 
            // _XGlyphElt8 is a minimum of 17 bytes, not sure about padding etc, 
            // but we'll say 16 for now, since we're just fishing for taints
            u_long mem_loc = ptr + (i * 16) + j;
            output_xcoords(xoutput_fd, current_thread->syscall_cnt,
                            (int) dst_x, (int) dst_y, mem_loc);
        }
    }
}

void string_inspect(ADDRINT ptr)
{
    fprintf(stderr,  "[TRACEX] string_inspect at %#x\n", ptr);
    for (int i = 0; i < (int)24; i++) {
            u_long mem_loc = ptr + i;
            output_xcoords(xoutput_fd, current_thread->syscall_cnt, 0, 0, mem_loc);
    }
}

void track_trace(TRACE trace, void* data)
{
    // System calls automatically end a Pin trace.
    // So we can instrument every trace (instead of every instruction) to check to see if
    // the beginning of the trace is the first instruction after a system call.
    TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_END);
}

void track_function(RTN rtn, void* v)
{
    RTN_Open(rtn);
    const char* name = RTN_Name(rtn).c_str();
    if (trace_x) {
        /* Note this does not work, if you don't have debug symbols
         * compiled into your library/binary */
        if (!strcmp(name, "XPutImage")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE,
                    (AFUNPTR)trace_x_xputimage_start,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
                    IARG_FUNCARG_ENTRYPOINT_REFERENCE, 8,
                    IARG_FUNCARG_ENTRYPOINT_REFERENCE, 9,
                    IARG_END);
        } else if (!strcmp(name, "_moz_cairo_show_glyphs") || 
                !strcmp(name, "cairo_show_glyphs")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE,
                    (AFUNPTR)trace_x_cairo_show_glyphs_start,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_END);
        } 
        else if (!strcmp(name, "_moz_cairo_glyph_extents") ||
                (!strcmp(name, "cairo_glyph_extents"))){
            RTN_InsertCall(rtn, IPOINT_BEFORE,
                    (AFUNPTR)trace_x_cairo_show_glyphs_start,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_END);
        }
        else if (!strcmp(name, "_moz_cairo_scaled_font_glyph_extents") ||
                strstr(name, "_cairo_scaled_font_glyph_device_extents")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, 
                    (AFUNPTR)trace_x_cairo_show_glyphs_start,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_END);
        }
        else if (strstr(name, "_cairo_scaled_font_show_glyphs")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE,
                    (AFUNPTR)trace_x_cairo_scaled_font_show_glyphs,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 11,
                    IARG_END);
        }
        else if (!strcmp(name, "XRenderCompositeText8")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE,
                    (AFUNPTR)trace_x_xrendercompositetext,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 7,   // dst x coord
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 8,   // dst y coord
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 9,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 10,
                    IARG_END);
        }
        else if (strstr(name, "Html5") && strstr(name, "AppendText")) {
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)string_inspect,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_END);
        }
    }

#ifdef HEARTBLEED
    if (strstr(name, "memcpy")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)bad_memcpy,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_END);
    }
    if (strstr(name, "dtls1_process_heartbeat") || strstr(name, "tls1_process_heartbeat")) {
        fprintf(stderr, "instrument process heartbeat\n");
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)instrument_before_badmemcpy, IARG_END);
    }
#endif
    RTN_Close(rtn);
}

int get_record_pid()
{
    //calling kernel for this replay thread's record log
    int record_log_id;

    record_log_id = get_log_id (dev_fd);
    if (record_log_id == -1) {
        int pid = PIN_GetPid();
        fprintf(stderr, "Could not get the record pid from kernel, pid is %d\n", pid);
        return pid;
    }
    return record_log_id;
}

void instrument_taint_reg2reg(INS ins, REG dstreg, REG srcreg, int extend);
void instrument_taint_reg2mem(INS ins, REG srcreg, int extend);
void instrument_taint_mem2reg(INS ins, REG dstreg, int extend);
void instrument_taint_mem2mem(INS ins, int extend);

void instrument_taint_add_reg2reg(INS ins, REG dstreg, REG srcreg);
void instrument_taint_add_reg2mem(INS ins, REG srcreg);
void instrument_taint_add_mem2reg(INS ins, REG dstreg);
void instrument_taint_add_mem2mem(INS ins);

// predicated instrumentation
void pred_instrument_taint_reg2reg(INS ins, REG dstreg, REG srcreg, int extend);
void pred_instrument_taint_reg2mem(INS ins, REG srcreg, int extend);
void pred_instrument_taint_mem2reg(INS ins, REG dstreg, int extend);
void pred_instrument_taint_mem2mem(INS ins, int extend);

void pred_instrument_taint_add_reg2reg(INS ins, REG dstreg, REG srcreg);
void pred_instrument_taint_add_reg2mem(INS ins, REG srcreg);
void pred_instrument_taint_add_mem2reg(INS ins, REG dstreg);
void pred_instrument_taint_add_mem2mem(INS ins);

void instrument_taint_immval2mem(INS ins);
void pred_instrument_taint_immval2mem(INS ins);

void instrument_clear_dst(INS ins);
void instrument_clear_reg(INS ins, REG reg);

// Trivial analysis routine to pass its argument back in an IfCall 
// so that we can use it to control the next piece of instrumentation.
static ADDRINT returnArg (BOOL arg)
{
    return arg;
}

/* Add instrumentation to taint from src reg to dst reg before 
 * instruction INS.
 *
 * This function handles mismatched sized registers
 * */
void instrument_taint_reg2reg(INS ins, REG dstreg, REG srcreg, int extend)
{
    int dst_treg;
    int src_treg;
    UINT32 dst_regsize;
    UINT32 src_regsize;

    if (dstreg == srcreg) {
        return;
    }

    dst_treg = translate_reg((int)dstreg);
    src_treg = translate_reg((int)srcreg);
    dst_regsize = REG_Size(dstreg);
    src_regsize = REG_Size(srcreg);

    if (dst_regsize == src_regsize) {
        switch(dst_regsize) {
            case 1:
                if (REG_is_Lower8(dstreg) && REG_is_Lower8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_lbreg2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                } else if (REG_is_Lower8(dstreg) && REG_is_Upper8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_UBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_ubreg2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                } else if (REG_is_Upper8(dstreg) && REG_is_Lower8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2UBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_lbreg2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                } else if (REG_is_Upper8(dstreg) && REG_is_Upper8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_UBREG2UBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_ubreg2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_HWREG2HWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_WREG2WREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_WREG2WREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_DWREG2DWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_dwreg2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_QWREG2QWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_qwreg2qwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else if (dst_regsize > src_regsize) {
        if (extend) {
            switch(src_regsize) {
                case 1:
                    if (REG_is_Lower8(srcreg)) {
                        switch(dst_regsize) {
                            case 2:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_LBREG2HWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_lbreg2hwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 4:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_LBREG2WREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_lbreg2wreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 8:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_LBREG2DWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_lbreg2dwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 16:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_LBREG2QWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_lbreg2qwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            default:
                                assert(0);
                                break;
                        }
                    } else if (REG_is_Upper8(srcreg)) {
                        switch(dst_regsize) {
                            case 2:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_UBREG2HWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_ubreg2hwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 4:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_UBREG2WREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_ubreg2wreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 8:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_UBREG2DWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_ubreg2dwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 16:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_UBREG2QWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_ubreg2qwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            default:
                                assert(0);
                                break;
                        }
                    } else {
                        assert(0);
                    }
                    break;
                case 2:
                    switch(dst_regsize) {
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWREG2WREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_hwreg2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWREG2DWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_hwreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_hwreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 4:
                    switch(dst_regsize) {
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_WREG2DWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_wreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_WREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_wreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_WREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 8:
                    switch(dst_regsize) {
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_DWREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_dwreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 16:
                    assert(0);
                    break;
                default:
                    assert(0);
                    break;
            }
        } else {
            switch(src_regsize) {
                case 1:
                    if (REG_is_Lower8(srcreg)) {
                        switch(dst_regsize) {
                            case 2:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_LBREG2HWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_lbreg2hwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 4:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_LBREG2WREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_lbreg2wreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 8:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_LBREG2DWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_lbreg2dwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 16:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_LBREG2QWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_lbreg2qwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            default:
                                assert(0);
                                break;
                        }
                    } else if (REG_is_Upper8(srcreg)) {
                        switch(dst_regsize) {
                            case 2:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_UBREG2HWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_ubreg2hwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 4:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_UBREG2WREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_ubreg2wreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 8:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_UBREG2DWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_ubreg2dwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 16:
#ifdef TRACE_TAINT_OPS
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_UBREG2QWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_ubreg2qwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            default:
                                assert(0);
                                break;
                        }
                    } else {
                        assert(0);
                    }
                    break;
                case 2:
                    switch(dst_regsize) {
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWREG2WREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_hwreg2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWREG2DWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_hwreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_hwreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 4:
                    switch(dst_regsize) {
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_WREG2DWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_wreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_WREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_wreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 8:
                    switch(dst_regsize) {
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_DWREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_dwreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 16:
                    assert(0);
                    break;
                default:
                    assert(0);
                    break;
            }
        }
    } else {
        // src_regsize > dst_regsize
        switch (dst_regsize) {
            case 1:
                assert(src_regsize >= 1);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_LBREG2LBREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_lbreg2lbreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 2:
                assert(src_regsize >= 2);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2HWREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 4:
                assert(src_regsize >= 4);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2WREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 8:
                assert(src_regsize >= 8);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2DWREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_dwreg2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 16:
                assert(src_regsize >= 16);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_QWREG2QWREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_qwreg2qwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            default:
                fprintf(stderr, "instrument_reg2reg dst reg size is %u, src reg size is %u\n",
                    dst_regsize, src_regsize);
                assert(0);
                break;
        }
    }
}

void instrument_taint_reg2mem(INS ins, REG reg, int extend)
{
    int treg = translate_reg((int)reg);
    UINT32 regsize = REG_Size(reg);
    UINT32 memsize = INS_MemoryWriteSize(ins);

    if (regsize == memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_lbreg2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(reg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_UBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_ubreg2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_dwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        //IARG_UINT32, find_static_address(INS_Address(ins)),
                        IARG_UINT32, TAINT_QWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_qwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        //IARG_UINT32, find_static_address(INS_Address(ins)),
                        IARG_UINT32, TAINT_QWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
        }
    } else if (regsize < memsize) {
        if (extend) {
            switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2HWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2hwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2WMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_lbreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2DWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2dwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2QWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2qwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else if (REG_is_Upper8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2HWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2hwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2WMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2wmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2DWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2dwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2QWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2qwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
                switch(memsize) {
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(memsize) {
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_WREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_wreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_WREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_wreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(memsize) {
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_DWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_dwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 16:
                fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                assert(0);
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
            }
        } else {
            switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2HWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2hwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else if (REG_is_Upper8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2HWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2hwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
                switch(memsize) {
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(memsize) {
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_WREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_wreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_WREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_wreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(memsize) {
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_DWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_dwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 16:
                fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                assert(0);
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
            }
        } 
    } else {
        // regsize if greater than mem, just move the lower memsize bits
        // of the register to memory
        switch(memsize) {
            case 1:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_LBREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_lbreg2mem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_LBREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_dwreg2mem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                break;
            default:
                INSTRUMENT_PRINT (log_f, "Instruction: %s\n", INS_Disassemble(ins).c_str());
                INSTRUMENT_PRINT (log_f, "memsize %d, regsize %d\n", memsize, regsize);
                assert(0);
                break;
        }
    }
}

void instrument_taint_mem2reg(INS ins, REG dstreg, int extend)
{
    int treg = translate_reg((int)dstreg);
    UINT32 regsize = REG_Size(dstreg);
    UINT32 memsize = INS_MemoryWriteSize(ins);

    if (regsize == memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(dstreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2LBREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_mem2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2LBREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(dstreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2UBREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_mem2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2UBREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                } else {
                    assert(0);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2HWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2HWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2WREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2WREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2DWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2DWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2QWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2qwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2QWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                break;
            default:
                assert(0);
                break;
        }
    } else if (regsize > memsize) {
        if (extend) {
            // dst is greater than reg, must extend
            switch(memsize) {
                case 1:
                    switch(regsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_BMEM2HWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_bmem2hwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_BMEM2WREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_bmem2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_BMEM2WREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_BMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_bmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_BMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_bmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 2:
                    switch(regsize) {
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWMEM2WREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_hwmem2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_hwmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_hwmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 4:
                    switch(regsize) {
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_WMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_wmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_WMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_wmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 8:
                    switch(regsize) {
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_DWMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_dwmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 16:
                    assert(0);
                    break;
                default:
                    assert(0);
                    break;
            }
        } else {
            switch(memsize) {
                case 1:
                    switch(regsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_BMEM2HWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_bmem2hwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_BMEM2WREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_bmem2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_BMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_bmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_BMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_bmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 2:
                    switch(regsize) {
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWMEM2WREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_hwmem2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_hwmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_hwmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 4:
                    switch(regsize) {
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_WMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_wmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_WMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_wmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 8:
                    switch(regsize) {
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_DWMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_dwmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 16:
                    assert(0);
                    break;
                default:
                    assert(0);
                    break;
            }
        }

    }
}

void instrument_taint_mem2mem(INS ins, int extend)
{
    UINT32 dst_memsize = INS_MemoryWriteSize(ins);
    UINT32 src_memsize = INS_MemoryReadSize(ins);

    assert(dst_memsize == src_memsize);

    switch (dst_memsize) {
        case 1:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_b),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
        case 2:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_hw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       case 4:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_W,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_w),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_W,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       case 8:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_DW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_dw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_DW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       case 16:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_QW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_qw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_QW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       default:
            assert(0);
            break;
    }
}

void instrument_taint_add_reg2reg(INS ins, REG dstreg, REG srcreg)
{
    int dst_treg;
    int src_treg;
    UINT32 dst_regsize;
    UINT32 src_regsize;

    if (dstreg == srcreg) {
        return;
    }

    dst_treg = translate_reg((int)dstreg);
    src_treg = translate_reg((int)srcreg);

    dst_regsize = REG_Size(dstreg);
    src_regsize = REG_Size(srcreg);

    if (dst_regsize == src_regsize) {
        switch(dst_regsize) {
            case 1:
                if (REG_is_Lower8(dstreg) && REG_is_Lower8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_lbreg2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                } else if (REG_is_Lower8(dstreg) && REG_is_Upper8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2UBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_lbreg2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2UBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(dstreg) && REG_is_Lower8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_UBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_ubreg2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_UBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(dstreg) && REG_is_Upper8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_ubreg2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_UBREG2UBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_HWREG2HWREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_hwreg2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_HWREG2HWREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2WREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_wreg2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2WREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_DWREG2DWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_dwreg2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_DWREG2DWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_QWREG2QWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_qwreg2qwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_QWREG2QWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                break;
            default:
                assert(0);
                break;
        }
    } else if (dst_regsize > src_regsize) {
        switch(src_regsize) {
            case 1:
                if (REG_is_Lower8(srcreg)) {
                    switch(dst_regsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2HWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2hwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2HWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                        case 4:
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 8:
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                } else if (REG_is_Upper8(srcreg)) {
                    switch(dst_regsize) {
                        case 2:
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2hwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 4:
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 8:
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                } else {
                    assert(0);
                }
                break;
            case 2:
                switch(dst_regsize) {
                    case 4:
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    case 8:
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    case 16:
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(dst_regsize) {
                    case 8:
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_wreg2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    case 16:
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_wreg2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "taint_add_reg2reg, src reg size: %d, dst reg size %d\n",
                                src_regsize, dst_regsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(dst_regsize) {
                    case 16:
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_dwreg2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 16:
                assert(0);
                break;
            default:
                break;
        }
    } else if (dst_regsize < src_regsize) {
        switch(dst_regsize) {
            case 1:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_lbreg2lbreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 2:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_hwreg2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_wreg2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 8:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_dwreg2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else {
        // should not get here
        fprintf(stderr, "instrument_taint_add_reg2reg, dst_regsize: %d, src_regsize: %d\n",
                dst_regsize, src_regsize);
        assert(0);
    }
}

void instrument_taint_add_reg2mem(INS ins, REG srcreg)
{
    int treg = translate_reg((int)srcreg);
    UINT32 regsize = REG_Size(srcreg);
    UINT32 memsize;
    IARG_TYPE mem_ea;

    if (INS_IsMemoryRead(ins)) {
        mem_ea = IARG_MEMORYREAD_EA;
        memsize = INS_MemoryReadSize(ins);
    } else if (INS_IsMemoryWrite(ins)) {
        mem_ea = IARG_MEMORYWRITE_EA;
        memsize = INS_MemoryWriteSize(ins);
    } else {
        assert(0);
    }

    if (regsize == memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2MEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_lbreg2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2MEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_UBREG2MEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_ubreg2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_UBREG2MEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2MEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_hwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_HWREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_WREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_wreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_WREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_DWREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_dwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_DWREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_QWREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_qwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_QWREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                break;
        }
    } else if (regsize < memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(srcreg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2HWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2hwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2HWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2WMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2wmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2WMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2DWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2dwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2QWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        case 16:
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2qwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2QWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            break;
                    }
                } else if (REG_is_Upper8(srcreg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2HWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2hwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2HWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2WMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2wmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2WMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2DWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2dwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2DWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2QWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2qwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2QWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            break;
                    }
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
                switch(memsize) {
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2WMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2WMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2DWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2DWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(memsize) {
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2DWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_wreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2DWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_wreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(memsize) {
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_DWREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_dwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_DWREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 16:
                fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                assert(0);
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
        }
    } else if (regsize > memsize) {
        switch(memsize) {
            case 1:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_lbreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 2:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_hwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_wreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 8:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_dwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else {
        assert(0);
    }
}

void instrument_taint_add_mem2reg(INS ins, REG dstreg)
{
    int treg = translate_reg((int)dstreg);
    UINT32 regsize = REG_Size(dstreg);
    UINT32 memsize = INS_MemoryWriteSize(ins);

    if (regsize == memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(dstreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_BMEM2LBREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_bmem2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, treg,
                            IARG_END);
                } else if (REG_is_Upper8(dstreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_BMEM2UBREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_bmem2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, treg,
                            IARG_END);
                } else {
                    assert(0);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_HWMEM2HWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_hwmem2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_WMEM2WREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_wmem2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_DWMEM2DWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_dwmem2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_QWMEM2QWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_qwmem2qwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else if (regsize > memsize) {
        // dst is greater than reg, must extend
        switch(memsize) {
            case 1:
                switch(regsize) {
                    case 2:
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_bmem2hwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op_enter),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_ADD_BMEM2WREG,
                                IARG_UINT32, treg,
                                IARG_MEMORYREAD_EA,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_bmem2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op_exit),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_ADD_BMEM2WREG,
                                IARG_UINT32, treg,
                                IARG_MEMORYREAD_EA,
                                IARG_END);
#endif
                        break;
                    case 8:
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_bmem2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_bmem2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 2:
                switch(regsize) {
                    case 4:
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_hwmem2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 8:
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_hwmem2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_hwmem2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(regsize) {
                    case 8:
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_wmem2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_wmem2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(regsize) {
                    case 16:
                        INS_InsertCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_dwmem2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 16:
                assert(0);
                break;
            default:
                assert(0);
                break;
        }
    } else {
        assert(0);
    }
}

void instrument_taint_add_mem2mem(INS ins)
{
    UINT32 dst_memsize = INS_MemoryWriteSize(ins);
    UINT32 src_memsize = INS_MemoryReadSize(ins);

    assert(dst_memsize == src_memsize);

    switch (dst_memsize) {
        case 1:
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_b),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
        case 2:
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_hw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       case 4:
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_w),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       case 8:
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_dw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       case 16:
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_qw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       default:
            assert(0);
            break;
    }
}

void pred_instrument_taint_reg2reg(INS ins, REG dstreg, REG srcreg, int extend)
{
    int dst_treg;
    int src_treg;
    UINT32 dst_regsize;
    UINT32 src_regsize;

    if (dstreg == srcreg) {
        return;
    }

    dst_treg = translate_reg((int)dstreg);
    src_treg = translate_reg((int)srcreg);
    dst_regsize = REG_Size(dstreg);
    src_regsize = REG_Size(srcreg);

    if (dst_regsize == src_regsize) {
        switch(dst_regsize) {
            case 1:
                if (REG_is_Lower8(dstreg) && REG_is_Lower8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_lbreg2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                } else if (REG_is_Lower8(dstreg) && REG_is_Upper8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_UBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_ubreg2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                } else if (REG_is_Upper8(dstreg) && REG_is_Lower8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2UBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_lbreg2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                } else if (REG_is_Upper8(dstreg) && REG_is_Upper8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_UBREG2UBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_ubreg2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_HWREG2HWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_WREG2WREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_WREG2WREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_DWREG2DWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_dwreg2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_QWREG2QWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_qwreg2qwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else if (dst_regsize > src_regsize) {
        if (extend) {
            switch(src_regsize) {
                case 1:
                    if (REG_is_Lower8(srcreg)) {
                        switch(dst_regsize) {
                            case 2:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_LBREG2HWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_lbreg2hwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 4:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_LBREG2WREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_lbreg2wreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 8:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_LBREG2DWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_lbreg2dwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 16:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_LBREG2QWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_lbreg2qwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            default:
                                assert(0);
                                break;
                        }
                    } else if (REG_is_Upper8(srcreg)) {
                        switch(dst_regsize) {
                            case 2:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_UBREG2HWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_ubreg2hwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 4:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_UBREG2WREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_ubreg2wreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 8:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_UBREG2DWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_ubreg2dwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 16:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINTX_UBREG2QWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taintx_ubreg2qwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            default:
                                assert(0);
                                break;
                        }
                    } else {
                        assert(0);
                    }
                    break;
                case 2:
                    switch(dst_regsize) {
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWREG2WREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_hwreg2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWREG2DWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_hwreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_hwreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 4:
                    switch(dst_regsize) {
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_WREG2DWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_wreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_WREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_wreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_WREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 8:
                    switch(dst_regsize) {
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_DWREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_dwreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 16:
                    assert(0);
                    break;
                default:
                    assert(0);
                    break;
            }
        } else {
            switch(src_regsize) {
                case 1:
                    if (REG_is_Lower8(srcreg)) {
                        switch(dst_regsize) {
                            case 2:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_LBREG2HWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_lbreg2hwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 4:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_LBREG2WREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_lbreg2wreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 8:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_LBREG2DWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_lbreg2dwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 16:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_LBREG2QWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_lbreg2qwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            default:
                                assert(0);
                                break;
                        }
                    } else if (REG_is_Upper8(srcreg)) {
                        switch(dst_regsize) {
                            case 2:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_UBREG2HWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_ubreg2hwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 4:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_UBREG2WREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_ubreg2wreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 8:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_UBREG2DWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_ubreg2dwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            case 16:
#ifdef TRACE_TAINT_OPS
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                        AFUNPTR(trace_taint_op),
                                        IARG_UINT32, trace_taint_outfd,
                                        IARG_THREAD_ID,
                                        IARG_INST_PTR,
                                        IARG_UINT32, TAINT_UBREG2QWREG,
                                        IARG_UINT32, dst_treg,
                                        IARG_UINT32, src_treg,
                                        IARG_END);
#endif
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                AFUNPTR(taint_ubreg2qwreg),
#ifdef FAST_INLINE
                                                IARG_FAST_ANALYSIS_CALL,
#endif
                                                IARG_UINT32, dst_treg,
                                                IARG_UINT32, src_treg,
                                                IARG_END);
                                break;
                            default:
                                assert(0);
                                break;
                        }
                    } else {
                        assert(0);
                    }
                    break;
                case 2:
                    switch(dst_regsize) {
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWREG2WREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_hwreg2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWREG2DWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_hwreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_hwreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 4:
                    switch(dst_regsize) {
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_WREG2DWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_wreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_WREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_wreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 8:
                    switch(dst_regsize) {
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_DWREG2QWREG,
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_dwreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 16:
                    assert(0);
                    break;
                default:
                    assert(0);
                    break;
            }
        }
    } else {
        // src_regsize > dst_regsize
        switch (dst_regsize) {
            case 1:
                assert(src_regsize >= 1);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_LBREG2LBREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_lbreg2lbreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 2:
                assert(src_regsize >= 2);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2HWREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 4:
                assert(src_regsize >= 4);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2WREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 8:
                assert(src_regsize >= 8);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2DWREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_dwreg2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 16:
                assert(src_regsize >= 16);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_QWREG2QWREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_qwreg2qwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            default:
                fprintf(stderr, "instrument_reg2reg dst reg size is %u, src reg size is %u\n",
                    dst_regsize, src_regsize);
                assert(0);
                break;
        }
    }
}

void pred_instrument_taint_reg2mem(INS ins, REG reg, int extend)
{
    int treg = translate_reg((int)reg);
    UINT32 regsize = REG_Size(reg);
    UINT32 memsize = INS_MemoryWriteSize(ins);

    if (regsize == memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_lbreg2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_LBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(reg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_UBREG2MEM,
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_ubreg2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYWRITE_EA,
                            IARG_UINT32, treg,
                            IARG_END);
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_dwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        //IARG_UINT32, find_static_address(INS_Address(ins)),
                        IARG_UINT32, TAINT_QWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_qwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        //IARG_UINT32, find_static_address(INS_Address(ins)),
                        IARG_UINT32, TAINT_QWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
        }
    } else if (regsize < memsize) {
        if (extend) {
            switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2HWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2hwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2WMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_lbreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2DWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2dwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_LBREG2QWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_lbreg2qwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else if (REG_is_Upper8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2HWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2hwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2WMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2wmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2DWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2dwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_UBREG2QWMEM,
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taintx_ubreg2qwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
                switch(memsize) {
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_HWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_hwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(memsize) {
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_WREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_wreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_WREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_wreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(memsize) {
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINTX_DWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taintx_dwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 16:
                fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                assert(0);
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
            }
        } else {
            switch(regsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2HWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2hwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_LBREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else if (REG_is_Upper8(reg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2HWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2hwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_UBREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            assert(0);
                            break;
                    }
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
                switch(memsize) {
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2WMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_HWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(memsize) {
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_WREG2DWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_wreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_WREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_wreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(memsize) {
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_DWREG2QWMEM,
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_dwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYWRITE_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 16:
                fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                assert(0);
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
            }
        } 
    } else {
        // regsize if greater than mem, just move the lower memsize bits
        // of the register to memory
        switch(memsize) {
            case 1:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_LBREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_lbreg2mem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_LBREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_HWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_WREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_DWREG2MEM,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_dwreg2mem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                break;
            default:
                INSTRUMENT_PRINT (log_f, "Instruction: %s\n", INS_Disassemble(ins).c_str());
                INSTRUMENT_PRINT (log_f, "memsize %d, regsize %d\n", memsize, regsize);
                assert(0);
                break;
        }
    }
}

void pred_instrument_taint_mem2reg(INS ins, REG dstreg, int extend)
{
    int treg = translate_reg((int)dstreg);
    UINT32 regsize = REG_Size(dstreg);
    UINT32 memsize = INS_MemoryWriteSize(ins);

    if (regsize == memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(dstreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2LBREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_mem2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2LBREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(dstreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2UBREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_mem2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2UBREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                } else {
                    assert(0);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2HWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2HWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2WREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2WREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2DWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2DWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2QWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2qwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2QWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                break;
            default:
                assert(0);
                break;
        }
    } else if (regsize > memsize) {
        if (extend) {
            // dst is greater than reg, must extend
            switch(memsize) {
                case 1:
                    switch(regsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_BMEM2HWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_bmem2hwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_BMEM2WREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_bmem2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_BMEM2WREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_BMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_bmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_BMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_bmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 2:
                    switch(regsize) {
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWMEM2WREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_hwmem2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_hwmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_HWMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_hwmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 4:
                    switch(regsize) {
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_WMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_wmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_WMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_wmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 8:
                    switch(regsize) {
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINTX_DWMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taintx_dwmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 16:
                    assert(0);
                    break;
                default:
                    assert(0);
                    break;
            }
        } else {
            switch(memsize) {
                case 1:
                    switch(regsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_BMEM2HWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_bmem2hwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_BMEM2WREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_bmem2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_BMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_bmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_BMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_bmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 2:
                    switch(regsize) {
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWMEM2WREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_hwmem2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_hwmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_HWMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_hwmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 4:
                    switch(regsize) {
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_WMEM2DWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_wmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_WMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_wmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 8:
                    switch(regsize) {
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_DWMEM2QWREG,
                                    IARG_UINT32, treg,
                                    IARG_MEMORYREAD_EA,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                    AFUNPTR(taint_dwmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                    break;
                case 16:
                    assert(0);
                    break;
                default:
                    assert(0);
                    break;
            }
        }

    }
}

void pred_instrument_taint_mem2mem(INS ins, int extend)
{
    UINT32 dst_memsize = INS_MemoryWriteSize(ins);
    UINT32 src_memsize = INS_MemoryReadSize(ins);

    assert(dst_memsize == src_memsize);

    switch (dst_memsize) {
        case 1:
#ifdef TRACE_TAINT_OPS
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_b),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
        case 2:
#ifdef TRACE_TAINT_OPS
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_hw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       case 4:
#ifdef TRACE_TAINT_OPS
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_W,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_w),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_W,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       case 8:
#ifdef TRACE_TAINT_OPS
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_DW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_dw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_DW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       case 16:
#ifdef TRACE_TAINT_OPS
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_QW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_mem2mem_qw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_QW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            break;
       default:
            assert(0);
            break;
    }
}

void pred_instrument_taint_add_reg2reg(INS ins, REG dstreg, REG srcreg)
{
    int dst_treg;
    int src_treg;
    UINT32 dst_regsize;
    UINT32 src_regsize;

    if (dstreg == srcreg) {
        return;
    }

    dst_treg = translate_reg((int)dstreg);
    src_treg = translate_reg((int)srcreg);

    dst_regsize = REG_Size(dstreg);
    src_regsize = REG_Size(srcreg);

    if (dst_regsize == src_regsize) {
        switch(dst_regsize) {
            case 1:
                if (REG_is_Lower8(dstreg) && REG_is_Lower8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_lbreg2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                } else if (REG_is_Lower8(dstreg) && REG_is_Upper8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2UBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_lbreg2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2UBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(dstreg) && REG_is_Lower8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_UBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_ubreg2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_UBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(dstreg) && REG_is_Upper8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2LBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_ubreg2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_UBREG2UBREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_HWREG2HWREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_hwreg2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_HWREG2HWREG,
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#endif
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2WREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_wreg2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2WREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_DWREG2DWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_dwreg2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_DWREG2DWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_QWREG2QWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_qwreg2qwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_QWREG2QWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                break;
            default:
                assert(0);
                break;
        }
    } else if (dst_regsize > src_regsize) {
        switch(src_regsize) {
            case 1:
                if (REG_is_Lower8(dstreg)) {
                    switch(dst_regsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2HWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2hwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2HWREG,
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
#endif
                        case 4:
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 8:
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                } else if (REG_is_Upper8(dstreg)) {
                    switch(dst_regsize) {
                        case 2:
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2hwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 4:
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2wreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 8:
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        case 16:
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, dst_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_END);
                            break;
                        default:
                            assert(0);
                            break;
                    }
                } else {
                    assert(0);
                }
                break;
            case 2:
                switch(dst_regsize) {
                    case 4:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    case 8:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    case 16:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(dst_regsize) {
                    case 8:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_wreg2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    case 16:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_wreg2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    default:
                        fprintf(stderr, "taint_add_reg2reg, src reg size: %d, dst reg size %d\n",
                                src_regsize, dst_regsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(dst_regsize) {
                    case 16:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_dwreg2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 16:
                assert(0);
                break;
            default:
                break;
        }
    } else if (dst_regsize < src_regsize) {
        switch(dst_regsize) {
            case 1:
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_lbreg2lbreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 2:
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_hwreg2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 4:
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_wreg2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            case 8:
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_dwreg2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dst_treg,
                        IARG_UINT32, src_treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else {
        // should not get here
        fprintf(stderr, "instrument_taint_add_reg2reg, dst_regsize: %d, src_regsize: %d\n",
                dst_regsize, src_regsize);
        assert(0);
    }
}

void pred_instrument_taint_add_reg2mem(INS ins, REG srcreg)
{
    int treg = translate_reg((int)srcreg);
    UINT32 regsize = REG_Size(srcreg);
    UINT32 memsize;
    IARG_TYPE mem_ea;

    if (INS_IsMemoryRead(ins)) {
        mem_ea = IARG_MEMORYREAD_EA;
        memsize = INS_MemoryReadSize(ins);
    } else if (INS_IsMemoryWrite(ins)) {
        mem_ea = IARG_MEMORYWRITE_EA;
        memsize = INS_MemoryWriteSize(ins);
    } else {
        assert(0);
    }

    if (regsize == memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2MEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_lbreg2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_LBREG2MEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                } else if (REG_is_Upper8(srcreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_UBREG2MEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_ubreg2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_UBREG2MEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2MEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_hwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_HWREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_WREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_wreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_WREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_DWREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_dwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_DWREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_QWREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_qwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_QWREG2MEM,
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
#endif
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                break;
        }
    } else if (regsize < memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(srcreg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2HWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2hwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2HWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2WMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2wmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
                            break;
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2WMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2DWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2dwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2QWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        case 16:
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_lbreg2qwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_LBREG2QWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            break;
                    }
                } else if (REG_is_Upper8(srcreg)) {
                    switch(memsize) {
                        case 2:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2HWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2hwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2HWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        case 4:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2WMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2wmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2WMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        case 8:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2DWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2dwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2DWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        case 16:
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_enter),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2QWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_ubreg2qwmem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#ifdef TRACE_TAINT_OPS
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(trace_taint_op_exit),
                                    IARG_UINT32, trace_taint_outfd,
                                    IARG_THREAD_ID,
                                    IARG_INST_PTR,
                                    IARG_UINT32, TAINT_ADD_UBREG2QWMEM,
                                    mem_ea,
                                    IARG_UINT32, treg,
                                    IARG_END);
#endif
                            break;
                        default:
                            fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                            break;
                    }
                } else {
                    fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown src reg\n");
                    assert(0);
                }
                break;
            case 2:
                switch(memsize) {
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2WMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2wmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2WMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2DWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2dwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2DWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_hwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_HWREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(memsize) {
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2DWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_wreg2dwmem),
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2DWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_wreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_WREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(memsize) {
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_DWREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add_dwreg2qwmem),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                mem_ea,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_ADD_DWREG2QWMEM,
                            mem_ea,
                            IARG_UINT32, treg,
                            IARG_END);
#endif
                        break;
                    default:
                        fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                        assert(0);
                        break;
                }
                break;
            case 16:
                fprintf(stderr, "[ERROR] Unsupported mem write size %d\n", memsize);
                assert(0);
                break;
            default:
                fprintf(stderr, "[ERROR] instrument_taint_reg2mem: unknown reg size %d\n", regsize);
                assert(0);
                break;
        }
    } else if (regsize > memsize) {
        switch(memsize) {
            case 1:
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_lbreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 2:
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_hwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_wreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 8:
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_dwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        mem_ea,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else {
        assert(0);
    }
}

void pred_instrument_taint_add_mem2reg(INS ins, REG dstreg)
{
    int treg = translate_reg((int)dstreg);
    UINT32 regsize = REG_Size(dstreg);
    UINT32 memsize = INS_MemoryWriteSize(ins);

    if (regsize == memsize) {
        switch(regsize) {
            case 1:
                if (REG_is_Lower8(dstreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_BMEM2LBREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_bmem2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, treg,
                            IARG_END);
                } else if (REG_is_Upper8(dstreg)) {
#ifdef TRACE_TAINT_OPS
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_BMEM2UBREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_add_bmem2ubreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, treg,
                            IARG_END);
                } else {
                    assert(0);
                }
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_HWMEM2HWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_hwmem2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_WMEM2WREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_wmem2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 8:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_DWMEM2DWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_dwmem2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 16:
#ifdef TRACE_TAINT_OPS
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_ADD_QWMEM2QWREG,
                        IARG_UINT32, treg,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_add_qwmem2qwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else if (regsize > memsize) {
        // dst is greater than reg, must extend
        switch(memsize) {
            case 1:
                switch(regsize) {
                    case 2:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_bmem2hwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op_enter),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_ADD_BMEM2WREG,
                                IARG_UINT32, treg,
                                IARG_MEMORYREAD_EA,
                                IARG_END);
#endif
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_bmem2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op_exit),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_ADD_BMEM2WREG,
                                IARG_UINT32, treg,
                                IARG_MEMORYREAD_EA,
                                IARG_END);
#endif
                        break;
                    case 8:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_bmem2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_bmem2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 2:
                switch(regsize) {
                    case 4:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_hwmem2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 8:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_hwmem2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_hwmem2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 4:
                switch(regsize) {
                    case 8:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_wmem2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    case 16:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_wmem2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 8:
                switch(regsize) {
                    case 16:
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
                                AFUNPTR(taint_add_dwmem2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                        break;
                    default:
                        assert(0);
                        break;
                }
                break;
            case 16:
                assert(0);
                break;
            default:
                assert(0);
                break;
        }
    } else {
        assert(0);
    }
}

void pred_instrument_taint_add_mem2mem(INS ins)
{
    UINT32 dst_memsize = INS_MemoryWriteSize(ins);
    UINT32 src_memsize = INS_MemoryReadSize(ins);

    assert(dst_memsize == src_memsize);

    switch (dst_memsize) {
        case 1:
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_b),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
        case 2:
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_hw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       case 4:
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_w),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       case 8:
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_dw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       case 16:
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_add_mem2mem_qw),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_END);
            break;
       default:
            assert(0);
            break;
    }
}

void instrument_taint_immval2mem(INS ins)
{
    UINT32 addrsize = INS_MemoryWriteSize(ins);
    switch(addrsize) {
                case 1:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immvalb2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYWRITE_EA, IARG_END);
                    break;
               case 2:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immvalhw2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYWRITE_EA, IARG_END);
                    break;
               case 4:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immvalw2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYWRITE_EA, IARG_END);
                    break;
               case 8:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immvaldw2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYWRITE_EA, IARG_END);
                    break;
               case 16:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immvalqw2mem),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYWRITE_EA, IARG_END);
                    break;
               default:
                    assert(0);
                    break;
            }

}

void pred_instrument_taint_immval2mem(INS ins)
{
    UINT32 addrsize = INS_MemoryWriteSize(ins);
    switch(addrsize) {
        case 1:
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_immvalb2mem),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYWRITE_EA, IARG_END);
            break;
        case 2:
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_immvalhw2mem),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYWRITE_EA, IARG_END);
            break;
        case 4:
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_immvalw2mem),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYWRITE_EA, IARG_END);
            break;
        case 8:
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_immvaldw2mem),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYWRITE_EA, IARG_END);
            break;
        case 16:
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_immvalqw2mem),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_MEMORYWRITE_EA, IARG_END);
            break;
        default:
            assert(0);
            break;
    }
}

void instrument_clear_dst(INS ins)
{
    if (INS_IsMemoryWrite(ins)) {
        uint32_t addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE,
                AFUNPTR(clear_mem_taints),
                IARG_MEMORYWRITE_EA,
                IARG_UINT32, addrsize,
                IARG_END);
    } else if (INS_OperandIsReg(ins, 0)) {
        REG reg = INS_OperandReg(ins, 0);
        int treg = translate_reg((int)reg);
        INS_InsertCall(ins, IPOINT_BEFORE,
                AFUNPTR(clear_reg),
                IARG_UINT32, treg,
                IARG_UINT32, REG_Size(reg),
                IARG_END);
    }
}

void instrument_clear_reg(INS ins, REG reg)
{
    int treg = translate_reg((int)reg);
    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(clear_reg),
            IARG_UINT32, treg,
            IARG_UINT32, REG_Size(reg),
            IARG_END);
}

static inline ADDRINT computeEA(ADDRINT firstEA, UINT eflags,
                                 UINT32 count, UINT32 op_size)
{
    if (eflags & DF_MASK) {
        ADDRINT size = op_size * count;
        return firstEA - size + op_size;
    } 
    return firstEA;
}

void taint_whole_mem2mem(ADDRINT src_mem_loc, ADDRINT dst_mem_loc,
                         ADDRINT eflags, ADDRINT counts, UINT32 op_size)
{
    int size = (int)(counts * op_size);
    if (!size) return;
    ADDRINT ea_src_mem_loc = computeEA(src_mem_loc, eflags, counts, op_size);
    ADDRINT ea_dst_mem_loc = computeEA(dst_mem_loc, eflags, counts, op_size);
#ifdef TRACE_TAINT_OPS
    trace_taint_op(trace_taint_outfd, 
		   PIN_ThreadId(),
		   0, // TODO fill ip in later
		   TAINT_MEM2MEM,
		   ea_dst_mem_loc,
		   ea_src_mem_loc); 
#endif
    taint_mem2mem(ea_src_mem_loc, ea_dst_mem_loc, size);
}

void taint_whole_lbreg2mem(ADDRINT dst_mem_loc,
			   REG reg,
			   ADDRINT eflags,
			   ADDRINT counts,
			   UINT32 op_size)
{
    // int size = (int)(counts * op_size);
    ADDRINT effective_addr = computeEA(dst_mem_loc, eflags, counts, op_size);
#ifdef TRACE_TAINT_OPS
    trace_taint_op(trace_taint_outfd,
		   PIN_ThreadId(),
		   0, // TODO fill ip in later
		   TAINT_REP_LBREG2MEM,
		   effective_addr,
		   (u_long) reg); 
#endif
    taint_rep_lbreg2mem(effective_addr, reg, counts);
}

void taint_whole_hwreg2mem(ADDRINT dst_mem_loc,
			   REG reg,
			   ADDRINT eflags,
			   ADDRINT counts,
			   UINT32 op_size)
{
    // int size = (int)(counts * op_size);
    ADDRINT effective_addr = computeEA(dst_mem_loc, eflags, counts, op_size);
#ifdef TRACE_TAINT_OPS
    trace_taint_op(trace_taint_outfd,
		   PIN_ThreadId(),
		   0, // TODO fill ip in later
		   TAINT_REP_HWREG2MEM,
		   effective_addr,
		   (u_long) reg); 
#endif
    taint_rep_hwreg2mem(effective_addr, reg, counts);
}

void taint_whole_wreg2mem(ADDRINT dst_mem_loc,
			  REG reg,
			  ADDRINT eflags,
			  ADDRINT counts,
			  UINT32 op_size)
{
    ADDRINT effective_addr = computeEA(dst_mem_loc, eflags, counts, op_size);
#ifdef TRACE_TAINT_OPS
    trace_taint_op(trace_taint_outfd,
		   PIN_ThreadId(),
		   0, // TODO fill ip in later
		   TAINT_REP_WREG2MEM,
		   effective_addr,
		   (u_long) reg); 
#endif
    taint_rep_wreg2mem(effective_addr, reg, counts);
}

void instrument_move_string(INS ins)
{
    UINT32 opw = INS_OperandWidth(ins, 0);
    UINT32 size = opw / 8;
    if (INS_RepPrefix(ins)) {
        assert(size == INS_MemoryOperandSize(ins, 0));
        INS_InsertIfCall (ins, IPOINT_BEFORE, (AFUNPTR)returnArg,
                IARG_FIRST_REP_ITERATION,
                IARG_END);
        INS_InsertThenCall (ins, IPOINT_BEFORE, (AFUNPTR)taint_whole_mem2mem,
                IARG_MEMORYREAD_EA,
                IARG_MEMORYWRITE_EA,
                IARG_REG_VALUE, REG_EFLAGS,
                IARG_REG_VALUE, INS_RepCountRegister(ins),
                IARG_UINT32, INS_MemoryOperandSize(ins, 0),
                IARG_END);
    } else {
        assert(size == INS_MemoryOperandSize(ins, 0));
        if (size > 0) {
            INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)taint_whole_mem2mem,
                    IARG_MEMORYREAD_EA,
                    IARG_MEMORYWRITE_EA,
                    IARG_REG_VALUE, REG_EFLAGS,
                    IARG_UINT32, 1,
                    IARG_UINT32, INS_MemoryOperandSize(ins, 0),
                    IARG_END);
        }
    }
}

void instrument_store_string(INS ins)
{
    UINT32 opw = INS_OperandWidth(ins, 0);
    UINT32 size = opw / 8;

    assert(INS_OperandIsMemory(ins, 0));
    assert(size == INS_MemoryOperandSize(ins, 0));

    // fprintf(stderr, "store string size %d\n", size);
    if (INS_RepPrefix(ins)) {
        INS_InsertIfCall (ins, IPOINT_BEFORE, (AFUNPTR)returnArg,
                IARG_FIRST_REP_ITERATION,
                IARG_END);
        switch(INS_MemoryOperandSize(ins, 0)) {
            case 1:
                INS_InsertThenCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_whole_lbreg2mem,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_REG_VALUE, REG_EFLAGS,
                        IARG_REG_VALUE, INS_RepCountRegister(ins),
                        IARG_UINT32, INS_MemoryOperandSize(ins, 0),
                        IARG_END);
                break;
            case 2:
                INS_InsertThenCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_whole_hwreg2mem,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_REG_VALUE, REG_EFLAGS,
                        IARG_REG_VALUE, INS_RepCountRegister(ins),
                        IARG_UINT32, INS_MemoryOperandSize(ins, 0),
                        IARG_END);
                break;
            case 4:
                INS_InsertThenCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_whole_wreg2mem,
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_REG_VALUE, REG_EFLAGS,
                        IARG_REG_VALUE, INS_RepCountRegister(ins),
                        IARG_UINT32, INS_MemoryOperandSize(ins, 0),
                        IARG_END);
                break;
            default:
                fprintf(stderr, "[ERROR]instrument_store_string unk op size %d\n",
                        INS_MemoryOperandSize(ins, 0));
                assert(0);
                break;
        }
    } else {
        switch(INS_MemoryOperandSize(ins, 0)) {
            case 1:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_lbreg2mem,
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_END);
                break;
            case 2:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_hwreg2mem,
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_wreg2mem,
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_END);
                break;
            default:
                fprintf(stderr, "[ERROR] store string, unknown size %d\n",
                        INS_MemoryOperandSize(ins, 0));
                assert(0);
                break;
        }
    }
}

void instrument_load_string(INS ins)
{
    assert(INS_OperandIsReg(ins, 0));
    assert(INS_OperandIsMemory(ins, 1));

    if (INS_RepPrefix(ins)) {
        INSTRUMENT_PRINT (log_f, "[WARN] a rep'ed load string\n");
        INS_InsertIfCall (ins, IPOINT_BEFORE, (AFUNPTR)returnArg,
                IARG_FIRST_REP_ITERATION,
                IARG_END);
        /* Even if it's rep'ed, we run this for every rep iteration.
         *  Because we really just want the last rep iteration.
         * */
        switch(INS_MemoryOperandSize(ins, 0)) {
            case 1:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2LBREG,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_mem2lbreg,
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_END);
                break;
            case 2:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2HWREG,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_mem2hwreg,
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_END);
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_enter),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2WREG,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif
                INS_InsertCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_mem2wreg,
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(trace_taint_op_exit),
                        IARG_UINT32, trace_taint_outfd,
                        IARG_THREAD_ID,
                        IARG_INST_PTR,
                        IARG_UINT32, TAINT_MEM2WREG,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_MEMORYREAD_EA,
                        IARG_END);
#endif

                break;
            default:
                assert(0);
                break;
        }
    } else {
        /* Ugh we don't know the address until runtime, so this is the
         * best we can do at instrumentation time. */
        switch(INS_MemoryOperandSize(ins, 0)) {
            case 1:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_mem2lbreg,
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_END);
                break;
            case 2:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_mem2hwreg,
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        (AFUNPTR)taint_mem2wreg,
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, LEVEL_BASE::REG_EAX,
                        IARG_END);
                break;
            default:
                // should not get here
                assert(0);
                break;
        }
    }
}

void instrument_xchg (INS ins)
{
    int op1mem, op2mem, op1reg, op2reg;
    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);

    if (op1reg && op2reg) {
        int treg1, treg2;
        REG reg1, reg2;

        INSTRUMENT_PRINT(log_f, "op1 and op2 of xchg are registers\n");
        reg1 = INS_OperandReg(ins, 0);
        reg2 = INS_OperandReg(ins, 1);
        if(!REG_valid(reg1) || !REG_valid(reg2)) {
            return;
        }
        assert(REG_Size(reg1) == REG_Size(reg2));
        treg1 = translate_reg(reg1);
        treg2 = translate_reg(reg2);

        switch(REG_Size(reg1)) {
            case 1:
                if (REG_is_Lower8(reg1) && REG_is_Lower8(reg2)) {
                    INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_lbreg2lbreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, treg1,
                        IARG_UINT32, treg2,
                        IARG_END);
                } else if (REG_is_Lower8(reg1) && REG_is_Upper8(reg2)) {
                    INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_lbreg2ubreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, treg1,
                        IARG_UINT32, treg2,
                        IARG_END);
                } else if (REG_is_Upper8(reg1) && REG_is_Lower8(reg2)) {
                    INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_ubreg2lbreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, treg1,
                        IARG_UINT32, treg2,
                        IARG_END);
                } else if (REG_is_Upper8(reg1) && REG_is_Upper8(reg2)) {
                    INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_ubreg2ubreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, treg1,
                        IARG_UINT32, treg2,
                        IARG_END);
                } else {
                    assert(0);
                }
                break;
            case 2:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_hwreg2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, treg1,
                        IARG_UINT32, treg2,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_wreg2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, treg1,
                        IARG_UINT32, treg2,
                        IARG_END);
                break;
            default:
                ERROR_PRINT (log_f, "Unsupported size %d for xchg reg2reg, %s %s\n",
                        REG_Size(reg1),
                        REG_StringShort(reg1).c_str(),
                        REG_StringShort(reg2).c_str());
                assert(0);
                break;
        }
    } else if (op1reg && op2mem) {
        REG reg;
        int treg;
        UINT32 addrsize;

        addrsize = INS_MemoryReadSize(ins);
        reg = INS_OperandReg(ins, 0);
        treg = translate_reg(reg);
        if (!REG_valid(reg)) {
            return;
        }
        assert(addrsize == REG_Size(reg));

        switch(addrsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_xchg_bmem2lbreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                } else {
                    assert(REG_is_Upper8(reg));
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_xchg_bmem2ubreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                }
                break;
            case 2:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_hwmem2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_wmem2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 8:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_dwmem2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else if (op1mem && op2reg) {
        REG reg;
        int treg;
        UINT32 addrsize;

        addrsize = INS_MemoryReadSize(ins);
        reg = INS_OperandReg(ins, 1);
        treg = translate_reg(reg);
        if (!REG_valid(reg)) {
            return;
        }
        assert(addrsize == REG_Size(reg));

        // Note: xchg mem2reg and reg2mem are the same
        switch(addrsize) {
            case 1:
                if (REG_is_Lower8(reg)) {
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_xchg_bmem2lbreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                } else {
                    assert(REG_is_Upper8(reg));
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_xchg_bmem2ubreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, treg,
                                IARG_END);
                }
                break;
            case 2:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_hwmem2hwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_wmem2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 8:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_xchg_dwmem2dwreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            default:
                assert(0);
                break;
        }
    } else {
        ERROR_PRINT (log_f, "Unknown combination of xchg\n");
        assert(0);
    }
}

void instrument_bswap (INS ins)
{
    int treg;
    assert(INS_OperandIsReg(ins, 0));
    assert(REG_Size(INS_OperandReg(ins, 0)) == 4);

    treg = translate_reg(INS_OperandReg(ins, 0));
    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(reverse_reg_taint),
            IARG_UINT32, treg,
            IARG_UINT32, 4,
            IARG_END);
}

void instrument_cmpxchg (INS ins)
{
}

void instrument_mov (INS ins) 
{
    int ismemread = 0, ismemwrite = 0;
    int immval = 0;
    REG reg = REG_INVALID();
    REG dstreg = REG_INVALID();
    int treg = (int)REG_INVALID();

    if(INS_IsMemoryRead(ins)) {
        ismemread = 1;
        reg = INS_OperandReg(ins, 0);
        if(!REG_valid(reg)) return;
    } else if(INS_IsMemoryWrite(ins)) {
        ismemwrite = 1;
        if(INS_OperandIsReg(ins, 1)) {
            reg = INS_OperandReg(ins, 1);
            if(!REG_valid(reg)) return;
        } else {
            if(!INS_OperandIsImmediate(ins, 1)) return;
            //must be an immediate value
            immval = 1;
        }
    } else {
        if(!(INS_OperandIsReg(ins, 0))) return;
        dstreg = INS_OperandReg(ins, 0);
        if(!REG_valid(dstreg)) return;

        if(INS_OperandIsReg(ins, 1)) {
            reg = INS_OperandReg(ins, 1);
            if(!REG_valid(reg)) return;
        } else {
            //sometimes get an offset into video memory
            if(!INS_OperandIsImmediate(ins, 1)) return;
            //must be an immediate value
            immval = 1;
        }
    }

    //2 (src) operand is memory...destination must be a register
    if(ismemread) {
        // REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        // REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
        // ADDRDELTA displacement = INS_MemoryDisplacement(ins);

        assert(INS_IsMemoryRead(ins) == 1);
        if (SPECIAL_REG(reg)) {
            return;
        }
#ifdef COPY_ONLY
        instrument_taint_mem2reg(ins, reg, 0);
#else
 #ifndef LINKAGE_DATA_OFFSET
       instrument_taint_mem2reg(ins, reg, 0);
 #else
        REG dst_reg = INS_OperandReg(ins, 0);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
        ADDRDELTA displacement = INS_MemoryDisplacement(ins);
        if (displacement >= 0x8000000 && REG_valid(base_reg) && !REG_valid(index_reg)) {
            // arithmetic operation
            instrument_taint_reg2reg(ins, dst_reg, base_reg, 0);
            instrument_taint_add_mem2reg(ins, dst_reg);
        } else if (REG_valid(base_reg) && REG_valid(index_reg)) {
            if (displacement >= 0x8000000) {
                instrument_taint_reg2reg(ins, dst_reg, index_reg, 0);
                instrument_taint_add_reg2reg(ins, dst_reg, base_reg);
                instrument_taint_add_mem2reg(ins, dst_reg);
            } else {
                instrument_taint_reg2reg(ins, dst_reg, index_reg, 0);
                instrument_taint_add_mem2reg(ins, dst_reg);
            }
        } else {
            instrument_taint_mem2reg(ins, dst_reg, 1);
        }
 #endif // LINKAGE_DATA_OFFSET
#endif // COPY_ONLY
    } else if(ismemwrite) {
        if(!immval) {
            //mov register to memory location
#ifdef COPY_ONLY
            instrument_taint_reg2mem(ins, reg, 0);
#else
 #ifndef LINKAGE_DATA_OFFSET
            instrument_taint_reg2mem(ins, reg, 0);
 #else
            REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
            REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
            ADDRDELTA displacement = INS_MemoryDisplacement(ins);
        
            if (displacement >= 0x8000000 &&
                    REG_valid(base_reg) && !REG_valid(index_reg)) {
                // arithmetic operation
                instrument_taint_reg2mem(ins, base_reg, 0);
                instrument_taint_add_reg2mem(ins, reg);
            } else if (REG_valid(base_reg) && REG_valid(index_reg)) {
                if (displacement >= 0x8000000) {
                    instrument_taint_reg2mem(ins, index_reg, 0);
                    instrument_taint_add_reg2mem(ins, base_reg);
                    instrument_taint_add_reg2mem(ins, reg);
                } else {
                    instrument_taint_reg2mem(ins, index_reg, 0);
                    instrument_taint_add_reg2mem(ins, reg);
                }
            } else {
                instrument_taint_reg2mem(ins, reg, 1);
            }
 #endif // LINKAGE_DATA_OFFSET
#endif // COPY_ONLY
        } else {
            //move immediate to memory location
            instrument_taint_immval2mem(ins);
        }
    } else if (!SPECIAL_REG(dstreg)) {
        if(immval) {
            treg = translate_reg((int)dstreg);
            //mov immediate value into register
            switch(REG_Size(dstreg)) {
                case 1:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 2:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2hwreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 4:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2wreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 8:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2dwreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 16:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2qwreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, treg, IARG_END);
                    break;
               default:
                    assert(0);
                    break;
            }
        } else {
            //mov one reg val into another
            if (REG_is_seg(reg) || REG_is_seg(dstreg)) {
                // ignore segment registers for now
                return;
            }
            if (REG_Size(reg) != REG_Size(dstreg)) {

                fprintf(stderr, "%#x [mov] %s\n", INS_Address(ins), INS_Disassemble(ins).c_str());
                fprintf(stderr, "%#x instrument mov is src reg: %d into dst reg: %d\n", INS_Address(ins), reg, dstreg); 
            }
            assert(REG_Size(reg) == REG_Size(dstreg));
            instrument_taint_reg2reg(ins, dstreg, reg, 0);
        }
    }
}

/* 
 * Instrument a move that extends if the dst is smaller than src.
 *
 * Dst: register/memory
 * Src: register/memory
 * */
void instrument_movx (INS ins)
{
    int op1mem, op2mem, op1reg, op2reg;
    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);

    INSTRUMENT_PRINT (log_f, "[movx] %#x %s\n",
            INS_Address(ins),
            INS_Disassemble(ins).c_str());

    if (op1reg && op2reg) {
        REG dst_reg = INS_OperandReg(ins, 0);
        REG src_reg = INS_OperandReg(ins, 1);
        if (SPECIAL_REG(dst_reg)) {
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument movx address %#x is src reg: %d into dst reg: %d\n", INS_Address(ins), src_reg, dst_reg); 
        instrument_taint_reg2reg(ins, dst_reg, src_reg, 1);
    } else if (op1reg && op2mem) {
        assert(INS_IsMemoryRead(ins) == 1);
#ifdef COPY_ONLY
        instrument_taint_mem2reg(ins, dst_reg, 1);
#else
        REG dst_reg = INS_OperandReg(ins, 0);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
 #ifndef LINKAGE_DATA_OFFSET
        ADDRDELTA displacement = INS_MemoryDisplacement(ins);
        if (displacement >= 0x8000000 && REG_valid(base_reg) && !REG_valid(index_reg)) {
            // arithmetic operation
            instrument_taint_reg2reg(ins, dst_reg, base_reg, 0);
            instrument_taint_add_mem2reg(ins, dst_reg);
        } else if (REG_valid(base_reg) && REG_valid(index_reg)) {
            if (displacement >= 0x8000000) {
                instrument_taint_reg2reg(ins, dst_reg, index_reg, 0);
                instrument_taint_add_reg2reg(ins, dst_reg, base_reg);
                instrument_taint_add_mem2reg(ins, dst_reg);
            } else {
                instrument_taint_reg2reg(ins, dst_reg, index_reg, 0);
                instrument_taint_add_mem2reg(ins, dst_reg);
            }
        } else {
            instrument_taint_mem2reg(ins, dst_reg, 1);
        }
 #else
        // no filtering in index mode
        if (REG_valid(base_reg) && REG_valid(index_reg)) {
            instrument_taint_reg2reg(ins, dst_reg, index_reg, 0);
            instrument_taint_add_reg2reg(ins, dst_reg, base_reg);
            instrument_taint_add_mem2reg(ins, dst_reg);
        } else if (REG_valid(base_reg)) {
            instrument_taint_reg2reg(ins, dst_reg, base_reg, 0);
            instrument_taint_add_mem2reg(ins, dst_reg);
        } else if (REG_valid(index_reg)) {
            assert(0);
        } else {
            instrument_taint_mem2reg(ins, dst_reg, 1);
        }
 #endif
#endif // COPY_ONLY
    } else if (op1mem && op2reg) {
        assert(INS_IsMemoryWrite(ins) == 1);
        REG src_reg = INS_OperandReg(ins, 1);
#ifdef COPY_ONLY
        instrument_taint_reg2mem(ins, src_reg, 1);
#else
 #ifndef LINKAGE_DATA_OFFSET
        instrument_taint_reg2mem(ins, src_reg, 1);
 #else
        REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
        REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
        // no filtering in index mode
        if (REG_valid(base_reg) && REG_valid(index_reg)) {
            instrument_taint_reg2mem(ins, index_reg, 0);
            instrument_taint_add_reg2mem(ins, base_reg);
            instrument_taint_add_reg2mem(ins, src_reg);
        } else if (REG_valid(base_reg)) {
            instrument_taint_reg2mem(ins, base_reg, 0);
            instrument_taint_add_reg2mem(ins, src_reg);
        } else if (REG_valid(index_reg)) {
            assert(0);
        } else {
            instrument_taint_mem2reg(ins, src_reg, 1);
        }
 #endif
#endif // COPY_ONLY
    } else if (op1mem && op2mem) {
        instrument_taint_mem2mem(ins, 1);
    } else {
        ERROR_PRINT(log_f, "ERROR: second operand of MOVZX/MOVSX is not reg or memory\n");
    }
} 

void instrument_cmov(INS ins)
{
    int ismemread = 0, ismemwrite = 0;
    int immval = 0;
    USIZE addrsize = 0;
    REG reg = REG_INVALID();
    REG dstreg = REG_INVALID();
    int treg = (int)REG_INVALID();

    assert(INS_IsPredicated(ins));

    if(INS_IsMemoryRead(ins)) {
        ismemread = 1;
        addrsize = INS_MemoryReadSize(ins);
        reg = INS_OperandReg(ins, 0);
        if(!REG_valid(reg)) return;
    } else if(INS_IsMemoryWrite(ins)) {
        ismemwrite = 1;
        addrsize = INS_MemoryWriteSize(ins);
        if(INS_OperandIsReg(ins, 1)) {
            reg = INS_OperandReg(ins, 1);
            if(!REG_valid(reg)) return;
        } else {
            if(!INS_OperandIsImmediate(ins, 1)) return;
            //must be an immediate value
            immval = 1;
        }
    } else {
        if(!(INS_OperandIsReg(ins, 0))) return;
        dstreg = INS_OperandReg(ins, 0);
        if(!REG_valid(dstreg)) return;

        if(INS_OperandIsReg(ins, 1)) {
            reg = INS_OperandReg(ins, 1);
            if(!REG_valid(reg)) return;
        } else {
            //sometimes get an offset into video memory
            if(!INS_OperandIsImmediate(ins, 1)) return;
            //must be an immediate value
            immval = 1;
        }
    }

    //2 (src) operand is memory...destination must be a register
    if(ismemread) {
        if (!SPECIAL_REG(reg)) {
            INSTRUMENT_PRINT(log_f, "instrument mov is mem read: reg: %d (%s), size of mem read is %u\n", 
                    reg, REG_StringShort(reg).c_str(), addrsize);
#ifdef ONLY_COPY
            pred_instrument_taint_mem2reg(ins, reg, 0);
#else
 #ifndef LINKAGE_DATA_OFFSET
            pred_instrument_taint_mem2reg(ins, reg, 0);
 #else
            REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
            REG base_reg = INS_OperandMemoryBaseReg(ins, 1);

            if (REG_valid(base_reg) && REG_valid(index_reg)) {
                pred_instrument_taint_reg2reg(ins, reg, index_reg, 0);
                pred_instrument_taint_add_reg2reg(ins, reg, base_reg);
                pred_instrument_taint_add_mem2reg(ins, reg);
            } else if (REG_valid(base_reg)) {
                pred_instrument_taint_reg2reg(ins, reg, base_reg, 0);
                pred_instrument_taint_add_mem2reg(ins, reg);
            } else if (REG_valid(index_reg)) {
                pred_instrument_taint_reg2reg(ins, reg, index_reg, 0);
                pred_instrument_taint_add_mem2reg(ins, reg);
            } else {
                pred_instrument_taint_mem2reg(ins, reg, 0);
            }
 #endif // LINKAGE_DATA_OFFSET
#endif // ONLY_COPY
        }
    } else if(ismemwrite) {
        if(!immval) {
            //mov register to memory location
            INSTRUMENT_PRINT(log_f, "instrument mov is mem write: reg: %d, \
                    reg size %u, size of mem write is %u\n",
                    reg, REG_Size(reg), addrsize);
#ifdef COPY_ONLY
            pred_instrument_taint_reg2mem(ins, reg, 0);
#else 
 #ifndef LINKAGE_DATA_OFFSET
            pred_instrument_taint_reg2mem(ins, reg, 0);
 #else
            REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
            REG base_reg = INS_OperandMemoryBaseReg(ins, 0);

            if (REG_valid(base_reg) && REG_valid(index_reg)) {
                pred_instrument_taint_reg2mem(ins, index_reg, 0);
                pred_instrument_taint_add_reg2mem(ins, base_reg);
                pred_instrument_taint_add_reg2mem(ins, reg);
            } else if (REG_valid(base_reg)) {
                pred_instrument_taint_reg2mem(ins, base_reg, 0);
                pred_instrument_taint_add_reg2mem(ins, reg);
            } else if (REG_valid(index_reg)) {
                assert(0);
            } else { 
                pred_instrument_taint_mem2reg(ins, reg, 1);
            }
 #endif // LINKAGE_DATA_OFFSET
#endif // ONLY_COPY
        } else {
            //move immediate to memory location
            pred_instrument_taint_immval2mem(ins);
        }
    } else if (!SPECIAL_REG(dstreg)) {
        if(immval) {
            treg = translate_reg((int)dstreg);
            //mov immediate value into register
            switch(addrsize) {
                case 1:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 2:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2hwreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 4:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2wreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 8:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2dwreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, treg, IARG_END);
                    break;
               case 16:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_immval2qwreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, treg, IARG_END);
                    break;
               default:
                    break;
            }
        } else {
            //mov one reg val into another
            assert(REG_Size(reg) == REG_Size(dstreg));
            int dst_treg = translate_reg((int)dstreg);
            int src_treg = translate_reg((int)reg);

            INSTRUMENT_PRINT(log_f, "instrument cmov is src reg: %d into dst reg: %d\n", reg, dstreg); 

            switch(REG_Size(reg)) {
                case 1:
                    if (REG_is_Lower8(dstreg) && REG_is_Lower8(reg)) {
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2lbreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                    } else if (REG_is_Lower8(dstreg) && REG_is_Upper8(reg)) {
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2ubreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                    } else if (REG_is_Upper8(dstreg) && REG_is_Lower8(reg)) {
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2lbreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                    } else if (REG_is_Upper8(dstreg) && REG_is_Upper8(reg)) {
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_ubreg2ubreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
                    } else {
                        ERROR_PRINT (log_f, "[ERROR] instrument_mov, unknown combo of 1 byte regs\n");
                    }
                    break;
                case 2:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_hwreg2hwreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                    break;
                case 4:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_wreg2wreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                    break;
                case 8:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_dwreg2dwreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                    break;
                case 16:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                            AFUNPTR(taint_qwreg2qwreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_UINT32, dst_treg,
                            IARG_UINT32, src_treg,
                            IARG_END);
                    break;
            }
        }
    }
}

void instrument_rotate(INS ins)
{
    // TODO
    assert(0);
    if (INS_OperandWidth(ins, 0) == 8) {
        // we only track taint at a byte granularily,
        //  rotating 8 bits doesn't affect the taint
        return;
    }
}

void instrument_shift(INS ins)
{
    int count = INS_OperandCount(ins);
    if(count == 2) {
        // TODO ctrlflow
    } else if (count == 3) {
        if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
            fprintf(stderr, "shift 3: %s\n", INS_Disassemble(ins).c_str());
            fprintf(stderr, "src reg is %s, dst reg is %s\n", REG_StringShort(INS_OperandReg(ins, 1)).c_str(),
                    REG_StringShort(INS_OperandReg(ins, 0)).c_str());
            instrument_taint_add_reg2reg(ins, INS_OperandReg(ins, 0),
                                            INS_OperandReg(ins, 1));
        }
    } else if (count == 4) {
        if (INS_OperandIsReg(ins, 2)) {
            fprintf(stderr, "2 %s\n", REG_StringShort(INS_OperandReg(ins, 2)).c_str());
            if (INS_OperandIsReg(ins, 0)) {
                instrument_taint_add_reg2reg(ins, INS_OperandReg(ins, 0),
                        INS_OperandReg(ins, 2));
            }
            if(INS_OperandIsReg(ins, 1)) {
                instrument_taint_add_reg2reg(ins, INS_OperandReg(ins, 1),
                        INS_OperandReg(ins, 2));
            } else if (INS_OperandIsMemory(ins, 1)) {
                instrument_taint_add_reg2mem(ins, INS_OperandReg(ins, 2));
            }
        }
    }
}

void instrument_lea(INS ins)
{
    REG dstreg = INS_OperandReg(ins, 0);
    REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
    REG index_reg = INS_OperandMemoryIndexReg(ins, 1);

    if (REG_valid (index_reg) && !REG_valid(base_reg)) {
        // This is a nummeric calculation in disguise
        INSTRUMENT_PRINT (log_f, "LEA: index reg is %d(%s) base reg invalid, dst %d(%s)\n",
                index_reg, REG_StringShort(index_reg).c_str(),
                dstreg, REG_StringShort(dstreg).c_str());
        assert(REG_Size(index_reg) == REG_Size(dstreg));
        switch(REG_Size(dstreg)) {
            case 4:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dstreg,
                        IARG_UINT32, index_reg,
                        IARG_END);
                break;
            default:
                ERROR_PRINT (log_f, "[ERROR] instrument_lea\n");
                break;
        }
    } else {
        //loading an effective address clears the dep set of the target
        //register.. then we add the depsets of the base/index regs used.
        // Looks like Mona decided not to do the above???
        switch(REG_Size(dstreg)) {
            case 4:
                INS_InsertCall(ins, IPOINT_BEFORE,
                        AFUNPTR(taint_immval2wreg),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_UINT32, dstreg,
                        IARG_END);
                break;
            default:
                ERROR_PRINT (log_f, "[ERROR] taint_immval2reg dstreg %d(%s) size is %d\n",
                        dstreg, REG_StringShort(dstreg).c_str(), REG_Size(dstreg));
                assert(0);
                break;
        }
    }
}

void instrument_push(INS ins)
{
    USIZE addrsize = INS_MemoryWriteSize(ins);
    int src_reg = INS_OperandIsReg(ins, 0);
    int src_imm = INS_OperandIsImmediate(ins, 0);

    if (src_imm) {
        switch(addrsize) {
            case 1:
                INS_InsertCall (ins, IPOINT_BEFORE,
                                        AFUNPTR(taint_immvalb2mem),
#ifdef FAST_INLINE
                                        IARG_FAST_ANALYSIS_CALL,
#endif
                                        IARG_MEMORYWRITE_EA,
                                        IARG_END);
                break;
            case 2:
                INS_InsertCall (ins, IPOINT_BEFORE,
                                        AFUNPTR(taint_immvalhw2mem),
#ifdef FAST_INLINE
                                        IARG_FAST_ANALYSIS_CALL,
#endif
                                        IARG_MEMORYWRITE_EA,
                                        IARG_END);
                break;
            case 4:
                INS_InsertCall (ins, IPOINT_BEFORE,
                                        AFUNPTR(taint_immvalw2mem),
#ifdef FAST_INLINE
                                        IARG_FAST_ANALYSIS_CALL,
#endif
                                        IARG_MEMORYWRITE_EA,
                                        IARG_END);
                break;
            default:
                ERROR_PRINT (log_f, "[ERROR]Unsupported imm push size\n");
                assert(0);
                break;
        }
    } else if (src_reg) {
        REG reg = INS_OperandReg(ins, 0);
        int treg = translate_reg(reg);
        assert(addrsize == REG_Size(reg));
        switch(addrsize) {
            case 1:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_lbreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 2:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_hwreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_wreg2mem),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYWRITE_EA,
                        IARG_UINT32, treg,
                        IARG_END);
                break;
            default:
                ERROR_PRINT (log_f, "[ERROR]Unsupported reg push size\n");
                assert(0);
                break;
        }
    } else {
        assert(INS_OperandIsMemory(ins, 0));
        switch(addrsize) {
            case 1:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2mem_b),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYWRITE_EA,
                        IARG_END);
                break;
            case 2:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2mem_hw),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYWRITE_EA,
                        IARG_END);
                break;
            case 4:
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2mem_w),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYWRITE_EA,
                        IARG_END);
                break;
            default:
                ERROR_PRINT (log_f, "[ERROR]Unsupported mem push size\n");
                assert(0);
                break;
        }
    }
}

void instrument_pop(INS ins)
{
    USIZE addrsize = INS_MemoryReadSize(ins);
    if (INS_OperandIsMemory(ins, 0)) {
        switch(addrsize) {
            case 1:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2mem_b),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYWRITE_EA,
                        IARG_END);
                break;
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_B,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
            case 2:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_HW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2mem_hw),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYWRITE_EA,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_HW,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
                break;
            case 4:
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_enter),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_W,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
                INS_InsertCall (ins, IPOINT_BEFORE,
                        AFUNPTR(taint_mem2mem_w),
#ifdef FAST_INLINE
                        IARG_FAST_ANALYSIS_CALL,
#endif
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYWRITE_EA,
                        IARG_END);
#ifdef TRACE_TAINT_OPS
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_taint_op_exit),
                    IARG_UINT32, trace_taint_outfd,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_UINT32, TAINT_MEM2MEM_W,
                    IARG_MEMORYWRITE_EA,
                    IARG_MEMORYREAD_EA,
                    IARG_END);
#endif
                break;
            default:
                ERROR_PRINT(log_f, "[ERROR] unsupported pop mem size\n");
                assert(0);
                break;
        }
    } else if (INS_OperandIsReg(ins, 0)) {
        REG reg = INS_OperandReg(ins, 0);
        int treg = translate_reg(reg);
        if (!SPECIAL_REG(reg)) {
            switch(addrsize) {
                case 1:
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2LBREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                    INS_InsertCall (ins, IPOINT_BEFORE,
                            AFUNPTR(taint_mem2lbreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2LBREG,
                            IARG_MEMORYWRITE_EA,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                    break;
                case 2:
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2HWREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                    INS_InsertCall (ins, IPOINT_BEFORE,
                            AFUNPTR(taint_mem2hwreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2HWREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                    break;
                case 4:
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_enter),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2WREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                    INS_InsertCall (ins, IPOINT_BEFORE,
                            AFUNPTR(taint_mem2wreg),
#ifdef FAST_INLINE
                            IARG_FAST_ANALYSIS_CALL,
#endif
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, treg,
                            IARG_END);
#ifdef TRACE_TAINT_OPS
                    INS_InsertCall(ins, IPOINT_BEFORE,
                            AFUNPTR(trace_taint_op_exit),
                            IARG_UINT32, trace_taint_outfd,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_UINT32, TAINT_MEM2WREG,
                            IARG_UINT32, treg,
                            IARG_MEMORYREAD_EA,
                            IARG_END);
#endif
                    break;
                default:
                    ERROR_PRINT(log_f, "[ERROR] unsupported pop reg size\n");
                    break;
            }
        }
    }
}

void instrument_addorsub(INS ins)
{
    int op1mem;
    int op2mem;
    int op1reg;
    int op2reg;
    int op2imm;

    OPCODE opcode;
    USIZE addrsize;

    opcode = INS_Opcode(ins);
    INSTRUMENT_PRINT(log_f, "instrument_addorsub: arith ins is %s (%#x)\n",
            INS_Mnemonic(ins).c_str(), INS_Address(ins));

    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op2imm = INS_OperandIsImmediate(ins, 1);

    if((op1mem && op2reg)) {
        REG reg = INS_OperandReg(ins, 1);
        if(!REG_valid(reg)) {
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is mem and op2 is register\n");
        addrsize = INS_MemoryWriteSize(ins);
        assert (REG_Size(reg) == addrsize);
        instrument_taint_add_reg2mem(ins, reg);
    } else if(op1reg && op2mem) {
        REG reg = INS_OperandReg(ins, 0);
        if(!INS_IsMemoryRead(ins) || !REG_valid(reg)) {
            //we ignore reads from video memory e.g. the gs segment register
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is register and op2 is mem\n");
        addrsize = INS_MemoryReadSize(ins);
        assert (addrsize == REG_Size(reg));
        instrument_taint_add_mem2reg(ins, reg);
    } else if(op1reg && op2reg) {
        REG reg;
        REG dstreg;

        dstreg = INS_OperandReg(ins, 0);
        reg = INS_OperandReg(ins, 1);
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 and op2 of Arith are registers: %d (%s), %d (%s)\n", 
                dstreg, REG_StringShort(dstreg).c_str(), reg, REG_StringShort(reg).c_str());
        if(!REG_valid(dstreg) || !REG_valid(reg)) {
            return;
        } 
        /*if((opcode == XED_ICLASS_XOR || opcode == XED_ICLASS_SUB || 
          opcode == XED_ICLASS_SBB || opcode == XED_ICLASS_PXOR ||
          opcode == XED_ICLASS_FSUB || opcode == XED_ICLASS_FSUBP ||
          opcode == XED_ICLASS_FSUBP || opcode == XED_ICLASS_FISUB ||
          opcode == XED_ICLASS_FSUBR || opcode == XED_ICLASS_FISUBR ||
          opcode == XED_ICLASS_FSUBRP || opcode == XED_ICLASS_XORPS ||
          opcode == XED_ICLASS_PSUBB || opcode == XED_ICLASS_PSUBW ||
          opcode == XED_ICLASS_PSUBD || opcode == XED_ICLASS_PSUBQ) 
          && (dstreg == reg)) {*/
        //TODO: think more about this part
        if((opcode == XED_ICLASS_SUB || opcode == XED_ICLASS_XOR ||
                    opcode == XED_ICLASS_PXOR || opcode == XED_ICLASS_XORPS)  
                && (dstreg == reg)) {
            int dst_treg = translate_reg(dstreg);
            INSTRUMENT_PRINT(log_f, "handling reg reset\n");
            switch(REG_Size(dstreg)) {
                case 1:
                    INS_InsertCall (ins, IPOINT_BEFORE,
                                            AFUNPTR(taint_immval2lbreg),
#ifdef FAST_INLINE
                                            IARG_FAST_ANALYSIS_CALL,
#endif
                                            IARG_UINT32, dst_treg,
                                            IARG_END);
                    break;
                case 2:
                    INS_InsertCall (ins, IPOINT_BEFORE,
                                            AFUNPTR(taint_immval2hwreg),
#ifdef FAST_INLINE
                                            IARG_FAST_ANALYSIS_CALL,
#endif
                                            IARG_UINT32, dst_treg,
                                            IARG_END);
                    break;
                case 4:
                    INS_InsertCall (ins, IPOINT_BEFORE,
                                            AFUNPTR(taint_immval2wreg),
#ifdef FAST_INLINE
                                            IARG_FAST_ANALYSIS_CALL,
#endif
                                            IARG_UINT32, dst_treg,
                                            IARG_END);
                    break;
                case 8:
                    INS_InsertCall (ins, IPOINT_BEFORE,
                                            AFUNPTR(taint_immval2dwreg),
#ifdef FAST_INLINE
                                            IARG_FAST_ANALYSIS_CALL,
#endif
                                            IARG_UINT32, dst_treg,
                                            IARG_END);
                    break;
                case 16:
                    INS_InsertCall (ins, IPOINT_BEFORE,
                                            AFUNPTR(taint_immval2qwreg),
#ifdef FAST_INLINE
                                            IARG_FAST_ANALYSIS_CALL,
#endif
                                            IARG_UINT32, dst_treg,
                                            IARG_END);
                    break;
                default:
                    ERROR_PRINT (log_f, "instrument_addorsub - reg reset unhandled size %d\n", REG_Size(reg));
                    assert(0);
                    break;
            }
        } else {
            assert (REG_Size(dstreg) == REG_Size(reg));
            if (dstreg != reg) {
                instrument_taint_add_reg2reg(ins, dstreg, reg);
            }
        }
    } else if(op1mem && op2imm) {
        /*imm does not change taint value of the destination*/
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is mem and op2 is immediate\n");
        addrsize = INS_MemoryWriteSize(ins);
        switch (addrsize) {
            case 1:
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_immvalb2mem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_END);
                break;
            case 2:
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_immvalhw2mem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_END);
                break;
            case 4:
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_immvalw2mem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_END);
                break;
            case 8:
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_immvaldw2mem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_END);
                break;
            case 16:
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_immvalqw2mem),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYWRITE_EA,
                                    IARG_END);
                break;
            default:
                ERROR_PRINT (log_f, "instrument_addorsub: unhandled op size\n");
                assert(0);
                break;
        }
    } else if(op1reg && op2imm){
        REG reg = INS_OperandReg(ins, 0);
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is reg (%d) and op2 is immediate\n", reg);
        if (!SPECIAL_REG(reg)) {
            int treg = translate_reg(reg);
            INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is reg and op2 is immediate\n");
            switch(REG_Size(reg)) {
                case 1:
                    INS_InsertCall (ins, IPOINT_BEFORE,
                                            AFUNPTR(taint_immval2lbreg),
#ifdef FAST_INLINE
                                            IARG_FAST_ANALYSIS_CALL,
#endif
                                            IARG_UINT32, treg,
                                            IARG_END);
                    break;
                case 2:
                    INS_InsertCall (ins, IPOINT_BEFORE,
                                            AFUNPTR(taint_immval2hwreg),
#ifdef FAST_INLINE
                                            IARG_FAST_ANALYSIS_CALL,
#endif
                                            IARG_UINT32, treg,
                                            IARG_END);
                    break;
                case 4:
                    INS_InsertCall (ins, IPOINT_BEFORE,
                                            AFUNPTR(taint_immval2hwreg),
#ifdef FAST_INLINE
                                            IARG_FAST_ANALYSIS_CALL,
#endif
                                            IARG_UINT32, treg,
                                            IARG_END);
                    break;
                default:
                    ERROR_PRINT (log_f, "instrument_addorsub - reg reset unhandled size %d\n", REG_Size(reg));
                    assert(0);
                    break;
            }
        }
    } else {
        //if the arithmatic involves an immediate instruction the taint does
        //not propagate...
        string instruction;
        instruction = INS_Disassemble(ins);
        printf("unknown combination of arithmatic ins: %s\n", instruction.c_str());
    }
}

/* Divide has 3 operands.
 *
 *  r/m, AX, AL/H/X <- quotient, AH <- remainder
 * */
void instrument_div(INS ins)
{
    INSTRUMENT_PRINT (log_f, "div instruction: %s\n", INS_Disassemble(ins).c_str());
    if (INS_IsMemoryRead(ins)) {
        UINT32 addrsize;
        // Register translations
        int msb_treg, lsb_treg, dst1_treg, dst2_treg;

        addrsize = INS_MemoryReadSize(ins);
        switch (addrsize) {
            case 2:
                // mem_loc is Divisor
                lsb_treg = translate_reg(LEVEL_BASE::REG_AX); // Dividend
                dst1_treg = translate_reg(LEVEL_BASE::REG_AL); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_AH); // Remainder
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add2_hwmemhwreg_2breg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, lsb_treg,
                                    IARG_UINT32, dst1_treg,
                                    IARG_UINT32, dst2_treg,
                                    IARG_END);
                break;
            case 4:
                // mem_loc is Divisor
                msb_treg = translate_reg(LEVEL_BASE::REG_DX);
                lsb_treg = translate_reg(LEVEL_BASE::REG_AX); // Dividend
                dst1_treg = translate_reg(LEVEL_BASE::REG_AX); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_DX); // Remainder
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add2_wmemwreg_2hwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, lsb_treg,
                                    IARG_UINT32, dst1_treg,
                                    IARG_UINT32, dst2_treg,
                                    IARG_END);
                break;
            case 8:
                // Dividend is msb_treg:lsb_treg
                // Divisor is src_treg
                msb_treg = translate_reg(LEVEL_BASE::REG_EDX);
                lsb_treg = translate_reg(LEVEL_BASE::REG_EAX);
                dst1_treg = translate_reg(LEVEL_BASE::REG_EAX); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_EDX); // Remainder
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add3_dwmem2wreg_2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, msb_treg,
                                IARG_UINT32, lsb_treg,
                                IARG_UINT32, dst1_treg,
                                IARG_UINT32, dst2_treg,
                                IARG_END);
                break;
            default:
                ERROR_PRINT(log_f, "[ERROR] Unsupported div sizes\n");
                ERROR_PRINT (log_f, "div ins: %s\n", INS_Disassemble(ins).c_str());
                assert(0);
                break;
        }
    } else {
        UINT32 size;
        REG src_reg;

        // Register translations
        int msb_treg, lsb_treg, src_treg, dst1_treg, dst2_treg;

        assert (INS_OperandIsReg(ins, 0));
        src_reg = INS_OperandReg(ins, 0);
        src_treg = translate_reg(src_reg);
        size = REG_Size(src_reg);
        // fprintf (stderr, "div: src_reg is %d(%s) size is %d\n", src_reg, REG_StringShort(src_reg).c_str(), size);
        switch (size) {
            case 1:
                lsb_treg = translate_reg(LEVEL_BASE::REG_AX); // Dividend
                dst1_treg = translate_reg(LEVEL_BASE::REG_AL); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_AH); // Remainder
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add2_hwregbreg_2breg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, lsb_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_UINT32, dst1_treg,
                                    IARG_UINT32, dst2_treg,
                                    IARG_END);
                break;
            case 2:
                lsb_treg = translate_reg(LEVEL_BASE::REG_AX); // Dividend
                dst1_treg = translate_reg(LEVEL_BASE::REG_AL); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_AH); // Remainder
                INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add2_2hwreg_2breg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, lsb_treg,
                                    IARG_UINT32, src_treg,
                                    IARG_UINT32, dst1_treg,
                                    IARG_UINT32, dst2_treg,
                                    IARG_END);
                break;
            case 4:
                // Dividend is msb_treg:lsb_treg
                // Divisor is src_treg
                msb_treg = translate_reg(LEVEL_BASE::REG_DX);
                lsb_treg = translate_reg(LEVEL_BASE::REG_AX);
                dst1_treg = translate_reg(LEVEL_BASE::REG_AX); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_DX); // Remainder
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add3_2hwreg_2hwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, msb_treg,
                                IARG_UINT32, lsb_treg,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, dst1_treg,
                                IARG_UINT32, dst2_treg,
                                IARG_END);
                break;
            case 8:
                // Dividend is msb_treg:lsb_treg
                // Divisor is src_treg
                msb_treg = translate_reg(LEVEL_BASE::REG_EDX);
                lsb_treg = translate_reg(LEVEL_BASE::REG_EAX);
                dst1_treg = translate_reg(LEVEL_BASE::REG_EAX); // Quotient
                dst2_treg = translate_reg(LEVEL_BASE::REG_EDX); // Remainder
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add3_2wreg_2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, msb_treg,
                                IARG_UINT32, lsb_treg,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, dst1_treg,
                                IARG_UINT32, dst2_treg,
                                IARG_END);
                break;
            default:
                ERROR_PRINT(log_f, "[ERROR] Unsupport div sizes\n");
                ERROR_PRINT (log_f, "div ins: %s\n", INS_Disassemble(ins).c_str());
                assert(0);
                break;
        }
    }
}

void instrument_mul(INS ins)
{
    INSTRUMENT_PRINT (log_f, "mul instruction: %s\n", INS_Disassemble(ins).c_str());
    if (INS_IsMemoryRead(ins)) {
        int lsb_dst_treg, msb_dst_treg;
        int src_treg;
        UINT32 addrsize;

        addrsize = INS_MemoryReadSize(ins);
        switch (addrsize) {
            case 1:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_AX);
                src_treg = translate_reg(LEVEL_BASE::REG_AL);
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_bmemlbreg_hwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_END);
                break;
            case 2:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_AX); 
                msb_dst_treg = translate_reg(LEVEL_BASE::REG_DX);
                src_treg = translate_reg(LEVEL_BASE::REG_AX); 
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_hwmemhwreg_2hwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_UINT32, msb_dst_treg,
                                IARG_END);
                break;
            case 4:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_EAX); 
                msb_dst_treg = translate_reg(LEVEL_BASE::REG_EDX);
                src_treg = translate_reg(LEVEL_BASE::REG_EAX); 
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_wmemwreg_2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, src_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_UINT32, msb_dst_treg,
                                IARG_END);
                break;
            default:
                ERROR_PRINT(log_f, "[ERROR] Unsupported mul sizes\n");
                ERROR_PRINT (log_f, "mul ins: %s\n", INS_Disassemble(ins).c_str());
                assert(0);
                break;
        }
    } else if (INS_OperandIsReg(ins, 0)) {
        REG src2_reg;
        int lsb_dst_treg, msb_dst_treg;
        int src_treg, src2_treg;

        assert (INS_OperandIsReg(ins, 0));
        src2_reg = INS_OperandReg(ins, 0);

        switch(REG_Size(src2_reg)) {
            case 1:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_AX);
                src_treg = translate_reg(LEVEL_BASE::REG_AL);
                src2_treg = translate_reg(src2_reg);
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_lbreglbreg_hwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, src_treg,
                                IARG_UINT32, src2_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_END);
                break;
            case 2:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_AX);
                msb_dst_treg = translate_reg(LEVEL_BASE::REG_DX);
                src_treg = translate_reg(LEVEL_BASE::REG_AX);
                src2_treg = translate_reg(src2_reg);
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_hwreghwreg_2hwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, src_treg,
                                IARG_UINT32, src2_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_UINT32, msb_dst_treg,
                                IARG_END);
                break;
            case 4:
                lsb_dst_treg = translate_reg(LEVEL_BASE::REG_EAX);
                msb_dst_treg = translate_reg(LEVEL_BASE::REG_EDX);
                src_treg = translate_reg(LEVEL_BASE::REG_EAX);
                src2_treg = translate_reg(src2_reg);
                INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_add2_wregwreg_2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, src_treg,
                                IARG_UINT32, src2_treg,
                                IARG_UINT32, lsb_dst_treg,
                                IARG_UINT32, msb_dst_treg,
                                IARG_END);
                break;
            default:
                ERROR_PRINT(log_f, "[ERROR] Unsupported mul sizes\n");
                ERROR_PRINT (log_f, "mul ins: %s\n", INS_Disassemble(ins).c_str());
                assert(0);
                break;
        }
    } else {
        ERROR_PRINT(log_f, "[ERROR] Unsupported mul sizes\n");
        ERROR_PRINT (log_f, "mul ins: %s\n", INS_Disassemble(ins).c_str());
        assert(0);
    }
}

void instrument_imul(INS ins)
{
    int count;
    INSTRUMENT_PRINT (log_f, "imul instruction: %s\n", INS_Disassemble(ins).c_str());
    count = INS_OperandCount(ins);
    INSTRUMENT_PRINT (log_f, "num operands is %d\n", count);
    if (count == 2) {
        // one operand version is same as mul
        INSTRUMENT_PRINT (log_f, "imul is the 2 operand version\n");
        INSTRUMENT_PRINT (log_f, "imul instruction: %s\n", INS_Disassemble(ins).c_str());
        instrument_mul(ins);
    } else if (count == 3) {
        // two operand version is taint_add src to dst
        REG dst_reg;
        int dst_treg;
        assert (INS_OperandIsReg(ins, 0));
        dst_reg = INS_OperandReg(ins, 0);
        dst_treg = translate_reg(dst_reg);
        if (INS_IsMemoryRead(ins)) {
            assert (REG_Size(dst_reg) == INS_MemoryReadSize(ins));
            switch(REG_Size(dst_reg)) {
                case 2:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_hwmem2hwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, dst_treg,
                                    IARG_END);
                    break;
                case 4:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                   AFUNPTR(taint_add_wmem2wreg),
#ifdef FAST_INLINE
                                   IARG_FAST_ANALYSIS_CALL,
#endif
                                   IARG_MEMORYREAD_EA,
                                   IARG_UINT32, dst_treg,
                                   IARG_END);
                    break;
                case 8:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_dwmem2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, dst_treg,
                                    IARG_END);
                    break;
                case 16:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_qwmem2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_MEMORYREAD_EA,
                                    IARG_UINT32, dst_treg,
                                    IARG_END);
                    break;
                default:
                    ERROR_PRINT(log_f, "[ERROR] imul unsupported sizes\n");
                    ERROR_PRINT (log_f, "imul instruction: %s\n", INS_Disassemble(ins).c_str());
                    assert(0);
                    break;
            }
        } else {
            REG src_reg;
            int src_treg;

            assert (INS_OperandIsReg(ins, 1));
            src_reg = INS_OperandReg(ins, 1);
            src_treg = translate_reg(src_reg);
            assert (REG_Size(dst_reg) == REG_Size(src_reg));
            switch (REG_Size(dst_reg)) {
                case 4:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                   AFUNPTR(taint_add_wreg2wreg),
#ifdef FAST_INLINE
                                   IARG_FAST_ANALYSIS_CALL,
#endif
                                   IARG_UINT32, src_treg,
                                   IARG_UINT32, dst_treg,
                                   IARG_END);
                    break;
                case 8:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_dwreg2dwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, src_treg,
                                    IARG_UINT32, dst_treg,
                                    IARG_END);
                    break;
                case 16:
                    INS_InsertCall(ins, IPOINT_BEFORE,
                                    AFUNPTR(taint_add_qwreg2qwreg),
#ifdef FAST_INLINE
                                    IARG_FAST_ANALYSIS_CALL,
#endif
                                    IARG_UINT32, src_treg,
                                    IARG_UINT32, dst_treg,
                                    IARG_END);
                    break;
                default:
                    ERROR_PRINT(log_f, "[ERROR] imul unsupported sizes\n");
                    ERROR_PRINT (log_f, "imul instruction: %s\n", INS_Disassemble(ins).c_str());
                    assert(0);
                    break;

            }
        }
    } else if (count == 4) {
        // three operand version is taint src to dst
        if (INS_OperandIsReg(ins, 0)) {
            REG dst_reg;
            int dst_treg;
            assert (INS_OperandIsReg(ins, 0));

            dst_reg = INS_OperandReg(ins, 0);
            dst_treg = translate_reg(dst_reg);

            if (INS_IsMemoryRead(ins)) {
                UINT32 addrsize;
                addrsize = INS_MemoryReadSize(ins);
                assert (addrsize == REG_Size(dst_reg));
                switch (addrsize) {
                    case 4:
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_mem2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, dst_treg,
                                IARG_END);
                        break;
                    case 8:
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_mem2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, dst_treg,
                                IARG_END);
                        break;
                    case 16:
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_mem2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, dst_treg,
                                IARG_END);
                        break;
                    default:
                        ERROR_PRINT (log_f, "[ERROR] imul unsupported size\n");
                        ERROR_PRINT (log_f, "imul ins: %s\n", INS_Disassemble(ins).c_str());
                        assert(0);
                        break;
                }
            } else {
                REG src_reg;
                int src_treg;

                assert (INS_OperandIsReg(ins, 1));
                src_reg = INS_OperandReg(ins, 1);
                src_treg = translate_reg(src_reg);
                assert (REG_Size(dst_reg) == REG_Size(src_reg));
                switch (REG_Size(dst_reg)) {
		    case 1:
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_lbreg2hwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, src_treg,
                                IARG_UINT32, dst_treg,
                                IARG_END);
                        break;
		      
                    case 2:
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_hwreg2hwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, src_treg,
                                IARG_UINT32, dst_treg,
                                IARG_END);
                        break;
                    case 4:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op_enter),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_WREG2WREG,
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_wreg2wreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, src_treg,
                                IARG_UINT32, dst_treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op_exit),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_WREG2WREG,
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
#endif
                        break;
                    case 8:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op_enter),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_DWREG2DWREG,
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_dwreg2dwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, src_treg,
                                IARG_UINT32, dst_treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op_exit),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_DWREG2DWREG,
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
#endif
                        break;
                    case 16:
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op_enter),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_QWREG2QWREG,
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
#endif
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(taint_qwreg2qwreg),
#ifdef FAST_INLINE
                                IARG_FAST_ANALYSIS_CALL,
#endif
                                IARG_UINT32, src_treg,
                                IARG_UINT32, dst_treg,
                                IARG_END);
#ifdef TRACE_TAINT_OPS
                        INS_InsertCall(ins, IPOINT_BEFORE,
                                AFUNPTR(trace_taint_op_exit),
                                IARG_UINT32, trace_taint_outfd,
                                IARG_THREAD_ID,
                                IARG_INST_PTR,
                                IARG_UINT32, TAINT_QWREG2QWREG,
                                IARG_UINT32, dst_treg,
                                IARG_UINT32, src_treg,
                                IARG_END);
#endif
                        break;
                    default:
                        ERROR_PRINT(log_f, "[ERROR] imul unsupported sizes\n");
                        ERROR_PRINT (log_f, "imul instruction: %s\n", INS_Disassemble(ins).c_str());
                        assert(0);
                        break;
                }
            }
        } else {
            // in this case the instruction looks like this:
            //   imul dword ptr [esp+0x88]
            //   which is just like the 2 count version,
            //   it's 4 because of the index register
            instrument_mul(ins);
        }
    }
}

void instrument_palignr(INS ins)
{
    UINT32 imm;
    REG reg;
    int treg;
    assert(INS_OperandIsImmediate(ins, 2));
    assert(INS_OperandIsReg(ins, 0));

    imm = INS_OperandImmediate(ins, 2);
    assert(imm > 0 && imm < 16);
    reg = INS_OperandReg(ins, 0);

    treg = translate_reg((int)reg);
    if (INS_OperandIsMemory(ins, 1)) {
        UINT32 addrsize;
        addrsize = INS_MemoryReadSize(ins);
        assert(addrsize == REG_Size(reg));
        assert(addrsize == 8 || addrsize == 16);

        if (addrsize == 8) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_palignr_mem2dwreg),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_UINT32, treg,
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, imm,
                    IARG_END);
        } else if (addrsize == 16) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_palignr_mem2qwreg),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_UINT32, treg,
                    IARG_MEMORYREAD_EA,
                    IARG_UINT32, imm,
                    IARG_END);
        } else {
            assert(0);
        }

    } else if (INS_OperandIsReg(ins, 1)) {
        REG reg2 = INS_OperandReg(ins, 1);
        int treg2 = translate_reg((int)reg2);

        assert(REG_Size(reg) == REG_Size(reg2));

        if (REG_Size(reg2) == 8) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_palignr_dwreg2dwreg),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_UINT32, treg,
                    IARG_UINT32, treg2,
                    IARG_UINT32, imm,
                    IARG_END);
        } else if (REG_Size(reg2) == 16) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(taint_palignr_qwreg2qwreg),
#ifdef FAST_INLINE
                    IARG_FAST_ANALYSIS_CALL,
#endif
                    IARG_UINT32, treg,
                    IARG_UINT32, treg2,
                    IARG_UINT32, imm,
                    IARG_END);
        }
    } else {
        assert(0);
    }
}

void instrument_psrldq(INS ins)
{
    assert(INS_OperandIsReg(ins, 0));
    assert(INS_OperandIsImmediate(ins, 1));
    int treg = translate_reg(INS_OperandReg(ins, 0));
    int shift = INS_OperandImmediate(ins, 1);

    INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(shift_reg_taint_right),
                    IARG_UINT32, treg,
                    IARG_UINT32, shift,
                    IARG_END);
}

void instrument_pmovmskb(INS ins)
{
    int src_treg;
    int dst_treg;

    assert(INS_OperandIsReg(ins, 0));
    assert(INS_OperandIsReg(ins, 1));
    assert(REG_Size(INS_OperandReg(ins, 0)) == 4);
    assert(REG_Size(INS_OperandReg(ins, 1)) == 16);

    dst_treg = translate_reg(INS_OperandReg(ins, 0));
    src_treg = translate_reg(INS_OperandReg(ins, 1));

#ifdef TRACE_TAINT_OPS
    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(trace_taint_op_enter),
            IARG_UINT32, trace_taint_outfd,
            IARG_THREAD_ID,
            IARG_INST_PTR,
            IARG_UINT32, TAINT_MASK_REG2REG,
            IARG_UINT32, dst_treg,
            IARG_UINT32, src_treg,
            IARG_END);
#endif

    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(taint_mask_reg2reg),
#ifdef FAST_INLINE
            IARG_FAST_ANALYSIS_CALL,
#endif
            IARG_UINT32, dst_treg,
            IARG_UINT32, src_treg,
            IARG_END);

#ifdef TRACE_TAINT_OPS
    INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(trace_taint_op_exit),
            IARG_UINT32, trace_taint_outfd,
            IARG_THREAD_ID,
            IARG_INST_PTR,
            IARG_UINT32, TAINT_MASK_REG2REG,
            IARG_UINT32, dst_treg,
            IARG_UINT32, src_treg,
            IARG_END);
#endif
}

#ifdef TAINT_DEBUG
void trace_inst(ADDRINT ptr)
{
    taint_debug_inst = ptr;
}
#endif
#if 0
void trace_inst(ADDRINT ip)
{
    if (*ppthread_log_clock > 12769910 && *ppthread_log_clock < 12769938) { 
	PIN_LockClient();
        printf("[INST] Pid %d (tid: %d) (record %d) - %#x clock %lu\n", PIN_GetPid(), PIN_GetTid(), get_record_pid(), ip, *ppthread_log_clock);
	if (IMG_Valid(IMG_FindByAddress(ip))) {
		printf("%s -- img %s static %#x\n", RTN_FindNameByAddress(ip).c_str(), IMG_Name(IMG_FindByAddress(ip)).c_str(), find_static_address(ip));
	}
	PIN_UnlockClient();
    }
}
#endif

void instruction_instrumentation(INS ins, void *v)
{
    OPCODE opcode;
    UINT32 category;
    int instrumented = 0;

#ifdef TAINT_STATS
    inst_instrumented++;
#endif
    if(INS_IsSyscall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_syscall),
                IARG_SYSCALL_NUMBER, 
                IARG_SYSARG_VALUE, 0, 
                IARG_SYSARG_VALUE, 1,
                IARG_SYSARG_VALUE, 2,
                IARG_SYSARG_VALUE, 3,
                IARG_SYSARG_VALUE, 4,
                IARG_SYSARG_VALUE, 5,
                IARG_END);
    }

    opcode = INS_Opcode(ins);
    category = INS_Category(ins);

#ifdef TAINT_DEBUG
    INS_InsertCall(ins, IPOINT_BEFORE,
                    AFUNPTR(trace_inst),
                    IARG_INST_PTR,
                    IARG_END);
#endif

#ifdef HEARTBLEED
    /*
    if (INS_Address(ins) == 0x811ac28 || INS_Address(ins) == 0x811ac2c) {
        fprintf(stderr, "found bad instruction!");
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)instrument_before_badmemcpy, IARG_END);
    }
    */
#endif

    // TODO: control flow
    switch(opcode) {
        case XED_ICLASS_JMP:
        case XED_ICLASS_JB:
        case XED_ICLASS_JNB:
        case XED_ICLASS_JBE:
        case XED_ICLASS_JNBE:
        case XED_ICLASS_JL:
        case XED_ICLASS_JNL:
        case XED_ICLASS_JLE:
        case XED_ICLASS_JNLE:
        case XED_ICLASS_JNO:
        case XED_ICLASS_JO:
        case XED_ICLASS_JNP:
        case XED_ICLASS_JP:
        case XED_ICLASS_JNS:
        case XED_ICLASS_JS:
        case XED_ICLASS_JNZ:
        case XED_ICLASS_JZ:
            instrumented = 1;
            break;
    }

#ifdef USE_CODEFLUSH_TRICK
    if (option_cnt != 0) {
#endif
    if (INS_IsMov(ins)) {
        instrument_mov(ins);
    } else if (category == XED_CATEGORY_CMOV) {
        // We separate out the tainting of the movement of data with
        //  cf, since we can do so much faster if we don't care about cf
#ifdef CTRL_FLOW
        // TODO
        instrument_cmov_cf(ins);
#else
        instrument_cmov(ins);
#endif
    } else if (category == XED_CATEGORY_SHIFT) {
#ifdef ONLY_COPY
        instrument_clear_dst(ins);
#else
        // instrument_shift(ins);
#endif
    } else {
        switch(opcode) {
            // Move and sign/zero extend
            case XED_ICLASS_MOVSX:
            case XED_ICLASS_MOVZX:
                //flags affected: none
                instrument_movx(ins);
                break;
            case XED_ICLASS_MOVD:
            case XED_ICLASS_MOVQ:
                instrument_movx(ins);
                break;
            case XED_ICLASS_MOVDQU:
            case XED_ICLASS_MOVDQA:
            case XED_ICLASS_MOVAPS:
            case XED_ICLASS_MOVUPS:
            case XED_ICLASS_MOVLPD:
            case XED_ICLASS_MOVHPD:
            case XED_ICLASS_MOVNTDQA:
            case XED_ICLASS_MOVNTDQ:
                instrument_mov(ins);
                break;
            case XED_ICLASS_PALIGNR:
                instrument_palignr(ins);
                break;
            case XED_ICLASS_MOVSB:
            case XED_ICLASS_MOVSW:
            case XED_ICLASS_MOVSD:
            case XED_ICLASS_MOVSQ:
                instrument_move_string(ins);
                break;
            case XED_ICLASS_STOSB:
            case XED_ICLASS_STOSW:
            case XED_ICLASS_STOSD:
            case XED_ICLASS_STOSQ:
                instrument_store_string(ins);
                break;
            case XED_ICLASS_LODSB:
            case XED_ICLASS_LODSW:
            case XED_ICLASS_LODSD:
            case XED_ICLASS_LODSQ:
                instrument_load_string(ins);
                break;
            case XED_ICLASS_XCHG:
                instrument_xchg(ins);
                break;
            case XED_ICLASS_BSWAP:
                instrument_bswap(ins);
                break;
                /*
            case XED_ICLASS_CMPXCHG:
                instrument_cmpxchg(ins);
                break;
                */
            case XED_ICLASS_PUSH:
                instrument_push(ins);
                break;
            case XED_ICLASS_POP:
                instrument_pop(ins);
                break;
            case XED_ICLASS_LEA:
                instrument_lea(ins);
                break;
            case XED_ICLASS_XADD:
                instrument_xchg(ins);
                instrument_addorsub(ins);
                break;
            case XED_ICLASS_ADD:
            case XED_ICLASS_SUB:
            case XED_ICLASS_SBB:
            case XED_ICLASS_OR:
            case XED_ICLASS_AND:
            case XED_ICLASS_XOR:
#ifdef COPY_ONLY
                instrument_clear_dst(ins);
#else
                instrument_addorsub(ins);
#endif
                break;
            case XED_ICLASS_ADC:
#ifdef COPY_ONLY
                instrument_clear_dst(ins);
#else
                instrument_addorsub(ins);
#ifdef CTRL_FLOW
                // TODO extra taint movement for flags
#endif
#endif
                break;
            case XED_ICLASS_DIV:
            case XED_ICLASS_IDIV:
#ifdef COPY_ONLY
                instrument_clear_reg(ins, LEVEL_BASE::REG_EAX);
#else
                instrument_div(ins);
#endif
                break;
            case XED_ICLASS_MUL:
#ifdef COPY_ONLY
                instrument_clear_reg(ins, LEVEL_BASE::REG_EAX);
#else
                instrument_mul(ins);
#endif
                break;
            case XED_ICLASS_IMUL:
                instrument_imul(ins);
                break;
            // now all of the XMM packed instructions
            case XED_ICLASS_POR:
            case XED_ICLASS_PAND:
            case XED_ICLASS_PANDN:
            case XED_ICLASS_PXOR:
            case XED_ICLASS_PADDB:
            case XED_ICLASS_PADDW:
            case XED_ICLASS_PADDD:
            case XED_ICLASS_PADDQ:
            case XED_ICLASS_PSUBB:
            case XED_ICLASS_PSUBW:
            case XED_ICLASS_PSUBD:
            case XED_ICLASS_PSUBQ:
            case XED_ICLASS_PMADDWD:
            case XED_ICLASS_PMULHUW:
            case XED_ICLASS_PMINUB:
            case XED_ICLASS_PMULLW:
            case XED_ICLASS_PADDUSW:
            case XED_ICLASS_PADDUSB:
            case XED_ICLASS_PACKUSWB:
            case XED_ICLASS_PSHUFHW:
            case XED_ICLASS_PSHUFLW:
            case XED_ICLASS_XORPS:
            case XED_ICLASS_SUBSD:
            case XED_ICLASS_DIVSD:
#ifdef COPY_ONLY
                instrument_clear_dst(ins);
#else
                instrument_addorsub(ins);
#endif
                break;
            case XED_ICLASS_PCMPEQB:
            case XED_ICLASS_PCMPEQW:
            case XED_ICLASS_PCMPEQD:
            case XED_ICLASS_PCMPGTB:
            case XED_ICLASS_PCMPGTW:
            case XED_ICLASS_PCMPGTD:
            case XED_ICLASS_PCMPGTQ:
#ifdef COPY_ONLY
                instrument_clear_dst(ins);
#else
                instrument_addorsub(ins);
#endif
                break;
            case XED_ICLASS_PSRLDQ:
                instrument_psrldq(ins);
                break;
                /*
            case XED_ICLASS_PSRLW:
            case XED_ICLASS_PSRLD:
            case XED_ICLASS_PSRLQ:
                assert(0);
                break;
                */
            case XED_ICLASS_PMOVMSKB:
#ifdef COPY_ONLY
                instrument_clear_dst(ins);
#else
                instrument_pmovmskb(ins);
#endif
                break;
            case XED_ICLASS_PUNPCKHBW:
            case XED_ICLASS_PUNPCKLBW:
            case XED_ICLASS_PUNPCKHWD:
            case XED_ICLASS_PUNPCKLWD:
            case XED_ICLASS_PUNPCKHDQ:
            case XED_ICLASS_PUNPCKLDQ:
            case XED_ICLASS_PUNPCKHQDQ:
            case XED_ICLASS_PUNPCKLQDQ:
                instrument_addorsub(ins);
                break;
                /*
            case XED_ICLASS_PSHUFD:
                break;
                */
            case XED_ICLASS_CALL_NEAR:
            case XED_ICLASS_CALL_FAR:
            case XED_ICLASS_RET_NEAR:
            case XED_ICLASS_RET_FAR:
                break;
#ifdef CTRL_FLOW
            // TODO
            // case XED_ICLASS_INC:
            // case XED_ICLASS_DEC:
            // case XED_ICLASS_NEG:
                // flags affected: all but CF
            //    break;
#else
            case XED_ICLASS_INC:
            case XED_ICLASS_DEC:
            case XED_ICLASS_NEG:
                // flags affected: all but CF
                break;
#endif
                /*
            case XED_ICLASS_ROR:
            case XED_ICLASS_ROL:
            case XED_ICLASS_RCL:
            case XED_ICLASS_RCR:
                instrument_rotate(ins);
                // flags affected: CF, OF
                break;
                */
#ifdef CTRL_FLOW
            case XED_ICLASS_SETB:
            case XED_ICLASS_SETNB:
            case XED_ICLASS_SETL:
            case XED_ICLASS_SETNL:
            case XED_ICLASS_SETNBE:
            case XED_ICLASS_SETBE:
            case XED_ICLASS_SETLE:
            case XED_ICLASS_SETNLE:
            case XED_ICLASS_SETNO:
            case XED_ICLASS_SETO:
            case XED_ICLASS_SETNP:
            case XED_ICLASS_SETP:
            case XED_ICLASS_SETNS:
            case XED_ICLASS_SETS:
            case XED_ICLASS_SETZ:
            case XED_ICLASS_SETNZ:
                // TODO
                break;
#else
            case XED_ICLASS_SETB:
            case XED_ICLASS_SETNB:
            case XED_ICLASS_SETL:
            case XED_ICLASS_SETNL:
            case XED_ICLASS_SETNBE:
            case XED_ICLASS_SETBE:
            case XED_ICLASS_SETLE:
            case XED_ICLASS_SETNLE:
            case XED_ICLASS_SETNO:
            case XED_ICLASS_SETO:
            case XED_ICLASS_SETNP:
            case XED_ICLASS_SETP:
            case XED_ICLASS_SETNS:
            case XED_ICLASS_SETS:
            case XED_ICLASS_SETZ:
            case XED_ICLASS_SETNZ:
                instrument_clear_dst(ins);
                break;
#endif
#ifdef CTRL_FLOW
            // TODO
           // case XED_ICLASS_BSF:
           // case XED_ICLASS_BSR:
           //     break;
#else
           case XED_ICLASS_BSF:
           case XED_ICLASS_BSR:
                instrument_clear_dst(ins);
                break;
#endif
#ifndef CTRL_FLOW
            // these instructions only affect control flow
            case XED_ICLASS_TEST:
                break;
            case XED_ICLASS_PTEST:
                break;
            case XED_ICLASS_CMP:
                break;
            case XED_ICLASS_NOT:
                break;
            case XED_ICLASS_LEAVE:
                break;
            case XED_ICLASS_CLD:
                break;
            case XED_ICLASS_BT:
                break;
#endif
            case XED_ICLASS_CPUID:
                // ignore this instruction
                break;
            default:
                if (INS_IsNop(ins)) {
                    INSTRUMENT_PRINT(log_f, "%#x: not instrument noop %s\n",
                            INS_Address(ins), INS_Disassemble(ins).c_str());
                    break;
                }
                if (INS_IsInterrupt(ins)) {
                    INSTRUMENT_PRINT(log_f, "%#x: not instrument an interrupt\n",
                            INS_Address(ins));
                    break;
                }
                if (INS_IsRDTSC(ins)) {
                    INSTRUMENT_PRINT(log_f, "%#x: not instrument an rdtsc\n",
                            INS_Address(ins));
                    break;
                }
                if (INS_IsSysenter(ins)) {
                    INSTRUMENT_PRINT(log_f, "%#x: not instrument a sysenter\n",
                            INS_Address(ins));
                    break;
                }
                if (instrumented) {
                    break;
                }
                ERROR_PRINT(log_f, "[NOOP] ERROR: instruction %s is not instrumented, address: %#x\n",
                        INS_Disassemble(ins).c_str(), (unsigned)INS_Address(ins));
                // XXX This printing may cause a deadlock in Pin!
                // print_static_address(log_f, INS_Address(ins));
                break;
        }
    }
#ifdef USE_CODEFLUSH_TRICK
    }
#endif
}

void trace_instrumentation(TRACE trace, void* v)
{
    struct timeval tv_end, tv_start;

    gettimeofday (&tv_start, NULL);
    TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_END);

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
	for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
	    instruction_instrumentation (ins, NULL);
	}
    }
    gettimeofday (&tv_end, NULL);

    traces_instrumented++;
    instrument_time += tv_end.tv_usec - tv_start.tv_usec + (tv_end.tv_sec - tv_start.tv_sec) * 1000000;
}

int restore_state_from_disk (struct thread_data* ptdata)
{
    int infd;
    int rc;
    char state_filename[256];
    struct save_state state;
    int monitor_size = 0;

    snprintf(state_filename, 256, "/tmp/%llu.%d.state",
            ptdata->rg_id,
            PIN_GetPid());
    if (access(state_filename, F_OK)) {
        fprintf(stderr, "retore_state: state file %s does not exist\n",
                state_filename);
        return -1;
    }
    infd = open(state_filename, O_RDONLY);
    if (infd < 0) {
        fprintf(stderr, "restore_state: could not open %s, %d\n",
                state_filename, errno);
        return -1;
    }

    rc = read(infd, &state, sizeof(struct save_state));
    if (rc != sizeof(struct save_state)) {
        fprintf(stderr, "could not read state info, errno %d\n", errno);
        return -1;
    }
    // integrity checks
    assert(ptdata->record_pid == state.record_pid);
    assert(ptdata->rg_id == state.rg_id);
    global_syscall_cnt = state.global_syscall_cnt;
    ptdata->syscall_cnt = state.syscall_cnt;
    open_file_cnt = state.open_file_cnt;

    // next read fd monitors
    rc = read(infd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "could not read open_fds monitor size, got %d, expected %d, errno %d\n", rc, sizeof(int), errno);
        close(infd);
        return -1;
    }
    if (monitor_size) {
        void* monitor_bytes;
        monitor_bytes = (void *) malloc(monitor_size);
	if (monitor_bytes == NULL) {
	    fprintf (stderr, "Unable to malloc monitor_bytes\n");
	    assert (0);
	}
        rc = read(infd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "could not read open_fds monitor, errno %d\n", errno);
            return -1;
        }

        monitor_deserialize(&open_fds, monitor_bytes);
    }

    rc = read(infd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "could not read open_socks monitor size, errno %d\n", errno);
        close(infd);
        return -1;
    }
    if (monitor_size) {
        void* monitor_bytes;
        monitor_bytes = (void *) malloc(monitor_size);
	if (monitor_bytes == NULL) {
	    fprintf (stderr, "Unable to malloc monitor_bytes\n");
	    assert (0);
	}
	rc = read(infd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "could not read open_socks monitor, errno %d\n", errno);
            return -1;
        }
        monitor_deserialize(&open_socks, monitor_bytes);
    }

    rc = read(infd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "could not read open_x_fds monitor size, errno %d\n", errno);
        close(infd);
        return -1;
    }
    if (monitor_size) {
        void* monitor_bytes;
        monitor_bytes = (void *) malloc(monitor_size);
	if (monitor_bytes == NULL) {
	    fprintf (stderr, "Unable to malloc monitor_bytes\n");
	    assert (0);
	}
        rc = read(infd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "could not read open_x_fds monitor, errno %d\n", errno);
            return -1;
        }
        monitor_deserialize(&open_x_fds, monitor_bytes);
    }

    // If we're restoring state, then we've successfully execv'ed.
    // Remove all fd's we were mirroring that were marked as CLOEXEC
    monitor_remove_cloexec(open_fds);
    monitor_remove_cloexec(open_socks);
    monitor_remove_cloexec(open_x_fds);

    // next read taint filters
    rc = deserialize_filters(infd);
    if (rc) {
        fprintf(stderr, "restore_state: problem restoring taint filters\n");
        return -1;
    }

    close(infd);
    // delete the state file
    if (unlink(state_filename)) {
        fprintf(stderr, "restore_state: cannot unlink state file %d\n", errno);
    }
    return 0;
}

int save_state_to_disk (struct thread_data* ptdata)
{
    int outfd;
    int rc;
    char state_filename[256];
    struct save_state state;
    int monitor_size = 0;
    void* monitor_bytes = NULL;

    snprintf(state_filename, 256, "/tmp/%llu.%d.state",
            ptdata->rg_id,
            PIN_GetPid());
    outfd = open(state_filename, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (outfd < 0) {
        fprintf(stderr, "save_state: could not open %s\n", state_filename);
        return -1;
    }

    // save state
    state.rg_id = ptdata->rg_id;
    state.record_pid = ptdata->record_pid;
    state.global_syscall_cnt = global_syscall_cnt;
    state.syscall_cnt = ptdata->syscall_cnt;
    state.open_file_cnt = open_file_cnt;
    rc = write(outfd, &state, sizeof(struct save_state));
    if (rc != sizeof(struct save_state)) {
        fprintf(stderr, "problem writing state, errno %d\n", errno);
        return -1;
    }

    // next save fd monitors
    monitor_size = monitor_serialize(open_fds, &monitor_bytes);
    assert (monitor_size >= 0);
    rc = write(outfd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not write open_fds monitor size, errno %d\n", errno);
    }
    if (monitor_size) {
        rc = write(outfd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "Could not write open_fds monitor to %s, errno %d\n", state_filename, errno);
            return -1;
        }
    }

    monitor_size = monitor_serialize(open_socks, &monitor_bytes);
    assert (monitor_size >= 0);
    rc = write(outfd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not write open_socks monitor size, errno %d\n", errno);
    }
    if (monitor_size) {
        rc = write(outfd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "Could not write open_socks monitor to %s, errno %d\n", state_filename, errno);
            return -1;
        }
    }

    monitor_size = monitor_serialize(open_x_fds, &monitor_bytes);
    assert (monitor_size >= 0);
    rc = write(outfd, &monitor_size, sizeof(int));
    if (rc != sizeof(int)) {
        fprintf(stderr, "Could not write open_x_fds monitor size, errno %d\n", errno);
    }
    if (monitor_size) {
        rc = write(outfd, monitor_bytes, monitor_size);
        if (rc != monitor_size) {
            fprintf(stderr, "Could not write open_x_fds monitor to %s, errno %d\n", state_filename, errno);
            return -1;
        }
    }

    // next save taint filters
    rc = serialize_filters(outfd);
    if (rc) {
        fprintf(stderr, "problem serializing taint filters\n");
        return -1;
    }

    close(outfd);
    return 0;
}

BOOL follow_child(CHILD_PROCESS child, void* data)
{
    char** argv;
    assert(main_prev_argv);
    char** prev_argv = main_prev_argv;
    struct thread_data* ptdata = (struct thread_data *) data;
    int index = 0;

    fprintf(stderr, "follow_child\n");
    /* the format of pin command would be:
     * pin_binary -follow_execv -t pin_tool new_addr*/
    int new_argc = 5;
    argv = (char**)malloc(sizeof(char*) * new_argc);
    if (argv == NULL) {
	fprintf (stderr, "Unable to malloc argv\n");
	assert (0);
    }

    fprintf(stderr, "follow_child: %p\n", main_prev_argv);
    argv[0] = prev_argv[index++];                   // pin
    argv[1] = (char *) "-follow_execv";
    while(strcmp(prev_argv[index], "-t")) index++;
    argv[2] = prev_argv[index++];
    argv[3] = prev_argv[index++];
    argv[4] = (char *) "--";

    CHILD_PROCESS_SetPinCommandLine(child, new_argc, argv);

    // save necessary state to disk before exec-ing
    save_state_to_disk(ptdata);

    return TRUE;
}
void AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    PRINTX(stderr, "%d,%d:AfterForkInChild\n", PIN_GetPid(),get_record_pid());

#ifndef NO_FILE_OUTPUT
    fclose(log_f); 
    log_f = NULL;
    init_logs();
#endif

    //for now there is no change for not using the network
#ifndef USE_FILE
    //we use the fork_flags to determine which path to follow: 
    //means that the fork_flag was a 0... so we need to make the outfd's all our bs value:
    PRINTX(stderr, "\t fork_flags %s\n",fork_flags);
    PRINTX(stderr, "\t fork_flags_index %d\n",fork_flags_index);
    PRINTX(stderr, "\t fork_flags char %d\n",fork_flags[fork_flags_index] - '0');
    if(fork_flags && !(fork_flags[fork_flags_index++] - '0')) { 
	PRINTX(stderr, "\tnot following child\n");
	//close the sockets and assign them to some garbage. 
	close(outfd);
	close(tokens_fd);
//	close(s); //should I close this? Why wouldn't I? 
	  	    
	outfd = -99999;
	tokens_fd = -99999;
	s = -99999;
    }
    else { 
	PRINTX(stderr, "\tfollowing child\n");
    }
#else
    /* grab the old file descriptors for things that we're going to have to copy
     * - close the old log, open a new log
     * - copy the filenames file
     * - copy the tokens file
     * - creating a new output file
     * 
     * are there any log files and things that need to be cleaned? 
     */
    int record_pid = get_record_pid();
    int tokens_fd_old = tokens_fd;


    //open new filenames

#ifdef OUTPUT_FILENAME
    FILE* filenames_f_old = filenames_f; 
    char filename_mapping[256];
    snprintf(filename_mapping, 256, "%s/filenames.%d", group_directory, record_pid);
    filenames_f = fopen(filename_mapping, "w");
    if (!filenames_f) {
      fprintf(stderr, "Could not open filenames mapping file %s\n", filename_mapping);
      exit(-1);
    }
    init_filename_mapping(filenames_f);
    copy_file(filenames_f_old, filenames_f); 
    fclose(filenames_f_old);
#endif

    char name[256];
    snprintf(name, 256, "%s/tokens.%d", group_directory, record_pid);
    tokens_fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (tokens_fd == -1) {
      fprintf(stderr, "Could not open tokens file %s\n", name);
      exit(-1);
    }
    copy_file(tokens_fd_old, tokens_fd);    
    close(tokens_fd_old);

    char output_file_name[256];
    snprintf(output_file_name, 256, "%s/dataflow.result.%d", group_directory, record_pid);
    outfd = open(output_file_name, O_CREAT | O_TRUNC | O_LARGEFILE | O_RDWR, 0644);
    if (outfd < 0) {
      fprintf(stderr, "could not open output file %s, errno %d\n", output_file_name, errno);
      exit(-1);
    }

    //copy the files and close the old ones 
    PRINTX(stderr, "\t- record_pid %d\n", record_pid);

#endif

    current_thread->record_pid = get_record_pid();
    // reset syscall index for thread
    current_thread->syscall_cnt = 0; //not ceratin that this is right anymore.. 
}

#ifndef USE_FILE
void AfterForkInParent(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    PRINTX(stderr, "%d,%d:AfterForkInParent\n", PIN_GetPid(),get_record_pid());

    //we use the fork_flags to determine which path to follow: 
    //means that the fork_flag was a 1... so we need to make the outfd's all our bs value:
    PRINTX(stderr, "\t fork_flags %s\n",fork_flags);
    PRINTX(stderr, "\t fork_flags_index %d\n",fork_flags_index);
    PRINTX(stderr, "\t fork_flags char %d\n",fork_flags[fork_flags_index] - '0');
    if(fork_flags && fork_flags[fork_flags_index++] - '0' ) { 
	PRINTX(stderr, "\t not following parent\n");

#ifdef USE_NW      
	//close the sockets and assign them to some garbage. 
	close(outfd);
	close(tokens_fd);
#endif 
//	close(s); //shouldn't I close this? 
	outfd = -99999; //wait a minute... how? 
	tokens_fd = -99999;
	s = -99999;
    }
    else { 
	PRINTX(stderr, "\tfollowing parent\n");
    }
}
#endif

void thread_start (THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    struct thread_data* ptdata;
    
    // TODO Use slab allocator
    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    if (ptdata == NULL) {
	fprintf (stderr, "Unable to malloc pdata\n");
	assert (0);
    }
    assert(ptdata);
    memset(ptdata, 0, sizeof(struct thread_data));

    ptdata->threadid = threadid;
    ptdata->app_syscall = 0;
    ptdata->record_pid = get_record_pid();
    get_record_group_id(dev_fd, &(ptdata->rg_id));

    int thread_ndx;
    long thread_status = set_pin_addr (dev_fd, (u_long) &(ptdata->app_syscall), ptdata, (void **) &current_thread, &thread_ndx);
#ifdef DEBUG
    fprintf (debug_f, "Thread %d gets rc %ld ndx %d from set_pin_addr\n", ptdata->record_pid, thread_status, thread_ndx);
#endif
    if (thread_status < 2) {
	current_thread = ptdata;
    }
    PIN_SetThreadData (tls_key, ptdata, threadid);

    if (splice_output && thread_status > 0) {
	int base = (NUM_REGS*REG_SIZE)*thread_ndx;
	//printf ("Thread %d gets reg_taints starting at %d\n", ptdata->record_pid, base+1);
	for (int i = 0; i < NUM_REGS * REG_SIZE; i++) {
	    ptdata->shadow_reg_table[i] = base+i+1; // For small number of threads, not part of AS
	}
    }

    if (child) {
        restore_state_from_disk(ptdata);
    }

    if (first_thread) {
#ifdef EXEC_INPUTS
        int acc = 0;
        char** args;
        struct taint_creation_info tci;
#endif
        PIN_AddFollowChildProcessFunction(follow_child, ptdata);
        first_thread = 0;
        if (!ptdata->syscall_cnt) {
            ptdata->syscall_cnt = 1;
        }
#ifdef OUTPUT_FILENAME
        if (!filenames_f) {
            // setup initial maps
            char filename_mapping[256];
            snprintf(filename_mapping, 256, "%s/filenames", group_directory);
            filenames_f = fopen(filename_mapping, "w");
            if (!filenames_f) {
                fprintf(stderr, "Could not open filenames mapping file %s\n", filename_mapping);
                exit(-1);
            }
            init_filename_mapping(filenames_f);
        }
#endif
        if (tokens_fd == -1) {
#ifdef USE_NW
	    tokens_fd = s;
#endif
#ifdef USE_SHMEM
	    char token_file[256];
	    snprintf(token_file, 256, "/tokens_shm%s", group_directory);
	    for (u_int i = 1; i < strlen(token_file); i++) {
		if (token_file[i] == '/') token_file[i] = '.';
	    }
	    tokens_fd = shm_open(token_file, O_CREAT | O_TRUNC | O_RDWR, 0644);
	    if (tokens_fd < 0) {
		fprintf(stderr, "could not open tokens shmem %s, errno %d\n", token_file, errno);
		assert(0);
	    }
	    int rc = ftruncate64 (tokens_fd, MAX_TOKENS_SIZE);
	    if (rc < 0) {
		fprintf(stderr, "could not truncate tokens %s, errno %d\n", token_file, errno);
		assert(0);
	    }
#endif
#ifdef USE_FILE
            char name[256];
            snprintf(name, 256, "%s/tokens", group_directory);
            tokens_fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
            if (tokens_fd < 0) {
                fprintf(stderr, "Could not open tokens file %s\n", name);
                exit(-1);
            }
#endif
        }
        if (outfd == -1) {
#ifdef USE_NW
	    outfd = s;
#endif
#ifdef USE_SHMEM
	    char output_file[256];
	    snprintf(output_file, 256, "/dataflow.results_shm%s", group_directory);
	    for (u_int i = 1; i < strlen(output_file); i++) {
		if (output_file[i] == '/') output_file[i] = '.';
	    }
	    outfd = shm_open(output_file, O_CREAT | O_TRUNC | O_RDWR, 0644);
	    if (outfd < 0) {
		fprintf(stderr, "could not open tokens shmem %s, errno %d\n", output_file, errno);
		assert(0);
	    }
	    int rc = ftruncate64 (outfd, MAX_OUT_SIZE);
	    if (rc < 0) {
		fprintf(stderr, "could not truncate tokens %s, errno %d\n", output_file, errno);
		assert(0);
	    }
#endif
#ifdef USE_FILE
            char output_file_name[256];
            snprintf(output_file_name, 256, "%s/dataflow.result", group_directory);
            outfd = open(output_file_name, O_CREAT | O_TRUNC | O_LARGEFILE | O_RDWR, 0644);
            if (outfd < 0) {
                fprintf(stderr, "could not open output file %s, errno %d\n", output_file_name, errno);
                exit(-1);
            }
#endif
        }

        if (trace_x && xoutput_fd == -1) {
            char xoutput_file_name[256];
            snprintf(xoutput_file_name, 256, "%s/xoutput.result", group_directory);
            xoutput_fd = open(xoutput_file_name, O_CREAT | O_TRUNC | O_LARGEFILE | O_RDWR, 0644);
            if (xoutput_fd < 0) {
                fprintf(stderr, "could not open output file %s, errno %d\n", xoutput_file_name, errno);
                exit(-1);
            }
        }

#ifdef EXEC_INPUTS
        args = (char **) get_replay_args (dev_fd);
        tci.rg_id = ptdata->rg_id;
        tci.record_pid = ptdata->record_pid;
        tci.syscall_cnt = ptdata->syscall_cnt;
        tci.offset = 0;
        tci.fileno = FILENO_ARGS;
        tci.data = 0;
        while (1) {
            char* arg;
            arg = *args;
            // args ends with a NULL
            if (!arg) {
                break;
            }
            fprintf (stderr, "input arg is %s\n", arg);
            tci.offset = acc;
            create_taints_from_buffer(arg, strlen(arg) + 1, &tci, tokens_fd,
                                                            (char *) "EXEC_ARG");
            acc += strlen(arg) + 1;
            args += 1;
        }
        // Retrieve the location of the env. var from the kernel
        args = (char **) get_env_vars (dev_fd);
        LOG_PRINT ("env. vars are %#lx\n", (unsigned long) args);
        tci.fileno = FILENO_ENVP;
        while (1) {
            char* arg;
            arg = *args;
            // args ends with a NULL
            if (!arg) {
                break;
            }
            fprintf ("input arg is %s\n", arg);
            tci.offset = acc;
            create_taints_from_buffer(arg, strlen(arg) + 1, &tci, tokens_fd,
                                                            (char *) "EXEC_ENV");
            acc += strlen(arg) + 1;
            args += 1;
        }
#endif
    }
#ifdef HEARTBLEED
    if (heartbleed_fd == -1) {
        char heartbleed_filename[256];
        snprintf(heartbleed_filename, 256, "%s/heartbleed.result", group_directory);
        heartbleed_fd = open(heartbleed_filename,
                                O_CREAT | O_TRUNC | O_LARGEFILE | O_RDWR, 0644);
        if (heartbleed_fd < 0) {
            fprintf(stderr, "could not open heartbleed file\n");
            exit(-1);
        }
    }
#endif
    active_threads[ptdata->record_pid] = ptdata;
}

void thread_fini (THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, threadid);
    active_threads.erase(tdata->record_pid);
}

#ifndef NO_FILE_OUTPUT
void init_logs(void)
{
    char log_name[256];
    if (!log_f) {
        snprintf(log_name, 256, "%s/confaid.log.%d",
                group_directory, PIN_GetPid());
        log_f = fopen(log_name, "w");
    }

#ifdef TAINT_DEBUG
    {
        char debug_log_name[256];
        if (!debug_f) {
            snprintf(debug_log_name, 256, "%s/debug_taint", group_directory);
	    debug_f = fopen(debug_log_name, "w");
            if (!debug_f) {
                fprintf(stderr, "could not create debug taint log file, errno %d\n", errno);
                exit(0);
            }
        }
    }
#endif
#ifdef TAINT_STATS
    {
        char stats_log_name[256];
        if (!stats_f) {
            snprintf(stats_log_name, 256, "%s/taint_stats", group_directory);
	    stats_f = fopen(stats_log_name, "w");
            if (!stats_f) {
                fprintf(stderr, "could not create taint stats file, errno %d\n", errno);
                exit(0);
            }
        }
	gettimeofday(&begin_tv, NULL);
    }
#endif
}
#endif

void fini(INT32 code, void* v)
{
    dift_done ();
}

#if 0
VOID ImageLoad (IMG img, VOID *v)
{
    uint32_t id = IMG_Id (img);

    ADDRINT load_offset = IMG_LoadOffset(img);
    fprintf(stderr, "[IMG] Loading image id %d, name %s with load offset %#x\n",
            id, IMG_Name(img).c_str(), load_offset);
}
#endif

int get_open_file_descriptors ()
{
    struct open_fd ofds[4096];
    long rc = get_open_fds (dev_fd, ofds, 4096);
    if (rc < 0) {
	fprintf (stderr, "get_open_file_desciptors returns %ld\n", rc);
	return rc;
    }

    for (long i = 0; i < rc; i++) {
	if (ofds[i].type == OPEN_FD_TYPE_FILE) {
	    struct open_info* oi = (struct open_info *) malloc (sizeof(struct open_info));
	    strcpy (oi->name, ofds[i].channel);
	    oi->flags = 0;
	    oi->fileno = 0;
	    monitor_add_fd(open_fds, ofds[i].fd, 0, oi);
	} else if (ofds[i].type == OPEN_FD_TYPE_SOCKET) {
	    struct socket_info* si = (struct socket_info *) malloc (sizeof(struct socket_info));
	    si->domain = ofds[i].data;
	    si->type = -1;
	    si->protocol = -1;
	    si->fileno = -1; 
	    si->ci = NULL;
	    monitor_add_fd(open_socks, ofds[i].fd, 0, si);
	}
    }

    return 0;
}

int main(int argc, char** argv) 
{    
    int rc;

    // This is a very specific trick to figure out if we're a child or not
    if (!strcmp(argv[4], "--")) { // pin injected into forked process
        child = 1;
    } else { // pin attached to replay process
        child = 0;
    }

    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        fprintf(stderr, "ERROR: could not initialize Pin?\n");
        exit(-1);
    }

    tls_key = PIN_CreateThreadDataKey(0);

    // Intialize the replay device
    rc = devspec_init (&dev_fd);
    if (rc < 0) return rc;
    global_syscall_cnt = 0;

    /* Create a directory for logs etc for this replay group*/
    snprintf(group_directory, 256, "/tmp/%d", PIN_GetPid());
#ifndef NO_FILE_OUTPUT
    if (mkdir(group_directory, 0755)) {
        if (errno == EEXIST) {
            fprintf(stderr, "directory already exists, using it: %s\n", group_directory);
        } else {
            fprintf(stderr, "could not make directory %s\n", group_directory);
            exit(-1);
        }
    }
#endif

    // Read in command line args
    trace_x = KnobTraceX.Value();
    print_all_opened_files = KnobRecordOpenedFiles.Value();
    filter_read_filename = KnobFilterReadFile.Value().c_str();
    segment_length = KnobSegmentLength.Value();
    splice_output = KnobSpliceOutput.Value();
    all_output = KnobAllOutput.Value();
    fork_flags = KnobForkFlags.Value().c_str();
    fork_flags_index = 0;   
    

    if (KnobMergeEntries.Value() > 0) {
	num_merge_entries = KnobMergeEntries.Value();
    }

    if (!open_fds) {
        open_fds = new_xray_monitor(sizeof(struct open_info));
    }
    if (!open_socks) {
        open_socks = new_xray_monitor(sizeof(struct socket_info));
    }
    if (!open_x_fds) {
        open_x_fds = new_xray_monitor(0);
    }

    // Determine open file descriptors for filters
    if (splice_output) get_open_file_descriptors();

#if defined(USE_NW) || defined(USE_SHMEM)
    // Open a connection to the 64-bit consumer process
    const char* hostname = KnobNWHostname.Value().c_str();
    int port = KnobNWPort.Value();
    
    struct hostent* hp = gethostbyname (hostname);
    if (hp == NULL) {
	fprintf (stderr, "Invalid host %s, errno=%d\n", hostname, h_errno);
	return -1;
    }

    s = socket (AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	fprintf (stderr, "Cannot create socket, errno=%d\n", errno);
	return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy (&addr.sin_addr, hp->h_addr, hp->h_length);

    int tries = 0;
    do {
	rc = connect (s, (struct sockaddr *) &addr, sizeof(addr));
	if (rc < 0) {
	    tries++;
	    usleep(1000);
	}
    } while (rc < 0 && tries <=100); //whats the punishment for increasing tries here? 

    if (rc < 0) {
	fprintf (stderr, "Cannot connect to socket (host %s, port %d), errno=%d\n", hostname, port, errno);
	return -1;
    }

#endif

#ifndef NO_FILE_OUTPUT
    init_logs();
#endif
    init_taint_structures(group_directory);

    // Try to map the log clock for this epoch
    ppthread_log_clock = map_shared_clock(dev_fd);
    //printf ("Log clock is %p, value is %ld\n", ppthread_log_clock, *ppthread_log_clock);

    //fprintf(stderr, "starting init_slab_allocs\n");
    init_slab_allocs();
    // how about 1000 opened files...ever?
    new_slab_alloc((char *)"OPEN_ALLOC", &open_info_alloc, sizeof(struct open_info), 1000);
    // shouldn't expect for than 100 threads?
    new_slab_alloc((char *)"THREAD_ALLOC", &thread_data_alloc, sizeof(struct thread_data), 100);

    if (!child) {
        // input filters
        init_filters();
        set_filter_inputs(KnobFilterInputs.Value());
        if (filter_input()) {
            for (unsigned i = 0; i < KnobFilterInputFiles.NumberOfValues(); i++) {
                add_input_filter(FILTER_FILENAME,
                        (void *) KnobFilterInputFiles.Value(i).c_str());
            }
            for (unsigned i = 0; i < KnobFilterInputSyscalls.NumberOfValues(); i++) {
                add_input_filter(FILTER_SYSCALL,
                        (void *) KnobFilterInputSyscalls.Value(i).c_str());
            }
            for (unsigned i = 0; i < KnobFilterInputPartFilename.NumberOfValues(); i++) {
                add_input_filter(FILTER_PARTFILENAME,
                        (void *) KnobFilterInputPartFilename.Value(i).c_str());
            }
            for (unsigned i = 0; i < KnobFilterInputRegex.NumberOfValues(); i++) {
                add_input_filter(FILTER_REGEX,
                        (void *) KnobFilterInputRegex.Value(i).c_str());
            }
            for (unsigned i = 0; i < KnobFilterByteRange.NumberOfValues(); i++) {
                add_input_filter(FILTER_BYTERANGE,
                        (void *) KnobFilterByteRange.Value(i).c_str());
            }
            if (filter_read_filename && strlen(filter_read_filename) > 0) {
                build_filters_from_file(filter_read_filename);
            }
        }

        // output filters
        if (trace_x) {
	    set_filter_outputs(1, -1);
        } else {
	    int filter_syscall = KnobFilterOutputSyscall.Value();
	    if (filter_syscall > 0) {
		set_filter_outputs(0, filter_syscall);
	    }
	}
    }

    PIN_AddThreadStartFunction(thread_start, 0);
    PIN_AddThreadFiniFunction(thread_fini, 0);
    PIN_AddFiniFunction(fini, 0);

    main_prev_argv = argv;

    TRACE_AddInstrumentFunction (trace_instrumentation, 0);

    // Register a notification handler that is called when the application
    // forks a new process
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);


#ifndef USE_FILE
    PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, AfterForkInParent, 0);
#endif

    if (trace_x) {
	// Right now, only used when this config variable set
	RTN_AddInstrumentFunction(track_function, 0);
    }

#if 0
    IMG_AddInstrumentFunction (ImageLoad, 0);
#endif

    PIN_AddSyscallExitFunction(instrument_syscall_ret, 0);
#ifdef HEARTBLEED
    fprintf(stderr, "heartbleed defined\n");
#endif

    PIN_StartProgram();

    return 0;
}
