#include <sys/types.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <syscall.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <shadow.h>
#include <fcntl.h>
#include "pin.H"
#include <glib-2.0/glib.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/rc4.h>
#include <sys/uio.h>
#include <dirent.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <sys/inotify.h>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


// for set_thread_area
#include <linux/unistd.h>
#include <asm/ldt.h>
#include <regex.h>

#include "common.h"
#include "functions.h"
#include "list.h"
#include "xray_monitor.h"
#include "reentry_lock.h"
#include "xray_image.h"

#ifdef LINKAGE_COPY
 #ifndef LINKAGE_DATA
  #include "taints/taints_copy.h"
 #else
  #include "taints/taints_data.h"
  //#include "taints/taints.h"
 #endif
#else
#include "taints/taints.h"
#endif
// #include "taints/taints.h"
// #define TAINT_STATS

// List of available Linkage macros
// // DO NOT TURN THESE ON HERE. Turn these on in makefile.rules.
// #define LINKAGE_COPY                 // just memory copies
// #define LINKAGE_DATA                 // data copies
// #define LINKAGE_SYSCALL              // system call & libc function abstraction
// #define CTRL_FLOW                    // direct control flow
// #define ALT_PATH_EXPLORATION         // indirect control flow
// #define CONFAID
// #define HAVE_REPLAY
// #define FILTER_INPUTS
// #define DUMP_TAINTS

// #define TRACK_MEMORY_AREAS
#ifdef TRACK_MEMORY_AREAS
#include "xray_memory_areas.h"
// keep track of which memory areas are used in the process
struct memory_areas* ma_list;
#endif

// keep track of which dynamic libraries (images) are currently loaded and their offsets
struct image_infos* img_list;

#define STACK_SIZE 8388608

// Logging
// #define LOGGING_ON
#define LOG_F log_f
#define MEM_F log_f
#define TRACE_F trace_f

#define FANCY_ALLOC

#ifndef HAVE_REPLAY
#define GLOBAL_LOCK
#endif

// Controls amount of log printing
#ifdef LOGGING_ON
#define WARN_PRINT(args...) \
{			   \
    fprintf(LOG_F, args);       \
    fflush(LOG_F);          \
}
#define LOG_PRINT(args...) \
{                           \
    fprintf(LOG_F, args);   \
    fflush(LOG_F);          \
}
#define MEM_PRINT(f, args...) \
{                               \
    fprintf(f, args);       \
    fflush(f);              \
}
#define SYSCALL_PRINT(args...) \
{                               \
    fprintf(LOG_F, args);       \
    fflush(LOG_F);              \
}
// #define INSTRUMENT_PRINT fflush(log_f); fprintf
#define INSTRUMENT_PRINT(x,...);
#else
#define WARN_PRINT(args...)
#define LOG_PRINT(x,...);
#define MEM_PRINT(x,...);
#define SYSCALL_PRINT(x,...);
#define INSTRUMENT_PRINT(x,...);
#endif // LOGGING_ON

// produce a trace of calls and rets
// #define TRACE_TAINTS
// Used for debugging taints
// #define DEBUG_TAINT
#define CURRENT_INSTRUCTION 0x80a136c
#define CURRENT_FUNCTION 0x806c481
#define TAINT_LOCATION 0xb
#define TAINT_TRACK

#define TAINT_CONDITION (ptdata->current_function == CURRENT_FUNCTION)
// #define TAINT_CONDITION (global_syscall_cnt > 26905 && global_syscall_cnt < 26936)
#ifdef DEBUG_TAINT
#define TAINT_PRINT(args...) \
{                           \
    if (TAINT_CONDITION) { \
        fprintf(LOG_F, args);   \
        fflush(LOG_F);          \
    }                       \
}
#define TAINT_PRINT_DEP_VECTOR(vector) \
{ \
    if (TAINT_CONDITION) { \
        __print_dependency_tokens (LOG_F, vector); \
    } \
}
#else
#define TAINT_PRINT(x,...);
#define TAINT_PRINT_DEP_VECTOR(x,...);
#endif

#ifdef HAVE_REPLAY
#include "util.h"
#endif

#define START_HANDLED_FUNCTION(name)     \
    ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId()); \
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

#define STOP_HANDLED_FUNCTION(funcname)	\
    ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());   \
    struct handled_function* hf = HANDLED_FUNC_HEAD;    \
    if (!hf || strcmp(hf->name, funcname)) return;

#define TAINT_START(name) \
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId()); \
    TAINT_PRINT("taint_%s start\n", name); \
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

int regex_match_string(regex_t* regex, const char* comp_str) {
    int rc;
    if (!regex) return 0;
    rc = regexec(regex, comp_str, 0, NULL, 0);
    if (rc == 0) {
        return 1;
    } else if (rc == REG_NOMATCH) {
        return 0;
    } else {
        return rc;
    }
}

#ifdef CONFAID
// Confaid states for config_fd
#define CONFIG_FD_INIT -1
#define CONFIG_FD_CLOSED -2

// Global Confaid specific structs
struct confaid_data {
    int config_fd;
    char config_filename[256];
    int config_file_opened;
    regex_t error_regex;
    // flags
    int read_from_config_fd;
    int line_num;
    char token_acc[256];
    int token_idx;
};
#endif

enum flags {ALL_FLAGS, BUT_CF, CF_OF};

typedef bool (*CMOV_TRUE_FN)(UINT32); //used for cmov instruction
typedef void (*MASK_OP_FN)(int*, int);

/* Each log_entry holds the address and the value of
   a memory location that is changing. This original
   value of this memory location will be restored 
   at rollback */
struct log_entry {
    ADDRINT    addr;
    UINT8      value;
};

typedef struct instbbl instbbl;

/* A bblock structure is very similar to BBL except that
   it keeps the whole picture of the code rather than just
   the execution path */
struct bblock{
    int                        size;     //size = number of instructions
    instbbl*                   first_inst;
    instbbl*                   last_inst;
    struct bblock**            pdoms;    //post dominators of the bblock
    struct bblock*             ipdom;    //immediate pdom
    int                        num_branches;
    struct bblock**            branches;
};

struct calling_bblock {
    int                       status;   //specifies how the code after this function call should be treated: conservatively? accurately?
    int                       prev_status; // the saved previous status; used for dynamic libraries and _dl_runtime_resolve
    int                       is_merge_point;
    int                       ctrflow_taint_stack_size;
    ADDRINT                   next_address;
    ADDRINT                   call_address;
    ADDRINT                   address;
    struct bblock*            bblock;
    struct calling_bblock*    prev;
#ifdef HANDLED_FUNCTION_DEBUG
    char name[256];
#endif
};

/* This is used to store shift values for memory modified on the real path */
struct real_mem_mod {
    ADDRINT address;
    char    shift;
};

#ifdef FANCY_ALLOC
/* This is a specail allocation structure for real_mem_mods as that allocation
   is an expensive operation */
struct real_mem_mod_header {
    u_long                      size; // Total entries in this block
    struct real_mem_mod*        next; // Pointer to next free entries
    struct real_mem_mod*        end;  // To detect when block is exhausted
    struct real_mem_mod_header* next_block;  // Pointer to previously alloced block
};
#endif

/* This is used to store values and taints for memory modified on an alternate path (so that it can be restored witht the checkpoint) */
struct alt_mem_mod {
    ADDRINT                      address;
    UINT8                        value;
    char                         is_tainted;
    struct taint taint;
};

/*This structure is used for keeping the ctrflow taints*/
struct taint_info {
    int                              alt_path;
    char                             real_mod_regs[NUM_REGS];    // which registers have been modified
    char                             real_mod_flags[NUM_FLAGS];  // which flags have been modified
    GHashTable*                      real_mod_mems;              // which memory locations have been modified
#ifdef FANCY_ALLOC
    struct real_mem_mod_header*      real_mod_mem_cache;         // special allocation for modifications along this path
#endif
    struct taint     condition_taint;            //This is the taint that the condition adds after merge point
    struct taint     ctrflow_taint;              //This is the total control flow taint at this point
#ifdef ALT_PATH_EXPLORATION
    struct taint     Ta;
#endif
    struct bblock*                   merge_bblock;
    int                              calling_bblock_size;
    struct taint_info*               prev;
};

/* This structure is used to put instructions in hashtable*/
struct instbbl{
    ADDRINT           inst_addr;
    int               branch;
    ADDRINT           taken_addr;
    ADDRINT           fall_addr;
    struct bblock*    bblock;
};

struct check_point{
    ADDRINT                      ckpt_inst;
    struct calling_bblock*       calling_bblocks;
    struct handled_function*     handled_functions;
    int                          num_insts;
    int                          memory_log_index;
    GHashTable*                  mem_val_taints;          // Save values and taints for any modified memory 
    struct taint reg_taints[NUM_REGS];    // Save previous taints of all registers here
    struct taint flag_taints[NUM_FLAGS];  // Save previous taints of all flags here
    int                          merge_on_next_ret;       // Save this in case of rollback 
    //CHECKPOINT                   ckpt;
    CONTEXT                      ctx;
    struct check_point*          prev;
};

// token types
#define TOK_READ 1
#define TOK_WRITE 2
#define TOK_EXEC 3
struct token {
    int type;
    int token_num;
    int syscall_cnt;
    int byte_offset;
#ifdef CONFAID
    char config_token[256];	// Name of the config token
    int line_num;		// Line number
    char config_filename[256];	// Name of the config file
#else
    char name[256];
#endif
    uint64_t rg_id;
    int record_pid;
};

struct handled_function{
    char                            name[64];
    struct taint    args_taint;
    unsigned                        special_value;       //this is set according to the function
    struct handled_function*        prev;
};

struct malloc_entry {
    ADDRINT    address;
    int        size;
    int        active;
};

struct input_bblock {
    ADDRINT    bblock_address;
    long long unsigned     total_inst_count;
};

/* This moemoizes(caches) the shift values at a merge point */
struct shift_cache{
    int cached[CONFIDENCE_LEVELS+1];
    struct taint value[CONFIDENCE_LEVELS+1];
};
shift_cache scache;
char  final_reg_shifts[NUM_REGS];    // which registers have been modified
char  final_flag_shifts[NUM_REGS];   // which flags have been modified
GHashTable* final_mem_shifts;        // which memory addresses have been modified
int mem_depth;

#ifdef MEM
int mems[15];
#endif
#ifdef FUNC_TIME
struct timeval current_time;
int current_num_inst;
GHashTable* function_times_hash;
struct function_time {
    ADDRINT name;
    long long time;
    int num_inst;
};
struct function_time function_times[10000];
int function_times_index = 0;
#endif

struct syscall_info {
    int sysnum;
};

#define OPEN_PATH_LEN 256
struct open_info {
    char name[OPEN_PATH_LEN];
    int flags;
};

struct read_info {
    int      fd;
    ADDRINT  fd_ref;
    char*    buf;
};

struct write_info {
    int      fd;
    char*    buf;
};

// Per-thread data structure
struct thread_data {
    int                      threadid;
    u_long                   app_syscall; // Per thread address for specifying pin vs. non-pin system calls
    int                      record_pid;  // Ask kernel for corresponding record pid and save it here
    int                      sysnum; // Stores number of system calls for return
    struct bblock*           current_bbl; // Holds current basic block between call and return
    struct calling_bblock*   calling_bblock_head; // Head of the calling bblock list
    int                      calling_bblock_size; // Size of the above list
    struct taint_info*       ctrflow_taint_stack; //control flow taints for each fn on stack
    int                      ctrflow_taint_stack_size; // size of the above stack
    struct check_point*      ckpts; // Stack of ckpts
    struct check_point*      alloc_ckpts; // Not sure - seems related to above
    int                      num_ckpts; // Number of ckpts on the stack
    int                      total_num_ckpts; // Number of ckpts allocated per alternate cf exploration
    struct handled_function* handled_func_head;
    int                      merge_on_next_ret; // Handles cases where instrumentation turned on in middle of a function
    int                      num_insts; // Number of specualative instructions - probably safer to make this per-thread
    int                      bbl_over; // Used to mark start of next basic block - prob. safer if this is also per-thread
    int                      bblock_difference_matched; // Should we analyze for path divergence?
    struct taint saved_reg_taints[NUM_REGS];    // Save taints here when switching threads
    struct taint saved_flag_taints[NUM_FLAGS];  // Save taints here when switching threads
    struct taint select_taint; // Not sure why we cannot treat this as a handled fn...
    u_long brk_saved_loc;
#ifdef DEBUG_TAINT
    ADDRINT current_function;
#endif
    struct handled_function syscall_taint_info; // saved info for propagating taint across syscall
    void* save_syscall_info;			// info to be saved across syscalls
    int syscall_handled;			// flag to indicate if a syscall is handled at the glibc wrapper instead
    uint64_t rg_id;                 // record group id
#ifdef HAVE_REPLAY
    u_long ignore_flag;             // location of the ignore flag
#endif
    struct thread_data*      next;
    struct thread_data*      prev;
};

#define SYSNUM                      (ptdata->sysnum)
#define CURRENT_BBL                 (ptdata->current_bbl)
#define CALLING_BBLOCK_HEAD         (ptdata->calling_bblock_head)
#define CALLING_BBLOCK_SIZE         (ptdata->calling_bblock_size)
#define CTRFLOW_TAINT_STACK         (ptdata->ctrflow_taint_stack)
#define CTRFLOW_TAINT_STACK_SIZE    (ptdata->ctrflow_taint_stack_size)
#define CKPTS                       (ptdata->ckpts)
#define ALLOC_CKPTS                 (ptdata->alloc_ckpts)
#define NUM_CKPTS                   (ptdata->num_ckpts)
#define TOTAL_NUM_CKPTS             (ptdata->total_num_ckpts)
#define HANDLED_FUNC_HEAD           (ptdata->handled_func_head)
#define MERGE_ON_NEXT_RET           (ptdata->merge_on_next_ret)
#define NUM_INSTS                   (ptdata->num_insts)
#define BBL_OVER                    (ptdata->bbl_over)
#define BBLOCK_DIFFERENCE_MATCHED   (ptdata->bblock_difference_matched)
#define SAVED_REG_TAINTS            (ptdata->saved_reg_taints)
#define SAVED_FLAG_TAINTS           (ptdata->saved_flag_taints)
#define SELECT_TAINT                (ptdata->select_taint)

/* Constants */
#define MAX_USED_ADDRS 100

#define MAX_MALLOC_INDEX 2000000

#ifdef FANCY_ALLOC
#define INIT_MEM_MODS_PER_CACHE_BLOCK 62
#endif

/* Global variables */
void* mem_loc_high[FIRST_TABLE_SIZE];  // Top-level table for memory taints
struct taint reg_table[NUM_REGS];  // reg taints
struct taint flag_table[NUM_FLAGS + 1]; // flag taints
GHashTable* hashtable; // keeps the instbbls, the first and last instructions for each bblock 
char static_analysis_path [PATH_MAX];
#ifdef HAVE_REPLAY
int dev_fd; // File descriptor for the replay device
int no_replay = 0;
#endif
int first_thread = 1; // Needed to create exec args
TLS_KEY tls_key; // Key for accessing TLS. 
struct token* tokens; // Tokens read from config file
struct malloc_entry malloc_array[MAX_MALLOC_INDEX]; // Keeps track of allocations
int malloc_index = 0; // Index into the used entries in the above array
ADDRINT main_low_addr; // Low address of image
ADDRINT main_high_addr; // High address of image
int segfault_captured = 0; // Segfault seen - OK to be global since next instruction will rollback
int main_started = 0; // Have we executed main() yet?
int first_inst = 0; // Looks like this marks the first instruction in a speculative path
FILE* output_f = NULL; // For output info
FILE* input_f; // For input info
char process_name[64]; // Records name during exec
long long unsigned total_inst_count = 0; // Total number of instructions
struct thread_data* plasttd = NULL; // Used to detect thread switch
struct input_bblock* current_input_bbl; // List of basic block to analyze
struct thread_data* tdhead = NULL; // doubly-linked list of per-thread structures
int option_cnt = 0; // Current count of an input-option, monotonically increasing
int option_byte = 1;       // Byte-to-byte analysis? (otherwise, we're doing message analysis)
GHashTable* option_info_table;    // Mapping of option_cnt to metadata about each option
regex_t* input_message_regex = NULL; // Regex to match the start of input messages
regex_t* output_message_regex = NULL; // Regex to match the start of input messages
int count_syscall = 0; // count
int global_syscall_cnt = 0;
struct xray_monitor* open_fds = NULL; // List of open fds
#ifdef FILTER_INPUTS
char input_file_name[256];
#endif
#ifdef TAINT_STATS
long instrumented_insts = 0;
#endif

FILE* log_f = NULL; // For debugging
FILE* trace_f = NULL; // for tracing taints

/* Command line Knobs */
#ifdef CONFAID
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", "/tmp/confaid.result", "output file");
#else
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", "/tmp/dataflow.result", "output file");
#endif
KNOB<string> KnobInputFile(KNOB_MODE_WRITEONCE, "pintool", "i", "/tmp/dataflow.in", "input file");
KNOB<string> KnobInputType(KNOB_MODE_WRITEONCE, "pintool", "t", "CMDLINE", "input type");
KNOB<string> KnobOutputType(KNOB_MODE_WRITEONCE, "pintool", "x", "ANY", "output type");
KNOB<string> KnobStaticAnalysisPath(KNOB_MODE_WRITEONCE, "pintool", "s", "/tmp/static", "static analysis path");
// Because I don't always want to recompile, but I don't want to run this all of the time with replay
KNOB<string> KnobTurnOffReplay(KNOB_MODE_WRITEONCE, "pintool", "n", "0", "standalone, no replay when compiled with replay support");
KNOB<string> KnobErrorRegex(KNOB_MODE_WRITEONCE, "pintool", "e", "blahblabhablahbalh", "error regex to match against");
#ifdef FILTER_INPUTS
KNOB<string> KnobInputFileFilter(KNOB_MODE_WRITEONCE, "pintool", "f", "blahbalbhablah", "input file to only create taints from");
#endif

#ifdef CONFAID
struct confaid_data* confaid_data;

void make_confaid_data (const char* config_filename, const char* regex_string) {
    int rc;
    confaid_data = (struct confaid_data *) malloc(sizeof(struct confaid_data));
    confaid_data->config_fd = CONFIG_FD_INIT;
    strncpy(confaid_data->config_filename, config_filename, 256);
    confaid_data->config_file_opened = 0;
    confaid_data->read_from_config_fd = 0;
    confaid_data->line_num = 1;
    confaid_data->token_idx = 0;
    memset(&confaid_data->error_regex, 0, sizeof(regex_t));
    if (regex_string) {
        rc = regcomp(&confaid_data->error_regex, regex_string, REG_EXTENDED);
        if (rc) {
            fprintf(stderr, "could not create error regex %d\n", rc);
            exit(1);
        }
    }
}
#endif

int print_first_inst = 1; // for debugging print the first instruction

long unsigned inst_count = 0;
#define INST_COUNT_INCREMENT 200000

#ifdef GLOBAL_LOCK
REENTRY_LOCK relock;
#endif

inline void __grab_global_lock (struct thread_data* ptdata) {
#ifdef GLOBAL_LOCK
    get_reentry_lock (&relock, ptdata->threadid);
#endif
}

inline void __release_global_lock(struct thread_data* ptdata) {
#ifdef GLOBAL_LOCK
    release_reentry_lock (&relock, ptdata->threadid);
#endif
}

#define GRAB_GLOBAL_LOCK __grab_global_lock
#define RELEASE_GLOBAL_LOCK __release_global_lock

#ifdef PPRINT
int pprint = 1; // Turn on debugging after certain system call
unsigned current_instruction = 0;
#endif

#ifdef TF_STATS
u_long num_real_mod_mems = 0;
#endif

#ifdef CHECK_WILD_ACCESSES
struct used_address uaddrs[MAX_USED_ADDRS]; // Address regions used by the app
int num_uaddrs; // Number of such regions
#endif

#ifdef DEBUG_TAINT
#ifdef TAINT_PRINT
FILE* taint_f = NULL;
#endif
#endif

// sets the rlimit to be infinite
int set_max_file_rlimit() {
    struct rlimit rbuf;
    rbuf.rlim_cur = RLIM_INFINITY;
    rbuf.rlim_max = RLIM_INFINITY;
    return setrlimit (RLIMIT_FSIZE, &rbuf);
}

//prototypes
int setup_logs(void);
int create_new_token (int type, int token_num, int syscall_cnt, int byte_offset, void* data);
#ifdef CONFAID
int create_new_named_token (int token_num, char* name);
#endif
void create_options_from_buffer (int type, long id, void* buf, int size, int offset, void* data);
struct bblock* read_return_bblock(struct thread_data*, ADDRINT);
void rollback(struct thread_data*, int);
void __print_dependency_tokens(FILE* file, struct taint* vector);
void __print_taint_string_buffer(FILE* file, char* buf, int size);
void rmdir_stop(ADDRINT res);

// interface for taint accessors
struct taint* get_reg_taint(REG reg);
struct taint* get_mem_taint(ADDRINT mem_loc);

// interface for propagating taint
inline void add_modified_mem(struct thread_data* ptdata, ADDRINT mem_location) ;
static inline void add_modified_reg(struct thread_data* ptdata, REG reg);
static inline void add_modified_flag(struct thread_data* ptdata, int flag);
static int mem_mod_dependency(struct thread_data* ptdata, ADDRINT mem_location, struct taint* vector, int mod, int ctrflow_propagate);
static int mem_clear_dependency(struct thread_data* ptdata, ADDRINT mem_location);
static inline void __reg_mod_dependency(struct thread_data* ptdata, REG reg, struct taint* vector, int mode, int ctrflow_propagate);
static int reg_mod_dependency(struct thread_data* ptdata, REG reg, struct taint* vector, int mode, int ctrflow_propagate);
static inline void __reg_clear_dependency(struct thread_data* ptdata, REG reg) ;
static void reg_clear_dependency(struct thread_data* ptdata, REG reg);
void flags_mod_dependency_but_cf (struct thread_data* ptdata, struct taint* vector, int mode, int ctrflow_propagate);
void flags_mod_dependency (struct thread_data* ptdata, struct taint* vector, int mode, int ctrflow_propagate);
void flags_clear_dependency_but_cf(struct thread_data* ptdata);
void flags_clear_dependency(struct thread_data* ptdata);
void flag_clear_dependency(struct thread_data* ptdata, int flag);

// TODO
// interface for propagating taints in the FPU

struct writev_info {
    struct iovec* vi;
    int count;
};
struct mmap_info {
    ADDRINT addr;
    int length;
    int prot;
    int flags;
    int fd;
    int fd_ref;
    int offset;
};

//########################################################################
#ifdef TAINT_STATS
void instrument_inst_count(void)
{
    instrumented_insts++;
}
#endif

void init_shift_cache(void)
{
    int i = 0;
	memset(&scache.cached, 0, sizeof(scache.cached));
    for (i = 0; i < CONFIDENCE_LEVELS + 1; i++) {
        new_taint(&scache.value[i]);
    }
}

void reset_shift_cache(void)
{
    int i = 0;
	memset(&scache.cached, 0, sizeof(scache.cached));
    for (i = 0; i < CONFIDENCE_LEVELS + 1; i++) {
        clear_taint(&scache.value[i]);
    }
}

void print_calling_bblocks (FILE* fp)
{
    struct thread_data* ptdata;
    ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct calling_bblock* tmp = CALLING_BBLOCK_HEAD;
    fprintf(fp, "calling bblock size: %d\n", CALLING_BBLOCK_SIZE);
    while (tmp != NULL) {
#ifdef HANDLED_FUNCTION_DEBUG
        //fprintf(fp, "%#x(%s)-", tmp->bblock->first_inst->inst_addr, tmp->name);
        fprintf(fp, "%#x(%s)-", tmp->address, tmp->name);
#else
        //fprintf(fp, "%#x-", tmp->bblock->first_inst->inst_addr);
        fprintf(fp, "%#x-", tmp->address);
#endif
        tmp = tmp->prev;
    }
    fprintf(fp, "\n");
}

void print_handled_functions (FILE* fp)
{
    struct thread_data* ptdata;
    ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* tmp = HANDLED_FUNC_HEAD;
    while (tmp != NULL) {
        fprintf(fp, "(%s)-", tmp->name);
        tmp = tmp->prev;
    }
    fprintf(fp, "\n");
}

void print_calling_status (FILE* fp, struct thread_data* ptdata)
{
    fprintf(fp, "CTRFLOW_TAINT_SIZE %d, CALLING_BBLOCK_HEAD(%p) SIZE(%d)\n", CTRFLOW_TAINT_STACK_SIZE, CALLING_BBLOCK_HEAD, CALLING_BBLOCK_SIZE);
    fflush(fp);
}

#ifdef MEM
void print_mems()
{
    for(int i = 0; i <15; i++) {
        fprintf(log_f, "%d: %d\n", i, mems[i]);
    }
    struct taint_info* tmp = CTRFLOW_TAINT_STACK;
    int i = modified_reg_index;
    int zero = 0;
    while(tmp) {
        while(i >= tmp->modified_reg_index) {
            fprintf(log_f, "reg is %d, count is %d\n", modified_regs[i].reg, modified_regs[i].count);
            if (modified_regs[i].count == 0) zero++;
            i--;
        }
        fprintf(log_f, "all: modified mem, reg, flag index: %d, %d, %d\n", tmp->modified_mem_index,
                tmp->modified_reg_index, tmp->modified_flag_index);
        fprintf(log_f, "real: modified mem, reg, flag index: %d, %d, %d\n", tmp->modified_mem_index_real,
                tmp->modified_reg_index_real, tmp->modified_flag_index_real);
        fprintf(log_f, "----------------------------------\n");
        
        tmp = tmp->prev; 
    }
    fprintf(log_f, "current mem/reg/flag index: %d, %d, %d\n", modified_mem_index,
            modified_reg_index, modified_flag_index);
    fprintf(log_f, "There are %d elements with zero count in the array\n", zero);
}
#endif

#ifdef FUNC_TIME
void print_function_times()
{
    struct function_time sorted[function_times_index];
    struct function_time tmp;
    memcpy(sorted, function_times, sizeof(sorted));

    for (int i = 1; i < function_times_index; i++) {
        for (int j = i-1; j >= 0; j--) {
            if (sorted[j].num_inst >= sorted[j+1].num_inst) {
                tmp = sorted[j];
                sorted[j] = sorted[j+1];
                sorted[j+1] = tmp;
            } else {
                break;
            }
        }
    }

    for(int i = 0; i < function_times_index; i++) {
        SPEC_PRINT(log_f, "Time for Function %#x is %lld, num %d\n", sorted[i].name, sorted[i].time,sorted[i].num_inst);
    }
}

void add_stat_to_function(struct timeval* new_time, int new_num_inst, ADDRINT address)
{
    PIN_LockClient();
    ADDRINT name = RTN_Address(RTN_FindByAddress(address));
    PIN_UnlockClient();
    
    void* value = 0;
    long long time_diff = (new_time->tv_sec - current_time.tv_sec)*1000000 + 
                            (new_time->tv_usec - current_time.tv_usec);
    int inst_diff = new_num_inst - current_num_inst;
    if ((value = g_hash_table_lookup(function_times_hash, &name)) != NULL) {
        //found
        struct function_time* v = (struct function_time*)value;
        v->time += time_diff;
        v->num_inst += inst_diff;
        SPEC_PRINT(log_f, "TIME: function %#x has time %lld, inst %d\n", name, v->time, v->num_inst);
    } else {
        //not found
        if (function_times_index >= 10000) {
            printf("Ran out of function_times space\n");
            return;
        }
        function_times[function_times_index].name = name;
        function_times[function_times_index].time = time_diff;
        function_times[function_times_index].num_inst = inst_diff;
        g_hash_table_insert(function_times_hash, &function_times[function_times_index].name, 
                &(function_times[function_times_index]));
        SPEC_PRINT(log_f, "TIME: function %#x has time %lld, num %d\n", function_times[function_times_index].name,
                function_times[function_times_index].time, function_times[function_times_index].num_inst);
        function_times_index++;
    }
}
#endif

int get_record_pid()
{
#ifdef HAVE_REPLAY
    int record_log_id;
    if (no_replay) return PIN_GetPid();
    record_log_id = get_log_id (dev_fd);
    if (record_log_id == -1) {
        LOG_PRINT ("Could not get log id from replay kernel\n");
        return -1;
    }
    return record_log_id;
#else
    return PIN_GetPid();
#endif
}

#define adjust_partial_reg(reg) { \
    if (reg == LEVEL_BASE::REG_DL || reg == LEVEL_BASE::REG_DH || reg == LEVEL_BASE::REG_DX) { \
        reg = LEVEL_BASE::REG_EDX; \
    } \
    if (reg == LEVEL_BASE::REG_AL || reg == LEVEL_BASE::REG_AH || reg == LEVEL_BASE::REG_AX) { \
        reg = LEVEL_BASE::REG_EAX; \
    } \
    if (reg == LEVEL_BASE::REG_CL || reg == LEVEL_BASE::REG_CH || reg == LEVEL_BASE::REG_CX) { \
        reg = LEVEL_BASE::REG_ECX; \
    } \
    if (reg == LEVEL_BASE::REG_BL || reg == LEVEL_BASE::REG_BH || reg == LEVEL_BASE::REG_BX) { \
        reg = LEVEL_BASE::REG_EBX; \
    } \
}

int in_main_image (ADDRINT addr) {
    return ((unsigned)addr > (unsigned)main_low_addr && (unsigned)addr < (unsigned)main_high_addr);
}

#define print_dependency_tokens(args) __print_dependency_tokens(log_f, args)

void __print_dependency_tokens(FILE* file, struct taint* vector)
{
    print_taint(file, vector);
}

#define print_ctrflow_stack_conditions(args) __print_ctrflow_stack_conditions(log_f, args);

void __print_ctrflow_stack_conditions(FILE* fp, struct thread_data* ptdata) {
    struct taint_info* top;

    if (ptdata == NULL) {
        fprintf(fp, "print ctrflow: ptdata is NULL\n");
        return;
    }

    top = CTRFLOW_TAINT_STACK;
    while (top != NULL) {
        if (top->merge_bblock && top->merge_bblock->first_inst) {
            fprintf(fp, "merge_bblock first inst: %#x:  ", top->merge_bblock->first_inst->inst_addr);
            __print_dependency_tokens(fp, &top->ctrflow_taint);
        }
        top = top->prev;
    }   
}

void __print_top_ctrflow_stack (FILE* fp, struct thread_data* ptdata, int spaces) {
    struct taint_info* top;

    if (ptdata == NULL) return;

    top = CTRFLOW_TAINT_STACK;
    if (top == NULL) return;    
    for (int i = 0; i < spaces; i++) { fprintf(fp, "\t"); }
    __print_dependency_tokens(fp, &top->ctrflow_taint);
}

void output_cf_taint(ADDRINT name)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (NUM_CKPTS > 0) return;

    GRAB_GLOBAL_LOCK (ptdata);    

    FILE* fp = log_f;

    // Let's file lock the results file
    if (flock(fileno(fp), LOCK_EX) == -1) {
        fprintf(log_f, "Could not grab the results file lock\n");
    }

    // flush immediately after grabbing flock
    fflush(fp);
    fprintf(fp, "beginning of the function %s\n", (char*)name);
    __print_ctrflow_stack_conditions(fp, ptdata);
    fprintf(fp, "-----------------------------------\n");
    fflush(fp);

    // flush before releasing flock
    fflush(fp);

    if (flock(fileno(fp), LOCK_UN) == -1) {
        fprintf(log_f, "Could not release the results file lock\n");
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

inline
void increment_syscall_cnt (struct thread_data* ptdata, int syscall_num)
{
	GRAB_GLOBAL_LOCK (ptdata);
#ifdef HAVE_REPLAY
    if (no_replay) {
        global_syscall_cnt++;
    } else {
        // ignore pthread syscalls, or deterministic system calls that we don't log (e.g. 243, 244)
        if (!(syscall_num == 17 || syscall_num == 31 || syscall_num == 32 || syscall_num == 35 || syscall_num == 44 || syscall_num == 53 || syscall_num == 56 || syscall_num == 98 || syscall_num == 243 || syscall_num == 244)) {
            if (ptdata->ignore_flag) {
                if (!(*(int *)(ptdata->ignore_flag))) {
                    global_syscall_cnt++;
                }
            } else {
                global_syscall_cnt++;
            }
        }
    }
#else
	global_syscall_cnt++;
#endif
	RELEASE_GLOBAL_LOCK (ptdata);
}

#define print_only_token(f,vector,token_num) {					\
    if (has_nonzero_token(vector, token_num)) { \
        __print_dependency_tokens(f, vector); \
    } \
}
	
int has_nonzero_token(struct taint* vector, OPTION_TYPE token_num)
{
    return (get_taint_value(vector, token_num)) != 0;
}

inline void add_modified_mem(struct thread_data* ptdata, ADDRINT mem_location) 
{
    GRAB_GLOBAL_LOCK (ptdata);

    // This is the Mona heuristic - track per-register cf effect, last stack depth wins
    // So if modified, just set value to 1
    struct real_mem_mod* pmod;

    pmod = (struct real_mem_mod *) g_hash_table_lookup(CTRFLOW_TAINT_STACK->real_mod_mems, &mem_location);
    if (pmod) {
        pmod->shift = 1;
    } else {
#if 0
	if (g_hash_table_size(CTRFLOW_TAINT_STACK->real_mod_mems) > 500000) {
	    if (NUM_CKPTS > 0) {
		fprintf (stderr, "Over limit for mod mem\n");
		rollback(ptdata, LIMIT);
		fprintf (stderr, "After rollback - oops\n");
	    } else {
		//fprintf (stderr, "Over limit on real path???\n");
	    }
	}
#endif
#ifdef FANCY_ALLOC
        struct real_mem_mod_header* pmmc, *new_pmmc;
        pmmc = CTRFLOW_TAINT_STACK->real_mod_mem_cache;
        pmod = pmmc->next++;
        if (pmmc->next == pmmc->end) {
            new_pmmc = (struct real_mem_mod_header *) malloc (sizeof(struct real_mem_mod_header) + (pmmc->size*2)*sizeof(struct real_mem_mod));
            MYASSERT(new_pmmc);
            new_pmmc->size = pmmc->size*2;
            new_pmmc->next = (struct real_mem_mod *) ((char *) new_pmmc + sizeof(struct real_mem_mod_header));
            new_pmmc->end = (struct real_mem_mod *) ((char *) new_pmmc + sizeof(struct real_mem_mod_header) + (pmmc->size*2)*sizeof(struct real_mem_mod));
            new_pmmc->next_block = pmmc;
            CTRFLOW_TAINT_STACK->real_mod_mem_cache = new_pmmc;
        }
#else
        pmod = (struct real_mem_mod *) malloc (sizeof(struct real_mem_mod));
#endif
#ifdef TF_STATS
        num_real_mod_mems++;
#endif
        pmod->address = mem_location;
        pmod->shift = 1;
        g_hash_table_insert (CTRFLOW_TAINT_STACK->real_mod_mems, &pmod->address, pmod);
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

// This is the Mona heuristic - track per-register cf effect, last stack depth wins
// So if modified, just set value to 1
//#define add_modified_reg(ptdata,reg) CTRFLOW_TAINT_STACK->real_mod_regs[(reg)] = 1;
//#define add_modified_flag(ptdata,flag) CTRFLOW_TAINT_STACK->real_mod_flags[flag] = 1;

static inline void add_modified_reg(struct thread_data* ptdata, REG reg) {
    GRAB_GLOBAL_LOCK (ptdata);
    CTRFLOW_TAINT_STACK->real_mod_regs[(reg)] = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

static inline void add_modified_flag(struct thread_data* ptdata, int flag) {
    GRAB_GLOBAL_LOCK (ptdata);
    CTRFLOW_TAINT_STACK->real_mod_flags[flag] = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

static int mem_mod_dependency(struct thread_data* ptdata, ADDRINT mem_location, struct taint* vector, int mod, int ctrflow_propagate) 
{   
    GRAB_GLOBAL_LOCK (ptdata);
    unsigned high_index;
    unsigned mid_index;
    unsigned low_index;
    unsigned mem_loc = (unsigned)mem_location;
    struct taint** first_t;
    struct taint *second_t, *value;

    MYASSERT(vector);
    high_index = (mem_loc >> (SECOND_TABLE_BITS + THIRD_TABLE_BITS));
    if(!mem_loc_high[high_index]) {
        mem_loc_high[high_index] = 
            (struct taint**) malloc (SECOND_TABLE_SIZE * sizeof(struct taint*));
        MYASSERT(mem_loc_high[high_index]);
        memset(mem_loc_high[high_index], 0, SECOND_TABLE_SIZE*sizeof(struct taint*));
#ifdef MEM
        mems[0] += SECOND_TABLE_SIZE * sizeof(struct taint);
#endif
    }
    mid_index = (mem_loc >> THIRD_TABLE_BITS) & (MID_INDEX_MASK);
    first_t = (struct taint**)mem_loc_high[high_index];
    if(!first_t[mid_index]) {
        first_t[mid_index] = 
            (struct taint*) malloc (THIRD_TABLE_SIZE*sizeof(struct taint));
        MYASSERT(first_t[mid_index]);
        // init taint
        for (int i = 0; i < THIRD_TABLE_SIZE; i++) {
            struct taint* t;
            t = first_t[mid_index] + i;
            new_taint(t);
        }
#ifdef MEM
        mems[0] += THIRD_TABLE_SIZE * sizeof(struct taint);
#endif
    }
    low_index = mem_loc & LOW_INDEX_MASK;
    second_t = first_t[mid_index];
    value = second_t + low_index;
#ifdef CTRL_FLOW
    if (CTRFLOW_TAINT_STACK->prev != 0 && ctrflow_propagate) add_modified_mem(ptdata, mem_location);
#endif
    
    if (mod == SET) {
        set_taint(value, vector);
    } else if (mod == MERGE) {
        merge_taints(value, vector);
    }

    DEP1_PRINT(log_f, "mem_mod_dependency: memory location %#x is marked, the vector is:", mem_location);
    PRINT_DEP1_VECTOR(value);
    RELEASE_GLOBAL_LOCK (ptdata);
    return 0;
}

static int mem_clear_dependency(struct thread_data* ptdata, ADDRINT mem_location)
{
    GRAB_GLOBAL_LOCK (ptdata);

    unsigned high_index;
    unsigned mid_index;
    unsigned low_index;
    unsigned mem_loc = (unsigned)mem_location;
    struct taint** first_t;
    struct taint *second_t, *value;

    high_index = (mem_loc >> (SECOND_TABLE_BITS + THIRD_TABLE_BITS)); 
    if (!mem_loc_high[high_index]) {
#ifdef CTRL_FLOW
        if (CTRFLOW_TAINT_STACK->prev != 0) add_modified_mem(ptdata, mem_location);
#endif
        RELEASE_GLOBAL_LOCK (ptdata);
        return 0;
    }
    first_t = (struct taint**)mem_loc_high[high_index];
    mid_index = (mem_loc >> THIRD_TABLE_BITS) & (MID_INDEX_MASK);
    if (!first_t[mid_index]) {
#ifdef CTRL_FLOW
        if (CTRFLOW_TAINT_STACK->prev != 0) add_modified_mem(ptdata, mem_location);
#endif
        RELEASE_GLOBAL_LOCK (ptdata);
        return 0;
    }

    low_index = mem_loc & LOW_INDEX_MASK;
    second_t = first_t[mid_index];
    value = second_t + low_index;
        
#ifdef CTRL_FLOW
    if (CTRFLOW_TAINT_STACK->prev != 0) add_modified_mem(ptdata, mem_location);
#endif
    
    if (value) {
        clear_taint(value);
    }

    DEP1_PRINT(log_f, "mem_clear_dependency: location %#x is cleared:", mem_location);
    RELEASE_GLOBAL_LOCK (ptdata);
    return 0;
}

static inline void __reg_mod_dependency(struct thread_data* ptdata, REG reg, struct taint* vector, int mode, int ctrflow_propagate)
{
    GRAB_GLOBAL_LOCK (ptdata);
    int reg_num = (int)reg;

    DEP_PRINT(log_f, "__reg_mod_dependency: reg %d(%s) is marked, the vector is:", reg_num, REG_StringShort(reg).c_str());
    PRINT_DEP_VECTOR(&reg_table[reg_num]);
    
#ifdef CTRL_FLOW
    if (CTRFLOW_TAINT_STACK->prev != 0 && ctrflow_propagate)
        add_modified_reg(ptdata, reg);
#endif
    if (mode == SET) {
        set_taint(&reg_table[reg_num], vector);
    } else if(mode == MERGE) {
        merge_taints(&reg_table[reg_num], vector);
    }
#ifdef PPRINT
    if (pprint) {
        fprintf (stderr, "\treg %d now has vector ", reg); 
        __print_dependency_tokens(stderr, &reg_table[reg_num]);
    }
#endif
    RELEASE_GLOBAL_LOCK (ptdata);
}

static int reg_mod_dependency(struct thread_data* ptdata, REG reg, struct taint* vector, int mode, int ctrflow_propagate) 
{
    if(SPECIAL_REG(reg)) return 0;
    MYASSERT(vector);

    GRAB_GLOBAL_LOCK (ptdata);

    adjust_partial_reg(reg);

    __reg_mod_dependency (ptdata, reg, vector, mode, ctrflow_propagate);

    //fix containing registers
    if (REG_is_gr16(reg) && (int)reg >= 30 && (int)reg <= 39) {
        __reg_mod_dependency(ptdata, (REG)((int)reg-1), vector, mode, ctrflow_propagate);
        __reg_mod_dependency(ptdata, (REG)((int)reg-2), vector, mode, ctrflow_propagate);
    } else if (REG_is_Half32(reg)) {
        if ((int)reg >= 16 && (int)reg <=19) {
            __reg_mod_dependency(ptdata, (REG)(((int)reg-16)*-3 + 39), vector, mode, ctrflow_propagate);
            __reg_mod_dependency(ptdata, (REG)(((int)reg-16)*-3 + 38), vector, mode, ctrflow_propagate);
            __reg_mod_dependency(ptdata, (REG)(((int)reg-16)*-3 + 37), vector, mode, ctrflow_propagate);
        } else if ((int)reg >= 12 && (int)reg <=14) 
            __reg_mod_dependency(ptdata, (REG)(54 - (int)reg), vector, mode, ctrflow_propagate);
        else if ((int)reg == 15)
            __reg_mod_dependency(ptdata, (REG)43, vector, mode, ctrflow_propagate);
    }

    RELEASE_GLOBAL_LOCK (ptdata);

    return 0;
}

static inline void __reg_clear_dependency(struct thread_data* ptdata, REG reg) 
{
    GRAB_GLOBAL_LOCK (ptdata);

    int reg_num = (int)reg;
    DEP_PRINT(log_f, "reg_clear_dependency: reg %d(%s) is cleared", reg_num, REG_StringShort(reg).c_str());
#ifdef CTRL_FLOW
    if (CTRFLOW_TAINT_STACK->prev != 0) 
        add_modified_reg(ptdata, reg);
#endif
    clear_taint(&reg_table[reg_num]);
#ifdef PPRINT
    if (pprint) {
        fprintf (stderr, "\treg %d now has vector ", reg); 
        __print_dependency_tokens(stderr, &reg_table[reg_num]);
    }
#endif
    RELEASE_GLOBAL_LOCK (ptdata);
}

static void reg_clear_dependency(struct thread_data* ptdata, REG reg) 
{
    if(SPECIAL_REG(reg)) return;

    GRAB_GLOBAL_LOCK (ptdata);

    adjust_partial_reg(reg);

    __reg_clear_dependency (ptdata, reg);

    //fix containing registers
    if (REG_is_gr16(reg) && (int)reg >= 30 && (int)reg <= 39) {
        __reg_clear_dependency (ptdata, (REG)((int)reg-1));
        __reg_clear_dependency (ptdata, (REG)((int)reg-2));
    } else if (REG_is_Half32(reg)) {
        if ((int)reg >= 16 && (int)reg <=19) {
            __reg_clear_dependency(ptdata, (REG)(((int)reg-16)*-3 + 39));
            __reg_clear_dependency(ptdata, (REG)(((int)reg-16)*-3 + 38));
            __reg_clear_dependency(ptdata, (REG)(((int)reg-16)*-3 + 37));
        } else if ((int)reg >= 12 && (int)reg <=14) 
            __reg_clear_dependency(ptdata, (REG)(54 - (int)reg));
        else if ((int)reg == 15)
            __reg_clear_dependency(ptdata, (REG)43);
    }

    RELEASE_GLOBAL_LOCK (ptdata);
    return;
}

void flags_mod_dependency_but_cf (struct thread_data* ptdata, struct taint* vector, int mode, int ctrflow_propagate)
{
    GRAB_GLOBAL_LOCK (ptdata);

    if(!vector) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
#ifdef CTRL_FLOW
    if (ctrflow_propagate && CTRFLOW_TAINT_STACK->prev != 0) {
        add_modified_flag(ptdata, AF_FLAG);
        add_modified_flag(ptdata, PF_FLAG);
        add_modified_flag(ptdata, SF_FLAG);
        add_modified_flag(ptdata, ZF_FLAG);
        add_modified_flag(ptdata, OF_FLAG);
    }
#endif
    if(mode == SET) {
        set_taint(&flag_table[AF_FLAG], vector);
        set_taint(&flag_table[PF_FLAG], vector);
        set_taint(&flag_table[SF_FLAG], vector);
        set_taint(&flag_table[ZF_FLAG], vector);
        set_taint(&flag_table[OF_FLAG], vector);
    } else if(mode == MERGE) {
        merge_taints(&flag_table[AF_FLAG], vector);
        merge_taints(&flag_table[PF_FLAG], vector);
        merge_taints(&flag_table[SF_FLAG], vector);
        merge_taints(&flag_table[ZF_FLAG], vector);
        merge_taints(&flag_table[OF_FLAG], vector);
    }
    DEP_PRINT(log_f, "flags_mod_dependency_but_cf: flags are marked, the vector is:");
    PRINT_DEP_VECTOR(vector);

    RELEASE_GLOBAL_LOCK (ptdata);
}

void flags_mod_dependency (struct thread_data* ptdata, struct taint* vector, int mode, int ctrflow_propagate)
{
    GRAB_GLOBAL_LOCK (ptdata);

    if(!vector) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
#ifdef CTRL_FLOW
    if (ctrflow_propagate && CTRFLOW_TAINT_STACK->prev != 0) {
        for (int i = 0; i < NUM_FLAGS; i++)
            add_modified_flag(ptdata, i);
    }
#endif
    if(mode == SET) {
        for (int i = 0; i < NUM_FLAGS; i++) {
            set_taint(&flag_table[i], vector);
        }

    } else if(mode == MERGE) {
        for (int i = 0; i < NUM_FLAGS; i++) {
            merge_taints(&flag_table[i], vector);
        }
    }
    DEP_PRINT(log_f, "flags_mod_dependency: flags are marked, the vector is:");
    PRINT_DEP_VECTOR(vector);
#ifdef PPRINT
    if (pprint) {
        for (int i = 0; i < NUM_FLAGS; i++) {
            if (mode == SET) {
                fprintf (stderr, "\tflag %d set with vector ", i); 
            } else {
                fprintf (stderr, "\tflag %d merged with vector ", i); 
            }
            __print_dependency_tokens(stderr, vector);
            fprintf (stderr, "\tflag %d now has taint ", i); 
            __print_dependency_tokens(stderr, &flag_table[i]);
        }
    }
#endif

    RELEASE_GLOBAL_LOCK (ptdata);
}

void flags_clear_dependency_but_cf(struct thread_data* ptdata)
{
    GRAB_GLOBAL_LOCK (ptdata);
#ifdef CTRL_FLOW
    if (CTRFLOW_TAINT_STACK->prev != 0) {
        add_modified_flag(ptdata, AF_FLAG);
        add_modified_flag(ptdata, PF_FLAG);
        add_modified_flag(ptdata, SF_FLAG);
        add_modified_flag(ptdata, ZF_FLAG);
        add_modified_flag(ptdata, OF_FLAG);
    }
#endif
    clear_taint(&flag_table[AF_FLAG]);
    clear_taint(&flag_table[PF_FLAG]);
    clear_taint(&flag_table[SF_FLAG]);
    clear_taint(&flag_table[ZF_FLAG]);
    clear_taint(&flag_table[OF_FLAG]);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void flags_clear_dependency(struct thread_data* ptdata)
{
    GRAB_GLOBAL_LOCK (ptdata);
#ifdef CTRL_FLOW
    if (CTRFLOW_TAINT_STACK->prev != 0)
        for(int i = 0; i < NUM_FLAGS; i++)
            add_modified_flag(ptdata, i);
#endif
    
    for (int i = 0; i < NUM_FLAGS; i++) {
        clear_taint(&flag_table[i]);
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void flag_clear_dependency(struct thread_data* ptdata, int flag)
{
#ifdef CTRL_FLOW
    if (flag < 0 || flag >= NUM_FLAGS) return;
    GRAB_GLOBAL_LOCK (ptdata);
    if (CTRFLOW_TAINT_STACK->prev != 0) {
        add_modified_flag(ptdata, flag);
    }
    
    clear_taint(&flag_table[flag]);
    RELEASE_GLOBAL_LOCK (ptdata);
#endif
}

inline struct taint* get_mem_taint(ADDRINT mem_loc) 
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);
    unsigned location = (unsigned)mem_loc;
    int high_index = location >> (SECOND_TABLE_BITS + THIRD_TABLE_BITS);
    struct taint** first = (struct taint**)mem_loc_high[high_index];
    if(!first) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return NULL;
    }
    
    int mid_index = (location >> THIRD_TABLE_BITS) & MID_INDEX_MASK;
    struct taint* second = first[mid_index];
    if(!second) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return NULL;
    }

    int low_index = location & LOW_INDEX_MASK;
    if (!is_taint_zero(second + low_index)) {

#if 0
#ifdef PPRINT
    if (pprint) {
		fprintf (stderr, "get_mem_taint of address 0x%x returns: ", mem_loc);
		__print_dependency_tokens(stderr, second + low_index);
	    }
#endif
#endif
        RELEASE_GLOBAL_LOCK (ptdata);
	    return (second + low_index);
    }
    RELEASE_GLOBAL_LOCK (ptdata);
    return NULL;
}

inline struct taint* get_reg_taint(REG reg) 
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);

    adjust_partial_reg(reg);

    if (!is_taint_zero(&reg_table[(int)reg])) {
#ifdef PPRINT
        if (pprint) {
            fprintf (stderr, "\tget_reg_taint of reg %d returns: ", reg);
            __print_dependency_tokens(stderr, &reg_table[(int)reg]);
        }
#endif
        RELEASE_GLOBAL_LOCK (ptdata);
        return &reg_table[(int)reg];
    }
    RELEASE_GLOBAL_LOCK (ptdata);
    return NULL;
}

#ifdef TAINT_TRACK
inline void taint_track_locations(const char* name, ADDRINT loc, int size)
{
    for (int i = 0; i < (int)size; i++) {
        if ((loc + i) == TAINT_LOCATION) {
            LOG_PRINT ("[TAINT_TRACK] %s %#x ", name, loc + i);
            __print_dependency_tokens (LOG_F, get_mem_taint(loc + i));
        }
    }
}
#endif // TAINT_TRACK

inline int content_non_pointer(ADDRINT reg_value)
{
    if ((unsigned)reg_value >= 1000) {
        return 0;
    }
    return 1;
}

void taint_mem2reg (ADDRINT mem_loc, UINT32 size, REG reg) 
{
    TAINT_START ("mem2reg");

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
    vector = get_mem_taint(mem_loc);
    TAINT_PRINT ("taint_mem2reg: memory location %#x has mark, vector is ", mem_loc);
    TAINT_PRINT_DEP_VECTOR (vector);
    if(vector) {
        reg_mod_dependency(ptdata, reg, vector, SET, 1);    
    } else {
        reg_clear_dependency(ptdata, reg);
    }
	
    for(int i = 1; i < (int)size; i++) {
        vector = get_mem_taint(mem_loc + i);
        if(vector) {
            TAINT_PRINT ("taint_mem2reg: memory location %#x has mark, vector is ", mem_loc + i);
            TAINT_PRINT_DEP_VECTOR(vector);

            reg_mod_dependency(ptdata, reg, vector, MERGE, 0);    
        }
    }
    TAINT_PRINT ("taint_mem2reg: reg is: ");
    TAINT_PRINT_DEP_VECTOR (get_reg_taint(reg));

#ifdef TAINT_TRACK
    taint_track_locations("taint_mem2reg", mem_loc, (int)size);
#endif

    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_mem2flag (ADDRINT mem_loc, UINT32 size) 
{
    TAINT_START ("mem2flag");

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
    vector = get_mem_taint(mem_loc);
    if(vector) {
        TAINT_PRINT ("taint_mem2flag: memory location %#x has mark, vector is ", mem_loc);
        TAINT_PRINT_DEP_VECTOR(vector);
        flags_mod_dependency(ptdata, vector, SET, 1);
    } else {
        flags_clear_dependency(ptdata);
    }
    for(int i = 1; i < (int)size; i++) {
        vector = get_mem_taint(mem_loc + i);
        if(vector) {
            TAINT_PRINT ("taint_mem2flag: memory location %#x has mark, vector is ", mem_loc + i);
            TAINT_PRINT_DEP_VECTOR(vector);
            flags_mod_dependency(ptdata, vector, MERGE, 0);
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_mem2cf (ADDRINT mem_loc, UINT32 size)
{
    TAINT_START ("taint_mem2cf");

    GRAB_GLOBAL_LOCK (ptdata);

#ifdef CTRL_FLOW
    if (CTRFLOW_TAINT_STACK->prev != 0) {
        add_modified_flag(ptdata, CF_FLAG);
    }
#endif
    struct taint* vector = 0;
    vector = get_mem_taint(mem_loc);
    if (vector) {
        TAINT_PRINT("taint_mem2cf: mem %#x has mark, vector is ", mem_loc);
        TAINT_PRINT_DEP_VECTOR(vector);
        set_taint(&flag_table[CF_FLAG], vector);
    } else {
        clear_taint(&flag_table[CF_FLAG]);
    }
    for (int i = 1; i < (int)size; i++) {
        vector = get_mem_taint(mem_loc + i);
        if (vector) {
            TAINT_PRINT("taint_mem2cf: mem %#x has mark, vector is ", mem_loc);
            TAINT_PRINT_DEP_VECTOR(vector);
            merge_taints(&flag_table[CF_FLAG], vector);
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_mem2flags_but_cf (ADDRINT mem_loc, UINT32 size, REG reg) 
{
    TAINT_START ("mem2flags_but_cf");

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
    vector = get_mem_taint(mem_loc);
    if(vector) {
        DEP_PRINT(log_f, "taint_mem2flag: memory location %#x has mark, vector is ", mem_loc);
        PRINT_DEP_VECTOR(vector);
        flags_mod_dependency_but_cf(ptdata, vector, SET, 1);
    } else {
        flags_clear_dependency_but_cf(ptdata);
    }

    for(int i = 1; i < (int)size; i++) {
        vector = get_mem_taint(mem_loc + i);
        if(vector) {
            DEP_PRINT(log_f, "taint_mem2flag: memory location %#x has mark, vector is ", mem_loc + i);
            PRINT_DEP_VECTOR(vector);
            flags_mod_dependency_but_cf(ptdata, vector, MERGE, 0);
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}


void taint_whole_reg2mem (ADDRINT mem_loc, ADDRINT eflags, ADDRINT reg_value, UINT32 op_size); //function signature
void rep_taint_whole_reg2mem (BOOL first, ADDRINT mem_loc, ADDRINT eflags, ADDRINT reg_value, UINT32 op_size) 
{
    if (first) {
        taint_whole_reg2mem(mem_loc, eflags, reg_value, op_size);
    }
}

void taint_whole_reg2mem (ADDRINT mem_loc, ADDRINT eflags, ADDRINT reg_value, UINT32 op_size) 
{
    TAINT_START ("whole_reg2mem");

    GRAB_GLOBAL_LOCK (ptdata);

    int size = (int)(reg_value*op_size);
    REG src_reg = (op_size == 1) ? LEVEL_BASE::REG_AL : ((op_size == 2) ? LEVEL_BASE::REG_AX : LEVEL_BASE::REG_EAX);
    int dir = eflags & DF_MASK ? -1 : 1;
    struct taint* vector = 0;
    vector = get_reg_taint(src_reg);
    if(vector) {
        TAINT_PRINT ("taint_whole_reg2mem: reg %d has mark, vector is ", src_reg);
        TAINT_PRINT_DEP_VECTOR(vector);
        for(int i = 0; i < (int)size; i++) {
            mem_mod_dependency(ptdata, mem_loc + i*dir, vector, SET, 1);    
        }
    } else {
        for(int i = 0; i < (int)size; i++) {
            mem_clear_dependency(ptdata, mem_loc + i*dir);
        }
    }   
#ifdef TAINT_TRACK
    taint_track_locations("taint_whole_reg2mem", mem_loc, size);
#endif
    RELEASE_GLOBAL_LOCK (ptdata);
}

// function signature
void taint_whole_mem2reg (ADDRINT mem_loc, REG dst_reg, ADDRINT eflags, ADDRINT reg_value, UINT32 op_size);

void rep_taint_whole_mem2reg (BOOL first, ADDRINT mem_loc, REG dst_reg, ADDRINT eflags, ADDRINT reg_value, UINT32 op_size) {
    if (first) {
        taint_whole_mem2reg(mem_loc, dst_reg, eflags, reg_value, op_size);
    }
}

void taint_whole_mem2reg (ADDRINT mem_loc, REG dst_reg, ADDRINT eflags, ADDRINT reg_value, UINT32 op_size) 
{
    TAINT_START ("whole_mem2reg");

    GRAB_GLOBAL_LOCK (ptdata);

    int size = (int)(reg_value*op_size);
    int dir = eflags & DF_MASK ? -1 : 1;
    //the inefficient version
    struct taint* vector;
    reg_clear_dependency(ptdata, dst_reg);
    
    for(int i = 0; i < (int)size; i++) {
        vector = get_mem_taint(mem_loc + i*dir);
        if(vector) {
            TAINT_PRINT("taint_whole_mem2reg: memory location %#x has mark, vector is ", mem_loc + i*dir);
            TAINT_PRINT_DEP_VECTOR(vector);

#ifdef PPRINT
#ifdef TARGET_PPRINT
        if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
		if (has_nonzero_token(vector, INTERESTED_TOKEN)) {
			fprintf(stderr, "taint_whole_mem2reg: mem_loc %#x has mark, vector is ", mem_loc + i*dir);
			__print_dependency_tokens(stderr, vector);
		}
	}
#endif
#endif

        reg_mod_dependency(ptdata, dst_reg, vector, MERGE, 0);    

#ifdef TAINT_TRACK
        taint_track_locations("taint_whole_mem2reg", mem_loc, size);
#endif

        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

// function signature
void taint_whole_mem2mem(ADDRINT src_mem_loc, ADDRINT dst_mem_loc, ADDRINT eflags, ADDRINT reg_value, UINT32 op_size);

void rep_taint_whole_mem2mem(BOOL first, ADDRINT src_mem_loc, ADDRINT dst_mem_loc,
                                ADDRINT eflags, ADDRINT reg_value, UINT32 op_size) {
    if (first) {
        taint_whole_mem2mem(src_mem_loc, dst_mem_loc, eflags, reg_value, op_size);
    }
}

void taint_whole_mem2mem(ADDRINT src_mem_loc, ADDRINT dst_mem_loc, ADDRINT eflags, ADDRINT reg_value, UINT32 op_size)
{
    TAINT_START ("whole_mem2mem");

    GRAB_GLOBAL_LOCK (ptdata);

    int size = (int)(reg_value*op_size);
    int dir = eflags & DF_MASK ? -1 : 1;
    //the inefficient version 
    struct taint* vector;
    int tainted = 0;
    
    TAINT_PRINT("taint_whole_mem2mem: size of memory is %d\n", size);
    for(int i = 0; i < (int)size; i++) {
        vector = get_mem_taint(src_mem_loc + i*dir);
        if(vector) {
            tainted++;
            mem_mod_dependency(ptdata, dst_mem_loc + i*dir, vector, SET, 1);    
        } else {
            mem_clear_dependency(ptdata, dst_mem_loc + i*dir);
        }
    }
    TAINT_PRINT ("taint_whole_mem2mem: memory was tainted for %d locations\n", tainted);

#ifdef TAINT_TRACK
    taint_track_locations("taint_whole_mem2mem: src loc", src_mem_loc, (int)size);
    taint_track_locations("taint_whole_mem2mem: dst loc", dst_mem_loc, (int)size);
#endif

    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_mem2mem (ADDRINT src_mem_loc, ADDRINT dst_mem_loc, UINT32 size) 
{
    TAINT_START ("mem2mem");

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
    for(int i = 0; i < (int)size; i++) {
        vector = get_mem_taint(src_mem_loc + i);
        if(vector) {
            TAINT_PRINT ("taint_mem2mem: src memory location %#x has mark, vector is ", src_mem_loc + i);
            TAINT_PRINT_DEP_VECTOR(vector);
            mem_mod_dependency(ptdata, dst_mem_loc + i, vector, SET, 0);
        } else {
            mem_clear_dependency(ptdata, dst_mem_loc + i);
        }
    }

#ifdef TAINT_TRACK
    taint_track_locations("taint_mem2mem: src loc", src_mem_loc, (int)size);
    taint_track_locations("taint_mem2mem: dst loc", dst_mem_loc, (int)size);
#endif

    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_reg2mem (ADDRINT mem_loc, UINT32 size, REG reg) 
{
    TAINT_START ("reg2mem");

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector = 0;
    vector = get_reg_taint(reg);
    TAINT_PRINT ("taint_reg2mem: reg %d has taint ", reg);
    TAINT_PRINT_DEP_VECTOR(vector);
    if(vector) {
        TAINT_PRINT ("taint_reg2mem: reg %d (%s) has mark, vector is ", reg, REG_StringShort(reg).c_str());
        TAINT_PRINT_DEP_VECTOR(vector);
        for(int i = 0; i < (int)size; i++) {
            mem_mod_dependency(ptdata, mem_loc + i, vector, SET, 1);    
            TAINT_PRINT ("taint_reg2mem: mem %#x ", mem_loc + i);
            TAINT_PRINT_DEP_VECTOR (get_mem_taint(mem_loc + i));
        }
    } else {
        for(int i = 0; i < (int)size; i++) {
            mem_clear_dependency(ptdata, mem_loc + i);    
        }
    }   
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_flag_clear(UINT32 flag)
{
    TAINT_START ("taint_flag_clear");

    GRAB_GLOBAL_LOCK (ptdata);
    flag_clear_dependency (ptdata, flag);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_reg2flag(REG reg)
{
    TAINT_START ("taint_reg2flag");

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector = 0;
    vector = get_reg_taint(reg);
    if(vector) {
        TAINT_PRINT ("taint_reg2flag: reg %d has mark, vector is ", reg);
        TAINT_PRINT_DEP_VECTOR(vector);

#ifdef PPRINT
#ifdef TARGET_PPRINT
        if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
		if (has_nonzero_token(vector, INTERESTED_TOKEN)) {
			fprintf(stderr, "taint_reg2flag: reg %d has mark, vector is ", reg);
			__print_dependency_tokens(stderr, vector);
		}
	}
#endif
#endif

        flags_mod_dependency(ptdata, vector, SET, 1);    
    } else {
        flags_clear_dependency(ptdata);    
    }   
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_reg2flags_but_cf(REG reg)
{
    TAINT_START ("reg2flags_but_cf");

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector = 0;
    vector = get_reg_taint(reg);
    if(vector) {
        TAINT_PRINT("taint_reg2flags_but_cf: reg %d has mark, vector is ", reg);
        TAINT_PRINT_DEP_VECTOR(vector);
        flags_mod_dependency_but_cf(ptdata, vector, SET, 1);    
    } else {
        flags_clear_dependency_but_cf(ptdata);    
    }   

    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_reg2cf_of(REG reg)
{
    TAINT_START ("taint_reg2cf_of");

    GRAB_GLOBAL_LOCK (ptdata);

#ifdef CTRL_FLOW
    if (CTRFLOW_TAINT_STACK->prev != 0) {
        add_modified_flag(ptdata, CF_FLAG);
        add_modified_flag(ptdata, OF_FLAG);
    }
#endif
    struct taint* vector = 0;
    vector = get_reg_taint(reg);
    if(vector) {
        TAINT_PRINT("taint_reg2cf_of: reg %d has mark, vector is ", reg);
        TAINT_PRINT_DEP_VECTOR(vector);
        set_taint(&flag_table[CF_FLAG], vector);
        set_taint(&flag_table[OF_FLAG], vector);
    } else {
        clear_taint(&flag_table[CF_FLAG]);
        clear_taint(&flag_table[OF_FLAG]);
    }   
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_reg2cf(REG reg, int mode)
{
    TAINT_START ("taint_reg2cf");
    
    GRAB_GLOBAL_LOCK (ptdata);

#ifdef CTRL_FLOW
    if (CTRFLOW_TAINT_STACK->prev != 0) {
        add_modified_flag(ptdata, CF_FLAG);
    }
#endif
    struct taint* vector = 0;
    vector = get_reg_taint(reg);
    if (vector) {
        TAINT_PRINT("taint_reg2cf: reg %d has mark, vector is ", reg);
        TAINT_PRINT_DEP_VECTOR(vector);
        if (mode == MERGE) {
            merge_taints(&flag_table[CF_FLAG], vector);
        } else if (mode == SET) {
            set_taint(&flag_table[CF_FLAG], vector);
        }
    } else {
        if (mode == SET) {
            clear_taint(&flag_table[CF_FLAG]);
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_flag2mem (ADDRINT mem_loc, UINT32 size, UINT32 mask, int mode)
{
    TAINT_START ("flag2mem");

    GRAB_GLOBAL_LOCK (ptdata);

    int i;
    struct taint tmp;
    new_taint(&tmp);
    clear_taint(&tmp);
    if(mask & CF_MASK) merge_taints(&tmp, &flag_table[CF_FLAG]);
    if(mask & SF_MASK) merge_taints(&tmp, &flag_table[SF_FLAG]);
    if(mask & ZF_MASK) merge_taints(&tmp, &flag_table[ZF_FLAG]);
    if(mask & OF_MASK) merge_taints(&tmp, &flag_table[OF_FLAG]);
    if(mask & AF_MASK) merge_taints(&tmp, &flag_table[AF_FLAG]);
    if(mask & PF_MASK) merge_taints(&tmp, &flag_table[PF_FLAG]);
    for(i = 0; i < (int)size; i++) {
        mem_mod_dependency(ptdata, mem_loc + i, &tmp, mode, 1);    
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_immval2flag()
{
    TAINT_START ("immval2flag");

    GRAB_GLOBAL_LOCK (ptdata);

    flags_clear_dependency(ptdata);

    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_immval2reg(REG reg, int mode) 
{
    TAINT_START ("immval2reg");

    GRAB_GLOBAL_LOCK (ptdata);

    if (mode == SET) {
        TAINT_PRINT ("taint_immval2reg: clear reg %s\n", REG_StringShort(reg).c_str());
        reg_clear_dependency(ptdata, reg);
    }
#ifdef CTRL_FLOW
    else if (CTRFLOW_TAINT_STACK->prev != 0) {
        add_modified_reg(ptdata, reg);
    }
#endif
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_reg2reg (REG dst_reg, REG src_reg) 
{
    TAINT_START ("reg2reg");

    GRAB_GLOBAL_LOCK (ptdata);

    TAINT_PRINT ("taint_reg2reg: dst %s ", REG_StringShort(dst_reg).c_str());
    TAINT_PRINT_DEP_VECTOR(get_reg_taint(dst_reg));
    TAINT_PRINT ("taint_reg2reg: src %s ", REG_StringShort(src_reg).c_str());
    TAINT_PRINT_DEP_VECTOR(get_reg_taint(src_reg));

    struct taint* vector = 0;
    vector = get_reg_taint(src_reg);
    if(vector) {
        TAINT_PRINT ("taint_reg2reg: reg %d has mark, vector is ", src_reg);
        TAINT_PRINT_DEP_VECTOR(vector);
        reg_mod_dependency(ptdata, dst_reg, vector, SET, 1);    
    } else {
        reg_clear_dependency(ptdata, dst_reg);
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_flag2reg (REG reg, UINT32 mask, int mode)
{
    TAINT_START ("flag2reg");

    GRAB_GLOBAL_LOCK (ptdata);
    TAINT_PRINT("taint_flag2reg: reg is %d\n", reg);

    struct taint tmp;
    new_taint(&tmp);
    clear_taint(&tmp);
    if(mask & CF_MASK) merge_taints(&tmp, &flag_table[CF_FLAG]);
    if(mask & SF_MASK) merge_taints(&tmp, &flag_table[SF_FLAG]);
    if(mask & ZF_MASK) merge_taints(&tmp, &flag_table[ZF_FLAG]);
    if(mask & OF_MASK) merge_taints(&tmp, &flag_table[OF_FLAG]);
    if(mask & AF_MASK) merge_taints(&tmp, &flag_table[AF_FLAG]);
    if(mask & PF_MASK) merge_taints(&tmp, &flag_table[PF_FLAG]);
    reg_mod_dependency(ptdata, reg, &tmp, mode, 1);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_immval2mem (ADDRINT mem_loc, UINT32 size, int mode) 
{
    TAINT_START ("immval2mem");

    GRAB_GLOBAL_LOCK (ptdata);

    if (mode == MERGE) {
#ifdef CTRL_FLOW
        if (CTRFLOW_TAINT_STACK->prev != 0) {
            for(int i = 0; i < (int)size; i++) {
                add_modified_mem(ptdata, mem_loc + i);
            }
        }
#endif
    } else {
        for(int i = 0; i < (int)size; i++) {
            mem_clear_dependency(ptdata, mem_loc + i);
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_add_reg2mem (ADDRINT mem_loc, UINT32 size, REG reg) 
{
    TAINT_START ("add_reg2mem");

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector = 0;
    vector = get_reg_taint(reg);
    if(vector) {
        TAINT_PRINT ("taint_add_reg2mem: reg %d has mark, vector is ", reg);
        TAINT_PRINT_DEP_VECTOR(vector);
	for(int i = 0; i < (int)size; i++) {
	    mem_mod_dependency(ptdata, mem_loc + i, vector, MERGE, 1);    
	}
	TAINT_PRINT_DEP_VECTOR(vector);
    } else {
#ifdef CTRL_FLOW
        if (CTRFLOW_TAINT_STACK->prev != 0) {
            for(int i = 0; i < (int)size; i++) {
                add_modified_mem(ptdata, mem_loc + i);
            }
        }
#endif
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_add_mem2reg (ADDRINT mem_loc, UINT32 size, REG reg) 
{
    TAINT_START ("add_mem2reg");

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
    TAINT_PRINT ("taint_add_mem2reg: reg is %d, mem is %#x, size %u\n", reg, mem_loc, size);
#ifdef CTRL_FLOW
    if (CTRFLOW_TAINT_STACK->prev != 0)
        add_modified_reg(ptdata, reg);
#endif
    for(int i = 0; i < (int)size; i++) {
        vector = get_mem_taint(mem_loc + i);
        if(vector) {
            DEP_PRINT(log_f, "taint_add_mem2reg: memory location %#x has mark, vector is ", mem_loc + i);
            PRINT_DEP_VECTOR(vector);

#ifdef PPRINT
#ifdef TARGET_PPRINT
            if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
                if (has_nonzero_token(vector, INTERESTED_TOKEN)) {
                    fprintf(stderr, "taint_add_mem2reg: mem_loc %#x has mark, vector is ", mem_loc + i);
                    __print_dependency_tokens(stderr, vector);
                }
            }
#endif
#endif
            reg_mod_dependency(ptdata, reg, vector, MERGE, 0);
#ifdef TAINT_TRACK
            taint_track_locations("taint_add_mem2reg", mem_loc, (int)size);
#endif
        }
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}


void taint_add_reg2reg (REG dst_reg, REG src_reg) 
{
    TAINT_START ("add_reg2reg");

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector = 0;
    vector = get_reg_taint(src_reg);
    if(vector) {
        TAINT_PRINT ("taint_add_reg2reg: src reg %d has mark, vector is ", src_reg);
        TAINT_PRINT_DEP_VECTOR(vector);
        reg_mod_dependency(ptdata, dst_reg, vector, MERGE, 1);    
    }
#ifdef CTRL_FLOW
    else if (CTRFLOW_TAINT_STACK->prev != 0) {
        add_modified_reg(ptdata, dst_reg);    
    }
#endif

    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_mem_reg_mov(ADDRINT mem_loc, UINT32 size, REG addr_reg, REG dst_reg, ADDRINT addr_val)
{
    TAINT_START ("mem_reg_mov");

    GRAB_GLOBAL_LOCK (ptdata);

    if (content_non_pointer(addr_val)) {
        taint_reg2reg(dst_reg, addr_reg);
        taint_add_mem2reg(mem_loc, size, dst_reg);
    } else {
        taint_mem2reg(mem_loc, size, dst_reg);
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_mem_2reg_mov(ADDRINT mem_loc, UINT32 size, REG index_reg, REG base_reg, REG dst_reg, 
                    ADDRINT index_val, ADDRINT base_val)
{
    TAINT_START ("mem_2reg_mov");

    GRAB_GLOBAL_LOCK (ptdata);

    int index_non_pointer = content_non_pointer(index_val);
    int base_non_pointer = content_non_pointer(base_val);
    if (index_non_pointer && base_non_pointer) {
        taint_reg2reg(dst_reg, index_reg);
        taint_add_reg2reg(dst_reg, base_reg);
        taint_add_mem2reg(mem_loc, size, dst_reg);

    } else if (index_non_pointer){
        taint_reg2reg(dst_reg, index_reg);
        taint_add_mem2reg(mem_loc, size, dst_reg);

    } else if (base_non_pointer){
        taint_reg2reg(dst_reg, base_reg);
        taint_add_mem2reg(mem_loc, size, dst_reg);
    } else {
        taint_mem2reg(mem_loc, size, dst_reg);
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}
      
// Macro that combines taint - max value wins
#define COMBINE_TAINT(x,y) (x) = ((x) < (y)) ? (y) : (x)
  
static void fix_modified_reg_real(struct thread_data* ptdata, int depth)
{

    GRAB_GLOBAL_LOCK (ptdata);
    for (int i = 0; i < NUM_REGS; i++) {
        if (!final_reg_shifts[i]) {
            int shift = CTRFLOW_TAINT_STACK->real_mod_regs[i];
            if (shift) {
                if (shift != CONFIDENCE_LEVELS) {
                    if (!scache.cached[shift]) {
                        int max_shift = depth+shift;
                        if (max_shift > CONFIDENCE_LEVELS) max_shift = CONFIDENCE_LEVELS;
                        shift_taints(&scache.value[shift], &(CTRFLOW_TAINT_STACK->condition_taint), shift);
                        struct taint_info* cts = CTRFLOW_TAINT_STACK->prev;
                        int level;
                        for (level = shift+1; level < max_shift; level++) {
                            shift_merge_taints(&scache.value[shift], &(cts->condition_taint), level);
                            cts = cts->prev;
                        }
                        scache.cached[shift] = level;
                    }
                    merge_taints(&reg_table[i], &scache.value[shift]);
                    final_reg_shifts[i] = scache.cached[shift];
                } else {
                    // XXX: No longer need to do this with new taint representation?
                    // merge_line_num(&reg_table[i], &(CTRFLOW_TAINT_STACK->condition_taint));				      		
                }
            }
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void fix_modified_reg_alt(int highest_level)
{
}

static void fix_modified_flag_real(struct thread_data* ptdata, int depth) 
{

    GRAB_GLOBAL_LOCK (ptdata);
    for (int i = 0; i < NUM_FLAGS; i++) {
        if (!final_flag_shifts[i]) {
            int shift = CTRFLOW_TAINT_STACK->real_mod_flags[i];
            if (shift) {
                if (shift != CONFIDENCE_LEVELS) {
                    if (!scache.cached[shift]) {
                        int max_shift = depth+shift;
                        if (max_shift > CONFIDENCE_LEVELS) max_shift = CONFIDENCE_LEVELS;
                        shift_taints(&scache.value[shift], &(CTRFLOW_TAINT_STACK->condition_taint), shift);
                        struct taint_info* cts = CTRFLOW_TAINT_STACK->prev;
                        int level;
                        for (level = shift+1; level < max_shift; level++) {
                            shift_merge_taints(&scache.value[shift], &(cts->condition_taint), level);
                            cts = cts->prev;
                        }
                        scache.cached[shift] = level;
                    }
                    merge_taints(&flag_table[i], &scache.value[shift]);
                    final_flag_shifts[i] = scache.cached[shift];
                } else {
                    // XXX: No longer need to do this with new taint representation?
                    // merge_line_num(&flag_table[i], &(CTRFLOW_TAINT_STACK->condition_taint));				      		
                }
            }
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void fix_modified_flag_alt(int highest_level)
{
}

static int mem_merge_shifted_dependency(ADDRINT mem_location, struct taint* vector, int level) 
{   

    unsigned high_index;
    unsigned mid_index;
    unsigned low_index;
    unsigned mem_loc = (unsigned)mem_location;
    struct taint** first_t;
    struct taint *second_t, *value;


    MYASSERT(vector);

    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);

    high_index = (mem_loc >> (SECOND_TABLE_BITS + THIRD_TABLE_BITS));
    if(!mem_loc_high[high_index]) {
        mem_loc_high[high_index] = 
            (struct taint**) malloc (SECOND_TABLE_SIZE * sizeof(struct taint*));
        MYASSERT(mem_loc_high[high_index]);
        memset(mem_loc_high[high_index], 0, SECOND_TABLE_SIZE*sizeof(struct taint*));
#ifdef MEM
        mems[0] += SECOND_TABLE_SIZE * sizeof(struct taint);
#endif
    }
    mid_index = (mem_loc >> THIRD_TABLE_BITS) & (MID_INDEX_MASK);
    first_t = (struct taint**)mem_loc_high[high_index];
    if(!first_t[mid_index]) {
        first_t[mid_index] = 
            (struct taint*) malloc (THIRD_TABLE_SIZE*sizeof(struct taint));
        MYASSERT(first_t[mid_index]);
        memset(first_t[mid_index], 0, THIRD_TABLE_SIZE*sizeof(struct taint));
#ifdef MEM
        mems[0] += THIRD_TABLE_SIZE * sizeof(struct taint);
#endif
    }
    low_index = mem_loc & LOW_INDEX_MASK;
    second_t = first_t[mid_index];
    value = second_t + low_index;

#ifdef PPRINT    
#ifdef TARGET_PPRINT
    //if (pprint && ptdata->record_pid == pid_pprint && count_syscall >= start_pprint && count_syscall < end_pprint) {
    if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint || mem_location == 0x814d754) {
#else
    if (pprint || mem_location == 0xb614c2f7) {
#endif
        if (has_nonzero_token(value, INTERESTED_TOKEN) || has_nonzero_token(vector, INTERESTED_TOKEN)) {
            fprintf (stderr, "\tmem location 0x%x before merge shift with level %d at instruction %x has vector ", mem_location, level, current_instruction); 
            __print_dependency_tokens(stderr, value);
            fprintf (stderr, "\t\tvector was: ");
            __print_dependency_tokens(stderr, vector);
        }
    }
#endif
    shift_merge_taints (value, vector, level);
#ifdef PPRINT    
#ifdef TARGET_PPRINT
    //if (pprint && ptdata->record_pid == pid_pprint && count_syscall >= start_pprint && count_syscall < end_pprint) {
    if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
#else
    if (pprint) {
#endif
        if (has_nonzero_token(value, INTERESTED_TOKEN)) {
            fprintf (stderr, "\tmem location 0x%x after merge shift at instruction %x has vector ", mem_location, current_instruction); 
            __print_dependency_tokens(stderr, value);
        }
    }
#endif

    RELEASE_GLOBAL_LOCK (ptdata);
    return 0;
}

static void update_mem_taint_simple (gpointer key, gpointer value, gpointer user_data)
{
    struct taint* vector = (struct taint *) user_data;
    struct real_mem_mod* pmod = (struct real_mem_mod *) value;

    mem_merge_shifted_dependency (pmod->address, vector, pmod->shift);
}

static gboolean update_mem_taint (gpointer key, gpointer hvalue, gpointer user_data)
{
    struct real_mem_mod* pmod = (struct real_mem_mod *) hvalue;
    struct thread_data* ptdata = (struct thread_data *) user_data;
    unsigned high_index;
    unsigned mid_index;
    unsigned low_index;
    unsigned mem_loc = pmod->address;
    int shift = pmod->shift;
    struct taint** first_t;
    struct taint *second_t, *value;

    high_index = (mem_loc >> (SECOND_TABLE_BITS + THIRD_TABLE_BITS));
    if(!mem_loc_high[high_index]) {
        mem_loc_high[high_index] = 
            (struct taint**) malloc (SECOND_TABLE_SIZE * sizeof(struct taint*));
        MYASSERT(mem_loc_high[high_index]);
        memset(mem_loc_high[high_index], 0, SECOND_TABLE_SIZE*sizeof(struct taint*));
#ifdef MEM
        mems[0] += SECOND_TABLE_SIZE * sizeof(struct taint);
#endif
    }
    mid_index = (mem_loc >> THIRD_TABLE_BITS) & (MID_INDEX_MASK);
    first_t = (struct taint**)mem_loc_high[high_index];
    if(!first_t[mid_index]) {
        first_t[mid_index] = 
            (struct taint*) malloc (THIRD_TABLE_SIZE*sizeof(struct taint));
        MYASSERT(first_t[mid_index]);
        memset(first_t[mid_index], 0, THIRD_TABLE_SIZE*sizeof(struct taint));
#ifdef MEM
        mems[0] += THIRD_TABLE_SIZE * sizeof(struct taint);
#endif
    }
    low_index = mem_loc & LOW_INDEX_MASK;
    second_t = first_t[mid_index];
    value = second_t + low_index;

#ifdef PPRINT    
#ifdef TARGET_PPRINT
    //if (pprint && ptdata->record_pid == pid_pprint && count_syscall >= start_pprint && count_syscall < end_pprint) {
    if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
#else
    if (pprint) {
#endif
        fprintf (stderr, "\tmem location 0x%x before merge shift with level %d at instruction %x has vector ", pmod->address, pmod->shift, current_instruction); 
        __print_dependency_tokens(stderr, value);
    }
#endif
	
    if (!g_hash_table_lookup_extended(final_mem_shifts, &pmod->address, NULL, NULL)) {
	if (shift != CONFIDENCE_LEVELS) {
	    if (!scache.cached[shift]) {
		int max_shift = mem_depth+shift;
		if (max_shift > CONFIDENCE_LEVELS) max_shift = CONFIDENCE_LEVELS;
		shift_taints(&scache.value[shift], &(CTRFLOW_TAINT_STACK->condition_taint), shift);
		struct taint_info* cts = CTRFLOW_TAINT_STACK->prev;
		int level;
		for (level = shift+1; level < max_shift; level++) {
		    shift_merge_taints(&scache.value[shift], &(cts->condition_taint), level);
		    cts = cts->prev;
		}
		scache.cached[shift] = level;
	    }
	    merge_taints(value, &scache.value[shift]);
	    pmod->shift = scache.cached[shift];
	    g_hash_table_insert(final_mem_shifts, &pmod->address, pmod); // Steal this entry
	}
    } else {
        // XXX: No longer need to do this with new taint representation?
        // merge_line_num(value, &(CTRFLOW_TAINT_STACK->condition_taint));
    }

#ifdef PPRINT    
#ifdef TARGET_PPRINT
    //if (pprint && ptdata->record_pid == pid_pprint && count_syscall >= start_pprint && count_syscall < end_pprint) {
    if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
#else
    if (pprint) {
#endif
	fprintf (stderr, "\tmem location 0x%x after merge shift at instruction %x has vector ", pmod->address, current_instruction); 
	__print_dependency_tokens(stderr, value);
    }
#endif
    return TRUE;
}

void fix_modified_memory_alt(int highest_level)
{
}

gboolean propagate_mem_taint (gpointer key, gpointer value, gpointer user_data)
{
    struct real_mem_mod* psrc = (struct real_mem_mod *) value;
    struct thread_data* ptdata = (struct thread_data *) user_data;
    struct real_mem_mod* pdest;

    pdest = (struct real_mem_mod *) g_hash_table_lookup (CTRFLOW_TAINT_STACK->real_mod_mems, &psrc->address);
    if (!pdest) {
	// Element in next stack hash does not exist - create it 
#ifdef FANCY_ALLOC
	struct real_mem_mod_header* pmmc, *new_pmmc;
	pmmc = CTRFLOW_TAINT_STACK->real_mod_mem_cache;
	pdest = pmmc->next++;
	if (pmmc->next == pmmc->end) {
	    new_pmmc = (struct real_mem_mod_header *) malloc (sizeof(struct real_mem_mod_header) + (pmmc->size*2)*sizeof(struct real_mem_mod));
	    MYASSERT(new_pmmc);
	    new_pmmc->size = pmmc->size*2;
	    new_pmmc->next = (struct real_mem_mod *) ((char *) new_pmmc + sizeof(struct real_mem_mod_header));
	    new_pmmc->end = (struct real_mem_mod *) ((char *) new_pmmc + sizeof(struct real_mem_mod_header) + (pmmc->size*2)*sizeof(struct real_mem_mod));
	    new_pmmc->next_block = pmmc;
	    CTRFLOW_TAINT_STACK->real_mod_mem_cache = new_pmmc;
	}
#else
	pdest = (struct real_mem_mod *) malloc (sizeof(struct real_mem_mod));
#endif
#ifdef TF_STATS
	num_real_mod_mems++;
#endif
	pdest->address = psrc->address;
	g_hash_table_insert (CTRFLOW_TAINT_STACK->real_mod_mems, &pdest->address, pdest);
    }
    pdest->shift = (psrc->shift < CONFIDENCE_LEVELS) ? psrc->shift + 1 : CONFIDENCE_LEVELS;  // No need to shift more than this
#ifndef FANCY_ALLOC
    free (psrc);
#endif

    return TRUE; // Destroy this element
}

gboolean propagate_final_taint (gpointer key, gpointer value, gpointer user_data)
{
    struct real_mem_mod* psrc = (struct real_mem_mod *) value;
    struct thread_data* ptdata = (struct thread_data *) user_data;
    struct real_mem_mod* pdest;

    pdest = (struct real_mem_mod *) g_hash_table_lookup (CTRFLOW_TAINT_STACK->real_mod_mems, &psrc->address);
    if (!pdest) {
	// Element in next stack hash does not exist - create it 
#ifdef FANCY_ALLOC
	struct real_mem_mod_header* pmmc, *new_pmmc;
	pmmc = CTRFLOW_TAINT_STACK->real_mod_mem_cache;
	pdest = pmmc->next++;
	if (pmmc->next == pmmc->end) {
	    new_pmmc = (struct real_mem_mod_header *) malloc (sizeof(struct real_mem_mod_header) + (pmmc->size*2)*sizeof(struct real_mem_mod));
	    MYASSERT(new_pmmc);
	    new_pmmc->size = pmmc->size*2;
	    new_pmmc->next = (struct real_mem_mod *) ((char *) new_pmmc + sizeof(struct real_mem_mod_header));
	    new_pmmc->end = (struct real_mem_mod *) ((char *) new_pmmc + sizeof(struct real_mem_mod_header) + (pmmc->size*2)*sizeof(struct real_mem_mod));
	    new_pmmc->next_block = pmmc;
	    CTRFLOW_TAINT_STACK->real_mod_mem_cache = new_pmmc;
	}
#else
	pdest = (struct real_mem_mod *) malloc (sizeof(struct real_mem_mod));
#endif
#ifdef TF_STATS
	num_real_mod_mems++;
#endif
	pdest->address = psrc->address;
	g_hash_table_insert (CTRFLOW_TAINT_STACK->real_mod_mems, &pdest->address, pdest);
    }
    pdest->shift = psrc->shift;
#ifndef FANCY_ALLOC
    free (psrc);
#endif

    return TRUE; // Destroy this element
}

gboolean free_mem_taint (gpointer key, gpointer value, gpointer user_data)
{
    free (value);
    return TRUE;
}

void fix_taints_and_remove_from_ctrflow (struct thread_data* ptdata, int code)
{
    GRAB_GLOBAL_LOCK (ptdata);
#ifdef ALT_PATH_EXPLORATION
    if (CTRFLOW_TAINT_STACK->alt_path == 1) {
        SPEC_PRINT(log_f, "In fix_taints: about to rollback the modified entities:\n");
        if (code == FAIL) {
            //get rid of this and later next element (spec and real elements) of the stack
            struct taint_info* tmp = CTRFLOW_TAINT_STACK;
            CTRFLOW_TAINT_STACK = tmp->prev;
            MYASSERT(CTRFLOW_TAINT_STACK);
            free (tmp);
            CTRFLOW_TAINT_STACK_SIZE--;
        }
    } else {
#endif
	// fix modified values directly
	struct taint* vector = &(CTRFLOW_TAINT_STACK->condition_taint);

	for (int i = 0; i < NUM_REGS; i++) {
	    int shift = CTRFLOW_TAINT_STACK->real_mod_regs[i];
	    if (shift) shift_merge_taints(&reg_table[i], vector, shift);
	}
	for (int i = 0; i < NUM_FLAGS; i++) {
	    int shift = CTRFLOW_TAINT_STACK->real_mod_flags[i];
	    if (shift) shift_merge_taints(&flag_table[i], vector, shift);
	}
	g_hash_table_foreach (CTRFLOW_TAINT_STACK->real_mod_mems, update_mem_taint_simple, vector);

#ifdef ALT_PATH_EXPLORATION
	fix_modified_memory_alt(highest_level);
	fix_modified_reg_alt(highest_level);
	fix_modified_flag_alt(highest_level);
    }
#endif
    
    struct taint_info* tmp = CTRFLOW_TAINT_STACK;
    CTRFLOW_TAINT_STACK = tmp->prev;
    MYASSERT(CTRFLOW_TAINT_STACK);
    CTRFLOW_TAINT_STACK_SIZE--;

#ifdef PPRINT
#ifdef TARGET_PPRINT
    //if (pprint && ptdata->record_pid == pid_pprint && count_syscall >= start_pprint && count_syscall < end_pprint) {
    if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
#else
    if (pprint) {
#endif
	fprintf (stderr, "remove cf taint, now:");
	__print_dependency_tokens(stderr, &CTRFLOW_TAINT_STACK->ctrflow_taint);
	fprintf (stderr, " cf taint stack size: %d\n", CTRFLOW_TAINT_STACK_SIZE);
    }
#endif

#ifdef ALT_PATH_EXPLORATION
    if (tmp->alt_path == 0) {
#endif
        // After real path, update the shifts for the registers - should be 1 more than for prev ctrflow stack entry
        // Mona heuristic is to just overwrite old value with new value 
        for (int i = 0; i < NUM_REGS; i++) {
            int shift = tmp->real_mod_regs[i];
            if (shift) {
            CTRFLOW_TAINT_STACK->real_mod_regs[i] = (shift < CONFIDENCE_LEVELS) ? shift + 1 : CONFIDENCE_LEVELS;  // No need to shift more than this
            }
        }
        for (int i = 0; i < NUM_FLAGS; i++) {
            int shift = tmp->real_mod_flags[i];
            if (shift) {
            CTRFLOW_TAINT_STACK->real_mod_flags[i] = (shift < CONFIDENCE_LEVELS) ? shift + 1 : CONFIDENCE_LEVELS;  // No need to shift more than this
            }
        }
        g_hash_table_foreach_remove (tmp->real_mod_mems, propagate_mem_taint, ptdata);
#ifdef ALT_PATH_EXPLORATION
    } else {
	// After alternate path, do nothing for now
        g_hash_table_foreach_remove (tmp->real_mod_mems, free_mem_taint, NULL);
    }
#endif
    g_hash_table_destroy (tmp->real_mod_mems);
#ifdef FANCY_ALLOC
    struct real_mem_mod_header* hdr = tmp->real_mod_mem_cache; 
    while (hdr) {
        struct real_mem_mod_header* tmp = hdr;
        hdr = hdr->next_block;
        free (tmp);
    }
#endif

    free (tmp);
    PRINT_SPEC_VECTOR(&CTRFLOW_TAINT_STACK->condition_taint);
    SPEC_PRINT(log_f, "size of ctrflow stack is %d\n", CTRFLOW_TAINT_STACK_SIZE);

    RELEASE_GLOBAL_LOCK (ptdata);
}


void fix_taints_and_remove_from_ctrflow_stack(struct thread_data* ptdata, int code, int depth)
{
    GRAB_GLOBAL_LOCK (ptdata);
#ifdef ALT_PATH_EXPLORATION
    if (CTRFLOW_TAINT_STACK->alt_path == 1) {
        SPEC_PRINT(log_f, "In fix_taints: about to rollback the modified entities:\n");
        if (code == FAIL) {
            //get rid of this and later next element (spec and real elements) of the stack
            struct taint_info* tmp = CTRFLOW_TAINT_STACK;
            CTRFLOW_TAINT_STACK = tmp->prev;
            MYASSERT(CTRFLOW_TAINT_STACK);
            free (tmp);
            CTRFLOW_TAINT_STACK_SIZE--;
        }
    } else {
#endif
	// re-init for new computations
	// memset(&scache.cached, 0, sizeof(scache.cached));
    reset_shift_cache();

	fix_modified_reg_real(ptdata, depth);
	fix_modified_flag_real(ptdata, depth);
	mem_depth = depth;
	g_hash_table_foreach_remove (CTRFLOW_TAINT_STACK->real_mod_mems, update_mem_taint, ptdata);
	g_hash_table_destroy (CTRFLOW_TAINT_STACK->real_mod_mems);

#ifdef ALT_PATH_EXPLORATION
	fix_modified_memory_alt(highest_level);
	fix_modified_reg_alt(highest_level);
	fix_modified_flag_alt(highest_level);
    }
#endif
    
    struct taint_info* tmp = CTRFLOW_TAINT_STACK;
    CTRFLOW_TAINT_STACK = tmp->prev;
    MYASSERT(CTRFLOW_TAINT_STACK);
    CTRFLOW_TAINT_STACK_SIZE--;

#ifdef PPRINT
#ifdef TARGET_PPRINT
    //if (pprint && ptdata->record_pid == pid_pprint && count_syscall >= start_pprint && count_syscall < end_pprint) {
    if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
#else
    if (pprint) {
#endif
	fprintf (stderr, "remove cf taint depth %d, now:", depth);
	__print_dependency_tokens(stderr, &CTRFLOW_TAINT_STACK->ctrflow_taint);
	fprintf (stderr, " cf taint stack size: %d\n", CTRFLOW_TAINT_STACK_SIZE);
    }
#endif

#ifdef ALT_PATH_EXPLORATION
    if (tmp->alt_path == 0) {
#endif
	// After real path, update the shifts for the registers - should be 1 more than for prev ctrflow stack entry
	// Mona heuristic is to just overwrite old value with new value 
	if (depth == 1) {
	    for (int i = 0; i < NUM_REGS; i++) {
		int shift = final_reg_shifts[i];
		if (shift) CTRFLOW_TAINT_STACK->real_mod_regs[i] = shift;
		final_reg_shifts[i] = 0;
	    }
	    for (int i = 0; i < NUM_FLAGS; i++) {
		int shift = final_flag_shifts[i];
		if (shift) CTRFLOW_TAINT_STACK->real_mod_flags[i] = shift;
		final_flag_shifts[i] = 0;
	    }
	    g_hash_table_foreach_remove (final_mem_shifts, propagate_final_taint, ptdata);
	}
#ifdef ALT_PATH_EXPLORATION
    } else {
	// After alternate path, do nothing for now
	g_hash_table_foreach_remove (tmp->real_mod_mems, free_mem_taint, NULL);
    }
#endif
#ifdef FANCY_ALLOC
    if (depth > 1) {
	struct real_mem_mod_header* hdr = CTRFLOW_TAINT_STACK->real_mod_mem_cache; 
	if (hdr == NULL) {
	    hdr = tmp->real_mod_mem_cache;
	} else {
	    while (hdr->next_block) hdr = hdr->next_block;  // Find the last entry
	    hdr->next_block = tmp->real_mod_mem_cache; // And stick us on the end
	}	
    } else {
	// This frees the blocks for all the stack - necessary to allow stealing
	struct real_mem_mod_header* hdr = tmp->real_mod_mem_cache; 
	while (hdr) {
	    struct real_mem_mod_header* tmp = hdr;
	    hdr = hdr->next_block;
	    free (tmp);
	}
    }
#endif

    free (tmp);
    PRINT_SPEC_VECTOR(&CTRFLOW_TAINT_STACK->condition_taint);
    SPEC_PRINT(log_f, "size of ctrflow stack is %d\n", CTRFLOW_TAINT_STACK_SIZE);
    RELEASE_GLOBAL_LOCK (ptdata);
}

static inline void init_taint_info (struct taint_info* tmp)
{
    // Initialize mod info
    for (int i = 0; i < NUM_REGS; i++) tmp->real_mod_regs[i] = 0;
    for (int i = 0; i < NUM_FLAGS; i++) tmp->real_mod_flags[i] = 0;
    tmp->real_mod_mems = g_hash_table_new (g_int_hash, g_int_equal);
#ifdef FANCY_ALLOC
    tmp->real_mod_mem_cache = (struct real_mem_mod_header *) malloc (sizeof(struct real_mem_mod_header) + INIT_MEM_MODS_PER_CACHE_BLOCK*sizeof(struct real_mem_mod));
    MYASSERT(tmp->real_mod_mem_cache);
    tmp->real_mod_mem_cache->size = INIT_MEM_MODS_PER_CACHE_BLOCK;
    tmp->real_mod_mem_cache->next = (struct real_mem_mod *) ((char *) tmp->real_mod_mem_cache + sizeof(struct real_mem_mod_header));
    tmp->real_mod_mem_cache->end = (struct real_mem_mod *) ((char *) tmp->real_mod_mem_cache + sizeof(struct real_mem_mod_header) + INIT_MEM_MODS_PER_CACHE_BLOCK*sizeof(struct real_mem_mod));
    tmp->real_mod_mem_cache->next_block = NULL;
#endif
}

void add_to_ctrflow_stack_onlyreal(struct thread_data* ptdata, struct taint* condition_taint)
{
    struct taint_info* tmp = (struct taint_info*) malloc (sizeof(struct taint_info));

    MYASSERT(tmp);

    GRAB_GLOBAL_LOCK (ptdata);
#ifdef MEM
    mems[2] += sizeof(struct taint_info);
#endif
    tmp->merge_bblock = NULL;
    tmp->calling_bblock_size = CALLING_BBLOCK_SIZE;
    tmp->alt_path = 0;
    new_taint(&tmp->condition_taint);
    new_taint(&tmp->ctrflow_taint);
    set_taint(&tmp->condition_taint, condition_taint);
    init_taint_info (tmp);
#ifdef ALT_PATH_EXPLORATION
    set_taint(&tmp->Ta, &CTRFLOW_TAINT_STACK->Ta);
#endif
    shift_cf_taint(&tmp->ctrflow_taint, condition_taint, &CTRFLOW_TAINT_STACK->ctrflow_taint);
#ifdef PPRINT
#ifdef TARGET_PPRINT
    //if (pprint && ptdata->record_pid == pid_pprint && count_syscall >= start_pprint && count_syscall < end_pprint) {
    if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
#else
    if (pprint) {
#endif
        fprintf (stderr, "adding cf taint: ");
        __print_dependency_tokens(stderr, condition_taint);
        fprintf (stderr, "add cf taint, now:");
        __print_dependency_tokens(stderr, &tmp->ctrflow_taint);
	fprintf (stderr, " cf taint stack size: %d\n", CTRFLOW_TAINT_STACK_SIZE);
    }
#endif
    tmp->prev = CTRFLOW_TAINT_STACK;
    CTRFLOW_TAINT_STACK = tmp;
    CTRFLOW_TAINT_STACK_SIZE++;
    
    //SPEC_PRINT(log_f, "size of ctrflow stack is %d, level is %d\n", CTRFLOW_TAINT_STACK_SIZE, tmp->count);
    RELEASE_GLOBAL_LOCK (ptdata);
}

#ifdef ALT_PATH_EXPLORATION
void add_to_ctrflow_stack_realandspec(struct thread_data* ptdata, struct taint* condition_taint)
{
    struct taint_info* tmp = (struct taint_info*) malloc (sizeof(struct taint_info));
    MYASSERT(tmp);

    GRAB_GLOBAL_LOCK (ptdata);
#ifdef MEM
    mems[2] += sizeof(struct taint_info);
#endif
    tmp->merge_bblock = NULL;
    tmp->calling_bblock_size = CALLING_BBLOCK_SIZE;
    tmp->alt_path = 0;
    new_taint(&tmp->condition_taint);
    new_taint(&tmp->ctrflow_taint);
    set_taint(&tmp->condition_taint, condition_taint);
    init_taint_info (tmp);
    set_taint(&tmp->Ta, &CTRFLOW_TAINT_STACK->Ta);
    tmp->prev = CTRFLOW_TAINT_STACK;
    
    struct taint_info* tmp1 = (struct taint_info*) malloc (sizeof(struct taint_info));
    MYASSERT(tmp1);
#ifdef MEM
    mems[2] += sizeof(struct taint_info);
#endif
    tmp1->merge_bblock = NULL;
    tmp1->calling_bblock_size = CALLING_BBLOCK_SIZE;
    tmp1->alt_path = 1;
    new_taint(&tmp1->condition_taint);
    new_taint(&tmp1->ctrflow_taint);
    set_taint(&tmp1->condition_taint, condition_taint);
    init_taint_info (tmp1);
    set_taint(&tmp->Ta, &CTRFLOW_TAINT_STACK->Ta);
    tmp1->prev = tmp;
    CTRFLOW_TAINT_STACK = tmp1;

    CTRFLOW_TAINT_STACK_SIZE+=2;
    SPEC_PRINT(log_f, "size of ctrflow stack is %d\n", CTRFLOW_TAINT_STACK_SIZE);

    RELEASE_GLOBAL_LOCK (ptdata);
}
#endif

void taint_ctrflow_jmp(REG reg)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;
    
    GRAB_GLOBAL_LOCK (ptdata);

    if (is_taint_zero(&reg_table[reg])) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
    //conservative branch in speculative path, no changes to the ctrflow.
    PRINT_SPEC_VECTOR(&CTRFLOW_TAINT_STACK->condition_taint);
    SPEC_PRINT(log_f, "indirect jmp: taint of reg %d is:\n", reg_num);
    PRINT_SPEC_VECTOR(&reg_table[reg_num]);

    //condition_taint = Ta ^ current_condition
    //if condition_taint is zero then we don't care about that conditional block
#ifdef CTRL_FLOW
#ifdef ALT_PATH_EXPLORATION
    int rc;
    int reg_num = (int)reg;
    struct taint* condition_taint;
    if (is_taint_full(&(CTRFLOW_TAINT_STACK->Ta))) {
        condition_taint = &reg_table[reg_num];
        rc = 1;
    } else {
      struct taint tmp;
      new_taint(&tmp);
      clear_taint(&tmp);
        // XXX: No longer need to do this with new taint representation?
        // merge_line_num(&tmp, &CTRFLOW_TAINT_STACK->Ta);
        for(int i = 0; i < NUM_OPTIONS; i++) {
            if (CTRFLOW_TAINT_STACK->Ta.options[i].conf_num < reg_table[reg_num].options[i].conf_num) {
                tmp.options[i].conf_num = CTRFLOW_TAINT_STACK->Ta.options[i].conf_num;
            } else {
                tmp.options[i].conf_num = reg_table[reg_num].options[i].conf_num;
            }
        }
        condition_taint = &tmp;
        rc = !is_taint_zero(condition_taint);
    }
#endif
#endif // CTRL_FLOW

    //this happens only if the resulting condition_taint is nonzero
#ifdef CTRL_FLOW
#ifdef ALT_PATH_EXPLORATION
    if (rc != 0) {
        if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & CONSERVATIVE) != 0)) {
            SPEC_PRINT(log_f, "Condition in conservative function is adding new taint\n");
            add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
            CALLING_BBLOCK_HEAD->is_merge_point++;
            CALLING_BBLOCK_HEAD->status |= MERGE_POINT;
        } else {
            SPEC_PRINT(log_f, "Condition in no_spec function is adding new taint\n");
            add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
        }
    }
#endif
#endif
    RELEASE_GLOBAL_LOCK (ptdata);
}

int taint_ctrflow_flag(UINT32 flag)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return 0;

#ifdef CTRL_FLOW
    GRAB_GLOBAL_LOCK (ptdata);
    if (first_inst) {
        first_inst = 0;
        RELEASE_GLOBAL_LOCK (ptdata);
        return 0;
    }
    if (is_taint_zero(&flag_table[flag])) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return 0;
    }
    //conservative branch in speculative path, no changes to the ctrflow.
    PRINT_SPEC_VECTOR(&CTRFLOW_TAINT_STACK->condition_taint);
    SPEC_PRINT(log_f, "taint of flag %d is:\n", flag);
    PRINT_SPEC_VECTOR(&flag_table[flag]);

    //condition_taint = Ta ^ current_condition
    //if condition_taint is zero then we don't care about that conditional block
    int rc;
    struct taint* condition_taint;
    condition_taint = &flag_table[flag];
    rc = 1;
#ifdef ALT_PATH_EXPLORATION
    if (is_taint_full(&(CTRFLOW_TAINT_STACK->Ta))) {
	condition_taint = &flag_table[flag];
        rc = 1;
    } else {
      struct taint tmp;
      new_taint(&tmp);
      clear_taint(&tmp);
        // XXX: No longer need to do this with new taint representation?
        // merge_line_num(&tmp, &CTRFLOW_TAINT_STACK->Ta);
        for(int i = 0; i < NUM_OPTIONS; i++) {
            if (CTRFLOW_TAINT_STACK->Ta.options[i].conf_num < flag_table[flag].options[i].conf_num) {
                tmp.options[i].conf_num = CTRFLOW_TAINT_STACK->Ta.options[i].conf_num;
            } else {
                tmp.options[i].conf_num = flag_table[flag].options[i].conf_num;
            }
        }
        condition_taint = &tmp;
        rc = !is_taint_zero(condition_taint);
    }
#endif // ALT_PATH_EXPLORATION

    //this happens only if the resulting condition_taint is nonzero
    if (rc != 0) {
#ifndef ALT_PATH_EXPLORATION
	if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & CONSERVATIVE) != 0)) {
	    SPEC_PRINT(log_f, "Condition in conservative function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	    CALLING_BBLOCK_HEAD->is_merge_point++;
	    CALLING_BBLOCK_HEAD->status |= MERGE_POINT;
	} else {
	    SPEC_PRINT(log_f, "Condition in no_spec function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	}
#else
	if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & CONSERVATIVE) != 0)) {
	    SPEC_PRINT(log_f, "Condition in conservative function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	    CALLING_BBLOCK_HEAD->is_merge_point++;
	    CALLING_BBLOCK_HEAD->status |= MERGE_POINT;
	} else if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & NO_SPEC) != 0)) {
	    SPEC_PRINT(log_f, "Condition in no_spec function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	} else {
	    SPEC_PRINT(log_f, "Condition is adding taint, we care about this block\n");
	    add_to_ctrflow_stack_realandspec(ptdata, condition_taint);
        RELEASE_GLOBAL_LOCK (ptdata);
	    return 1;
	}
#endif // ALT_PATH_EXPLORATION
    }
    
    RELEASE_GLOBAL_LOCK (ptdata);
#endif // CTRL_FLOW
    return 0;
}

int taint_ctrflow_flags(UINT32 flag1, UINT32 flag2) 
{             
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return 0;

#ifdef CTRL_FLOW
    GRAB_GLOBAL_LOCK (ptdata);
    if (first_inst) {
        first_inst = 0;
        RELEASE_GLOBAL_LOCK (ptdata);
        return 0;
    }
    struct taint flags;
    new_taint(&flags);
    set_taint(&flags,&flag_table[flag1]);
    merge_taints(&flags,&flag_table[flag2]);
    
    if (is_taint_zero(&flags)) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return 0;
    }
    
    SPEC_PRINT(log_f, "taint of flags %d and %d:\n", flag1, flag2);
    PRINT_SPEC_VECTOR(&flags);
    
    //condition_taint = Ta ^ current_condition
    //if condition_taint is zero then we don't care about that conditional block
    int rc;
    struct taint* condition_taint;
#ifdef ALT_PATH_EXPLORATION
    if (is_taint_full(&(CTRFLOW_TAINT_STACK->Ta))) {
        condition_taint = &flags;
        rc = 1;
   } else {
	struct taint tmp;
    new_taint(&tmp);
        // XXX: No longer need to do this with new taint representation?
        // merge_line_num(&tmp, &CTRFLOW_TAINT_STACK->Ta);
        for(int i = 0; i < NUM_OPTIONS; i++) {
            tmp.options[i].conf_num = (CTRFLOW_TAINT_STACK->Ta.options[i].conf_num < flags.options[i].conf_num) ?
                CTRFLOW_TAINT_STACK->Ta.options[i].conf_num : flags.options[i].conf_num;
        }
        condition_taint = &tmp;
        rc = !is_taint_zero(condition_taint);
    }
#else
    condition_taint = &flags;
    rc = 1;
#endif // ALT_PATH_EXPLORATION

    if (rc != 0) {
#ifndef ALT_PATH_EXPLORATION
	if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & CONSERVATIVE) != 0)) {
	    SPEC_PRINT(log_f, "Condition in conservative function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	    CALLING_BBLOCK_HEAD->is_merge_point++;
	    CALLING_BBLOCK_HEAD->status |= MERGE_POINT;
	} else {
	    SPEC_PRINT(log_f, "Condition in no_spec function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	}
#else
	if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & CONSERVATIVE) != 0)) {
	    SPEC_PRINT(log_f, "Condition in conservative function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	    CALLING_BBLOCK_HEAD->is_merge_point++;
	    CALLING_BBLOCK_HEAD->status |= MERGE_POINT;
	} else if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & NO_SPEC) != 0)) {
	    SPEC_PRINT(log_f, "Condition in no_spec function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	} else {
	    SPEC_PRINT(log_f, "Condition is adding taint, we care about this block\n");
	    add_to_ctrflow_stack_realandspec(ptdata, condition_taint);
        RELEASE_GLOBAL_LOCK (ptdata);
	    return 1;
	}
#endif
    }
    RELEASE_GLOBAL_LOCK (ptdata);
#endif // CTRL_FLOW
    return 0;
}

int taint_ctrflow_sf_of_zf() 
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return 0;

#ifdef CTRL_FLOW
    GRAB_GLOBAL_LOCK (ptdata);

    if (first_inst) {
        first_inst = 0;
        RELEASE_GLOBAL_LOCK (ptdata);
        return 0;
    }
    struct taint flags;
    new_taint(&flags);
    set_taint(&flags,&flag_table[SF_FLAG]);
    merge_taints(&flags,&flag_table[OF_FLAG]);
    merge_taints(&flags,&flag_table[ZF_FLAG]);

    if (is_taint_zero(&flags)) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return 0;
    }
    
    SPEC_PRINT(log_f, "taint of sf|of|zf is:\n");
    PRINT_SPEC_VECTOR(&flags);
    
    //condition_taint = Ta ^ current_condition
    //if condition_taint is zero then we don't care about that conditional block
    int rc;
    struct taint* condition_taint;
#ifdef ALT_PATH_EXPLORATION
    if (is_taint_full(&(CTRFLOW_TAINT_STACK->Ta))) {
        condition_taint = &flags;
        rc = 1;
    } else {
	struct taint tmp;
    new_taint (&tmp);
        // XXX: No longer need to do this with new taint representation?
        // merge_line_num(&tmp, &CTRFLOW_TAINT_STACK->Ta);
        for(int i = 0; i < NUM_OPTIONS; i++) {
            tmp.options[i].conf_num = (CTRFLOW_TAINT_STACK->Ta.options[i].conf_num < flags.options[i].conf_num) ?
                CTRFLOW_TAINT_STACK->Ta.options[i].conf_num : flags.options[i].conf_num;
        }
        condition_taint = &tmp;
        rc = !is_taint_equal(condition_taint);
    }
#else
    condition_taint = &flags;
    rc = 1;
#endif // ALT_PATH_EXPLORATION

    if (rc != 0) {
#ifndef ALT_PATH_EXPLORATION
	if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & CONSERVATIVE) != 0)) {
	    SPEC_PRINT(log_f, "Condition in conservative function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	    CALLING_BBLOCK_HEAD->is_merge_point++;
	    CALLING_BBLOCK_HEAD->status |= MERGE_POINT;
	} else {
	    SPEC_PRINT(log_f, "Condition in no_spec function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	}
#else
	if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & CONSERVATIVE) != 0)) {
	    SPEC_PRINT(log_f, "Condition in conservative function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	    CALLING_BBLOCK_HEAD->is_merge_point++;
	    CALLING_BBLOCK_HEAD->status |= MERGE_POINT;
	} else if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & NO_SPEC) != 0)) {
	    SPEC_PRINT(log_f, "Condition in no_spec function is adding new taint\n");
	    add_to_ctrflow_stack_onlyreal(ptdata, condition_taint);
	} else {
	    SPEC_PRINT(log_f, "Condition is adding taint, we care about this block\n");
	    add_to_ctrflow_stack_realandspec(ptdata, condition_taint);
        RELEASE_GLOBAL_LOCK (ptdata);
	    return 1;
	}
#endif // ALT_PATH_EXPLORATION
    }
    RELEASE_GLOBAL_LOCK (ptdata);
#endif // CTRL_FLOW
    return 0;
}

static inline bool cmovbe_true(UINT32 eflags)
{
    INT32 r1, r2, r3;

   /*Are either the carry flag or zero flag set?*/ 
    r1 = eflags & CF_MASK;
    r2 = (r1 == CF_MASK);
    r1 = eflags & ZF_MASK;
    r3 = (r1 == ZF_MASK);
    r3 = r3 | r2;

    return r3;
}

static inline bool cmovna_true(UINT32 eflags)
{
    INT32 r1, r2, r3;

   /*Are either the carry flag or zero flag set?*/ 
    r1 = eflags & CF_MASK;
    r2 = (r1 == CF_MASK);
    r1 = eflags & ZF_MASK;
    r3 = (r1 == ZF_MASK);
    r3 = r3 | r2;

    return r3;
}

static inline bool cmovl_true(UINT32 eflags)
{
    INT32 r1, r2, r3;

   /*Do the overflow and sign flags differ? */
    r1 = eflags & SF_MASK;
    r2 = r1 >> 7;
    r1 = eflags & OF_MASK;
    r3 = r1 >> 11;
    r3 = (r2 ^ r3);

    return r3;
}

static inline bool cmovnl_true(UINT32 eflags)
{
    INT32 r1, r2, r3;

   /*Do the overflow and sign flags differ? */
    r1 = eflags & SF_MASK;
    r2 = r1 >> 7;
    r1 = eflags & OF_MASK;
    r3 = r1 >> 11;
    r3 = !(r2 ^ r3);

    return r3;
}

static inline bool cmovle_true(UINT32 eflags)
{
    INT32 r1, r2, r3;

    /*do the sign flag and overflow flag differ OR is the zero flag set?? */
    r1 = cmovl_true(eflags);
    
    r2 = eflags & ZF_MASK;
    r3 = (r2 == ZF_MASK);
    r3 = r3 | r1;

    return r3;
}

static inline bool cmovnle_true(UINT32 eflags)
{
    INT32 r1, r2, r3;

    /*do the sign flag and overflow flag match AND is the zero flag 0?? */
    r1 = !cmovl_true(eflags);
    
    r2 = eflags & ZF_MASK;
    r3 = (r2 == 0);
    r3 = r3 & r1;
    
    return r3;
}

static inline bool cmovg_true(UINT32 eflags)
{
    INT32 r1, r2, r3;

    /*do the sign flag and overflow flag match AND is the zero flag 0?? */
    r1 = !cmovl_true(eflags);
    
    r2 = eflags & ZF_MASK;
    r3 = (r2 == 0);
    r3 = r3 & r1;
    
    return r3;
}

static inline bool cmovng_true(UINT32 eflags)
{
    INT32 r1, r2, r3;

    /*do the sign flag and overflow flag differ OR is the zero flag set?? */
    r1 = cmovl_true(eflags);
    
    r2 = eflags & ZF_MASK;
    r3 = (r2 == ZF_MASK);
    r3 = r3 | r1;

    return r3;
}

static inline bool cmovge_true(UINT32 eflags)
{
    INT32 r1, r2, r3;

   /*Do the overflow and sign flags differ? */
    r1 = eflags & SF_MASK;
    r2 = r1 >> 7;
    r1 = eflags & OF_MASK;
    r3 = r1 >> 11;
    r3 = !(r2 ^ r3);

    return r3;
}

static inline bool cmovnge_true(UINT32 eflags)
{
    INT32 r1, r2, r3;

   /*Do the overflow and sign flags differ? */
    r1 = eflags & SF_MASK;
    r2 = r1 >> 7;
    r1 = eflags & OF_MASK;
    r3 = r1 >> 11;
    r3 = (r2 ^ r3);

    return r3;
}

INT32 cmov_flags(INS ins, OPCODE opcode, UINT32* mask, UINT32* condition)
{
    INT32 rc = 0;

    switch(opcode) {
    case XED_ICLASS_CMOVB:
	//CF == 1
	*mask = CF_MASK;
	*condition = CF_MASK;
	rc = CMOV_GENERIC;
	break;
    case XED_ICLASS_CMOVBE:
	//CF == 1 || ZF == 1
	rc = CMOVBE;
	break;
    case XED_ICLASS_CMOVL:
	//SF != OF
	rc = CMOVL;
	break;
    case XED_ICLASS_CMOVLE:
	//ZF == 1 || SF != OF
	rc = CMOVLE;
	break;
    case XED_ICLASS_CMOVNB:
	//CF == 0
	*mask = CF_MASK;
	*condition = 0;
	rc = CMOV_GENERIC;
	break;
    case XED_ICLASS_CMOVNBE:
	//CF == 0 && ZF == 0
	*mask = (CF_MASK | ZF_MASK);
	*condition = 0;
	rc = CMOV_GENERIC;
	break;
    case XED_ICLASS_CMOVNL:
	//SF == OF
	rc = CMOVNL;
	break;
    case XED_ICLASS_CMOVNLE:
	//ZF == 0 && SF == OF
	rc = CMOVNLE;
	break;
    case XED_ICLASS_CMOVNO:
	//OF == 0
	*mask = OF_MASK;
	*condition = 0;
	rc = CMOV_GENERIC;
	break;
    case XED_ICLASS_CMOVNP:
	//PF == 0
	*mask = PF_MASK;
	*condition = 0;
	rc = CMOV_GENERIC;
	break;
    case XED_ICLASS_CMOVNS:
	//SF == 0
	*mask = SF_MASK;
	*condition = 0;
	rc = CMOV_GENERIC;
	break;
    case XED_ICLASS_CMOVNZ:
	//ZF == 0
	*mask = ZF_MASK;
	*condition = 0;
	rc = CMOV_GENERIC;
	break;
    case XED_ICLASS_CMOVO:
	//OF == 1
	*mask = OF_MASK;
	*condition = OF_MASK;
	rc = CMOV_GENERIC;
	break;
    case XED_ICLASS_CMOVP:
	//PF == 1
	*mask = PF_MASK;
	*condition = PF_MASK;
	rc = CMOV_GENERIC;
	break;
    case XED_ICLASS_CMOVS:
	//SF == 1
	*mask = SF_MASK;
	*condition = SF_MASK;
	rc = CMOV_GENERIC;
	break;
    case XED_ICLASS_CMOVZ:
	//ZF == 1
	*mask = ZF_MASK;
	*condition = ZF_MASK;
	rc = CMOV_GENERIC;
	break;
    }
    return rc;
}

bool check_flag_effect(UINT32 mask)
{
    if(mask & CF_MASK) {
        if(!is_taint_zero(&flag_table[CF_FLAG]))
            return 1;
    }
    if(mask & PF_MASK){
        if(!is_taint_zero(&flag_table[PF_FLAG]))
            return 1;
    }
    if(mask & SF_MASK){
        if(!is_taint_zero(&flag_table[SF_FLAG]))
            return 1;
    }
    if(mask & ZF_MASK){
        if(!is_taint_zero(&flag_table[ZF_FLAG]))
            return 1;
    }
    if(mask & OF_MASK){
        if(!is_taint_zero(&flag_table[OF_FLAG]))
            return 1;
    }
    if(mask & AF_MASK){
        if(!is_taint_zero(&flag_table[AF_FLAG]))
            return 1;
    }
    return 0;
}

/*we have a seperate set of reg_addr_differ checks to manage cmov and its kin*/
bool check_mem_cmov(UINT32 addr, UINT32 size, REG reg, UINT32 eflags, UINT32 mask, UINT32 condition)
{
    struct taint* v1;
    struct taint* v2;
    int r1 = 0, r2;
    int i = 0;

    /*do the taint values of the reg and addr location differ? */    
    v1 = get_reg_taint(reg);
    for(i = 0; i < (int)size; i++) {
        v2 = get_mem_taint(addr + i);
        r1 = (r1 || !(is_taint_equal(v1, v2)));
    }
    
    
    /*generic condition check */
    eflags = eflags & mask;
    r2 = (eflags == condition);
    r1 = r1 & r2;

    DEP_PRINT(log_f, "check_mem_cmov: mem_location %#x, reg %d, taint & condition? %d\n", addr, reg, r1);
    return (r1); 
}

bool check_mem_cmovx(UINT32 addr, UINT32 size, REG reg, UINT32 eflags, CMOV_TRUE_FN cmov_true)
{
    struct taint* v1;
    struct taint* v2;
    int r1 = 0, r2;
    int i = 0;

    /*do the taint values of the reg and addr location differ? */    
    v1 = get_reg_taint(reg);
    for(i = 0; i < (int)size; i++) {
        v2 = get_mem_taint(addr + i);
        r1 = (r1 || !(is_taint_equal(v1, v2)));
    }

    r2 = cmov_true(eflags);
 
    r1 = r1 & r2;

    DEP_PRINT(log_f, "check_mem_cmovx: mem_location %#x, reg %d, taint & condition? %d\n", addr, reg, r1);
    return (r1); 
}


bool check_reg_cmov(REG src_reg, REG dst_reg, UINT32 eflags, UINT32 mask, UINT32 condition)
{
    struct taint* v1;
    struct taint* v2;
    int r1 = 0, r2;

    /*do the taint values of the reg and addr location differ? */    
    v1 = get_reg_taint(src_reg);
    v2 = get_reg_taint(dst_reg);
    r1 = !(is_taint_equal(v1, v2));
    
    /*generic condition check */
    eflags = eflags & mask;
    r2 = (eflags == condition);
    r1 = r1 & r2;

    DEP_PRINT(log_f, "%d: check_reg_cmov: src_reg %d, dst_reg %d, taint & condition? %d\n", 
            PIN_GetPid(), src_reg, dst_reg, r1);
    return (r1); 
}

bool check_reg_cmovx(REG src_reg, REG dst_reg, UINT32 eflags, CMOV_TRUE_FN cmov_true)
{
    struct taint* v1;
    struct taint* v2;
    int r1 = 0, r2;

    /*do the taint values of the reg and addr location differ? */    
    v1 = get_reg_taint(src_reg);
    v2 = get_reg_taint(dst_reg);
    r1 = !(is_taint_equal(v1, v2));

    r2 = cmov_true(eflags);
 
    r1 = r1 & r2;

    ANALYSIS_PRINT(log_f, "check_reg_cmovx: src_reg %d, dst_reg %d, taint & condition? %d\n", src_reg, dst_reg, r1);
    ANALYSIS_PRINT(log_f, "src reg vector: ");
    PRINT_DEP_VECTOR(v1);
    ANALYSIS_PRINT(log_f, "dst reg vector: ");
    PRINT_DEP_VECTOR(v2);
    
    return (r1); 
}

void cmov_mem2reg (ADDRINT mem_location, int size, REG reg) 
{
    taint_mem2reg(mem_location, size, reg);
}

void cmov_memread(INS ins, INT32 cmov_type, USIZE addrsize, UINT32 mask, UINT32 condition, REG reg)
{

    UINT32 new_mask = 0;
    
    switch(cmov_type) {
        case CMOV_GENERIC:
            new_mask = mask;
            INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmov),
                    IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, 
                    IARG_REG_VALUE, REG_EFLAGS, IARG_UINT32, mask, IARG_UINT32, condition, IARG_END);
            break;
        case CMOVBE:
            new_mask = CF_MASK | ZF_MASK;
            INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmovx),
                    IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_PTR, cmovbe_true, IARG_END);
            break;	    
        case CMOVL:
            new_mask = SF_MASK | OF_MASK;
            INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmovx),
                    IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_PTR, cmovl_true, IARG_END);
            break;	    
        case CMOVNL:                     
            new_mask = SF_MASK | OF_MASK;
            INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmovx),
                    IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_PTR, cmovnl_true, IARG_END);
            break;	    
        case CMOVLE:
            new_mask = ZF_MASK | SF_MASK | OF_MASK;
            INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmovx),
                    IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_PTR, cmovle_true, IARG_END);
            break;	    
        case CMOVNLE:
            new_mask = ZF_MASK | SF_MASK | OF_MASK;
            INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmovx),
                    IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_REG_VALUE, REG_EFLAGS, 
                    IARG_PTR, cmovnle_true, IARG_END);
            break;	    
    }
    INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(cmov_mem2reg),
            IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);

    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_flag_effect), IARG_UINT32, mask, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(taint_flag2reg),
            IARG_UINT32, reg, IARG_UINT32, new_mask, IARG_UINT32, MERGE, IARG_END);

}

void cmov_reg2mem (ADDRINT mem_location, int size, REG reg) 
{
    taint_reg2mem(mem_location, size, reg);
}

void cmov_memwrite(INS ins, INT32 cmov_type, USIZE addrsize, UINT32 mask, UINT32 condition, REG reg)
{
    UINT32 new_mask = 0;
    
    switch(cmov_type) {
    case CMOV_GENERIC:
	new_mask = mask;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmov),
			 IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, 
			 IARG_REG_VALUE, REG_EFLAGS, IARG_UINT32, mask, IARG_UINT32, condition, IARG_END);
	break;
    case CMOVBE:
	new_mask = CF_MASK | ZF_MASK;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmovx),
			 IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_REG_VALUE, REG_EFLAGS, 
			 IARG_PTR, cmovbe_true, IARG_END);
	break;	    
    case CMOVL:
	new_mask = SF_MASK | OF_MASK;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmovx),
			 IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_REG_VALUE, REG_EFLAGS, 
			 IARG_PTR, cmovl_true, IARG_END);
	break;	    
    case CMOVNL:                                    
	new_mask = SF_MASK | OF_MASK;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmovx),
			 IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_REG_VALUE, REG_EFLAGS, 
			 IARG_PTR, cmovnl_true, IARG_END);
	break;	    
    case CMOVLE:
	new_mask = ZF_MASK | SF_MASK | OF_MASK;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmovx),
			 IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_REG_VALUE, REG_EFLAGS, 
			 IARG_PTR, cmovle_true, IARG_END);
	break;	    
    case CMOVNLE:
	new_mask = ZF_MASK | SF_MASK | OF_MASK;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_mem_cmovx),
			 IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_REG_VALUE, REG_EFLAGS, 
			 IARG_PTR, cmovnle_true, IARG_END);
	break;	    
    }
    INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(cmov_reg2mem),
		       IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
    
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_flag_effect), IARG_UINT32, mask, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(taint_flag2mem),
		   IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, new_mask, IARG_UINT32, MERGE, IARG_END);

}

void cmov_reg2reg (REG dst_reg, REG src_reg) 
{
    taint_reg2reg(dst_reg, src_reg);
}

void cmov_regmov(INS ins, INT32 cmov_type, USIZE addrsize, UINT32 mask, UINT32 condition, REG src_reg, REG dst_reg)
{
    UINT32 new_mask = 0;
    switch(cmov_type) {
    case CMOV_GENERIC:
	new_mask = mask;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_reg_cmov),
			 IARG_UINT32, src_reg, IARG_UINT32, dst_reg,  
			 IARG_REG_VALUE, REG_EFLAGS, IARG_UINT32, mask, IARG_UINT32, condition, IARG_END);
	break;
    case CMOVBE:
	new_mask = CF_MASK | ZF_MASK;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_reg_cmovx),
			 IARG_UINT32, src_reg, IARG_UINT32, dst_reg, IARG_REG_VALUE, REG_EFLAGS, 
			 IARG_PTR, cmovbe_true, IARG_END);
	break;	    
    case CMOVL:
	new_mask = SF_MASK | OF_MASK;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_reg_cmovx),
			 IARG_UINT32, src_reg, IARG_UINT32, dst_reg, IARG_REG_VALUE, REG_EFLAGS, 
			 IARG_PTR, cmovl_true, IARG_END);
	break;	    
    case CMOVNL:                     
	new_mask = SF_MASK | OF_MASK;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_reg_cmovx),
			 IARG_UINT32, src_reg, IARG_UINT32, dst_reg, IARG_REG_VALUE, REG_EFLAGS, 
			 IARG_PTR, cmovnl_true, IARG_END);
	break;	    
    case CMOVLE:
	new_mask = ZF_MASK | SF_MASK | OF_MASK;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_reg_cmovx),
			 IARG_UINT32, src_reg, IARG_UINT32, dst_reg, IARG_REG_VALUE, REG_EFLAGS, 
			 IARG_PTR, cmovle_true, IARG_END);
	break;	    
    case CMOVNLE:
	new_mask = ZF_MASK | SF_MASK | OF_MASK;
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_reg_cmovx),
			 IARG_UINT32, src_reg, IARG_UINT32, dst_reg, IARG_REG_VALUE, REG_EFLAGS, 
			 IARG_PTR, cmovnle_true, IARG_END);
	break;	    
    }
    INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(cmov_reg2reg),
		       IARG_UINT32, dst_reg, IARG_UINT32, src_reg, IARG_END);

    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_flag_effect), IARG_UINT32, mask, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(taint_flag2reg),
		   IARG_UINT32, dst_reg, IARG_UINT32, new_mask, IARG_UINT32, MERGE, IARG_END);

}

void instrument_cmov(INS ins, OPCODE opcode) 
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int ismemread = 0;
    int ismemwrite = 0;
    USIZE addrsize = 0;
    UINT32 mask = 0;
    UINT32 condition = 0;
    REG reg;
    REG dstreg;
    INT32 cmov_type;

    reg = (REG) 0;
    dstreg = (REG) 0;

    //if one operand is memory the other must be a register for cmov
    if(INS_IsMemoryRead(ins)) {
        ismemread = 1;
        addrsize = INS_MemoryReadSize(ins);
        reg = INS_OperandReg(ins, 0);
        if(!REG_valid(reg)) return;
    } else if(INS_IsMemoryWrite(ins)) {
        ismemwrite = 1;
        addrsize = INS_MemoryWriteSize(ins);
        reg = INS_OperandReg(ins, 1);
        if(!REG_valid(reg)) return;
    }

    cmov_type = cmov_flags(ins, opcode, &mask, &condition);
    INSTRUMENT_PRINT(log_f, "cmov type is %d\n", cmov_type);
    if(ismemread) {
        INSTRUMENT_PRINT(log_f, "cmov with mem read\n");
        cmov_memread(ins, cmov_type, addrsize,mask, condition, reg);

    } else if(ismemwrite) {
        INSTRUMENT_PRINT(log_f, "cmov with mem write\n");
        cmov_memwrite(ins, cmov_type, addrsize, mask, condition, reg);

    } else {
        //sometimes get an offset into video memory
        if(!(INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1))) return;
        dstreg = INS_OperandReg(ins, 0);
        reg = INS_OperandReg(ins, 1);
        if(!REG_valid(dstreg) || !REG_valid(reg)) return;
        INSTRUMENT_PRINT(log_f, "cmov with reg2reg\n");
        cmov_regmov(ins, cmov_type, addrsize, mask, condition, reg, dstreg);
    }
}

/* Dst: register
 * Src: register/memory
 * */
void instrument_movx (INS ins) 
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    //first operand is always reg
    MYASSERT(INS_OperandIsReg(ins, 0) == 1);
    REG dst_reg = INS_OperandReg(ins, 0);
    if (SPECIAL_REG(dst_reg)) return;
    if (INS_OperandIsReg(ins, 1)) {
        REG src_reg = INS_OperandReg(ins, 1);
        INSTRUMENT_PRINT(log_f, "instrument movx is src reg: %d into dst reg: %d\n", src_reg, dst_reg); 
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2reg), IARG_UINT32, dst_reg, IARG_UINT32, src_reg, IARG_END);

    } else if (INS_OperandIsMemory(ins, 1)) {
        MYASSERT(INS_IsMemoryRead(ins) == 1);
        UINT32 addrsize = INS_MemoryReadSize(ins);
        REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
        REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
    
        if (REG_valid(base_reg) && REG_valid(index_reg)) {
            INSTRUMENT_PRINT(log_f, "instrument movx address %#x base reg is %s, index reg is %s, size %d\n",
                       INS_Address(ins), REG_StringShort(base_reg).c_str(), REG_StringShort(index_reg).c_str(), addrsize);
            
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem_2reg_mov),
                           IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, 
                           IARG_UINT32, index_reg, IARG_UINT32, base_reg, IARG_UINT32, dst_reg,  
                           IARG_REG_VALUE, index_reg, IARG_REG_VALUE, base_reg, IARG_END);
        
        } else if (REG_valid(base_reg)) {
            INSTRUMENT_PRINT(log_f, "instrument movx address %#x base reg is %s, size %d\n",
                       INS_Address(ins), REG_StringShort(base_reg).c_str(), addrsize);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem_reg_mov),
                           IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, 
                           IARG_UINT32, base_reg, IARG_UINT32, dst_reg, IARG_REG_VALUE, base_reg, IARG_END);

        } else if (REG_valid(index_reg)) {
            INSTRUMENT_PRINT(log_f, "instrument movx address %#x index reg is %s, size %d\n",
                       INS_Address(ins), REG_StringShort(index_reg).c_str(), addrsize);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem_reg_mov),
                           IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, 
                           IARG_UINT32, index_reg, IARG_UINT32, dst_reg, IARG_REG_VALUE, index_reg, IARG_END);
        } else {
            INSTRUMENT_PRINT(log_f, "instrument movx address %#x dst reg is %s, size %d\n",
                    INS_Address(ins), REG_StringShort(dst_reg).c_str(), addrsize);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2reg), IARG_MEMORYREAD_EA, 
                    IARG_UINT32, addrsize, IARG_UINT32, dst_reg, IARG_END);
        }

    } else {
        fprintf(log_f, "ERROR: second operand of MOVZX/MOVSX is not reg or memory\n");
    }
}       

void instrument_mov (INS ins) 
{
    INSTRUMENT_PRINT (log_f, "starting instrument_mov\n");

    int ismemread = 0, ismemwrite = 0;
    int immval = 0;
    USIZE addrsize = 0;
    REG reg = REG_INVALID();
    REG dstreg = REG_INVALID();
    
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
            REG index_reg = INS_OperandMemoryIndexReg(ins, 1);
            REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
        
            if (REG_valid(base_reg) && REG_valid(index_reg)) {
                INSTRUMENT_PRINT(log_f, "instrument mov address %#x base reg is %s, index reg is %s\n",
                           INS_Address(ins), REG_StringShort(base_reg).c_str(), REG_StringShort(index_reg).c_str());
                
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem_2reg_mov),
                               IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, 
                               IARG_UINT32, index_reg, IARG_UINT32, base_reg, IARG_UINT32, reg,  
                               IARG_REG_VALUE, index_reg, IARG_REG_VALUE, base_reg, IARG_END);
            
            } else if (REG_valid(base_reg)) {
                INSTRUMENT_PRINT(log_f, "instrument mov address %#x base reg is %s\n",
                           INS_Address(ins), REG_StringShort(base_reg).c_str());
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem_reg_mov),
                               IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, 
                               IARG_UINT32, base_reg, IARG_UINT32, reg, IARG_REG_VALUE, base_reg, IARG_END);

            } else if (REG_valid(index_reg)) {
                INSTRUMENT_PRINT(log_f, "instrument mov address %#x index reg is %s\n",
                           INS_Address(ins), REG_StringShort(index_reg).c_str());
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem_reg_mov),
                               IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, 
                               IARG_UINT32, index_reg, IARG_UINT32, reg, IARG_REG_VALUE, index_reg, IARG_END);
            } else {
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2reg), IARG_MEMORYREAD_EA, 
                        IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);

            }
        }
    } else if(ismemwrite) {
        if(!immval) {
            //mov register to memory location
            INSTRUMENT_PRINT(log_f, "instrument mov is mem write: reg: %d, size of mem write is %u\n", reg, addrsize);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2mem),
                    IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
        } else {
            //move immediate to memory location
            INSTRUMENT_PRINT(log_f, "instrument mov is mem write: with immval\n"); 
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2mem),
                    IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, SET, IARG_END);
        }
    } else if (!SPECIAL_REG(dstreg)) {
        if(immval) {
            INSTRUMENT_PRINT(log_f, "instrument mov is immval into register, reg: %d\n", dstreg); 
            //mov immediate value into register
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2reg), IARG_UINT32, dstreg, IARG_UINT32, SET, IARG_END);
        } else {
            //mov one reg val into another
            INSTRUMENT_PRINT(log_f, "instrument mov is src reg: %d into dst reg: %d\n", reg, dstreg); 
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2reg),
                    IARG_UINT32, dstreg, IARG_UINT32, reg, IARG_END);
        }
    }
}

void instrument_cdq(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
   REG dstreg, srcreg;

   dstreg = INS_OperandReg(ins, 0);
   srcreg = INS_OperandReg(ins, 1);
   if (!REG_valid(dstreg) || !REG_valid(srcreg)) return;

   INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2reg), 
		IARG_UINT32, dstreg, IARG_UINT32, srcreg, IARG_END);
   
}

// TODO, unimplemented
void instrument_bt(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    // Different forms of bt:
    //   bt reg, reg
    //   bt mem, reg
    //   bt reg, imm
    //   bt mem, imm
    if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
        REG reg1, reg2;
        reg1 = INS_OperandReg(ins, 0);
        reg2 = INS_OperandReg(ins, 1);
        INSTRUMENT_PRINT(log_f, "instrument bt address %#x reg %d reg %d\n", INS_Address(ins), reg1, reg2);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2cf),
                IARG_UINT32, reg1, IARG_UINT32, SET, IARG_END);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2cf),
                IARG_UINT32, reg2, IARG_UINT32, MERGE, IARG_END);
    } else if (INS_OperandIsReg(ins, 0) && INS_OperandIsImmediate(ins, 1)) {
        REG reg1;
        reg1 = INS_OperandReg(ins, 0);
        INSTRUMENT_PRINT(log_f, "instrument bt address %#x reg %d\n", INS_Address(ins), reg1);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2cf),
                IARG_UINT32, reg1, IARG_UINT32, SET, IARG_END);
    } else if (INS_OperandIsMemory(ins, 0) && INS_OperandIsReg(ins, 1)) {
        // REG reg2;
        fprintf(log_f, "[NOOP] instrument bt address %#x not implemented memory operand\n", INS_Address(ins));
        // reg2 = INS_OperandReg(ins, 1);
    } else if (INS_OperandIsMemory(ins, 0) && INS_OperandIsImmediate(ins, 1)) {
        fprintf(log_f, "[NOOP] instrument bt address %#x not implemented memory operand\n", INS_Address(ins));
    } else {
        fprintf(log_f, "[NOOP] instrument bt unknown operands\n");
    }
}

/*
void instrument_pmovx(INS ins)
{
    // first and second operand always reg
    // but make sure anyways
    MYASSERT(INS_OperandIsReg(ins, 0) == 1);
    MYASSERT(INS_OperandIsReg(ins, 1) == 1);
    REG src_reg = INS_OperandReg(ins, 1);
    REG dst_reg = INS_OperandReg(ins, 0);
    if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
        INSTRUMENT_PRINT(log_f, "instrument pmovmskb is src reg: %d into dst reg: %d\n", src_reg, dst_reg);
       INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2reg), IARG_UINT32, dst_reg, IARG_UINT32, src_reg, IARG_END);
        
    }   
    else {
        fprintf(log_f, "[NOOP] instrument pmovmskb unknown operands\n");
    }
}
*/

void instrument_movaps(INS ins)
{
    int op1mem, op2mem, op1reg, op2reg;
    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    USIZE addrsize;

    if (op1reg && op2reg) {
        MYASSERT (INS_OperandIsReg(ins, 0) == 1);
        MYASSERT (INS_OperandIsReg(ins, 1) == 1);
        REG src_reg = INS_OperandReg(ins, 1);
        REG dst_reg = INS_OperandReg(ins, 0);
        INSTRUMENT_PRINT (log_f, "instrument movaps is src reg: %d into dst reg: %d\n", src_reg, dst_reg);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2reg), IARG_UINT32, dst_reg, IARG_UINT32, src_reg, IARG_END);
    } else if (op1reg && op2mem) {
        MYASSERT (INS_IsMemoryRead(ins));
        REG dst_reg = INS_OperandReg(ins, 0);
        addrsize = INS_MemoryReadSize(ins);
        INSTRUMENT_PRINT (log_f, "instrument movaps dst reg %d, mem read size %u\n", dst_reg, addrsize);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2reg), IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, dst_reg, IARG_END);
    } else if (op1mem && op2reg) {
        MYASSERT (INS_IsMemoryWrite(ins));
        REG src_reg = INS_OperandReg(ins, 1);
        addrsize = INS_MemoryWriteSize(ins);
        INSTRUMENT_PRINT (log_f, "instrument movaps src reg %d, mem write size %u\n", dst_reg, addrsize);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2mem), IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, src_reg, IARG_END);
    } else if (op1mem && op2mem) {
        MYASSERT (INS_IsMemoryRead(ins));
        MYASSERT (INS_IsMemoryWrite(ins));
        addrsize = INS_MemoryReadSize(ins);
        INSTRUMENT_PRINT (log_f, "instrument movaps, mem2mem size %u\n", addrsize);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2mem), IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
    } else {
        fprintf(log_f, "[NOOP] instrument movaps unknown operands\n");
    }
}
 
void instrument_xgetbv(INS ins)
{
    MYASSERT(INS_OperandIsReg(ins, 0) == 1);
    MYASSERT(INS_OperandIsReg(ins, 1) == 1);
    if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
        REG src_reg = INS_OperandReg(ins, 1);
        REG dst_reg = INS_OperandReg(ins, 0);
        INSTRUMENT_PRINT(log_f, "instrument xgetbv is src reg: %d into dst reg: %d\n", src_reg, dst_reg);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2reg), IARG_UINT32, dst_reg, IARG_UINT32, src_reg, IARG_END);
    }   
    else {
        fprintf(log_f, "[NOOP] instrument xgetbv unknown operands\n");
    }
}


void instrument_push(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    REG reg = REG_INVALID();
    USIZE addrsize = INS_MemoryWriteSize(ins);
    int src_reg = INS_OperandIsReg(ins, 0);
    int src_imm = INS_OperandIsImmediate(ins, 0);
    //pin push format src reg, mem write loc, stackpointer
    if(src_imm) {
        //pushing an imm value onto the stack
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2mem),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, SET, IARG_END);
    } else if (src_reg){
        reg = INS_OperandReg(ins, 0);
        if (!SPECIAL_REG(reg)) 
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2mem),
                    IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);

    } else {
        //src is memory
        if(!INS_IsMemoryRead(ins)) return;

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2mem),
                IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
    }   
}

void instrument_pop(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    REG reg = REG_INVALID();
    USIZE addrsize = INS_MemoryReadSize(ins);

    //pin pop format dest reg, mem read loc, stackpointer
    if(INS_OperandIsMemory(ins, 0)) {
	//the first operand is memory
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2mem),
			   IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
    } else if (INS_OperandIsReg(ins, 0)) {
        reg = INS_OperandReg(ins, 0);
        if (!SPECIAL_REG(reg)) {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2reg),
                               IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
        }
    }
}                                                                  

void taint_xadd_regs(REG dst, REG src)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;
    struct taint* v_tmp = get_reg_taint(src);
    if(v_tmp) {
        struct taint v_reg;
        new_taint(&v_reg);
        set_taint(&v_reg,v_tmp);
        DEP_PRINT(log_f, "taint_xadd_regs: src reg %d has mark:\n", src);
        PRINT_DEP_VECTOR(&v_reg);
        taint_reg2reg(src, dst);
        reg_mod_dependency(ptdata, dst, &v_reg, MERGE, 1);    
    } else{
        DEP_PRINT(log_f, "taint_xadd_regs: reg %d does not have mark\n", src);
        taint_reg2reg(src, dst);
#ifdef CTRL_FLOW
        if (CTRFLOW_TAINT_STACK->prev != 0)
            add_modified_reg(ptdata, dst);
#endif
    }
}

void taint_xadd_mem_reg(ADDRINT mem_loc, UINT addrsize, REG src)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

    struct taint* v_tmp = get_reg_taint(src);
    if(v_tmp) {
        struct taint v_reg;
        new_taint(&v_reg);
        set_taint(&v_reg, v_tmp);
        DEP_PRINT(log_f, "taint_xadd_mem_reg: src reg %d has mark:\n", src);
        PRINT_DEP_VECTOR(&v_reg);
        taint_mem2reg(mem_loc, addrsize, src);
        for(int i = 0; i < (int)addrsize; i++) {
            mem_mod_dependency(ptdata, mem_loc + i, &v_reg, MERGE, 1);    
        }
    } else{
        DEP_PRINT(log_f, "taint_xadd_regs: reg %d does not have mark\n", src);
        taint_mem2reg(mem_loc, addrsize, src);
#ifdef CTRL_FLOW
        if (CTRFLOW_TAINT_STACK->prev != 0)
            for(int i = 0; i < (int)addrsize; i++) {
                add_modified_mem(ptdata, mem_loc + i);
            }
#endif
    }
}

void xchg_reg2reg (REG reg1, REG reg2) 
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;
    struct taint* v_tmp = get_reg_taint(reg1);
    if(v_tmp) {
        struct taint v_reg;
        new_taint(&v_reg);
        set_taint(&v_reg, v_tmp);
        DEP_PRINT(log_f, "xchg_reg2reg: reg %d has mark:\n", reg1);
        PRINT_DEP_VECTOR(&v_reg);
        taint_reg2reg(reg1, reg2);
        reg_mod_dependency(ptdata, reg2, &v_reg, SET, 1);    
    } else{
        DEP_PRINT(log_f, "xchg_reg2reg: reg %d does not have mark\n", reg1);
        taint_reg2reg(reg1, reg2);
        reg_clear_dependency(ptdata, reg2);    
    }

}

void xchg_reg2mem (REG reg, ADDRINT mem_loc, UINT32 addrsize) 
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

    struct taint* v_tmp = get_reg_taint(reg);
    if(v_tmp) {
        struct taint v_reg;
        new_taint (&v_reg);
        set_taint(&v_reg,v_tmp);
        PRINT_DEP_VECTOR(&v_reg);
        taint_mem2reg(mem_loc, addrsize, reg);
        for(int i = 0; i < (int)addrsize; i++) {
            mem_mod_dependency(ptdata, mem_loc + i, &v_reg, SET, 1);    
        }
    } else{
        DEP_PRINT(log_f, "xchg_reg2mem: reg %d does not have mark\n", reg);
        taint_mem2reg(mem_loc, addrsize, reg);
        for(int i = 0; i < (int)addrsize; i++) {
            mem_clear_dependency(ptdata, mem_loc + i);   
        }
    }

}
 

void muldiv_mem_taint_dest_regs(ADDRINT mem_loc, UINT32 addrsize, REG reg1, UINT32 reg1stat, REG reg2, UINT32 reg2stat, REG reg3, UINT32 reg3stat)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;
    int r1, r2, r3;
    struct taint dst_v;
    struct taint* src_v;
    int written;
    
    new_taint(&dst_v);

    if (REG_valid(reg1)) {
        r1 = (reg1stat & REG_READ);
        if(r1 == REG_READ) {
            src_v = get_reg_taint(reg1);
            if (src_v) {
                merge_taints(&dst_v, src_v);
            }
        }
    }
    if (REG_valid(reg2)) {
        r2 = (reg2stat & REG_READ);
        if(r2 == REG_READ) {
            src_v = get_reg_taint(reg2);
            if (src_v) {
                merge_taints(&dst_v, src_v);
            }
        }
    }
    
    if (REG_valid(reg3)) {
        r3 = (reg3stat & REG_READ);
        if(r3 == REG_READ) {
            src_v = get_reg_taint(reg3);
            if (src_v) {
                merge_taints(&dst_v, src_v);
            }
        }
    }
    
    for(int i = 0; i < (int)addrsize; i++) {
        src_v = get_mem_taint(mem_loc + i);
        if(src_v) {
            merge_taints(&dst_v, src_v);
        }
    }
    DEP_PRINT(log_f, "muldiv_mem_taint: reg2 is %d and reg3 is %d\n", reg2, reg3);

    if (REG_valid(reg1)) {
        written = (reg1stat & REG_WRITE);
        if (written == REG_WRITE) 
            reg_mod_dependency(ptdata, reg1, &dst_v, SET, 1);
    }
    if (REG_valid(reg2)) {
        written = (reg2stat & REG_WRITE);
        if (written == REG_WRITE) 
            reg_mod_dependency(ptdata, reg2, &dst_v, SET, 1);
    }
    if (REG_valid(reg3)) {
	written = (reg3stat & REG_WRITE);
	if (written == REG_WRITE) 
	    reg_mod_dependency(ptdata, reg3, &dst_v, SET, 1);
    }
}

void muldiv_taint_dest_regs(REG reg1, UINT32 reg1stat, 
			REG reg2, UINT32 reg2stat, REG reg3, UINT32 reg3stat)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;
    int r1, r2, r3;
    struct taint dst_v;
    struct taint* src_v;
    int written;

    new_taint(&dst_v);
    r1 = (reg1stat & REG_READ);
    if(r1 == REG_READ) {
        src_v = get_reg_taint(reg1);
        if(src_v) {
            merge_taints(&dst_v, src_v);
        }
    }

    r2 = (reg2stat & REG_READ);
    if(r2 == REG_READ) {
        src_v = get_reg_taint(reg2);
        if(src_v) {
            merge_taints(&dst_v, src_v);
        }
    }

    if (REG_valid(reg3)) {
        r3 = (reg3stat & REG_READ);
        if(r3 == REG_READ) {
            src_v = get_reg_taint(reg3);
            if(src_v) {
                merge_taints(&dst_v, src_v);
            }
        }
    }
    DEP_PRINT(log_f, "muldiv_reg_taint: reg1 is %d, reg2 is %d and reg3 is %d\n", reg1, reg2, reg3);

    written = (reg1stat & REG_WRITE);
    if (written == REG_WRITE) 
        reg_mod_dependency(ptdata, reg1, &dst_v, SET, 1);

    written = (reg2stat & REG_WRITE);
    if (written == REG_WRITE) 
        reg_mod_dependency(ptdata, reg2, &dst_v, SET, 1);

    if(REG_valid(reg3)) {
        written = (reg3stat & REG_WRITE);
        if (written == REG_WRITE) 
            reg_mod_dependency(ptdata, reg3, &dst_v, SET, 1);
    }
}

void instrument_xchg(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1mem, op2mem, op1reg, op2reg;
    USIZE addrsize;

    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);

    if(op1reg && op2reg) {
        REG reg1, reg2;
        INSTRUMENT_PRINT(log_f, "op1 and op2 of xchg are registers\n");
        reg1 = INS_OperandReg(ins, 0);
        reg2 = INS_OperandReg(ins, 1);
        if(!REG_valid(reg1) || !REG_valid(reg2)) {
            return;
        }

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(xchg_reg2reg), IARG_UINT32, reg1, IARG_UINT32, reg2, IARG_END);
    } else if(op1reg && op2mem) {
        REG reg;
        INSTRUMENT_PRINT(log_f, "op1 is reg && op2 is mem\n");
        addrsize = INS_MemoryReadSize(ins);
        reg = INS_OperandReg(ins, 0);
        if(!REG_valid(reg)) {
            //we ignore reads from video memory e.g. the gs segment register
            return;
        }
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(xchg_reg2mem),
                IARG_UINT32, reg, IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_END);
    } else if(op1mem && op2reg) {
        REG reg;
        INSTRUMENT_PRINT(log_f, "op1 is mem && op2 is reg\n");
        addrsize = INS_MemoryReadSize(ins);
        reg = INS_OperandReg(ins, 1);
        if(!REG_valid(reg)) {
            //we ignore reads from video memory e.g. the gs segment register
            return;
        }
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(xchg_reg2mem),
                IARG_UINT32, reg, IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_END);
    } else {
        string instruction;
        instruction = INS_Disassemble(ins);
        printf("unknown combination of XCHG ins: %s\n", instruction.c_str());
    }
}

void adc_reg_flag2mem (ADDRINT mem_loc, UINT32 addrsize, REG reg) 
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
    int effect = !is_taint_zero(&flag_table[CF_FLAG]);
    vector = get_reg_taint(reg);
    //merge with cf_dep
    if(vector) {
        if(effect) {
            merge_taints(vector,&flag_table[CF_FLAG]);
        }
        DEP_PRINT(log_f, "adc_reg_flag2mem: reg %d & cf has join mark, vector is ", reg);
        PRINT_DEP_VECTOR(vector);
        for(int i = 0; i < (int)addrsize; i++) {
            mem_mod_dependency(ptdata, mem_loc + i, vector, MERGE, 1);    
        }
    } else if (effect) {
        DEP_PRINT(log_f, "adc_reg_flag2mem: only cf has mark, vector is ");
        PRINT_DEP_VECTOR(&flag_table[CF_FLAG]);
        for(int i = 0; i < (int)addrsize; i++) {
            mem_mod_dependency(ptdata, mem_loc + i, &flag_table[CF_FLAG], MERGE, 1);    
        }
    } else {
#ifdef CTRL_FLOW
        if (CTRFLOW_TAINT_STACK->prev != 0)
            for(int i = 0; i < (int)addrsize; i++) {
                add_modified_mem(ptdata, mem_loc + i);
            }
#endif
    }

    vector = get_mem_taint(mem_loc);

#ifdef PPRINT
#ifdef TARGET_PPRINT
        if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
		if (has_nonzero_token(vector, INTERESTED_TOKEN)) {
			fprintf(stderr, "adc_reg_flag2mem: mem_loc %#x has mark, vector is ", mem_loc);
			__print_dependency_tokens(stderr, vector);
		}
	}
#endif
#endif

    flags_mod_dependency(ptdata, vector, SET, 1);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void adc_mem_flag2reg (ADDRINT mem_loc, UINT32 addrsize, REG reg) 
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
#ifdef CTRL_FLOW
    int flag = 0;
#endif
    int effect = !is_taint_zero(&flag_table[CF_FLAG]);
    
    if (effect) 
        reg_mod_dependency(ptdata, reg, &flag_table[CF_FLAG], MERGE, 1);
    for(int i = 0; i < (int)addrsize; i++) {
        vector = get_mem_taint(mem_loc + i);
        if(vector) {
            reg_mod_dependency(ptdata, reg, vector, MERGE, 1);
#ifdef CTRL_FLOW
            flag = 1;
#endif
        }
    }
#ifdef CTRL_FLOW
    if (!effect && !flag && CTRFLOW_TAINT_STACK->prev != 0) 
        add_modified_reg(ptdata, reg);    
#endif
    vector = get_reg_taint(reg);

    flags_mod_dependency(ptdata, vector, SET, 1);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void adc_reg_flag2reg(REG dst_reg, REG src_reg)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
    int effect = !is_taint_zero(&flag_table[CF_FLAG]);
    if (effect)
        reg_mod_dependency(ptdata, dst_reg, &flag_table[CF_FLAG], MERGE, 1);
    vector = get_reg_taint(src_reg);
    if(vector) {
        reg_mod_dependency(ptdata, dst_reg, vector, MERGE, 1);    
    }
#ifdef CTRL_FLOW
    if (!effect && !vector && CTRFLOW_TAINT_STACK->prev != 0)
        add_modified_reg(ptdata, dst_reg);
#endif
    vector = get_reg_taint(dst_reg);
    flags_mod_dependency(ptdata, vector, SET, 1);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void adc_flag2reg(REG dst_reg)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
    int effect = !is_taint_zero(&flag_table[CF_FLAG]);
    
    if(effect) 
        reg_mod_dependency(ptdata, dst_reg, &flag_table[CF_FLAG], MERGE, 1);
    vector = get_reg_taint(dst_reg);
    //alread has the ctrflow
    flags_mod_dependency(ptdata, vector, SET, 0);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void adc_flag2mem (ADDRINT mem_loc, UINT32 addrsize) 
{
    int i;
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
    int effect = !is_taint_zero(&flag_table[CF_FLAG]);
    
    if(effect) {
        for(i = 0; i < (int)addrsize; i++) {
            mem_mod_dependency(ptdata, mem_loc + i, &flag_table[CF_FLAG], MERGE, 1);
        }
    }
    vector = get_mem_taint(mem_loc);

#ifdef PPRINT
#ifdef TARGET_PPRINT
    if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
        if (has_nonzero_token(vector, INTERESTED_TOKEN)) {
            fprintf(stderr, "adc_flag2mem: mem_loc %#x has mark, vector is ", mem_loc);
            __print_dependency_tokens(stderr, vector);
        }
	}
#endif
#endif

    flags_mod_dependency(ptdata, vector, SET, 1);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void instrument_adc(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1mem, op2mem, op1reg, op2reg, op2imm;
    string instruction;
    USIZE addrsize;
    REG reg;

    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op2imm = INS_OperandIsImmediate(ins, 1);

    if((op1mem && op2reg)) {
        reg = INS_OperandReg(ins, 1);
        if(!REG_valid(reg)) {
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_adc: op1 is mem and op2 is register\n");
        addrsize = INS_MemoryWriteSize(ins);

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(adc_reg_flag2mem),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
    } else if(op1reg && op2mem) {
        reg = INS_OperandReg(ins, 0);
        if(!INS_IsMemoryRead(ins) || !REG_valid(reg)) {
            //we ignore reads from video memory e.g. the gs segment register
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_adc: op1 is register and op2 is mem\n");
        addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(adc_mem_flag2reg), 
                IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
    } else if(op1reg && op2reg) {
        REG dstreg;
        INSTRUMENT_PRINT(log_f, "instrument_adc: op1 and op2 of Artith are registers\n");
        dstreg = INS_OperandReg(ins, 0);
        reg = INS_OperandReg(ins, 1);
        if(!REG_valid(dstreg) || !REG_valid(reg)) {
            return;
        } 
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(adc_reg_flag2reg),
                IARG_UINT32, dstreg, IARG_UINT32, reg, IARG_END);
    } else if(op1mem && op2imm) {
        /*imm does not change taint value of the destination*/
        INSTRUMENT_PRINT(log_f, "instrument_adc: op1 is mem and op2 is immediate\n");
        addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(adc_flag2mem),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
        return;
    } else if(op1reg && op2imm){
        INSTRUMENT_PRINT(log_f, "instrument_adc: op1 is reg and op2 is immediate\n");
        REG dstreg = INS_OperandReg(ins, 0);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(adc_flag2reg),
                IARG_UINT32, dstreg, IARG_END);
        return;
    } else{
        //if the arithmatic involves an immediate instruction the taint does
        //not propagate...
        string instruction;
        instruction = INS_Disassemble(ins);
        printf("unknown combination of ADC ins: %s\n", instruction.c_str());
    }
}

void cmp_reg_mem(ADDRINT mem_location, int size, REG reg)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

    GRAB_GLOBAL_LOCK (ptdata);

    int i = 0;
    struct taint* vector;
    
    flags_clear_dependency(ptdata);
    vector = get_reg_taint(reg);
    if(vector) {
        DEP_PRINT(log_f, "taint_reg_mem2flag: reg %d has mark, vector is ", reg);
        PRINT_DEP_VECTOR(vector);

#ifdef PPRINT
#ifdef TARGET_PPRINT
        if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
		if (has_nonzero_token(vector, INTERESTED_TOKEN)) {
			fprintf(stderr, "cmp_reg_mem: reg %d has mark, vector is ", reg);
			__print_dependency_tokens(stderr, vector);
		}
	}
#endif
#endif

        flags_mod_dependency(ptdata, vector, MERGE, 0);    
    } 
    
    for(i = 0; i < (int)size; i++) {
        vector = get_mem_taint(mem_location + i);
        if(vector) {
            DEP_PRINT(log_f, "taint_reg_mem2flag: memory location %#x has mark, vector is ", mem_location + i);
            PRINT_DEP_VECTOR(vector);
#ifdef PPRINT
#ifdef TARGET_PPRINT
            if (pprint && ptdata->record_pid == pid_pprint && total_inst_count >= start_pprint && total_inst_count < end_pprint) {
                if (has_nonzero_token(vector, INTERESTED_TOKEN)) {
                    fprintf(stderr, "cmp_reg_mem: mem_loc %#x has mark, vector is ", mem_location + i);
                    __print_dependency_tokens(stderr, vector);
                }
            }
#endif
#endif

            flags_mod_dependency(ptdata, vector, MERGE, 0);
        }
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

void cmp_reg_reg(REG dstreg, REG reg)
{   
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
    flags_clear_dependency(ptdata);
    vector = get_reg_taint(dstreg);
    if(vector) {
        DEP_PRINT(log_f, "taint_reg_reg2flag: reg %d has mark, vector is ", dstreg);
        PRINT_DEP_VECTOR(vector);
        flags_mod_dependency(ptdata, vector, MERGE, 0);    
    } 

    vector = get_reg_taint(reg);
    if(vector) {
        DEP_PRINT(log_f, "taint_reg_reg2flag: reg %d has mark, vector is ", reg);
        PRINT_DEP_VECTOR(vector);
        flags_mod_dependency(ptdata, vector, MERGE, 0);   

    } 
    RELEASE_GLOBAL_LOCK (ptdata);
}

void instrument_test(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1mem, op1reg, op2reg, op2imm;
    string instruction;
    USIZE addrsize;
    REG reg;

    op1mem = INS_OperandIsMemory(ins, 0);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op2imm = INS_OperandIsImmediate(ins, 1);
    if((op1mem && op2reg)) {
        reg = INS_OperandReg(ins, 1);
        if(!REG_valid(reg)) {
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_test: op1 is mem and op2 is register\n");
        addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(cmp_reg_mem),
                IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
    } else if(op1reg && op2reg) {
        REG dstreg;
        dstreg = INS_OperandReg(ins, 0);
        reg = INS_OperandReg(ins, 1);
        INSTRUMENT_PRINT(log_f, "instrument_test: op1 and op2 of are registers %d(%s), %d(%s)\n", 
                dstreg, REG_StringShort(dstreg).c_str(), reg, REG_StringShort(reg).c_str());
        if(!REG_valid(dstreg) || !REG_valid(reg)) {
            return;
        } 
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(cmp_reg_reg), 
                IARG_UINT32, dstreg, IARG_UINT32, reg, IARG_END);
    } else if(op1mem && op2imm) {
        /*imm does not change taint value of the destination*/
        INSTRUMENT_PRINT(log_f, "instrument_test: op1 is mem and op2 is immediate\n");
        addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2flag),
                IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_END);
        return;
    }else if(op1reg && op2imm){
        INSTRUMENT_PRINT(log_f, "instrument_test op1 is reg and op2 is immediate\n");
        reg = INS_OperandReg(ins, 0);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2flag), IARG_UINT32, reg, IARG_END);
        return;
    }else{
        //if the arithmatic involves an immediate instruction the taint does
        //not propagate...
        string instruction;
        instruction = INS_Disassemble(ins);
        printf("unknown combination of CMP ins: %s\n", instruction.c_str());
    }
}

void instrument_pcmpeqx(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    REG reg;
    int op2reg, op2mem;
    op2reg = INS_OperandIsReg(ins, 1);
    op2mem = INS_OperandIsMemory(ins, 1);
    reg = INS_OperandReg(ins, 0);
    if (op2reg) {
        REG reg2 = INS_OperandReg(ins ,1);

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2reg),
                IARG_UINT32, reg, IARG_UINT32, reg2, IARG_END);

    } else if (op2mem) {
        USIZE addrsize = INS_MemoryReadSize(ins);
        assert (addrsize == 16);
        assert (INS_IsMemoryRead(ins));
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_mem2reg),
                IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
    } else {
        fprintf(stderr, "[ERROR] unknown comibnation of PCMPEQB\n");
    }
}

void instrument_palign(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    // op3imm - shouldn't effect taint
    int op1reg, op2reg, op2mem; 

    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op2mem = INS_OperandIsMemory(ins, 1);

    if(op1reg && op2reg) {
        REG srcreg, dstreg;
        srcreg = INS_OperandReg(ins, 1);
        dstreg = INS_OperandReg(ins, 0);

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2reg), IARG_UINT32, dstreg, IARG_UINT32, srcreg, IARG_END);
    }
    else if(op1reg && op2mem) {
        REG dstreg = INS_OperandReg(ins, 0);
        USIZE addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_mem2reg), IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, dstreg, IARG_END);
    }
    else {
        fprintf(log_f, "instrument_palign: operand arguments don't match.\n");
    }
}

void instrument_psllx(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1reg, op2reg, op2mem, op2imm;

    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op2mem = INS_OperandIsMemory(ins, 1);
    op2imm = INS_OperandIsImmediate(ins, 1);
    
    if (op1reg && op2reg) {
        REG srcreg, dstreg;
        srcreg = INS_OperandReg(ins, 1);
        dstreg = INS_OperandReg(ins, 0);

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2reg), IARG_UINT32, dstreg, IARG_UINT32, srcreg, IARG_END);

    }
    else if (op1reg && op2mem) {
        REG dstreg = INS_OperandReg(ins, 0);
        USIZE addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_mem2reg), IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, dstreg, IARG_END);
    }

    // TODO: AJYL
    else if (op1reg && op2imm) {
        REG dstreg = INS_OperandReg(ins, 0);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2reg), IARG_UINT32, dstreg, IARG_UINT32, dstreg, IARG_END);
    }

    else {
        fprintf(log_f, "instrument_psllx: operant arguments don't match.\n");
    }
}


void instrument_cmp(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1mem, op2mem, op1reg, op2reg, op2imm;
    string instruction;
    USIZE addrsize;
    REG reg;

    INSTRUMENT_PRINT(log_f, "instrument_cmp: instruction is %s\n", INS_Mnemonic(ins).c_str());

    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op2imm = INS_OperandIsImmediate(ins, 1);

    if((op1mem && op2reg)) {
        reg = INS_OperandReg(ins, 1);
        if(!REG_valid(reg)) {
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_cmp: op1 is mem and op2 is register\n");
        addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(cmp_reg_mem),
                IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);

    } else if(op1reg && op2mem) {
        reg = INS_OperandReg(ins, 0);
        if(!INS_IsMemoryRead(ins) || !REG_valid(reg)) {
            //we ignore reads from video memory e.g. the gs segment register
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_cmp: op1 is register and op2 is mem\n");
        addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(cmp_reg_mem), 
                IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);

    } else if(op1reg && op2reg) {
        REG dstreg;
        dstreg = INS_OperandReg(ins, 0);
        reg = INS_OperandReg(ins, 1);
        INSTRUMENT_PRINT(log_f, "instrument_cmp: op1 and op2 of are registers %d(%s), %d(%s)\n", 
                dstreg, REG_StringShort(dstreg).c_str(), reg, REG_StringShort(reg).c_str());
        if(!REG_valid(dstreg) || !REG_valid(reg)) {
            return;
        } 
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(cmp_reg_reg), 
                IARG_UINT32, dstreg, IARG_UINT32, reg, IARG_END);
    } else if(op1mem && op2imm) {
        /*imm does not change taint value of the destination*/
        INSTRUMENT_PRINT(log_f, "instrument_cmp: op1 is mem and op2 is immediate\n");
        addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2flag),
                IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_END);
        return;
    }else if(op1reg && op2imm){
        INSTRUMENT_PRINT(log_f, "instrument_cmp op1 is reg and op2 is immediate\n");
        reg = INS_OperandReg(ins, 0);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2flag), IARG_UINT32, reg, IARG_END);
        return;
    }else{
        //if the arithmatic involves an immediate instruction the taint does
        //not propagate...
        string instruction;
        instruction = INS_Disassemble(ins);
        printf("unknown combination of CMP ins: %s\n", instruction.c_str());
    }
}

void reg_cmpxchg(REG dst_reg, REG reg, int eflag_value)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* vector;
    REG a_reg = LEVEL_BASE::REG_EAX;
    if (REG_is_gr8)
        a_reg = REG_AL;
    else if (REG_is_gr16(dst_reg))
        a_reg = REG_AX;
    else if (REG_is_gr32(dst_reg))
        a_reg = LEVEL_BASE::REG_EAX;
    else 
        printf("ERROR: in reg_cmpxchg, reg size is not gr8/16/32\n");

    flags_clear_dependency(ptdata);
    if (eflag_value & ZF_MASK) {
        //ZF is set, therefore AL/AX/EAX was equal to memory operand
#ifdef CTRL_FLOW
        if (CTRFLOW_TAINT_STACK->prev != 0)
            add_modified_reg(ptdata, dst_reg);
#endif
        vector = get_reg_taint(dst_reg);
#ifdef CTRL_FLOW
        if (vector) {
            flags_mod_dependency(ptdata, vector, MERGE, 0);
            //the value of al is dependent on al == dst_reg condition
            //reg_mod_dependency(a_reg, MERGE);
        }
#endif
        vector = get_reg_taint(reg);
        if(vector) {
            reg_mod_dependency(ptdata, dst_reg, vector, MERGE, 0);    
        } 
        vector = get_reg_taint(a_reg);
        if (vector) {
            reg_mod_dependency(ptdata, dst_reg, vector, MERGE, 0);   
#ifdef CTRL_FLOW
            flags_mod_dependency(ptdata, vector, MERGE, 0);
#endif
        }
        //already has the ctrflow
    } else {      
        /*if(speculation) {
          add_reg_taint_log_entry(a_reg);
          }*/
#ifdef CTRL_FLOW
        if (CTRFLOW_TAINT_STACK->prev != 0)
            add_modified_reg(ptdata, a_reg);
#endif
        vector = get_reg_taint(dst_reg);
        if (vector) {
            reg_mod_dependency(ptdata, a_reg, vector, MERGE, 0);   
        }
        vector = get_reg_taint(a_reg);
        if (vector) {
#ifdef CTRL_FLOW
            flags_mod_dependency(ptdata, vector, MERGE, 0);
#endif
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void mem_cmpxchg(ADDRINT mem_location, int addrsize, REG reg, int eflag_value)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && CALLING_BBLOCK_HEAD->status == HANDLED) return;

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint *vector, *vector_reg, *vector_a_reg;
    REG a_reg = LEVEL_BASE::REG_EAX;
    switch(addrsize) {
        case 1: a_reg = REG_AL;
                break;
        case 2: a_reg = REG_AX;
                break;
        case 4: a_reg = LEVEL_BASE::REG_EAX;
                break;
        default: printf("ERROR: in mem_cmpxchg, mem size is %d\n", addrsize);
    }
#ifdef CTRL_FLOW
    flags_clear_dependency(ptdata);
#endif
    if (eflag_value & ZF_MASK) {
        //ZF is set, therefore AL/AX/EAX was equal to memory operand
        vector_reg = get_reg_taint(reg);
        vector_a_reg = get_reg_taint(a_reg);
#ifdef CTRL_FLOW
        if (vector_a_reg) {    
            flags_mod_dependency(ptdata, vector_a_reg, MERGE, 0);
        }
#endif
        for (int i = 0; i < addrsize; i++) {
            vector = get_mem_taint(mem_location + i);
#ifdef CTRL_FLOW
            if (CTRFLOW_TAINT_STACK->prev != 0)
                add_modified_mem(ptdata, mem_location + i);
#endif
#ifdef CTRL_FLOW
            if (vector) {
                flags_mod_dependency(ptdata, vector, MERGE, 0);
            }
#endif
            if(vector_reg) {
                mem_mod_dependency(ptdata, mem_location + i, vector_reg, MERGE, 0);    
            } 
            if (vector_a_reg) {
                mem_mod_dependency(ptdata, mem_location + i, vector_a_reg, MERGE, 0);   
            }
        }
    } else {
#ifdef CTRL_FLOW
        if (CTRFLOW_TAINT_STACK->prev != 0)
            add_modified_reg(ptdata, a_reg);
#endif
        for (int i = 0; i < addrsize; i++) {
            vector = get_mem_taint(mem_location + i);
            if (vector) {
                reg_mod_dependency(ptdata, a_reg, vector, MERGE, 0);   
            }
        }
        vector = get_reg_taint(a_reg);
#ifdef CTRL_FLOW
        if (vector) {
            flags_mod_dependency(ptdata, vector, MERGE, 0);
        }
#endif
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void instrument_cmpxchg(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1mem;
    REG reg;
    
    op1mem = INS_OperandIsMemory(ins, 0);
    reg = INS_OperandReg(ins, 1);
    if(op1mem) {
        USIZE addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mem_cmpxchg, IARG_MEMORYWRITE_EA, 
                IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_REG_VALUE, REG_EFLAGS, IARG_END);   
    } else {
        REG dst_reg = INS_OperandReg(ins, 0);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)reg_cmpxchg, IARG_UINT32, dst_reg, IARG_UINT32, reg, 
                IARG_REG_VALUE, REG_EFLAGS, IARG_END);   
    }
}

void instrument_incordec(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int opmem, opreg;
    string instruction;
    USIZE addrsize;
    REG reg;

    opmem = INS_OperandIsMemory(ins, 0);
    opreg = INS_OperandIsReg(ins, 0);
    
    if(opmem) {
        INSTRUMENT_PRINT(log_f, "instrument_incordec: op is memory\n");
        addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2mem),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, MERGE, IARG_END);
#ifdef CTRL_FLOW
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2flags_but_cf),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
#endif
    } else if(opreg) {
        reg = INS_OperandReg(ins, 0);
        if(!REG_valid(reg)) {
            //we ignore reads from video memory e.g. the gs segment register
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_incordec: op is register %d\n", reg);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2reg), 
                IARG_UINT32, reg, IARG_UINT32, MERGE, IARG_END);
#ifdef CTRL_FLOW
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2flags_but_cf), IARG_UINT32, reg, IARG_END);
#endif
    } else{
        //if the arithmatic involves an immediate instruction the taint does
        //not propagate...
        string instruction;
        instruction = INS_Disassemble(ins);
        printf("unknown combination of inc/dec ins: %s\n", instruction.c_str());
    }
}

void instrument_shift(INS ins) 
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1reg, op1mem, count, op2reg, op2imm, op2imp;
    REG reg, reg2;
    UINT32 addrsize;

    count = INS_OperandCount(ins);
    INSTRUMENT_PRINT(log_f, "instrument_shft: instruction is %s and count is %d\n", INS_Mnemonic(ins).c_str(), count);

    op1reg = INS_OperandIsReg(ins, 0);
    op1mem = INS_OperandIsMemory(ins, 0);
    if(count == 2) {
#ifdef CTRL_FLOW  // Only flags are affected
        if(op1reg) {
            reg = INS_OperandReg(ins, 0);
            if(!REG_valid(reg)) return;
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2flag), IARG_UINT32, reg, IARG_END);
        } else if(op1mem) {
            addrsize = INS_MemoryWriteSize(ins);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2flag), IARG_MEMORYWRITE_EA, 
                    IARG_UINT32, addrsize, IARG_END);
        } else {
            string instruction;
            instruction = INS_Disassemble(ins);
            printf("unknown combination of shift ins (count=1): %s\n", instruction.c_str());
        }
#endif
    } else if (count == 3) {
        op2reg = INS_OperandIsReg(ins, 1);
        op2imm = INS_OperandIsImmediate(ins, 1);
        op2imp = INS_OperandIsImplicit(ins, 1);
        if(op1reg && op2reg) {
            INSTRUMENT_PRINT(log_f, "instrument_shift: op1 is reg and op2 is reg\n");
            reg = INS_OperandReg(ins, 0);
            reg2 = INS_OperandReg(ins ,1);
            if(!REG_valid(reg) || !REG_valid(reg2)) return;
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2reg),
                    IARG_UINT32, reg, IARG_UINT32, reg2, IARG_END);
#ifdef CTRL_FLOW
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2flag), IARG_UINT32, reg, IARG_END);
#endif

        } else if(op1mem && op2reg) {
            INSTRUMENT_PRINT(log_f, "instrument_shift: op1 is memory and op2 is reg\n");
            reg2 = INS_OperandReg(ins ,1);
            addrsize = INS_MemoryWriteSize(ins);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2mem),
                    IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg2, IARG_END);
#ifdef CTRL_FLOW
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2flag),
                    IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
#endif
        } else if(op1reg && (op2imm || op2imp)) {
            INSTRUMENT_PRINT(log_f, "instrument_shift: op1 is reg and op2 is immediate\n");
            reg = INS_OperandReg(ins, 0);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2reg), IARG_UINT32, reg, IARG_UINT32, MERGE, IARG_END);
#ifdef CTRL_FLOW
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2flag), IARG_UINT32, reg, IARG_END);
#endif
        } else if(op1mem && (op2imm || op2imp)){
            INSTRUMENT_PRINT(log_f, "instrument_shift: op1 is mem and op2 is immediate\n");
            addrsize = INS_MemoryWriteSize(ins);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2mem),
                    IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, MERGE, IARG_END);
#ifdef CTRL_FLOW
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2flag),
                    IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
#endif
        } else {
            string instruction;
            instruction = INS_Disassemble(ins);
            printf("unknown combination of shift ins(count=2): %s\n", instruction.c_str());
            fprintf(log_f, "unknown combination of shift ins(count=2): %s\n", instruction.c_str());
        }

    } else if (count == 4) {
        //SHRD and SHDL cases
        if (!INS_OperandIsReg(ins, 1)) {
            string instruction;
            instruction = INS_Disassemble(ins);
            printf("unknown combination of shift ins(count=4): %s\n", instruction.c_str());
            fprintf(log_f, "unknown combination of shift ins(count=4): %s\n", instruction.c_str());
            return;
        }
        reg2 = INS_OperandReg(ins ,1);
        if (op1reg) {
            reg = INS_OperandReg(ins, 0);
            if(!REG_valid(reg) || !REG_valid(reg2)) return;
            INSTRUMENT_PRINT(log_f, "instrument_shift: op1 is reg %s and op2 is reg %s\n", REG_StringShort(reg).c_str(), REG_StringShort(reg2).c_str());
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2reg),
                    IARG_UINT32, reg, IARG_UINT32, reg2, IARG_END);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2flag), IARG_UINT32, reg, IARG_END);
        } else if (op1mem) {
            addrsize = INS_MemoryWriteSize(ins);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2mem),
                    IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg2, IARG_END);
#ifdef CTRL_FLOW
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2flag),
                    IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
#endif
        }
    } else {
        string instruction;
        instruction = INS_Disassemble(ins);
        printf("unknown combination of shift ins: %s, count is %d\n", instruction.c_str(), count);
    }
}

void instrument_addorsub(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1mem, op2mem, op1reg, op2reg, op2imm;
    string instruction;
    OPCODE opcode;
    USIZE addrsize;
    REG reg;

    opcode = INS_Opcode(ins);
    INSTRUMENT_PRINT(log_f, "instrument_addorsub: arith ins is %s (%#x)\n", INS_Mnemonic(ins).c_str(), *((char*)INS_Address(ins)));
    
    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op2imm = INS_OperandIsImmediate(ins, 1);
    
    if((op1mem && op2reg)) {
        reg = INS_OperandReg(ins, 1);
        if(!REG_valid(reg)) {
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is mem and op2 is register\n");
        addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2mem),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
#ifdef CTRL_FLOW
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2flag),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
#endif
    } else if(op1reg && op2mem) {
        reg = INS_OperandReg(ins, 0);
        if(!INS_IsMemoryRead(ins) || !REG_valid(reg)) {
            //we ignore reads from video memory e.g. the gs segment register
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is register and op2 is mem\n");
        //printf("instrument_addorsub: op1 is register and op2 is mem\n");
        addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_mem2reg), 
                IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
#ifdef CTRL_FLOW
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2flag), IARG_UINT32, reg, IARG_END);
#endif
    } else if(op1reg && op2reg) {
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
	if((opcode == XED_ICLASS_SUB || opcode == XED_ICLASS_XOR) 
                && (dstreg == reg)) {
	    INSTRUMENT_PRINT(log_f, "handling reg reset\n");
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2reg), IARG_UINT32, dstreg, IARG_UINT32, SET, IARG_END);
#ifdef CTRL_FLOW
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2flag), IARG_END);
#endif

	} else {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2reg),
                             IARG_UINT32, dstreg, IARG_UINT32, reg, IARG_END);
#ifdef CTRL_FLOW
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2flag), IARG_UINT32, dstreg, IARG_END);
#endif
        }
    } else if(op1mem && op2imm) {
        /*imm does not change taint value of the destination*/
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is mem and op2 is immediate\n");
        addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2mem),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, MERGE, IARG_END);
#ifdef CTRL_FLOW
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2flag),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
#endif
    } else if(op1reg && op2imm){
        reg = INS_OperandReg(ins, 0);
        INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is reg (%d) and op2 is immediate\n", reg);
        if (!SPECIAL_REG(reg)) {
            INSTRUMENT_PRINT(log_f, "instrument_addorsub: op1 is reg and op2 is immediate\n");
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2reg), IARG_UINT32, reg, IARG_UINT32, MERGE, IARG_END);
#ifdef CTRL_FLOW
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2flag), IARG_UINT32, reg, IARG_END);
#endif
        }
    } else{
        //if the arithmatic involves an immediate instruction the taint does
        //not propagate...
        string instruction;
        instruction = INS_Disassemble(ins);
        printf("unknown combination of arithmatic ins: %s\n", instruction.c_str());
    }
}

void instrument_addorsub_noflags(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1mem, op2mem, op1reg, op2reg, op2imm;
    string instruction;
    USIZE addrsize;
    REG reg;

    INSTRUMENT_PRINT(log_f, "instrument_addorsub_noflags: arith ins is %s (%#x)\n", INS_Mnemonic(ins).c_str(), *((char*)INS_Address(ins)));
    
    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op2imm = INS_OperandIsImmediate(ins, 1);
    
    if((op1mem && op2reg)) {
        reg = INS_OperandReg(ins, 1);
        if(!REG_valid(reg)) {
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_addorsub_noflags: op1 is mem and op2 is register\n");
        addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2mem),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);

    } else if(op1reg && op2mem) {
        reg = INS_OperandReg(ins, 0);
        if(!INS_IsMemoryRead(ins) || !REG_valid(reg)) {
            //we ignore reads from video memory e.g. the gs segment register
            return;
        }
        INSTRUMENT_PRINT(log_f, "instrument_addorsub_noflags: op1 is register and op2 is mem\n");
        //printf("instrument_addorsub: op1 is register and op2 is mem\n");
        addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_mem2reg), 
                IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);

    } else if(op1reg && op2reg) {
        REG dstreg;
        dstreg = INS_OperandReg(ins, 0);
        reg = INS_OperandReg(ins, 1);
        INSTRUMENT_PRINT(log_f, "instrument_addorsub_noflags: op1 and op2 of Arith are registers: %d (%s), %d (%s)\n", 
                dstreg, REG_StringShort(dstreg).c_str(), reg, REG_StringShort(reg).c_str());
        if(!REG_valid(dstreg) || !REG_valid(reg)) {
            return;
        } 
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2reg),
                IARG_UINT32, dstreg, IARG_UINT32, reg, IARG_END);
    } else if(op1mem && op2imm) {
        /*imm does not change taint value of the destination*/
        INSTRUMENT_PRINT(log_f, "instrument_addorsub_noflags: op1 is mem and op2 is immediate\n");
        addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2mem),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, MERGE, IARG_END);
    } else if(op1reg && op2imm){
        reg = INS_OperandReg(ins, 0);
        INSTRUMENT_PRINT(log_f, "instrument_addorsub_noflags: op1 is reg (%d) and op2 is immediate\n", reg);
        //printf("instrument_addorsub: op1 is reg and op2 is immediate\n");
        if (!SPECIAL_REG(reg))
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2reg), IARG_UINT32, reg, IARG_UINT32, MERGE, IARG_END);
    } else{
        //if the arithmatic involves an immediate instruction the taint does
        //not propagate...
        string instruction;
        instruction = INS_Disassemble(ins);
        printf("unknown combination of arithmatic ins: %s\n", instruction.c_str());
    }
}

void old_instrument_addorsub(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1mem, op2mem, op1reg, op2reg, op2imm;
    string instruction;
    USIZE addrsize;
    REG reg;

    INSTRUMENT_PRINT(log_f, "old_instrument_addorsub: arith instruction is %s\n", INS_Mnemonic(ins).c_str());

    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op2imm = INS_OperandIsImmediate(ins, 1);

    if((op1mem && op2reg)) {
        reg = INS_OperandReg(ins, 1);
        if(!REG_valid(reg)) {
            return;
        }
        INSTRUMENT_PRINT(log_f, "old_instrument_addorsub: op1 is mem and op2 is register\n");
        addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2mem),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
    }

    else if(op1reg && op2mem) {
        reg = INS_OperandReg(ins, 0);
        if(!INS_IsMemoryRead(ins) || !REG_valid(reg)) {
            //we ignore reads from video memory e.g. the gs segment register
            return;
        }
        INSTRUMENT_PRINT(log_f, "old_instrument_addorsub: op1 is register and op2 is mem\n");
        addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_mem2reg), 
                IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);

    } else if(op1reg && op2reg) {
        REG dstreg;
        INSTRUMENT_PRINT(log_f, "old_instrument_addorsub: op1 and op2 of Artith are registers\n");
        dstreg = INS_OperandReg(ins, 0);
        reg = INS_OperandReg(ins, 1);
        if(!REG_valid(dstreg) || !REG_valid(reg)) {
            return;
        } 
        /*if((opcode == XED_ICLASS_PXOR ||
          opcode == XED_ICLASS_FSUB || opcode == XED_ICLASS_FSUBP ||
          opcode == XED_ICLASS_FSUBP || opcode == XED_ICLASS_FISUB ||
          opcode == XED_ICLASS_FSUBR || opcode == XED_ICLASS_FISUBR ||
          opcode == XED_ICLASS_FSUBRP || opcode == XED_ICLASS_XORPS ||
          opcode == XED_ICLASS_PSUBB || opcode == XED_ICLASS_PSUBW ||
          opcode == XED_ICLASS_PSUBD || opcode == XED_ICLASS_PSUBQ) 
          && (dstreg == reg)) {
          INSTRUMENT_PRINT(log_f, "handling reg reset\n");
          INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2reg),
          IARG_UINT32, dstreg, IARG_END);
          } else {*/
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2reg),
                IARG_UINT32, dstreg, IARG_UINT32, reg, IARG_END);

   } else if(op1mem && op2imm) {
        INSTRUMENT_PRINT(log_f, "old_instrument_addorsub: op1 is mem and op2 is immediate\n");
        addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2mem),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, MERGE, IARG_END);
    }else if(op1reg && op2imm){
        reg = INS_OperandReg(ins, 0);
        INSTRUMENT_PRINT(log_f, "old_instrument_addorsub: op1 is reg (%d) and op2 is immediate\n", reg);
        //printf("instrument_addorsub: op1 is reg and op2 is immediate\n");
        if (!SPECIAL_REG(reg))
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2reg), IARG_UINT32, reg, IARG_UINT32, MERGE, IARG_END);
        return;
    } else{
        string instruction;
        instruction = INS_Disassemble(ins);
        fprintf(stderr, "[ERROR] unknown combination of old_addorsub ins: %s\n", instruction.c_str());
    }
}

/* Set the taint of the dst to the taint of the src. 
 *  2 operands
 * */
void instrument_set_src2dst(INS ins) 
{
    int op1reg, op2reg;
    int op1mem, op2mem;

    op1mem = INS_OperandIsMemory(ins, 0);
    op2mem = INS_OperandIsMemory(ins, 1);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);

    if (op1reg && op2reg) {
        REG dstreg = INS_OperandReg(ins, 0);
        REG reg = INS_OperandReg(ins, 1);
        if(!REG_valid(dstreg) || !REG_valid(reg)) {
            return;
        } 
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2reg),
                IARG_UINT32, dstreg, IARG_UINT32, reg, IARG_END);
    } else if (op1reg && op2mem) {
        REG dstreg = INS_OperandReg(ins, 0);
        if(!INS_IsMemoryRead(ins) || !REG_valid(dstreg)) {
            return;
        }
        USIZE addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2reg),
                IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, dstreg, IARG_END);
    } else if (op1mem && op2reg) {
        REG reg = INS_OperandReg(ins, 1);
        if(!REG_valid(reg)) {
            return;
        }
        USIZE addrsize = INS_MemoryWriteSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2mem),
                IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
    } else if (op1mem && op2mem) {
        USIZE addrsize = INS_MemoryReadSize(ins);
        assert (INS_IsMemoryWrite(ins));
        assert (INS_IsMemoryRead(ins));
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2mem), IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
    } else {
        string instruction;
        instruction = INS_Disassemble(ins);
        fprintf(stderr, "[ERROR] unknown combination of src2dst: %s\n", instruction.c_str());
    }
}

void instrument_paddx_or_psubx(INS ins)
{
    int op1reg, op2reg, op2mem;

    op1reg = INS_OperandIsReg(ins, 0); 	
    op2reg = INS_OperandIsReg(ins, 1); 	
    op2mem = INS_OperandIsMemory(ins, 1); 	

    if(op1reg && op2reg) {
        REG srcreg, dstreg;
        srcreg = INS_OperandReg(ins, 1); 
        dstreg = INS_OperandReg(ins, 0); 

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2reg), 
                       IARG_UINT32, dstreg, IARG_UINT32, srcreg, IARG_END);
    }
    else if(op1reg && op2mem) {
        REG dstreg = INS_OperandReg(ins, 0);
	USIZE addrsize = INS_MemoryReadSize(ins);	
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_mem2reg), IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, dstreg, IARG_END);
    }
    else {
        fprintf(log_f, "instrument_paddx: operand arguments don't match.\n");
    }
}

void instrument_punpckx(INS ins)
{
    int op1reg, op2reg, op2mem;
    fprintf(log_f, "instrument_punpckx (%s) starting.\n", INS_Mnemonic(ins).c_str());

    op1reg = INS_OperandIsReg(ins, 0); 	
    op2reg = INS_OperandIsReg(ins, 1); 	
    op2mem = INS_OperandIsMemory(ins, 1); 	

    if(op1reg && op2reg) {
        REG srcreg, dstreg;
        srcreg = INS_OperandReg(ins, 1);
        dstreg = INS_OperandReg(ins, 0);

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_reg2reg), IARG_UINT32, dstreg, IARG_UINT32, srcreg, IARG_END);
    }
    else if(op1reg && op2mem) {
        REG dstreg = INS_OperandReg(ins, 0);
        USIZE addrsize = INS_MemoryReadSize(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_add_mem2reg), IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_UINT32, dstreg, IARG_END);
    }
    else {
        fprintf(log_f, "instrument_punpckx: operant arguments don't match.\n");
    }
}


void instrument_imul(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1reg;
    string instruction;
    int memread;
    UINT32 reg1stat, reg2stat, reg3stat;
    REG reg1, reg2, reg3;
    USIZE addrsize;

    reg1 = REG_INVALID();
    reg2 = REG_INVALID();
    reg3 = REG_INVALID();
    reg1stat = 0;
    reg2stat = 0;
    reg3stat = 0;
    
    int count = INS_OperandCount(ins);
    memread = INS_IsMemoryRead(ins);
    if (count == 3) {
        op1reg = INS_OperandIsReg(ins, 0);
        if (!op1reg) {
            printf("ERROR in imul\n");
            return;
        }
        reg1 = INS_OperandReg(ins, 0);
        if(INS_RegRContain(ins, reg1)) {
            reg1stat |= REG_READ;
        }
        if(INS_RegWContain(ins, reg1)) {
            reg1stat |= REG_WRITE;
        }
        if (!memread) {
            reg2 = INS_OperandReg(ins, 1);
            if(INS_RegRContain(ins, reg2)) {
                reg2stat |= REG_READ;
            }
            if(INS_RegWContain(ins, reg2)) {
                reg2stat |= REG_WRITE;
            }
        }
        if (memread) {
            addrsize = INS_MemoryReadSize(ins);
            //reg2 and reg3 is being invalid, no effect
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(muldiv_mem_taint_dest_regs),
                             IARG_MEMORYREAD_EA, IARG_UINT32, addrsize,  
                             IARG_UINT32, reg1, IARG_UINT32, reg1stat, 
                             IARG_UINT32, reg2, IARG_UINT32, reg2stat,
                             IARG_UINT32, reg3, IARG_UINT32, reg3stat,IARG_END);
        } else {
            //reg3 is invalid, no effect
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(muldiv_taint_dest_regs),
                             IARG_UINT32, reg1, IARG_UINT32, reg1stat, 
                             IARG_UINT32, reg2, IARG_UINT32, reg2stat, 
                             IARG_UINT32, reg3, IARG_UINT32, reg3stat,
                             IARG_END);
        }
#ifdef CTRL_FLOW
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2cf_of), IARG_UINT32, reg1, IARG_END);
#endif
    } else if (count == 4) {       
        if (!memread) {
            reg1 = INS_OperandReg(ins, 0);
            if(INS_RegRContain(ins, reg1)) {
                reg1stat |= REG_READ;
            }
            if(INS_RegWContain(ins, reg1)) {
                reg1stat |= REG_WRITE;
            }
        }

        reg2 = INS_OperandReg(ins, 1);
        if(INS_RegRContain(ins, reg2)) {
            reg2stat |= REG_READ;
        }
        if(INS_RegWContain(ins, reg2)) {
            reg2stat |= REG_WRITE;
        }
        reg3 = INS_OperandReg(ins, 2);
        if(INS_RegRContain(ins, reg3)) {
            reg3stat |= REG_READ;
        }
        if(INS_RegWContain(ins, reg3)) {
            reg3stat |= REG_WRITE;
        }

        if(memread) {
            //reg1 is invalid
            addrsize = INS_MemoryReadSize(ins);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(muldiv_mem_taint_dest_regs),
                             IARG_MEMORYREAD_EA, IARG_UINT32, addrsize,  
                             IARG_UINT32, reg1, IARG_UINT32, reg1stat,
                             IARG_UINT32, reg2, IARG_UINT32, reg2stat, 
                             IARG_UINT32, reg3, IARG_UINT32, reg3stat, IARG_END); 
        } else {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(muldiv_taint_dest_regs),
                             IARG_UINT32, reg1, IARG_UINT32, reg1stat, 
                             IARG_UINT32, reg2, IARG_UINT32, reg2stat, 
                             IARG_UINT32, reg3, IARG_UINT32, reg3stat,
                             IARG_END);
        }       
#ifdef CTRL_FLOW
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2cf_of), IARG_UINT32, reg2, IARG_END);
#endif
    } else {
        printf("The operand count of imul (%#x) is %d\n", INS_Address(ins), INS_OperandCount(ins));
    }
}

/*mul can have 1, 2, or 3 operands results are always stored in a register.*/
void instrument_mul(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    string instruction;
    int memread;                                                 
    UINT32 reg1stat, reg2stat, reg3stat;
    REG reg1, reg2, reg3;
    USIZE addrsize;

    reg1 = REG_INVALID();
    reg2 = REG_INVALID();
    reg3 = REG_INVALID();
    reg1stat = 0;
    reg2stat = 0;
    reg3stat = 0;

    memread = INS_IsMemoryRead(ins);
    if (!INS_OperandIsReg(ins, 1) || !INS_OperandIsReg(ins, 2)) {
        printf("shiiiiiiiiit this is wrong again\n");
    }
    
    if (!memread) {
        reg1 = INS_OperandReg(ins, 0);
        if(INS_RegRContain(ins, reg1)) {
            reg1stat |= REG_READ;
        }
        if(INS_RegWContain(ins, reg1)) {
            reg1stat |= REG_WRITE;
        }
    }

    reg2 = INS_OperandReg(ins, 1);
    if(INS_RegRContain(ins, reg2)) {
        reg2stat |= REG_READ;
    }
    if(INS_RegWContain(ins, reg2)) {
        reg2stat |= REG_WRITE;
    }
    reg3 = INS_OperandReg(ins, 2);
    if(INS_RegRContain(ins, reg3)) {
        reg3stat |= REG_READ;
    }
    if(INS_RegWContain(ins, reg3)) {
        reg3stat |= REG_WRITE;
    }
    
    if(memread) {
	//memlocation cannot be destination for mul or divide
	addrsize = INS_MemoryReadSize(ins);
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(muldiv_mem_taint_dest_regs),
			 IARG_MEMORYREAD_EA, IARG_UINT32, addrsize,  
			 IARG_UINT32, reg2, IARG_UINT32, reg2stat, 
			 IARG_UINT32, reg3, IARG_UINT32, reg3stat, 
			 IARG_UINT32, reg1, IARG_UINT32, reg1stat,IARG_END);
    } else {
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(muldiv_taint_dest_regs),
			 IARG_UINT32, reg1, IARG_UINT32, reg1stat, 
			 IARG_UINT32, reg2, IARG_UINT32, reg2stat, 
			 IARG_UINT32, reg3, IARG_UINT32, reg3stat,
			 IARG_END);
    }       
#ifdef CTRL_FLOW
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2cf_of), IARG_UINT32, reg2, IARG_END);
#endif
}

inline void check_speculative_div_reg(ADDRINT reg_value)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (NUM_CKPTS > 0 && reg_value == 0) {
        INFO_PRINT(log_f, "ERROR: about to divide by zero, rollback now\n");
        rollback(ptdata, LIMIT);
    }
}
inline void check_speculative_div_mem(ADDRINT mem_addr, int size)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (NUM_CKPTS > 0) {
        for (int i = 0; i < size; i++) {
            if (*(char*)(mem_addr + i) != 0) return;
        }
        INFO_PRINT(log_f, "ERROR: about to divide by zero, rollback now\n");
        rollback(ptdata, LIMIT);
    }
}
/*div has 3 operands and the results are always stored in a register*/
void instrument_div(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1reg, op2reg, op3reg;
    string instruction;
    int memread;
    UINT32 reg1stat, reg2stat, reg3stat;
    REG reg1, reg2, reg3;
    USIZE addrsize;

    INSTRUMENT_PRINT(log_f, "instrument_div: instruction is %s\n", INS_Mnemonic(ins).c_str());

    reg1 = REG_INVALID();
    reg2 = REG_INVALID();
    reg3 = REG_INVALID();

    reg1stat = 0;
    reg2stat = 0;
    reg3stat = 0;

    memread = INS_IsMemoryRead(ins);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);
    op3reg = 0;
    if(op1reg) {
	reg1 = INS_OperandReg(ins, 0);
	if(INS_RegRContain(ins, reg1)) {
	    reg1stat |= REG_READ;
	}
	if(INS_RegWContain(ins, reg1)) {
	    reg1stat |= REG_WRITE;
	}
    }
    if(op2reg) {
	reg2 = INS_OperandReg(ins, 1);
	if(INS_RegRContain(ins, reg2)) {
	    reg2stat |= REG_READ;
	}
	if(INS_RegWContain(ins, reg2)) {
	    reg2stat |= REG_WRITE;
	}
    }
    if(op3reg) {
	reg3 = INS_OperandReg(ins, 2);
	if(INS_RegRContain(ins, reg3)) {
	    reg3stat |= REG_READ;
	}
	if(INS_RegWContain(ins, reg3)) {
	    reg3stat |= REG_WRITE;
	}
    }
    
    if(memread) {
	//memlocation cannot be destination for mul or divide
	addrsize = INS_MemoryReadSize(ins);
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(check_speculative_div_mem),
                    IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, IARG_END);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(muldiv_mem_taint_dest_regs),
			 IARG_MEMORYREAD_EA, IARG_UINT32, addrsize, 
			 IARG_UINT32, reg1, IARG_UINT32, reg1stat, 
			 IARG_UINT32, reg2, IARG_UINT32, reg2stat, 
			 IARG_UINT32, reg3, IARG_UINT32, reg3stat,IARG_END);
    } else {
	if ((reg1stat & REG_READ) != 0) {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(check_speculative_div_reg),
                        IARG_REG_VALUE, reg1, IARG_END);
        } else if ((reg2stat & REG_READ) != 0) {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(check_speculative_div_reg),
                        IARG_REG_VALUE, reg2, IARG_END);
        } else if ((reg3stat & REG_READ) != 0) {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(check_speculative_div_reg),
                        IARG_REG_VALUE, reg3, IARG_END);
        }
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(muldiv_taint_dest_regs),
			 IARG_UINT32, reg1, IARG_UINT32, reg1stat, 
			 IARG_UINT32, reg2, IARG_UINT32, reg2stat, 
			 IARG_UINT32, reg3, IARG_UINT32, reg3stat,
			 IARG_END);
    }
}

void instrument_xadd(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int op1mem, op1reg, op2reg;
    USIZE addrsize;

    op1mem = INS_OperandIsMemory(ins, 0);
    op1reg = INS_OperandIsReg(ins, 0);
    op2reg = INS_OperandIsReg(ins, 1);

    if(op1reg && op2reg) {
	REG reg1, reg2;
	INSTRUMENT_PRINT(log_f, "instrument_xadd: op1 and op2 of Artith are registers\n");
	reg1 = INS_OperandReg(ins, 0);
	reg2 = INS_OperandReg(ins, 1);
	if(!REG_valid(reg1) || !REG_valid(reg2)) {
	    return;
	}
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_xadd_regs),
		       IARG_UINT32, reg1, IARG_UINT32, reg2, IARG_END);
#ifdef CTRL_FLOW
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2flag), IARG_UINT32, reg1, IARG_END);
#endif
    } else if(op1mem && op2reg) {
	REG reg;
	INSTRUMENT_PRINT(log_f, "instrument_xadd: op1 is memory && op2 is register\n");
	addrsize = INS_MemoryReadSize(ins);
	reg = INS_OperandReg(ins, 1);
	if(!REG_valid(reg)) {
	    //we ignore reads from video memory e.g. the gs segment register
	    return;
	}
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_xadd_mem_reg),
			 IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_UINT32, reg, IARG_END);
#ifdef CTRL_FLOW
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_mem2flag), IARG_MEMORYWRITE_EA, IARG_UINT32, addrsize, IARG_END);
#endif
    } else {
	string instruction;
	instruction = INS_Disassemble(ins);
	printf("instrument_xadd: unknown combination of XADD ins: %s\n", instruction.c_str());
    }    
}

void instrument_setcc(INS ins, UINT32 mask)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    int opmem, opreg;
    
    opmem = INS_OperandIsMemory(ins, 0);
    opreg = INS_OperandIsReg(ins, 0);

    if (opmem) {
	UINT32 addrsize;
	INSTRUMENT_PRINT(log_f, "instrument_setcc: instruction is %s and first operand is memory\n", INS_Mnemonic(ins).c_str());
	addrsize = INS_MemoryWriteSize(ins);
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_flag_effect), IARG_UINT32, mask, IARG_END);
	INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(taint_flag2mem), IARG_MEMORYWRITE_EA, 
			    IARG_UINT32, addrsize, IARG_UINT32, mask, IARG_UINT32, SET, IARG_END);
    } else if(opreg) {
	REG reg = INS_OperandReg(ins, 0);
	INSTRUMENT_PRINT(log_f, "instrument_setcc: instruction is %s and first operand is reg %d (%s)\n", INS_Mnemonic(ins).c_str(), reg,
			 REG_StringShort(reg).c_str());
	INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(check_flag_effect), IARG_UINT32, mask, IARG_END);
	INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(taint_flag2reg), IARG_UINT32, reg, IARG_UINT32, mask, IARG_UINT32, SET, IARG_END);
    } else {
	string instruction;
	instruction = INS_Disassemble(ins);
	printf("instrument_setcc: unknown combination of XADD ins: %s\n", instruction.c_str());
    }
	
}

void instrument_lea(INS ins)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    REG dstreg = INS_OperandReg(ins, 0);
    REG base_reg = INS_OperandMemoryBaseReg(ins, 1);
    REG index_reg = INS_OperandMemoryIndexReg(ins, 1);

    if (REG_valid (index_reg) && !REG_valid(base_reg)) {
	// This is a nummeric calculation in disguise
	INSTRUMENT_PRINT (log_f, "LEA: index reg is %d base reg invalid\n", index_reg);
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_reg2reg), IARG_UINT32, dstreg, IARG_UINT32, index_reg, IARG_END);
    } else {
	//loading an effective address clears the dep set of the target
	//register.. then we add the depsets of the base/index regs used.
	// Looks like Mona decided not to do the above???
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_immval2reg), IARG_UINT32, dstreg, IARG_UINT32, SET, IARG_END);
    }

}

void instrument_move_string(INS ins, OPCODE opcode)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    UINT32 opw = INS_OperandWidth(ins, 0);
    UINT32 size = opw/8;
    if(INS_RepPrefix(ins)) {
        REG reg = LEVEL_BASE::REG_ECX;
        if (opw == 16) {
            reg = REG_CX;    
        } else if (opw == 64) {
            printf("Doing 64 bit repeat string operation in instrument_move_string\n");
        }
        INSTRUMENT_PRINT(log_f, "REP-Prefix in move_string, operand width is %d\n", opw);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(rep_taint_whole_mem2mem),
                IARG_FIRST_REP_ITERATION, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_REG_VALUE, REG_EFLAGS,
                IARG_REG_VALUE, reg, IARG_UINT32, size, IARG_END);	
        return;
    }

    if (opw == 64 )
        printf("ERROR: instrument_move_string: got a 64 bit movsq!!!\n");
    else { 
        int rep = 1;
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_whole_mem2mem),
			   IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_REG_VALUE, REG_EFLAGS, 
                           IARG_UINT32, rep, IARG_UINT32, size, IARG_END);
    }
}

void instrument_load_string(INS ins, OPCODE opcode)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    REG dst_reg = INS_OperandReg(ins, 0);
    UINT32 opw = INS_OperandWidth(ins, 0);
    UINT32 size = opw/8;
    if(INS_RepPrefix(ins)) {
        REG reg = LEVEL_BASE::REG_ECX;
        if (opw == 16) {
            reg = REG_CX;    
        } else if (opw == 64) {
            printf("Doing 64 bit repeat string operation in instrument_load_string\n");
        }
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(rep_taint_whole_mem2reg),
                IARG_FIRST_REP_ITERATION, IARG_MEMORYREAD_EA, IARG_UINT32, dst_reg, IARG_REG_VALUE, REG_EFLAGS, 
                IARG_REG_VALUE, reg, IARG_UINT32, size, IARG_END);	
        INSTRUMENT_PRINT(log_f, "REP-Prefix in load_string, operand width is %d\n", opw);
        return;
    }

    if (opw == 64)
	printf("ERROR: instrument_load_string: got a 64 bit load!!!\n");
    else 
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_whole_mem2reg),
		       IARG_MEMORYREAD_EA, IARG_UINT32, dst_reg, IARG_REG_VALUE, REG_EFLAGS, IARG_UINT32, size, IARG_END);	
}

/*
void store_string_debug(ADDRINT inst, ADDRINT reg_cx, ADDRINT reg_ecx)
{
    fprintf(log_f, "store_string_debug %#x, reg cx %d, reg ecx %d\n", inst, reg_cx, reg_ecx);
    fflush(log_f);
}
*/

void instrument_store_string(INS ins, OPCODE opcode)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    UINT32 opw = INS_OperandWidth(ins, 0);
    UINT32 size = opw/8;
    if(INS_RepPrefix(ins)) {
        //the instruction gets repeated itself
        REG rep_reg = LEVEL_BASE::REG_ECX;
        if (opw == 16) {
            rep_reg = REG_CX;    
        } else if (opw == 64) {
            printf("Doing 64 bit repeat string operation in instrument_store_string\n");
        }
	
/*
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(store_string_debug),
            IARG_INST_PTR, IARG_REG_VALUE, REG_CX, IARG_REG_VALUE, LEVEL_BASE::REG_ECX, IARG_END);	
*/
	
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(rep_taint_whole_reg2mem),
		       IARG_FIRST_REP_ITERATION, IARG_MEMORYWRITE_EA, IARG_REG_VALUE, REG_EFLAGS,
		       IARG_REG_VALUE, rep_reg, IARG_UINT32, size, IARG_END);	
        INSTRUMENT_PRINT(log_f, "REP-Prefix in store_string, operand width is %d\n", opw);
        return;
    }
    
    if (opw == 64)
        printf("ERROR: instrument_store_string: got a 64 bit store!!!\n");
    else {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_whole_reg2mem),
		       IARG_MEMORYWRITE_EA, IARG_REG_VALUE, REG_EFLAGS, IARG_UINT32, 1, IARG_UINT32, size, IARG_END);	
    }
}

void output_buffer_result (char * output_type, char * output_channel, void* buf, int size, int offset)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (size < 0) return;

    GRAB_GLOBAL_LOCK (ptdata);
    if (!buf) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
    for (int i = 0; i < size; i++) {
        struct taint* t;
        GList* options;
        GList* tmp;
        ADDRINT loc = ((ADDRINT) buf) + i;
        t = get_mem_taint(loc);
        if (!t) {
            // only print out non-zero taints
            continue;
        }
        options = get_non_zero_taints(t);
        tmp = options;
        // traverse list and do lookup
        while (tmp) {
            struct token* tok;
            // only for non-zero taint options
            if ((get_taint_value(t, GPOINTER_TO_INT(options->data)))) {
                tok = (struct token* ) g_hash_table_lookup(option_info_table, options->data);
                if (tok) {
                    const char* token_type;
                    char * token_channel = NULL;
                    if (tok->type == TOK_READ) {
                        token_type = "READ";
                    } else if (tok->type == TOK_WRITE) {
                        token_type = "WRITE";
                    } else if (tok->type == TOK_EXEC) {
                        token_type = "EXEC";
                    } else {
                        token_type = "UNK";
                    }
                    if (tok->name) {
                        token_channel = tok->name;
                    } else {
                        token_channel = (char *) "--";
                    }
                    // Output format:
                    // Output <-- Input that caused it
                    // TYPE CHANNEL GROUP_ID RECORD_PID SYSCALL_CNT OFFSET
                    fprintf(output_f, "%s %s %llu %d %d %d %s %s %llu %d %d %d\n",
                            output_type, output_channel, ptdata->rg_id, ptdata->record_pid, global_syscall_cnt, i + offset,
                            token_type, token_channel, tok->rg_id, tok->record_pid, tok->syscall_cnt, tok->byte_offset);
                    fflush(output_f);
                } else {
                    LOG_PRINT ("  could not find input token for %d\n", GPOINTER_TO_INT(options->data));
                }
            }
            tmp = g_list_next(tmp);
        }
    }
}

void analyze_buffer_stop (long id, void* buf, int size)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (size < 0) return;

    GRAB_GLOBAL_LOCK (ptdata);
    if (!buf) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
    // fprintf(output_f, "write syscall number: %ld\n", id);
    // write out the results to the output file
    for (int i = 0; i < size; i++) {
        struct taint* t;
        GList* options;
        GList* tmp;
        ADDRINT loc = ((ADDRINT) buf) + i;
        // fprintf(output_f, "%#x (value: \"%c\"): ", loc, *((char *)loc));
        t = get_mem_taint(loc);
        if (!t) {
            // fprintf(output_f, "\n");
            continue;
        }
        options = get_non_zero_taints(t);
        tmp = options;
        // traverse list and do lookup
        while (tmp) {
            struct token* tok;
            // only for non-zero taint options
            if ((get_taint_value(t, GPOINTER_TO_INT(options->data)))) {
                tok = (struct token* ) g_hash_table_lookup(option_info_table, options->data);
                if (!tok) {
                    LOG_PRINT ("  could not find input token for %d\n", GPOINTER_TO_INT(options->data));
                    // fprintf(output_f, "\n");
                } else {
#ifndef CONFAID
#ifdef HAVE_REPLAY
                    const char* token_type;
                    if (tok->type == TOK_READ) {
                        token_type = "READ";
                    } else if (tok->type == TOK_WRITE) {
                        token_type = "WRITE";
                    } else if (tok->type == TOK_EXEC) {
                        token_type = "EXEC";
                    } else {
                        token_type = "UNK";
                    }
                    fprintf(output_f, "%s %s %llu %d %ld %d %s %s %s %llu %d %d %d %s\n",
                            "WRITE", "--", ptdata->rg_id, ptdata->record_pid, id, i, "FILE",
                            token_type, "--", ptdata->rg_id, ptdata->record_pid, tok->syscall_cnt, tok->byte_offset, tok->name);
                    fflush(output_f);
                    // fprintf(output_f, "input byte num: %d, record_pid %d, syscall_cnt %d, byte_offset %d -- file %s\n", tok->token_num, get_record_pid(), tok->syscall_cnt, tok->byte_offset, tok->name); 
#else
                    fprintf(output_f, "input byte num: %d, record_pid %d, syscall_cnt %d, byte_offset %d -- file %s\n", tok->token_num, get_record_pid(), tok->syscall_cnt, tok->byte_offset, tok->name); 
#endif // HAVE_REPLAY
#else
                    fprintf(output_f, "input byte num: %d, record_pid %d, syscall_cnt %d, byte_offset %d\n", tok->token_num, get_record_pid(), tok->syscall_cnt, tok->byte_offset); 
#endif
                }
            }

            tmp = g_list_next(tmp);
        }
        // __print_dependency_tokens(output_f, t);
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

void print_input_data (FILE* fp)
{
    int i = 0;
    struct token* tok;
    fprintf(fp, "Inputs:\n");
    for (i = 0; i < option_cnt; i++) {
        tok = (struct token *) g_hash_table_lookup(option_info_table, GINT_TO_POINTER(i));
        if (!tok) {
            fprintf(fp, "%d: NO TOKEN?!\n", i);
        } else {
            fprintf(fp, "%d: syscall cnt %d byte %d %s\n", i, tok->syscall_cnt, tok->byte_offset, tok->name);
        }
    }
    fflush(fp);
}

#ifdef CONFAID
void print_confaid_results (FILE* fp, struct thread_data* ptdata)
{
    GRAB_GLOBAL_LOCK (ptdata);
    fprintf(fp, "ConfAid Result:\n");
    __print_ctrflow_stack_conditions(fp, ptdata);
    fprintf(fp, "-------------------------------\n");

    fflush(fp);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void analyze_buffer (void* buf, int size)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (size < 0) return;

    GRAB_GLOBAL_LOCK (ptdata);
    if (!buf) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
    // check to make sure the buf is \0 terminated
    char c;
    char * cbuf;
    if (PIN_SafeCopy(&c, (const void *) (((ADDRINT) buf) + size - 1), 1) != 1) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
    if (c != '\0') {
        cbuf = (char *) malloc(sizeof(char) * (size + 1));
        memcpy(cbuf, buf, size);
        cbuf[size] = '\0';
    } else {
        cbuf = (char *) malloc(sizeof(char) * (size));
        memcpy(cbuf, buf, size);
    }

    if (regex_match_string(&confaid_data->error_regex, cbuf)) {
        fprintf(output_f, "Found match in string: %s", cbuf);
        print_confaid_results(output_f, ptdata);
    }

    free(cbuf);
    RELEASE_GLOBAL_LOCK (ptdata);
}

// checks to see if the argument could be possible valid string.
// It walks the value from the pointer until it reaches either
// the null-terminated character \0 or an invalid memory address.
//
// returns 1 for a valid string at arg, 0 for invalid
int check_argument_validity(ADDRINT arg)
{
    int valid = 0;
    char* ptr = (char *) arg;
    //fprintf(stderr, "check validity: %#x\n", arg);
    if (arg == 0) return 0;

    while (is_valid_address(ma_list, (u_long) ptr)) {
        if (*ptr == '\0') {
            valid = 1;
            break;
        }
        ptr += 1;
    }
    //fprintf(stderr, "arg: %#x, valid %d\n", arg, valid);
    return valid;
}

int match_argument(char* func_name, regex_t* regex, char* arg, int arg_num)
{
    //fprintf(stderr, "match argument: %s\n", arg);
    if (regex_match_string(regex, arg)) {
        struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
        fprintf(log_f, "found argument match! in function %s\n", func_name);
        print_ctrflow_stack_conditions(ptdata);
        fprintf(log_f, "-------------------------------\n");

        if (output_f) {
            fprintf(output_f, "match argument(%d) \"%s\" in function %s\n", arg_num, arg, func_name);
            print_confaid_results(output_f, ptdata);
        }
        return 1;
    } else {
        return 0;
    }
}

void check_function_args(ADDRINT name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2,
                            ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
    char* func_name = (char *) name;
    fprintf(stderr, "Check function args in function %s\n", func_name);
    fprintf(stderr, "%#x %#x %#x %#x %#x %#x\n", arg0, arg1, arg2, arg3, arg4, arg5);

    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    regex_t* error_regex = &confaid_data->error_regex;
    __print_ctrflow_stack_conditions(stderr, ptdata);
    fprintf(stderr, "-------------------------------\n");
    print_confaid_results(stderr, ptdata);

    if (check_argument_validity(arg0)) {
        fprintf(stderr, "print arg0:\n");
        fprintf(stderr, "%s\n", (char *) arg0);
        if (match_argument(func_name, error_regex, (char *)arg0, 0)) {
            fprintf(log_f, "found argument in: %s\n", (char *) arg0);
        }
    }
    if (check_argument_validity(arg1)) {
        fprintf(stderr, "print arg1:\n");
        fprintf(stderr, "%s\n", (char *) arg1);
        if (match_argument(func_name, error_regex, (char *)arg1, 1)) {
            fprintf(log_f, "found argument in: %s\n", (char *) arg1);
        }
    }
    if (check_argument_validity(arg2)) {
        fprintf(stderr, "print arg2:\n");
        fprintf(stderr, "%s\n", (char *) arg2);
        if (match_argument(func_name, error_regex, (char *)arg2, 2)) {
            fprintf(log_f, "found argument in: %s\n", (char *) arg2);
        }
    }
    if (check_argument_validity(arg3)) {
        fprintf(stderr, "print arg3:\n");
        fprintf(stderr, "%s\n", (char *) arg3);
        if (match_argument(func_name, error_regex, (char *)arg3, 3)) {
            fprintf(log_f, "found argument in: %s\n", (char *) arg3);
        }
    }
    if (check_argument_validity(arg4)) {
        fprintf(stderr, "print arg4:\n");
        fprintf(stderr, "%s\n", (char *) arg4);
        if (match_argument(func_name, error_regex, (char *)arg4, 4)) {
            fprintf(log_f, "found argument in: %s\n", (char *) arg4);
        }
    }
    if (check_argument_validity(arg5)) {
        fprintf(stderr, "print arg5:\n");
        fprintf(stderr, "%s\n", (char *) arg5);
        if (match_argument(func_name, error_regex, (char *)arg5, 5)) {
            fprintf(log_f, "found argument in: %s\n", (char *) arg5);
        }
    }
}
#endif

/* In cases where we can't intercept at the glibc wrapper (e.g. it doesn't exist or debug symbols have been stripped),
 * we need to handle how taint propagates through system calls here.
 * */
void handle_syscall_start (int sysnum, ADDRINT syscallarg1, ADDRINT syscallarg2, ADDRINT syscallarg3)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct syscall_info* si;
   
    // the syscall glibc wrapper should catch the syscall here
    if (ptdata->syscall_handled) {
        return;
    }

    si = (struct syscall_info*) malloc(sizeof(struct syscall_info));
    si->sysnum = sysnum;

    ptdata->syscall_taint_info.special_value = (ADDRINT) si;

    // set args taint according to the arguments for specific syscalls
    switch(sysnum) {
        // explicit cases where we say we don't so anything with these are syscalls
        case 91:
        case 252:
            break;
        // catch syscalls that we miss, either because they're unsupported or
        // we missed them at the glibc wrapper
        default:
            ERROR_PRINT(log_f, "ERROR: syscall num %d is not handled\n", sysnum);
            break;
    }
}

/* Called at the end of system calls, this should describe how taint is propagated through the specified system call */
void handle_syscall_stop (int ret_value)
{
    int sysnum;
    struct syscall_info* si;
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (ptdata->syscall_handled) {
        ptdata->syscall_handled = 0;
        return;
    }

    si = (struct syscall_info*) ptdata->syscall_taint_info.special_value;
    sysnum = si->sysnum;
    
    // propagate the taints from the input to the output according to specific syscalls
    switch(sysnum) {
        // TODO finish
        default:
            break;
    }

    free(si);
}

// Bookeeping functions that start and end within system calls
inline void __sys_execve_start(struct thread_data* ptdata, char* filename, char ** argv, char ** envp) {
#ifndef CONFAID
    int acc = 0;
    char **tmp = NULL;
    if (filename) {
        LOG_PRINT ("exec of %s\n", filename);
        fprintf(output_f, "# execve: %s\n", filename);
        output_buffer_result ((char *)"EXEC", (char *)"NAME", filename, strlen(filename), acc);
        acc += strlen(filename);
    }
    if (argv) {
        tmp = argv;
        while (1) {
            char* arg;
            arg = *tmp;
            // args ends with a NULL
            if (!arg) {
                break;
            }
            LOG_PRINT ("exec arg is %s\n", arg);
            output_buffer_result ((char *)"EXEC", (char *)"ARGS", arg, strlen(arg), acc);
            acc += strlen(arg);
            tmp += 1;
        }
    }
    if (envp) {
        tmp = envp;
        while (1) {
            char * arg;
            arg = *tmp;
            // args ends with a NULL
            if (!arg) {
                break;
            }
            LOG_PRINT ("exec envp is %s\n", arg);
            output_buffer_result ((char *)"EXEC", (char *)"ENVP", arg, strlen(arg), acc);
            acc += strlen(arg);
            tmp += 1;
        }
    }
#endif
}

inline void __sys_open_start(struct thread_data* ptdata, char* filename, int flags) {
#ifdef CONFAID
    LOG_PRINT ("OPEN file %s %s\n", filename, confaid_data->config_filename);
    LOG_PRINT ("strcmp %d\n", !strcmp(filename, confaid_data->config_filename));
    if (!strcmp(filename, confaid_data->config_filename)) {
        confaid_data->config_file_opened = 1;
    }
#else
    struct open_info* oi = (struct open_info *) malloc(sizeof(struct open_info));
    strncpy(oi->name, filename, OPEN_PATH_LEN);
    oi->flags = flags;
    ptdata->save_syscall_info = (void *) oi;
#endif
}

inline void __sys_open_stop(struct thread_data* ptdata, int rc) {
#ifdef CONFAID
    if (confaid_data->config_file_opened && (rc > 0)) {
        confaid_data->config_fd = rc;
        LOG_PRINT ("config file OPENED config_fd is %d\n", confaid_data->config_fd);
    } else if (rc <= 0) {
        confaid_data->config_file_opened = 0;
    }
#else
    if (rc > 0) {
        monitor_add_fd(open_fds, rc, 0, ptdata->save_syscall_info);
        ptdata->save_syscall_info = 0;
    }
#endif
}

inline void __sys_read_start(struct thread_data* ptdata, int fd, char* buf, int size) {
    struct read_info* ri = (struct read_info *) malloc(sizeof(struct read_info));
    ri->fd = fd;
    ri->buf = buf;
    ptdata->save_syscall_info = (void *) ri;
    LOG_PRINT ("read on fd %d\n", fd);
#ifdef CONFAID
    if (fd == confaid_data->config_fd && (fd != CONFIG_FD_CLOSED)) {
        confaid_data->read_from_config_fd = 1;
    }
#endif
}

inline void __sys_read_stop(struct thread_data* ptdata, int rc) {
    struct read_info* ri = (struct read_info *) ptdata->save_syscall_info;
    LOG_PRINT ("Pid %d syscall read returns %d\n", PIN_GetPid(), rc);
    // new tokens created here	
#ifndef CONFAID
    void* data = NULL;
    if (monitor_has_fd(open_fds, ri->fd)) {
        data = monitor_get_fd_data(open_fds, ri->fd);
    } else if(ri->fd == fileno(stdin)) {
        const char* s = "stdin";
        data = (void *) s;
    }
#ifdef FILTER_INPUTS
    if (data && !strncmp(input_file_name, (char *) data, 256)) {
        create_options_from_buffer (TOK_READ, global_syscall_cnt, (void *) ri->buf, (int) ret_value, 0, data);
    }
#else
    create_options_from_buffer (TOK_READ, global_syscall_cnt, (void *) ri->buf, rc, 0, data);
#endif // FILTER_INPUTS
#else
    if (confaid_data->read_from_config_fd && (((int) ret_value) > 0)) {
        assert (ri->buf);
        // traverse the whole buffer and mark them as having the config file taint.
        /*
           struct taint vector;
           new_taint(&vector);
           set_taint_value(&vector, 0, get_max_taint_value()); // 0 means config file taint
           int i = 0;
           for (i = 0; i < ((int) ret_value); i++) {
           mem_mod_dependency(ptdata, ri->buf + i, &vector, SET, 1);
           }
           LOG_PRINT ("Set memory locations (%#x, %#x] to taint:", ri->buf, ri->buf + i);
           __print_dependency_tokens(log_f, &vector);
           */

        // Read through the buffer, if we see a new line create a new token
        int i = 0;
        for (i = 0; i < ((int) ret_value); i++) {
            char dst;
            struct taint vector;
            new_taint(&vector);
            set_taint_value(&vector, option_cnt, get_max_taint_value());

            dst = *(char *)(ri->buf + i);
            if (dst == '\n') {
                if (confaid_data->token_idx != 254) {
                    confaid_data->token_acc[confaid_data->token_idx] = dst;
                    confaid_data->token_acc[confaid_data->token_idx + 1] = '\0';
                }
                create_new_named_token(option_cnt, confaid_data->token_acc);
                LOG_PRINT ("[OPTION] New token from config file, line %d, %s\n", confaid_data->line_num, confaid_data->token_acc);
                confaid_data->token_idx = 0;
                option_cnt++;
                confaid_data->line_num++;
            } else {
                // truncate
                if (confaid_data->token_idx == 254) {
                    confaid_data->token_acc[confaid_data->token_idx] = '\n';
                    confaid_data->token_acc[confaid_data->token_idx + 1] = '\0';
                }
                confaid_data->token_acc[confaid_data->token_idx] = dst;
                confaid_data->token_idx++;
            }
            mem_mod_dependency(ptdata, ri->buf + i, &vector, SET, 1);
        }
    }
#endif
    free(ri);
    ptdata->save_syscall_info = 0;
}

inline void __sys_write_start(struct thread_data* ptdata, int fd, char* buf, int size) {
    struct write_info* wi = (struct write_info *) malloc(sizeof(struct write_info));
    wi->fd = fd;
    wi->buf = buf;
    ptdata->save_syscall_info = (void *) wi;
}

inline void __sys_write_stop(struct thread_data* ptdata, int rc) {
    struct write_info* wi = (struct write_info *) ptdata->save_syscall_info;
#ifdef CONFAID
    analyze_buffer((void *) wi->buf, rc);
#else
    char* channel_name = NULL;
    if (monitor_has_fd(open_fds, wi->fd)) {
        struct open_info* oi;
        oi = (struct open_info *) monitor_get_fd_data(open_fds, wi->fd);
        assert(oi);
        channel_name = oi->name;
    } else if (wi->fd == fileno(stdout)) {
        channel_name = (char *) "stdout";
    } else if (wi->fd == fileno(stderr)) {
        channel_name = (char *) "stderr";
    } else if (wi->fd == fileno(stdin)) {
        channel_name = (char *) "stdin";
    } else {
        channel_name = (char *) "--";
    }
    output_buffer_result ((char *) "WRITE", channel_name, wi->buf, rc, 0);
#endif
    free(wi);
}

inline void __sys_close_start(struct thread_data* ptdata, int fd) {
#ifdef CONFAID
    // TODO handle if close fails
    if (fd == confaid_data->config_fd) {
        confaid_data->config_fd = CONFIG_FD_CLOSED;
        confaid_data->config_file_opened = 0;
        confaid_data->read_from_config_fd = 0;
        LOG_PRINT ("config_fd is closed\n");
    }
#else
    ptdata->save_syscall_info = (void *) fd;
#endif
}

inline void __sys_close_stop(struct thread_data* ptdata, int rc) {
#ifdef CONFAID
#else 
    int fd = (int) ptdata->save_syscall_info;
    // remove the fd from the list of open files
    if (!rc) {
        if (monitor_has_fd(open_fds, fd)) {
            struct open_info* oi = (struct open_info *) monitor_get_fd_data(open_fds, fd);
            assert(oi);
            free(oi);
            monitor_remove_fd(open_fds, fd);
        }
    }
#endif
}

void instrument_syscall(ADDRINT syscall_num, ADDRINT syscallarg1, ADDRINT syscallarg1_ref, ADDRINT syscallarg2, ADDRINT syscallarg3, ADDRINT syscallarg4, ADDRINT syscallarg5)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);

    SYSNUM = (int)syscall_num;
#ifdef LOGGING_ON
    SYSCALL_PRINT ("%d: Pid %d calling syscall %d\n", global_syscall_cnt, PIN_GetPid(), SYSNUM);
#endif

#ifdef LINKAGE_SYSCALL
    handle_syscall_start((int)syscall_num, syscallarg1, syscallarg2, syscallarg3);
#endif

#ifdef ALT_PATH_EXPLORATION
    if(NUM_CKPTS > 0) {
        //No syscall is allowed
        SPEC_PRINT(log_f, "About to call speculative syscall: %d, rolling back\n", SYSNUM);
        rollback(ptdata, LIMIT);
    }
#endif

    switch (SYSNUM) {
        case SYS_execve:
        {
            __sys_execve_start(ptdata, (char *)syscallarg1, (char **)syscallarg2, (char **)syscallarg3);
            break;
        }
#ifdef HAVE_REPLAY
        case 31:
            // get the ignore flag location
            ptdata->ignore_flag = (u_long) syscallarg2;
            fprintf(stderr, "ignore flag set to %lu\n", ptdata->ignore_flag);
            break;
#endif
        case SYS_open:
        {
            char* filename = (char *) syscallarg1;
            __sys_open_start(ptdata, filename, (int)syscallarg2);
            break;
        }
        case SYS_close:
        {
            __sys_close_start(ptdata, (int)syscallarg1);
            break;
        }
        case SYS_read:
        {
            __sys_read_start(ptdata, (int)syscallarg1, (char *)syscallarg2, (int)syscallarg3);
            break;
        }
        case SYS_write:
            __sys_write_start(ptdata, (int)syscallarg1, (char *)syscallarg2, (int)syscallarg3);
            break;
        case SYS_writev:
        {
            struct writev_info* wvi;
            wvi = (struct writev_info*) malloc(sizeof(struct writev_info));
            wvi->count = (int) syscallarg3;
            wvi->vi = (struct iovec *) syscallarg2;

            // we'll just stuff it in there
            ptdata->save_syscall_info = (void *) wvi;

            break;
        }
        case SYS_mmap:
        case SYS_mmap2:
        {
            struct mmap_info* mmi;
            mmi = (struct mmap_info*) malloc(sizeof(struct mmap_info));
            mmi->addr = (u_long) syscallarg1;
            mmi->length = (int) syscallarg2;
            mmi->fd = (int) syscallarg5;

            ptdata->save_syscall_info = (void *) mmi;
            break;
        }
        case SYS_munmap:
        {
            struct mmap_info* mmi;
            mmi = (struct mmap_info*) malloc(sizeof(struct mmap_info));
            mmi->addr = (u_long) syscallarg1;
            mmi->length = (int) syscallarg2;

            ptdata->save_syscall_info = (void *) mmi;
            break;
        }
    }

#ifdef HAVE_REPLAY
    if (SYSNUM == 91 || SYSNUM == 120 || SYSNUM == 125 || SYSNUM == 174 || SYSNUM == 175 || SYSNUM == 190 || SYSNUM == 192) {
        check_clock_before_syscall (dev_fd, (int) syscall_num);
    }
#endif
    ptdata->app_syscall = syscall_num;
    // NO SYSTEM CALLS AFTER THIS POINT
    RELEASE_GLOBAL_LOCK (ptdata);
}

void instrument_syscall_ret(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (ptdata && ptdata->app_syscall != 999) {
        ptdata->app_syscall = 0;
    }

    ADDRINT ret_value = PIN_GetSyscallReturn(ctxt, std);
    SYSCALL_PRINT (" syscall %d returns %d(%#x)\n", SYSNUM, (int)ret_value, ret_value);
#ifdef LINKAGE_SYSCALL
    handle_syscall_stop((int) ret_value);
#endif

    switch (SYSNUM) {
        case SYS_open:
        {
            __sys_open_stop(ptdata, (int) ret_value);
            break;
        } 
        case SYS_close:
        {
            __sys_close_stop(ptdata, (int) ret_value);
            break;
        }
        case SYS_execve:
        {
            fprintf(log_f, "sys call execve is returned...\n");
            break;
        } 
        case SYS_clone:
        {
            fprintf(log_f, "Pid %d syscall clone returns %d\n", PIN_GetPid(), ret_value);
            break;
        }
        case SYS_read:
        {
            __sys_read_stop(ptdata, (int) ret_value);
            break;
        } 
        case SYS_write:
            __sys_write_stop(ptdata, (int) ret_value);
            break;
        case SYS_writev:
            struct writev_info* wvi;
            wvi = (struct writev_info*) ptdata->save_syscall_info;

            for (int i = 0; i < wvi->count; i++) {
                struct iovec* vi = (wvi->vi + i);
                analyze_buffer_stop(global_syscall_cnt, vi->iov_base, vi->iov_len);
            }
            free((void *)ptdata->save_syscall_info);
            break;
        case SYS_mmap:
        case SYS_mmap2:
        {
            u_long addr;
            int len;
            struct mmap_info* mmi;

            mmi = (struct mmap_info*) ptdata->save_syscall_info;
            addr = mmi->addr;
            len = mmi->length;

            addr = ret_value;
            if (ret_value > 0 && addr && len) {
#ifdef TRACK_MEMORY_AREAS
                if (add_memory_area(ma_list, addr, addr + len)) {
                    MEM_PRINT(MEM_F, "Could not add memory area [%#x, %#x)\n", (unsigned int) (addr), (unsigned int) (addr + len));
                }
#endif

#ifndef CONFAID
                // treat this as a read if we've mmap'ed a file
                if (option_byte && mmi->fd != -1) {
                    void* data = NULL;
                    if (monitor_has_fd(open_fds, mmi->fd)) {
                        data = monitor_get_fd_data(open_fds, mmi->fd);
                    }
#ifdef FILTER_INPUTS
                    if (data && !strncmp(input_file_name, (char *) data, 256)) {
                        create_options_from_buffer (TOK_READ, global_syscall_cnt, (void *) mmi->addr, mmi->length, 0, data);
                    }
#else
                    create_options_from_buffer (TOK_READ, global_syscall_cnt, (void *) mmi->addr, mmi->length, 0, data);
#endif // FILTER_INPUTS
                }
#endif // CONFAID
            }

            ptdata->save_syscall_info = 0;
            free((void *)mmi);
            break;
        }
        case SYS_munmap:
        {
            u_long addr;
            int len;
            struct mmap_info* mmi;

            mmi = (struct mmap_info*) ptdata->save_syscall_info;
            addr = mmi->addr;
            len = mmi->length;

            if ((int)ret_value != -1 && addr && len) {
#ifdef TRACK_MEMORY_AREAS
                if (remove_memory_area(ma_list, addr, addr + len)) {
                    MEM_PRINT(MEM_F, "Could not remove memory area [%#x, %#x)\n", (unsigned int)(addr), (unsigned int)(addr+len));
                    fflush(MEM_F);
                }
#endif
            }
            ptdata->save_syscall_info = 0;
            free((void *)mmi);
            break;
        }
        case SYS_brk:
        {
#ifdef TRACK_MEMORY_AREAS
            if (ptdata->brk_saved_loc) {
                if (ret_value == ptdata->brk_saved_loc) break;
                if (ret_value < ptdata->brk_saved_loc) {
                    fprintf(stderr, "[ERROR]ret_value %#x is less than or equal to the saved brk %#x\n", ret_value, (unsigned int) ptdata->brk_saved_loc);
                }
                assert(ret_value > ptdata->brk_saved_loc);
                if (add_memory_area(ma_list, ptdata->brk_saved_loc, ret_value)) {
                    MEM_PRINT (MEM_F, "brk: Could not add memory area [%#x, %#x)\n", (unsigned int) (ptdata->brk_saved_loc), (unsigned int) (ret_value));
                }
            } else {
                ptdata->brk_saved_loc = ret_value;
            }
            break;
#endif
        }
        case SYS_rmdir:
        {
            rmdir_stop(ret_value);
            break;
        }
    }
    // Increment on syscall return for consistency with the log
    increment_syscall_cnt (ptdata, (int)SYSNUM);
}

#ifdef HAVE_REPLAY
void syscall_instr_after (ADDRINT ip)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (no_replay) return;

    if (ptdata->app_syscall == 999) {
        if (check_clock_after_syscall (dev_fd) != 0) {
            fprintf (stderr, "Check clock failed\n");
        }
        ptdata->app_syscall = 0;  
    }
}
#endif


struct handled_function* copy_handled_functions(struct handled_function* head)
{
    struct handled_function *cur_hf, *prev_hf, *hf;
    struct handled_function* tmp = head;
    cur_hf = prev_hf = hf = NULL;
    while(tmp != NULL) {
	cur_hf = (struct handled_function*) malloc (sizeof(struct handled_function));
	MYASSERT(cur_hf);
#ifdef MEM
        mems[9] += sizeof(struct handled_function);
#endif
        strcpy(cur_hf->name, tmp->name);
        cur_hf->special_value = tmp->special_value;
	set_taint(&cur_hf->args_taint,&tmp->args_taint);
	cur_hf->prev = 0;
	if(prev_hf != NULL) 
	    prev_hf->prev = cur_hf;
	else
	    hf = cur_hf;
	prev_hf = cur_hf;
	tmp = tmp->prev;
    }
    return hf;
}

struct calling_bblock* copy_calling_bblocks(struct calling_bblock* head)
{
    struct calling_bblock *cur_cb, *prev_cb, *cb;
    struct calling_bblock* tmp = head;
    cur_cb = prev_cb = cb = NULL;
    while(tmp != NULL) {
	cur_cb = (struct calling_bblock*) malloc (sizeof(struct calling_bblock));
	MYASSERT(cur_cb);
#ifdef MEM
        mems[8] += sizeof(struct calling_bblock);
#endif
	memcpy(cur_cb, tmp, sizeof(struct calling_bblock));
	cur_cb->prev = 0;
        if(prev_cb != NULL) 
	    prev_cb->prev = cur_cb;
	else
	    cb = cur_cb;
	prev_cb = cur_cb;
	tmp = tmp->prev;
    }
    return cb;
}

void jbe_op(int* value, int mask) {
    if ((*value & (CF_MASK | ZF_MASK)) == 0)
        *value ^= (CF_MASK | ZF_MASK);
    else if (*value & (CF_MASK == 0)) 
        *value ^= ZF_MASK;
    else if (*value & (ZF_MASK == 0)) 
        *value ^= CF_MASK;
    else *value ^= (CF_MASK | ZF_MASK);
}

void jle_op(int* value, int mask) {
    if ((*value & ZF_MASK) != 0) {
        *value ^= ZF_MASK;
         *value |= (OF_MASK | SF_MASK);
    } else 
        *value ^= SF_MASK;
}

void xor_op (int* value, int mask) {
    *value ^= mask;
}

void chase_address(ADDRINT addr, ADDRINT target_addr, CONTEXT* context, MASK_OP_FN mask_op, int mask)
{
#ifdef CTRL_FLOW
    struct check_point* orig_ckpt;
    struct check_point* tmp_ckpt;
    int value; 

    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (TOTAL_NUM_CKPTS >= TOTAL_MAX_CKPTS) {
        INFO_PRINT(log_f, "SPEC_INFO: number of checkpoints exceeding the max, rollback now\n");
        fix_taints_and_remove_from_ctrflow (ptdata, LIMIT);
        return;
    }   
    
    while (ALLOC_CKPTS != CKPTS) {
        MYASSERT(ALLOC_CKPTS != 0);
        tmp_ckpt = ALLOC_CKPTS->prev;
        SPEC_PRINT(log_f, "SPEC_INFO: freeing a checkpoint\n");
        free (ALLOC_CKPTS);
        ALLOC_CKPTS = tmp_ckpt;
#ifdef MEM
        mems[5] -= sizeof(struct check_point);
#endif
    }
    
    SPEC_PRINT(log_f, "SPEC_INFO: in function %s chasing addresses: inst-addr %#x, target-addr %#x\n", 
	    RTN_FindNameByAddress(addr).c_str(), addr, target_addr);
    //printf("INFO: chasing addresses: inst-addr %#x, target-addr is %#x\n", addr, target_addr);
    
    orig_ckpt = (struct check_point*) malloc (sizeof(struct check_point));
    if(!orig_ckpt) {
	printf("ERROR: cannot allocate ckpt\n");
	return;
    }
#ifdef MEM
        mems[5] += sizeof(struct check_point);
#endif
    INFO_PRINT(log_f, "creating a checkpoint ...\n");

    orig_ckpt->prev = CKPTS;
    orig_ckpt->ckpt_inst = addr;
    orig_ckpt->handled_functions = copy_handled_functions(HANDLED_FUNC_HEAD);
    orig_ckpt->calling_bblocks = copy_calling_bblocks(CALLING_BBLOCK_HEAD);
    orig_ckpt->num_insts = NUM_INSTS;
    orig_ckpt->mem_val_taints = g_hash_table_new (g_int_hash, g_int_equal);
    for (int i = 0; i < NUM_REGS; i++) orig_ckpt->reg_taints[i] = reg_table[i];
    for (int i = 0; i < NUM_FLAGS; i++) orig_ckpt->flag_taints[i] = flag_table[i];
    orig_ckpt->merge_on_next_ret = MERGE_ON_NEXT_RET;
    //PIN_SaveCheckpoint(ckpt, &(orig_ckpt->ckpt));
    PIN_SaveContext(context, &(orig_ckpt->ctx));
    CKPTS = orig_ckpt;
    ALLOC_CKPTS = orig_ckpt;
    NUM_CKPTS++;
    TOTAL_NUM_CKPTS++;
    
    //run the context
    first_inst = 1;
    value = (int)PIN_GetContextReg(context, REG_EFLAGS);
    SPEC_PRINT(log_f, "INFO: EFLAGS value is %#x\n", value);
    mask_op(&value, mask);
    SPEC_PRINT(log_f, "INFO:Changing EFLAGS to %#x\n", value);
    PIN_SetContextReg(context, REG_EFLAGS, value);
    PIN_ExecuteAt(context);
#endif
}

void print_bblock(struct bblock* bbl)
{
    if(!bbl) return;
    SPEC_PRINT(log_f, "size: %d\n", bbl->size);
    //printf("size: %d\n", bbl->size);
    SPEC_PRINT(log_f, "first inst: %#x\n", bbl->first_inst->inst_addr);
    if (bbl->last_inst) {
        SPEC_PRINT(log_f, "last inst: %#x\n", bbl->last_inst->inst_addr);
    }

    SPEC_PRINT(log_f, "number of branches: %d\n", bbl->num_branches);
    for(int i = 0; i < bbl->num_branches; i++) {
        SPEC_PRINT(log_f, "branch %d: %#x\n", i, bbl->branches[i]->first_inst->inst_addr);
    }

    //printf("pdoms: \n");
    if (bbl->ipdom) {
        SPEC_PRINT(log_f, "\nipdom: %#x\n", bbl->ipdom->first_inst->inst_addr);
    }
    SPEC_PRINT(log_f, "\n-----------------------------\n");
    //printf("\n-----------------------------\n");
}


int intersect_pdoms(struct bblock* parent, struct bblock** result, int max)
{
    int exists = 0, index = 0;
    struct helper {
        struct bblock* pdom;
        int            in;
    } result_tmp[max+1];

    memset(result_tmp, 0, sizeof(struct helper)*(max+1));

    for(int i = 0; parent->branches[0]->pdoms[i] != 0; i++) {
        result_tmp[i].pdom = parent->branches[0]->pdoms[i];
        result_tmp[i].in = 1;
    }
    for(int i = 1; i < parent->num_branches; i++) {         
        for(int k = 0; result_tmp[k].pdom != 0; k++) {
            if (result_tmp[k].in == 1) {
                exists = 0;
                for (int j = 0; parent->branches[i]->pdoms[j] != 0; j++) {
                    if (result_tmp[k].pdom == parent->branches[i]->pdoms[j]) {
                        exists = 1;
                        break;
                    }
                }
                if (exists == 0) {
                    result_tmp[k].in = 0;
                }
            }
        }
    }
    result[index++] = parent;
    for(int i = 0; result_tmp[i].pdom != 0; i++) {
        if (result_tmp[i].in && result_tmp[i].pdom != parent) {
                result[index++] = result_tmp[i].pdom;
        }
    }
    return index;
}

int compare_pdoms (struct bblock** pdom1, struct bblock** pdom2) 
{
    int i, j;
    for(i = 0; pdom1[i] != NULL; i++);
    for(j = 0; pdom2[j] != NULL; j++);
    if (i != j) return 1;

    int is_there;
    for (i = 0; pdom2[i] != NULL; i++) {
	is_there = 0;
	for(int j = 0; pdom1[j] != NULL; j++) {
	    if (pdom1[j] == pdom2[i]) {
		is_there = 1;
		break;
	    }
	}
	if (!is_there) return 1;
    }
    return 0;    
}

int find_pdoms(struct bblock** list, struct bblock* first_bblock)
{
    int tail = 1;
    int current = 0;
    int equal;
    int change = 1;
    int i, j;

    list[0] = first_bblock;
    while(1) {
	MYASSERT(current < MAX_NUM_BBLOCKS);
	if(list[current] == NULL)
	    break;
	MYASSERT(tail < MAX_NUM_BBLOCKS);
	for (i = 0; i < list[current]->num_branches; i++) {
            equal = 0;
            for(j = 0; j < tail; j++)
                if (list[current]->branches[i] == list[j]) {
                    equal = 1;
                    break;
                }
            if (!equal) list[tail++] = list[current]->branches[i];
        }
	current++;
    }
    for (i=0; i < current; i++) {
        list[i]->pdoms = (struct bblock**) malloc ((current+1)*sizeof(struct bblock*)); 
        if (list[i]->pdoms == 0) {
            printf("ERROR:cannot allocate pdoms\n");
            return 0;
        }
	memset(list[i]->pdoms, 0, (current+1)*sizeof(struct bblock*));
        j = 0;
        tail = 1;
        
        list[i]->pdoms[j] = list[i];
	while(1) {
            if(list[i]->pdoms[j] == NULL) break;
            for(int k = 0; k < list[i]->pdoms[j]->num_branches; k++) {
                equal = 0;
                for(int t = 0; t < tail; t++)
                    if(list[i]->pdoms[j]->branches[k] == list[i]->pdoms[t]) {
                        equal = 1;
                        break;
                    }
                if (!equal) list[i]->pdoms[tail++] = list[i]->pdoms[j]->branches[k];
            }
            j++;
        }
	//I think this should be true!!
	//The last pdom (or the one before last if the last pdom is 
	//the bblock itseld) is the ipdom
	int index = (list[i]->pdoms[0] == list[i] && list[i]->pdoms[1] != 0);
        list[i]->ipdom = list[i]->pdoms[index];
	//STATIC_PRINT ("STATIC_INFO:The ipdom is %#x\n", list[i]->ipdom->first_inst->inst_addr);
    }
    struct bblock* tmp_pdoms[current+1];
    while(change) {
	change = 0;
	for(i = current-1; i >= 0; i--) {
	    memset(tmp_pdoms, 0, (current+1)*sizeof(struct bblock*));
            if (list[i]->num_branches == 0) { 
		tmp_pdoms[0] = list[i];
	    } else {
		if(intersect_pdoms(list[i], tmp_pdoms, current) == 0) {
		    STATIC_PRINT ("STATIC_INFO: the if-else paths did not merge for bblock %#x\n", 
			    list[i]->first_inst->inst_addr);
		}
	    }
	    if(compare_pdoms(tmp_pdoms, list[i]->pdoms)) {
		change = 1;
		//STATIC_PRINT ("STATIC_INFO:Change is observed in %#x bblock pdoms\n", list[i]->first_inst->inst_addr);
                for(j = 0; tmp_pdoms[j] != NULL; j++) { 
		    list[i]->pdoms[j] = tmp_pdoms[j];
		    //printf("%#x - ", list[i]->pdoms[j]->first_inst->inst_addr);
		    //SPEC_PRINT(log_f, "%#x - ", list[i]->pdoms[j]->first_inst->inst_addr);
		}
		list[i]->pdoms[j] = 0;
		//I think this should be true!!
		//The last pdom (or the one before last if the last pdom is 
		//the bblock itseld) is the ipdom
                int index = (list[i]->pdoms[0] == list[i] && list[i]->pdoms[1] != 0);
                list[i]->ipdom = list[i]->pdoms[index];
	    }
	}
    }
    for (i=0; i < current; i++) {
        free (list[i]->pdoms);
    }
    return current;
}

void free_calling_bblocks (struct thread_data* ptdata) 
{
    struct calling_bblock* tmp;
    while(CALLING_BBLOCK_HEAD != NULL) {
	tmp = CALLING_BBLOCK_HEAD;
	CALLING_BBLOCK_HEAD = tmp->prev;
	free (tmp);
#ifdef MEM
        mems[8] -= sizeof(struct calling_bblock);
#endif
    }
    CALLING_BBLOCK_SIZE = 0;
}

void free_handled_functions(struct thread_data* ptdata)
{
    struct handled_function* tmp;
    while (HANDLED_FUNC_HEAD != NULL) {
	tmp = HANDLED_FUNC_HEAD;
	HANDLED_FUNC_HEAD = tmp->prev;
	free (tmp);
#ifdef MEM
        mems[9] -= sizeof(struct handled_function);
#endif
    }
}

gboolean restore_mem_val_taint (gpointer key, gpointer value, gpointer user_data)
{
    struct alt_mem_mod* pmod = (struct alt_mem_mod *) value;
    struct thread_data* ptdata = (struct thread_data *) user_data;

    PIN_SafeCopy((void*)(pmod->address), &(pmod->value), 1);
    if (pmod->is_tainted) {
	mem_mod_dependency (ptdata, pmod->address, &pmod->taint, SET, 0);
    } else {
	mem_clear_dependency (ptdata, pmod->address);
    }

    free (pmod);

    return TRUE; // Destroy this element
}


void rollback(struct thread_data* ptdata, int rollback_code) 
{
    //needs to remove at least one taint object with alt_path = 1
    while (CTRFLOW_TAINT_STACK->alt_path == 0)
        fix_taints_and_remove_from_ctrflow (ptdata, rollback_code); 
    fix_taints_and_remove_from_ctrflow (ptdata, rollback_code);
    
    struct check_point* current = CKPTS;
    CKPTS = current->prev;
    NUM_CKPTS--;
    //restoring the changes memory locations
    g_hash_table_foreach_remove (current->mem_val_taints, restore_mem_val_taint, ptdata);
    g_hash_table_destroy (current->mem_val_taints);
    for (int i = 0; i < NUM_REGS; i++) reg_table[i] = current->reg_taints[i];
    for (int i = 0; i < NUM_FLAGS; i++) flag_table[i] = current->flag_taints[i];
    MERGE_ON_NEXT_RET = current->merge_on_next_ret;
    if (NUM_CKPTS == 0) {
        TOTAL_NUM_CKPTS = 0;
    }
    free_calling_bblocks(ptdata);
    CALLING_BBLOCK_HEAD = current->calling_bblocks;
    CALLING_BBLOCK_SIZE = 0;
    struct calling_bblock* tmp_b = CALLING_BBLOCK_HEAD;
    while(tmp_b) { 
        CALLING_BBLOCK_SIZE++;
        tmp_b = tmp_b->prev;
    }

    free_handled_functions(ptdata);
    HANDLED_FUNC_HEAD = current->handled_functions;
    NUM_INSTS = current->num_insts;
    
    /*fixing the current_bbl*/ 
    instbbl tmp_key;
    tmp_key.inst_addr = current->ckpt_inst;
    SPEC_PRINT(log_f, "rollback: current ckpt inst is %#x\n", current->ckpt_inst);
    instbbl* tmp = (instbbl*)g_hash_table_lookup(hashtable, &tmp_key);
    MYASSERT(tmp);
    CURRENT_BBL = tmp->bblock;
    MYASSERT(CURRENT_BBL);
    SPEC_PRINT(log_f, "rollback: The current bbl is set to %#x\n", CURRENT_BBL->first_inst->inst_addr); 
    MYASSERT(CURRENT_BBL->last_inst->inst_addr == current->ckpt_inst);
    //PIN_Resume(&current->ckpt);
    PIN_ExecuteAt(&current->ctx);
}

instbbl* build_instbbl(ADDRINT address) 
{
    instbbl* hash_instbbl = (instbbl*) malloc (sizeof(instbbl));
    MYASSERT(hash_instbbl != NULL);
#ifdef MEM
    mems[6] += sizeof(struct instbbl);
#endif
    hash_instbbl->inst_addr = address;
    hash_instbbl->branch = 0;
    hash_instbbl->taken_addr = 0;
    hash_instbbl->fall_addr = 0;
    g_hash_table_insert(hashtable, hash_instbbl, hash_instbbl);
    return hash_instbbl;
}
        
/*
 * Builds bblock tree from static analysis
 *
 * @param ptdata - pointer to thread local data
 * @param address - address to build bblock tree from
 * @retparam decided_address - actual address the bblock tree is built from (either the address of RTN_FindByAddress(address)
 * @retparam this_bblock - 
 */
int build_bblock_tree(struct thread_data* ptdata, ADDRINT address, ADDRINT* decided_address, struct bblock** this_bblock)
{
    char path[256];
    char tmp_string[32];
    FILE* f_file;
    int number_insts, num_edges, rc, i, bblock_num;
    unsigned int start_address, end_address, next_bblock;
    instbbl tmp_key;
    instbbl* tmp;
    struct bblock* bblock_entry;
    
    //check to see if the address is the head of a function
    if (!in_main_image(address) && NUM_CKPTS > 0) {
	fprintf (stderr, "addr 0x%lx not in main image\n", (u_long) address);
        INFO_PRINT(log_f, "going out of the image, rollback now\n");
        rollback(ptdata, SUCCESS);
        return -1;
    }
    sprintf(path, "%s/%#x", static_analysis_path, address);
    f_file = fopen(path, "r");
    if(!f_file) {
        // RTN_FindByAddress and IMG_FindByAddress need to be help with PIN_LockClient held
        PIN_LockClient();
        ADDRINT rtn_address = RTN_Address(RTN_FindByAddress(address));

        // mcc: Find the image the RTN is located in
        ADDRINT img_offset = 0;
        //IMG img = IMG_FindByAddress(rtn_address);
        //fprintf(stderr, "STATIC: rtn_address %#x, img name: %s\n", rtn_address, IMG_Name(img).c_str());
        PIN_UnlockClient();

        img_offset = get_image_offset(img_list, rtn_address);
        /*
        LOG_PRINT ("STATIC: dynamic library rtn: address %#x, offset: %#x, rtn_address %#x\n",
                rtn_address, img_offset, rtn_address - img_offset);
        */
        rtn_address -= img_offset;
        /*
        if (IMG_Valid(img)) {
            img_offset = IMG_LoadOffset(img);
            fprintf(stderr, "STATIC: dynamic library rtn: address %#x, offset: %#x, rtn_address %#x\n",
                rtn_address, img_offset, rtn_address - img_offset);
            rtn_address -= img_offset;
        }
        */

        sprintf(path, "%s/%#x", static_analysis_path, rtn_address);
        if (!rtn_address) {
            return 0;
        }
        f_file = fopen(path, "r");
        if(!f_file) {
            /*
            fprintf (stderr, "STATIC_ERROR: not able to open function static analysis in path %s, %d, userid: %d, %d\n", path, errno, getuid(), geteuid());
            fprintf (stderr, "STATIC_ERROR: image name is %s\n", get_image_name(img_list, address));
            SPEC_PRINT(log_f, "STATIC_ERROR: not able to open function static analysis in path %s, %d, userid: %d, %d\n", 
            path, errno, getuid(), geteuid());
            */
            return -1;
        }
        SPEC_PRINT(log_f, "STATIC_INFO: building bblock tree for function %s, (%#x)\n", 
                RTN_FindNameByAddress(rtn_address).c_str(), rtn_address);
        *decided_address = rtn_address;
    } else {
        *decided_address = address;
    }

    rc = fscanf(f_file, "%d\n", &bblock_num);
    MYASSERT(rc == 1);
    if (rc != 1) {
        fprintf(stderr, "STATIC analysis -- invalid file format\n");
        return -1;
    }
    for (i = 0; i < bblock_num ; i++) {
        rc = fscanf(f_file, "%x %x\n%d\n%s %d\n", &start_address, &end_address, &number_insts, tmp_string, &num_edges);
        MYASSERT(rc == 5);
        tmp_key.inst_addr = start_address;
        tmp = (instbbl*)(g_hash_table_lookup(hashtable, &tmp_key));
        if (tmp == NULL) {
            STATIC_PRINT ("STATIC_INFO: building bblock for address %#x\n", start_address);
            bblock_entry = (struct bblock*) malloc (sizeof(struct bblock));
            MYASSERT(bblock_entry != NULL);
#ifdef MEM
            mems[7] += sizeof(struct bblock);
#endif
            memset(bblock_entry, 0, sizeof(struct bblock));
            bblock_entry->first_inst = build_instbbl(start_address);
            bblock_entry->first_inst->bblock = bblock_entry;
        } else {
            STATIC_PRINT ("STATIC_INFO: bblock for address %#x exists\n", start_address);
            bblock_entry = tmp->bblock;
        }
        bblock_entry->branches = (struct bblock**) malloc (num_edges*sizeof(struct bblock*));
        MYASSERT(num_edges <= 0 || bblock_entry->branches != NULL);
        memset(bblock_entry->branches, 0, num_edges*sizeof(struct bblock*));
        bblock_entry->num_branches = num_edges;
        bblock_entry->size = number_insts;
        bblock_entry->last_inst = build_instbbl(end_address);
        bblock_entry->last_inst->bblock = bblock_entry;
        for(int j = 0; j < num_edges; j++) {
            rc = fscanf(f_file, "%x\n", &next_bblock);
            MYASSERT(rc == 1);
            tmp_key.inst_addr = next_bblock;
            tmp = (instbbl*)(g_hash_table_lookup(hashtable, &tmp_key));
            if (tmp == NULL) {
                STATIC_PRINT ("STATIC_INFO: building bblock for address %#x for the %dth branch of %#x\n", next_bblock, j,start_address);
                struct bblock* bb_tmp = (struct bblock*) malloc (sizeof(struct bblock));
#ifdef MEM
                mems[7] += sizeof(struct bblock);
#endif
                MYASSERT(bb_tmp != NULL);
                memset(bb_tmp, 0, sizeof(struct bblock));
                bb_tmp->first_inst = build_instbbl(next_bblock);
                bb_tmp->first_inst->bblock = bb_tmp;
                bblock_entry->branches[j] = bb_tmp;
            } else {
                STATIC_PRINT ("STATIC_INFO: branch %d (%#x) for bblock %#x exists\n", j, next_bblock, start_address);
                bblock_entry->branches[j] = tmp->bblock;
            }
        }
        if (!*this_bblock && address >= bblock_entry->first_inst->inst_addr &&
                address <= bblock_entry->last_inst->inst_addr) {
            *this_bblock = bblock_entry;
        }
        rc = fscanf(f_file, "%s\n", tmp_string);
    }
    //adding one for the last dummy one
    fclose(f_file);
    return (bblock_num++);
}

void reached_merge_point(struct thread_data* ptdata) {
    //take care of the modified stuff!
    if (CTRFLOW_TAINT_STACK->alt_path) {
        INFO_PRINT(log_f, "The merge point is reached for ctrflow_taint, rollback now\n");
        rollback(ptdata, SUCCESS);
    }

    SPEC_PRINT(log_f, "The merge point is reached for ctrflow_taint\n");
    fix_taints_and_remove_from_ctrflow (ptdata, SUCCESS);
}

struct bblock* read_return_bblock(struct thread_data* ptdata, ADDRINT inst_ptr) 
{
    ADDRINT decided_address;
    struct bblock* this_bblock = 0;
    int num_bblocks = build_bblock_tree(ptdata, inst_ptr, &decided_address, &this_bblock);
    //MYASSERT(num_bblocks >= 0);
    if (num_bblocks <= 0) {
        WARN_PRINT("%d: num_bblocks is %d for address %lx\n", PIN_GetPid(), num_bblocks, (u_long) inst_ptr);
        MYASSERT (0);
        return 0;
    }

    struct bblock* list[num_bblocks+1];
    memset(list, 0, (num_bblocks+1)*sizeof(struct bblock*));
    //we update num_bblocks here with the number of bblocks
    //that are reachable. Sometimes static analysis gives
    //unreachable bblocks
    instbbl tmp_key;
    tmp_key.inst_addr = decided_address;
    instbbl* tmp = (instbbl*)(g_hash_table_lookup(hashtable, &tmp_key)); 
    MYASSERT(tmp != NULL);
    num_bblocks = find_pdoms(list, tmp->bblock); 
    
    // mcc: need a fast way of translating from inst ptr to static address
    // On image load, save the image range, map to image offset
    ADDRINT img_offset;
    img_offset = get_image_offset(img_list, inst_ptr);
    tmp_key.inst_addr = inst_ptr - img_offset;
    //tmp_key.inst_addr = inst_ptr;
    tmp = (instbbl*)(g_hash_table_lookup(hashtable, &tmp_key)); 
    if (!tmp) {
        if (this_bblock) {
#ifdef PRINT_WARNINGS
            printf("WARNING: pid %d (record: %d): still don't have bblock for address %#x, using %#x\n", 
                    PIN_GetPid(), ptdata->record_pid, inst_ptr, this_bblock->first_inst->inst_addr);
#endif
            return this_bblock;
        } else {
            WARN_PRINT("%d (record: %d): still don't have bblock for address %#x, image offset %#x\n", 
                    PIN_GetPid(), ptdata->record_pid, inst_ptr, img_offset);
            //exit(-1);
            // whelp, let's see if we can continue
            return 0;
        }
    }       
    return tmp->bblock;
}

#ifdef CTRL_FLOW
void instrument_inst_ctrflow(ADDRINT inst_ptr)
{
    
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);

    if (ptdata != plasttd) {
        if (plasttd) {
            for (int i = 0; i < NUM_REGS; i++) plasttd->saved_reg_taints[i] = reg_table[i];
            for (int i = 0; i < NUM_FLAGS; i++) plasttd->saved_flag_taints[i] = flag_table[i];
            for (int i = 0; i < NUM_REGS; i++) reg_table[i] = ptdata->saved_reg_taints[i];
            for (int i = 0; i < NUM_FLAGS; i++) flag_table[i] = ptdata->saved_flag_taints[i];
        }
        plasttd = ptdata;
    }

#ifdef ALT_PATH_EXPLORATION
    if (segfault_captured) {
        segfault_captured = 0;
        rollback(ptdata, LIMIT);
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
    total_inst_count += (NUM_CKPTS == 0);
#else
    total_inst_count++;
#endif

#ifdef FUNC_TIME
    if (total_inst_count % 100000 == 0) {
        print_function_times();
    }
#endif

    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED || ((CALLING_BBLOCK_HEAD->status & CONSERVATIVE) != 0))) {

#ifdef ALT_PATH_EXPLORATION
        NUM_INSTS += (NUM_CKPTS > 0);
#else
        NUM_INSTS++;
#endif
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
   
    if (!CURRENT_BBL || BBL_OVER) {
        //we are not in the middle of a bblock
        instbbl tmp_key;
        tmp_key.inst_addr = inst_ptr;
        instbbl* tmp = (instbbl*)(g_hash_table_lookup(hashtable, &tmp_key));
        if(tmp == NULL) {
            //INFO: reading the bblocks from the file
            SPEC_PRINT(log_f, "SPEC_INFO: no bblock for instruction %#x, about to read files...\n", inst_ptr);
            CURRENT_BBL = read_return_bblock(ptdata, inst_ptr);
            if (CURRENT_BBL == NULL) {
                RELEASE_GLOBAL_LOCK (ptdata);
                return;
            }
        } else {
            CURRENT_BBL = tmp->bblock;
        }
    } 

    if (!CTRFLOW_TAINT_STACK->merge_bblock) {
        CTRFLOW_TAINT_STACK->merge_bblock = CURRENT_BBL->ipdom;
        if (CURRENT_BBL->ipdom->size == 0) {
            if (CALLING_BBLOCK_HEAD) {
                CALLING_BBLOCK_HEAD->is_merge_point++;
                CALLING_BBLOCK_HEAD->status |= MERGE_POINT;
            } else {
                MERGE_ON_NEXT_RET++;
            }
        }
        SPEC_PRINT(log_f, "The merge point is set to %#x\n", CTRFLOW_TAINT_STACK->merge_bblock->first_inst->inst_addr);
    }
    MYASSERT(CTRFLOW_TAINT_STACK->merge_bblock);
    BBL_OVER = (inst_ptr == CURRENT_BBL->last_inst->inst_addr);

#ifdef ALT_PATH_EXPLORATION    
    if (NUM_CKPTS > 0) {
        if (NUM_INSTS >= MAX_SPEC_INSTS) {
            INFO_PRINT(log_f, "INFO: number of speculative instructions exceeded the max, rollback now\n");
            rollback(ptdata, LIMIT);
        }
	NUM_INSTS++;
    }
#endif
    if (NUM_CKPTS > 0 || CTRFLOW_TAINT_STACK->prev != 0) {
        int stack_size = 0;
        struct taint_info* cts = CTRFLOW_TAINT_STACK;
        while (cts->merge_bblock
                && (cts->merge_bblock->first_inst->inst_addr == inst_ptr)
                && (cts->calling_bblock_size == CALLING_BBLOCK_SIZE)) {
            stack_size++;
            cts = cts->prev;
        }
        if (stack_size) {
            if (stack_size == 1) {
                reached_merge_point(ptdata);
            } else {
                for (int d = stack_size; d > 0; d--) {
                    fix_taints_and_remove_from_ctrflow_stack(ptdata, SUCCESS, d);
                }
            }
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}
#endif // CTRL_FLOW

#ifdef ALT_PATH_EXPLORATION
void store_memory_locations (struct thread_data* ptdata, ADDRINT mem_loc, int size, int dir)
{
    struct alt_mem_mod* mem_entry;
    ADDRINT addr;
    char tmp_mems[size];
    struct taint* ptaint;

    GRAB_GLOBAL_LOCK (ptdata);

#ifdef CHECK_WILD_ACCESSES
    int safe = 0;
    for (int i = 0; i < num_uaddrs; i++) {
	if (mem_loc >= uaddrs[i].start && mem_loc+size-1 <= uaddrs[i].end) {
	    safe = 1;
	    break;
	}
    }
    if (!safe) {
	fprintf (stderr, "Access to memory location %#x size %d is not safe\n", mem_loc, size);
    }
#endif

    int rc = PIN_SafeCopy(tmp_mems, (ADDRINT*)(mem_loc-dir*size), (size_t)size);
    if (rc != size) {
        INFO_PRINT(log_f, "Couldn't successfully read all memory bytes, rollback now, %#x, %d, %d\n", mem_loc, dir, size);
        rollback(ptdata, LIMIT);
    }
#ifdef CHECK_WILD_ACCESSES
    if (!safe) fprintf (stderr, "Copy check failed too\n");
#endif

    for (int i = 0; i < rc; i++) {
        addr = mem_loc - dir*size + i; 

        if (!g_hash_table_lookup(CKPTS->mem_val_taints, &addr)) {

            mem_entry = (struct alt_mem_mod *) malloc (sizeof(struct alt_mem_mod));
            MYASSERT(mem_entry);

            mem_entry->address = addr;
            mem_entry->value = tmp_mems[i];
            ptaint = get_mem_taint(addr);
            mem_entry->is_tainted = (ptaint != NULL);
            if (ptaint) mem_entry->taint = *get_mem_taint(addr);
            g_hash_table_insert (CKPTS->mem_val_taints, &mem_entry->address, mem_entry);
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}
#endif

#ifdef ALT_PATH_EXPLORATION
//the reason that the I kept the memory_log although I added the hash table
//was that I didn't want to do a malloc for every address that I wanted to add
//plus sscanf works much easier with the current memory_log
void instrument_speculative_write(ADDRINT mem_loc, UINT32 reg_value, UINT32 op_size, UINT32 eflags)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    fprintf(log_f, "instrument_speculative_write called\n");
    if (NUM_CKPTS == 0) return;

    GRAB_GLOBAL_LOCK (ptdata);

    int dir = eflags & DF_MASK ? 1 : 0;
    int size = op_size * reg_value;
    if (size < 0 || size > MAX_SPEC_MEM_MODS) {
        fprintf (stderr, "speculative_write size %d - rollback\n", size);
        rollback (ptdata, LIMIT);
    }
    store_memory_locations(ptdata, mem_loc, size, dir);        

    RELEASE_GLOBAL_LOCK (ptdata);
}
#endif // end #ifdef ALT_PATH_EXPLORATION

void add_to_calling_bblock(struct thread_data* ptdata, int status, ADDRINT address, ADDRINT call_address, ADDRINT next_address)
{
    GRAB_GLOBAL_LOCK (ptdata);

    struct calling_bblock* cb = (struct calling_bblock*) malloc (sizeof(struct calling_bblock));
    MYASSERT(cb);
#ifdef MEM
    mems[8] += sizeof(struct calling_bblock);
#endif
    cb->prev = CALLING_BBLOCK_HEAD;
    cb->bblock = CURRENT_BBL;
    cb->address = address;
    cb->call_address = call_address;
    cb->next_address = next_address;
    cb->status = status;
    cb->is_merge_point = 0;
    cb->ctrflow_taint_stack_size = CTRFLOW_TAINT_STACK_SIZE;
    CALLING_BBLOCK_HEAD = cb;
    CALLING_BBLOCK_SIZE++;
    SPEC_PRINT(log_f, "adding bblock to the calling bblock log, status: %d, next_address: %#x\n", CALLING_BBLOCK_HEAD->status, next_address);
    if (CURRENT_BBL) {
        SPEC_PRINT(log_f, "%d: calling bblock curretn_bbl is set to %#x\n", 
                PIN_GetPid(), CURRENT_BBL->first_inst->inst_addr);
    } else {
        SPEC_PRINT(log_f, "%d: calling bblock curretn_bbl is set to 0\n", PIN_GetPid());
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

#ifdef ALT_PATH_EXPLORATION
void nowhere_land_check(ADDRINT target)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    GRAB_GLOBAL_LOCK (ptdata);

    if (NUM_CKPTS > 0 && !in_main_image(target)) {
        INFO_PRINT(log_f, "Flying to nowhere land, rollback now\n");
        rollback(ptdata, LIMIT);
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}
#endif

#ifdef LINKAGE_SYSCALL
void instrument_call(ADDRINT address, ADDRINT target, ADDRINT next_address)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (!main_started) { 
        return;
    }

#ifdef FUNC_TIME
    struct timeval new_time;
    gettimeofday(&new_time, NULL);
    add_stat_to_function(&new_time, total_inst_count, address);
    current_time = new_time;
    current_num_inst = total_inst_count;
#endif    

    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) {
        return;
    }
    
    GRAB_GLOBAL_LOCK (ptdata);

#ifdef ALT_PATH_EXPLORATION
    nowhere_land_check(target);
#endif
    //if the parent is conservative, you become conservative
    if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & CONSERVATIVE) != 0)) { 
        add_to_calling_bblock(ptdata, CONSERVATIVE, address, target, next_address);
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
    if (CALLING_BBLOCK_HEAD && ((CALLING_BBLOCK_HEAD->status & NO_SPEC) != 0)) {
        add_to_calling_bblock(ptdata, NO_SPEC, address, target, next_address);
    } else {
        add_to_calling_bblock(ptdata, ACCURATE, address, target, next_address);
    }
    BBL_OVER = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}
#endif // LINKAGE_SYSCALL

void instrument_hlt ()
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);
    if (NUM_CKPTS > 0) {
        INFO_PRINT(log_f, "it wants to halt!! about to rollback now\n");
        rollback(ptdata, FAIL);
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void instrument_ret(ADDRINT address, ADDRINT target)
{
#ifdef TAINT_STATS
    instrument_inst_count();
#endif
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (ptdata == NULL) return;

    GRAB_GLOBAL_LOCK (ptdata);

    if (!CALLING_BBLOCK_HEAD) {
#ifdef CTRL_FLOW
        while (MERGE_ON_NEXT_RET > 0) {
            reached_merge_point(ptdata);
            MERGE_ON_NEXT_RET--;
        }
#endif // CTRL_FLOW
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
    if (CALLING_BBLOCK_HEAD->next_address != target) {
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
#ifdef FUNC_TIME
    struct timeval new_time;
    gettimeofday(&new_time, NULL);
    add_stat_to_function(&new_time, total_inst_count, address);
    current_time = new_time;
    current_num_inst = total_inst_count;
#endif    
#ifdef CTRL_FLOW
    if ((CALLING_BBLOCK_HEAD->status & MERGE_POINT) != 0) {
        while (CALLING_BBLOCK_HEAD->is_merge_point > 0) {
            reached_merge_point(ptdata);
            CALLING_BBLOCK_HEAD->is_merge_point--;
        }
    }
#endif
    BBL_OVER = 0;
    CURRENT_BBL = 0;

    //if ctrflow_taint is 0, we don't want current_bbl
    //if (CTRFLOW_TAINT_STACK->prev) {
        instbbl tmp_key;
        instbbl* tmp = 0;
        tmp_key.inst_addr = target;
        tmp = (instbbl*)(g_hash_table_lookup(hashtable, &tmp_key));
        if (tmp) {
            CURRENT_BBL = tmp->bblock;
        } else {
            if (CALLING_BBLOCK_HEAD) {
                CURRENT_BBL = CALLING_BBLOCK_HEAD->bblock;
                if (CURRENT_BBL) {
                    SPEC_PRINT(log_f, "instrument_ret: the bblock is set to %#x\n", CURRENT_BBL->first_inst->inst_addr);
                }
            }
        }
    //}

#ifdef CTRL_FLOW
    //There are crazy cases where it's not possible to correctly
    //identify the pdoms of a branch (compile_branch in apache for instance)
    //and therefore, we can't automatically eliminate the taint added to 
    //CTRFLOW_TAINT_STACK.
    while (CTRFLOW_TAINT_STACK_SIZE != CALLING_BBLOCK_HEAD->ctrflow_taint_stack_size) {
#ifdef PRINT_WARNINGS
        fprintf(stderr, "WARNING: the size of ctrflow stack at the end of function %d and at the begining %d "
                "are not matching, address is %#x, target is %#x\n", CTRFLOW_TAINT_STACK_SIZE, CALLING_BBLOCK_HEAD->ctrflow_taint_stack_size, address, target);
#endif
        fix_taints_and_remove_from_ctrflow (ptdata, SUCCESS);
    }
#endif // CTRL_FLOW

    // remove calling bblock head
    struct calling_bblock* tmp_head = CALLING_BBLOCK_HEAD;

    if (tmp_head == NULL) {
        goto close;
    }

#ifdef TRACE_TAINTS
    for (int spaces = 0; spaces < (CALLING_BBLOCK_SIZE-1); spaces++) {
        fprintf(TRACE_F, "\t");
        fflush(TRACE_F);
    }
    fprintf(TRACE_F, "ret %#x (%#x) (return of %#x (%#x)) CTRFLOW_STACK_SIZE %d CALLING_BBLOCK_HEAD size %d\n",
            address, (unsigned int) get_static_address(img_list, address), tmp_head->call_address,
            (unsigned int) get_static_address(img_list, tmp_head->call_address),
            CTRFLOW_TAINT_STACK_SIZE, CALLING_BBLOCK_SIZE);
#endif
    CALLING_BBLOCK_HEAD = tmp_head->prev;
    free (tmp_head);
#ifdef MEM
    mems[8] -= sizeof(struct calling_bblock);
#endif
    CALLING_BBLOCK_SIZE--;

close:
    RELEASE_GLOBAL_LOCK (ptdata);
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

#ifdef LOGGING_ON
void instrument_inst(ADDRINT inst_ptr, ADDRINT next_addr, ADDRINT target, ADDRINT sp, ADDRINT opcode)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);

    if (print_first_inst) {
        LOG_PRINT ("first inst: %#x, sp %#x\n", inst_ptr, sp);
        print_first_inst = 0;

#ifdef TRACK_MEMORY_AREAS
        if (add_memory_area (ma_list, sp, sp + STACK_SIZE)) {
            MEM_PRINT (MEM_F, "Could not add stack [%#x, %#x)\n", sp, sp + STACK_SIZE);
        }
        LOG_PRINT ("Added stack [%#x, %#x)\n", sp, sp+STACK_SIZE);
#endif
    }

#if 0
    PIN_LockClient();
    fprintf(LOG_F, "[INST] Pid %d (tid: %d) (record %d) - %#x\n", PIN_GetPid(), PIN_GetTid(), get_record_pid(), inst_ptr);
    if (IMG_Valid(IMG_FindByAddress(inst_ptr))) {
        fprintf(LOG_F, "%s -- img %s static %#x\n", RTN_FindNameByAddress(inst_ptr).c_str(), IMG_Name(IMG_FindByAddress(inst_ptr)).c_str(), find_static_address(inst_ptr));
        PIN_UnlockClient();
    } else {
        PIN_UnlockClient();
    }
#endif

    // Count instructios
    inst_count++;
#ifdef LOGGING_ON
    if ((inst_count % INST_COUNT_INCREMENT) == 0) {
        LOG_PRINT ("inst count is %lu, inst_ptr is %#x\n", inst_count, inst_ptr);
	LOG_PRINT ("num options is %d\n", option_cnt);
    }
#endif

#if 0
    if (opcode == XED_ICLASS_RET_NEAR || opcode == XED_ICLASS_RET_FAR) {
#ifndef CTRL_FLOW
        if (CALLING_BBLOCK_SIZE != 0) {
#endif
            instrument_ret(inst_ptr, target);
#ifndef CTRL_FLOW
        }
#endif
    }
#endif
/*
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED || ((CALLING_BBLOCK_HEAD->status & CONSERVATIVE) != 0))) {
        if (opcode == XED_ICLASS_RET_NEAR || opcode == XED_ICLASS_RET_FAR) {
            //LOG_PRINT ("Inst %#x ret (handled)\n", inst_ptr);
//#ifdef CTRL_FLOW
            instrument_ret(inst_ptr, target);
//#endif
        } else {
            //LOG_PRINT("Inst %#x (handled)\n", inst_ptr);
        }
    } else {
        if (opcode == XED_ICLASS_RET_NEAR || opcode == XED_ICLASS_RET_FAR) {
            //LOG_PRINT("Inst %#x ret\n", inst_ptr);
            //instrument_ret(inst_ptr, target);
        } else {
            //LOG_PRINT("Inst %#x\n", inst_ptr);
        }
    }
*/
    RELEASE_GLOBAL_LOCK (ptdata);
}
#endif // LOGGING_ON

void track_file(INS ins, void *v) 
{
    CALLBACK_PRINT(log_f, "CALLBACK_PRINT: track file starts\n");
    OPCODE opcode;
    UINT32 category;
#ifdef CTRL_FLOW
    UINT32 mask;
#endif
    category = INS_Category(ins);
    opcode = INS_Opcode(ins);
    int instrumented = 0;

#ifdef LOGGING_ON
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)instrument_inst, IARG_INST_PTR, 
            IARG_ADDRINT, INS_NextAddress(ins),
            IARG_BRANCH_TARGET_ADDR, IARG_REG_VALUE, LEVEL_BASE::REG_ESP, IARG_UINT32, opcode, IARG_END);
#endif

#ifdef CTRL_FLOW
        switch(opcode) {
            case XED_ICLASS_JMP:
            case XED_ICLASS_JMP_FAR:
                INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                if (INS_OperandIsReg(ins, 0)) {
                    INSTRUMENT_PRINT(log_f, "%#x: register %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                    REG target_reg = INS_OperandReg(ins, 0);
                    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_ctrflow_jmp),
                            IARG_UINT32, target_reg, IARG_END);
                } else if (INS_OperandIsMemory(ins, 0)) {
                    REG index_reg = INS_OperandMemoryIndexReg(ins, 0);
                    if (REG_valid(index_reg)) {
                        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_ctrflow_jmp), IARG_UINT32, index_reg, IARG_END);
                    }
                } else {
                    INSTRUMENT_PRINT(log_f, "%#x: about to NOT instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                }
                break;

            case XED_ICLASS_JB:
            case XED_ICLASS_JNB:
                instrumented = 1;
                INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(taint_ctrflow_flag), IARG_UINT32, CF_FLAG, IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(chase_address), 
                                        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
                                        //IARG_CONTEXT, IARG_CHECKPOINT, IARG_PTR, xor_op, IARG_UINT32, CF_MASK, IARG_END);
                                        IARG_CONTEXT, IARG_PTR, xor_op, IARG_UINT32, CF_MASK, IARG_END);
                break;
                                           
            case XED_ICLASS_JBE:
            case XED_ICLASS_JNBE:
                instrumented = 1;
                INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(taint_ctrflow_flags), 
                                IARG_UINT32, CF_FLAG, IARG_UINT32, ZF_FLAG, IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(chase_address), 
                                        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
                                        //IARG_CONTEXT, IARG_CHECKPOINT, IARG_PTR, jbe_op, IARG_UINT32, 0, IARG_END);
                                        IARG_CONTEXT, IARG_PTR, jbe_op, IARG_UINT32, 0, IARG_END);
                break;

            case XED_ICLASS_JL:
            case XED_ICLASS_JNL:
                instrumented = 1;
                INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(taint_ctrflow_flags), 
                                IARG_UINT32, SF_FLAG, IARG_UINT32, OF_FLAG, IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(chase_address), 
                                        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
                                        //IARG_CONTEXT, IARG_CHECKPOINT, IARG_PTR, xor_op, IARG_UINT32, SF_MASK, IARG_END);
                                        IARG_CONTEXT, IARG_PTR, xor_op, IARG_UINT32, SF_MASK, IARG_END);
                break;
            
            case XED_ICLASS_JLE:
            case XED_ICLASS_JNLE:
                instrumented = 1;
                INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(taint_ctrflow_sf_of_zf), IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(chase_address), 
                                        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
                                        //IARG_CONTEXT, IARG_CHECKPOINT, IARG_PTR, jle_op, IARG_UINT32, 0, IARG_END);
                                        IARG_CONTEXT, IARG_PTR, jle_op, IARG_UINT32, 0, IARG_END);
                break;

            case XED_ICLASS_JNO:
            case XED_ICLASS_JO:
                instrumented = 1;
                INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(taint_ctrflow_flag), IARG_UINT32, OF_FLAG, IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(chase_address), 
                                        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
                                        //IARG_CONTEXT, IARG_CHECKPOINT, IARG_PTR, xor_op, IARG_UINT32, OF_MASK, IARG_END);
                                        IARG_CONTEXT, IARG_PTR, xor_op, IARG_UINT32, OF_MASK, IARG_END);
                break;
            
            case XED_ICLASS_JNP:
            case XED_ICLASS_JP:
                instrumented = 1;
                INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(taint_ctrflow_flag), IARG_UINT32, PF_FLAG, IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(chase_address), 
                                        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
                                        //IARG_CONTEXT, IARG_CHECKPOINT, IARG_PTR, xor_op, IARG_UINT32, PF_MASK, IARG_END);
                                        IARG_CONTEXT, IARG_PTR, xor_op, IARG_UINT32, PF_MASK, IARG_END);
                break;

            case XED_ICLASS_JNS:
            case XED_ICLASS_JS:
                instrumented = 1;
                INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(taint_ctrflow_flag), IARG_UINT32, SF_FLAG, IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(chase_address), 
                                        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
                                        //IARG_CONTEXT, IARG_CHECKPOINT, IARG_PTR, xor_op, IARG_UINT32, SF_MASK, IARG_END);
                                        IARG_CONTEXT, IARG_PTR, xor_op, IARG_UINT32, SF_MASK, IARG_END);
                break; 
            
            case XED_ICLASS_JNZ:
            case XED_ICLASS_JZ:
                instrumented = 1;
                INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s, %#x\n", INS_Address(ins), INS_Mnemonic(ins).c_str(), *((char*)INS_Address(ins)));
                INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(taint_ctrflow_flag), IARG_UINT32, ZF_FLAG, IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(chase_address), 
                                        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
                                        //IARG_CONTEXT, IARG_CHECKPOINT, IARG_PTR, xor_op, IARG_UINT32, ZF_MASK, IARG_END);
                                        IARG_CONTEXT, IARG_PTR, xor_op, IARG_UINT32, ZF_MASK, IARG_END);
                break;
            
        } // end switch(opcode)
#else
        switch(opcode) {
            case XED_ICLASS_JB:
            case XED_ICLASS_JNB:
            case XED_ICLASS_JBE:
            case XED_ICLASS_JNBE:
            case XED_ICLASS_JLE:
            case XED_ICLASS_JNLE:
            case XED_ICLASS_JNO:
            case XED_ICLASS_JO:
            case XED_ICLASS_JNS:
            case XED_ICLASS_JS:
            case XED_ICLASS_JNZ:
            case XED_ICLASS_JZ:
                instrumented = 1;
                break;
        }
#endif  // CTRL_FLOW

#ifdef CTRL_FLOW
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)instrument_inst_ctrflow, IARG_INST_PTR, IARG_END);
#endif

#ifdef CTRL_FLOW
#ifdef ALT_PATH_EXPLORATION
        if (INS_IsMemoryWrite(ins)) {
            if((opcode == XED_ICLASS_STOSB || opcode == XED_ICLASS_STOSW || opcode == XED_ICLASS_STOSD ||
                        opcode == XED_ICLASS_STOSQ || opcode == XED_ICLASS_MOVSB || opcode == XED_ICLASS_MOVSW || 
                        opcode == XED_ICLASS_MOVSD || opcode == XED_ICLASS_MOVSQ) && INS_RepPrefix(ins)) {
                UINT32 opw = INS_OperandWidth(ins, 0);
                REG reg = LEVEL_BASE::REG_ECX;
                if (opw == 16) 
                    reg = REG_CX;

                UINT32 size = opw/8;
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)instrument_speculative_write, IARG_MEMORYWRITE_EA, IARG_REG_VALUE, 
                        reg, IARG_UINT32, size, IARG_REG_VALUE, REG_EFLAGS, IARG_END);
            } else {
                UINT32 addrsize = INS_MemoryWriteSize(ins);
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)instrument_speculative_write, IARG_MEMORYWRITE_EA, IARG_UINT32, 
                        addrsize, IARG_UINT32, 1, IARG_REG_VALUE, REG_EFLAGS, IARG_END);
            }
        }
#endif // ALT_PATH_EXPLORATION
#endif // CTRL_FLOW

        if (instrumented) {
            INSTRUMENT_PRINT(log_f, "%#X: already instrumented\n", INS_Address(ins));
            return;
        }

        if(INS_IsMov(ins)) {
#ifdef LINKAGE_COPY
            INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
            //flag affected: none
            instrument_mov(ins);
#endif

        } else if(category == XED_CATEGORY_CMOV) {
#ifdef LINKAGE_COPY
            //flag affected: none, propagated flags
            INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
            instrument_cmov(ins, opcode);
#endif

        } else if (category == XED_CATEGORY_SHIFT) {
#ifdef LINKAGE_DATA
            //flags affected: almost all, some are undefined in some cases
            INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
            instrument_shift(ins);
#endif
        } else {
            switch(opcode) {
                case XED_ICLASS_XCHG:
                    //flags affected: none
#ifdef LINKAGE_DATA
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument xchg\n", INS_Address(ins));
                    instrument_xchg(ins);
#endif
                    break;

                case XED_ICLASS_LEAVE:
                case XED_ICLASS_NOT:
                    INSTRUMENT_PRINT(log_f, "%#x: nothing is done for instruction %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                    break;

                case XED_ICLASS_MOVSX:
                case XED_ICLASS_MOVZX:
                case XED_ICLASS_MOVD:
                case XED_ICLASS_MOVQ:
                case XED_ICLASS_MOVDQU:
                case XED_ICLASS_MOVDQA:
#ifdef LINKAGE_COPY
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                    //flag affected: none
                    instrument_movx(ins);
#endif
                    break;
                case XED_ICLASS_PUSH:
#ifdef LINKAGE_DATA
                    //flags affected: none
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument push\n", INS_Address(ins));
                    instrument_push(ins);
#endif
                    break;

                case XED_ICLASS_POP:
#ifdef LINKAGE_DATA
                    //flags affected: none
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument pop\n", INS_Address(ins));
                    instrument_pop(ins);
#endif
                    break;
                
                case XED_ICLASS_ADC:
#ifdef LINKAGE_DATA
                    //flags affected: all
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument adc\n", INS_Address(ins));
                    instrument_adc(ins);
#endif
                    break;

                case XED_ICLASS_ADD:
                case XED_ICLASS_SUB:
#ifdef LINKAGE_DATA
                    //flags affected: all
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument addorsub\n", INS_Address(ins));
                    instrument_addorsub(ins);
#endif
                    break;

                case XED_ICLASS_SBB:                
#ifdef LINKAGE_DATA
                    //flags affected: all
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument sbb\n", INS_Address(ins));
                    instrument_adc(ins);
#endif
                    break;

                case XED_ICLASS_OR:
                case XED_ICLASS_AND:
                case XED_ICLASS_XOR:
#ifdef LINKAGE_DATA
                    //flags affected: all but AF (AF is undefined)
                    //TODO: this taints all the flags, should be carefull about AF
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument logical\n", INS_Address(ins));
                    instrument_addorsub(ins);
#endif
                    break;

                case XED_ICLASS_POR:
                case XED_ICLASS_PAND:
                case XED_ICLASS_PANDN:
                case XED_ICLASS_PXOR:
#ifdef LINKAGE_DATA
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument logical, no flags\n", INS_Address(ins));
                    instrument_addorsub_noflags(ins);
#endif
                    break;

                case XED_ICLASS_MUL:
#ifdef LINKAGE_DATA
                    //flags affected: CF and OF, the rest are undefined
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument mul\n", INS_Address(ins));
                    instrument_mul(ins);
#endif
                    break;

                case XED_ICLASS_IMUL:
#ifdef LINKAGE_DATA
                    //flags affected: CF and OF, the rest are undefined
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument mul\n", INS_Address(ins));
                    instrument_imul(ins);
#endif
                    break;
                
                case XED_ICLASS_DIV:
                case XED_ICLASS_IDIV:
#ifdef LINKAGE_DATA
                    //flags affected: all flags are undefined
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument div\n", INS_Address(ins));
                    instrument_div(ins);
#endif
                    break;
                
                case XED_ICLASS_XADD:
#ifdef LINKAGE_DATA
                    //flags affected: all 
                    INSTRUMENT_PRINT(log_f, "%#x: about to instruent xadd\n", INS_Address(ins));
                    instrument_xadd(ins);
#endif
                    break;

                case XED_ICLASS_MOVSB:
                case XED_ICLASS_MOVSW:
                case XED_ICLASS_MOVSD:
                case XED_ICLASS_MOVSQ:
#ifdef LINKAGE_COPY
                    //flags affected: none
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument move string\n", INS_Address(ins));
                    instrument_move_string(ins, opcode);
#endif
                    break;
                
                case XED_ICLASS_STOSB:
                case XED_ICLASS_STOSW:
                case XED_ICLASS_STOSD:
                case XED_ICLASS_STOSQ:
// XXX Is this a copy or a data linkage?
#ifdef LINKAGE_COPY
                    //flags affected: none
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument store string\n", INS_Address(ins));
                    instrument_store_string(ins, opcode);
#endif
                    break;
                
                case XED_ICLASS_LODSB:
                case XED_ICLASS_LODSW:
                case XED_ICLASS_LODSD:
                case XED_ICLASS_LODSQ:
// XXX Is this a copy or a data linkage?
#ifdef LINKAGE_DATA
                    //flags affected: none
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument load string\n", INS_Address(ins));
                    instrument_load_string(ins, opcode);
#endif
                    break;

                case XED_ICLASS_LEA:
#ifdef LINKAGE_DATA
                    //flags affected: none
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument LEA\n", INS_Address(ins));
                    instrument_lea(ins);
#endif
                    break;
                
                case XED_ICLASS_CVTSD2SS:
                case XED_ICLASS_CVTTSD2SI:
#ifdef LINKAGE_COPY
                    //flags affected: none
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument CVTSD2SS\n", INS_Address(ins));
                    instrument_mov(ins);
#endif
                    break;

                case XED_ICLASS_FADD:
                case XED_ICLASS_FADDP:
                case XED_ICLASS_FIADD:
                case XED_ICLASS_FSUB: 
                case XED_ICLASS_FSUBP:
                case XED_ICLASS_FISUB:
                case XED_ICLASS_FSUBR:
                case XED_ICLASS_FSUBRP:
                case XED_ICLASS_FISUBR:
#ifdef LINKAGE_DATA
                    //flags affected: FPU flags are affected. not considered now
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument FADD/FSUB\n", INS_Address(ins));
                    old_instrument_addorsub(ins);
#endif
                    break;

                case XED_ICLASS_FXCH:
#ifdef LINKAGE_DATA
                    //flags affected: FPU flags
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument FXCH\n", INS_Address(ins));
                    instrument_xchg(ins);
#endif
                    break;

                case XED_ICLASS_FYL2X:
                case XED_ICLASS_FYL2XP1:
#ifdef LINKAGE_DATA
                    //flags affected: FPU flags
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument FYL2X\n", INS_Address(ins));
                    old_instrument_addorsub(ins);
#endif
                    break;
                
                /*case XED_ICLASS_PACKSSWB:
                    //flags affected: none
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument PACK\n", INS_Address(ins));
                    old_instrument_addorsub(ins);
                    break;
		*/

                
                case XED_ICLASS_PADDB:
                case XED_ICLASS_PADDW:
                case XED_ICLASS_PADDD:
                case XED_ICLASS_PSUBB:
                case XED_ICLASS_PSUBW:
                case XED_ICLASS_PSUBD:
                case XED_ICLASS_PSUBQ:

	            case XED_ICLASS_PMADDWD:
                case XED_ICLASS_PMULHUW:
		/*
                case XED_ICLASS_PAND:
                case XED_ICLASS_PAVGB:
                case XED_ICLASS_PAVGW:
                case XED_ICLASS_PMAXUB:
                case XED_ICLASS_PMINUB:
                case XED_ICLASS_POR:
                case XED_ICLASS_PXOR:
                case XED_ICLASS_XORPS:
		*/
                    //flags affected: none
#ifdef LINKAGE_DATA
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument PADDX/PSUBX/PMADDWD/PMULHUW\n", INS_Address(ins));
                    instrument_paddx_or_psubx(ins);
#endif
                    break;
                
                case XED_ICLASS_PUNPCKHBW:
                case XED_ICLASS_PUNPCKHWD:
                case XED_ICLASS_PUNPCKHDQ:
                case XED_ICLASS_PUNPCKHQDQ:
                case XED_ICLASS_PUNPCKLBW:
                case XED_ICLASS_PUNPCKLWD:
                case XED_ICLASS_PUNPCKLDQ:
                case XED_ICLASS_PUNPCKLQDQ:
#ifdef LINKAGE_DATA
                    // no flags affected
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument PUNPCK\n", INS_Address(ins));
                    old_instrument_addorsub(ins);
#endif
                    break;
                case XED_ICLASS_PCMPEQB:
                case XED_ICLASS_PCMPEQW:
                case XED_ICLASS_PCMPEQD:
                case XED_ICLASS_PCMPGTB:
#ifdef LINKAGE_DATA
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument PCMPEQB\n", INS_address(ins));
                    instrument_pcmpeqx(ins);
#endif
                    break;
                case XED_ICLASS_PSHUFD:
#ifdef LINKAGE_DATA
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument PSHUFD\n", INS_address(ins));
                    instrument_set_src2dst(ins);
#endif
                    break;
                case XED_ICLASS_PMOVMSKB:
#ifdef LINKAGE_DATA
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument PMOVMSKB\n", INS_address(ins));
                    instrument_set_src2dst(ins);
#endif
                    break;

                case XED_ICLASS_PALIGNR:
#ifdef LINKAGE_DATA
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument PALIGNR\n", INS_address(ins));
                    instrument_palign(ins);
#endif
                    break;

                case XED_ICLASS_PSLLW:
                case XED_ICLASS_PSLLD:
                case XED_ICLASS_PSLLQ:
                case XED_ICLASS_PSLLDQ:
#ifdef LINKAGE_DATA
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument PSLLX\n", INS_address(ins));
                    instrument_psllx(ins);
#endif
                    break;

                case XED_ICLASS_PSRAD:
                case XED_ICLASS_PSRAW:
#ifdef LINKAGE_DATA
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument PSRAD:\n", INS_address(ins));
                    instrument_psllx(ins);
#endif
                    break;

                case XED_ICLASS_PACKSSDW:
#ifdef LINKAGE_DATA

                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument PACKSSDW:\n", INS_address(ins));
                    instrument_paddx_or_psubx(ins);
#endif
                    break;

                case XED_ICLASS_TEST:
#ifdef CTRL_FLOW
                    //flags affected: all for CMP, all but AF for TEST. we are being conservative for TEST
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument TEST\n", INS_Address(ins));
                    instrument_test(ins);
#endif
                    break;
                
                case XED_ICLASS_CMP:
#ifdef CTRL_FLOW
                    //flags affected: all for CMP, all but AF for TEST. we are being conservative for TEST
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument CMP\n", INS_Address(ins));
                    instrument_cmp(ins);
#endif
                    break;
                
                case XED_ICLASS_CMPXCHG:
#ifdef LINKAGE_DATA
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument CMPXCHNG\n", INS_Address(ins));
                    instrument_cmpxchg(ins);
#endif
                    break;
                
                case XED_ICLASS_INC:
                case XED_ICLASS_DEC:
                case XED_ICLASS_NEG:
#ifdef LINKAGE_DATA
                    //flags affected: all but CF
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument INC/DEC\n", INS_Address(ins));
                    instrument_incordec(ins);
#endif
                    break;
                
                case XED_ICLASS_SETB:
                case XED_ICLASS_SETNB:
#ifdef CTRL_FLOW
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument SETcc\n", INS_Address(ins));
                    mask = CF_MASK;
                    instrument_setcc(ins, mask);
#endif
                    break;

                case XED_ICLASS_SETL:
                case XED_ICLASS_SETNL:
#ifdef CTRL_FLOW
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument SETcc\n", INS_Address(ins));
                    mask = SF_MASK | OF_MASK;
                    instrument_setcc(ins, mask);
#endif
                    break;

                case XED_ICLASS_SETNBE:
                case XED_ICLASS_SETBE:
#ifdef CTRL_FLOW
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument SETcc\n", INS_Address(ins));
                    mask = CF_MASK | ZF_MASK;
                    instrument_setcc(ins, mask);
#endif
                    break;
                
                case XED_ICLASS_SETLE:
                case XED_ICLASS_SETNLE:
#ifdef CTRL_FLOW
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument SETcc\n", INS_Address(ins));
                    mask = ZF_MASK | SF_MASK | OF_MASK;
                    instrument_setcc(ins, mask);
#endif
                    break;

                case XED_ICLASS_SETNO:
                case XED_ICLASS_SETO:
#ifdef CTRL_FLOW
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument SETcc\n", INS_Address(ins));
                    mask = OF_MASK;
                    instrument_setcc(ins, mask);
#endif
                    break;

                case XED_ICLASS_SETNP:
                case XED_ICLASS_SETP:
#ifdef CTRL_FLOW
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument SETcc\n", INS_Address(ins));
                    mask = PF_MASK;
                    instrument_setcc(ins, mask);
#endif
                    break;

                case XED_ICLASS_SETNS:
                case XED_ICLASS_SETS:
#ifdef CTRL_FLOW
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument SETcc\n", INS_Address(ins));
                    mask = SF_MASK;
                    instrument_setcc(ins, mask);
#endif
                    break;

                case XED_ICLASS_SETZ:
                case XED_ICLASS_SETNZ:
#ifdef CTRL_FLOW
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument SETcc\n", INS_Address(ins));
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument SETcc\n", INS_Address(ins));
                    mask = ZF_MASK;
                    instrument_setcc(ins, mask);
#endif
                    break;
                
                case XED_ICLASS_CALL_NEAR:
                case XED_ICLASS_CALL_FAR:
#ifdef LINKAGE_SYSCALL
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument a call instruction: %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_call), IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
				   IARG_ADDRINT, INS_NextAddress(ins), IARG_END);
#endif

                   break;
                
                case XED_ICLASS_RET_NEAR:
                case XED_ICLASS_RET_FAR:
#ifdef LINKAGE_SYSCALL
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument ret instruction: %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_ret), IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);    
#endif
                    break;
                case XED_ICLASS_CWD:
                case XED_ICLASS_CDQ:
#ifdef LINKAGE_DATA
                    //flags affected: none
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument CWD/CDQ\n", INS_Address(ins));
                    instrument_cdq(ins);
#endif
                    break;
                
                case XED_ICLASS_HLT:
#ifdef LINKAGE_DATA
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument HLT\n", INS_Address(ins));
                    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_hlt), IARG_END);   
#endif
                    break;

                //uninstrumented insts.
                case XED_ICLASS_JMP:
                case XED_ICLASS_JMP_FAR:
#ifdef ALT_PATH_EXPLORATION
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument jmp %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(nowhere_land_check), IARG_BRANCH_TARGET_ADDR, IARG_END);
#endif
                    break;

                case XED_ICLASS_BT:
#ifdef CTRL_FLOW
                    // flags affected: CF
                    INSTRUMENT_PRINT(log_f, "%#x: about to instrument bt %s\n", INS_Address(ins), INS_Mnemonic(ins).c_str());
                    instrument_bt(ins);
#endif
                    break;
                case XED_ICLASS_CLD:
#ifdef CTRL_FLOW
                    INSTRUMENT_PRINT(log_,f "%#x: about to instrument cld %s\n", INS_Address(ins), INS_Mneomic(ins).c_str());
                    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(taint_clear_flag), UINT32, DF_FLAG, IARG_END);
#endif
                    break;

                case XED_ICLASS_MOVAPS:
                case XED_ICLASS_MOVLPD:
                case XED_ICLASS_MOVHPD:
#ifdef LINKAGE_COPY
                    instrument_movaps(ins);
#endif
                    break;

                case XED_ICLASS_BSWAP:
                case XED_ICLASS_ROR:
                case XED_ICLASS_ROL:
                case XED_ICLASS_CWDE:
                case XED_ICLASS_CBW:
                case XED_ICLASS_CDQE:
                    // No taint propogation here
                    break;

                case XED_ICLASS_BSF:
                case XED_ICLASS_BSR:
                    instrument_set_src2dst(ins);
                    break;

                case XED_ICLASS_XGETBV:
#ifdef LINKAGE_DATA
                    instrument_xgetbv(ins);
#endif
                    break;

                case XED_ICLASS_CPUID:
                    INSTRUMENT_PRINT(log_f, "%#x: not instrument cpuid\n", INS_Address(ins));
                    break;

                default:
                    {
                        // these types of instructions are purposefully left uninstrumented
                        if (INS_IsNop(ins)) {
                            INSTRUMENT_PRINT(log_f, "%#x: not instrument noop %s\n", INS_Address(ins), INS_Disassemble(ins).c_str());
                            break;
                        }
                        if (INS_IsInterrupt(ins)) {
                            INSTRUMENT_PRINT(log_f, "%#x: not instrument an interrupt\n", INS_Address(ins));
                            break;
                        }
                        if (INS_IsRDTSC(ins)) {
                            INSTRUMENT_PRINT(log_f, "%#x: not instrument an rdtsc\n", INS_Address(ins));
                            break;
                        }
                        ERROR_PRINT(log_f, "[NOOP] ERROR: instruction %s is not instrumented, address: %#x\n", INS_Disassemble(ins).c_str(), (unsigned)INS_Address(ins));
                        INSTRUMENT_PRINT(log_f, " instruction category %d, %s, opcode: %d, %s\n", category, CATEGORY_StringShort(category).c_str(), opcode, INS_Mnemonic(ins).c_str());
                    }
            }
        } 
    
    if(INS_IsSyscall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_syscall), IARG_SYSCALL_NUMBER,
                IARG_SYSARG_VALUE, 0, 
                IARG_SYSARG_REFERENCE, 0,
                IARG_SYSARG_VALUE, 1, 
                IARG_SYSARG_VALUE, 2, 
                IARG_SYSARG_VALUE, 3, 
                IARG_SYSARG_VALUE, 4, 
                IARG_END);    
    } else {
#ifdef HAVE_REPLAY
#if 0
        // Ugh - I guess we have to instrument every instruction to find which
        // ones are after a system call - would be nice to do better.
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)syscall_instr_after, IARG_INST_PTR, IARG_END);
#endif
#endif
    }    
}

void initialize_functions() 
{
    int index = 0;
    while(functions[index].name != 0) {
        g_hash_table_insert(functions_hash, (char *) functions[index].name, &(functions[index].status));
        index++;
    }
}

struct handled_function* make_handled_function(struct thread_data* ptdata, const char* name, unsigned special_value)
{
    struct handled_function* hf = (struct handled_function*) malloc (sizeof(struct handled_function));
    MYASSERT(hf != NULL);
#ifdef MEM
    mems[9] += sizeof(struct handled_function);
#endif
    strcpy(hf->name, name);
    hf->special_value = special_value;
    new_taint(&hf->args_taint);
    hf->prev = HANDLED_FUNC_HEAD;
    HANDLED_FUNC_HEAD = hf;
    //calling bblock head should not be NULL
    //unless we are doing something crazy like using
    //handled functions when config file is not open yet
    if (CALLING_BBLOCK_HEAD) {
        CALLING_BBLOCK_HEAD->prev_status = CALLING_BBLOCK_HEAD->status;
        CALLING_BBLOCK_HEAD->status = HANDLED;
#ifdef HANDLED_FUNCTION_DEBUG
        strcpy(CALLING_BBLOCK_HEAD->name, name);
#endif
    }
    
    SPEC_PRINT(log_f, "making handled function %s\n", name);
    return hf;
}

inline void free_handled_function(struct thread_data* ptdata)
{
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    HANDLED_FUNC_HEAD = hf->prev;
    free (hf);
#ifdef MEM
    mems[9] -= sizeof(struct handled_function);
#endif
}

void generic_string_start(ADDRINT first_arg, ADDRINT name)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) {
        return;
    }

    GRAB_GLOBAL_LOCK (ptdata);
    struct taint* arg_taint;
    struct handled_function* hf = make_handled_function(ptdata, (char*)name, first_arg);
    //the special value means whether the argument had taint or not
    char dest_char;
    while(1) {
        arg_taint = get_mem_taint(first_arg);
        merge_taints(&hf->args_taint, arg_taint);
        if ((PIN_SafeCopy(&dest_char, (const void*)first_arg, 1) != 1) || (dest_char == '\0'))
            break;
        first_arg++;
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

struct socket_info {
    int domain;
    int type;
};

void socket_start(ADDRINT domain, ADDRINT type)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("socket");
    GRAB_GLOBAL_LOCK (ptdata);

    struct socket_info* si = (struct socket_info*) malloc(sizeof(struct socket_info));
    si->domain = domain;
    si->type = type;

    make_handled_function(ptdata, "socket", (ADDRINT)si);
    
    RELEASE_GLOBAL_LOCK (ptdata);
}

void socket_stop(ADDRINT fd)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("socket");

    GRAB_GLOBAL_LOCK (ptdata);


    struct socket_info* si = (struct socket_info*)hf->special_value;
    free(si);

    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);

    RELEASE_GLOBAL_LOCK (ptdata);
}

struct socketpair_info {
    int*   pair;
    int    domain;
    int    type;
};

void socketpair_start(ADDRINT domain, ADDRINT type, ADDRINT pair)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("socketpair");
    GRAB_GLOBAL_LOCK (ptdata);

    struct socketpair_info* si = (struct socketpair_info*)malloc(sizeof(struct socketpair_info));
    si->pair = (int *) pair;
    si->domain = (int)domain;
    si->type = (int)type;
    make_handled_function(ptdata, "socketpair", (ADDRINT)si);

    RELEASE_GLOBAL_LOCK (ptdata);
}

// On Linux, the only supported domain for this call is AF_UNIX (or synonymously, AF_LOCAL).  (Most implementations have the same restriction.)
void socketpair_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("socketpair");
    GRAB_GLOBAL_LOCK (ptdata);

    struct socketpair_info* si = (struct socketpair_info*)hf->special_value;
   
    for (int i = 0; i < 2*(int)sizeof(int); i++) {
        mem_clear_dependency(ptdata, (ADDRINT)(si->pair) + i);
    }
    free(si);
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);

    RELEASE_GLOBAL_LOCK (ptdata);
}

struct bind_connect_info {
    int fd;
    int send_req_id;
    int port; // for side channel
    char* path;
};

void bind_connect_start(ADDRINT fd, ADDRINT sockaddr, ADDRINT name)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;

    GRAB_GLOBAL_LOCK (ptdata);

    struct bind_connect_info* bci = (struct bind_connect_info *) malloc(sizeof(struct bind_connect_info));
    bci->fd = fd;

    make_handled_function(ptdata, (char*)name, (ADDRINT) bci);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void bind_connect_stop(ADDRINT res, ADDRINT name)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    if (!hf || strcmp(hf->name, (char*)name)) return;

    GRAB_GLOBAL_LOCK (ptdata);

    struct bind_connect_info* bci = (struct bind_connect_info *) hf->special_value;

    free(bci);
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);

    RELEASE_GLOBAL_LOCK (ptdata);
}

void dup2_start(ADDRINT fd, ADDRINT fd_ref)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("dup2");

    GRAB_GLOBAL_LOCK (ptdata);

    struct handled_function* hf = make_handled_function(ptdata, "dup2", fd);
    for (int i =0 ; i < (int)sizeof(int); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(fd_ref + i));
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

void dup2_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("dup2");

    GRAB_GLOBAL_LOCK (ptdata);

    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);

    RELEASE_GLOBAL_LOCK (ptdata);
}

struct fcntl_info {
    int fd;
    int cmd;
    int value;
};

void fcntl_start(ADDRINT fd, ADDRINT fd_ref, ADDRINT cmd, ADDRINT value)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("fcntl");
    GRAB_GLOBAL_LOCK (ptdata);

    struct handled_function* hf = make_handled_function(ptdata, "fcntl", 0);

    struct fcntl_info* fi = (struct fcntl_info*) malloc(sizeof(struct fcntl_info));
    fi->fd = (int)fd;
    fi->cmd = (int)cmd;
    fi->value = (int)value;
    hf->special_value = (ADDRINT)fi;

    for (int i =0 ; i < (int)sizeof(int); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(fd_ref + i));
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

void fcntl_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("fcntl");

    GRAB_GLOBAL_LOCK (ptdata);
    struct fcntl_info* fi = (struct fcntl_info*)hf->special_value;

    free(fi);
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);

    RELEASE_GLOBAL_LOCK (ptdata);
}

void listen_start(ADDRINT fd)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("listen");

    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "listen", fd);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void listen_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("listen");

    GRAB_GLOBAL_LOCK (ptdata);

    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);

    RELEASE_GLOBAL_LOCK (ptdata);
}

struct accept_info {
    int              fd;
    struct sockaddr* addr;
    int*             len;
};

void accept_start(ADDRINT fd, ADDRINT fd_ref, ADDRINT addr, ADDRINT len)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("accept");

    GRAB_GLOBAL_LOCK (ptdata);

    struct accept_info* info = (struct accept_info*)malloc(sizeof(struct accept_info));
    MYASSERT(info);
    info->fd = (int)fd;
    info->addr = (struct sockaddr*)addr;
    info->len = (int*)len;
    SPEC_PRINT(log_f, "Accepting on fd %d\n", fd);
    fprintf(log_f, "Accepting on fd %d\n", fd);
    struct handled_function* hf = make_handled_function(ptdata, "accept", (ADDRINT)info);
    struct taint* arg_taint = get_mem_taint(fd_ref);
    merge_taints(&hf->args_taint, arg_taint);

    RELEASE_GLOBAL_LOCK (ptdata);
}

void accept_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("accept");

    GRAB_GLOBAL_LOCK (ptdata);

    struct accept_info* info = (struct accept_info*)(hf->special_value);

    if ((int)res != -1) {
    }

    for(int i= 0; i < (int)sizeof(socklen_t); i++) {
        mem_mod_dependency(ptdata, (ADDRINT)(info->len) + i, &hf->args_taint, SET, 1);
    }
    if (info->addr) {
        for(int i= 0; i < *(info->len); i++) {
            mem_mod_dependency(ptdata, (ADDRINT)(info->addr) + i, &hf->args_taint, SET, 1);
        }
    }

    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free(info);
    free_handled_function(ptdata);

    RELEASE_GLOBAL_LOCK (ptdata);
}

// Since glibc caches the pid, we need to call into the kernel on replay
#ifdef HAVE_REPLAY
void change_getpid(ADDRINT reg_ref)
{
   if (no_replay) return;
   int pid = get_record_pid();
   *(int*)reg_ref = pid;
}
#endif

void writev_start(ADDRINT vec_addr, ADDRINT vec_cnt)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("writev");

    GRAB_GLOBAL_LOCK (ptdata);

    struct handled_function* hf = make_handled_function(ptdata, "writev", 0);
    struct iovec* vec = (struct iovec*)vec_addr;
    LOG_PRINT ("writev: starting address is %#x, len is %d\n", 
            (ADDRINT)(vec->iov_base), vec->iov_len);

    struct writev_info* wi = (struct writev_info *) malloc(sizeof(struct writev_info));
    wi->count = (int)vec_cnt;
    wi->vi = vec;
    /*
    struct vec_info* vi = (struct vec_info *) malloc(sizeof(struct vec_info) * ((int)vec_cnt));

    for(int i = 0; i < (int)vec->iov_len; i++) {
        SPEC_PRINT(log_f, "%c", *((char*)(vec->iov_base) + i));
        PRINT_SPEC_VECTOR(get_mem_taint((ADDRINT)(vec->iov_base) + i));
    }

    for (int i = 0; i < (int)vec_cnt; i++) {
        struct iovec* vec = ((struct iovec *) vec_addr) + i;
        struct vec_info* tmp = vi + i;

        tmp->base = (ADDRINT) vec->iov_base;
        tmp->len = vec->iov_len;
    }
    */
    hf->special_value = (ADDRINT)wi;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void writev_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("writev");

    GRAB_GLOBAL_LOCK (ptdata);

    struct writev_info* wi = (struct writev_info *) hf->special_value;

    /*
    // for each iovvec
    LOG_PRINT("writev_stop, count is %d\n", wi->count);
    for (int i = 0; i < wi->count; i++) {
        struct vec_info* vi = ((struct vec_info *) wi->vi) + i;
        LOG_PRINT ("write buf is %s\n", (char *) vi->base);

        for (int j = 0; j < vi->len; j++) {
            ADDRINT loc = vi->base + j;
            LOG_PRINT ("RESULT: %#x (\"%c\")\n", loc, *((char *)loc));
            __print_dependency_tokens(log_f, get_mem_taint(loc));
        }
    }
    */

    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);

    free(wi);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void write_start(ADDRINT fd, ADDRINT fd_ref, ADDRINT buf, ADDRINT size)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("write");    
    GRAB_GLOBAL_LOCK (ptdata);

    struct write_info* wi = (struct write_info*)malloc(sizeof(struct write_info));
    MYASSERT(wi);
    wi->fd = fd;
    wi->buf = (char*)buf;
    make_handled_function(ptdata, "write", (ADDRINT)wi);

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void write_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("write");
    GRAB_GLOBAL_LOCK (ptdata);

    struct write_info* wi = (struct write_info*)hf->special_value;

    free(wi);
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    ptdata->syscall_handled = 0;

    RELEASE_GLOBAL_LOCK (ptdata);
}

void send_start(ADDRINT fd, ADDRINT buf, ADDRINT size, ADDRINT flags)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("send");

    GRAB_GLOBAL_LOCK (ptdata);

    // we'll use write_info for send, since they're similar
    struct write_info* wi = (struct write_info*)malloc(sizeof(struct write_info));
    MYASSERT(wi);
    wi->fd = fd;
    wi->buf = (char*)buf;

    make_handled_function (ptdata, "send", (ADDRINT)wi);

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void send_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("send");
    
    GRAB_GLOBAL_LOCK (ptdata);

    struct write_info* wi = (struct write_info*)hf->special_value;
    free(wi);

    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    ptdata->syscall_handled = 0;

    RELEASE_GLOBAL_LOCK (ptdata);
}


void unlink_start(ADDRINT first_arg)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("unlink");

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* arg_taint;
    struct handled_function* hf = make_handled_function(ptdata, "unlink", first_arg);
    //the special value means whether the argument had taint or not
    char dest_char;
    while(1) {
	arg_taint = get_mem_taint(first_arg);
        merge_taints(&hf->args_taint, arg_taint);
	if ((PIN_SafeCopy(&dest_char, (const void*)first_arg, 1) != 1) || (dest_char == '\0'))
	    break;
	first_arg++;
    } 

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void unlink_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("unlink");
    
    GRAB_GLOBAL_LOCK (ptdata);

    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    ptdata->syscall_handled = 0;

    RELEASE_GLOBAL_LOCK (ptdata);
}

struct rename_info {
    char*    new_path;
    char*    old_path;
};

void rename_start(ADDRINT old_path, ADDRINT new_path)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("rename"); 

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* arg_taint;
    struct handled_function* hf = make_handled_function(ptdata, "rename", 0);
#ifdef INTER_PROCESS_PROPAGATION
    struct rename_info* info = (struct rename_info*)malloc(sizeof(struct rename_info));
    info->old_path = (char*)old_path;
    info->new_path = (char*)new_path;
    hf->special_value = (ADDRINT)info;
#endif    
    char dest_char;
    while(1) {
	if ((arg_taint = get_mem_taint(old_path)) != NULL) {
            merge_taints(&hf->args_taint, arg_taint);
	}
	if ((PIN_SafeCopy(&dest_char, (const void*)old_path, 1) != 1) || (dest_char == '\0'))
	    break;
	old_path++;
    } 
    while(1) {
	if ((arg_taint = get_mem_taint(new_path)) != NULL) {
            merge_taints(&hf->args_taint, arg_taint);
	}
	if ((PIN_SafeCopy(&dest_char, (const void*)new_path, 1) != 1) || (dest_char == '\0'))
	    break;
	new_path++;
    }

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void rename_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("rename");

    GRAB_GLOBAL_LOCK (ptdata);

    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    ptdata->syscall_handled = 0;

    RELEASE_GLOBAL_LOCK (ptdata);
}

void uname_start(ADDRINT first_arg)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("uname");

    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "uname", first_arg);
    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void uname_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("uname");

    GRAB_GLOBAL_LOCK (ptdata);

    for (int i = 0; i < (int)sizeof(struct utsname); i++) {
        mem_clear_dependency(ptdata, hf->special_value + i);
    }
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    ptdata->syscall_handled = 0;

    RELEASE_GLOBAL_LOCK (ptdata);
}

struct sockopt_info{
    void*   optval;
    socklen_t*    optlen;
};

void getsockopt_start(ADDRINT optval, ADDRINT optlen)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("getsockopt");

    GRAB_GLOBAL_LOCK (ptdata);

    struct sockopt_info* si = (struct sockopt_info*)malloc(sizeof(struct sockopt_info));
    si->optval = (void*)optval;
    si->optlen = (socklen_t*)optlen;
    make_handled_function(ptdata, "getsockopt", (ADDRINT)si);

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getsockopt_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("getsockopt");

    GRAB_GLOBAL_LOCK (ptdata);

    struct sockopt_info* si = (struct sockopt_info*)hf->special_value;
    for (int i = 0; i < (int)sizeof(socklen_t); i++) {
        mem_clear_dependency(ptdata, (ADDRINT)(si->optlen) + i);
    }
    for (int i = 0; i < (int)(*(si->optlen)); i++) {
        mem_clear_dependency(ptdata, (ADDRINT)(si->optval) + i);
    }
    free(si);
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);

    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void pipe_start(ADDRINT fds)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("pipe");

    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "pipe", fds);
    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void pipe_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("pipe");

    GRAB_GLOBAL_LOCK (ptdata);
    for (int i = 0; i < 2*(int)sizeof(int); i++) {
        mem_clear_dependency(ptdata, hf->special_value + i);
    }
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void open_start(ADDRINT filename, ADDRINT flag) 
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("open");

    GRAB_GLOBAL_LOCK (ptdata);
    struct open_info* oi = (struct open_info*)malloc(sizeof(struct open_info));
    MYASSERT(oi);
    // copy open info
    int filename_len;
    filename_len = strlen((char*)filename);
    if (filename_len >= OPEN_PATH_LEN) {
        strncpy(oi->name, (char*)filename, OPEN_PATH_LEN-1);
                oi->name[OPEN_PATH_LEN-1] = '\0';
    } else {
        strcpy(oi->name, (char*)filename);
    }
    
    LOG_PRINT ("open_start opens file %s\n", oi->name); 

    oi->flags = (int)flag;
    struct handled_function* hf = make_handled_function(ptdata, "open", (ADDRINT)oi);

    // now transfer taint from the filename
    struct taint* arg_taint;
    char dest_char;
    LOG_PRINT ("open_start filename %s\n", (char *) filename);
    while(1) {
        arg_taint = get_mem_taint(filename);
        LOG_PRINT ("%#x", filename);
        __print_dependency_tokens(LOG_F, arg_taint);
        merge_taints(&hf->args_taint, arg_taint);
        if ((PIN_SafeCopy(&dest_char, (const void*)filename, 1) != 1) || (dest_char == '\0'))
            break;
        filename++;
    }

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void open_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("open")

    GRAB_GLOBAL_LOCK (ptdata);
    struct open_info* oi = (struct open_info*)hf->special_value;
    free(oi);

    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);

    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void dl_runtime_resolve_start(ADDRINT name)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("_dl_runtime_resolve");
    
    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "_dl_runtime_resolve", 0);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void dl_runtime_resolve_stop(void* name)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("_dl_runtime_resolve");

    GRAB_GLOBAL_LOCK (ptdata);
    free_handled_function(ptdata);
    if (CALLING_BBLOCK_HEAD) {
        CALLING_BBLOCK_HEAD->status = CALLING_BBLOCK_HEAD->prev_status;
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void generic_start(void* name)
{            
#ifdef LOGGING_ON
    char* name_func;
    name_func = (char*) name;
    LOG_PRINT("start handled function (generic_start) %s\n", name_func);
#endif

    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, (char*)name, 0);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void generic_void_stop(void* name)
{
#ifdef LOGGING_ON
    char* funcname = (char*) name;
    LOG_PRINT ("stop handled function (generic_void_stop) %s\n", funcname);
#endif
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    if (!hf || strcmp(hf->name, (char*)name)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void generic_stop(void* name)
{
#ifdef LOGGING_ON
    char* funcname = (char*) name;
    LOG_PRINT ("stop handled function (generic_stop) %s\n", funcname);
#endif
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    if (!hf || strcmp(hf->name, (char*)name)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void readdir_stop(ADDRINT res)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    if (!hf || strcmp(hf->name, "readdir")) return;
    GRAB_GLOBAL_LOCK (ptdata);
    if (res) {
        for (int i = 0; i < (int)sizeof(struct dirent); i++) {
            mem_clear_dependency(ptdata, res + i);
        }
    }
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void rmdir_start(ADDRINT inst_ptr, ADDRINT path, ADDRINT name)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("rmdir");
    GRAB_GLOBAL_LOCK (ptdata);

    struct handled_function* hf = make_handled_function(ptdata, "rmdir", 0);
    struct taint* arg_taint = NULL;
    char dest_char = 0;

    // merge the taints of the path
    while (1) {
        LOG_PRINT ("rmdir_start taint of addr %#x:\n", path);
        __print_dependency_tokens(log_f, get_mem_taint(path));

        if ((arg_taint = get_mem_taint(path)) != NULL) {
            merge_taints(&hf->args_taint, arg_taint);
        }
        if ((PIN_SafeCopy(&dest_char, (const void*)path, 1) != 1) || (dest_char == '\0'))
            break;
        path++;
    }

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void rmdir_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("rmdir");

    GRAB_GLOBAL_LOCK (ptdata);

    // taint the return code with the argument's taints
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);

    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void main_start(ADDRINT arg1, ADDRINT arg2)
{
#ifdef LOGGING_ON
    int argc = (int) arg1;
    char** argv = (char **) arg2;

    LOG_PRINT ("in main_start\n");
    LOG_PRINT ( "argc: %d\n", argc);
    LOG_PRINT ( "argv: %#x\n", arg2);
    for (int i = 0; i < argc; i++) {
        LOG_PRINT ("argv[%d]: %s\n", i, argv[i]);
    }
#endif

    main_started = 1;

#ifdef FUNC_TIME
    gettimeofday(&current_time, NULL);
    current_num_inst = total_inst_count;
    function_times_hash = g_hash_table_new(g_int_hash, g_int_equal);
#endif
    //RELEASE_GLOBAL_LOCK (ptdata);
}

void main_stop()
{
    ANALYSIS_PRINT(log_f, "main stopped is called\n");
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    //GRAB_GLOBAL_LOCK (ptdata);
    if (NUM_CKPTS == 0) {
        //need to finish this crap
        fprintf(log_f, "ABOUT TO DETACH PIN\n");
        //printf("ABOUT TO DETACH PIN\n");
        //print_ctrflow_stack_conditions(ptdata);
        //PIN_Detach();
    } else {
        INFO_PRINT(log_f, "about to leave main function, rollback now\n");
        rollback(ptdata, FAIL);
        //RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
    //RELEASE_GLOBAL_LOCK (ptdata);
}               

void mmap_start (ADDRINT addr, ADDRINT length, ADDRINT prot, ADDRINT flags, ADDRINT fd, ADDRINT fd_ref, ADDRINT offset) {
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("mmap");

    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "mmap", 0);

    struct mmap_info* mi = (struct mmap_info*)malloc(sizeof(struct mmap_info));
    MYASSERT(mi);
    mi->addr = addr;
    mi->length = length;
    mi->prot = prot;
    mi->flags = flags;
    mi->fd = (int)fd;
    mi->fd_ref = fd_ref;
    mi->offset = offset;
    hf->special_value = (ADDRINT)mi;

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void mmap_stop(ADDRINT result) {
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("mmap");

    GRAB_GLOBAL_LOCK (ptdata);

    struct mmap_info* mi = (struct mmap_info*)hf->special_value;
    if (result > 0) {
        
        // this is a file-backed mmap
        if (mi->fd != -1) {
            // taint each of the memory values with the taint of the fd
            struct taint tmp;
            new_taint (&tmp);
            for (int i = 0; i < (int)(sizeof(int)); i++) {
                merge_taints(&tmp, get_mem_taint(mi->fd_ref + i));
            }
            if (!is_taint_zero(&tmp)) {
                for (int i=0; i < mi->length; i++) {
                    ADDRINT loc = result + i;
                    mem_mod_dependency(ptdata, loc, &tmp, SET, 1);
                }
            }
        }
    }

    free(mi);
    free_handled_function(ptdata);

    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

struct option_info {
    int option_num;     // which option is this?
    long clock_value;   // clock value that option was created from, if no replay, then use the global syscall count
    int offset;         // offset into a buffer from the syscall that this option was created from
};

int create_new_token (int type, int token_num, int syscall_cnt, int byte_offset, void* data)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    struct token* tok; 
    tok = (struct token *) malloc(sizeof(struct token));
    tok->type = type;
    tok->token_num = token_num;
    tok->syscall_cnt = syscall_cnt;
    tok->byte_offset = byte_offset;
    tok->rg_id = ptdata->rg_id;
    tok->record_pid = ptdata->record_pid;
#ifndef CONFAID
    if (data) {
        strncpy(tok->name, (char *)data, 256);
    } else {
        strncpy(tok->name, (char *) "NOTAFILE", 256);
    }
#endif

    GRAB_GLOBAL_LOCK (ptdata);
    MYASSERT (option_info_table);
    g_hash_table_insert(option_info_table, GINT_TO_POINTER(token_num), tok);

    // LOG_PRINT ("[OPTION] Created new token (option metadata) %d, %d, %d\n", tok->token_num, tok->syscall_cnt, tok->byte_offset);

    RELEASE_GLOBAL_LOCK (ptdata);

    return token_num;
}

#ifdef CONFAID
int create_new_named_token (int token_num, char* token_name)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    struct token* tok; 
    tok = (struct token *) malloc(sizeof(struct token));
    tok->token_num = token_num;
    // not necessary for Confaid
    tok->syscall_cnt = 0;
    tok->byte_offset = 0;
    strncpy(tok->config_token, token_name, 256);
    // TODO token line num and config_filename
    tok->line_num = 0;
    strncpy(tok->config_filename, confaid_data->config_filename, 256);

    GRAB_GLOBAL_LOCK (ptdata);
    MYASSERT (option_info_table);
    g_hash_table_insert(option_info_table, GINT_TO_POINTER(token_num), tok);

    LOG_PRINT ("[OPTION] Created new token (option metadata %d, %s)\n", tok->token_num, tok->config_token);

    RELEASE_GLOBAL_LOCK (ptdata);

    return token_num;
}
#endif

/* 
 * Only creates an option for a byte in the buffer if it's a valid address
 *
 * @param id - identifier of this buffer (e.g. syscall count or replay clock)
 * @param buf
 * @param size
 * */
void create_options_from_buffer (int type, long id, void* buf, int size, int offset, void* data)
{
    int rc;
    char c;
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    if (size <= 0) return;
    if (!buf) return;

    if (option_cnt >= NUM_OPTIONS) {
        LOG_PRINT ("[ERROR] Cannot create more than %d options, not making any more options\n", NUM_OPTIONS);
        return;
    }

    GRAB_GLOBAL_LOCK (ptdata);

    if (option_byte) {
        for (int i = 0; i < size; i++) {
            ADDRINT mem_location = ((ADDRINT) buf) + i;
            rc = PIN_SafeCopy((void*)&c, (void *) mem_location, sizeof(char));
            if (rc) {
                struct taint vector;

                if (option_cnt >= NUM_OPTIONS) {
                    fprintf(stderr, "[ERROR]Not enough options\n");
                    exit(-1);
                }
                new_taint(&vector);
                set_taint_value(&vector, option_cnt, get_max_taint_value());

                create_new_token (type, option_cnt, global_syscall_cnt, i + offset, data);

                option_cnt++;    
                mem_mod_dependency(ptdata, mem_location, &vector, SET, 1);
            }
        }
    } else {
        char* bufcpy;
        // we are dealing with messages...
        LOG_PRINT ("[OPTION] Dealing with messages\n");

        if (!input_message_regex) {
            LOG_PRINT ("[ERROR] There is no input message regex!\n");
            RELEASE_GLOBAL_LOCK (ptdata);
            return;
        }

        // make sure the string is null terminated
        bufcpy = (char *) malloc(sizeof(char) * (size + 1));
        strncpy(bufcpy, (char *) buf, size);
        bufcpy[size] = '\0';

        LOG_PRINT ("Made copy of buf: %s\n", bufcpy);

        if (regex_match_string(input_message_regex, bufcpy)) {
            struct taint vector;
            struct taint merge_vector;
            char req_num[256];
            LOG_PRINT ("[OPTION] input message regex matched!\n");

            sprintf(req_num, "%d", option_cnt);
            new_taint(&vector);
            new_taint(&merge_vector);
            set_taint_value(&vector, option_cnt, get_max_taint_value());
            for (int j=0; j < size; j++) {
                mem_mod_dependency(ptdata, ((ADDRINT)buf) + j, &vector, SET, 1);
                merge_taints (&merge_vector, &vector);
                LOG_PRINT ("Set memory location %#x to taint:", ((ADDRINT)buf) + j);
                __print_dependency_tokens(log_f, get_mem_taint(((ADDRINT)buf) + j));
                __print_dependency_tokens(log_f, &vector);
            }
            option_cnt++;
            LOG_PRINT ("[OPTION] Created a new option %d for a message\n", option_cnt);
        }
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

void strcmp_start(ADDRINT first_arg, ADDRINT second_arg)
{                   
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("strcmp");
    GRAB_GLOBAL_LOCK (ptdata);

    // struct handled_function* hf = make_handled_function(ptdata, "strcmp", 0);
    //make_handled_function(ptdata, "strcmp", 0);
#ifdef CONFAID
    struct handled_function* hf = make_handled_function(ptdata, "strcmp", 0);
    struct taint* arg_taint = NULL;
    LOG_PRINT ("strcmp of %s and %s\n", (char *) first_arg, (char *) second_arg);
    int tainted1 = 0;
    int tainted2 = 0;
    ADDRINT tmp_ptr = first_arg;
    char tmp_char;
    while(1) {
        if ((arg_taint = get_mem_taint(tmp_ptr)) != NULL) {
            merge_taints(&hf->args_taint, arg_taint);
            SPEC_PRINT(log_f, "location: %#x: val:%c ", tmp_ptr, *(char*)tmp_ptr);
            PRINT_SPEC_VECTOR(arg_taint);
            tainted1 = 1;                 
        }
        if(PIN_SafeCopy(&tmp_char, (const void*)tmp_ptr, 1) != 1) {
            MYASSERT(NUM_CKPTS > 0);
            rollback(ptdata, LIMIT);
            printf("ERROR: we are back in the problamatic strcmp...\n");
        } else {
            if (tmp_char == '\0')
                break;
        }
        tmp_ptr++;
    }
    tmp_ptr = second_arg;
    while(1) {
        if ((arg_taint = get_mem_taint(tmp_ptr)) != NULL) {
            merge_taints(&hf->args_taint, arg_taint);
            SPEC_PRINT(log_f, "location: %#x: val:%c ", tmp_ptr, *(char*)tmp_ptr);
            PRINT_SPEC_VECTOR(arg_taint);
            tainted2 = 1;
        }
        if(PIN_SafeCopy(&tmp_char, (const void*)tmp_ptr, 1) != 1) {
            MYASSERT(NUM_CKPTS > 0);
            rollback(ptdata, LIMIT);
            printf("ERROR: we are back in the problamatic strcmp...\n");
        } else {
            if (tmp_char == '\0')
                break;
        }
        tmp_ptr++;
    }
#ifdef ALT_PATH_EXPLORATION
    //don't create new token while speculative
    if (NUM_CKPTS > 0) return;
#endif
    //create a token if one of the strcmp arguments is
    //from the config file and the other one is not tainted at all.
    if ((get_taint_value(&hf->args_taint, 0) == 0) || (tainted2 && tainted1)) return;

    struct taint new_token_dep;
    new_taint(&new_token_dep);

#ifdef CTRL_FLOW
    // add in the current control flow to the new token
    int level = 1;
    struct taint_info* tmp_stack = CTRFLOW_TAINT_STACK;
    while (tmp_stack) {
        shift_merge_taints(&new_token_dep, &tmp_stack->condition_taint, level);
        tmp_stack = tmp_stack->prev;
        level++;
    }
#endif
    tmp_ptr = (tainted1 == 1) ? first_arg : second_arg;

    create_new_named_token(option_cnt, (char *) tmp_ptr);
    set_taint_value(&new_token_dep, option_cnt, get_max_taint_value());
    LOG_PRINT ("[OPTION] Created new option %d for config token %s\n", option_cnt, (char *) tmp_ptr);

    while (1) {
        mem_mod_dependency(ptdata, tmp_ptr, &new_token_dep, MERGE, 0);
        if (*(char *)tmp_ptr == '\0') {
            break;
        }
        tmp_ptr++;
    }

    option_cnt++;
#endif
    RELEASE_GLOBAL_LOCK (ptdata);
}

void strcmp_stop(ADDRINT result)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("strcmp");

    GRAB_GLOBAL_LOCK (ptdata);
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void fgets_start(ADDRINT file_ptr)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("fgets");

    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "fgets", (int)fileno((FILE*)file_ptr));
    RELEASE_GLOBAL_LOCK (ptdata);
}

void fgets_stop(ADDRINT buffer_pointer)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("fgets");

    GRAB_GLOBAL_LOCK (ptdata);

    if (buffer_pointer != 0) {
#ifdef CONFAID
        if ((int)hf->special_value == confaid_data->config_fd) {
            LOG_PRINT ("fgets from config_fd, %s\n", (char *) buffer_pointer);
            struct taint tmp;
            new_taint (&tmp);
            set_taint_value(&tmp, 0, get_max_taint_value());
            while (1) {
                mem_mod_dependency(ptdata, buffer_pointer, &tmp, SET, 1);
                if ((* (char *)buffer_pointer) == '\n') {
                    confaid_data->line_num++;
                }
                if (*(char*)buffer_pointer == '\0') break;
                buffer_pointer++;
            }
        } else {
            while(1) {
                mem_clear_dependency(ptdata, buffer_pointer);
                if (*(char*)buffer_pointer == '\0') break;
                buffer_pointer++;
            }
        }
#else
        while(1) {
            mem_clear_dependency(ptdata, buffer_pointer);
            if (*(char*)buffer_pointer == '\0') break;
            buffer_pointer++;
        }
#endif
    }
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);

    RELEASE_GLOBAL_LOCK (ptdata);
}

void read_start(ADDRINT fd, ADDRINT fd_ref, ADDRINT buf, ADDRINT size) 
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("read");
    // we use the same syscall when handling the function

    GRAB_GLOBAL_LOCK (ptdata);

    struct handled_function* hf = make_handled_function(ptdata, "read", 0);

    for(int i =0; i < (int)sizeof(int); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(fd_ref + i));
    }

    struct read_info* ri = (struct read_info*)malloc(sizeof(struct read_info));
    MYASSERT(ri);
    ri->fd = (int)fd;
    ri->fd_ref = fd_ref;
    ri->buf = (char*)buf;
    hf->special_value = (ADDRINT)ri;
   
    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void read_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    struct taint merge_vector;
    STOP_HANDLED_FUNCTION("read");

    GRAB_GLOBAL_LOCK (ptdata);

    struct read_info* ri = (struct read_info*)hf->special_value;
    int result = (int)res;

    if (result > 0) {
        new_taint(&merge_vector);
        for (int i = 0; i < (int)result; i++) {
            mem_mod_dependency(ptdata, (ADDRINT)(ri->buf + i), &hf->args_taint, MERGE, 1);
            LOG_PRINT ("read_stop address %#x\n", (ADDRINT)(ri->buf + i));
            __print_dependency_tokens(log_f, get_mem_taint((ADDRINT)(ri->buf + i)));
            merge_taints(&merge_vector, get_mem_taint((ADDRINT(ri->buf + i))));
        }

        for (int i = 0; i < (int)(sizeof(int)); i++) {
            LOG_PRINT ("read_stop fd_ref address %#x\n", (ADDRINT)(ri->fd_ref + i));
            mem_mod_dependency(ptdata, (ADDRINT)(ri->fd_ref + i), &merge_vector, MERGE, 1);
            __print_dependency_tokens(log_f, get_mem_taint((ADDRINT)(ri->fd_ref + i)));
        }
    }

    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);

    free(ri);
    free_handled_function(ptdata);
    ptdata->syscall_handled = 0;

    RELEASE_GLOBAL_LOCK (ptdata);
}

struct readv_info {
    int fd;
    struct iovec* iov;
    int iovcnt;
};

void readv_start(ADDRINT name, ADDRINT fd, ADDRINT fd_ref, ADDRINT iov, ADDRINT iovcnt)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION((char *) name);

    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, (char *) name, 0);

    for(int i =0; i < (int)sizeof(int); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(fd_ref + i));
    }

    struct readv_info* rvi = (struct readv_info*) malloc(sizeof(struct readv_info));
    rvi->fd = (int)fd;
    rvi->iov = (struct iovec *)iov;
    rvi->iovcnt = (int) iovcnt;
    hf->special_value = (ADDRINT)rvi;

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void readv_stop(ADDRINT name, ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION((char *)name);

    GRAB_GLOBAL_LOCK (ptdata);

    struct readv_info* rvi = (struct readv_info*)hf->special_value;
    int result = (int)res;

    // if the readv succeeds
    int bytes = 0;
    if (result > 0) {
        for (int i = 0; i < rvi->iovcnt; i++) {
            struct iovec* tmp;
            ADDRINT loc = ((ADDRINT)(rvi->iov)) + (sizeof(struct iovec) * i);
            tmp = (struct iovec*) loc;
            for (int j = 0; j < ((int)tmp->iov_len); j++) {
                mem_mod_dependency(ptdata, loc + j, &hf->args_taint, MERGE, 1);
                bytes++;
            }
            // for partial readv's
            if (bytes >= result) {
                break;
            }
        }
    }

    // taint the return value
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);

    free(rvi);
    free_handled_function(ptdata);

    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void recv_start(ADDRINT fd, ADDRINT fd_ref, ADDRINT buf, ADDRINT size) 
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("recv");

    GRAB_GLOBAL_LOCK (ptdata);

    struct handled_function* hf = make_handled_function(ptdata, "recv", 0);
    SPEC_PRINT(log_f, "%d: recving from fd %d, size %d\n", PIN_GetPid(), (int)fd, (int)size);
    SPEC_PRINT(log_f, "%d: taint of the connection is:\n", PIN_GetPid());
    for(int i =0; i < (int)sizeof(int); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(fd_ref + i));
    }
    struct read_info* ri = (struct read_info*)malloc(sizeof(struct read_info));
    MYASSERT(ri);
    ri->fd = (int)fd;
    ri->buf = (char*)buf;
    hf->special_value = (ADDRINT)ri;

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void recv_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("recv");

    GRAB_GLOBAL_LOCK (ptdata);

    struct read_info* ri = (struct read_info*)hf->special_value;
    int result = (int)res;

    if (result > 0) {
        for (int i = 0; i < (int)result; i++) {
            mem_mod_dependency(ptdata, (ADDRINT)(ri->buf + i), &hf->args_taint, SET, 1);
        }
        for (int i = 0; i < (int)result; i++) {
            mem_mod_dependency(ptdata, (ADDRINT)(ri->buf + i), &hf->args_taint, SET, 1);
        }
    }
    free(ri);
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);

    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void select_start(ADDRINT timeout)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;

    GRAB_GLOBAL_LOCK (ptdata);

    struct taint* ptaint = get_mem_taint(timeout);
    if (ptaint) set_taint(&SELECT_TAINT,ptaint);

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void select_stop(ADDRINT res)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    GRAB_GLOBAL_LOCK (ptdata);
    if (res == 0) {
        struct taint_info* tmp = CTRFLOW_TAINT_STACK;
        for (int i = 0; tmp && i < CONFIDENCE_LEVELS-1; i++) {
            shift_cf_taint(&tmp->ctrflow_taint, &SELECT_TAINT, &tmp->ctrflow_taint);
            shift_taints(&SELECT_TAINT, &SELECT_TAINT, 1);
            tmp = tmp->prev;
        }
    }
    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void fstat_start(ADDRINT fd_ref, ADDRINT buf, ADDRINT name)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, (char*)name, buf);
    for (int i =0; i < (int)sizeof(int); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(fd_ref + i));
    }
    LOG_PRINT ("fstat start fd_ref %#x taint is: \n", fd_ref);
    __print_dependency_tokens(log_f, &hf->args_taint);
    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void stat_start(ADDRINT path, ADDRINT buf, ADDRINT name)
{
    struct thread_data* ptdata;
    LOG_PRINT ("stat of path %s\n", (char *) path);
    START_HANDLED_FUNCTION ((char *)name);

    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, (char*)name, buf);
    struct taint* arg_taint = NULL;
    char dest_char = 0;
    while(1) {
        if ((arg_taint = get_mem_taint(path)) != NULL) {
            merge_taints(&hf->args_taint, arg_taint);
        }
        if ((PIN_SafeCopy(&dest_char, (const void*)path, 1) != 1) || (dest_char == '\0'))
            break;
        path++;
    }

    LOG_PRINT("the args_taint for %s is ", (char *)name);
    __print_dependency_tokens (LOG_F, &hf->args_taint);

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void stat_stop(ADDRINT name)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ((char *)name);

    GRAB_GLOBAL_LOCK (ptdata);
    ADDRINT buf = hf->special_value;
#ifdef LARGEFILE_USED   
    for (int i=0; i < (int)sizeof(struct stat64); i++) {
#else
    for (int i=0; i < (int)sizeof(struct stat); i++) {
#endif
        mem_mod_dependency(ptdata, buf + i, &hf->args_taint, SET, 1);
    }
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);

    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void close_start(ADDRINT fd, ADDRINT fd_ref)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("close");

    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "close", fd);
    for (int i =0; i < (int)sizeof(int); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(fd_ref + i));
    }

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void close_stop(ADDRINT name, ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("close");

    GRAB_GLOBAL_LOCK (ptdata);

    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);

    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void chdir_stop()
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    if (!hf || strcmp(hf->name, "chdir")) return;
    GRAB_GLOBAL_LOCK (ptdata);
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void apr_palloc_start()
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (NUM_CKPTS > 0) {
        rollback(ptdata, LIMIT);
        return;
    }
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;
    //ANALYSIS_PRINT(log_f, "%s is called\n", (char*)name);
    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "apr_palloc", 0);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void malloc_start(ADDRINT size)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("malloc");

    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "malloc", size);
    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void malloc_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("malloc");

    GRAB_GLOBAL_LOCK (ptdata);
    if (NUM_CKPTS == 0) {
        if (res) {
            malloc_array[malloc_index].address = res;
            malloc_array[malloc_index].active = 1;
            malloc_array[malloc_index].size = (int)hf->special_value;
            malloc_index++;
            MYASSERT(malloc_index < MAX_MALLOC_INDEX);
            assert(malloc_index < MAX_MALLOC_INDEX);
        }
    }
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

struct alloc_info {
    ADDRINT   ptr;
    int     size;
};

void realloc_start(ADDRINT ptr, ADDRINT size)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("realloc");

    GRAB_GLOBAL_LOCK (ptdata);
    struct alloc_info* ai = (struct alloc_info*)malloc(sizeof(struct alloc_info));
    MYASSERT(ai);
    ai->ptr = ptr;
    ai->size = (int)size;
    make_handled_function(ptdata, "realloc", (ADDRINT)ai);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void realloc_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("realloc");

    GRAB_GLOBAL_LOCK (ptdata);
    if (NUM_CKPTS == 0 && res) {
        struct alloc_info* ai = (struct alloc_info*)hf->special_value;
        if (ai->ptr) {
            int old_size = -1;
            for(int i = 0; i < malloc_index; i++) {
                if (malloc_array[i].address == ai->ptr && malloc_array[i].active) {
                    old_size = malloc_array[i].size;
                    break;
                }
            }
            struct taint* vector;
            for (int i = 0; i < ((old_size < ai->size) ? old_size : ai->size) ; i++) {
                vector = get_mem_taint(ai->ptr + i);
                if (vector) {
                    mem_mod_dependency(ptdata, res + i, vector, SET, 1);
                } else 
                    mem_clear_dependency(ptdata, res + i);
            }
        }
        malloc_array[malloc_index].address = res;
        malloc_array[malloc_index].active = 1;
        malloc_array[malloc_index].size = ai->size;
        malloc_index++;
        MYASSERT(malloc_index < MAX_MALLOC_INDEX);
        assert(malloc_index < MAX_MALLOC_INDEX);
    }
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void calloc_start(ADDRINT num, ADDRINT size)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("calloc");

    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "calloc", (int)num*(int)size);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void calloc_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("calloc");
    GRAB_GLOBAL_LOCK (ptdata);
    if (NUM_CKPTS == 0) {
        if (res) {
            malloc_array[malloc_index].address = res;
            malloc_array[malloc_index].active = 1;
            malloc_array[malloc_index].size = (int)hf->special_value;
            malloc_index++;
            MYASSERT(malloc_index < MAX_MALLOC_INDEX);
            assert(malloc_index < MAX_MALLOC_INDEX);
        }
    }
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void free_start(ADDRINT ptr, ADDRINT name) 
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, (char*)name, ptr);
    if (NUM_CKPTS > 0) {
        RELEASE_GLOBAL_LOCK (ptdata);
         return;
    }
    for(int i = 0; i < malloc_index; i++) {
        if (malloc_array[i].address == ptr && malloc_array[i].active) {
            malloc_array[i].active = 0;
            break;
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void llseek_start(ADDRINT first_ref, ADDRINT sec_ref, ADDRINT third_ref,
                    ADDRINT forth_value, ADDRINT fifth_ref)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("llseek");
    //the special value is the first argument, pointer to the result
    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "llseek", forth_value);
    merge_taints(&hf->args_taint, get_mem_taint(first_ref));
    merge_taints(&hf->args_taint, get_mem_taint(sec_ref));
    merge_taints(&hf->args_taint, get_mem_taint(third_ref));
    merge_taints(&hf->args_taint, get_mem_taint(fifth_ref));

    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

//don't care about the result value, will taint the result anyway
void llseek_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("llseek");

    GRAB_GLOBAL_LOCK (ptdata);
    mem_mod_dependency(ptdata, hf->special_value, &hf->args_taint, SET, 1);
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);

    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getspnam_stop(ADDRINT res)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    GRAB_GLOBAL_LOCK (ptdata);
    if (!hf || strcmp(hf->name, "getspnam")) return;

    if(res) {
        for (int i = 0; i < (int)sizeof(struct spwd); i++){
            mem_mod_dependency(ptdata, res + i, &hf->args_taint, SET, 1);
        }
        char* tmp_c = ((struct spwd*)res)->sp_namp;
        char tmp_char;
        while(1) {
            mem_mod_dependency(ptdata, (ADDRINT)tmp_c, &hf->args_taint, SET, 1);
            if(PIN_SafeCopy(&tmp_char, (const void*)tmp_c, 1) != 1) {
                MYASSERT(NUM_CKPTS > 0);
                rollback(ptdata, LIMIT);
            } else {
                if (tmp_char == '\0')
                    break;
            }
            tmp_c++;
        }
        tmp_c = ((struct spwd*)res)->sp_pwdp;
        while(1) {
            mem_mod_dependency(ptdata, (ADDRINT)tmp_c, &hf->args_taint, SET, 1);
            if(PIN_SafeCopy(&tmp_char, (const void*)tmp_c, 1) != 1) {
                MYASSERT(NUM_CKPTS > 0);
                rollback(ptdata, LIMIT);
            } else {
                if (tmp_char == '\0')
                    break;
            }
            tmp_c++;
        }
    }
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void tainting_strings(struct thread_data* ptdata, char* tmp_c, struct taint* taint)
{
    GRAB_GLOBAL_LOCK (ptdata);
    char tmp_char;
    while(1) {
        if (taint) {
            mem_mod_dependency(ptdata, (ADDRINT)tmp_c, taint, SET, 1);
        } else
            mem_clear_dependency(ptdata, (ADDRINT)tmp_c);
        if(PIN_SafeCopy(&tmp_char, (const void*)tmp_c, 1) != 1) {
            MYASSERT(NUM_CKPTS > 0);
            rollback(ptdata, LIMIT);
        } else {
            if (tmp_char == '\0')
                break;
        }
        tmp_c++;
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getpw_stop(ADDRINT name, ADDRINT res)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    if (!hf || strcmp(hf->name, (char*)name)) return;

    GRAB_GLOBAL_LOCK (ptdata);
    if(res) {
        for (int i = 0; i < (int)sizeof(struct passwd); i++){
            mem_mod_dependency(ptdata, res + i, &hf->args_taint, SET, 1);
        }
        tainting_strings(ptdata, ((struct passwd*)res)->pw_name, &hf->args_taint);
        tainting_strings(ptdata, ((struct passwd*)res)->pw_passwd, &hf->args_taint);
        tainting_strings(ptdata, ((struct passwd*)res)->pw_gecos, &hf->args_taint);
        tainting_strings(ptdata, ((struct passwd*)res)->pw_dir, &hf->args_taint);
        tainting_strings(ptdata, ((struct passwd*)res)->pw_shell, &hf->args_taint);

    }
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getpwuid_start(ADDRINT first_ref)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "getpwuid", 0);
    for (int i = 0; i < (int)sizeof(uid_t); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(first_ref + i));
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void time_start(ADDRINT first_arg)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("time");

    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "time", first_arg);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void time_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("time");

    GRAB_GLOBAL_LOCK (ptdata);
    if (hf->special_value != 0) {
        for (int i = 0; i < (int)sizeof(time_t); i++) {
            mem_clear_dependency(ptdata, hf->special_value + i);
        }
    }
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void sigaction_start(ADDRINT oldact_ptr)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("sigaction");
    
    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "sigaction", oldact_ptr);
    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void sigaction_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("sigaction");

    GRAB_GLOBAL_LOCK (ptdata);
    if (hf->special_value != 0) {
        for (int i = 0; i < (int)sizeof(struct sigaction); i++) {
            mem_clear_dependency(ptdata, hf->special_value + i);
        }
    }
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void fork_stop(ADDRINT result)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    if (!hf || strcmp(hf->name, "fork")) return;

    GRAB_GLOBAL_LOCK (ptdata);
    if ((int)result == 0) {
        //in the child
        int rc = setup_logs();
        if (rc) {
            fprintf(stderr, "Pid %d could not setup logs, error code %d\n", PIN_GetPid(), rc);
            exit(1);
        }
        LOG_PRINT ("New record pid after fork is %d\n", ptdata->record_pid);
    }
    else { // only in the parent
    }
    LOG_PRINT ("End of fork, the pid is %d\n", (int)result);
#ifdef FUNC_TIME
    print_function_times();
#endif    
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getaddrinfo_start(ADDRINT first_arg, ADDRINT sec_arg, ADDRINT third_arg, ADDRINT res)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("getaddrinfo");

    GRAB_GLOBAL_LOCK (ptdata);

    struct handled_function* hf = make_handled_function(ptdata, "getaddrinfo", res);
    char dest_char;
    if (first_arg) {
        while(1) {
            merge_taints(&hf->args_taint, get_mem_taint(first_arg));
            if ((PIN_SafeCopy(&dest_char, (const void*)first_arg, 1) != 1) || (dest_char == '\0'))
                break;
            first_arg++;
        } 
    }
    if (sec_arg) {
        while(1) {
            merge_taints(&hf->args_taint, get_mem_taint(sec_arg));
            if ((PIN_SafeCopy(&dest_char, (const void*)sec_arg, 1) != 1) || (dest_char == '\0'))
                break;
            sec_arg++;
        }
    }
    if (third_arg) {
        for (int i = 0; i < (int)sizeof(struct addrinfo); i++)
            merge_taints(&hf->args_taint, get_mem_taint(third_arg + i));
        struct addrinfo* hints = (struct addrinfo*)third_arg;
        if (hints->ai_canonname) {
            char* tmp = hints->ai_canonname;
            while(1) {
                merge_taints(&hf->args_taint, get_mem_taint((ADDRINT)tmp));
                if ((PIN_SafeCopy(&dest_char, (const void*)tmp, 1) != 1) || (dest_char == '\0'))
                    break;
                tmp++;
            }
        }
        struct sockaddr* sa = hints->ai_addr;
        if (sa) {
            for (int i = 0; i < (int)sizeof(struct sockaddr); i++) 
                merge_taints(&hf->args_taint, get_mem_taint((ADDRINT)sa + i));
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getaddrinfo_stop(ADDRINT ret_val)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("getaddrinfo");    

    GRAB_GLOBAL_LOCK (ptdata);
    if ((int)ret_val != 0) goto end;

    for(int i = 0; i < (int)sizeof(int); i++)
        mem_mod_dependency(ptdata, hf->special_value + i, &hf->args_taint, SET, 1);
    
    if (hf->special_value) {
        struct addrinfo* res = *((struct addrinfo**)hf->special_value); 
        for(int i = 0; i < (int)sizeof(int); i++)
            mem_mod_dependency (ptdata, (ADDRINT)res + i, &hf->args_taint, SET, 1);
        while (res) {
            for (int i=0; i < (int)sizeof(struct addrinfo); i++)
                mem_mod_dependency(ptdata, (ADDRINT)res + i, &hf->args_taint, SET, 1);
            if (res->ai_canonname) {
                char* tmp = res->ai_canonname;
                char dest_char;
                while(1) {
                    mem_mod_dependency(ptdata, (ADDRINT)tmp, &hf->args_taint, SET, 1);
                    if ((PIN_SafeCopy(&dest_char, (const void*)tmp, 1) != 1) || (dest_char == '\0'))
                        break;
                    tmp++;
                }
            }
            struct sockaddr* sa = res->ai_addr;
            if (sa) {
                for (int i = 0; i < (int)sizeof(struct sockaddr); i++) 
                    mem_mod_dependency(ptdata, (ADDRINT)sa + i, &hf->args_taint, SET, 1);
            }
            res = res->ai_next;
        }

    }       
end:
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getgrgid_start(ADDRINT first_ref)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "getgrgid", 0);
    for (int i = 0; i < (int)sizeof(gid_t); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(first_ref + i));
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getgr_stop(ADDRINT name, ADDRINT res)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    if (!hf || strcmp(hf->name, (char*)name)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    if(res) {
        for (int i = 0; i < (int)sizeof(struct group); i++){
            mem_mod_dependency(ptdata, res + i, &hf->args_taint, SET, 1);
        }
        tainting_strings(ptdata, ((struct group*)res)->gr_name, &hf->args_taint);
        tainting_strings(ptdata, ((struct group*)res)->gr_passwd, &hf->args_taint);

    }
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getc_start(ADDRINT stream_arg)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION("getc");
    
    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "getc", fileno((FILE*)stream_arg));
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getc_stop(ADDRINT result)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION("getc");
    
    GRAB_GLOBAL_LOCK (ptdata);
#ifdef CONFAID
#ifdef ALT_PATH_EXPLORATION
    if (NUM_CKPTS != 0) {
        free_handled_function(ptdata);
        RELEASE_GLOBAL_LOCK (ptdata);
        return;
    }
#endif
    if (((int)hf->special_value == confaid_data->config_fd)) {
        LOG_PRINT ("fgetc of config_fd\n");
        struct taint tmp;
        new_taint(&tmp);
        set_taint_value(&tmp, 0, get_max_taint_value());
        if ((char)result == '\n') {
            confaid_data->line_num++;
        }
        reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &tmp, SET, 1);
    }
#endif
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void crypt_start(ADDRINT first_arg, ADDRINT sec_arg)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("crypt");
    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "crypt", 0);
    struct taint* arg_taint = NULL;
    int tainted = 0;
    char tmp_char;
    while(1) {
	if ((arg_taint = get_mem_taint(first_arg)) != NULL) {
            merge_taints(&hf->args_taint, arg_taint);
            tainted = 1;
	}
        if(PIN_SafeCopy(&tmp_char, (const void*)first_arg, 1) != 1) {
            MYASSERT(NUM_CKPTS > 0);
            rollback(ptdata, LIMIT);
        } else {
            if (tmp_char == '\0')
                break;
        }
	first_arg++;
    }
    while(1) {
	if ((arg_taint = get_mem_taint(sec_arg)) != NULL) {
            merge_taints(&hf->args_taint, arg_taint);
	    tainted = 1;
	}
        if(PIN_SafeCopy(&tmp_char, (const void*)sec_arg, 1) != 1) {
            MYASSERT(NUM_CKPTS > 0);
            rollback(ptdata, LIMIT);
            printf("ERROR: we are back in the problamatic strcmp...\n");
        } else {
            if (tmp_char == '\0')
                break;
        }
	sec_arg++;
    }
    hf->special_value = tainted;
    
    RELEASE_GLOBAL_LOCK (ptdata);
}

void crypt_stop(ADDRINT result)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("crypt");
    GRAB_GLOBAL_LOCK (ptdata);
    if (result != 0) {
        if ((int)(hf->special_value) == 1) {
            for (int i = 2; i < 13; i++) {
                mem_mod_dependency(ptdata, result + i, &hf->args_taint, SET, 1);
            }
        } else {
            for (int i = 2; i < 13; i++) {
                mem_clear_dependency(ptdata, result + i);
            }
	}
    }
    if ((int)(hf->special_value) == 1) {
        reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    } else  
        reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void fcrypt_start(ADDRINT first_arg)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("fcrypt");
    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "fcrypt", 0);
    struct taint* arg_taint = NULL;
    int tainted = 0;
    while(1) {
        if ((arg_taint = get_mem_taint(first_arg)) != NULL) {
            merge_taints(&hf->args_taint, arg_taint);
            tainted = 1;
        }
        if (*(char*)first_arg == '\0')
            break;
        first_arg++;
    } 
    hf->special_value = tainted;
    
    RELEASE_GLOBAL_LOCK (ptdata);
}
void fcrypt_stop(ADDRINT result)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("fcrypt");

    GRAB_GLOBAL_LOCK (ptdata);

    if (result != 0) {
        while(1) {
            if ((int)(hf->special_value) == 1) {
                mem_mod_dependency(ptdata, result, &hf->args_taint, SET, 1);
            } else
                mem_clear_dependency(ptdata, result);
            if (*(char*)result == '\0') break;
            result++;
        }
    }
    if ((int)(hf->special_value) == 1) {
        reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    } else  
        reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);

    RELEASE_GLOBAL_LOCK (ptdata);
}

void fclose_start(ADDRINT first_arg)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("fclose");
    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "fclose", 0);
    ptdata->syscall_handled = 1;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void fclose_stop(ADDRINT name)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("fclose");
    GRAB_GLOBAL_LOCK (ptdata);
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    ptdata->syscall_handled = 0;
    RELEASE_GLOBAL_LOCK (ptdata);
}

void mutex_trylock_start(ADDRINT first_arg)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("mutex_trylock");
    struct taint* arg_taint;

    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "mutex_trylock", 0);
    for (u_int i = 0; i < sizeof(int); i++) {
        if ((arg_taint = get_mem_taint(first_arg+i)) != NULL) {
            merge_taints(&hf->args_taint, arg_taint);
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void mutex_trylock_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("mutex_trylock");
    GRAB_GLOBAL_LOCK (ptdata);
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void exit_start()
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);
    if (NUM_CKPTS > 0) {
        INFO_PRINT(log_f, "about to perform exit/assert funtion, about to rollback now\n");
        rollback(ptdata, FAIL);
    }
    // on exit, we send a SIGCHLD to the parent so we need to propagate this taint
    FILE* tf = fopen("/tmp/pids", "a+");
    if (!tf) {
        SPEC_PRINT(log_f, "Could not open/create pids file %d\n", errno);
        fprintf(stderr, "Could not open/create pids file %d\n", errno);
        exit(-1);
    }
    struct taint dep;
    new_taint(&dep);
    shift_taints(&dep, &CTRFLOW_TAINT_STACK->ctrflow_taint, 1);

    int pid = get_record_pid();
    SPEC_PRINT(log_f, "in exit_start, writing info for pid %d/ recpid %d\n", PIN_GetPid(), pid);
    if(flock(fileno(tf), LOCK_EX) == -1) {
        SPEC_PRINT(log_f,"Process %d couldn't grab the pids file lock\n", PIN_GetPid());
        fprintf(stderr,"Process %d couldn't grab the pids file lock\n", PIN_GetPid());
        exit(-1);
    }
    fprintf(tf, "%c", *((char*)&pid));
    fprintf(tf, "%c", *((char*)&pid + 1));
    fprintf(tf, "%c", *((char*)&pid + 2));
    fprintf(tf, "%c", *((char*)&pid + 3));
    
    for(int i = 0; i < (int)sizeof(struct taint); i++)
        fprintf(tf, "%c", *((char*)&dep + i));
    fsync(fileno(tf));
    
    if (flock(fileno(tf), LOCK_UN) == -1) {
        SPEC_PRINT(log_f,"Process %d couldn't release the important file lock\n", PIN_GetPid());
        fprintf(stderr,"Process %d couldn't release the important file lock\n", PIN_GetPid());
        exit(-1);
    }
    fclose(tf);
    PRINT_SPEC_VECTOR(&dep);

    make_handled_function(ptdata, "exit", 0);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void error_start()
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);
    if (NUM_CKPTS > 0) {
        INFO_PRINT(log_f, "about to perform error funtion, about to rollback now\n");
        rollback(ptdata, FAIL);
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void errno_stop(ADDRINT eax)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    if (!hf || strcmp(hf->name, "errno")) return;
    
    GRAB_GLOBAL_LOCK (ptdata);
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    mem_clear_dependency(ptdata, eax);
    mem_clear_dependency(ptdata, eax + 1);
    mem_clear_dependency(ptdata, eax + 2);
    mem_clear_dependency(ptdata, eax + 3);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getprotobyname_start(ADDRINT name) 
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("getprotobyname");

    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "getprotobyname", 0);
    //the special value means whether the argument had taint or not
    struct taint* arg_taint;
    char dest_char;
    while(1) {
        if ((arg_taint = get_mem_taint(name)) != NULL) {
            merge_taints(&hf->args_taint, arg_taint);
            hf->special_value = 1;
        }
        if ((PIN_SafeCopy(&dest_char, (const void*)name, 1) != 1) || (dest_char == '\0'))
            break;
        name++;
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}

void getprotobyname_stop(ADDRINT protoent_ptr)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("getprotobyname");
    GRAB_GLOBAL_LOCK (ptdata);
    if (protoent_ptr) {
        struct protoent* prot = (struct protoent*)protoent_ptr;
        char dest_char;
        while((PIN_SafeCopy(&dest_char, (const void*)prot->p_name, 1) == 1) && (dest_char != '\0')) {
            if (hf->special_value) {
                mem_mod_dependency(ptdata, (ADDRINT)(prot->p_name), &hf->args_taint, SET, 1); 
	    } else
                mem_clear_dependency(ptdata, (ADDRINT)(prot->p_name));
            prot->p_name++;
        }
        char* alias;
        while((alias = *(prot->p_aliases)) != 0) {
            while((PIN_SafeCopy(&dest_char, (const void*)alias, 1) == 1) && (dest_char != '\0')) {
                if (hf->special_value) {
                    mem_mod_dependency(ptdata, (ADDRINT)alias, &hf->args_taint, SET, 1); 
                } else
                    mem_clear_dependency(ptdata, (ADDRINT)alias);
                alias++;
            }
            prot->p_aliases++;
        }
        if (hf->special_value) {
            mem_mod_dependency(ptdata, (ADDRINT)&(prot->p_proto), &hf->args_taint, SET, 1);
        } else
            mem_clear_dependency(ptdata, (ADDRINT)&(prot->p_proto));
    }
    if (hf->special_value == 1) {
        reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    } else  
        reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);

    RELEASE_GLOBAL_LOCK (ptdata);
}

void getnameinfo_start(ADDRINT host, ADDRINT host_size, ADDRINT serv, ADDRINT serv_size) 
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;

    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "getnameinfo", 0);
    if (host !=0 && (int)host_size !=0) {
        for (int i = 0; i < (int)host_size; i++) {
            mem_clear_dependency(ptdata, host + i);
        }
    }
    if (serv != 0 && (int)serv_size != 0) {
        for (int i = 0; i < (int)serv_size; i++) {
            mem_clear_dependency(ptdata, serv + i);
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}


void lowupper_start(ADDRINT first_ref)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("lowupper");
    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "lowupper", 0);
    for(int i = 0; i < (int)sizeof(int); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(first_ref + i));
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void lowupper_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("lowupper");
    GRAB_GLOBAL_LOCK (ptdata);
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void gettimeofday_start(ADDRINT tv, ADDRINT tz)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;

    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "gettimeofday", 0);

    for(int i = 0; i < (int)sizeof(struct timeval); i++)
        mem_clear_dependency(ptdata, (ADDRINT)tv + i);
    for(int i = 0; i < (int)sizeof(struct timezone); i++)
        mem_clear_dependency(ptdata, (ADDRINT)tz + i);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getsockname_start(ADDRINT sock_ref, ADDRINT name, ADDRINT len)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("getsockname");
    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "getsockname", 0);

    for (int i = 0; i < (int)sizeof(int); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(sock_ref + i));
    }
    int size = *((int*)len);
    for(int i = 0; i < size; i++)
        mem_mod_dependency(ptdata, (ADDRINT)name + i, &hf->args_taint, SET, 1);
    
    for(int i = 0; i < (int)sizeof(int); i++)
        mem_mod_dependency(ptdata, (ADDRINT)len + i, &hf->args_taint, SET, 1);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void getsockname_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("getsockname");
    GRAB_GLOBAL_LOCK (ptdata);
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void isspace_start(ADDRINT arg_ref)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("isspace");
    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "isspace", 0);

    for (int i = 0; i < (int)sizeof(int); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(arg_ref + i));
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void isspace_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("isspace");
    GRAB_GLOBAL_LOCK (ptdata);
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

int check_pid_file(struct thread_data* ptdata, int pid, struct taint* dep) 
{
    GRAB_GLOBAL_LOCK (ptdata);
    int tf, rc = 0, found_flag = 0;
    int size = 2*sizeof(int) + sizeof(struct taint);
    char data[size];
    int read_pid = 0;
    int read_req = 0;
    int read_data = 0;

    tf = open("/tmp/pids", O_RDONLY|O_CREAT, 0644);
    if (!tf) {
        printf("Could not open /tmp/pids file\n");
        RELEASE_GLOBAL_LOCK (ptdata);
        return -1;
    }
    //lock the file we're gonna read from
    if (flock(tf, LOCK_EX) == -1) {
        printf("Process %d couldn't grab the pids file lock\n", PIN_GetPid());
        goto error;
    }
    while(1) {
        read_data = 0;
        while (read_data < size) {
            rc = read(tf, data + read_data, size - read_data);
            if (rc == 0) {
                if(flock(tf, LOCK_UN) == -1) {
                    printf("Process %d couldn't release the /tmp/pids file lock\n", PIN_GetPid());
                    goto error;
                }
                if (read_data != 0) {
                    printf("%d: Could not read from /tmp/pids, errno: %d\n", PIN_GetPid(), errno);
                    int cd = access("/tmp/pids", R_OK);
                    if (cd) {
                        printf("%d: whelp couldn't read the file on access\n", PIN_GetPid());
                    } else {
                        printf("%d: wait i could read it\n", PIN_GetPid());
                    }
                    // get the file size of the file
                    struct stat buf;
                    fstat(tf, &buf);
                    printf("%d: the offset of the file is %ld, file size is %ld\n", PIN_GetPid(), lseek(tf, 0, SEEK_CUR), buf.st_size);
                    goto error;
                }
                goto normal;
            } else if (rc < 0) {
                goto error;
            }
            read_data += rc;
        }
        memcpy(&read_pid, data, sizeof(int));
        memcpy(&read_req, data + sizeof(int), sizeof(int));
        SPEC_PRINT(log_f, "we read pid %d with req_id %d\n", read_pid, read_req);
        memcpy(dep, data + 2*sizeof(int), sizeof(struct taint));
                                          
        if (read_pid == (int)pid) {
            SPEC_PRINT(log_f, "the pid we want (%d) has returned\n", (int)pid);
            found_flag = 1;
            break;
        }
    }

    //unlock the file
    if(flock(tf, LOCK_UN) == -1) {
        printf("Process %d couldn't release the important file lock\n", PIN_GetPid());
        goto error;
    }
    
    close(tf);
    RELEASE_GLOBAL_LOCK (ptdata);
    return found_flag;
error:
    close(tf);
    RELEASE_GLOBAL_LOCK (ptdata);
    return -1;
normal:
    close(tf);
    RELEASE_GLOBAL_LOCK (ptdata);
    return 0;
}

void waitpid_start(ADDRINT status_addr)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "waitpid", status_addr);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void waitpid_stop(ADDRINT pid)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    if (!hf || strcmp(hf->name, "waitpid")) return;

    GRAB_GLOBAL_LOCK (ptdata);
    
    int rc = 0;
    int n_fd, watch_desc;
    char buf[sizeof(struct inotify_event)];
    struct taint dep;
    new_taint(&dep);
    
    if ((int)pid <= 0) {
        goto end;
    }

    // mcc: this is pretty gross and hard-coded in.
    // on a successful return from a waitpid we watch the /tmp/pids file
    // and read back the receiving taint

    // waitpid returned if pid > 0

    rc = check_pid_file(ptdata, (int)pid, &dep);
    if (rc == 1) {
        goto found_end;
    } else if (rc == -1) {
        goto end;
    }
    
    if ((n_fd = inotify_init()) == -1) {
        printf("could not initialize inotify, errno: %d\n", errno);
        goto end;
    }

    watch_desc = inotify_add_watch(n_fd, "/tmp/pids", IN_MODIFY);
    while(1) {
        SPEC_PRINT(log_f, "Start watching the pid for modifications...\n");
        rc = read(watch_desc, buf, sizeof(struct inotify_event));
        if (rc <= 0) {
            SPEC_PRINT(log_f, "could not read from the watch descriptor\n");
            close(watch_desc);
            close(n_fd);
            break;
        }
        //our file is modified.
        rc = check_pid_file(ptdata, (int)pid, &dep);
        if (rc == 1) {
            close(watch_desc);
            close(n_fd);
            goto found_end;
        } else if (rc == -1) {
            close(watch_desc);
            close(n_fd);
            goto end;
        }
    }

found_end:
    fprintf (stderr, "Pid %d (recpid %d) wait_pid stop of pid %d read taint: ", PIN_GetPid(), ptdata->record_pid, (int)pid); 
    __print_dependency_tokens(stderr, &dep);

    PRINT_SPEC_VECTOR(&dep);
    if (hf->special_value) {
        for (int i = 0; i < (int)sizeof(int); i++) {
            // mcc: this will taint the retval status of waitpid
            mem_mod_dependency(ptdata, (ADDRINT)(hf->special_value + i), &dep, SET, 1);
            fprintf(stderr, "\t set memory address %#x to that taint\n", (hf->special_value + i));
        }
    }
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &dep, SET, 1); // mcc: this will taint the return value of waitpid
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
    return;
end:
    if (hf->special_value) {
        for (int i = 0; i < (int)sizeof(int); i++) 
            mem_clear_dependency(ptdata, (ADDRINT)(hf->special_value + i));
    }
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void memcmp_start(ADDRINT s1, ADDRINT s2, ADDRINT size_ref, ADDRINT size)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("memcmp_start");
    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "memcmp", 0);
    for(int i = 0; i < (int)size; i++) {
        merge_taints(&hf->args_taint, get_mem_taint(s1 + i));
    }
    for(int i = 0; i < (int)size; i++) {
        merge_taints(&hf->args_taint, get_mem_taint(s2 + i));
    }
    for(int i = 0; i < (int)sizeof(int); i++) {
        merge_taints(&hf->args_taint, get_mem_taint(size_ref + i));
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void memcmp_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("memcmp");
    GRAB_GLOBAL_LOCK (ptdata);
    reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void dh_compute_start(ADDRINT first_arg)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("DH_compute_key");
    GRAB_GLOBAL_LOCK (ptdata);
    //the special value is the first argument, pointer to the result
    make_handled_function(ptdata, "DH_compute_key", 0);
    for (int i = 0; i < (int)sizeof(DH); i++) {
        mem_clear_dependency(ptdata, first_arg + i);
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void dh_compute_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("DH_compute_key");
    GRAB_GLOBAL_LOCK (ptdata);
    reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void dh_generate_start(ADDRINT first_arg)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    //the special value is the first argument, pointer to the result
    struct handled_function* hf = make_handled_function(ptdata, "DH_generate_key", first_arg);
    DH* dh_ptr = (DH*)first_arg;
    ADDRINT p_num = (ADDRINT)dh_ptr->p->d;
    ADDRINT g_num = (ADDRINT)dh_ptr->g->d;
    for(int i = 0; i < dh_ptr->p->dmax; i++) {
        merge_taints(&hf->args_taint, get_mem_taint(p_num + i));
    }
    for(int i = 0; i < dh_ptr->g->dmax; i++) {
        merge_taints(&hf->args_taint, get_mem_taint(g_num + i));
    }
    BIGNUM* priv_key = dh_ptr->priv_key;
    if (priv_key) {
        ADDRINT priv_num = (ADDRINT)priv_key->d;
        for(int i = 0; i < priv_key->dmax; i++) {
            merge_taints(&hf->args_taint, get_mem_taint(priv_num + i));
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void taint_BIGNUM(struct thread_data* ptdata, BIGNUM* big_num, struct taint* taint, int tainted)
{
    GRAB_GLOBAL_LOCK (ptdata);
    ADDRINT addr = (ADDRINT)(big_num->d);
    for (int i = 0; i < (int)sizeof(BIGNUM); i++) {
        if (tainted) {
            mem_mod_dependency(ptdata, (ADDRINT)big_num+i, taint, SET, 1);
        } else {
            mem_clear_dependency(ptdata, (ADDRINT)big_num+i);
        }
    }
    for (int i = 0; i < 4*big_num->dmax; i++) {
        if (tainted) {
            mem_mod_dependency(ptdata, addr+i, taint, SET, 1);
        } else {
            mem_clear_dependency(ptdata, addr+i);
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void dh_generate_stop(ADDRINT res)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    struct handled_function* hf = HANDLED_FUNC_HEAD;
    if (!hf || strcmp(hf->name, "DH_generate_key")) return;
    GRAB_GLOBAL_LOCK (ptdata);
    //int tainted = !is_taint_equal(&hf->args_taint, &zero);
    int tainted = 0;
    if (res) {
        taint_BIGNUM(ptdata, ((DH*)hf->special_value)->pub_key, &hf->args_taint, tainted);
    }
    if (tainted) {
        reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    }
    else {
        reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    }
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void rsa_sign_start(ADDRINT m, ADDRINT m_len, ADDRINT sigret, ADDRINT sig_len)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("RSA_sign");
    GRAB_GLOBAL_LOCK (ptdata);
    struct taint tmp;
    new_taint(&tmp);
    
    for(int i = 0; i < (int)m_len; i++) {
        merge_taints(&tmp, get_mem_taint(m + i));
    }                           
    //int tainted = !is_taint_equal(&tmp, &zero);
    int tainted = 0;

    for(int i = 0; i < (int)sig_len; i++) {                 
        if (tainted) {
            mem_mod_dependency(ptdata, sigret+i, &tmp, SET, 1);
        } else
            mem_clear_dependency(ptdata, sigret + i);
    }
    struct handled_function* hf = make_handled_function(ptdata, "RSA_sign", tainted);
    if (tainted)
        set_taint(&hf->args_taint, &tmp);
    
    RELEASE_GLOBAL_LOCK (ptdata);
}

void rsa_sign_stop()
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("RSA_sign");
    GRAB_GLOBAL_LOCK (ptdata);
    if (hf->special_value) {
        reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    } else  
        reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void rand_bytes_start(ADDRINT buf, ADDRINT num)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    make_handled_function(ptdata, "RAND_bytes", 0);
    //gonna go ahread and taint the output right now.
    for (int i = 0; i < (int)num; i++) {
        mem_clear_dependency(ptdata, buf + i);
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}

void hex2bn_start(ADDRINT first_arg, ADDRINT sec_arg)
{
    struct thread_data* ptdata;
    START_HANDLED_FUNCTION ("BN_hex2bn");
    GRAB_GLOBAL_LOCK (ptdata);
    struct handled_function* hf = make_handled_function(ptdata, "BN_hex2bn", first_arg);
    int i = 0;
    while(1) {
        merge_taints(&hf->args_taint, get_mem_taint(sec_arg + i));
        if(*(char*)(sec_arg+i) == '\0') break;
        i++;
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}
        
void hex2bn_stop(ADDRINT res)
{
    struct thread_data* ptdata;
    STOP_HANDLED_FUNCTION ("BN_hex2bn");
    GRAB_GLOBAL_LOCK (ptdata);
    int tainted = !is_taint_zero(&hf->args_taint);
    if(res) {               
        BIGNUM* addr = *(BIGNUM**)hf->special_value; 
        if (addr)  {
            taint_BIGNUM(ptdata, addr, &hf->args_taint, tainted);
        }
    }
    if (tainted) {
        reg_mod_dependency(ptdata, LEVEL_BASE::REG_EAX, &hf->args_taint, SET, 1);
    } else  
        reg_clear_dependency(ptdata, LEVEL_BASE::REG_EAX);
    free_handled_function(ptdata);
    RELEASE_GLOBAL_LOCK (ptdata);
}

void nptl_deallocate_start ()
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);
    // Eventually need to turn off alternate path here 

//    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
//    fprintf (stderr, "Thread is starting to exit\n");
//    fprintf (stderr, "Exiting record pid is %d\n", ptdata->record_pid);
    RELEASE_GLOBAL_LOCK (ptdata);
}

#ifdef CTRL_FLOW
void set_no_spec()
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED || CALLING_BBLOCK_HEAD->status == CONSERVATIVE)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    MYASSERT(CALLING_BBLOCK_HEAD);
    CALLING_BBLOCK_HEAD->status = NO_SPEC;
    SPEC_PRINT(log_f, "setting a function no_spec\n");
    RELEASE_GLOBAL_LOCK (ptdata);
}

void set_conservative()
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (CALLING_BBLOCK_HEAD && (CALLING_BBLOCK_HEAD->status == HANDLED)) return;
    GRAB_GLOBAL_LOCK (ptdata);
    MYASSERT(CALLING_BBLOCK_HEAD);
    CALLING_BBLOCK_HEAD->status = CONSERVATIVE;
    SPEC_PRINT(log_f, "setting a function conservative\n");
    RELEASE_GLOBAL_LOCK (ptdata);
}
#endif

#ifdef DEBUG_TAINT
void instrument_current_function (ADDRINT name, ADDRINT address)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (ptdata) ptdata->current_function = address;
    // LOG_PRINT ("Calling function %s\n", (char *) name);
}
#endif

void inspect_function_args_start(ADDRINT name, ADDRINT arg0, ADDRINT arg1, ADDRINT arg0_ref, ADDRINT arg1_ref)
{
#ifdef LOGGING_ON
    char* funcname = (char *) name;
    LOG_PRINT ("[INSPECT] inspect_function_args_start: %s\n", funcname);
#endif

    for (int i = 0; i < (int)(sizeof(int) * 2); i++) {
        LOG_PRINT ("[INSPECT] arg1_ref %#x ", arg1_ref + i);
        __print_dependency_tokens(LOG_F, get_mem_taint(arg1_ref + i));
    }
}

void inspect_function_args_stop(ADDRINT name, ADDRINT res)
{
#ifdef LOGGING_ON
    char* funcname = (char *) name;
    LOG_PRINT ("[INSPECT] inspect_function_args_stop: %s\n", funcname);
    __print_dependency_tokens(LOG_F, get_reg_taint(LEVEL_BASE::REG_EAX));
#endif
}

void track_function(RTN rtn, void* v) 
{
    RTN_Open(rtn);
#ifdef DEBUG_TAINT
    const char* name = RTN_Name(rtn).c_str();
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)instrument_current_function, IARG_PTR, name, IARG_PTR, RTN_Address(rtn), IARG_END);
#endif

#ifdef CONFAID
    /*
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)check_function_args, IARG_PTR, name, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                IARG_END);
*/
#endif

#ifdef CTRL_FLOW
    int* status_ptr = (int*)(g_hash_table_lookup(functions_hash, name));
    int status;
    if (!status_ptr) goto close_out;
    status = *status_ptr;
    if (status == NO_SPEC) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)set_no_spec, IARG_END);
        goto close_out;
    }
    if (status == CONSERVATIVE) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)set_conservative, IARG_END); 
        goto close_out;
    }
#endif

#ifdef LINKAGE_SYSCALL
    /* All syscall wrapper abstractions. For system calls with no glibc wrappers,
     * see handle_syscall_start and handle_syscall_stop */
    else if (!strcmp(name, "llseek") || !strcmp(name, "__llseek") || !strcmp(name, "__libc_lseek")
            || !strcmp(name, "__lseek64") || !strcmp(name, "lseek64") || !strcmp(name, "__libc_lseek64")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)llseek_start, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 4, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)llseek_stop, IARG_END);
    }
    else if (!strcmp(name, "__close") || !strcmp(name, "__close_nocancel")
               || !strcmp(name, "close") || !strcmp(name, "__libc_close")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)close_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)close_stop, IARG_PTR, name,
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } else if (!strcmp(name, "fstat64") || !strcmp(name, "fstat")
            || !strcmp(name, "__fstat") || !strcmp(name, "__fxstat64")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fstat_start, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_PTR, name, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)stat_stop, IARG_PTR, name,  IARG_END);
    } else if (!strcmp(name, "stat64") || !strcmp(name, "stat") || !strcmp(name, "__stat") || 
            !strcmp(name, "lstat64") || !strcmp(name, "lstat") || !strcmp(name, "__lstat")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)stat_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_PTR, name, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)stat_stop, IARG_PTR, name,  IARG_END);
    } else if (!strcmp(name, "___lxstat64") || !strcmp(name, "__xstat") 
            || !strcmp(name, "___xstat64") || !strcmp(name, "__xstat64")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)stat_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_PTR, name, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)stat_stop, IARG_PTR, name,  IARG_END);
    } else if (!strcmp(name, "__read") || !strcmp(name, "__read_nocancel")

            || !strcmp(name, "__libc_read") || !strcmp(name, "read")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)read_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)read_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } else if (!strcmp(name, "readv") || !strcmp(name, "preadv")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)readv_start,
               IARG_PTR, name,
               IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
               IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)readv_stop,
                IARG_PTR, name,
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } else if (!strcmp(name, "recv") || !strcmp(name, "__libc_recv")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)recv_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)recv_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } else if (!strcmp(name, "mmap") || !strcmp(name, "__mmap") || 
            !strcmp(name, "__mmap64") || !strcmp(name, "mmap64")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mmap_start, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)mmap_stop, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } else if (!strcmp(name, "send") || !strcmp(name, "__send") ||
             !strcmp(name, "__libc_send")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)send_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)send_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } 
    else if (!strcmp(name, "llseek") || !strcmp(name, "__llseek") || !strcmp(name, "__libc_lseek")
            || !strcmp(name, "__lseek64") || !strcmp(name, "lseek64") || !strcmp(name, "__libc_lseek64")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)llseek_start, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 4, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)llseek_stop, IARG_END);
    } else if (!strcmp(name, "__open") || !strcmp(name, "__open64") || 
            !strcmp(name, "open") || !strcmp(name, "open64") ||
            !strcmp(name, "__open_nocancel") ||
            !strcmp(name, "__libc_open") || !strcmp(name, "__libc_open64"))  {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)open_start, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)open_stop, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } 
    /* Libc functions that we abstract that aren't system calls */

    /* enable and disable dep prints*/
    if (!strcmp(name, "socket") || !strcmp(name, "__socket")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)socket_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)socket_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } else if (!strcmp(name, "socketpair")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)socketpair_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)socketpair_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "__bind") || !strcmp(name, "bind")
            || !strcmp(name, "__connect") || !strcmp(name, "__connect_internal") 
            || !strcmp(name, "connect") || !strcmp(name, "__libc_connect")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)bind_connect_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
                IARG_PTR, name, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)bind_connect_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_PTR, name,  IARG_END);

    } else if (!strcmp(name, "__dup2") ||!strcmp(name, "dup2") ) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)dup2_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)dup2_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "__libc_fcntl") || !strcmp(name, "__fcntl") ||
            !strcmp(name, "__fcntl_nocancel") || !strcmp(name, "fcntl")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fcntl_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fcntl_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    
    } else if (!strcmp(name, "listen") || !strcmp(name, "__listen")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)listen_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)listen_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "__write") || !strcmp(name, "write") 
            || !strcmp(name, "__libc_write")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)write_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
    
    } else if (!strcmp(name, "__write_nocancel")) {
        //seems like Pin cannot recognize the IPOINT_AFTER of write.
        
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)write_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_FUNCRET_EXITPOINT_REFERENCE, IARG_END);

    } else if (!strcmp(name, "unlink") || !strcmp(name, "__unlink")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)unlink_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_PTR, "unlink", IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)unlink_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "rename")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)rename_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)rename_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    
    } else if (!strcmp(name, "uname") || !strcmp(name, "__uname")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)uname_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)uname_stop, IARG_END);
    
    } else if (!strcmp(name, "setsockopt") || !strcmp(name, "__setsockopt")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, IARG_PTR, name, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_stop, IARG_PTR, name, IARG_END);

    } else if (!strcmp(name, "getsockopt") || !strcmp(name, "__getsockopt")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getsockopt_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getsockopt_stop, IARG_END);

    } else if (!strcmp(name, "pipe") || !strcmp(name, "__pipe")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)pipe_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)pipe_stop, IARG_END);
    
    } else if (!strcmp(name, "accept") || !strcmp(name, "__libc_accept")) {
        //didnot propagate taint between the two fds
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)accept_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)accept_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    
    } else if (!strcmp(name, "getpid") || !strcmp(name, "__getpid") ) {
#ifdef HAVE_REPLAY
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)change_getpid, 
                IARG_REG_REFERENCE, LEVEL_BASE::REG_EAX, IARG_END);
#endif
    } else if (!strcmp(name, "execve") || !strcmp(name, "__execve") ) {
	// RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)check_exec_path, 
        //        IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);

    } else if (!strcmp(name, "__libc_writev") || !strcmp(name, "writev") || 
            !strcmp(name, "__writev")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)writev_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                IARG_END);
        // RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, IARG_PTR, name, IARG_END);
	// RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_stop, IARG_PTR, name, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)writev_stop,
		IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "mmap") || !strcmp(name, "__mmap") || 
            !strcmp(name, "__mmap64") || !strcmp(name, "mmap64")) {
        // Instrumentation to track memory areas
        /*
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mem_mmap_start, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)mem_mmap_stop, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        */

    } else if (!strcmp(name, "munmap") || !strcmp(name, "__munmap")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, IARG_PTR, name, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_stop, IARG_PTR, name, IARG_END);

        // Instrumentation to track memory areas
        /*
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mem_munmap_start, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)mem_munmap_stop, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        */

    } else if (!strcmp(name, "__readdir") || !strcmp(name, "__readdir64_r") ||
            !strcmp(name, "readdir64_r")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, IARG_PTR, "readdir", IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)readdir_stop, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } else if (!strcmp(name, "rmdir") || !strcmp(name, "__rmdir")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)rmdir_start, IARG_INST_PTR, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_PTR, "rmdir", IARG_END);
        // Looks like Pin can't recognize the point after rmdir, so we instrument after the system call
        //RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)rmdir_stop, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    }
    else if (!strcmp(name, "main")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)main_start, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)main_stop, IARG_END);
    } else if (!strcmp(name, "strcmp") || !strcmp(name, "__strcasecmp") 
            || !strcmp(name, "strcasecmp")
            || !strcmp(name, "__strcmp_gg")) {     
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcmp_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)strcmp_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } else if (!strcmp(name, "_IO_fgets") || !strcmp(name, "fgets_unlocked")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fgets_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fgets_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "__chdir") || !strcmp(name, "chdir")) { 
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_string_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_PTR, "chdir", IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)chdir_stop, IARG_END);

    } else if (!strcmp(name, "apr_palloc") || !strcmp(name, "apr_pcalloc")) { 
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)apr_palloc_start, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_stop, IARG_PTR, name, IARG_END);

    } else if (!strcmp(name, "__libc_malloc") || !strcmp(name, "__malloc")
            || !strcmp(name, "malloc")) {                                       
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)malloc_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)malloc_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "__realloc") || !strcmp(name, "__libc_realloc")
            || !strcmp(name, "realloc")) { 
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)realloc_start, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)realloc_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    
    } else if (!strcmp(name, "__calloc") ||!strcmp(name, "__libc_calloc") 
            || !strcmp(name, "calloc")) {
       RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)calloc_start, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
        		  IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
       RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)calloc_stop, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "__cfree") || !strcmp(name, "cfree")
            || !strcmp(name, "__free") || !strcmp(name, "free") || !strcmp(name, "__libc_free")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)free_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_PTR, name, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_void_stop, IARG_PTR, name, IARG_END);
     
    }
    else if (!strcmp(name, "_dl_runtime_resolve")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)dl_runtime_resolve_start, IARG_PTR, name, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)dl_runtime_resolve_stop, IARG_PTR, name, IARG_END);
    } else if (!strcmp(name, "__dcgettext")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, IARG_PTR, name, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_void_stop, IARG_PTR, name, IARG_END);
    } else if (!strcmp(name, "getspnam")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_string_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_PTR, "getspnam", IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getspnam_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } else if (!strcmp(name, "getpwnam")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_string_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_PTR, name, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getpw_stop, IARG_PTR, name,
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "getpwuid")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getpwuid_start, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getpw_stop, IARG_PTR, "getpwuid",
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "__fork") || !strcmp(name, "__libc_fork")
           || !strcmp(name, "fork")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, IARG_PTR, "fork", IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fork_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "time")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)time_start, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)time_stop, IARG_END);
    
    } else if (!strcmp(name, "__sigaction") || !strcmp(name, "sigaction") || 
            !strcmp(name, "__libc_sigaction")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)sigaction_start, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)sigaction_stop, IARG_END);
                                   

    } else if (!strcmp(name, "select") || !strcmp(name, "__select") || !strcmp(name,"__libc_select") ||!strcmp(name, "___newselect_nocancel")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)select_start, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)select_stop, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } else if ( //!strcmp(name, "fflush") || !strcmp(name, "_IO_fflush") || 
        !strcmp(name, "kill") || !strcmp(name, "__kill") ||
        !strcmp(name, "__closedir") || !strcmp(name, "closedir") || 
        !strcmp(name, "dlsym") || !strcmp(name, "__dlsym") || !strcmp(name, "__libc_dlsym") || 
        !strcmp(name, "initgroups") ||
        !strcmp(name, "getuid") || !strcmp(name, "__getuid") ||
        !strcmp(name, "getgid") || !strcmp(name, "__getgid") ||
        !strcmp(name, "geteuid") || !strcmp(name, "__geteuid") ||
        !strcmp(name, "getegid") || !strcmp(name, "__getegid") ||
        !strcmp(name, "setgid") || !strcmp(name, "__setgid") ||
        !strcmp(name, "setuid") || !strcmp(name, "__setuid") ||
        !strcmp(name, "epoll_create") ||
        !strcmp(name, "epoll_ctl") ||
        !strcmp(name, "poll") || !strcmp(name, "__poll") || !strcmp(name, "__libc_poll") || 
        //!strcmp(name, "sendfile64") ||
        !strcmp(name, "semget") ||
        !strcmp(name, "_IO_vfprintf") || !strcmp(name, "vfprintf") ||
        !strcmp(name, "_IO_vfprintf_internal") || 
        !strcmp(name, "getservbyname") || 
        !strcmp(name, "semop") ||
        !strcmp(name, "_IO_ferror") || !strcmp(name, "ferror")) {

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, IARG_PTR, name, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_stop, IARG_PTR, name, IARG_END);

    }  else if (!strcmp(name, "sendfile64")) {
#ifdef CONFAID
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)output_cf_taint, IARG_PTR, name, IARG_END);
#endif
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, IARG_PTR, name, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_stop, IARG_PTR, name, IARG_END);
    }
    else if (!strcmp(name, "getaddrinfo")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getaddrinfo_start,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getaddrinfo_stop,
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "getgrnam")) { 
        //some fields are not covered yet
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_string_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_PTR, name, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getgr_stop, IARG_PTR, name,  
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "getgrgid")) { 
        //some fields are not covered yet
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getgrgid_start, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getgr_stop, IARG_PTR, "getgrgid",  
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "_IO_getc")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getc_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0 ,IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getc_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "crypt") || !strcmp(name, "__crypt_r")) {
        //ignoring the taint of the delim
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)crypt_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)crypt_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "fcrypt")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fcrypt_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fcrypt_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "_IO_new_fclose") || !strcmp(name, "_IO_fclose") ||
            !strcmp(name, "__new_fclose") || !strcmp(name, "fclose")) { 
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fclose_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fclose_stop, IARG_PTR, name, IARG_END);

    } else if (!strcmp(name, "mutex_trylock")) { 
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mutex_trylock_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)mutex_trylock_stop, IARG_END);

    } else if (!strcmp(name, "exit") || !strcmp(name, "_exit")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)exit_start, IARG_END);
        
    } else if (!strcmp(name, "error") || !strcmp(name, "__assert_fail")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)error_start, IARG_END);
        
    } else if (!strcmp(name, "__errno_location")) {
        //I think errno doesn't need to be tainted!!!source of trouble
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, 
                IARG_PTR, "errno", IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)errno_stop, 
                IARG_REG_VALUE, LEVEL_BASE::REG_EAX, IARG_END);
    
    } else if (!strcmp(name, "getprotobyname")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getprotobyname_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getprotobyname_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    
    } else if (!strcmp(name, "getnameinfo")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getnameinfo_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_stop, IARG_PTR, "getnameinfo", IARG_END);

    } else if (!strcmp(name, "tolower") || !strcmp(name, "toupper")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)lowupper_start, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)lowupper_stop, IARG_END);
    
    } else if (!strcmp(name, "gettimeofday") || !strcmp(name, "__gettimeofday") ||
            !strcmp(name, "__gettimeofday_internal")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)gettimeofday_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_stop, IARG_PTR, "gettimeofday", IARG_END);

    } else if (!strcmp(name, "__getsockname") || !strcmp(name, "getsockname")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)getsockname_start, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getsockname_stop, IARG_END);
    
    } else if (!strcmp(name, "isspace")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)isspace_start, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)isspace_stop, IARG_END);
    
    } else if (!strcmp(name, "__libc_waitpid") || !strcmp(name, "__waitpid_nocancel") 
            || !strcmp(name, "__waitpid") || !strcmp(name, "waitpid")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)waitpid_start,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)waitpid_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    
    } else if (!strcmp(name, "memcmp")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memcmp_start,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
                IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)memcmp_stop, IARG_END);
    }

    /* openSSL related functions */
    else if (!strcmp(name, "DH_compute_key")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)dh_compute_start,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)dh_compute_stop, IARG_END);

    } else if (!strcmp(name, "DH_generate_key")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)dh_generate_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)dh_generate_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

    } else if (!strcmp(name, "RSA_blinding_on") || 
            !strcmp(name, "RAND_status")) { 
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, IARG_PTR, name, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_stop, IARG_PTR, name, IARG_END);

    } else if (!strcmp(name, "RSA_sign")) {
        //TODO: ignoring the rsa key taint now
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)rsa_sign_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2 ,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4,IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)rsa_sign_stop, IARG_END);

    } else if (!strcmp(name, "RAND_seed")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, IARG_PTR, name, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_void_stop, IARG_PTR, name, IARG_END);

    } else if (!strcmp(name, "RAND_bytes")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)rand_bytes_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_stop, 
                IARG_PTR, name, IARG_END);
    } else if (!strcmp(name, "BN_hex2bn")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hex2bn_start, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
	RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)hex2bn_stop, 
                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    } else if (!strcmp(name, "__nptl_deallocate_tsd")) {
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)nptl_deallocate_start, IARG_END);
    }
    // lighttpd yacc
    //else if (!strcmp(name, "yy_shift") || !strcmp(name, "yy_reduce") || !strcmp(name, "yy_accept")) {
    else if (!strcmp(name, "yy_shift") || !strcmp(name, "yy_find_shift_action") || !strcmp(name, "yy_accept")) {
	    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)generic_start, IARG_PTR, name, IARG_END);
	    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)generic_void_stop, IARG_PTR, name, IARG_END);
    } 
    else if (!strcmp(name, "log_scripterror") || !strcmp(name, "logit") 
		    || !strcmp(name, "ap_log_rerror") || !strcmp(name, "msg_fatal")
		    || !strcmp(name, "msg_warn")) {
	    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)output_cf_taint, IARG_PTR, name, IARG_END);
    } 
#endif // LINKAGE_SYSCALL
    
#ifdef CTRL_FLOW
close_out:
#endif
    RTN_Close(rtn);
    return;
}

guint instbbl_hash(gconstpointer key)
{
    return (guint)(((instbbl*)key)->inst_addr);
}

gboolean instbbl_cmp(gconstpointer arg1, gconstpointer arg2)
{
    
    if (((unsigned)((instbbl*)arg1)->inst_addr) != ((unsigned)((instbbl*)arg2)->inst_addr))
        return FALSE;
    return TRUE;
}

#ifdef ALT_PATH_EXPLORATION
BOOL pin_segv_signal_handler(THREADID id, INT32 sig, CONTEXT* ctx, BOOL hasHandler, 
                                const EXCEPTION_INFO* pExceptInfo, VOID* v) {
    CALLBACK_PRINT(log_f, "CALLBACK_PRINT: pin_signal_handler starts\n");
    SIGNAL_PRINT(log_f, "SIGNAL: signal %d is received\n", sig);
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if(NUM_CKPTS > 0) {
	INFO_PRINT(log_f, "INFO: a segfault is received, about to rollback now\n");
	segfault_captured = 1;
        CALLBACK_PRINT(log_f, "CALLBACK_PRINT: pin_signal_handler ends\n");
        return FALSE;
    }
    CALLBACK_PRINT(log_f, "CALLBACK_PRINT: pin_signal_handler ends\n");
    return TRUE;
}
#endif

struct cmd_line_args {
    int argc;
    char ** argv;
};

#ifdef HAVE_REPLAY
void track_trace(TRACE trace, void* data)
{
	// System calls automatically end a Pin trace.
	// So we can instrument every trace (instead of every instruction) to check to see if
	// the beginning of the trace is the first instruction after a system call.
	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_instr_after, IARG_INST_PTR, IARG_END);
}
#endif

BOOL follow_child(CHILD_PROCESS child, void* data)
{
    // FIXME
    fprintf(stderr, "ERROR: following exec NEEDS to be FIXED\n");
    return TRUE;
}

void load_image(IMG img, void* v)
{
    ADDRINT start_address;
    ADDRINT end_address;
    ADDRINT offset;

    //start_address = IMG_StartAddress(img);
    //end_address = start_address + IMG_SizeMapped(img);
    start_address = IMG_LowAddress(img);
    end_address = IMG_HighAddress(img);
    offset = IMG_LoadOffset(img);

    LOG_PRINT ("load_image (%s): start %#x end %#x load offset %#x\n", IMG_Name(img).c_str(), start_address, end_address, IMG_LoadOffset(img));

    if (IMG_IsMainExecutable(img)) {
        main_low_addr = IMG_LowAddress(img);
        main_high_addr = IMG_HighAddress(img);
    }

    add_image_info(img_list, start_address, end_address, offset, IMG_Id(img), IMG_Name(img).c_str());
}

void unload_image(IMG img, void* v)
{
    remove_image_info(img_list, IMG_Id(img));
}

gboolean remove_instbbl_bblock(gpointer key, gpointer value, gpointer user_data)
{
    struct instbbl* arg = (struct instbbl*)key;
    if (arg->inst_addr == arg->bblock->first_inst->inst_addr) goto free;
    if (!arg->bblock) goto free;
    free(arg->bblock);
#ifdef MEM
    mems[7] -= sizeof(struct bblock);
#endif
free:
    free(arg);
#ifdef MEM
    mems[6] -= sizeof(struct instbbl);
#endif
    return TRUE;
}

void cleanup_bblocks_instbbls()
{
    g_hash_table_foreach_remove(hashtable, remove_instbbl_bblock, 0);
    g_hash_table_destroy(hashtable);
}

gboolean functions_cmp(gconstpointer arg1, gconstpointer arg2)
{
    if (strcmp((char*)arg1, (char*)arg2) == 0)
        return TRUE;
    return FALSE;
}

#ifdef DUMP_TAINTS
/* Dump the state of the taints at the end of the analysis
 * Warning, this could be big
 * */
void dump_taints(FILE* out_file)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);

    struct taint** first_t;
    struct taint* second_t;
    u_long address;

    for (int i = 0; i < FIRST_TABLE_SIZE; i++) {
        first_t = (struct taint**) mem_loc_high[i];
        if (first_t) {
            for (int j = 0; j < SECOND_TABLE_SIZE; j++) {
                second_t = first_t[j];
                if (second_t) {
                    for (int k = 0; k < THIRD_TABLE_SIZE; k++) {
                        if (!is_taint_zero(&second_t[k])) {
                            address = (i << (SECOND_TABLE_BITS + THIRD_TABLE_BITS)) | (j << THIRD_TABLE_BITS) | k;
                            fprintf (out_file, "0x%08lx: ", address);
                            print_taint(out_file, &second_t[k]);
                        }
                    }
                }
            }
        }
    }
    RELEASE_GLOBAL_LOCK (ptdata);
}
#endif

void __print_taint_string_buffer(FILE* file, char* buf, int size)
{
    int cnt = 0;
    char dest_char;
    struct taint* vector;
    ADDRINT tmp = (ADDRINT) buf;
    fprintf(file, "will print string starting at %#x to %#x\n", (ADDRINT) buf, ((ADDRINT) buf) + size);
    fflush(file);
    while(1) {
        if ((PIN_SafeCopy(&dest_char, (const void*)tmp, 1) != 1) || (dest_char == '\0')) {
            break;
        }
        if (cnt >= size) {
            break;
        }
        vector = get_mem_taint((ADDRINT) tmp);
        fprintf(file, "%#x: ", (ADDRINT) tmp);
        __print_dependency_tokens(file, vector);
        fflush(file);
        tmp += 1;
        cnt += 1;
    }
    fflush(file);
}

void fini(INT32 code, void* v) {
    time_t t = time(0);
    struct tm* tm = localtime(&t);
    fprintf(stderr, "process %d in fini\n", PIN_GetPid());
    fprintf(stderr, "time is: %d:%d:%d\n", tm->tm_hour, tm->tm_min, tm->tm_sec);
#ifdef TAINT_STATS
    fprintf(stderr, "option cnt is %d\n", option_cnt);
#ifdef TAINT_IMPL_INDEX
    fprintf(stderr, "index cnt is %ld\n", idx_cnt);
#endif
    fprintf(stderr, "Instrument insts: %ld\n", instrumented_insts);
    // print_input_data (stderr);
#endif // TAINT_STATS

#ifdef DUMP_TAINTS
    FILE* dtaint;
    dtaint = fopen("/tmp/taint_dump", "w");
    dump_taints(dtaint);
    fclose(dtaint);
#endif

#ifdef TF_STATS
    fprintf (stderr, "Number of real mod mems allocated %ld\n", num_real_mod_mems);
#endif
#ifdef INTER_PROCESS_PROPAGATION
    //cleanup_pin_fds();
#endif
#ifdef DEBUG_TAINT
#ifdef TAINT_PRINT
    fclose(taint_f);
#endif
#endif
    cleanup_bblocks_instbbls();
    
    fclose(log_f);
}

void usage() 
{
    printf("usage: (all the locations should be complete address\n");
    exit(-1);
}

void thread_start (THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    struct thread_data* ptdata;

    LOG_PRINT ("Pid %d thread start with threadid %d\n", PIN_GetPid(), threadid);

    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    if (ptdata == NULL) {
        fprintf (stderr, "ptdata is NULL\n");
        assert (0);
    }
    assert (ptdata);
    
    ptdata->next = tdhead;
    ptdata->prev = NULL;
    if (tdhead) tdhead->prev = ptdata;
    tdhead = ptdata;
	
    ptdata->threadid = threadid;
    ptdata->record_pid = get_record_pid();
#ifdef HAVE_REPLAY
    get_record_group_id(dev_fd, &ptdata->rg_id);
    fprintf(stderr, "record group is is %llu\n", ptdata->rg_id);
    ptdata->ignore_flag = 0; // set when syscall 31 is called
#else
    ptdata->rg_id = get_record_pid();
#endif
    ptdata->app_syscall = 0;
    ptdata->brk_saved_loc = 0;
    SYSNUM = 0;
    CURRENT_BBL = NULL;
    CALLING_BBLOCK_HEAD = NULL;
    CALLING_BBLOCK_SIZE = 0;

    /*Initializing the ctrflow taint stack*/
    CTRFLOW_TAINT_STACK = (struct taint_info*)malloc(sizeof(struct taint_info));
    MYASSERT(CTRFLOW_TAINT_STACK);
    new_taint(&(CTRFLOW_TAINT_STACK->condition_taint));
#ifdef ALT_PATH_EXPLORATION
    memset(&(CTRFLOW_TAINT_STACK->Ta), 255, sizeof(struct taint));
#endif
    init_taint_info(CTRFLOW_TAINT_STACK);
    CTRFLOW_TAINT_STACK->merge_bblock = 0;
    CTRFLOW_TAINT_STACK->calling_bblock_size = 0;
    CTRFLOW_TAINT_STACK->prev = 0;
    CTRFLOW_TAINT_STACK->alt_path = 0;
    CTRFLOW_TAINT_STACK_SIZE = 1;
    new_taint(&CTRFLOW_TAINT_STACK->ctrflow_taint);
    new_taint(&SELECT_TAINT);
    CKPTS = NULL;
    ALLOC_CKPTS = NULL;
    NUM_CKPTS = 0;
    TOTAL_NUM_CKPTS = 0;
    HANDLED_FUNC_HEAD = NULL;
    MERGE_ON_NEXT_RET = 0;
    NUM_INSTS = 0;
    BBL_OVER = 0;
    BBLOCK_DIFFERENCE_MATCHED = 0;

    for (int i = 0; i < NUM_REGS; i++) {
        new_taint(&(SAVED_REG_TAINTS[i]));
    }
    for (int i = 0; i < NUM_FLAGS; i++) {
        new_taint(&(SAVED_FLAG_TAINTS[i]));
    }
    memset(&ptdata->syscall_taint_info, 0, sizeof(struct handled_function));

    ptdata->save_syscall_info = 0;
    ptdata->syscall_handled = 0;

#ifdef HAVE_REPLAY
    if (!no_replay) {
        set_pin_addr (dev_fd, (u_long) &(ptdata->app_syscall));
    }
#endif

    PIN_SetThreadData (tls_key, ptdata, threadid);

    // create options for each of the program args
#ifdef HAVE_REPLAY
#ifndef CONFAID
    if (!no_replay && first_thread) {
        // Need to make the args and envp in an exec count as input
        // Retrieve the location of the args from the kernel
        int acc = 0;
        char** args;
        args = (char **) get_replay_args (dev_fd);
        LOG_PRINT ("replay args are %#lx\n", (unsigned long) args);
        while (1) {
            char* arg;
            arg = *args;

            // args ends with a NULL
            if (!arg) {
                break;
            }
            LOG_PRINT ("arg is %s\n", arg);
#ifndef FILTER_INPUTS
            create_options_from_buffer (TOK_EXEC, global_syscall_cnt, arg, strlen(arg) + 1, acc, (void *) "ARGS");
            acc += strlen(arg) + 1;
#endif
            args += 1;
        }
        // Retrieve the location of the env. var from the kernel
        args = (char **) get_env_vars (dev_fd);
        LOG_PRINT ("env. vars are %#lx\n", (unsigned long) args);
        while (1) {
            char* arg;
            arg = *args;

            // args ends with a NULL
            if (!arg) {
                break;
            }
            LOG_PRINT ("arg is %s\n", arg);
#ifndef FILTER_INPUTS
            create_options_from_buffer (TOK_EXEC, global_syscall_cnt, arg, strlen(arg) + 1, acc, (void *) "ENV");
            acc += strlen(arg) + 1;
#endif
            args += 1;
        }
    }
#endif // CONFAID
#endif

#ifdef DEBUG_TAINT
    fprintf(stderr, "DEBUG TAINT is ON\n");
#endif

#ifdef CONFAID
    if (first_thread) {
        // set the first option to be the config file.
        // The config file is used to tokenize the config options.
        create_new_named_token (0, (char *) "config_file");
        option_cnt = 1;
    }
#endif
    first_thread = 0;
}

void force_exit() {
    fprintf(stderr, "Exiting...\n");
    exit(1);
}

int setup_logs() {
    int rc;
    char log_name[64];
#ifdef DEBUG_TAINT
#ifdef TAINT_PRINT
    char taint_log_name[256];
#endif
#ifdef TRACE_TAINTS
    char trace_log_name[256];
#endif
#endif

    if (log_f) fclose(log_f);
    sprintf(log_name, "/tmp/confaid.log.%d", PIN_GetPid());
    log_f = fopen(log_name, "a");
    if(!log_f) {
        printf("ERROR: cannot open log_file\n");
        return -1;
    }
    fprintf(stderr, "Log file name is %s\n", log_name);

#ifdef DEBUG_TAINT
#ifdef TAINT_PRINT
    if (taint_f) fclose(taint_f);
    // set up taint printing
    sprintf(taint_log_name, "/tmp/confaid.taintfile.%d", get_record_pid());
    taint_f = fopen(taint_log_name, "w");
    if(!taint_f) {
        printf("ERROR: cannot open taint_file\n");
        return -4;
    }
#endif
#ifdef TRACE_TAINTS
    if (trace_f) fclose(trace_f);
    // set up taint tracing
    sprintf(trace_log_name, "/tmp/confaid.tracefile.%d", get_record_pid());
    trace_f = fopen(trace_log_name, "w");
    if (!trace_f) {
        printf("ERROR: cannot open trace_file\n");
        return -5;
    }
#endif
#endif

    // now that files are created, change permissions
    rc = chmod(log_name, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    if (rc != 0) {
        printf("whaaat??\n");
        return -6;
    }
#ifdef DEBUG_TAINT
#ifdef TAINT_PRINT
    rc = chmod(taint_log_name, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    if (rc != 0) {
        printf("whaaat??\n");
        return -9;
    }
#endif
#ifdef TRACE_TAINT
    rc = chmod(trace_log_name, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    if (rc != 0) {
        printf("whaaaat??\n");
        return -10;
    }
#endif
#endif

    return 0;
}

/* Should be called at the beginning...not thread-safe */
void setup_message_input(const char* input_msg)
{
    int rc;
    input_message_regex = (regex_t *) malloc(sizeof(regex_t));
    rc = regcomp(input_message_regex, input_msg, REG_EXTENDED);
    if (rc) {
        fprintf(stderr, "Could not create input message regex, rc: %d\n", rc);
        exit(-1);
    }
}

int main(int argc, char** argv) 
{
    int rc;

    fprintf(stderr, "Starting up\n");

    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        fprintf(stderr, "could not init?\n");
    }

    fprintf(stderr, "output file is %s\n", KnobOutputFile.Value().c_str());
    fprintf(stderr, "Starting up the PIN tool, pid: %d\n", PIN_GetPid());
    /*Initialization*/
    rc = setup_logs();
    if (rc) {
        fprintf(stderr, "Could not setup logs, error code %d\n", rc);
        exit(1);
    }

    LOG_PRINT ("%d, starting the process\n", PIN_GetPid());
    LOG_PRINT ("%d, starting the process with argc %d and the following argv\n", argc, PIN_GetPid());
    for (int i = 0; i < argc; i++) {
        LOG_PRINT ("argv[%d]: %s\n", i, argv[i]);
    }
        
    // make a copy of argv for follow_child
    char** follow_argv;
    follow_argv = (char **) malloc(sizeof(char *) * argc);
    for (int i = 0; i < argc; i++) {
        follow_argv[i] = argv[i];
    }

    LOG_PRINT ("this is the dataflow too, we'll be running the dataflow analysis\n");

    // Open in "w+" mode because an exec will wipe out this file, if in "w"
    output_f = fopen(KnobOutputFile.Value().c_str(), "w+");
    if (output_f == 0) {
        fprintf(stderr, "no output file is specified, exiting..\n");
        exit(-1);
    }

    if (!option_byte) {
        // pass in the regex string that identifies a new request
        setup_message_input("echo");
    }

    // TODO check to make sure the path actually exists
#ifdef CTRL_FLOW
    if (!realpath(KnobStaticAnalysisPath.Value().c_str(), static_analysis_path)) {
        fprintf(stderr, "could not get static analysis path %s, errno %d\n", KnobStaticAnalysisPath.Value().c_str(), errno);
        exit(-1);
    }
#endif

    memset(mem_loc_high, 0, FIRST_TABLE_SIZE*sizeof(void*));
    for (int i  = 0; i < NUM_REGS; i++) {
        new_taint(&(reg_table[i]));
    }
    for (int i = 0; i < NUM_FLAGS; i++) {
        new_taint(&(flag_table[i]));
    }
 
    struct rlimit rbuf;
    getrlimit (RLIMIT_FSIZE, &rbuf);
    LOG_PRINT ("file size soft limit %ld, hard limit %ld, unlimited is %ld\n", rbuf.rlim_cur, rbuf.rlim_max, RLIM_INFINITY);

    /* Initializaing the hash table */
    hashtable = g_hash_table_new(instbbl_hash, instbbl_cmp);
    
    memset (final_reg_shifts, 0, sizeof(final_reg_shifts));
    memset (final_flag_shifts, 0, sizeof(final_flag_shifts));
    final_mem_shifts = g_hash_table_new(g_int_hash, g_int_equal);

    /* Initializing the functions hashtable */
    functions_hash = g_hash_table_new(g_str_hash, functions_cmp);
    initialize_functions();

    // init the list of memory areas
#ifdef TRACK_MEMORY_AREAS
    ma_list = new_memory_areas();
#endif

    // init the list of images
    img_list = new_image_infos();

    // init the option metadata hashtable
    option_info_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    if (!open_fds) {
        open_fds = new_xray_monitor(sizeof(struct open_info));
    }

    fflush(log_f);

#ifdef GLOBAL_LOCK
    // Initialize the giant lock
    init_reentry_lock(&relock);
#endif

#ifdef HAVE_REPLAY
    no_replay = atoi(KnobTurnOffReplay.Value().c_str());
    if (!no_replay && devspec_init (&dev_fd) < 0) {
        fprintf(stderr, "devspec_init failed, can't setup replay? exiting.\n");
        return -1;
    }
    if (!no_replay) {
        // account for the first exec that we miss
        global_syscall_cnt = 1;
    }
#endif

#ifdef CONFAID
    make_confaid_data(KnobInputFile.Value().c_str(), KnobErrorRegex.Value().c_str());
    LOG_PRINT ("Starting in Confaid mode\n");
#endif
#ifdef FILTER_INPUTS
    strncpy(input_file_name, KnobInputFileFilter.Value().c_str(), 256);
#endif

    init_shift_cache();

#ifdef TAINT_IMPL_INDEX
    INIT_TAINT_INDEX();
#endif

    // Obtain a key for TLS storage
    tls_key = PIN_CreateThreadDataKey(0);

    PIN_AddThreadStartFunction(thread_start, 0);
    IMG_AddInstrumentFunction(load_image, 0);
    IMG_AddUnloadFunction(unload_image, 0);
#ifdef HAVE_REPLAY
    TRACE_AddInstrumentFunction (track_trace, 0);
#endif
    //instrument each instruction
    INS_AddInstrumentFunction(track_file, 0);
    RTN_AddInstrumentFunction(track_function, 0);
    
    struct cmd_line_args* cla;
    cla = (struct cmd_line_args *) malloc(sizeof(struct cmd_line_args));
    cla->argc = argc;
    cla->argv = follow_argv;

    PIN_AddFollowChildProcessFunction(follow_child, cla);

#ifdef ALT_PATH_EXPLORATION
    PIN_InterceptSignal(SIGSEGV, pin_segv_signal_handler, 0);
#endif

    PIN_AddFiniFunction(fini, 0);
    PIN_AddSyscallExitFunction(instrument_syscall_ret, 0);

    fprintf(stderr, "About to start program with pid %d\n", PIN_GetPid());
    LOG_PRINT("Starting program now with pid %d\n", PIN_GetPid());

    PIN_StartProgram();
    return 0;
}
