#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <syscall.h>
#include "util.h"
#include <sys/wait.h>
#include <sys/time.h>
#include <glib-2.0/glib.h>
#include <iostream>

//#define PLUS_TWO
//#define TIMING_ON

struct thread_data* current_thread; // Always points to thread-local data (changed by kernel on context switch)

u_long print_limit = 0;
KNOB<string> KnobPrintLimit(KNOB_MODE_WRITEONCE, "pintool", "p", "10000000", "syscall print limit");
u_long print_stop = 100;
KNOB<string> KnobPrintStop(KNOB_MODE_WRITEONCE, "pintool", "s", "10000000", "syscall print stop");
char* addr_save = NULL;
KNOB<string> KnobSaveSyscallAddrs(KNOB_MODE_WRITEONCE, "pintool", "addr_save", "", "save syscall addrs to file");
char* addr_load = NULL;
KNOB<string> KnobLoadSyscallAddrs(KNOB_MODE_WRITEONCE, "pintool", "addr_load", "", "save syscall addrs to file");

#define DEBUG_FUNCTIONS
#ifdef DEBUG_FUNCTIONS
long function_print_limit = 10;
long function_print_stop = 10;
KNOB<string> KnobFunctionPrintLimit(KNOB_MODE_WRITEONCE, "pintool", "f", "10000000", "function print limit");
KNOB<string> KnobFunctionPrintStop(KNOB_MODE_WRITEONCE, "pintool", "g", "10000000", "function print stop");
#endif

long global_syscall_cnt = 0;
u_long* ppthread_log_clock = NULL;
/* Toggle between which syscall count to use */
#define SYSCALL_CNT tdata->syscall_cnt
// #define SYSCALL_CNT global_syscall_cnt

// Use a Pin virtual register to store the TLS pointer
#define USE_TLS_SCRATCH
#ifdef USE_TLS_SCRATCH
REG tls_reg;
#endif

struct thread_data {
    u_long app_syscall; // Per thread address for specifying pin vs. non-pin system calls
    int record_pid; 	// per thread record pid
    int syscall_cnt;	// per thread count of syscalls
    int sysnum;		// current syscall number
    u_long ignore_flag;
};

ADDRINT array[10000];
int child = 0;

int fd; // File descriptor for the replay device
TLS_KEY tls_key; // Key for accessing TLS. 

GHashTable* sysexit_addr_table; 

int get_record_pid(void);

ADDRINT find_static_address(ADDRINT ip)
{
	PIN_LockClient();
	IMG img = IMG_FindByAddress(ip);
	if (!IMG_Valid(img)) return ip;
	ADDRINT offset = IMG_LoadOffset(img);
	PIN_UnlockClient();
	return ip - offset;
}

inline void increment_syscall_cnt (struct thread_data* ptdata, int syscall_num)
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
    }
}


void inst_syscall_end(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
#ifdef USE_TLS_SCRATCH
    struct thread_data* tdata = (struct thread_data *) PIN_GetContextReg(ctxt, tls_reg);
#else
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
#endif
    if (tdata != current_thread) printf ("tdata %p current_thread %p\n", tdata, current_thread);

    if (current_thread) {
	if (current_thread->app_syscall != 999) current_thread->app_syscall = 0;
    } else {
	fprintf (stderr, "inst_syscall_end: NULL current_thread\n");
    }	

    increment_syscall_cnt(current_thread, current_thread->sysnum);
    // reset the syscall number after returning from system call
    current_thread->sysnum = 0;
    increment_syscall_cnt(current_thread, current_thread->sysnum);
}

// called before every application system call
#ifdef USE_TLS_SCRATCH
#ifdef PLUS_TWO
void set_address_one(ADDRINT syscall_num, ADDRINT ebx_value, ADDRINT tls_ptr, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2, ADDRINT ip)
#else
void set_address_one(ADDRINT syscall_num, ADDRINT ebx_value, ADDRINT tls_ptr, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2)
#endif
#else
void set_address_one(ADDRINT syscall_num, ADDRINT ebx_value, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2)
#endif
{
#ifdef USE_TLS_SCRATCH
    struct thread_data* tdata = (struct thread_data *) tls_ptr;
#else
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
#endif
//    if (tdata != current_thread) printf ("sao: tdata %p current_thread %p\n", tdata, current_thread);
    if (tdata) {
	int sysnum = (int) syscall_num;
	
	printf ("%ld Pid %d, tid %d, (record pid %d), %d: syscall num is %d, clock is %lu\n", global_syscall_cnt, PIN_GetPid(), PIN_GetTid(), tdata->record_pid, tdata->syscall_cnt, (int) syscall_num, *ppthread_log_clock);

	if (sysnum == SYS_open) {
	    printf("try to open %s\n", (char *) syscallarg0);
	}
	if (sysnum == 31) {
	    tdata->ignore_flag = (u_long) syscallarg1;
	}

#ifdef PLUS_TWO
	    g_hash_table_add(sysexit_addr_table, GINT_TO_POINTER(ip+2));
	    printf ("Add address %x\n", ip+2);
	    g_hash_table_add(sysexit_addr_table, GINT_TO_POINTER(ip+11));
	    printf ("Add address %x\n", ip+11);
#endif	    
	if (sysnum == 45 || sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
	    check_clock_before_syscall (fd, (int) syscall_num);
	}
	tdata->app_syscall = syscall_num;
	tdata->sysnum = syscall_num;
    } else {
	fprintf (stderr, "set_address_one: NULL current_thread\n");
    }
}

#ifdef USE_TLS_SCRATCH
void syscall_after (ADDRINT ip, ADDRINT tls_ptr)
#else
void syscall_after (ADDRINT ip)
#endif
{
#ifdef USE_TLS_SCRATCH
//    struct thread_data* tdata = (struct thread_data *) tls_ptr;
#else
//    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
#endif
//    if (tdata != current_thread) printf ("sa: tdata %p current_thread %p\n", tdata, current_thread);
    if (current_thread) {
	if (current_thread->app_syscall == 999) {
	    if (addr_save) g_hash_table_add(sysexit_addr_table, GINT_TO_POINTER(ip));
	    if (check_clock_after_syscall (fd) == 0) {
	    } else {
		fprintf (stderr, "Check clock failed\n");
	    }
	    current_thread->app_syscall = 0;  
	}
    } else {
	fprintf (stderr, "syscall_after: NULL current_thread\n");
    }
}

void AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
#ifdef USE_TLS_SCRATCH
    struct thread_data* tdata = (struct thread_data *) PIN_GetContextReg(ctxt, tls_reg);
#else
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
#endif
    int record_pid;
    if (tdata != current_thread) printf ("afic: tdata %p current_thread %p\n", tdata, current_thread);
    printf ("AfterForkInChild\n");
    record_pid = get_record_pid();
    printf ("get record id %d\n", record_pid);
    current_thread->record_pid = record_pid;

    // reset syscall index for thread
    current_thread->syscall_cnt = 0;
}



void instrument_inst_print (ADDRINT ip)
{
    if (*ppthread_log_clock > print_limit && *ppthread_log_clock <= print_stop) {
	PIN_LockClient();
	
        printf("[INST] record %d - %#x, %lu\n", get_record_pid(), ip, *ppthread_log_clock);

	if (IMG_Valid(IMG_FindByAddress(ip))) {
		printf("%s -- img %s static %#x\n", RTN_FindNameByAddress(ip).c_str(), IMG_Name(IMG_FindByAddress(ip)).c_str(), find_static_address(ip));	 
	}
	


	PIN_UnlockClient();
    }
}

void instrument_inst_print_one_reg (ADDRINT ip, 
				    ADDRINT r1val,
				    REG r1 )
{
    if (*ppthread_log_clock > print_limit && *ppthread_log_clock <= print_stop) {
	PIN_LockClient();
	
        printf("[INST] record %d - %#x, %lu", get_record_pid(), ip, *ppthread_log_clock);
	printf(" (%s,%x)", REG_StringShort(r1).c_str(), r1val);

	printf("\n");

	if (IMG_Valid(IMG_FindByAddress(ip))) {
		printf("%s -- img %s static %#x\n", RTN_FindNameByAddress(ip).c_str(), IMG_Name(IMG_FindByAddress(ip)).c_str(), find_static_address(ip));	 
	}
	


	PIN_UnlockClient();
    }
}

void instrument_inst_print_two_reg (ADDRINT ip, 
				    ADDRINT r1val,
				    REG r1,
				    ADDRINT r2val,
				    REG r2)
{
    if (*ppthread_log_clock > print_limit && *ppthread_log_clock <= print_stop) {
	PIN_LockClient();
	
        printf("[INST] record %d - %#x, %lu", get_record_pid(), ip, *ppthread_log_clock);
	printf(" (%s,%x)", REG_StringShort(r1).c_str(), r1val);
	printf(" (%s,%x)", REG_StringShort(r2).c_str(), r2val);

	printf("\n");

	if (IMG_Valid(IMG_FindByAddress(ip))) {
		printf("%s -- img %s static %#x\n", RTN_FindNameByAddress(ip).c_str(), IMG_Name(IMG_FindByAddress(ip)).c_str(), find_static_address(ip));	 
	}
	


	PIN_UnlockClient();
    }
}


void track_inst(INS ins, void* data) 
{
    if (print_limit != print_stop) {

	REG r1 = REG_INVALID(), r2 = REG_INVALID();
	if (INS_OperandCount(ins) >= 1 && INS_OperandIsReg(ins, 0)) { 
	    r1 = INS_OperandReg(ins, 0);
	    if (!(REG_is_gr(r1) || REG_is_gr(r1) || REG_is_gr16(r1) || REG_is_gr8(r1))) {
		r1 = REG_INVALID();
	    }
	}
	if (INS_OperandCount(ins) >= 2 && INS_OperandIsReg(ins, 1)) { 
	    r2 = INS_OperandReg(ins, 1);
	    if (!(REG_is_gr(r2) || REG_is_gr32(r2) || REG_is_gr16(r2) || REG_is_gr8(r2))) {
		r2 = REG_INVALID();
	    }
	}	

	if (r1 != REG_INVALID() && r2 != REG_INVALID()) { 
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)instrument_inst_print_two_reg, IARG_INST_PTR, 
			   IARG_REG_VALUE, r1,
			   IARG_UINT32, r1,
			   IARG_REG_VALUE, r2,
			   IARG_UINT32, r2,	
			   IARG_END);	    
	}
	else if (r1 != REG_INVALID()){ 
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)instrument_inst_print_one_reg, IARG_INST_PTR, 
			   IARG_REG_VALUE, r1,
			   IARG_UINT32, r1,
			   IARG_END);	    
	}
	else if (r2 != REG_INVALID()) { 
	    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)instrument_inst_print_one_reg, IARG_INST_PTR, 
			   IARG_REG_VALUE, r2,
			   IARG_UINT32, r2,
			   IARG_END);	    
	}
	else {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)instrument_inst_print, IARG_INST_PTR,     IARG_END);
	}
 

    }
#ifdef USE_TLS_SCRATCH
    if(INS_IsSyscall(ins)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(set_address_one), IARG_SYSCALL_NUMBER, 
			   IARG_REG_VALUE, LEVEL_BASE::REG_EBX, 
			   IARG_REG_VALUE, tls_reg,
			   IARG_SYSARG_VALUE, 0, 
			   IARG_SYSARG_VALUE, 1,
			   IARG_SYSARG_VALUE, 2,
#ifdef PLUS_TWO
			   IARG_INST_PTR,
#endif
			   IARG_END);
    }
#else
    if(INS_IsSyscall(ins)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(set_address_one), IARG_SYSCALL_NUMBER, 
                    IARG_REG_VALUE, LEVEL_BASE::REG_EBX, 
		    IARG_SYSARG_VALUE, 0, 
		    IARG_SYSARG_VALUE, 1,
		    IARG_SYSARG_VALUE, 2,
		    IARG_END);
    }
#endif
}

void track_trace(TRACE trace, void* data)
{
#ifdef PLUS_TWO
    ADDRINT addr = TRACE_Address (trace);
    if (!g_hash_table_contains (sysexit_addr_table, GINT_TO_POINTER(addr))) return;
#endif

    if (addr_load) {
	ADDRINT addr = TRACE_Address (trace);
	if (!g_hash_table_contains (sysexit_addr_table, GINT_TO_POINTER(addr))) return;
    }
	
#ifdef USE_TLS_SCRATCH
    TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_REG_VALUE, tls_reg, IARG_END);
#else
    TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_END);
#endif
}

BOOL follow_child(CHILD_PROCESS child, void* data)
{
    char** argv;
    char** prev_argv = (char**)data;
    int index = 0;

    printf ("following child...\n");

    /* the format of pin command would be:
     * pin_binary -follow_execv -t pin_tool new_addr*/
    int new_argc = 5;
    argv = (char**)malloc(sizeof(char*) * new_argc);

    argv[0] = prev_argv[index++];
    argv[1] = (char *) "-follow_execv";
    while(strcmp(prev_argv[index], "-t")) index++;
    argv[2] = prev_argv[index++];
    argv[3] = prev_argv[index++];
    argv[4] = (char *) "--";

    CHILD_PROCESS_SetPinCommandLine(child, new_argc, argv);

    printf("returning from follow child\n");
    printf("pin my pid is %d\n", PIN_GetPid());
    printf("%d is application thread\n", PIN_IsApplicationThread());

    return TRUE;
}

int get_record_pid()
{
    //calling kernel for this replay thread's record log
    int record_log_id;

    record_log_id = get_log_id (fd);
    if (record_log_id == -1) {
        int pid = PIN_GetPid();
        fprintf(stderr, "Could not get the record pid from kernel, pid is %d\n", pid);
        return pid;
    }
    return record_log_id;
}

void thread_start (THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    struct thread_data* ptdata;

    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    assert (ptdata);
//    getppid();
//    fprintf (stderr, "Start of threadid %d ptdata %p\n", (int) threadid, ptdata);
    
    ptdata->app_syscall = 0;
    ptdata->record_pid = get_record_pid();
    //   get_record_group_id(dev_fd, &(ptdata->rg_id));

#ifdef USE_TLS_SCRATCH
    // set the TLS in the virutal register
    PIN_SetContextReg(ctxt, tls_reg, (ADDRINT) ptdata);
#else
    PIN_SetThreadData (tls_key, ptdata, threadid);
#endif

    int thread_ndx;
    long thread_status = set_pin_addr (fd, (u_long) &(ptdata->app_syscall), ptdata, (void **) &current_thread, &thread_ndx);
    /*
     * DON'T PUT SYSCALLS ABOVE THIS POINT! 
     */

    if (thread_status < 2) {
	current_thread = ptdata;
    }
    fprintf (stderr,"Thread %d gets rc %ld ndx %d from set_pin_addr\n", ptdata->record_pid, thread_status, thread_ndx);

}

void thread_fini (THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    struct thread_data* ptdata;
    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    printf("Pid %d (recpid %d, tid %d) thread fini\n", PIN_GetPid(), ptdata->record_pid, PIN_GetTid());
}

#ifdef DEBUG_FUNCTIONS
void before_function_call(ADDRINT name, ADDRINT rtn_addr)
{
    if (global_syscall_cnt >= function_print_limit && global_syscall_cnt < function_print_stop) {
        printf("Before call to %s (%#x)\n", (char *) name, rtn_addr);
    }
}

void after_function_call(ADDRINT name, ADDRINT rtn_addr)
{
    if (global_syscall_cnt >= function_print_limit && global_syscall_cnt < function_print_stop) {
        printf("After call to %s (%#x)\n", (char *) name, rtn_addr);
    }
}

void routine (RTN rtn, VOID *v)
{
    const char *name;

    name = RTN_Name(rtn).c_str();

    RTN_Open(rtn);

    if (!strstr(name, "get_pc_thunk")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)before_function_call,
                IARG_PTR, name, IARG_ADDRINT, RTN_Address(rtn), IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)after_function_call,
			    IARG_PTR, name, IARG_ADDRINT, RTN_Address(rtn), IARG_END);
    }

    RTN_Close(rtn);
}
#endif

VOID ImageLoad (IMG img, VOID *v)
{
	uint32_t id = IMG_Id (img);

	ADDRINT load_offset = IMG_LoadOffset(img);
	printf ("[IMG] Loading image id %d, name %s with load offset %#x\n",
		id, IMG_Name(img).c_str(), load_offset);
}

void print_addr (gpointer key, gpointer value, gpointer data)
{
	FILE* fp = (FILE*) data;
	fprintf (fp, "syscall addr: %p\n", key);
}

void fini(INT32 code, void* v) {
    printf ("process is done\n");
#ifdef TIMING_ON
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        printf("Pid %d start %ld secs %ld usecs\n", PIN_GetPid(), tv.tv_sec, tv.tv_usec);
    }
#endif

    if (addr_save) {
	FILE* fp;
	fp = fopen (addr_save, "w");
	if (fp == NULL) {
	    fprintf (stderr, "Cannot save addresses to file %s\n", addr_save);
	} else {
	    g_hash_table_foreach (sysexit_addr_table, print_addr, fp);
	    fclose(fp);
	}
    }
}

int main(int argc, char** argv) 
{    
    int rc;

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

    // Intialize the replay device
    rc = devspec_init (&fd);
    if (rc < 0) return rc;

#ifdef USE_TLS_SCRATCH
    // Claim a Pin virtual register to store the pointer to a thread's TLS
    tls_reg = PIN_ClaimToolRegister();
#else
    // Obtain a key for TLS storage
    tls_key = PIN_CreateThreadDataKey(0);
#endif

#ifdef DEBUG_FUNCTIONS
    print_limit = atoi(KnobPrintLimit.Value().c_str());
    print_stop = atoi(KnobPrintStop.Value().c_str());
    print_limit = 1;
//    print_stop = 100;
    function_print_limit = atoi(KnobFunctionPrintLimit.Value().c_str());
    function_print_stop = atoi(KnobFunctionPrintStop.Value().c_str());
#endif
    
    addr_load = (char *) KnobLoadSyscallAddrs.Value().c_str();
    addr_save = (char *) KnobSaveSyscallAddrs.Value().c_str();
    if (!strcmp(addr_load,"")) addr_load = NULL;
    if (!strcmp(addr_save,"")) addr_save = NULL;

    sysexit_addr_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (addr_load) {
	FILE* fp;
	u_long value;
	
	fp = fopen (addr_load, "r");
	if (fp == NULL) {
	    fprintf (stderr, "Cannot load addresses from %s\n", addr_load);
	    addr_load = NULL;
	} else {
	    while (!feof(fp)) {
		rc = fscanf (fp, "syscall addr: %lx\n", &value);
		if (rc == 1) {
		    g_hash_table_add(sysexit_addr_table, GINT_TO_POINTER(value));
		}
	    }
	    fclose(fp);
	}
    }

    PIN_AddThreadStartFunction(thread_start, 0);
    PIN_AddThreadFiniFunction(thread_fini, 0);
    PIN_AddFiniFunction(fini, 0);

    PIN_AddFollowChildProcessFunction(follow_child, argv);
    INS_AddInstrumentFunction(track_inst, 0);

    // Register a notification handler that is called when the application
    // forks a new process
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);

    TRACE_AddInstrumentFunction (track_trace, 0);
#ifdef DEBUG_FUNCTIONS
    RTN_AddInstrumentFunction (routine, 0);
#endif

    PIN_AddSyscallExitFunction(inst_syscall_end, 0);
#ifdef TIMING_ON
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        printf ("Pid %d start %ld secs %ld usecs\n", PIN_GetPid(), tv.tv_sec, tv.tv_usec);
    }
#endif



    ppthread_log_clock = map_shared_clock(fd);
    printf ("Log clock is %p, value is %ld\n", ppthread_log_clock, *ppthread_log_clock);

    PIN_StartProgram();

    return 0;
}
