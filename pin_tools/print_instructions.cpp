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

// #define TIMING_ON

long print_limit = 10;
KNOB<string> KnobPrintLimit(KNOB_MODE_WRITEONCE, "pintool", "p", "10000000", "syscall print limit");
long print_stop = 10;
KNOB<string> KnobPrintStop(KNOB_MODE_WRITEONCE, "pintool", "s", "10000000", "syscall print stop");
// #define DEBUG_FUNCTIONS
#ifdef DEBUG_FUNCTIONS
long function_print_limit = 10;
long function_print_stop = 10;
KNOB<string> KnobFunctionPrintLimit(KNOB_MODE_WRITEONCE, "pintool", "f", "10000000", "function print limit");
KNOB<string> KnobFunctionPrintStop(KNOB_MODE_WRITEONCE, "pintool", "g", "10000000", "function print stop");
#endif

long global_syscall_cnt = 0;
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
	if (!(syscall_num == 17 || syscall_num == 31 || syscall_num == 32 || syscall_num == 35 || 
				syscall_num == 44 || syscall_num == 53 || syscall_num == 56 || syscall_num == 98 ||
				syscall_num == 119 || syscall_num == 123 || syscall_num == 186 ||
				syscall_num == 243 || syscall_num == 244)) {
		if (ptdata->ignore_flag) {
			if (!(*(int *)(ptdata->ignore_flag))) {
				global_syscall_cnt++;
				ptdata->syscall_cnt++;
			}
		} else {
			global_syscall_cnt++;
			ptdata->syscall_cnt++;
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
    if (tdata) {
	if (tdata->app_syscall != 999) tdata->app_syscall = 0;
    } else {
	fprintf (stderr, "inst_syscall_end: NULL tdata\n");
    }	

    // reset the syscall number after returning from system call
    tdata->sysnum = 0;
}

// called before every application system call
#ifdef USE_TLS_SCRATCH
void set_address_one(ADDRINT syscall_num, ADDRINT ebx_value, ADDRINT tls_ptr, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2)
#else
void set_address_one(ADDRINT syscall_num, ADDRINT ebx_value, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2)
#endif
{   
#ifdef USE_TLS_SCRATCH
    struct thread_data* tdata = (struct thread_data *) tls_ptr;
#else
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
#endif
    if (tdata) {
	int sysnum = (int) syscall_num;
	
	fprintf (stderr, "%ld Pid %d, tid %d, (record pid %d), %d: syscall num is %d\n", global_syscall_cnt, PIN_GetPid(), PIN_GetTid(), tdata->record_pid, tdata->syscall_cnt, (int) syscall_num);

    if (sysnum == SYS_open) {
        fprintf(stderr, "try to open %s\n", (char *) syscallarg0);
    }
    if (sysnum == 31) {
	    tdata->ignore_flag = (u_long) syscallarg1;
    }

	if (sysnum == 45 || sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
	//if (sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
	    check_clock_before_syscall (fd, (int) syscall_num);
	}
	tdata->app_syscall = syscall_num;
	tdata->sysnum = syscall_num;
    } else {
	fprintf (stderr, "set_address_one: NULL tdata\n");
    }
}

#ifdef USE_TLS_SCRATCH
void syscall_after (ADDRINT ip, ADDRINT tls_ptr)
#else
void syscall_after (ADDRINT ip)
#endif
{
#ifdef USE_TLS_SCRATCH
    struct thread_data* tdata = (struct thread_data *) tls_ptr;
#else
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
#endif
    if (tdata) {
	if (tdata->app_syscall == 999) {
	    // fprintf (stderr, "Pid %d Waiting for clock after syscall,ip=%lx\n", PIN_GetPid(), (u_long) ip);
	    if (check_clock_after_syscall (fd) == 0) {
	    } else {
		fprintf (stderr, "Check clock failed\n");
	    }
	    tdata->app_syscall = 0;  
	}
    } else {
	fprintf (stderr, "syscall_after: NULL tdata\n");
    }
    increment_syscall_cnt(tdata, tdata->sysnum);
}

void AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
#ifdef USE_TLS_SCRATCH
    struct thread_data* tdata = (struct thread_data *) PIN_GetContextReg(ctxt, tls_reg);
#else
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
#endif
    int record_pid;
    fprintf(stderr, "AfterForkInChild\n");
    record_pid = get_record_pid();
    fprintf(stderr, "get record id %d\n", record_pid);
    tdata->record_pid = record_pid;

    // reset syscall index for thread
    tdata->syscall_cnt = 0;
}

void instrument_inst_print (ADDRINT ip)
{
    if (global_syscall_cnt > print_limit && global_syscall_cnt < print_stop) {
	PIN_LockClient();
        fprintf(stderr, "[INST] Pid %d (tid: %d) (record %d) - %#x\n", PIN_GetPid(), PIN_GetTid(), get_record_pid(), ip);
	if (IMG_Valid(IMG_FindByAddress(ip))) {
		fprintf(stderr, "%s -- img %s static %#x\n", RTN_FindNameByAddress(ip).c_str(), IMG_Name(IMG_FindByAddress(ip)).c_str(), find_static_address(ip));
	}
	PIN_UnlockClient();
    }
}

void track_inst(INS ins, void* data) 
{
    if (print_limit != print_stop) {
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)instrument_inst_print, IARG_INST_PTR, IARG_END);
    }
#ifdef USE_TLS_SCRATCH
    if(INS_IsSyscall(ins)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(set_address_one), IARG_SYSCALL_NUMBER, 
                    IARG_REG_VALUE, LEVEL_BASE::REG_EBX, 
		    IARG_REG_VALUE, tls_reg,
		    IARG_SYSARG_VALUE, 0, 
		    IARG_SYSARG_VALUE, 1,
		    IARG_SYSARG_VALUE, 2,
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
	// System calls automatically end a Pin trace.
	// So we can instrument every trace (instead of every instruction) to check to see if
	// the beginning of the trace is the first instruction after a system call.
    /*
	struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
	if (tdata) {
		if (tdata->app_syscall == 999) {
			TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_END);
		}
	} else {
		fprintf (stderr, "syscall_after: NULL tdata\n");
	}
    */

    //TRACE_InsertIfCall(trace, IPOINT_BEFORE, (AFUNPTR) check_syscall_after, IARG_REG_VALUE, tls_reg, IARG_END);
    //TRACE_InsertThenCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_END);
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

    fprintf(stderr, "following child...\n");

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

    fprintf(stderr, "returning from follow child\n");
    fprintf(stderr, "pin my pid is %d\n", PIN_GetPid());
    fprintf(stderr, "%d is application thread\n", PIN_IsApplicationThread());
    getppid();

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

    fprintf (stderr, "Start of threadid %d\n", (int) threadid);

    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    assert (ptdata);
    
    ptdata->app_syscall = 0;
    ptdata->record_pid = get_record_pid();
    ptdata->syscall_cnt = 0;

#ifdef USE_TLS_SCRATCH
    // set the TLS in the virutal register
    PIN_SetContextReg(ctxt, tls_reg, (ADDRINT) ptdata);
#else
    PIN_SetThreadData (tls_key, ptdata, threadid);
#endif

    set_pin_addr (fd, (u_long) ptdata->app_syscall);
}

void thread_fini (THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    struct thread_data* ptdata;
    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    fprintf(stderr, "Pid %d (recpid %d, tid %d) thread fini\n", PIN_GetPid(), ptdata->record_pid, PIN_GetTid());
}

#ifdef DEBUG_FUNCTIONS
void before_function_call(ADDRINT name, ADDRINT rtn_addr)
{
    if (global_syscall_cnt >= function_print_limit && global_syscall_cnt < print_stop) {
        fprintf(stderr, "Before call to %s (%#x)\n", (char *) name, rtn_addr);
    }
}

void after_function_call(ADDRINT name, ADDRINT rtn_addr)
{
    if (global_syscall_cnt >= function_print_limit && global_syscall_cnt < print_stop) {
        fprintf(stderr, "After call to %s (%#x)\n", (char *) name, rtn_addr);
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
	fprintf(stderr, "[IMG] Loading image id %d, name %s with load offset %#x\n",
			id, IMG_Name(img).c_str(), load_offset);
}


void fini(INT32 code, void* v) {
    fprintf(stderr, "process is done\n");
#ifdef TIMING_ON
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        fprintf(stderr, "Pid %d start %ld secs %ld usecs\n", PIN_GetPid(), tv.tv_sec, tv.tv_usec);
    }
#endif
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
    function_print_limit = atoi(KnobFunctionPrintLimit.Value().c_str());
    function_print_stop = atoi(KnobFunctionPrintStop.Value().c_str());
#endif

    PIN_AddThreadStartFunction(thread_start, 0);
    PIN_AddThreadFiniFunction(thread_fini, 0);
    PIN_AddFiniFunction(fini, 0);

    PIN_AddFollowChildProcessFunction(follow_child, argv);
    INS_AddInstrumentFunction(track_inst, 0);

    // Register a notification handler that is called when the application
    // forks a new process
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);

    IMG_AddInstrumentFunction (ImageLoad, 0);
    TRACE_AddInstrumentFunction (track_trace, 0);
#ifdef DEBUG_FUNCTIONS
    RTN_AddInstrumentFunction (routine, 0);
#endif

    PIN_AddSyscallExitFunction(inst_syscall_end, 0);
#ifdef TIMING_ON
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        fprintf(stderr, "Pid %d start %ld secs %ld usecs\n", PIN_GetPid(), tv.tv_sec, tv.tv_usec);
    }
#endif

    PIN_StartProgram();

    return 0;
}
