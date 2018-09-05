/* This pintool is the minimal Pin tool that supports Pin + Replay,
 * no extra functionality */
#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <syscall.h>
#include "util.h"
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

struct thread_data {
    u_long app_syscall; // Per thread address for specifying pin vs. non-pin system calls
    uint64_t rg_id;
    int record_pid; 	// per thread record pid
    int sysnum;		// current syscall number
};

TLS_KEY tls_key; // Key for accessing TLS. 

#if 0
int dev_fd; // File descriptor for the replay device

int get_record_pid(void);
#endif

void inst_syscall_end(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
        if (tdata->app_syscall != 999) tdata->app_syscall = 0;
    } else {
        fprintf (stderr, "inst_syscall_end: NULL tdata\n");
    }	

    // reset the syscall number after returning from system call
    tdata->sysnum = 0;
}

// called before every application system call
void set_address_one(ADDRINT syscall_num, ADDRINT ebx_value, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2)
{   
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
#if 0
        int sysnum = (int) syscall_num;
        // fprintf (stderr, "Pid %d, tid %d, (record pid %d), syscall num is %d\n", PIN_GetPid(), PIN_GetTid(), tdata->record_pid, (int) syscall_num);

        if (sysnum == 45 || sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
            check_clock_before_syscall (dev_fd, (int) syscall_num);
        }
#endif
        tdata->app_syscall = syscall_num;
    } else {
        fprintf (stderr, "set_address_one: NULL tdata\n");
    }
}

void syscall_after (ADDRINT ip)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    printf ("syscall is %x\n", ip);
    if (tdata) {
        if (tdata->app_syscall == 999) {
#if 0
            // fprintf (stderr, "Pid %d Waiting for clock after syscall,ip=%lx\n", PIN_GetPid(), (u_long) ip);
            if (check_clock_after_syscall (dev_fd) == 0) {
            } else {
                fprintf (stderr, "Check clock failed\n");
            }
#endif
            tdata->app_syscall = 0;  
        }
    } else {
        fprintf (stderr, "syscall_after: NULL tdata\n");
    }
}

#if 0
void AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    int record_pid;
    record_pid = get_record_pid();
    tdata->record_pid = record_pid;
}
#endif

static int foo = 0;

void track_inst(INS ins, void* data) 
{
    if(INS_IsSyscall(ins)) {
      foo = 1;
      ADDRINT addr = LEVEL_PINCLIENT::INS_Address(ins);
      printf ("Syscall at address %x\n", addr);
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(set_address_one), IARG_SYSCALL_NUMBER, 
                    IARG_REG_VALUE, LEVEL_BASE::REG_EBX, 
		    IARG_SYSARG_VALUE, 0, 
		    IARG_SYSARG_VALUE, 1,
		    IARG_SYSARG_VALUE, 2,
		    IARG_END);
    } else if (foo) {
      ADDRINT addr = LEVEL_PINCLIENT::INS_Address(ins);
      printf ("After syscall at address %x\n", addr);
      foo = 0;
    }
}

void track_trace(TRACE trace, void* data)
{
	// System calls automatically end a Pin trace.
	// So we can instrument every trace (instead of every instruction) to check to see if
	// the beginning of the trace is the first instruction after a system call.
	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_END);
}

BOOL follow_child(CHILD_PROCESS child, void* data)
{
#if 0
    char** argv;
    char** prev_argv = (char**)data;
    int index = 0;

    /* the format of pin command would be:
     * pin_binary -follow_execv -t pin_tool new_addr*/
    int new_argc = 5;
    argv = (char**)malloc(sizeof(char*) * new_argc);

    argv[0] = prev_argv[index++];                   // pin
    argv[1] = (char *) "-follow_execv";
    while(strcmp(prev_argv[index], "-t")) index++;
    argv[2] = prev_argv[index++];
    argv[3] = prev_argv[index++];
    argv[4] = (char *) "--";

    CHILD_PROCESS_SetPinCommandLine(child, new_argc, argv);
#endif

    return TRUE;
}

#if 0
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
#endif

void thread_start (THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    struct thread_data* ptdata;
    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    
    ptdata->app_syscall = 0;
    //ptdata->record_pid = get_record_pid();
    //get_record_group_id(dev_fd, &ptdata->rg_id);

    PIN_SetThreadData (tls_key, ptdata, threadid);

    //set_pin_addr (dev_fd, (u_long) ptdata);
}

int main(int argc, char** argv) 
{    
  //int rc;

    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        fprintf(stderr, "ERROR: could not initialize Pin?\n");
        exit(-1);
    }

#if 0
    // Intialize the replay device
    rc = devspec_init (&dev_fd);
    if (rc < 0) return rc;

#endif
    // Obtain a key for TLS storage
    tls_key = PIN_CreateThreadDataKey(0);

    PIN_AddThreadStartFunction(thread_start, 0);

    PIN_AddFollowChildProcessFunction(follow_child, argv);

    INS_AddInstrumentFunction(track_inst, 0);
#if 0

    // Register a notification handler that is called when the application
    // forks a new process
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);
    TRACE_AddInstrumentFunction (track_trace, 0);
#endif
    PIN_AddSyscallExitFunction(inst_syscall_end, 0);

    PIN_StartProgram();

    return 0;
}

