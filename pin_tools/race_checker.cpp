#include "pin.H"
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include "util.h"
#include <string.h>
#include <stdlib.h>

#define START_AT_SYSCALL 717020
#define STOP_AT_SYSCALL  717031

// BEGIN GENERIC STUFF NEEDED TO REPLAY WITH PIN

struct thread_data {
    u_long app_syscall; // Per thread address for specifying pin vs. non-pin system calls
};

int fd; // File descriptor for the replay device
TLS_KEY tls_key; // Key for accessing TLS. 

void inst_syscall_end(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
	if (tdata->app_syscall != 999) tdata->app_syscall = 0;
    } else {
	fprintf (stderr, "inst_syscall_end: NULL tdata\n");
    }	
}

int syscall_cnt = 0;

void set_address_one(ADDRINT syscall_num, ADDRINT eax_ref)
{   
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
	int sysnum = (int) syscall_num;
	
	fprintf (stderr, "In set_address_one, num is %d, cnt is %d\n", (int) syscall_num, ++syscall_cnt);
	if (sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
	    check_clock_before_syscall (fd, (int) syscall_num);
	}
	tdata->app_syscall = syscall_num;
    } else {
	fprintf (stderr, "set_address_one: NULL tdata\n");
    }
}

void syscall_after (ADDRINT ip)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
	if (tdata->app_syscall == 999) {
	    fprintf (stderr, "Waiting for clock after syscall,ip=%lx\n", (u_long) ip);
	    if (check_clock_after_syscall (fd) == 0) {
	    } else {
		fprintf (stderr, "Check clock failed\n");
	    }
	    tdata->app_syscall = 0;  
	}
    } else {
	fprintf (stderr, "syscall_after: NULL tdata\n");
    }
}

// END GENERIC STUFF NEEDED TO REPLAY WITH PIN

#ifdef START_AT_SYSCALL

void instrument_call(ADDRINT address, ADDRINT target, ADDRINT next_address)
{
    if (syscall_cnt > START_AT_SYSCALL) {
#ifdef STOP_AT_SYSCALL
	if (syscall_cnt < STOP_AT_SYSCALL) {
#endif
	    fprintf (stderr, "Thread %5d Call 0x%08x target 0x%08x next 0x%08x\n", PIN_ThreadId(), address, target, next_address);
#ifdef STOP_AT_SYSCALL
	}
#endif
    }
}

void instrument_ret(ADDRINT address, ADDRINT target)
{
    if (syscall_cnt > START_AT_SYSCALL) {
#ifdef STOP_AT_SYSCALL
	if (syscall_cnt < STOP_AT_SYSCALL) {
#endif
	    fprintf (stderr, "Thread %5d Ret  0x%08x target 0x%08x\n", PIN_ThreadId(), address, target);
#ifdef STOP_AT_SYSCALL
	}
#endif
    }
}

void log_replay_enter (ADDRINT type, ADDRINT check)
{
    if (syscall_cnt > START_AT_SYSCALL) {
#ifdef STOP_AT_SYSCALL
	if (syscall_cnt < STOP_AT_SYSCALL) {
#endif
	    fprintf (stderr, "Thread %5d Repl type %d check %08lx\n", PIN_ThreadId(), (int) type, (u_long) check);
#ifdef STOP_AT_SYSCALL
	}
#endif
    }
}

void record_read (VOID* ip, VOID* addr, ADDRINT size)
{
    if (syscall_cnt > START_AT_SYSCALL) {
#ifdef STOP_AT_SYSCALL
	if (syscall_cnt < STOP_AT_SYSCALL) {
#endif
	    fprintf (stderr, "Thread %5d read address %p size 0x%lx (inst %p)\n", PIN_ThreadId(), addr, (u_long) size, ip);
#ifdef STOP_AT_SYSCALL
	}
#endif
    }
}

void record_read2 (VOID* ip, VOID* addr)
{
    if (syscall_cnt > START_AT_SYSCALL) {
#ifdef STOP_AT_SYSCALL
	if (syscall_cnt < STOP_AT_SYSCALL) {
#endif
	    fprintf (stderr, "Thread %5d read2 address %p (inst %p)\n", PIN_ThreadId(), addr, ip);
#ifdef STOP_AT_SYSCALL
	}
#endif
    }
}

void record_write (VOID* ip, VOID* addr, ADDRINT size)
{
    if (syscall_cnt > START_AT_SYSCALL) {
#ifdef STOP_AT_SYSCALL
	if (syscall_cnt < STOP_AT_SYSCALL) {
#endif
	    fprintf (stderr, "Thread %5d wrote address %p size 0x%lx (inst %p)\n", PIN_ThreadId(), addr, (u_long) size, ip);
#ifdef STOP_AT_SYSCALL
	}
#endif
    }
}

void record_locked (VOID* ip)
{
    if (syscall_cnt > START_AT_SYSCALL) {
#ifdef STOP_AT_SYSCALL
	if (syscall_cnt < STOP_AT_SYSCALL) {
#endif
	    fprintf (stderr, "Thread %5d locked inst %p\n", PIN_ThreadId(), ip);
#ifdef STOP_AT_SYSCALL
	}
#endif
    }
}

void log_replay_exit ()
{
    if (syscall_cnt > START_AT_SYSCALL) {
#ifdef STOP_AT_SYSCALL
	if (syscall_cnt < STOP_AT_SYSCALL) {
#endif
	    fprintf (stderr, "Thread %5d Repl Exit\n", PIN_ThreadId());
#ifdef STOP_AT_SYSCALL
	}
#endif
    }
}

void track_function(RTN rtn, void* v) 
{
    RTN_Open(rtn);
    const char* name = RTN_Name(rtn).c_str();
    if (!strcmp (name, "pthread_log_replay")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) log_replay_enter, 
		       IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) log_replay_exit, IARG_END);
    }
    RTN_Close(rtn);
}

#endif

void track_inst(INS ins, void* data) 
{
  // BEGIN GENERIC STUFF NEEDED TO REPLAY WITH PIN

    // The first system call is the ioctl associated with fork_replay.
    // We do not want to issue it again, so we NULL the call and return.
    if(INS_IsSyscall(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(set_address_one), IARG_SYSCALL_NUMBER, 
			   IARG_REG_REFERENCE, LEVEL_BASE::REG_EAX, IARG_END);

    } else {
	// Ugh - I guess we have to instrument every instruction to find which
	// ones are after a system call - would be nice to do better.
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)syscall_after, IARG_INST_PTR, IARG_END);
    }
  // END GENERIC STUFF NEEDED TO REPLAY WITH PIN

    if (INS_IsMemoryRead(ins)) {
	INS_InsertPredicatedCall (ins, IPOINT_BEFORE, AFUNPTR(record_read), IARG_INST_PTR,
				  IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    }
    if (INS_IsMemoryWrite(ins)) {
	INS_InsertPredicatedCall (ins, IPOINT_BEFORE, AFUNPTR(record_write), IARG_INST_PTR,
				  IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
    }
    if (INS_HasMemoryRead2(ins)) {
	INS_InsertPredicatedCall (ins, IPOINT_BEFORE, AFUNPTR(record_read2), IARG_INST_PTR,
				  IARG_MEMORYREAD2_EA, IARG_END);
    }
    if (INS_LockPrefix(ins)) {
	INS_InsertPredicatedCall (ins, IPOINT_BEFORE, AFUNPTR(record_locked), IARG_INST_PTR, IARG_END);
    }

#ifdef START_AT_SYSCALL
    // sometimes commented out to make testing faster
    switch (INS_Opcode(ins)) {
	case XED_ICLASS_CALL_NEAR:
	case XED_ICLASS_CALL_FAR:
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_call), IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
			   IARG_ADDRINT, INS_NextAddress(ins), IARG_END);
	    
	    break;
	    
	case XED_ICLASS_RET_NEAR:
	case XED_ICLASS_RET_FAR:
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_ret), IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);    
	    break;
    }
#endif
}

// BEGIN GENERIC STUFF NEEDED TO REPLAY WITH PIN

BOOL follow_child(CHILD_PROCESS child, void* data)
{
    char** argv;
    char** prev_argv = (char**)data;
    int index = 0;

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
    return TRUE;
}

void thread_start (THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    struct thread_data* ptdata;

    fprintf (stderr, "Start of threadid %d\n", (int) threadid);

    ptdata = (struct thread_data *) malloc (sizeof(struct thread_data));
    assert (ptdata);
    
    ptdata->app_syscall = 0;

    PIN_SetThreadData (tls_key, ptdata, threadid);

    set_pin_addr (fd, (u_long) ptdata);
}

int main(int argc, char** argv) 
{    
    int rc;

    PIN_InitSymbols();
    PIN_Init(argc, argv);

    // Intialize the replay device
    rc = devspec_init (&fd);
    if (rc < 0) return rc;

    // Obtain a key for TLS storage
    tls_key = PIN_CreateThreadDataKey(0);

    PIN_AddThreadStartFunction(thread_start, 0);

    PIN_AddFollowChildProcessFunction(follow_child, argv);
    INS_AddInstrumentFunction(track_inst, 0);
    RTN_AddInstrumentFunction(track_function, 0);
    PIN_AddSyscallExitFunction(inst_syscall_end, 0);
    PIN_StartProgram();
    return 0;
}
// END GENERIC STUFF NEEDED TO REPLAY WITH PIN
