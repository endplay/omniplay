#include <stdio.h>
#include <stdlib.h>
#include "pin.H"
#include <stack>
#include <assert.h>
#include <syscall.h>
#include "reentry_lock.h"
#include <map>
#include <locale>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/net.h>
#include "util.h"
#include <sys/wait.h>
#include <string.h>

/* ================================================================ */
/* Globals                                                          */
/* ================================================================ */
//KNOB<string> KnobOutputFile(
struct thread_data* tdhead = NULL; 
TLS_KEY tls_key; // Key for accessing TLS. 
struct thread_data {
    int                  threadid;
    int                  syscall_cnt;
    bool                 returned;
    struct thread_data*  next;
    struct thread_data*  prev;
    int                  syscall_num;

    char*                syscall_filename;
    int                  socket_call;
    int                  socket_count;
    int                  pipe_count;
    std::stack<ADDRINT>  call_stack; 
    std::stack<string>   string_stack;
    std::map<long, int> stack_count;

    u_long app_syscall;
    int record_pid;
};


FILE* stack_f = NULL;
FILE* debug_f = NULL;

int child = 0;
int fd;

int global_push_stack = 0;
int global_mark_pop = 0;

#define STACK_F stack_f
#define STACK_PRINT(args...) \
{                            \
    fprintf(STACK_F, args);  \
    fflush(STACK_F);         \
}

//#define DEBUG
#ifdef DEBUG
#define DEBUG_F debug_f
#define DEBUG_PRINT(args...) \
{                            \
    fprintf(DEBUG_F, args);  \
    fflush(DEBUG_F);         \
}
#endif


// Lock Stuf__________________________________________________________
REENTRY_LOCK relock;

inline void __grab_global_lock (struct thread_data* ptdata) {
    get_reentry_lock (&relock, ptdata->threadid);
}

inline void __release_global_lock (struct thread_data* ptdata) {
    release_reentry_lock (&relock, ptdata->threadid);
}

#define GRAB_GLOBAL_LOCK __grab_global_lock
#define RELEASE_GLOBAL_LOCK __release_global_lock
// End of Lock Stuff__________________________________________________

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
    ptdata = new struct thread_data;
    if (ptdata == NULL) {
        fprintf (stderr, "ptdata is NULL\n");
        assert (0);
    }
    assert (ptdata);

    ptdata->next = tdhead;
    ptdata->syscall_cnt = 0;
    ptdata->prev = NULL;
    if(tdhead) tdhead->prev = ptdata;
    tdhead = ptdata;

    ptdata->app_syscall = 0;
    ptdata->record_pid = get_record_pid();

    ptdata->threadid = threadid;
    ptdata->returned = 0;
    ptdata->syscall_num = 0;
    ptdata->socket_call = 0;
    ptdata->socket_count = 0;
    ptdata->pipe_count = 0;
    fprintf(stdout, "threadid = %d.\n", ptdata->threadid);

    PIN_SetThreadData (tls_key, ptdata, threadid);
    set_pin_addr (fd, (u_long) &ptdata->app_syscall);
}

void mark_pop(ADDRINT ip)
{
    struct thread_data* ptdata = (struct thread_data*) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK(ptdata);

    global_mark_pop++;
    ptdata->returned = 1; 
    RELEASE_GLOBAL_LOCK(ptdata);

}

void pop_stack(ADDRINT ip)
{
    struct thread_data* ptdata = (struct thread_data*) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK(ptdata);

    ADDRINT static_ip;
    PIN_LockClient();
    IMG img = IMG_FindByAddress(ip);
    if (IMG_Valid(img)) {
         ADDRINT offset = IMG_LoadOffset(img);
         static_ip = ip - offset;
    }
    else {
        static_ip = ip;
    }
    PIN_UnlockClient();
   
    ptdata->returned = 0;

    std::stack<ADDRINT> tmp_addr_stack;
    std::stack<string> tmp_string_stack;
    tmp_addr_stack = ptdata->call_stack;
    tmp_string_stack = ptdata->string_stack;

    int matched = 0;
    while(!tmp_addr_stack.empty()) {
        if (static_ip == tmp_addr_stack.top()) {
            matched = 1;
            break;
        }
        tmp_addr_stack.pop();
    }

#ifdef DEBUG
    std::stack<string> tmp_stack;
    tmp_stack = ptdata->string_stack;
    DEBUG_PRINT("Pop_Stack_Before\n");
    while(!tmp_stack.empty()) {
        DEBUG_PRINT("%s", tmp_stack.top().c_str());
        tmp_stack.pop();
    }
#endif
 
    if(matched){
    while(!ptdata->call_stack.empty()){
        if (ptdata->call_stack.top() == static_ip){
            ptdata->call_stack.pop();
            ptdata->string_stack.pop();
            break;
        }
        else{
            ptdata->call_stack.pop();
            ptdata->string_stack.pop();
        }
    }
    }
 
#ifdef DEBUG
    tmp_stack = ptdata->string_stack;
    DEBUG_PRINT("Pop_Stack_After\n");
    while(!tmp_stack.empty()) {
        DEBUG_PRINT("%s", tmp_stack.top().c_str());
        tmp_stack.pop();
    }
#endif
 
    RELEASE_GLOBAL_LOCK(ptdata);
}

void push_stack(ADDRINT ip, ADDRINT ins_size)
{
    struct thread_data* ptdata = (struct thread_data*) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK(ptdata);

    global_push_stack++;

    ADDRINT static_ip;
    PIN_LockClient();
    IMG img = IMG_FindByAddress(ip);
    string img_name;
    if (IMG_Valid(img)) {
         ADDRINT offset = IMG_LoadOffset(img);
         img_name = IMG_Name(img);
         static_ip = ip - offset;
    }
    else {
        img_name = "[ERROR: Unknown IMG]";
        static_ip = ip;
    }

    static_ip = static_ip + (int)ins_size;
    ptdata->call_stack.push(static_ip);
    char buffer [50];
    sprintf(buffer, "%#x", static_ip);
    string push_string = img_name + ": " + RTN_FindNameByAddress(ip).c_str() + ": " + buffer + "\n";
    ptdata->string_stack.push(push_string);
 
#ifdef DEBUG
    std::stack<string> tmp_stack;
    tmp_stack = ptdata->string_stack;
    DEBUG_PRINT("Push_Stack\n");
    while(!tmp_stack.empty()) {
        DEBUG_PRINT("%s", tmp_stack.top().c_str());
        tmp_stack.pop();
    }
#endif
   
    PIN_UnlockClient();
    RELEASE_GLOBAL_LOCK(ptdata);
}

void record_callstack(struct thread_data* ptdata, char* filename){
#ifdef DEBUG
    DEBUG_PRINT("Record Callstack\n");
#endif
    std::stack<string> tmp_stack;
    tmp_stack = ptdata->string_stack;
    string tmp_string = "";
    while(!tmp_stack.empty()){
        tmp_string = tmp_string + tmp_stack.top();
        tmp_stack.pop();
    }

    std::locale loc;
    const std::collate<char>& coll = std::use_facet<std::collate<char> >(loc);
    long stack_hash = coll.hash(tmp_string.data(), tmp_string.data() + tmp_string.length());

    std::pair<std::map<long, int>::iterator, bool> ret;
    ret = ptdata->stack_count.insert(std::pair<long, int>(stack_hash, 1));
    if (!ret.second) {
        ptdata->stack_count[stack_hash] = ptdata->stack_count[stack_hash] + 1;
    }
}

void instrument_syscall(ADDRINT syscall_num, ADDRINT syscallarg1, ADDRINT syscallarg2)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    GRAB_GLOBAL_LOCK (ptdata);

    ptdata->syscall_cnt++;
    ptdata->syscall_num = (int)syscall_num;
    switch(ptdata->syscall_num) {
        case SYS_open:
            ptdata->syscall_filename = (char*) syscallarg1;
            break;
        case SYS_socketcall:
            ptdata->socket_call = (int)syscallarg1;
            switch (ptdata->socket_call) {
                case SYS_SOCKET:
                    ptdata->socket_count++;
                    break;
                default:
                    break;
            }
            break;
        case SYS_pipe:
            ptdata->pipe_count++;
            break;
        default:
            break;
    }

    RELEASE_GLOBAL_LOCK (ptdata);
}


void instrument_syscall_ret(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    struct thread_data* ptdata = (struct thread_data*) PIN_GetThreadData(tls_key, PIN_ThreadId());
    
    if (ptdata) {
	if (ptdata->app_syscall != 999) ptdata->app_syscall = 0;
    } else {
	fprintf (stderr, "inst_syscall_end: NULL tdata\n");
    }	

    int ret_val = (int) PIN_GetSyscallReturn(ctxt, std);
    switch (ptdata->syscall_num) {
        case SYS_open:
        {
            if (ret_val >= 0) {
                char* filename = ptdata->syscall_filename;
                record_callstack(ptdata, filename);
            }
        }
            break;

        case SYS_socketcall:
            switch (ptdata->socket_call) {
                case SYS_SOCKET:
                    string socket_name = "socket_";
                    char socket_count[50];
                    sprintf(socket_count, "%d", ptdata->socket_count);
                    socket_name = socket_name + socket_count;
                    record_callstack(ptdata, &socket_name[0]);
            }
            break;
        case SYS_pipe:
            if (ret_val == 0) {
                string pipe_name = "pipe_";
                char pipe_count[50];
                sprintf(pipe_count, "%d", ptdata->pipe_count);
                pipe_name = pipe_name + pipe_count;
                record_callstack(ptdata, &pipe_name[0]);
            }
            break;
        default:
            break;
    }
}

void set_address_one(ADDRINT syscall_num, ADDRINT ebx_value, ADDRINT syscallarg0, ADDRINT syscallarg1, ADDRINT syscallarg2)
{   
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
	int sysnum = (int) syscall_num;
	
    tdata->syscall_cnt++;

	if (sysnum == 45 || sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
	//if (sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
	    check_clock_before_syscall (fd, (int) syscall_num);
	}
	tdata->app_syscall = syscall_num;
	tdata->syscall_num = (int) syscall_num;
    } else {
	fprintf (stderr, "set_address_one: NULL tdata\n");
    }
}

void trace(INS ins, void* v)
{
    struct thread_data* ptdata = (struct thread_data*) PIN_GetThreadData(tls_key, PIN_ThreadId());
    OPCODE opcode = INS_Opcode(ins); 
    switch(opcode) {
        case XED_ICLASS_RET_NEAR:
        case XED_ICLASS_RET_FAR:
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) mark_pop, IARG_INST_PTR, IARG_END);
            break;

        case XED_ICLASS_CALL_NEAR:
        case XED_ICLASS_CALL_FAR:
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) push_stack, IARG_INST_PTR, IARG_ADDRINT, INS_Size(ins), IARG_END);
            break;
        default:
            break;
    }

    if(ptdata->returned==1) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) pop_stack, IARG_INST_PTR, IARG_END);
        ptdata->returned = 0;
    }

    if(INS_IsSyscall(ins)) {
         INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(instrument_syscall), IARG_SYSCALL_NUMBER,
                IARG_SYSARG_VALUE, 0, 
                IARG_SYSARG_VALUE, 1, 
                IARG_END);    
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(set_address_one), IARG_SYSCALL_NUMBER,
                        IARG_REG_VALUE, LEVEL_BASE::REG_EBX,
                        IARG_SYSARG_VALUE, 0,
                        IARG_SYSARG_VALUE, 1,
                        IARG_SYSARG_VALUE, 2,
                        IARG_END);
   }
}

void syscall_after (ADDRINT ip)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
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
}

void track_trace(TRACE trace, void* data)
{
	// System calls automatically end a Pin trace.
	// So we can instrument every trace (instead of every instruction) to check to see if
	// the beginning of the trace is the first instruction after a system call.
	struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
	if (tdata) {
		if (tdata->app_syscall == 999) {
			TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR) syscall_after, IARG_INST_PTR, IARG_END);
		}
	} else {
		fprintf (stderr, "syscall_after: NULL tdata\n");
	}
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

    return TRUE;
}

void AfterForkInChild(THREADID threadid, const CONTEXT* ctxt, VOID* arg)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    int record_pid;
    fprintf(stderr, "AfterForkInChild\n");
    record_pid = get_record_pid();
    fprintf(stderr, "get record id %d\n", record_pid);
    tdata->record_pid = record_pid;
}

INT32 Usage()
{
    PIN_ERROR("Error Message, Explain Usage.\n");
    return -1;
}

void Fini(INT32 code, void* v)
{
	fprintf(stderr, "push_stack_count = %d\n", global_push_stack);
	fprintf(stderr, "mark_pop count = %d\n", global_mark_pop);
	
    fprintf(stdout, "End.\n");
}

/* =========================================================== */
/* Main                                                        */
/* =========================================================== */
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
        fprintf(stderr, "Could not PIN_Init().\n");
        exit(-1);
    }

    rc = devspec_init (&fd);
    if (rc < 0) return rc;

    char stack_file_name[256];
    if (stack_f) fclose(stack_f);
    snprintf(stack_file_name, 256, "/tmp/stack_file.%d", PIN_GetPid());
    stack_f = fopen(stack_file_name, "a");
    if(!stack_f) {
        printf("ERROR: cannot open stack file %s.\n", stack_file_name);
        return -1;
    }
    fprintf(stderr, "Stack file name is %s.\n", stack_file_name);

#ifdef DEBUG
    char debug_file_name[256];
    if (debug_f) fclose(debug_f);
    snprintf(debug_file_name, 256, "/tmp/debug_file.%d", PIN_GetPid());
    debug_f = fopen(debug_file_name, "a");
    if(!debug_f) {
        printf("ERROR: cannot open debug file %s.\n", debug_file_name);
        return -1;
    }
    fprintf(stderr, "Debug file name is %s.\n", debug_file_name);
#endif



    // Initialize Thread
    init_reentry_lock(&relock);
    tls_key = PIN_CreateThreadDataKey(0);
    PIN_AddThreadStartFunction(thread_start, 0);

    PIN_AddFollowChildProcessFunction(follow_child, argv);
    INS_AddInstrumentFunction(trace, 0);

    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);

    TRACE_AddInstrumentFunction (track_trace, 0);

    PIN_AddFiniFunction(Fini, 0);
    PIN_AddSyscallExitFunction(instrument_syscall_ret, 0);

    PIN_StartProgram();
    return 0;
}
