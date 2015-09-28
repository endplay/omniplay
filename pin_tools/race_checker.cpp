#include "pin.H"
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include "util.h"
#include <string.h>
#include <stdlib.h>
// edited by hyihe
#include "happens_before.h"

#define INSTMNT_CALL_RET
#define START_AT_SYSCALL 0
#define STOP_AT_SYSCALL  224999

int print_limit = 0;
int print_stop = 2000000000;

KNOB<string> KnobPrintLimit(KNOB_MODE_WRITEONCE, "pintool", "p", "10000000", "syscall print limit");
KNOB<string> KnobPrintStop(KNOB_MODE_WRITEONCE, "pintool", "s", "10000000", "syscall print stop");

// BEGIN GENERIC STUFF NEEDED TO REPLAY WITH PIN


// moved forward by hyihe
int fd; // File descriptor for the replay device
TLS_KEY tls_key; // Key for accessing TLS. 
int syscall_cnt = 0;

// edited by hyihe
#define MEM_REF_READ  0
#define MEM_REF_WRITE 1
#define MEM_REF_READ2 2

typedef std::map<var_key_t, var_t *, var_key_comp> var_map_t;
// current intervals of the threads
std::vector<interval_t *> thd_ints;
std::vector<int> thd_entr_type;
int num_threads = 0;
// the map containing all variables accessed in the program
var_map_t variables;

static inline bool inrange() {
    return ((syscall_cnt >= print_limit) 
        && (syscall_cnt <= print_stop));
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

ADDRINT find_static_address(ADDRINT ip)
{
	PIN_LockClient();
	IMG img = IMG_FindByAddress(ip);
	if (!IMG_Valid(img)) return ip;
	ADDRINT offset = IMG_LoadOffset(img);
	PIN_UnlockClient();
	return ip - offset;
}

bool detect_race(THREADID tid, VOID *ref_addr, ADDRINT size, VOID *ip, int ref_type) {
    // Ignore instructions from shared libraries/syscalls
    if((unsigned long)ip > 0x80000000 || num_threads == 1)
        return false;
    if(!inrange())
        return false;
    var_map_t::iterator lkup = variables.find(std::make_pair((void *)ref_addr, (int)size));
    if(lkup == variables.end()) {
        // No sharing conflict upon first access
        var_t *insert = new var_t;
        insert->resize_intvls(num_threads);
        insert->update_intvls(ref_type, thd_ints, tid);
        variables.insert(std::make_pair(std::make_pair((void *)ref_addr, (int)size), insert));
        return false;
    } else {
    	// Update varible access history and check for violations
        int race;
        bool ret = false;
        lkup->second->resize_intvls(num_threads);
        race = lkup->second->check_for_race(ref_type, thd_ints, tid);
        if(race) {
            fprintf(stderr, "race at %p, addr %p, size %d\n", ip, ref_addr, size);
            // do not abort, always return false
            //ret = true;
        }
        lkup->second->update_intvls(ref_type, thd_ints, tid);
        return ret;
    }
}
// end edited by hyihe

struct thread_data {
    u_long app_syscall; // Per thread address for specifying pin vs. non-pin system calls
};

void inst_syscall_end(THREADID thread_id, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
	if (tdata->app_syscall != 999) tdata->app_syscall = 0;
    } else {
	fprintf (stderr, "inst_syscall_end: NULL tdata\n");
    }	
}

void set_address_one(ADDRINT syscall_num, ADDRINT eax_ref)
{   
    struct thread_data* tdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());
    if (tdata) {
	int sysnum = (int) syscall_num;
	
	fprintf (stderr, "In set_address_one, num is %d, cnt is %d\n", (int) syscall_num, ++syscall_cnt);
	if (sysnum == 45 || sysnum == 91 || sysnum == 120 || sysnum == 125 || sysnum == 174 || sysnum == 175 || sysnum == 190 || sysnum == 192) {
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

void instrument_call(ADDRINT address, ADDRINT target, ADDRINT next_address)
{
//    if(inrange()) {
//        fprintf (stderr, "Thread %5d Call 0x%08x target 0x%08x next 0x%08x\n", PIN_ThreadId(), address, target, next_address);
//    }
}

void instrument_ret(ADDRINT address, ADDRINT target)
{
//    if(inrange()) {
//        fprintf (stderr, "Thread %5d Ret  0x%08x target 0x%08x\n", PIN_ThreadId(), address, target);
//    }
}

bool type_is_enter (ADDRINT type) {
    if((type & 0x1) && (type != 15) && (type != 17)) {
        return true;
    } else {
        return false;
    }
}

void log_replay_enter (ADDRINT type, ADDRINT check)
{
    long curr_clock = get_clock_value(fd);
    if(type_is_enter(type)) {
        // Indicates the end of an interval
        thd_entr_type[PIN_ThreadId()] = type;
        //fprintf (stderr, "Thread %5d reaches sync point (%d) at clock %ld\n", PIN_ThreadId(), type, curr_clock);
        update_interval_speculate(thd_ints, PIN_ThreadId(), curr_clock);
    } else {
        thd_entr_type[PIN_ThreadId()] = type;
        //fprintf (stderr, "Thread %5d resumes (%d) at clock %ld\n", PIN_ThreadId(), type, curr_clock);
    }
}

void record_read (VOID* ip, VOID* addr, ADDRINT size)
{
    if(detect_race(PIN_ThreadId(), addr, size, ip, MEM_REF_READ))
        exit(1);
}

void record_read2 (VOID* ip, VOID* addr)
{
//    if (inrange()) {
//        fprintf (stderr, "Thread %5d read2 address %p (inst %p)\n", PIN_ThreadId(), addr, ip);
//    }
}

void record_write (VOID* ip, VOID* addr, ADDRINT size)
{
    if(detect_race(PIN_ThreadId(), addr, size, ip, MEM_REF_WRITE))
        exit(1);
}

void record_locked (ADDRINT ip)
{
    if (inrange()) {
	PIN_LockClient();
	fprintf (stderr, "Thread %5d (record pid %d) locked inst %08x\n", PIN_ThreadId(), get_record_pid(), ip);
	if (IMG_Valid(IMG_FindByAddress(ip))) {
		fprintf(stderr, "%s -- img %s static %#x\n", RTN_FindNameByAddress(ip).c_str(), 
			IMG_Name(IMG_FindByAddress(ip)).c_str(), find_static_address(ip));
	}
	PIN_UnlockClient();
    }
}

void log_replay_exit ()
{
    int type = thd_entr_type[PIN_ThreadId()];
    if(!type_is_enter(type)) {
        long curr_clock = get_clock_value(fd) - 1;
        //fprintf (stderr, "Thread %5d resumes (%d) at clock %ld\n", PIN_ThreadId(), type, curr_clock);
        thd_ints[PIN_ThreadId()] = new_interval(curr_clock);
    }
}

// Update the exit time of the current interval upon context switch
void log_replay_block(ADDRINT block_until) {
    long curr_clock = get_clock_value(fd);
    fprintf(stderr, "Context Switch! Thread %d reaches %d, current clock is %ld\n",
        PIN_ThreadId(), block_until, curr_clock);
    // do not overwrite if context switch happened after an _EXIT
    if(type_is_enter(thd_entr_type[PIN_ThreadId()]))
        update_interval_overwrite(thd_ints, PIN_ThreadId(), block_until);
}

void track_function(RTN rtn, void* v) 
{
    RTN_Open(rtn);
    const char* name = RTN_Name(rtn).c_str();
    if (!strcmp (name, "pthread_log_replay")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) log_replay_enter, 
		       IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) log_replay_exit, IARG_END);
    } else if (!strcmp (name, "pthread_log_block")) {
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) log_replay_block, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
    }
    RTN_Close(rtn);
}

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

#ifdef INSTMNT_CALL_RET
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

    // edited by hyihe
    num_threads++;
    // need to start a new interval for a new thread
    thd_ints.push_back(new_interval(get_clock_value(fd)));
    thd_entr_type.push_back(0);

    ptdata->app_syscall = 0;

    PIN_SetThreadData (tls_key, ptdata, threadid);

    set_pin_addr (fd, (u_long) ptdata, NULL, NULL);
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
    print_limit = atoi(KnobPrintLimit.Value().c_str());
    print_stop = atoi(KnobPrintStop.Value().c_str());

    PIN_AddThreadStartFunction(thread_start, 0);

    PIN_AddFollowChildProcessFunction(follow_child, argv);
    INS_AddInstrumentFunction(track_inst, 0);
    RTN_AddInstrumentFunction(track_function, 0);
    PIN_AddSyscallExitFunction(inst_syscall_end, 0);
    PIN_StartProgram();
    return 0;
}
// END GENERIC STUFF NEEDED TO REPLAY WITH PIN


// edited by hyihe
// Implementations of functions and data types defined in happens_before.h
int var_t::check_for_race(int acc_type, std::vector<interval_t *> &thd_ints, uint32_t tid) {
	int ret = 0;
	interval_t prev;
	interval_t *current = thd_ints[tid];
	if (acc_type == MEM_REF_WRITE) {
		for(uint32_t i=0; i<thd_ints.size(); i++) {
			if(i == tid)
				continue;
			// Write must happen AFTER all previous writes
			// AND reads
			if(!happens_before(this->last_wr[i], current) || 
				!happens_before(this->last_rd[i], current)) {
				ret = 1;
				prev = (!happens_before(this->last_wr[i], current))?
					*this->last_wr[i] : *this->last_rd[i];
				break;
			}
		}
	} else {
		for(uint32_t i=0; i<thd_ints.size(); i++) {
			if(i == tid)
				continue;
			// Read must happen AFTER all previous writes
			if(!happens_before(this->last_wr[i], current)) {
				ret = 1;
				prev = *this->last_wr[i];
				break;
			}
		}
	}
	if(ret) {
		std::cerr << "@@@@ Race detected! Violating access is a "
		<< ((acc_type==MEM_REF_WRITE)? "write" : "read") << "!" << std::endl;
		fprintf(stderr, "@@@@ Interval interleaving %ld:%ld with %ld:%ld\n",
			prev.first, prev.second, current->first, current->second);
	}
	return ret;
}

void var_t::update_intvls(int acc_type, const std::vector<interval_t *> &thd_ints, uint32_t tid) {
	// skipping error checking here to speed up
	interval_t *current = thd_ints[tid];
	if(acc_type == MEM_REF_WRITE) {
		this->last_wr[tid] = current;
	} else {
		this->last_rd[tid] = current;
	}
}

int var_t::resize_intvls(int target_size) {
	int diff = target_size - this->last_rd.size();
	if(diff < 0)
		return -1;
	for(int i = 0; i < diff; ++i) {
		// Intervals associated with NULL pointers
		// happens before all other intervals
		this->last_rd.push_back(0);
		this->last_wr.push_back(0);
	}
	return 0;
}

interval_t *new_interval(long clock) {
	interval_t *ret = new interval_t;
	ret->first = clock;
	ret->second = clock + 1;
	return ret;
}

void update_interval_speculate(std::vector<interval_t *> &thd_ints, uint32_t tid, long clock) {
	if(thd_ints[tid]->second != clock) {
//		fprintf(stderr, "Thread %5d's interval updated (spec) from %ld to %ld\n",
//			tid, thd_ints[tid]->second, clock);
		thd_ints[tid]->second = clock;
	}
}

void update_interval_overwrite(std::vector<interval_t *> &thd_ints, uint32_t tid, long clock) {
	thd_ints[tid]->second = clock;
}
// end edited by hyihe
