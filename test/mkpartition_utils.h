#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <dirent.h>
#include <cstdint>
#include <math.h>
#include <map>
#include <queue>
#include <set>
#include <limits>

#include <unistd.h>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <list>
#include <array>

#ifndef MKPARTITION_UTILS_H
#define MKPARTITION_UTILS_H


typedef std::unordered_set<u_int> my_set;
typedef std::unordered_map<u_long,u_long> my_map;
typedef std::vector<u_int> my_vect;
typedef std::list<u_long> my_ll;

struct timing_data {
    pid_t     pid;
    u_long    index;
    short     syscall;
    u_int     ut;      //should I not include this as it is only used to calculate dtiming? 
    u_int     fft;    //the timing from our ff data
    bool      can_attach; 
    short     blocking_syscall; //the syscall number that is forcing this to be unattachable
    pid_t     blocking_pid; //the syscall number that is forcing this to be unattachable

    pid_t     forked_pid; //the pid of the forked process (if applicable).
    bool      should_track; //should I track this rp_timing? 
    u_long    call_clock;   //the clock value of the most recent sync operation before this syscall is called. 
    u_long    start_clock;  //when the syscall starts
    u_long    stop_clock;   //when the syscall is done running
    u_long    aindex;

    //used to estimate dift time
    double    dtiming;
    double    ftiming;;    //the timing from our ff data
    uint64_t  cache_misses;
    u_long    taint_in; //the amount of taint that we've gotten in at this point
    u_long    taint_out; //the amount of taint that we've output at this point

    my_vect   sampled_insts;
//    my_set    pin_traces; //traces from a previously produced round
//    my_ll      pin_traces;
    my_vect   pin_traces; //gathered from a first query with pin
    u_long    num_merges; //gathered from a first query with pin
    u_long    num_saved; //gathered from a first query with pin
    u_long    imisses;
};

struct partition {

    pid_t pid; //the pid for this partition
    u_long start_clock; //start clock for this parititon
    u_long stop_clock;  //stop clock for this parititon

    char   start_level[8];
    char   stop_level[8];    

    int start_i; //the start index (within timing_data array) of the begin of this part. If this is user level, 
                 //this refers to the start of the user level splits
    int stop_i; //the stop index (within timing_data array) of the begin of this part. If this is user level, 
                 //this refers to the stop of the user level splits
};

//used simply for the read from the file system
struct replay_timing {
    pid_t     pid;
    u_long    index;
    short     syscall;
    u_int     ut;
    uint64_t  cache_misses;
};

struct ckpt_data {
    u_long proc_count;
    unsigned long long  rg_id;
    int    clock;
};

struct ckpt_proc_data {
	pid_t  record_pid;
	long   retval;
	loff_t logpos;
	u_long outptr;
	u_long consumed;
	u_long expclock;
};

struct pin_trace_iter { 

    char* dir; //the directory where the trace files are located
    u_int epochs; //the number of epochs 
    u_int curr_epoch; //the number of epochs 
    
    int    fd;   //the fd that is currently opened for the trace file
    u_long *log; //the pointer to our buffer
    u_long filedone; //the size of our file
    u_long mapsize; //the size that we mapped, used to munmap when we need
    u_long fileoffset; //the offset within the file
    u_long bufstart; //the start of the current region (to figure out how far we've gone)


    u_long num_merges; //running total of the number of merges across all files

    //////
    //all the data for the current item
    //////
    u_long  cpid;    //the current item's pid
    u_long  cclock;  //the current item's clock
    u_long  csysnum; //the current item's sysnum
    u_long  cnmerges;//the current item's num_merges
    u_long *ctraces; //the traces in the current item
    
    

};


#define MAX_CKPT_CNT 1024
struct ckpt {
    char   name[20];
    u_long index;
    u_long rp_clock;
};



int generate_timings(std::vector<struct timing_data> td, u_int num_parts, char *fork_flags,char *pin_dir, int pin_epochs);
int parse_klogs(std::vector<struct timing_data> &td, const u_long stop_clock, const char* dir, const char* fork_flags, const std::unordered_set<pid_t> procs);
int parse_ulogs(std::vector<struct timing_data> &td, const char* dir);
int parse_timing_data(std::vector<struct timing_data> &td);
int adjust_for_ckpts(std::vector<struct timing_data> &td, struct ckpt *ckpts, int ckpt_cnt);
int parse_instructions(std::vector<struct timing_data> &td, FILE *file);
int parse_pin_instructions(my_map &ninsts, char* dir, u_int epochs);
int parse_pin_traces(std::vector<struct timing_data> &td,char* dir, u_int epochs);
int parse_pin_traces_saved(std::vector<struct timing_data> &td,char* dir, u_int epochs);
u_long pin_trace_iter_next( struct pin_trace_iter &pti);
int init_pin_trace_iter(struct pin_trace_iter &pti, char *dir, u_int epochs);
int destroy_pin_trace_iter(struct pin_trace_iter &pti);

#endif /* MKPARTITION_UTILS_H*/
