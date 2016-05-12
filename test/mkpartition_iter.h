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

#ifndef MKPARTITION_ITER_H
#define MKPARTITION_ITER_H


typedef std::unordered_set<u_int> my_set;
typedef std::unordered_map<u_int,u_int> my_map;
typedef std::vector<u_int> my_vect;


//used everywhere else
struct timing_data {
    pid_t     pid;
    u_long    index;
    short     syscall;
    u_int     ut;      //should I not include this as it is only used to calculate dtiming? 

    bool      can_attach; 
    short     blocking_syscall; //the syscall number that is forcing this to be unattachable

    pid_t     forked_pid; //the pid of the forked process (if applicable).
    bool      should_track; //should I track this rp_timing? 
    u_long    call_clock;   //the clock value of the most recent sync operation before this syscall is called. 
    u_long    start_clock;  //when the syscall starts
    u_long    stop_clock;   //when the syscall is done running
    u_long    aindex;

    //used to estimate dift time
    double    dtiming;
    uint64_t  cache_misses;
    u_long    taint_in; //the amount of taint that we've gotten in at this point
    u_long    taint_out; //the amount of taint that we've output at this point

    my_vect   sampled_insts;
    my_set    pin_traces; //traces from a previously produced round
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

#define MAX_CKPT_CNT 1024
struct ckpt {
    char   name[20];
    u_long clock;
};



int generate_timings(std::vector<struct timing_data> td, u_int num_parts, char *fork_flags);
#endif /* MKPARTITION_ITER_H*/
