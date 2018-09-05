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


typedef std::unordered_set<uint32_t> my_set;
typedef std::unordered_map<uint32_t,uint32_t> my_map;
typedef std::vector<uint32_t> my_vect;

struct timing_data {
    pid_t     pid;
    u_long    index;
    short     syscall;
//    u_int     ut;      //should I not include this as it is only used to calculate dtiming? 
//    u_int     fft;    //the timing from our ff data
    char     can_attach; 
    short     blocking_syscall; //the syscall number that is forcing this to be unattachable
//    pid_t     blocking_pid; //the syscall number that is forcing this to be unattachable

//    pid_t     forked_pid; //the pid of the forked process (if applicable).
    char      should_track; //should I track this rp_timing? 
//    u_long    call_clock;   //the clock value of the most recent sync operation before this syscall is called. 
    u_long    start_clock;  //when the syscall starts
    u_long    stop_clock;   //when the syscall is done running
    u_long    aindex;

    //used to estimate dift time
    double    dtiming;
    double    ftiming;;    //the timing from our ff data

    /*
     * filled in by instructions files
     */

    my_vect   sampled_insts; //gathered from recording
    my_vect   pin_traces;    //gathered from a first query with pin
    u_long    num_merges;    //gathered from a first query with pin
    u_long    num_saved;     //gathered from a first query with pin
    u_long    imisses;
};

struct partition {

    pid_t pid; //the pid for this partition
    u_long start_clock; //start clock for this parititon
    u_long stop_clock;  //stop clock for this parititon

    u_long ckpt; //the clock value of the ckpt associated with this partition

    char   start_level[8];
    char   stop_level[8];    

    int start_i; //the start index (within timing_data array) of the begin of this part. If this is user level, 
                 //this refers to the start of the user level splits
    int stop_i; //the stop index (within timing_data array) of the begin of this part. If this is user level, 
                 //this refers to the stop of the user level splits
};

#define MAX_CKPT_CNT 1024
struct ckpt {
    u_long rp_clock;

    bool operator==(const struct ckpt &other) const
	{
	    return rp_clock == other.rp_clock;
	}   
};

namespace std{
    template<>
	struct hash<struct ckpt>
    {
	std::size_t operator()(const struct ckpt &c) const
	{	    
	    return hash<u_long>()(c.rp_clock);
	}
    };
}


int read_ckpts(std::vector<struct ckpt> &ckpts, FILE *file);
int adjust_for_ckpts(std::vector<struct timing_data> &td, 
		     std::vector<struct ckpt> &ckpt);
int read_timing_data(std::vector<struct timing_data> &td, FILE *file);
int parse_instructions(std::vector<struct timing_data> &td, FILE *file);
int parse_pin_instructions(my_map &ninsts, char* dir, u_int epochs);
int parse_pin_traces(std::vector<struct timing_data> &td,char* dir, u_int epochs);
//int parse_pin_traces_saved(std::vector<struct timing_data> &td,char* dir, u_int epochs);

#endif /* MKPARTITION_UTILS_H*/
