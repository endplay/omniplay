#ifndef GET_STATS_H
#define GET_STATS_H

struct my_stats {

    pid_t pid;
    u_long start_clock;
    double timing;
    u_long taint_in;
    u_long taint_out; 
    uint64_t cmisses;
};

struct epoch { 

    int start_pid; 
    char start_level;
    u_int start_clock;
    char stop_level; 
    u_int stop_clock;
    u_int filter_syscall;
    u_int ckpt;
    u_int fork_flags;
};

#endif
