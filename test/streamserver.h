#ifndef __STREAMSERVER_H__
#define __STREAMSERVER_H__

#define STREAMSERVER_PORT 19764

#define SEND_ACK     0x1
#define SEND_RESULTS 0x2

// Info from description file
struct epoch_hdr {
    char   flags;
    char   dirname[256];
    u_long epochs;
    bool   start_flag;
    bool   finish_flag;
    char   next_host[256];
};

struct epoch_data {
    pid_t  start_pid;
    u_long start_syscall;
    u_long stop_syscall;
    u_long filter_syscall;
    u_long ckpt;
    char   hostname[256];
};

#define TAINTQSIZE (512*1024*1024)
#define TAINTENTRIES ((TAINTQSIZE-sizeof(atomic_ulong)*2)/sizeof(u_long))
struct taintq {
    atomic_ulong    read_index;
    atomic_ulong    write_index;
    u_long          buffer[TAINTENTRIES];
};

#endif
