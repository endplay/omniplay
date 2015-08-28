#ifndef __STREAMSERVER_H__
#define __STREAMSERVER_H__

#define STREAMSERVER_PORT 19764

#define SEND_ACK      0x1
#define SEND_RESULTS  0x2
#define SYNC_LOGFILES 0x4

#define NAMELEN 256
#define PATHLEN 512

struct replay_path {
    char path[PATHLEN];
};

struct cache_info {
    u_long          dev;
    u_long          ino;
    struct timespec mtime;
};
// Info from description file
struct epoch_hdr {
    char   flags;
    char   dirname[NAMELEN];
    u_long epochs;
    bool   start_flag;
    bool   finish_flag;
    char   next_host[NAMELEN];
};

struct epoch_data {
    pid_t  start_pid;
    u_long start_syscall;
    u_long stop_syscall;
    u_long filter_syscall;
    u_long ckpt;
    char   hostname[NAMELEN];
};

#define TAINTQSIZE (512*1024*1024)
#define TAINTENTRIES ((TAINTQSIZE-sizeof(atomic_ulong)*2)/sizeof(u_long))
struct taintq {
    atomic_ulong    read_index;
    atomic_ulong    write_index;
    u_long          buffer[TAINTENTRIES];
};

#endif
