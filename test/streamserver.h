#ifndef __STREAMSERVER_H__
#define __STREAMSERVER_H__

#include <semaphore.h>

#define STREAMSERVER_PORT 19764
#define AGG_BASE_PORT     10000

#define SEND_ACK      0x1
#define SEND_RESULTS  0x2
#define SYNC_LOGFILES 0x4

#define NAMELEN 256
#define PATHLEN 512

struct replay_path {
    char path[PATHLEN];
};

struct cache_info {
    uint32_t        dev;
    uint32_t        ino;
    struct timespec mtime;
};

// Possible commands
#define DO_DIFT         0
#define AGG_TYPE_STREAM 1
#define AGG_TYPE_SEQ    2

// Info from description file
struct epoch_hdr {
    uint32_t epochs;
    bool     start_flag;
    bool     finish_flag;
    u_char   cmd_type;
    char     flags;
    char     dirname[NAMELEN];
    char     prev_host[NAMELEN];
    char     next_host[NAMELEN];
};

struct epoch_data {
    pid_t    start_pid;
    uint32_t start_syscall;
    uint32_t stop_syscall;
    uint32_t filter_syscall;
    uint32_t ckpt;
    uint32_t port;              // Aggregation port
    char     hostname[NAMELEN]; // Aggregation hostname
};

struct epoch_ack {
    uint32_t retval;
};

#define TAINTQSIZE (512*1024*1024)
#define TAINTENTRIES ((TAINTQSIZE-(sizeof(sem_t)+sizeof(atomic_ulong)*2+64*3))/sizeof(uint32_t))
struct taintq {
    sem_t           epoch_sem;
    char            pad1[64];
    atomic_ulong    read_index;
    char            pad2[64];
    atomic_ulong    write_index;
    char            pad3[64];
    uint32_t        buffer[TAINTENTRIES];
};

#endif
