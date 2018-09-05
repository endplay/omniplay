#ifndef LINKAGE_COMMON_H
#define LINKAGE_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "taint_interface/taint.h"

// constants
#define DF_MASK 0x0400

#define NUM_REGS 120
#define REG_SIZE 16

#define OPEN_PATH_LEN 256
struct open_info {
    char name[OPEN_PATH_LEN];
    int flags;
    int fileno;
};

struct read_info {
    int      fd;
    u_long  fd_ref;
    char*    buf;
};

struct write_info {
    int      fd;
    char*    buf;
};

struct writev_info {
    int fd;
    struct iovec* vi;
    int count;
};

struct mmap_info {
    u_long addr;
    int length;
    int prot;
    int flags;
    int fd;
    int fd_ref;
    int offset;
};

struct socket_info {
    int call;
    int domain;
    int type;
    int protocol;
    int fileno; // so we can later interpret our results
    struct connect_info* ci;
};

struct connect_info {
    int fd;
    char path[OPEN_PATH_LEN];    // for AF_UNIX
    int port;                   // for AF_INET/6
    struct in_addr sin_addr;    // for AF_INET
    struct in6_addr sin_addr6;  // for AF_INET6
};

struct sendmsg_info {
    int fd;
    struct msghdr* msg;
    int flags;
};

struct recvmsg_info {
    int fd;
    struct msghdr* msg;
    int flags;
};

struct select_info {
    int nfds;
    fd_set* readfds;
    fd_set* writefds;
    fd_set* exceptfds;
    struct timeval* timeout;
};

/* Commonly used fields in a syscall */
struct syscall_info {
    char name[256];
    int flags;
    int fd;
    void* arg;
    int len;
};

// Per-thread data structure
struct thread_data {
    int                      threadid;
    // This stuff only used for replay
    u_long                   app_syscall; // Per thread address for specifying pin vs. non-pin system calls
    int                      record_pid;  // Ask kernel for corresponding record pid and save it here
    uint64_t                 rg_id;       // record group id
    u_long                   ignore_flag; // location of the ignore flag
    int                      sysnum;      // Stores number of system calls for return
    int                      syscall_in_progress; // True when in middle of a syscall
    int                      syscall_cnt; // per-thread syscall cnt, resets on fork
    
    // These caches are to avoid extra allocations 
    // and resulting memory fragmentation
    struct read_info read_info_cache;
    struct write_info write_info_cache;
    struct writev_info writev_info_cache;
    struct mmap_info mmap_info_cache;
    struct select_info select_info_cache;

    void* save_syscall_info;
    int socketcall;
    int syscall_handled;            // flag to indicate if a syscall is handled at the glibc wrapper instead
    taint_t shadow_reg_table[NUM_REGS * REG_SIZE];
    struct syscall_info syscall_info_cache;
    struct thread_data*      next;
    struct thread_data*      prev;
};

struct memcpy_header {
    u_long dst;
    u_long src;
    u_long len;
};

#endif
