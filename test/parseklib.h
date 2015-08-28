#ifndef __PARSEKLIB_H
#define __PARSEKLIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/timex.h>
#include <sys/quota.h>
#include <signal.h>
#ifndef __USE_LARGEFILE64
#  define __USE_LARGEFILE64
#endif
#include <sys/stat.h>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ustat.h>
#include <time.h>
#include <mqueue.h>

#include <linux/net.h>
#include <linux/utsname.h>
#include <linux/ipc.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/statfs.h>
#include <linux/capability.h>
#include <asm/ldt.h>
#include <sys/resource.h>

#include "replay_headers/include/linux/replay_configs.h"

#ifndef __USE_LARGEFILE64
#  define __USE_LARGEFILE64
#endif
//#include <limits.h>
#include <fcntl.h>

#define NR_SYSCALLS 511

#ifdef TRACE_READ_WRITE
struct replayfs_syscache_id {
	loff_t unique_id : 48; 
	loff_t pid : 16; 
	loff_t sysnum : 56; 
	loff_t mod : 8;
} __attribute__((aligned(16)));

struct replayfs_btree_value {
	struct replayfs_syscache_id id;

	size_t buff_offs;
};

struct replayfs_filemap_value {
	struct replayfs_btree_value bval;

	loff_t offset;
	size_t size;
	size_t read_offset;
};

struct replayfs_filemap_entry {
	int num_elms;
	struct replayfs_filemap_value elms[0];
};
#endif

#define CACHE_MASK 1

#ifdef TRACE_PIPE_READ_WRITE
#  define IS_PIPE 2
#  define IS_PIPE_WITH_DATA 4
#endif
#define IS_RECORDED_FILE (1<<3)
#define READ_NEW_CACHE_FILE (1<<4)
#define NORMAL_FILE (1<<5)


struct repsignal {
	int signr;
	siginfo_t info;
	struct /* k_ */ sigaction ka;
	sigset_t blocked;
	sigset_t real_blocked;
	struct repsignal* next;
};

#define SR_HAS_RETPARAMS        0x1 
#define SR_HAS_SIGNAL           0x2
#define SR_HAS_START_CLOCK_SKIP 0x4
#define SR_HAS_STOP_CLOCK_SKIP  0x8
#define SR_HAS_NONZERO_RETVAL   0x10

#define REPLAY_MAX_RANDOM_VALUES 10
struct rvalues {
	int cnt;
	long val[REPLAY_MAX_RANDOM_VALUES];
};

struct open_retvals {
	u_long           dev;
	u_long          ino;
	struct timespec mtime;
};

struct gettimeofday_retvals {
	short           has_tv;
	short           has_tz;
	struct timeval  tv;
	struct timezone tz;
};

struct pselect6_retvals {
	char            has_inp;
	char            has_outp;
	char            has_exp;
	char            has_tsp;
	fd_set          inp;
	fd_set          outp;
	fd_set          exp;
	struct timespec tsp;
};

struct generic_socket_retvals {
	int call;
};

struct accept_retvals {
	int call;
	int addrlen;
	char addr; // Variable length buffer follows
};

struct exec_values {
	int uid;
	int euid;
	int gid;
	int egid; 
	int secureexec;
};

struct execve_retvals {
	u_char is_new_group;
	union {
		struct {
			struct rvalues     rvalues;
			struct exec_values evalues;
			u_long             dev;
			u_long             ino;
			struct timespec    mtime;
		} same_group;
		struct {
			__u64           log_id;
		} new_group;
	} data;
};

struct socketpair_retvals {
	int call;
	int sv0;
	int sv1;
};

struct recvfrom_retvals {
	int call;
	struct sockaddr addr;
	int addrlen;
	char buf;  // Variable length buffer follows 
};

struct getxattr_retvals {
	char value; // Variable length buffer follows
};

struct sendfile64_retvals {
	loff_t offset;
};

struct recvmsg_retvals {
	int          call;
	int          msg_namelen;
	long         msg_controllen;
	unsigned int msg_flags;
};
// Followed by msg_namelen bytes of msg_name, msg_controllen bytes of msg_control and rc of data

struct getsockopt_retvals {
	int call;
	int optlen;
	char optval; // Variable length buffer follows
};

// generic ipc retvals
struct ipc_retvals {
	int call;
};

// semaphore ipc retvals
struct sem_retvals {
	struct ipc_retvals ipc_rv;
};

// retvals for shmat, since we need to save additional information
struct shmat_retvals {
	int    call;
	u_long size;
	u_long raddr;
};

struct set_thread_area_retvals {
	struct user_desc u_info;
};

struct mmap_pgoff_retvals {
	u_long          dev;
	u_long          ino;
	struct timespec mtime; 
};

struct splice_retvals {
	loff_t off_in;
	loff_t off_out;
};

u_long scount[512];
u_long bytes[512];

/* grabbed from asm/stat.h - ick - cannot include */
/* for 32bit emulation and 32 bit kernels */
struct __old_kernel_stat {
	unsigned short st_dev;
	unsigned short st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned short st_rdev;
#ifdef __i386__
	unsigned long  xst_size;
  	unsigned long  xst_atime;
  	unsigned long  xst_mtime;
  	unsigned long  xst_ctime;
#else
	unsigned int  st_size;
	unsigned int  st_atime;
	unsigned int  st_mtime;
	unsigned int  st_ctime;
#endif
};

struct wait4_retvals {
	int           stat_addr;
	struct rusage ru;
};

struct waitid_retvals {
	struct siginfo info;
	struct rusage  ru;
};

struct get_robust_list_retvals {
	struct robust_list_head * head_ptr;
	size_t                    len;
};

struct file_handle_internal
{
  unsigned int handle_bytes;
  int handle_type;
  /* File identifier.  */
  unsigned char f_handle[0];
};

struct name_to_handle_at_retvals {
	struct file_handle_internal handle;
	int                mnt_id;
};

struct syscall_result {
	short			sysnum;		// system call number executed
	u_char			flags;          // See defs above
};

struct klog_signal {
	char raw[172];
	struct repsignal sig;
	struct klog_signal *next;
};

struct klog_result {
	struct klogfile *log;
	loff_t index;
	struct syscall_result psr;
	int retparams_size;
	void *retparams;

	u_long start_clock;
	u_long stop_clock;

	/* Is there a retval? */
	long retval;

	/* Is there a signal? */
	struct klog_signal *signal;

	void (*printfcn)(FILE *, struct klog_result *);
};

struct parse_rules {
	u_long (*get_retparamsize)(struct klogfile *log, struct klog_result *result);
	int retparamsize;
};

struct klogfile {
	int fd;

	/* TODO: Not initialized yet... */
	loff_t num_psrs;

	loff_t cur_idx;

	loff_t expected_clock;

	loff_t active_start_idx;
	loff_t active_num_psrs;
	struct klog_result *active_psrs;

	struct parse_rules *parse_rules[NR_SYSCALLS];

	void (*default_printfcn)(FILE *out, struct klog_result *);
	void (*printfcns[NR_SYSCALLS])(FILE *out, struct klog_result *);
	void (*signal_print)(FILE *out, struct klog_result *);
};

/* 
 * NOTE: after getting a klog_result the previous result is not guaranteed to be
 * valid
 */
struct klogfile *parseklog_open(const char *filename);
void parseklog_close(struct klogfile *log);

struct klog_result *parseklog_get_next_psr(struct klogfile *log);
struct klog_result *parseklog_get_psr(struct klogfile *log, loff_t idx);

int parseklog_read_next_chunk(struct klogfile *log);
int parseklog_cur_chunk_size(struct klogfile *log);
int parseklog_write_chunk(struct klogfile *log, int destfd);
int parseklog_do_write_chunk(int count, struct klog_result *psrs, int destfd);

void parseklog_set_signalprint(struct klogfile *log,
		void (*printfcn)(FILE *out, struct klog_result *));
void parseklog_set_default_printfcn(struct klogfile *log,
		void (*printfcn)(FILE *out, struct klog_result *));
void parseklog_set_printfcn(struct klogfile *log,
		void (*printfcn)(FILE *out, struct klog_result *), int sysnum);

static inline void parseklog_default_print(FILE *out, struct klog_result *res) {
	res->log->default_printfcn(out, res);
}

int klog_print(FILE *out, struct klog_result *result);

#ifdef __cplusplus
}
#endif

#endif

