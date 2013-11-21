#ifndef _UTIL_H_
#define _UTIL_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct used_address {
    u_long start;
    u_long end;
};

struct replay_stat_data {
	int started;
	int finished;
	int mismatched;
};

int devspec_init (int* fd_spec);
int replay_fork (int fd_spec, const char** args, const char** env, char* linkpath, char* logdir, int save_mmap);
int resume (int fd_spec, int attach_pin, int follow_splits, char* logdir, char* linker);
int set_pin_addr (int fd_spec, u_long app_syscall_addr);
int check_clock_before_syscall (int fd_spec, int syscall);
int check_clock_after_syscall (int fd_spec);
int get_log_id (int fd_spec);
int get_used_addresses (int fd_spec, struct used_address* paddrs, int naddrs);
int get_replay_stats (int fd_spec, struct replay_stat_data * stats);

#ifdef __cplusplus
}
#endif

#endif
