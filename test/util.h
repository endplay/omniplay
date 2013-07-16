#ifndef _UTIL_H_
#define _UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

struct used_address {
    u_long start;
    u_long end;
};

int devspec_init (int* fd_spec);
int replay_fork (int fd_spec, const char** args, const char** env, u_int uid, char* linkpath);
int resume (int fd_spec, int attach_pin, char* logdir, char* linker);
int set_pin_addr (int fd_spec, u_long app_syscall_addr);
int check_clock_before_syscall (int fd_spec, int syscall);
int check_clock_after_syscall (int fd_spec);
int get_log_id (int fd_spec);
int get_used_addresses (int fd_spec, struct used_address* paddrs, int naddrs);

#ifdef __cplusplus
}
#endif

#endif
