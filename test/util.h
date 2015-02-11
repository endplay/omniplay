#ifndef _UTIL_H_
#define _UTIL_H_

#include <sys/types.h>
#include <stdint.h>

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

struct filemap_num_entry {
	int fd;
	loff_t offset;
	size_t size;
};

struct filemap_entry {
	int fd;
	loff_t offset;
	int size;
	struct replay_filemap_entry* entries;
	int num_entries;
};

int devspec_init (int* fd_spec);
int replay_fork (int fd_spec, const char** args, const char** env, char* linkpath, char* logdir, int save_mmap, int output_fd);
int resume(int fd_spec, int attach_pin, int follow_splits, int save_mmap,
		char* logdir, char* linker, loff_t attach_index, int attach_pid);
int set_pin_addr (int fd_spec, u_long app_syscall_addr);
int check_clock_before_syscall (int fd_spec, int syscall);
int check_clock_after_syscall (int fd_spec);
int get_log_id (int fd_spec);
long get_clock_value (int fd_spec);
int get_used_addresses (int fd_spec, struct used_address* paddrs, int naddrs);
int get_replay_stats (int fd_spec, struct replay_stat_data * stats);
unsigned long get_replay_args (int fd_spec);
unsigned long get_env_vars (int fd_spec);
int get_record_group_id (int fd_spec, uint64_t* rg_id);

int get_num_filemap_entries (int fd_spec, int fd, loff_t offset, int size);
int get_filemap(int fd_spec, int fd, loff_t offset, int size, void* entries, int num_entries);

long reset_replay_ndx(int fd_spec);

#ifdef __cplusplus
}
#endif

#endif
