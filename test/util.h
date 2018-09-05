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

#define OPEN_FD_TYPE_FILE   0
#define OPEN_FD_TYPE_SOCKET 1

struct open_fd {
	int fd;
	int type;
	int data;
	char channel[256];
};

int devspec_init (int* fd_spec);
int replay_fork (int fd_spec, const char** args, const char** env, char* linkpath, char* logdir, int save_mmap, int output_fd);
int resume(int fd_spec, int attach_pin, int attach_gdb, int follow_splits, int save_mmap,
	   char* logdir, char* linker, loff_t attach_index, int attach_pid, int record_timing,
	   u_long nfake_calls, u_long* fake_calls);
int resume_with_ckpt (int fd_spec, int pin, int gdb, int follow_splits, int save_mmap, 
		      char* logdir, char* linker, loff_t attach_index, int attach_pid, int ckpt_at, int record_timing,
		      u_long nfake_calls, u_long* fake_calls);

int resume_after_ckpt (int fd_spec, int pin, int gdb, int follow_splits, int save_mmap, 
		       char* logdir, char* linker, char* filename, char *uniqueid, loff_t attach_index, int attach_pid
		       ,u_long nfake_calls, u_long* fake_calls);

int resume_proc_after_ckpt (int fd_spec, char* logdir, char* filename, char *uniqueid, int ckpt_pos);
int set_pin_addr (int fd_spec, u_long app_syscall_addr, void* pthread_data, void** pcurthread, int* pattach_ndx);
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
int get_open_fds (int fd_spec, struct open_fd* entries, int num_entries);
long reset_replay_ndx(int fd_spec);
pid_t get_current_record_pid(int fd_spec, pid_t nonrecord_pid);
long get_attach_status (int fd_spec, pid_t pid);
int wait_for_replay_group(int fd_spec, pid_t pid);
long try_to_exit (int fd_spec, pid_t pid);
int is_pin_attaching (int fd_spec);
pid_t get_replay_pid(int fd_spec, pid_t parent_pid, pid_t record_pid);
u_long* map_shared_clock (int fd_spec);
long check_for_redo (int fd_spec);
long redo_mmap (int fd_spec, u_long* prc, u_long* plen);
long redo_munmap (int fd_spec);

long reset_replay_ndx(int fd_spec);

#ifdef __cplusplus
}
#endif

#endif
