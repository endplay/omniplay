#ifndef __REPLAY_H__
#define __REPLAY_H__

#define MAX_LOGDIR_STRLEN 80

/* These are the device numbers for the attach mechanism in replay_ckpt_wakeup */
#define ATTACH_PIN 1
#define ATTACH_GDB 2

/* These are return values from set_pin_address */
#define PIN_NORMAL         0
#define PIN_ATTACH_RUNNING 1
#define PIN_ATTACH_BLOCKED 2
#define PIN_ATTACH_REDO    4

#include <linux/signal.h>
#include <linux/mm_types.h>

/* Starts replay with a (possibly) multithreaded fork */
int fork_replay (char __user * logdir, const char __user *const __user *args,
		const char __user *const __user *env, char* linker, int save_mmap, int fd,
		int pipe_fd);

/* Restore ckpt from disk - replaces AS of current process (like exec) */
/* Linker may be NULL - otherwise points to special libc linker */
long replay_ckpt_wakeup (int attach_device, char* logdir, char* linker, int fd,
			 int follow_splits, int save_mmap, loff_t syscall_index, int attach_pid, int ckpt_at, int record_timing,
			 u_long nfake_calls, u_long* fake_call_points);
long replay_full_ckpt_wakeup (int attach_device, char* logdir, char* filename, char* linker, int fd, 
			      int follow_splits, int save_mmap, loff_t syscall_index, int attach_pid);
long replay_full_ckpt_proc_wakeup (char* logdir, char* filename, int fd);

/* Returns linker for exec to use */
char* get_linker (void);

/* These should be used only by a PIN tool */
struct used_address {
    u_long start;
    u_long end;
};

int set_pin_address (u_long pin_address, u_long thread_data, u_long __user* curthread_ptr, int* attach_ndx);
long get_log_id (void);
unsigned long get_clock_value (void);
long check_clock_before_syscall (int syscall);
long check_clock_after_syscall (int syscall);
long check_for_redo (void);
long redo_mmap (u_long __user * prc, u_long __user * plen);
long get_used_addresses (struct used_address __user * plist, int listsize);
void print_memory_areas (void);

/* Handles replay-specific work to record a signal */
int get_record_ignore_flag (void);
long check_signal_delivery (int signr, siginfo_t* info, struct k_sigaction* ka, int ignore_flag);
long record_signal_delivery (int signr, siginfo_t* info, struct k_sigaction* ka);
void replay_signal_delivery (int* signr, siginfo_t* info);
int replay_has_pending_signal (void);
int get_record_pending_signal (siginfo_t* info);

/* Called when a record/replay thread exits */
void recplay_exit_start(void);
void recplay_exit_middle(void);
void recplay_exit_finish(void);

/* Called during a vfork */
void record_vfork_handler (struct task_struct* tsk);
void replay_vfork_handler (struct task_struct* tsk);

/* Common helper functions */
struct pt_regs* get_pt_regs(struct task_struct* tsk);
char* get_path_helper (struct vm_area_struct* vma, char* path);

/* For synchronization points in kernel outside of replay.c */
#define TID_WAKE_CALL 500
struct syscall_result;

long new_syscall_enter_external (long sysnum);
long new_syscall_exit_external (long sysnum, long retval, void* retparams);
long get_next_syscall_enter_external (int syscall, char** ppretparams, struct syscall_result** ppsr);
void get_next_syscall_exit_external (struct syscall_result* psr);

/* For handling randomness within the kernel */
void record_randomness(u_long);
u_long replay_randomness(void);

/* ... and for other exec values */
void record_execval(int uid, int euid, int gid, int egid, int secureexec);
void replay_execval(int* uid, int* euid, int* gid, int* egid, int* secureexec);

/* For replaying exec from a cache file */
const char* replay_get_exec_filename (void);


/* In replay_logdb.c */
__u64 get_replay_id (void);
void get_logdir_for_replay_id (__u64 id, char* buf);
int make_logdir_for_replay_id (__u64 id, char* buf);

/* In replay_ckpt.h */
char* copy_args (const char __user* const __user* args, const char __user* const __user* env, int* buflen);
long replay_checkpoint_to_disk (char* filename, char* execname, char* buf, int buflen, __u64 parent_rg_id);
long replay_resume_from_disk (char* filename, char** execname, char*** argsp, char*** envp, __u64* prg_id);
long replay_full_resume_hdr_from_disk (char* filename, __u64* prg_id, int* pclock, u_long* pproccount, loff_t* ppos);
long replay_full_checkpoint_hdr_to_disk (char* filename, __u64 rg_id, int clock, u_long proc_count, loff_t* ppos);
long replay_full_checkpoint_proc_to_disk (char* filename, struct task_struct* tsk, pid_t record_pid, long retval, loff_t logpos, u_long outptr, u_long consumed, u_long expclock, loff_t* ppos);
long replay_full_resume_proc_from_disk (char* filename, pid_t clock_pid, long* pretval, loff_t* plogpos, u_long* poutptr, u_long* pconsumed, u_long* pexpclock, loff_t* ppos);

/* Helper functions for checkpoint/resotre */
int checkpoint_replay_cache_files (struct task_struct* tsk, struct file* cfile, loff_t* ppos);
int restore_replay_cache_files (struct file* cfile, loff_t* ppos);
long get_ckpt_state (pid_t pid);

/* Optional stats interface */
#define REPLAY_STATS
#ifdef REPLAY_STATS
struct replay_stats {
	atomic_t started;
	atomic_t finished;
	atomic_t mismatched;
};

long get_replay_stats (struct replay_stats __user * ustats);

#endif

/* For tracking where the args are in Pin, only valid on replay */
void save_exec_args(unsigned long argv, int argc, unsigned long envp, int envc);
unsigned long get_replay_args(void);
unsigned long get_env_vars(void);
long get_attach_status(pid_t pid);
int wait_for_replay_group(pid_t pid);
pid_t get_replay_pid(pid_t parent_pid, pid_t record_pid);


long get_record_group_id(__u64 __user * prg_id);

/* Pass in the "real" resume process pid and it will give back the
	recorded replay pid that is currently running.
	Does not need to be called from a replay thread.*/
pid_t get_current_record_pid(pid_t nonrecord_pid);

/* Calls to read the filemap */
long get_num_filemap_entries(int fd, loff_t offset, int size);
long get_filemap(int fd, loff_t offset, int size, void __user * entries, int num_entries);

long reset_replay_ndx(void);

/* Used for gdb attachment */
int replay_gdb_attached(void);
void replay_unlink_gdb(struct task_struct* tsk);

/* Set to force a replay to exit on fatal signal */
long try_to_exit (u_long pid);

/* Let's the PIN tool read the clock value too */
long pthread_shm_path (void);

/* For obtaining list of open sockets */
struct monitor_data {
	int fd;
	int type;
	int data;
	char channel[256];
};
long get_open_socks (struct monitor_data __user* entries, int num_entries);

#endif
