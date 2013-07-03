#ifndef __REPLAY_H__
#define __REPLAY_H__

#define MAX_LOGDIR_STRLEN 80

/* Starts replay with a (possibly) multithreaded fork */
int fork_replay (u_long app_syscall_addr, char* logdir);

/* Restore ckpt from disk - replaces AS of current process (like exec) */
/* Linker may be NULL - otherwise points to special libc linker */
long replay_ckpt_wakeup (int attach_pin, char* logdir, char* linker);

/* Sets the linker to use for a user-level pthread library */
void set_linker (char* linker);
char* get_linker (void);

int get_app_syscall_addr (void);

/* These should be used only by a PIN tool */
struct used_address {
    u_long start;
    u_long end;
};

int set_pin_address (u_long pin_address);
long get_log_id (void);
long check_clock_before_syscall (int syscall);
long check_clock_after_syscall (int syscall);
long get_used_addresses (struct used_address __user * plist, int listsize);
void print_memory_areas (void);

/* Handles replay-specific work to record a signal */
void record_signal_delivery (int signr, siginfo_t* info, struct k_sigaction* ka);
void replay_signal_delivery (int* signr, siginfo_t* info);
int replay_has_pending_signal (void);

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

/* Checkpoint functions */
long replay_checkpoint_to_disk (char* filename, u_long app_syscall_addr);
long replay_resume_from_disk (char* filename, u_long* app_syscall_addr);

/* For synchronization points in kernel outside of replay.c */
#define TID_WAKE_CALL 500
struct syscall_result;

long new_syscall_enter_external (long sysnum);
long new_syscall_exit_external (long sysnum, long retval, void* retparams);
long get_next_syscall_enter_external (int syscall, char** ppretparams, char** ppargs, struct syscall_result** ppsr);
void get_next_syscall_exit_external (struct syscall_result* psr);

/* For handling randomness within the kernel */
void record_randomness(long);
long replay_randomness(void);

// agreed upon length of the SHM_PATH_LENGTH
#define SHM_PATH_LENGTH 64

#endif
