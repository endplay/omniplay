#ifndef __DEVSPEC_H__
#define __DEVSPEC_H__

#define SPEC_PSDEV_MAJOR 149

#define SPEC_DEV "/dev/spec0"

#define ROLLED_BACK 1

struct record_data {
	u_long                           app_syscall_addr;
	const char __user *const __user *args;
	const char __user *const __user *env;
	int                              save_mmap;
	char __user *                    linkpath;
	int                              fd;
	char __user *                    logdir;
	int                              pipe_fd;
};

struct wakeup_data {
	int             pin;
	int             gdb;
	char __user *   logdir;
	char __user *   linker;
	int             fd;
	int             follow_splits;
	loff_t          attach_index;
	int             attach_pid;
	int	        save_mmap;
	int             ckpt_at;
	int             record_timing;
	u_long          nfake_calls;
	u_long __user * fake_calls;
};

struct wakeup_ckpt_data {
	int           pin;
	int           gdb;
	char __user * logdir;
	char __user * filename;
	char __user * linker;
	int           fd;
	int           follow_splits;
	loff_t        attach_index;
	int           attach_pid;
	int	      save_mmap;
};

struct get_used_addr_data {
	struct used_address __user * plist;
	int                          nlist;
};

struct replay_stats_data {
	int started;
	int finished;
	int mismatched;
};

struct filemap_num_data {
	int fd;
	loff_t offset;
	int size;
};

struct filemap_entry_data {
	int fd;
	loff_t offset;
	int size;
	void __user* entries;
	int num_entries;
};

struct open_sockets_data {
	void __user* entries;
	int num_entries;
};

struct get_record_pid_data {
	pid_t nonrecordPid;
};

struct get_replay_pid_data {
	pid_t record_pid;
        pid_t parent_pid;
};


struct set_pin_address_data {
	u_long pin_address;
	u_long pthread_data;
	u_long __user* pcurthread;
	int attach_ndx;
};

#define SPECI_REPLAY_FORK _IOR('u', 0, struct record_data)
#define SPECI_RESUME _IOR('u', 1, struct wakeup_data)
#define SPECI_SET_PIN_ADDR _IOWR('u',2,struct set_pin_address_data)
#define SPECI_CHECK_BEFORE _IOR('u',3,int)
#define SPECI_CHECK_AFTER _IOR('u',4,int)
#define SPECI_GET_LOG_ID _IO('u',5)
#define SPECI_GET_USED_ADDR _IOR('u',6,struct get_used_addr_data)
#define SPECI_GET_REPLAY_STATS _IOW('u',7,struct replay_stats_data)
#define SPECI_GET_CLOCK_VALUE _IO('u',8)
#define SPECI_GET_REPLAY_ARGS _IO('u',9)
#define SPECI_GET_ENV_VARS _IO('u',10)
#define SPECI_GET_RECORD_GROUP_ID _IOW('u',11, u_long)
#define SPECI_GET_NUM_FILEMAP_ENTRIES _IOR('u',12,struct filemap_num_data)
#define SPECI_GET_FILEMAP _IOR('u', 13,struct filemap_entry_data)
#define SPECI_RESET_REPLAY_NDX _IO('u', 14)
#define SPECI_GET_CURRENT_RECORD_PID _IOR('u', 15, struct get_record_pid_data)
#define SPECI_CKPT_RESUME _IOR('u', 16, struct wakeup_ckpt_data)
#define SPECI_CKPT_PROC_RESUME _IOR('u', 17, struct wakeup_ckpt_data)
#define SPECI_GET_ATTACH_STATUS _IOR('u', 18, pid_t)
#define SPECI_WAIT_FOR_REPLAY_GROUP _IOR('u', 19, pid_t)
#define SPECI_TRY_TO_EXIT _IOR('u', 20, pid_t)
#define SPECI_GET_REPLAY_PID _IOR('u', 21, struct get_replay_pid_data)
#define SPECI_MAP_CLOCK _IO('u',22)
#define SPECI_GET_OPEN_SOCKETS _IOR('u', 23, struct open_sockets_data)

#endif
