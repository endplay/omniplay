#ifndef __DEVSPEC_H__
#define __DEVSPEC_H__

#define SPEC_PSDEV_MAJOR 149

#define SPEC_DEV "/dev/spec0"

#define ROLLED_BACK 1

struct record_data {
	u_long                           app_syscall_addr;
	const char __user *const __user *args;
	const char __user *const __user *env;
	int				 save_mmap;
	char __user *                    linkpath;
	int                              fd;
	char __user *                    logdir;
	int                              pipe_fd;
};

struct wakeup_data {
	int           pin;
	int           gdb;
	char __user * logdir;
	char __user * linker;
	int           fd;
	int           follow_splits;
	int           syscall_index;
	int           save_mmap;
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

#define SPECI_REPLAY_FORK _IOR('u', 0, struct record_data)
#define SPECI_RESUME _IOR('u', 1, struct wakeup_data)
#define SPECI_SET_PIN_ADDR _IOR('u',2,u_long)
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

#endif
