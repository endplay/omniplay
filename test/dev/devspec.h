#ifndef __DEVSPEC_H__
#define __DEVSPEC_H__

#define SPEC_PSDEV_MAJOR 149

#define SPEC_DEV "/dev/spec0"

#define ROLLED_BACK 1

struct record_data {
	u_long                           app_syscall_addr;
	const char __user *const __user *args;
	const char __user *const __user *env;
	u_int                            uid;
	char *                           linkpath;
	int                              fd;
	char *                           logdir;
};

struct wakeup_data {
	int           pin;
	char __user * logdir;
	char __user * linker;
	int           fd;
};
	
struct get_used_addr_data {
	struct used_address __user * plist;
	int                          nlist;
};


#define SPECI_REPLAY_FORK _IOR('u', 0, struct record_data)
#define SPECI_RESUME _IOR('u', 1, struct wakeup_data)
#define SPECI_SET_PIN_ADDR _IOR('u',2,u_long)
#define SPECI_CHECK_BEFORE _IOR('u',3,int)
#define SPECI_CHECK_AFTER _IOR('u',4,int)
#define SPECI_GET_LOG_ID _IO('u',5)
#define SPECI_GET_USED_ADDR _IOR('u',6,struct get_used_addr_data)

#endif
