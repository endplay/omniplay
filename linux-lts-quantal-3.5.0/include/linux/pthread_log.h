#ifndef __PTHREAD_LOG_H__
#define __PTHREAD_LOG_H__

/* Note: must update both user-level (in glibc) and kernel headers together*/

struct pthread_log_data {
	unsigned long clock;
	int           retval;
	unsigned long type;
	unsigned long check;
};

struct pthread_log_head {
	struct pthread_log_data __user * next;
	struct pthread_log_data __user * end;
	int ignore_flag;
	int need_fake_calls;
};

#define PTHREAD_LOG_ENTRIES (1024*1024)

#define PTHREAD_LOG_NONE           0
#define PTHREAD_LOG_RECORD         1
#define PTHREAD_LOG_REPLAY         2
#define PTHREAD_LOG_OFF            3
#define PTHREAD_LOG_REP_AFTER_FORK 4

#endif
