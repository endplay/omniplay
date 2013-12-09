#ifndef __PTHREAD_LOG_H__
#define __PTHREAD_LOG_H__

/* Note: must update both user-level (in glibc) and kernel headers together*/

// Debug log uses uncompressed format
//#define USE_DEBUG_LOG

#ifdef USE_DEBUG_LOG
struct pthread_log_data {
	unsigned long clock;
	int           retval;
	int           errno;
	unsigned long type;
	unsigned long check;
};

struct pthread_log_head {
	struct pthread_log_data* next;
	struct pthread_log_data* end;
	int ignore_flag;
	int need_fake_calls;
};

#define FAKE_SYSCALLS                        127

#else
struct pthread_log_head {
	char* next;
	char* end;
	int ignore_flag;
	int need_fake_calls;
	unsigned long expected_clock;
	unsigned long num_expected_records;
	int save_errno; // Tracks whether errno changes in an ignored region
};

#define NONZERO_RETVAL_FLAG 0x80000000
#define FAKE_CALLS_FLAG     0x40000000
#define SKIPPED_CLOCK_FLAG  0x20000000
#define ERRNO_CHANGE_FLAG   0x10000000
#define CLOCK_MASK          0x0fffffff

#endif

#define PTHREAD_LOG_SIZE (16*1024*1024)

#define PTHREAD_LOG_NONE           0
#define PTHREAD_LOG_RECORD         1
#define PTHREAD_LOG_REPLAY         2
#define PTHREAD_LOG_OFF            3
#define PTHREAD_LOG_REP_AFTER_FORK 4

#endif
