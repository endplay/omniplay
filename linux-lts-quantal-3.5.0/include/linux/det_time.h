#include <linux/times.h>
#include <linux/utime.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

#define MAX_TIME_DIFF 10000000 //10 MS, when you set up a new number other 10 ms, make sure it's smaller than 1 s
#define TIME_NSEC_TO_SEC 1000000000
struct det_time_struct {
	//time_t fake_sec_accum;
	//long fake_nsec_accum;
	int flag;

	struct timeval fake_init_tv;
	struct timespec fake_init_tp;

	time_t last_fake_sec_accum;
	long last_fake_nsec_accum;

	time_t last_actual_sec_accum;
	long last_actual_nsec_accum;

	long syscall_count;
	long step_time;
	long threshold;
};

void init_det_time (struct det_time_struct *det_time, struct timeval *tv, struct timespec *tp);
inline long get_time_diff (time_t sec_new, long nsec_new, time_t sec_old, long nsec_old);
inline long update_actual_accum_gettimeofday (struct det_time_struct *det_time, struct timeval* now);
inline long update_actual_accum_clock_gettime (struct det_time_struct *det_time, struct timespec* now);
inline void update_fake_accum (struct det_time_struct *det_time);
inline int is_shift_time (struct det_time_struct* det_time, long actual_elipse_time);
inline int is_shift_gettimeofday (struct det_time_struct *det_time, struct timeval* now);
inline int is_shift_clock_gettime (struct det_time_struct *det_time, struct timespec* now);
