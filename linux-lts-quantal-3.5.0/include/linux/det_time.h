#include <linux/times.h>
#include <linux/utime.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/atomic.h>

#define MAX_TIME_DIFF 10000000 //10 MS
#define TIME_NSEC_TO_SEC 1000000000
struct det_time_struct {
	atomic_t flag;

	struct timeval fake_init_tv;
	struct timespec fake_init_tp;

	time_t last_fake_sec_accum;
	long last_fake_nsec_accum;

	unsigned long last_clock;
	long step_time;
	long threshold;
};

void init_det_time (struct det_time_struct *det_time, struct timeval *tv, struct timespec *tp);
inline long long get_time_diff (time_t sec_new, long nsec_new, time_t sec_old, long nsec_old);
inline void update_fake_accum_gettimeofday (struct det_time_struct *det_time, struct timeval* now, unsigned long current_clock);
inline void update_fake_accum_clock_gettime (struct det_time_struct *det_time, struct timespec* now, unsigned long current_clock);
inline void update_step_time (long long diff, struct det_time_struct* det_time, unsigned long current_clock);
inline long long get_diff_gettimeofday (struct det_time_struct *det_time, struct timeval* now, unsigned long current_clock);
inline long long get_diff_clock_gettime (struct det_time_struct *det_time, struct timespec* now, unsigned long current_clock);
inline int is_shift_time (struct det_time_struct * det_time, long long  diff, unsigned long current_clock);
inline void calc_det_gettimeofday (struct det_time_struct* det_time, struct timeval* tv, unsigned long current_clock);
inline void calc_det_clock_gettime (struct det_time_struct* det_time, struct timespec* tp, unsigned long current_clock);
