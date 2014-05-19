#include <linux/det_time.h>
#include <linux/math64.h>

#define DPRINT(x,...)
//#define DPRINT printk

void init_det_time (struct det_time_struct *det_time, struct timeval *tv, struct timespec *tp) {
	atomic_set (&det_time->flag, 0);

	det_time->fake_init_tv.tv_sec = tv->tv_sec;
	det_time->fake_init_tv.tv_usec = tv->tv_usec;
	det_time->fake_init_tp.tv_sec = tp->tv_sec;
	det_time->fake_init_tp.tv_nsec = tp->tv_nsec;

	det_time->last_fake_sec_accum = 0; //last time we shift the clock
	det_time->last_fake_nsec_accum = 0;

	det_time->last_clock = 0;
	det_time->step_time = 256;
	det_time->threshold = 1024;
	DPRINT ("det_time init ends.\n");
}

inline long long get_time_diff (time_t sec_new, long nsec_new, time_t sec_old, long nsec_old) {
	return (sec_new - sec_old)*TIME_NSEC_TO_SEC + (nsec_new - nsec_old);
}

inline void update_fake_accum_gettimeofday (struct det_time_struct *det_time, struct timeval* now, unsigned long current_clock) {
	DPRINT ("update_fake_accum last_fake_sec: %lu, last_fake_nsec %lu, last_clock:%lu, current_clock:%lu\n", 
			det_time->last_fake_sec_accum, det_time->last_fake_nsec_accum, det_time->last_clock, current_clock);
	det_time->last_fake_sec_accum = now->tv_sec - det_time->fake_init_tv.tv_sec;
	det_time->last_fake_nsec_accum = (now->tv_usec - det_time->fake_init_tv.tv_usec) * 1000;
	if (det_time->last_fake_nsec_accum < 0) {
		-- det_time->last_fake_sec_accum;
		det_time->last_fake_nsec_accum += TIME_NSEC_TO_SEC;
	}
	//also remember to update last_clock hereh
	det_time->last_clock = current_clock;
}

inline void update_fake_accum_clock_gettime (struct det_time_struct *det_time, struct timespec* now, unsigned long current_clock) {
	DPRINT ("update_fake_accum last_fake_sec: %lu, last_fake_nsec %lu, last_clock:%lu, current_clock:%lu\n", 
			det_time->last_fake_sec_accum, det_time->last_fake_nsec_accum, det_time->last_clock, current_clock);
	det_time->last_fake_sec_accum = now->tv_sec - det_time->fake_init_tp.tv_sec;
	det_time->last_fake_nsec_accum = now->tv_nsec - det_time->fake_init_tp.tv_nsec;
	if (det_time->last_fake_nsec_accum < 0) {
		-- det_time->last_fake_sec_accum;
		det_time->last_fake_nsec_accum += TIME_NSEC_TO_SEC;
	}
	//also remember to update last_clock hereh
	det_time->last_clock = current_clock;
}

inline void update_step_time (long long diff, struct det_time_struct* det_time, unsigned long current_clock) {
	unsigned long actual_step_time;
	unsigned long count = current_clock - det_time->last_clock;
	actual_step_time = div64_long (diff, count);
	DPRINT ("update_step_time: diff:%lld, count:%ld, step_time:%ld, threshold:%ld, actual_step_time:%ld\n", diff, count, det_time->step_time, det_time->threshold, actual_step_time);
	det_time->threshold = actual_step_time*9/10;
	det_time->step_time = actual_step_time*9/10;
}

inline long long get_diff_gettimeofday (struct det_time_struct *det_time, struct timeval* now, unsigned long current_clock) {
	//this function return the diff between current time and the last shifted time
	unsigned long fake_tv_sec = det_time->fake_init_tv.tv_sec + det_time->last_fake_sec_accum;
	unsigned long fake_tv_nsec = det_time->fake_init_tv.tv_usec * 1000 + det_time->last_fake_nsec_accum;
	// note: fake_tv_nsec could be greater than TIME_NSEC_TO_SEC
	return get_time_diff (now->tv_sec, now->tv_usec*1000, fake_tv_sec, fake_tv_nsec);
}

inline long long get_diff_clock_gettime (struct det_time_struct *det_time, struct timespec* now, unsigned long current_clock) {
	unsigned long fake_tv_sec = det_time->fake_init_tp.tv_sec + det_time->last_fake_sec_accum;
	unsigned long fake_tv_nsec = det_time->fake_init_tp.tv_nsec + det_time->last_fake_nsec_accum;
	// note: fake_tv_nsec could be greater than TIME_NSEC_TO_SEC
	return get_time_diff (now->tv_sec, now->tv_nsec, fake_tv_sec, fake_tv_nsec);
}

inline int is_shift_time (struct det_time_struct * det_time, long long  diff, unsigned long current_clock) {
	//now the diff is between current real time and the current fake time
	diff -= det_time->step_time * (current_clock - det_time->last_clock);
	if (diff < 0 || diff > MAX_TIME_DIFF) 
		return 1;
	return 0;
}

inline void calc_det_gettimeofday (struct det_time_struct* det_time, struct timeval* tv, unsigned long current_clock) {
	unsigned long fake_tv_sec = det_time->fake_init_tv.tv_sec + det_time->last_fake_sec_accum;
	unsigned long fake_tv_nsec = det_time->fake_init_tv.tv_usec * 1000 + det_time->last_fake_nsec_accum + det_time->step_time * (current_clock - det_time->last_clock);
	while (fake_tv_nsec >= TIME_NSEC_TO_SEC) {
		fake_tv_nsec -= TIME_NSEC_TO_SEC;
		++ fake_tv_sec;
	}
	tv->tv_sec = fake_tv_sec;
	tv->tv_usec = fake_tv_nsec/1000;
}

inline void calc_det_clock_gettime (struct det_time_struct* det_time, struct timespec* tp, unsigned long current_clock) {
	unsigned long fake_tv_sec = det_time->fake_init_tp.tv_sec + det_time->last_fake_sec_accum;
	unsigned long fake_tv_nsec = det_time->fake_init_tp.tv_nsec + det_time->last_fake_nsec_accum + det_time->step_time * (current_clock - det_time->last_clock);
	while (fake_tv_nsec >= TIME_NSEC_TO_SEC) {
		fake_tv_nsec -= TIME_NSEC_TO_SEC;
		++ fake_tv_sec;
	}
	tp->tv_sec = fake_tv_sec;
	tp->tv_nsec = fake_tv_nsec;
}
