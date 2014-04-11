#include <linux/det_time.h>

#define DPRINT(x,...)

void init_det_time (struct det_time_struct *det_time, struct timeval *tv, struct timespec *tp) {
	//det_time->fake_sec_accum = 0;
	//det_time->fake_nsec_accum = 0;
	det_time->flag = 0;
	det_time->fake_init_tv.tv_sec = tv->tv_sec;
	det_time->fake_init_tv.tv_usec = tv->tv_usec;
	det_time->fake_init_tp.tv_sec = tp->tv_sec;
	det_time->fake_init_tp.tv_nsec = tp->tv_nsec;

	det_time->last_fake_sec_accum = 0;
	det_time->last_fake_nsec_accum = 0;
	det_time->last_actual_sec_accum = 0;
	det_time->last_actual_nsec_accum = 0;

	det_time->syscall_count = 0;
	det_time->step_time = 256;
	det_time->threshold = 1024;
}

inline void print_accums (struct det_time_struct* det_time) {
	DPRINT ("fake_sec:%ld, fake_nsec:%ld, actual_sec:%ld, actual_nsec:%ld\n", det_time->last_fake_sec_accum, det_time->last_fake_nsec_accum, det_time->last_actual_sec_accum, det_time->last_actual_nsec_accum);
}

inline long get_time_diff (time_t sec_new, long nsec_new, time_t sec_old, long nsec_old) {
	if (sec_new < sec_old || (sec_new == sec_old && nsec_new < nsec_old))
		return -1;
	BUG_ON (sec_new > nsec_new + 2);
	return (sec_new - sec_old)*TIME_NSEC_TO_SEC + (nsec_new - nsec_old);
}

inline long update_actual_accum_gettimeofday (struct det_time_struct *det_time, struct timeval* now) {
	//this function will return the diff between the new time and the last time
	time_t sec;
	long usec;
	long diff;

	sec = now->tv_sec - det_time->fake_init_tv.tv_sec;
	usec = now->tv_usec - det_time->fake_init_tv.tv_usec;

	if (usec < 0) {
		sec --;
		usec += 1000000;
	}
	diff = get_time_diff (sec, usec*1000, det_time->last_actual_sec_accum, det_time->last_actual_nsec_accum);

	det_time->last_actual_sec_accum = sec;
	det_time->last_actual_nsec_accum = usec *1000;

	return diff;
}

inline long update_actual_accum_clock_gettime (struct det_time_struct *det_time, struct timespec* now) {
	//this function will return the diff between the new time and the last time
	time_t sec;
	long nsec;
	long diff;

	sec = now->tv_sec - det_time->fake_init_tp.tv_sec;
	nsec = now->tv_nsec - det_time->fake_init_tp.tv_nsec;

	if (nsec < 0) {
		sec --;
		nsec += 1000000000;
	}
	diff = get_time_diff (sec, nsec, det_time->last_actual_sec_accum, det_time->last_actual_nsec_accum);

	det_time->last_actual_sec_accum = sec;
	det_time->last_actual_nsec_accum = nsec;

	return diff;
}

inline void update_fake_accum (struct det_time_struct *det_time) {
	long passed_time = det_time->step_time * det_time->syscall_count;
	passed_time += det_time->last_fake_nsec_accum;
	while (passed_time >= TIME_NSEC_TO_SEC) {
		passed_time -=TIME_NSEC_TO_SEC;
		++ det_time->last_fake_sec_accum;
	}
	det_time->last_fake_nsec_accum = passed_time;
}

inline int is_shift_time (struct det_time_struct* det_time, long actual_elipse_time) {
	long diff = 0;
	long actual_step_time;
	if (!det_time->syscall_count) det_time->syscall_count = 1;
	actual_step_time = actual_elipse_time / det_time->syscall_count;
	print_accums (det_time);
	update_fake_accum (det_time);
	print_accums (det_time);
	diff = get_time_diff (det_time->last_actual_sec_accum, det_time->last_actual_nsec_accum, det_time->last_fake_sec_accum, det_time->last_fake_nsec_accum);
	DPRINT ("In is_shift_time: diff:%ld, count:%ld, step_time:%ld, threshold:%ld, actual_elipse_time:%ld\n", diff, det_time->syscall_count, det_time->step_time, det_time->threshold, actual_step_time);
	det_time->syscall_count = 0;
	if (diff < 0) {
		det_time->threshold = actual_step_time/2;
		det_time->step_time = actual_step_time*2/3;
		DPRINT ("After is_shift_time: diff:%ld, step_time:%ld, threshold:%ld, actual_elipse_time:%ld\n", diff, det_time->step_time, det_time->threshold, actual_step_time);
		return 1;
	} else if (diff >= MAX_TIME_DIFF) {
		if (det_time->step_time < actual_step_time) {
			det_time->threshold = actual_step_time;
			if (det_time->step_time < actual_step_time*2/3) 
				det_time->step_time = actual_step_time*2/3;
		}
		DPRINT ("After is_shift_time: diff:%ld, step_time:%ld, threshold:%ld, actual_elipse_time:%ld\n", diff, det_time->step_time, det_time->threshold, actual_step_time);
		return 1;
	} else {
		if (det_time->step_time < det_time->threshold) {
			det_time->step_time <<= 1;
		} else
			det_time->step_time += 100;
		DPRINT ("After is_shift_time: diff:%ld, step_time:%ld, threshold:%ld, actual_elipse_time:%ld\n", diff, det_time->step_time, det_time->threshold, actual_step_time);
		return 0;
	}
}

inline int is_shift_gettimeofday (struct det_time_struct *det_time, struct timeval* now) {
	long actual_elipse_time = 0;
	print_accums (det_time);
	actual_elipse_time = update_actual_accum_gettimeofday (det_time, now);
	print_accums (det_time);
	return is_shift_time (det_time, actual_elipse_time);
}

inline int is_shift_clock_gettime (struct det_time_struct *det_time, struct timespec* now) {
	long actual_elipse_time;
	print_accums (det_time);
	actual_elipse_time = update_actual_accum_clock_gettime (det_time, now);
	print_accums (det_time);
	return is_shift_time (det_time, actual_elipse_time);
}
