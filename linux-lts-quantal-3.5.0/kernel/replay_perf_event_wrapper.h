#ifndef REPLAY_PERF_EVENT_WRAPPER_H
#define REPLAY_PERF_EVENT_WRAPPER_H

#include <linux/perf_event.h>


#define PERF_OUTBUF_ENTRIES 10000
#define BUFFER_SIZE 512

struct replay_perf_wrapper { 
	int perf_fd;
	int first_time;
	int overflow_count;
	u_long num_syscalls;
	u_int data_size;
	int  bufcnt; //index within above buffer	

	char *logdir; //pointer to the log_dir for this wrapper's replay
	__u32 *outbuf; //pointer to buffer of things to write to file
	loff_t outpos; //index within our output file

	struct perf_event_mmap_page *mapping;
};

int init_replay_perf_wrapper(struct replay_perf_wrapper *wrapper, 
			     char *logdir,
			     unsigned int sample_type, 
			     unsigned int  config,
			     unsigned int sample_period,
			     unsigned int data_size);

void destroy_replay_perf_wrapper(struct replay_perf_wrapper *wrapper);
void replay_perf_wrapper_start_sampling(struct replay_perf_wrapper *wrapper);
void replay_perf_wrapper_stop_sampling(struct replay_perf_wrapper *wrapper);
void replay_perf_wrapper_iterate(struct replay_perf_wrapper *wrapper);

#endif /* REPLAY_PERF_EVENT_WRAPPER_H */
