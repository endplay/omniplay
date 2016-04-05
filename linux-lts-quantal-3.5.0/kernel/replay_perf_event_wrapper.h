#ifndef REPLAY_PERF_EVENT_WRAPPER_H
#define REPLAY_PERF_EVENT_WRAPPER_H

#include <linux/perf_event.h>


#define BUFFER_SIZE 512
#define DATA_PAGES 2
#define DATA_SIZE (2 * PAGE_SIZE)
#define MMAP_SIZE (3 * PAGE_SIZE)

struct record_perf_event_wrapper { 
	int perf_fd;
	int first_time;
	struct page *mapping_shared_pages;
	struct vm_area_struct *vmas;
	struct perf_event_mmap_page *mapping;
};

int init_record_perf_event_wrapper(struct record_perf_event_wrapper *wrapper, unsigned int sampling_period);
void destroy_record_perf_event_wrapper(struct record_perf_event_wrapper *wrapper);
void record_perf_event_wrapper_start_sampling(struct record_perf_event_wrapper *wrapper);
void record_perf_event_wrapper_stop_sampling(struct record_perf_event_wrapper *wrapper);
void record_perf_event_wrapper_iterate(struct record_perf_event_wrapper *wrapper);

#endif /* REPLAY_PERF_EVENT_WRAPPER_H */
