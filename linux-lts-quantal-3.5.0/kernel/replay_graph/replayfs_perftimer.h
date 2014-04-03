#ifndef __PERFTIMER_H
#define __PERFTIMER_H

#include <linux/kernel.h>
#include <linux/list.h>

struct perftimer {
	struct list_head list;
	char name[0x100];
	u64 count;
	int started;
	s64 start_val;
	u64 total_elapsed;
};

int perftimer_init(void);
void perftimer_close(void);
void perftimer_printall(struct perftimer *);

/* All timers are deallocated at close, but not before */
struct perftimer *perftimer_create(const char *name, const char *group);
int perftimer_start(struct perftimer *);
int perftimer_stop(struct perftimer *);
int perftimer_tick(struct perftimer *);

#endif

