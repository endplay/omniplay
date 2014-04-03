#ifndef __PERFTIMER_H
#define __PERFTIMER_H

#include <linux/kernel.h>
#include <linux/list.h>

#define DO_PERFTIMER

struct perftimer {
	struct list_head list;
	char name[0x100];
	u64 count;
	int started;
	s64 start_val;
	u64 total_elapsed;
	u64 max;
};

#ifdef DO_PERFTIMER
int perftimer_init(void);
void perftimer_close(void);
void perftimer_printall(struct perftimer *);

/* All timers are deallocated at close, but not before */
struct perftimer *perftimer_create(const char *name, const char *group);
int perftimer_start(struct perftimer *);
int perftimer_stop(struct perftimer *);
int perftimer_tick(struct perftimer *);
#else
static inline int perftimer_init(void) { return 0; }
static inline void perftimer_close(void) { }
static inline void perftimer_printall(struct perftimer *) { }

/* All timers are deallocated at close, but not before */
static inline struct perftimer *perftimer_create(const char *name,
		const char *group) {
	return NULL;
}

static inline int perftimer_start(struct perftimer *) { return 0; }
static inline int perftimer_stop(struct perftimer *) { return 0; }
static inline int perftimer_tick(struct perftimer *) { return 0; }
#endif

#endif

