#ifndef __DATA_ENTRY_H__
#define __DATA_ENTRY_H__

#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/kernel.h>
#include <asm/atomic.h>

struct data_entry_desc {
	int start_clock;
	int pid;
	/* FIXME: This should contain more? */
	loff_t unique_id;
};

/* Data entry structure */
struct data_entry {
	struct data_entry_desc desc;
	wait_queue_head_t waitq;

	struct mutex lock;
	void *data;
	atomic_t refcount;
};

/* Entry table accessors */
void entry_table_init(void);

struct data_entry *entry_table_get(struct data_entry_desc *desc);
struct data_entry *entry_table_tryget(struct data_entry_desc *desc);
void entry_table_put(struct data_entry *entry);

/* Data_entry_desc function(s) */
static inline void data_entry_desc_init(struct data_entry_desc *desc,
		int clock, int pid, int unique_id) {
	desc->start_clock = clock;
	desc->pid = pid;
	desc->unique_id = unique_id;
}

/* data_entry accessors */
/* Called from data_entry_table functions: */
/* Refcounted, refcount initialized to 1 */
void data_entry_init(struct data_entry *entry, struct data_entry_desc *desc);
/* Destroys when refcount is 0 */
void data_entry_put(struct data_entry *entry);

/* Called from FS functions */
void *data_entry_get_data(struct data_entry *);
int data_entry_put_data(struct data_entry *, void *data, size_t size);


#endif

