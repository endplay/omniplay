#include "replayfs_perftimer.h"

#ifdef DO_PERFTIMER

#include <linux/proc_fs.h>
#include <linux/time.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/err.h>

#include <linux/seq_file.h>

struct group_header {
	struct list_head list;

	struct list_head tmr_list;
	
	char group_name[0x100];
};

struct list_head group_list;

extern atomic_t other_kmallocs;

static struct group_header *get_group_header(const char *group) {
	int found;
	struct group_header *header;

	found = 0;
	list_for_each_entry(header, &group_list, list) {
		if (!strncmp(header->group_name, group, 0x100)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		header = kmalloc(sizeof(struct group_header), GFP_KERNEL);
		atomic_inc(&other_kmallocs);

		if (header == NULL) {
			BUG();
			return ERR_PTR(-ENOMEM);
		}

		list_add(&header->list, &group_list);
		INIT_LIST_HEAD(&header->tmr_list);

		strncpy(header->group_name, group, 0x100);
	}

	return header;
}

static void perftimer_reset(struct perftimer *tmr) {
	tmr->started = 0;

	tmr->count = 0;
	tmr->start_val = 0;
	tmr->total_elapsed = 0;
	tmr->max = 0;
}


static struct perftimer *create_perf_timer(struct group_header *header,
		const char *name) {
	struct perftimer *tmr = kmalloc(sizeof(struct perftimer), GFP_KERNEL);
	atomic_inc(&other_kmallocs);

	if (tmr == NULL) {
		BUG();
		return ERR_PTR(-ENOMEM);
	}

	/* Add tail to make the ordering nicer... */
	list_add_tail(&tmr->list, &header->tmr_list);

	perftimer_reset(tmr);

	strncpy(tmr->name, name, 0x100);

	return tmr;
}

struct perftimer *perftimer_create(const char *name, const char *group) {
	struct group_header *group_header = get_group_header(group);
	struct perftimer *tmr;

	if (group_header == NULL) {
		return NULL;
	}

	tmr = create_perf_timer(group_header, name);

	return tmr;
}

int perftimer_start(struct perftimer *tmr) {
	struct timespec ts;
	if (tmr->started) {
		/*BUG(); */
		return -1;
	}

	tmr->started = 1;
	getnstimeofday(&ts);
	tmr->start_val = timespec_to_ns(&ts);

	return 0;
}

int perftimer_stop(struct perftimer *tmr) {
	if (tmr->started) {
		struct timespec ts;
		s64 elapsed;

		getnstimeofday(&ts);
		
		elapsed = timespec_to_ns(&ts) - tmr->start_val;

		if (elapsed > tmr->max) {
			tmr->max = elapsed;
		}

		tmr->total_elapsed += (u64)elapsed;
		tmr->count++;
	}

	tmr->started = 0;

	return 0;
}

int perftimer_tick(struct perftimer *tmr) {
	perftimer_stop(tmr);
	perftimer_start(tmr);

	return 0;
}

#define STATE_START 0
#define STATE_GROUP 1
#define STATE_TMR 2
#define STATE_END 3
struct list_info_holder {
	int state;

	struct group_header *group;
	struct perftimer *tmr;
};

static void *c_start(struct seq_file *m, loff_t *pos) {
	struct list_info_holder *holder;

	if (*pos != 0) {
		return NULL;
	}
	
	holder = kmalloc(sizeof(struct list_info_holder),
			GFP_KERNEL);
	atomic_inc(&other_kmallocs);

	holder->state = STATE_START;

	if (list_empty(&group_list)) {
		holder->group = NULL;
	} else {
		holder->group = list_first_entry(&group_list, struct group_header, list);
		holder->tmr = list_first_entry(&holder->group->tmr_list, struct perftimer, list);
	}


	printk("Returning holder %p\n", holder);
	return holder;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos) {
	struct list_info_holder *holder = v;
	switch(holder->state) {
		case STATE_START:
			if (holder->group != NULL) {
				holder->state = STATE_GROUP;
			} else {
				holder->state = STATE_END;
			}
			break;
		case STATE_GROUP:
			holder->state = STATE_TMR;
			break;
		case STATE_TMR:
			if (holder->tmr->list.next != &holder->group->tmr_list) {
				holder->tmr =
					list_first_entry(&holder->tmr->list, struct perftimer, list);
					holder->state = STATE_TMR;
			} else {
				if (holder->group->list.next != &group_list) {
					holder->group =
						list_first_entry(&holder->group->list, struct group_header, list);
					holder->tmr = list_first_entry(&holder->group->tmr_list,
							struct perftimer, list);
					holder->state = STATE_GROUP;
				} else {
					holder->state = STATE_END;
				}
			}
			break;
		case STATE_END:
			printk("Returning NULL\n");
			return NULL;
			break;
	}
	*pos = *pos+1;
	printk("Returning holder %p with state %d\n", holder, holder->state);
	return holder;
}

static void c_stop(struct seq_file *m, void *v) {
	printk("Freeing holder %p\n", v);
	kfree(v);
}

static int perftimer_show(struct seq_file *m, void *v) {
	struct list_info_holder *holder = v;
	struct group_header *header;
	struct perftimer *tmr;
	u64 avg;
	int ret = 0;

	printk("Showing v %p, holder %p\n", v, holder);
	switch (holder->state) {
		case STATE_START:
			seq_printf(m, "========================================================\n");
			seq_printf(m, "===               TIMER STATISITICS                  ===\n");
			seq_printf(m, "========================================================\n\n");
			break;
		case STATE_END:
			seq_printf(m, "========================================================\n");
			seq_printf(m, "===         end   TIMER STATISITICS  end             ===\n");
			seq_printf(m, "========================================================\n\n");
			break;
		case STATE_TMR:

			tmr = holder->tmr;
			avg = tmr->total_elapsed;
			if (tmr->count > 0) {
				do_div(avg, tmr->count);
			} else {
				avg = (u64)-1;
			}

			tmr = holder->tmr;
			seq_printf(m, "\t%25s: Average time %10lld, Max time %12lld, Num Triggers %10lld, Total Time %15lld\n",
					tmr->name, avg, tmr->max, tmr->count, tmr->total_elapsed);
			break;
		case STATE_GROUP:
		  header = holder->group;
			seq_printf(m, "=== %s Timers ===\n", header->group_name);
			break;
	}

	return ret;
}

struct seq_operations perftimer_seq_ops = {
	.start = c_start,
	.next = c_next,
	.stop = c_stop,
	.show = perftimer_show
};

static int perftimer_open(struct inode *inode, struct file *file) {
	return seq_open(file, &perftimer_seq_ops);
}

static int reset_perftimers(struct file *filp, const char __user *data,
		size_t size, loff_t *ppos) {
	struct group_header *header;

	list_for_each_entry(header, &group_list, list) {
		struct perftimer *tmr;

		list_for_each_entry(tmr, &header->tmr_list, list) {
			perftimer_reset(tmr);
		}
	}
	
	return 1;
}

struct file_operations proc_fops = {
	.open = perftimer_open,
	.release = seq_release,
	.read = seq_read,
	.write = reset_perftimers,
	.llseek = seq_lseek,
};

int perftimer_init(void) {
	INIT_LIST_HEAD(&group_list);

	proc_create("replayfs_perftimers", 0777, NULL, &proc_fops);

	return 0;
}

void perftimer_close(void) {
	struct group_header *header;
	struct group_header *__tmp1;

	remove_proc_entry("replayfs_perftimers", NULL);

	/* Close all groups */
	list_for_each_entry_safe(header, __tmp1, &group_list, list) {
		struct perftimer *tmr;
		struct perftimer *__tmp2;

		/* Close all timers in each group */
		list_for_each_entry_safe(tmr, __tmp2, &header->tmr_list, list) {
			kfree(tmr);
		}

		kfree(header);
	}

	INIT_LIST_HEAD(&group_list);
}

#endif
