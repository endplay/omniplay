#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/btree.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/mutex.h>
#include <asm/stacktrace.h>

#include "replayfs_kmap.h"

//#define KMAP_DEBUG_PRINTING

#ifdef KMAP_DEBUG_PRINTING
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

#define MAPPING_TRACING

#define PRINT_ENTRIES_ONCE

//#define DOUBLE_ALLOC_CHECK
#define DO_TIMING_PRINTS
#define DO_TIMING_PRINTS_ON_USE

/* Maximum allocation lifetime allowed in seconds before warnings */
#define MAX_ALLOCATION_LIFETIME 5


#ifdef BUILD_KMAP
static atomic_t num_kmaps = {0};
static atomic_t num_kunmaps = {0};
static struct mutex lock;
struct btree_head64 mapping_table;
struct btree_head64 alloc_table;

#define TYPE_INVALID -1
#define IS_KMAP 0
#define IS_KUNMAP 1

struct allocation_record {
	struct allocation_record *next;
	int line;
	const char *function;
};

struct allocation_entry {
	int nallocs;
	int nfrees;

	struct timespec alloc_time;
	u64 inited_time;

	int last_type;

	struct allocation_record *allocs;
	struct allocation_record *frees;

	int printed;
	char prev_stack_frame[4000];
	char *first_stack_frame;
	char *second_stack_frame;
};

static inline u64 key(struct page *page) {
	u64 ret;
	ret = (u64)page->index | (((u64)((u32)page->mapping)) << 32);
	return ret;
}

void replayfs_kmap_init(void) {
	mutex_init(&lock);
	btree_init64(&mapping_table);
	btree_init64(&alloc_table);
}

void replayfs_kmap_destroy(void) {
	printk("%s %d: FIXME: I should check for unmapped mappings here!!!\n",
			__func__, __LINE__);
	mutex_destroy(&lock);
	btree_destroy64(&mapping_table);
	btree_destroy64(&alloc_table);
}

#ifdef MAPPING_TRACING
static struct allocation_entry *cur_entry;
void print_address(unsigned long address, int reliable,
		struct allocation_entry *entry) {
	char addr[200];
	addr[0] = '\0';
	snprintf(addr, 200, " [<%p>] %s %pB\n", (void *)address, reliable ? "" : "? ",
			(void *)address);
	strncat(entry->prev_stack_frame, addr, 200);
}

static int print_trace_stack(void *data, char *name) {
	char addr[200];
	snprintf(addr, 200, "%s <%s> ", (char *)data, name);
	strncat(cur_entry->prev_stack_frame, addr, 200);
	return 0;
}

static void print_trace_address(void *data, unsigned long addr, int reliable) {
	strcat(cur_entry->prev_stack_frame, data);
	print_address(addr, reliable, cur_entry);
}

struct stacktrace_ops trace_ops_to_entry = {
	.stack = print_trace_stack,
	.address = print_trace_address,
	.walk_stack = print_context_stack,
};

static void get_stack_info(struct allocation_entry *entry) {
	unsigned long bp;
	unsigned long stack;

	entry->prev_stack_frame[0] = '\0';
	cur_entry = entry;

	bp = stack_frame(current, NULL);
	dump_trace(NULL, NULL, &stack, bp, &trace_ops_to_entry, "");

	if (entry->first_stack_frame == NULL) {
		size_t size;

		size = strlen(entry->prev_stack_frame);

		entry->first_stack_frame = kmalloc(size+1, GFP_KERNEL);
		BUG_ON(entry->first_stack_frame == NULL);

		strcpy(entry->first_stack_frame, entry->prev_stack_frame);
	} else if (entry->second_stack_frame == NULL) {
		size_t size;

		size = strlen(entry->prev_stack_frame);

		entry->second_stack_frame = kmalloc(size+1, GFP_KERNEL);
		BUG_ON(entry->second_stack_frame == NULL);

		strcpy(entry->second_stack_frame, entry->prev_stack_frame);
	}
}

static void destroy_entry(struct btree_head64 *tree, u64 key) {
	struct allocation_entry *entry;
	struct allocation_record *record;

	entry = btree_remove64(tree, key);
	BUG_ON(entry == NULL);

	if (entry->first_stack_frame != NULL) {
		kfree(entry->first_stack_frame);
	}

	if (entry->second_stack_frame != NULL) {
		kfree(entry->second_stack_frame);
	}

	while (entry->allocs != NULL) {
		record = entry->allocs;
		entry->allocs = record->next;
		kfree(record);
	}

	while (entry->frees != NULL) {
		record = entry->frees;
		entry->frees = record->next;
		kfree(record);
	}

	kfree(entry);
}

static void print_entry_status(struct allocation_entry *entry) {
	struct allocation_record *record;
	unsigned long rem_nsec;


#ifdef PRINT_ENTRIES_ONCE
	if (entry->printed) {
		return;
	}
#endif
	entry->printed = 1;

	printk("\tEntry->nallocs: %d\n", entry->nallocs);
	record = entry->allocs;
	while (record != NULL) {
		printk("\t\tAllocation from: %s %d\n", record->function, record->line);
		record = record->next;
	}
	printk("\tEntry->nfrees: %d\n", entry->nfrees);
	record = entry->frees;
	while (record != NULL) {
		printk("\t\tFree from: %s %d\n", record->function, record->line);
		record = record->next;
	}

	rem_nsec = do_div(entry->inited_time, 1000000000);
	printk("\tAllocation Time: [%5lu.%06lu]\n", (unsigned long)entry->inited_time,
			rem_nsec/1000);
	printk("\tStack History:\n");
	if (entry->first_stack_frame) {
		printk("\t\tFirst Stack Frame:\n");
		printk("%s\n", entry->first_stack_frame);
	}
	if (entry->second_stack_frame) {
		printk("\t\tFirst Stack Frame:\n");
		printk("%s\n", entry->first_stack_frame);
	}
	printk("\t\tPrev Stack Frame:\n");
	printk("%s\n", entry->prev_stack_frame);

	printk("\t\tCur Stack Frame:\n");
	dump_stack();
}

static void check_use(struct allocation_entry *entry) {
#ifdef DO_TIMING_PRINTS_ON_USE
	__kernel_time_t allocation_lifetime = 
		CURRENT_TIME_SEC.tv_sec - entry->alloc_time.tv_sec;

	if (allocation_lifetime > MAX_ALLOCATION_LIFETIME) {
		printk("%s %d: Warning, mapping is living longer than expected!\n", __func__,
				__LINE__);
		dump_stack();
		print_entry_status(entry);
	}
#endif
}

static void check_entry(struct allocation_entry *entry) {
#ifdef DO_TIMING_PRINTS
	__kernel_time_t allocation_lifetime = 
		CURRENT_TIME_SEC.tv_sec - entry->alloc_time.tv_sec;

	if (allocation_lifetime > MAX_ALLOCATION_LIFETIME) {
		/*
		printk("%s %d: Warning, mapping is living longer than expected!\n", __func__,
				__LINE__);
				*/
		print_entry_status(entry);
	}
#endif
}

static void check_all_entries(struct btree_head64 *tree) {
	u64 key;
	struct allocation_entry *entry;
	btree_for_each_safe64(tree, key, entry) {
		check_entry(entry);
	}
}

static void update_entry(struct page *page, const char *func, int line,
		int type, struct btree_head64 *tree, int do_checks) {
	struct allocation_entry *entry;
	struct allocation_record *record;
	struct allocation_record *cur_record;
	/* First, lookup */
	mutex_lock(&lock);
	/*
	debugk("%s %d: %s lookup on key %llx, {%lX, %p}\n", __func__, __LINE__,
			((type)?"Kunmap":"Kmap"),
			key(page), page->index, page->mapping);
			*/
	entry = btree_lookup64(tree, key(page));
	if (entry == NULL) {
		int err;
		entry = kmalloc(sizeof(struct allocation_entry), GFP_KERNEL);
		/* I don't deal with this... */
		if (entry == NULL) {
			BUG();
		}

		entry->nallocs = 0;
		entry ->nfrees = 0;
		entry->alloc_time = CURRENT_TIME_SEC;
		entry->inited_time = local_clock();
		entry->allocs = NULL;
		entry->frees = NULL;

		entry->last_type = TYPE_INVALID;

		entry->printed = 0;
		entry->first_stack_frame = NULL;
		entry->second_stack_frame = NULL;
		
		err = btree_insert64(tree, key(page), entry, GFP_KERNEL);
		BUG_ON(err);
	}

	if (type == IS_KMAP) {
		entry->nallocs++;
	} else {
		entry->nfrees++;
		if (entry->nallocs == 0) {
			printk("%s %d: Free before use??? from %s %d\n", __func__, __LINE__, func,
					line);
			BUG();
		}
	}

#ifdef DOUBLE_ALLOC_CHECK
	if (entry->last_type == type) {
		printk("!!!!Have double alloc!!!!\n");
		printk("%s\n", entry->prev_stack_frame);

		printk("!!!! Current stack during double alloc !!!!\n");
		dump_stack();
	}
	entry->last_type = type;

#endif


	record = kmalloc(sizeof(struct allocation_record), GFP_KERNEL);
	BUG_ON(record == NULL);

	record->next = NULL;
	record->line = line;
	record->function = func;

	if (type == IS_KMAP) {
		if (entry->allocs == NULL) {
			entry->allocs = record;
			cur_record = NULL;
		} else {
			cur_record = entry->allocs;
		}
	} else if (type == IS_KUNMAP) {
		if (entry->frees == NULL) {
			entry->frees = record;
			cur_record = NULL;
		} else {
			cur_record = entry->frees;
		}
	} else {
		BUG();
	}

	if (cur_record != NULL) {
		while (cur_record->next != NULL) {
			cur_record = cur_record->next;
		}
		cur_record->next = record;
	}

	if (entry->nallocs == entry->nfrees) {
		debugk("%s %d: Destroying entry %lu {%lld}\n", __func__, __LINE__,
				page->index, key(page));
		destroy_entry(tree, key(page));
	}

	if (do_checks) {
		check_use(entry);
		check_all_entries(tree);
	}

	get_stack_info(entry);

	mutex_unlock(&lock);
}
#else
#define update_entry(...)
#define periodic_check(...)
#endif

void __pagealloc_get(struct page *page, const char *function, int line) {

	debugk("%s %d: Pagealloc_get on (%lu) {%llX}\n", __func__, __LINE__,
			page->index, key(page));

	if (page->index == 217) {
		dump_stack();
	}

	update_entry(page, function, line, IS_KMAP, &alloc_table, 0);
}

void __pagealloc_put(struct page *page, const char *function, int line) {
	debugk("%s %d: Pagealloc_put on (%lu) {%llX}\n", __func__, __LINE__,
			page->index, key(page));

	if (page->index == 217) {
		dump_stack();
	}

	update_entry(page, function, line, IS_KUNMAP, &alloc_table, 0);
}

void pagealloc_print_status(struct page *page) {
	struct allocation_entry *entry;

	entry = btree_lookup64(&alloc_table, key(page));

	if (entry != NULL) {
		print_entry_status(entry);
	}
}

void *__replayfs_kmap(struct page *page, const char *function, int line) {
	void *ret;
	ret = kmap(page);
	debugk("%s %d: Map on (%lu) {%llX}\n", __func__, __LINE__, page->index, key(page));

	atomic_inc(&num_kmaps);

	/* Okay, keep a record of this allocation (if enabled) */
	update_entry(page, function, line, IS_KMAP, &mapping_table, 1);

	BUG_ON(ret == NULL);
	return ret;
}

void __replayfs_kunmap(struct page *page, const char *function, int line) {
	debugk("%s %d: Unmap on (%lu) {%llX}\n", __func__, __LINE__, page->index, key(page));

	update_entry(page, function, line, IS_KUNMAP, &mapping_table, 1);

	atomic_inc(&num_kunmaps);
	kunmap(page);
}

#endif // BUILD_KMAP
