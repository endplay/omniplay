#include "data_entry.h"
#include "replayfs_file_log.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>

#include <linux/replay.h>

/* 10 kilo entries? */
#define ENTRY_TABLE_SIZE ((1<<10) * 10)
/* 100? */
#define MUTEX_TABLE_SIZE (1<<7)

static struct mutex mutex_table[MUTEX_TABLE_SIZE];
static struct data_entry *table[ENTRY_TABLE_SIZE];

/* Custom allocator (in case of slab allocations) */
static struct data_entry *data_entry_alloc(void);
static void data_entry_free(struct data_entry *);

/* Destructor, once ref hits 0 */
static void data_entry_destroy(struct data_entry *);

/* Internal helper function */
static inline struct data_entry *__data_entry_get_internal(struct data_entry_desc *);

/* Simple utility functions */
static inline void lock_table(struct data_entry_desc *desc);
static inline void unlock_table(struct data_entry_desc *desc);

static inline unsigned int desc_hash(struct data_entry_desc *desc);
static inline int desc_cmp(struct data_entry_desc *desc1,
		struct data_entry_desc *desc2);

static inline int get_entry_num(struct data_entry_desc *desc);


void entry_table_init(void) {
	int i;

	memset(table, 0, sizeof(struct data_entry *) * ENTRY_TABLE_SIZE);

	for (i = 0; i < MUTEX_TABLE_SIZE; i++) {
		mutex_init(&mutex_table[i]);
	}
}

struct data_entry *entry_table_get(struct data_entry_desc *desc) {
	struct data_entry *ret;

	lock_table(desc);

	ret = __data_entry_get_internal(desc);

	/* No entry, we must allocate one! */
	if (ret == NULL) {
		unsigned int entry_num;

		entry_num = get_entry_num(desc);

		ret = data_entry_alloc();
		BUG_ON(ret == NULL);

		data_entry_init(ret, desc);

		table[entry_num] = ret;
	} else {
		/* Ref! */
		atomic_inc(&ret->refcount);
	}

	if (desc_cmp(desc, &ret->desc)) {
		BUG();
	}

	unlock_table(desc);

	return ret;
}

struct data_entry *entry_table_tryget(struct data_entry_desc *desc) {
	struct data_entry *ret;

	lock_table(desc);
	ret = __data_entry_get_internal(desc);
	unlock_table(desc);

	if (ret != NULL) {
		atomic_inc(&ret->refcount);
	}

	return ret;
}

void entry_table_put(struct data_entry *entry) {
	/* Deref our object */
	if (atomic_dec_and_test(&entry->refcount)) {
		unsigned int hash;
		int mutex_num;
		int entry_num;

		hash = desc_hash(&entry->desc);
		mutex_num = hash % MUTEX_TABLE_SIZE;
		entry_num = hash % ENTRY_TABLE_SIZE;
		mutex_lock(&mutex_table[mutex_num]);
		table[entry_num] = NULL;
		mutex_unlock(&mutex_table[mutex_num]);

		data_entry_destroy(entry);
	}
}

void data_entry_init(struct data_entry *entry, struct data_entry_desc *desc) {

	memcpy(&entry->desc, desc, sizeof(struct data_entry_desc));
	/* Set up the refcount */
	atomic_set(&entry->refcount, 1);

	/* Initialize the waitqueue */
	init_waitqueue_head(&entry->waitq);

	mutex_init(&entry->lock);

	entry->data = NULL;
}

void *data_entry_get_data(struct data_entry *entry) {
	void *ret;
	int null_count;

	mutex_lock(&entry->lock);

	ret = entry->data;

	null_count = 0;
	while (ret == NULL) {
		/* Wait for data */
		mutex_unlock(&entry->lock);
		wait_event_interruptible(entry->waitq, entry->data != NULL);
		mutex_lock(&entry->lock);

		ret = entry->data;

		if (ret == NULL) {
			printk("REPLAYFS %s, %d: WOAH, ret is null?\n", __FILE__, __LINE__);
			null_count++;

			if (null_count > 20) {
				BUG();
			}
		}
	}

	mutex_unlock(&entry->lock);

	return ret;
}

int data_entry_put_data(struct data_entry *entry, void *data, size_t size) {
	void *data_save;

	data_save = kmalloc(size, GFP_KERNEL);
	if (data_save == NULL) {
		BUG();
		return -1;
	}

	mutex_lock(&entry->lock);

	memcpy(data_save, data, size);
	entry->data = data_save;

	wake_up_interruptible(&entry->waitq);

	mutex_unlock(&entry->lock);

	return 1;
}

static struct data_entry *data_entry_alloc(void) {
	return kmalloc(sizeof(struct data_entry), GFP_KERNEL);
}

static void data_entry_free(struct data_entry *entry) {
	if (entry->data != NULL) {
		kfree(entry->data);
	}
	kfree(entry);
}

static unsigned int hash(unsigned int a) {
	a = (a+0x7ed55d16) + (a<<12);
	a = (a^0xc761c23c) ^ (a>>19);
	a = (a+0x165667b1) + (a<<5);
	a = (a+0xd3a2646c) ^ (a<<9);
	a = (a+0xfd7046c5) + (a<<3);
	a = (a^0xb55a4f09) ^ (a>>16);
	return a;
}

static inline unsigned int desc_hash(struct data_entry_desc *desc) {
	return hash(desc->unique_id);
}

static int desc_cmp(struct data_entry_desc *desc1,
		struct data_entry_desc *desc2) {
	return desc1->unique_id != desc2->unique_id;
}

static void data_entry_destroy(struct data_entry *entry) {
	BUG_ON(atomic_read(&entry->refcount) != 0);

	data_entry_free(entry);
}

static inline void lock_table(struct data_entry_desc *desc) {
	unsigned int hash;
	unsigned int mutex_num;

	hash = desc_hash(desc);
	mutex_num = hash % MUTEX_TABLE_SIZE;

	mutex_lock(&mutex_table[mutex_num]);
}

static inline void unlock_table(struct data_entry_desc *desc) {
	unsigned int hash;
	unsigned int mutex_num;

	hash = desc_hash(desc);
	mutex_num = hash % MUTEX_TABLE_SIZE;

	mutex_unlock(&mutex_table[mutex_num]);
}

static inline int get_entry_num(struct data_entry_desc *desc) {
	unsigned int hash;
	unsigned int entry_num;

	hash = desc_hash(desc);
	entry_num = hash % ENTRY_TABLE_SIZE;

	return entry_num;
}

static inline struct data_entry *__data_entry_get_internal(
		struct data_entry_desc *desc) {
	struct data_entry *ret;

	unsigned int entry_num;

	entry_num = get_entry_num(desc);

	/* Check to see if the entry is present */
	ret = table[entry_num];

	if (ret != NULL && desc_cmp(desc, &ret->desc)) {
		BUG();
	}

	return ret;
}


