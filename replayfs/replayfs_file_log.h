#ifndef __REPLAYFS_FILE_LOG_H__
#define __REPLAYFS_FILE_LOG_H__


#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>

#include <asm/atomic.h>

#include "replayfs_pagealloc.h"
#include "replayfs_perftimer.h"

#define FILE_LOG_MEMCHK

#define REPLAYFS_FILE_LOG_CACHE_SIZE (1<<12)

#define REPLAYFS_CURRENT_VERSION 0xFFFFFFFFFFFFFFFFULL

#define ENTRIES_PER_PAGE (PAGE_SIZE / sizeof(struct replayfs_file_log_entry))

#define REPLAYFS_ENTRY_LOG_DATA  0xFFFFFFFFFFFFFFFFULL

/* 
 * NOTE: Aligned to 16 bytes for simplicity (same as replayfs unique id) If this
 * changes, the read and write functions related to adding mods must be fixed
 */
/* NOTE: Padded to 16 bytes... to remove modulus requirement */
struct replayfs_unique_id {
	loff_t log_num;
	loff_t sys_num;
} __attribute__ ((aligned (16)));

/* Padded to be a power of 2... for alignment padding magic */
struct replayfs_file_mod {
	loff_t offset;
	size_t size;
	char _reserved[4];
} __attribute__ ((aligned (16)));

/* NOTE: logs are uniquely identified by ino_t's */
/* Constant size component of entry */
struct replayfs_file_log_entry {
	/* 
	 * Specifies replay or non-replay operation
	 *   If non-replay - REPLAYFS_ENTRY_LOG_DATA
	 *   Else - unique_id of the replaying thread
	 */
	loff_t type;

	/* 
	 * If the data is provided from a replay process, this represents the syscall
	 * number that the data came from
	 */
	loff_t sysnum;

	/* File size, so we don't have to replay entire history... */
	loff_t file_size;

	/* Offset within the data segment of the file of the first mod */
	loff_t offset;

	/* When was this modification? */
	struct timespec mtime;

	/*
	 * Number of file modification structures placed in the data section
	 * associated with this entry
	 */
	int nmods;
} __attribute__ ((aligned (64)));

struct replayfs_file_log_meta {
	loff_t cur_data_offs;
	loff_t num_entries;
};

/* NOTE: Currently assumes only 1 process accesses the log at a time... */
/* /really/ need to fix concurrency */
struct replayfs_file_log {
	struct hlist_node list;
	struct list_head free_list;

	struct replayfs_unique_id id;

	struct mutex lock;

	atomic_t refs;

	/* Disk representation */
	page_alloc_t entry_alloc;
	page_alloc_t data_alloc;

	/* Our offset in the data_alloc section */
	loff_t cur_data_offs;

	/* Reference to the syscall cache */
	struct replayfs_syscall_cache *cache;

	struct replayfs_file_log_cache *log_cache;

	/* In-memory representation */
	loff_t num_entries;
};

struct replayfs_file_log_cache {
	struct mutex lock;

	struct list_head free_list;

	struct perftimer *read_cache_timer;
	struct perftimer *log_get_entry_timer;

	struct replayfs_syscall_cache *syscall_cache;

	/* Holds a record of all open logs */
	struct hlist_head cache[REPLAYFS_FILE_LOG_CACHE_SIZE];

#ifdef FILE_LOG_MEMCHK
	struct kmem_cache *file_log_cache;
	struct kmem_cache *range_set_cache;
#endif
};

/* Public interface */
/* Cache */
int replayfs_file_log_cache_init(struct replayfs_file_log_cache *cache,
		struct replayfs_syscall_cache *syscall_cache);
void replayfs_file_log_cache_destroy(struct replayfs_file_log_cache *cache);

struct replayfs_file_log *replayfs_file_log_cache_get(
		struct replayfs_file_log_cache *cache, struct replayfs_unique_id *id);

void replayfs_file_log_cache_put(
		struct replayfs_file_log_cache *cache, struct replayfs_file_log *log);

/* Log operations */
/* Should be for read-only consumption */
struct replayfs_file_log_entry *replayfs_file_log_get_entry(
		struct replayfs_file_log *log, loff_t entry_num);
void replayfs_file_log_put_entry(struct replayfs_file_log *log,
		struct replayfs_file_log_entry *entry, loff_t entry_num);

/* Used to start (and finish) adding a new entry */
void replayfs_file_log_add_next(struct replayfs_file_log *log);
void replayfs_file_log_next_done(struct replayfs_file_log *log, loff_t i_size);

/* When called between add_next and next_done returns the entry being added */
struct replayfs_file_log_entry *replayfs_file_log_get_current(
		struct replayfs_file_log *log);
void replayfs_file_log_put_current(struct replayfs_file_log_entry *entry,
		struct replayfs_file_log *log);

size_t replayfs_file_log_entry_add(struct replayfs_file_log_entry *entry,
		struct replayfs_file_log *log, const void *data, size_t size, loff_t pos);

size_t replayfs_file_log_entry_add_user(struct replayfs_file_log_entry *entry,
		struct replayfs_file_log *log, const void __user *data, size_t size, loff_t pos);

#define replayfs_file_log_size(X) ((X)->num_entries)

ssize_t replayfs_file_log_read_user(struct replayfs_file_log *log, loff_t version,
		char __user *buf, size_t len, loff_t *ppos);

ssize_t replayfs_file_log_read(struct replayfs_file_log *log, loff_t version,
		char *buf, size_t len, loff_t *ppos);

/* Log entry operations */
size_t replayfs_file_log_entry_get_data(struct replayfs_file_log_entry *entry,
		struct replayfs_file_log *log, int mod_num, void *data, loff_t size,
		loff_t offs);

/* User version (need user version to allow 1 copy per read) */
size_t replayfs_file_log_entry_get_data_user(struct replayfs_file_log_entry *entry,
		void __user *data, loff_t size, loff_t offs);

#define replayfs_file_log_entry_mtime(X) ((X)->mtime)

#endif

