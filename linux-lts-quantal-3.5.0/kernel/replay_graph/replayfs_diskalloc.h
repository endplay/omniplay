#ifndef __REPLAYFS_DISKALLOC_H
#define __REPLAYFS_DISKALLOC_H

#include <linux/kernel.h>
#include <linux/btree.h>
#include <linux/mutex.h>

#define REPLAYFS_DISK_FILE "/replay_cache/replaymap.disk"

#define PAGE_ALLOC_SIZE (1<<30)
#define PAGE_ALLOC_PAGES (PAGE_ALLOC_SIZE / PAGE_SIZE)

/* 
 * The actual extent, a large chunk of disk memory (to amortize seek times)
 */

/* The allocator */
struct replayfs_diskalloc {
	struct mutex lock;

	/* The data file! */
	struct file *filp;

	int last_free_page_word;

	/* FIXME */
	//struct list_head freed_extents;
	//struct list_head merge_extents;
};

int replayfs_diskalloc_init(struct replayfs_diskalloc *alloc);
void replayfs_diskalloc_destroy(struct replayfs_diskalloc *alloc);

struct page *replayfs_diskalloc_alloc_page(struct replayfs_diskalloc *alloc);
void replayfs_diskalloc_free_page(struct replayfs_diskalloc *alloc,
		struct page *page);
struct page *replayfs_diskalloc_get_page(struct replayfs_diskalloc *alloc, loff_t page);
void replayfs_diskalloc_sync_page(struct replayfs_diskalloc *alloc,
		struct page *page);
void replayfs_diskalloc_put_page(struct replayfs_diskalloc *alloc, struct page *page);

#endif

