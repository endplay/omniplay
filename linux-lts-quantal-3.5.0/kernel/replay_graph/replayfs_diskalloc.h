#ifndef __REPLAYFS_DISKALLOC_H
#define __REPLAYFS_DISKALLOC_H

#include <linux/kernel.h>
#include <linux/btree.h>
#include <linux/mutex.h>
#include <linux/mm.h>

#define REPLAYFS_DISK_FILE "/replay_cache/replaymap.disk"
/* 4MB extents */
#define EXTENT_SIZE (1 << 22)
/* The number of free'd bytes in an extent before its scheduled to merge */
#define EXTENT_FREE_SIZE (EXTENT_SIZE >> 1)

/* 1GB pagealloc? */
#define PAGE_ALLOC_SIZE (1LL<<30)
#define PAGE_ALLOC_PAGES (PAGE_ALLOC_SIZE / PAGE_SIZE)

/* 
 * The actual extent, a large chunk of disk memory (to amortize seek times)
 */

/* The allocator */
struct replayfs_diskalloc {
	struct mutex lock;

	struct replayfs_extent *cur_extent;

	/* The data file! */
	struct file *filp;

	loff_t last_free_page_word;

	loff_t extent_pos;

	loff_t num_allocated_extents;

	struct list_head alloced_pages;
	struct list_head dirty_pages;

	/* For debugging (on deterministic test cases)... */
	int allocnum;

	atomic_t refcnt;
};

/* 
 * The actual extent, a large chunk of disk memory (to amortize seek times)
 */
struct replayfs_extent {
	atomic_t refcnt;

	/* The disk offset is the id */
	loff_t id;

	/* The position within the extent */
	loff_t pos;

	loff_t size;

	/* 
	 * When data is freed nfree is incremented to denote the number of free'd
	 * bytes
	 */
	loff_t nfree;

	struct replayfs_diskalloc *alloc;
};

struct replayfs_disk_alloc {
	struct replayfs_diskalloc *alloc;
	u32 offset;
	u32 size;
	loff_t extent;
};

static inline void replayfs_diskalloc_page_access(struct page *page) {
	SetPageReferenced(page);
}

/* Page should be locked... */
static inline void replayfs_diskalloc_page_dirty(struct page *page) {
	SetPageDirty(page);
}

int glbl_diskalloc_init(void);
struct replayfs_diskalloc *replayfs_diskalloc_create(struct file *filp);
struct replayfs_diskalloc *replayfs_diskalloc_init(struct file *filp);
void replayfs_diskalloc_destroy(struct replayfs_diskalloc *alloc);

/* 
 * Syncs all dirty pages in alloc to fs, must still fsync afterwards... for
 * on-disk consistency
 */
void replayfs_diskalloc_sync(struct replayfs_diskalloc *alloc);

struct replayfs_disk_alloc *replayfs_diskalloc_alloc(
		struct replayfs_diskalloc *alloc, int size);
void replayfs_diskalloc_free(struct replayfs_disk_alloc *alloc);

__must_check int replayfs_disk_alloc_write(struct replayfs_disk_alloc *alloc, void *data,
		size_t size, loff_t offset, int user);
__must_check int replayfs_disk_alloc_read(struct replayfs_disk_alloc *alloc, void *data,
		size_t size, loff_t offset, int user);
void replayfs_disk_alloc_put(struct replayfs_disk_alloc *alloc);

struct replayfs_disk_alloc *replayfs_disk_alloc_get(struct replayfs_diskalloc *alloc, loff_t pos);

static inline loff_t replayfs_disk_alloc_pos(struct replayfs_disk_alloc *alloc) {
	return alloc->extent + alloc->offset;
}

struct page *replayfs_diskalloc_alloc_page(struct replayfs_diskalloc *alloc);
void replayfs_diskalloc_free_page(struct replayfs_diskalloc *alloc,
		struct page *page);
void replayfs_diskalloc_free_page_noput(struct replayfs_diskalloc *alloc,
		struct page *page);
struct page *replayfs_diskalloc_get_page(struct replayfs_diskalloc *alloc, loff_t page);
void replayfs_diskalloc_sync_page(struct replayfs_diskalloc *alloc,
		struct page *page);
void replayfs_diskalloc_put_page(struct replayfs_diskalloc *alloc, struct page *page);

#endif

