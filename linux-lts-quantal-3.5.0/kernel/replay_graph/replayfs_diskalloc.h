#ifndef __REPLAYFS_DISKALLOC_H
#define __REPLAYFS_DISKALLOC_H

#include <linux/kernel.h>
#include <linux/btree.h>
#include <linux/mutex.h>
#include <linux/mm.h>

#define REPLAYFS_DISK_FILE "/replay_logdb/replaymap.disk"
/* 4MB extents */
#define EXTENT_SIZE (1 << 22)
/* The number of free'd bytes in an extent before its scheduled to merge */
#define EXTENT_FREE_SIZE (EXTENT_SIZE >> 1)

/* 256GB pagealloc? */
#define PAGE_ALLOC_SIZE (1LL<<33)
#define PAGE_ALLOC_PAGES (PAGE_ALLOC_SIZE / PAGE_SIZE)

#define WORDS_PER_PAGE (PAGE_SIZE/sizeof(unsigned int))
#define MAPPINGS_PER_PAGE (PAGE_SIZE * 8)
#define PAGE_MASK_SIZE_IN_PAGES ((loff_t)PAGE_ALLOC_PAGES / MAPPINGS_PER_PAGE)

/* The first page to be alloced by the diskalloc */
#define FIRST_PAGEALLOC_PAGE ((loff_t)PAGE_MASK_SIZE_IN_PAGES * PAGE_SIZE)

/* 
 * The actual extent, a large chunk of disk memory (to amortize seek times)
 */

/* Ugh... quick fix */
struct replayfs_syscache_id {
	loff_t unique_id : 48;
	loff_t pid : 16;
	loff_t sysnum : 64;
} __attribute__((aligned(16)));


struct replayfs_btree_key {
	loff_t offset;
	loff_t size;
};

struct replayfs_btree_value {
	struct replayfs_syscache_id id;

	/* ... I hate this field */
	size_t buff_offs;
};

struct replayfs_btree_meta {
	loff_t node_page;
	int height;

	/* FIXME: Yeah, its hacky... on the todo list */
	loff_t i_size;

	loff_t cache_tree_loc;

	struct replayfs_btree_key key;
	struct replayfs_btree_value val;
};

#define HEADER_SIZE 16

/* FIXME: The -1 is a hack... ugh */
#define NO_PAIRS (((PAGE_SIZE - HEADER_SIZE) / (sizeof(struct replayfs_btree_meta))))

struct meta_page {
	unsigned long header[HEADER_SIZE/sizeof(unsigned long)];

	struct replayfs_btree_meta meta[NO_PAIRS];
};

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

	struct page *meta_page;

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


/* Shouldn't be used externally... */
void __replayfs_diskalloc_page_dirty(struct page *page);

/* Page should be locked... */
/* Should be used externally... */
static inline void replayfs_diskalloc_page_dirty(struct page *page) {
	if (!PageDirty(page)) {
		__replayfs_diskalloc_page_dirty(page);
	}
}

int glbl_diskalloc_init(void);
void glbl_diskalloc_destroy(void);
struct replayfs_diskalloc *replayfs_diskalloc_create(struct file *filp);
struct replayfs_diskalloc *replayfs_diskalloc_init(struct file *filp);
void replayfs_diskalloc_destroy(struct replayfs_diskalloc *alloc);

/* Deal with btree metadata */
loff_t replayfs_diskalloc_alloc_meta(struct replayfs_diskalloc *alloc);
void replayfs_diskalloc_free_meta(struct replayfs_diskalloc *alloc,
		loff_t meta_loc);

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
int replayfs_diskalloc_page_is_alloced(struct replayfs_diskalloc *alloc,
		loff_t page);

#endif

