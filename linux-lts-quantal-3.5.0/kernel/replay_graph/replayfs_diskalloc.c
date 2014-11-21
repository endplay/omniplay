#include "replayfs_diskalloc.h"

#include "replayfs_btree128.h"
#include "replayfs_syscall_cache.h"
#include "replay_data.h"

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/swap.h>
#include <linux/gfp.h>
#include <linux/file.h>
#include <linux/list.h>

#include "replayfs_kmap.h"
#include "replayfs_perftimer.h"

/*
#define REPLAYFS_DISKALLOC_DEBUG_ALLOCREF

#define REPLAYFS_DISKALLOC_DEBUG

#define REPLAYFS_DISKALLOC_RDWR_DEBUG

#define REPLAYFS_DISKALLOC_DEBUG_MIN

#define REPLAYFS_DISKALLOC_DEBUG_LOCK

#define REPLAYFS_DISKALLOC_DEBUG_CACHE

#define REPLAYFS_DISKALLOC_ALLOC_DEBUG

#define REPLAYFS_DISKALLOC_MONITOR_LISTS

#define REPLAYFS_DISKALLOC_STANDARD_CHECKS

#define REPLAYFS_DISKALLOC_NO_SYNCS
*/

#if defined(REPLAYFS_DISKALLOC_DEBUG) && !defined(REPLAYFS_DISKALLOC_DEBUG_MIN)
#  define REPLAYFS_DISKALLOC_DEBUG_MIN
#endif

DEFINE_MUTEX(glbl_allocnum_lock);
int glbl_allocnum = 0;

extern atomic_t diskalloc_kmallocs;
extern atomic_t disk_alloc_kmallocs;
extern atomic_t data_kmallocs;

struct perftimer *sync_timer;
struct perftimer *sync_write_timer;

struct perftimer *write_timer;

extern unsigned long replayfs_debug_page_index;

extern int replayfs_print_leaks;

extern int replayfs_diskalloc_debug;
extern int replayfs_diskalloc_debug_alloc;
extern int replayfs_diskalloc_debug_alloc_min;
extern int replayfs_diskalloc_debug_cache;
extern int replayfs_diskalloc_debug_full;
extern int replayfs_diskalloc_debug_allocref;
extern int replayfs_diskalloc_debug_lock;
#ifdef REPLAYFS_DISKALLOC_DEBUG_MIN
#define min_debugk(...) if(replayfs_diskalloc_debug) {printk(__VA_ARGS__);}
#else
#define min_debugk(...)
#endif

#ifdef REPLAYFS_DISKALLOC_DEBUG_LOCK
#define lock_debugk(...) if(replayfs_diskalloc_debug_lock) {printk(__VA_ARGS__);}
#else
#define lock_debugk(...)
#endif

#ifdef REPLAYFS_DISKALLOC_DEBUG_ALLOCREF
#define allocref_debugk(...) if(replayfs_diskalloc_debug_allocref) {printk(__VA_ARGS__);}
#define allocref_dump_stack() if(replayfs_diskalloc_debug_allocref) {dump_stack();}
#else
#define allocref_debugk(...)
#define allocref_dump_stack()
#endif

#ifdef REPLAYFS_DISKALLOC_RDWR_DEBUG
#define alloc_rdwr_debugk(...) if (replayfs_diskalloc_debug) {printk(__VA_ARGS__);}
#else
#define alloc_rdwr_debugk(...)
#endif

#ifdef REPLAYFS_DISKALLOC_DEBUG
#define debugk(...) if (replayfs_diskalloc_debug_full) {printk(__VA_ARGS__);}
#else
#define debugk(...)
#endif

#ifdef REPLAYFS_DISKALLOC_DEBUG_CACHE
#define cache_debugk(...) if (replayfs_diskalloc_debug_cache) {printk(__VA_ARGS__);}
#else
#define cache_debugk(...)
#endif

#ifdef REPLAYFS_DISKALLOC_ALLOC_DEBUG
#define alloc_min_debugk(...) if (replayfs_diskalloc_debug_alloc_min || replayfs_diskalloc_debug_alloc) {printk(__VA_ARGS__);}
#define alloc_debugk(...) if (replayfs_diskalloc_debug_alloc) {printk(__VA_ARGS__);}
#define alloc_dump_stack() if (replayfs_diskalloc_debug_alloc) {dump_stack();}
#else
#define alloc_min_debugk(...)
#define alloc_debugk(...)
#define alloc_dump_stack()
#endif

void replayfs_diskalloc_sync_page_internal(struct replayfs_diskalloc *alloc,
		struct page *page);

/* Unique key is inode.index */
//#define crappy_pagecache_key(X, Y) ((((u64)((X)->filp->f_dentry->d_inode->i_ino))<<32) | (u64)(Y))
static inline u64 crappy_pagecache_key(struct replayfs_diskalloc *alloc,
		unsigned long page) {
	u64 ret = 0;

	ret = alloc->filp->f_dentry->d_inode->i_ino;
	ret <<= 32;
	ret |= (u64)page;

	return ret;
}

atomic_t initd = {0};
atomic_t init_done = {0};
struct replayfs_diskalloc *replayfs_alloc;
struct replayfs_btree128_head filemap_meta_tree;

/* FIXME: #define somewhere? */
static struct replayfs_btree128_key write_data_key = {0, 1};

struct replayfs_btree128_head write_data_tree;

struct replayfs_syscall_cache syscache;
static int crappy_pagecache_size;
static int crappy_pagecache_allocated_pages;
static struct btree_head64 crappy_pagecache;
static struct list_head crappy_pagecache_lru_list;
static struct list_head crappy_pagecache_free_list;
static struct mutex crappy_pagecache_lock;
atomic_t diskalloc_num_blocks = {0};

atomic_t open_in_replay = {0};

static struct timespec last_print_time;
#define CRAPPY_PAGECACHE_MAX_SIZE 0x1000

void replayfs_diskalloc_read_page_location(struct replayfs_diskalloc *alloc,
		void *buffer, loff_t page);
void replayfs_diskalloc_write_page_location(struct replayfs_diskalloc *alloc,
		void *buffer, loff_t page);

static struct replayfs_diskalloc *alloc_get(struct replayfs_diskalloc *alloc);
static void alloc_put(struct replayfs_diskalloc *alloc);

static struct replayfs_extent *create_extent_nolock(struct replayfs_diskalloc *alloc,
		int shared);
static struct replayfs_extent *create_extent(struct replayfs_diskalloc *alloc,
		int shared);
static struct replayfs_extent *extent_read_from_disk(
		struct replayfs_diskalloc *alloc, loff_t extent);

static struct replayfs_diskalloc *replayfs_diskalloc_create_with_extent(struct file *filp);

static void extent_put(struct replayfs_extent *extent);

struct page_data {
	struct list_head lru;
	struct list_head free;

	struct list_head alloc_list;
	struct list_head dirty_list;

	int referenced;
	int count;
	struct page *page;
	struct replayfs_diskalloc *alloc;
};

static int alloc_free_page_nolock(struct page_data *data,
		struct replayfs_diskalloc *alloc);

struct diskalloc_raw {
	__le64 active_extent;
	__le64 free_list_start;
};

struct extent_raw {
	__le64 pos;
	__le64 size;
	__le64 nfree;
};

struct alloc_header {
	__le64 size;
	/* ??? */
	__le32 valid;
	/* If this allocation took more than 1 chunk */
	__le64 next;

	/* We need backptrs if we copy data around during free */
	__le64 bkptr;
};

static struct page *alloc_get_page_nocheck(struct replayfs_diskalloc *alloc,
		loff_t offset);
static void alloc_put_page_nocheck(struct replayfs_diskalloc *alloc,
		struct page *page);

#ifdef REPLAYFS_DISKALLOC_STANDARD_CHECKS
void check_page_allocated(struct replayfs_diskalloc *alloc, loff_t index) {
	/* The word offset of this bit */
	/* NOTE PAGE_SIZE / PAGE_SIZE is 1... */
	struct page *page = alloc_get_page_nocheck(alloc, index/(8));
	loff_t word = index / (sizeof(unsigned long) * 8);
	unsigned int *used_page_map = replayfs_kmap(page);
	int shift = (sizeof(unsigned long) * 8) - 1;
	word %= (PAGE_SIZE/sizeof(unsigned long));

	alloc_min_debugk("%s %d: Checking page with index %lld, index %lu, word %lld, offs %d, used_page_map[word] 0x%08X\n", 
			__func__, __LINE__, index, page->index, word,
			(1<<(index&shift)), used_page_map[word]);

	/* K, now that we have the page, mark the offset as read */
	BUG_ON((used_page_map[word] & (1 << (index & shift))) == 0);

	replayfs_kunmap(page);
	alloc_put_page_nocheck(alloc, page);
}
#else
#define check_page_allocated(...)
#endif

#ifdef REPLAYFS_DISKALLOC_MONITOR_LISTS
static struct btree_head32 free_list_verify_tree;
static struct btree_head64 lru_list_verify_tree;

static void init_monitor_lists(void) {
	btree_init32(&free_list_verify_tree);
	btree_init64(&lru_list_verify_tree);
}

static void check_not_in_lru(struct page_data *data) {
	u64 key;
	struct page_data *verify_data = NULL;

	key = crappy_pagecache_key(data->alloc, data->page->index);

	cache_debugk("%s %d: Looking up key of 0x%016llX\n", __func__, __LINE__, key);
	verify_data = btree_lookup64(&lru_list_verify_tree, key);
	if (verify_data != NULL || IS_ERR(verify_data)) {
		printk("%s %d: Lookup returns unexpected result for key of 0x%016llX, verify_data is %p\n",
				__func__, __LINE__, key, verify_data);
		BUG();
	}
}

static void add_to_lru_list(struct page_data *data, struct list_head *head,
		struct list_head *list, struct btree_head64 *verify_tree) {
	u64 key;
	struct page_data *verify_data = NULL;

	key = crappy_pagecache_key(data->alloc, data->page->index);

	cache_debugk("%s %d: Looking up key of 0x%016llX\n", __func__, __LINE__, key);
	verify_data = btree_lookup64(verify_tree, key);
	if (verify_data != NULL || IS_ERR(verify_data)) {
		printk("%s %d: Lookup returns unexpected result for key of 0x%016llX, verify_data is %p\n",
				__func__, __LINE__, key, verify_data);
		BUG();
	}

	cache_debugk("%s %d: Inserting key of 0x%016llX\n", __func__, __LINE__, key);
	btree_insert64(verify_tree, key, data, GFP_KERNEL);
	list_add(head, list);
}

static void add_to_free_list(struct page_data *data, struct list_head *head,
		struct list_head *list, struct btree_head32 *verify_tree) {
	u32 key;
	struct page_data *verify_data = NULL;

	key = (u32)data;

	verify_data = btree_lookup32(verify_tree, key);
	BUG_ON(verify_data != NULL || IS_ERR(verify_data));

	/* If this is on the free list it cannot also be on the lru list */
	/*
	if (verify_tree == &free_list_verify_tree) {
		verify_data = btree_lookup32(&lru_list_verify_tree, key);
		BUG_ON(verify_data != NULL || IS_ERR(verify_data));
	}
	*/

	btree_insert32(verify_tree, key, data, GFP_KERNEL);
	list_add(head, list);
}

static void remove_from_lru_list(struct page_data *data, struct list_head *head,
		struct list_head *list, struct btree_head64 *verify_tree) {
	u64 key;
	struct page_data *verify_data = NULL;

	key = crappy_pagecache_key(data->alloc, data->page->index);

	verify_data = btree_lookup64(verify_tree, key);
	BUG_ON(verify_data == NULL || IS_ERR(verify_data));

	list_del(head);
	INIT_LIST_HEAD(head);

	cache_debugk("%s %d: Deleting key of 0x%016llX\n", __func__, __LINE__, key);
	btree_remove64(verify_tree, key);
}

static void remove_from_free_list(struct page_data *data, struct list_head *head,
		struct list_head *list, struct btree_head32 *verify_tree) {
	u32 key;
	struct page_data *verify_data = NULL;

	key = (u32)data;

	verify_data = btree_lookup32(verify_tree, key);
	BUG_ON(verify_data == NULL || IS_ERR(verify_data));

	list_del(head);
	INIT_LIST_HEAD(head);

	btree_remove32(verify_tree, key);
}
#else
#define init_monitor_lists()
#define add_to_free_list(_U, X, Y, _O) list_add(X, Y)
#define remove_from_free_list(_U, X, _P, _O) list_del(X)
#define add_to_lru_list(_U, X, Y, _O) list_add(X, Y)
#define remove_from_lru_list(_U, X, _P, _O) list_del(X)
#define check_not_in_lru(X)
#endif

void glbl_diskalloc_destroy(void) {
	/* If we've init'd, do a destroy */
	if (atomic_read(&initd)) {
		/* First sync */
		replayfs_diskalloc_sync(replayfs_alloc);
		replayfs_diskalloc_destroy(replayfs_alloc);
	}
}

int glbl_diskalloc_init(void) {
	int ret = 0;
	int val;

	/* Run the initialization once */
	//debugk("%s %d: Initing!!!! (akslekdj)\n", __func__, __LINE__);

	val = atomic_add_unless(&initd, 1, 1);

	if (val) {
		struct file *filp;
		struct page *page;
		struct replayfs_btree_meta *meta;

		mm_segment_t old_fs;

		loff_t pos;

		/* Make sure the filemap is ready */
		replayfs_filemap_glbl_init();

		write_timer = perftimer_create("vfs_write", "Diskalloc");
		sync_timer = perftimer_create("diskalloc_sync", "Diskalloc");
		sync_write_timer = perftimer_create("diskalloc_sync writebacks", "Diskalloc");

		last_print_time = CURRENT_TIME_SEC;

		/* Only does something if monitoring is turned on... */
		init_monitor_lists();

		crappy_pagecache_size = 0;
		crappy_pagecache_allocated_pages = 0;
		btree_init64(&crappy_pagecache);
		INIT_LIST_HEAD(&crappy_pagecache_lru_list);
		INIT_LIST_HEAD(&crappy_pagecache_free_list);
		mutex_init(&crappy_pagecache_lock);

		/* Memleak debugging stuffs */
		replayfs_kmap_init();
		replay_cache_init();

		old_fs = get_fs();
		set_fs(KERNEL_DS);
		atomic_set(&open_in_replay, 1);
		filp = filp_open(REPLAYFS_DISK_FILE, O_RDWR | O_LARGEFILE, 0777);
		atomic_set(&open_in_replay, 0);
		set_fs(old_fs);
		if (IS_ERR(filp)) {
			struct page *syscache_page;

			loff_t index;

			atomic_set(&open_in_replay, 1);
			filp = filp_open(REPLAYFS_DISK_FILE, O_RDWR | O_CREAT | O_LARGEFILE, 0777);
			atomic_set(&open_in_replay, 0);

			replayfs_alloc = replayfs_diskalloc_create_with_extent(filp);

			page = replayfs_diskalloc_alloc_page(replayfs_alloc);
			syscache_page = replayfs_diskalloc_alloc_page(replayfs_alloc);

			index = (loff_t)page->index * PAGE_SIZE;

			debugk("%s %d: page->index is %lu, index is %lld, FIRST_PAGEALLOC_PAGE is %lld\n", __func__,
					__LINE__, page->index, index, FIRST_PAGEALLOC_PAGE);

			BUG_ON(index != FIRST_PAGEALLOC_PAGE);
			meta = replayfs_kmap(page);
			// Blocks in use
			meta->i_size = 0;
			meta->cache_tree_loc = (loff_t)syscache_page->index * PAGE_SIZE;
			printk("Setting cache_tree_loc to %lld\n", meta->cache_tree_loc);
			pos = meta->cache_tree_loc;
			//SetPageDirty(page);
			replayfs_diskalloc_page_dirty(page);
			replayfs_kunmap(page);

			replayfs_diskalloc_put_page(replayfs_alloc, page);
			replayfs_diskalloc_put_page(replayfs_alloc, syscache_page);

			debugk("%s %d: Creating meta tree at %lld (tree is %p)\n", __func__,
					__LINE__, index, &filemap_meta_tree);
			replayfs_btree128_create(&filemap_meta_tree, replayfs_alloc, index);

			replayfs_syscache_init(&syscache, replayfs_alloc, pos, 1);

			/* FIXME: Put this in some library function or something... */
			{
				struct replayfs_btree128_value v;
				page = replayfs_diskalloc_alloc_page(replayfs_alloc);
				v.id = (loff_t)page->index * PAGE_SIZE;
				replayfs_btree128_create(&write_data_tree, replayfs_alloc, v.id);

				printk("Setting val->id to be %lld page->index: %lu\n", v.id, page->index);
				replayfs_btree128_insert(&filemap_meta_tree, &write_data_key, &v, GFP_NOFS);
			}

			replayfs_diskalloc_put_page(replayfs_alloc, page);
		} else {
			replayfs_alloc = replayfs_diskalloc_init(filp);
			page = replayfs_diskalloc_get_page(replayfs_alloc, FIRST_PAGEALLOC_PAGE);
			meta = replayfs_kmap(page);
			atomic_set(&diskalloc_num_blocks, meta->i_size);
			pos = meta->cache_tree_loc;
			replayfs_kunmap(page);
			replayfs_diskalloc_put_page(replayfs_alloc, page);

			debugk("%s %d: Initing meta tree at %lld\n", __func__, __LINE__,
					(loff_t)FIRST_PAGEALLOC_PAGE);
			replayfs_btree128_init(&filemap_meta_tree, replayfs_alloc,
					(loff_t)FIRST_PAGEALLOC_PAGE);

			printk("Initing with cache_tree_loc at %lld\n", pos);
			replayfs_syscache_init(&syscache, replayfs_alloc, pos, 0);

			/* FIXME: Put this in some library function or something... */
			{
				struct replayfs_btree128_value *val;
				struct page *page;

				val = replayfs_btree128_lookup(&filemap_meta_tree, &write_data_key, &page);

				printk("Got val->id of %lld (page idx of %lu\n", val->id, page->index);
				replayfs_btree128_init(&write_data_tree, replayfs_alloc, val->id);

				replayfs_diskalloc_put_page(replayfs_alloc, page);
			}
		}

		filp_close(filp, NULL);

		wmb();
		atomic_set(&init_done, 1);
	} else {
		while (!atomic_read(&init_done)) {
			rmb();
		}
	}

	return ret;
}

static int alloc_readpage(struct file *file, struct page *page,
		struct replayfs_diskalloc *alloc) {
	struct inode *inode;

	void *page_addr;

	loff_t page_num;

	inode = page->mapping->host;

	/* Which page should we read from? */
	page_num = (loff_t)page->index * PAGE_SIZE;

	/* If the page is part of the root inode... */
	/* Copy that memory to the page */
	//SetPageUptodate(page);
	page_addr = replayfs_kmap(page);
	if (page_addr) {
		/*
		printk("%s %d: Filling Page %lld\n", __func__, __LINE__,
				(loff_t)page->index*PAGE_SIZE);
		*/

		min_debugk("%s %d: Loading page %lu into %p\n", __func__, __LINE__, page->index,
				page);

		replayfs_diskalloc_read_page_location(alloc,
			page_addr, page_num);

		/*
		min_debugk("%s %d: Pageloc 0 contains %d\n", __func__, __LINE__,
				(int)((char *)page_addr)[0]);
				*/
	} else {
		BUG();
	}

	//SetPageMappedToDisk(page);

	/*
	if (PageLocked(page)) {
		unlock_page(page);
	}
	*/

	/* deallocate the page */
	replayfs_kunmap(page);

	SetPageUptodate(page);
	SetPageChecked(page);

	//debugk("%s %d: Returning success!\n", __func__, __LINE__);
	return 0;
}

int alloc_writepage(struct page *page,
		struct writeback_control *wbc, struct replayfs_diskalloc *alloc) {
	struct inode *inode;
	void *page_addr = replayfs_kmap(page);

	inode = page->mapping->host;

	/*
	printk("%s %d: Writing back page %lld\n", __func__, __LINE__, (loff_t)page->index *
			PAGE_SIZE);
	*/
	min_debugk("%s %d: Writing back page %lu from page %p\n", __func__, __LINE__,
			page->index, page);
	min_debugk("%s %d: Pageloc 0 contains %d\n", __func__, __LINE__,
			(int)((char *)page_addr)[0]);
	replayfs_diskalloc_write_page_location(alloc,
			page_addr, (loff_t)page->index * PAGE_SIZE);

	replayfs_kunmap(page);

	/* Should be handled in diskalloc_sync_page */
	//ClearPageDirty(page);

	return 0;
}

static inline void add_to_free(struct page_data *data) {
	add_to_free_list(data, &data->free, &crappy_pagecache_free_list,
			&free_list_verify_tree);
}

static inline void add_to_lru(struct page_data *data) {
	add_to_lru_list(data, &data->lru, &crappy_pagecache_lru_list,
			&lru_list_verify_tree);
}

static inline void remove_from_free(struct page_data *data) {
	remove_from_free_list(data, &data->free, &crappy_pagecache_free_list,
			&free_list_verify_tree);
}

static inline void remove_from_lru(struct page_data *data) {
	remove_from_lru_list(data, &data->lru, &crappy_pagecache_lru_list,
			&lru_list_verify_tree);
}

static void alloc_free_page_internal(struct page_data *data, struct replayfs_diskalloc *alloc) {
	if (PageDirty(data->page)) {
		allocref_debugk("%s %d: About to write page %lu with alloc %p, filp %p\n", __func__,
				__LINE__, data->page->index, data->alloc, data->alloc->filp);
		replayfs_diskalloc_sync_page_internal(data->alloc, data->page);
	}

	/* Count should be 1... */
	/*
	cache_debugk("%s %d: Re-incing page %p to count of %d\n", __func__, __LINE__,
			page, data->count);
	cache_debugk("%s %d: Freeing page with count %d\n", __func__, __LINE__,
			data->count);
			*/

	cache_debugk("%s %d: Freeing page %lu\n", __func__, __LINE__,
			data->page->index);

	/* 
	 * NOTE: We have to take this page off of the crappy pagecache list only
	 * after its count has been dec'd for the last time... otherwise it may be
	 * allocated (and duplicated) twice
	 */
	btree_remove64(&crappy_pagecache,
			crappy_pagecache_key(data->alloc, data->page->index));

	/* I don't trust this... we're going to do some other stuffs */
	//__free_page(page);

	/* Recycle cached pages */
	//printk("%s %d: Adding list for page %p\n", __func__, __LINE__, page);
	BUG_ON(!mutex_is_locked(&crappy_pagecache_lock));
	add_to_free(data);

	/* Remove the element from the alloc list */
	check_not_in_lru(data);
	cache_debugk("%s %d: Removing {%lu, %lu} from alloc_list\n", __func__,
			__LINE__, data->page->index, data->alloc->filp->f_dentry->d_inode->i_ino);
	list_del_init(&data->alloc_list);

	allocref_debugk("%s %d: About to put data->alloc %p\n", __func__, __LINE__,
			data->alloc);
	alloc_put(data->alloc);
}

static void delete_from_cache(struct page_data *data,
		struct replayfs_diskalloc *alloc) {
	if (PageDirty(data->page)) {
		replayfs_diskalloc_sync_page_internal(alloc, data->page);
	}

	crappy_pagecache_size--;

	cache_debugk("%s %d: Removing page %p from lru with key of {%lu, %lu}, ({%lu, %d})\n",
			__func__, __LINE__, data->page, data->page->index,
			data->alloc->filp->f_dentry->d_inode->i_ino, data->page->index,
			data->alloc->allocnum);
	remove_from_lru(data);
	INIT_LIST_HEAD(&data->lru);

	alloc_free_page_nolock(data, alloc);
}

static void alloc_evict_page(struct replayfs_diskalloc *alloc) {
	struct page_data *data;
	struct page_data *_t;
	struct page_data *out = NULL;

	/* FIXME: Start from last position... */
	BUG_ON(!mutex_is_locked(&crappy_pagecache_lock));
	list_for_each_entry_safe(data, _t, &crappy_pagecache_lru_list, lru) {
		/* Move to the tail, to keep the lru order correct for the next scan */
		//list_move_tail(&data->lru, &crappy_pagecache_lru_list);
		debugk("%s %d: Scanning entry %p\n", __func__, __LINE__, data);
		list_del(&data->lru);
		list_add_tail(&data->lru, &crappy_pagecache_lru_list);
		if (data->referenced) {
			data->referenced = 0;
		} else {
			out = data;
			break;
		}
	}

	if (out != NULL) {
		cache_debugk("%s %d: Evicting page %lu\n", __func__, __LINE__, out->page->index);
		delete_from_cache(out, alloc);
	}
}

static atomic_t num_out = {0};
static struct page_data *alloc_make_page(pgoff_t pg_offset, struct replayfs_diskalloc *alloc) {
	struct page_data *data;

	crappy_pagecache_size++;
#if 0
	if (crappy_pagecache_size % 4096 == 0) {
		printk("%s %d: Creating page #%d\n", __func__, __LINE__,
				crappy_pagecache_size);
		if (crappy_pagecache_size > 50000) {
			while (crappy_pagecache_size > 0x4000) {
				//cache_debugk("%s %d: Evicting page\n", __func__, __LINE__);
				BUG_ON(!mutex_is_locked(&crappy_pagecache_lock));
				/* Technically possible... if there are more pages in-use than in-cache */
				BUG_ON(list_empty(&crappy_pagecache_lru_list));
				alloc_evict_page(alloc);
			}
		}
	}
#endif
	/* Never evict... */
//#ifndef REPLAYFS_DISKALLOC_NO_SYNCS
	while (crappy_pagecache_size > CRAPPY_PAGECACHE_MAX_SIZE) {
		//cache_debugk("%s %d: Evicting page\n", __func__, __LINE__);
		BUG_ON(!mutex_is_locked(&crappy_pagecache_lock));
		/* Technically possible... if there are more pages in-use than in-cache */
		BUG_ON(list_empty(&crappy_pagecache_lru_list));
		alloc_evict_page(alloc);
	}
//#endif

	if (list_empty(&crappy_pagecache_free_list)) {
		crappy_pagecache_allocated_pages++;
		cache_debugk("%s %d: Alloc page\n", __func__, __LINE__);

		data = kmalloc(sizeof(struct page_data), GFP_KERNEL);
		BUG_ON(data == NULL);
		atomic_inc(&data_kmallocs);

		data->count = 1;
		data->referenced = 0;

		INIT_LIST_HEAD(&data->lru);
		INIT_LIST_HEAD(&data->free);
		INIT_LIST_HEAD(&data->dirty_list);

		data->page = alloc_page(GFP_KERNEL);
		BUG_ON(IS_ERR(data->page));
		BUG_ON(data->page == NULL);
		atomic_inc(&num_out);
#ifdef REPLAYFS_KEEP_MAPPED
		kmap(data->page);
#endif
	} else {
		BUG_ON(list_empty(&crappy_pagecache_free_list));
		BUG_ON(!mutex_is_locked(&crappy_pagecache_lock));
		data = list_first_entry(&crappy_pagecache_free_list, struct page_data, free);
		/*
		printk("%s %d: Got entry %p from free_list\n", __func__,
				__LINE__, data);
		printk("%s %d: Getting freed page %p (base count %d)\n", __func__,
				__LINE__, data->page, data->count);
		printk("%s %d: data->page->index %lu)\n", __func__,
				__LINE__, data->page->index);
				*/

		data->count = 1;

		//printk("%s %d - %p: Deleting list for page %p\n", __func__, __LINE__,
				//current, page);
		BUG_ON(!mutex_is_locked(&crappy_pagecache_lock));
		remove_from_free(data);
		/* FIXME: This doesnt seem right... */
		//printk("%s %d: initing list????\n", __func__, __LINE__);
		BUG_ON(PageDirty(data->page));
		BUG_ON(!list_empty(&data->dirty_list));
	}

	allocref_debugk("%s %d: About to get data->alloc %p\n", __func__, __LINE__,
			alloc);
	data->alloc = alloc_get(alloc);
	cache_debugk("%s %d: Alloced page %p with count of %d\n", __func__, __LINE__,
			data->page, data->count);
	/* Make sure we read in the data... */

	list_add(&data->alloc_list, &alloc->alloced_pages);

	data->page->private = (unsigned long)data;
	data->page->index = pg_offset;
	ClearPageUptodate(data->page);

	replayfs_diskalloc_page_access(data->page);

	cache_debugk("%s %d: Adding page %p to lru with key of {%lu, %lu}, ({%lu, %d}) output_key 0x%016llX\n",
			__func__, __LINE__, data->page, data->page->index,
			data->alloc->filp->f_dentry->d_inode->i_ino, data->page->index,
			data->alloc->allocnum, crappy_pagecache_key(data->alloc, data->page->index));
	add_to_lru(data);

	btree_insert64(&crappy_pagecache, crappy_pagecache_key(data->alloc, pg_offset), data, GFP_KERNEL);

	return data;
}

static int alloc_free_page_nolock(struct page_data *data, struct replayfs_diskalloc *alloc) {
	if (replayfs_print_leaks && data->count > 7) {
		printk("%s %d: Warning it appears page %lu is leaking (count %d), doing stack dump\n",
				__func__, __LINE__, data->page->index, data->count);
		dump_stack();
	}

	data->count--;
	cache_debugk("%s %d - %p: Dec'd page %lu to count of %d\n", __func__,
			__LINE__, current, data->page->index, data->count);

	/*
	if(data->page->index == 4231) {
		dump_stack();
	}
	*/

	if (data->count == 0) {
		alloc_free_page_internal(data, alloc);

		return 1;
	}

	return 0;
}

/*
static int alloc_free_page(struct page_data *data, struct replayfs_diskalloc *alloc) {
	mutex_lock(&crappy_pagecache_lock);
	cache_debugk("%s %d - %p: About to dec page %lu to count of %d\n", __func__,
			__LINE__, current, data->page->index, data->count);
	data->count--;
	if (data->count == 0) {

		alloc_free_page_internal(data, alloc);

		return 1;
	}
	mutex_unlock(&crappy_pagecache_lock);

	return 0;
}
*/


static struct page *alloc_get_page(struct replayfs_diskalloc *alloc, loff_t offset) {
	if (offset < 0 || offset > PAGE_ALLOC_SIZE) {
		printk("%s %d: Passing invalid offset: %lld\n", __func__, __LINE__, offset);
		BUG();
	}
	check_page_allocated(alloc, offset>>PAGE_CACHE_SHIFT);
	return alloc_get_page_nocheck(alloc, offset);
}

static atomic_t gets = {0};
static atomic_t puts = {0};
static struct page *alloc_get_page_nocheck(struct replayfs_diskalloc *alloc, loff_t offset) {
	struct page_data *data;
	u64 key;

	//pgoff_t pg_offset = offset & ~(PAGE_SIZE-1);
	pgoff_t pg_offset = offset >> PAGE_CACHE_SHIFT;

	/*
	printk("%s %d: About to get page from alloc %p", __func__, __LINE__, alloc);
	printk(" alloc->filp: %p", alloc->filp);
	printk(" alloc->filp->f_dentry->d_inode: %p", alloc->filp->f_dentry->d_inode);
	printk(" ino: %lu\n", alloc->filp->f_dentry->d_inode->i_ino);
	*/
	key = crappy_pagecache_key(alloc, pg_offset);

	lock_debugk("%s %d - %p: About to lock %p\n", __func__, __LINE__, current, &crappy_pagecache_lock);
	mutex_lock(&crappy_pagecache_lock);
	lock_debugk("%s %d - %p: Locked %p\n", __func__, __LINE__, current, &crappy_pagecache_lock);
	data = btree_lookup64(&crappy_pagecache, key);

	if (data == NULL) {
		data = alloc_make_page(pg_offset, alloc);
	}

	cache_debugk("%s %d: Got page %lu\n", __func__, __LINE__, data->page->index);

	/* Refcnt the page before you use it! */
	data->count++;

	if (replayfs_print_leaks && data->count > 7) {
		printk("%s %d: Warning it appears page %lu is leaking (count %d), doing stack dump\n",
				__func__, __LINE__, data->page->index, data->count);
		dump_stack();
	}

	cache_debugk("%s %d: Inc'd page %p to count of %d\n", __func__, __LINE__,
			data->page, data->count);

	debugk("%s %d: Alloc: %p (%d) Loading Page: {%lu, %lu} offset %lld\n", __func__, __LINE__, 
			alloc, alloc->allocnum, data->page->index, data->alloc->filp->f_dentry->d_inode->i_ino, offset);

	if (!PageChecked(data->page) || !PageUptodate(data->page)) {
		alloc_readpage(NULL, data->page, data->alloc);
	}

	data->referenced = 1;

	lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current, &crappy_pagecache_lock);
	mutex_unlock(&crappy_pagecache_lock);

	//debugk("%s %d: Returning page %p\n", __func__, __LINE__, data->page);

	atomic_inc(&gets);

	if (replayfs_print_leaks) {
		struct timespec tv = CURRENT_TIME_SEC;
		if (tv.tv_sec - last_print_time.tv_sec > 30) {
			//u64 key;
			//struct page_data *btree_data;
			//printk("%s %d: Alloc leak check, currently out %d pages\n", __func__, __LINE__, atomic_read(&gets) - atomic_read(&puts));
			printk("%s %d: Alloc leak check, currently out %d pages\n", __func__,
					__LINE__, atomic_read(&num_out));
			last_print_time = tv;

			/*
			mutex_lock(&crappy_pagecache_lock);
			printk("%s %d: Now listing all alloc'ed pages!\n", __func__, __LINE__);
			btree_for_each_safe64(&crappy_pagecache, key, btree_data) {
				if ((btree_data->count > 1 && !list_empty(&btree_data->lru)) || 
						(btree_data->count >= 1 && list_empty(&btree_data->lru))) {
					printk("\tPage %lu is allocated (data %p, page addr %p)\n",
							btree_data->page->index, btree_data, btree_data->page);
				}
			}
			mutex_unlock(&crappy_pagecache_lock);
			*/
		}
	}

	if (data->page->index == replayfs_debug_page_index) {
		printk("%s %d: Have allocation for page %lu, dumping stack:\n", __func__,
				__LINE__, data->page->index);
		dump_stack();
	}

	replayfs_pagealloc_get(data->page);

	/* No locking this page! */
	//lock_page(page);

	//debugk("%s %d: Returning page %p\n", __func__, __LINE__, data->page);
	return data->page;
}

void __replayfs_diskalloc_page_dirty(struct page *page) {
	struct page_data *data = (void *)page->private;

	BUG_ON(data->page != page);
	
	mutex_lock(&crappy_pagecache_lock);

	if (!PageDirty(page)) {
		SetPageDirty(page);
		cache_debugk("%s %d: Adding data %p to dirty_list\n", __func__, __LINE__, data);
		BUG_ON(!list_empty(&data->dirty_list));
		list_add(&data->dirty_list, &data->alloc->dirty_pages);
	}

	mutex_unlock(&crappy_pagecache_lock);
}

void replayfs_diskalloc_sync_page(struct replayfs_diskalloc *alloc,
		struct page *page) {
	mutex_lock(&crappy_pagecache_lock);
	if (PageDirty(page)) {
		replayfs_diskalloc_sync_page_internal(alloc, page);
	}
	mutex_unlock(&crappy_pagecache_lock);
}

void replayfs_diskalloc_sync_page_internal(struct replayfs_diskalloc *alloc,
		struct page *page) {

	struct page_data *data = (void *)page->private;

	BUG_ON(!PageDirty(page));

	cache_debugk("%s %d: Writing back page %lld\n", __func__, __LINE__,
			(loff_t)page->index * PAGE_SIZE);
	alloc_writepage(page, NULL, alloc);
	ClearPageDirty(page);

	BUG_ON(!mutex_is_locked(&crappy_pagecache_lock));
	cache_debugk("%s %d: Syncing and deleting data %p from dirty_list\n", __func__, __LINE__, data);
	list_del_init(&data->dirty_list);
}

static void alloc_put_page(struct replayfs_diskalloc *alloc, struct page *page) {
	check_page_allocated(alloc, page->index);
	alloc_put_page_nocheck(alloc, page);
}

static void alloc_put_page_nocheck(struct replayfs_diskalloc *alloc, struct page *page) {
	struct page_data *data;

	replayfs_pagealloc_put(page);

	//if (PageDirty(page)) {
		/*
		printk("%s %d: Writing back page %lld\n", __func__, __LINE__,
				(loff_t)page->index * PAGE_SIZE);
		*/
		//alloc_writepage(page, NULL, alloc);
	//}

	if (PageLocked(page)) {
		unlock_page(page);
	}

	//debugk("%s %d: Page dirty status of %lu is %d\n", __func__, __LINE__, page->index, PageDirty(page));

	debugk("%s %d: Putting page %lu\n", __func__, __LINE__,
			page->index);

	lock_debugk("%s %d - %p: About to lock %p\n", __func__, __LINE__, current, &crappy_pagecache_lock);
	mutex_lock(&crappy_pagecache_lock);
	lock_debugk("%s %d - %p: Locked %p\n", __func__, __LINE__, current, &crappy_pagecache_lock);

	data = btree_lookup64(&crappy_pagecache,
			crappy_pagecache_key(alloc, page->index));

	if (data != NULL) {
		cache_debugk("%s %d: Got page %p\n", __func__, __LINE__, page);

		if (data->page->index == replayfs_debug_page_index) {
			printk("%s %d: Have allocation for page %lu, dumping stack:\n", __func__,
					__LINE__, data->page->index);
			dump_stack();
		}

		atomic_inc(&puts);
		/* OOps! */

		alloc_free_page_nolock(data, alloc);
	}

	lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current, &crappy_pagecache_lock);
	mutex_unlock(&crappy_pagecache_lock);
}

struct extent_metadata {
	loff_t pos;
};

static void load_extent_alloc_data(struct replayfs_diskalloc *alloc) {
	struct page *extent_page;

	struct extent_metadata *meta;

	extent_page = alloc_get_page_nocheck(alloc, PAGE_ALLOC_SIZE);

	meta = replayfs_kmap(extent_page);

	alloc->extent_pos = meta->pos;

	mark_page_accessed(extent_page);

	replayfs_kunmap(extent_page);

	alloc_put_page_nocheck(alloc, extent_page);
}

static void save_extent_alloc_data(struct replayfs_diskalloc *alloc) {
	struct page *extent_page;

	struct extent_metadata *meta;

	extent_page = alloc_get_page_nocheck(alloc, PAGE_ALLOC_SIZE);

	meta = replayfs_kmap(extent_page);

	meta->pos = alloc->extent_pos;

	mark_page_accessed(extent_page);
	debugk("%s %d; Setting page %lu dirity\n", __func__, __LINE__,
			extent_page->index);
	__set_page_dirty_nobuffers(extent_page);

	replayfs_kunmap(extent_page);

	alloc_put_page_nocheck(alloc, extent_page);
}

static int create_diskalloc(struct replayfs_diskalloc *alloc, struct file *filp,
		int do_extent) {
	int ret = 0;
	int i;

	/* Initialize the free page map */
	for (i = 0; i < PAGE_MASK_SIZE_IN_PAGES; i++) {
		struct page *page;
		unsigned long *words;

		page = alloc_get_page_nocheck(alloc, i/8);
		words = replayfs_kmap(page);

		words[i/(8*sizeof(unsigned long))] |= 1<<(i%(8*sizeof(unsigned long)));

		//mark_page_accessed(page);
		//SetPageDirty(page);
		replayfs_diskalloc_page_dirty(page);

		replayfs_kunmap(page);
		alloc_put_page_nocheck(alloc, page);
	}

	if (do_extent) {
		alloc->extent_pos = PAGE_ALLOC_SIZE + EXTENT_SIZE;
		save_extent_alloc_data(alloc);
	} else {
		alloc->extent_pos = -1;
	}
	return ret;
}

static int init_diskalloc(struct replayfs_diskalloc *alloc, struct file *filp,
		int do_extent) {
	int ret = 0;
 
	allocref_debugk("%s %d: Setting refcnt for alloc %p to 1\n", __func__,
			__LINE__, alloc);
	atomic_set(&alloc->refcnt, 1);

	ret = create_diskalloc(alloc, filp, do_extent);
	if (ret) {
		goto out;
	}

	alloc->last_free_page_word = 0;

out:
	return ret;
}

static int read_diskalloc(struct replayfs_diskalloc *alloc) {
	int ret = 0;

	/* 
	 * Not sure if I need to do anything here... probably initialize the 
	 *     lru lists n stuff
	 */

	allocref_debugk("%s %d: Setting refcnt for alloc %p to 1\n", __func__,
			__LINE__, alloc);
	atomic_set(&alloc->refcnt, 1);

	alloc->last_free_page_word = 0;

	load_extent_alloc_data(alloc);

	return ret;
}

static void do_init(struct replayfs_diskalloc *alloc, struct file *filp) {
	mutex_init(&alloc->lock);

	get_file(filp);
	alloc->filp = filp;

	alloc->cur_extent = NULL;

	alloc->meta_page = NULL;

	/* Gah... race.. */
#ifdef REPLAYFS_DISKALLOC_DEBUG
	mutex_lock(&glbl_allocnum_lock);
	alloc->allocnum = ++glbl_allocnum;
	mutex_unlock(&glbl_allocnum_lock);
#endif

	INIT_LIST_HEAD(&alloc->alloced_pages);
	INIT_LIST_HEAD(&alloc->dirty_pages);
}

static struct replayfs_diskalloc *replayfs_diskalloc_create_with_extent(struct file *filp) {
	int ret;
	struct replayfs_diskalloc *alloc;

	alloc = kmalloc(sizeof(struct replayfs_diskalloc), GFP_KERNEL);
	if (alloc == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	atomic_inc(&diskalloc_kmallocs);

	do_init(alloc, filp);

	ret = init_diskalloc(alloc, filp, 1);

	if (ret) {
		kfree(alloc);
		alloc = ERR_PTR(ret);
	}

	return alloc;
}

struct replayfs_diskalloc *replayfs_diskalloc_create(struct file *filp) {
	int ret;
	struct replayfs_diskalloc *alloc;

	alloc = kmalloc(sizeof(struct replayfs_diskalloc), GFP_KERNEL);
	if (alloc == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	atomic_inc(&diskalloc_kmallocs);

	do_init(alloc, filp);

	ret = init_diskalloc(alloc, filp, 0);

	if (ret) {
		kfree(alloc);
		alloc = ERR_PTR(ret);
	}

	return alloc;
}

struct replayfs_diskalloc *replayfs_diskalloc_init(struct file *filp) {
	int ret;
	struct replayfs_diskalloc *alloc;

	alloc = kmalloc(sizeof(struct replayfs_diskalloc), GFP_KERNEL);
	if (alloc == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	atomic_inc(&diskalloc_kmallocs);

	debugk("%s %d: Initing %p\n", __func__, __LINE__, &alloc->lock);
	do_init(alloc, filp);

	ret = read_diskalloc(alloc);

	if (ret) {
		kfree(alloc);
		alloc = ERR_PTR(ret);
	}

	return alloc;
}

static void alloc_put(struct replayfs_diskalloc *alloc) {
	allocref_debugk("%s %d: About to dec alloc %p to %d\n", __func__, __LINE__,
			alloc, atomic_read(&alloc->refcnt)-1);

	if (atomic_dec_and_test(&alloc->refcnt)) {
		allocref_debugk("%s %d: Putting alloc->filp %p\n", __func__, __LINE__, alloc->filp);
		allocref_dump_stack();

		fput(alloc->filp);

		mutex_destroy(&alloc->lock);

		kfree(alloc);
		allocref_debugk("%s %d: Done putting alloc\n", __func__, __LINE__);
	}
}

static struct replayfs_diskalloc *alloc_get(struct replayfs_diskalloc *alloc) {
	atomic_inc(&alloc->refcnt);
	allocref_debugk("%s %d: Inc'd alloc %p to %d\n", __func__, __LINE__,
			alloc, atomic_read(&alloc->refcnt));
	allocref_dump_stack();

	return alloc;
}

void replayfs_diskalloc_sync(struct replayfs_diskalloc *alloc) {
	struct page_data *data;
	struct page_data *_t;

	perftimer_start(sync_timer);

	mutex_lock(&crappy_pagecache_lock);

	/* Must be safe, as sync_page_internal will remove from list */
	list_for_each_entry_safe(data, _t, &alloc->dirty_pages, dirty_list) {
		cache_debugk("%s %d: Iterated over data %p on dirty_list\n", __func__, __LINE__, data);

		BUG_ON(data->alloc != alloc);
		BUG_ON(!PageDirty(data->page));

		alloc_debugk("%s %d: About to write page %lu with alloc %p, filp %p\n", __func__,
				__LINE__, data->page->index, data->alloc, data->alloc->filp);
		perftimer_start(sync_write_timer);
		replayfs_diskalloc_sync_page_internal(data->alloc, data->page);
		perftimer_stop(sync_write_timer);
	}

	mutex_unlock(&crappy_pagecache_lock);

	perftimer_stop(sync_timer);
}

void replayfs_diskalloc_destroy(struct replayfs_diskalloc *alloc) {
	allocref_debugk("%s %d: About to put alloc %p\n", __func__, __LINE__,
			alloc);

	debugk("%s %d: Doing destroy on alloc %p (%lu) (%d)\n", __func__, __LINE__, alloc,
			alloc->filp->f_dentry->d_inode->i_ino, alloc->allocnum);

	/* Flush/delete all of the pages in alloc */
#ifndef REPLAYFS_DISKALLOC_NO_SYNCS
	mutex_lock(&crappy_pagecache_lock);

	{
		struct page_data *data;
		struct page_data *_t;
		list_for_each_entry_safe(data, _t, &alloc->alloced_pages, alloc_list) {
			BUG_ON(data->alloc != alloc);
			if (data->count == 1) {
				debugk("%s %d: Deleting page %lu from alloc %d!\n", __func__, __LINE__,
						data->page->index, alloc->allocnum);
				delete_from_cache(data, alloc);
				list_del_init(&data->alloc_list);
			} else if (data->count == 0) {
				debugk("%s %d: Got data %p page %lu (%p) with count 0???\n", __func__,
						__LINE__, data, data->page->index, data->page);
			} else {
				printk("%s %d: Got data %p page %lu (%p) with count %d???\n", __func__,
						__LINE__, data, data->page->index, data->page, data->count);
				BUG();
			}
		}
	}

	mutex_unlock(&crappy_pagecache_lock);
#endif

	alloc_put(alloc);
}

static int page_can_fit(loff_t offs, int size) {
	offs %= PAGE_SIZE;

	return size + offs <= PAGE_SIZE;
}

static int extent_can_fit(struct replayfs_extent *ext, int size) {
	int extra_space = 0;

	if (ext == NULL) {
		return 0;
	}

	/* Header alignment takes up space... */
	if (!page_can_fit(ext->pos, sizeof(struct alloc_header))) {
		/* Align pos to page size */
		extra_space += PAGE_SIZE - (ext->pos % PAGE_SIZE);
	}

	return extra_space + sizeof(struct alloc_header) + size + ext->pos <=
		ext->size;
}

static int too_big_for_extent(int size) {
	return size > EXTENT_SIZE >> 1;
}

struct file *alloc_filp = NULL;
static struct replayfs_disk_alloc *replayfs_extent_alloc(
		struct replayfs_extent *extent, int size) {
	struct replayfs_disk_alloc *alloc;
	struct alloc_header *header;
	struct page *page;

	if (alloc_filp == NULL) {
		alloc_filp = extent->alloc->filp;
	}

	BUG_ON(alloc_filp != extent->alloc->filp);

	alloc = kmalloc(sizeof(struct replayfs_disk_alloc), GFP_NOFS);
	/* For now, shouldn't be here! */
	if (alloc == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	atomic_inc(&disk_alloc_kmallocs);

	/* Wohoo, this is where we actually allocate space in the extent! */
	alloc->alloc = extent->alloc;
	alloc->extent = extent->id;
	alloc->offset = extent->pos + sizeof(struct alloc_header);
	alloc->size = size;
	debugk("%s %d: Creating alloc with extent id %lld, size %d, offset %u\n", __func__, __LINE__,
			extent->id, size, alloc->offset);

	if (!page_can_fit(extent->pos, sizeof(struct alloc_header))) {
		/* Align pos to page size */
		extent->nfree += PAGE_SIZE - (extent->pos % PAGE_SIZE);
		extent->pos += PAGE_SIZE - (extent->pos % PAGE_SIZE);
	}

	/* Get the header page */
	page = alloc_get_page_nocheck(extent->alloc, extent->id + extent->pos);
	debugk("%s %d: Got page %lu\n", __func__, __LINE__, page->index);
	header = (void *)(((char *)replayfs_kmap(page)) + (extent->pos % PAGE_SIZE));
	header->size = cpu_to_le64(size);
	header->valid = cpu_to_le32(1);
	header->next = 0;

	mark_page_accessed(page);
	//SetPageDirty(page);
	replayfs_diskalloc_page_dirty(page);
	//__set_page_dirty_nobuffers(page);
	//TestSetPageWriteback(page);
	replayfs_kunmap(page);

	debugk("%s %d: Putting page %lu\n", __func__, __LINE__, page->index);
	alloc_put_page_nocheck(extent->alloc, page);

	extent->pos += size + sizeof(struct alloc_header);

	debugk("%s %d: returning alloc %p\n", __func__, __LINE__, alloc);
	return alloc;
}

static struct replayfs_disk_alloc *diskalloc_large(
		struct replayfs_diskalloc *alloc, int size) {
	/* Allocation too large for an extent, see how many extents we need */
	struct replayfs_disk_alloc *ret;
	struct replayfs_extent *ext = NULL;

	int nextents;
	int i;

	/* See how many extents we need */
	nextents = (sizeof(struct replayfs_disk_alloc) + size + (EXTENT_SIZE-1)) 
		/ EXTENT_SIZE;

	/* Poop, need to allocate them consecutively */
	for (i = 0; i < nextents; i++) {
		if (i == 0) {
			ext = create_extent_nolock(alloc, 0);
			BUG_ON(ext == NULL);
		} else {
			struct replayfs_extent *tmp;
			tmp = create_extent_nolock(alloc, 0);
			BUG_ON(tmp == NULL);
			extent_put(tmp);
		}
	}

	ret = replayfs_extent_alloc(ext, size);

	extent_put(ext);

	return ret;
}

struct replayfs_disk_alloc *replayfs_diskalloc_alloc(
		struct replayfs_diskalloc *alloc, int size) {
	struct replayfs_extent *ext;
	/* Need to choose the correct diskalloc pool */
	struct replayfs_disk_alloc *ret;

	mutex_lock(&alloc->lock);
	debugk("%s %d: Entering %s\n", __func__, __LINE__, __func__);
retry:
	/* Get the extent */
	ext = alloc->cur_extent;
	debugk("%s %d: Got ext %p\n", __func__, __LINE__, ext);

	/* Some size checks... */
	if (extent_can_fit(ext, size)) {
		debugk("%s %d: Allocing %d from %p\n", __func__, __LINE__, size, ext);
		ret = replayfs_extent_alloc(ext, size);
	} else {
		if (too_big_for_extent(size)) {
			debugk("%s %d: Large alloc of %d\n", __func__, __LINE__, size);
			ret = diskalloc_large(alloc, size);
		} else {
			/* First, mark the rest of this extent as free */
			/* TODO: */
			//extent_mark_rest_free(ext);
			extent_put(alloc->cur_extent);
			debugk("%s %d: Creating new extent\n", __func__, __LINE__);
			alloc->cur_extent = create_extent(alloc, 0);
			/* FIXME: I should free extents at some point? */
			goto retry;
		}
	}

	debugk("%s %d: Returning %p\n", __func__, __LINE__, ret);
	/* Alloc from that extent */
	mutex_unlock(&alloc->lock);
	return ret;
}

static struct replayfs_extent *get_extent(struct replayfs_diskalloc *alloc,
		loff_t extent) {
	struct replayfs_extent *ret;
	debugk("%s %d: calling btree_lookup with alloc %p, and extent %lld\n", __func__,
			__LINE__, alloc, extent);
	ret = extent_read_from_disk(alloc, extent);

	return ret;
}

static void add_to_freed_queue(struct replayfs_diskalloc *alloc,
		struct replayfs_extent *extent) {
	/* FIXME: Do something */
}

static int can_free(struct replayfs_diskalloc *alloc) {
	/* FIXME: Do something... */
	return 0;
}

static void free_extents(struct replayfs_diskalloc *alloc) {
	/* FIXME: There should be actual work here... */
}


static void mark_item_freed(struct replayfs_disk_alloc *alloc,
		struct replayfs_extent *extent) {
	/* Take the item, and mark it as freed... */
	struct page *page;
	struct alloc_header *header;
	page = alloc_get_page_nocheck(extent->alloc, extent->id + alloc->offset - 
			sizeof(struct alloc_header));
	header = replayfs_kmap(page);
	mark_page_accessed(page);
	//SetPageDirty(page);
	//__set_page_dirty_nobuffers(page);
	replayfs_diskalloc_page_dirty(page);
	//TestSetPageWriteback(page);
	header->valid = 0;

	replayfs_kunmap(page);

	alloc_put_page_nocheck(alloc->alloc, page);
}

void replayfs_diskalloc_free(struct replayfs_disk_alloc *alloc) {
	struct replayfs_extent *extent;

	/* For each allocated item */
	loff_t old_freed;
	loff_t new_freed;

	/* Mark the region as free'd */
	mutex_lock(&alloc->alloc->lock);
	extent = get_extent(alloc->alloc, alloc->extent);

	/* 
	 * If the free'd size is greater than the minimum for freeing add the extent
	 * to the to_free list 
	 */
	old_freed = extent->nfree;
	extent->nfree += alloc->size;
	new_freed = extent->nfree;
	mark_item_freed(alloc, extent);


	if (new_freed >= EXTENT_FREE_SIZE && old_freed < EXTENT_FREE_SIZE) {
		add_to_freed_queue(extent->alloc, extent);
	}

	/* If there are more than 1 extents to free (counting this one) do freeing */
	if (can_free(alloc->alloc)) {
		free_extents(alloc->alloc);
	}

	extent_put(extent);

	mutex_unlock(&alloc->alloc->lock);
}

__must_check int replayfs_disk_alloc_write(struct replayfs_disk_alloc *alloc, void *data,
		size_t size, loff_t offset, int user) {
	int ret = 0;
	loff_t ntowrite;
	loff_t nwritten;

	if (alloc_filp == NULL) {
		alloc_filp = alloc->alloc->filp;
	}

	if ((alloc_filp != alloc->alloc->filp)) {
		printk("%s %d: alloc_filp is %p, alloc->alloc->filp is %p!\n", __func__,
				__LINE__, alloc_filp, alloc->alloc->filp);
		BUG();
	}

	nwritten = 0;
	ntowrite = size;
	/* For each page of the write */
	while (ntowrite > 0) {
		struct page *page;

		char *page_addr;

		int page_offs;
		int navailable;

		loff_t total_offs = alloc->offset + offset + nwritten;
		loff_t page_loc;

		/* The number we can read is the page size - the offset within the page */
		page_offs = total_offs % PAGE_SIZE;
		navailable = PAGE_SIZE - page_offs;

		if (navailable > ntowrite) {
			navailable = ntowrite;
		}

		alloc_rdwr_debugk("%s %d: ------ alloc->offset is %u, alloc->extent is %lld\n", __func__,
				__LINE__, alloc->offset, alloc->extent);
		/* Get the actual page */
		page_loc = alloc->extent + offset + (loff_t)alloc->offset + (loff_t)nwritten;
		debugk("%s %d: Requesting page at %lld (%lld)\n", __func__, __LINE__,
				page_loc, page_loc >> PAGE_CACHE_SHIFT);
		page = alloc_get_page_nocheck(alloc->alloc, page_loc);

		if (page == NULL) {
			BUG();
		}

		page_addr = replayfs_kmap(page);

		alloc_rdwr_debugk("%s %d: page (%lu) page_addr is %p page_offs is %d\n", __func__, __LINE__,
				page->index, page_addr, page_offs);
		alloc_rdwr_debugk("%s %d: navailable is %d, data is %p, nwritten is %lld\n", __func__,
				__LINE__, navailable, data, nwritten);

		//if (nwritten == 0) {
			alloc_rdwr_debugk("%s %d: Writing first char %d (page %lu, page_offs %d, nwritten %lld)\n", __func__, __LINE__,
					(int)((char *)data)[0], page->index, page_offs, nwritten);
		//}

		/* Copy the data into the page */
		alloc_rdwr_debugk("%s %d: Before page[0] is %d\n", __func__, __LINE__,
				(int)((char *)page_addr)[0]);
		if (!user) {
			memcpy(page_addr + page_offs, ((char *)data) + nwritten, navailable);
		} else {
			if (copy_from_user(page_addr + page_offs, ((char *)data) + nwritten,
					navailable)) { 
				ret = -EFAULT;
				ntowrite = 0;
			}
		}
		alloc_rdwr_debugk("%s %d: Before page[0] is %d\n", __func__, __LINE__,
				(int)((char *)page_addr)[0]);

		/* Mark page dirty */
		//mark_page_accessed(page);
		//SetPageDirty(page);
		//__set_page_dirty_nobuffers(page);
		replayfs_diskalloc_page_dirty(page);
		//TestSetPageWriteback(page);
		ntowrite -= navailable;
		nwritten += navailable;

		replayfs_kunmap(page);

		alloc_put_page_nocheck(alloc->alloc, page);
	}

	return ret;
}

__must_check int replayfs_disk_alloc_read(struct replayfs_disk_alloc *alloc, void *data,
		size_t size, loff_t offset, int user) {
	loff_t ntoread;
	loff_t nread;

	int ret = 0;

	if (alloc_filp == NULL) {
		alloc_filp = alloc->alloc->filp;
	}

	if ((alloc_filp != alloc->alloc->filp)) {
		printk("%s %d: alloc_filp is %p, alloc->alloc->filp is %p!\n", __func__,
				__LINE__, alloc_filp, alloc->alloc->filp);
		BUG();
	}

	nread = 0;
	ntoread = size;
	/* For each page of the write */
	while (ntoread > 0) {
		struct page *page;

		char *page_addr;

		int page_offs;
		int navailable;
		loff_t total_offs = alloc->offset + offset + nread;
		loff_t page_loc;

		/* The number we can read is the page size - the offset within the page */
		page_offs = total_offs % PAGE_SIZE;
		navailable = PAGE_SIZE - page_offs;

		if (navailable > ntoread) {
			navailable = ntoread;
		}

		/* Get the actual page */
		alloc_rdwr_debugk("%s %d: ------ alloc->offset is %u, alloc->extent is %lld\n", __func__,
				__LINE__, alloc->offset, alloc->extent);
		page_loc = alloc->extent + offset + (loff_t)alloc->offset + (loff_t)nread;
		debugk("%s %d: Requesting page at %lld (%lld)\n", __func__, __LINE__,
				page_loc, page_loc >> PAGE_CACHE_SHIFT);
		page = alloc_get_page_nocheck(alloc->alloc, page_loc);

		/* Copy the data from the page */
		page_addr = replayfs_kmap(page);
		alloc_rdwr_debugk("%s %d: data is %p nread is %lld, page (%lu) page_addr is %p, page_offs is %d, navailable is %d\n",
				__func__, __LINE__, data, nread, page->index, page_addr, page_offs, navailable);
		if (!user) {
			memcpy(((char *)data) + nread, page_addr + page_offs, navailable);
		} else {
			if (copy_to_user(((char *)data) + nread, page_addr + page_offs,
						navailable)) {
				ret = -EFAULT;
				ntoread = 0;
			}
		}

		alloc_rdwr_debugk("%s %d: page[0] is %d\n", __func__, __LINE__,
				(int)((char *)page_addr)[0]);
		if (nread == 0) {
			alloc_rdwr_debugk("%s %d: Read first char %d\n", __func__, __LINE__,
					(int)((char *)data)[0]);
		}

		mark_page_accessed(page);

		ntoread -= navailable;
		nread += navailable;

		replayfs_kunmap(page);

		alloc_put_page_nocheck(alloc->alloc, page);
	}

	return ret;
}

struct replayfs_disk_alloc *replayfs_disk_alloc_get(
		struct replayfs_diskalloc *alloc, loff_t pos) {
	loff_t page_id;
	loff_t header_pos;
	int offset;
	struct alloc_header hdr;
	struct page *page;

	struct replayfs_disk_alloc *ret;

	ret = kmalloc(sizeof(struct replayfs_disk_alloc), GFP_NOFS);
	if (ret == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	atomic_inc(&disk_alloc_kmallocs);

	header_pos = pos - sizeof(struct alloc_header);

	/* Read the alloc_header out of the disk */
	page_id = header_pos & ~(PAGE_SIZE-1);
	offset = header_pos & (PAGE_SIZE-1);

	/* Get the page */
	page = alloc_get_page_nocheck(alloc, page_id);

	/* Get the address */
	memcpy(&hdr, replayfs_kmap(page)+offset, sizeof(struct alloc_header));

	ret->alloc = alloc;
	ret->offset = pos & (EXTENT_SIZE-1);
	ret->size = le64_to_cpu(hdr.size);
	ret->extent = pos & ~(EXTENT_SIZE-1);

	replayfs_kunmap(page);
	alloc_put_page_nocheck(alloc, page);

	return ret;
}

void replayfs_disk_alloc_put(struct replayfs_disk_alloc *alloc) {
	/* Free the disk_alloc? */
	kfree(alloc);
}

static struct replayfs_extent *replayfs_extent_create_disk(
		struct replayfs_diskalloc *alloc, loff_t extent) {
	struct replayfs_extent *ret;
	struct extent_raw *raw;
	struct page *page;
	loff_t write_pos;

	ret = kmalloc(sizeof(struct replayfs_extent), GFP_NOFS);
	atomic_inc(&disk_alloc_kmallocs);

	ret->id = extent;

	/* FIXME: GAHHHH! */
	//ret->shared = alloc->shared;
	ret->nfree = 0;
	ret->pos = 0;
	ret->size = EXTENT_SIZE;
	ret->alloc = alloc;

	atomic_set(&ret->refcnt, 1);

	/* FIXME: Should use page cache... */
	/* Create page for data... */
	page = alloc_get_page_nocheck(alloc, extent);

	/* Now, create the extent metadata page on disk */
	write_pos = extent;

	raw = replayfs_kmap(page);
	raw->nfree = cpu_to_le64(ret->nfree);
	raw->pos = cpu_to_le64(ret->pos);

	mark_page_accessed(page);
	//SetPageDirty(page);
	//__set_page_dirty_nobuffers(page);
	replayfs_diskalloc_page_dirty(page);
	//TestSetPageWriteback(page);

	replayfs_kunmap(page);

	alloc_put_page_nocheck(alloc, page);

	return ret;
}

/*static*/ struct replayfs_extent *replayfs_extent_create(
		struct replayfs_diskalloc *alloc, loff_t extent) {
	struct replayfs_extent *ret;

	/*
	ret = extent_read_from_disk(alloc, extent);
	if (ret == NULL) {
	*/
		ret = replayfs_extent_create_disk(alloc, extent);
	//}

	return ret;
}

static void extent_write_to_disk(struct replayfs_extent *extent) {
	struct extent_raw raw;
	struct replayfs_disk_alloc alloc;

	raw.pos = cpu_to_le64(extent->pos);
	raw.size = cpu_to_le64(extent->size);
	raw.nfree = cpu_to_le64(extent->nfree);

	alloc.alloc = extent->alloc;
	alloc.offset = 0;
	alloc.size = 0;
	alloc.extent = extent->id;

	if (replayfs_disk_alloc_write(&alloc, &raw, sizeof(struct extent_raw), 0, 0)) {
		BUG();
	}
}

static struct replayfs_extent *extent_read_from_disk(
		struct replayfs_diskalloc *alloc, loff_t extent) {
	struct replayfs_extent *ret;
	struct extent_raw *raw;
	struct page *page;

	ret = kmalloc(sizeof(struct replayfs_extent), GFP_NOFS);
	if (ret == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	atomic_inc(&disk_alloc_kmallocs);

	/* TODO: left off here */
	page = alloc_get_page_nocheck(alloc, extent);
	raw = replayfs_kmap(page);

	ret->id = extent;
	ret->alloc = alloc;
	ret->pos = le64_to_cpu(raw->pos);
	ret->size = le64_to_cpu(raw->size);
	ret->nfree = le64_to_cpu(raw->nfree);

	replayfs_kunmap(page);

	alloc_put_page_nocheck(alloc, page);

	return ret;
}

static struct replayfs_extent *create_extent_nolock(struct replayfs_diskalloc *alloc,
		int shared) {
	struct replayfs_extent *ret;

	loff_t pos;

	/* Alloate the extent */
	ret = kmalloc(sizeof(struct replayfs_extent), GFP_NOFS);
	if (ret == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	atomic_inc(&disk_alloc_kmallocs);

	/* Get the next chunk from the alloc */
	pos = alloc->extent_pos;
	alloc->extent_pos += EXTENT_SIZE;
	atomic_add((EXTENT_SIZE+PAGE_SIZE-1)/PAGE_SIZE, &diskalloc_num_blocks);
	save_extent_alloc_data(alloc);

	/* 
	 * Now, we have the extents position, fill out its data then save it to disk
	 */
	atomic_set(&ret->refcnt, 1);

	ret->id = pos;
	/* The first page is reserved for extent data */
	ret->pos = PAGE_SIZE;
	ret->size = EXTENT_SIZE;
	ret->nfree = 0;

	ret->alloc = alloc;

	extent_write_to_disk(ret);

	atomic_inc(&ret->refcnt);

	return ret;
}

static struct replayfs_extent *create_extent(struct replayfs_diskalloc *alloc,
		int shared) {
	struct replayfs_extent *ret;

	loff_t pos;

	/* Alloate the extent */
	ret = kmalloc(sizeof(struct replayfs_extent), GFP_NOFS);
	if (ret == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	atomic_inc(&disk_alloc_kmallocs);

	/* Get the next chunk from the alloc */

	pos = alloc->extent_pos;
	alloc->extent_pos += EXTENT_SIZE;
	save_extent_alloc_data(alloc);

	/* 
	 * Now, we have the extents position, fill out its data then save it to disk
	 */
	atomic_set(&ret->refcnt, 1);

	ret->id = pos;
	/* The first page is reserved for extent data */
	ret->pos = PAGE_SIZE;
	ret->size = EXTENT_SIZE;
	ret->nfree = 0;

	ret->alloc = alloc;

	extent_write_to_disk(ret);

	atomic_inc(&ret->refcnt);

	return ret;
}

struct replayfs_extent *replayfs_extent_get(struct replayfs_diskalloc *alloc, loff_t extent) {
	struct replayfs_extent *ret;

	ret = extent_read_from_disk(alloc, extent);
	atomic_inc(&ret->refcnt);

	return ret;
}

static void extent_destroy(struct replayfs_extent *extent) {
	kfree(extent);
}

static void extent_put(struct replayfs_extent *extent) {
	/* Should already be syncted to disk... */
	if (extent != NULL) {
		if (atomic_dec_and_test(&extent->refcnt)) {
			extent_destroy(extent);
		}
	}
}

void replayfs_extent_put(struct replayfs_extent *extent) {
	extent_put(extent);
}

static loff_t first_free_page(struct replayfs_diskalloc *alloc) {
	loff_t ret = -1;
	struct page *page;
	int *used_page_map;
	int offset;

	/* Scan for the first free page */
	/* Get the page of our value */
	ret = (loff_t)alloc->last_free_page_word * 32;
	page = alloc_get_page(alloc, (loff_t)alloc->last_free_page_word * sizeof(unsigned int));
	alloc_debugk("%s %d: Checking page %lu\n", __func__, __LINE__, page->index);

	offset = alloc->last_free_page_word % (PAGE_SIZE / sizeof(unsigned int));
	alloc_debugk("%s %d: Offset %d\n", __func__, __LINE__, offset);

	used_page_map = replayfs_kmap(page);

	/* If the map isn't properly initalized, there is a bug */
	BUG_ON(page->index == 0 && used_page_map[0] == 0);

	while ((loff_t)page->index < PAGE_ALLOC_SIZE / PAGE_SIZE) {
		if (offset * sizeof(unsigned int) == PAGE_SIZE) {
			struct page *old_page = page;
			offset = 0;
			page = alloc_get_page(alloc, (loff_t)(old_page->index + 1) * PAGE_SIZE);
			alloc_debugk("%s %d: Got new page %lu\n", __func__, __LINE__, page->index);
			replayfs_kunmap(old_page);
			alloc_put_page(alloc, old_page);
			used_page_map = replayfs_kmap(page);
		}

		alloc_debugk("%s %d: offset is %d\n", __func__, __LINE__, offset);
		alloc_debugk("%s %d: checking %u for zeros\n", __func__, __LINE__,
				used_page_map[offset]);

		if (~used_page_map[offset] != 0) {

			/* __builtin_clz == find the offset of the msb(it) != 0 */
			ret = ((loff_t)page->index * PAGE_SIZE)*8 + offset*32 + (__builtin_ctz(~used_page_map[offset]));

			alloc_debugk("%s %d: Got ret of %lld, page->index of %lu, offset %d, used_map_page[offset] 0x%X, builtin_ctz returns %d\n", __func__, __LINE__,
					ret, page->index, offset, used_page_map[offset], __builtin_ctz(~used_page_map[offset]));

			alloc->last_free_page_word = ret / (8 * sizeof(unsigned int));

			alloc_debugk("%s %d: Got last_free_page_word: %lld\n", __func__, __LINE__,
					alloc->last_free_page_word);


			used_page_map[offset] |= 1 << (__builtin_ctz(~used_page_map[offset]));
			alloc_debugk("%s %d: Adjusted used_page_map[offset] to %u\n", __func__, __LINE__,
					used_page_map[offset]);
			mark_page_accessed(page);
			//SetPageDirty(page);
			replayfs_diskalloc_page_dirty(page);

			/* Sync the page immediately, This metadata page shouldn't get out of sync... */
#ifndef REPLAYFS_DISKALLOC_NO_SYNCS
			replayfs_diskalloc_sync_page(alloc, page);
#endif
			//__set_page_dirty_nobuffers(page);
			//TestSetPageWriteback(page);

			break;
		}

		offset++;
	}

	replayfs_kunmap(page);
	alloc_put_page(alloc, page);

	alloc_debugk("%s %d: returning %lld\n", __func__, __LINE__, ret);

	/*
	if (alloc != replayfs_alloc) {
		printk("%s %d: returning %lld\n", __func__, __LINE__, ret);
	}
	*/

	return ret;
}

void mark_free(struct replayfs_diskalloc *alloc, loff_t index) {
	/* The word offset of this bit */
	struct page *page = alloc_get_page_nocheck(alloc, index/(8));
	loff_t word = index / (sizeof(unsigned long) * 8);
	unsigned int *used_page_map = replayfs_kmap(page);
	int shift = (sizeof(unsigned long) * 8) - 1;
	loff_t last_free_word;
	word %= (PAGE_SIZE/sizeof(unsigned long));

	check_page_allocated(alloc, index);

	alloc_debugk("%s %d: Freeing page with index %lld, index %lu, word %lld, offs %d, used_page_map[word] 0x08%X\n", 
			__func__, __LINE__, index, page->index, word, (1<<(index&shift)), used_page_map[word]);

	/* K, now that we have the page, mark the offset as read */
	used_page_map[word] &= ~(1 << (index & shift));

	alloc_debugk("%s %d: used_page_map[word] after free: 0x%08X\n", 
			__func__, __LINE__, used_page_map[word]);

	last_free_word = index / (8 * sizeof(unsigned int));

	if (last_free_word < alloc->last_free_page_word) {
		alloc->last_free_page_word = last_free_word;
	}

	mark_page_accessed(page);
	//SetPageDirty(page);
	replayfs_diskalloc_page_dirty(page);
	//__set_page_dirty_nobuffers(page);
	//TestSetPageWriteback(page);

	replayfs_kunmap(page);
	alloc_put_page(alloc, page);
}

/*static*/ void diskalloc_free_page(struct replayfs_diskalloc *alloc,
		struct page *page) {
	debugk("%s %d: UNIMPLMENTED!!!\n", __func__, __LINE__);
}

loff_t replayfs_diskalloc_alloc_page_idx(struct replayfs_diskalloc *alloc) {
	loff_t page_idx;

	page_idx = first_free_page(alloc);

	return page_idx;
}

int replayfs_diskalloc_page_is_alloced(struct replayfs_diskalloc *alloc,
		loff_t page_offs) {
	/* The word offset of this bit */
	/* NOTE PAGE_SIZE / PAGE_SIZE is 1... */
	loff_t index = page_offs / PAGE_SIZE;
	struct page *page = alloc_get_page_nocheck(alloc, index/(8));
	loff_t word = index / (sizeof(unsigned long) * 8);
	unsigned int *used_page_map = replayfs_kmap(page);
	int shift = (sizeof(unsigned long) * 8) - 1;
	int ret;
	word %= (PAGE_SIZE/sizeof(unsigned long));

	/* Magic here */
	/* Okay, allocation policy, get the next page from the first extent */
	mutex_lock(&alloc->lock);


	alloc_min_debugk("%s %d: Checking page with index %lld, index %lu, word %lld, offs %d, used_page_map[word] 0x%08X\n", 
			__func__, __LINE__, index, page->index, word,
			(1<<(index&shift)), used_page_map[word]);

	ret = ((used_page_map[word] & (1 << (index & shift))) != 0);

	replayfs_kunmap(page);
	alloc_put_page_nocheck(alloc, page);

	mutex_unlock(&alloc->lock);
	return ret;
}

static struct page *replayfs_diskalloc_alloc_page_nolock(struct replayfs_diskalloc *alloc) {
	struct page *page;
	loff_t page_idx;
	/* Magic here */
	/* Okay, allocation policy, get the next page from the first extent */

	alloc_debugk("%s %d: Requested page for alloc %p\n", __func__, __LINE__,
			alloc);

	page = ERR_PTR(-ENOMEM);

	debugk("%s %d: Locking %p\n", __func__, __LINE__, &alloc->lock);
	/* Lock the diskalloc */

	/* Find the first free page */
	page_idx = first_free_page(alloc);
	debugk("%s %d: Got page_idx of %lld\n", __func__, __LINE__, page_idx);
	if (page_idx > 0) {
		atomic_inc(&diskalloc_num_blocks);
		/* ask the extent for a  page */
		debugk("%s %d: Alloc/Getting page: %lld\n", __func__, __LINE__, page_idx);
		page = alloc_get_page(alloc, page_idx * PAGE_SIZE);
		alloc_debugk("%s %d: Allocated page: %lu\n", __func__, __LINE__, page->index);
		//alloc_dump_stack();

		SetPageUptodate(page);
	} else {
		printk("%s %d: WARNING: Ran out of allocator pages!!!\n", __func__, __LINE__);
		BUG();
	}

	alloc_min_debugk("%s %d: Alloc'd page %lu\n", __func__, __LINE__, page->index);

	return page;
}

struct page *replayfs_diskalloc_alloc_page(struct replayfs_diskalloc *alloc) {
	struct page *page;

	mutex_lock(&alloc->lock);
	page = replayfs_diskalloc_alloc_page_nolock(alloc);
	mutex_unlock(&alloc->lock);

	return page;
}

void replayfs_diskalloc_free_page_noput(struct replayfs_diskalloc *alloc,
		struct page *page) {

	mutex_lock(&alloc->lock);

	/* Undo the magic */
	atomic_dec(&diskalloc_num_blocks);
	mark_free(alloc, (loff_t)page->index);
	alloc_min_debugk("%s %d: Freed page: %lu\n", __func__, __LINE__, page->index);
	//alloc_dump_stack();

	mutex_unlock(&alloc->lock);
}

void replayfs_diskalloc_free_page(struct replayfs_diskalloc *alloc,
		struct page *page) {

	mutex_lock(&alloc->lock);

	/* Undo the magic */
	atomic_dec(&diskalloc_num_blocks);
	mark_free(alloc, (loff_t)page->index);
	alloc_min_debugk("%s %d: Freed page: %lu\n", __func__, __LINE__, page->index);
	//alloc_dump_stack();

	//mutex_lock(&crappy_pagecache_lock);
	alloc_put_page_nocheck(alloc, page);
	//mutex_unlock(&crappy_pagecache_lock);

	mutex_unlock(&alloc->lock);
}

struct page *replayfs_diskalloc_get_page(struct replayfs_diskalloc *alloc,
		loff_t page) {
	struct page *ret;
	/* Just return the page at the spot */

	ret = alloc_get_page(alloc, page);

	return ret;
}

void replayfs_diskalloc_read_page_location(struct replayfs_diskalloc *alloc,
		void *buffer, loff_t page) {
	struct file *filp;
	loff_t pos;
	int nread;
	mm_segment_t old_fs;
	int fmode;

	pos = page;

	filp = alloc->filp;
	fmode = alloc->filp->f_mode;
	alloc->filp->f_mode |= FMODE_READ;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	/*
	debugk("%s %d: Args to vfs_read are %p, %p, PAGE_SIZE and pos of %p (%lld)\n", 
			__func__, __LINE__, filp, buffer, &pos, pos);
			*/
	min_debugk("%s %d: filp is %p, inode is %p, ino is %lu\n", __func__, __LINE__,
			filp, filp->f_dentry->d_inode, filp->f_dentry->d_inode->i_ino);
	//dump_stack();
	min_debugk("%s %d: Pageloc 0 contains %d, pos is %lld, isize is %lld\n", __func__, __LINE__,
			(int)((char *)buffer)[0], pos, i_size_read(filp->f_dentry->d_inode));
	nread = vfs_read(filp, buffer, PAGE_SIZE, &pos);
	min_debugk("%s %d: Post-Pageloc 0 contains %d, pos is %lld, nread is %d, isize is %lld\n",
			__func__, __LINE__, (int)((char *)buffer)[0], pos, nread, i_size_read(filp->f_dentry->d_inode));

	alloc->filp->f_mode = fmode;
	set_fs(old_fs);

	if (nread < 0) {
		printk("%s %d: nread is %d\n", __func__, __LINE__, nread);
		BUG();
	} 
	/*
	else {
		debugk("%s %d: nread is %d\n", __func__, __LINE__, nread);
	}
	*/

	if (nread < PAGE_SIZE) {
		memset(buffer + nread, 0, PAGE_SIZE - nread);
		nread = PAGE_SIZE - nread;
	}

	BUG_ON(nread != PAGE_SIZE);
}

void replayfs_diskalloc_write_page_location(struct replayfs_diskalloc *alloc,
		void *buffer, loff_t page) {
	struct file *filp;
	int nwritten;
	mm_segment_t old_fs;
	loff_t pos;
	loff_t expected_pos;
	unsigned int fmode;

	filp = alloc->filp;
	fmode = alloc->filp->f_mode;
	alloc->filp->f_mode |= FMODE_WRITE;

	/* Which page should we read from */
	pos = page;
	expected_pos = pos + PAGE_SIZE;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	BUG_ON(!S_ISREG(filp->f_dentry->d_inode->i_mode));
	min_debugk("%s %d: filp is %p, inode is %p, ino is %lu\n", __func__, __LINE__,
			filp, filp->f_dentry->d_inode, filp->f_dentry->d_inode->i_ino);
	/*
	printk("%s %d: REMOVE_ME: i_flags are 0x%X i_mode is 0x%X, f_flags are 0x%lX\n", __func__,
			__LINE__, filp->f_dentry->d_inode->i_flags,
			(unsigned int)filp->f_dentry->d_inode->i_mode, (unsigned long)fmode);
	printk("%s %d: REMOVE_ME: sb is %p are Dev is %d\n", __func__,
			__LINE__, filp->f_dentry->d_inode->i_sb,
			filp->f_dentry->d_inode->i_sb->s_dev);
			*/

	min_debugk("%s %d: Pageloc 0 contains %d, pos is %lld, i_size is %lld\n", __func__, __LINE__,
			(int)((char *)buffer)[0], pos, i_size_read(filp->f_dentry->d_inode));
	perftimer_start(write_timer);
	/*
	printk("%s %d: Doing write??\n", __func__, __LINE__);
	dump_stack();
	*/
	nwritten = vfs_write(filp, buffer, PAGE_SIZE, &pos);
	perftimer_stop(write_timer);
	min_debugk("%s %d: pos-Pageloc 0 contains %d, pos is %lld, nwritten is %d\n", __func__, __LINE__,
			(int)((char *)buffer)[0], pos, nwritten);

	if (pos != expected_pos) {
		char path[200];
		char *real_path;

		real_path = d_path(&filp->f_path, path, 200);
		if (IS_ERR(real_path)) {
			BUG();
		}

		printk("%s %d: File %p (%s) has unexpected return pos (got %lld instead of %lld), nwritten is %d\n", 
				__func__, __LINE__, filp, real_path, pos, expected_pos, nwritten);
	}

	alloc->filp->f_mode = fmode;

	set_fs(old_fs);
}

void replayfs_diskalloc_put_page(struct replayfs_diskalloc *alloc,
		struct page *page) {
	alloc_put_page(alloc, page);
}

static void make_new_meta_page(struct replayfs_diskalloc *alloc) {
	struct page *meta_page;
	struct meta_page *header;

	BUILD_BUG_ON(sizeof(struct meta_page) > PAGE_SIZE);
	BUILD_BUG_ON(NO_PAIRS > HEADER_SIZE * 8);

	/* Allocate the page */
	meta_page = replayfs_diskalloc_alloc_page_nolock(alloc);

	header = replayfs_kmap(meta_page);

	/* Set its allocated bits to zero */
	memset(header, 0, sizeof(header->header));
	replayfs_diskalloc_page_dirty(meta_page);

	replayfs_kunmap(meta_page);

	alloc->meta_page = meta_page;
}

int meta_page_empty(struct page *meta_page) {
	struct meta_page *header;
	int ret = 1;
	int i;

	header = replayfs_kmap(meta_page);

	for (i = 0; i < HEADER_SIZE/sizeof(unsigned long); i++) {
		if (header->header[i] != 0x0) {
			ret = 0;
			break;
		}
	}

	replayfs_kunmap(meta_page);

	return ret;
}
int popcountl(unsigned long i) {
	i = i - ((i >> 1) & 0x55555555);
	i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
	return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

static int meta_page_full(struct page *meta_page) {
	struct meta_page *header;
	int ret = 0;
	int i;
	int num_alloc = 0;

	header = replayfs_kmap(meta_page);

	for (i = 0; i < HEADER_SIZE/sizeof(unsigned long); i++) {
		if (~header->header[i] == 0x0) {
			num_alloc += 32;
		} else {
			//num_alloc += __builtin_popcountl(header->header[i]);
			num_alloc += popcountl(header->header[i]);

			/*
			printk("%s %d: Just got (likely) max alloc %d from %lu\n", __func__,
					__LINE__, num_alloc, meta_page->index);
					*/
		}

		if (num_alloc == NO_PAIRS) {
			ret = 1;
			break;
		}
		BUG_ON(num_alloc > NO_PAIRS);
	}

	replayfs_kunmap(meta_page);

	return ret;
}

static loff_t first_free_meta(struct replayfs_diskalloc *alloc,
		struct page *meta_page) {
	struct meta_page *header;
	int i;
	int idx=0;
	int offset;
	int found = 0;

	/* get the meta header... */
	header = replayfs_kmap(meta_page);

	/* For each int in the header */
	for (i = 0; i < HEADER_SIZE/sizeof(unsigned long); i++) {
		/* if the int isn't all zeros */
		if (~header->header[i] != 0) {
			int bit;

			found = 1;
			/* Get the first 0, and mark it as allocated */
			/*
			printk("%s %d: scanning %lX for zeros\n", __func__, __LINE__,
					header->header[i]);
					*/

			bit = __builtin_ctz(~header->header[i]);

			header->header[i] |= (1<<bit);
			/*
			printk("%s %d: After update now %lX,  switched bit %d\n", __func__, __LINE__,
					header->header[i], bit);
					*/

			/* idx = 32*i + first 0 */
			idx = (32*i) + bit;

			break;
		}
	}

	BUG_ON(!found);

	/*
	printk("%s %d: Allocating index %d from page %lu\n", __func__, __LINE__, idx,
			meta_page->index);
			*/

	replayfs_diskalloc_page_dirty(meta_page);

	/* Offset is 32 + sizeof(btree_meta) * idx */
	offset = HEADER_SIZE + (sizeof(struct replayfs_btree_meta) * idx);

	BUG_ON(offset+sizeof(struct replayfs_btree_meta) > PAGE_SIZE);
	
	/* Return the offset + page->index * PAGE_SIZE */
	return ((loff_t)meta_page->index * PAGE_SIZE) + (loff_t)offset;
}

loff_t replayfs_diskalloc_alloc_meta(struct replayfs_diskalloc *alloc) {
	loff_t ret;

	mutex_lock(&alloc->lock);
	if (alloc->meta_page == NULL || meta_page_full(alloc->meta_page)) {
		if (alloc->meta_page) {
			alloc_put_page(alloc, alloc->meta_page);
		}
		/* Allocate a new meta page */
		make_new_meta_page(alloc);
	}

	ret = first_free_meta(alloc, alloc->meta_page);

	mutex_unlock(&alloc->lock);

	return ret;
}

void replayfs_diskalloc_free_meta(struct replayfs_diskalloc *alloc,
		loff_t meta_loc) {
	/* 
	 * FIXME: For some reason freeing breaks my system right now... I need to make
	 * this work later...
	 */
#if 0
	/* Use replayfs_diskalloc version, as we are not locked */
	struct page *page = replayfs_diskalloc_get_page(alloc, meta_loc);
	struct meta_page *header;

	int offset = meta_loc % PAGE_SIZE;
	int idx_tmp;
	int idx;
	int bit;

	mutex_lock(&alloc->lock);

	header = replayfs_kmap(page);

	idx_tmp = offset - HEADER_SIZE;
	idx = idx_tmp / sizeof(struct replayfs_btree_meta);

	bit = idx % 32;
	idx /= 32;

	printk("%s %d: Freeing bit %d on page %lu, before %lX\n", __func__, __LINE__,
			bit, page->index, header->header[idx]);
	header->header[idx] &= ~(1UL<<bit);
	printk("%s %d: after %lX\n", __func__, __LINE__,
			header->header[idx]);

	replayfs_diskalloc_page_dirty(page);

	replayfs_kunmap(page);

	mutex_unlock(&alloc->lock);

	if (meta_page_empty(page)) {
		replayfs_diskalloc_free_page(alloc, page);
	} else {
		replayfs_diskalloc_put_page(alloc, page);
	}
#endif
}

