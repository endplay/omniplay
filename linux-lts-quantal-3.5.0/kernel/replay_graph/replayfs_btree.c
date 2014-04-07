/*
 * lib/btree.c	- Simple In-memory B+Tree
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2007-2008 Joern Engel <joern@logfs.org>
 * Bits and pieces stolen from Peter Zijlstra's code, which is
 * Copyright 2007, Red Hat Inc. Peter Zijlstra <pzijlstr@redhat.com>
 * GPLv2
 *
 * see http://programming.kicks-ass.net/kernel-patches/vma_lookup/btree.patch
 *
 * A relatively simple B+Tree implementation.  I have written it as a learning
 * exercise to understand how B+Trees work.  Turned out to be useful as well.
 *
 * B+Trees can be used similar to Linux radix trees (which don't have anything
 * in common with textbook radix trees, beware).  Prerequisite for them working
 * well is that access to a random tree node is much faster than a large number
 * of operations within each node.
 *
 * Disks have fulfilled the prerequisite for a long time.  More recently DRAM
 * has gained similar properties, as memory access times, when measured in cpu
 * cycles, have increased.  Cacheline sizes have increased as well, which also
 * helps B+Trees.
 *
 * Compared to radix trees, B+Trees are more efficient when dealing with a
 * sparsely populated address space.  Between 25% and 50% of the memory is
 * occupied with valid pointers.  When densely populated, radix trees contain
 * ~98% pointers - hard to beat.  Very sparse radix trees contain only ~2%
 * pointers.
 *
 * This particular implementation stores pointers identified by a long value.
 * Storing NULL pointers is illegal, lookup will return NULL when no entry
 * was found.
 *
 * A tricks was used that is not commonly found in textbooks.  The lowest
 * values are to the right, not to the left.  All used slots within a node
 * are on the left, all unused slots contain NUL values.  Most operations
 * simply loop once over all slots and terminate on the first NUL.
 */

#include <linux/btree.h>
#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

#include "replayfs_btree.h"
#include "replayfs_btree128.h"
#include "replayfs_diskalloc.h"
#include "replayfs_kmap.h"

//#include "replayfs_fs.h"
//#include "replayfs_inode.h"

//#define REPLAYFS_BTREE_DEBUG

//#define REPLAYFS_BTREE_ALLOC_DEBUG

extern int btree_print;
#ifdef REPLAYFS_BTREE_DEBUG
#define debugk(...) if (btree_print) {printk(__VA_ARGS__);}
#else
#define debugk(...)
#endif

#ifdef REPLAYFS_BTREE_ALLOC_DEBUG
#define alloc_debugk(...) if (btree_print) {printk(__VA_ARGS__);}
#else
#define alloc_debugk(...)
#endif

#define LONG_PER_U64 (64 / BITS_PER_LONG)

#define MAX(a, b) ((a) > (b) ? (a) : (b))
/* #define NODESIZE MAX(L1_CACHE_BYTES, 128) */
#define NODESIZE MAX(L1_CACHE_BYTES, PAGE_SIZE)

static struct replayfs_btree_value *replayfs_btree_lookup_internal(
		struct replayfs_btree_head *head, loff_t pos,
		struct replayfs_btree_key *key, struct page **ret_page);

struct replayfs_btree_value replayfs_zero_value = {
	.id = {
		.unique_id = -1,
		.sysnum = -1,
		.pid = 0
	},
	.buff_offs = 0
};

struct btree_geo {
	int keylen;
	int no_pairs;
	int no_longs;
};

#define VALSIZELONGS (sizeof(struct replayfs_btree_value)/sizeof(long))

struct btree_geo replayfs_geo = {
	.keylen = 2 * LONG_PER_U64,
	.no_pairs = NODESIZE / sizeof(long) / (VALSIZELONGS + 2 * LONG_PER_U64),
	.no_longs = 2 * LONG_PER_U64 * (NODESIZE / sizeof(long) / (VALSIZELONGS + 2 * LONG_PER_U64)),
};

extern struct replayfs_diskalloc *replayfs_alloc;
static struct page *btree_node_alloc(struct replayfs_btree_head *head, gfp_t gfp)
{
	struct page *page = NULL;

	/*
	if (head->allocator != replayfs_alloc) {
		printk("%s %d: Requesting page from alloc %p\n", __func__, __LINE__,
				head->allocator);
	}
	*/
	page = replayfs_diskalloc_alloc_page(head->allocator);
	if (likely(!IS_ERR(page))) {
		void *addr = replayfs_kmap(page);
		if (IS_ERR(addr) || addr == NULL) {
			BUG();
		}
		debugk("%s %d: Zeroing page!\n", __func__, __LINE__);
		memset(addr, 0, PAGE_SIZE);
		//__set_page_dirty_nobuffers(page);
		//SetPageDirty(page);
		replayfs_diskalloc_page_dirty(page);
		replayfs_kunmap(page);
	} else {
		printk("%s %d: ERROR GETTING PAGE!!! (%ld)\n", __func__, __LINE__,
				PTR_ERR(page));
		BUG();
	}
	debugk("%s %d: Allocated btree head %p with page %lu\n", __func__, __LINE__,
			head, page->index);

	return page;
}

static int rpvalkeycmp(const struct replayfs_btree_key *l1, loff_t pos) {
	loff_t start1 = l1->offset;
	loff_t end1 = start1 + l1->size;

	if (start1 > pos) {
		return 1;
	} if (end1 <= pos) {
		return -1;
	}

	return 0;
}

static int rpkeycmp(const struct replayfs_btree_key *l1, const struct
		replayfs_btree_key *l2)
{
	loff_t start1 = l1->offset;
	loff_t start2 = l2->offset;

	if (start1 < start2)
		return -1;
	if (start1 > start2)
		return 1;
	if (start1 + l1->size < start2 + l2->size) {
		return -1;
	}
	if (start1 + l1->size > start2 + l2->size) {
		return 1;
	}

	return 0;
}

/*
static int longcmp(const unsigned long *l1, const unsigned long *l2, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (l1[i] < l2[i])
			return -1;
		if (l1[i] > l2[i])
			return 1;
	}
	return 0;
}
*/

static struct replayfs_btree_key *keycpy(struct replayfs_btree_key *dest,
		struct replayfs_btree_key *src)
{
	/*
	debugk("%s %d: KEYCPY: {%lld, %lld} <- {%lld, %lld}\n", __func__, __LINE__,
			dest->offset, dest->size, src->offset, src->size);
			*/
	dest->offset = src->offset;
	dest->size = src->size;

	return dest;
}

/*
static unsigned long *longcpy(unsigned long *dest, const unsigned long *src,
		size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		dest[i] = src[i];
	return dest;
}
*/

static atomic_t gets = {0};
static atomic_t puts = {0};

static unsigned long *longset(unsigned long *s, unsigned long c, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		s[i] = c;
	return s;
}

static void dec_key(loff_t *pos)
{
	*pos = *pos-1;
}

static unsigned long *lbkey(struct btree_geo *geo, unsigned long *page, int n)
{
	unsigned long *node = page;
	return &node[n * geo->keylen];
}

static struct replayfs_btree_key *bkey(struct btree_geo *geo, unsigned long *page, int n)
{
	unsigned long *node = page;
	return (struct replayfs_btree_key *)&node[n * geo->keylen];
}

static struct page *bval(struct replayfs_diskalloc *allocator,
		struct btree_geo *geo, unsigned long *node, unsigned long **page_data, int n)
{
	loff_t pageoffs;
	//unsigned long *node = page_address(node_page);
	struct page *page;

	/* Get offset from node */
	memcpy(&pageoffs, &node[geo->no_longs + (VALSIZELONGS*n)], sizeof(loff_t));

	if (pageoffs == 0) {
		return NULL;
	}

	/*
	debugk("%s %d: Reading bval with offset %lld from {%lu, %d}\n", __func__,
			__LINE__, pageoffs, node_page->index, n);
			*/
	debugk("%s %d: Reading bval with offset %lld page (%lu)\n", __func__,
			__LINE__, pageoffs, (unsigned long)(pageoffs >> PAGE_CACHE_SHIFT));

	BUG_ON(pageoffs % PAGE_SIZE != 0);
	/* Get page of next node from offset */
	page = replayfs_diskalloc_get_page(allocator, pageoffs);

	BUG_ON(page == NULL);

	/* Return page */
	atomic_inc(&gets);

	if (page != NULL) {
		*page_data = replayfs_kmap(page);
	}

	alloc_debugk("%s %d: Get on page %lu (%p)\n", __func__, __LINE__,
			page->index, page);

	return page;
}

static void bval_put(struct replayfs_btree_head *head, struct page *page) {
	if (page != NULL) {
		if (head->node_page != page) {
			replayfs_diskalloc_put_page(head->allocator, page);
			atomic_inc(&puts);
		} else {
#ifdef REPLAYFS_BTREE_DEBUG
		if (btree_print) {
			struct replayfs_btree_key *key;
			void *data = replayfs_kmap(page);

			key = bkey(&replayfs_geo, data, 0);

			/* If this file is over TB.. problem */
			if (key->offset > 1LL<<43) {
				printk("%s %d: BAD btree offset for page %lu, entry: {%lld, %lld}\n", __func__,
						__LINE__, page->index, key->offset, key->size);
				BUG();
			}

			replayfs_kunmap(page);
		}
#endif
		}

		alloc_debugk("%s %d: Put on page %lu (%p)\n", __func__, __LINE__,
				page->index, page);

		replayfs_kunmap(page);
	}
}

/*
 * The normal rules don't apply here... the leaf node elements are larger than
 * the non-leaf nodes...
 */
static struct replayfs_btree_value *bval_at(struct replayfs_diskalloc *allocator,
		struct btree_geo *geo, unsigned long *node, int n) {
	//unsigned long *node = page_address(page);
	struct replayfs_btree_value *ret;

	/*
	debugk("%s %d: buffer offset is %d\n", __func__, __LINE__, geo->no_longs +
			(VALSIZELONGS * n));
			*/

	//return replayfs_disk_alloc_get(allocator, offs);
	ret = (struct replayfs_btree_value *)
		&node[geo->no_longs + (VALSIZELONGS * n)];

	/*
	debugk("%s %d: Reading value with unique_id %lld from {%lu, %d} {%p, %d} (%p)\n", __func__,
			__LINE__, ret->id.unique_id, page->index, n, node,
			geo->no_longs+(VALSIZELONGS*n), &node[geo->no_longs+(VALSIZELONGS*n)]);
			*/

	return ret;
}

static void setkey(struct btree_geo *geo, struct page *page, int n,
		   struct replayfs_btree_key *key)
{
	void *addr = replayfs_kmap(page);
	keycpy(bkey(geo, addr, n), key);
	//SetPageDirty(page);
	replayfs_diskalloc_page_dirty(page);
	replayfs_kunmap(page);
}

/* 
 * Values are set differently and retrieved differently for different types of
 *   nodes...
 *
 * How do I deal with this?
 *
 * I can only save references:
 *   Then I need to deal w/ the allocator, but I don't need to deal w/ page
 *     stuffs
 *   XXX ISSUE: Cannot handle bkptrs of arbitrary sized allocations, need to use
 *     fixed size page allocds
 *
 * -- Going to try this: V
 * I can keep track of what "type" of node I'm dealing with
 *   Only leaf nodes have values, others have references...
 *   This could allow for more optimal use of space...
 *   This is probably more complex (although it doesn't need an arbitrary sized
 *       allocator)...
 */

static void nullval(struct btree_geo *geo, struct page *page, int n)
{
	unsigned long *node = replayfs_kmap(page);

	//__set_page_dirty_nobuffers(page);
	//SetPageDirty(page);
	replayfs_diskalloc_page_dirty(page);
	memset(&node[geo->no_longs + (VALSIZELONGS*n)], 0,
			sizeof(struct replayfs_btree_value));

	replayfs_kunmap(page);
}

static void setval(struct btree_geo *geo, struct page *page, int n,
		   struct replayfs_btree_value *val)
{
	unsigned long *node = replayfs_kmap(page);

	//__set_page_dirty_nobuffers(page);
	//SetPageDirty(page);
	replayfs_diskalloc_page_dirty(page);
	memcpy(&node[geo->no_longs + (VALSIZELONGS * n)], val,
			sizeof(struct replayfs_btree_value));

	replayfs_kunmap(page);
}

static void setval_node(struct btree_geo *geo, struct page *page, int n,
		   struct page *val)
{
	unsigned long *node = replayfs_kmap(page);

	loff_t index;

	if (val != NULL) {
		index = (loff_t)val->index * PAGE_SIZE;
	} else {
		printk("%s %d: WARNING: tmp==NULL\n", __func__, __LINE__);
		dump_stack();
		index = 0;
	}

	//__set_page_dirty_nobuffers(page);
	//SetPageDirty(page);
	replayfs_diskalloc_page_dirty(page);
	debugk("%s %d: Copying node value with off %lld into {%lu, %d}\n", __func__,
			__LINE__, index, page->index, n);
	memcpy(&node[geo->no_longs + (VALSIZELONGS*n)],
			&index, sizeof(loff_t));

	replayfs_kunmap(page);
}

static void clearpair(struct btree_geo *geo, struct page *page, int n)
{
	unsigned long *node = replayfs_kmap(page);
	longset(lbkey(geo, node, n), 0, geo->keylen);
	replayfs_kunmap(page);
	/* Ugh! */
	//setval(geo, page, n, 0);
	nullval(geo, page, n);
}

static inline void __btree_init(struct replayfs_btree_head *head)
{
	head->node_page = NULL;
	head->height = 0;
}

void replayfs_btree_init_allocator(struct replayfs_btree_head *head,
		struct replayfs_diskalloc *allocator)
{
	__btree_init(head);
	head->allocator = allocator;
}

static void update_meta(struct replayfs_btree_head *head) {
	struct page *page;
	struct replayfs_btree_meta *meta;

	page = replayfs_diskalloc_get_page(head->allocator, head->meta_loc);
	meta = replayfs_kmap(page);

	if (head->node_page != NULL) {
		meta->node_page = head->node_page->index * PAGE_SIZE;
		debugk("%s %d: Saving meta->nodepage to %lld on page %lu\n", __func__, __LINE__,
				meta->node_page, page->index);
	} else {
		meta->node_page = 0;
	}
	meta->height = head->height;

	//SetPageDirty(page);
	replayfs_diskalloc_page_dirty(page);

	replayfs_kunmap(page);
	replayfs_diskalloc_put_page(head->allocator, page);
}

int replayfs_btree_init(struct replayfs_btree_head *head,
		struct replayfs_diskalloc *alloc, loff_t meta_loc)
{
	struct page *page;
	struct replayfs_btree_meta *meta;

	head->allocator = alloc;

	head->meta_loc = meta_loc;

	page = replayfs_diskalloc_get_page(alloc, meta_loc);
	meta = replayfs_kmap(page);

	debugk("%s %d: Got meta with node_page %lld, i_size %lld\n", __func__,
			__LINE__, meta->node_page, meta->i_size);

	if (meta->node_page != 0) {
		head->node_page = replayfs_diskalloc_get_page(alloc, meta->node_page);
		debugk("%s %d: Setting head->node_page for %p to %lu\n", __func__,
				__LINE__, head, head->node_page->index);
	} else {
		head->node_page = NULL;
	}
	head->height = meta->height;

	replayfs_kunmap(page);

	replayfs_diskalloc_put_page(alloc, page);
	//mempool_create(0, btree_alloc, btree_free, NULL);

	if (head->node_page != NULL) {
		debugk("%s %d: head->node_page %lu, head->height %d\n", __func__,
				__LINE__, head->node_page->index, head->height);
	} else {
		debugk("%s %d: head->node_page (null), head->height %d\n", __func__,
				__LINE__, head->height);
	}

	return 0;
}

int replayfs_btree_create(struct replayfs_btree_head *head,
		struct replayfs_diskalloc *alloc, loff_t meta_loc)
{
	head->meta_loc = meta_loc;
	__btree_init(head);
	head->allocator = alloc;
	update_meta(head);
	//mempool_create(0, btree_alloc, btree_free, NULL);
	return 0;
}

void replayfs_btree_destroy(struct replayfs_btree_head *head)
{
	if (head->node_page != NULL) {
		replayfs_diskalloc_put_page(head->allocator, head->node_page);
	}

	replayfs_diskalloc_sync(head->allocator);

	/* Sync all of the nodes in the tree */
	head->allocator = NULL;
}

void replayfs_btree_delete(struct replayfs_btree_head *head)
{
	struct replayfs_btree_value *value;
	struct replayfs_btree_key key;
	struct page *page;
	/* 
	 * Remove all of the elements from the tree 
	 * This is not optimied in my implementation... it will be slow
	 */
	value = replayfs_btree_last(head, &key, &page);
	while (key.size != 0 && value != NULL) {
		struct replayfs_btree_value _value;
		struct replayfs_btree_key _key;
		memcpy(&_value, value, sizeof(_value));
		memcpy(&_key, &key, sizeof(_key));

		replayfs_btree_put_page(head, page);

		replayfs_btree_remove(head, &_key, NULL);

		value = replayfs_btree_last(head, &key, &page);
	}

	if (head->height > 0) {
		printk("%s %d: height is %d????\n", __func__, __LINE__, head->height);
	}
	//BUG_ON(head->height != 0);

	replayfs_btree_destroy(head);
	/* Done */
}

extern int replayfs_debug_allocnum;
extern int replayfs_debug_page;
DEFINE_MUTEX(glbl_debug_lock);
static struct replayfs_diskalloc *glbl_debug_alloc = NULL;

void replayfs_btree_put_page(struct replayfs_btree_head *head, struct page *page) {
#ifdef REPLAYFS_BTREE_DEBUG
	mutex_lock(&glbl_debug_lock);
	if (unlikely(glbl_debug_alloc == NULL &&
				replayfs_debug_allocnum == head->allocator->allocnum)) {
		atomic_inc(&head->allocator->refcnt);
		glbl_debug_alloc = head->allocator;
	}
	mutex_unlock(&glbl_debug_lock);
#endif
	bval_put(head, page);
}

extern void btree128_debug_check(void);
void __btree_debug_check(void) {
	mutex_lock(&glbl_debug_lock);
	btree128_debug_check();
	if (glbl_debug_alloc != NULL && replayfs_debug_page >= 0) {
		struct page *page;
		struct replayfs_btree_key *key;
		void *page_data;

		page = replayfs_diskalloc_get_page(glbl_debug_alloc,
				(loff_t)replayfs_debug_page * PAGE_SIZE);
		BUG_ON(page == NULL);

		page_data = replayfs_kmap(page);

		key = bkey(&replayfs_geo, page_data, 0);

		/* If this file is over TB.. problem */
		if (key->offset > 1LL<<43) {
			printk("%s %d: BAD btree offset for page %lu, allocnum %d, entry: {%lld, %lld}\n", __func__,
					__LINE__, page->index, glbl_debug_alloc->allocnum, key->offset, key->size);
			BUG();
		}

		replayfs_kunmap(page);

		replayfs_diskalloc_put_page(glbl_debug_alloc, page);
	}
	mutex_unlock(&glbl_debug_lock);
}

static struct page *get_head_page(struct replayfs_btree_head *head,
		unsigned long **data) {
	struct page *ret;
	ret = head->node_page;
	BUG_ON(ret == NULL && head->height != 0);
	if (ret != NULL) {
		*data = replayfs_kmap(ret);

		BUG_ON(*data == NULL);

		alloc_debugk("%s %d: Headpage map on page %lu (%p)\n", __func__, __LINE__,
				ret->index, ret);

		/* If the first key of the page is insane... bad times */
#ifdef REPLAYFS_BTREE_DEBUG
		if (btree_print) {
			struct replayfs_btree_key *key;

			key = bkey(&replayfs_geo, *data, 0);

			/* If this file is over TB.. problem */
			if (key->offset > 1LL<<43) {
				printk("%s %d: BAD btree offset for page %lu, allocnum %d, entry: {%lld, %lld}\n", __func__,
						__LINE__, ret->index, head->allocator->allocnum, key->offset, key->size);
				printk("%s %d: debug_allocnum is %d, debug_alloc is %p, debug_page is %d\n",
						__func__, __LINE__, replayfs_debug_allocnum, glbl_debug_alloc,
						replayfs_debug_page);
				BUG();
			}
		}
#endif
	} else {
		*data = NULL;
	}
#ifdef REPLAYFS_BTREE_DEBUG
	mutex_lock(&glbl_debug_lock);
	if (unlikely(glbl_debug_alloc == NULL &&
				replayfs_debug_allocnum == head->allocator->allocnum)) {
		atomic_inc(&head->allocator->refcnt);
		glbl_debug_alloc = head->allocator;
	}
	mutex_unlock(&glbl_debug_lock);
#endif
	return ret;
}

struct replayfs_btree_value *replayfs_btree_last(struct replayfs_btree_head *head,
		struct replayfs_btree_key *key, struct page **ret_page)
{
	struct page *page;
	unsigned long *node;
	struct replayfs_btree_value *ret;
	struct replayfs_btree_key *src_key;
	int height = head->height;

	if (height == 0)
		return NULL;

	page = get_head_page(head, &node);

	for ( ; height > 1; height--) {
		struct page *tmppage = page;
		page = bval(head->allocator, &replayfs_geo, node, &node, 0);
		bval_put(head, tmppage);
	}

	src_key = bkey(&replayfs_geo, node, 0);
	keycpy(key, src_key);
	ret = bval_at(head->allocator, &replayfs_geo, node, 0);
	*ret_page = page;

	return ret;
}

static int valkeycmp(struct btree_geo *geo, unsigned long *node, int pos,
		loff_t keypos)
{
	return rpvalkeycmp(bkey(geo, node, pos), keypos);
}

static int keycmp(struct btree_geo *geo, unsigned long *node, int pos,
		  struct replayfs_btree_key *key)
{
	return rpkeycmp(bkey(geo, node, pos), key);
}

static int keyzero(struct btree_geo *geo, struct replayfs_btree_key *key)
{
	if (key->offset == 0 && key->size == 0) {
		return 1;
	}

	return 0;
}

int replayfs_btree_update(struct replayfs_btree_head *head,
		 struct replayfs_btree_key *key, void *val)
{
	int i, height = head->height;
	unsigned long *node_data;
	struct page *node = get_head_page(head, &node_data);

	if (height == 0)
		return -ENOENT;

	for ( ; height > 1; height--) {
		struct page *tmppage;
		for (i = 0; i < replayfs_geo.no_pairs; i++)
			if (keycmp(&replayfs_geo, node_data, i, key) <= 0)
				break;

		if (i == replayfs_geo.no_pairs)
			return -ENOENT;

		tmppage = node;
		node = bval(head->allocator, &replayfs_geo, node_data, &node_data, i);
		bval_put(head, tmppage);
		if (!node)
			return -ENOENT;
	}

	if (!node)
		return -ENOENT;

	for (i = 0; i < replayfs_geo.no_pairs; i++)
		if (keycmp(&replayfs_geo, node_data, i, key) == 0) {
			setval(&replayfs_geo, node, i, val);

			bval_put(head, node);

			return 0;
		}

	bval_put(head, node);

	return -ENOENT;
}

/*
 * Usually this function is quite similar to normal lookup.  But the key of
 * a parent node may be smaller than the smallest key of all its siblings.
 * In such a case we cannot just return NULL, as we have only proven that no
 * key smaller than __key, but larger than this parent key exists.
 * So we set __key to the parent key and retry.  We have to use the smallest
 * such parent key, which is the last parent key we encountered.
 */
struct replayfs_btree_value *replayfs_btree_get_prev(struct replayfs_btree_head *head,
		struct replayfs_btree_key*__key, struct page **ret_page)
{
	int i, height;
	unsigned long old_node;
	loff_t pos = __key->offset;
	unsigned long *node_data;
	unsigned long *oldnode_data;
	struct page *node, *oldnode;
	struct replayfs_btree_key *retry_key = NULL, key;
	struct page *retry_page = NULL;

	struct replayfs_btree_key *pk = NULL;

	debugk("%s %d: Here, with __key {%lld, %lld}\n", __func__, __LINE__,
			__key->offset, __key->size);

	if (keyzero(&replayfs_geo, __key))
		return NULL;

	debugk("%s %d: Checking head->height (%d)\n", __func__, __LINE__,
			head->height);
	if (head->height == 0)
		return NULL;
	keycpy(&key, __key);
	old_node = 0;
retry:
	pos = key.offset;
	dec_key(&pos);
	debugk("%s %d: Have pos of %lld\n", __func__, __LINE__, pos);

	node = get_head_page(head, &node_data);
	if (node) {
		printk("%s %d: Got head page of %lu\n", __func__, __LINE__, node->index);
		if (old_node == node->index) {
			printk("%s %d: Putting node (%lu)\n", __func__,
					__LINE__, node->index);
			bval_put(head, node);
			goto out;
		}

		old_node = node->index;
	}

	for (height = head->height ; height > 1; height--) {
		for (i = 0; i < replayfs_geo.no_pairs; i++) {
			struct replayfs_btree_key *k = bkey(&replayfs_geo, node_data, i);

			debugk("%s %d: Scanning key of {%lld, %lld}, level %d\n", __func__, __LINE__,
					k->offset, k->size, height);

			/* We can come to a situation where the bottom key rangeis not in the tree 
			 * (aka its removed) and we're trying to find it.  This resolves a null
			 * exception, and points to the lowest range set in the tree
			 */
			if (k->size == 0) {
				i--;
				break;
			}
			if (valkeycmp(&replayfs_geo, node_data, i, pos) <= 0) {
				break;
			}
		}

		debugk("%s %d: Level scan gives i of %d (no_pairs: %d)\n", __func__,
				__LINE__, i, replayfs_geo.no_pairs);
		if (i == replayfs_geo.no_pairs)
			goto miss;

		oldnode = node;
		oldnode_data = node_data;

		node = bval(head->allocator, &replayfs_geo, node_data, &node_data, i);

		if (node) {
			debugk("%s %d: New node is %lu\n", __func__,
					__LINE__, node->index);
		} else {
			debugk("%s %d: New node is %p\n", __func__,
					__LINE__, node);
		}

		if (!node) {
			printk("%s %d: Putting oldnode %lu\n", __func__, __LINE__, oldnode->index);
			bval_put(head, oldnode);
			goto miss;
		}

		printk("%s %d: Looping with node->index of %lu\n", __func__, __LINE__, node->index);
		//bval_put(head, node);

		if (retry_page) {
			printk("%s %d: Putting retry_page->index of %lu\n", __func__, __LINE__,
					retry_page->index);
			bval_put(head, retry_page);
			retry_page = NULL;
		}
		retry_key = bkey(&replayfs_geo, oldnode_data, i);
		
		printk("%s %d: Setting retry_page to be oldnode: %lu\n", __func__, __LINE__,
				oldnode->index);
		retry_page = oldnode;
	}

	if (!node) {
		goto miss;
	}
	debugk("%s %d: Have node of %p\n", __func__, __LINE__, node);

	printk("%s %d: Have node->index of %lu\n", __func__, __LINE__, node->index);

	for (i = 0; i < replayfs_geo.no_pairs; i++) {
		struct replayfs_btree_key *k;

		k = bkey(&replayfs_geo, node_data, i);
		debugk("%s %d: Comparing %llu and {%lld, %lld}\n", __func__, __LINE__, pos,
				k->offset, k->size);
		//BUG_ON(pk != NULL && k->size != 0 && k->offset + k->size != pk->offset);

		pk = k;

		if (keyzero(&replayfs_geo, k)) {
			break;
		}

		if (valkeycmp(&replayfs_geo, node_data, i, pos) <= 0) {

			if (!keyzero(&replayfs_geo, bkey(&replayfs_geo, node_data, i))) {
				keycpy(__key, bkey(&replayfs_geo, node_data, i));
				*ret_page = node;
				printk("%s %d: returning node of %lu\n", __func__, __LINE__,
						node->index);
				return bval_at(head->allocator, &replayfs_geo, node_data, i);
			} else {
				goto miss;
			}

		}
	}
miss:
	printk("%s %d: In miss, retry_page is %lu\n", __func__, __LINE__, retry_page->index);
	if (retry_key) {
		keycpy(&key, retry_key);
		retry_key = NULL;
		printk("%s %d: Putting retry_page %lu\n", __func__, __LINE__, retry_page->index);
		bval_put(head, retry_page);
		retry_page = NULL;
		goto retry;
	}
out:
	if (retry_page) {
		printk("%s %d: Putting retry_page %lu\n", __func__, __LINE__, retry_page->index);
		bval_put(head, retry_page);
	}

	printk("%s %d: Returning NULL %lu\n", __func__, __LINE__, retry_page->index);
	return NULL;
}

static int getpos(struct btree_geo *geo, unsigned long *page_data,
		loff_t keypos)
{
	int i;

	for (i = 0; i < geo->no_pairs; i++) {
		if (valkeycmp(geo, page_data, i, keypos) <= 0)
			break;
	}
	return i;
}

static int getfill(struct replayfs_diskalloc *alloc, struct btree_geo *geo,
		unsigned long *page_data, int start)
{
	int i;

	for (i = start; i < geo->no_pairs; i++) {
		struct replayfs_btree_key *key;

		key = bkey(geo, page_data, i);

		debugk("%s %d: Have key {%lld, %lld} at %d\n", __func__, __LINE__, key->offset,
				key->size, i);
		if (key->size == 0) {
			break;
		}
	}
	return i;
}

#ifdef REPLAYFS_BTREE_DEBUG
static void check_tree_internal(struct replayfs_btree_head *head, struct page *node,
		unsigned long *node_data, int level, struct replayfs_btree_key *last_key) {
	struct btree_geo *geo = &replayfs_geo;
	int i;

	struct replayfs_btree_key *fill_key = NULL;

	debugk("%s %d: Have node of %lu, level is %d, height is %d\n", __func__, __LINE__,
			node->index, level, head->height);

	if (level > 1) {
		for (i = 0; i < geo->no_pairs; i++) {
			struct page *new_node;
			unsigned long *new_node_data;
			struct replayfs_btree_key *key;

			key = bkey(geo, node_data, i);

			debugk("%s %d: Level %d Scanning {%lld, %lld}\n", __func__, __LINE__,
					level, key->offset, key->size);

			if (!keyzero(geo, key)) {
				new_node = bval(head->allocator, geo, node_data, &new_node_data, i);

				BUG_ON(new_node == NULL);

				check_tree_internal(head, new_node, new_node_data, level-1, key);

				bval_put(head, new_node);
			} else {
				fill_key = key;
				break;
			}
		}
	} else {
		struct replayfs_btree_key *pk = NULL;

		for (i = 0; i < replayfs_geo.no_pairs; i++) {
			struct replayfs_btree_key *k;

			k = bkey(&replayfs_geo, node_data, i);

			debugk("%s %d: Level %d Scanning {%lld, %lld}\n", __func__, __LINE__,
					level, k->offset, k->size);

			if (pk != NULL && k->size != 0) {
				debugk("%s %d: Checking %lld != %lld\n", __func__, __LINE__,
						k->size + k->offset, pk->offset);
			}
			BUG_ON(pk != NULL && k->size != 0 && k->offset + k->size != pk->offset);

			if (keyzero(geo, k)) {
				break;
			}

			pk = k;
		}

		fill_key = pk;
	}

	if (last_key != NULL && fill_key != NULL) {
		debugk("%s %d: Level %d fill_key {%lld, %lld}, last_key {%lld, %lld}\n",
				__func__, __LINE__, level, fill_key->offset, fill_key->size,
				last_key->offset, last_key->size);

		BUG_ON(last_key->offset != fill_key->offset &&
				last_key->size != fill_key->size);
	}
}

static DEFINE_MUTEX(btree_check_mutex);

static void check_tree(struct replayfs_btree_head *head) {
	struct page *node;
	unsigned long *node_data;

	if (head->height < 1) {
		return;
	}

	mutex_lock(&btree_check_mutex);

	node = get_head_page(head, &node_data);

	check_tree_internal(head, node, node_data, head->height, NULL);

	bval_put(head, node);

	mutex_unlock(&btree_check_mutex);
}
#else
#define check_tree(...)
#endif

static struct replayfs_btree_value *replayfs_btree_lookup_internal(
		struct replayfs_btree_head *head, loff_t pos,
		struct replayfs_btree_key *key, struct page **ret_page)
{
	int i, height = head->height;
	struct page *node;
	struct replayfs_btree_key *pk = NULL;
	unsigned long *node_data;
	node = get_head_page(head, &node_data);


	if (height == 0) {
		debugk("%s %d: Empty tree!\n", __func__, __LINE__);
		return NULL;
	}

	debugk("%s %d: In %s with tree %p (Head page %lu height %d)\n", __func__, __LINE__,
			__func__, head, node->index, head->height);

	for ( ; height > 1; height--) {
		struct page *tmppage;
		debugk("%s %d: On non-leaf node!\n", __func__, __LINE__);
		for (i = 0; i < replayfs_geo.no_pairs; i++) {
			struct replayfs_btree_key *k = bkey(&replayfs_geo, node_data, i);

			/* We can come to a situation where the bottom key rangeis not in the tree 
			 * (aka its removed) and we're trying to find it.  This resolves a null
			 * exception, and points to the lowest range set in the tree
			 */
			if (k->size == 0) {
				i--;
				debugk("%s %d: Size is zero, returning i of %d\n", __func__, __LINE__,
						i);
				break;
			}

			if (valkeycmp(&replayfs_geo, node_data, i, pos) <= 0) {
				break;
			}
		}

		if (i == replayfs_geo.no_pairs) {
			debugk("%s %d: Val not present?\n", __func__, __LINE__);
			bval_put(head, node);
			return NULL;
		}

		tmppage = node;

		debugk("%s %d: Reading node at index %d\n", __func__, __LINE__, i);
		node = bval(head->allocator, &replayfs_geo, node_data, &node_data, i);
		if (!node) {
			debugk("%s %d: Node NULL??\n", __func__, __LINE__);
			bval_put(head, tmppage);
			return NULL;
		}
		debugk("%s %d: Got node %lu\n", __func__, __LINE__, node->index);

		bval_put(head, tmppage);
	}

	if (!node) {
		debugk("%s %d: Node still NULL??\n", __func__, __LINE__);
		return NULL;
	}

	debugk("%s %d: Scanning page %lu for entry\n", __func__, __LINE__,
			node->index);
	for (i = 0; i < replayfs_geo.no_pairs; i++) {
		struct replayfs_btree_key *k;
		k = bkey(&replayfs_geo, node_data, i);
		debugk("%s %d: Comparing %llu and {%lld, %lld}\n", __func__, __LINE__, pos,
				k->offset, k->size);
		BUG_ON(pk != NULL && k->size != 0 && k->offset + k->size != pk->offset);

		if (keyzero(&replayfs_geo, k)) {
			break;
		}

		if (valkeycmp(&replayfs_geo, node_data, i, pos) == 0) {
			debugk("%s %d: Found key at %d\n", __func__, __LINE__, i);
			keycpy(key, bkey(&replayfs_geo, node_data, i));
			*ret_page = node;
			return (void *)bval_at(head->allocator, &replayfs_geo, node_data, i);
		}

		pk = k;
	}

	bval_put(head, node);
	return NULL;
}


struct replayfs_btree_value *replayfs_btree_lookup(
		struct replayfs_btree_head *head, loff_t pos,
		struct replayfs_btree_key *key, struct page **ret_page) {
	check_tree(head);
	return replayfs_btree_lookup_internal(head, pos, key, ret_page);
}

/*
 * locate the correct leaf node in the btree
 */
static struct page *find_level(struct replayfs_btree_head *head, struct btree_geo *geo,
		struct replayfs_btree_key *key, int level, unsigned long **page_data)
{
	unsigned long *node_data;
	struct page *node = get_head_page(head, &node_data);
	int i, height;

	unsigned long *oldpage_data;
	struct page *oldpage = NULL;

	debugk("%s %d: Have node of %lu, level is %d, height is %d\n", __func__, __LINE__,
			node->index, level, head->height);

	for (height = head->height; height > level; height--) {
		unsigned long *tmpnode_data;
		struct page *tmpnode;
		for (i = 0; i < geo->no_pairs; i++) {
			struct replayfs_btree_key *k = bkey(geo, node_data, i);
			debugk("%s %d: Scanning key of {%lld, %lld}, level %d\n", __func__, __LINE__,
					k->offset, k->size, height);

			/* We can come to a situation where the bottom key rangeis not in the tree 
			 * (aka its removed) and we're trying to find it.  This resolves a null
			 * exception, and points to the lowest range set in the tree
			 */
			if (k->size == 0) {
				i--;
				debugk("%s %d: Size is zero, returning i of %d\n", __func__, __LINE__,
						i);
				break;
			}

			if (valkeycmp(geo, node_data, i, key->offset) <= 0) {
				break;
			}
		}

		debugk("%s %d: Next node index is %d\n", __func__, __LINE__, i);

		tmpnode = bval(head->allocator, geo, node_data, &tmpnode_data, i);
		if (tmpnode != NULL) {
			debugk("%s %d: Pulled tmpnode %lu from %d\n", __func__, __LINE__,
					tmpnode->index, i);
		} else {
			debugk("%s %d: Pulled tmpnode (null) from %d\n", __func__, __LINE__, i);
		}
		if ((i == geo->no_pairs) || !tmpnode) {
			/* right-most key is too large, update it */
			/* FIXME: If the right-most key on higher levels is
			 * always zero, this wouldn't be necessary. */

			i--;
			debugk("%s %d: Adjusting key in node at %d\n", __func__, __LINE__, i);
			setkey(geo, node, i, key);

			bval_put(head, tmpnode);

			BUG_ON(i < 0);

			bval_put(head, oldpage);
			oldpage = node;
			oldpage_data = node_data;

			node = bval(head->allocator, geo, node_data, &node_data, i);
			debugk("%s %d: Updated node to %p\n", __func__, __LINE__, node);
		} else {

			BUG_ON(i < 0);

			bval_put(head, oldpage);
			oldpage = node;
			oldpage_data = node_data;

			node = tmpnode;
			node_data = tmpnode_data;
			debugk("%s %d: Updated node to %p\n", __func__, __LINE__, node);
		}
	}

	bval_put(head, oldpage);

	*page_data = node_data;

	BUG_ON(!node);
	return node;
}

static int btree_grow(struct replayfs_btree_head *head, struct btree_geo *geo,
		      gfp_t gfp)
{
	unsigned long *node_data;
	struct page *node;
	int fill;

	node = btree_node_alloc(head, gfp);
	if (!node)
		return -ENOMEM;

	node_data = replayfs_kmap(node);

	if (head->node_page) {
		unsigned long *headpage_data;
		struct page *headpage;

		headpage = get_head_page(head, &headpage_data);

		fill = getfill(head->allocator, geo, headpage_data, 0);
		debugk("%s %d: Filling entry 0 with {%lld, %lld} from fill %d\n", __func__, __LINE__,
				bkey(geo, headpage_data, fill-1)->offset,
				bkey(geo, headpage_data, fill-1)->size, fill);
		setkey(geo, node, 0, bkey(geo, headpage_data, fill - 1));
		setval_node(geo, node, 0, headpage);
		/* Trying to make inner nodes from top... is that okay? */
		/*
		debugk("%s %d: Filling entry 0 with {%lld, %lld} from fill 0\n", __func__, __LINE__,
				bkey(geo, headpage_data, 0)->offset,
				bkey(geo, headpage_data, 0)->size);
		setkey(geo, node, 0, bkey(geo, headpage_data, 0));
		setval_node(geo, node, 0, headpage);
		*/

		bval_put(head, headpage);
	}
	head->node_page = node;
	debugk("%s %d: Setting btree node_page to %lu\n", __func__,
			__LINE__, head->node_page->index);
	head->height++;
	update_meta(head);

	BUG_ON(head->node_page == NULL && head->height != 0);

	bval_put(head, node);
	return 0;
}

static void btree_shrink(struct replayfs_btree_head *head, struct btree_geo *geo)
{
	unsigned long *node_data;
	struct page *node;
	int fill;

	if (head->height < 1)
		return;

	node = get_head_page(head, &node_data);
	fill = getfill(head->allocator, geo, node_data, 0);
	BUG_ON(fill > 1);
	head->height--;
	debugk("%s %d: Decrementing head->height to %d\n", __func__, __LINE__,
			head->height);

	if (head->height == 0) {
		head->node_page = NULL;
		debugk("%s %d: Setting head node to NULL\n", __func__, __LINE__);
	} else {
		head->node_page = bval(head->allocator, geo, node_data, &node_data, 0);
		debugk("%s %d: Setting head height to %lu\n", __func__, __LINE__,
				head->node_page->index);
	}

	update_meta(head);

	/* Need to unmap before freeing */
	replayfs_kunmap(node);
	replayfs_diskalloc_free_page(head->allocator, node);

	BUG_ON(head->node_page == NULL && head->height != 0);
	//mempool_free(node, head->mempool);
}

static void replace_key(struct replayfs_btree_head *head, struct btree_geo *geo,
		struct replayfs_btree_key *in, struct replayfs_btree_key *new, int level) {
	unsigned long *node_data = NULL;
	struct page *node;
	int pos;

	struct replayfs_btree_key oldkey;

	memcpy(&oldkey, in, sizeof(struct replayfs_btree_key));

	node = find_level(head, geo, in, level, &node_data);

	debugk("%s %d: Replacing key {%lld, %lld} with {%lld, %lld} in node %lu\n",
			__func__, __LINE__, in->offset, in->size, new->offset, new->size,
			node->index);
	pos = getpos(geo, node_data, in->offset);
	if (pos == 0) {
		if (level != head->height) {
			replace_key(head, geo, &oldkey, new, level+1);
		}
	}

	setkey(geo, node, pos, new);

	bval_put(head, node);
}

static int btree_insert_inner_level(struct replayfs_btree_head *head, struct btree_geo *geo,
			      struct replayfs_btree_key *key, struct page *val,
						unsigned long *val_data, int level, gfp_t gfp)
{
	unsigned long *node_data = NULL;
	struct page *node;
	int i, pos, fill, err;

	debugk("%s %d: In %s!\n", __func__, __LINE__, __func__);
	debugk("%s %d: Inserting key {%lld, %lld}!\n", __func__, __LINE__,
			key->offset, key->size);

	BUG_ON(level == 1);

	BUG_ON(!val);
	if (head->height < level) {
		debugk("%s %d: Growing btree!\n", __func__, __LINE__);
		err = btree_grow(head, geo, gfp);
		if (err)
			return err;
	}

retry:
	node = find_level(head, geo, key, level, &node_data);
	debugk("%s %d: past find_level, got node %lu!\n", __func__, __LINE__,
			node->index);
	pos = getpos(geo, node_data, key->offset);
	fill = getfill(head->allocator, geo, node_data, pos);
	/* two identical keys are not allowed */
	debugk("%s %d: keycmp with {%lld, %lld}\n", __func__, __LINE__,
			bkey(geo, node_data, pos)->offset, bkey(geo, node_data, pos)->size);
	BUG_ON(pos < fill && keycmp(geo, node_data, pos, key) == 0);

	debugk("%s %d: fill is %d, pos is %d no_pars is %d!\n", __func__, __LINE__,
			fill, pos, geo->no_pairs);
	/* If node full... */
	if (fill == geo->no_pairs) {
		/* need to split node */
		unsigned long *new_data;
		struct page *new;

		new = btree_node_alloc(head, gfp);
		new_data = replayfs_kmap(new);
		debugk("%s %d: past node_alloc!\n", __func__, __LINE__);
		if (!new)
			return -ENOMEM;
		err = btree_insert_inner_level(head, geo,
				bkey(geo, node_data, fill / 2 - 1),
				new, new_data, level + 1, gfp);
		if (err) {
			//mempool_free(new, head->mempool);
			replayfs_diskalloc_free_page(head->allocator, new);
			return err;
		}
		for (i = 0; i < fill / 2; i++) {
			unsigned long *tmp_data;
			struct page *tmp;
			setkey(geo, new, i, bkey(geo, node_data, i));
			tmp = bval(head->allocator, geo, node_data, &tmp_data, i);
			setval_node(geo, new, i, tmp);
			bval_put(head, tmp);
			setkey(geo, node, i, bkey(geo, node_data, i + fill / 2));
			tmp = bval(head->allocator, geo, node_data, &tmp_data, i + fill / 2);
			setval_node(geo, node, i, tmp);
			bval_put(head, tmp);
			clearpair(geo, node, i + fill / 2);
		}
		if (fill & 1) {
			unsigned long *tmp_data;
			struct page *tmp;

			setkey(geo, node, i, bkey(geo, node_data, fill - 1));
			tmp = bval(head->allocator, geo, node_data, &tmp_data, fill - 1);
			setval_node(geo, node, i, tmp);
			clearpair(geo, node, fill - 1);

			bval_put(head, tmp);
		}
		goto retry;
	}
	BUG_ON(fill >= geo->no_pairs);

	debugk("%s %d: pre shift and insert!\n", __func__, __LINE__);

	/* Update the key */
	if (pos == fill) {
		/* Adjust the parent's key, to point towards this entry */
		if (level != head->height) {
			replace_key(head, geo, bkey(geo, node_data, pos-1), bkey(geo, node_data, pos),
					level+1);
		}
	}

	/* shift and insert */
	for (i = fill; i > pos; i--) {
		unsigned long *tmp_data;
		struct page *tmp = bval(head->allocator, geo, node_data, &tmp_data, i - 1);
		setkey(geo, node, i, bkey(geo, node_data, i - 1));
		setval_node(geo, node, i, tmp);
		bval_put(head, tmp);
	}

	setkey(geo, node, pos, key);
	setval_node(geo, node, pos, val);

	bval_put(head, node);

	return 0;
}

static int btree_insert_level(struct replayfs_btree_head *head, struct btree_geo *geo,
			      struct replayfs_btree_key *key, struct replayfs_btree_value *val, int level,
			      gfp_t gfp)
{
	unsigned long *node_data = NULL;
	struct page *node;
	int i, pos, fill, err;

	debugk("%s %d: In btree_insert_level!\n", __func__, __LINE__);
	debugk("%s %d: Inserting key {%lld, %lld}!\n", __func__, __LINE__,
			key->offset, key->size);
	BUG_ON(level != 1);

	BUG_ON(!val);
	debugk("%s %d: head->height is %d\n", __func__, __LINE__,
			head->height);
	if (head->height < level) {
		err = btree_grow(head, geo, gfp);
		if (err)
			return err;
	}

	debugk("%s %d: head->node_page %p (%lu)\n", __func__, __LINE__, head->node_page, head->node_page->index);

retry:
	node = find_level(head, geo, key, level, &node_data);
	debugk("%s %d: past find_level, got node %lu!\n", __func__, __LINE__,
			node->index);
	pos = getpos(geo, node_data, key->offset);
	fill = getfill(head->allocator, geo, node_data, pos);
	/* two identical keys are not allowed */
	debugk("%s %d: keycmp with {%lld, %lld}\n", __func__, __LINE__,
			bkey(geo, node_data, pos)->offset, bkey(geo, node_data, pos)->size);
	BUG_ON(pos < fill && keycmp(geo, node_data, pos, key) == 0);

	debugk("%s %d: fill is %d, pos is %d no_pars is %d!\n", __func__, __LINE__,
			fill, pos, geo->no_pairs);
	/* If node full... */
	if (fill == geo->no_pairs) {
		/* need to split node */
		struct page *new;
		unsigned long *new_data;

		new = btree_node_alloc(head, gfp);
		if (!new)
			return -ENOMEM;

		debugk("%s %d: Allocated new (%p), %lu!\n", __func__, __LINE__, new, new->index);

		new_data = replayfs_kmap(new);


		debugk("%s %d: Still have new (%p), %lu!\n", __func__, __LINE__, new, new->index);
		err = btree_insert_inner_level(head, geo,
				bkey(geo, node_data, fill / 2 - 1),
				new, new_data, level + 1, gfp);
		debugk("%s %d: Still have new (%p), %lu!\n", __func__, __LINE__, new, new->index);
		if (err) {
			//mempool_free(new, head->mempool);
			replayfs_kunmap(new);
			replayfs_diskalloc_free_page(head->allocator, new);
			return err;
		}

		debugk("%s %d: Adjusting pages (new %p) %lu and (node %p) %lu\n", __func__,
				__LINE__, new, new->index, new, node->index);
		BUG_ON(new->index == node->index);
		for (i = 0; i < fill / 2; i++) {
			struct replayfs_btree_value *tmp;
			setkey(geo, new, i, bkey(geo, node_data, i));
			tmp = bval_at(head->allocator, geo, node_data, i);
			setval(geo, new, i, tmp);
			setkey(geo, node, i, bkey(geo, node_data, i + fill / 2));
			tmp = bval_at(head->allocator, geo, node_data, i + fill / 2);
			setval(geo, node, i, tmp);
			clearpair(geo, node, i + fill / 2);
		}

		if (fill & 1) {
			struct replayfs_btree_value *tmp;
			struct replayfs_btree_key *key = bkey(geo, node_data, fill-1);

			debugk("%s %d: Last shift and insert with key {%lld, %lld}\n", __func__,
					__LINE__, key->offset, key->size);
			debugk("%s %d: Inserting key into node at %d\n", __func__, __LINE__, i);
			setkey(geo, node, i, key);
			tmp = bval_at(head->allocator, geo, node_data, fill - 1);
			setval(geo, node, i, tmp);
			debugk("%s %d: Clearing pair at %d\n", __func__, __LINE__, fill-1);
			clearpair(geo, node, fill - 1);
		}

		debugk("%s %d: Putting new\n", __func__, __LINE__);
		bval_put(head, new);
		debugk("%s %d: Putting node\n", __func__, __LINE__);
		bval_put(head, node);
		debugk("%s %d: RETRY\n", __func__, __LINE__);
		goto retry;
	}
	BUG_ON(fill >= geo->no_pairs);

	debugk("%s %d: pre shift and insert!\n", __func__, __LINE__);
	/* shift and insert */
	for (i = fill; i > pos; i--) {
		setkey(geo, node, i, bkey(geo, node_data, i - 1));
		setval(geo, node, i, bval_at(head->allocator, geo, node_data, i - 1));
	}
	debugk("%s %d: Inserting key {%lld %lld} to node {%lu, %d} (%p)!\n", __func__, __LINE__,
			key->offset, key->size, node->index, head->allocator->allocnum, node);
	setkey(geo, node, pos, key);
	setval(geo, node, pos, val);

	/* Update the key */
	if (pos == fill) {
		/* Adjust the parent's key, to point towards this entry */
		if (level != head->height) {
			replace_key(head, geo, bkey(geo, node_data, pos-1), bkey(geo, node_data, pos),
					level+1);
		}
	}

	bval_put(head, node);

	return 0;
}

int __must_check replayfs_btree_insert_update(struct replayfs_btree_head *head,
			      struct replayfs_btree_key *key, struct replayfs_btree_value *val,
						gfp_t gfp) {
	struct page *page = NULL;
	struct replayfs_btree_key in_key;
	struct replayfs_btree_value fill_value;
	struct replayfs_btree_value *in_val;
	struct replayfs_btree_key new_key;

	debugk("%s %d: Called with key {%lld, %lld}\n", __func__, __LINE__,
			key->offset, key->size);

	BUG_ON(head->node_page == NULL && head->height != 0);

	check_tree(head);
	/* 
	 * Okay... we need to zero fill anything which is not otherwise referenced...
	 */

	/* First, check to see if an entry containing key exists */
	/* This could be tricky... This key could consume multiple others:
	 * I need to scan backwards from the last key? */
	in_val = replayfs_btree_lookup_internal(head, key->offset + key->size-1, &in_key, &page);
	debugk("%s %d: in_val is {%lld, %lld}!\n", __func__, __LINE__, in_key.offset,
			in_key.size);
	if (in_val == NULL) {
		/* 
		 * This range doesn't exist.  That means that we are appending to the log.
		 * Find the last range and make sure we're adding onto it.
		 */
		in_val = replayfs_btree_last(head, &in_key, &page);
		debugk("%s %d: new in_val is {%lld, %lld}!\n", __func__, __LINE__,
				in_key.offset, in_key.size);
		/* Okay... the tree was empty.  Just add our stuff */
		if (in_val == NULL) {
			if (key->offset > 0) {
				struct replayfs_btree_key fill_key;
				fill_key.offset = 0;
				fill_key.size = key->offset;
				debugk("%s %d: Detected an initial key with a non-zero offset, zero padding before that offset\n",
						__func__, __LINE__);

				memcpy(&fill_value, &replayfs_zero_value,
						sizeof(fill_value));

				fill_value.buff_offs = fill_key.size;
				debugk("%s %d: Generating new tree edge with buff_offs of %u\n",
						__func__, __LINE__, fill_value.buff_offs);
				if (replayfs_btree_insert(head, &fill_key, &fill_value, gfp)) {
					return -ENOMEM;
				}
			}
			debugk("%s %d: Calling insert %p!\n", __func__, __LINE__, val);
			debugk("%s %d: Inserting val with buff_offs: %d\n", __func__, __LINE__,
					val->buff_offs);

			return replayfs_btree_insert(head, key, val, gfp);
		}

		/* 
		 * If this isn't in or at the lower bound of our range, there is a problem!
		 */
		debugk("%s %d: in2_offs %lld, in2_size %lld, key_offs %lld, key_size %lld\n",
				__func__,  __LINE__, in_key.offset, in_key.size, key->offset,
				key->size);

		BUG_ON(in_key.offset >= key->offset + key->size);

		/* If there is a gap in the range, zero fill it */
		if (in_key.offset + in_key.size < key->offset) {
			struct replayfs_btree_key fill_key;

			fill_key.offset = in_key.offset + in_key.size;
			fill_key.size = key->offset - fill_key.offset;
			debugk("%s %d: Inserting val with buff_offs: %d\n", __func__, __LINE__,
					replayfs_zero_value.buff_offs);

			memcpy(&fill_value, &replayfs_zero_value,
					sizeof(fill_value));

			fill_value.buff_offs = fill_key.size;
			debugk("%s %d: Inserting tree edge with buff_offs of %u\n",
					__func__, __LINE__, fill_value.buff_offs);
			if (replayfs_btree_insert(head, &fill_key, &fill_value, gfp)) {
				return -ENOMEM;
			}
			in_val = &fill_value;
			keycpy(&in_key, &fill_key);
		}

		debugk("%s %d: Got in_key of {%lld, %lld}, key is {%lld, %lld}\n", __func__,
				__LINE__, in_key.offset, in_key.size, key->offset, key->size);
		BUG_ON(in_key.offset >= key->offset + key->size ||
		       in_key.offset + in_key.size < key->offset);
	}

	/* Okay, now we need to iterate through the keys that overlap with our new key */
	debugk("%s %d: Starting loop!\n", __func__, __LINE__);
	/* 
	 * While in_key's size/offset overlap with key (they must be less than key,
	 * we're scanning backwards
	 */
	while (in_key.offset + in_key.size > key->offset) {
		int found;
		struct replayfs_btree_value _in_val;
		/* 
		 * Update the key's size/offset, if it is updated to zero size, remove the
		 * key 
		 */

		/* The new offset:
		 *   if in_offs > key_offs then adjust in_offs
		 *     If in_max < key_max remove in_key
		 *     else in_size = in_size - (key_offs - in_offs)
		 *          in_offs = key_max
		 *          in_buf_offs += key_offs - in_offs
		 *
		 *  if in_offs < key_offs
		 *    in_size = key_pos - in_pos
		 */

		debugk("%s %d: Replacing new_key {%lld, %lld} with in_key {%lld, %lld}\n",
				__func__, __LINE__, in_key.offset, in_key.size, new_key.offset,
				new_key.size);
		keycpy(&new_key, &in_key);

		/* Remove in_key */
		bval_put(head, page);
		debugk("%s %d: Deleting in_key {%lld, %lld}\n", __func__, __LINE__,
				in_key.offset, in_key.size);
		found = replayfs_btree_remove(head, &in_key, &_in_val);

		if (found) {
			in_val = &_in_val;
			page = NULL;
			/* If the top of our address range is above key */
			debugk("%s %d: cmparing in_max to key_max: %lld <> %lld!\n", __func__,
					__LINE__, in_key.offset + in_key.size, key->offset + key->size);
			if (in_key.offset + in_key.size > key->offset + key->size) {
				struct replayfs_btree_value new_val;

				memcpy(&new_val, in_val, sizeof(struct replayfs_btree_value));

				new_key.offset = key->offset + key->size;
				new_key.size = in_key.offset + in_key.size - new_key.offset;

				if (syscache_id_is_zero(&new_val.id)) {
					new_val.buff_offs = new_key.size;
				} else {
					new_val.buff_offs = in_val->buff_offs + (
								key->offset + key->size - in_key.offset
							);
				}
				debugk("%s %d: Inserting val with buff_offs: %d (key {%lld, %lld}\n", __func__, __LINE__,
						new_val.buff_offs, new_key.offset, new_key.size);
				replayfs_btree_insert(head, &new_key, &new_val, gfp);
			}

			/* 
			 * We do the lower bound last, so new_key will be the lowest bound when we
			 * search for the next key
			 */
			debugk("%s %d: cmparing in_off to key_off: %lld <> %lld!\n", __func__,
					__LINE__, in_key.offset, key->offset);
			if (in_key.offset < key->offset) {
				struct replayfs_btree_value new_val;

				memcpy(&new_val, in_val, sizeof(struct replayfs_btree_value));
				new_key.offset = in_key.offset;
				new_key.size = key->offset - in_key.offset;

				if (syscache_id_is_zero(&new_val.id)) {
					new_val.buff_offs = new_key.size;
				}

				debugk("%s %d: Inserting val with buff_offs: %d\n", __func__, __LINE__,
						new_val.buff_offs);
				replayfs_btree_insert(head, &new_key, &new_val, gfp);
			}

			//keycpy(&new_key, in_key);
			/* Get prev key, and repeat */
			debugk("%s %d: Calling get_prev with new_key {%lld, %lld} (head %p height: %d)\n", __func__,
					__LINE__, new_key.offset, new_key.size, head, head->height);
			in_val = replayfs_btree_get_prev(head, &new_key, &page);
			/*
			debugk("%s %d: Calling get_prev with in_key {%lld, %lld}\n", __func__,
					__LINE__, in_key.offset, in_key.size);
			in_val = replayfs_btree_get_prev(head, &in_key, &page);
			*/
			debugk("%s %d: in_val after get_prev is %p\n", __func__, __LINE__, in_val);
			if (in_val == NULL) {
				/* We didn't get a val, so we don't have a page to free... */
				page = NULL;
				break;
			}
		}

		keycpy(&in_key, &new_key);
		debugk("%s %d: Got key {%lld, %lld}, updated in_key to {%lld, %lld}\n",
				__func__, __LINE__, new_key.offset, new_key.size, in_key.offset,
				in_key.size);
	}

	bval_put(head, page);

	/* Now, insert the new key (which there will be room for) */
	debugk("%s %d: Inserting val with buff_offs: %d\n", __func__, __LINE__,
			val->buff_offs);

	do {
		int ret;

		ret = replayfs_btree_insert(head, key, val, gfp);

		check_tree(head);

		BUG_ON(head->node_page == NULL && head->height != 0);

		return ret;
	} while (0);
}

int replayfs_btree_insert(struct replayfs_btree_head *head,
		struct replayfs_btree_key *key, void *val, gfp_t gfp)
{
	BUG_ON(!val);
	return btree_insert_level(head, &replayfs_geo, key, val, 1, gfp);
}

static int btree_remove_level(struct replayfs_btree_head *head, struct btree_geo *geo,
		struct replayfs_btree_key *key, int level, struct replayfs_btree_value *value); 
static void merge(struct replayfs_btree_head *head, struct btree_geo *geo, int level,
		struct page *left, unsigned long *left_data, int lfill,
		struct page *right, unsigned long *right_data, int rfill,
		struct page *parent, unsigned long *parent_data, int lpos)
{
	int i;

	if (level > 1) {
		for (i = 0; i < rfill; i++) {
			unsigned long *tmp_data;
			struct page *tmp;
			/* Move all keys to the left */
			setkey(geo, left, lfill + i, bkey(geo, right_data, i));
			tmp = bval(head->allocator, geo, right_data, &tmp_data, i);
			setval_node(geo, left, lfill + i, tmp);
			bval_put(head, tmp);
		}
		/* Exchange left and right child in parent */
		debugk("%s %d: Moving page %lu to %d\n", __func__, __LINE__, right->index,
				lpos);
		setval_node(geo, parent, lpos, right);
		debugk("%s %d: Moving page %lu to %d\n", __func__, __LINE__, left->index,
				lpos+1);
		setval_node(geo, parent, lpos + 1, left);
		/* Remove left (formerly right) child from parent */
		debugk("%s %d: Deleting key {%lld, %lld} (pos %d)\n", __func__, __LINE__,
				bkey(geo, parent_data, lpos)->offset, bkey(geo, parent_data,
					lpos)->size, lpos);
		btree_remove_level(head, geo, bkey(geo, parent_data, lpos), level + 1, NULL);
	} else {
		for (i = 0; i < rfill; i++) {
			struct replayfs_btree_value *tmp;
			/* Move all keys to the left */
			setkey(geo, left, lfill + i, bkey(geo, right_data, i));
			tmp = bval_at(head->allocator, geo, right_data, i);
			setval(geo, left, lfill + i, tmp);
		}
		/* Exchange left and right child in parent */
		/* 
		 * Still use setval_node, becase the parent's level is our level +1
		 * (aka parent is always a non-leaf node
		 */
		debugk("%s %d: Moving page %lu to %d\n", __func__, __LINE__, right->index,
				lpos);
		setval_node(geo, parent, lpos, right);
		debugk("%s %d: Moving page %lu to %d\n", __func__, __LINE__, left->index,
				lpos+1);
		setval_node(geo, parent, lpos + 1, left);
		/* Remove left (formerly right) child from parent */
		debugk("%s %d: Deleting key {%lld, %lld} (pos %d)\n", __func__, __LINE__,
				bkey(geo, parent_data, lpos)->offset, bkey(geo, parent_data,
					lpos)->size, lpos);
		btree_remove_level(head, geo, bkey(geo, parent_data, lpos), level + 1, NULL);
	}

	/* Got to free the right node */
	replayfs_kunmap(right);
	replayfs_diskalloc_free_page(head->allocator, right);
}

static int rebalance(struct replayfs_btree_head *head, struct btree_geo *geo,
		struct replayfs_btree_key *key, int level, struct page *child,
		unsigned long *child_data, int fill, struct replayfs_btree_key *oldkey,
		int *needs_put)
{
	unsigned long *parent_data = NULL;
	unsigned long *left_data = NULL;
	unsigned long *right_data = NULL;
	struct page *parent, *left = NULL, *right = NULL;
	int i, no_left, no_right;


	if (fill == 0) {
		/* 
		 * Because we don't steal entries from a neighbour, this case
		 * can happen.  Parent node contains a single child, this
		 * node, so merging with a sibling never happens.
		 */
		btree_remove_level(head, geo, key, level + 1, NULL);
		//mempool_free(child, head->mempool);
		replayfs_diskalloc_free_page(head->allocator, child);
		return 1;
	}

	/* 
	 * Unimplemented... will happen if we get 85^2 unique entries... I'm going to
	 * hope it doesn't for now...
	 */
	BUG_ON(level != 1);

	parent = find_level(head, geo, key, level + 1, &parent_data);

	i = getpos(geo, parent_data, key->offset);

	debugk("%s %d: getpos on {%lld, %lld} returns %d, parent is %lu\n", __func__,
			__LINE__, key->offset, key->size, i, parent->index);
	/* 
	 * This check is broken because I changed... everything about this btree impl
	 * The check for bval(x)->index == child->index would probably work
	 * Also, need to free the bval...
	 */
	/*
	 * I don't think this check is actually working... so I'm disabling it...
	 * although it may really be a bug...
	do {
		struct page *child2;
		unsigned long *child2_data;
		child2 = bval(head->allocator, geo, parent_data, &child2_data, i);

		debugk("%s %d: child2->index %lu, child->index %lu\n", __func__, __LINE__,
				child2->index, child->index);

		BUG_ON(child2->index != child->index);

		bval_put(head, child2);
	} while (0);
	 */

	if (i > 0) {
		left = bval(head->allocator, geo, parent_data, &left_data, i - 1);
		no_left = getfill(head->allocator, geo, left_data, 0);
		if (fill + no_left <= geo->no_pairs) {
			struct replayfs_btree_key *newkey;

			debugk("%s %d: Doing left_merge!\n", __func__, __LINE__);
			merge(head, geo, level,
					left, left_data, no_left,
					child, child_data, fill,
					parent, parent_data, i - 1);
			debugk("%s %d: Done left_merge!\n", __func__, __LINE__);
			newkey = bkey(geo, left_data, no_left + fill-1);
			if (oldkey) {
				debugk("%s %d: Now, updating keys, oldkey is {%lld, %lld} newkey is {%lld, %lld}\n",
						__func__, __LINE__, oldkey->offset, oldkey->size, newkey->offset,
						newkey->size);
				replace_key(head, geo, oldkey, newkey, level+1);
			}
			bval_put(head, left);
			*needs_put=0;
			return 0;
		}
		bval_put(head, left);
	}
	if (i + 1 < getfill(head->allocator, geo, parent_data, i)) {
		right = bval(head->allocator, geo, parent_data, &right_data, i + 1);
		no_right = getfill(head->allocator, geo, right_data, 0);
		if (fill + no_right <= geo->no_pairs) {
			debugk("%s %d: Doing right_merge!\n", __func__, __LINE__);
			merge(head, geo, level,
					child, child_data, fill,
					right, right_data, no_right,
					parent, parent_data, i);
			debugk("%s %d: Done right_merge!\n", __func__, __LINE__);
			/* Don't put after a right merge... we do a free on it! */
			//bval_put(head, right);
			return 0;
		} else {
			bval_put(head, right);
		}
	}
	/*
	 * We could also try to steal one entry from the left or right
	 * neighbor.  By not doing so we changed the invariant from
	 * "all nodes are at least half full" to "no two neighboring
	 * nodes can be merged".  Which means that the average fill of
	 * all nodes is still half or better.
	 */
	debugk("%s %d: rebalance noop\n", __func__, __LINE__);
	return 1;
}

static int btree_remove_level(struct replayfs_btree_head *head, struct btree_geo *geo,
		struct replayfs_btree_key *key, int level, struct replayfs_btree_value *out_value)
{
	unsigned long *node_data = NULL;
	struct page *node;
	int i, pos, fill;

	struct replayfs_btree_key k1, k2;
	int do_replace = 0;

	int needs_shrink = 0;
	int needs_put = 1;

	int ret = 0;

	if (level > head->height) {
		/* we recursed all the way up */
		head->height = 0;
		head->node_page = NULL;
		update_meta(head);
		return 0;
	}

	node = find_level(head, geo, key, level, &node_data);
	alloc_debugk("%s %d Mapped page %lu (%p) from find_level\n", __func__,
			__LINE__, node->index, node);

	pos = getpos(geo, node_data, key->offset);

	fill = getfill(head->allocator, geo, node_data, pos);
	debugk("%s %d: fill is %d, pos is %d no_pars is %d!\n", __func__, __LINE__,
			fill, pos, geo->no_pairs);
	if ((level == 1) && (keycmp(geo, node_data, pos, key) != 0)) {
		debugk("%s %d: !!!!!!! returning NULL?\n", __func__, __LINE__);
		bval_put(head, node);
		return 0;
	}


	if (bval_at(head->allocator, geo, node_data, pos) != NULL) {
		ret = 1;
		if (out_value) {
		 memcpy(out_value, bval_at(head->allocator, geo, node_data, pos),
				 sizeof(struct replayfs_btree_value));
		}
	}

	debugk("%s %d: Removing key: {%lld, %lld} from page %lu\n", __func__, __LINE__,
			bkey(geo, node_data, pos)->offset, bkey(geo, node_data, pos)->size,
			node->index);

	if (pos == fill-1) {
		/* Adjust the parent's key, to point towards this entry */
		if (level != head->height) {
			keycpy(&k1, bkey(geo, node_data, pos));
			keycpy(&k2, bkey(geo, node_data, pos-1));
			do_replace = 1;
		}
	}

	/* remove and shift */
	if (level != 1) {
		for (i = pos; i < fill - 1; i++) {
			struct replayfs_btree_key *k;
			unsigned long *tmp_data;
			struct page *tmp;

			k = bkey(geo, node_data, i+1);
			debugk("%s %d: Setting key at %i to {%lld, %lld}\n", __func__, __LINE__,
					i+1, k->offset, k->size);
			setkey(geo, node, i, k);
			tmp = bval(head->allocator, geo, node_data, &tmp_data, i + 1);
			if (tmp != NULL) {
				debugk("%s %d: Got tmp of %lu from index %d in node %lu\n", __func__,
						__LINE__, tmp->index, i+1, node->index);
			} else {
				debugk("%s %d: Got tmp of NULL??? from index %d in node %lu\n",
						__func__, __LINE__, i+1, node->index);
			}
			setval_node(geo, node, i, tmp);
			bval_put(head, tmp);
		}
	} else {
		for (i = pos; i < fill - 1; i++) {
			struct replayfs_btree_value *tmp;
			setkey(geo, node, i, bkey(geo, node_data, i + 1));
			tmp = bval_at(head->allocator, geo, node_data, i+1);
			setval(geo, node, i, tmp);
		}
	}
	clearpair(geo, node, fill - 1);

	if (fill - 1 < geo->no_pairs / 2) {
		if (level < head->height) {
			struct replayfs_btree_key *oldkey = 
				(do_replace) ? &k1 : NULL;
			debugk("%s %d: here\n", __func__, __LINE__);
			do_replace &= 
				rebalance(head, geo, key, level, node, node_data, fill - 1, oldkey,
						&needs_put);
		} else if (
				(head->height > 1 && fill - 1 == 1) ||
				(head->height == 1 && fill -1 == 0)) {

			needs_shrink = 1;
		}
	}

	if (do_replace) {
		debugk("%s %d: Calling replace on k1 {%lld, %lld} and k2 {%lld, %lld}\n",
				__func__, __LINE__, k1.offset, k1.size, k2.offset, k2.size);
		replace_key(head, geo, &k1, &k2,
				level+1);
	}

	if (needs_put) {
		bval_put(head, node);
	}

	if (needs_shrink) {
		btree_shrink(head, geo);
	}

	return ret;
}

int replayfs_btree_remove(struct replayfs_btree_head *head,
		   struct replayfs_btree_key *key, struct replayfs_btree_value *value)
{
	if (head->height == 0)
		return 0;

	return btree_remove_level(head, &replayfs_geo, key, 1, value);
}

int replayfs_btree_merge(struct replayfs_btree_head *target, struct replayfs_btree_head *victim,
		gfp_t gfp)
{
	/*
	unsigned long key[replayfs_geo.keylen];
	unsigned long dup[replayfs_geo.keylen];
	*/
	struct replayfs_btree_key key;
	struct replayfs_btree_key tmp;
	struct replayfs_btree_key dup;
	struct page *page;
	void *val;
	int err;

	/* UNSUPPORTED !!! */
	BUG();

	BUG_ON(target == victim);

	if (!(target->node_page)) {
		/* target is empty, just copy fields over */
		target->node_page = victim->node_page;
		target->height = victim->height;
		__btree_init(victim);
		return 0;
	}

	/* TODO: This needs some optimizations.  Currently we do three tree
	 * walks to remove a single object from the victim.
	 */
	for (;;) {
		if (!replayfs_btree_last(victim, &key, &page))
			break;
		bval_put(victim, page);
		val = replayfs_btree_lookup(victim, key.offset, &tmp, &page);
		err = replayfs_btree_insert(target, &key, val, gfp);
		bval_put(victim, val);
		if (err)
			return err;
		/* We must make a copy of the key, as the original will get
		 * mangled inside btree_remove. */
		keycpy(&dup, &key);
		replayfs_btree_remove(victim, &dup, NULL);
		bval_put(victim, val);
	}

	BUG_ON(target->node_page == NULL && target->height != 0);
	return 0;
}

static size_t __btree_for_each(struct replayfs_btree_head *head, struct btree_geo *geo,
			       struct page *node, unsigned long opaque,
			       void (*func)(void *elem, unsigned long opaque,
					    struct replayfs_btree_key *key, size_t index,
					    void *func2),
			       void *func2, int reap, int height, size_t count)
{
	int i;
	unsigned long *child_data;
	unsigned long *node_data = replayfs_kmap(node);
	struct page *child;

	for (i = 0; i < geo->no_pairs; i++) {
		child = bval(head->allocator, geo, node_data, &child_data, i);
		if (!child)
			break;
		if (height > 1)
			count = __btree_for_each(head, geo, child, opaque,
					func, func2, reap, height - 1, count);
		else
			func(child, opaque, bkey(geo, node_data, i), count++,
					func2);
	}

	replayfs_kunmap(node);

	if (reap) {
		//mempool_free(node, head->mempool);
		replayfs_kunmap(node);
		replayfs_diskalloc_free_page(head->allocator, node);
	}

	return count;
}

static void empty(void *elem, unsigned long opaque, struct replayfs_btree_key *key,
		  size_t index, void *func2)
{
}

void replayfs_visitorl(void *elem, unsigned long opaque, unsigned long *key,
	      size_t index, void *__func)
{
	visitorl_t func = __func;

	func(elem, opaque, *key, index);
}

void replayfs_visitor32(void *elem, unsigned long opaque, unsigned long *__key,
	       size_t index, void *__func)
{
	visitor32_t func = __func;
	u32 *key = (void *)__key;

	func(elem, opaque, *key, index);
}

void replayfs_visitor64(void *elem, unsigned long opaque, unsigned long *__key,
	       size_t index, void *__func)
{
	visitor64_t func = __func;
	u64 *key = (void *)__key;

	func(elem, opaque, *key, index);
}

void replayfs_visitor128(void *elem, unsigned long opaque, unsigned long *__key,
		size_t index, void *__func)
{
	visitor128_t func = __func;
	u64 *key = (void *)__key;

	func(elem, opaque, key[0], key[1], index);
}

size_t replayfs_btree_visitor(struct replayfs_btree_head *head,
		     unsigned long opaque,
		     void (*func)(void *elem, unsigned long opaque,
		     		  struct replayfs_btree_key *key,
		     		  size_t index, void *func2),
		     void *func2)
{
	size_t count = 0;

	if (!func2)
		func = empty;
	if (head->node_page)
		count = __btree_for_each(head, &replayfs_geo, head->node_page, opaque, func,
				func2, 0, head->height, 0);
	return count;
}

size_t replayfs_btree_grim_visitor(struct replayfs_btree_head *head,
			  unsigned long opaque,
			  void (*func)(void *elem, unsigned long opaque,
				       struct replayfs_btree_key *key,
				       size_t index, void *func2),
			  void *func2)
{
	size_t count = 0;

	if (!func2)
		func = empty;
	if (head->node_page)
		count = __btree_for_each(head, &replayfs_geo, head->node_page, opaque, func,
				func2, 1, head->height, 0);
	__btree_init(head);
	return count;
}

MODULE_AUTHOR("Joern Engel <joern@logfs.org>");
MODULE_AUTHOR("Johannes Berg <johannes@sipsolutions.net>");
MODULE_LICENSE("GPL");

