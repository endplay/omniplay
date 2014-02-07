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

//#include "replayfs_fs.h"
//#include "replayfs_inode.h"

//#define REPLAYFS_BTREE_DEBUG

#ifdef REPLAYFS_BTREE_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

#define LONG_PER_U64 (64 / BITS_PER_LONG)

#define MAX(a, b) ((a) > (b) ? (a) : (b))
/* #define NODESIZE MAX(L1_CACHE_BYTES, 128) */
#define NODESIZE MAX(L1_CACHE_BYTES, PAGE_SIZE)

struct replayfs_btree_value replayfs_zero_value = {
	.id = {
		.unique_id = -1,
		.sysnum = -1,
		.mod = 0
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

static struct page *btree_node_alloc(struct replayfs_btree_head *head, gfp_t gfp)
{
	struct page *page = NULL;

	page = replayfs_diskalloc_alloc_page(head->allocator);
	if (likely(page && !IS_ERR(page))) {
		void *addr = kmap(page);
		if (IS_ERR(addr)) {
			BUG();
		}
		memset(addr, 0, NODESIZE);
		//__set_page_dirty_nobuffers(page);
		SetPageDirty(page);
		kunmap(page);
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
	debugk("%s %d: Reading bval with offset %lld\n", __func__,
			__LINE__, pageoffs);

	/* Get page of next node from offset */
	page = replayfs_diskalloc_get_page(allocator, pageoffs);

	BUG_ON(page == NULL);

	/* Return page */
	atomic_inc(&gets);

	if (page != NULL) {
		*page_data = kmap(page);
	}
	return page;
}

static void bval_put(struct replayfs_btree_head *head, struct page *page) {
	if (page != NULL) {
		if (head->node_page != page) {
			replayfs_diskalloc_put_page(head->allocator, page);
			atomic_inc(&puts);
		}
		kunmap(page);
	}
}

/*
 * The normal rules don't apply here... the leaf node elements are larger than
 * the non-leaf nodes...
 */
static struct replayfs_btree_value *bval_at(struct replayfs_diskalloc *allocator,
		struct btree_geo *geo, unsigned long *node, int n) {
	loff_t offs;
	//unsigned long *node = page_address(page);
	struct replayfs_btree_value *ret;

	/*
	debugk("%s %d: buffer offset is %d\n", __func__, __LINE__, geo->no_longs +
			(VALSIZELONGS * n));
			*/
	memcpy(&offs, &node[geo->no_longs + (VALSIZELONGS*n)], sizeof(loff_t));

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
	void *addr =kmap(page);
	SetPageDirty(page);
	keycpy(bkey(geo, addr, n), key);
	kunmap(page);
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
	unsigned long *node = kmap(page);

	//__set_page_dirty_nobuffers(page);
	SetPageDirty(page);
	memset(&node[geo->no_longs + (VALSIZELONGS*n)], 0,
			sizeof(struct replayfs_btree_value));

	kunmap(page);
}

static void setval(struct btree_geo *geo, struct page *page, int n,
		   struct replayfs_btree_value *val)
{
	unsigned long *node = kmap(page);

	//__set_page_dirty_nobuffers(page);
	SetPageDirty(page);
	memcpy(&node[geo->no_longs + (VALSIZELONGS * n)], val,
			sizeof(struct replayfs_btree_value));

	kunmap(page);
}

static void setval_node(struct btree_geo *geo, struct page *page, int n,
		   struct page *val)
{
	unsigned long *node = kmap(page);
	loff_t index = (loff_t)val->index * PAGE_SIZE;

	//__set_page_dirty_nobuffers(page);
	SetPageDirty(page);
	debugk("%s %d: Copying node value with off %lld into {%lu, %d}\n", __func__,
			__LINE__, index, page->index, n);
	memcpy(&node[geo->no_longs + (VALSIZELONGS*n)],
			&index, sizeof(loff_t));

	kunmap(page);
}

static void clearpair(struct btree_geo *geo, struct page *page, int n)
{
	unsigned long *node = kmap(page);
	longset(lbkey(geo, node, n), 0, geo->keylen);
	kunmap(page);
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
	meta = kmap(page);

	if (head->node_page != NULL) {
		meta->node_page = head->node_page->index * PAGE_SIZE;
	} else {
		meta->node_page = 0;
	}
	meta->height = head->height;

	SetPageDirty(page);

	kunmap(page);
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
	meta = kmap(page);

	if (meta->node_page != 0) {
		head->node_page = replayfs_diskalloc_get_page(alloc, meta->node_page);
	} else {
		head->node_page = NULL;
	}
	head->height = meta->height;

	kunmap(page);
	replayfs_diskalloc_put_page(alloc, page);
	//mempool_create(0, btree_alloc, btree_free, NULL);
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
	while (key.size != 0) {
		struct replayfs_btree_value _value;
		struct replayfs_btree_key _key;
		memcpy(&_value, value, sizeof(_value));
		memcpy(&_key, &key, sizeof(_key));

		replayfs_btree_put_page(head, page);

		value = replayfs_btree_remove(head, &_key, &page);
		replayfs_btree_put_page(head, page);

		value = replayfs_btree_last(head, &key, &page);
	}

	if (head->height > 0) {
		printk("%s %d: height is %d????\n", __func__, __LINE__, head->height);
	}
	//BUG_ON(head->height != 0);

	replayfs_btree_destroy(head);
	/* Done */
}

void replayfs_btree_put_page(struct replayfs_btree_head *head, struct page *page) {
	bval_put(head, page);
}

static struct page *get_head_page(struct replayfs_btree_head *head,
		unsigned long **data) {
	struct page *ret;
	ret = head->node_page;
	if (ret != NULL) {
		*data = kmap(ret);
	} else {
		*data = NULL;
	}
	return ret;
}

struct replayfs_btree_value *replayfs_btree_last(struct replayfs_btree_head *head,
		struct replayfs_btree_key *key, struct page **ret_page)
{
	struct page *page;
	unsigned long *node;
	struct replayfs_btree_value *ret;
	int height = head->height;

	page = get_head_page(head, &node);

	if (height == 0)
		return NULL;

	for ( ; height > 1; height--) {
		struct page *tmppage = page;
		page = bval(head->allocator, &replayfs_geo, node, &node, 0);
		bval_put(head, tmppage);
	}

	keycpy(key, bkey(&replayfs_geo, node, 0));
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
		return 0;
	}

	return 1;
}

struct replayfs_btree_value *replayfs_btree_lookup(
		struct replayfs_btree_head *head, loff_t pos,
		struct replayfs_btree_key *key, struct page **ret_page)
{
	int i, height = head->height;
	struct page *node;
	unsigned long *node_data;
	node = get_head_page(head, &node_data);


	debugk("%s %d: In %s\n", __func__, __LINE__, __func__);
	if (height == 0) {
		debugk("%s %d: Empty tree!\n", __func__, __LINE__);
		return NULL;
	}

	for ( ; height > 1; height--) {
		struct page *tmppage;
		debugk("%s %d: On non-leaf node!\n", __func__, __LINE__);
		for (i = 0; i < replayfs_geo.no_pairs; i++)
			if (valkeycmp(&replayfs_geo, node_data, i, pos) <= 0) {
				break;
			}

		if (i == replayfs_geo.no_pairs) {
			bval_put(head, node);
			return NULL;
		}

		tmppage = node;

		node = bval(head->allocator, &replayfs_geo, node_data, &node_data, i);
		if (!node) {
			bval_put(head, tmppage);
			return NULL;
		}

		bval_put(head, tmppage);
	}

	if (!node) {
		return NULL;
	}

	for (i = 0; i < replayfs_geo.no_pairs; i++) {
		/*
		debugk("%s %d: Comparing %llu and {%lld, %lld}\n", __func__, __LINE__, pos,
				bkey(&replayfs_geo, node_data, i)->offset,
				bkey(&replayfs_geo, node_data, i)->size);
				*/
		if (valkeycmp(&replayfs_geo, node_data, i, pos) == 0) {
			debugk("%s %d: Found key at %d\n", __func__, __LINE__, i);
			keycpy(key, bkey(&replayfs_geo, node_data, i));
			*ret_page = node;
			return (void *)bval_at(head->allocator, &replayfs_geo, node_data, i);
		}
	}

	bval_put(head, node);
	return NULL;
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
	loff_t pos = __key->offset;
	unsigned long *node_data;
	unsigned long *oldnode_data;
	struct page *node, *oldnode;
	struct replayfs_btree_key *retry_key = NULL, key;
	struct page *retry_page;

	if (keyzero(&replayfs_geo, __key))
		return NULL;

	if (head->height == 0)
		return NULL;
	keycpy(&key, __key);
retry:
	pos = key.offset;
	dec_key(&pos);

	node = get_head_page(head, &node_data);
	for (height = head->height ; height > 1; height--) {
		for (i = 0; i < replayfs_geo.no_pairs; i++)
			if (valkeycmp(&replayfs_geo, node_data, i, pos) <= 0)
				break;
		if (i == replayfs_geo.no_pairs)
			goto miss;
		oldnode = node;
		oldnode_data = node_data;


		node = bval(head->allocator, &replayfs_geo, node_data, &node_data, i);

		if (!node) {
			bval_put(head, oldnode);
			goto miss;
		}

		bval_put(head, node);

		if (retry_key) {
			bval_put(head, retry_page);
		}
		retry_key = bkey(&replayfs_geo, oldnode_data, i);
		retry_page = oldnode;
	}

	if (!node)
		goto miss;

	for (i = 0; i < replayfs_geo.no_pairs; i++) {
		if (valkeycmp(&replayfs_geo, node_data, i, pos) <= 0) {
			struct page *tmppage;
			unsigned long *tmppage_data;

			tmppage = bval(head->allocator, &replayfs_geo, node_data, &tmppage_data, i);
			if (tmppage) {
				bval_put(head, tmppage);
				keycpy(__key, bkey(&replayfs_geo, node_data, i));
				*ret_page = node;
				return bval_at(head->allocator, &replayfs_geo, node_data, i);
			} else
				goto miss;
		}
	}
miss:
	if (retry_key) {
		keycpy(&key, retry_key);
		retry_key = NULL;
		bval_put(head, retry_page);
		goto retry;
	}
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
	struct page *oldpage = get_head_page(head, &oldpage_data);

	for (height = head->height; height > level; height--) {
		unsigned long *tmpnode_data;
		struct page *tmpnode;
		for (i = 0; i < geo->no_pairs; i++)
			if (valkeycmp(geo, node_data, i, key->offset) <= 0)
				break;

		tmpnode = bval(head->allocator, geo, node_data, &tmpnode_data, i);
		if ((i == geo->no_pairs) || !tmpnode) {
			/* right-most key is too large, update it */
			/* FIXME: If the right-most key on higher levels is
			 * always zero, this wouldn't be necessary. */

			i--;
			setkey(geo, node, i, key);

		}

		bval_put(head, tmpnode);

		BUG_ON(i < 0);

		node = bval(head->allocator, geo, node_data, &node_data, i);

		bval_put(head, oldpage);
		oldpage = node;
		oldpage_data = node_data;
	}

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

	node_data = kmap(node);

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

		bval_put(head, headpage);
	}
	head->node_page = node;
	debugk("%s %d: Setting btree node_page to %lu\n", __func__,
			__LINE__, head->node_page->index);
	head->height++;
	update_meta(head);

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
	head->node_page = bval(head->allocator, geo, node_data, &node_data, 0);
	head->height--;
	update_meta(head);

	/* Need to unmap before freeing */
	kunmap(node);
	replayfs_diskalloc_free_page(head->allocator, node);
	//mempool_free(node, head->mempool);
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
		new_data = kmap(new);
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
		new_data = kmap(new);
		debugk("%s %d: past node_alloc!\n", __func__, __LINE__);
		if (!new)
			return -ENOMEM;
		err = btree_insert_inner_level(head, geo,
				bkey(geo, node_data, fill / 2 - 1),
				new, new_data, level + 1, gfp);
		if (err) {
			//mempool_free(new, head->mempool);
			kunmap(new);
			replayfs_diskalloc_free_page(head->allocator, new);
			return err;
		}

		debugk("%s %d: Adjusting pages (new) %lu and (node) %lu\n", __func__,
				__LINE__, new->index, node->index);
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

			setkey(geo, node, i, bkey(geo, node_data, fill - 1));
			tmp = bval_at(head->allocator, geo, node_data, fill - 1);
			setval(geo, node, i, tmp);
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
	debugk("%s %d: Inserting key {%lld %lld} to node %lu!\n", __func__, __LINE__,
			key->offset, key->size, node->index);
	setkey(geo, node, pos, key);
	setval(geo, node, pos, val);

	bval_put(head, node);

	return 0;
}

int __must_check replayfs_btree_insert_update(struct replayfs_btree_head *head,
			      struct replayfs_btree_key *key, struct replayfs_btree_value *val,
						gfp_t gfp) {
	struct page *page = NULL;
	struct replayfs_btree_key in_key;
	struct replayfs_btree_value *in_val;
	struct replayfs_btree_key new_key;

	/* 
	 * Okay... we need to zero fill anything which is not otherwise referenced...
	 */

	/* First, check to see if an entry containing key exists */
	/* This could be tricky... This key could consume multiple others:
	 * I need to scan backwards from the last key? */
	in_val = replayfs_btree_lookup(head, key->offset + key->size-1, &in_key, &page);
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
				if (replayfs_btree_insert(head, &fill_key, &replayfs_zero_value, gfp)) {
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
			if (replayfs_btree_insert(head, &fill_key, &replayfs_zero_value, gfp)) {
				return -ENOMEM;
			}
			in_val = &replayfs_zero_value;
			keycpy(&in_key, &fill_key);
		}

		debugk("%s %d: Got in_key of {%lld, %lld}, key is {%lld, %lld}\n", __func__,
				__LINE__, in_key.offset, in_key.size, key->offset, key->size);
		BUG_ON(in_key.offset >= key->offset + key->size ||
		       in_key.offset + in_key.size < key->offset);
	}

	/* Okay, now we need to iterate through the thinggy */
	debugk("%s %d: Starting loop!\n", __func__, __LINE__);
	while (in_key.offset + in_key.size > key->offset) {
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

		keycpy(&new_key, &in_key);

		/* Remove in_key */
		bval_put(head, page);

		debugk("%s %d: Replacing in_key with new_key\n", __func__, __LINE__);
		in_val = replayfs_btree_remove(head, &in_key, &page);

		if (in_val != NULL) {
			/* If the top of our address range is above key */
			debugk("%s %d: cmparing in_max to key_max: %lld <> %lld!\n", __func__,
					__LINE__, in_key.offset + in_key.size, key->offset + key->size);
			if (in_key.offset + in_key.size > key->offset + key->size) {
				struct replayfs_btree_value new_val;

				memcpy(&new_val, in_val, sizeof(struct replayfs_btree_value));

				new_key.offset = key->offset + key->size;
				new_key.size = in_key.offset + in_key.size - new_key.offset;
				new_val.buff_offs = in_val->buff_offs + (
							key->offset + key->size - in_key.offset
						);
				debugk("%s %d: Inserting val with buff_offs: %d\n", __func__, __LINE__,
						new_val.buff_offs);
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
				debugk("%s %d: Inserting val with buff_offs: %d\n", __func__, __LINE__,
						new_val.buff_offs);
				replayfs_btree_insert(head, &new_key, &new_val, gfp);
			}

			bval_put(head, page);

			/* Get prev key, and repeat */
			in_val = replayfs_btree_get_prev(head, &new_key, &page);
			debugk("%s %d: in_val after get_prev is %p\n", __func__, __LINE__, in_val);
			if (in_val == NULL) {
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
	return replayfs_btree_insert(head, key, val, gfp);
}

int replayfs_btree_insert(struct replayfs_btree_head *head,
		struct replayfs_btree_key *key, void *val, gfp_t gfp)
{
	BUG_ON(!val);
	return btree_insert_level(head, &replayfs_geo, key, val, 1, gfp);
}

static void *btree_remove_level(struct replayfs_btree_head *head, struct btree_geo *geo,
		struct replayfs_btree_key *key, int level, struct page **);
static void merge(struct replayfs_btree_head *head, struct btree_geo *geo, int level,
		struct page *left, unsigned long *left_data, int lfill,
		struct page *right, unsigned long *right_data, int rfill,
		struct page *parent, unsigned long *parent_data, int lpos)
{
	int i;
	struct page *page = NULL;

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
		setval_node(geo, parent, lpos, right);
		setval_node(geo, parent, lpos + 1, left);
		/* Remove left (formerly right) child from parent */
		btree_remove_level(head, geo, bkey(geo, parent_data, lpos), level + 1, &page);
		bval_put(head, page);

		/* Must unmap before free */
		kunmap(right);
		replayfs_diskalloc_free_page(head->allocator, right);
	} else {
		for (i = 0; i < rfill; i++) {
			struct replayfs_btree_value *tmp;
			/* Move all keys to the left */
			setkey(geo, left, lfill + i, bkey(geo, right_data, i));
			tmp = bval_at(head->allocator, geo, right_data, i);
			setval(geo, left, lfill + i, tmp);
		}
		/* Exchange left and right child in parent */
		setval(geo, parent, lpos, (void *)right);
		setval(geo, parent, lpos + 1, (void *)left);
		/* Remove left (formerly right) child from parent */
		btree_remove_level(head, geo, bkey(geo, parent_data, lpos), level + 1, &page);
		bval_put(head, page);
	}
}

static void rebalance(struct replayfs_btree_head *head, struct btree_geo *geo,
		struct replayfs_btree_key *key, int level, struct page *child,
		unsigned long *child_data, int fill)
{
	unsigned long *parent_data = NULL;
	unsigned long *left_data = NULL;
	unsigned long *right_data = NULL;
	struct page *parent, *left = NULL, *right = NULL;
	struct page *page;
	int i, no_left, no_right;

	if (fill == 0) {
		/* Because we don't steal entries from a neighbour, this case
		 * can happen.  Parent node contains a single child, this
		 * node, so merging with a sibling never happens.
		 */
		btree_remove_level(head, geo, key, level + 1, &page);
		bval_put(head, page);
		//mempool_free(child, head->mempool);
		replayfs_diskalloc_free_page(head->allocator, child);
		return;
	}

	parent = find_level(head, geo, key, level + 1, &parent_data);

	i = getpos(geo, parent_data, key->offset);
	/* 
	 * This check is broken because I changed... everything about this btree impl
	 * The check for bval(x)->index == child->index would probably work
	 * Also, need to free the bval...
	 */
	/* BUG_ON(bval(head->allocator, geo, parent, i) != child); */

	if (i > 0) {
		left = bval(head->allocator, geo, parent_data, &left_data, i - 1);
		no_left = getfill(head->allocator, geo, left_data, 0);
		if (fill + no_left <= geo->no_pairs) {
			merge(head, geo, level,
					left, left_data, no_left,
					child, child_data, fill,
					parent, parent_data, i - 1);
			bval_put(head, left);
			return;
		}
		bval_put(head, left);
	}
	if (i + 1 < getfill(head->allocator, geo, parent_data, i)) {
		right = bval(head->allocator, geo, parent_data, &right_data, i + 1);
		no_right = getfill(head->allocator, geo, right_data, 0);
		if (fill + no_right <= geo->no_pairs) {
			merge(head, geo, level,
					child, child_data, fill,
					right, right_data, no_right,
					parent, parent_data, i);
			bval_put(head, right);
			return;
		}
		bval_put(head, right);
	}
	/*
	 * We could also try to steal one entry from the left or right
	 * neighbor.  By not doing so we changed the invariant from
	 * "all nodes are at least half full" to "no two neighboring
	 * nodes can be merged".  Which means that the average fill of
	 * all nodes is still half or better.
	 */
}

static void *btree_remove_level(struct replayfs_btree_head *head, struct btree_geo *geo,
		struct replayfs_btree_key *key, int level, struct page **page)
{
	unsigned long *node_data = NULL;
	struct page *node;
	int i, pos, fill;
	void *ret;

	if (level > head->height) {
		/* we recursed all the way up */
		head->height = 0;
		head->node_page = NULL;
		update_meta(head);
		return NULL;
	}

	node = find_level(head, geo, key, level, &node_data);

	pos = getpos(geo, node_data, key->offset);

	fill = getfill(head->allocator, geo, node_data, pos);
	debugk("%s %d: fill is %d, pos is %d no_pars is %d!\n", __func__, __LINE__,
			fill, pos, geo->no_pairs);
	if ((level == 1) && (keycmp(geo, node_data, pos, key) != 0)) {
		debugk("%s %d: !!!!!!! returning NULL?\n", __func__, __LINE__);
		return NULL;
	}
	*page = node;
	ret = bval_at(head->allocator, geo, node_data, pos);

	debugk("%s %d: Removing key: {%lld, %lld}\n", __func__, __LINE__,
			bkey(geo, node_data, pos)->offset, bkey(geo, node_data, pos)->size);

	/* remove and shift */
	if (level != 1) {
		for (i = pos; i < fill - 1; i++) {
			unsigned long *tmp_data;
			struct page *tmp;
			setkey(geo, node, i, bkey(geo, node_data, i + 1));
			tmp = bval(head->allocator, geo, node_data, &tmp_data, i + 1);
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
		if (level < head->height)
			rebalance(head, geo, key, level, node, node_data, fill - 1);
		else if (fill - 1 == 1)
			btree_shrink(head, geo);
	}

	return ret;
}

struct replayfs_btree_value *replayfs_btree_remove(struct replayfs_btree_head *head,
		   struct replayfs_btree_key *key, struct page **page)
{
	if (head->height == 0)
		return NULL;

	return btree_remove_level(head, &replayfs_geo, key, 1, page);
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
		replayfs_btree_remove(victim, &dup, &page);
		bval_put(victim, val);
	}
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
	unsigned long *node_data = kmap(node);
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

	kunmap(node);

	if (reap) {
		//mempool_free(node, head->mempool);
		kunmap(node);
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

