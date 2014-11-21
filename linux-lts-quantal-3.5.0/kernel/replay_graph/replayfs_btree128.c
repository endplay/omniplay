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
#include <linux/pagemap.h>

#include "replayfs_btree128.h"
#include "replayfs_diskalloc.h"
#include "replayfs_kmap.h"

//#define REPLAYFS_BTREE128_DEBUG

/*
#define REPLAYFS_BTREE128_VERIFY
*/

#ifdef REPLAYFS_BTREE128_VERIFY
extern struct mutex glbl_debug_lock;
#endif

extern int replayfs_btree128_do_verify;

#ifdef REPLAYFS_BTREE128_DEBUG
extern int replayfs_btree128_debug;
extern int replayfs_btree128_debug_verbose;
#define debugk(...) if (replayfs_btree128_debug) { printk(__VA_ARGS__); }
#define check_debugk(...) if (replayfs_btree128_debug_verbose) { printk(__VA_ARGS__); }
#define debug_dump_stack() if (replayfs_btree128_debug) { dump_stack(); }
#else
#define debugk(...)
#define check_debugk(...)
#define debug_dump_stack() 
#endif

#define LONG_PER_U64 (64 / BITS_PER_LONG)

#define MAX(a, b) ((a) > (b) ? (a) : (b))
/* #define NODESIZE MAX(L1_CACHE_BYTES, 128) */
#define NODESIZE MAX(L1_CACHE_BYTES, PAGE_SIZE)

#define VALSIZELONGS (sizeof(struct replayfs_btree128_value)/sizeof(long))

LIST_HEAD(active_trees);

static int keyzero(struct btree_geo *geo, struct replayfs_btree128_key *key);

#ifdef REPLAYFS_BTREE_128_VERIFY
static void replayfs_btree128_verify_init(struct replayfs_btree128_head *head) {

	mutex_lock(&glbl_debug_lock);
	list_add(&head->active_list, &active_trees);
	mutex_unlock(&glbl_debug_lock);

	btree_init128(&head->verify_btree);
}

static void replayfs_btree128_verify_destroy(struct replayfs_btree128_head *head) {
	mutex_lock(&glbl_debug_lock);
	list_del(&head->active_list);
	mutex_unlock(&glbl_debug_lock);

	btree_destroy128(&head->verify_btree);
}

static void replayfs_btree128_verify_insert(struct replayfs_btree128_head *head,
		struct replayfs_btree_128key *key, struct replayfs_btree128_value *val,
		gfp_t gfp) {
	int rc;
	struct replayfs_btree128_value *ins_val;

	ins_val = kmalloc(sizeof(struct replayfs_btree128_value), gfp);
	BUG_ON(ins_val == NULL);

	memcpy(ins_val, val, sizeof(struct replayfs_btree128_value));

	rc = btree_insert128(&head->verify_btree, key->id1, key->id2, ins_val, gfp);
	BUG_ON(rc != 0);
}

static void replayfs_btree128_verify_remove(struct replayfs_btree128_head *head,
		struct replayfs_btree_128key *key, int expected_ret) {
	void *ret;

	ret = btree_remove128(&head->verify_btree, key->id1, key->id2, val, gfp);

	if (ret != NULL) {
		BUG_ON(expected_ret == 0);
		kfree(ret);
	} else {
		BUG_ON(exptected_ret != 0);
	}
}

static void replayfs_btree128_verify_lookup(struct replayfs_btree128_head *head,
		struct replayfs_btree_128key *key,
		struct replayfs_btree128_value *expected_val) {
	struct replyafs_btree128_value *got_val;

	got_val = btree_lookup128(&head->verify_btree, key->id1, key->id2);

	if (
			((got_val == NULL || expected_val == NULL) && got_val != expected_val) ||
			(!IS_ERR(got_val) != !IS_ERR(exptected_val))
			) { 

		printk("%s %d: got_val %p, expected_val %p, Failing\n", __func__, __LINE__,
				got_val, expected_val);
		BUG();
	}

	if (got_val != NULL) {
		if (!memcmp(got_val, exptected_val, sizeof(struct replayfs_btree128_value))) {
			printk("%s %d: got_val is %lld, expected_val is %lld\n", __func__, __LINE__,
					got_val->id, expected_val->id);
			BUG();
		}
	}
}
#else
#define replayfs_btree128_verify_init(...)
#define replayfs_btree128_verify_destroy(...)
#define replayfs_btree128_verify_insert(...)
#define replayfs_btree128_verify_remove(...)
#define replayfs_btree128_verify_lookup(...)
#endif

struct replayfs_btree128_value replayfs_zero128_value = {
	.id = 0
};

struct btree_geo {
	int keylen;
	int no_pairs;
	int no_longs;
};

struct btree_geo replayfs128_geo = {
	.keylen = 2 * LONG_PER_U64,
	.no_pairs = NODESIZE / sizeof(long) / (VALSIZELONGS + 2 * LONG_PER_U64),
	.no_longs = 2 * LONG_PER_U64 * (NODESIZE / sizeof(long) / (VALSIZELONGS + 2 * LONG_PER_U64)),
};

static struct page *btree_node_alloc(struct replayfs_btree128_head *head, gfp_t gfp)
{
	struct page *page = NULL;

	page = replayfs_diskalloc_alloc_page(head->allocator);
	debugk("%s %d: Allocated btree head %p with page %lu\n", __func__, __LINE__,
			head, page->index);
	if (likely(page && !IS_ERR(page))) {
		void *addr = replayfs_kmap(page);
		memset(addr, 0, NODESIZE);
		//__set_page_dirty_nobuffers(page);
		//SetPageDirty(page);
		replayfs_diskalloc_page_dirty(page);
		replayfs_kunmap(page);
	} else {
		printk("%s %d: ERROR GETTING PAGE!!! (%ld)\n", __func__, __LINE__,
				PTR_ERR(page));
		BUG();
	}

	return page;
}

static int rpkeycmp(const struct replayfs_btree128_key *l1,
		const struct replayfs_btree128_key *l2)
{
	u64 val1_1 = l1->id1;
	u64 val1_2 = l1->id2;

	u64 val2_1 = l2->id1;
	u64 val2_2 = l2->id2;


	//debugk("%s %d: Comparing %llu with %llu\n", __func__, __LINE__, val1_1, val2_1);
	if (val1_1 < val2_1) {
		return -1;
	}
	if (val1_1 > val2_1) {
		return 1;
	}

	//debugk("%s %d: Comparing %llu with %llu\n", __func__, __LINE__, val1_2, val2_2);
	if (val1_2 < val2_2) {
		return -1;
	}
	if (val1_2 > val2_2) {
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

static struct replayfs_btree128_key *keycpy(struct replayfs_btree128_key *dest,
		struct replayfs_btree128_key *src)
{
	/*
	debugk("%s %d: KEYCPY: {%lld, %lld} <- {%lld, %lld}\n", __func__, __LINE__,
			dest->offset, dest->size, src->offset, src->size);
			*/

#ifdef REPLAYFS_BTREE128_DEBUG
	/* Invalid key bug, not zero key, with invalid id2... */
	BUG_ON (src->id2 == 0 && src->id1 != 0);
#endif

	dest->id1 = src->id1;
	dest->id2 = src->id2;

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

static void dec_key(struct replayfs_btree128_key *pos)
{
	if (pos->id1 == 0) {
		pos->id1 = ~pos->id1;
		pos->id2--;
	} else {
		pos->id1--;
	}
}

static struct replayfs_btree128_key *bkey(struct btree_geo *geo, unsigned long *page, int n)
{
	unsigned long *node = page;
	return (struct replayfs_btree128_key *)&node[n * geo->keylen];
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

	if ((pageoffs % PAGE_SIZE) != 0 || pageoffs >= PAGE_ALLOC_SIZE) {
		printk("%s %d: Have invalid pgoffs: %lld, node %p, index %d\n", __func__,
				__LINE__, pageoffs, node, n);
		BUG();
	}

	/*
	debugk("%s %d: Reading bval with offset %lld from {%lu, %d}\n", __func__,
			__LINE__, pageoffs, node_page->index, n);
			*/
	/*
	debugk("%s %d: Reading bval with offset %lld\n", __func__,
			__LINE__, pageoffs);
			*/

	/* Get page of next node from offset */
	page = replayfs_diskalloc_get_page(allocator, pageoffs);

	BUG_ON(page == NULL);

	/* Return page */
	atomic_inc(&gets);

	if (page != NULL) {
		*page_data = replayfs_kmap(page);
	}
	return page;
}

#ifdef REPLAYFS_BTREE128_VERIFY
static void check_key_zero(struct replayfs_btree128_head *head,
		struct page *page) {
	struct replayfs_btree128_key *key;
	unsigned long *data;
	/* Make sure the key is valid */
	data = replayfs_kmap(page);

	key = bkey(&replayfs128_geo, data, 0);

	if (!keyzero(&replayfs128_geo, key)) {
		/* Okay, key is nonzero, check val */
		if (head->height > 1) {
			loff_t pageoffs;

			memcpy(&pageoffs, &data[replayfs128_geo.no_longs], sizeof(loff_t));

			if ((pageoffs % PAGE_SIZE) != 0) {
				printk("%s %d: Page %lu (alloc %d) has invalid pgoffs: %lld\n", __func__, __LINE__,
						page->index, head->allocator->allocnum, pageoffs);
				BUG();
			}

			if (pageoffs >= PAGE_ALLOC_SIZE) {
				printk("%s %d: Page %lu (alloc %d) has invalid pgoffs: %lld\n", __func__, __LINE__,
						page->index, head->allocator->allocnum, pageoffs);
				BUG();
			}
		}
	}

	replayfs_kunmap(page);
}
#else
#define check_key_zero(...)
#endif

static void bval_put(struct replayfs_btree128_head *head, struct page *page) {
	if (page != NULL) {
		replayfs_kunmap(page);
		if (head->node_page != page) {
			replayfs_diskalloc_put_page(head->allocator, page);
			atomic_inc(&puts);
		} else {
			check_key_zero(head, head->node_page);
			//replayfs_diskalloc_sync_page(head->allocator, page);
		}
	}
}

/*
 * The normal rules don't apply here... the leaf node elements are larger than
 * the non-leaf nodes...
 */
static struct replayfs_btree128_value *bval_at(struct replayfs_diskalloc *allocator,
		struct btree_geo *geo, unsigned long *node, int n) {
	loff_t offs;
	//unsigned long *node = page_address(page);
	struct replayfs_btree128_value *ret;

	/*
	debugk("%s %d: buffer offset is %d\n", __func__, __LINE__, geo->no_longs +
			(VALSIZELONGS * n));
			*/
	memcpy(&offs, &node[geo->no_longs + (VALSIZELONGS*n)], sizeof(loff_t));

	//return replayfs_disk_alloc_get(allocator, offs);
	ret = (struct replayfs_btree128_value *)
		&node[geo->no_longs + (VALSIZELONGS * n)];

	/*
	debugk("%s %d: Reading value with unique_id %lld from {%lu, %d} {%p, %d} (%p)\n", __func__,
			__LINE__, ret->id.unique_id, page->index, n, node,
			geo->no_longs+(VALSIZELONGS*n), &node[geo->no_longs+(VALSIZELONGS*n)]);
			*/

	return ret;
}

static void setkey(struct btree_geo *geo, struct page *page, int n,
		   struct replayfs_btree128_key *key)
{
	void *addr = replayfs_kmap(page);
	//SetPageDirty(page);
	replayfs_diskalloc_page_dirty(page);
	keycpy(bkey(geo, addr, n), key);
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

static void setval(struct btree_geo *geo, struct page *page, int n,
		   struct replayfs_btree128_value *val)
{
	unsigned long *node = replayfs_kmap(page);

	//__set_page_dirty_nobuffers(page);
	//SetPageDirty(page);
	replayfs_diskalloc_page_dirty(page);
	memcpy(&node[geo->no_longs + (VALSIZELONGS * n)], val,
			sizeof(struct replayfs_btree128_value));

	replayfs_kunmap(page);
}

static void setval_node(struct btree_geo *geo, struct page *page, int n,
		   struct page *val)
{
	unsigned long *node = replayfs_kmap(page);
	loff_t index = (loff_t)val->index * PAGE_SIZE;

	//__set_page_dirty_nobuffers(page);
	//SetPageDirty(page);
	replayfs_diskalloc_page_dirty(page);
	/*
	debugk("%s %d: Copying node value with off %lld into {%lu, %d}\n", __func__,
			__LINE__, index, page->index, n);
			*/

	if ((index % PAGE_SIZE) != 0 || index >= PAGE_ALLOC_SIZE) {
		printk("%s %d: Have invalid index: %lld, page->index %lu, offset %d\n", __func__,
				__LINE__, index, val->index, n);
		BUG();
	}

	memcpy(&node[geo->no_longs + (VALSIZELONGS*n)],
			&index, sizeof(loff_t));

	replayfs_kunmap(page);
}

static void clearpair(struct btree_geo *geo, struct page *page, int n)
{
	struct replayfs_btree128_key key;
	unsigned long *node = replayfs_kmap(page);
	struct replayfs_btree128_key *dest;

	key.id1 = 0;
	key.id2 = 0;

	replayfs_diskalloc_page_dirty(page);
	dest = bkey(geo, node, n);

	debugk("%s %d: Copying {%llu, %llu} from zero key to page %lu (%p) offset %lu overriding {%llu, %llu}\n",
			__func__, __LINE__, key.id1, key.id2, page->index, page, ((unsigned long)dest) % (PAGE_SIZE),
			dest->id1, dest->id2);
	keycpy(dest, &key);
	debugk("%s %d: Overwrote dest to {%llu, %llu}\n", __func__, __LINE__,
			dest->id1, dest->id2);

	memset(&node[geo->no_longs + (VALSIZELONGS*n)], 0,
			sizeof(struct replayfs_btree128_value));

	replayfs_kunmap(page);
}

static inline void __btree_init(struct replayfs_btree128_head *head)
{
	head->node_page = NULL;
	head->height = 0;

	replayfs_btree128_verify_init(head);
}

/*
void replayfs_btree128_init_allocator(struct replayfs_btree128_head *head,
		struct replayfs_diskalloc *allocator)
{
	__btree_init(head);
	head->allocator = allocator;
}
*/

static void update_meta128(struct replayfs_btree128_head *head) {
	struct page *page;
	char *cpage;
	struct replayfs_btree_meta *meta;

	page = replayfs_diskalloc_get_page(head->allocator, head->meta_loc);
	cpage = replayfs_kmap(page);
	meta = (void *)(cpage + (head->meta_loc % PAGE_SIZE));

	if (head->node_page != NULL) {
		meta->node_page = head->node_page->index * PAGE_SIZE;
	} else {
		meta->node_page = 0;
	}

	debugk("%s %d: Saved meta_height to %d for meta_loc %lld\n", __func__,
			__LINE__, head->height, head->meta_loc);
	meta->height = head->height;

	//SetPageDirty(page);
	replayfs_diskalloc_page_dirty(page);

	replayfs_kunmap(page);
	replayfs_diskalloc_put_page(head->allocator, page);
}

int replayfs_btree128_init(struct replayfs_btree128_head *head,
		struct replayfs_diskalloc *alloc, loff_t meta_loc)
{
	struct page *page;
	char *cpage;
	struct replayfs_btree_meta *meta;

	__btree_init(head);

	head->allocator = alloc;

	head->meta_loc = meta_loc;

	debugk("%s %d: Init called for head %p with meta_loc of %lld\n", __func__,
			__LINE__, head, head->meta_loc);

	BUG_ON((meta_loc % PAGE_SIZE) != 0);
	page = replayfs_diskalloc_get_page(alloc, meta_loc);
	cpage = replayfs_kmap(page);

	meta = (void *)(cpage + (meta_loc % PAGE_SIZE));

	if (meta->node_page != 0) {
		head->node_page = replayfs_diskalloc_get_page(alloc, meta->node_page);
	} else {
		head->node_page = NULL;
	}
	head->height = meta->height;

	debugk("%s %d: Loaded head %p head->height to %d and node->page to %p!!!\n", __func__,
			__LINE__, head, head->height, head->node_page);

	BUG_ON(head->height != 0 && head->node_page == 0);

	replayfs_kunmap(page);
	replayfs_diskalloc_put_page(alloc, page);
	return 0;
}

int replayfs_btree128_create(struct replayfs_btree128_head *head,
		struct replayfs_diskalloc *alloc, loff_t meta_loc)
{
	head->meta_loc = meta_loc;
	__btree_init(head);
	head->allocator = alloc;
	update_meta128(head);
	//mempool_create(0, btree_alloc, btree_free, NULL);
	debugk("%s %d: INIT'd head %p head->height to %d!!!\n", __func__, __LINE__,
			head, head->height);
	return 0;
}

void replayfs_btree128_destroy(struct replayfs_btree128_head *head)
{
	replayfs_diskalloc_sync(head->allocator);

	/* Sync all of the nodes in the tree */
	head->allocator = NULL;

	replayfs_btree128_verify_destroy(head);
}

void replayfs_btree128_put_page(struct replayfs_btree128_head *head, struct page *page) {
	bval_put(head, page);
}

static struct page *get_head_page(struct replayfs_btree128_head *head,
		unsigned long **data) {
	struct page *ret;
	ret = head->node_page;
	if (ret != NULL) {
		*data = replayfs_kmap(ret);
		check_key_zero(head, head->node_page);
	} else {
		*data = NULL;
	}
	return ret;
}

struct replayfs_btree128_value *replayfs_btree128_last(struct replayfs_btree128_head *head,
		struct replayfs_btree128_key *key, struct page **ret_page)
{
	struct page *page;
	unsigned long *node;
	struct replayfs_btree128_value *ret;
	int height = head->height;

	page = get_head_page(head, &node);

	if (height == 0)
		return NULL;

	for ( ; height > 1; height--) {
		struct page *tmppage = page;
		page = bval(head->allocator, &replayfs128_geo, node, &node, 0);
		bval_put(head, tmppage);
	}

	keycpy(key, bkey(&replayfs128_geo, node, 0));
	ret = bval_at(head->allocator, &replayfs128_geo, node, 0);
	*ret_page = page;

	return ret;
}

static int valkeycmp(struct btree_geo *geo, unsigned long *node, int pos,
		struct replayfs_btree128_key *key)
{
	return rpkeycmp(bkey(geo, node, pos), key);
}

static int keycmp(struct btree_geo *geo, unsigned long *node, int pos,
		  struct replayfs_btree128_key *key)
{
	return rpkeycmp(bkey(geo, node, pos), key);
}

static int keyzero(struct btree_geo *geo, struct replayfs_btree128_key *key)
{
	if (key->id1 == 0 && key->id2 == 0) {
		return 1;
	}

	return 0;
}

#ifdef REPLAYFS_BTREE128_VERIFY
static void check_tree_internal(struct replayfs_btree128_head *head, struct page *node,
		unsigned long *node_data, int level, struct replayfs_btree128_key *last_key) {
	struct btree_geo *geo = &replayfs128_geo;
	int i;

	struct replayfs_btree128_key *fill_key = NULL;

	check_debugk("%s %d: Have node of {%lu, %d} (%p), level is %d, height is %d\n", __func__, __LINE__,
			node->index, head->allocator->allocnum, node, level, head->height);
	if (last_key != NULL) {
		check_debugk("%s %d: Last key is {%llu, %llu}\n", __func__, __LINE__,
				last_key->id1, last_key->id2);
	}

	BUG_ON(level == head->height && last_key != NULL);

	if (level > 1) {
		for (i = 0; i < geo->no_pairs; i++) {
			struct page *new_node;
			unsigned long *new_node_data;
			struct replayfs_btree128_key *key;

			key = bkey(geo, node_data, i);

			check_debugk("%s %d: Level %d Scanning {%llu, %llu}\n", __func__, __LINE__,
					level, key->id1, key->id2);

			if (!keyzero(geo, key)) {
				new_node = bval(head->allocator, geo, node_data, &new_node_data, i);

				BUG_ON(new_node == NULL);

				check_debugk("%s %d: Checking node at page %lu\n", __func__, __LINE__, new_node->index);
				check_tree_internal(head, new_node, new_node_data, level-1, key);

				bval_put(head, new_node);

				fill_key = key;
			} else {
				BUG_ON(i == 0);
				break;
			}
		}
	} else {
		struct replayfs_btree128_key *pk = NULL;

		for (i = 0; i < geo->no_pairs; i++) {
			struct replayfs_btree128_key *k;

			k = bkey(geo, node_data, i);

			check_debugk("%s %d: Level %d Scanning {%lld, %lld}\n", __func__, __LINE__,
					level, k->id1, k->id2);

			if (pk != NULL) {
				BUG_ON(rpkeycmp(k, pk) >= 0);
			}

			if (keyzero(geo, k)) {
				break;
			}

			/* Specific to filemap... */
			/* If the key is not zero, the sdev cannot be == 0!!! */
			BUG_ON(k->id2 == 0);

			pk = k;
		}

		fill_key = pk;
	}

	BUG_ON(level == head->height && last_key != NULL);
	if (last_key != NULL && fill_key != NULL) {
		check_debugk("%s %d: Level %d (height %d) fill_key {%llu, %llu}, last_key {%llu, %llu}\n",
				__func__, __LINE__, level, head->height, fill_key->id1, fill_key->id2,
				last_key->id1, last_key->id2);

		BUG_ON(rpkeycmp(fill_key, last_key) < 0);
	}
}

static void check_page(struct replayfs_btree128_head *head, struct page *node,
		unsigned long *node_data, int level) {
	if (replayfs_btree128_do_verify) {
		struct btree_geo *geo = &replayfs128_geo;
		int i;

		check_debugk("%s %d: Have node of {%lu, %d} (%p), level is %d, height is %d\n", __func__, __LINE__,
				node->index, head->allocator->allocnum, node, level, head->height);

		if (level > 1) {
			for (i = 0; i < geo->no_pairs; i++) {
				struct page *new_node;
				unsigned long *new_node_data;
				struct replayfs_btree128_key *key;

				key = bkey(geo, node_data, i);

				check_debugk("%s %d: Level %d Scanning {%llu, %llu}\n", __func__, __LINE__,
						level, key->id1, key->id2);

				if (!keyzero(geo, key)) {
					new_node = bval(head->allocator, geo, node_data, &new_node_data, i);

					BUG_ON(new_node == NULL);

					bval_put(head, new_node);
				} else {
					BUG_ON(i == 0);
					break;
				}
			}
		} else {
			struct replayfs_btree128_key *pk = NULL;

			for (i = 0; i < geo->no_pairs; i++) {
				struct replayfs_btree128_key *k;

				k = bkey(geo, node_data, i);

				check_debugk("%s %d: Level %d Scanning {%lld, %lld}\n", __func__, __LINE__,
						level, k->id1, k->id2);

				if (pk != NULL) {
					BUG_ON(rpkeycmp(k, pk) >= 0);
				}

				if (keyzero(geo, k)) {
					break;
				}

				/* Specific to filemap... */
				/* If the key is not zero, the sdev cannot be == 0!!! */
				BUG_ON(k->id2 == 0);

				pk = k;
			}
		}
	}
}

static void check_tree(struct replayfs_btree128_head *head) {
	if (replayfs_btree128_do_verify) {
		struct page *node;
		unsigned long *node_data;

		if (head->height < 1) {
			return;
		}

		node = get_head_page(head, &node_data);

		debugk("%s %d: Scanning tree %p\n", __func__, __LINE__, head);
		//debug_dump_stack();

		check_tree_internal(head, node, node_data, head->height, NULL);

		bval_put(head, node);
	}
}
#else
#define check_tree(...)
#define check_page(...)
#endif

void btree128_debug_check(void) {
	struct replayfs_btree128_head *head;
	list_for_each_entry(head, &active_trees, active_list) {
		check_tree(head);
	}
}


struct replayfs_btree128_value *replayfs_btree128_lookup(
		struct replayfs_btree128_head *head, struct replayfs_btree128_key *pos,
		struct page **ret_page)
{
	int i, height = head->height;
	struct page *node;
	unsigned long *node_data;

	struct replayfs_btree128_value *ret;

	check_tree(head);

	node = get_head_page(head, &node_data);

	ret = NULL;


	//debugk("%s %d: In %s\n", __func__, __LINE__, __func__);
	if (height == 0) {
		debugk("%s %d: Head height of 0, returning 0\n", __func__, __LINE__);
		goto out;
	}

	for ( ; height > 1; height--) {
		struct page *tmppage;
		debugk("%s %d: On non-leaf node (key is {%llu, %llu})!\n", __func__,
				__LINE__, pos->id1, pos->id2);
		for (i = 0; i < replayfs128_geo.no_pairs; i++) {
			/*
			debugk("%s %d: Checking against {%llu, %llu}\n", __func__, __LINE__, 
					bkey(&replayfs128_geo, node_data, i)->id1,
					bkey(&replayfs128_geo, node_data, i)->id2);
					*/
			if (valkeycmp(&replayfs128_geo, node_data, i, pos) <= 0) {
				debugk("%s %d: Match!\n", __func__, __LINE__);
				break;
			}
		}

		if (i == replayfs128_geo.no_pairs) {
			debugk("%s %d: key not found, returning NULL\n", __func__, __LINE__);
			bval_put(head, node);
			goto out;
		}

		tmppage = node;

		debugk("%s %d: bkey is {%llu, %llu}\n", __func__, __LINE__,
				bkey(&replayfs128_geo, node_data, i)->id1,
				bkey(&replayfs128_geo, node_data, i)->id2);

		node = bval(head->allocator, &replayfs128_geo, node_data, &node_data, i);
		if (!node) {
			//debugk("%s %d: Next-level page is NULL\n", __func__, __LINE__);
			bval_put(head, tmppage);
			goto out;
		}

		bval_put(head, tmppage);
	}

	//debugk("%s %d: Node is NULL?\n", __func__, __LINE__);
	if (!node) {
		goto out;
	}

	debugk("%s %d: Base key is {%llu, %llu}\n", __func__, __LINE__, pos->id1, pos->id2);
	for (i = 0; i < replayfs128_geo.no_pairs; i++) {
		int cmpval;
		/*
		debugk("%s %d: Comparing to key {%llu, %llu}\n", __func__, __LINE__,
				bkey(&replayfs128_geo, node_data, i)->id1,
				bkey(&replayfs128_geo, node_data, i)->id2);
				*/

		cmpval = valkeycmp(&replayfs128_geo, node_data, i, pos);
		if (cmpval == 0) {
			debugk("%s %d: Found key at %d\n", __func__, __LINE__, i);
			*ret_page = node;
			ret = bval_at(head->allocator, &replayfs128_geo, node_data, i);
			goto out;
		}

		if (keyzero(&replayfs128_geo, bkey(&replayfs128_geo, node_data, i))) {
				break;
		}
	}

	bval_put(head, node);

out:
	replayfs_btree128_verify_lookup(head, pos, ret);

	return ret;
}

int replayfs_btree128_update(struct replayfs_btree128_head *head,
		 struct replayfs_btree128_key *key, void *val)
{
	int i, height = head->height;
	unsigned long *node_data;
	struct page *node = get_head_page(head, &node_data);

	if (height == 0)
		return -ENOENT;

	for ( ; height > 1; height--) {
		struct page *tmppage;
		for (i = 0; i < replayfs128_geo.no_pairs; i++)
			if (keycmp(&replayfs128_geo, node_data, i, key) <= 0)
				break;

		if (i == replayfs128_geo.no_pairs)
			return -ENOENT;

		tmppage = node;
		node = bval(head->allocator, &replayfs128_geo, node_data, &node_data, i);
		bval_put(head, tmppage);
		if (!node)
			return -ENOENT;
	}

	if (!node)
		return -ENOENT;

	for (i = 0; i < replayfs128_geo.no_pairs; i++)
		if (keycmp(&replayfs128_geo, node_data, i, key) == 0) {
			setval(&replayfs128_geo, node, i, val);

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
struct replayfs_btree128_value *replayfs_btree128_get_prev(struct replayfs_btree128_head *head,
		struct replayfs_btree128_key*__key, struct page **ret_page)
{
	int i, height;
	struct replayfs_btree128_key pos = *__key;
	unsigned long *node_data;
	unsigned long *oldnode_data;
	struct page *node, *oldnode;
	struct replayfs_btree128_key *retry_key = NULL, key;
	struct page *retry_page;

	if (keyzero(&replayfs128_geo, __key))
		return NULL;

	if (head->height == 0)
		return NULL;
	keycpy(&key, __key);
retry:
	pos = key;
	dec_key(&pos);

	node = get_head_page(head, &node_data);
	for (height = head->height ; height > 1; height--) {
		for (i = 0; i < replayfs128_geo.no_pairs; i++)
			if (valkeycmp(&replayfs128_geo, node_data, i, &pos) <= 0)
				break;
		if (i == replayfs128_geo.no_pairs)
			goto miss;
		oldnode = node;
		oldnode_data = node_data;


		node = bval(head->allocator, &replayfs128_geo, node_data, &node_data, i);

		if (!node) {
			bval_put(head, oldnode);
			goto miss;
		}

		bval_put(head, node);

		if (retry_key) {
			bval_put(head, retry_page);
		}
		retry_key = bkey(&replayfs128_geo, oldnode_data, i);
		retry_page = oldnode;
	}

	if (!node)
		goto miss;

	for (i = 0; i < replayfs128_geo.no_pairs; i++) {
		if (valkeycmp(&replayfs128_geo, node_data, i, &pos) <= 0) {
			struct page *tmppage;
			unsigned long *tmppage_data;

			tmppage = bval(head->allocator, &replayfs128_geo, node_data, &tmppage_data, i);
			if (tmppage) {
				bval_put(head, tmppage);
				keycpy(__key, bkey(&replayfs128_geo, node_data, i));
				*ret_page = node;
				return bval_at(head->allocator, &replayfs128_geo, node_data, i);
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
		struct replayfs_btree128_key *keypos)
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
		struct replayfs_btree128_key *key;

		key = bkey(geo, page_data, i);

		/*
		debugk("%s %d: Have key {%llu, %llu} at %d\n", __func__, __LINE__, key->id1,
				key->id2, i);
				*/
		if (key->id1 == 0 && key->id2 == 0) {
			break;
		}
	}
	return i;
}


/*
 * locate the correct leaf node in the btree
 */
static struct page *find_level(struct replayfs_btree128_head *head, struct btree_geo *geo,
		struct replayfs_btree128_key *key, int level, unsigned long **page_data)
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
		for (i = 0; i < geo->no_pairs; i++)
			if (valkeycmp(geo, node_data, i, key) <= 0)
				break;

		debugk("%s %d: Next node index is %d\n", __func__, __LINE__, i);

		tmpnode = bval(head->allocator, geo, node_data, &tmpnode_data, i);
		if (tmpnode) {
			debugk("%s %d: Pulled tmpnode %lu from %d\n", __func__, __LINE__,
					tmpnode->index, i);
		} else {
			debugk("%s %d: Null tmpnode! from %d\n", __func__, __LINE__, i);
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
			debugk("%s %d: Updated node to %lu\n", __func__, __LINE__, node->index);
		} else {

			BUG_ON(i < 0);

			bval_put(head, oldpage);
			oldpage = node;
			oldpage_data = node_data;

			node = tmpnode;
			node_data = tmpnode_data;
			debugk("%s %d: Updated node to %lu\n", __func__, __LINE__, node->index);
		}
	}

	bval_put(head, oldpage);

	*page_data = node_data;

	BUG_ON(!node);
	return node;
}

static int btree_grow(struct replayfs_btree128_head *head, struct btree_geo *geo,
		      gfp_t gfp)
{
	unsigned long *node_data;
	struct page *node;
	int fill;

	debugk("%s %d: about to alloc\n", __func__, __LINE__);
	node = btree_node_alloc(head, gfp);
	if (!node)
		return -ENOMEM;

	node_data = replayfs_kmap(node);

	debugk("%s %d: head->node_page is %p\n", __func__, __LINE__, head->node_page);
	if (head->node_page) {
		unsigned long *headpage_data;
		struct page *headpage;
		debugk("%s %d: Manipulating node page for tree %p\n", __func__, __LINE__,
				head);

		headpage = get_head_page(head, &headpage_data);

		fill = getfill(head->allocator, geo, headpage_data, 0);
		debugk("%s %d: here?\n", __func__, __LINE__);
		debugk("%s %d: Filling entry 0 with {%llu, %llu} from fill %d\n", __func__, __LINE__,
				bkey(geo, headpage_data, fill-1)->id1,
				bkey(geo, headpage_data, fill-1)->id2, fill);
		setkey(geo, node, 0, bkey(geo, headpage_data, fill - 1));
		setval_node(geo, node, 0, headpage);

		bval_put(head, headpage);
	}
	debugk("%s %d: Updating metadata\n", __func__, __LINE__);
	head->node_page = node;
	debugk("%s %d: Incing head->height from %d to %d\n", __func__, __LINE__,
			head->height, head->height+1);
	head->height++;
	update_meta128(head);

	debugk("%s %d: Putting node\n", __func__, __LINE__);
	bval_put(head, node);
	return 0;
}

static void btree_shrink(struct replayfs_btree128_head *head, struct btree_geo *geo)
{
	unsigned long *node_data;
	struct page *node;
	int fill;

	if (head->height <= 1)
		return;

	node = get_head_page(head, &node_data);
	fill = getfill(head->allocator, geo, node_data, 0);
	BUG_ON(fill > 1);
	head->node_page = bval(head->allocator, geo, node_data, &node_data, 0);
	head->height--;
	update_meta128(head);

	/* Need to unmap before freeing */
	replayfs_kunmap(node);
	replayfs_diskalloc_free_page(head->allocator, node);
	//mempool_free(node, head->mempool);
}

static int btree_insert_inner_level(struct replayfs_btree128_head *head, struct btree_geo *geo,
			      struct replayfs_btree128_key *key, struct page *val,
						unsigned long *val_data, int level, gfp_t gfp)
{
	unsigned long *node_data = NULL;
	struct page *node;
	int i, pos, fill, err;

	debugk("%s %d: In %s!\n", __func__, __LINE__, __func__);
	debugk("%s %d: Inserting key {%llu, %llu}!\n", __func__, __LINE__,
			key->id1, key->id2);

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
	pos = getpos(geo, node_data, key);
	fill = getfill(head->allocator, geo, node_data, pos);
	/* two identical keys are not allowed */
	debugk("%s %d: keycmp key {%llu, %llu} with fill {%llu, %llu}\n", __func__, __LINE__,
			key->id1, key->id2, bkey(geo, node_data, pos)->id1, bkey(geo, node_data, pos)->id2);
	//dump_stack();
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
		debugk("%s %d: Inserting inner-inner level?\n", __func__, __LINE__);
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

		check_page(head, node, node_data, level);
		check_page(head, new, new_data, level);

		bval_put(head, node);
		bval_put(head, new);

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

	debugk("%s %d: Inserting node %lu into pos %d with key {%llu, %llu}\n", __func__, __LINE__,
			node->index, pos, key->id1, key->id2);
	setkey(geo, node, pos, key);
	setval_node(geo, node, pos, val);

	check_page(head, node, node_data, level);

	bval_put(head, node);

	return 0;
}

static int btree_insert_level(struct replayfs_btree128_head *head, struct btree_geo *geo,
			      struct replayfs_btree128_key *key, struct replayfs_btree128_value *val, int level,
			      gfp_t gfp)
{
	unsigned long *node_data = NULL;
	struct page *node;
	int i, pos, fill, err;

	debugk("%s %d: In btree_insert_level with head %p!\n", __func__, __LINE__,
			head);
	debugk("%s %d: Inserting key {%llu, %llu}!\n", __func__, __LINE__,
			key->id1, key->id2);
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
	debugk("%s %d: past find_level, got node %lu (%p)!\n", __func__, __LINE__,
			node->index, node);
	pos = getpos(geo, node_data, key);
	fill = getfill(head->allocator, geo, node_data, pos);
	/* two identical keys are not allowed */
	debugk("%s %d: keycmp with {%llu, %llu}\n", __func__, __LINE__,
			bkey(geo, node_data, pos)->id1, bkey(geo, node_data, pos)->id2);
	BUG_ON(pos < fill && keycmp(geo, node_data, pos, key) == 0);

	debugk("%s %d: fill is %d, pos is %d no_pars is %d!\n", __func__, __LINE__,
			fill, pos, geo->no_pairs);
	/* If node full... */
	if (fill == geo->no_pairs) {
		/* need to split node */
		struct page *new;
		unsigned long *new_data;

		new = btree_node_alloc(head, gfp);
		new_data = replayfs_kmap(new);
		debugk("%s %d: past node_alloc!\n", __func__, __LINE__);
		if (!new)
			return -ENOMEM;
		debugk("%s %d: Inserting inner level\n", __func__, __LINE__);
		err = btree_insert_inner_level(head, geo,
				bkey(geo, node_data, fill / 2 - 1),
				new, new_data, level + 1, gfp);
		if (err) {
			//mempool_free(new, head->mempool);
			replayfs_kunmap(new);
			replayfs_diskalloc_free_page(head->allocator, new);
			return err;
		}

		debugk("%s %d: Adjusting (allocator %d) pages (new) %lu and (node) %lu into tree with head %p\n", __func__,
				__LINE__, head->allocator->allocnum, new->index, node->index, head);
		for (i = 0; i < fill / 2; i++) {
			struct replayfs_btree128_value *tmp;
			struct replayfs_btree128_key *key = bkey(geo, node_data, i);
			debugk("%s %d: Dealing with key at %lu offset %lu\n", __func__, __LINE__,
					node->index, ((unsigned long)key) % (PAGE_SIZE));
			debugk("%s %d: Moving key {%llu, %llu} from node %lu (%d) to %lu (%d)\n",
					__func__, __LINE__, key->id1, key->id2, node->index, i, new->index,
					i);
			setkey(geo, new, i, key);
			tmp = bval_at(head->allocator, geo, node_data, i);
			setval(geo, new, i, tmp);
			key = bkey(geo, node_data, i+fill/2);
			debugk("%s %d: Dealing with key at %lu offset %lu\n", __func__, __LINE__,
					node->index, ((unsigned long)key) % (PAGE_SIZE));
			debugk("%s %d: Moving key {%llu, %llu} from node %lu (%d) to %lu (%d)\n",
					__func__, __LINE__, key->id1, key->id2, node->index, i+fill/2, node->index,
					i);
			setkey(geo, node, i, key);
			tmp = bval_at(head->allocator, geo, node_data, i + fill / 2);
			setval(geo, node, i, tmp);
			debugk("%s %d: Clearing index %d in node %lu\n", 
					__func__, __LINE__, i+fill/2, node->index);
			clearpair(geo, node, i + fill / 2);
		}

		if (fill & 1) {
			struct replayfs_btree128_value *tmp;
			struct replayfs_btree128_key *key = bkey(geo, node_data, fill-1);

			debugk("%s %d: Moving key {%llu, %llu} from node %lu (%d) to %lu (%d)\n",
					__func__, __LINE__, key->id1, key->id2, node->index, fill-1, node->index,
					i);
			setkey(geo, node, i, key);
			tmp = bval_at(head->allocator, geo, node_data, fill - 1);
			setval(geo, node, i, tmp);
			debugk("%s %d: Clearing index %d in node %lu\n", 
					__func__, __LINE__, fill-1, node->index);
			clearpair(geo, node, fill - 1);
		}

		check_page(head, node, node_data, level);
		check_page(head, new, new_data, level);

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
	setkey(geo, node, pos, key);
	setval(geo, node, pos, val);

	debugk("%s %d: Putting node %lu\n", __func__, __LINE__, node->index);
	bval_put(head, node);

	return 0;
}

int replayfs_btree128_insert(struct replayfs_btree128_head *head,
		struct replayfs_btree128_key *key, struct replayfs_btree128_value *val, gfp_t gfp)
{
	int ret;
	BUG_ON(!val);
	check_tree(head);

	ret =  btree_insert_level(head, &replayfs128_geo, key, val, 1, gfp);

	replayfs_btree128_verify_insert(head, key, val, gfp);

	if (head->node_page != NULL) {
		replayfs_diskalloc_sync_page(head->allocator, head->node_page);
	}

	check_tree(head);

	return ret;
}

static int btree_remove_level(struct replayfs_btree128_head *head, struct btree_geo *geo,
		struct replayfs_btree128_key *key, int level);
static void merge(struct replayfs_btree128_head *head, struct btree_geo *geo, int level,
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
		debugk("%s %d: Deleting key {%llu, %llu} (pos %d)\n", __func__, __LINE__,
				bkey(geo, parent_data, lpos)->id1, bkey(geo, parent_data,
					lpos)->id2, lpos);
		btree_remove_level(head, geo, bkey(geo, parent_data, lpos), level + 1);
	} else {
		for (i = 0; i < rfill; i++) {
			struct replayfs_btree128_value *tmp;
			/* Move all keys to the left */
			setkey(geo, left, lfill + i, bkey(geo, right_data, i));
			tmp = bval_at(head->allocator, geo, right_data, i);
			setval(geo, left, lfill + i, tmp);
		}
		/* Exchange left and right child in parent */
		debugk("%s %d: Moving page %lu to %d\n", __func__, __LINE__, right->index,
				lpos);
		setval_node(geo, parent, lpos, right);
		debugk("%s %d: Moving page %lu to %d\n", __func__, __LINE__, left->index,
				lpos+1);
		setval_node(geo, parent, lpos + 1, left);
		/* Remove left (formerly right) child from parent */
		debugk("%s %d: Deleting key {%llu, %llu} (pos %d)\n", __func__, __LINE__,
				bkey(geo, parent_data, lpos)->id1, bkey(geo, parent_data,
					lpos)->id2, lpos);
		btree_remove_level(head, geo, bkey(geo, parent_data, lpos), level + 1);
	}

	/* Got to free the right node */
	replayfs_kunmap(right);
	replayfs_diskalloc_free_page(head->allocator, right);
}

/* Returns with do-free for node */
static int rebalance(struct replayfs_btree128_head *head, struct btree_geo *geo,
		struct replayfs_btree128_key *key, int level, struct page *child,
		unsigned long *child_data, int fill)
{
	unsigned long *parent_data = NULL;
	unsigned long *left_data = NULL;
	unsigned long *right_data = NULL;
	struct page *parent, *left = NULL, *right = NULL;
	int i, no_left, no_right;

	if (fill == 0) {
		/* Because we don't steal entries from a neighbour, this case
		 * can happen.  Parent node contains a single child, this
		 * node, so merging with a sibling never happens.
		 */
		btree_remove_level(head, geo, key, level + 1);
		//mempool_free(child, head->mempool);
		replayfs_diskalloc_free_page(head->allocator, child);
		return 0;
	}

	parent = find_level(head, geo, key, level + 1, &parent_data);

	i = getpos(geo, parent_data, key);
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
			return 0;
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
			/* Don't put right... we just free'd it... */
			//bval_put(head, right);
			return 1;
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

	return 1;
}

static int btree_remove_level(struct replayfs_btree128_head *head, struct btree_geo *geo,
		struct replayfs_btree128_key *key, int level)
{
	unsigned long *node_data = NULL;
	struct page *node;
	int i, pos, fill;

	int needs_shrink = 0;
	int needs_put = 1;

	if (level > head->height) {
		/* we recursed all the way up */
		head->height = 0;
		head->node_page = NULL;
		update_meta128(head);
		return 0;
	}

	node = find_level(head, geo, key, level, &node_data);

	pos = getpos(geo, node_data, key);

	fill = getfill(head->allocator, geo, node_data, pos);
	debugk("%s %d: fill is %d, pos is %d no_pars is %d!\n", __func__, __LINE__,
			fill, pos, geo->no_pairs);
	if ((level == 1) && (keycmp(geo, node_data, pos, key) != 0)) {
		bval_put(head, node);
		debugk("%s %d: returning NULL?\n", __func__, __LINE__);
		return 0;
	}

	debugk("%s %d: Removing key from head %p: {%llu, %llu}\n", __func__, __LINE__,
			head, bkey(geo, node_data, pos)->id1, bkey(geo, node_data, pos)->id2);

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
			struct replayfs_btree128_value *tmp;
			setkey(geo, node, i, bkey(geo, node_data, i + 1));
			tmp = bval_at(head->allocator, geo, node_data, i+1);
			setval(geo, node, i, tmp);
		}
	}
	clearpair(geo, node, fill - 1);

	if (fill - 1 < geo->no_pairs / 2) {
		if (level < head->height)
			needs_put = rebalance(head, geo, key, level, node, node_data, fill - 1);
		else if (fill - 1 == 1) {

			needs_shrink = 1;
		}
	}

	if (needs_put) {
		bval_put(head, node);
	}

	if (needs_shrink) {
		btree_shrink(head, geo);
	}

	return 1;
}

int replayfs_btree128_remove(struct replayfs_btree128_head *head,
		   struct replayfs_btree128_key *key)
{
	int ret;

	check_tree(head);

	if (head->height == 0)
		return 0;

	ret = btree_remove_level(head, &replayfs128_geo, key, 1);

	replayfs_btree128_verify_remove(head, key, ret);

	check_tree(head);

	return ret;
}

int replayfs_btree128_merge(struct replayfs_btree128_head *target, struct replayfs_btree128_head *victim,
		gfp_t gfp)
{
	/*
	unsigned long key[replayfs128_geo.keylen];
	unsigned long dup[replayfs128_geo.keylen];
	*/
	struct replayfs_btree128_key key;
	struct replayfs_btree128_key dup;
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
		if (!replayfs_btree128_last(victim, &key, &page))
			break;
		bval_put(victim, page);
		val = replayfs_btree128_lookup(victim, &key, &page);
		err = replayfs_btree128_insert(target, &key, val, gfp);
		bval_put(victim, val);
		if (err)
			return err;
		/* We must make a copy of the key, as the original will get
		 * mangled inside btree_remove. */
		keycpy(&dup, &key);
		replayfs_btree128_remove(victim, &dup);
		bval_put(victim, val);
	}
	return 0;
}

MODULE_AUTHOR("Joern Engel <joern@logfs.org>");
MODULE_AUTHOR("Johannes Berg <johannes@sipsolutions.net>");
MODULE_LICENSE("GPL");

