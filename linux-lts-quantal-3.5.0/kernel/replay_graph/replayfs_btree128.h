#ifndef REPLAYFS_BTREE128_H
#define REPLAYFS_BTREE128_H

#include <linux/replay.h>
#include <linux/kernel.h>
#include <linux/mempool.h>
#include <linux/slab.h>

#include "replayfs_diskalloc.h"

/**
 * DOC: B+Tree basics
 *
 * A B+Tree is a data structure for looking up arbitrary (currently allowing
 * unsigned long, u32, u64 and 2 * u64) keys into pointers. The data structure
 * is described at http://en.wikipedia.org/wiki/B-tree, we currently do not
 * use binary search to find the key on lookups.
 *
 * Each B+Tree consists of a head, that contains bookkeeping information and
 * a variable number (starting with zero) nodes. Each node contains the keys
 * and pointers to sub-nodes, or, for leaf nodes, the keys and values for the
 * tree entries.
 *
 * Each node in this implementation has the following layout:
 * [key1, key2, ..., keyN] [val1, val2, ..., valN]
 *
 * Each key here is an array of unsigned longs, geo->no_longs in total. The
 * number of keys and values (N) is geo->no_pairs.
 */

struct replayfs_btree_meta {
	loff_t node_page;
	int height;

	/* FIXME: Yeah, its hacky... on the todo list */
	loff_t i_size;

	loff_t cache_tree_loc;
};

struct replayfs_btree128_key {
	u64 id1;
	u64 id2;
};

struct replayfs_btree128_value {
	loff_t id;
};

extern struct replayfs_btree128_value replayfs_zero128_value;

/**
 * struct btree_head - btree head
 *
 * @node: the first node in the tree
 * @mempool: mempool used for node allocations
 * @height: current of the tree
 */
struct replayfs_btree128_head {
	struct page *node_page;
	loff_t meta_loc;
	//mempool_t *mempool;
	struct replayfs_diskalloc *allocator;
	int height;
};

/**
 * btree_alloc - allocate function for the mempool
 * @gfp_mask: gfp mask for the allocation
 * @pool_data: unused
 */
void *replayfs_btree128_alloc(gfp_t gfp_mask, void *pool_data);

/**
 * btree_free - free function for the mempool
 * @element: the element to free
 * @pool_data: unused
 */
void replayfs_btree128_free(void *element, void *pool_data);

/**
 * btree_init_mempool - initialise a btree with given mempool
 *
 * @head: the btree head to initialise
 * @mempool: the mempool to use
 *
 * When this function is used, there is no need to destroy
 * the mempool.
 */
void replayfs_btree128_init_allocator(struct replayfs_btree128_head *head, struct
		replayfs_diskalloc *allocator);

/**
 * btree_init - initialise a btree
 *
 * @head: the btree head to initialise
 * @disk_pos: the offset on disk of the root node
 *
 * This function allocates the memory pool that the
 * btree needs. Returns zero or a negative error code
 * (-%ENOMEM) when memory allocation fails.
 *
 */
int __must_check replayfs_btree128_init(struct replayfs_btree128_head *head,
		struct replayfs_diskalloc *alloc, loff_t meta_loc);

int __must_check replayfs_btree128_create(struct replayfs_btree128_head *head,
	struct replayfs_diskalloc *alloc, loff_t meta_loc);

/**
 * btree_destroy - destroy mempool
 *
 * @head: the btree head to destroy
 *
 * This function destroys the internal memory pool, use only
 * when using btree_init(), not with btree_init_mempool().
 */
void replayfs_btree128_destroy(struct replayfs_btree128_head *head);

void replayfs_btree128_put_page(struct replayfs_btree128_head *head,
		struct page *page);
/**
 * btree_lookup - look up a key in the btree
 *
 * @head: the btree to look in
 * @pos: the position to find
 * @key: (output) the key that contains pos
 *
 * This function returns the value for the given key, or %NULL.
 */
struct replayfs_btree128_value *replayfs_btree128_lookup(struct replayfs_btree128_head *head,
		   struct replayfs_btree128_key *key, struct page **ret_page);

/**
 * btree_insert - insert an entry into the btree
 *
 * @head: the btree to add to
 * @key: the key to add (must not already be present)
 * @val: the value to add (must not be %NULL)
 * @gfp: allocation flags for node allocations
 *
 * This function returns 0 if the item could be added, or an
 * error code if it failed (may fail due to memory pressure).
 */
int replayfs_btree128_insert(struct replayfs_btree128_head *head,
		struct replayfs_btree128_key *key, struct replayfs_btree128_value *val, gfp_t gfp);

/**
 * btree_remove - remove an entry from the btree
 *
 * @head: the btree to update
 * @key: the key to remove
 *
 * This function returns the removed entry, or %NULL if the key
 * could not be found.
 */
struct replayfs_btree128_value *replayfs_btree128_remove(struct replayfs_btree128_head *head,
		   struct replayfs_btree128_key *key, struct page **page);

/**
 * btree_merge - merge two btrees
 *
 * @target: the tree that gets all the entries
 * @victim: the tree that gets merged into @target
 * @gfp: allocation flags
 *
 * The two trees @target and @victim may not contain the same keys,
 * that is a bug and triggers a BUG(). This function returns zero
 * if the trees were merged successfully, and may return a failure
 * when memory allocation fails, in which case both trees might have
 * been partially merged, i.e. some entries have been moved from
 * @victim to @target.
 */
int replayfs_btree128_merge(struct replayfs_btree128_head *target, struct replayfs_btree128_head *victim,
		gfp_t gfp);

/**
 * btree_last - get last entry in btree
 *
 * @head: btree head
 * @key: last key
 *
 * Returns the last entry in the btree, and sets @key to the key
 * of that entry; returns NULL if the tree is empty, in that case
 * key is not changed.
 */
struct replayfs_btree128_value *replayfs_btree128_last(struct replayfs_btree128_head *head, 
		struct replayfs_btree128_key *key, struct page **ret_page);

/**
 * btree_get_prev - get previous entry
 *
 * @head: btree head
 * @key: pointer to key
 *
 * The function returns the next item right before the value pointed to by
 * @key, and updates @key with its key, or returns %NULL when there is no
 * entry with a key smaller than the given key.
 */
struct replayfs_btree128_value *replayfs_btree128_get_prev(struct replayfs_btree128_head *head,
		     struct replayfs_btree128_key *key, struct page **ret_page);


/* internal use, use btree_visitor{l,32,64,128} */
size_t replayfs_btree128_visitor(struct replayfs_btree128_head *head,
		     unsigned long opaque,
		     void (*func)(void *elem, unsigned long opaque,
				  struct replayfs_btree128_key *key, size_t index,
				  void *func2),
		     void *func2);

/* internal use, use btree_grim_visitor{l,32,64,128} */
size_t replayfs_btree128_grim_visitor(struct replayfs_btree128_head *head,
			  unsigned long opaque,
			  void (*func)(void *elem, unsigned long opaque,
				       struct replayfs_btree128_key *key,
				       size_t index, void *func2),
			  void *func2);


#if 0
#include <linux/btree-128.h>

extern struct btree_geo btree_geo32;
#define BTREE_TYPE_SUFFIX l
#define BTREE_TYPE_BITS BITS_PER_LONG
#define BTREE_TYPE_GEO &btree_geo32
#define BTREE_KEYTYPE unsigned long
#include <linux/btree-type.h>

#define btree_for_each_safel(head, key, val)	\
	for (val = btree_lastl(head, &key);	\
	     val;				\
	     val = btree_get_prevl(head, &key))

#define BTREE_TYPE_SUFFIX 32
#define BTREE_TYPE_BITS 32
#define BTREE_TYPE_GEO &btree_geo32
#define BTREE_KEYTYPE u32
#include <linux/btree-type.h>

#define btree_for_each_safe32(head, key, val)	\
	for (val = btree_last32(head, &key);	\
	     val;				\
	     val = btree_get_prev32(head, &key))

extern struct btree_geo btree_geo64;
#define BTREE_TYPE_SUFFIX 64
#define BTREE_TYPE_BITS 64
#define BTREE_TYPE_GEO &btree_geo64
#define BTREE_KEYTYPE u64
#include <linux/btree-type.h>

#define btree_for_each_safe64(head, key, val)	\
	for (val = btree_last64(head, &key);	\
	     val;				\
	     val = btree_get_prev64(head, &key))

#endif

#endif
