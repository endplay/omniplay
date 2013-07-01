/**************************************************************************
 *
 * Copyright 2006 Tungsten Graphics, Inc., Bismarck, ND., USA.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 **************************************************************************/

/*
 * Generic simple memory manager implementation. Intended to be used as a base
 * class implementation for more advanced memory managers.
 *
 * Note that the algorithm used is quite simple and there might be substantial
 * performance gains if a smarter free list is implemented. Currently it is just an
 * unordered stack of free regions. This could easily be improved if an RB-tree
 * is used instead. At least if we expect heavy fragmentation.
 *
 * Aligned allocations can also see improvement.
 *
 * Authors:
 * Thomas Hellström <thomas-at-tungstengraphics-dot-com>
 */

#include <drm/drmP.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/export.h>

#define MM_UNUSED_TARGET 4

static struct drm_mm_node_hsw *drm_mm_kmalloc_hsw(struct drm_mm_hsw *mm, int atomic)
{
	struct drm_mm_node_hsw *child;

	if (atomic)
		child = kzalloc(sizeof(*child), GFP_ATOMIC);
	else
		child = kzalloc(sizeof(*child), GFP_KERNEL);

	if (unlikely(child == NULL)) {
		spin_lock(&mm->unused_lock);
		if (list_empty(&mm->unused_nodes))
			child = NULL;
		else {
			child =
			    list_entry(mm->unused_nodes.next,
				       struct drm_mm_node_hsw, node_list);
			list_del(&child->node_list);
			--mm->num_unused;
		}
		spin_unlock(&mm->unused_lock);
	}
	return child;
}

/* drm_mm_pre_get_hsw() - pre allocate drm_mm_node structure
 * drm_mm:	memory manager struct we are pre-allocating for
 *
 * Returns 0 on success or -ENOMEM if allocation fails.
 */
int drm_mm_pre_get_hsw(struct drm_mm_hsw *mm)
{
	struct drm_mm_node_hsw *node;

	spin_lock(&mm->unused_lock);
	while (mm->num_unused < MM_UNUSED_TARGET) {
		spin_unlock(&mm->unused_lock);
		node = kzalloc(sizeof(*node), GFP_KERNEL);
		spin_lock(&mm->unused_lock);

		if (unlikely(node == NULL)) {
			int ret = (mm->num_unused < 2) ? -ENOMEM : 0;
			spin_unlock(&mm->unused_lock);
			return ret;
		}
		++mm->num_unused;
		list_add_tail(&node->node_list, &mm->unused_nodes);
	}
	spin_unlock(&mm->unused_lock);
	return 0;
}
EXPORT_SYMBOL(drm_mm_pre_get_hsw);

static inline unsigned long drm_mm_hole_node_start_hsw(struct drm_mm_node_hsw *hole_node)
{
	return hole_node->start + hole_node->size;
}

static inline unsigned long drm_mm_hole_node_end_hsw(struct drm_mm_node_hsw *hole_node)
{
	struct drm_mm_node_hsw *next_node =
		list_entry(hole_node->node_list.next, struct drm_mm_node_hsw,
			   node_list);

	return next_node->start;
}

static void drm_mm_insert_helper_hsw(struct drm_mm_node_hsw *hole_node,
				 struct drm_mm_node_hsw *node,
				 unsigned long size, unsigned alignment,
				 unsigned long color)
{
	struct drm_mm_hsw *mm = hole_node->mm;
	unsigned long hole_start = drm_mm_hole_node_start_hsw(hole_node);
	unsigned long hole_end = drm_mm_hole_node_end_hsw(hole_node);
	unsigned long adj_start = hole_start;
	unsigned long adj_end = hole_end;

	BUG_ON(!hole_node->hole_follows || node->allocated);

	if (mm->color_adjust)
		mm->color_adjust(hole_node, color, &adj_start, &adj_end);

	if (alignment) {
		unsigned tmp = adj_start % alignment;
		if (tmp)
			adj_start += alignment - tmp;
	}

	if (adj_start == hole_start) {
		hole_node->hole_follows = 0;
		list_del(&hole_node->hole_stack);
	}

	node->start = adj_start;
	node->size = size;
	node->mm = mm;
	node->color = color;
	node->allocated = 1;

	INIT_LIST_HEAD(&node->hole_stack);
	list_add(&node->node_list, &hole_node->node_list);

	BUG_ON(node->start + node->size > adj_end);

	node->hole_follows = 0;
	if (node->start + node->size < hole_end) {
		list_add(&node->hole_stack, &mm->hole_stack);
		node->hole_follows = 1;
	}
}

struct drm_mm_node_hsw *drm_mm_get_block_generic_hsw(struct drm_mm_node_hsw *hole_node,
					     unsigned long size,
					     unsigned alignment,
					     unsigned long color,
					     int atomic)
{
	struct drm_mm_node_hsw *node;

	node = drm_mm_kmalloc_hsw(hole_node->mm, atomic);
	if (unlikely(node == NULL))
		return NULL;

	drm_mm_insert_helper_hsw(hole_node, node, size, alignment, color);

	return node;
}
EXPORT_SYMBOL(drm_mm_get_block_generic_hsw);

/**
 * Search for free space and insert a preallocated memory node. Returns
 * -ENOSPC if no suitable free area is available. The preallocated memory node
 * must be cleared.
 */
int drm_mm_insert_node_hsw(struct drm_mm_hsw *mm, struct drm_mm_node_hsw *node,
		       unsigned long size, unsigned alignment)
{
	struct drm_mm_node_hsw *hole_node;

	hole_node = drm_mm_search_free_generic_hsw(mm, size, alignment, 0, false);
	if (!hole_node)
		return -ENOSPC;

	drm_mm_insert_helper_hsw(hole_node, node, size, alignment, 0);

	return 0;
}
EXPORT_SYMBOL(drm_mm_insert_node_hsw);

static void drm_mm_insert_helper_range_hsw(struct drm_mm_node_hsw *hole_node,
				       struct drm_mm_node_hsw *node,
				       unsigned long size, unsigned alignment,
				       unsigned long color,
				       unsigned long start, unsigned long end)
{
	struct drm_mm_hsw *mm = hole_node->mm;
	unsigned long hole_start = drm_mm_hole_node_start_hsw(hole_node);
	unsigned long hole_end = drm_mm_hole_node_end_hsw(hole_node);
	unsigned long adj_start = hole_start;
	unsigned long adj_end = hole_end;

	BUG_ON(!hole_node->hole_follows || node->allocated);

	if (mm->color_adjust)
		mm->color_adjust(hole_node, color, &adj_start, &adj_end);

	if (adj_start < start)
		adj_start = start;

	if (alignment) {
		unsigned tmp = adj_start % alignment;
		if (tmp)
			adj_start += alignment - tmp;
	}

	if (adj_start == hole_start) {
		hole_node->hole_follows = 0;
		list_del(&hole_node->hole_stack);
	}

	node->start = adj_start;
	node->size = size;
	node->mm = mm;
	node->color = color;
	node->allocated = 1;

	INIT_LIST_HEAD(&node->hole_stack);
	list_add(&node->node_list, &hole_node->node_list);

	BUG_ON(node->start + node->size > adj_end);
	BUG_ON(node->start + node->size > end);

	node->hole_follows = 0;
	if (node->start + node->size < hole_end) {
		list_add(&node->hole_stack, &mm->hole_stack);
		node->hole_follows = 1;
	}
}

struct drm_mm_node_hsw *drm_mm_get_block_range_generic_hsw(struct drm_mm_node_hsw *hole_node,
						unsigned long size,
						unsigned alignment,
						unsigned long color,
						unsigned long start,
						unsigned long end,
						int atomic)
{
	struct drm_mm_node_hsw *node;

	node = drm_mm_kmalloc_hsw(hole_node->mm, atomic);
	if (unlikely(node == NULL))
		return NULL;

	drm_mm_insert_helper_range_hsw(hole_node, node, size, alignment, color,
				   start, end);

	return node;
}
EXPORT_SYMBOL(drm_mm_get_block_range_generic_hsw);

/**
 * Search for free space and insert a preallocated memory node. Returns
 * -ENOSPC if no suitable free area is available. This is for range
 * restricted allocations. The preallocated memory node must be cleared.
 */
int drm_mm_insert_node_in_range_hsw(struct drm_mm_hsw *mm, struct drm_mm_node_hsw *node,
				unsigned long size, unsigned alignment,
				unsigned long start, unsigned long end)
{
	struct drm_mm_node_hsw *hole_node;

	hole_node = drm_mm_search_free_in_range_generic_hsw(mm, size, alignment, 0,
						start, end, false);
	if (!hole_node)
		return -ENOSPC;

	drm_mm_insert_helper_range_hsw(hole_node, node, size, alignment, 0,
				   start, end);

	return 0;
}
EXPORT_SYMBOL(drm_mm_insert_node_in_range_hsw);

/**
 * Remove a memory node from the allocator.
 */
void drm_mm_remove_node_hsw(struct drm_mm_node_hsw *node)
{
	struct drm_mm_hsw *mm = node->mm;
	struct drm_mm_node_hsw *prev_node;

	BUG_ON(node->scanned_block || node->scanned_prev_free
				   || node->scanned_next_free);

	prev_node =
	    list_entry(node->node_list.prev, struct drm_mm_node_hsw, node_list);

	if (node->hole_follows) {
		BUG_ON(drm_mm_hole_node_start_hsw(node)
				== drm_mm_hole_node_end_hsw(node));
		list_del(&node->hole_stack);
	} else
		BUG_ON(drm_mm_hole_node_start_hsw(node)
				!= drm_mm_hole_node_end_hsw(node));

	if (!prev_node->hole_follows) {
		prev_node->hole_follows = 1;
		list_add(&prev_node->hole_stack, &mm->hole_stack);
	} else
		list_move(&prev_node->hole_stack, &mm->hole_stack);

	list_del(&node->node_list);
	node->allocated = 0;
}
EXPORT_SYMBOL(drm_mm_remove_node_hsw);

/*
 * Remove a memory node from the allocator and free the allocated struct
 * drm_mm_node. Only to be used on a struct drm_mm_node_hsw obtained by one of the
 * drm_mm_get_block functions.
 */
void drm_mm_put_block_hsw(struct drm_mm_node_hsw *node)
{

	struct drm_mm_hsw *mm = node->mm;

	drm_mm_remove_node_hsw(node);

	spin_lock(&mm->unused_lock);
	if (mm->num_unused < MM_UNUSED_TARGET) {
		list_add(&node->node_list, &mm->unused_nodes);
		++mm->num_unused;
	} else
		kfree(node);
	spin_unlock(&mm->unused_lock);
}
EXPORT_SYMBOL(drm_mm_put_block_hsw);

static int check_free_hole_hsw(unsigned long start, unsigned long end,
			   unsigned long size, unsigned alignment)
{
	if (end - start < size)
		return 0;

	if (alignment) {
		unsigned tmp = start % alignment;
		if (tmp)
			start += alignment - tmp;
	}

	return end >= start + size;
}

struct drm_mm_node_hsw *drm_mm_search_free_generic_hsw(const struct drm_mm_hsw *mm,
					       unsigned long size,
					       unsigned alignment,
					       unsigned long color,
					       bool best_match)
{
	struct drm_mm_node_hsw *entry;
	struct drm_mm_node_hsw *best;
	unsigned long best_size;

	BUG_ON(mm->scanned_blocks);

	best = NULL;
	best_size = ~0UL;

	list_for_each_entry(entry, &mm->hole_stack, hole_stack) {
		unsigned long adj_start = drm_mm_hole_node_start_hsw(entry);
		unsigned long adj_end = drm_mm_hole_node_end_hsw(entry);

		if (mm->color_adjust) {
			mm->color_adjust(entry, color, &adj_start, &adj_end);
			if (adj_end <= adj_start)
				continue;
		}

		BUG_ON(!entry->hole_follows);
		if (!check_free_hole_hsw(adj_start, adj_end, size, alignment))
			continue;

		if (!best_match)
			return entry;

		if (entry->size < best_size) {
			best = entry;
			best_size = entry->size;
		}
	}

	return best;
}
EXPORT_SYMBOL(drm_mm_search_free_generic_hsw);

struct drm_mm_node_hsw *drm_mm_search_free_in_range_generic_hsw(const struct drm_mm_hsw *mm,
							unsigned long size,
							unsigned alignment,
							unsigned long color,
							unsigned long start,
							unsigned long end,
							bool best_match)
{
	struct drm_mm_node_hsw *entry;
	struct drm_mm_node_hsw *best;
	unsigned long best_size;

	BUG_ON(mm->scanned_blocks);

	best = NULL;
	best_size = ~0UL;

	list_for_each_entry(entry, &mm->hole_stack, hole_stack) {
		unsigned long adj_start = drm_mm_hole_node_start_hsw(entry) < start ?
			start : drm_mm_hole_node_start_hsw(entry);
		unsigned long adj_end = drm_mm_hole_node_end_hsw(entry) > end ?
			end : drm_mm_hole_node_end_hsw(entry);

		BUG_ON(!entry->hole_follows);

		if (mm->color_adjust) {
			mm->color_adjust(entry, color, &adj_start, &adj_end);
			if (adj_end <= adj_start)
				continue;
		}

		if (!check_free_hole_hsw(adj_start, adj_end, size, alignment))
			continue;

		if (!best_match)
			return entry;

		if (entry->size < best_size) {
			best = entry;
			best_size = entry->size;
		}
	}

	return best;
}
EXPORT_SYMBOL(drm_mm_search_free_in_range_generic_hsw);

/**
 * Moves an allocation. To be used with embedded struct drm_mm_node_hsw.
 */
void drm_mm_replace_node_hsw(struct drm_mm_node_hsw *old, struct drm_mm_node_hsw *new)
{
	list_replace(&old->node_list, &new->node_list);
	list_replace(&old->hole_stack, &new->hole_stack);
	new->hole_follows = old->hole_follows;
	new->mm = old->mm;
	new->start = old->start;
	new->size = old->size;
	new->color = old->color;

	old->allocated = 0;
	new->allocated = 1;
}
EXPORT_SYMBOL(drm_mm_replace_node_hsw);

/**
 * Initializa lru scanning.
 *
 * This simply sets up the scanning routines with the parameters for the desired
 * hole.
 *
 * Warning: As long as the scan list is non-empty, no other operations than
 * adding/removing nodes to/from the scan list are allowed.
 */
void drm_mm_init_scan_hsw(struct drm_mm_hsw *mm,
		      unsigned long size,
		      unsigned alignment,
		      unsigned long color)
{
	mm->scan_color = color;
	mm->scan_alignment = alignment;
	mm->scan_size = size;
	mm->scanned_blocks = 0;
	mm->scan_hit_start = 0;
	mm->scan_hit_size = 0;
	mm->scan_check_range = 0;
	mm->prev_scanned_node = NULL;
}
EXPORT_SYMBOL(drm_mm_init_scan_hsw);

/**
 * Initializa lru scanning.
 *
 * This simply sets up the scanning routines with the parameters for the desired
 * hole. This version is for range-restricted scans.
 *
 * Warning: As long as the scan list is non-empty, no other operations than
 * adding/removing nodes to/from the scan list are allowed.
 */
void drm_mm_init_scan_with_range_hsw(struct drm_mm_hsw *mm,
				 unsigned long size,
				 unsigned alignment,
				 unsigned long color,
				 unsigned long start,
				 unsigned long end)
{
	mm->scan_color = color;
	mm->scan_alignment = alignment;
	mm->scan_size = size;
	mm->scanned_blocks = 0;
	mm->scan_hit_start = 0;
	mm->scan_hit_size = 0;
	mm->scan_start = start;
	mm->scan_end = end;
	mm->scan_check_range = 1;
	mm->prev_scanned_node = NULL;
}
EXPORT_SYMBOL(drm_mm_init_scan_with_range_hsw);

/**
 * Add a node to the scan list that might be freed to make space for the desired
 * hole.
 *
 * Returns non-zero, if a hole has been found, zero otherwise.
 */
int drm_mm_scan_add_block_hsw(struct drm_mm_node_hsw *node)
{
	struct drm_mm_hsw *mm = node->mm;
	struct drm_mm_node_hsw *prev_node;
	unsigned long hole_start, hole_end;
	unsigned long adj_start;
	unsigned long adj_end;

	mm->scanned_blocks++;

	BUG_ON(node->scanned_block);
	node->scanned_block = 1;

	prev_node = list_entry(node->node_list.prev, struct drm_mm_node_hsw,
			       node_list);

	node->scanned_preceeds_hole = prev_node->hole_follows;
	prev_node->hole_follows = 1;
	list_del(&node->node_list);
	node->node_list.prev = &prev_node->node_list;
	node->node_list.next = &mm->prev_scanned_node->node_list;
	mm->prev_scanned_node = node;

	hole_start = drm_mm_hole_node_start_hsw(prev_node);
	hole_end = drm_mm_hole_node_end_hsw(prev_node);

	adj_start = hole_start;
	adj_end = hole_end;

	if (mm->color_adjust)
		mm->color_adjust(prev_node, mm->scan_color, &adj_start, &adj_end);

	if (mm->scan_check_range) {
		if (adj_start < mm->scan_start)
			adj_start = mm->scan_start;
		if (adj_end > mm->scan_end)
			adj_end = mm->scan_end;
	}

	if (check_free_hole_hsw(adj_start, adj_end,
			    mm->scan_size, mm->scan_alignment)) {
		mm->scan_hit_start = hole_start;
		mm->scan_hit_size = hole_end;

		return 1;
	}

	return 0;
}
EXPORT_SYMBOL(drm_mm_scan_add_block_hsw);

/**
 * Remove a node from the scan list.
 *
 * Nodes _must_ be removed in the exact same order from the scan list as they
 * have been added, otherwise the internal state of the memory manager will be
 * corrupted.
 *
 * When the scan list is empty, the selected memory nodes can be freed. An
 * immediately following drm_mm_search_free with best_match = 0 will then return
 * the just freed block (because its at the top of the free_stack list).
 *
 * Returns one if this block should be evicted, zero otherwise. Will always
 * return zero when no hole has been found.
 */
int drm_mm_scan_remove_block_hsw(struct drm_mm_node_hsw *node)
{
	struct drm_mm_hsw *mm = node->mm;
	struct drm_mm_node_hsw *prev_node;

	mm->scanned_blocks--;

	BUG_ON(!node->scanned_block);
	node->scanned_block = 0;

	prev_node = list_entry(node->node_list.prev, struct drm_mm_node_hsw,
			       node_list);

	prev_node->hole_follows = node->scanned_preceeds_hole;
	INIT_LIST_HEAD(&node->node_list);
	list_add(&node->node_list, &prev_node->node_list);

	/* Only need to check for containement because start&size for the
	 * complete resulting free block (not just the desired part) is
	 * stored. */
	if (node->start >= mm->scan_hit_start &&
	    node->start + node->size
	    		<= mm->scan_hit_start + mm->scan_hit_size) {
		return 1;
	}

	return 0;
}
EXPORT_SYMBOL(drm_mm_scan_remove_block_hsw);

int drm_mm_clean_hsw(struct drm_mm_hsw * mm)
{
	struct list_head *head = &mm->head_node.node_list;

	return (head->next->next == head);
}
EXPORT_SYMBOL(drm_mm_clean_hsw);

int drm_mm_init_hsw(struct drm_mm_hsw * mm, unsigned long start, unsigned long size)
{
	INIT_LIST_HEAD(&mm->hole_stack);
	INIT_LIST_HEAD(&mm->unused_nodes);
	mm->num_unused = 0;
	mm->scanned_blocks = 0;
	spin_lock_init(&mm->unused_lock);

	/* Clever trick to avoid a special case in the free hole tracking. */
	INIT_LIST_HEAD(&mm->head_node.node_list);
	INIT_LIST_HEAD(&mm->head_node.hole_stack);
	mm->head_node.hole_follows = 1;
	mm->head_node.scanned_block = 0;
	mm->head_node.scanned_prev_free = 0;
	mm->head_node.scanned_next_free = 0;
	mm->head_node.mm = mm;
	mm->head_node.start = start + size;
	mm->head_node.size = start - mm->head_node.start;
	list_add_tail(&mm->head_node.hole_stack, &mm->hole_stack);

	mm->color_adjust = NULL;

	return 0;
}
EXPORT_SYMBOL(drm_mm_init_hsw);

void drm_mm_takedown_hsw(struct drm_mm_hsw * mm)
{
	struct drm_mm_node_hsw *entry, *next;

	if (!list_empty(&mm->head_node.node_list)) {
		DRM_ERROR("Memory manager not clean. Delaying takedown\n");
		return;
	}

	spin_lock(&mm->unused_lock);
	list_for_each_entry_safe(entry, next, &mm->unused_nodes, node_list) {
		list_del(&entry->node_list);
		kfree(entry);
		--mm->num_unused;
	}
	spin_unlock(&mm->unused_lock);

	BUG_ON(mm->num_unused != 0);
}
EXPORT_SYMBOL(drm_mm_takedown_hsw);

void drm_mm_debug_table_hsw(struct drm_mm_hsw *mm, const char *prefix)
{
	struct drm_mm_node_hsw *entry;
	unsigned long total_used = 0, total_free = 0, total = 0;
	unsigned long hole_start, hole_end, hole_size;

	hole_start = drm_mm_hole_node_start_hsw(&mm->head_node);
	hole_end = drm_mm_hole_node_end_hsw(&mm->head_node);
	hole_size = hole_end - hole_start;
	if (hole_size)
		printk(KERN_DEBUG "%s 0x%08lx-0x%08lx: %8lu: free\n",
			prefix, hole_start, hole_end,
			hole_size);
	total_free += hole_size;

	drm_mm_hsw_for_each_node(entry, mm) {
		printk(KERN_DEBUG "%s 0x%08lx-0x%08lx: %8lu: used\n",
			prefix, entry->start, entry->start + entry->size,
			entry->size);
		total_used += entry->size;

		if (entry->hole_follows) {
			hole_start = drm_mm_hole_node_start_hsw(entry);
			hole_end = drm_mm_hole_node_end_hsw(entry);
			hole_size = hole_end - hole_start;
			printk(KERN_DEBUG "%s 0x%08lx-0x%08lx: %8lu: free\n",
				prefix, hole_start, hole_end,
				hole_size);
			total_free += hole_size;
		}
	}
	total = total_free + total_used;

	printk(KERN_DEBUG "%s total: %lu, used %lu free %lu\n", prefix, total,
		total_used, total_free);
}
EXPORT_SYMBOL(drm_mm_debug_table_hsw);

#if defined(CONFIG_DEBUG_FS)
int drm_mm_dump_table_hsw(struct seq_file *m, struct drm_mm_hsw *mm)
{
	struct drm_mm_node_hsw *entry;
	unsigned long total_used = 0, total_free = 0, total = 0;
	unsigned long hole_start, hole_end, hole_size;

	hole_start = drm_mm_hole_node_start_hsw(&mm->head_node);
	hole_end = drm_mm_hole_node_end_hsw(&mm->head_node);
	hole_size = hole_end - hole_start;
	if (hole_size)
		seq_printf(m, "0x%08lx-0x%08lx: 0x%08lx: free\n",
				hole_start, hole_end, hole_size);
	total_free += hole_size;

	drm_mm_hsw_for_each_node(entry, mm) {
		seq_printf(m, "0x%08lx-0x%08lx: 0x%08lx: used\n",
				entry->start, entry->start + entry->size,
				entry->size);
		total_used += entry->size;
		if (entry->hole_follows) {
			hole_start = drm_mm_hole_node_start_hsw(entry);
			hole_end = drm_mm_hole_node_end_hsw(entry);
			hole_size = hole_end - hole_start;
			seq_printf(m, "0x%08lx-0x%08lx: 0x%08lx: free\n",
					hole_start, hole_end, hole_size);
			total_free += hole_size;
		}
	}
	total = total_free + total_used;

	seq_printf(m, "total: %lu, used %lu free %lu\n", total, total_used, total_free);
	return 0;
}
EXPORT_SYMBOL(drm_mm_dump_table_hsw);
#endif
