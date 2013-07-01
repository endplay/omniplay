/**************************************************************************
 *
 * Copyright 2006-2008 Tungsten Graphics, Inc., Cedar Park, TX. USA.
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
 * Authors:
 * Thomas Hellstrom <thomas-at-tungstengraphics-dot-com>
 */

#ifndef _DRM_MM_HSW_H_
#define _DRM_MM_HSW_H_

/*
 * Generic range manager structs
 */
#include <linux/list.h>
#ifdef CONFIG_DEBUG_FS
#include <linux/seq_file.h>
#endif

struct drm_mm_node_hsw {
	struct list_head node_list;
	struct list_head hole_stack;
	unsigned hole_follows : 1;
	unsigned scanned_block : 1;
	unsigned scanned_prev_free : 1;
	unsigned scanned_next_free : 1;
	unsigned scanned_preceeds_hole : 1;
	unsigned allocated : 1;
	unsigned long color;
	unsigned long start;
	unsigned long size;
	struct drm_mm_hsw *mm;
};

struct drm_mm_hsw {
	/* List of all memory nodes that immediately precede a free hole. */
	struct list_head hole_stack;
	/* head_node.node_list is the list of all memory nodes, ordered
	 * according to the (increasing) start address of the memory node. */
	struct drm_mm_node_hsw head_node;
	struct list_head unused_nodes;
	int num_unused;
	spinlock_t unused_lock;
	unsigned int scan_check_range : 1;
	unsigned scan_alignment;
	unsigned long scan_color;
	unsigned long scan_size;
	unsigned long scan_hit_start;
	unsigned scan_hit_size;
	unsigned scanned_blocks;
	unsigned long scan_start;
	unsigned long scan_end;
	struct drm_mm_node_hsw *prev_scanned_node;

	void (*color_adjust)(struct drm_mm_node_hsw *node, unsigned long color,
			     unsigned long *start, unsigned long *end);
};

static inline bool drm_mm_node_allocated_hsw(struct drm_mm_node_hsw *node)
{
	return node->allocated;
}

static inline bool drm_mm_initialized_hsw(struct drm_mm_hsw *mm)
{
	return mm->hole_stack.next;
}
#define drm_mm_hsw_for_each_node(entry, mm) list_for_each_entry(entry, \
						&(mm)->head_node.node_list, \
						node_list)
#define drm_mm_hsw_for_each_scanned_node_reverse(entry, n, mm) \
	for (entry = (mm)->prev_scanned_node, \
		next = entry ? list_entry(entry->node_list.next, \
			struct drm_mm_node_hsw, node_list) : NULL; \
	     entry != NULL; entry = next, \
		next = entry ? list_entry(entry->node_list.next, \
			struct drm_mm_node_hsw, node_list) : NULL) \
/*
 * Basic range manager support (drm_mm.c)
 */
extern struct drm_mm_node_hsw *drm_mm_get_block_generic_hsw(struct drm_mm_node_hsw *node,
						    unsigned long size,
						    unsigned alignment,
						    unsigned long color,
						    int atomic);
extern struct drm_mm_node_hsw *drm_mm_get_block_range_generic_hsw(
						struct drm_mm_node_hsw *node,
						unsigned long size,
						unsigned alignment,
						unsigned long color,
						unsigned long start,
						unsigned long end,
						int atomic);
static inline struct drm_mm_node_hsw *drm_mm_get_block_hsw(struct drm_mm_node_hsw *parent,
						   unsigned long size,
						   unsigned alignment)
{
	return drm_mm_get_block_generic_hsw(parent, size, alignment, 0, 0);
}
static inline struct drm_mm_node_hsw *drm_mm_get_block_atomic_hsw(struct drm_mm_node_hsw *parent,
							  unsigned long size,
							  unsigned alignment)
{
	return drm_mm_get_block_generic_hsw(parent, size, alignment, 0, 1);
}
static inline struct drm_mm_node_hsw *drm_mm_get_block_range_hsw(
						struct drm_mm_node_hsw *parent,
						unsigned long size,
						unsigned alignment,
						unsigned long start,
						unsigned long end)
{
	return drm_mm_get_block_range_generic_hsw(parent, size, alignment, 0,
					      start, end, 0);
}
static inline struct drm_mm_node_hsw *drm_mm_get_color_block_range_hsw(
						struct drm_mm_node_hsw *parent,
						unsigned long size,
						unsigned alignment,
						unsigned long color,
						unsigned long start,
						unsigned long end)
{
	return drm_mm_get_block_range_generic_hsw(parent, size, alignment, color,
					      start, end, 0);
}
static inline struct drm_mm_node_hsw *drm_mm_get_block_atomic_range_hsw(
						struct drm_mm_node_hsw *parent,
						unsigned long size,
						unsigned alignment,
						unsigned long start,
						unsigned long end)
{
	return drm_mm_get_block_range_generic_hsw(parent, size, alignment, 0,
						start, end, 1);
}
extern int drm_mm_insert_node_hsw(struct drm_mm_hsw *mm, struct drm_mm_node_hsw *node,
			      unsigned long size, unsigned alignment);
extern int drm_mm_insert_node_in_range_hsw(struct drm_mm_hsw *mm,
				       struct drm_mm_node_hsw *node,
				       unsigned long size, unsigned alignment,
				       unsigned long start, unsigned long end);
extern void drm_mm_put_block_hsw(struct drm_mm_node_hsw *cur);
extern void drm_mm_remove_node_hsw(struct drm_mm_node_hsw *node);
extern void drm_mm_replace_node_hsw(struct drm_mm_node_hsw *old, struct drm_mm_node_hsw *new);
extern struct drm_mm_node_hsw *drm_mm_search_free_generic_hsw(const struct drm_mm_hsw *mm,
						      unsigned long size,
						      unsigned alignment,
						      unsigned long color,
						      bool best_match);
extern struct drm_mm_node_hsw *drm_mm_search_free_in_range_generic_hsw(
						const struct drm_mm_hsw *mm,
						unsigned long size,
						unsigned alignment,
						unsigned long color,
						unsigned long start,
						unsigned long end,
						bool best_match);
static inline struct drm_mm_node_hsw *drm_mm_search_free_hsw(const struct drm_mm_hsw *mm,
						     unsigned long size,
						     unsigned alignment,
						     bool best_match)
{
	return drm_mm_search_free_generic_hsw(mm,size, alignment, 0, best_match);
}
static inline  struct drm_mm_node_hsw *drm_mm_search_free_in_range_hsw(
						const struct drm_mm_hsw *mm,
						unsigned long size,
						unsigned alignment,
						unsigned long start,
						unsigned long end,
						bool best_match)
{
	return drm_mm_search_free_in_range_generic_hsw(mm, size, alignment, 0,
						   start, end, best_match);
}
static inline struct drm_mm_node_hsw *drm_mm_search_free_color_hsw(const struct drm_mm_hsw *mm,
							   unsigned long size,
							   unsigned alignment,
							   unsigned long color,
							   bool best_match)
{
	return drm_mm_search_free_generic_hsw(mm,size, alignment, color, best_match);
}
static inline  struct drm_mm_node_hsw *drm_mm_search_free_in_range_color_hsw(
						const struct drm_mm_hsw *mm,
						unsigned long size,
						unsigned alignment,
						unsigned long color,
						unsigned long start,
						unsigned long end,
						bool best_match)
{
	return drm_mm_search_free_in_range_generic_hsw(mm, size, alignment, color,
						   start, end, best_match);
}
extern int drm_mm_init_hsw(struct drm_mm_hsw *mm,
		       unsigned long start,
		       unsigned long size);
extern void drm_mm_takedown_hsw(struct drm_mm_hsw *mm);
extern int drm_mm_clean_hsw(struct drm_mm_hsw *mm);
extern int drm_mm_pre_get_hsw(struct drm_mm_hsw *mm);

static inline struct drm_mm_hsw *drm_get_mm_hsw(struct drm_mm_node_hsw *block)
{
	return block->mm;
}

void drm_mm_init_scan_hsw(struct drm_mm_hsw *mm,
		      unsigned long size,
		      unsigned alignment,
		      unsigned long color);
void drm_mm_init_scan_with_range_hsw(struct drm_mm_hsw *mm,
				 unsigned long size,
				 unsigned alignment,
				 unsigned long color,
				 unsigned long start,
				 unsigned long end);
int drm_mm_scan_add_block_hsw(struct drm_mm_node_hsw *node);
int drm_mm_scan_remove_block_hsw(struct drm_mm_node_hsw *node);

extern void drm_mm_debug_table_hsw(struct drm_mm_hsw *mm, const char *prefix);
#ifdef CONFIG_DEBUG_FS
int drm_mm_dump_table_hsw(struct seq_file *m, struct drm_mm_hsw *mm);
#endif

#endif
