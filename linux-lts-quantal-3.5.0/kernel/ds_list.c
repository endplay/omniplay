#ifndef _ODYBLURB_
#define _ODYBLURB_
/*
 *                               Data Station 1.0
 *                 A Data Staging System for Seamless Mobility
 * 
 *                    Copyright (c) 2002, Intel Corporation
 *                             All Rights Reserved
 * 
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 * 
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 * 
 *     * Neither the name of Intel Research Pittsburgh nor the names of
 *       its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#endif /* _ODYBLURB_ */

/*
** ds_list.c: implementation of ds_list_t.
*/

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>

#include <linux/ds_list.h>
#include "ds_list.private.h"

static struct kmem_cache* l_cachep;
static struct kmem_cache* le_cachep;
static struct kmem_cache* li_cachep;

/* list elements */

static
ds_list_elt_t *
ds_list_elt_create(void *contents) 
{
	ds_list_elt_t *result;
	
	result = kmem_cache_alloc (le_cachep, GFP_ATOMIC);
	if (result == NULL) {
		printk ("ds_list: allocation failed\n");
		return NULL;
	}

	result->magic = ds_list_elt_magic;
	result->p = result->n = NULL;
	result->contents = contents;

	return result;
}

static
void
ds_list_elt_destroy(ds_list_elt_t *e) 
{
	if (!DS_LIST_ELT_VALID(e)) {
		printk ("ds_list: magic# for elt %lx invalid\n", (u_long) e);
	}

	e->p = e->n = NULL;
	e->contents = NULL;
	e->magic = 0;
	
	kmem_cache_free(le_cachep, e);
}

/* ds_list_t's */

int
ds_list_valid(ds_list_t *l) 
{
	return DS_LIST_VALID(l);
}

int
ds_list_count(ds_list_t *l) 
{
	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
		
	return l->count;
}

void *
ds_list_first(ds_list_t *l) 
{
	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
		
	if (l->head) {
		if (!DS_LIST_ELT_VALID(l->head)) {
			printk ("ds_list: magic# for elt %lx invalid\n", 
				(u_long) l->head);
			return NULL;
		}

		return l->head->contents;
	} else {
		return NULL;
	}
}

void *
ds_list_last(ds_list_t *l) 
{
	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
	if (l->tail) {
		if (!DS_LIST_ELT_VALID(l->tail)) {
			printk ("ds_list: magic# for elt %lx invalid\n", 
				(u_long) l->tail);
			return NULL;
		}
		return l->tail->contents;
	} else {
		return NULL;
	}
}

static ds_list_elt_t *
ds_list_find_member(ds_list_t *l, void *e) 
{
	ds_list_elt_t *cur;
	int           found = 0;
	
	/* calling functions must test validity of l */
	cur = l->head;
	
	while (!found && cur != NULL) {
		if (!DS_LIST_ELT_VALID(cur)) {
			printk ("ds_list: magic# for elt %lx invalid\n", 
				(u_long) cur);
			return NULL;
		}
		
		/* test is different for sorted, unsorted lists */
		if (l->cmpfn != NULL) {
			if (l->cmpfn(e,cur->contents) == 0) {
				found = 1;
			} else {
				cur = cur->n;
			}
		} else {
			if (e == cur->contents) {
				found = 1;
			} else {
				cur = cur->n;
			}
		}
	}
	return cur;
}

void *
ds_list_member(ds_list_t *l, void *e) 
{
	ds_list_elt_t *elt;

	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
	if (e == NULL) {
		printk ("ds_list: comparison element NULL\n");
		return NULL;
	}

	elt = ds_list_find_member(l,e);
	if (elt)
		return elt->contents;
	else
		return NULL;
}


ds_list_t *
ds_list_create(COMPFN c,
	       int   safe_destroy,
	       int   dups_ok) 
{
	ds_list_t *result;
	
	result = kmem_cache_alloc (l_cachep, GFP_ATOMIC);
	if (result == NULL) {
		printk ("ds_list: unable to allocate list\n");
		return NULL;
	}
	result->magic = ds_list_magic;
	
	result->cmpfn = c;
	result->is_safe = safe_destroy;
	result->has_dups= dups_ok;
	result->count = 0;
	result->head = result->tail = NULL;
	result->iter_list = NULL;
	
	return result;
}

int
ds_list_destroy(ds_list_t *l) 
{
	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
	
	/* Either the list must be unsafe, or there must be nothing in it. */
	if (!l->is_safe && l->count > 0) {
		printk ("ds_list: cannot destroy safe list with elements\n");
		return -1;
	}
	
	l->magic = 7879;
	l->cmpfn = NULL;
	l->head = l->tail = NULL;
	l->count = 0;
	
	kmem_cache_free (l_cachep, l);

	return 0;
}

void *
ds_list_insert(ds_list_t *l, void *i) 
{
	ds_list_elt_t *result;

	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
	if (i == NULL) {
		printk ("ds_list: element to insert is NULL\n");
		return NULL;
	}
	
	/* test for duplicates */
	if (!l->has_dups) 
		if (ds_list_find_member(l,i))
			return NULL;
	
	result = ds_list_elt_create(i);
	
	/* Is the list empty? */
	if (l->head == NULL) {
		l->head = result;
		l->tail = result;
	} else {
		/* Is the list unsorted? */
		if (l->cmpfn == NULL) {
			if (!DS_LIST_ELT_VALID(l->head)) {
				printk ("ds_list: magic# for elt %lx inval\n", 
					(u_long) l->head);
				return NULL;
			}
			result->n = l->head;
			l->head->p = result;
			l->head = result;
		} else {
			/* Walk through the list, checking insertion point */
			ds_list_elt_t *cur = l->head;
			while (cur != NULL
			       && DS_LIST_ELT_VALID(cur)
			       && l->cmpfn(cur->contents,result->contents)<0) 
			{
				cur = cur->n;
			}
			if (cur == NULL) {  /* new element at end of list */
				result->p = l->tail;
				l->tail->n = result;
				l->tail = result;
			} else {
				if (!DS_LIST_ELT_VALID(cur)) {
					printk ("ds_list: magic for elt %lx\n",
						(u_long) cur);
					return NULL;
				}
				result->n = cur;
				result->p = cur->p;
				result->n->p = result;
				if (result->p) 
					result->p->n = result;
				else  /* new element at beginning */
					l->head = result;
			}
		}
	}
	l->count++;
	return i;
}

void *
ds_list_append(ds_list_t *l, void *i) 
{
	ds_list_elt_t *result;
	
	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
	if (i == NULL) {
		printk ("ds_list: element to append is NULL\n");
		return NULL;
	}
	
	/* test for duplicates */
	if (!l->has_dups) 
		if (ds_list_find_member(l,i))
			return NULL;
	
	result = ds_list_elt_create(i);
	
	/* Is the list empty? */
	if (l->head == NULL) {
		l->head = result;
		l->tail = result;
	} else {
		/* Is the list unsorted? */
		if (l->cmpfn == NULL) {
			if (!DS_LIST_ELT_VALID(l->tail)) {
				printk ("ds_list: magic# for elt %lx inval\n", 
					(u_long) l->tail);
				return NULL;
			}
			result->p = l->tail;
			l->tail->n = result;
			l->tail = result;
		} else {
			/* Walk backwards, checking for the insertion point */
			ds_list_elt_t *cur = l->tail;
			while (cur != NULL
			       && DS_LIST_ELT_VALID(cur)
			       && l->cmpfn(result->contents,cur->contents) < 0)
			{
				cur = cur->p;
			}
			if (cur == NULL) { 
                                /* new element at beginning of list */
				result->n = l->head;
				l->head->p = result;
				l->head = result;
			} else {
				if (!DS_LIST_ELT_VALID(cur)) {
					printk ("ds_list: magic for elt %lx\n",
						(u_long) cur);
					return NULL;
				}
				result->p = cur;
				result->n = cur->n;
				result->p->n = result;
				if (result->n) 
					result->n->p = result;
				else  /* new element at end of list */
					l->tail = result;
			}
		}
	}
	l->count++;
	return i;
}


/* helper function to advance iters whose next fields point to
   dying elements.  "dropping" must not have been pulled off of 
   the list when this is called. */

static void
ds_list_advance_iters(ds_list_elt_t *dropping, 
		      ds_list_iter_t *iter) 
{
	while (iter != NULL) {
		if (!DS_LIST_ITER_VALID(iter)) {
			printk ("ds_list: iterator %lx invalid\n", 
				(u_long) iter);
			return;
		}
		if (iter->next_elt == dropping) 
			iter->next_elt = iter->next_elt->n;
		iter = iter->next_iter;
	}
}

void *
ds_list_get_first(ds_list_t *l) 
{
	void *result = NULL;
	ds_list_elt_t *removed = NULL;
	
	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
	if (l->head != NULL) {        /* if the list is not empty */
		removed = l->head;
		if (!DS_LIST_ELT_VALID(removed)) {
			printk ("ds_list: magic# for elt %lx invalid\n", 
				(u_long) removed);
			return NULL;
		}
		ds_list_advance_iters(removed,l->iter_list);
		result = l->head->contents;
		l->head = l->head->n;
		if (l->head == NULL) {
			l->tail = NULL;      /* list is now empty */
		} else {
			if (!DS_LIST_ELT_VALID(l->head)) {
				printk ("ds_list: elt %lx invalid\n", 
					(u_long) l->head);
				return NULL;
			}
			l->head->p = NULL;   /* unchain this element */
		}
		ds_list_elt_destroy(removed);
		l->count--;
	}
	return result;
}

void *
ds_list_get_last(ds_list_t *l) 
{
	void *result = NULL;
	ds_list_elt_t *removed = NULL;

	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
	if (l->tail != NULL) {     /* if the list is not empty */
		removed = l->tail;
		if (!DS_LIST_ELT_VALID(removed)) {
			printk ("ds_list: magic# for elt %lx invalid\n", 
				(u_long) removed);
			return NULL;
		}
		ds_list_advance_iters(removed,l->iter_list);
		result = l->tail->contents;
		l->tail = l->tail->p;
		if (l->tail == NULL) {
			l->head = NULL;   /* list is now empty */
		} else {
			if (!DS_LIST_ELT_VALID(l->tail)) {
				printk ("ds_list: elt %lx invalid\n", 
					(u_long) l->tail);
				return NULL;
			}
			l->tail->n = NULL; /* unchain this element */
		}
		ds_list_elt_destroy(removed);
		l->count--;
	}
	return result;
}

void *
ds_list_remove(ds_list_t *l, void *e) 
{
	ds_list_elt_t *elt;
	void          *result;
	
	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
	if (e == NULL) {
		printk ("ds_lsit: cannot remove NULL element\n");
		return NULL;
	}

	elt = ds_list_find_member(l,e);
	
	if (elt == NULL) return NULL;    /* not in list */
	
	ds_list_advance_iters(elt,l->iter_list);
	result = elt->contents;          /* save the answer */
	l->count--;
	
	if (elt->p == NULL && elt->n == NULL) {  /* only element */
		l->head = l->tail = NULL;
		ds_list_elt_destroy(elt);
		return result;
	}
	
	if (elt->p == NULL) {            /* first element */
		l->head = elt->n;
		if (!DS_LIST_ELT_VALID(l->head)) {
			printk ("ds_list: magic# for elt %lx invalid\n", 
				(u_long) l->head);
			return NULL;
		}
		l->head->p = NULL;
		ds_list_elt_destroy(elt);
		return result;
	} 
	
	if (elt->n == NULL) {           /* last element */
		l->tail = elt->p;
		if (!DS_LIST_ELT_VALID(l->tail)) {
			printk ("ds_list: magic# for elt %lx invalid\n", 
				(u_long) l->tail);
			return NULL;
		}
		l->tail->n = NULL;
		ds_list_elt_destroy(elt);
		return result;
	}

	/* neither first nor last element */
	if (!DS_LIST_ELT_VALID(elt->n)) {
		printk ("ds_list: magic# for elt %lx invalid\n", 
			(u_long) elt->n);
		return NULL;
	}
	if (!DS_LIST_ELT_VALID(elt->p)) {
		printk ("ds_list: magic# for elt %lx invalid\n", 
			(u_long) elt->p);
		return NULL;
	}
	elt->p->n = elt->n;
	elt->n->p = elt->p;
	ds_list_elt_destroy(elt);
	return result;
}

void
ds_list_print(ds_list_t *l, int forward, void (*printer)(void *)) 
{
	ds_list_elt_t *cur;
	
	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
	if (printer == NULL) return;

	if (forward) {
		cur = l->head;
		while (cur != NULL) {
			printer(cur->contents);
			cur = cur->n;
		}
	} else {
		cur = l->tail;
		while (cur != NULL) {
			printer(cur->contents);
			cur = cur->p;
		}
	}
}

ds_list_iter_t *
ds_list_iter_create(ds_list_t *l) 
{
	ds_list_iter_t *result;
	
	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
	result = kmem_cache_alloc (li_cachep, GFP_ATOMIC);
	if (result == NULL) {
		printk ("ds_list: cannot allocate\n");
		return NULL;
	}
	
	result->next_iter = l->iter_list;
	result->next_elt = l->head;
	result->magic = ds_list_iter_magic;
	result->list = l;
	
	l->iter_list = result;
	
	return result;
}

void
ds_list_iter_destroy(ds_list_iter_t *i) 
{
	ds_list_iter_t *trail;
	ds_list_iter_t *cur;
	ds_list_t      *l;
	
	if (!DS_LIST_ITER_VALID(i)) {
		printk ("ds_list: iterator %lx invalid\n", (u_long) i);
		return;
	}
	l = i->list;
	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}

	trail = NULL;
	cur = l->iter_list;
	
	while (cur != NULL) {
		if (cur == i) break;
		trail = cur;
		cur = cur->next_iter;
	}
	
	if (trail == NULL) 
		l->iter_list = cur->next_iter;
	else
		trail->next_iter = cur->next_iter;
	
	i->magic = 0;
	i->list = NULL;
	i->next_elt = NULL;
	i->next_iter = NULL;
	kmem_cache_free (li_cachep, i);
}

void *
ds_list_iter_next(ds_list_iter_t *i) 
{
	ds_list_t      *l;
	void           *result = NULL;
	
	if (!DS_LIST_ITER_VALID(i)) {
		printk ("ds_list: iterator %lx invalid\n", (u_long) i);
		return NULL;
	}
	l = i->list;
	if (!DS_LIST_VALID(l)) {
		printk ("ds_list: magic# (%lu) for list %lx invalid\n", 
			l->magic, (u_long) l);
		BUG();
	}
	
	if (i->next_elt) {
		if (!DS_LIST_ELT_VALID(i->next_elt)) {
			printk ("ds_list: magic# for elt %lx invalid\n", 
				(u_long) i->next_elt);
			return NULL;
		}
		result = i->next_elt->contents;
		i->next_elt = i->next_elt->n;
	}
	
	return result;
}

static int __init
ds_list_init (void)
{
	l_cachep = kmem_cache_create("list", sizeof(ds_list_t), 0, SLAB_HWCACHE_ALIGN, NULL);
	if(!l_cachep) panic("ds_list_init: Cannot alloc list SLAB cache");

	le_cachep = kmem_cache_create("list element", sizeof(ds_list_elt_t), 0,	SLAB_HWCACHE_ALIGN, NULL);
	if(!le_cachep) panic("ds_list_init: Cannot alloc list element SLAB cache");

	li_cachep = kmem_cache_create("list iterator", sizeof(ds_list_iter_t), 0, SLAB_HWCACHE_ALIGN, NULL);
	if(!li_cachep) panic("ds_list_init: Cannot alloc list iterator SLAB cache");
	return 0;
}

module_init(ds_list_init)

EXPORT_SYMBOL(ds_list_create);
EXPORT_SYMBOL(ds_list_destroy);
EXPORT_SYMBOL(ds_list_get_first);
EXPORT_SYMBOL(ds_list_append);
EXPORT_SYMBOL(ds_list_remove);
EXPORT_SYMBOL(ds_list_valid);
EXPORT_SYMBOL(ds_list_member);
