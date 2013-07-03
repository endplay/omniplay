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
** ds_list.private.h: Implementation details of ds_list_t, ds_list_elt_t
*/

#ifndef _DS_LIST_PRIVATE_H_
#define _DS_LIST_PRIVATE_H_

#include <linux/ds_list.h>  /* public parts */

/* magic numbers for structures */
#define ds_list_magic      257652478
#define ds_list_elt_magic  152060319
#define ds_list_iter_magic 195588386
typedef u_long magic_t;

/* the structures themselves. */


/* 
 * An element has a magic number, a next and prev link, and the contents.
 * The contents themselves are untyped.
 */


typedef struct ds_list_elt_t {
    magic_t              magic;
    struct ds_list_elt_t *n;
    struct ds_list_elt_t *p;
    void                 *contents;
} ds_list_elt_t;

/* 
 * A list has a magic number, a comparison function, 
 * safety and duplicate information, a count of elements, and a pointer
 * to the head  and tail elements.  
 * The list is doubly-linked: the head and tail elements each point to
 * null "off the end" of the list.
 * There is also a "list" of active (i.e.: not-destroyed) iterators
 * for this list.  Naturally, the iterator "list" cannot be a ds_list_t.
 */

struct ds_list_t {
    magic_t                magic;
    COMPFN                 cmpfn;
    int                    is_safe;
    int                    has_dups;
    int                    count;
    struct ds_list_elt_t  *head;
    struct ds_list_elt_t  *tail;
    struct ds_list_iter_t *iter_list;
};

struct ds_list_iter_t {
    magic_t                 magic;
    ds_list_t              *list;
    ds_list_elt_t          *next_elt;
    struct ds_list_iter_t  *next_iter;
};

#define DS_LIST_VALID(lp) ((lp) && ((lp)->magic == ds_list_magic))
#define DS_LIST_ELT_VALID(ep) ((ep) && ((ep)->magic == ds_list_elt_magic))
#define DS_LIST_ITER_VALID(ip) ((ip) && ((ip)->magic == ds_list_iter_magic))

#endif /* _DS_LIST_PRIVATE_H_ */

