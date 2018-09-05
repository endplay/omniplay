#ifndef TAINTS_GRAPH_FLAT_H
#define TAINTS_GRAPH_FLAT_H

#include <stdio.h>
#include <stdlib.h>
#include "../list.h"
#include <glib-2.0/glib.h>
#include <assert.h>
#include <string.h>

#include "slab_alloc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * This file contains all of the functions for manipulating taint
 * if we're using references to taints
 * */
#define NUM_OPTIONS G_MAXUINT32
#define CONFIDENCE_LEVELS 1
typedef guint8 TAINT_TYPE;

/* Some performance optimizations */
#define USE_SLAB_ALLOCATOR

/* Different options */
#define MERGE_STATS

#ifdef MERGE_STATS
#include "../taints_profile.h"
struct taints_profile merge_profile;
#endif

// the type of an index
typedef guint32 OPTION_TYPE;

struct node {
    struct node* parent1;
    struct node* parent2;
};

/* leafnode is a node with two NULL parents and an option value */
struct leafnode {
    struct node node;
    OPTION_TYPE option; 
};

typedef u_long taint_type;

// structure for holding merged indices
GHashTable* taint_merge_index;

struct slab_alloc leaf_alloc;
struct slab_alloc node_alloc;
struct slab_alloc uint_alloc;

inline void init_taint_index(void)
{
    taint_merge_index = g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);
#ifdef USE_SLAB_ALLOCATOR
    init_slab_alloc();
    new_slab_alloc((char *)"LEAF_ALLOC", &leaf_alloc, sizeof(struct leafnode), 20000);
    new_slab_alloc((char *)"NODE_ALLOC", &node_alloc, sizeof(struct node), 20000);
    new_slab_alloc((char *)"UINT_ALLOC", &uint_alloc, sizeof(guint64), 20000);
#endif
}

struct leafnode* get_new_leafnode(OPTION_TYPE option) {
    struct leafnode* ln;
#ifdef USE_SLAB_ALLOCATOR
    ln = (struct leafnode *) get_slice(&leaf_alloc);
#else
    ln = (struct leafnode *) malloc(sizeof(struct leafnode*));
#endif
    memset(ln, 0, sizeof(struct leafnode));
    ln->node.parent1 = NULL;
    ln->node.parent2 = NULL;
    ln->option = option;

    return ln;
}

struct node* get_new_node(struct node* parent1, struct node* parent2) {
    struct node* n;
#ifdef USE_SLAB_ALLOCATOR
    n = (struct node *) get_slice(&node_alloc);
#else
    n = (struct node *) malloc(sizeof(struct node *));
#endif
    memset(n, 0, sizeof(struct node));
    n->parent1 = parent1;
    n->parent2 = parent2;
    return n;
}

guint64* get_new_64() {
#ifdef USE_SLAB_ALLOCATOR    
    return (guint64 *) get_slice(&uint_alloc);
#else
    return (guint64 *) malloc(sizeof(guint64));
#endif
}

inline guint64 hash_indices(guint32 index1, guint32 index2) {
    guint64 hash;
    // make index 2 always be the bigger number
    if (index1 > index2) {
        guint32 tmp;
        tmp = index2;
        index2 = index1;
        index1 = tmp;
    }

    hash = index1;
    hash = hash << 32;
    hash += index2;
    // fprintf(stderr, "hash is %llx, index1 %lx, index2 %lx\n", hash, (unsigned long) index1, (unsigned long) index2);
    return hash;
}

inline void new_taint(taint_type t) {
    // really can't do anything here
    return;
}

inline TAINT_TYPE get_max_taint_value(void) {
    // return G_MAXINT8;
    return 1;
}

inline TAINT_TYPE get_taint_value(taint_type t, OPTION_TYPE option) {
    GQueue* queue = g_queue_new();
    GHashTable* seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
    struct node* n = (struct node *) t;
    g_queue_push_tail(queue, n);
    TAINT_TYPE found = 0;
    while(!g_queue_is_empty(queue)) {
        n = (struct node *) g_queue_pop_head(queue);
        if (g_hash_table_lookup(seen_indices, n)) {
            continue;
        }
        g_hash_table_insert(seen_indices, GUINT_TO_POINTER(n), GINT_TO_POINTER(1));

        if (!n->parent1 && !n->parent2) { // leaf node
            struct leafnode* ln = (struct leafnode *) n;
            if (ln->option == option) {
                found = get_max_taint_value();
                break;
            }
        } else {
            if (!g_hash_table_lookup(seen_indices, GUINT_TO_POINTER(n->parent1))) {
                g_queue_push_tail(queue, n->parent1);
            }
            if (!g_hash_table_lookup(seen_indices, GUINT_TO_POINTER(n->parent2))) {
                g_queue_push_tail(queue, n->parent2);
            }
        }
    }
    g_queue_free(queue);
    g_hash_table_destroy(seen_indices);
    return found;
}

inline taint_type set_taint_value (OPTION_TYPE option, TAINT_TYPE value) {
    // really can't do anything here
    struct leafnode* ln;
    ln = get_new_leafnode(option);

#ifdef MERGE_STATS
    increment_taint_op(&merge_profile, STATS_OP_UNIQUE_TAINTS);
#endif
    return (taint_type) ln;
}

inline int is_taint_equal(taint_type first, taint_type second) {
    return first == second;
}

inline int is_taint_zero(taint_type src) {
    return (src == 0);
}

inline void is_taint_full(taint_type t) {
    fprintf(stderr, "Should not use full taints in index mode\n");
}

inline void set_taint_full (taint_type t) {
    fprintf(stderr, "Should not use full taints in index mode\n");
}

inline void clear_taint(taint_type t) {
    // really can't do anything here
#ifdef MERGE_STATS
    increment_taint_op(&merge_profile, STATS_OP_CLEAR);
#endif
    return;
}

inline void set_taint(taint_type dst, taint_type src) {
#ifdef MERGE_STATS
    increment_taint_op(&merge_profile, STATS_OP_SET);
#endif
    return;
}

#ifdef BINARY_FWD_TAINT
static inline taint_type merge_taints(taint_type dst, taint_type src) {
    if (dst == 0) {
        return src;
    }
    if (src == 0) {
        return dst;
    }
    if (dst || src) {
        return 1;
    }
    return 0;
}
#else
static inline taint_type merge_taints(taint_type dst, taint_type src) {
    struct node* n;
    guint64 hash;
    guint64* phash;

    if (!dst || !src) return 0;
    if (dst == 0) {
        return src;
    }
    if (src == 0) {
        return dst;
    }
    if (dst == src) {
        return dst;
    }

    hash = hash_indices((guint32) dst, (guint32) src);
#ifdef MERGE_STATS
    increment_taint_op(&merge_profile, STATS_OP_MERGE);	
#endif
    n = (struct node *) g_hash_table_lookup(taint_merge_index, &hash);
    if (!n) {
        n = get_new_node((struct node *) dst, (struct node *) src);
        //phash = (guint64 *) malloc(sizeof(guint64));
        phash = (guint64 *) get_new_64();
        memcpy(phash, &hash, sizeof(guint64));
        g_hash_table_insert(taint_merge_index, phash, n);
#ifdef MERGE_STATS
        increment_taint_op(&merge_profile, STATS_OP_UNIQUE_MERGE);	
        increment_taint_op(&merge_profile, STATS_OP_UNIQUE_TAINTS);
#endif
    }
    //fprintf(stderr, "merge (%lu, %lu) result: %lu\n", (unsigned long) dst->id, (unsigned long) src->id, (unsigned long) n);
    return (taint_type) n;
}
#endif

void shift_taints(taint_type dst, taint_type src, int level) {
    fprintf(stderr, "Should not use SHIFT taints in index mode\n");
}
void shift_merge_taints(taint_type dst, taint_type src, int level) {
    fprintf(stderr, "Should not use SHIFT MERGE taints in index mode\n");
}

void shift_cf_taint(taint_type dst, taint_type cond, taint_type prev) {
    fprintf(stderr, "Should not use SHIFT CF taints in index mode\n");
}

void print_kv(gpointer key, gpointer value, gpointer user_data)
{
    fprintf(stderr, "k: %p, v: %d\n", key, GPOINTER_TO_INT(value));
}

void print_taint(FILE* fp, taint_type src) {
    if (!src) {
        fprintf(fp, "id {0}\n");
    } else {
        GQueue* queue = g_queue_new();
        GHashTable* seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
        struct node* n = (struct node *) src;

        fprintf(fp, "id {");
        g_queue_push_tail(queue, n);
        while(!g_queue_is_empty(queue)) {
            n = (struct node *) g_queue_pop_head(queue);
            if (g_hash_table_lookup(seen_indices, n)) {
                continue;
            }
            g_hash_table_insert(seen_indices, n, GINT_TO_POINTER(1));

            if (!n->parent1 && !n->parent2) { // leaf node
                struct leafnode* ln = (struct leafnode *) n;
                fprintf(fp, "%lu,", (unsigned long) ln->option);
            } else {
                if (!g_hash_table_lookup(seen_indices, n->parent1)) {
                    g_queue_push_tail(queue, n->parent1);
                }
                if (!g_hash_table_lookup(seen_indices, n->parent2)) {
                    g_queue_push_tail(queue, n->parent2);
                }
            }
        }
        g_queue_free(queue);
        g_hash_table_destroy(seen_indices);
        fprintf(fp, "}\n");
    }
}

/* Compute the taints in the index */
GList* get_non_zero_taints(taint_type t) {
    GHashTable* seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
    GList* list = NULL;
    GQueue* queue = g_queue_new();
    struct node* n = (struct node *) t;

    g_queue_push_tail(queue, n);
    while(!g_queue_is_empty(queue)) {
        n = (struct node *) g_queue_pop_head(queue);
        if (g_hash_table_lookup(seen_indices, n)) {
            continue;
        }
        g_hash_table_insert(seen_indices, n, GINT_TO_POINTER(1));

        if (!n->parent1 && !n->parent2) { // leaf node
            struct leafnode* ln = (struct leafnode *) n;
            list = g_list_prepend(list, GUINT_TO_POINTER(ln->option));
        } else {
            if (!g_hash_table_lookup(seen_indices, n->parent1)) {
                g_queue_push_tail(queue, n->parent1);
            }
            if (!g_hash_table_lookup(seen_indices, n->parent2)) {
                g_queue_push_tail(queue, n->parent2);
            }
        }
    }

    g_queue_free(queue);
    g_hash_table_destroy(seen_indices);
    return list;
}

void remove_index(guint32 idx) {
    // TODO
}

#ifdef MERGE_STATS
inline unsigned long get_unique_taint_count(void)
{
    return merge_profile.stats_op_count[STATS_OP_UNIQUE_TAINTS];
}
#endif

#ifdef __cplusplus
}
#endif

#endif // end guard TAINTS_GRAPH_FLAT_H
