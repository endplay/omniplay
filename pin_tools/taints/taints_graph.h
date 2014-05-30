#ifndef TAINTS_GRAPH_H
#define TAINTS_GRAPH_H

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
#define SPLIT_MERGE_HASH_SPACE

/* Different options */
// #define MERGE_PREDICTOR // simple 1-bit predictor
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
#ifdef MERGE_PREDICTOR
    struct node* prev_merged_with;  // who did I last merge with?
    struct node* prev_merged_result; // what was the result of the merge?
#endif
};

/* leafnode is a node with two NULL parents and an option value */
struct leafnode {
    struct node node;
    OPTION_TYPE option; 
};

struct taint {
    struct node* id;
};

#ifdef SPLIT_MERGE_HASH_SPACE
#define NUM_MERGE_TABLES 0x4
GHashTable* taint_merge_index_tables[NUM_MERGE_TABLES];
#else
// structure for holding merged indices
GHashTable* taint_merge_index;
#endif

#ifdef MERGE_STATS
#ifdef MERGE_PREDICTOR
long merge_predict_count = 0;
#endif
#endif

struct slab_alloc leaf_alloc;
struct slab_alloc node_alloc;
struct slab_alloc uint_alloc;

inline void init_taint_tables(void)
{
    int i = 0;
    for (i = 0; i < NUM_MERGE_TABLES; i++) {
        taint_merge_index_tables[i] = g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL); 
    }
}

inline void init_taint_index(void)
{
#ifdef SPLIT_MERGE_HASH_SPACE
    init_taint_tables();
#else
    taint_merge_index = g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);
#endif
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
#ifdef MERGE_PREDICTOR
    ln->node.prev_merged_with = NULL;
    ln->node.prev_merged_result = NULL;
#endif
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
#ifdef MERGE_PREDICTOR
    n->prev_merged_with = NULL;
    n->prev_merged_result = NULL;
#endif
    return n;
}

guint64* get_new_64() {
#ifdef USE_SLAB_ALLOCATOR    
    return (guint64 *) get_slice(&uint_alloc);
#else
    return (guint 64 *) malloc(sizeof(guint64));
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

inline void new_taint(struct taint* t) {
    t->id = 0;
}

inline TAINT_TYPE get_max_taint_value(void) {
    // return G_MAXINT8;
    return 1;
}

inline TAINT_TYPE get_taint_value(struct taint* t, OPTION_TYPE option) {
    GQueue* queue = g_queue_new();
    GHashTable* seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
    struct node* n = t->id;
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

inline void set_taint_value (struct taint* t, OPTION_TYPE option, TAINT_TYPE value) {
    struct leafnode* ln;
    ln = get_new_leafnode(option);

    t->id = (struct node *) ln;
#ifdef MERGE_STATS
    increment_taint_op(&merge_profile, STATS_OP_UNIQUE_TAINTS);
#endif
}

inline int is_taint_equal(struct taint* first, struct taint* second) {
    if (!first && !second) return 0;
    if ((first && !second) || (!first && second)) return 1;
    return first->id == second->id;
}

inline int is_taint_zero(struct taint* src) {
#ifdef BINARY_FWD_TAINT
    if ((u_long) src) {
        return 1;
    } else {
        return 0;
    }
#else
    if (!src) return 0;
    return !src->id;
#endif
}

inline void is_taint_full(struct taint* t) {
    fprintf(stderr, "Should not use full taints in index mode\n");
}

inline void set_taint_full (struct taint* t) {
    fprintf(stderr, "Should not use full taints in index mode\n");
}

inline void clear_taint(struct taint* t) {
    if (!t) return;
    t->id = 0;
#ifdef MERGE_STATS
    increment_taint_op(&merge_profile, STATS_OP_CLEAR);
#endif
}

inline void set_taint(struct taint* dst, struct taint* src) {
    dst->id = src->id;
#ifdef MERGE_STATS
    increment_taint_op(&merge_profile, STATS_OP_SET);
#endif
}

inline void merge_taints(struct taint* dst, struct taint* src) {
    struct node* n;
    guint64 hash;
    guint64* phash;
    GHashTable* taint_merge_index;

    if (!dst || !src) return;
    if (dst->id == 0) {
        dst->id = src->id;
        return;
    }
    if (src->id == 0) {
        return;
    }
    if (dst->id == src->id) {
        return;
    }
#ifdef BINARY_FWD_TAINT
    if (src->id) {
        dst->id = src->id;
        return;
    }
#endif

#ifdef MERGE_PREDICTOR
    n = dst->id;
    if (n->prev_merged_with == src->id) {
        dst->id = n->prev_merged_result;
#ifdef MERGE_STATS
        merge_predict_count = 0;
#endif
        return;
    }
#endif

    hash = hash_indices((guint32) dst->id, (guint32) src->id);
#ifdef MERGE_STATS
    increment_taint_op(&merge_profile, STATS_OP_MERGE);	
#endif
    taint_merge_index = taint_merge_index_tables[hash & (NUM_MERGE_TABLES-1)];
    n = (struct node *) g_hash_table_lookup(taint_merge_index, &hash);
    if (!n) {
        n = get_new_node(dst->id, src->id);
        //phash = (guint64 *) malloc(sizeof(guint64));
        phash = (guint64 *) get_new_64();
        memcpy(phash, &hash, sizeof(guint64));
        g_hash_table_insert(taint_merge_index, phash, n);
#ifdef MERGE_STATS
        increment_taint_op(&merge_profile, STATS_OP_UNIQUE_MERGE);	
        increment_taint_op(&merge_profile, STATS_OP_UNIQUE_TAINTS);
#endif
    }
#ifdef MERGE_PREDICTOR
    dst->id->prev_merged_with = src->id;
    dst->id->prev_merged_result = n;
#endif
    //fprintf(stderr, "merge (%lu, %lu) result: %lu\n", (unsigned long) dst->id, (unsigned long) src->id, (unsigned long) n);
    dst->id = n;
}

void shift_taints(struct taint* dst, struct taint* src, int level) {
    fprintf(stderr, "Should not use SHIFT taints in index mode\n");
}
void shift_merge_taints(struct taint* dst, struct taint* src, int level) {
    fprintf(stderr, "Should not use SHIFT MERGE taints in index mode\n");
}

void shift_cf_taint(struct taint* dst, struct taint* cond, struct taint* prev) {
    fprintf(stderr, "Should not use SHIFT CF taints in index mode\n");
}

void print_kv(gpointer key, gpointer value, gpointer user_data)
{
    fprintf(stderr, "k: %p, v: %d\n", key, GPOINTER_TO_INT(value));
}

void print_taint(FILE* fp, struct taint* src) {
    if (!src) {
        fprintf(fp, "id {0}\n");
    } else if (!src->id) {
        fprintf(fp, "id {0}\n");
    } else {
        GQueue* queue = g_queue_new();
        GHashTable* seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);
        struct node* n = src->id;

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
GList* get_non_zero_taints(struct taint* t) {
    GHashTable* seen_indices;
    GList* list = NULL;
    struct node* n = t->id;
    GQueue* queue;

    if (!n) {
        return NULL;
    }
    queue = g_queue_new();
    seen_indices = g_hash_table_new(g_direct_hash, g_direct_equal);

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

#endif // end guard TAINTS_GRAPH_H
