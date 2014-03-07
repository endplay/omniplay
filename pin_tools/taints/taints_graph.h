#ifndef TAINTS_GRAPH_H
#define TAINTS_GRAPH_H

#include <stdio.h>
#include <stdlib.h>
#include "../list.h"
#include <glib-2.0/glib.h>
#include <assert.h>
#include <string.h>

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

// the type of an index
typedef guint32 OPTION_TYPE;

struct taint {
    guint32 id;
};

struct merge_pair {
    guint32 id1;
    guint32 id2;
};

guint32 idx_cnt = 1;
// structure for holding taint index
GHashTable* taint_index_table;
// structure for holding merged indices
GHashTable* taint_merge_index;
// structure to map indices to options (to figure out which syscall created a taint)
GHashTable* index_option_table;

// #define MERGE_STATS
#ifdef MERGE_STATS
long merge_count = 0;
long unique_merge_count = 0;
#endif

#define INIT_TAINT_INDEX() { \
    taint_index_table = g_hash_table_new(g_direct_hash, g_direct_equal); \
    taint_merge_index = g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL); \
    index_option_table = g_hash_table_new(g_direct_hash, g_direct_equal); \
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

struct merge_pair* get_new_merge_pair(guint32 id1, guint32 id2)
{
    struct merge_pair* mp;
    mp = (struct merge_pair *) malloc(sizeof(struct merge_pair));
    mp->id1 = id1;
    mp->id2 = id2;

    return mp;
}

int mp_has_option(struct merge_pair* mp, OPTION_TYPE option)
{
    // basicaly, return true if root node
    return (mp->id1 == 0 && mp->id2 == option);
}

inline guint32 get_new_index(void) {
    guint32 idx = idx_cnt;
    idx_cnt++; 
    return idx;
}

#define new_taint(t) { (t)->id = 0; }

inline TAINT_TYPE get_max_taint_value(void) {
    // return G_MAXINT8;
    return 1;
}

inline TAINT_TYPE get_taint_value(struct taint* t, OPTION_TYPE option) {
    GQueue* queue = g_queue_new();
    guint32 idx = t->id;
    g_queue_push_tail(queue, GUINT_TO_POINTER(idx));
    TAINT_TYPE found = 0;
    while(!g_queue_is_empty(queue)) {
        struct merge_pair* mp;
        idx = GPOINTER_TO_UINT(g_queue_pop_head(queue));

        mp = (struct merge_pair *) g_hash_table_lookup(taint_index_table, GUINT_TO_POINTER(idx));
        assert(mp);
        if (mp->id1 == 0) {
            if (mp->id2 == option) {
                found = get_max_taint_value();
                break;
            }
        } else {
            g_queue_push_tail(queue, GUINT_TO_POINTER(mp->id1));
            g_queue_push_tail(queue, GUINT_TO_POINTER(mp->id2));
        }
    }
    g_queue_free(queue);
    return found;
}


inline void set_taint_value (struct taint* t, OPTION_TYPE option, TAINT_TYPE value) {
    guint32 index;
    struct merge_pair* mp;
    assert (value == get_max_taint_value());
    index = get_new_index();
    mp = get_new_merge_pair(0, index);
    t->id = index;

    // now insert into table
    g_hash_table_insert(taint_index_table, GUINT_TO_POINTER(index), mp);
    // map index to option
    g_hash_table_insert(index_option_table, GUINT_TO_POINTER(index), GUINT_TO_POINTER(option));
}

OPTION_TYPE get_option_from_index(guint32 index)
{
    OPTION_TYPE option = GPOINTER_TO_UINT(g_hash_table_lookup(index_option_table, GUINT_TO_POINTER(index)));
    return option;
}

inline int is_taint_equal(struct taint* first, struct taint* second) {
    if (!first && !second) return 0;
    if ((first && !second) || (!first && second)) return 1;
    return first->id == second->id;
}

inline int is_taint_zero(struct taint* src) {
    if (!src) return 0;
    return src->id == 0;
}

inline void is_taint_full(struct taint* t) {
    fprintf(stderr, "Should not use full taints in index mode\n");
}

inline void set_taint_full (struct taint* t) {
    fprintf(stderr, "Should not use full taints in index mode\n");
}

#define clear_taint(dst) { (dst)->id = 0; }
#define set_taint(dst, src) { (dst)->id = (src)->id; }

inline guint32 merge_indices(guint32 index1, guint32 index2) {
    guint32 idx = idx_cnt;
    guint32 merge_idx;
    guint64 hash_idx;
    guint64* phash_idx;

    // fast paths
    if (index1 == 0 && index2 == 0) return 0;
    if (index1 == 0 && index2 != 0) return index2;
    if (index1 != 0 && index2 == 0) return index1;
    if (index1 == index2) return index1;

    hash_idx = hash_indices(index1, index2);
    phash_idx = (guint64 *) malloc(sizeof(guint64));
    memcpy(phash_idx, &hash_idx, sizeof(guint64));

    merge_idx  = (guint32) g_hash_table_lookup(taint_merge_index, phash_idx);

#ifdef MERGE_STATS
    merge_count++;
    fprintf(stderr, "[MERGE] %lu %lu\n", (unsigned long) index1, (unsigned long) index2);
#endif

    if (merge_idx) {
        free(phash_idx);
        return merge_idx;
    }

#ifdef MERGE_STATS
    unique_merge_count++;
    fprintf(stderr, "[MERGE] %lu %lu -> %lu\n", (unsigned long) index1, (unsigned long) index2, (unsigned long) merge_idx);
#endif

    assert (!g_hash_table_contains(taint_merge_index, phash_idx));
    g_hash_table_insert(taint_merge_index, phash_idx, GUINT_TO_POINTER(idx));
    idx_cnt++;
    return idx;
}

inline void merge_taints(struct taint* dst, struct taint* src) {
#ifdef COPY_ONLY
    dst->id = 0;
#else
    guint32 new_index;
    struct merge_pair* mp;
    if (!dst || !src) return;    
    if (dst->id == 0) {
        return;
    }
    if (src->id == 0) {
        dst->id = 0;
        return;
    }
    if (dst->id == src->id) {
        return;
    }
    new_index = merge_indices(dst->id, src->id);
    mp = get_new_merge_pair(dst->id, src->id);
    dst->id = new_index;
    g_hash_table_insert(taint_index_table, GUINT_TO_POINTER(new_index), mp);
#endif
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

void print_taint(FILE* fp, struct taint* src) {
    if (!src) {
        fprintf(fp, "id {0}\n");
    } else if (src->id == 0) {
        fprintf(fp, "id {0}\n");
    } else {
        GQueue* queue = g_queue_new();
        guint32 idx = src->id;

        fprintf(fp, "id %lu: {", (unsigned long) src->id);
        g_queue_push_tail(queue, GUINT_TO_POINTER(idx));
        while(!g_queue_is_empty(queue)) {
            struct merge_pair* mp;
            idx = GPOINTER_TO_UINT(g_queue_pop_head(queue));

            mp = (struct merge_pair *) g_hash_table_lookup(taint_index_table, GUINT_TO_POINTER(idx));
            assert(mp);
            if (mp->id1 == 0) {
                // leaf node
                fprintf(fp, "%lu,", (unsigned long) mp->id2);
            } else {
                g_queue_push_tail(queue, GUINT_TO_POINTER(mp->id1));
                g_queue_push_tail(queue, GUINT_TO_POINTER(mp->id2));
            }
        }
        g_queue_free(queue);
        fprintf(fp, "}\n");
    }
}

/* Compute the taints in the index */
GList* get_non_zero_taints(struct taint* t) {
    GList* list = NULL;
    GQueue* queue = g_queue_new();
    guint32 idx = t->id;
    g_queue_push_tail(queue, GUINT_TO_POINTER(idx));
    while(!g_queue_is_empty(queue)) {
        struct merge_pair* mp;
        idx = GPOINTER_TO_UINT(g_queue_pop_head(queue));

        mp = (struct merge_pair *) g_hash_table_lookup(taint_index_table, GUINT_TO_POINTER(idx));
        assert(mp);
        if (mp->id1 == 0) {
            // leaf node
            OPTION_TYPE option;
            option = get_option_from_index(mp->id2);
            if (!option) {
                fprintf(stderr, "could not look up index %lu\n", (unsigned long) mp->id2);
            }
            assert(option);
            list = g_list_prepend(list, GUINT_TO_POINTER(option));
        } else {
            g_queue_push_tail(queue, GUINT_TO_POINTER(mp->id1));
            g_queue_push_tail(queue, GUINT_TO_POINTER(mp->id2));
        }
    }
    g_queue_free(queue);
    return list;
}

void remove_index(guint32 idx) {
    // TODO
}

#ifdef __cplusplus
}
#endif

#endif // end guard TAINTS_GRAPH_H
