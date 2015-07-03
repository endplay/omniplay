#ifndef TAINTS_MERGE_LIST_H
#define TAINTS_MERGE_LIST_H

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

/* Different options */
//#define MERGE_STATS

#ifdef MERGE_STATS
#include "../taints_profile.h"
struct taints_profile merge_profile;
#endif

// the type of an index
typedef guint32 OPTION_TYPE;

struct taint {
    GList* id;
};

// structure for holding merged indices
GHashTable* taint_merge_index;

#ifdef MERGE_STATS
long merge_predict_count = 0;
#endif

struct slab_alloc leaf_alloc;
struct slab_alloc node_alloc;

#define INIT_TAINT_INDEX() { \
    taint_merge_index = g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL); \
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
    t->id = NULL;
}

inline TAINT_TYPE get_max_taint_value(void) {
    // return G_MAXINT8;
    return 1;
}

inline TAINT_TYPE get_taint_value(struct taint* t, OPTION_TYPE option) {
    GList* tmp;
    tmp = t->id;
    while(tmp) {
        if (GPOINTER_TO_UINT(tmp->data) == option) {
            return 1;
        }
        tmp = tmp->next;
    }
    return 0;
}

inline void set_taint_value (struct taint* t, OPTION_TYPE option, TAINT_TYPE value) {
    GList* taints = NULL;
    taints = g_list_append(taints, GUINT_TO_POINTER(option));
    t->id = taints;
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
    if (!src) return 0;
    return !src->id;
}

inline void is_taint_full(struct taint* t) {
    fprintf(stderr, "Should not use full taints in index mode\n");
}

inline void set_taint_full (struct taint* t) {
    fprintf(stderr, "Should not use full taints in index mode\n");
}

inline void clear_taint(struct taint* t) {
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

GList* merge_taint_lists(GList* list1, GList* list2)
{
    GHashTable* table; // tmp table
    GList* list1_copy;
    GList* list2_copy;
    GList* tmp;

    // Since we are just storing the data in the pointer, we don't need
    // to do a deep copy
    list1_copy = g_list_copy(list1);
    list2_copy = g_list_copy(list2);
    table = g_hash_table_new(g_direct_hash, g_direct_equal);
    
    tmp = list1_copy;
    while (tmp) {
        g_hash_table_insert(table, tmp->data, GINT_TO_POINTER(1));
        tmp = tmp->next;
    }
    tmp = list2_copy;
    while (tmp) {
        g_hash_table_insert(table, tmp->data, GINT_TO_POINTER(1));
        tmp = tmp->next;
    }

    tmp = g_hash_table_get_keys(table);
    // clean up temporary structures
    g_list_free(list1_copy);
    g_list_free(list2_copy);
    g_hash_table_destroy(table);

    return tmp;
}

inline void merge_taints(struct taint* dst, struct taint* src) {
    GList* n;
    guint64 hash;
    guint64* phash;

    if (!dst || !src) return;    
    if (dst->id == 0) {
        dst->id = src->id;
        return;
    }
    if (src->id == 0) {
        return;
    }
    if (!src->id) {
        return;
    }
    if (dst->id == src->id) {
        return;
    }
    if (!dst->id) {
        dst->id = src->id;
        return;
    }

    hash = hash_indices((guint32) dst->id, (guint32) src->id);
#ifdef MERGE_STATS
    increment_taint_op(&merge_profile, STATS_OP_MERGE);	
#endif
    n = (GList *) g_hash_table_lookup(taint_merge_index, &hash);
    if (!n) {
        n = merge_taint_lists(dst->id, src->id);
        phash = (guint64 *) malloc(sizeof(guint64));
        memcpy(phash, &hash, sizeof(guint64));
        g_hash_table_insert(taint_merge_index, phash, n);
#ifdef MERGE_STATS
        increment_taint_op(&merge_profile, STATS_OP_UNIQUE_MERGE);	
        increment_taint_op(&merge_profile, STATS_OP_UNIQUE_TAINTS);
#endif
    }
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

void __print_taint(gpointer data, gpointer user_data) {
    FILE* fp = (FILE *) user_data;
    fprintf(fp, "%u, ", GPOINTER_TO_UINT(data));
}

void print_taint(FILE* fp, struct taint* src) {
    if (!src) {
        fprintf(fp, "id {0}\n");
    } else if (!src->id) {
        fprintf(fp, "id {0}\n");
    } else {
        fprintf(fp, "{ ");
        g_list_foreach(src->id, __print_taint, fp);
        fprintf(fp, "}\n");
    }
}

/* Compute the taints in the index */
GList* get_non_zero_taints(struct taint* t) {
    return g_list_copy(t->id);
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
