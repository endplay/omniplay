#ifndef TAINTS_INDEX_H
#define TAINTS_INDEX_H

#include <stdio.h>
#include <stdlib.h>
#include "../list.h"
#include <glib-2.0/glib.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * This file contains all of the functions for manipulating taint
 * if we're using references to taints
 * */

#define NUM_OPTIONS INT_MAX
#define CONFIDENCE_LEVELS 1
typedef unsigned char TAINT_TYPE;
typedef long OPTION_TYPE;

struct taint {
    long id;
};

struct ltaints {
    OPTION_TYPE option;
    struct list_head list;
};

long idx_cnt = 1;
// structure for holding taint index
// Probably just a hash table
GHashTable* taint_index_table;
GHashTable* taint_merge_index;

#define INIT_TAINT_INDEX() { \
	taint_index_table = g_hash_table_new(g_direct_hash, g_direct_equal); \
    taint_merge_index = g_hash_table_new(g_direct_hash, g_direct_equal); \
}

// TODO: right now, there are no merge conflicts, need a better hash function, also to handle merge conflicts
inline unsigned long hash_indices(long index1, long index2) {
    return ((index1 + 205) + (index2 * 3)) % 7;
}

inline long new_index(OPTION_TYPE option) {
    struct list_head* lh;
    struct ltaints* lt;
    long idx = idx_cnt;
    lh = (struct list_head*) malloc(sizeof(struct list_head));
    INIT_LIST_HEAD (lh);

    lt = (struct ltaints *) malloc(sizeof(struct ltaints));
    lt->option = option;
    list_add (&lt->list, lh);

    g_hash_table_insert(taint_index_table, GINT_TO_POINTER(idx), lh);
    idx_cnt++; 

    return idx;
}

/* returns new index */
inline long merge_indices(long index1, long index2) {
    struct list_head* lh;
    struct ltaints* tmp;
    struct ltaints* tmp2;
    struct list_head* lt1;
    struct list_head* lt2;
    long idx = idx_cnt;
    unsigned long merge_idx;
    unsigned long hash_idx;

    // fast paths
    if (index1 == 0 && index2 == 0) return 0;
    if (index1 == 0 && index2 != 0) return index2;
    if (index1 != 0 && index2 == 0) return index1;
    if (index1 == index2) return index1;

    hash_idx = hash_indices(index1, index2);
    merge_idx  = (long) g_hash_table_lookup(taint_merge_index, GINT_TO_POINTER(hash_idx));
    if (merge_idx) return merge_idx;

    lt1 = (struct list_head *) g_hash_table_lookup(taint_index_table, GINT_TO_POINTER(index1));
    lt2 = (struct list_head *) g_hash_table_lookup(taint_index_table, GINT_TO_POINTER(index2));

    if (!lt1 && !lt2) return 0;

    lh = (struct list_head *) malloc(sizeof(struct list_head));
    assert(lh);
    INIT_LIST_HEAD (lh);
    if (lt1) {
        list_for_each_entry (tmp, lt1, list) {
            struct ltaints* m;
            m = (struct ltaints *) malloc(sizeof(struct ltaints));
            assert (m);
            m->option = tmp->option;
            list_add_tail(&m->list, lh);
        }
    }

    if (lt2) {
        list_for_each_entry (tmp, lt2, list) {
            int found = 0;
            struct ltaints* m;
            list_for_each_entry (tmp2, lh, list) {
                if (tmp2->option == tmp->option) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                m = (struct ltaints *) malloc(sizeof(struct ltaints));
                assert (m);
                m->option = tmp->option;
                list_add_tail(&m->list, lh);
            }
        }
    }

    g_hash_table_insert(taint_index_table, GINT_TO_POINTER(idx), lh);
    assert (!g_hash_table_contains(taint_merge_index, GINT_TO_POINTER(hash_idx)));
    g_hash_table_insert(taint_merge_index, GINT_TO_POINTER(hash_idx), GINT_TO_POINTER(idx));
    idx_cnt++;
    return idx;
}

#define new_taint(t) { (t)->id = 0; }
inline TAINT_TYPE get_taint_value(struct taint* t, OPTION_TYPE option) {
    struct ltaints* tmp;
    struct list_head* lt1;
    if (!t) return 0;
    if (t->id == 0) return 0;
    lt1 = (struct list_head *) g_hash_table_lookup(taint_index_table, GINT_TO_POINTER(t->id));
    if (!lt1) return 0;
    list_for_each_entry (tmp, lt1, list) {
        if (tmp->option == option) {
            return 1;
        }
    }
    return 0;
}

inline TAINT_TYPE get_max_taint_value(void) {
    return 1;
}

inline void set_taint_value (struct taint* t, OPTION_TYPE option, TAINT_TYPE value) {
    long index;
    assert (value == get_max_taint_value());
    index = new_index(option);
    t->id = index;
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

inline int get_num_taint_values(struct taint* src) {
    int count = 0;
    struct list_head* tmp;
    struct ltaints* tmp2;
    if (!src) return 0;
    if (src->id == 0) return 0;
    tmp = (struct list_head *) g_hash_table_lookup(taint_index_table, GINT_TO_POINTER(src->id));

    list_for_each_entry(tmp2, tmp, list) {
        count++;
    }

    return count;
}

#define clear_taint(dst) { (dst)->id = 0; }
#define set_taint(dst, src) { (dst)->id = (src)->id; }
inline void merge_taints(struct taint* dst, struct taint* src) {
    long new_index;
    if (!dst || !src) return;    
    if (src->id == 0) {
        dst->id = 0;
        return;
    }
    new_index = merge_indices(dst->id, src->id);
    dst->id = new_index;
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
    } else {
        struct list_head *lh;
        struct ltaints* lt;
        fprintf(fp, "id %ld: {", src->id);
        lh = (struct list_head *) g_hash_table_lookup(taint_index_table, GINT_TO_POINTER(src->id));
        list_for_each_entry (lt, lh, list) {
            fprintf(fp, "%d,", (int)lt->option);
        }
        fprintf(fp, "}\n");

    }
}

GList* get_non_zero_taints(struct taint* src) {
    struct list_head* lh;
    struct ltaints* tmp;
    GList* taint_list = NULL;
    if (!src || (src->id == 0)) return NULL;
    lh = (struct list_head *) g_hash_table_lookup(taint_index_table, GINT_TO_POINTER(src->id));
    if (!lh) return NULL;
    list_for_each_entry(tmp, lh, list) {
        taint_list = g_list_append(taint_list, GINT_TO_POINTER(tmp->option)); 
    }
    return taint_list;
}

#ifdef __cplusplus
}
#endif

#endif // end guard TAINTS_INDEX_H
