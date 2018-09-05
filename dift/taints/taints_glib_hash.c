#include "taints.h"
#include <glib-2.0/glib.h>
#include <stdlib.h>
#include <assert.h>

struct taint* new_ptaint(void)
{
    struct taint* t;
    t = (struct taint*) malloc(sizeof(struct taint));
    new_taint(t);
    return t;
}

void new_taint(struct taint* t)
{
    t->taint_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    assert(t->taint_table);
    clear_taint(t);
}

TAINT_TYPE get_taint_value (struct taint* vector, OPTION_TYPE option)
{
    return GPOINTER_TO_INT(g_hash_table_lookup (vector->taint_table, GINT_TO_POINTER(option)));
}

void set_taint_value(struct taint* vector, OPTION_TYPE option, TAINT_TYPE value)
{
    return g_hash_table_insert(vector->taint_table, GINT_TO_POINTER(option), GINT_TO_POINTER(value));
}

int is_taint_equal(struct taint* first, struct taint* second)
{
    GHashTableIter iter;
    gpointer key, value;
    if (!first && !second) return 0;
    if ((first && !second) || (!first && second)) return 1;

    g_hash_table_iter_init (&iter, first->taint_table);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        if (g_hash_table_lookup (second->taint_table, key) != value) return 0;
    }

    g_hash_table_iter_init (&iter, second->taint_table);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        if (g_hash_table_lookup (first->taint_table, key) != value) return 0;
    }

    return 1;
}

int is_taint_zero(struct taint* src)
{
	GList* values;
	GList* next = NULL;
	int rc = 1;
	if (!src) return 1;
	if (!src->taint_table) return 1;
	// iterate through all values
	values = g_hash_table_get_values(src->taint_table);
	next = values;
	while (next != NULL) {
		if (next->data != 0) {
			// return 0
			rc = 0;
			break;
		}
		next = g_list_next(next);
	}
	g_list_free(values);
	return rc;
}

int is_taint_full(struct taint* src)
{
	// XXX implement me
	fprintf(stderr, "[ERROR]is_taint_full is not implemented yet for this taint type\n");
	return 0;
}

TAINT_TYPE get_max_taint_value(void)
{
	return 255;
}

void set_taint_full(struct taint* src)
{
	// XXX implement me
    fprintf(stderr, "[ERROR]set_taint_full is not implemented yet for this taint type\n");
}

void destroy_taint(struct taint* vector)
{
    g_hash_table_destroy(vector->taint_table);
}

void clear_taint(struct taint* dst)
{
    if(!dst) return;
    assert(dst->taint_table);
    /*
    if (!dst->taint_table) {
	    dst->taint_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    */
    g_hash_table_remove_all(dst->taint_table);
}

void set_taint(struct taint* dst, struct taint* src)
{
    GHashTableIter iter;
    gpointer key, value;

    clear_taint(dst);

    g_hash_table_iter_init (&iter, src->taint_table);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        g_hash_table_insert (dst->taint_table, key, value);
    }
}

void merge_taints(struct taint* dst, struct taint* src) 
{
    GHashTableIter iter;
    gpointer key, value;

    if(!dst || !src) return;
    g_hash_table_iter_init (&iter, src->taint_table);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        if (g_hash_table_lookup (dst->taint_table, key) < value) {
            g_hash_table_insert (dst->taint_table, key, value);
        }
    }
}

void shift_taints(struct taint* dst, struct taint* src, int level)
{
    GHashTableIter iter;
    gpointer key, value;
    // not sure if this is right
    clear_taint(dst);

    g_hash_table_iter_init (&iter, src->taint_table);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        TAINT_TYPE tt = ((TAINT_TYPE) GPOINTER_TO_INT(value)) >> level;
        g_hash_table_insert (dst->taint_table, key, GINT_TO_POINTER(tt));
    }
}

void shift_merge_taints(struct taint* dst, struct taint* src, int level)
{
    GHashTableIter iter;
    gpointer key, value;
    if (level != CONFIDENCE_LEVELS) {
        g_hash_table_iter_init (&iter, src->taint_table);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
            TAINT_TYPE smt_shifted = ((TAINT_TYPE) GPOINTER_TO_INT(value)) >> level;
            if ((GPOINTER_TO_INT(g_hash_table_lookup (dst->taint_table, key))) < smt_shifted) {
                g_hash_table_insert (dst->taint_table, key, GINT_TO_POINTER(smt_shifted));
            }
        }
    }
}

void shift_cf_taint(struct taint* dst, struct taint* cond, struct taint* prev)
{
    GHashTableIter iter;
    GHashTableIter conditer;
    gpointer key, value;
    // go through all options in prev, compare that taint value >> 1 with the option in cond, take cond if larger
    g_hash_table_iter_init (&iter, prev->taint_table);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
            TAINT_TYPE smt_shifted = ((TAINT_TYPE) GPOINTER_TO_INT(value)) >> 1;
            TAINT_TYPE cond_value = ((TAINT_TYPE) (GPOINTER_TO_INT(g_hash_table_lookup (cond->taint_table, key))));
            if (cond_value > smt_shifted) {
                g_hash_table_insert (dst->taint_table, key, GINT_TO_POINTER(cond_value));
            } else {
                g_hash_table_insert (dst->taint_table, key, GINT_TO_POINTER(smt_shifted));
            }
    }

    // go through all options in cond, if not in prev, take cond
    g_hash_table_iter_init (&conditer, cond->taint_table);
    while (g_hash_table_iter_next (&conditer, &key, &value)) {
        if (!g_hash_table_contains(prev->taint_table, key)) {
            TAINT_TYPE cond_value = ((TAINT_TYPE) (GPOINTER_TO_INT(g_hash_table_lookup (cond->taint_table, key))));
            g_hash_table_insert (dst->taint_table, key, GINT_TO_POINTER(cond_value));
        }
    }
}

void __print_taint_value(gpointer key, gpointer value, gpointer user_data)
{
	FILE* fp = (FILE *) user_data;
	if (GPOINTER_TO_INT(value) != 0) {
		fprintf(fp, "%d:%u, ", GPOINTER_TO_INT(key), GPOINTER_TO_INT(value));
	}
}

void print_taint(FILE* fp, struct taint* src)
{
	int i = 0;
	fprintf(fp, "{");
	// traverse values, output non-zero taints
	if (src) {
		g_hash_table_foreach(src->taint_table, __print_taint_value, fp);
	}
	fprintf(fp, "}\n");
	fflush(fp);
}

void __add_non_zero_taint(gpointer key, gpointer value, gpointer user_data)
{
	GList* taint_list = *((GList**) user_data);
	if (GPOINTER_TO_INT(value) != 0) {
		taint_list = g_list_append(taint_list, key);
	}
}

GList* get_non_zero_taints(struct taint* src)
{
	/*
	GList** taint_list;
	*(taint_list) = NULL;
	if (src) {
		g_hash_table_foreach(src->taint_table, __add_non_zero_taint, taint_list);
	}
	return *(taint_list);
	*/
	return g_hash_table_get_keys(src->taint_table);
}


