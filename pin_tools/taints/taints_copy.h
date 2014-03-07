#ifndef TAINTS_COPY_H
#define TAINTS_COPY_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * This file contains all of the functions for manipulating taint
 * if we're running in only the copy linkage.
 * */

#define NUM_OPTIONS INT_MAX
struct taint {
    long id;
};

#define CONFIDENCE_LEVELS 1
typedef unsigned char TAINT_TYPE;
typedef long OPTION_TYPE;

#define new_taint(t) { (t)->id = 0; }

struct taint* new_ptaint(void) {
    struct taint *t;
    t = (struct taint *) malloc(sizeof(struct taint));
    new_taint(t);
    return t;
}

void destroy_taint(struct taint* vector) {
    free(vector);
}

#define get_taint_value(vector, option) { ((vector)->id == option); }
#define set_taint_value(vector, option, value) { (vector)->id = option; }

inline int is_taint_equal(struct taint* first, struct taint* second) {
    if (!first && !second) return 0;
    if ((first && !second) || (!first && second)) return 1;
    return first->id == second->id;
}

inline int is_taint_zero(struct taint* src) {
    if (!src) return 0;
    return src->id == 0;
}

inline int is_taint_full(struct taint* src) {
    return 0;
}

inline TAINT_TYPE get_max_taint_value(void) {
    return 1;
}

inline void set_taint_full(struct taint* src) {
    return;
};

inline int get_num_taint_values(struct taint* src) {
    if (!src) return 0;
    return src->id != 0;
}

#define clear_taint(dst) { (dst)->id = 0; }
#define set_taint(dst, src) { (dst)->id = (src)->id; }
#define __merge_taints(dst, src) { \
	if ((dst)->id != (src)->id && (src)->id != 0) { \
		(dst)->id = 0; \
	} \
}
inline void merge_taints(struct taint* dst, struct taint* src) {
    if (!dst || !src) return;    
    __merge_taints (dst, src);
}

void copy_taint(struct taint* dst, struct taint* src) {
}

void shift_taints(struct taint* dst, struct taint* src, int level) {
    fprintf(stderr, "Should not use SHIFT taints in copy mode\n");
}
void shift_merge_taints(struct taint* dst, struct taint* src, int level) {
    fprintf(stderr, "Should not use SHIFT MERGE taints in copy mode\n");
}

void shift_cf_taint(struct taint* dst, struct taint* cond, struct taint* prev) {
    fprintf(stderr, "Should not use SHIFT CF taints in copy mode\n");
}

void print_taint(FILE* fp, struct taint* src) {
    if (!src) { fprintf(fp, "{ }\n"); return; }
    fprintf(fp, "id {%ld}\n", src->id);
}

GList* get_non_zero_taints(struct taint* src) {
    GList* taint_list = NULL;
    if (!src) return NULL;
    if (src->id) {
        taint_list = g_list_append(taint_list, GINT_TO_POINTER(src->id));
    }
    return taint_list;
}

#ifdef __cplusplus
}
#endif

#endif // end guard TAINTS_COPY_H
