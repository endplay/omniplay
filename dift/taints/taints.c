#include "taints.h"
#include <stdlib.h>
#include <string.h>

/*
struct taint {
	TAINT_TYPE options[NUM_OPTIONS];
};
*/

struct taint* new_ptaint(void)
{
	struct taint* t;
	t = (struct taint*) malloc(sizeof(struct taint));
	new_taint(t);
	return t;
}

void new_taint(struct taint* t)
{
	clear_taint(t);
}

void destroy_taint(struct taint* vector) {
	free(vector);
}

TAINT_TYPE get_taint_value(struct taint* vector, OPTION_TYPE option)
{
	return vector->options[option];
}

void set_taint_value(struct taint* vector, OPTION_TYPE option, TAINT_TYPE value)
{
	vector->options[option] = value;
}

int is_taint_equal(struct taint* first, struct taint* second)
{
	int i = 0;
	if (!first && !second) return 0;
	if ((first && !second) || (!first && second)) return 1;
	for(i = 0; i < NUM_OPTIONS; i++) {
		if (first->options[i] != second->options[i]) return 0;
	}
	return 1;
}

int is_taint_zero(struct taint* src)
{
	int i;
	if (!src) return 1;
	for(i = 0; i < NUM_OPTIONS; i++) {
		if (src->options[i] != 0) return 0;
	}
	return 1;
}

int is_taint_full(struct taint* src)
{
	int i;
	if (!src) return 0;
	for(i = 0; i < NUM_OPTIONS; i++) {
		if (src->options[i] != 255) return 0;
	}
	return 1;
}

TAINT_TYPE get_max_taint_value(void)
{
	return 255;
}

void set_taint_full(struct taint* src)
{
	int i = 0;
	for (i = 0; i < NUM_OPTIONS; i++) {
		src->options[i] = 255;
	}
}

void clear_taint(struct taint* dst)
{
	memset((dst), 0, sizeof(struct taint));
}

void set_taint(struct taint* dst, struct taint* src)
{
	memcpy((dst), (src), sizeof(struct taint));
}

void merge_taints(struct taint* dst, struct taint* src) 
{
	int mt_i;
	if(!dst || !src) return;
	for(mt_i = 0; mt_i < NUM_OPTIONS; mt_i++) {
		if ((dst)->options[mt_i] < (src)->options[mt_i]) {
			(dst)->options[mt_i] = (src)->options[mt_i];
		}
	}	
}

void shift_taints(struct taint* dst, struct taint* src, int level)
{
	int st_i;
	if(!dst || !src) return;
	for(st_i = 0; st_i < NUM_OPTIONS; st_i++) {
		(dst)->options[st_i] = (src)->options[st_i] >> level;
	}
}

void shift_merge_taints(struct taint* dst, struct taint* src, int level)
{
	int smt_i;
	if (level != CONFIDENCE_LEVELS) {
		for(smt_i = 0; smt_i < NUM_OPTIONS; smt_i++) {
			TAINT_TYPE smt_shifted = (src)->options[smt_i] >> level;
			if ((dst)->options[smt_i] < smt_shifted) {
				(dst)->options[smt_i] = smt_shifted;
			}
		}
	}
}

void shift_cf_taint(struct taint* dst, struct taint* cond, struct taint* prev)
{
	int sct_i;
	for(sct_i = 0; sct_i < NUM_OPTIONS; sct_i++) {
		TAINT_TYPE smt_shifted = (prev)->options[sct_i] >> 1;
		(dst)->options[sct_i] = ((cond)->options[sct_i] > smt_shifted) ? (cond)->options[sct_i] : smt_shifted;
	}	
}

void print_taint(FILE *fp, struct taint* src)
{
	int i = 0;
	fprintf(fp, "{");
	if (src) {
		for (i = 0; i < NUM_OPTIONS; i++) {
			TAINT_TYPE t = src->options[i];
			if (t != 0) {
				fprintf(fp, "%d:%u, ", i, t);
			}
		}
	}
	fprintf(fp, "}\n");
	fflush(fp);
}

GList* get_non_zero_taints (struct taint* src)
{
	int i = 0;
	GList* taint_list = NULL;
	for (i = 0; i < NUM_OPTIONS; i++) {
		if (src->options[i] != 0) {
			taint_list = g_list_append(taint_list, GINT_TO_POINTER(i));
		}
	}
	return taint_list;
}
