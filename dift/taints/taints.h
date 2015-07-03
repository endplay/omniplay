#ifndef TAINTS_H
#define TAINTS_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// the struct of the taint can be defined in the implementation
struct taint;

/* need to change at the same time */
// #define CONFIDENCE_LEVELS (sizeof(unsigned char) * 8)
#define CONFIDENCE_LEVELS 8
typedef unsigned char TAINT_TYPE;     
/* all above need to change at the same time*/

typedef int OPTION_TYPE;

#define TAINTS_HASH
// definition of a taint
#ifdef TAINTS_HASH
#include "taints-hash.h"
#else
// default definition
#include "taints-array.h"
#endif


// Function signatures
/* Allocates a new taint structure and returns it */
struct taint* new_ptaint(void);
/* Initializes the fields of the taint and clears it*/
void new_taint(struct taint* t);
/* Frees taint structure, should be called on all taints created with new_ptaint */
void destroy_taint(struct taint* vector);

TAINT_TYPE get_taint_value(struct taint* vector, OPTION_TYPE option);
void set_taint_value(struct taint* vector, OPTION_TYPE option, TAINT_TYPE value);
int is_taint_equal(struct taint* first, struct taint* second);
int is_taint_zero(struct taint* src);
int is_taint_full(struct taint* src);

TAINT_TYPE get_max_taint_value(void);
/* Sets the taint value to the maximum value for every possible taint */
void set_taint_full(struct taint* src);

/* Returns the number of non-zero taint tokens */
int get_num_taint_values(struct taint* src);

// Clears all taints, i.e. sets equal to 0
void clear_taint(struct taint* dst);
// Sets dst taint to src
void set_taint(struct taint* dst, struct taint* src);
void merge_taints(struct taint* dst, struct taint* src);
void copy_taint(struct taint* dst, struct taint* src);

// sets the dst taint equal to the src taint shifted by level
void shift_taints(struct taint* dst, struct taint* src, int level);
void shift_merge_taints(struct taint* dst, struct taint* src, int level);

void shift_cf_taint(struct taint* dst, struct taint* cond, struct taint* prev);

void print_taint(FILE* fp, struct taint* src);
GList* get_non_zero_taints(struct taint* src);

#ifdef __cplusplus
}
#endif

#endif // end guard TAINTS_H
