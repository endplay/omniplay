#ifndef TAINTS_HASH_H
#define TAINTS_HASH_H

#include <glib-2.0/glib.h>
#include <stdlib.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NUM_OPTIONS INT_MAX

struct taint {
    GHashTable* taint_table;
};

#ifdef __cplusplus
}
#endif

#endif // end guard TAINTS_ARRAY_H

