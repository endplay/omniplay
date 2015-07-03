#ifndef XRAY_SLAB_ALLOC_H
#define XRAY_SLAB_ALLOC_H

#include "list.h"
#include <stdlib.h>
#include <assert.h>

// A simple allocator that gets memory in slab sizes and returns
// allocations in fixed slice sizes.

#ifdef __cplusplus
extern "C" {
#endif

struct slab_alloc {
    char alloc_name[256]; // name, for debugging purposes
    int slab_size;      // size of a slab
    int slice_size;     // size of the allocations
    struct slab* current_slab; // current slab
    void* pos;  // current_position in slab
    int num_slabs; // number of slabs allocated
    unsigned long num_slices; // number of slices issued
    struct list_head list; // list of slabs
};

struct slab {
    void* start;
    void* end;
    struct list_head list;
};

// Needs to be called first to init global structures
void init_slab_allocs(void);

// Get a new slab allocator
void new_slab_alloc(char* alloc_name, struct slab_alloc* alloc,
                        int slice_size, int num_slices);

// Return a slice of memory from the slab allocator
void* get_slice(struct slab_alloc* alloc);

int serialize_slab_alloc(int outd, struct slab_alloc* alloc);

#ifdef __cplusplus
}
#endif

#endif
