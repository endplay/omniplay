#ifndef TAINTS_SLAB_ALLOC_H
#define TAINTS_SLAB_ALLOC_H
/* A Simple slab alocator */
#include "../list.h"
#include <stdlib.h>
#include <assert.h>

#define PAGE_SIZE 4096

#define NUM_SLAB_STRUCTS 2097152

int inited = 0;
struct slab* slab_structs;
struct slab* slab_structs_end;

struct slab_alloc {
    char alloc_name[256];
    int slab_size;
    int slice_size;
    struct slab* current_slab; // current slab
    void* pos;  // current_position in slab
    int num_slabs; // number of slabs allocated
    struct list_head list; // list of slabs
};

struct slab {
    void* s;
    void* end;
    struct list_head list;
};

int gcd(int a, int b)
{
    while (1) {
        if (a == 0) return b;
        b %= a;
        if (b == 0) return a;
        a %= b;
    }
}

int lcm(int a, int b)
{
    int g = gcd(a, b);
    return (a / g) * b;
}

void init_slab_alloc(void) {
    if (inited) {
        return;
    }
    slab_structs = (struct slab *) malloc(sizeof(struct slab) * NUM_SLAB_STRUCTS);
    slab_structs_end = slab_structs + NUM_SLAB_STRUCTS;
    inited = 1;
}

struct slab* new_slab_struct(void) {
    struct slab* slab;
    slab = slab_structs;
    slab_structs++;
    if (slab_structs == slab_structs_end) {
        slab_structs = (struct slab *) malloc(sizeof(struct slab) * NUM_SLAB_STRUCTS);
        slab_structs_end = slab_structs + NUM_SLAB_STRUCTS;
        // XXX TODO We lose the reference here, if we want to garbage collect, we'll have to
        // clean this up later.
    }
    return slab;
}

struct slab* new_slab(char* name, int size) {
    //struct slab* slab = (struct slab *) malloc(sizeof(struct slab));
    struct slab* slab = new_slab_struct();
    assert(slab);
    slab->s = malloc(size);
    if (!slab->s) {
        fprintf(stderr, "[%s] ERROR could not allocate new slab of size %d\n", name, size);
        assert(0);
    }
    slab->end = (void *) (((unsigned long) slab->s) + size);
    fprintf(stderr, "[%s] creating new slab of size %d\n", name, size);
    return slab;
}

/* Makes the slab size page aligned given a slice size */
int calculate_slab_size(int slice_size) {
    return lcm(slice_size, PAGE_SIZE);
}

/* Create a new allocator, which keeps a reference to all the slabs */
void new_slab_alloc(char* alloc_name, struct slab_alloc* alloc, int slice_size, int factor) {
    strncpy(alloc->alloc_name, alloc_name, 256);
    // the factor lets us have a page-aligned slab, but just larger
    alloc->slab_size = calculate_slab_size(slice_size) * factor; 
    fprintf(stderr, "[%s] Creating new slab allocate with slab size %d\n", alloc->alloc_name, alloc->slab_size);
    alloc->slice_size = slice_size;
    INIT_LIST_HEAD(&alloc->list);
    alloc->current_slab = new_slab(alloc_name, alloc->slab_size);
    list_add(&alloc->current_slab->list, &alloc->list);
    alloc->pos = alloc->current_slab->s;
    alloc->num_slabs = 1;
}

void* get_slice(struct slab_alloc* alloc) {
    void* pos = alloc->pos;
    alloc->pos = (void *) (((unsigned long)alloc->pos) + alloc->slice_size);
    if (alloc->pos == alloc->current_slab->end) {
        alloc->current_slab = new_slab(alloc->alloc_name, alloc->slab_size);
        alloc->pos = alloc->current_slab->s;
        alloc->num_slabs++;
        list_add(&alloc->current_slab->list, &alloc->list);
    } 
    return pos;
}

#endif // end guard
