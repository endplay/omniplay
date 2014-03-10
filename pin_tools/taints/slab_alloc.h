/* A Simple slab alocator */
#include "../list.h"
#include <stdlib.h>
#include <assert.h>

#define PAGE_SIZE 4096

struct slab_alloc {
    int slab_size;
    int slice_size;
    struct slab* current_slab; // current slab
    void* pos;  // current_position in slab
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

struct slab* new_slab(int size) {
    struct slab* slab = (struct slab *) malloc(sizeof(struct slab));
    assert(slab);
    slab->s = malloc(size);
    slab->end = (void *) (((unsigned long) slab->s) + size);
    return slab;
}

/* Makes the slab size page aligned given a slice size */
int calculate_slab_size(int slice_size) {
    return lcm(slice_size, PAGE_SIZE);
}

/* Create a new allocator, which keeps a reference to all the slabs */
void new_slab_alloc(struct slab_alloc* alloc, int slice_size, int factor) {
    // the factor lets us have a page-aligned slab, but just larger
    alloc->slab_size = calculate_slab_size(slice_size) * factor; 
    alloc->slice_size = slice_size;
    INIT_LIST_HEAD(&alloc->list);
    alloc->current_slab = new_slab(alloc->slab_size);
    list_add(&alloc->current_slab->list, &alloc->list);
    alloc->pos = alloc->current_slab->s;
}

void* get_slice(struct slab_alloc* alloc) {
    void* pos = alloc->pos;
    alloc->pos = (void *) (((unsigned long)alloc->pos) + alloc->slice_size);
    if (alloc->pos == alloc->current_slab->end) {
        alloc->current_slab = new_slab(alloc->slab_size);
        alloc->pos = alloc->current_slab->s;
        list_add(&alloc->current_slab->list, &alloc->list);
    } 
    return pos;
}
