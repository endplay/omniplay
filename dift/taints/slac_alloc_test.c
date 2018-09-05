#include "slab_alloc.h"
#include <stdio.h>

// The struct we want to slab allocate
struct a {
    int me;
    int me2;
};

int main(int argc, char** argv)
{
    struct a* a;
    // let's make a new slab allocator first
    struct slab_alloc alloc;
    int i = 0;

    new_slab_alloc(&alloc, sizeof(struct a));

    for (i = 0; i < 10000; i++) {
        a = get_slice(&alloc);
    }
}
