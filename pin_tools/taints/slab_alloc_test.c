#include "slab_alloc.h"
#include <stdio.h>
#include <assert.h>

#define NUM_ALLOCS 10000

// The struct we want to slab allocate
struct a {
    int me;
    int me2;
};

int main(int argc, char** argv)
{
    struct a* a;
    struct a* my_a[NUM_ALLOCS];
    // let's make a new slab allocator first
    struct slab_alloc alloc;
    int i = 0;

    new_slab_alloc(&alloc, sizeof(struct a));

    for (i = 0; i < NUM_ALLOCS; i++) {
        a = get_slice(&alloc);
        a->me = i;
        a->me2 = -i;
        my_a[i] = a;
    }

    for (i = 0; i < NUM_ALLOCS; i++) {
        int t;
        a = my_a[i];
        t = a->me + a->me2;
        assert(t == 0);
    }

    printf("done\n");
}
