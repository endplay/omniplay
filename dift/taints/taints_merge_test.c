#include "taints_graph.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define NUM_TAINTS 500000
#define NUM_ITERS 10000000

void create_taints(int num, struct taint* taints)
{
    int i = 0;
    srand(1);
    // assumes taints is allocated already
    for (i = 0; i < num; i++) {
        struct taint* t;
        t = &taints[i];
        new_taint(t);
        set_taint_value(t, rand(), 1);
    }
}

int main(int argc, char** argv)
{
    int i = 0;
    struct taint* mytaints;
    struct timeval start;
    struct timeval end;
    struct timeval result;

    // create an array of a bunch of pointers to taints
    mytaints = (struct taint *) malloc(sizeof(struct taint) * NUM_TAINTS);
    assert(mytaints);

    fprintf(stdout, "Starting merge taints test\n");
    
    INIT_TAINT_INDEX();

    gettimeofday(&start, NULL);
    create_taints(NUM_TAINTS, mytaints);
    gettimeofday(&end, NULL);
    timersub(&end, &start, &result);
    fprintf(stdout, "create taints took %ld secs, %ld usecs\n", result.tv_sec, result.tv_usec);

    gettimeofday(&start, NULL);
    for (i = 0; i < NUM_ITERS; i++) {
        // randomly pick two taints and merge them
        int taint_idx1 = rand() % NUM_TAINTS;
        int taint_idx2 = rand() % NUM_TAINTS;

        merge_taints(&mytaints[taint_idx1], &mytaints[taint_idx2]);
    }
    gettimeofday(&end, NULL);

    timersub(&end, &start, &result);
    fprintf(stdout, "merging took %ld secs, %ld usecs\n", result.tv_sec, result.tv_usec);
    print_taint_profile_op(stdout, &merge_profile);

    return 0;
}

