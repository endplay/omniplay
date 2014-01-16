#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/time.h>
#include "taints.h"

#define NUM_REGS 10000

int main(int argc, char** argv)
{
    int i = 0;
    unsigned long long iters;
    struct timeval tv_start;
    struct timeval tv_end;
    unsigned long long start;
    unsigned long long end;

    // simulate a 1000 register machine
    struct taint* regs[NUM_REGS];

    fprintf(stdout, "Starting taints test\n");
#ifdef TAINTS_HASH
    fprintf(stdout, "Using a hash table for taints\n");
#else
    fprintf(stdout, "Using an array\n");
#endif
    // seed
    srand(time(NULL));
    fprintf(stdout, "%d\n", rand() % NUM_OPTIONS);
    fprintf(stdout, "%d\n", rand() % NUM_OPTIONS);
    fprintf(stdout, "%d\n", rand() % NUM_OPTIONS);
    fprintf(stdout, "%d\n", rand() % NUM_OPTIONS);
    fprintf(stdout, "%d\n", rand() % NUM_OPTIONS);
    fprintf(stdout, "%d\n", rand() % NUM_OPTIONS);
    fprintf(stdout, "%d\n", rand() % NUM_OPTIONS);
    fprintf(stdout, "confidence levels %d\n", CONFIDENCE_LEVELS);
    fprintf(stdout, "%d\n", rand() % CONFIDENCE_LEVELS);
    fprintf(stdout, "%d\n", rand() % CONFIDENCE_LEVELS);
    fprintf(stdout, "%d\n", rand() % CONFIDENCE_LEVELS);
    fprintf(stdout, "%d\n", rand() % CONFIDENCE_LEVELS);
    fprintf(stdout, "%d\n", rand() % CONFIDENCE_LEVELS);
    fprintf(stdout, "%d\n", rand() % CONFIDENCE_LEVELS);

    // create all of the empty taints
    gettimeofday(&tv_start, NULL);
    for (i = 0; i < NUM_REGS; i++) {
        regs[i] = new_ptaint();
    }
    gettimeofday(&tv_end, NULL);
    start = tv_start.tv_sec * 100000 + tv_start.tv_usec;
    end = tv_end.tv_sec * 100000 + tv_end.tv_usec;
    fprintf(stdout, "Creation time: %llu microseconds\n", end - start);

    // random test
    for (iters = 0; iters < 100000000; iters++) {
        int reg;
        int option;
        int confidence;
        reg = rand() % NUM_REGS;
        option = rand() % NUM_OPTIONS;
        confidence = rand() % CONFIDENCE_LEVELS;
        set_taint_value(regs[reg], option, confidence);
    }

    fprintf(stdout, "check for zero\n");
    for (i = 0; i < NUM_REGS; i++) {
        is_taint_zero(regs[i]);
    }
    fprintf(stdout, "check for zero done\n");

    fprintf(stdout, "Starting merge test\n");
    gettimeofday(&tv_start, NULL);
    for (i = 0; i < NUM_REGS; i+=2) {
        merge_taints(regs[i], regs[i+1]);
    }
    gettimeofday(&tv_end, NULL);
    start = tv_start.tv_sec * 100000 + tv_start.tv_usec;
    end = tv_end.tv_sec * 100000 + tv_end.tv_usec;
    fprintf(stdout, "Merge test took: %llu microseconds\n", end - start);

    // free all of the taints
    gettimeofday(&tv_start, NULL);
    for (i = 0; i < NUM_REGS; i++) {
        destroy_taint(regs[i]);
    }
    gettimeofday(&tv_end, NULL);
    start = tv_start.tv_sec * 100000 + tv_start.tv_usec;
    end = tv_end.tv_sec * 100000 + tv_end.tv_usec;
    fprintf(stdout, "Deletion time: %llu microseconds\n", end - start);
}
