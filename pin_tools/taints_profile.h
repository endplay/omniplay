#ifndef TAINTS_PROFILE_H
#define TAINTS_PROFILE_H

#include <string.h>

// encode different taint transfers
#define STATS_TAINT_MEM2REG     0
#define STATS_TAINT_MEM2MEM     1
#define STATS_TAINT_MEM2FLAG    2
#define STATS_TAINT_FLAG2MEM    3
#define STATS_TAINT_REG2REG     4
#define STATS_TAINT_REG2MEM     5
#define STATS_TAINT_FLAG2REG    6
#define STATS_TAINT_REG2FLAG    7
#define STATS_TAINT_REG2FLAG_BUTCF 8
#define STATS_TAINT_REG2CF_OF   9
#define STATS_TAINT_REG2CF      10
#define STATS_TAINT_MEM2CF      11
#define STATS_TAINT_WHOLEMEM2REG 12
#define STATS_TAINT_WHOLEMEM2MEM 13
#define STATS_TAINT_WHOLEREG2MEM 14
#define STATS_TAINT_ADD_REG2MEM 15
#define STATS_TAINT_ADD_MEM2REG 16
#define STATS_TAINT_ADD_REG2REG 17
#define STATS_TAINT_MEM_REG_MOV 18
#define STATS_TAINT_MEM2REG_MOV 19
#define STATS_TAINT_REG_MEM_MOV 20
#define STATS_TAINT_2REGMEM_MOV 21
#define STATS_TAINT_IMMVAL2MEM  22
#define STATS_TAINT_IMMVAL2REG	23
#define STATS_TAINT_IMMVAL2FLAG	24
#define STATS_TAINT_SIZE 25

// encode different taint operations
#define STATS_OP_MERGE 0
#define STATS_OP_UNIQUE_MERGE 1
#define STATS_OP_CLEAR 2
#define STATS_OP_SET 3
#define STATS_OP_UNIQUE_TAINTS 4
#define STATS_OP_SIZE 5

// individual operations microstats
#define STATS_CLEAR 0
#define STATS_SET 1
#define STATS_GET 2

struct taints_profile {
    long stats_taint_count[STATS_TAINT_SIZE];
    long stats_op_count[STATS_OP_SIZE];
    long stats_mem2reg[2];
    long stats_reg2reg[2];
    long stats_reg2mem[2];
    long stats_add_mem2reg[2];
    long stats_add_reg2reg[2];
    long stats_add_reg2mem[2];

    /* Stats about the taint memory structure */
    long stats_memory[3];
};

struct taints_profile* new_taints_profile(void) {
    struct taints_profile* tp;
    tp = (struct taints_profile *) malloc(sizeof(struct taints_profile));
    memset(tp, 0, sizeof(struct taints_profile));

    return tp;
};

const char* taint_count_op_to_string(int op);
const char* taint_op_to_string(int op);

inline void increment_taint_count(struct taints_profile* profile, int taint_count_op)
{
    profile->stats_taint_count[taint_count_op] = profile->stats_taint_count[taint_count_op] + 1;
}

inline void increment_taint_op(struct taints_profile* profile, int taint_op)
{
    profile->stats_op_count[taint_op] = profile->stats_op_count[taint_op] + 1;
}

void copy_taints_profile(struct taints_profile* dst, struct taints_profile* src)
{
    memcpy(dst, src, sizeof(struct taints_profile));
}

void diff_taints_profile(struct taints_profile* profile1, struct taints_profile* profile2, struct taints_profile* result)
{
    int i = 0;
    for (i = 0; i < STATS_TAINT_SIZE; i++) {
        result->stats_taint_count[i] = profile1->stats_taint_count[i] - profile2->stats_taint_count[i];
    }
    for (i = 0; i < STATS_OP_SIZE; i++) {
        result->stats_op_count[i] = profile1->stats_op_count[i] - profile2->stats_op_count[i];
    }
    for (i = 0; i < 2; i++) {
        result->stats_mem2reg[i] = profile1->stats_mem2reg[i] - profile2->stats_mem2reg[i];
        result->stats_reg2reg[i] = profile1->stats_reg2reg[i] - profile2->stats_reg2reg[i];
        result->stats_reg2mem[i] = profile1->stats_reg2mem[i] - profile2->stats_reg2mem[i];
        result->stats_add_mem2reg[i] = profile1->stats_add_mem2reg[i] - profile2->stats_add_mem2reg[i];
        result->stats_add_reg2reg[i] = profile1->stats_add_reg2reg[i] - profile2->stats_add_reg2reg[i];
        result->stats_add_reg2mem[i] = profile1->stats_add_reg2mem[i] - profile2->stats_add_reg2mem[i];
    }
    for (i = 0; i < 3; i++) {
        result->stats_memory[i] = profile1->stats_memory[i] - profile2->stats_memory[i];
    }
}

void print_taint_profile_count_op(FILE* fp, struct taints_profile* profile)
{
    int i = 0;
    fprintf(fp, "Taint profile count operations: \n");
    for (i = 0; i < STATS_TAINT_SIZE; i++) {
        fprintf(fp, "%s: %lu\n", taint_count_op_to_string(i), profile->stats_taint_count[i]);
    }

    fprintf(fp, "memory sets: %ld\n", profile->stats_memory[STATS_SET]);
    fprintf(fp, "memory gets: %ld\n", profile->stats_memory[STATS_GET]);
    fprintf(fp, "memory clears: %ld\n", profile->stats_memory[STATS_CLEAR]);
}

void print_taint_profile_op(FILE* fp, struct taints_profile* profile)
{
    int i = 0;
    fprintf(fp, "Taint profile taint operations: \n");
    for (i = 0; i < STATS_OP_SIZE; i++) {
        fprintf(fp, "%s: %lu\n", taint_op_to_string(i), profile->stats_op_count[i]);
    }
}

void print_taint_profile(FILE* fp, struct taints_profile* profile)
{
    print_taint_profile_count_op(fp, profile);
    print_taint_profile_op(fp, profile);
}

const char* taint_count_op_to_string(int op)
{
    switch(op) {
        case STATS_TAINT_MEM2REG:
            return "mem2reg";
        case STATS_TAINT_MEM2MEM:
            return "mem2mem";
        case STATS_TAINT_MEM2FLAG:
            return "mem2flag";
        case STATS_TAINT_FLAG2MEM:
            return "flag2mem";
        case STATS_TAINT_REG2REG:
            return "reg2reg";
        case STATS_TAINT_REG2MEM:
            return "reg2mem";
        case STATS_TAINT_FLAG2REG:
            return "flag2reg";
        case STATS_TAINT_REG2FLAG:
            return "reg2flag";
        case STATS_TAINT_REG2FLAG_BUTCF:
            return "reg2flag_but_cf";
        case STATS_TAINT_REG2CF_OF:
            return "reg2cf_of";
        case STATS_TAINT_REG2CF:
            return "reg2cf";
        case STATS_TAINT_MEM2CF:
            return "mem2cf";
        case STATS_TAINT_WHOLEMEM2REG:
            return "whole_mem2reg";
        case STATS_TAINT_WHOLEMEM2MEM:
            return "whole_mem2mem";
        case STATS_TAINT_WHOLEREG2MEM:
            return "whole_reg2mem";
        case STATS_TAINT_ADD_REG2MEM:
            return "add_reg2mem";
        case STATS_TAINT_ADD_MEM2REG:
            return "add_mem2reg";
        case STATS_TAINT_ADD_REG2REG:
            return "add_reg2reg";
        case STATS_TAINT_MEM_REG_MOV:
            return "mem_reg_mov";
        case STATS_TAINT_MEM2REG_MOV:
            return "mem2reg_mov";
        case STATS_TAINT_REG_MEM_MOV:
            return "reg_mem_mov";
        case STATS_TAINT_2REGMEM_MOV:
            return "2reg_mem_mov";
        case STATS_TAINT_IMMVAL2MEM:
            return "immval2mem";
        case STATS_TAINT_IMMVAL2REG:
            return "immval2reg";
        case STATS_TAINT_IMMVAL2FLAG:
            return "immval2flag";
        default:
            return "UNKNOWN_OP";
    }
}

const char* taint_op_to_string(int op)
{
    switch(op) {
        case STATS_OP_MERGE:
            return "merge";
        case STATS_OP_UNIQUE_MERGE:
            return "unique merge";
        case STATS_OP_CLEAR:
            return "clear";
        case STATS_OP_SET:
            return "set";
        case STATS_OP_UNIQUE_TAINTS:
            return "unique taints";
        default:
            return "unknown";
    }
}

#endif // TAINTS_PROFILE_H
