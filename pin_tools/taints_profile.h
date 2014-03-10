#ifndef TAINTS_PROFILE_H
#define TAINTS_PROFILE_H

// encode different taint transfers
#define STATS_TAINT_MEM2REG     0
#define STATS_TAINT_MEM2MEM     1
#define STATS_TAINT_MEM2FLAG    2
#define STATS_TAINT_FLAG2MEM    3
#define STATS_TAINT_REG2REG     4
#define STATS_TAINT_FLAG2REG    5
#define STATS_TAINT_REG2FLAG    6
#define STATS_TAINT_REG2FLAG_BUTCF 7
#define STATS_TAINT_REG2CF_OF   8
#define STATS_TAINT_REG2CF   9
#define STATS_TAINT_WHOLEMEM2REG 10
#define STATS_TAINT_WHOLEMEM2MEM 11
#define STATS_TAINT_ADD_REG2MEM 12
#define STATS_TAINT_ADD_MEM2REG 13
#define STATS_TAINT_ADD_REG2REG 14
#define STATS_TAINT_MEM_REG_MOV 15
#define STATS_TAINT_MEM2REG_MOV 16
#define STATS_TAINT_IMMVAL2MEM  17
#define STATS_TAINT_SIZE 18

// encode different taint operations
#define STATS_OP_MERGE 0
#define STATS_OP_UNIQUE_MERGE 1
#define STATS_OP_CLEAR 2
#define STATS_OP_SET 3
#define STATS_OP_UNIQUE_TAINTS 4
#define STATS_OP_SIZE 5

struct taints_profile {
    unsigned long stats_taint_count[STATS_TAINT_SIZE];
    unsigned long stats_op_count[STATS_OP_SIZE];
};

struct taints_profile* new_taints_profile(void) {
    struct taints_profile* tp;
    tp = (struct taints_profile *) malloc(sizeof(struct taints_profile));
    memset(tp, 0, sizeof(taints_profile));

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

void print_taint_profile_count_op(FILE* fp, struct taints_profile* profile)
{
    int i = 0;
    fprintf(fp, "Taint profile count operations: \n");
    for (i = 0; i < STATS_TAINT_SIZE; i++) {
        fprintf(fp, "%s: %lu\n", taint_count_op_to_string(i), profile->stats_taint_count[i]);
    }
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
        case STATS_TAINT_WHOLEMEM2REG:
            return "whole_mem2reg";
        case STATS_TAINT_WHOLEMEM2MEM:
            return "whole_mem2mem";
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
        case STATS_TAINT_IMMVAL2MEM:
            return "immval2mem";
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
