#include "../linkage_common.h"
#include "taint_interface.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

void print_reg(struct thread_data* ptdata, int reg)
{
    taint_t* reg_table = ptdata->shadow_reg_table;
    int i = 0;
    fprintf(stdout, "reg %d\n", reg);
    for (i = 0; i < REG_SIZE; i++) {
        fprintf(stdout, "%d: %lu\n", i, reg_table[reg * REG_SIZE + i]);
    }
}

void reset_regs(struct thread_data* ptdata)
{
    int i = 0;
    int j = 0;
    for (i = 0; i < NUM_REGS; i++) {
        clear_reg(ptdata, i, REG_SIZE);
    }
}

void test_qw(struct thread_data* ptdata)
{
    u_long start_addr = 0x890888c;
    taint_t start_t = 1;
    int i = 0;
    int size = 200 * 16;

    for (i = 0; i < size; i++) {
        taint_mem(start_addr + i, start_t + i);
    }

    taint_mem2qwreg(ptdata, start_addr, 50);
    print_reg(ptdata, 50);
    taint_mem2qwreg(ptdata, start_addr + 16, 51);
    taint_qwreg2mem(ptdata, start_addr, 51);
    taint_mem2qwreg(ptdata, start_addr, 50);
    print_reg(ptdata, 50);
}

void test_taint_mem2lbreg(struct thread_data* ptdata)
{
    u_long start_addr = 0x8908752;
    taint_t start_t = 15;

    taint_mem(start_addr, start_t);

    fprintf(stderr, "test_taint_mem2lbreg\n");
    clear_reg(ptdata, 50, REG_SIZE);
    taint_mem2lbreg(ptdata, start_addr, 50);
    print_reg(ptdata, 50);
    assert(ptdata->shadow_reg_table[50 * REG_SIZE] == 15);
}

void test_taint_lbreg2mem(struct thread_data* ptdata)
{
    u_long start_addr = 0x8908752;
    taint_t start_t = 15;
    taint_t* mem_taints;

    taint_mem(start_addr, start_t);

    fprintf(stderr, "test_taint_lbreg2mem\n");
    clear_reg(ptdata, 50, REG_SIZE);
    ptdata->shadow_reg_table[50 * REG_SIZE] = 16;
    taint_lbreg2mem(ptdata, start_addr, 50);
    print_reg(ptdata, 50);
    mem_taints = get_mem_taints(start_addr, 1);
    assert(mem_taints);
    fprintf(stderr, "%lu\n", mem_taints[0]);
    assert(mem_taints[0] == 16);
}

void test_taintx_wreg2qwreg(struct thread_data* ptdata)
{
    int correct = 1;
    int reg = 50;
    int reg2 = 8;
    int i = 0;
    // set the taint of a qw register
    taint_t* reg_table = ptdata->shadow_reg_table;

    clear_reg(ptdata, reg, REG_SIZE);
    clear_reg(ptdata, reg2, REG_SIZE);

    for (i = 0; i < REG_SIZE; i++) {
        reg_table[reg * REG_SIZE + i] = 2;
    } 
    for (i = 0; i < REG_SIZE; i++) {
        reg_table[reg2 * REG_SIZE + i] = 3;
    }
    print_reg(ptdata, reg);
    print_reg(ptdata, reg2);

    taintx_wreg2qwreg(ptdata, reg, reg2);

    print_reg(ptdata, reg);
    print_reg(ptdata, reg2);

    // correctness checks
    correct &= (reg_table[reg * REG_SIZE] == 3);
    correct &= (reg_table[reg * REG_SIZE + 1] == 3);
    correct &= (reg_table[reg * REG_SIZE + 2] == 3);
    correct &= (reg_table[reg * REG_SIZE + 3] == 3);
    for (i = 4; i < REG_SIZE; i++) {
        correct &= (reg_table[reg * REG_SIZE + i] == 0);
    }
    for (i = 0; i < REG_SIZE; i++) {
        correct &= (reg_table[reg2 * REG_SIZE + i] == 3);
    }
    assert(correct);
}

void test_taint_mem2ubreg(struct thread_data* ptdata)
{
    int i = 0;
    int reg = 8;
    u_long addr = 0xb7700000;
    taint_t* reg_table = ptdata->shadow_reg_table;

    clear_reg(ptdata, reg, REG_SIZE);
    taint_mem(addr, (taint_t) 5);
    taint_mem2ubreg(ptdata, addr, reg);
    print_reg(ptdata, reg);

    // correctness checks
    assert(reg_table[reg * REG_SIZE] == 0);
    assert(reg_table[reg * REG_SIZE + 1] == 5);
    for (i = 2; i < REG_SIZE; i++) {
        assert(reg_table[reg * REG_SIZE + i] == 0);
    }
}

void test_taint_palignr_mem2qwreg(struct thread_data* ptdata)
{
    u_long mem_loc = 0xb7700000;
    int reg1;
    int i = 0;
    taint_t* mem_taints;
    taint_t* reg_table = ptdata->shadow_reg_table;

    reg1 = 51;
    clear_reg(ptdata, reg1, REG_SIZE);

    // set the values in the reg and mem
    for (i = 0; i < REG_SIZE; i++) {
        reg_table[reg1 * REG_SIZE + i] = i;
    }
    print_reg(ptdata, reg1);

    for (i = 0; i < 16; i++) {
        taint_mem(mem_loc + i, i + 16);
        mem_taints = get_mem_taints(mem_loc + i, 1);
        fprintf(stderr, "%lx %lu\n", mem_loc + i, mem_taints[0]);
    }

    taint_palignr_mem2qwreg(ptdata, reg1, mem_loc, 7);
    print_reg(ptdata, reg1);
}


void test_taint_add_bmem2lbreg(struct thread_data* ptdata)
{
    // redefine these here (these are internal structures)
    struct taint_node {
        struct taint_node* parent1;
        struct taint_node* parent2;
    };
    struct taint_leafnode {
        struct taint_node node;
        option_t option;
    };

    struct taint_leafnode* ln;
    int reg1 = 8;
    u_long mem_loc = 0x8600000;
    taint_t* reg_table = ptdata->shadow_reg_table;

    clear_reg(ptdata, reg1, REG_SIZE);
    ln = (struct taint_leafnode *) malloc(sizeof(struct taint_leafnode));
    ln->node.parent1 = 0;
    ln->node.parent2 = 0;
    ln->option = 5;
    taint_mem(mem_loc, (taint_t) ln);

    ln = (struct taint_leafnode *) malloc(sizeof(struct taint_leafnode));
    ln->node.parent1 = 0;
    ln->node.parent2 = 0;
    ln->option = 6;

    reg_table[reg1 * REG_SIZE] = (taint_t) ln;

    taint_add_bmem2lbreg(ptdata, mem_loc, reg1);
    fprintf(stdout, "{");
    print_options(stdout, reg_table[reg1 * REG_SIZE]);
    fprintf(stdout, "}\n");
    // should be 5 and 6
}

void test_taint_add_bmem2hwreg(struct thread_data* ptdata)
{
    // redefine these here (these are internal structures)
    struct taint_node {
        struct taint_node* parent1;
        struct taint_node* parent2;
    };
    struct taint_leafnode {
        struct taint_node node;
        option_t option;
    };

    struct taint_leafnode* ln;
    int reg1 = 8;
    u_long mem_loc = 0x8600000;
    taint_t* reg_table = ptdata->shadow_reg_table;

    clear_reg(ptdata, reg1, REG_SIZE);
    ln = (struct taint_leafnode *) malloc(sizeof(struct taint_leafnode));
    ln->node.parent1 = 0;
    ln->node.parent2 = 0;
    ln->option = 5;
    taint_mem(mem_loc, (taint_t) ln);

    ln = (struct taint_leafnode *) malloc(sizeof(struct taint_leafnode));
    ln->node.parent1 = 0;
    ln->node.parent2 = 0;
    ln->option = 6;

    reg_table[reg1 * REG_SIZE] = (taint_t) ln;

    taint_add_bmem2hwreg(ptdata, mem_loc, reg1);
    fprintf(stdout, "test taint_add_bmem2hwreg\n");
    fprintf(stdout, "{");
    print_options(stdout, reg_table[reg1 * REG_SIZE]);
    fprintf(stdout, "}\n");
    // should be 5 and 6
}


void test_taint_add_bmem2wreg(struct thread_data* ptdata)
{
    // redefine these here (these are internal structures)
    struct taint_node {
        struct taint_node* parent1;
        struct taint_node* parent2;
    };
    struct taint_leafnode {
        struct taint_node node;
        option_t option;
    };

    struct taint_leafnode* ln;
    int reg1 = 8;
    u_long mem_loc = 0x8600000;
    taint_t* reg_table = ptdata->shadow_reg_table;

    clear_reg(ptdata, reg1, REG_SIZE);
    ln = (struct taint_leafnode *) malloc(sizeof(struct taint_leafnode));
    ln->node.parent1 = 0;
    ln->node.parent2 = 0;
    ln->option = 5;
    taint_mem(mem_loc, (taint_t) ln);

    ln = (struct taint_leafnode *) malloc(sizeof(struct taint_leafnode));
    ln->node.parent1 = 0;
    ln->node.parent2 = 0;
    ln->option = 6;

    reg_table[reg1 * REG_SIZE] = (taint_t) ln;

    taint_add_bmem2wreg(ptdata, mem_loc, reg1);
    fprintf(stdout, "test taint_add_bmem2wreg\n");
    fprintf(stdout, "{");
    print_options(stdout, reg_table[reg1 * REG_SIZE]);
    fprintf(stdout, "}\n");
    // should be 5 and 6
}


void test_taint_add_wmem2wreg(struct thread_data* ptdata)
{
    int i = 0;
    // redefine these here (these are internal structures)
    struct taint_node {
        struct taint_node* parent1;
        struct taint_node* parent2;
    };
    struct taint_leafnode {
        struct taint_node node;
        option_t option;
    };

    struct taint_leafnode* ln;
    int reg1 = 8;
    u_long mem_loc = 0x8700000;
    taint_t* reg_table = ptdata->shadow_reg_table;

    clear_reg(ptdata, reg1, REG_SIZE);
    for (i = 0; i < 4; i++) { 
        ln = (struct taint_leafnode *) malloc(sizeof(struct taint_leafnode));
        ln->node.parent1 = 0;
        ln->node.parent2 = 0;
        ln->option = 5 + i;
        taint_mem(mem_loc + i, (taint_t) ln);
    }

    for (i = 0; i < 4; i++) { 

        ln = (struct taint_leafnode *) malloc(sizeof(struct taint_leafnode));
        ln->node.parent1 = 0;
        ln->node.parent2 = 0;
        ln->option = 12 + i;

        reg_table[reg1 * REG_SIZE + i] = (taint_t) ln;
    }

    taint_add_wmem2wreg(ptdata, mem_loc, reg1);
    for (i = 0; i < 4; i++) { 
        fprintf(stdout, "%d {", i);
        print_options(stdout, reg_table[reg1 * REG_SIZE + i]);
        fprintf(stdout, "}\n");
    }
    // should be 5 and 6
}

void test_taint_add_lbreg2mem(struct thread_data* ptdata)
{
    taint_t* mem_taints;
    // redefine these here (these are internal structures)
    struct taint_node {
        struct taint_node* parent1;
        struct taint_node* parent2;
    };
    struct taint_leafnode {
        struct taint_node node;
        option_t option;
    };

    struct taint_leafnode* ln;
    int reg1 = 8;
    u_long mem_loc = 0x8600000;
    taint_t* reg_table = ptdata->shadow_reg_table;

    clear_reg(ptdata, reg1, REG_SIZE);
    ln = (struct taint_leafnode *) malloc(sizeof(struct taint_leafnode));
    ln->node.parent1 = 0;
    ln->node.parent2 = 0;
    ln->option = 5;
    taint_mem(mem_loc, (taint_t) ln);

    ln = (struct taint_leafnode *) malloc(sizeof(struct taint_leafnode));
    ln->node.parent1 = 0;
    ln->node.parent2 = 0;
    ln->option = 6;

    reg_table[reg1 * REG_SIZE] = (taint_t) ln;

    taint_add_lbreg2mem(ptdata, mem_loc, reg1);
    fprintf(stdout, "test taint_add_lbreg2mem\n");
    fprintf(stdout, "{");
    print_options(stdout, reg_table[reg1 * REG_SIZE]);
    fprintf(stdout, "}\n");
    // should be 5 and 6

    mem_taints = get_mem_taints(mem_loc, 1);
    assert(mem_taints);
    print_options(stdout, mem_taints[0]);
    fprintf(stdout, "\n");
}


void test_taint_palignr_qwreg2qwreg(struct thread_data* ptdata)
{
    int reg1, reg2;
    int i = 0;
    taint_t* reg_table = ptdata->shadow_reg_table;

    reg1 = 51;
    reg2 = 52;
    clear_reg(ptdata, reg1, REG_SIZE);
    clear_reg(ptdata, reg2, REG_SIZE);

    // set the values in the reg
    for (i = 0; i < REG_SIZE; i++) {
        reg_table[reg1 * REG_SIZE + i] = i;
    }
    for (i = 0; i < REG_SIZE; i++) {
        reg_table[reg2 * REG_SIZE + i] = i + 16;
    }
    print_reg(ptdata, reg1);
    print_reg(ptdata, reg2);

    taint_palignr_qwreg2qwreg(ptdata, reg1, reg2, 7);
    print_reg(ptdata, reg1);
}

int main(int argc, char** argv)
{
    uint32_t s;
    uint32_t count = 0;
    uint32_t offset = 0;
    u_long mem_offset;
    struct thread_data ptdata;

    taint_t* tp = NULL;
    u_long m;
    u_long mem_loc;

    init_taint_structures();
    memset(&ptdata, 0, sizeof(struct thread_data));
    taint_mem(0x800000, (taint_t) 1234);

    s = get_cmem_taints(0x800000, 2, &tp);
    fprintf(stderr, "%lu\n", tp[0]);
    fprintf(stderr, "%lu\n", tp[1]);

    mem_loc = 0xb772159e;
    mem_offset = mem_loc;
    taint_mem(0xb772159e, (taint_t) 5);
    taint_mem(0xb772159f, (taint_t) 6);
    taint_mem(0xb77215a0, (taint_t) 7);
    taint_mem(0xb77215a1, (taint_t) 8);

    while (offset < 4) {
        taint_t* mem_taints = NULL;
        uint32_t count = 0;
        count = get_cmem_taints(mem_offset, 4 - offset, &mem_taints);
        fprintf(stderr, "count is %d\n", count);
        fprintf(stderr, "offset is %d\n", offset);

        offset += count;
        mem_offset += count;

        fprintf(stderr, "mem_taints %p\n", mem_taints);
        if (!mem_taints) {
            break;
        }
        fprintf(stderr, "%lu\n", mem_taints[0]);
        fprintf(stderr, "%lu\n", mem_taints[1]);
    }

    test_qw(&ptdata);
    test_taint_lbreg2mem(&ptdata);
    test_taintx_wreg2qwreg(&ptdata);
    test_taint_mem2ubreg(&ptdata);
    test_taint_palignr_qwreg2qwreg(&ptdata);
    test_taint_palignr_mem2qwreg(&ptdata);
    test_taint_add_bmem2lbreg(&ptdata);
    test_taint_add_bmem2hwreg(&ptdata);
    test_taint_add_bmem2wreg(&ptdata);
    test_taint_add_wmem2wreg(&ptdata);
    test_taint_add_lbreg2mem(&ptdata);
}
