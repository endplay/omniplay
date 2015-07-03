#include "../linkage_common.h"
#include "taint_interface.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

void reset_regs(struct thread_data* ptdata)
{
    int i = 0;
    int j = 0;
    for (i = 0; i < NUM_REGS; i++) {
        ptdata->shadow_reg_table[i] = 0;
    }
}

void reset_mem(void)
{
    taint_t* t = get_mem_taints(0, 1);
    memset(t, 0, 402653184);
}

void print_reg(struct thread_data* ptdata, int reg)
{
    uint16_t t;
    t = (uint16_t) ptdata->shadow_reg_table[reg];
    fprintf(stdout, "%#x\n", t);
}

static uint16_t get_reg_taint(struct thread_data* ptdata, int reg)
{
    uint16_t t;
    t = (uint16_t) ptdata->shadow_reg_table[reg];
    return t;
}

uint16_t get_mem_taint(u_long mem_loc)
{
    /*
    uint16_t* t;
    t = (uint16_t *) get_mem_taints(mem_loc, 4);
    return *t;
    */
    uint32_t* qw_mem;
    int offset = (mem_loc % 8);
    qw_mem = (uint32_t *) get_mem_taints(mem_loc, 4);
    return (*qw_mem) >> offset;
}

uint8_t get_mem_taint8(u_long mem_loc)
{
    uint8_t* t;
    t = (uint8_t *) get_mem_taints(mem_loc, 4);
    return *t;
}


void test_clear_reg (struct thread_data* ptdata)
{
    int reg1 = 7;
    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg1] = UINT16_MAX;

    print_reg(ptdata, reg1);
    clear_reg(ptdata, reg1, 3);
    print_reg(ptdata, reg1);
    clear_reg(ptdata, reg1, 7);
    print_reg(ptdata, reg1);
}

void test_taint_wreg2wreg (struct thread_data* ptdata)
{
    int reg1 = 6;
    int reg2 = 10;

    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg2] = UINT16_MAX;

    taint_wreg2wreg(ptdata, reg1, reg2);
    print_reg(ptdata, reg1);
    assert(ptdata->shadow_reg_table[reg1] = 0xf);
    assert(ptdata->shadow_reg_table[reg2] = UINT16_MAX);
}

void test_taint_mem2lbreg (struct thread_data* ptdata)
{
    int reg1 = 8;
    reset_regs(ptdata);
    taint_mem(0x800000, (taint_t) 1234);

    taint_mem2lbreg(ptdata, 0x800000, reg1);
    print_reg(ptdata, reg1);

    assert(ptdata->shadow_reg_table[reg1] = 0x1);
}

void test_taint_mem2ubreg (struct thread_data* ptdata)
{
    int reg1 = 8;
    reset_regs(ptdata);
    taint_mem(0x800000, (taint_t) 1234);

    taint_mem2ubreg(ptdata, 0x800000, reg1);
    print_reg(ptdata, reg1);

    assert(ptdata->shadow_reg_table[reg1] = 0x2);
}

void test_taint_mem2wreg (struct thread_data* ptdata)
{
    int reg1 = 8;
    reset_regs(ptdata);
    taint_mem(0x800000, (taint_t) 1234);
    taint_mem(0x800001, (taint_t) 1234);
    taint_mem(0x800002, (taint_t) 1234);
    taint_mem(0x800003, (taint_t) 1234);

    taint_mem2wreg(ptdata, 0x800000, reg1);
    print_reg(ptdata, reg1);

    assert(ptdata->shadow_reg_table[reg1] = 0xf);
}

void test_taint_mem2qwreg (struct thread_data* ptdata)
{
    int i = 0;
    u_long mem_loc = 0x800006;
    int reg1 = 8;
    reset_regs(ptdata);

    fprintf(stderr, "test_taint_mem2qwreg\n");
    for (i = 0; i < 16; i++) {
        taint_mem(mem_loc + i, (taint_t) 1);
    }

    taint_mem2qwreg(ptdata, mem_loc, reg1);
    print_reg(ptdata, reg1);
    assert(ptdata->shadow_reg_table[reg1] == 0xffff);
}

void test_taint_palignr_mem2dwreg (struct thread_data* ptdata)
{
    int i;
    uint16_t taint;
    int reg = 50;
    u_long mem_loc = 0x900000;
    reset_regs(ptdata);
    fprintf(stderr, "test_palignr_mem2dwreg\n");
    for (i = 0; i < 8; i++) {
        taint_mem(mem_loc + i, (taint_t) 1);
    }

    taint_palignr_mem2dwreg(ptdata, reg, mem_loc, 3);
    print_reg(ptdata, reg);
    taint = get_reg_taint(ptdata, reg);
    assert(taint == 0x1f);
}

void test_taint_palignr_mem2qwreg (struct thread_data* ptdata)
{
    int i;
    int reg = 50;
    u_long mem_loc = 0x900000;
    reset_regs(ptdata);
    fprintf(stderr, "test_palignr_mem2qwreg\n");
    for (i = 0; i < 16; i++) {
        taint_mem(mem_loc + i, (taint_t) 1);
    }

    taint_palignr_mem2qwreg(ptdata, reg, mem_loc, 3);
    print_reg(ptdata, reg);
}

void test_taint_mem2mem (struct thread_data* ptdata)
{
    int i = 0;
    u_long src_mem_loc = 0x900040;
    u_long dst_mem_loc = 0x900100;
    uint16_t t;

    fprintf(stderr, "test_taint_mem2mem\n");
    for (i = 0; i < 100; i++) {
        taint_mem(src_mem_loc + i, (taint_t) 1);
    }

    taint_mem2mem(ptdata, src_mem_loc, dst_mem_loc, 100);
    for (i = 0; i < 96; i += 4) {
        t = get_mem_taint8(dst_mem_loc + i);
        assert(t == 0xff);
    }
    t = get_mem_taint8(dst_mem_loc + 96);
    assert(t == 0xf);
}

void test_taint_wreg2mem (struct thread_data* ptdata)
{
    uint16_t t;
    int reg = 7;
    int reg2 = 10;
    u_long mem_loc = 0x94121e3;
    u_long mem_loc2 = 0x94121e4;
    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg] = UINT16_MAX;
    ptdata->shadow_reg_table[reg2] = 0x7;

    fprintf(stderr, "test_taint_wreg2mem\n");
    taint_wreg2mem(ptdata, mem_loc, reg);
    t = get_mem_taint(mem_loc);
    fprintf(stderr, "%lu: %x\n", mem_loc, t);
    t = get_mem_taint(mem_loc - 1);
    fprintf(stderr, "%lu: %x\n", mem_loc - 1, t);
    taint_wreg2mem(ptdata, mem_loc2, reg2);
    t = get_mem_taint(mem_loc2);
    fprintf(stderr, "%lu: %x\n", mem_loc2, t);
    t = get_mem_taint(mem_loc - 1);
    fprintf(stderr, "%lu: %x\n", mem_loc - 1, t);
    taint_wreg2mem(ptdata, mem_loc2, reg2);
}

void test_taint_dwreg2mem (struct thread_data* ptdata)
{
    uint16_t t;
    int reg = 50;
    u_long dst_mem_loc = 0x900800;
    u_long dst_mem_loc2 = 0x300302;
    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg] = UINT16_MAX;

    fprintf(stderr, "test_taint_dwreg2mem\n");
    taint_dwreg2mem(ptdata, dst_mem_loc, reg);
    t = get_mem_taint(dst_mem_loc);
    fprintf(stderr, "%x\n", t);
    assert(t == 0xff);
    taint_dwreg2mem(ptdata, dst_mem_loc2, reg);
    t = get_mem_taint(dst_mem_loc2);
    fprintf(stderr, "%x\n", t);
    assert(t == 0xff);
}


void test_taint_qwreg2mem (struct thread_data* ptdata)
{
    uint16_t t;
    int reg = 50;
    u_long dst_mem_loc = 0x900200;
    u_long dst_mem_loc2 = 0x900302;
    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg] = UINT16_MAX;

    fprintf(stderr, "test_taint_qwreg2mem\n");
    taint_qwreg2mem(ptdata, dst_mem_loc, reg);
    t = get_mem_taint(dst_mem_loc);
    fprintf(stderr, "%x\n", t);
    assert(t == 0xffff);
    taint_qwreg2mem(ptdata, dst_mem_loc2, reg);
    t = get_mem_taint(dst_mem_loc2);
    fprintf(stderr, "%x\n", t);
    assert(t == 0xffff);
}

void test_taintx_lbreg2wreg (struct thread_data* ptdata)
{
    int reg1 = 50;
    int reg2 = 8;
    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg2] = UINT16_MAX;

    fprintf(stderr, "test_taintx_lbreg2wreg\n");
    taintx_lbreg2wreg(ptdata, reg1, reg2);
    // print_reg(ptdata, reg1);
    assert(get_reg_taint(ptdata, reg1) == 0x1);

    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg1] = UINT16_MAX;
    taintx_lbreg2wreg(ptdata, reg1, reg2);
    // print_reg(ptdata, reg1);
    assert(get_reg_taint(ptdata, reg1) == 0xfff0);

    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg1] = UINT16_MAX;
    ptdata->shadow_reg_table[reg2] = UINT16_MAX;
    taintx_lbreg2wreg(ptdata, reg1, reg2);
    // print_reg(ptdata, reg1);
    assert(get_reg_taint(ptdata, reg1) == 0xfff1);
}

void test_taintx_hwreg2qwreg (struct thread_data* ptdata)
{
    int reg1 = 50;
    int reg2 = 8;
    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg2] = UINT16_MAX;

    fprintf(stderr, "test_taintx_hwreg2qwreg\n");
    taintx_hwreg2qwreg(ptdata, reg1, reg2);
    print_reg(ptdata, reg1);
    assert(get_reg_taint(ptdata, reg1) == 0x3);
}


void test_taintx_wreg2qwreg (struct thread_data* ptdata)
{
    int reg1 = 50;
    int reg2 = 8;
    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg2] = UINT16_MAX;

    fprintf(stderr, "test_taintx_wreg2qwreg\n");
    taintx_wreg2qwreg(ptdata, reg1, reg2);
    print_reg(ptdata, reg1);
    assert(get_reg_taint(ptdata, reg1) == 0xf);
}

void test_taintx_dwreg2qwreg (struct thread_data* ptdata)
{
    int reg1 = 50;
    int reg2 = 8;
    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg2] = UINT16_MAX;

    fprintf(stderr, "test_taintx_dwreg2qwreg\n");
    taintx_dwreg2qwreg(ptdata, reg1, reg2);
    print_reg(ptdata, reg1);
    assert(get_reg_taint(ptdata, reg1) == 0xff);
}

void test_taintx_bmem2wreg (struct thread_data* ptdata) 
{
    int reg = 5;
    u_long src_mem_loc = 0x400090;

    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg] = UINT16_MAX;

    fprintf(stderr, "test_taintx_bmem2wreg\n");
    taintx_bmem2wreg (ptdata, src_mem_loc, reg);

    assert(get_reg_taint(ptdata, reg) == 0xfff0);

    taint_mem(src_mem_loc, (taint_t) 1);
    taintx_bmem2wreg (ptdata, src_mem_loc, reg);
    assert(get_reg_taint(ptdata, reg) == 0xfff1);
}

void test_taintx_hwmem2wreg (struct thread_data* ptdata) 
{
    int reg = 5;
    u_long src_mem_loc = 0x500090;

    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg] = UINT16_MAX;

    fprintf(stderr, "test_taintx_hwmem2wreg\n");
    taintx_hwmem2wreg (ptdata, src_mem_loc, reg);

    print_reg(ptdata, reg);
    assert(get_reg_taint(ptdata, reg) == 0xfff0);

    taint_mem(src_mem_loc, (taint_t) 1);
    taint_mem(src_mem_loc + 1, (taint_t) 1);
    taintx_hwmem2wreg (ptdata, src_mem_loc, reg);
    print_reg(ptdata, reg);
    assert(get_reg_taint(ptdata, reg) == 0xfff3);
}

void test_taint_rep_hwreg2mem (struct thread_data* ptdata)
{
    int i = 0;
    int reg = 6;
    u_long mem_loc = 0x700090;
    int count = 14;

    reset_regs(ptdata);
    ptdata->shadow_reg_table[reg] = UINT16_MAX;

    fprintf(stderr, "test_taint_rep_hwreg2mem\n");
    taint_rep_hwreg2mem(ptdata, mem_loc, reg, count);
    for (i = 0; i < (count * 2); i+=16) {
        uint16_t t;
        t = get_mem_taint(mem_loc + i);
        fprintf(stderr, "%lu: %x\n", mem_loc + i, t);
    }
}

void test_taint_rep_wreg2mem (struct thread_data* ptdata)
{
    int i = 0;
    int reg = 6;
    u_long mem_loc = 0x700090;
    int count = 14;

    reset_regs(ptdata);
    reset_mem();
    ptdata->shadow_reg_table[reg] = UINT16_MAX;

    fprintf(stderr, "test_taint_rep_wreg2mem\n");
    taint_rep_wreg2mem(ptdata, mem_loc, reg, count);
    for (i = 0; i < (count * 4); i+=16) {
        uint16_t t;
        t = get_mem_taint(mem_loc + i);
        fprintf(stderr, "%lu: %x\n", mem_loc + i, t);
    }
}


int main(int argc, char** argv)
{
    uint16_t t;
    struct thread_data ptdata;
    init_taint_structures("/tmp/blah");
    memset(&ptdata, 0, sizeof(struct thread_data));

    taint_mem(0x800000, (taint_t) 1234);
    fprintf(stderr, "%x\n", get_mem_taint(0x800000));
    t = get_mem_taint(0x800000);
    assert(t = 0x1);
    taint_mem(0x800001, (taint_t) 1234);
    t = get_mem_taint(0x800000);
    assert(t = 0x3);
    taint_mem(0x800002, (taint_t) 1234);
    t = get_mem_taint(0x800000);
    assert(t = 0x7);
    taint_mem(0x800003, (taint_t) 1234);
    taint_mem(0x800004, (taint_t) 1234);
    taint_mem(0x800005, (taint_t) 1234);
    taint_mem(0x800006, (taint_t) 1234);
    taint_mem(0x800007, (taint_t) 1234);
    taint_mem(0x800008, (taint_t) 1234);
    taint_mem(0x800009, (taint_t) 1234);
    taint_mem(0x80000a, (taint_t) 1234);
    taint_mem(0x80000b, (taint_t) 1234);
    taint_mem(0x80000c, (taint_t) 1234);
    fprintf(stderr, "%x\n", get_mem_taint(0x800000));

    test_taint_wreg2wreg(&ptdata);
    test_taint_mem2lbreg(&ptdata);
    test_taint_mem2ubreg(&ptdata);
    test_taint_mem2wreg(&ptdata);
    test_taint_mem2qwreg(&ptdata);
    test_clear_reg(&ptdata);
    test_taint_palignr_mem2dwreg(&ptdata);
    test_taint_palignr_mem2qwreg(&ptdata);
    test_taint_mem2mem(&ptdata);
    test_taint_wreg2mem(&ptdata);
    test_taint_dwreg2mem(&ptdata);
    test_taint_qwreg2mem(&ptdata);
    test_taintx_hwreg2qwreg(&ptdata);
    test_taintx_wreg2qwreg(&ptdata);
    test_taintx_dwreg2qwreg(&ptdata);
    test_taintx_bmem2wreg(&ptdata);
    test_taintx_hwmem2wreg(&ptdata);
    test_taintx_lbreg2wreg(&ptdata);
    test_taint_rep_hwreg2mem(&ptdata);
    test_taint_rep_wreg2mem(&ptdata);
}
