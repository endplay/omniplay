#include "../linkage_common.h"
#include "taint_interface.h"

#include <stdint.h>
#include <string.h>
#include <assert.h>

extern struct thread_data* current_thread;

uint8_t* shadow_memory = NULL;

// #define LOGGING_ON
#ifdef LOGGING_ON
#define TAINT_START(name) \
    fprintf(stderr, "%s start\n", name);
#else
#define TAINT_START(x,...);
#endif

// masks for registers
#define LB_MASK     0x1
#define UB_MASK     0x2
#define HW_MASK     0x3
#define W_MASK      0xf
#define DW_MASK     0xff
#define QW_MASK     0xffff

int translate_reg(int reg)
{
    if (reg == 25 || reg == 26 || reg == 27) {
        return 8;
    } else if (reg == 22 || reg == 23 || reg == 24) {
        return 9;
    } else if (reg == 28 || reg == 29 || reg == 30) {
        return 7;
    } else if (reg == 19 || reg == 20 || reg == 21) {
        return 10;
    }
    return reg;
}

void init_taint_structures (char* group_dir)
{
    if (!shadow_memory) {
        shadow_memory = (uint8_t *) malloc(402653184);
        memset(shadow_memory, 0, 402653184);
    }
    assert(shadow_memory);
}

void print_taint_stats(FILE* fp)
{
    /*
    fprintf(fp, "Taint statistics:\n");
    fprintf(fp, "Second tables allocated: %lu\n", tsp.num_second_tables);
    fprintf(fp, "Third tables allocated: %lu\n", tsp.num_third_tables);
    fprintf(fp, "Num taint options: %lu\n", tsp.options);
    fprintf(fp, "Num merges: %lu\n", tsp.merges);
    fflush(fp);
    */
}

taint_t* get_reg_taints(int reg)
{
    return &(current_thread->shadow_reg_table[reg]);
}

void clear_reg (int reg, int size)
{
    uint16_t bitfield = (0x1 << size) - 1;
    current_thread->shadow_reg_table[reg] &= ~bitfield;
}

// clears the register using the inverse of the provided mask
static inline void clear_reg_mask(int reg, uint16_t mask)
{
    current_thread->shadow_reg_table[reg] &= ~mask;
}

static inline void set_reg_taint(int reg, uint16_t reg_taint)
{
    current_thread->shadow_reg_table[reg] = reg_taint;
}

static inline uint16_t get_reg_taint(int reg)
{
    return (uint16_t) current_thread->shadow_reg_table[reg];
}

static inline void merge_reg_taint(int reg, uint16_t reg_taint)
{
    current_thread->shadow_reg_table[reg] |= reg_taint;
}

static inline void clear_mem_mask(u_long mem_loc, uint16_t mask)
{
    uint32_t* qw_mem;
    int idx = mem_loc >> 3;
    int offset = (mem_loc % 8);
    qw_mem = (uint32_t *) &(shadow_memory[idx]);
    assert(qw_mem);
    *qw_mem &= ~(mask << offset);
}

static inline void set_mem_taint(u_long mem_loc, uint16_t taint)
{
    uint32_t* qw_mem;
    int idx = mem_loc >> 3;
    int offset = (mem_loc % 8);
    qw_mem = (uint32_t *) &(shadow_memory[idx]);
    *qw_mem &= (taint << offset);
}

static inline void merge_mem_taint(u_long mem_loc, uint16_t taint)
{
    uint32_t* qw_mem;
    int idx = mem_loc >> 3;
    int offset = (mem_loc % 8);
    qw_mem = (uint32_t *) &shadow_memory[idx];
    *qw_mem |= (taint << offset);
}

static inline uint16_t get_mem_taint(u_long mem_loc)
{
    uint32_t* qw_mem;
    int idx = mem_loc >> 3;
    int offset = (mem_loc % 8);
    qw_mem = (uint32_t *) &(shadow_memory[idx]);
    return (*qw_mem) >> offset;
}

taint_t* get_mem_taints(u_long mem_loc, uint32_t size)
{
    int idx;
    idx = mem_loc >> 3;

    return (taint_t *) &shadow_memory[idx];
}

void clear_mem_taints(u_long mem_loc, uint32_t size)
{
    u_long tmp = mem_loc;
    uint32_t nsize = size;
    while(1) {
        if (nsize < 16) {
            uint16_t mask = (0x1 << size) - 1;
            clear_mem_mask(tmp, mask);
            break;
        }
        clear_mem_mask(tmp, QW_MASK);
        tmp += 16;
        nsize -= 16;
    }
}

void taint_mem(u_long mem_loc, taint_t t)
{
    uint16_t bitfield;
    uint16_t* qw_mem;
    int idx = mem_loc >> 3;
    bitfield = 0x1 << (mem_loc - (idx << 3));

    qw_mem = (uint16_t *) &shadow_memory[idx];
    *qw_mem |= bitfield;
}

void shift_reg_taint_right(int reg, int shift)
{
    assert(shift > 0);
    if (shift > 15) {
        clear_reg(reg, REG_SIZE);
    } else {
        uint16_t t;
        t = get_reg_taint(reg);
        t = t >> shift;
        set_reg_taint(reg, t);
    }
}

void reverse_reg_taint(int reg, int size)
{
    assert(size == 4);
    uint16_t t;
    uint16_t tmp;
    t = get_reg_taint(reg);

    // first bit
    tmp = t & 0x1;
    tmp = tmp << 1;
    tmp |= ((t >> 1) & 0x1);
    tmp = tmp << 1;
    tmp |= ((t >> 2) & 0x1);
    tmp = tmp << 1;
    tmp |= ((t >> 3) & 0x1);

    set_reg_taint(reg, tmp);
}

// interface for different taint transfers
// mem2reg
TAINTSIGN taint_mem2lbreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2lbreg");
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, LB_MASK);
    merge_reg_taint(reg, t & LB_MASK);
}

TAINTSIGN taint_mem2ubreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2ubreg");
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, UB_MASK);
    merge_reg_taint(reg, t & UB_MASK);
}

TAINTSIGN taint_mem2hwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2hwreg");
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, HW_MASK);
    merge_reg_taint(reg, t & HW_MASK);
}

TAINTSIGN taint_mem2wreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2wreg");
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, W_MASK);
    merge_reg_taint(reg, t & W_MASK);
}

TAINTSIGN taint_mem2dwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2dwreg");
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, DW_MASK);
    merge_reg_taint(reg, t & DW_MASK);
}

TAINTSIGN taint_mem2qwreg (u_long mem_loc, int reg)
{
    TAINT_START("taint_mem2qwreg");
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, QW_MASK);
    merge_reg_taint(reg, t & QW_MASK);
}

TAINTSIGN taint_bmem2hwreg (u_long mem_loc, int reg)
{
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_bmem2wreg (u_long mem_loc, int reg)
{
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_bmem2dwreg (u_long mem_loc, int reg)
{
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_bmem2qwreg (u_long mem_loc, int reg)
{
    taint_mem2lbreg(mem_loc, reg);
}

TAINTSIGN taint_hwmem2wreg (u_long mem_loc, int reg)
{
    taint_mem2wreg(mem_loc, reg);
}

TAINTSIGN taint_hwmem2dwreg (u_long mem_loc, int reg)
{
    taint_mem2hwreg(mem_loc, reg);
}

TAINTSIGN taint_hwmem2qwreg (u_long mem_loc, int reg)
{
    taint_mem2hwreg(mem_loc, reg);
}

TAINTSIGN taint_wmem2dwreg (u_long mem_loc, int reg)
{
    taint_mem2wreg(mem_loc, reg);
}

TAINTSIGN taint_wmem2qwreg (u_long mem_loc, int reg)
{
    taint_mem2wreg(mem_loc, reg);
}

TAINTSIGN taint_dwmem2qwreg (u_long mem_loc, int reg)
{
    taint_mem2dwreg(mem_loc, reg);
}

// mem2reg extend
TAINTSIGN taintx_bmem2hwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, HW_MASK);
    merge_reg_taint(reg, t & LB_MASK);
}

TAINTSIGN taintx_bmem2wreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, W_MASK);
    merge_reg_taint(reg, t & LB_MASK);
}

TAINTSIGN taintx_bmem2dwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, DW_MASK);
    merge_reg_taint(reg, t & LB_MASK);
}

TAINTSIGN taintx_bmem2qwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, QW_MASK);
    merge_reg_taint(reg, t & LB_MASK);
}

TAINTSIGN taintx_hwmem2wreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, W_MASK);
    merge_reg_taint(reg, t & HW_MASK);
}

TAINTSIGN taintx_hwmem2dwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, DW_MASK);
    merge_reg_taint(reg, t & HW_MASK);
}

TAINTSIGN taintx_hwmem2qwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, QW_MASK);
    merge_reg_taint(reg, t & HW_MASK);
}

TAINTSIGN taintx_wmem2dwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, DW_MASK);
    merge_reg_taint(reg, t & W_MASK);
}

TAINTSIGN taintx_wmem2qwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, QW_MASK);
    merge_reg_taint(reg, t & W_MASK);
}

TAINTSIGN taintx_dwmem2qwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    clear_reg_mask(reg, QW_MASK);
    merge_reg_taint(reg, t & DW_MASK);
}

// mem2reg add
TAINTSIGN taint_add_bmem2lbreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & LB_MASK);
}

TAINTSIGN taint_add_bmem2ubreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & UB_MASK);
}

TAINTSIGN taint_add_hwmem2hwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & HW_MASK);
}

TAINTSIGN taint_add_wmem2wreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & W_MASK);
}

TAINTSIGN taint_add_dwmem2dwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & DW_MASK);
}

TAINTSIGN taint_add_qwmem2qwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & QW_MASK);
}

TAINTSIGN taint_add_bmem2hwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & LB_MASK);
}

TAINTSIGN taint_add_bmem2wreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & LB_MASK);
}

TAINTSIGN taint_add_bmem2dwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & LB_MASK);
}

TAINTSIGN taint_add_bmem2qwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & LB_MASK);
}

TAINTSIGN taint_add_hwmem2wreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & HW_MASK);
}

TAINTSIGN taint_add_hwmem2dwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & HW_MASK);
}

TAINTSIGN taint_add_hwmem2qwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & HW_MASK);
}

TAINTSIGN taint_add_wmem2dwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & W_MASK);
}

TAINTSIGN taint_add_wmem2qwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & W_MASK);
}

TAINTSIGN taint_add_dwmem2qwreg (u_long mem_loc, int reg)
{
    uint16_t t = get_mem_taint(mem_loc);
    merge_reg_taint(reg, t & DW_MASK);
}

// mem2reg xchg
TAINTSIGN taint_xchg_bmem2lbreg (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    uint16_t mem_taint = get_mem_taint(mem_loc);
    clear_reg_mask(reg, LB_MASK);
    merge_reg_taint(reg, mem_taint & LB_MASK);
    clear_mem_mask(mem_loc, LB_MASK);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taint_xchg_bmem2ubreg (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    uint16_t mem_taint = get_mem_taint(mem_loc);
    clear_reg_mask(reg, UB_MASK);
    merge_reg_taint(reg, mem_taint & UB_MASK);
    clear_mem_mask(mem_loc, LB_MASK);
    merge_mem_taint(mem_loc, (reg_taint >> 1 )& LB_MASK);
}

TAINTSIGN taint_xchg_hwmem2hwreg (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    uint16_t mem_taint = get_mem_taint(mem_loc);
    clear_reg_mask(reg, HW_MASK);
    merge_reg_taint(reg, mem_taint & HW_MASK);
    clear_mem_mask(mem_loc, HW_MASK);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taint_xchg_wmem2wreg (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    uint16_t mem_taint = get_mem_taint(mem_loc);
    clear_reg_mask(reg, W_MASK);
    merge_reg_taint(reg, mem_taint & W_MASK);
    clear_mem_mask(mem_loc, W_MASK);
    merge_mem_taint(mem_loc, reg_taint & W_MASK);
}

TAINTSIGN taint_xchg_dwmem2dwreg (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    uint16_t mem_taint = get_mem_taint(mem_loc);
    clear_reg_mask(reg, DW_MASK);
    merge_reg_taint(reg, mem_taint & DW_MASK);
    clear_mem_mask(mem_loc, DW_MASK);
    merge_mem_taint(mem_loc, reg_taint & DW_MASK);
}

TAINTSIGN taint_xchg_qwmem2qwreg( u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    uint16_t mem_taint = get_mem_taint(mem_loc);
    clear_reg_mask(reg, QW_MASK);
    merge_reg_taint(reg, mem_taint & QW_MASK);
    clear_mem_mask(mem_loc, QW_MASK);
    merge_mem_taint(mem_loc, reg_taint & QW_MASK);
}

// reg2mem
TAINTSIGN taint_lbreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, LB_MASK);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taint_ubreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, UB_MASK);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taint_hwreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, HW_MASK);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taint_wreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, W_MASK);
    merge_mem_taint(mem_loc, reg_taint & W_MASK);
}

TAINTSIGN taint_dwreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, DW_MASK);
    merge_mem_taint(mem_loc, reg_taint & DW_MASK);
}

TAINTSIGN taint_qwreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, QW_MASK);
    merge_mem_taint(mem_loc, reg_taint & QW_MASK);
}

TAINTSIGN taint_lbreg2hwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, LB_MASK);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taint_lbreg2wmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, LB_MASK);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taint_lbreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, LB_MASK);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taint_lbreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, LB_MASK);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taint_ubreg2hwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, UB_MASK);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taint_ubreg2wmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, UB_MASK);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taint_ubreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, UB_MASK);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taint_ubreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, UB_MASK);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taint_hwreg2wmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, HW_MASK);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taint_hwreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, HW_MASK);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taint_hwreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, HW_MASK);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taint_wreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, W_MASK);
    merge_mem_taint(mem_loc, reg_taint & W_MASK);
}

TAINTSIGN taint_wreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, W_MASK);
    merge_mem_taint(mem_loc, reg_taint & W_MASK);
}

TAINTSIGN taint_dwreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, DW_MASK);
    merge_mem_taint(mem_loc, reg_taint & DW_MASK);
}

// reg2mem extend
TAINTSIGN taintx_lbreg2hwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, HW_MASK);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taintx_lbreg2wmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, W_MASK);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taintx_lbreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, DW_MASK);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taintx_lbreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, QW_MASK);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taintx_ubreg2hwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, HW_MASK);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taintx_ubreg2wmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, W_MASK);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taintx_ubreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, DW_MASK);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taintx_ubreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, QW_MASK);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}


TAINTSIGN taintx_hwreg2wmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, W_MASK);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taintx_hwreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, DW_MASK);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taintx_hwreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, QW_MASK);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taintx_wreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, DW_MASK);
    merge_mem_taint(mem_loc, reg_taint & W_MASK);
}

TAINTSIGN taintx_wreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, QW_MASK);
    merge_mem_taint(mem_loc, reg_taint & W_MASK);
}

TAINTSIGN taintx_dwreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    clear_mem_mask(mem_loc, QW_MASK);
    merge_mem_taint(mem_loc, reg_taint & DW_MASK);
}

// reg2mem add
TAINTSIGN taint_add_lbreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taint_add_ubreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taint_add_hwreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taint_add_wreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & W_MASK);
}

TAINTSIGN taint_add_dwreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & DW_MASK);
}

TAINTSIGN taint_add_qwreg2mem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & QW_MASK);
}

TAINTSIGN taint_add_lbreg2hwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taint_add_lbreg2wmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taint_add_lbreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taint_add_lbreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & LB_MASK);
}

TAINTSIGN taint_add_ubreg2hwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taint_add_ubreg2wmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taint_add_ubreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taint_add_ubreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & UB_MASK);
}

TAINTSIGN taint_add_hwreg2wmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taint_add_hwreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taint_add_hwreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & HW_MASK);
}

TAINTSIGN taint_add_wreg2dwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & W_MASK);
}

TAINTSIGN taint_add_wreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & W_MASK);
}

TAINTSIGN taint_add_dwreg2qwmem (u_long mem_loc, int reg)
{
    uint16_t reg_taint = get_reg_taint(reg);
    merge_mem_taint(mem_loc, reg_taint & DW_MASK);
}

// reg2mem rep
TAINTSIGN taint_rep_lbreg2mem (u_long mem_loc, int reg, int count)
{
    // TODO this can be optimized
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_lbreg2mem(mem_loc + i, reg);
    }
}

TAINTSIGN taint_rep_ubreg2mem (u_long mem_loc, int reg, int count)
{
    // TODO this can be optimized
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_ubreg2mem(mem_loc + i, reg);
    }
}

TAINTSIGN taint_rep_hwreg2mem (u_long mem_loc, int reg, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_hwreg2mem(mem_loc + (i * 2), reg);
    }
}

TAINTSIGN taint_rep_wreg2mem (u_long mem_loc, int reg, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_wreg2mem(mem_loc + (i * 4), reg);
    }
}

TAINTSIGN taint_rep_dwreg2mem (u_long mem_loc, int reg, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_dwreg2mem(mem_loc + (i * 8), reg);
    }
}

TAINTSIGN taint_rep_qwreg2mem (u_long mem_loc, int reg, int count)
{
    int i = 0;
    for (i = 0; i < count; i++) {
        taint_qwreg2mem(mem_loc + (i * 16), reg);
    }
}

// reg2reg
TAINTSIGN taint_lbreg2lbreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, LB_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_ubreg2lbreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    t &= UB_MASK;
    t = t >> 1;
    clear_reg_mask(dst_reg, LB_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_lbreg2ubreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    t &= LB_MASK;
    t = t << 1;
    clear_reg_mask(dst_reg, UB_MASK);
    merge_reg_taint(dst_reg, t & UB_MASK);
}

TAINTSIGN taint_ubreg2ubreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, UB_MASK);
    merge_reg_taint(dst_reg, t & UB_MASK);
}

TAINTSIGN taint_hwreg2hwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, HW_MASK);
    merge_reg_taint(dst_reg, t & HW_MASK);
}

TAINTSIGN taint_wreg2wreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, W_MASK);
    merge_reg_taint(dst_reg, t & W_MASK);
}

TAINTSIGN taint_dwreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, DW_MASK);
    merge_reg_taint(dst_reg, t & DW_MASK);
}

TAINTSIGN taint_qwreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, QW_MASK);
    merge_reg_taint(dst_reg, t & QW_MASK);
}

TAINTSIGN taint_lbreg2wreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, LB_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_lbreg2hwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, LB_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_lbreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, LB_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_lbreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, LB_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_ubreg2hwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, UB_MASK);
    merge_reg_taint(dst_reg, t & UB_MASK);
}

TAINTSIGN taint_ubreg2wreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    t &= UB_MASK;
    t = t >> 1;
    clear_reg_mask(dst_reg, LB_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_ubreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    t &= UB_MASK;
    t = t >> 1;
    clear_reg_mask(dst_reg, LB_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_ubreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    t &= UB_MASK;
    t = t >> 1;
    clear_reg_mask(dst_reg, LB_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_hwreg2wreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, HW_MASK);
    merge_reg_taint(dst_reg, t & HW_MASK);
}

TAINTSIGN taint_hwreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, HW_MASK);
    merge_reg_taint(dst_reg, t & HW_MASK);
}

TAINTSIGN taint_hwreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, HW_MASK);
    merge_reg_taint(dst_reg, t & HW_MASK);
}

TAINTSIGN taint_wreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, W_MASK);
    merge_reg_taint(dst_reg, t & W_MASK);
}

TAINTSIGN taint_wreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, W_MASK);
    merge_reg_taint(dst_reg, t & W_MASK);
}

TAINTSIGN taint_dwreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, DW_MASK);
    merge_reg_taint(dst_reg, t & DW_MASK);
}

// reg2reg extend
TAINTSIGN taintx_lbreg2wreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, W_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taintx_lbreg2hwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, HW_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taintx_lbreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, DW_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taintx_lbreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, QW_MASK);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taintx_ubreg2wreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, W_MASK);
    merge_reg_taint(dst_reg, t & UB_MASK);
}

TAINTSIGN taintx_ubreg2hwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, HW_MASK);
    merge_reg_taint(dst_reg, t & UB_MASK);
}

TAINTSIGN taintx_ubreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, DW_MASK);
    merge_reg_taint(dst_reg, t & UB_MASK);
}

TAINTSIGN taintx_ubreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, QW_MASK);
    merge_reg_taint(dst_reg, t & UB_MASK);
}

TAINTSIGN taintx_hwreg2wreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, W_MASK);
    merge_reg_taint(dst_reg, t & HW_MASK);
}

TAINTSIGN taintx_hwreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, DW_MASK);
    merge_reg_taint(dst_reg, t & HW_MASK);
}

TAINTSIGN taintx_hwreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, QW_MASK);
    merge_reg_taint(dst_reg, t & HW_MASK);
}

TAINTSIGN taintx_wreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, DW_MASK);
    merge_reg_taint(dst_reg, t & W_MASK);
}

TAINTSIGN taintx_wreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, QW_MASK);
    merge_reg_taint(dst_reg, t & W_MASK);
}

TAINTSIGN taintx_dwreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, QW_MASK);
    merge_reg_taint(dst_reg, t & DW_MASK);
}

// reg2reg add
TAINTSIGN taint_add_lbreg2lbreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_add_ubreg2lbreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    t &= UB_MASK;
    t = t >> 1;
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_add_lbreg2ubreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    t &= LB_MASK;
    t = t << 1;
    merge_reg_taint(dst_reg, t & UB_MASK);
}

TAINTSIGN taint_add_ubreg2ubreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & UB_MASK);
}

TAINTSIGN taint_add_wreg2wreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & W_MASK);
}

TAINTSIGN taint_add_hwreg2hwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & HW_MASK);
}

TAINTSIGN taint_add_dwreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & DW_MASK);
}

TAINTSIGN taint_add_qwreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & QW_MASK);
}

TAINTSIGN taint_add_lbreg2wreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_add_lbreg2hwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_add_lbreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_add_lbreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_add_ubreg2hwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    t &= UB_MASK;
    t = t >> 1;
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_add_ubreg2wreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    t &= UB_MASK;
    t = t >> 1;
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_add_ubreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    t &= UB_MASK;
    t = t >> 1;
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_add_ubreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    t &= UB_MASK;
    t = t >> 1;
    merge_reg_taint(dst_reg, t & LB_MASK);
}

TAINTSIGN taint_add_hwreg2wreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & HW_MASK);
}

TAINTSIGN taint_add_hwreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & HW_MASK);
}

TAINTSIGN taint_add_hwreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & HW_MASK);
}

TAINTSIGN taint_add_wreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & W_MASK);
}

TAINTSIGN taint_add_wreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & W_MASK);
}

TAINTSIGN taint_add_dwreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t t = get_reg_taint(src_reg);
    merge_reg_taint(dst_reg, t & DW_MASK);
}

// reg2reg xchg
TAINTSIGN taint_xchg_lbreg2lbreg (int dst_reg, int src_reg)
{
    uint16_t dst_taint = get_reg_taint(src_reg);
    uint16_t src_taint = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, LB_MASK);
    clear_reg_mask(src_reg, LB_MASK);
    merge_reg_taint(dst_reg, src_taint & LB_MASK);
    merge_reg_taint(src_reg, dst_taint & LB_MASK);
}

TAINTSIGN taint_xchg_ubreg2ubreg (int dst_reg, int src_reg)
{
    uint16_t dst_taint = get_reg_taint(src_reg);
    uint16_t src_taint = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, UB_MASK);
    clear_reg_mask(src_reg, UB_MASK);
    merge_reg_taint(dst_reg, src_taint & UB_MASK);
    merge_reg_taint(src_reg, dst_taint & UB_MASK);
}

TAINTSIGN taint_xchg_ubreg2lbreg (int dst_reg, int src_reg)
{
    uint16_t dst_taint = get_reg_taint(src_reg);
    uint16_t src_taint = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, LB_MASK);
    clear_reg_mask(src_reg, UB_MASK);
    merge_reg_taint(dst_reg, (src_taint >> 1) & LB_MASK);
    merge_reg_taint(src_reg, (dst_taint << 1) & UB_MASK);
}

TAINTSIGN taint_xchg_lbreg2ubreg (int dst_reg, int src_reg)
{
    uint16_t dst_taint = get_reg_taint(src_reg);
    uint16_t src_taint = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, UB_MASK);
    clear_reg_mask(src_reg, LB_MASK);
    merge_reg_taint(dst_reg, (src_taint << 1) & UB_MASK);
    merge_reg_taint(src_reg, (dst_taint >> 1) & LB_MASK);
}

TAINTSIGN taint_xchg_hwreg2hwreg (int dst_reg, int src_reg)
{
    uint16_t dst_taint = get_reg_taint(src_reg);
    uint16_t src_taint = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, HW_MASK);
    clear_reg_mask(src_reg, HW_MASK);
    merge_reg_taint(dst_reg, src_taint & HW_MASK);
    merge_reg_taint(src_reg, dst_taint & HW_MASK);
}

TAINTSIGN taint_xchg_wreg2wreg (int dst_reg, int src_reg)
{
    uint16_t dst_taint = get_reg_taint(src_reg);
    uint16_t src_taint = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, W_MASK);
    clear_reg_mask(src_reg, W_MASK);
    merge_reg_taint(dst_reg, src_taint & W_MASK);
    merge_reg_taint(src_reg, dst_taint & W_MASK);
}

TAINTSIGN taint_xchg_dwreg2dwreg (int dst_reg, int src_reg)
{
    uint16_t dst_taint = get_reg_taint(src_reg);
    uint16_t src_taint = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, DW_MASK);
    clear_reg_mask(src_reg, DW_MASK);
    merge_reg_taint(dst_reg, src_taint & DW_MASK);
    merge_reg_taint(src_reg, dst_taint & DW_MASK);
}

TAINTSIGN taint_xchg_qwreg2qwreg (int dst_reg, int src_reg)
{
    uint16_t dst_taint = get_reg_taint(src_reg);
    uint16_t src_taint = get_reg_taint(src_reg);
    clear_reg_mask(dst_reg, QW_MASK);
    clear_reg_mask(src_reg, QW_MASK);
    merge_reg_taint(dst_reg, src_taint & QW_MASK);
    merge_reg_taint(src_reg, dst_taint & QW_MASK);
}

TAINTSIGN taint_mask_reg2reg (int dst_reg, int src_reg)
{
    // TODO
}

// mem2mem
TAINTSIGN taint_mem2mem (u_long src_loc, u_long dst_loc,
                                                        uint32_t size)
{
    if (size == 1) {
        taint_mem2mem_b(src_loc, dst_loc);
    } else if (size == 2) {
        taint_mem2mem_hw(src_loc, dst_loc);
    } else if (size == 4) {
        taint_mem2mem_w(src_loc, dst_loc);
    } else {
        u_long count = 0;
        uint32_t nsize = size;
        while (1) {
            uint16_t t;
            if (nsize < 16) {
                uint16_t mask;
                mask = (0x1 << nsize) - 1;
                t = get_mem_taint(src_loc + count);
                clear_mem_mask(dst_loc + count, mask);
                merge_mem_taint(dst_loc + count, t & mask);
                break;
            }
            t = get_mem_taint(src_loc + count);
            clear_mem_mask(dst_loc + count, QW_MASK);
            merge_mem_taint(dst_loc + count, t);
            count += 16;
            nsize -= 16;
        }
        /*
        assert(0);
        int src_idx;
        int dst_idx;
        uint32_t new_size;
        new_size = size - (size % 8);
        assert(dst_loc + size <= src_loc);
        assert(new_size % 8 == 0);

        src_idx = src_loc >> 3;
        dst_idx = dst_loc >> 3;

        memcpy(&shadow_memory[dst_idx], &shadow_memory[src_idx],
                new_size * sizeof(uint8_t));

        // the remainder
        if (size % 8 != 0) {
            int bitfield = (0x1 << (size % 8)) - 1;
            src_idx = (src_loc + new_size) >> 3;
            dst_idx = (dst_loc + new_size) >> 3;

            shadow_memory[dst_idx] &= ~bitfield;
            shadow_memory[dst_idx] |= shadow_memory[src_idx] & bitfield;
        }
        */
    }
}

TAINTSIGN taint_mem2mem_b (u_long src_loc, u_long dst_loc)
{
    uint16_t t = get_mem_taint(src_loc);
    clear_mem_mask(dst_loc, LB_MASK);
    merge_mem_taint(dst_loc, t & LB_MASK);
}

TAINTSIGN taint_mem2mem_hw (u_long src_loc, u_long dst_loc)
{
    uint16_t t = get_mem_taint(src_loc);
    clear_mem_mask(dst_loc, HW_MASK);
    merge_mem_taint(dst_loc, t & HW_MASK);
}

TAINTSIGN taint_mem2mem_w (u_long src_loc, u_long dst_loc)
{
    uint16_t t = get_mem_taint(src_loc);
    clear_mem_mask(dst_loc, W_MASK);
    merge_mem_taint(dst_loc, t & W_MASK);
}

TAINTSIGN taint_mem2mem_dw (u_long src_loc, u_long dst_loc)
{
    uint16_t t = get_mem_taint(src_loc);
    clear_mem_mask(dst_loc, DW_MASK);
    merge_mem_taint(dst_loc, t & DW_MASK);
}

TAINTSIGN taint_mem2mem_qw (u_long src_loc, u_long dst_loc)
{
    uint16_t t = get_mem_taint(src_loc);
    clear_mem_mask(dst_loc, QW_MASK);
    merge_mem_taint(dst_loc, t & QW_MASK);
}

TAINTSIGN taint_add_mem2mem_b (u_long src_loc, u_long dst_loc)
{
    uint16_t t = get_mem_taint(src_loc);
    merge_mem_taint(dst_loc, t & LB_MASK);
}

TAINTSIGN taint_add_mem2mem_hw (u_long src_loc, u_long dst_loc)
{
    uint16_t t = get_mem_taint(src_loc);
    merge_mem_taint(dst_loc, t & HW_MASK);
}

TAINTSIGN taint_add_mem2mem_w (u_long src_loc, u_long dst_loc)
{
    uint16_t t = get_mem_taint(src_loc);
    merge_mem_taint(dst_loc, t & W_MASK);
}

TAINTSIGN taint_add_mem2mem_dw (u_long src_loc, u_long dst_loc)
{
    uint16_t t = get_mem_taint(src_loc);
    merge_mem_taint(dst_loc, t & DW_MASK);
}

TAINTSIGN taint_add_mem2mem_qw (u_long src_loc, u_long dst_loc)
{
    uint16_t t = get_mem_taint(src_loc);
    merge_mem_taint(dst_loc, t & DW_MASK);
}

// 3-way operations (for supporting instructions like mul and div)
TAINTSIGN taint_add2_bmemlbreg_hwreg (u_long mem_loc, int src_reg, int dst_reg)
{
    uint16_t t;
    t = get_mem_taint(mem_loc);
    // merge with lower byte of src reg
    t |= get_reg_taint(src_reg);
    t &= LB_MASK;

    // set the two lower bytes of dst_reg to be t
    clear_reg_mask(dst_reg, HW_MASK);
    t |= (t << 1);
    merge_reg_taint(dst_reg, t);
}

TAINTSIGN taint_add2_hwmemhwreg_2hwreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2)
{
    uint16_t t;
    t = get_mem_taint(mem_loc);
    // merge with lower half word of src reg
    t |= get_reg_taint(src_reg);
    t &= HW_MASK;
    t |= (t >> 1); // set the lower bit to be the merged result
    t &= LB_MASK;
    t |= (t << 1); // t[0] and t[1] should have the same result now

    // set the lower half word of dst_reg1 and dst_reg2 to be t
    clear_reg_mask(dst_reg1, HW_MASK);
    clear_reg_mask(dst_reg2, HW_MASK);
    merge_reg_taint(dst_reg1, t);
    merge_reg_taint(dst_reg2, t);
}

TAINTSIGN taint_add2_wmemwreg_2wreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2)
{
    uint16_t t;
    t = get_mem_taint(mem_loc);
    // merge with lower word of src reg
    t |= get_reg_taint(src_reg);
    t &= W_MASK;
    // set t[0] to be the merge result of t[0:4]
    t |= (t >> 1);
    t |= (t >> 2);
    t |= (t >> 3);
    t &= LB_MASK;
    t |= (t << 1);
    t |= (t << 2);
    t |= (t << 3);
    // set t[0:4] to be the same as t[0]

    clear_reg_mask(dst_reg1, W_MASK);
    merge_reg_taint(dst_reg1, t);
    clear_reg_mask(dst_reg2, W_MASK);
    merge_reg_taint(dst_reg2, t);
}

TAINTSIGN taint_add2_lbreglbreg_hwreg (int src_reg1, int src_reg2, int dst_reg)
{
    uint16_t merged_taint;
    merged_taint = (get_reg_taint(src_reg1) & LB_MASK) |
                        (get_reg_taint(src_reg2) & LB_MASK);
    merged_taint &= LB_MASK;
    merged_taint |= (merged_taint << 1);
    clear_reg_mask(dst_reg, HW_MASK);
    merge_reg_taint(dst_reg, merged_taint);
}

TAINTSIGN taint_add2_hwreghwreg_2hwreg (int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2)
{
    uint16_t merged_taint;
    merged_taint = (get_reg_taint(src_reg1) & HW_MASK) |
                        (get_reg_taint(src_reg2) & HW_MASK);
    merged_taint &= HW_MASK;
    merged_taint |= (merged_taint >> 1);
    merged_taint &= LB_MASK;
    merged_taint |= (merged_taint << 1);

    clear_reg_mask(dst_reg1, HW_MASK);
    merge_reg_taint(dst_reg1, merged_taint);
    clear_reg_mask(dst_reg2, HW_MASK);
    merge_reg_taint(dst_reg2, merged_taint);
}

TAINTSIGN taint_add2_wregwreg_2wreg (int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2)
{
    uint16_t merged_taint;
    merged_taint = (get_reg_taint(src_reg1) & W_MASK) |
                        (get_reg_taint(src_reg2) & W_MASK);
    merged_taint &= W_MASK;
    merged_taint |= (merged_taint >> 1);
    merged_taint |= (merged_taint >> 2);
    merged_taint |= (merged_taint >> 3);
    merged_taint &= LB_MASK;
    merged_taint |= (merged_taint << 1);
    merged_taint |= (merged_taint << 2);
    merged_taint |= (merged_taint << 3);

    clear_reg_mask(dst_reg1, W_MASK);
    merge_reg_taint(dst_reg1, merged_taint);
    clear_reg_mask(dst_reg2, W_MASK);
    merge_reg_taint(dst_reg2, merged_taint);
}

TAINTSIGN taint_add2_hwmemhwreg_2breg (u_long mem_loc,
                                    int src_reg, int dst_reg1, int dst_reg2)
{
    uint16_t t;
    t = get_mem_taint(mem_loc);
    t |= get_reg_taint(src_reg);
    t &= HW_MASK;
    t |= (t >> 1);
    t &= LB_MASK;

    clear_reg_mask(dst_reg1, LB_MASK);
    merge_reg_taint(dst_reg1, t);
    clear_reg_mask(dst_reg2, LB_MASK);
    merge_reg_taint(dst_reg2, t);
}

TAINTSIGN taint_add2_wmemwreg_2hwreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2)
{
    uint16_t t;
    t = get_mem_taint(mem_loc);
    t |= get_reg_taint(src_reg);
    t &= W_MASK;
    t |= (t >> 1);
    t |= (t >> 2);
    t |= (t >> 3);
    t &= LB_MASK;
    t |= (t << 1);

    clear_reg_mask(dst_reg1, HW_MASK);
    merge_reg_taint(dst_reg1, t);
    clear_reg_mask(dst_reg2, HW_MASK);
    merge_reg_taint(dst_reg2, t);
}

TAINTSIGN taint_add3_dwmem2wreg_2wreg (u_long mem_loc,
                                    int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2)
{
    uint16_t t;
    t = get_mem_taint(mem_loc);
    t &= DW_MASK;
    t |= get_reg_taint(src_reg1);
    t |= ((get_reg_taint(src_reg2) & W_MASK) << 4);

    t |= (t >> 1);
    t |= (t >> 2);
    t |= (t >> 3);
    t |= (t >> 4);
    t |= (t >> 5);
    t |= (t >> 6);
    t |= (t >> 7);
    t &= LB_MASK;
    t |= (t << 1);
    t |= (t << 2);
    t |= (t << 3);

    clear_reg_mask(dst_reg1, W_MASK);
    merge_reg_taint(dst_reg1, t);
    clear_reg_mask(dst_reg2, W_MASK);
    merge_reg_taint(dst_reg2, t);
}

TAINTSIGN taint_add2_2hwreg_2breg (int src_reg1, int src_reg2,
                                int dst_reg1, int dst_reg2)
{
    uint16_t t;
    t = get_reg_taint(src_reg1) | get_reg_taint(src_reg2);
    t &= HW_MASK;
    t |= (t >> 1);
    t &= LB_MASK;

    clear_reg_mask(dst_reg1, LB_MASK);
    merge_reg_taint(dst_reg1, t);
    clear_reg_mask(dst_reg2, LB_MASK);
    merge_reg_taint(dst_reg2, t);
}

TAINTSIGN taint_add3_2hwreg_2hwreg (int src_reg1, int src_reg2,
                                    int src_reg3,
                                    int dst_reg1, int dst_reg2)
{
    uint16_t t;
    t = get_reg_taint(src_reg1) | get_reg_taint(src_reg3);
    t &= HW_MASK;
    t |= (get_reg_taint(src_reg2) | 
            ((get_reg_taint(src_reg3) >> 2) & HW_MASK)) << 2;
    t &= W_MASK;

    t |= (t >> 1);
    t |= (t >> 2);
    t |= (t >> 3);
    t &= LB_MASK;
    t |= (t << 1);

    clear_reg_mask(dst_reg1, HW_MASK);
    merge_reg_taint(dst_reg1, t);
    clear_reg_mask(dst_reg2, HW_MASK);
    merge_reg_taint(dst_reg2, t);
}

TAINTSIGN taint_add3_2wreg_2wreg (int src_reg1, int src_reg2,
                                    int src_reg3,
                                    int dst_reg1, int dst_reg2)
{
    uint16_t t;
    t = get_reg_taint(src_reg1) | get_reg_taint(src_reg3);
    t &= W_MASK;
    t |= (get_reg_taint(src_reg2) |
            ((get_reg_taint(src_reg3) >> 4) & W_MASK)) << 4;
    t &= DW_MASK;

    t |= (t >> 1);
    t |= (t >> 2);
    t |= (t >> 3);
    t |= (t >> 4);
    t |= (t >> 5);
    t |= (t >> 6);
    t |= (t >> 7);
    t &= LB_MASK;
    t |= (t >> 1);
    t |= (t >> 2);
    t |= (t >> 3);

    clear_reg_mask(dst_reg1, W_MASK);
    merge_reg_taint(dst_reg1, t);
    clear_reg_mask(dst_reg2, W_MASK);
    merge_reg_taint(dst_reg2, t);
}

// immval2mem
TAINTSIGN taint_immvalb2mem (u_long mem_loc)
{
    clear_mem_mask(mem_loc, LB_MASK);
}

TAINTSIGN taint_immvalhw2mem (u_long mem_loc)
{
    clear_mem_mask(mem_loc, HW_MASK);
}

TAINTSIGN taint_immvalw2mem (u_long mem_loc)
{
    clear_mem_mask(mem_loc, W_MASK);
}

TAINTSIGN taint_immvaldw2mem (u_long mem_loc)
{
    clear_mem_mask(mem_loc, DW_MASK);
}

TAINTSIGN taint_immvalqw2mem (u_long mem_loc)
{
    clear_mem_mask(mem_loc, QW_MASK);
}

// immval2mem add
TAINTSIGN taint_add_immvalb2mem (u_long mem_loc)
{
}

TAINTSIGN taint_add_immvalhw2mem (u_long mem_loc)
{
}

TAINTSIGN taint_add_immvalw2mem (u_long mem_loc)
{
}

TAINTSIGN taint_add_immvaldw2mem (u_long mem_loc)
{
}

TAINTSIGN taint_add_immvalqw2mem (u_long mem_loc)
{
}

// immval2reg
TAINTSIGN taint_immval2lbreg(int reg)
{
    clear_reg_mask(reg, LB_MASK);
}

TAINTSIGN taint_immval2ubreg(int reg)
{
    clear_reg_mask(reg, UB_MASK);
}

TAINTSIGN taint_immval2hwreg(int reg)
{
    clear_reg_mask(reg, HW_MASK);
}

TAINTSIGN taint_immval2wreg(int reg)
{
    clear_reg_mask(reg, W_MASK);
}

TAINTSIGN taint_immval2dwreg(int reg)
{
    clear_reg_mask(reg, DW_MASK);
}

TAINTSIGN taint_immval2qwreg(int reg)
{
    clear_reg_mask(reg, QW_MASK);
}

// immval2reg add
TAINTSIGN taint_add_immval2lbreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2ubreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2hwreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2wreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2dwreg(int reg)
{
    return;
}

TAINTSIGN taint_add_immval2qwreg(int reg)
{
    return;
}

TAINTSIGN taint_palignr_mem2dwreg(int reg, u_long mem_loc, int imm)
{
    uint16_t tmp;
    uint16_t dst_taint;
    uint16_t src_taint;

    dst_taint = get_reg_taint(reg) & DW_MASK;
    src_taint = get_mem_taint(mem_loc) & DW_MASK;

    // concat
    tmp = dst_taint << 8;
    tmp |= src_taint;

    set_reg_taint(reg, (tmp >> imm) & 0xffff);
}

TAINTSIGN taint_palignr_mem2qwreg(int reg, u_long mem_loc, int imm)
{
    uint32_t tmp;
    uint16_t dst_taint;
    uint16_t src_taint;

    dst_taint = get_reg_taint(reg) & QW_MASK;
    src_taint = get_mem_taint(mem_loc) & QW_MASK;

    // concat
    tmp = dst_taint << 16;
    tmp |= src_taint;

    set_reg_taint(reg, (tmp >> imm) & 0xffff);
}

TAINTSIGN taint_palignr_dwreg2dwreg(int dst_reg, int src_reg, int imm)
{
    uint16_t tmp;
    uint16_t dst_taint;
    uint16_t src_taint;

    dst_taint = get_reg_taint(dst_reg) & DW_MASK;
    src_taint = get_reg_taint(src_reg) & DW_MASK;

    // concat
    tmp = dst_taint << 8;
    tmp |= src_taint;

    set_reg_taint(dst_reg, (tmp >> imm) & 0xffff);
}

TAINTSIGN taint_palignr_qwreg2qwreg(int dst_reg, int src_reg, int imm)
{
    uint32_t tmp;
    uint16_t dst_taint;
    uint16_t src_taint;

    dst_taint = get_reg_taint(dst_reg) & QW_MASK;
    src_taint = get_reg_taint(src_reg) & QW_MASK;

    // concat
    tmp = dst_taint << 16;
    tmp |= src_taint;

    set_reg_taint(dst_reg, (tmp >> imm) & 0xffff);
}
