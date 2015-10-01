#ifndef TAINT_INTERFACE_H
#define TAINT_INTERFACE_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include "pin.H"
#include "taint.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t option_t;
typedef uint8_t taintvalue_t;

#define MAX_NUM_OPTIONS 2147483648
#define MAX_TAINT_VALUE 1

#define FAST_INLINE
#ifdef FAST_INLINE
#define TAINTSIGN void PIN_FAST_ANALYSIS_CALL
#else
#define TAINTSIGN void
#endif


/* Creates a new taint for a memory input */
taint_t create_and_taint_option (u_long mem_addr);

/* Get the taint value for an option in the taint structure t */
taintvalue_t get_taint_value (taint_t t, option_t option);

taintvalue_t get_max_taint_value(void);
int is_taint_zero(taint_t src);
taint_t merge_taints(taint_t dst, taint_t src);

/* Translate a register from the Pin representation
 *  E.g. translates AH to EAX
 * */
int translate_reg(int reg);

/* Init all structures required to for tainting.
 * Call this first before calling any taint function
 * */
void init_taint_structures(char* group_dir);
void* get_non_zero_taints(taint_t t);
void print_options(FILE* fp, taint_t t);


/* Any sort of cleanup goes here */
void taint_fini(void);

void finish_and_print_taint_stats(FILE* fp);

taint_t* get_reg_taints(int reg);

/* Clear size bytes of the register. (starts from the LSB) */
void clear_reg (int reg, int size);

/* Set the taint of a memory address */
void taint_mem (u_long mem_loc, taint_t t);

/* Returns the taints for continuous series of memory addresses */
taint_t* get_mem_taints(u_long mem_loc, uint32_t size);
uint32_t get_cmem_taints(u_long mem_loc, uint32_t size, taint_t**);
void clear_mem_taints(u_long mem_loc, uint32_t size);

/* shift the taints of the bytes of a reg by shift num of bytes */
void shift_reg_taint_right(int reg, int shift);
void reverse_reg_taint(int reg, int size);

// interface for different taint transfers
// mem2reg
TAINTSIGN taint_mem2lbreg (u_long mem_loc, int reg);
TAINTSIGN taint_mem2ubreg (u_long mem_loc, int reg);
TAINTSIGN taint_mem2hwreg (u_long mem_loc, int reg);
TAINTSIGN taint_mem2wreg (u_long mem_loc, int reg);
TAINTSIGN taint_mem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taint_mem2qwreg (u_long mem_loc, int reg);

TAINTSIGN taint_bmem2hwreg (u_long mem_loc, int reg);
TAINTSIGN taint_bmem2wreg (u_long mem_loc, int reg);
TAINTSIGN taint_bmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taint_bmem2qwreg (u_long mem_loc, int reg);

TAINTSIGN taint_hwmem2wreg (u_long mem_loc, int reg);
TAINTSIGN taint_hwmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taint_hwmem2qwreg (u_long mem_loc, int reg);

TAINTSIGN taint_wmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taint_wmem2qwreg (u_long mem_loc, int reg);

TAINTSIGN taint_dwmem2qwreg (u_long mem_loc, int reg);

// mem2reg extend
TAINTSIGN taintx_bmem2hwreg (u_long mem_loc, int reg);
TAINTSIGN taintx_bmem2wreg (u_long mem_loc, int reg);
TAINTSIGN taintx_bmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taintx_bmem2qwreg (u_long mem_loc, int reg);

TAINTSIGN taintx_hwmem2wreg (u_long mem_loc, int reg);
TAINTSIGN taintx_hwmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taintx_hwmem2qwreg (u_long mem_loc, int reg);

TAINTSIGN taintx_wmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taintx_wmem2qwreg (u_long mem_loc, int reg);

TAINTSIGN taintx_dwmem2qwreg (u_long mem_loc, int reg);

// mem2reg add
TAINTSIGN taint_add_bmem2lbreg (u_long mem_loc, int reg);
TAINTSIGN taint_add_bmem2ubreg (u_long mem_loc, int reg);
TAINTSIGN taint_add_hwmem2hwreg (u_long mem_loc, int reg);
TAINTSIGN taint_add_wmem2wreg (u_long mem_loc, int reg);
TAINTSIGN taint_add_dwmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taint_add_qwmem2qwreg (u_long mem_loc, int reg);

TAINTSIGN taint_add_bmem2hwreg (u_long mem_loc, int reg);
TAINTSIGN taint_add_bmem2wreg (u_long mem_loc, int reg);
TAINTSIGN taint_add_bmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taint_add_bmem2qwreg (u_long mem_loc, int reg);

TAINTSIGN taint_add_hwmem2wreg (u_long mem_loc, int reg);
TAINTSIGN taint_add_hwmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taint_add_hwmem2qwreg (u_long mem_loc, int reg);

TAINTSIGN taint_add_wmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taint_add_wmem2qwreg (u_long mem_loc, int reg);

TAINTSIGN taint_add_dwmem2qwreg (u_long mem_loc, int reg);

// mem2reg xchg
TAINTSIGN taint_xchg_bmem2lbreg (u_long mem_loc, int reg);
TAINTSIGN taint_xchg_bmem2ubreg (u_long mem_loc, int reg);
TAINTSIGN taint_xchg_hwmem2hwreg (u_long mem_loc, int reg);
TAINTSIGN taint_xchg_wmem2wreg (u_long mem_loc, int reg);
TAINTSIGN taint_xchg_dwmem2dwreg (u_long mem_loc, int reg);
TAINTSIGN taint_xchg_qwmem2qwreg( u_long mem_loc, int reg);

// reg2mem
TAINTSIGN taint_lbreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_ubreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_hwreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_wreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_dwreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_qwreg2mem (u_long mem_loc, int reg);

TAINTSIGN taint_lbreg2hwmem (u_long mem_loc, int reg);
TAINTSIGN taint_lbreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taint_lbreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_lbreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_ubreg2hwmem (u_long mem_loc, int reg);
TAINTSIGN taint_ubreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taint_ubreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_ubreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_hwreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taint_hwreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_hwreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_wreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_wreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_dwreg2qwmem (u_long mem_loc, int reg);

// reg2mem extend
TAINTSIGN taintx_lbreg2hwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_lbreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taintx_lbreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_lbreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taintx_ubreg2hwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_ubreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taintx_ubreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_ubreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taintx_hwreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taintx_hwreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_hwreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taintx_wreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taintx_wreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taintx_dwreg2qwmem (u_long mem_loc, int reg);

// reg2mem add
TAINTSIGN taint_add_lbreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_add_ubreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_add_hwreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_add_wreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_add_dwreg2mem (u_long mem_loc, int reg);
TAINTSIGN taint_add_qwreg2mem (u_long mem_loc, int reg);

TAINTSIGN taint_add_lbreg2hwmem (u_long mem_loc, int reg);
TAINTSIGN taint_add_lbreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taint_add_lbreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_add_lbreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_add_ubreg2hwmem (u_long mem_loc, int reg);
TAINTSIGN taint_add_ubreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taint_add_ubreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_add_ubreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_add_hwreg2wmem (u_long mem_loc, int reg);
TAINTSIGN taint_add_hwreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_add_hwreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_add_wreg2dwmem (u_long mem_loc, int reg);
TAINTSIGN taint_add_wreg2qwmem (u_long mem_loc, int reg);

TAINTSIGN taint_add_dwreg2qwmem (u_long mem_loc, int reg);

// reg2mem rep
TAINTSIGN taint_rep_lbreg2mem (u_long mem_loc, int reg, int count);
TAINTSIGN taint_rep_ubreg2mem (u_long mem_loc, int reg, int count);
TAINTSIGN taint_rep_hwreg2mem (u_long mem_loc, int reg, int count);
TAINTSIGN taint_rep_wreg2mem (u_long mem_loc, int reg, int count);
TAINTSIGN taint_rep_dwreg2mem (u_long mem_loc, int reg, int count);
TAINTSIGN taint_rep_qwreg2mem (u_long mem_loc, int reg, int count);

// reg2reg
TAINTSIGN taint_lbreg2lbreg (int dst_reg, int src_reg);
TAINTSIGN taint_ubreg2lbreg (int dst_reg, int src_reg);
TAINTSIGN taint_lbreg2ubreg (int dst_reg, int src_reg);
TAINTSIGN taint_ubreg2ubreg (int dst_reg, int src_reg);
TAINTSIGN taint_wreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taint_hwreg2hwreg (int dst_reg, int src_reg);
TAINTSIGN taint_dwreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taint_qwreg2qwreg (int dst_reg, int src_reg);

TAINTSIGN taint_lbreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taint_lbreg2hwreg (int dst_reg, int src_reg);
TAINTSIGN taint_lbreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taint_lbreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taint_ubreg2hwreg (int dst_reg, int src_reg);
TAINTSIGN taint_ubreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taint_ubreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taint_ubreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taint_hwreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taint_hwreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taint_hwreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taint_wreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taint_wreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taint_dwreg2qwreg (int dst_reg, int src_reg);

// reg2reg extend
TAINTSIGN taintx_lbreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taintx_lbreg2hwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_lbreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_lbreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_ubreg2hwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_ubreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taintx_ubreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_ubreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_hwreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taintx_hwreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_hwreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_wreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_wreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taintx_dwreg2qwreg (int dst_reg, int src_reg);

// reg2reg add
TAINTSIGN taint_add_lbreg2lbreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_ubreg2lbreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_lbreg2ubreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_ubreg2ubreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_wreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_hwreg2hwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_dwreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_qwreg2qwreg (int dst_reg, int src_reg);

TAINTSIGN taint_add_lbreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_lbreg2hwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_lbreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_lbreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_ubreg2hwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_ubreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_ubreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_ubreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_hwreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_hwreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_hwreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_wreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_wreg2qwreg (int dst_reg, int src_reg);
TAINTSIGN taint_add_dwreg2qwreg (int dst_reg, int src_reg);

// reg2reg xchg
TAINTSIGN taint_xchg_lbreg2lbreg (int dst_reg, int src_reg);
TAINTSIGN taint_xchg_ubreg2ubreg (int dst_reg, int src_reg);
TAINTSIGN taint_xchg_ubreg2lbreg (int dst_reg, int src_reg);
TAINTSIGN taint_xchg_lbreg2ubreg (int dst_reg, int src_reg);
TAINTSIGN taint_xchg_hwreg2hwreg (int dst_reg, int src_reg);
TAINTSIGN taint_xchg_wreg2wreg (int dst_reg, int src_reg);
TAINTSIGN taint_xchg_dwreg2dwreg (int dst_reg, int src_reg);
TAINTSIGN taint_xchg_qwreg2qwreg (int dst_reg, int src_reg);

TAINTSIGN taint_mask_reg2reg (int dst_reg, int src_reg);

// mem2mem
TAINTSIGN taint_mem2mem (u_long src_loc, u_long dst_loc, uint32_t size);
TAINTSIGN taint_mem2mem_b (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_mem2mem_hw (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_mem2mem_w (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_mem2mem_dw (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_mem2mem_qw (u_long src_loc, u_long dst_loc);

// mem2mem add
TAINTSIGN taint_add_mem2mem_b (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_add_mem2mem_hw (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_add_mem2mem_w (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_add_mem2mem_dw (u_long src_loc, u_long dst_loc);
TAINTSIGN taint_add_mem2mem_qw (u_long src_loc, u_long dst_loc);

// 3-way operations (for supporting instructions like mul and div)
TAINTSIGN taint_add2_bmemlbreg_hwreg (u_long mem_loc, int src_reg, int dst_reg);
TAINTSIGN taint_add2_hwmemhwreg_2hwreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2);
TAINTSIGN taint_add2_wmemwreg_2wreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2);
TAINTSIGN taint_add2_lbreglbreg_hwreg (int src_reg1, int src_reg2, int dst_reg);
TAINTSIGN taint_add2_hwreghwreg_2hwreg (int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2);
TAINTSIGN taint_add2_wregwreg_2wreg (int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2);


TAINTSIGN taint_add2_hwmemhwreg_2breg (u_long mem_loc,
                                    int src_reg, int dst_reg1, int dst_reg2);
TAINTSIGN taint_add2_wmemwreg_2hwreg (u_long mem_loc, int src_reg,
                                    int dst_reg1, int dst_reg2);
TAINTSIGN taint_add3_dwmem2wreg_2wreg (u_long mem_loc,
                                    int src_reg1, int src_reg2,
                                    int dst_reg1, int dst_reg2);
TAINTSIGN taint_add2_2hwreg_2breg (int src_reg1, int src_reg2,
                                int dst_reg1, int dst_reg2);
TAINTSIGN taint_add3_2hwreg_2hwreg (int src_reg1, int src_reg2, int src_reg3,
                                    int dst_reg1, int dst_reg2);
TAINTSIGN taint_add3_2wreg_2wreg (int src_reg1, int src_reg2, int src_reg3,
                                    int dst_reg1, int dst_reg2);

// immval2mem
TAINTSIGN taint_immvalb2mem (u_long mem_loc);
TAINTSIGN taint_immvalhw2mem (u_long mem_loc);
TAINTSIGN taint_immvalw2mem (u_long mem_loc);
TAINTSIGN taint_immvaldw2mem (u_long mem_loc);
TAINTSIGN taint_immvalqw2mem (u_long mem_loc);

// immval2mem add
TAINTSIGN taint_add_immvalb2mem (u_long mem_loc);
TAINTSIGN taint_add_immvalhw2mem (u_long mem_loc);
TAINTSIGN taint_add_immvalw2mem (u_long mem_loc);
TAINTSIGN taint_add_immvaldw2mem (u_long mem_loc);
TAINTSIGN taint_add_immvalqw2mem (u_long mem_loc);

// immval2reg
TAINTSIGN taint_immval2lbreg(int reg);
TAINTSIGN taint_immval2ubreg(int reg);
TAINTSIGN taint_immval2hwreg(int reg);
TAINTSIGN taint_immval2wreg(int reg);
TAINTSIGN taint_immval2dwreg(int reg);
TAINTSIGN taint_immval2qwreg(int reg);

// immval2reg add
TAINTSIGN taint_add_immval2lbreg(int reg);
TAINTSIGN taint_add_immval2ubreg(int reg);
TAINTSIGN taint_add_immval2hwreg(int reg);
TAINTSIGN taint_add_immval2wreg(int reg);
TAINTSIGN taint_add_immval2dwreg(int reg);
TAINTSIGN taint_add_immval2qwreg(int reg);

// TODO need to do transfers to and from flags
TAINTSIGN taint_immval2flag();

// Ugh, weird XMM instructions that we need to support
TAINTSIGN taint_palignr_mem2dwreg(int reg, u_long mem_loc, int imm);
TAINTSIGN taint_palignr_mem2qwreg(int reg, u_long mem_loc, int imm);
TAINTSIGN taint_palignr_dwreg2dwreg(int dst_reg, int src_reg, int imm);
TAINTSIGN taint_palignr_qwreg2qwreg(int dst_reg, int src_reg, int imm);


// File descriptor taint-tracking
int add_taint_fd(int fd, int cloexec);
taint_t create_and_taint_fdset(int nfds, fd_set* fds);
int remove_taint_fd(int fd);
int remove_cloexec_taint_fds(void);
int is_fd_tainted(int fd);
void taint_mem2fd(u_long mem_loc, int fd);
/* Merge taints from mem_loc to mem_loc + size into one fd taint */
void taint_mem2fd_size(u_long mem_loc, uint32_t size, int fd);
void taint_reg2fd(int reg, int fd);
void taint_add_mem2fd(u_long mem_loc, int fd);
void taint_add_reg2fd(int reg, int fd);
void taint_fd2mem(u_long mem_loc, uint32_t size, int fd);
void taint_add_fd2mem(u_long mem_loc, uint32_t size, int fd);

#ifdef __cplusplus
}
#endif

#endif
