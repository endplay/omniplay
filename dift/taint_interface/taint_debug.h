#ifndef TAINT_INTERFACE_TAINT_DEBUG_H
#define TAINT_INTERFACE_TAINT_DEBUG_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    // mem2reg
    TAINT_MEM2LBREG = 0,
    TAINT_MEM2UBREG,
    TAINT_MEM2HWREG,
    TAINT_MEM2WREG,
    TAINT_MEM2DWREG,
    TAINT_MEM2QWREG,
    TAINT_BMEM2HWREG,
    TAINT_BMEM2WREG,
    TAINT_BMEM2DWREG,
    TAINT_BMEM2QWREG,
    TAINT_HWMEM2WREG,
    TAINT_HWMEM2DWREG,
    TAINT_HWMEM2QWREG,
    TAINT_WMEM2DWREG,
    TAINT_WMEM2QWREG,
    TAINT_DWMEM2QWREG,
    TAINTX_BMEM2HWREG,
    TAINTX_BMEM2WREG,
    TAINTX_BMEM2DWREG,
    TAINTX_BMEM2QWREG,
    TAINTX_HWMEM2WREG,
    TAINTX_HWMEM2DWREG,
    TAINTX_HWMEM2QWREG,
    TAINTX_WMEM2DWREG,
    TAINTX_WMEM2QWREG,
    TAINTX_DWMEM2QWREG,
    TAINT_ADD_BMEM2LBREG,
    TAINT_ADD_BMEM2UBREG,
    TAINT_ADD_HWMEM2HWREG,
    TAINT_ADD_WMEM2WREG,
    TAINT_ADD_DWMEM2DWREG,
    TAINT_ADD_QWMEM2QWREG,
    TAINT_ADD_BMEM2HWREG,
    TAINT_ADD_BMEM2WREG,
    TAINT_ADD_BMEM2DWREG,
    TAINT_ADD_BMEM2QWREG,
    TAINT_ADD_HWMEM2WREG,
    TAINT_ADD_HWMEM2DWREG,
    TAINT_ADD_HWMEM2QWREG,
    TAINT_ADD_WMEM2DWREG,
    TAINT_ADD_WMEM2QWREG,
    TAINT_ADD_DWMEM2QWREG,
    TAINT_XCHG_BMEM2LBREG,
    TAINT_XCHG_BMEM2UBREG,
    TAINT_XCHG_HWMEM2HWREG,
    TAINT_XCHG_WMEM2WREG,
    TAINT_XCHG_DWMEM2DWREG,
    TAINT_XCHG_QWMEM2QWREG,
    // reg2mem
    TAINT_LBREG2MEM,
    TAINT_UBREG2MEM,
    TAINT_HWREG2MEM,
    TAINT_WREG2MEM,
    TAINT_DWREG2MEM,
    TAINT_QWREG2MEM,
    TAINT_LBREG2HWMEM,
    TAINT_LBREG2WMEM,
    TAINT_LBREG2DWMEM,
    TAINT_LBREG2QWMEM,
    TAINT_UBREG2HWMEM,
    TAINT_UBREG2WMEM,
    TAINT_UBREG2DWMEM,
    TAINT_UBREG2QWMEM,
    TAINT_HWREG2WMEM,
    TAINT_HWREG2DWMEM,
    TAINT_HWREG2QWMEM,
    TAINT_WREG2DWMEM,
    TAINT_WREG2QWMEM,
    TAINT_DWREG2QWMEM,
    TAINTX_LBREG2HWMEM,
    TAINTX_LBREG2WMEM,
    TAINTX_LBREG2DWMEM,
    TAINTX_LBREG2QWMEM,
    TAINTX_UBREG2HWMEM,
    TAINTX_UBREG2WMEM,
    TAINTX_UBREG2DWMEM,
    TAINTX_UBREG2QWMEM,
    TAINTX_HWREG2WMEM,
    TAINTX_HWREG2DWMEM,
    TAINTX_HWREG2QWMEM,
    TAINTX_WREG2DWMEM,
    TAINTX_WREG2QWMEM,
    TAINTX_DWREG2QWMEM,
    TAINT_ADD_LBREG2MEM,
    TAINT_ADD_UBREG2MEM,
    TAINT_ADD_HWREG2MEM,
    TAINT_ADD_WREG2MEM,
    TAINT_ADD_DWREG2MEM,
    TAINT_ADD_QWREG2MEM,
    TAINT_ADD_LBREG2HWMEM,
    TAINT_ADD_LBREG2WMEM,
    TAINT_ADD_LBREG2DWMEM,
    TAINT_ADD_LBREG2QWMEM,
    TAINT_ADD_UBREG2HWMEM,
    TAINT_ADD_UBREG2WMEM,
    TAINT_ADD_UBREG2DWMEM,
    TAINT_ADD_UBREG2QWMEM,
    TAINT_ADD_HWREG2WMEM,
    TAINT_ADD_HWREG2DWMEM,
    TAINT_ADD_HWREG2QWMEM,
    TAINT_ADD_WREG2DWMEM,
    TAINT_ADD_WREG2QWMEM,
    TAINT_ADD_DWREG2QWMEM,
    TAINT_REP_LBREG2MEM,
    TAINT_REP_UBREG2MEM,
    TAINT_REP_HWREG2MEM,
    TAINT_REP_WREG2MEM,
    TAINT_REP_DWREG2MEM,
    TAINT_REP_QWREG2MEM,
    // reg2reg
    TAINT_LBREG2LBREG,
    TAINT_UBREG2LBREG,
    TAINT_LBREG2UBREG,
    TAINT_UBREG2UBREG,
    TAINT_WREG2WREG,
    TAINT_HWREG2HWREG,
    TAINT_DWREG2DWREG,
    TAINT_QWREG2QWREG,
    TAINT_LBREG2WREG,
    TAINT_LBREG2HWREG,
    TAINT_LBREG2DWREG,
    TAINT_LBREG2QWREG,
    TAINT_UBREG2HWREG,
    TAINT_UBREG2WREG,
    TAINT_UBREG2DWREG,
    TAINT_UBREG2QWREG,
    TAINT_HWREG2WREG,
    TAINT_HWREG2DWREG,
    TAINT_HWREG2QWREG,
    TAINT_WREG2DWREG,
    TAINT_WREG2QWREG,
    TAINT_DWREG2QWREG,
    TAINTX_LBREG2WREG,
    TAINTX_LBREG2HWREG,
    TAINTX_LBREG2DWREG,
    TAINTX_LBREG2QWREG,
    TAINTX_UBREG2HWREG,
    TAINTX_UBREG2WREG,
    TAINTX_UBREG2DWREG,
    TAINTX_UBREG2QWREG,
    TAINTX_HWREG2WREG,
    TAINTX_HWREG2DWREG,
    TAINTX_HWREG2QWREG,
    TAINTX_WREG2DWREG,
    TAINTX_WREG2QWREG,
    TAINTX_DWREG2QWREG,
    TAINT_ADD_LBREG2LBREG,
    TAINT_ADD_UBREG2LBREG,
    TAINT_ADD_LBREG2UBREG,
    TAINT_ADD_UBREG2UBREG,
    TAINT_ADD_WREG2WREG,
    TAINT_ADD_HWREG2HWREG,
    TAINT_ADD_DWREG2DWREG,
    TAINT_ADD_QWREG2QWREG,
    TAINT_ADD_LBREG2WREG,
    TAINT_ADD_LBREG2HWREG,
    TAINT_ADD_LBREG2DWREG,
    TAINT_ADD_LBREG2QWREG,
    TAINT_ADD_UBREG2HWREG,
    TAINT_ADD_UBREG2WREG,
    TAINT_ADD_UBREG2DWREG,
    TAINT_ADD_UBREG2QWREG,
    TAINT_ADD_HWREG2WREG,
    TAINT_ADD_HWREG2DWREG,
    TAINT_ADD_HWREG2QWREG,
    TAINT_ADD_WREG2DWREG,
    TAINT_ADD_WREG2QWREG,
    TAINT_ADD_DWREG2QWREG,
    TAINT_XCHG_LBREG2LBREG,
    TAINT_XCHG_UBREG2UBREG,
    TAINT_XCHG_UBREG2LBREG,
    TAINT_XCHG_LBREG2UBREG,
    TAINT_XCHG_HWREG2HWREG,
    TAINT_XCHG_WREG2WREG,
    TAINT_XCHG_DWREG2DWREG,
    TAINT_XCHG_QWREG2QWREG,
    TAINT_MASK_REG2REG,
    // mem2mem
    TAINT_MEM2MEM,
    TAINT_MEM2MEM_B,
    TAINT_MEM2MEM_HW,
    TAINT_MEM2MEM_W,
    TAINT_MEM2MEM_DW,
    TAINT_MEM2MEM_QW,
    TAINT_ADD_MEM2MEM_B,
    TAINT_ADD_MEM2MEM_HW,
    TAINT_ADD_MEM2MEM_W,
    TAINT_ADD_MEM2MEM_DW,
    TAINT_ADD_MEM2MEM_QW,
    TAINT_ADD2_BMEMLBREG_HWREG,
    TAINT_ADD2_HWMEMHWREG_2HWREG,
    TAINT_ADD2_WMEMWREG_2WREG,
    TAINT_ADD2_LBREGLBREG_HWREG,
    TAINT_ADD2_HWREGHWREG_2HWREG,
    TAINT_ADD2_WREGWREG_2WREG,
    TAINT_ADD2_HWMEMHWREG_2BREG,
    TAINT_ADD2_WMEMWREG_2HWREG,
    TAINT_ADD3_DWMEM2WREG_2WREG,
    TAINT_ADD2_2HWREG_2BREG,
    TAINT_ADD3_2HWREG_2HWREG,
    TAINT_ADD3_2WREG_2WREG,
    TAINT_IMMVALB2MEM,
    TAINT_IMMVALHW2MEM,
    TAINT_IMMVALW2MEM,
    TAINT_IMMVALDW2MEM,
    TAINT_IMMVALQW2MEM,
    TAINT_ADD_IMMVALB2MEM,
    TAINT_ADD_IMMVALHW2MEM,
    TAINT_ADD_IMMVALW2MEM,
    TAINT_ADD_IMMVALDW2MEM,
    TAINT_ADD_IMMVALQW2MEM,
    // immval2reg
    TAINT_IMMVAL2LBREG,
    TAINT_IMMVAL2UBREG,
    TAINT_IMMVAL2HWREG,
    TAINT_IMMVAL2WREG,
    TAINT_IMMVAL2DWREG,
    TAINT_IMMVAL2QWREG,
    TAINT_ADD_IMMVAL2LBREG,
    TAINT_ADD_IMMVAL2UBREG,
    TAINT_ADD_IMMVAL2HWREG,
    TAINT_ADD_IMMVAL2WREG,
    TAINT_ADD_IMMVAL2DWREG,
    TAINT_ADD_IMMVAL2QWREG,
    TAINT_IMMVAL2FLAG,
    // SPECIAL
    TAINTOP_SYSCALL
} taint_op_t;

static inline const char* taint_op_str(taint_op_t taint_op)
{
    switch(taint_op) {
        case TAINT_MEM2LBREG:
            return "taint_mem2lbreg";
        case TAINT_MEM2UBREG:
            return "taint_mem2ubreg";
        case TAINT_MEM2HWREG:
            return "taint_mem2hwreg";
        case TAINT_MEM2WREG:
            return "taint_mem2wreg";
        case TAINT_MEM2DWREG:
            return "taint_mem2dwreg";
        case TAINT_MEM2QWREG:
            return "taint_mem2qwreg";
        case TAINT_BMEM2HWREG:
            return "taint_bmem2hwreg";
        case TAINT_BMEM2WREG:
            return "taint_bmem2wreg";
        case TAINT_BMEM2DWREG:
            return "taint_bmem2dwreg";
        case TAINT_BMEM2QWREG:
            return "taint_bmem2qwreg";
        case TAINT_HWMEM2WREG:
            return "taint_hwmem2wreg";
        case TAINT_HWMEM2DWREG:
            return "taint_hwmem2dwreg";
        case TAINT_HWMEM2QWREG:
            return "taint_hwmem2qwreg";
        case TAINT_WMEM2DWREG:
            return "taint_wmem2dwreg";
        case TAINT_WMEM2QWREG:
            return "taint_wmem2qwreg";
        case TAINT_DWMEM2QWREG:
            return "taint_dwmem2qwreg";
        case TAINTX_BMEM2HWREG:
            return "taintx_bmem2hwreg";
        case TAINTX_BMEM2WREG:
            return "taintx_bmem2wreg";
        case TAINTX_BMEM2DWREG:
            return "taintx_bmem2dwreg";
        case TAINTX_BMEM2QWREG:
            return "taintx_bmem2qwreg";
        case TAINTX_HWMEM2WREG:
            return "taintx_hwmem2wreg";
        case TAINTX_HWMEM2DWREG:
            return "taintx_hwmem2dwreg";
        case TAINTX_HWMEM2QWREG:
            return "taintx_hwmem2qwreg";
        case TAINTX_WMEM2DWREG:
            return "taintx_wmem2dwreg";
        case TAINTX_WMEM2QWREG:
            return "taintx_wmem2qwreg";
        case TAINTX_DWMEM2QWREG:
            return "taintx_dwmem2qwreg";
        case TAINT_ADD_BMEM2LBREG:
            return "taint_add_bmem2lbreg";
        case TAINT_ADD_BMEM2UBREG:
            return "taint_add_bmem2ubreg";
        case TAINT_ADD_HWMEM2HWREG:
            return "taint_add_hwmem2hwreg";
        case TAINT_ADD_WMEM2WREG:
            return "taint_add_wmem2wreg";
        case TAINT_ADD_DWMEM2DWREG:
            return "taint_add_dwmem2dwreg";
        case TAINT_ADD_QWMEM2QWREG:
            return "taint_add_qwmem2qwreg";
        case TAINT_ADD_BMEM2HWREG:
            return "taint_add_bmem2hwreg";
        case TAINT_ADD_BMEM2WREG:
            return "taint_add_bmem2wreg";
        case TAINT_ADD_BMEM2DWREG:
            return "taint_add_bmem2dwreg";
        case TAINT_ADD_BMEM2QWREG:
            return "taint_add_bmem2qwreg";
        case TAINT_ADD_HWMEM2WREG:
            return "taint_add_hwmem2wreg";
        case TAINT_ADD_HWMEM2DWREG:
            return "taint_add_hwmem2dwreg";
        case TAINT_ADD_HWMEM2QWREG:
            return "taint_add_hwmem2qwreg";
        case TAINT_ADD_WMEM2DWREG:
            return "taint_add_wmem2dwreg";
        case TAINT_ADD_WMEM2QWREG:
            return "taint_add_wmem2qwreg";
        case TAINT_ADD_DWMEM2QWREG:
            return "taint_add_dwmem2qwreg";
        case TAINT_XCHG_BMEM2LBREG:
            return "taint_xchg_bmem2lbreg";
        case TAINT_XCHG_BMEM2UBREG:
            return "taint_xchg_bmem2ubreg";
        case TAINT_XCHG_HWMEM2HWREG:
            return "taint_xchg_hwmem2hwreg";
        case TAINT_XCHG_WMEM2WREG:
            return "taint_xchg_wmem2wreg";
        case TAINT_XCHG_DWMEM2DWREG:
            return "taint_xchg_dwmem2dwreg";
        case TAINT_XCHG_QWMEM2QWREG:
            return "taint_xchg_qwmem2qwreg";
        case TAINT_LBREG2MEM:
            return "taint_lbreg2mem";
        case TAINT_UBREG2MEM:
            return "taint_ubreg2mem";
        case TAINT_HWREG2MEM:
            return "taint_hwreg2mem";
        case TAINT_WREG2MEM:
            return "taint_wreg2mem";
        case TAINT_DWREG2MEM:
            return "taint_dwreg2mem";
        case TAINT_QWREG2MEM:
            return "taint_qwreg2mem";
        case TAINT_LBREG2HWMEM:
            return "taint_lbreg2hwmem";
        case TAINT_LBREG2WMEM:
            return "taint_lbreg2wmem";
        case TAINT_LBREG2DWMEM:
            return "taint_lbreg2dwmem";
        case TAINT_LBREG2QWMEM:
            return "taint_lbreg2qwmem";
        case TAINT_UBREG2HWMEM:
            return "taint_ubreg2hwmem";
        case TAINT_UBREG2WMEM:
            return "taint_ubreg2wmem";
        case TAINT_UBREG2DWMEM:
            return "taint_ubreg2dwmem";
        case TAINT_UBREG2QWMEM:
            return "taint_ubreg2qwmem";
        case TAINT_HWREG2WMEM:
            return "taint_hwreg2wmem";
        case TAINT_HWREG2DWMEM:
            return "taint_hwreg2dwmem";
        case TAINT_HWREG2QWMEM:
            return "taint_hwreg2qwmem";
        case TAINT_WREG2DWMEM:
            return "taint_wreg2dwmem";
        case TAINT_WREG2QWMEM:
            return "taint_wreg2qwmem";
        case TAINT_DWREG2QWMEM:
            return "taint_dwreg2qwmem";
        case TAINTX_LBREG2HWMEM:
            return "taintx_lbreg2hwmem";
        case TAINTX_LBREG2WMEM:
            return "taintx_lbreg2wmem";
        case TAINTX_LBREG2DWMEM:
            return "taintx_lbreg2dwmem";
        case TAINTX_LBREG2QWMEM:
            return "taintx_lbreg2qwmem";
        case TAINTX_UBREG2HWMEM:
            return "taintx_ubreg2hwmem";
        case TAINTX_UBREG2WMEM:
            return "taintx_ubreg2wmem";
        case TAINTX_UBREG2DWMEM:
            return "taintx_ubreg2dwmem";
        case TAINTX_UBREG2QWMEM:
            return "taintx_ubreg2qwmem";
        case TAINTX_HWREG2WMEM:
            return "taintx_hwreg2wmem";
        case TAINTX_HWREG2DWMEM:
            return "taintx_hwreg2dwmem";
        case TAINTX_HWREG2QWMEM:
            return "taintx_hwreg2qwmem";
        case TAINTX_WREG2DWMEM:
            return "taintx_wreg2dwmem";
        case TAINTX_WREG2QWMEM:
            return "taintx_wreg2qwmem";
        case TAINTX_DWREG2QWMEM:
            return "taintx_dwreg2qwmem";
        case TAINT_ADD_LBREG2MEM:
            return "taint_add_lbreg2mem";
        case TAINT_ADD_UBREG2MEM:
            return "taint_add_ubreg2mem";
        case TAINT_ADD_HWREG2MEM:
            return "taint_add_hwreg2mem";
        case TAINT_ADD_WREG2MEM:
            return "taint_add_wreg2mem";
        case TAINT_ADD_DWREG2MEM:
            return "taint_add_dwreg2mem";
        case TAINT_ADD_QWREG2MEM:
            return "taint_add_qwreg2mem";
        case TAINT_ADD_LBREG2HWMEM:
            return "taint_add_lbreg2hwmem";
        case TAINT_ADD_LBREG2WMEM:
            return "taint_add_lbreg2wmem";
        case TAINT_ADD_LBREG2DWMEM:
            return "taint_add_lbreg2dwmem";
        case TAINT_ADD_LBREG2QWMEM:
            return "taint_add_lbreg2qwmem";
        case TAINT_ADD_UBREG2HWMEM:
            return "taint_add_ubreg2hwmem";
        case TAINT_ADD_UBREG2WMEM:
            return "taint_add_ubreg2wmem";
        case TAINT_ADD_UBREG2DWMEM:
            return "taint_add_ubreg2dwmem";
        case TAINT_ADD_UBREG2QWMEM:
            return "taint_add_ubreg2qwmem";
        case TAINT_ADD_HWREG2WMEM:
            return "taint_add_hwreg2wmem";
        case TAINT_ADD_HWREG2DWMEM:
            return "taint_add_hwreg2dwmem";
        case TAINT_ADD_HWREG2QWMEM:
            return "taint_add_hwreg2qwmem";
        case TAINT_ADD_WREG2DWMEM:
            return "taint_add_wreg2dwmem";
        case TAINT_ADD_WREG2QWMEM:
            return "taint_add_wreg2qwmem";
        case TAINT_ADD_DWREG2QWMEM:
            return "taint_add_dwreg2qwmem";
        case TAINT_REP_LBREG2MEM:
            return "taint_rep_lbreg2mem";
        case TAINT_REP_UBREG2MEM:
            return "taint_rep_ubreg2mem";
        case TAINT_REP_HWREG2MEM:
            return "taint_rep_hwreg2mem";
        case TAINT_REP_WREG2MEM:
            return "taint_rep_wreg2mem";
        case TAINT_REP_DWREG2MEM:
            return "taint_rep_dwreg2mem";
        case TAINT_REP_QWREG2MEM:
            return "taint_rep_qwreg2mem";
        case TAINT_LBREG2LBREG:
            return "taint_lbreg2lbreg";
        case TAINT_UBREG2LBREG:
            return "taint_ubreg2lbreg";
        case TAINT_LBREG2UBREG:
            return "taint_lbreg2ubreg";
        case TAINT_UBREG2UBREG:
            return "taint_ubreg2ubreg";
        case TAINT_WREG2WREG:
            return "taint_wreg2wreg";
        case TAINT_HWREG2HWREG:
            return "taint_hwreg2hwreg";
        case TAINT_DWREG2DWREG:
            return "taint_dwreg2dwreg";
        case TAINT_QWREG2QWREG:
            return "taint_qwreg2qwreg";
        case TAINT_LBREG2WREG:
            return "taint_lbreg2wreg";
        case TAINT_LBREG2HWREG:
            return "taint_lbreg2hwreg";
        case TAINT_LBREG2DWREG:
            return "taint_lbreg2dwreg";
        case TAINT_LBREG2QWREG:
            return "taint_lbreg2qwreg";
        case TAINT_UBREG2HWREG:
            return "taint_ubreg2hwreg";
        case TAINT_UBREG2WREG:
            return "taint_ubreg2wreg";
        case TAINT_UBREG2DWREG:
            return "taint_ubreg2dwreg";
        case TAINT_UBREG2QWREG:
            return "taint_ubreg2qwreg";
        case TAINT_HWREG2WREG:
            return "taint_hwreg2wreg";
        case TAINT_HWREG2DWREG:
            return "taint_hwreg2dwreg";
        case TAINT_HWREG2QWREG:
            return "taint_hwreg2qwreg";
        case TAINT_WREG2DWREG:
            return "taint_wreg2dwreg";
        case TAINT_WREG2QWREG:
            return "taint_wreg2qwreg";
        case TAINT_DWREG2QWREG:
            return "taint_dwreg2qwreg";
        case TAINTX_LBREG2WREG:
            return "taintx_lbreg2wreg";
        case TAINTX_LBREG2HWREG:
            return "taintx_lbreg2hwreg";
        case TAINTX_LBREG2DWREG:
            return "taintx_lbreg2dwreg";
        case TAINTX_LBREG2QWREG:
            return "taintx_lbreg2qwreg";
        case TAINTX_UBREG2HWREG:
            return "taintx_ubreg2hwreg";
        case TAINTX_UBREG2WREG:
            return "taintx_ubreg2wreg";
        case TAINTX_UBREG2DWREG:
            return "taintx_ubreg2dwreg";
        case TAINTX_UBREG2QWREG:
            return "taintx_ubreg2qwreg";
        case TAINTX_HWREG2WREG:
            return "taintx_hwreg2wreg";
        case TAINTX_HWREG2DWREG:
            return "taintx_hwreg2dwreg";
        case TAINTX_HWREG2QWREG:
            return "taintx_hwreg2qwreg";
        case TAINTX_WREG2DWREG:
            return "taintx_wreg2dwreg";
        case TAINTX_WREG2QWREG:
            return "taintx_wreg2qwreg";
        case TAINTX_DWREG2QWREG:
            return "taintx_dwreg2qwreg";
        case TAINT_ADD_LBREG2LBREG:
            return "taint_add_lbreg2lbreg";
        case TAINT_ADD_UBREG2LBREG:
            return "taint_add_ubreg2lbreg";
        case TAINT_ADD_LBREG2UBREG:
            return "taint_add_lbreg2ubreg";
        case TAINT_ADD_UBREG2UBREG:
            return "taint_add_ubreg2ubreg";
        case TAINT_ADD_WREG2WREG:
            return "taint_add_wreg2wreg";
        case TAINT_ADD_HWREG2HWREG:
            return "taint_add_hwreg2hwreg";
        case TAINT_ADD_DWREG2DWREG:
            return "taint_add_dwreg2dwreg";
        case TAINT_ADD_QWREG2QWREG:
            return "taint_add_qwreg2qwreg";
        case TAINT_ADD_LBREG2WREG:
            return "taint_add_lbreg2wreg";
        case TAINT_ADD_LBREG2HWREG:
            return "taint_add_lbreg2hwreg";
        case TAINT_ADD_LBREG2DWREG:
            return "taint_add_lbreg2dwreg";
        case TAINT_ADD_LBREG2QWREG:
            return "taint_add_lbreg2qwreg";
        case TAINT_ADD_UBREG2HWREG:
            return "taint_add_ubreg2hwreg";
        case TAINT_ADD_UBREG2WREG:
            return "taint_add_ubreg2wreg";
        case TAINT_ADD_UBREG2DWREG:
            return "taint_add_ubreg2dwreg";
        case TAINT_ADD_UBREG2QWREG:
            return "taint_add_ubreg2qwreg";
        case TAINT_ADD_HWREG2WREG:
            return "taint_add_hwreg2wreg";
        case TAINT_ADD_HWREG2DWREG:
            return "taint_add_hwreg2dwreg";
        case TAINT_ADD_HWREG2QWREG:
            return "taint_add_hwreg2qwreg";
        case TAINT_ADD_WREG2DWREG:
            return "taint_add_wreg2dwreg";
        case TAINT_ADD_WREG2QWREG:
            return "taint_add_wreg2qwreg";
        case TAINT_ADD_DWREG2QWREG:
            return "taint_add_dwreg2qwreg";
        case TAINT_XCHG_LBREG2LBREG:
            return "taint_xchg_lbreg2lbreg";
        case TAINT_XCHG_UBREG2UBREG:
            return "taint_xchg_ubreg2ubreg";
        case TAINT_XCHG_UBREG2LBREG:
            return "taint_xchg_ubreg2lbreg";
        case TAINT_XCHG_LBREG2UBREG:
            return "taint_xchg_lbreg2ubreg";
        case TAINT_XCHG_HWREG2HWREG:
            return "taint_xchg_hwreg2hwreg";
        case TAINT_XCHG_WREG2WREG:
            return "taint_xchg_wreg2wreg";
        case TAINT_XCHG_DWREG2DWREG:
            return "taint_xchg_dwreg2dwreg";
        case TAINT_XCHG_QWREG2QWREG:
            return "taint_xchg_qwreg2qwreg";
	case TAINT_MASK_REG2REG:
	    return "taint_mask_reg2reg";
        case TAINT_MEM2MEM:
            return "taint_mem2mem";
        case TAINT_MEM2MEM_B:
            return "taint_mem2mem_b";
        case TAINT_MEM2MEM_HW:
            return "taint_mem2mem_hw";
        case TAINT_MEM2MEM_W:
            return "taint_mem2mem_w";
        case TAINT_MEM2MEM_DW:
            return "taint_mem2mem_dw";
        case TAINT_MEM2MEM_QW:
            return "taint_mem2mem_qw";
        case TAINT_ADD_MEM2MEM_B:
            return "taint_add_mem2mem_b";
        case TAINT_ADD_MEM2MEM_HW:
            return "taint_add_mem2mem_hw";
        case TAINT_ADD_MEM2MEM_W:
            return "taint_add_mem2mem_w";
        case TAINT_ADD_MEM2MEM_DW:
            return "taint_add_mem2mem_dw";
        case TAINT_ADD_MEM2MEM_QW:
            return "taint_add_mem2mem_qw";
        case TAINT_ADD2_BMEMLBREG_HWREG:
            return "taint_add2_bmemlbreg_hwreg";
        case TAINT_ADD2_HWMEMHWREG_2HWREG:
            return "taint_add2_hwmemhwreg_2hwreg";
        case TAINT_ADD2_WMEMWREG_2WREG:
            return "taint_add2_wmemwreg_2wreg";
        case TAINT_ADD2_LBREGLBREG_HWREG:
            return "taint_add2_lbreglbreg_hwreg";
        case TAINT_ADD2_HWREGHWREG_2HWREG:
            return "taint_add2_hwreghwreg_2hwreg";
        case TAINT_ADD2_WREGWREG_2WREG:
            return "taint_add2_wregwreg_2wreg";
        case TAINT_ADD2_HWMEMHWREG_2BREG:
            return "taint_add2_hwmemhwreg_2breg";
        case TAINT_ADD2_WMEMWREG_2HWREG:
            return "taint_add2_wmemwreg_2hwreg";
        case TAINT_ADD3_DWMEM2WREG_2WREG:
            return "taint_add3_dwmem2wreg_2wreg";
        case TAINT_ADD2_2HWREG_2BREG:
            return "taint_add2_2hwreg_2breg";
        case TAINT_ADD3_2HWREG_2HWREG:
            return "taint_add3_2hwreg_2hwreg";
        case TAINT_ADD3_2WREG_2WREG:
            return "taint_add3_2wreg_2wreg";
        case TAINT_IMMVALB2MEM:
            return "taint_immvalb2mem";
        case TAINT_IMMVALHW2MEM:
            return "taint_immvalhw2mem";
        case TAINT_IMMVALW2MEM:
            return "taint_immvalw2mem";
        case TAINT_IMMVALDW2MEM:
            return "taint_immvaldw2mem";
        case TAINT_IMMVALQW2MEM:
            return "taint_immvalqw2mem";
        case TAINT_ADD_IMMVALB2MEM:
            return "taint_add_immvalb2mem";
        case TAINT_ADD_IMMVALHW2MEM:
            return "taint_add_immvalhw2mem";
        case TAINT_ADD_IMMVALW2MEM:
            return "taint_add_immvalw2mem";
        case TAINT_ADD_IMMVALDW2MEM:
            return "taint_add_immvaldw2mem";
        case TAINT_ADD_IMMVALQW2MEM:
            return "taint_add_immvalqw2mem";
        case TAINT_IMMVAL2LBREG:
            return "taint_immval2lbreg";
        case TAINT_IMMVAL2UBREG:
            return "taint_immval2ubreg";
        case TAINT_IMMVAL2HWREG:
            return "taint_immval2hwreg";
        case TAINT_IMMVAL2WREG:
            return "taint_immval2wreg";
        case TAINT_IMMVAL2DWREG:
            return "taint_immval2dwreg";
        case TAINT_IMMVAL2QWREG:
            return "taint_immval2qwreg";
        case TAINT_ADD_IMMVAL2LBREG:
            return "taint_add_immval2lbreg";
        case TAINT_ADD_IMMVAL2UBREG:
            return "taint_add_immval2ubreg";
        case TAINT_ADD_IMMVAL2HWREG:
            return "taint_add_immval2hwreg";
        case TAINT_ADD_IMMVAL2WREG:
            return "taint_add_immval2wreg";
        case TAINT_ADD_IMMVAL2DWREG:
            return "taint_add_immval2dwreg";
        case TAINT_ADD_IMMVAL2QWREG:
            return "taint_add_immval2qwreg";
        case TAINT_IMMVAL2FLAG:
            return "taint_immval2flaG";
        default:
            return "UNKNOWN?!";
    }
}

static inline int is_dst_reg(taint_op_t taint_op)
{
    return (
            taint_op == TAINT_MEM2LBREG ||
            taint_op == TAINT_MEM2UBREG ||
            taint_op == TAINT_MEM2HWREG ||
            taint_op == TAINT_MEM2WREG ||
            taint_op == TAINT_MEM2DWREG ||
            taint_op == TAINT_MEM2QWREG ||
            taint_op == TAINT_BMEM2HWREG ||
            taint_op == TAINT_BMEM2WREG ||
            taint_op == TAINT_BMEM2DWREG ||
            taint_op == TAINT_BMEM2QWREG ||
            taint_op == TAINT_HWMEM2WREG ||
            taint_op == TAINT_HWMEM2DWREG ||
            taint_op == TAINT_HWMEM2QWREG ||
            taint_op == TAINT_WMEM2DWREG ||
            taint_op == TAINT_WMEM2QWREG ||
            taint_op == TAINT_DWMEM2QWREG ||
            taint_op == TAINTX_BMEM2HWREG ||
            taint_op == TAINTX_BMEM2WREG ||
            taint_op == TAINTX_BMEM2DWREG ||
            taint_op == TAINTX_BMEM2QWREG ||
            taint_op == TAINTX_HWMEM2WREG ||
            taint_op == TAINTX_HWMEM2DWREG ||
            taint_op == TAINTX_HWMEM2QWREG ||
            taint_op == TAINTX_WMEM2DWREG ||
            taint_op == TAINTX_WMEM2QWREG ||
            taint_op == TAINTX_DWMEM2QWREG ||
            taint_op == TAINT_ADD_BMEM2LBREG ||
            taint_op == TAINT_ADD_BMEM2UBREG ||
            taint_op == TAINT_ADD_HWMEM2HWREG ||
            taint_op == TAINT_ADD_WMEM2WREG ||
            taint_op == TAINT_ADD_DWMEM2DWREG ||
            taint_op == TAINT_ADD_QWMEM2QWREG ||
            taint_op == TAINT_ADD_BMEM2HWREG ||
            taint_op == TAINT_ADD_BMEM2WREG ||
            taint_op == TAINT_ADD_BMEM2DWREG ||
            taint_op == TAINT_ADD_BMEM2QWREG ||
            taint_op == TAINT_ADD_HWMEM2WREG ||
            taint_op == TAINT_ADD_HWMEM2DWREG ||
            taint_op == TAINT_ADD_HWMEM2QWREG ||
            taint_op == TAINT_ADD_WMEM2DWREG ||
            taint_op == TAINT_ADD_WMEM2QWREG ||
            taint_op == TAINT_ADD_DWMEM2QWREG ||
            taint_op == TAINT_XCHG_BMEM2LBREG ||
            taint_op == TAINT_XCHG_BMEM2UBREG ||
            taint_op == TAINT_XCHG_HWMEM2HWREG ||
            taint_op == TAINT_XCHG_WMEM2WREG ||
            taint_op == TAINT_XCHG_DWMEM2DWREG ||
            taint_op == TAINT_XCHG_QWMEM2QWREG ||
            taint_op == TAINT_LBREG2LBREG ||
            taint_op == TAINT_UBREG2LBREG ||
            taint_op == TAINT_LBREG2UBREG ||
            taint_op == TAINT_UBREG2UBREG ||
            taint_op == TAINT_WREG2WREG ||
            taint_op == TAINT_HWREG2HWREG ||
            taint_op == TAINT_DWREG2DWREG ||
            taint_op == TAINT_QWREG2QWREG ||
            taint_op == TAINT_LBREG2WREG ||
            taint_op == TAINT_LBREG2HWREG ||
            taint_op == TAINT_LBREG2DWREG ||
            taint_op == TAINT_LBREG2QWREG ||
            taint_op == TAINT_UBREG2HWREG ||
            taint_op == TAINT_UBREG2WREG ||
            taint_op == TAINT_UBREG2DWREG ||
            taint_op == TAINT_UBREG2QWREG ||
            taint_op == TAINT_HWREG2WREG ||
            taint_op == TAINT_HWREG2DWREG ||
            taint_op == TAINT_HWREG2QWREG ||
            taint_op == TAINT_WREG2DWREG ||
            taint_op == TAINT_WREG2QWREG ||
            taint_op == TAINT_DWREG2QWREG ||
            taint_op == TAINTX_LBREG2WREG ||
            taint_op == TAINTX_LBREG2HWREG ||
            taint_op == TAINTX_LBREG2DWREG ||
            taint_op == TAINTX_LBREG2QWREG ||
            taint_op == TAINTX_UBREG2HWREG ||
            taint_op == TAINTX_UBREG2WREG ||
            taint_op == TAINTX_UBREG2DWREG ||
            taint_op == TAINTX_UBREG2QWREG ||
            taint_op == TAINTX_HWREG2WREG ||
            taint_op == TAINTX_HWREG2DWREG ||
            taint_op == TAINTX_HWREG2QWREG ||
            taint_op == TAINTX_WREG2DWREG ||
            taint_op == TAINTX_WREG2QWREG ||
            taint_op == TAINTX_DWREG2QWREG ||
            taint_op == TAINT_ADD_LBREG2LBREG ||
            taint_op == TAINT_ADD_UBREG2LBREG ||
            taint_op == TAINT_ADD_LBREG2UBREG ||
            taint_op == TAINT_ADD_UBREG2UBREG ||
            taint_op == TAINT_ADD_WREG2WREG ||
            taint_op == TAINT_ADD_HWREG2HWREG ||
            taint_op == TAINT_ADD_DWREG2DWREG ||
            taint_op == TAINT_ADD_QWREG2QWREG ||
            taint_op == TAINT_ADD_LBREG2WREG ||
            taint_op == TAINT_ADD_LBREG2HWREG ||
            taint_op == TAINT_ADD_LBREG2DWREG ||
            taint_op == TAINT_ADD_LBREG2QWREG ||
            taint_op == TAINT_ADD_UBREG2HWREG ||
            taint_op == TAINT_ADD_UBREG2WREG ||
            taint_op == TAINT_ADD_UBREG2DWREG ||
            taint_op == TAINT_ADD_UBREG2QWREG ||
            taint_op == TAINT_ADD_HWREG2WREG ||
            taint_op == TAINT_ADD_HWREG2DWREG ||
            taint_op == TAINT_ADD_HWREG2QWREG ||
            taint_op == TAINT_ADD_WREG2DWREG ||
            taint_op == TAINT_ADD_WREG2QWREG ||
            taint_op == TAINT_ADD_DWREG2QWREG ||
            taint_op == TAINT_XCHG_LBREG2LBREG ||
            taint_op == TAINT_XCHG_UBREG2UBREG ||
            taint_op == TAINT_XCHG_UBREG2LBREG ||
            taint_op == TAINT_XCHG_LBREG2UBREG ||
            taint_op == TAINT_XCHG_HWREG2HWREG ||
            taint_op == TAINT_XCHG_WREG2WREG ||
            taint_op == TAINT_XCHG_DWREG2DWREG ||
            taint_op == TAINT_XCHG_QWREG2QWREG ||
	    taint_op == TAINT_MASK_REG2REG ||
            taint_op == TAINT_IMMVAL2LBREG ||
            taint_op == TAINT_IMMVAL2UBREG ||
            taint_op == TAINT_IMMVAL2HWREG ||
            taint_op == TAINT_IMMVAL2WREG ||
            taint_op == TAINT_IMMVAL2DWREG ||
            taint_op == TAINT_IMMVAL2QWREG ||
            taint_op == TAINT_ADD_IMMVAL2LBREG ||
            taint_op == TAINT_ADD_IMMVAL2UBREG ||
            taint_op == TAINT_ADD_IMMVAL2HWREG ||
            taint_op == TAINT_ADD_IMMVAL2WREG ||
            taint_op == TAINT_ADD_IMMVAL2DWREG ||
            taint_op == TAINT_ADD_IMMVAL2QWREG
        );
}

static inline int is_src_reg(taint_op_t taint_op)
{
    return (
            taint_op == TAINT_LBREG2MEM ||
            taint_op == TAINT_UBREG2MEM ||
            taint_op == TAINT_HWREG2MEM ||
            taint_op == TAINT_WREG2MEM ||
            taint_op == TAINT_DWREG2MEM ||
            taint_op == TAINT_QWREG2MEM ||
            taint_op == TAINT_LBREG2HWMEM ||
            taint_op == TAINT_LBREG2WMEM ||
            taint_op == TAINT_LBREG2DWMEM ||
            taint_op == TAINT_LBREG2QWMEM ||
            taint_op == TAINT_UBREG2HWMEM ||
            taint_op == TAINT_UBREG2WMEM ||
            taint_op == TAINT_UBREG2DWMEM ||
            taint_op == TAINT_UBREG2QWMEM ||
            taint_op == TAINT_HWREG2WMEM ||
            taint_op == TAINT_HWREG2DWMEM ||
            taint_op == TAINT_HWREG2QWMEM ||
            taint_op == TAINT_WREG2DWMEM ||
            taint_op == TAINT_WREG2QWMEM ||
            taint_op == TAINT_DWREG2QWMEM ||
            taint_op == TAINTX_LBREG2HWMEM ||
            taint_op == TAINTX_LBREG2WMEM ||
            taint_op == TAINTX_LBREG2DWMEM ||
            taint_op == TAINTX_LBREG2QWMEM ||
            taint_op == TAINTX_UBREG2HWMEM ||
            taint_op == TAINTX_UBREG2WMEM ||
            taint_op == TAINTX_UBREG2DWMEM ||
            taint_op == TAINTX_UBREG2QWMEM ||
            taint_op == TAINTX_HWREG2WMEM ||
            taint_op == TAINTX_HWREG2DWMEM ||
            taint_op == TAINTX_HWREG2QWMEM ||
            taint_op == TAINTX_WREG2DWMEM ||
            taint_op == TAINTX_WREG2QWMEM ||
            taint_op == TAINTX_DWREG2QWMEM ||
            taint_op == TAINT_ADD_LBREG2MEM ||
            taint_op == TAINT_ADD_UBREG2MEM ||
            taint_op == TAINT_ADD_HWREG2MEM ||
            taint_op == TAINT_ADD_WREG2MEM ||
            taint_op == TAINT_ADD_DWREG2MEM ||
            taint_op == TAINT_ADD_QWREG2MEM ||
            taint_op == TAINT_ADD_LBREG2HWMEM ||
            taint_op == TAINT_ADD_LBREG2WMEM ||
            taint_op == TAINT_ADD_LBREG2DWMEM ||
            taint_op == TAINT_ADD_LBREG2QWMEM ||
            taint_op == TAINT_ADD_UBREG2HWMEM ||
            taint_op == TAINT_ADD_UBREG2WMEM ||
            taint_op == TAINT_ADD_UBREG2DWMEM ||
            taint_op == TAINT_ADD_UBREG2QWMEM ||
            taint_op == TAINT_ADD_HWREG2WMEM ||
            taint_op == TAINT_ADD_HWREG2DWMEM ||
            taint_op == TAINT_ADD_HWREG2QWMEM ||
            taint_op == TAINT_ADD_WREG2DWMEM ||
            taint_op == TAINT_ADD_WREG2QWMEM ||
            taint_op == TAINT_ADD_DWREG2QWMEM ||
            taint_op == TAINT_REP_LBREG2MEM ||
            taint_op == TAINT_REP_UBREG2MEM ||
            taint_op == TAINT_REP_HWREG2MEM ||
            taint_op == TAINT_REP_WREG2MEM ||
            taint_op == TAINT_REP_DWREG2MEM ||
            taint_op == TAINT_REP_QWREG2MEM ||
            taint_op == TAINT_LBREG2LBREG ||
            taint_op == TAINT_UBREG2LBREG ||
            taint_op == TAINT_LBREG2UBREG ||
            taint_op == TAINT_UBREG2UBREG ||
            taint_op == TAINT_WREG2WREG ||
            taint_op == TAINT_HWREG2HWREG ||
            taint_op == TAINT_DWREG2DWREG ||
            taint_op == TAINT_QWREG2QWREG ||
            taint_op == TAINT_LBREG2WREG ||
            taint_op == TAINT_LBREG2HWREG ||
            taint_op == TAINT_LBREG2DWREG ||
            taint_op == TAINT_LBREG2QWREG ||
            taint_op == TAINT_UBREG2HWREG ||
            taint_op == TAINT_UBREG2WREG ||
            taint_op == TAINT_UBREG2DWREG ||
            taint_op == TAINT_UBREG2QWREG ||
            taint_op == TAINT_HWREG2WREG ||
            taint_op == TAINT_HWREG2DWREG ||
            taint_op == TAINT_HWREG2QWREG ||
            taint_op == TAINT_WREG2DWREG ||
            taint_op == TAINT_WREG2QWREG ||
            taint_op == TAINT_DWREG2QWREG ||
            taint_op == TAINTX_LBREG2WREG ||
            taint_op == TAINTX_LBREG2HWREG ||
            taint_op == TAINTX_LBREG2DWREG ||
            taint_op == TAINTX_LBREG2QWREG ||
            taint_op == TAINTX_UBREG2HWREG ||
            taint_op == TAINTX_UBREG2WREG ||
            taint_op == TAINTX_UBREG2DWREG ||
            taint_op == TAINTX_UBREG2QWREG ||
            taint_op == TAINTX_HWREG2WREG ||
            taint_op == TAINTX_HWREG2DWREG ||
            taint_op == TAINTX_HWREG2QWREG ||
            taint_op == TAINTX_WREG2DWREG ||
            taint_op == TAINTX_WREG2QWREG ||
            taint_op == TAINTX_DWREG2QWREG ||
            taint_op == TAINT_ADD_LBREG2LBREG ||
            taint_op == TAINT_ADD_UBREG2LBREG ||
            taint_op == TAINT_ADD_LBREG2UBREG ||
            taint_op == TAINT_ADD_UBREG2UBREG ||
            taint_op == TAINT_ADD_WREG2WREG ||
            taint_op == TAINT_ADD_HWREG2HWREG ||
            taint_op == TAINT_ADD_DWREG2DWREG ||
            taint_op == TAINT_ADD_QWREG2QWREG ||
            taint_op == TAINT_ADD_LBREG2WREG ||
            taint_op == TAINT_ADD_LBREG2HWREG ||
            taint_op == TAINT_ADD_LBREG2DWREG ||
            taint_op == TAINT_ADD_LBREG2QWREG ||
            taint_op == TAINT_ADD_UBREG2HWREG ||
            taint_op == TAINT_ADD_UBREG2WREG ||
            taint_op == TAINT_ADD_UBREG2DWREG ||
            taint_op == TAINT_ADD_UBREG2QWREG ||
            taint_op == TAINT_ADD_HWREG2WREG ||
            taint_op == TAINT_ADD_HWREG2DWREG ||
            taint_op == TAINT_ADD_HWREG2QWREG ||
            taint_op == TAINT_ADD_WREG2DWREG ||
            taint_op == TAINT_ADD_WREG2QWREG ||
            taint_op == TAINT_ADD_DWREG2QWREG ||
            taint_op == TAINT_XCHG_LBREG2LBREG ||
            taint_op == TAINT_XCHG_UBREG2UBREG ||
            taint_op == TAINT_XCHG_UBREG2LBREG ||
            taint_op == TAINT_XCHG_LBREG2UBREG ||
            taint_op == TAINT_XCHG_HWREG2HWREG ||
            taint_op == TAINT_XCHG_WREG2WREG ||
            taint_op == TAINT_XCHG_DWREG2DWREG ||
            taint_op == TAINT_XCHG_QWREG2QWREG ||
	    taint_op == TAINT_MASK_REG2REG
        );
}

static inline int is_dst_mem(taint_op_t taint_op)
{
    return (
    taint_op == TAINT_LBREG2MEM ||
    taint_op == TAINT_UBREG2MEM ||
    taint_op == TAINT_HWREG2MEM ||
    taint_op == TAINT_WREG2MEM ||
    taint_op == TAINT_DWREG2MEM ||
    taint_op == TAINT_QWREG2MEM ||
    taint_op == TAINT_LBREG2HWMEM ||
    taint_op == TAINT_LBREG2WMEM ||
    taint_op == TAINT_LBREG2DWMEM ||
    taint_op == TAINT_LBREG2QWMEM ||
    taint_op == TAINT_UBREG2HWMEM ||
    taint_op == TAINT_UBREG2WMEM ||
    taint_op == TAINT_UBREG2DWMEM ||
    taint_op == TAINT_UBREG2QWMEM ||
    taint_op == TAINT_HWREG2WMEM ||
    taint_op == TAINT_HWREG2DWMEM ||
    taint_op == TAINT_HWREG2QWMEM ||
    taint_op == TAINT_WREG2DWMEM ||
    taint_op == TAINT_WREG2QWMEM ||
    taint_op == TAINT_DWREG2QWMEM ||
    taint_op == TAINTX_LBREG2HWMEM ||
    taint_op == TAINTX_LBREG2WMEM ||
    taint_op == TAINTX_LBREG2DWMEM ||
    taint_op == TAINTX_LBREG2QWMEM ||
    taint_op == TAINTX_UBREG2HWMEM ||
    taint_op == TAINTX_UBREG2WMEM ||
    taint_op == TAINTX_UBREG2DWMEM ||
    taint_op == TAINTX_UBREG2QWMEM ||
    taint_op == TAINTX_HWREG2WMEM ||
    taint_op == TAINTX_HWREG2DWMEM ||
    taint_op == TAINTX_HWREG2QWMEM ||
    taint_op == TAINTX_WREG2DWMEM ||
    taint_op == TAINTX_WREG2QWMEM ||
    taint_op == TAINTX_DWREG2QWMEM ||
    taint_op == TAINT_ADD_LBREG2MEM ||
    taint_op == TAINT_ADD_UBREG2MEM ||
    taint_op == TAINT_ADD_HWREG2MEM ||
    taint_op == TAINT_ADD_WREG2MEM ||
    taint_op == TAINT_ADD_DWREG2MEM ||
    taint_op == TAINT_ADD_QWREG2MEM ||
    taint_op == TAINT_ADD_LBREG2HWMEM ||
    taint_op == TAINT_ADD_LBREG2WMEM ||
    taint_op == TAINT_ADD_LBREG2DWMEM ||
    taint_op == TAINT_ADD_LBREG2QWMEM ||
    taint_op == TAINT_ADD_UBREG2HWMEM ||
    taint_op == TAINT_ADD_UBREG2WMEM ||
    taint_op == TAINT_ADD_UBREG2DWMEM ||
    taint_op == TAINT_ADD_UBREG2QWMEM ||
    taint_op == TAINT_ADD_HWREG2WMEM ||
    taint_op == TAINT_ADD_HWREG2DWMEM ||
    taint_op == TAINT_ADD_HWREG2QWMEM ||
    taint_op == TAINT_ADD_WREG2DWMEM ||
    taint_op == TAINT_ADD_WREG2QWMEM ||
    taint_op == TAINT_ADD_DWREG2QWMEM ||
    taint_op == TAINT_REP_LBREG2MEM ||
    taint_op == TAINT_REP_UBREG2MEM ||
    taint_op == TAINT_REP_HWREG2MEM ||
    taint_op == TAINT_REP_WREG2MEM ||
    taint_op == TAINT_REP_DWREG2MEM ||
    taint_op == TAINT_REP_QWREG2MEM ||
    taint_op == TAINT_MEM2MEM ||
    taint_op == TAINT_MEM2MEM_B ||
    taint_op == TAINT_MEM2MEM_HW ||
    taint_op == TAINT_MEM2MEM_W ||
    taint_op == TAINT_MEM2MEM_DW ||
    taint_op == TAINT_MEM2MEM_QW ||
    taint_op == TAINT_ADD_MEM2MEM_B ||
    taint_op == TAINT_ADD_MEM2MEM_HW ||
    taint_op == TAINT_ADD_MEM2MEM_W ||
    taint_op == TAINT_ADD_MEM2MEM_DW ||
    taint_op == TAINT_ADD_MEM2MEM_QW
);


}

static inline int is_src_mem(taint_op_t taint_op)
{
    return (
            taint_op == TAINT_MEM2LBREG ||
            taint_op == TAINT_MEM2UBREG ||
            taint_op == TAINT_MEM2HWREG ||
            taint_op == TAINT_MEM2WREG ||
            taint_op == TAINT_MEM2DWREG ||
            taint_op == TAINT_MEM2QWREG ||
            taint_op == TAINT_BMEM2HWREG ||
            taint_op == TAINT_BMEM2WREG ||
            taint_op == TAINT_BMEM2DWREG ||
            taint_op == TAINT_BMEM2QWREG ||
            taint_op == TAINT_HWMEM2WREG ||
            taint_op == TAINT_HWMEM2DWREG ||
            taint_op == TAINT_HWMEM2QWREG ||
            taint_op == TAINT_WMEM2DWREG ||
            taint_op == TAINT_WMEM2QWREG ||
            taint_op == TAINT_DWMEM2QWREG ||
            taint_op == TAINTX_BMEM2HWREG ||
            taint_op == TAINTX_BMEM2WREG ||
            taint_op == TAINTX_BMEM2DWREG ||
            taint_op == TAINTX_BMEM2QWREG ||
            taint_op == TAINTX_HWMEM2WREG ||
            taint_op == TAINTX_HWMEM2DWREG ||
            taint_op == TAINTX_HWMEM2QWREG ||
            taint_op == TAINTX_WMEM2DWREG ||
            taint_op == TAINTX_WMEM2QWREG ||
            taint_op == TAINTX_DWMEM2QWREG ||
            taint_op == TAINT_ADD_BMEM2LBREG ||
            taint_op == TAINT_ADD_BMEM2UBREG ||
            taint_op == TAINT_ADD_HWMEM2HWREG ||
            taint_op == TAINT_ADD_WMEM2WREG ||
            taint_op == TAINT_ADD_DWMEM2DWREG ||
            taint_op == TAINT_ADD_QWMEM2QWREG ||
            taint_op == TAINT_ADD_BMEM2HWREG ||
            taint_op == TAINT_ADD_BMEM2WREG ||
            taint_op == TAINT_ADD_BMEM2DWREG ||
            taint_op == TAINT_ADD_BMEM2QWREG ||
            taint_op == TAINT_ADD_HWMEM2WREG ||
            taint_op == TAINT_ADD_HWMEM2DWREG ||
            taint_op == TAINT_ADD_HWMEM2QWREG ||
            taint_op == TAINT_ADD_WMEM2DWREG ||
            taint_op == TAINT_ADD_WMEM2QWREG ||
            taint_op == TAINT_ADD_DWMEM2QWREG ||
            taint_op == TAINT_XCHG_BMEM2LBREG ||
            taint_op == TAINT_XCHG_BMEM2UBREG ||
            taint_op == TAINT_XCHG_HWMEM2HWREG ||
            taint_op == TAINT_XCHG_WMEM2WREG ||
            taint_op == TAINT_XCHG_DWMEM2DWREG ||
            taint_op == TAINT_XCHG_QWMEM2QWREG ||
            taint_op == TAINT_MEM2MEM ||
            taint_op == TAINT_MEM2MEM_B ||
            taint_op == TAINT_MEM2MEM_HW ||
            taint_op == TAINT_MEM2MEM_W ||
            taint_op == TAINT_MEM2MEM_DW ||
            taint_op == TAINT_MEM2MEM_QW ||
            taint_op == TAINT_ADD_MEM2MEM_B ||
            taint_op == TAINT_ADD_MEM2MEM_HW ||
            taint_op == TAINT_ADD_MEM2MEM_W ||
            taint_op == TAINT_ADD_MEM2MEM_DW ||
            taint_op == TAINT_ADD_MEM2MEM_QW
        );
}

static inline int get_dst_size(taint_op_t taint_op)
{
    if (
        taint_op == TAINT_MEM2LBREG ||
        taint_op == TAINT_MEM2UBREG ||
        taint_op == TAINT_ADD_BMEM2LBREG ||
        taint_op == TAINT_ADD_BMEM2UBREG ||
        taint_op == TAINT_XCHG_BMEM2LBREG ||
        taint_op == TAINT_XCHG_BMEM2UBREG ||
        taint_op == TAINT_LBREG2MEM ||
        taint_op == TAINT_UBREG2MEM ||
        taint_op == TAINT_ADD_LBREG2MEM ||
        taint_op == TAINT_ADD_UBREG2MEM ||
        taint_op == TAINT_REP_LBREG2MEM ||
        taint_op == TAINT_REP_UBREG2MEM ||
        taint_op == TAINT_LBREG2LBREG ||
        taint_op == TAINT_UBREG2LBREG ||
        taint_op == TAINT_LBREG2UBREG ||
        taint_op == TAINT_UBREG2UBREG ||
        taint_op == TAINT_ADD_LBREG2LBREG ||
        taint_op == TAINT_ADD_UBREG2LBREG ||
        taint_op == TAINT_ADD_LBREG2UBREG ||
        taint_op == TAINT_ADD_UBREG2UBREG ||
        taint_op == TAINT_XCHG_LBREG2LBREG ||
        taint_op == TAINT_XCHG_UBREG2UBREG ||
        taint_op == TAINT_XCHG_UBREG2LBREG ||
        taint_op == TAINT_XCHG_LBREG2UBREG ||
        taint_op == TAINT_MEM2MEM_B ||
        taint_op == TAINT_ADD_MEM2MEM_B ||
        taint_op == TAINT_IMMVALB2MEM ||
        taint_op == TAINT_ADD_IMMVALB2MEM ||
        taint_op == TAINT_IMMVAL2LBREG
        ) {
        return 1;
    } else if (
                taint_op == TAINT_HWREG2MEM ||
		taint_op == TAINT_ADD_HWREG2MEM ||
                taint_op == TAINT_MEM2HWREG ||
                taint_op == TAINT_BMEM2HWREG ||
                taint_op == TAINTX_BMEM2HWREG ||
                taint_op == TAINT_ADD_HWMEM2HWREG ||
                taint_op == TAINT_ADD_BMEM2HWREG ||
                taint_op == TAINT_XCHG_HWMEM2HWREG ||
                taint_op == TAINT_LBREG2HWMEM ||
                taint_op == TAINT_UBREG2HWMEM ||
                taint_op == TAINTX_LBREG2HWMEM ||
                taint_op == TAINTX_UBREG2HWMEM ||
                taint_op == TAINT_ADD_LBREG2HWMEM ||
                taint_op == TAINT_ADD_UBREG2HWMEM ||
                taint_op == TAINT_REP_HWREG2MEM ||
                taint_op == TAINT_HWREG2HWREG ||
                taint_op == TAINT_LBREG2HWREG ||
                taint_op == TAINT_UBREG2HWREG ||
                taint_op == TAINTX_LBREG2HWREG ||
                taint_op == TAINTX_UBREG2HWREG ||
                taint_op == TAINT_ADD_HWREG2HWREG ||
                taint_op == TAINT_ADD_LBREG2HWREG ||
                taint_op == TAINT_ADD_UBREG2HWREG ||
                taint_op == TAINT_XCHG_HWREG2HWREG ||
                taint_op == TAINT_MEM2MEM_HW ||
                taint_op == TAINT_ADD_MEM2MEM_HW ||
                taint_op == TAINT_IMMVALHW2MEM ||
                taint_op == TAINT_ADD_IMMVALHW2MEM ||
                taint_op == TAINT_IMMVAL2HWREG ||
                taint_op == TAINT_ADD_IMMVAL2HWREG
            ) {
        return 2;
    } else if (
                taint_op == TAINT_MEM2WREG ||
                taint_op == TAINT_BMEM2WREG ||
                taint_op == TAINTX_BMEM2WREG ||
                taint_op == TAINT_HWMEM2WREG ||
                taint_op == TAINT_WMEM2DWREG ||
                taint_op == TAINTX_HWMEM2WREG ||
                taint_op == TAINT_ADD_WMEM2WREG ||
                taint_op == TAINT_ADD_BMEM2WREG ||
                taint_op == TAINT_ADD_HWMEM2WREG ||
                taint_op == TAINT_XCHG_WMEM2WREG ||
                taint_op == TAINT_WREG2MEM ||
                taint_op == TAINT_LBREG2WMEM ||
                taint_op == TAINT_UBREG2WMEM ||
                taint_op == TAINT_HWREG2WMEM ||
                taint_op == TAINTX_LBREG2WMEM ||
                taint_op == TAINTX_UBREG2WMEM ||
                taint_op == TAINTX_HWREG2WMEM ||
                taint_op == TAINT_ADD_WREG2MEM ||
                taint_op == TAINT_ADD_LBREG2WMEM ||
                taint_op == TAINT_ADD_UBREG2WMEM ||
                taint_op == TAINT_ADD_HWREG2WMEM ||
                taint_op == TAINT_REP_WREG2MEM ||
                taint_op == TAINT_WREG2WREG ||
                taint_op == TAINT_LBREG2WREG ||
                taint_op == TAINT_UBREG2WREG ||
                taint_op == TAINT_HWREG2WREG ||
                taint_op == TAINTX_LBREG2WREG ||
                taint_op == TAINTX_UBREG2WREG ||
                taint_op == TAINTX_HWREG2WREG ||
                taint_op == TAINT_ADD_WREG2WREG ||
                taint_op == TAINT_ADD_LBREG2WREG ||
                taint_op == TAINT_ADD_UBREG2WREG ||
                taint_op == TAINT_ADD_HWREG2WREG ||
                taint_op == TAINT_XCHG_WREG2WREG ||
                taint_op == TAINT_MEM2MEM_W ||
                taint_op == TAINT_ADD_MEM2MEM_W ||
                taint_op == TAINT_IMMVALW2MEM ||
                taint_op == TAINT_ADD_IMMVALW2MEM ||
                taint_op == TAINT_IMMVAL2WREG ||
                taint_op == TAINT_ADD_IMMVAL2WREG ||
		taint_op == TAINT_MASK_REG2REG
            ) {
        return 4;
    } else if (
                taint_op == TAINT_MEM2DWREG ||
                taint_op == TAINT_BMEM2DWREG ||
                taint_op == TAINT_HWMEM2DWREG ||
                taint_op == TAINT_WMEM2DWREG ||
                taint_op == TAINTX_BMEM2DWREG ||
                taint_op == TAINTX_HWMEM2DWREG ||
                taint_op == TAINTX_WMEM2DWREG ||
                taint_op == TAINT_ADD_DWMEM2DWREG ||
                taint_op == TAINT_ADD_BMEM2DWREG ||
                taint_op == TAINT_ADD_HWMEM2DWREG ||
                taint_op == TAINT_ADD_WMEM2DWREG ||
                taint_op == TAINT_XCHG_DWMEM2DWREG ||
                taint_op == TAINT_DWREG2MEM ||
                taint_op == TAINT_LBREG2DWMEM ||
                taint_op == TAINT_UBREG2DWMEM ||
                taint_op == TAINT_HWREG2DWMEM ||
                taint_op == TAINT_WREG2DWMEM ||
                taint_op == TAINTX_LBREG2DWMEM ||
                taint_op == TAINTX_UBREG2DWMEM ||
                taint_op == TAINTX_HWREG2DWMEM ||
                taint_op == TAINTX_WREG2DWMEM ||
                taint_op == TAINT_ADD_LBREG2DWMEM ||
                taint_op == TAINT_ADD_UBREG2DWMEM ||
                taint_op == TAINT_ADD_HWREG2DWMEM ||
                taint_op == TAINT_ADD_WREG2DWMEM ||
                taint_op == TAINT_REP_DWREG2MEM ||
                taint_op == TAINT_DWREG2DWREG ||
                taint_op == TAINT_LBREG2DWREG ||
                taint_op == TAINT_UBREG2DWREG ||
                taint_op == TAINT_HWREG2DWREG ||
                taint_op == TAINT_WREG2DWREG ||
                taint_op == TAINTX_LBREG2DWREG ||
                taint_op == TAINTX_UBREG2DWREG ||
                taint_op == TAINTX_HWREG2DWREG ||
                taint_op == TAINTX_WREG2DWREG ||
                taint_op == TAINT_ADD_DWREG2DWREG ||
                taint_op == TAINT_ADD_LBREG2DWREG ||
                taint_op == TAINT_ADD_UBREG2DWREG ||
                taint_op == TAINT_ADD_HWREG2DWREG ||
                taint_op == TAINT_ADD_WREG2DWREG ||
                taint_op == TAINT_XCHG_DWREG2DWREG ||
                taint_op == TAINT_MEM2MEM_DW ||
                taint_op == TAINT_ADD_MEM2MEM_DW ||
                taint_op == TAINT_IMMVALDW2MEM ||
                taint_op == TAINT_ADD_IMMVALDW2MEM ||
                taint_op == TAINT_IMMVAL2DWREG ||
                taint_op == TAINT_ADD_IMMVAL2DWREG
            ) {
        return 8;
    } else if (
                taint_op == TAINT_MEM2QWREG ||
                taint_op == TAINT_BMEM2QWREG ||
                taint_op == TAINT_HWMEM2QWREG ||
                taint_op == TAINT_WMEM2QWREG ||
                taint_op == TAINT_DWMEM2QWREG ||
                taint_op == TAINTX_BMEM2QWREG ||
                taint_op == TAINTX_HWMEM2QWREG ||
                taint_op == TAINTX_WMEM2QWREG ||
                taint_op == TAINTX_DWMEM2QWREG ||
                taint_op == TAINT_ADD_QWMEM2QWREG ||
                taint_op == TAINT_ADD_BMEM2QWREG ||
                taint_op == TAINT_ADD_HWMEM2QWREG ||
                taint_op == TAINT_ADD_WMEM2QWREG ||
                taint_op == TAINT_ADD_DWMEM2QWREG ||
                taint_op == TAINT_XCHG_QWMEM2QWREG ||
                taint_op == TAINT_QWREG2MEM ||
                taint_op == TAINT_LBREG2QWMEM ||
                taint_op == TAINT_UBREG2QWMEM ||
                taint_op == TAINT_HWREG2QWMEM ||
                taint_op == TAINT_WREG2QWMEM ||
                taint_op == TAINT_DWREG2QWMEM ||
                taint_op == TAINTX_LBREG2QWMEM ||
                taint_op == TAINTX_UBREG2QWMEM ||
                taint_op == TAINTX_HWREG2QWMEM ||
                taint_op == TAINTX_WREG2QWMEM ||
                taint_op == TAINTX_DWREG2QWMEM ||
                taint_op == TAINT_ADD_LBREG2QWMEM ||
                taint_op == TAINT_ADD_UBREG2QWMEM ||
                taint_op == TAINT_ADD_HWREG2QWMEM ||
                taint_op == TAINT_ADD_WREG2QWMEM ||
                taint_op == TAINT_ADD_DWREG2QWMEM ||
                taint_op == TAINT_REP_QWREG2MEM ||
                taint_op == TAINT_QWREG2QWREG ||
                taint_op == TAINT_LBREG2QWREG ||
                taint_op == TAINT_UBREG2QWREG ||
                taint_op == TAINT_HWREG2QWREG ||
                taint_op == TAINT_WREG2QWREG ||
                taint_op == TAINT_DWREG2QWREG ||
                taint_op == TAINTX_LBREG2QWREG ||
                taint_op == TAINTX_UBREG2QWREG ||
                taint_op == TAINTX_HWREG2QWREG ||
                taint_op == TAINTX_WREG2QWREG ||
                taint_op == TAINTX_DWREG2QWREG ||
                taint_op == TAINT_ADD_QWREG2QWREG ||
                taint_op == TAINT_ADD_LBREG2QWREG ||
                taint_op == TAINT_ADD_UBREG2QWREG ||
                taint_op == TAINT_ADD_HWREG2QWREG ||
                taint_op == TAINT_ADD_WREG2QWREG ||
                taint_op == TAINT_ADD_DWREG2QWREG ||
                taint_op == TAINT_XCHG_QWREG2QWREG ||
                taint_op == TAINT_MEM2MEM_QW ||
                taint_op == TAINT_ADD_MEM2MEM_QW ||
                taint_op == TAINT_IMMVALQW2MEM ||
                taint_op == TAINT_ADD_IMMVALQW2MEM ||
                taint_op == TAINT_IMMVAL2QWREG ||
                taint_op == TAINT_ADD_IMMVAL2QWREG
            ) {
        return 16;
    }
    return 0;
}

static inline int get_src_size(taint_op_t taint_op)
{
    if (
            taint_op == TAINT_MEM2LBREG ||
            taint_op == TAINT_MEM2UBREG ||
            taint_op == TAINT_BMEM2HWREG ||
            taint_op == TAINT_BMEM2WREG ||
            taint_op == TAINT_BMEM2DWREG ||
            taint_op == TAINT_BMEM2QWREG ||
            taint_op == TAINTX_BMEM2HWREG ||
            taint_op == TAINTX_BMEM2WREG ||
            taint_op == TAINTX_BMEM2DWREG ||
            taint_op == TAINTX_BMEM2QWREG ||
            taint_op == TAINT_ADD_BMEM2LBREG ||
            taint_op == TAINT_ADD_BMEM2UBREG ||
            taint_op == TAINT_ADD_BMEM2HWREG ||
            taint_op == TAINT_ADD_BMEM2WREG ||
            taint_op == TAINT_ADD_BMEM2DWREG ||
            taint_op == TAINT_ADD_BMEM2QWREG ||
            taint_op == TAINT_XCHG_BMEM2LBREG ||
            taint_op == TAINT_XCHG_BMEM2UBREG ||
            taint_op == TAINT_LBREG2MEM ||
            taint_op == TAINT_UBREG2MEM ||
            taint_op == TAINT_LBREG2HWMEM ||
            taint_op == TAINT_LBREG2WMEM ||
            taint_op == TAINT_LBREG2DWMEM ||
            taint_op == TAINT_LBREG2QWMEM ||
            taint_op == TAINT_UBREG2HWMEM ||
            taint_op == TAINT_UBREG2WMEM ||
            taint_op == TAINT_UBREG2DWMEM ||
            taint_op == TAINT_UBREG2QWMEM ||
            taint_op == TAINTX_LBREG2HWMEM ||
            taint_op == TAINTX_LBREG2WMEM ||
            taint_op == TAINTX_LBREG2DWMEM ||
            taint_op == TAINTX_LBREG2QWMEM ||
            taint_op == TAINTX_UBREG2HWMEM ||
            taint_op == TAINTX_UBREG2WMEM ||
            taint_op == TAINTX_UBREG2DWMEM ||
            taint_op == TAINTX_UBREG2QWMEM ||
            taint_op == TAINT_ADD_LBREG2MEM ||
            taint_op == TAINT_ADD_UBREG2MEM ||
            taint_op == TAINT_ADD_LBREG2HWMEM ||
            taint_op == TAINT_ADD_LBREG2WMEM ||
            taint_op == TAINT_ADD_LBREG2DWMEM ||
            taint_op == TAINT_ADD_LBREG2QWMEM ||
            taint_op == TAINT_ADD_UBREG2HWMEM ||
            taint_op == TAINT_ADD_UBREG2WMEM ||
            taint_op == TAINT_ADD_UBREG2DWMEM ||
            taint_op == TAINT_ADD_UBREG2QWMEM ||
            taint_op == TAINT_REP_LBREG2MEM ||
            taint_op == TAINT_REP_UBREG2MEM ||
            taint_op == TAINT_LBREG2LBREG ||
            taint_op == TAINT_UBREG2LBREG ||
            taint_op == TAINT_LBREG2UBREG ||
            taint_op == TAINT_UBREG2UBREG ||
            taint_op == TAINT_LBREG2WREG ||
            taint_op == TAINT_LBREG2HWREG ||
            taint_op == TAINT_LBREG2DWREG ||
            taint_op == TAINT_LBREG2QWREG ||
            taint_op == TAINT_UBREG2HWREG ||
            taint_op == TAINT_UBREG2WREG ||
            taint_op == TAINT_UBREG2DWREG ||
            taint_op == TAINT_UBREG2QWREG ||
            taint_op == TAINTX_LBREG2WREG ||
            taint_op == TAINTX_LBREG2HWREG ||
            taint_op == TAINTX_LBREG2DWREG ||
            taint_op == TAINTX_LBREG2QWREG ||
            taint_op == TAINTX_UBREG2HWREG ||
            taint_op == TAINTX_UBREG2WREG ||
            taint_op == TAINTX_UBREG2DWREG ||
            taint_op == TAINTX_UBREG2QWREG ||
            taint_op == TAINT_ADD_LBREG2LBREG ||
            taint_op == TAINT_ADD_UBREG2LBREG ||
            taint_op == TAINT_ADD_LBREG2UBREG ||
            taint_op == TAINT_ADD_UBREG2UBREG ||
            taint_op == TAINT_ADD_LBREG2WREG ||
            taint_op == TAINT_ADD_LBREG2HWREG ||
            taint_op == TAINT_ADD_LBREG2DWREG ||
            taint_op == TAINT_ADD_LBREG2QWREG ||
            taint_op == TAINT_ADD_UBREG2HWREG ||
            taint_op == TAINT_ADD_UBREG2WREG ||
            taint_op == TAINT_ADD_UBREG2DWREG ||
            taint_op == TAINT_ADD_UBREG2QWREG ||
            taint_op == TAINT_XCHG_LBREG2LBREG ||
            taint_op == TAINT_XCHG_UBREG2UBREG ||
            taint_op == TAINT_XCHG_UBREG2LBREG ||
            taint_op == TAINT_XCHG_LBREG2UBREG ||
            taint_op == TAINT_MEM2MEM_B ||
            taint_op == TAINT_ADD_MEM2MEM_B
        ) {
        return 1;
    } else if (
                taint_op == TAINT_MEM2HWREG ||
                taint_op == TAINT_HWMEM2WREG ||
                taint_op == TAINT_HWMEM2DWREG ||
                taint_op == TAINT_HWMEM2QWREG ||
                taint_op == TAINTX_HWMEM2WREG ||
                taint_op == TAINTX_HWMEM2DWREG ||
                taint_op == TAINTX_HWMEM2QWREG ||
                taint_op == TAINT_ADD_HWMEM2HWREG ||
                taint_op == TAINT_ADD_HWMEM2WREG ||
                taint_op == TAINT_ADD_HWMEM2DWREG ||
                taint_op == TAINT_ADD_HWMEM2QWREG ||
                taint_op == TAINT_XCHG_HWMEM2HWREG ||
                taint_op == TAINT_HWREG2MEM ||
                taint_op == TAINT_HWREG2WMEM ||
                taint_op == TAINT_HWREG2DWMEM ||
                taint_op == TAINT_HWREG2QWMEM ||
                taint_op == TAINTX_HWREG2WMEM ||
                taint_op == TAINTX_HWREG2DWMEM ||
                taint_op == TAINTX_HWREG2QWMEM ||
                taint_op == TAINT_ADD_HWREG2MEM ||
                taint_op == TAINT_ADD_HWREG2WMEM ||
                taint_op == TAINT_ADD_HWREG2DWMEM ||
                taint_op == TAINT_ADD_HWREG2QWMEM ||
                taint_op == TAINT_REP_HWREG2MEM ||
                taint_op == TAINT_HWREG2HWREG ||
                taint_op == TAINT_HWREG2WREG ||
                taint_op == TAINT_HWREG2DWREG ||
                taint_op == TAINT_HWREG2QWREG ||
                taint_op == TAINTX_HWREG2WREG ||
                taint_op == TAINTX_HWREG2DWREG ||
                taint_op == TAINTX_HWREG2QWREG ||
                taint_op == TAINT_ADD_HWREG2HWREG ||
                taint_op == TAINT_ADD_HWREG2WREG ||
                taint_op == TAINT_ADD_HWREG2DWREG ||
                taint_op == TAINT_ADD_HWREG2QWREG ||
                taint_op == TAINT_MEM2MEM_HW ||
                taint_op == TAINT_ADD_MEM2MEM_HW
            ) {
        return 2;
    } else if (
                taint_op == TAINT_MEM2WREG ||
                taint_op == TAINTX_WMEM2DWREG ||
                taint_op == TAINTX_WMEM2QWREG ||
                taint_op == TAINT_ADD_WMEM2WREG ||
                taint_op == TAINT_ADD_WMEM2DWREG ||
                taint_op == TAINT_ADD_WMEM2QWREG ||
                taint_op == TAINT_XCHG_WMEM2WREG ||
                taint_op == TAINT_WREG2MEM ||
                taint_op == TAINT_WREG2DWMEM ||
                taint_op == TAINT_WREG2QWMEM ||
                taint_op == TAINTX_WREG2DWMEM ||
                taint_op == TAINTX_WREG2QWMEM ||
                taint_op == TAINT_ADD_WREG2MEM ||
                taint_op == TAINT_ADD_WREG2DWMEM ||
                taint_op == TAINT_ADD_WREG2QWMEM ||
                taint_op == TAINT_REP_WREG2MEM ||
                taint_op == TAINT_WREG2WREG ||
                taint_op == TAINT_WREG2DWREG ||
                taint_op == TAINT_WREG2QWREG ||
                taint_op == TAINTX_WREG2DWREG ||
                taint_op == TAINTX_WREG2QWREG ||
                taint_op == TAINT_ADD_WREG2WREG ||
                taint_op == TAINT_ADD_WREG2DWREG ||
                taint_op == TAINT_ADD_WREG2QWREG ||
                taint_op == TAINT_XCHG_WREG2WREG ||
                taint_op == TAINT_MEM2MEM_W ||
                taint_op == TAINT_ADD_MEM2MEM_W
            ) {
        return 4;
    } else if (
                taint_op == TAINT_DWMEM2QWREG ||
                taint_op == TAINTX_DWMEM2QWREG ||
                taint_op == TAINT_ADD_DWMEM2DWREG ||
                taint_op == TAINT_ADD_DWMEM2QWREG ||
                taint_op == TAINT_XCHG_DWMEM2DWREG ||
                taint_op == TAINT_DWREG2MEM ||
                taint_op == TAINT_DWREG2QWMEM ||
                taint_op == TAINTX_DWREG2QWMEM ||
                taint_op == TAINTX_LBREG2WREG ||
                taint_op == TAINT_ADD_DWREG2MEM ||
                taint_op == TAINT_ADD_DWREG2QWMEM ||
                taint_op == TAINT_REP_DWREG2MEM ||
                taint_op == TAINT_DWREG2DWREG ||
                taint_op == TAINT_DWREG2QWREG ||
                taint_op == TAINTX_DWREG2QWREG ||
                taint_op == TAINT_ADD_DWREG2DWREG ||
                taint_op == TAINT_ADD_DWREG2QWREG ||
                taint_op == TAINT_XCHG_DWREG2DWREG ||
                taint_op == TAINT_MEM2MEM_DW ||
                taint_op == TAINT_ADD_MEM2MEM_DW
            ) {
        return 8;
    } else if (
                taint_op == TAINT_MEM2QWREG ||
                taint_op == TAINT_ADD_QWMEM2QWREG ||
                taint_op == TAINT_XCHG_QWMEM2QWREG ||
                taint_op == TAINT_QWREG2MEM ||
                taint_op == TAINT_ADD_QWREG2MEM ||
                taint_op == TAINT_REP_QWREG2MEM ||
                taint_op == TAINT_QWREG2QWREG ||
                taint_op == TAINT_ADD_QWREG2QWREG ||
                taint_op == TAINT_XCHG_QWREG2QWREG ||
		taint_op == TAINT_MASK_REG2REG ||
                taint_op == TAINT_MEM2MEM_QW ||
                taint_op == TAINT_ADD_MEM2MEM_QW
            ) {
        return 16;
    }
    return 0;
}

struct taint_op {
    u_long ip;
    int threadid;
    taint_op_t taint_op;
    u_long dst;
    u_long src;
};

void trace_syscall_op(int outfd, int threadid,
		      u_long ip, taint_op_t taint_op,
		      u_long syscall_num,
		      u_long syscall_cnt);

void trace_taint_op(int outfd, int threadid,
		    u_long ip, taint_op_t taint_op,
		    u_long dst, u_long src);

void trace_taint_op_enter(int outfd, int threadid,
			  u_long ip, taint_op_t taint_op,
			  u_long dst, u_long src);

void trace_taint_op_exit(int outfd, int threadid,
			 u_long ip, taint_op_t taint_op,
			 u_long dst, u_long src);

#ifdef __cplusplus
}
#endif

#endif
