#ifndef __timer_defs_asm_h
#define __timer_defs_asm_h

/*
 * This file is autogenerated from
 *   file:           ../../inst/timer/rtl/timer_regs.r
 *     id:           timer_regs.r,v 1.7 2003/03/11 11:16:59 perz Exp
 *     last modfied: Mon Apr 11 16:09:53 2005
 *
 *   by /n/asic/design/tools/rdesc/src/rdes2c -asm --outfile asm/timer_defs_asm.h ../../inst/timer/rtl/timer_regs.r
 *      id: $Id$
 * Any changes here will be lost.
 *
 * -*- buffer-read-only: t -*-
 */

#ifndef REG_FIELD
#define REG_FIELD( scope, reg, field, value ) \
  REG_FIELD_X_( value, reg_##scope##_##reg##___##field##___lsb )
#define REG_FIELD_X_( value, shift ) ((value) << shift)
#endif

#ifndef REG_STATE
#define REG_STATE( scope, reg, field, symbolic_value ) \
  REG_STATE_X_( regk_##scope##_##symbolic_value, reg_##scope##_##reg##___##field##___lsb )
#define REG_STATE_X_( k, shift ) (k << shift)
#endif

#ifndef REG_MASK
#define REG_MASK( scope, reg, field ) \
  REG_MASK_X_( reg_##scope##_##reg##___##field##___width, reg_##scope##_##reg##___##field##___lsb )
#define REG_MASK_X_( width, lsb ) (((1 << width)-1) << lsb)
#endif

#ifndef REG_LSB
#define REG_LSB( scope, reg, field ) reg_##scope##_##reg##___##field##___lsb
#endif

#ifndef REG_BIT
#define REG_BIT( scope, reg, field ) reg_##scope##_##reg##___##field##___bit
#endif

#ifndef REG_ADDR
#define REG_ADDR( scope, inst, reg ) REG_ADDR_X_(inst, reg_##scope##_##reg##_offset)
#define REG_ADDR_X_( inst, offs ) ((inst) + offs)
#endif

#ifndef REG_ADDR_VECT
#define REG_ADDR_VECT( scope, inst, reg, index ) \
         REG_ADDR_VECT_X_(inst, reg_##scope##_##reg##_offset, index, \
			 STRIDE_##scope##_##reg )
#define REG_ADDR_VECT_X_( inst, offs, index, stride ) \
                          ((inst) + offs + (index) * stride)
#endif

/* Register rw_tmr0_div, scope timer, type rw */
#define reg_timer_rw_tmr0_div_offset 0

/* Register r_tmr0_data, scope timer, type r */
#define reg_timer_r_tmr0_data_offset 4

/* Register rw_tmr0_ctrl, scope timer, type rw */
#define reg_timer_rw_tmr0_ctrl___op___lsb 0
#define reg_timer_rw_tmr0_ctrl___op___width 2
#define reg_timer_rw_tmr0_ctrl___freq___lsb 2
#define reg_timer_rw_tmr0_ctrl___freq___width 3
#define reg_timer_rw_tmr0_ctrl_offset 8

/* Register rw_tmr1_div, scope timer, type rw */
#define reg_timer_rw_tmr1_div_offset 16

/* Register r_tmr1_data, scope timer, type r */
#define reg_timer_r_tmr1_data_offset 20

/* Register rw_tmr1_ctrl, scope timer, type rw */
#define reg_timer_rw_tmr1_ctrl___op___lsb 0
#define reg_timer_rw_tmr1_ctrl___op___width 2
#define reg_timer_rw_tmr1_ctrl___freq___lsb 2
#define reg_timer_rw_tmr1_ctrl___freq___width 3
#define reg_timer_rw_tmr1_ctrl_offset 24

/* Register rs_cnt_data, scope timer, type rs */
#define reg_timer_rs_cnt_data___tmr___lsb 0
#define reg_timer_rs_cnt_data___tmr___width 24
#define reg_timer_rs_cnt_data___cnt___lsb 24
#define reg_timer_rs_cnt_data___cnt___width 8
#define reg_timer_rs_cnt_data_offset 32

/* Register r_cnt_data, scope timer, type r */
#define reg_timer_r_cnt_data___tmr___lsb 0
#define reg_timer_r_cnt_data___tmr___width 24
#define reg_timer_r_cnt_data___cnt___lsb 24
#define reg_timer_r_cnt_data___cnt___width 8
#define reg_timer_r_cnt_data_offset 36

/* Register rw_cnt_cfg, scope timer, type rw */
#define reg_timer_rw_cnt_cfg___clk___lsb 0
#define reg_timer_rw_cnt_cfg___clk___width 2
#define reg_timer_rw_cnt_cfg_offset 40

/* Register rw_trig, scope timer, type rw */
#define reg_timer_rw_trig_offset 48

/* Register rw_trig_cfg, scope timer, type rw */
#define reg_timer_rw_trig_cfg___tmr___lsb 0
#define reg_timer_rw_trig_cfg___tmr___width 2
#define reg_timer_rw_trig_cfg_offset 52

/* Register r_time, scope timer, type r */
#define reg_timer_r_time_offset 56

/* Register rw_out, scope timer, type rw */
#define reg_timer_rw_out___tmr___lsb 0
#define reg_timer_rw_out___tmr___width 2
#define reg_timer_rw_out_offset 60

/* Register rw_wd_ctrl, scope timer, type rw */
#define reg_timer_rw_wd_ctrl___cnt___lsb 0
#define reg_timer_rw_wd_ctrl___cnt___width 8
#define reg_timer_rw_wd_ctrl___cmd___lsb 8
#define reg_timer_rw_wd_ctrl___cmd___width 1
#define reg_timer_rw_wd_ctrl___cmd___bit 8
#define reg_timer_rw_wd_ctrl___key___lsb 9
#define reg_timer_rw_wd_ctrl___key___width 7
#define reg_timer_rw_wd_ctrl_offset 64

/* Register r_wd_stat, scope timer, type r */
#define reg_timer_r_wd_stat___cnt___lsb 0
#define reg_timer_r_wd_stat___cnt___width 8
#define reg_timer_r_wd_stat___cmd___lsb 8
#define reg_timer_r_wd_stat___cmd___width 1
#define reg_timer_r_wd_stat___cmd___bit 8
#define reg_timer_r_wd_stat_offset 68

/* Register rw_intr_mask, scope timer, type rw */
#define reg_timer_rw_intr_mask___tmr0___lsb 0
#define reg_timer_rw_intr_mask___tmr0___width 1
#define reg_timer_rw_intr_mask___tmr0___bit 0
#define reg_timer_rw_intr_mask___tmr1___lsb 1
#define reg_timer_rw_intr_mask___tmr1___width 1
#define reg_timer_rw_intr_mask___tmr1___bit 1
#define reg_timer_rw_intr_mask___cnt___lsb 2
#define reg_timer_rw_intr_mask___cnt___width 1
#define reg_timer_rw_intr_mask___cnt___bit 2
#define reg_timer_rw_intr_mask___trig___lsb 3
#define reg_timer_rw_intr_mask___trig___width 1
#define reg_timer_rw_intr_mask___trig___bit 3
#define reg_timer_rw_intr_mask_offset 72

/* Register rw_ack_intr, scope timer, type rw */
#define reg_timer_rw_ack_intr___tmr0___lsb 0
#define reg_timer_rw_ack_intr___tmr0___width 1
#define reg_timer_rw_ack_intr___tmr0___bit 0
#define reg_timer_rw_ack_intr___tmr1___lsb 1
#define reg_timer_rw_ack_intr___tmr1___width 1
#define reg_timer_rw_ack_intr___tmr1___bit 1
#define reg_timer_rw_ack_intr___cnt___lsb 2
#define reg_timer_rw_ack_intr___cnt___width 1
#define reg_timer_rw_ack_intr___cnt___bit 2
#define reg_timer_rw_ack_intr___trig___lsb 3
#define reg_timer_rw_ack_intr___trig___width 1
#define reg_timer_rw_ack_intr___trig___bit 3
#define reg_timer_rw_ack_intr_offset 76

/* Register r_intr, scope timer, type r */
#define reg_timer_r_intr___tmr0___lsb 0
#define reg_timer_r_intr___tmr0___width 1
#define reg_timer_r_intr___tmr0___bit 0
#define reg_timer_r_intr___tmr1___lsb 1
#define reg_timer_r_intr___tmr1___width 1
#define reg_timer_r_intr___tmr1___bit 1
#define reg_timer_r_intr___cnt___lsb 2
#define reg_timer_r_intr___cnt___width 1
#define reg_timer_r_intr___cnt___bit 2
#define reg_timer_r_intr___trig___lsb 3
#define reg_timer_r_intr___trig___width 1
#define reg_timer_r_intr___trig___bit 3
#define reg_timer_r_intr_offset 80

/* Register r_masked_intr, scope timer, type r */
#define reg_timer_r_masked_intr___tmr0___lsb 0
#define reg_timer_r_masked_intr___tmr0___width 1
#define reg_timer_r_masked_intr___tmr0___bit 0
#define reg_timer_r_masked_intr___tmr1___lsb 1
#define reg_timer_r_masked_intr___tmr1___width 1
#define reg_timer_r_masked_intr___tmr1___bit 1
#define reg_timer_r_masked_intr___cnt___lsb 2
#define reg_timer_r_masked_intr___cnt___width 1
#define reg_timer_r_masked_intr___cnt___bit 2
#define reg_timer_r_masked_intr___trig___lsb 3
#define reg_timer_r_masked_intr___trig___width 1
#define reg_timer_r_masked_intr___trig___bit 3
#define reg_timer_r_masked_intr_offset 84

/* Register rw_test, scope timer, type rw */
#define reg_timer_rw_test___dis___lsb 0
#define reg_timer_rw_test___dis___width 1
#define reg_timer_rw_test___dis___bit 0
#define reg_timer_rw_test___en___lsb 1
#define reg_timer_rw_test___en___width 1
#define reg_timer_rw_test___en___bit 1
#define reg_timer_rw_test_offset 88


/* Constants */
#define regk_timer_ext                            0x00000001
#define regk_timer_f100                           0x00000007
#define regk_timer_f29_493                        0x00000004
#define regk_timer_f32                            0x00000005
#define regk_timer_f32_768                        0x00000006
#define regk_timer_hold                           0x00000001
#define regk_timer_ld                             0x00000000
#define regk_timer_no                             0x00000000
#define regk_timer_off                            0x00000000
#define regk_timer_run                            0x00000002
#define regk_timer_rw_cnt_cfg_default             0x00000000
#define regk_timer_rw_intr_mask_default           0x00000000
#define regk_timer_rw_out_default                 0x00000000
#define regk_timer_rw_test_default                0x00000000
#define regk_timer_rw_tmr0_ctrl_default           0x00000000
#define regk_timer_rw_tmr1_ctrl_default           0x00000000
#define regk_timer_rw_trig_cfg_default            0x00000000
#define regk_timer_start                          0x00000001
#define regk_timer_stop                           0x00000000
#define regk_timer_time                           0x00000001
#define regk_timer_tmr0                           0x00000002
#define regk_timer_tmr1                           0x00000003
#define regk_timer_yes                            0x00000001
#endif /* __timer_defs_asm_h */
