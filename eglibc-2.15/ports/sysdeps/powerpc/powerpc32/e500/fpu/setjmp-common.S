/* setjmp for PowerPC E500.
   Copyright (C) 2004, 2006 Free Software Foundation, Inc.
   Contributed by Aldy Hernandez <aldyh@redhat.com>.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <sysdep.h>
#define _ASM
#ifdef __NO_VMX__
# include <novmxsetjmp.h>
#else
# include <jmpbuf-offsets.h>
#endif
#include <bp-sym.h>
#include <bp-asm.h>

ENTRY (BP_SYM (__sigsetjmp))
	CHECK_BOUNDS_BOTH_WIDE_LIT (r3, r8, r9, JB_SIZE)

#ifdef PTR_MANGLE
	mr   r5,r1
	PTR_MANGLE(r5, r10)
	stw  r5,(JB_GPR1*4)(3)
#else
	stw  r1,(JB_GPR1*4)(3)
#endif
	mflr r0
	stw  r14,((JB_GPRS+0)*4)(3)
#ifdef PTR_MANGLE
	PTR_MANGLE2 (r0, r10)
	li   r10,0
#endif
	/*stfd fp14,((JB_FPRS+0*2)*4)(3)*/
	evstdd r14,((JB_FPRS+0*2)*4)(3)
	stw  r0,(JB_LR*4)(3)
	stw  r15,((JB_GPRS+1)*4)(3)
	/*stfd fp15,((JB_FPRS+1*2)*4)(3)*/
	evstdd r15,((JB_FPRS+1*2)*4)(3)
	mfcr r0
	stw  r16,((JB_GPRS+2)*4)(3)
	/*stfd fp16,((JB_FPRS+2*2)*4)(3)*/
	evstdd r16,((JB_FPRS+2*2)*4)(3)
	stw  r0,(JB_CR*4)(3)
	stw  r17,((JB_GPRS+3)*4)(3)
	/*stfd fp17,((JB_FPRS+3*2)*4)(3)*/
	evstdd r17,((JB_FPRS+3*2)*4)(3)
	stw  r18,((JB_GPRS+4)*4)(3)
	/*stfd fp18,((JB_FPRS+4*2)*4)(3)*/
	evstdd r18,((JB_FPRS+4*2)*4)(3)
	stw  r19,((JB_GPRS+5)*4)(3)
	/*stfd fp19,((JB_FPRS+5*2)*4)(3)*/
	evstdd r19,((JB_FPRS+5*2)*4)(3)
	stw  r20,((JB_GPRS+6)*4)(3)
	/*stfd fp20,((JB_FPRS+6*2)*4)(3)*/
	evstdd r20,((JB_FPRS+6*2)*4)(3)
	stw  r21,((JB_GPRS+7)*4)(3)
	/*stfd fp21,((JB_FPRS+7*2)*4)(3)*/
	evstdd r21,((JB_FPRS+7*2)*4)(3)
	stw  r22,((JB_GPRS+8)*4)(3)
	/*stfd fp22,((JB_FPRS+8*2)*4)(3)*/
	evstdd r22,((JB_FPRS+8*2)*4)(3)
	stw  r23,((JB_GPRS+9)*4)(3)
	/*stfd fp23,((JB_FPRS+9*2)*4)(3)*/
	evstdd r23,((JB_FPRS+9*2)*4)(3)
	stw  r24,((JB_GPRS+10)*4)(3)
	/*stfd fp24,((JB_FPRS+10*2)*4)(3)*/
	evstdd r24,((JB_FPRS+10*2)*4)(3)
	stw  r25,((JB_GPRS+11)*4)(3)
	/*stfd fp25,((JB_FPRS+11*2)*4)(3)*/
	evstdd r25,((JB_FPRS+11*2)*4)(3)
	stw  r26,((JB_GPRS+12)*4)(3)
	/*stfd fp26,((JB_FPRS+12*2)*4)(3)*/
	evstdd r26,((JB_FPRS+12*2)*4)(3)
	stw  r27,((JB_GPRS+13)*4)(3)
	/*stfd fp27,((JB_FPRS+13*2)*4)(3)*/
	evstdd r27,((JB_FPRS+13*2)*4)(3)
	stw  r28,((JB_GPRS+14)*4)(3)
	/*stfd fp28,((JB_FPRS+14*2)*4)(3)*/
	evstdd r28,((JB_FPRS+14*2)*4)(3)
	stw  r29,((JB_GPRS+15)*4)(3)
	/*stfd fp29,((JB_FPRS+15*2)*4)(3)*/
	evstdd r29,((JB_FPRS+15*2)*4)(3)
	stw  r30,((JB_GPRS+16)*4)(3)
	/*stfd fp30,((JB_FPRS+16*2)*4)(3)*/
	evstdd r30,((JB_FPRS+16*2)*4)(3)
	stw  r31,((JB_GPRS+17)*4)(3)
	/*stfd fp31,((JB_FPRS+17*2)*4)(3)*/
	evstdd r31,((JB_FPRS+17*2)*4)(3)
#if defined NOT_IN_libc && defined IS_IN_rtld
	li   r3,0
	blr
#else
	b BP_SYM (__sigjmp_save@local)
#endif
END (BP_SYM (__sigsetjmp))
