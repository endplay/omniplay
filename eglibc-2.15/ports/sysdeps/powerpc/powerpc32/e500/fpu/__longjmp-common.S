/* longjmp for PowerPC E500.
   Copyright (C) 2004, 2006, 2009 Free Software Foundation, Inc.
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
#define _SETJMP_H
#ifdef __NO_VMX__
# include <novmxsetjmp.h>
#else
# include <jmpbuf-offsets.h>
#endif
#include <bp-sym.h>
#include <bp-asm.h>

ENTRY (BP_SYM (__longjmp))
	CHECK_BOUNDS_BOTH_WIDE_LIT (r3, r8, r9, JB_SIZE)

#if defined PTR_DEMANGLE || defined CHECK_SP
	lwz r24,(JB_GPR1*4)(r3)
# ifdef CHECK_SP
#  ifdef PTR_DEMANGLE
	PTR_DEMANGLE3 (r24, r24, r25)
#  endif
	CHECK_SP (r24)
	mr r1,r24
# endif
#else
	lwz r1,(JB_GPR1*4)(r3)
#endif
	lwz r0,(JB_LR*4)(r3)
	/*lfd fp14,((JB_FPRS+0*2)*4)(r3)*/
	evldd r14,((JB_FPRS+0*2)*4)(r3)
	lwz r14,((JB_GPRS+0)*4)(r3)
	/*lfd fp15,((JB_FPRS+1*2)*4)(r3)*/
	evldd r15,((JB_FPRS+1*2)*4)(r3)
	lwz r15,((JB_GPRS+1)*4)(r3)
	/*lfd fp16,((JB_FPRS+2*2)*4)(r3)*/
	evldd r16,((JB_FPRS+2*2)*4)(r3)
	lwz r16,((JB_GPRS+2)*4)(r3)
	/*lfd fp17,((JB_FPRS+3*2)*4)(r3)*/
	evldd r17,((JB_FPRS+3*2)*4)(r3)
	lwz r17,((JB_GPRS+3)*4)(r3)
	/*lfd fp18,((JB_FPRS+4*2)*4)(r3)*/
	evldd r18,((JB_FPRS+4*2)*4)(r3)
	lwz r18,((JB_GPRS+4)*4)(r3)
	/*lfd fp19,((JB_FPRS+5*2)*4)(r3)*/
	evldd r19,((JB_FPRS+5*2)*4)(r3)
	lwz r19,((JB_GPRS+5)*4)(r3)
	/*lfd fp20,((JB_FPRS+6*2)*4)(r3)*/
	evldd r20,((JB_FPRS+6*2)*4)(r3)
	lwz r20,((JB_GPRS+6)*4)(r3)
#ifdef PTR_DEMANGLE
# ifndef CHECK_SP
	PTR_DEMANGLE3 (r1, r24, r25)
# endif
	PTR_DEMANGLE2 (r0, r25)
#endif
	mtlr r0
	/*lfd fp21,((JB_FPRS+7*2)*4)(r3)*/
	evldd r21,((JB_FPRS+7*2)*4)(r3)
	lwz r21,((JB_GPRS+7)*4)(r3)
	/*lfd fp22,((JB_FPRS+8*2)*4)(r3)*/
	evldd r22,((JB_FPRS+8*2)*4)(r3)
	lwz r22,((JB_GPRS+8)*4)(r3)
	lwz r0,(JB_CR*4)(r3)
	/*lfd fp23,((JB_FPRS+9*2)*4)(r3)*/
	evldd r23,((JB_FPRS+9*2)*4)(r3)
	lwz r23,((JB_GPRS+9)*4)(r3)
	/*lfd fp24,((JB_FPRS+10*2)*4)(r3)*/
	evldd r24,((JB_FPRS+10*2)*4)(r3)
	lwz r24,((JB_GPRS+10)*4)(r3)
	/*lfd fp25,((JB_FPRS+11*2)*4)(r3)*/
	evldd r25,((JB_FPRS+11*2)*4)(r3)
	lwz r25,((JB_GPRS+11)*4)(r3)
	mtcrf 0xFF,r0
	/*lfd fp26,((JB_FPRS+12*2)*4)(r3)*/
	evldd r26,((JB_FPRS+12*2)*4)(r3)
	lwz r26,((JB_GPRS+12)*4)(r3)
	/*lfd fp27,((JB_FPRS+13*2)*4)(r3)*/
	evldd r27,((JB_FPRS+13*2)*4)(r3)
	lwz r27,((JB_GPRS+13)*4)(r3)
	/*lfd fp28,((JB_FPRS+14*2)*4)(r3)*/
	evldd r28,((JB_FPRS+14*2)*4)(r3)
	lwz r28,((JB_GPRS+14)*4)(r3)
	/*lfd fp29,((JB_FPRS+15*2)*4)(r3)*/
	evldd r29,((JB_FPRS+15*2)*4)(r3)
	lwz r29,((JB_GPRS+15)*4)(r3)
	/*lfd fp30,((JB_FPRS+16*2)*4)(r3)*/
	evldd r30,((JB_FPRS+16*2)*4)(r3)
	lwz r30,((JB_GPRS+16)*4)(r3)
	/*lfd fp31,((JB_FPRS+17*2)*4)(r3)*/
	evldd r31,((JB_FPRS+17*2)*4)(r3)
	lwz r31,((JB_GPRS+17)*4)(r3)
	mr r3,r4
	blr
END (BP_SYM (__longjmp))
