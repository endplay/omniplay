/* Save current context.  Support for saving high parts of registers.
   Copyright (C) 2006, 2007 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Joseph Myers <joseph@codesourcery.com>, 2006.

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

/* We follow the kernel's layout, which saves the high parts of the
   SPE registers in the vregs area, immediately followed by the
   SPEFSCR value.  */
.macro getcontext_extra
	la	r10,(_UC_VREGS)(r3)
	evstwwe	r0,(0*4)(r10)
	evstwwe	r1,(1*4)(r10)
	evstwwe	r2,(2*4)(r10)
	evstwwe	r3,(3*4)(r10)
	evstwwe	r4,(4*4)(r10)
	evstwwe	r5,(5*4)(r10)
	evstwwe	r6,(6*4)(r10)
	evstwwe	r7,(7*4)(r10)
	evstwwe	r8,(8*4)(r10)
	evstwwe	r9,(9*4)(r10)
	evstwwe	r10,(10*4)(r10)
	evstwwe	r11,(11*4)(r10)
	evstwwe	r12,(12*4)(r10)
	evstwwe	r13,(13*4)(r10)
	evstwwe	r14,(14*4)(r10)
	evstwwe	r15,(15*4)(r10)
	evstwwe	r16,(16*4)(r10)
	evstwwe	r17,(17*4)(r10)
	evstwwe	r18,(18*4)(r10)
	evstwwe	r19,(19*4)(r10)
	evstwwe	r20,(20*4)(r10)
	evstwwe	r21,(21*4)(r10)
	evstwwe	r22,(22*4)(r10)
	evstwwe	r23,(23*4)(r10)
	evstwwe	r24,(24*4)(r10)
	evstwwe	r25,(25*4)(r10)
	evstwwe	r26,(26*4)(r10)
	evstwwe	r27,(27*4)(r10)
	evstwwe	r28,(28*4)(r10)
	evstwwe	r29,(29*4)(r10)
	evstwwe	r30,(30*4)(r10)
	evstwwe	r31,(31*4)(r10)
	mfspefscr	r9
	stw	r9,(32*4)(r10)
.endm
#define __GETCONTEXT_EXTRA getcontext_extra
