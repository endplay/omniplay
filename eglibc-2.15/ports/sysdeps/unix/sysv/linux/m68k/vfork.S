/* Copyright (C) 1999, 2002, 2003, 2010 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Andreas Schwab <schwab@gnu.org>.

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
#define _ERRNO_H	1
#include <bits/errno.h>
#include <kernel-features.h>

#ifndef SAVE_PID
#define SAVE_PID
#endif

#ifndef RESTORE_PID
#define RESTORE_PID
#endif

/* Clone the calling process, but without copying the whole address space.
   The calling process is suspended until the new process exits or is
   replaced by a call to `execve'.  Return -1 for errors, 0 to the new process,
   and the process ID of the new process to the old process.  */

ENTRY (__vfork)

#ifdef __NR_vfork

	/* SAVE_PID clobbers call-clobbered registers and
	   saves data in D1 and A1.  */

	SAVE_PID

	/* Pop the return PC value into A0.  */
	movel	%sp@+, %a0

	/* Stuff the syscall number in D0 and trap into the kernel.  */
	movel	#SYS_ify (vfork), %d0
	trap	#0

	RESTORE_PID

	tstl	%d0
	jmi	.Lerror		/* Branch forward if it failed.  */

	/* Jump to the return PC.  */
	jmp	%a0@

.Lerror:
	/* Push back the return PC.  */
	movel	%a0,%sp@-

# ifdef __ASSUME_VFORK_SYSCALL
#  ifndef PIC
	jbra	SYSCALL_ERROR_LABEL
#  endif
# else
	/* Check if vfork syscall is known at all.  */
	movel	#-ENOSYS,%d1
	cmpl	%d0,%d1
	jne	SYSCALL_ERROR_LABEL

# endif
#endif

#ifndef __ASSUME_VFORK_SYSCALL
	/* If we don't have vfork, fork is close enough.  */

	movel	#SYS_ify (fork), %d0
	trap	#0
	tstl	%d0
	jmi	SYSCALL_ERROR_LABEL
	rts
#endif

PSEUDO_END (__vfork)
libc_hidden_def (__vfork)

weak_alias (__vfork, vfork)
