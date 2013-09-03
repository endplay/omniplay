/* Copyright (C) 2002, 2003, 2004, 2009 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2002.

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

#include <errno.h>
#include <signal.h>
#include "pthreadP.h"
#include "atomic.h"
#include <sysdep.h>
#include <kernel-features.h>


int
pthread_cancel (th)
     pthread_t th;
{
  volatile struct pthread *pd = (volatile struct pthread *) th;

  /* Make sure the descriptor is valid.  */
  if (INVALID_TD_P (pd))
    /* Not a valid thread handle.  */
    return ESRCH;

#ifdef SHARED
  pthread_cancel_init ();
#endif
  int result = 0;
  int oldval;
  int newval, b;
  do
    {
    again:
      if (is_recording()) {
	pthread_log_record (0, PTHREAD_CANCELHANDLING_ENTER, (u_long) &pd->cancelhandling, 1); 
	oldval = pd->cancelhandling;
	pthread_log_record (oldval, PTHREAD_CANCELHANDLING_EXIT, (u_long) &pd->cancelhandling, 0); 
      } else if (is_replaying()) {
	pthread_log_replay (PTHREAD_CANCELHANDLING_ENTER, (u_long) &pd->cancelhandling); 
	oldval = pthread_log_replay (PTHREAD_CANCELHANDLING_EXIT, (u_long) &pd->cancelhandling); 
      } else {
	oldval = pd->cancelhandling;
      }
      newval = oldval | CANCELING_BITMASK | CANCELED_BITMASK;

      /* Avoid doing unnecessary work.  The atomic operation can
	 potentially be expensive if the bug has to be locked and
	 remote cache lines have to be invalidated.  */
      if (oldval == newval)
	break;

      /* If the cancellation is handled asynchronously just send a
	 signal.  We avoid this if possible since it's more
	 expensive.  */
      if (CANCEL_ENABLED_AND_CANCELED_AND_ASYNCHRONOUS (newval))
	{
	  /* Mark the cancellation as "in progress".  */
	  if (is_recording()) {
	    pthread_log_record (0, PTHREAD_CANCELHANDLING_ENTER, (u_long) &pd->cancelhandling, 1); 
	    b = atomic_compare_and_exchange_bool_acq (&pd->cancelhandling, oldval | CANCELING_BITMASK, oldval);
	    pthread_log_record (b, PTHREAD_CANCELHANDLING_EXIT, (u_long) &pd->cancelhandling, 0); 
	  } else if (is_replaying()) {
	    pthread_log_replay (PTHREAD_CANCELHANDLING_ENTER, (u_long) &pd->cancelhandling); 
	    b = pthread_log_replay (PTHREAD_CANCELHANDLING_EXIT, (u_long) &pd->cancelhandling); 
	  } else {
	    b = atomic_compare_and_exchange_bool_acq (&pd->cancelhandling, oldval | CANCELING_BITMASK, oldval);
	  }
	  if (b)
	    goto again;

	  /* The cancellation handler will take care of marking the
	     thread as canceled.  */
	  INTERNAL_SYSCALL_DECL (err);

	  /* One comment: The PID field in the TCB can temporarily be
	     changed (in fork).  But this must not affect this code
	     here.  Since this function would have to be called while
	     the thread is executing fork, it would have to happen in
	     a signal handler.  But this is no allowed, pthread_cancel
	     is not guaranteed to be async-safe.  */
	  int val;
#if __ASSUME_TGKILL
	  val = INTERNAL_SYSCALL (tgkill, err, 3,
				  THREAD_GETMEM (THREAD_SELF, pid), pd->tid,
				  SIGCANCEL);
#else
# ifdef __NR_tgkill
	  val = INTERNAL_SYSCALL (tgkill, err, 3,
				  THREAD_GETMEM (THREAD_SELF, pid), pd->tid,
				  SIGCANCEL);
	  if (INTERNAL_SYSCALL_ERROR_P (val, err)
	      && INTERNAL_SYSCALL_ERRNO (val, err) == ENOSYS)
# endif
	    val = INTERNAL_SYSCALL (tkill, err, 2, pd->tid, SIGCANCEL);
#endif

	  if (INTERNAL_SYSCALL_ERROR_P (val, err))
	    result = INTERNAL_SYSCALL_ERRNO (val, err);

	  break;
	}
      if (is_recording()) {
	pthread_log_record (0, PTHREAD_CANCELHANDLING_ENTER, (u_long) &pd->cancelhandling, 1); 
	b = atomic_compare_and_exchange_bool_acq (&pd->cancelhandling, newval, oldval);
	pthread_log_record (b, PTHREAD_CANCELHANDLING_EXIT, (u_long) &pd->cancelhandling, 0); 
      } else if (is_replaying()) {
	pthread_log_replay (PTHREAD_CANCELHANDLING_ENTER, (u_long) &pd->cancelhandling); 
	b = pthread_log_replay (PTHREAD_CANCELHANDLING_EXIT, (u_long) &pd->cancelhandling); 
      } else {
	b = atomic_compare_and_exchange_bool_acq (&pd->cancelhandling, newval, oldval);
      }
    }
  /* Mark the thread as canceled.  This has to be done
     atomically since other bits could be modified as well.  */
  while (b);

  return result;
}

PTHREAD_STATIC_FN_REQUIRE (pthread_create)
