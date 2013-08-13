/* Copyright (C) 2002, 2003, 2005 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <atomic.h>
#include "pthreadP.h"
#include "pthread_log.h"

static void
cleanup (void *arg)
{
  *(void **) arg = NULL;
}


int
pthread_timedjoin_np (threadid, thread_return, abstime)
     pthread_t threadid;
     void **thread_return;
     const struct timespec *abstime;
{
  struct pthread *self;
  struct pthread *pd = (struct pthread *) threadid;
  int result;
  int b;

  /* Make sure the descriptor is valid.  */
  if (INVALID_NOT_TERMINATED_TD_P (pd))
    /* Not a valid thread handle.  */
    return ESRCH;

  /* Is the thread joinable?.  */
  if (is_recording()) {
    pthread_log_record (0, PTHREAD_JOINID_ENTER, (u_long) &pd->joinid, 1); 
    b = IS_DETACHED (pd);
    pthread_log_record (b, PTHREAD_JOINID_EXIT, (u_long) &pd->joinid, 0); 
  } else if (is_replaying()) {
    pthread_log_replay (PTHREAD_JOINID_ENTER, (u_long) &pd->joinid); 
    b = pthread_log_replay (PTHREAD_JOINID_EXIT, (u_long) &pd->joinid); 
  } else {
    b = IS_DETACHED (pd);
  }
  if (b)
    /* We cannot wait for the thread.  */
    return EINVAL;

  self = THREAD_SELF;
  
  if (is_recording()) {
    pthread_log_record (0, PTHREAD_JOINID_ENTER, (u_long) &self->joinid, 1); 
    b = (self->joinid == pd);
    pthread_log_record (b, PTHREAD_JOINID_EXIT, (u_long) &self->joinid, 0); 
  } else if (is_replaying()) {
    pthread_log_replay (PTHREAD_JOINID_ENTER, (u_long) &self->joinid); 
    b = pthread_log_replay (PTHREAD_JOINID_EXIT, (u_long) &self->joinid); 
  } else {
    b = (self->joinid == pd);
  }
  if (pd == self || b)
    /* This is a deadlock situation.  The threads are waiting for each
       other to finish.  Note that this is a "may" error.  To be 100%
       sure we catch this error we would have to lock the data
       structures but it is not necessary.  In the unlikely case that
       two threads are really caught in this situation they will
       deadlock.  It is the programmer's problem to figure this
       out.  */
    return EDEADLK;

  /* Wait for the thread to finish.  If it is already locked something
     is wrong.  There can only be one waiter.  */
  if (is_recording()) {
    pthread_log_record (0, PTHREAD_JOINID_ENTER, (u_long) &pd->joinid, 1); 
    b = atomic_compare_and_exchange_bool_acq (&pd->joinid, self, NULL);
    pthread_log_record (b, PTHREAD_JOINID_EXIT, (u_long) &pd->joinid, 0); 
  } else if (is_replaying()) {
    pthread_log_replay (PTHREAD_JOINID_ENTER, (u_long) &pd->joinid); 
    b = pthread_log_replay (PTHREAD_JOINID_EXIT, (u_long) &pd->joinid); 
  } else {
    b = atomic_compare_and_exchange_bool_acq (&pd->joinid, self, NULL);
  }
  if (__builtin_expect (b, 0))
    /* There is already somebody waiting for the thread.  */
    return EINVAL;


  /* During the wait we change to asynchronous cancellation.  If we
     are cancelled the thread we are waiting for must be marked as
     un-wait-ed for again.  */
  pthread_cleanup_push (cleanup, &pd->joinid);

  /* Switch to asynchronous cancellation.  */
  int oldtype = CANCEL_ASYNC ();


  /* Wait for the child.  */
  result = pthread_log_lll_timedwait_tid (&pd->tid, abstime);


  /* Restore cancellation mode.  */
  CANCEL_RESET (oldtype);

  /* Remove the handler.  */
  pthread_cleanup_pop (0);


  /* We might have timed out.  */
  if (result == 0)
    {
      /* Store the return value if the caller is interested.  */
      if (thread_return != NULL)
	*thread_return = pd->result;


      /* Free the TCB.  */
      __free_tcb (pd);
    }
  else {
    if (is_recording()) {
      pthread_log_record (0, PTHREAD_JOINID_ENTER, (u_long) &pd->joinid, 1); 
      pd->joinid = NULL;
      pthread_log_record (0, PTHREAD_JOINID_EXIT, (u_long) &pd->joinid, 0); 
    } else if (is_replaying()) {
      pthread_log_replay (PTHREAD_JOINID_ENTER, (u_long) &pd->joinid); 
      pthread_log_replay (PTHREAD_JOINID_EXIT, (u_long) &pd->joinid); 
    } else {
      pd->joinid = NULL;
    }
  }

  return result;
}
