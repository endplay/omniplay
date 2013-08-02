/* Copyright (C) 2005, 2006, 2010 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2005.

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
#include <pthreadP.h>
#include "pthread_log.h" // REPLAY

int
internal_pthread_mutex_consistent (mutex) // REPLAY
     pthread_mutex_t *mutex;
{
  /* Test whether this is a robust mutex with a dead owner.  */
  if ((mutex->__data.__kind & PTHREAD_MUTEX_ROBUST_NORMAL_NP) == 0
      || mutex->__data.__owner != PTHREAD_MUTEX_INCONSISTENT)
    return EINVAL;

  mutex->__data.__owner = THREAD_GETMEM (THREAD_SELF, tid);

  return 0;
}

/* Begin REPLAY */
int
pthread_mutex_consistent (mutex) // REPLAY
     pthread_mutex_t *mutex;
{
  int rc;

  if (is_recording()) {
    pthread_log_record (0, PTHREAD_MUTEX_CONSISTENT_ENTER, (u_long) mutex, 1); 
    rc = internal_pthread_mutex_consistent (mutex);
    pthread_log_record (rc, PTHREAD_MUTEX_CONSISTENT_EXIT, (u_long) mutex, 0); 
  } else if (is_replaying()) {
    pthread_log_replay (PTHREAD_MUTEX_CONSISTENT_ENTER, (u_long) mutex); 
    rc = pthread_log_replay (PTHREAD_MUTEX_CONSISTENT_EXIT, (u_long) mutex); 
  } else {
    rc = internal_pthread_mutex_consistent (mutex);
  }
  return rc;
}
/* End REPLAY */

weak_alias (pthread_mutex_consistent, pthread_mutex_consistent_np)
