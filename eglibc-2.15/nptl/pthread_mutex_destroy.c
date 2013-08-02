/* Copyright (C) 2002, 2003, 2005, 2006 Free Software Foundation, Inc.
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
#include "pthreadP.h"
#include "pthread_log.h" // REPLAY

int
__internal_pthread_mutex_destroy (mutex) // REPLAY
     pthread_mutex_t *mutex;
{
  if ((mutex->__data.__kind & PTHREAD_MUTEX_ROBUST_NORMAL_NP) == 0
      && mutex->__data.__nusers != 0)
    return EBUSY;

  /* Set to an invalid value.  */
  mutex->__data.__kind = -1;

  return 0;
}

/* Begin REPLAY */
int
__pthread_mutex_destroy (mutex)
     pthread_mutex_t *mutex;
{
  int rc;

  if (is_recording()) {
    pthread_log_record (0, PTHREAD_MUTEX_DESTROY_ENTER, (u_long) mutex, 1); 
    rc = __internal_pthread_mutex_destroy (mutex);
    pthread_log_record (rc, PTHREAD_MUTEX_DESTROY_EXIT, (u_long) mutex, 0); 
  } else if (is_replaying()) {
    pthread_log_replay (PTHREAD_MUTEX_DESTROY_ENTER, (u_long) mutex); 
    rc = pthread_log_replay (PTHREAD_MUTEX_DESTROY_EXIT, (u_long) mutex); 
  } else {
    rc = __internal_pthread_mutex_destroy (mutex);
  }
  return rc;
}
/* End REPLAY */

strong_alias (__pthread_mutex_destroy, pthread_mutex_destroy)
INTDEF(__pthread_mutex_destroy)
