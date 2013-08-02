/* Get current priority ceiling of pthread_mutex_t.
   Copyright (C) 2006 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Jakub Jelinek <jakub@redhat.com>, 2006.

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
internal_pthread_mutex_getprioceiling (mutex, prioceiling) // REPLAY
     const pthread_mutex_t *mutex;
     int *prioceiling;
{
  if (__builtin_expect ((mutex->__data.__kind
			 & PTHREAD_MUTEX_PRIO_PROTECT_NP) == 0, 0))
    return EINVAL;

  *prioceiling = (mutex->__data.__lock & PTHREAD_MUTEX_PRIO_CEILING_MASK)
		 >> PTHREAD_MUTEX_PRIO_CEILING_SHIFT;

  return 0;
}

/* Begin REPLAY */
int
pthread_mutex_getprioceiling (mutex, prioceiling)
     const pthread_mutex_t *mutex;
     int *prioceiling;
{
  int rc;

  if (is_recording()) {
    pthread_log_record (0, PTHREAD_MUTEX_GETPRIOCEILING_ENTER, (u_long) mutex, 1); 
    rc = internal_pthread_mutex_getprioceiling (mutex, prioceiling);
    pthread_log_record (rc, PTHREAD_MUTEX_GETPRIOCEILING_EXIT_1, (u_long) mutex, 0); 
    pthread_log_record (*prioceiling, PTHREAD_MUTEX_GETPRIOCEILING_EXIT_2, (u_long) mutex, 0); 
  } else if (is_replaying()) {
    pthread_log_replay (PTHREAD_MUTEX_GETPRIOCEILING_ENTER, (u_long) mutex); 
    rc = pthread_log_replay (PTHREAD_MUTEX_GETPRIOCEILING_EXIT_1, (u_long) mutex); 
    *prioceiling = pthread_log_replay (PTHREAD_MUTEX_GETPRIOCEILING_EXIT_2, (u_long) mutex); 
  } else {
    rc = internal_pthread_mutex_getprioceiling (mutex, prioceiling);
  }
  return rc;
}
/* End REPLAY */

