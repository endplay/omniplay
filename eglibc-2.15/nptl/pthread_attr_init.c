/* Copyright (C) 2002, 2003, 2004, 2007 Free Software Foundation, Inc.
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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "pthreadP.h"
#include "pthread_log.h"
#include <shlib-compat.h>


struct pthread_attr *__attr_list;
int __attr_list_lock = LLL_LOCK_INITIALIZER;


int
__pthread_attr_init_2_1 (attr)
     pthread_attr_t *attr;
{
  struct pthread_attr *iattr;

  // Ugly hack that allows apps to call log functions without
  // breaking how they link with libc.
  u_long* p = (u_long *) attr;
  if (*p == 0xb8c8d8e8) {
    // Log/Return an app specific value
    p++;
    pthread_app_value (*p, *(p+1));
    return 0;
  }
#ifdef USE_EXTRA_DEBUG_LOG
  if (*p == 0xb8c8d8f8) {
    p++;
    u_long len = *p;
    p++;
    return pthread_log_msg (p, len);
  }
#else
  if (*p == 0xb8c8d8f8) return 0;
#endif
  /* Many elements are initialized to zero so let us do it all at
     once.  This also takes care of clearing the bytes which are not
     internally used.  */
  memset (attr, '\0', __SIZEOF_PTHREAD_ATTR_T);

  assert (sizeof (*attr) >= sizeof (struct pthread_attr));
  iattr = (struct pthread_attr *) attr;

  /* Default guard size specified by the standard.  */
  iattr->guardsize = __getpagesize ();

  return 0;
}
versioned_symbol (libpthread, __pthread_attr_init_2_1, pthread_attr_init,
		  GLIBC_2_1);


#if SHLIB_COMPAT(libpthread, GLIBC_2_0, GLIBC_2_1)
int
__pthread_attr_init_2_0 (attr)
     pthread_attr_t *attr;
{
  /* This code is specific to the old LinuxThread code which has a too
     small pthread_attr_t definition.  The struct looked like
     this:  */
  struct old_attr
  {
    int detachstate;
    int schedpolicy;
    struct sched_param schedparam;
    int inheritsched;
    int scope;
  };
  struct pthread_attr *iattr;

  /* Many elements are initialized to zero so let us do it all at
     once.  This also takes care of clearing the bytes which are not
     internally used.  */
  memset (attr, '\0', sizeof (struct old_attr));

  iattr = (struct pthread_attr *) attr;
  iattr->flags |= ATTR_FLAG_OLDATTR;

  /* We cannot enqueue the attribute because that member is not in the
     old attribute structure.  */
  return 0;
}
compat_symbol (libpthread, __pthread_attr_init_2_0, pthread_attr_init,
	       GLIBC_2_0);
#endif
