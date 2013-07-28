/* Copyright (C) 2009 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by CodeSourcery.

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

#include <execinfo.h>
#include <search.h>
#include <string.h>

static int do_test (void);
#define TEST_FUNCTION do_test ()
#include "../test-skeleton.c"

/* Set to a non-zero value if the test fails.  */
int ret;

/* Accesses to X are used to prevent optimization.  */
volatile int x;

/* Called if the test fails.  */
#define FAIL() \
  do { printf ("Failure on line %d\n", __LINE__); ret = 1; } while (0)

/* The backtrace should include at least f1, f2, f3, and do_test.  */
#define NUM_FUNCTIONS 4

/* Use this attribute to prevent inlining, so that all expected frames
   are present.  */
#define NO_INLINE __attribute__((noinline))

NO_INLINE void
fn1 (void) 
{
  void *addresses[NUM_FUNCTIONS];
  char **symbols;
  int n;
  int i;

  /* Get the backtrace addresses.  */
  n = backtrace (addresses, sizeof (addresses) / sizeof (addresses[0]));
  printf ("Obtained backtrace with %d functions\n", n);
  /*  Check that there are at least four functions.  */
  if (n < NUM_FUNCTIONS)
    {
      FAIL ();
      return;
    }
  /* Convert them to symbols.  */
  symbols = backtrace_symbols (addresses, n);
  /* Check that symbols were obtained.  */
  if (symbols == NULL) 
    {
      FAIL ();
      return;
    }
  for (i = 0; i < n; ++i)
    printf ("Function %d: %s\n", i, symbols[i]);
  /* Check that the function names obtained are accurate.  */
  if (strstr (symbols[0], "fn1") == NULL)
    {
      FAIL ();
      return;
    }
  /* Symbol names are not available for static functions, so we do not
     check f2.  */
  if (strstr (symbols[2], "fn3") == NULL)
    {
      FAIL ();
      return;
    }
  /* Symbol names are not available for static functions, so we do not
     check do_test.  */
}

NO_INLINE static int 
fn2 (void) 
{
  fn1 ();
  /* Prevent tail calls.  */
  return x;
}

NO_INLINE int 
fn3 (void)
{
  fn2();
  /* Prevent tail calls.  */
  return x;
}

NO_INLINE static int 
do_test (void) 
{
  fn3 ();
  return ret;
}
