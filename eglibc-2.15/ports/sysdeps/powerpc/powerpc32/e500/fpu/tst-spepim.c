/* Test SPE PIM functions.
   Copyright (C) 2007 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Joseph Myers <joseph@codesourcery.com>, 2007.

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
#include <fenv.h>
#include <spe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int16_t sint16_t;
typedef int32_t sint32_t;
typedef int64_t sint64_t;

#define SAT_MAX_U16	0xffff
#define SAT_MAX_U32	0xffffffffu
#define SAT_MAX_U64	0xffffffffffffffffull
#define SAT_MAX_S16	0x7fff
#define SAT_MAX_S32	0x7fffffff
#define SAT_MAX_S64	0x7fffffffffffffffll
#define SAT_MIN_S16	(-SAT_MAX_S16 - 1)
#define SAT_MIN_S32	(-SAT_MAX_S32 - 1)
#define SAT_MIN_S64	(-SAT_MAX_S64 - 1)

/* Test results for a single rounding mode.  For each type of result,
   store the expected result and the expected errno.  */
struct res {
  sint16_t s16;
  int es16;
  sint32_t s32;
  int es32;
  sint64_t s64;
  int es64;
  uint16_t u16;
  int eu16;
  uint32_t u32;
  int eu32;
  uint64_t u64;
  int eu64;
};

struct testcase {
  /* String to test.  */
  const char *s;
  /* Number of junk characters at end.  */
  size_t njunk;
  /* Expected results for rounding to nearest, zero, upward and
     downward.  */
  struct res res[4];
};

/* Saturating value.  */
#define SAT(VAL)	VAL, ERANGE
/* Unsaturating value.  */
#define UNSAT(VAL)	VAL, 0
/* Values saturating for both signed and unsigned.  */
#define SAT6(VAL0, VAL1, VAL2, VAL3, VAL4, VAL5)	\
  {							\
    SAT (VAL0), SAT (VAL1), SAT (VAL2),			\
    SAT (VAL3), SAT (VAL4), SAT (VAL5)			\
  }
#define SAT6_MAX				\
  SAT6 (SAT_MAX_S16, SAT_MAX_S32, SAT_MAX_S64,	\
	SAT_MAX_U16, SAT_MAX_U32, SAT_MAX_U64)
#define SAT6_MIN					\
  SAT6 (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64, 0, 0, 0)
/* Values saturating for unsigned but not signed.  */
#define SATNEG(VAL0, VAL1, VAL2)		\
  {						\
    UNSAT (VAL0), UNSAT (VAL1), UNSAT (VAL2),	\
    SAT (0), SAT (0), SAT (0)			\
  }
/* Values not saturating.  */
#define UNSAT6(VAL0, VAL1, VAL2, VAL3, VAL4, VAL5)	\
  {							\
    UNSAT (VAL0), UNSAT (VAL1), UNSAT (VAL2),		\
    UNSAT (VAL3), UNSAT (VAL4), UNSAT (VAL5)		\
  }
/* Results not depending on rounding mode.  */
#define EXACT_SAT6_MAX				\
  {						\
    SAT6_MAX,					\
    SAT6_MAX,					\
    SAT6_MAX,					\
    SAT6_MAX					\
  }
#define EXACT_SAT6_MIN				\
  {						\
    SAT6_MIN,					\
    SAT6_MIN,					\
    SAT6_MIN,					\
    SAT6_MIN					\
  }
#define EXACT_SATNEG(VAL0, VAL1, VAL2)		\
  {						\
    SATNEG (VAL0, VAL1, VAL2),			\
    SATNEG (VAL0, VAL1, VAL2),			\
    SATNEG (VAL0, VAL1, VAL2),			\
    SATNEG (VAL0, VAL1, VAL2)			\
  }
#define EXACT_UNSAT6(VAL0, VAL1, VAL2, VAL3, VAL4, VAL5)	\
  {								\
    UNSAT6 (VAL0, VAL1, VAL2, VAL3, VAL4, VAL5),		\
    UNSAT6 (VAL0, VAL1, VAL2, VAL3, VAL4, VAL5),		\
    UNSAT6 (VAL0, VAL1, VAL2, VAL3, VAL4, VAL5),		\
    UNSAT6 (VAL0, VAL1, VAL2, VAL3, VAL4, VAL5)			\
  }

static const struct testcase tests[] = {
  /* Strings evaluating to 0, including INF and NaN (not supported by
     SPE PIM functions).  */
  { "", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "00", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "+0", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "-0", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0.0", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { ".0", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0.", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { " \n-0.", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0e100000000000000000", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { " \t 0e-100000000000000000", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0x0", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0x0.", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0x.0", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0x0.p100000000000000000", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "-0x0.p002000000000000000", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0x.0p-100000000000000000", 0, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0x", 1, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0x.", 2, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { ".", 1, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { " .", 2, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "+.", 2, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { " +.", 3, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { " -.", 3, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0xp", 2, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0x.p", 3, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "+0x.p", 3, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "-0x.p0", 4, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "0x0q", 1, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "INF", 3, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  { "nan", 3, EXACT_UNSAT6 (0, 0, 0, 0, 0, 0) },
  /* Strings evaluating to 1.0 or greater, saturating unconditionally.  */
  { "1", 0, EXACT_SAT6_MAX },
  { "1.0", 0, EXACT_SAT6_MAX },
  { "1e0", 0, EXACT_SAT6_MAX },
  { "10e-1", 0, EXACT_SAT6_MAX },
  { "0.1e1", 0, EXACT_SAT6_MAX },
  { "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e-100", 0, EXACT_SAT6_MAX },
  { "2", 0, EXACT_SAT6_MAX },
  { "0x1", 0, EXACT_SAT6_MAX },
  { "0x2p-1", 0, EXACT_SAT6_MAX },
  { "0x.8p1", 0, EXACT_SAT6_MAX },
  { "0x.40p2", 0, EXACT_SAT6_MAX },
  /* Strings evaluating to less than -1.0, saturating unconditionally.  */
  { "-1.1", 0, EXACT_SAT6_MIN },
  { "-.11e1", 0, EXACT_SAT6_MIN },
  { "-11e-1", 0, EXACT_SAT6_MIN },
  { "-100", 0, EXACT_SAT6_MIN },
  { "-2", 0, EXACT_SAT6_MIN },
  { "-0x1.00000000000000000000000001", 0, EXACT_SAT6_MIN },
  { "-0x2.00000000000000000000000001p-1", 0, EXACT_SAT6_MIN },
  { "-0x0.80000000000000000000000001p1", 0, EXACT_SAT6_MIN },
  { "-1.000000000000000000000000000000000000000000000000000000000000000000000000000000001", 0, EXACT_SAT6_MIN },
  /* Strings evaluating to -1.0 exactly, saturating for unsigned but
     exactly representable for signed.  */
  { "-1", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-1e", 1, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-1.0", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-10e-1", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-.1e+1", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-.0000000001e+10", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-10000000000e-10", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-0x1", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-0x1p+", 2, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-0x2p-1", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-0x4.0p-2", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-0x8.p-3", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-0x10p-4", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-0x.8p1", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-0x.4p+2", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-0x.2p+3", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-0x.1p+4", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  { "-0x.08p5", 0, EXACT_SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64) },
  /* Strings evaluating to exactly representable values between -1.0
     and 0.0, saturating for unsigned.  */
  { "-0.5", 0, EXACT_SATNEG (-0x4000, -0x40000000, -0x4000000000000000ll) },
  { "-0.5e-", 2, EXACT_SATNEG (-0x4000, -0x40000000, -0x4000000000000000ll) },
  { "-05e-1", 0, EXACT_SATNEG (-0x4000, -0x40000000, -0x4000000000000000ll) },
  { "-05000000000e-10", 0, EXACT_SATNEG (-0x4000, -0x40000000, -0x4000000000000000ll) },
  { "-0.5e0", 0, EXACT_SATNEG (-0x4000, -0x40000000, -0x4000000000000000ll) },
  { "-0.00000000005e10", 0, EXACT_SATNEG (-0x4000, -0x40000000, -0x4000000000000000ll) },
  { "-0x.8", 0, EXACT_SATNEG (-0x4000, -0x40000000, -0x4000000000000000ll) },
  { "-0x1p-1", 0, EXACT_SATNEG (-0x4000, -0x40000000, -0x4000000000000000ll) },
  { "-0x.4p1", 0, EXACT_SATNEG (-0x4000, -0x40000000, -0x4000000000000000ll) },
  { "-0.25", 0, EXACT_SATNEG (-0x2000, -0x20000000, -0x2000000000000000ll) },
  { "-2.5e-1", 0, EXACT_SATNEG (-0x2000, -0x20000000, -0x2000000000000000ll) },
  { "-0.75", 0, EXACT_SATNEG (-0x6000, -0x60000000, -0x6000000000000000ll) },
  { "-0.000030517578125", 0, EXACT_SATNEG (-0x0001, -0x00010000, -0x0001000000000000ll) },
  { "-0.376739501953125", 0, EXACT_SATNEG (-12345, -12345*0x10000, -12345*0x1000000000000ll) },
  { "-0x.dcba", 0, EXACT_SATNEG (-0x6e5d, -0x6e5d0000, -0x6e5d000000000000ll) },
  { "-0xd.cbap-4", 0, EXACT_SATNEG (-0x6e5d, -0x6e5d0000, -0x6e5d000000000000ll) },
  /* Strings evaluating to exactly representable values between 0.0
     and 1.0.  */
  { "0.5", 0, EXACT_UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000000ull) },
  { "0.5e-", 2, EXACT_UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000000ull) },
  { "05e-1", 0, EXACT_UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000000ull) },
  { "05000000000e-10", 0, EXACT_UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000000ull) },
  { "0.5e0", 0, EXACT_UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000000ull) },
  { "0.00000000005e10", 0, EXACT_UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000000ull) },
  { "0x.8", 0, EXACT_UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000000ull) },
  { "0x1p-1", 0, EXACT_UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000000ull) },
  { "0x.4p1", 0, EXACT_UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000000ull) },
  { "0.25", 0, EXACT_UNSAT6 (0x2000, 0x20000000, 0x2000000000000000ll, 0x4000, 0x40000000u, 0x4000000000000000ull) },
  { "2.5e-1", 0, EXACT_UNSAT6 (0x2000, 0x20000000, 0x2000000000000000ll, 0x4000, 0x40000000u, 0x4000000000000000ull) },
  { "0.75", 0, EXACT_UNSAT6 (0x6000, 0x60000000, 0x6000000000000000ll, 0xc000, 0xc0000000u, 0xc000000000000000ull) },
  { "0.000030517578125", 0, EXACT_UNSAT6 (0x0001, 0x00010000, 0x0001000000000000ll, 0x0002, 0x00020000u, 0x0002000000000000ull) },
  { "0.376739501953125", 0, EXACT_UNSAT6 (12345, 12345*0x10000, 12345*0x1000000000000ll, 12345*0x2, 12345*0x20000u, 12345*0x2000000000000ull) },
  { "0x.dcba", 0, EXACT_UNSAT6 (0x6e5d, 0x6e5d0000, 0x6e5d000000000000ll, 0xdcba, 0xdcba0000u, 0xdcba000000000000ull) },
  { "0xd.cbap-4", 0, EXACT_UNSAT6 (0x6e5d, 0x6e5d0000, 0x6e5d000000000000ll, 0xdcba, 0xdcba0000u, 0xdcba000000000000ull) },
  /* Strings evaluating to values between 0.0 and 1.0, depending on
     rounding mode.  */
  { "0.1", 0,
    {
      UNSAT6 (0xccd, 0xccccccd, 0xccccccccccccccdll, 0x199a, 0x1999999au, 0x199999999999999aull),
      UNSAT6 (0xccc, 0xccccccc, 0xcccccccccccccccll, 0x1999, 0x19999999u, 0x1999999999999999ull),
      UNSAT6 (0xccd, 0xccccccd, 0xccccccccccccccdll, 0x199a, 0x1999999au, 0x199999999999999aull),
      UNSAT6 (0xccc, 0xccccccc, 0xcccccccccccccccll, 0x1999, 0x19999999u, 0x1999999999999999ull)
    }
  },
  { "0.5000152587890625", 0,
    {
      UNSAT6 (0x4000, 0x40008000, 0x4000800000000000ll, 0x8001, 0x80010000u, 0x8001000000000000ull),
      UNSAT6 (0x4000, 0x40008000, 0x4000800000000000ll, 0x8001, 0x80010000u, 0x8001000000000000ull),
      UNSAT6 (0x4001, 0x40008000, 0x4000800000000000ll, 0x8001, 0x80010000u, 0x8001000000000000ull),
      UNSAT6 (0x4000, 0x40008000, 0x4000800000000000ll, 0x8001, 0x80010000u, 0x8001000000000000ull)
    }
  },
  { "0.50001525878906250000000000000000000000000000000000000000000000000000000000001", 0,
    {
      UNSAT6 (0x4001, 0x40008000, 0x4000800000000000ll, 0x8001, 0x80010000u, 0x8001000000000000ull),
      UNSAT6 (0x4000, 0x40008000, 0x4000800000000000ll, 0x8001, 0x80010000u, 0x8001000000000000ull),
      UNSAT6 (0x4001, 0x40008001, 0x4000800000000001ll, 0x8002, 0x80010001u, 0x8001000000000001ull),
      UNSAT6 (0x4000, 0x40008000, 0x4000800000000000ll, 0x8001, 0x80010000u, 0x8001000000000000ull)
    }
  },
  { "0.50000000000000000008131516293641283255055896006524562835693359375", 0,
    {
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000001ll, 0x8000, 0x80000000u, 0x8000000000000002ull),
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000001ull),
      UNSAT6 (0x4001, 0x40000001, 0x4000000000000001ll, 0x8001, 0x80000001u, 0x8000000000000002ull),
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000001ull)
    }
  },
  { "0.50000000000000000008131516293641283255055896006524562835693359376", 0,
    {
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000001ll, 0x8000, 0x80000000u, 0x8000000000000002ull),
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000001ull),
      UNSAT6 (0x4001, 0x40000001, 0x4000000000000001ll, 0x8001, 0x80000001u, 0x8000000000000002ull),
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000001ull)
    }
  },
  { "0.50000000000000000008131516293641283255055896006524562835693359374", 0,
    {
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000001ll, 0x8000, 0x80000000u, 0x8000000000000001ull),
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000001ull),
      UNSAT6 (0x4001, 0x40000001, 0x4000000000000001ll, 0x8001, 0x80000001u, 0x8000000000000002ull),
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000001ull)
    }
  },
  { "0x0.80000000000000018", 0,
    {
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000001ll, 0x8000, 0x80000000u, 0x8000000000000002ull),
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000001ull),
      UNSAT6 (0x4001, 0x40000001, 0x4000000000000001ll, 0x8001, 0x80000001u, 0x8000000000000002ull),
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000001ull)
    }
  },
  { "0x0.80000000000000017", 0,
    {
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000001ll, 0x8000, 0x80000000u, 0x8000000000000001ull),
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000001ull),
      UNSAT6 (0x4001, 0x40000001, 0x4000000000000001ll, 0x8001, 0x80000001u, 0x8000000000000002ull),
      UNSAT6 (0x4000, 0x40000000, 0x4000000000000000ll, 0x8000, 0x80000000u, 0x8000000000000001ull)
    }
  },
  /* Strings evaluating to values between -1.0 and 0.0, depending on
     rounding mode.  */
  { "-0.1", 0,
    {
      SATNEG (-0xccd, -0xccccccd, -0xccccccccccccccdll),
      SATNEG (-0xccc, -0xccccccc, -0xcccccccccccccccll),
      SATNEG (-0xccc, -0xccccccc, -0xcccccccccccccccll),
      SATNEG (-0xccd, -0xccccccd, -0xccccccccccccccdll)
    }
  },
  { "-0.5000000000000000001626303258728256651011179201304912567138671875", 0,
    {
      SATNEG (-0x4000, -0x40000000, -0x4000000000000002ll),
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4001, -0x40000001, -0x4000000000000002ll)
    }
  },
  { "-0.5000000000000000001626303258728256651011179201304912567138671874", 0,
    {
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4001, -0x40000001, -0x4000000000000002ll)
    }
  },
  { "-0.5000000000000000001626303258728256651011179201304912567138671876", 0,
    {
      SATNEG (-0x4000, -0x40000000, -0x4000000000000002ll),
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4001, -0x40000001, -0x4000000000000002ll)
    }
  },
  { "-0x.8000000000000003", 0,
    {
      SATNEG (-0x4000, -0x40000000, -0x4000000000000002ll),
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4001, -0x40000001, -0x4000000000000002ll)
    }
  },
  { "-0x.8000000000000002f", 0,
    {
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4000, -0x40000000, -0x4000000000000001ll),
      SATNEG (-0x4001, -0x40000001, -0x4000000000000002ll)
    }
  },
  /* Strings evaluating very close to 1.0, saturation depending on
     rounding mode.  */
  { "0x.fffe1", 0,
    {
      { UNSAT (0x7fff), UNSAT (0x7fff0800), UNSAT (0x7fff080000000000ll), UNSAT (0xfffe), UNSAT (0xfffe1000u), UNSAT (0xfffe100000000000ull) },
      { UNSAT (0x7fff), UNSAT (0x7fff0800), UNSAT (0x7fff080000000000ll), UNSAT (0xfffe), UNSAT (0xfffe1000u), UNSAT (0xfffe100000000000ull) },
      { SAT (0x7fff), UNSAT (0x7fff0800), UNSAT (0x7fff080000000000ll), UNSAT (0xffff), UNSAT (0xfffe1000u), UNSAT (0xfffe100000000000ull) },
      { UNSAT (0x7fff), UNSAT (0x7fff0800), UNSAT (0x7fff080000000000ll), UNSAT (0xfffe), UNSAT (0xfffe1000u), UNSAT (0xfffe100000000000ull) }
    }
  },
  { "0x.ffff8", 0,
    {
      { SAT (0x7fff), UNSAT (0x7fffc000), UNSAT (0x7fffc00000000000ll), SAT (0xffff), UNSAT (0xffff8000u), UNSAT (0xffff800000000000ull) },
      { UNSAT (0x7fff), UNSAT (0x7fffc000), UNSAT (0x7fffc00000000000ll), UNSAT (0xffff), UNSAT (0xffff8000u), UNSAT (0xffff800000000000ull) },
      { SAT (0x7fff), UNSAT (0x7fffc000), UNSAT (0x7fffc00000000000ll), SAT (0xffff), UNSAT (0xffff8000u), UNSAT (0xffff800000000000ull) },
      { UNSAT (0x7fff), UNSAT (0x7fffc000), UNSAT (0x7fffc00000000000ll), UNSAT (0xffff), UNSAT (0xffff8000u), UNSAT (0xffff800000000000ull) }
    }
  },
  { "0x.fffffffffffffffff", 0,
    {
      { SAT (0x7fff), SAT (0x7fffffff), SAT (0x7fffffffffffffffll), SAT (0xffff), SAT (0xffffffffu), SAT (0xffffffffffffffffull) },
      { UNSAT (0x7fff), UNSAT (0x7fffffff), UNSAT (0x7fffffffffffffffll), UNSAT (0xffff), UNSAT (0xffffffffu), UNSAT (0xffffffffffffffffull) },
      { SAT (0x7fff), SAT (0x7fffffff), SAT (0x7fffffffffffffffll), SAT (0xffff), SAT (0xffffffffu), SAT (0xffffffffffffffffull) },
      { UNSAT (0x7fff), UNSAT (0x7fffffff), UNSAT (0x7fffffffffffffffll), UNSAT (0xffff), UNSAT (0xffffffffu), UNSAT (0xffffffffffffffffull) }
    }
  },
  /* Strings evaluating very close to -1.0, may round to -1 but only
     saturate for unsigned.  */
  { "-0x.fffe1", 0,
    {
      SATNEG (-0x7fff, -0x7fff0800, -0x7fff080000000000ll),
      SATNEG (-0x7fff, -0x7fff0800, -0x7fff080000000000ll),
      SATNEG (-0x7fff, -0x7fff0800, -0x7fff080000000000ll),
      SATNEG (SAT_MIN_S16, -0x7fff0800, -0x7fff080000000000ll)
    }
  },
  { "-0x.ffffffffffffffff", 0,
    {
      SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64),
      SATNEG (-0x7fff, -0x7fffffff, -0x7fffffffffffffffll),
      SATNEG (-0x7fff, -0x7fffffff, -0x7fffffffffffffffll),
      SATNEG (SAT_MIN_S16, SAT_MIN_S32, SAT_MIN_S64)
    }
  }
};

static const int rounding_modes[4] = {
  FE_TONEAREST,
  FE_TOWARDZERO,
  FE_UPWARD,
  FE_DOWNWARD
};

static const char *const mode_names[4] = {
  "FE_TONEAREST",
  "FE_TOWARDZERO",
  "FE_UPWARD",
  "FE_DOWNWARD"
};

int
main (void)
{
  int passes = 0;
  int fails = 0;
  size_t i;
  for (i = 0; i < sizeof (tests) / sizeof (tests[0]); i++)
    {
      size_t j;
      for (j = 0; j < 4; j++)
	{
	  if (fesetround (rounding_modes[j]) != 0)
	    {
	      printf ("fesetround (%s) failed.\n", mode_names[j]);
	      abort ();
	    }
#define DO_TEST(SU, SZ, PR)						\
	  do {								\
	    SU##int##SZ##_t expret = tests[i].res[j].SU##SZ;		\
	    int experr = tests[i].res[j].e##SU##SZ;			\
	    size_t explen = strlen (tests[i].s) - tests[i].njunk;	\
	    SU##int##SZ##_t ret0, ret1;					\
	    int reterr;							\
	    size_t retlen;						\
	    char *ep;							\
	    errno = 0;							\
	    ret0 = strto##SU##fix##SZ (tests[i].s, &ep);		\
	    reterr = errno;						\
	    retlen = ep - tests[i].s;					\
	    if (ret0 == expret)						\
	      passes++;							\
	    else							\
	      {								\
		fails++;						\
		printf ("strto"#SU"fix"#SZ" (\"%s\") in mode %s "	\
			"returned %0"PR"x, expected %0"PR"x.\n",	\
			tests[i].s, mode_names[j], ret0, expret);	\
	      }								\
	    if (reterr == experr)					\
	      passes++;							\
	    else							\
	      {								\
		fails++;						\
		printf ("strto"#SU"fix"#SZ" (\"%s\") in mode %s "	\
			"left errno as %d, expected %d.\n",		\
			tests[i].s, mode_names[j], reterr, experr);	\
	      }								\
	    if (retlen == explen)					\
	      passes++;							\
	    else							\
	      {								\
		fails++;						\
		printf ("strto"#SU"fix"#SZ" (\"%s\") in mode %s "	\
			"consumed %zu characters, expected %zu.\n",	\
			tests[i].s, mode_names[j], retlen, explen);	\
	      }								\
	    if (experr == 0)						\
	      {								\
		ret1 = ato##SU##fix##SZ (tests[i].s);			\
		if (ret1 == expret)					\
		  passes++;						\
		else							\
		  {							\
		    fails++;						\
		    printf ("ato"#SU"fix"#SZ" (\"%s\") in mode %s "	\
			    "returned %0"PR"x, expected %0"PR"x.\n",	\
			    tests[i].s, mode_names[j], ret1, expret);	\
		  }							\
	      }								\
	  } while (0)
	  DO_TEST (s, 16, "4h");
	  DO_TEST (s, 32, "8");
	  DO_TEST (s, 64, "16ll");
	  DO_TEST (u, 16, "4h");
	  DO_TEST (u, 32, "8");
	  DO_TEST (u, 64, "16ll");
	}
    }
  printf ("Number of passes: %d\nNumber of failures: %d\n", passes, fails);
  return fails != 0;
}
