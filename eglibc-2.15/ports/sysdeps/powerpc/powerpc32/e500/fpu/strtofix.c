/* Convert string representing a number to float value, using given locale.
   Copyright (C) 1997,1998,2002,2004,2005,2006,2008
   Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1997.

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

/* Cut down from strtod_l.c for converting to fixed-point, no locale
   choice, no grouping, narrow strings only.  */


#include <ctype.h>
#include <errno.h>
#include <fenv_libc.h>
#include <locale/localeinfo.h>
#include <locale.h>
#include <math.h>
#include <spe.h>
#include <stdlib.h>
#include <string.h>

/* The gmp headers need some configuration frobs.  */
#define HAVE_ALLOCA 1

/* Include gmp-mparam.h first, such that definitions of _SHORT_LIMB
   and _LONG_LONG_LIMB in it can take effect into gmp.h.  */
#include <gmp-mparam.h>
#include <gmp.h>
#include <stdlib/gmp-impl.h>
#include <stdlib/longlong.h>
#include <stdlib/fpioconst.h>

/*#define NDEBUG 1*/
#include <assert.h>

#if UNSIGNED
#define RETURN_FRAC_BITS RETURN_TYPE_BITS
#else
#define RETURN_FRAC_BITS (RETURN_TYPE_BITS - 1)
#endif

#define RETURN(val,end)					\
    do { if (endptr != NULL) *endptr = (char *) (end);	\
	 return val; } while (0)

/* Definitions according to limb size used.  */
#if	BITS_PER_MP_LIMB == 32
# define MAX_DIG_PER_LIMB	9
# define MAX_FAC_PER_LIMB	1000000000UL
#elif	BITS_PER_MP_LIMB == 64
# define MAX_DIG_PER_LIMB	19
# define MAX_FAC_PER_LIMB	10000000000000000000ULL
#else
# error "mp_limb_t size " BITS_PER_MP_LIMB "not accounted for"
#endif

/* Local data structure.  */
static const mp_limb_t _tens_in_limb[MAX_DIG_PER_LIMB + 1] =
{    0,                   10,                   100,
     1000,                10000,                100000L,
     1000000L,            10000000L,            100000000L,
     1000000000L
#if BITS_PER_MP_LIMB > 32
	        ,	  10000000000ULL,       100000000000ULL,
     1000000000000ULL,    10000000000000ULL,    100000000000000ULL,
     1000000000000000ULL, 10000000000000000ULL, 100000000000000000ULL,
     1000000000000000000ULL, 10000000000000000000ULL
#endif
#if BITS_PER_MP_LIMB > 64
  #error "Need to expand tens_in_limb table to" MAX_DIG_PER_LIMB
#endif
};

/* Define pow5 to be 5^(RETURN_FRAC_BITS + 1), shifted left so the
   most significant bit is set (as required by mpn_divrem), pow5size
   to be the size in limbs and pow5shift to be the shift.  */
#if RETURN_FRAC_BITS + 1 == 16
# if BITS_PER_MP_LIMB == 32
static const mp_limb_t pow5[] = { 0x04000000, 0x8e1bc9bf };
#  define pow5shift 26
#  define pow5size 2
# else
static const mp_limb_t pow5[] = { 0x8e1bc9bf04000000ull };
#  define pow5shift 26
#  define pow5size 1
# endif
#elif RETURN_FRAC_BITS + 1 == 17
# if BITS_PER_MP_LIMB == 32
static const mp_limb_t pow5[] = { 0xc5000000, 0xb1a2bc2e };
#  define pow5shift 24
#  define pow5size 2
# else
static const mp_limb_t pow5[] = { 0xb1a2bc2ec5000000ull };
#  define pow5shift 24
#  define pow5size 1
# endif
#elif RETURN_FRAC_BITS + 1 == 32
# if BITS_PER_MP_LIMB == 32
static const mp_limb_t pow5[] = { 0xf0200000, 0x2b70b59d, 0x9dc5ada8 };
#  define pow5shift 21
#  define pow5size 3
# else
static const mp_limb_t pow5[] = { 0xf020000000000000ull, 0x9dc5ada82b70b59dull };
#  define pow5shift 53
#  define pow5size 2
# endif
#elif RETURN_FRAC_BITS + 1 == 33
# if BITS_PER_MP_LIMB == 32
static const mp_limb_t pow5[] = { 0x6c280000, 0x364ce305, 0xc5371912 };
#  define pow5shift 19
#  define pow5size 3
# else
static const mp_limb_t pow5[] = { 0x6c28000000000000ull, 0xc5371912364ce305ull };
#  define pow5shift 51
#  define pow5size 2
# endif
#elif RETURN_FRAC_BITS + 1 == 64
# if BITS_PER_MP_LIMB == 32
static const mp_limb_t pow5[] = { 0x50f80800, 0xc76b25fb, 0x3cbf6b71, 0xffcfa6d5, 0xc2781f49 };
#  define pow5shift 11
#  define pow5size 5
# else
static const mp_limb_t pow5[] = { 0x50f8080000000000ull, 0x3cbf6b71c76b25fbull, 0xc2781f49ffcfa6d5ull };
#  define pow5shift 43
#  define pow5size 3
# endif
#elif RETURN_FRAC_BITS + 1 == 65
# if BITS_PER_MP_LIMB == 32
static const mp_limb_t pow5[] = { 0x25360a00, 0x3945ef7a, 0x8bef464e, 0x7fc3908a, 0xf316271c };
#  define pow5shift 9
#  define pow5size 5
# else
static const mp_limb_t pow5[] = { 0x25360a0000000000ull, 8bef464e3945ef7aull, 0xf316271c7fc3908aull };
#  define pow5shift 41
#  define pow5size 3
# endif
#else
# error "Unknown RETURN_FRAC_BITS value."
#endif

/* Read a multi-precision integer starting at STR with exactly DIGCNT digits
   into N.  Return the size of the number limbs in NSIZE.  */
static void
str_to_mpn (const char *str, int digcnt, mp_limb_t *n, mp_size_t *nsize)
{
  /* Number of digits for actual limb.  */
  int cnt = 0;
  mp_limb_t low = 0;
  mp_limb_t start;

  *nsize = 0;
  assert (digcnt > 0);
  do
    {
      if (cnt == MAX_DIG_PER_LIMB)
	{
	  if (*nsize == 0)
	    {
	      n[0] = low;
	      *nsize = 1;
	    }
	  else
	    {
	      mp_limb_t cy;
	      cy = __mpn_mul_1 (n, n, *nsize, MAX_FAC_PER_LIMB);
	      cy += __mpn_add_1 (n, n, *nsize, low);
	      if (cy != 0)
		{
		  n[*nsize] = cy;
		  ++(*nsize);
		}
	    }
	  cnt = 0;
	  low = 0;
	}

      low = low * 10 + *str++ - '0';
      ++cnt;
    }
  while (--digcnt > 0);

  start = _tens_in_limb[cnt];

  if (*nsize == 0)
    {
      n[0] = low;
      *nsize = 1;
    }
  else
    {
      mp_limb_t cy;
      cy = __mpn_mul_1 (n, n, *nsize, start);
      cy += __mpn_add_1 (n, n, *nsize, low);
      if (cy != 0)
	n[(*nsize)++] = cy;
    }
}

/* Round a fixed point number according to the current rounding mode
   and set its sign.  VAL is the initial part of the number
   (RETURN_TYPE_BITS for unsigned, one fewer for signed; values equal
   to -1.0 do not come here).  SIGN is 1 for negative, 0 for positive;
   this function will not be called for negative numbers in the
   unsigned case.  HALF is 1 if the next bit is 1; REST is 1 if any of
   the subsequent bits are 1.  */
static RETURN_TYPE
round_and_set_sign (RETURN_TYPE val, int sign, int half, int rest)
{
  int incr = 0;
  unsigned int mode = fegetenv_register ();
  mode &= 3;
  switch (mode)
    {
    case FE_TONEAREST:
      incr = (half && (rest || (val & 1)));
      break;
    case FE_TOWARDZERO:
      break;
    case FE_UPWARD:
      incr = (!sign && (half || rest));
      break;
    case FE_DOWNWARD:
      incr = (sign && (half || rest));
      break;
    }
  if (incr)
    {
      if (val == SAT_MAX)
	{
	  if (sign)
	    val = SAT_MIN;
	  else
	    {
	      __set_errno (ERANGE);
	      return SAT_MAX;
	    }
	}
      else
	{
	  val++;
	  if (sign)
	    val = -val;
	}
    }
  else if (sign)
    val = -val;
  return val;
}

/* Return a fixed point number with the value of the given string
   NPTR, handling out-of-range numbers as described in the SPE PIM.
   Set *ENDPTR to the character after the last used one.  */
RETURN_TYPE
STRTOFIX (const char *nptr, char **endptr)
{
  int negative;			/* The sign of the number.  */
  int exponent;			/* Exponent of the number.  */

  /* Numbers starting `0X' or `0x' have to be processed with base 16.  */
  int base = 10;

  /* Running pointer after the last character processed in the string.  */
  const char *cp;
  /* Start of significant part of the number.  */
  const char *startp, *start_of_digits;
  /* Points at the character following the integer and fractional digits.  */
  const char *expp;
  /* Total number of digit and number of digits in integer part.  */
  int dig_no, int_no, lead_zero;
  /* Contains the last character read.  */
  char c;

  /* The radix character of the current locale.  */
  const char *decimal;
  size_t decimal_len;
  /* Used in several places.  */
  int cnt;

  decimal = _NL_CURRENT (LC_NUMERIC, DECIMAL_POINT);
  decimal_len = strlen (decimal);
  assert (decimal_len > 0);

  /* Prepare number representation.  */
  exponent = 0;
  negative = 0;

  /* Parse string to get maximal legal prefix.  We need the number of
     characters of the integer part, the fractional part and the exponent.  */
  cp = nptr - 1;
  /* Ignore leading white space.  */
  do
    c = *++cp;
  while (isspace (c));

  /* Get sign of the result.  */
  if (c == '-')
    {
      negative = 1;
      c = *++cp;
    }
  else if (c == '+')
    c = *++cp;

  /* Return 0.0 if no legal string is found.
     No character is used even if a sign was found.  */
  for (cnt = 0; decimal[cnt] != '\0'; ++cnt)
    if (cp[cnt] != decimal[cnt])
      break;
  if (decimal[cnt] == '\0' && cp[cnt] >= '0' && cp[cnt] <= '9')
    {
      /* We accept it.  This funny construct is here only to indent
	 the code directly.  */
    }
  else if (c < '0' || c > '9')
    {
      /* The SPE PIM says NaN and Inf are not supported.  */
      /* It is really a text we do not recognize.  */
      RETURN (0, nptr);
    }

  /* First look whether we are faced with a hexadecimal number.  */
  if (c == '0' && tolower (cp[1]) == 'x')
    {
      /* Okay, it is a hexa-decimal number.  Remember this and skip
	 the characters.  BTW: hexadecimal numbers must not be
	 grouped.  */
      base = 16;
      cp += 2;
      c = *cp;
    }

  /* Record the start of the digits, in case we will check their grouping.  */
  start_of_digits = startp = cp;

  /* Ignore leading zeroes.  This helps us to avoid useless computations.  */
  while (c == '0')
    c = *++cp;

  /* If no other digit but a '0' is found the result is 0.0.
     Return current read pointer.  */
  if ((c < '0' || c > '9')
      && (base != 16 || (c < (char) tolower ('a')
			 || c > (char) tolower ('f')))
      && ({ for (cnt = 0; decimal[cnt] != '\0'; ++cnt)
	      if (decimal[cnt] != cp[cnt])
		break;
	    decimal[cnt] != '\0'; })
      && (base != 16 || (cp == start_of_digits
			 || (char) tolower (c) != 'p'))
      && (base == 16 || (char) tolower (c) != 'e'))
    {
      /* If CP is at the start of the digits, there was no correctly
	 grouped prefix of the string; so no number found.  */
      RETURN (0, cp == start_of_digits ? (base == 16 ? cp - 1 : nptr) : cp);
    }

  /* Remember first significant digit and read following characters until the
     decimal point, exponent character or any non-FP number character.  */
  startp = cp;
  dig_no = 0;
  while (1)
    {
      if ((c >= '0' && c <= '9')
	  || (base == 16 && tolower (c) >= 'a'
	      && tolower (c) <= 'f'))
	++dig_no;
      else
	{
	  break;
	}
      c = *++cp;
    }

  /* We have the number digits in the integer part.  Whether these are all or
     any is really a fractional digit will be decided later.  */
  int_no = dig_no;
  lead_zero = int_no == 0 ? -1 : 0;

  /* Read the fractional digits.  A special case are the 'american style'
     numbers like `16.' i.e. with decimal but without trailing digits.  */
  if (
      ({ for (cnt = 0; decimal[cnt] != '\0'; ++cnt)
	   if (decimal[cnt] != cp[cnt])
	     break;
	 decimal[cnt] == '\0'; })
      )
    {
      cp += decimal_len;
      c = *cp;
      while ((c >= '0' && c <= '9') ||
	     (base == 16 && tolower (c) >= 'a' && tolower (c) <= 'f'))
	{
	  if (c != '0' && lead_zero == -1)
	    lead_zero = dig_no - int_no;
	  ++dig_no;
	  c = *++cp;
	}
    }

  /* For numbers like "0x." with no hex digits, only the "0" is valid.  */
  if (base == 16
      && startp == start_of_digits
      && dig_no == 0)
    RETURN (0, start_of_digits - 1);

  /* Remember start of exponent (if any).  */
  expp = cp;

  /* Read exponent.  */
  if ((base == 16 && tolower (c) == 'p')
      || (base != 16 && tolower (c) == 'e'))
    {
      int exp_negative = 0;

      c = *++cp;
      if (c == '-')
	{
	  exp_negative = 1;
	  c = *++cp;
	}
      else if (c == '+')
	c = *++cp;

      if (c >= '0' && c <= '9')
	{
	  int exp_limit;

	  /* Get the exponent limit. */
	  if (base == 16)
	    exp_limit = (exp_negative ?
			 RETURN_TYPE_BITS + 4 * int_no :
			 4 - 4 * int_no + 4 * lead_zero);
	  else
	    exp_limit = (exp_negative ?
			 (RETURN_TYPE_BITS + 2) / 3 + int_no :
			 1 - int_no + lead_zero);

	  do
	    {
	      exponent *= 10;

	      if (exponent > exp_limit)
		/* The exponent is too large/small to represent a valid
		   number.  */
		{
		  RETURN_TYPE result;

		  /* Accept all following digits as part of the exponent.  */
		  do
		    ++cp;
		  while (*cp >= '0' && *cp <= '9');

		  /* We have to take care for special situation: a joker
		     might have written "0.0e100000" which is in fact
		     zero.  */
		  if (lead_zero == -1)
		    result = 0;
#if UNSIGNED
		  else if (negative)
		    {
		      /* Saturate to 0.  */
		      __set_errno (ERANGE);
		      result = SAT_MIN;
		    }
#endif
		  else if (exp_negative)
		    {
		      /* Round to either 0 or smallest value.  */
		      result = round_and_set_sign (0, negative, 0, 1);
		    }
		  else
		    {
		      /* Overflow.  */
		      __set_errno (ERANGE);
		      result = (negative ? SAT_MIN : SAT_MAX);
		    }

		  RETURN (result, cp);
		  /* NOTREACHED */
		}

	      exponent += c - '0';
	      c = *++cp;
	    }
	  while (c >= '0' && c <= '9');

	  if (exp_negative)
	    exponent = -exponent;
	}
      else
	cp = expp;
    }

  /* We don't want to have to work with trailing zeroes after the radix.  */
  if (dig_no > int_no)
    {
      while (expp[-1] == '0')
	{
	  --expp;
	  --dig_no;
	}
      assert (dig_no >= int_no);
    }

  if (dig_no == int_no && dig_no > 0)
    do
      {
	while (! (base == 16 ? isxdigit (expp[-1]) : isdigit (expp[-1])))
	  --expp;

	if (expp[-1] != '0')
	  break;

	--expp;
	--dig_no;
	--int_no;
	exponent += (base == 16 ? 4 : 1);
      }
    while (dig_no > 0);

  /* The whole string is parsed.  Store the address of the next character.  */
  if (endptr)
    *endptr = (char *) cp;

  if (dig_no == 0)
    return 0;

#if UNSIGNED
  if (negative)
    {
      /* Saturate to 0.  */
      __set_errno (ERANGE);
      return SAT_MIN;
    }
#endif

  if (lead_zero)
    {
      /* Find the decimal point */
      while (1)
	{
	  if (*startp == decimal[0])
	    {
	      for (cnt = 1; decimal[cnt] != '\0'; ++cnt)
		if (decimal[cnt] != startp[cnt])
		  break;
	      if (decimal[cnt] == '\0')
		break;
	    }
	  ++startp;
	}
      startp += lead_zero + decimal_len;
      exponent -= base == 16 ? 4 * lead_zero : lead_zero;
      dig_no -= lead_zero;
    }

  /* Normalize the exponent so that all digits can be considered to
     start just after the point.  */
  exponent += base == 16 ? 4 * int_no : int_no;

  if (exponent > (base == 16 ? 4 : 1))
    {
      /* Overflow.  */
      __set_errno (ERANGE);
      return (negative ? SAT_MIN : SAT_MAX);
    }

  /* Copy just the digits needed to a separate buffer.  */
  int digits_needed = (base == 16 ? RETURN_TYPE_BITS / 4 + 2 : RETURN_FRAC_BITS + 1);
  char buf[RETURN_TYPE_BITS + 1];
  int digits_copied = 0;
  int extra = 0;
  int rdigno = dig_no;
  while (exponent < 0)
    {
      buf[digits_copied++] = '0';
      exponent += (base == 16 ? 4 : 1);
      if (digits_copied == digits_needed)
	return round_and_set_sign (0, negative, 0, 1);
    }
  while (digits_copied < digits_needed && rdigno > 0)
    {
      if (!(base == 16 ? isxdigit (*startp) : isdigit (*startp)))
	startp += decimal_len;
      buf[digits_copied++] = *startp++;
      rdigno--;
    }
  if (rdigno)
    extra = 1;
  else
    while (digits_copied < digits_needed)
      buf[digits_copied++] = '0';

  if (base == 10 && exponent == 1)
    {
      assert (buf[0] != '0');
      /* At least 1.0; see if there is overflow.  */
      if (UNSIGNED
	  || !negative
	  || buf[0] > '1'
	  || dig_no > 1)
	__set_errno (ERANGE);
      return (negative ? SAT_MIN : SAT_MAX);
    }

  if (base == 16 && exponent > 0)
    {
      int max_dig = (16 >> exponent) + '0';
      assert (buf[0] != '0');
      if (buf[0] >= max_dig)
	{
	  /* At least 1.0; see if there is overflow.  */
	  if (UNSIGNED
	      || !negative
	      || buf[0] > max_dig
	      || dig_no > 1)
	    __set_errno (ERANGE);
	  return (negative ? SAT_MIN : SAT_MAX);
	}
    }

  /* Now strictly in the range (0, 1) (though rounding may yet
     saturate to 1.0).  */
  if (base == 10)
    assert (exponent == 0);
  else
    assert (exponent >= 0 && exponent <= 3);

  if (base == 16)
    {
      RETURN_TYPE r = 0;
      int half = 0;
      for (int i = 0; i < digits_needed; i++)
	{
	  RETURN_TYPE val;
	  int shift;
	  if (isdigit (buf[i]))
	    val = buf[i] - '0';
	  else
	    val = 10 + tolower (buf[i]) - 'a';
	  shift = RETURN_FRAC_BITS - 4 + exponent - 4 * i;
	  if (shift >= 0)
	    r |= val << shift;
	  else if (shift < -4)
	    extra |= (val != 0);
	  else
	    {
	      r |= val >> -shift;
	      half = (val & (1 << (-shift - 1))) != 0;
	      extra |= (val & ((1 << (-shift - 1)) - 1)) != 0;
	    }
	}
      return round_and_set_sign (r, negative, half, extra);
    }

  /* Now we have RETURN_FRAC_BITS + 1 digits after the decimal point.
     Interpret these as an integer and divide by 5^(RETURN_FRAC_BITS +
     1).  If there is a remainder, set extra.  If the result of the
     division is odd, set half.  Divide by 2 again, and round the
     result.  */
  mp_limb_t frac[8];
  mp_size_t fracsize;
  str_to_mpn (buf, digits_needed, frac, &fracsize);
  if (fracsize < pow5size)
    return round_and_set_sign (0, negative, 0, 1);
  frac[fracsize] = __mpn_lshift (frac, frac, fracsize, pow5shift);
  if (frac[fracsize])
    fracsize++;
  mp_limb_t quot[8];
  quot[fracsize - pow5size] = mpn_divmod (quot, frac, fracsize, pow5, pow5size);
  for (int i = 0; i < pow5size; i++)
    if (frac[i])
      extra = 1;
  int half = quot[0] & 1;
  RETURN_TYPE val = quot[0] >> 1;
#if RETURN_FRAC_BITS > BITS_PER_MP_LIMB - 1
  val |= ((RETURN_TYPE) quot[1]) << (BITS_PER_MP_LIMB - 1);
# if RETURN_FRAC_BITS > 2 * BITS_PER_MP_LIMB - 1
  val |= ((RETURN_TYPE) quot[2]) << (2 * BITS_PER_MP_LIMB - 1);
#  if RETURN_FRAC_BITS > 3 * BITS_PER_MP_LIMB - 1
#   error "Too many bits."
#  endif
# endif
#endif
  return round_and_set_sign (val, negative, half, extra);
}

libc_hidden_def (STRTOFIX)
