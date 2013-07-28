/* Copyright (C) 2008, 2009, 2010
   Free Software Foundation, Inc.
   This file is part of the GNU C Library.

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

/* eglibc: The following piece of code was extracted from
   confstr.c to share it with cross-getconf.c.  */

    case _CS_V7_WIDTH_RESTRICTED_ENVS:
      /* We have to return a newline-separated list of named of
	 programming environements in which the widths of blksize_t,
	 cc_t, mode_t, nfds_t, pid_t, ptrdiff_t, size_t, speed_t,
	 ssize_t, suseconds_t, tcflag_t, useconds_t, wchar_t, and
	 wint_t types are no greater than the width of type long.

	 Currently this means all environment which the system allows.  */
      {
	char restenvs[4 * sizeof "POSIX_V7_LPBIG_OFFBIG"];

	string_len = 0;
#ifndef _POSIX_V7_ILP32_OFF32
	if (__sysconf (_SC_V7_ILP32_OFF32) > 0)
#endif
#if !defined _POSIX_V7_ILP32_OFF32 || _POSIX_V7_ILP32_OFF32 > 0
	  {
	    memcpy (restenvs + string_len, "POSIX_V7_ILP32_OFF32",
		    sizeof "POSIX_V7_ILP32_OFF32" - 1);
	    string_len += sizeof "POSIX_V7_ILP32_OFF32" - 1;
	  }
#endif
#ifndef _POSIX_V7_ILP32_OFFBIG
	if (__sysconf (_SC_V7_ILP32_OFFBIG) > 0)
#endif
#if !defined _POSIX_V7_ILP32_OFFBIG || _POSIX_V7_ILP32_OFFBIG > 0
	  {
	    if (string_len)
	      restenvs[string_len++] = '\n';
	    memcpy (restenvs + string_len, "POSIX_V7_ILP32_OFFBIG",
		    sizeof "POSIX_V7_ILP32_OFFBIG" - 1);
	    string_len += sizeof "POSIX_V7_ILP32_OFFBIG" - 1;
	  }
#endif
#ifndef _POSIX_V7_LP64_OFF64
	if (__sysconf (_SC_V7_LP64_OFF64) > 0)
#endif
#if !defined _POSIX_V7_LP64_OFF64 || _POSIX_V7_LP64_OFF64 > 0
	  {
	    if (string_len)
	      restenvs[string_len++] = '\n';
	    memcpy (restenvs + string_len, "POSIX_V7_LP64_OFF64",
		    sizeof "POSIX_V7_LP64_OFF64" - 1);
	    string_len += sizeof "POSIX_V7_LP64_OFF64" - 1;
	  }
#endif
#ifndef _POSIX_V7_LPBIG_OFFBIG
	if (__sysconf (_SC_V7_LPBIG_OFFBIG) > 0)
#endif
#if !defined _POSIX_V7_LPBIG_OFFBIG || _POSIX_V7_LPBIG_OFFBIG > 0
	  {
	    if (string_len)
	      restenvs[string_len++] = '\n';
	    memcpy (restenvs + string_len, "POSIX_V7_LPBIG_OFFBIG",
		    sizeof "POSIX_V7_LPBIG_OFFBIG" - 1);
	    string_len += sizeof "POSIX_V7_LPBIG_OFFBIG" - 1;
	  }
#endif
	restenvs[string_len++] = '\0';
	string = restenvs;
      }
      break;

    case _CS_V6_WIDTH_RESTRICTED_ENVS:
      /* We have to return a newline-separated list of named of
	 programming environements in which the widths of blksize_t,
	 cc_t, mode_t, nfds_t, pid_t, ptrdiff_t, size_t, speed_t,
	 ssize_t, suseconds_t, tcflag_t, useconds_t, wchar_t, and
	 wint_t types are no greater than the width of type long.

	 Currently this means all environment which the system allows.  */
      {
	char restenvs[4 * sizeof "POSIX_V6_LPBIG_OFFBIG"];

	string_len = 0;
#ifndef _POSIX_V6_ILP32_OFF32
	if (__sysconf (_SC_V6_ILP32_OFF32) > 0)
#endif
#if !defined _POSIX_V6_ILP32_OFF32 || _POSIX_V6_ILP32_OFF32 > 0
	  {
	    memcpy (restenvs + string_len, "POSIX_V6_ILP32_OFF32",
		    sizeof "POSIX_V6_ILP32_OFF32" - 1);
	    string_len += sizeof "POSIX_V6_ILP32_OFF32" - 1;
	  }
#endif
#ifndef _POSIX_V6_ILP32_OFFBIG
	if (__sysconf (_SC_V6_ILP32_OFFBIG) > 0)
#endif
#if !defined _POSIX_V6_ILP32_OFFBIG || _POSIX_V6_ILP32_OFFBIG > 0
	  {
	    if (string_len)
	      restenvs[string_len++] = '\n';
	    memcpy (restenvs + string_len, "POSIX_V6_ILP32_OFFBIG",
		    sizeof "POSIX_V6_ILP32_OFFBIG" - 1);
	    string_len += sizeof "POSIX_V6_ILP32_OFFBIG" - 1;
	  }
#endif
#ifndef _POSIX_V6_LP64_OFF64
	if (__sysconf (_SC_V6_LP64_OFF64) > 0)
#endif
#if !defined _POSIX_V6_LP64_OFF64 || _POSIX_V6_LP64_OFF64 > 0
	  {
	    if (string_len)
	      restenvs[string_len++] = '\n';
	    memcpy (restenvs + string_len, "POSIX_V6_LP64_OFF64",
		    sizeof "POSIX_V6_LP64_OFF64" - 1);
	    string_len += sizeof "POSIX_V6_LP64_OFF64" - 1;
	  }
#endif
#ifndef _POSIX_V6_LPBIG_OFFBIG
	if (__sysconf (_SC_V6_LPBIG_OFFBIG) > 0)
#endif
#if !defined _POSIX_V6_LPBIG_OFFBIG || _POSIX_V6_LPBIG_OFFBIG > 0
	  {
	    if (string_len)
	      restenvs[string_len++] = '\n';
	    memcpy (restenvs + string_len, "POSIX_V6_LPBIG_OFFBIG",
		    sizeof "POSIX_V6_LPBIG_OFFBIG" - 1);
	    string_len += sizeof "POSIX_V6_LPBIG_OFFBIG" - 1;
	  }
#endif
	restenvs[string_len++] = '\0';
	string = restenvs;
      }
      break;

    case _CS_V5_WIDTH_RESTRICTED_ENVS:
      /* We have to return a newline-separated list of named of
	 programming environements in which the widths of blksize_t,
	 cc_t, mode_t, nfds_t, pid_t, ptrdiff_t, size_t, speed_t,
	 ssize_t, suseconds_t, tcflag_t, useconds_t, wchar_t, and
	 wint_t types are no greater than the width of type long.

	 Currently this means all environment which the system allows.  */
      {
	char restenvs[4 * sizeof "XBS5_LPBIG_OFFBIG"];

	string_len = 0;
#ifndef _XBS5_ILP32_OFF32
	if (__sysconf (_SC_XBS5_ILP32_OFF32) > 0)
#endif
#if !defined _XBS5_ILP32_OFF32 || _XBS5_ILP32_OFF32 > 0
	  {
	    memcpy (restenvs + string_len, "XBS5_ILP32_OFF32",
		    sizeof "XBS5_ILP32_OFF32" - 1);
	    string_len += sizeof "XBS5_ILP32_OFF32" - 1;
	  }
#endif
#ifndef _XBS5_ILP32_OFFBIG
	if (__sysconf (_SC_XBS5_ILP32_OFFBIG) > 0)
#endif
#if !defined _XBS5_ILP32_OFFBIG || _XBS5_ILP32_OFFBIG > 0
	  {
	    if (string_len)
	      restenvs[string_len++] = '\n';
	    memcpy (restenvs + string_len, "XBS5_ILP32_OFFBIG",
		    sizeof "XBS5_ILP32_OFFBIG" - 1);
	    string_len += sizeof "XBS5_ILP32_OFFBIG" - 1;
	  }
#endif
#ifndef _XBS5_LP64_OFF64
	if (__sysconf (_SC_XBS5_LP64_OFF64) > 0)
#endif
#if !defined _XBS5_LP64_OFF64 || _XBS5_LP64_OFF64 > 0
	  {
	    if (string_len)
	      restenvs[string_len++] = '\n';
	    memcpy (restenvs + string_len, "XBS5_LP64_OFF64",
		    sizeof "XBS5_LP64_OFF64" - 1);
	    string_len += sizeof "XBS5_LP64_OFF64" - 1;
	  }
#endif
#ifndef _XBS5_LPBIG_OFFBIG
	if (__sysconf (_SC_XBS5_LPBIG_OFFBIG) > 0)
#endif
#if !defined _XBS5_LPBIG_OFFBIG || _XBS5_LPBIG_OFFBIG > 0
	  {
	    if (string_len)
	      restenvs[string_len++] = '\n';
	    memcpy (restenvs + string_len, "XBS5_LPBIG_OFFBIG",
		    sizeof "XBS5_LPBIG_OFFBIG" - 1);
	    string_len += sizeof "XBS5_LPBIG_OFFBIG" - 1;
	  }
#endif
	restenvs[string_len++] = '\0';
	string = restenvs;
      }
      break;
