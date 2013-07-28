# Copyright (C) 1996, 1997, 1999, 2000, 2008 Free Software Foundation, Inc.
# This file is part of the GNU C Library.

# The GNU C Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.

# The GNU C Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with the GNU C Library; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
# 02111-1307 USA.

#
#	Sub-makefile for wctype portion of the library.
#
include ../option-groups.mak

subdir	:= wctype

headers		:= wctype.h
distribute	:= wchar-lookup.h
routines 	:= wctrans towctrans towctrans_l
routines-$(OPTION_POSIX_C_LANG_WIDE_CHAR) \
		:= wcfuncs wctype iswctype \
		   wcfuncs_l wctype_l iswctype_l wctrans_l

tests	:= 
tests-$(OPTION_POSIX_C_LANG_WIDE_CHAR) \
     += test_wctype test_wcfuncs bug-wctypeh

include ../Rules
