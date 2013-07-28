# Copyright (C) 1991,1992,1995-2003,2005,2009,2011
# Free Software Foundation, Inc.
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
#	Makefile for locales.
#
include ../option-groups.mak

subdir	:= locale

headers		= locale.h bits/locale.h langinfo.h xlocale.h
distribute	= localeinfo.h categories.def iso-639.def iso-3166.def \
		  iso-4217.def weight.h weightwc.h strlen-hash.h elem-hash.h \
		  indigits.h indigitswc.h outdigits.h outdigitswc.h \
		  coll-lookup.h C-translit.h.in C-translit.h gen-translit.pl \
		  locarchive.h hashval.h dummy-setlocale.c \
		  $(addprefix programs/, \
			      locale.c localedef.c \
			      $(localedef-modules:=.c) $(locale-modules:=.c) \
			      $(lib-modules:=.c) config.h simple-hash.h \
			      charmap-kw.gperf charmap-kw.h locfile-token.h \
			      locfile-kw.gperf locfile-kw.h linereader.h \
			      locfile.h charmap.h repertoire.h localedef.h \
			      3level.h charmap-dir.h locarchive.c)
# catnames is needed by OPTION_EGLIBC_LOCALE_CODE and by the 'intl' code.
# If we put the latter in an option group, too, we can omit catnames
# when both option groups are disabled.  libstdc++-v3 needs mb_cur_max.
routines-y      := catnames mb_cur_max
routines-$(OPTION_EGLIBC_LOCALE_CODE) \
		+= setlocale findlocale loadlocale loadarchive \
		   localeconv nl_langinfo nl_langinfo_l \
		   newlocale duplocale freelocale uselocale
ifneq (y,$(OPTION_EGLIBC_LOCALE_CODE))
routines-y	+= dummy-setlocale
endif
tests-$(OPTION_EGLIBC_LOCALE_CODE) += tst-C-locale tst-locname tst-duplocale
categories	= ctype messages monetary numeric time paper name \
		  address telephone measurement identification collate
# C-messages belongs in an intl option group.
aux-y		:= C-ctype C-time \
		   SYS_libc C_name xlocale global-locale coll-lookup
aux-$(OPTION_EGLIBC_LOCALE_CODE) \
		+= $(filter-out $(aux-y), \
	                        $(categories:%=lc-%) $(categories:%=C-%)) \
	           localename
others-$(OPTION_EGLIBC_LOCALE_CODE) = localedef locale
#others-static	= localedef locale
install-bin	= $(others-y)
extra-objs-$(OPTION_EGLIBC_LOCALE_CODE) \
		= $(localedef-modules:=.o) $(localedef-aux:=.o) \
		  $(locale-modules:=.o) $(lib-modules:=.o)

extra-libs-$(OPTION_EGLIBC_LOCALE_CODE) = libBrokenLocale
extra-libs-others = $(extra-libs-y)

libBrokenLocale-routines = broken_cur_max

subdir-dirs	= programs
vpath %.c programs ../crypt
vpath %.h programs
vpath %.gperf programs

localedef-modules	:= localedef $(categories:%=ld-%) \
			   charmap linereader locfile \
			   repertoire locarchive
localedef-aux		:= md5
locale-modules		:= locale locale-spec
lib-modules		:= charmap-dir simple-hash xmalloc xstrdup


GPERF = gperf
GPERFFLAGS = -acCgopt -k1,2,5,9,$$ -L ANSI-C

include ../Rules

programs/%-kw.h: programs/%-kw.gperf
	cd programs \
	&& $(GPERF) $(GPERFFLAGS) -N $(@F:-kw.h=_hash) $(<F) > $(@F).new
	mv -f $@.new $@

$(objpfx)localedef: $(localedef-modules:%=$(objpfx)%.o)
$(objpfx)localedef: $(localedef-aux:%=$(objpfx)%.o)
$(objpfx)locale: $(locale-modules:%=$(objpfx)%.o)
$(objpfx)localedef $(objpfx)locale: $(lib-modules:%=$(objpfx)%.o)

C-translit.h: C-translit.h.in gen-translit.pl
	$(PERL) gen-translit.pl < $< > $@.tmp
	mv -f $@.tmp $@

localepath = "$(localedir):$(i18ndir)"

# -Iprograms doesn't really belong here, but this gets it at the head
# of the list instead of the tail, where CPPFLAGS-$(lib) gets added.
# We need it before the standard -I's to see programs/config.h first.
locale-CPPFLAGS = -DLOCALEDIR='"$(localedir)"' \
		  -DLOCALE_ALIAS_PATH='"$(msgcatdir)"' \
		  -Iprograms

CPPFLAGS-locale-programs = -DLOCALE_PATH='$(localepath)' \
			   -DCHARMAP_PATH='"$(i18ndir)/charmaps"' \
			   -DREPERTOIREMAP_PATH='"$(i18ndir)/repertoiremaps"' \
			   -DLOCSRCDIR='"$(i18ndir)/locales"' \
			   -DHAVE_CONFIG_H -DNOT_IN_libc

CFLAGS-charmap.c = -Wno-write-strings -Wno-char-subscripts
CFLAGS-locfile.c = -Wno-write-strings -Wno-char-subscripts
CFLAGS-charmap-dir.c = -Wno-write-strings
ifneq (y,$(OPTION_EGLIBC_SPAWN))
CFLAGS-charmap-dir.c += -DNO_UNCOMPRESS
endif

# This makes sure -DNOT_IN_libc et al are passed for all these modules.
cpp-srcs-left := $(addsuffix .c,$(localedef-modules) $(localedef-aux) \
				$(locale-modules) $(lib-modules))
lib := locale-programs
include $(patsubst %,$(..)cppflags-iterator.mk,$(cpp-srcs-left))

# Depend on libc.so so a DT_NEEDED is generated in the shared objects.
# This ensures they will load libc.so for needed symbols if loaded by
# a statically-linked program that hasn't already loaded it.
$(objpfx)libBrokenLocale.so: $(common-objpfx)libc.so \
			     $(common-objpfx)libc_nonshared.a
