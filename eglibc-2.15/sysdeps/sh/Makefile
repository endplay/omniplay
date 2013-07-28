ifeq ($(subdir),gmon)
sysdep_routines += _mcount
endif

ifeq ($(subdir),debug)
CFLAGS-backtrace.c += -funwind-tables
CFLAGS-tst-backtrace2.c += -funwind-tables
CFLAGS-tst-backtrace3.c += -funwind-tables
CFLAGS-tst-backtrace4.c += -funwind-tables
CFLAGS-tst-backtrace5.c += -funwind-tables
CFLAGS-tst-backtrace6.c += -funwind-tables
endif
