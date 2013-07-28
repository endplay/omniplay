ifeq ($(subdir),stdlib)
spepim_routines = atosfix16 atosfix32 atosfix64 atoufix16 atoufix32 atoufix64 \
  strtosfix16 strtosfix32 strtosfix64 strtoufix16 strtoufix32 strtoufix64
sysdep_routines += $(spepim_routines)
tests += tst-spepim
ifeq ($(build-shared),yes)
$(objpfx)tst-spepim: $(common-objpfx)math/libm.so$(libm.so-version)
else
$(objpfx)tst-spepim: $(common-objpfx)math/libm.a
endif
endif
