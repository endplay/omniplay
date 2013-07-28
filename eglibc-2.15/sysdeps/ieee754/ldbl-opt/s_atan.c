#include <math_ldbl_opt.h>
#include <gnu/option-groups.h>
#if __OPTION_EGLIBC_LIBM_BIG
# include <sysdeps/ieee754/dbl-64/s_atan.c>
#else
# include <sysdeps/ieee754/dbl-wrap/s_atan.c>
#endif
#if LONG_DOUBLE_COMPAT(libm, GLIBC_2_0)
compat_symbol (libm, atan, atanl, GLIBC_2_0);
#endif
