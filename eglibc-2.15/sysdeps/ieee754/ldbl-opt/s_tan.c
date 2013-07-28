#include <math_ldbl_opt.h>
#include <gnu/option-groups.h>
#if __OPTION_EGLIBC_LIBM_BIG
# include <sysdeps/ieee754/dbl-64/s_tan.c>
#else
# include <sysdeps/ieee754/dbl-wrap/s_tan.c>
#endif
#if LONG_DOUBLE_COMPAT(libm, GLIBC_2_0)
compat_symbol (libm, tan, tanl, GLIBC_2_0);
#endif
