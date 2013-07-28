/* dbl-64/s_sin.c uses NAN and sincos identifiers internally.  */
#define sincos sincos_disable
#include <math_ldbl_opt.h>
#include <gnu/option-groups.h>
#undef NAN
#undef sincos
#if __OPTION_EGLIBC_LIBM_BIG
# include <sysdeps/ieee754/dbl-64/s_sin.c>
#else
# include <sysdeps/ieee754/dbl-wrap/s_sin.c>
#endif
#if LONG_DOUBLE_COMPAT(libm, GLIBC_2_0)
compat_symbol (libm, __sin, sinl, GLIBC_2_0);
compat_symbol (libm, __cos, cosl, GLIBC_2_0);
#endif
