#include "ldbl-wrap.h"

wrap_type_t WRAP_FUNC (__erf) (wrap_type_t);

long double
__erfl (long double x)
{
  return (long double) WRAP_FUNC (__erf) ((wrap_type_t) x);
}

wrap_type_t WRAP_FUNC (__erfc) (wrap_type_t);

long double
__erfcl (long double x)
{
  return (long double) WRAP_FUNC (__erfc) ((wrap_type_t) x);
}
