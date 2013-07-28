#include "ldbl-wrap.h"

wrap_type_t WRAP_FUNC (__ieee754_j0) (wrap_type_t);

long double
__ieee754_j0l (long double x)
{
  return (long double) WRAP_FUNC (__ieee754_j0) ((wrap_type_t) x);
}

wrap_type_t WRAP_FUNC (__ieee754_y0) (wrap_type_t);

long double
__ieee754_y0l (long double x)
{
  return (long double) WRAP_FUNC (__ieee754_y0) ((wrap_type_t) x);
}
