#include "ldbl-wrap.h"

wrap_type_t WRAP_FUNC (__ieee754_j1) (wrap_type_t);

long double
__ieee754_j1l (long double x)
{
  return (long double) WRAP_FUNC (__ieee754_j1) ((wrap_type_t) x);
}

wrap_type_t WRAP_FUNC (__ieee754_y1) (wrap_type_t);

long double
__ieee754_y1l (long double x)
{
  return (long double) WRAP_FUNC (__ieee754_y1) ((wrap_type_t) x);
}
