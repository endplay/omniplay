#include "dbl-wrap.h"

wrap_type_t WRAP_FUNC (__ieee754_asin) (wrap_type_t);

double
__ieee754_asin (double x)
{
  return (double) WRAP_FUNC (__ieee754_asin) ((wrap_type_t) x);
}

wrap_type_t WRAP_FUNC (__ieee754_acos) (wrap_type_t);

double
__ieee754_acos (double x)
{
  return (double) WRAP_FUNC (__ieee754_acos) ((wrap_type_t) x);
}
