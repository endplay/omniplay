#include "ldbl-wrap.h"

wrap_type_t WRAP_FUNC (__ieee754_asin) (wrap_type_t);

long double
__ieee754_asinl (long double x)
{
  return (long double) WRAP_FUNC (__ieee754_asin) ((wrap_type_t) x);
}
