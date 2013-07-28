#include "ldbl-wrap.h"

wrap_type_t WRAP_FUNC (__ieee754_pow) (wrap_type_t, wrap_type_t);

long double
__ieee754_powl (long double x, long double y)
{
  return (long double) WRAP_FUNC (__ieee754_pow) ((wrap_type_t) x,
						  (wrap_type_t) y);
}
