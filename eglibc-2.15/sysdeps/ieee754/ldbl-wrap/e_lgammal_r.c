#include "ldbl-wrap.h"

wrap_type_t WRAP_FUNC2 (__ieee754_lgamma, _r) (wrap_type_t, int *);

long double
__ieee754_lgammal_r (long double x, int *s)
{
  return (long double) WRAP_FUNC2 (__ieee754_lgamma, _r) ((wrap_type_t) x, s);
}
