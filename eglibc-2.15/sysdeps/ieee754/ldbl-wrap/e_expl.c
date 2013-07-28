#include "ldbl-wrap.h"

wrap_type_t WRAP_FUNC (__ieee754_exp) (wrap_type_t);

long double
__ieee754_expl (long double x)
{
  return (long double) WRAP_FUNC (__ieee754_exp) ((wrap_type_t) x);
}
