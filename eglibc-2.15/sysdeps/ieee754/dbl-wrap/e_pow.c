#include "dbl-wrap.h"

wrap_type_t WRAP_FUNC (__ieee754_pow) (wrap_type_t, wrap_type_t);

double
__ieee754_pow (double x, double y)
{
  return (double) WRAP_FUNC (__ieee754_pow) ((wrap_type_t) x, (wrap_type_t) y);
}
