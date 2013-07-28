#include "dbl-wrap.h"

wrap_type_t WRAP_FUNC (__ieee754_atan2) (wrap_type_t, wrap_type_t);

double
__ieee754_atan2 (double y, double x)
{
  return (double) WRAP_FUNC (__ieee754_atan2) ((wrap_type_t) y, (wrap_type_t) x);
}
