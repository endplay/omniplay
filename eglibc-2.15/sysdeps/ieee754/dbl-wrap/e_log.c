#include "dbl-wrap.h"

wrap_type_t WRAP_FUNC (__ieee754_log) (wrap_type_t);

double __ieee754_log (double x)
{
  return (double) WRAP_FUNC (__ieee754_log) ((wrap_type_t) x);
}
