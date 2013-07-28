#include "dbl-wrap.h"

wrap_type_t WRAP_FUNC (__ieee754_exp2) (wrap_type_t);

double
__ieee754_exp2 (double x)
{
  return (double) WRAP_FUNC (__ieee754_exp2) ((wrap_type_t) x);
}
