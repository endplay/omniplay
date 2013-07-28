#include "dbl-wrap.h"

wrap_type_t WRAP_FUNC (__sin) (wrap_type_t);

double
__sin (double x)
{
  return (double) WRAP_FUNC (__sin) ((wrap_type_t) x);
}

wrap_type_t WRAP_FUNC (__cos) (wrap_type_t);

double
__cos (double x)
{
  return (double) WRAP_FUNC (__cos) ((wrap_type_t) x);
}

weak_alias (__cos, cos)
weak_alias (__sin, sin)

#ifdef NO_LONG_DOUBLE
strong_alias (__sin, __sinl)
weak_alias (__sin, sinl)
strong_alias (__cos, __cosl)
weak_alias (__cos, cosl)
#endif
