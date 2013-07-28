#include "ldbl-wrap.h"

wrap_type_t WRAP_FUNC (__log1p) (wrap_type_t);

long double
__log1pl (long double x)
{
  return (long double) WRAP_FUNC (__log1p) ((wrap_type_t) x);
}
