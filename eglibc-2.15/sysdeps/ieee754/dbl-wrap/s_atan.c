#include "dbl-wrap.h"

wrap_type_t WRAP_FUNC (atan) (wrap_type_t);

double
atan (double x)
{
  return (double) WRAP_FUNC (atan) ((wrap_type_t) x);
}

#ifdef NO_LONG_DOUBLE
weak_alias (atan, atanl)
#endif
