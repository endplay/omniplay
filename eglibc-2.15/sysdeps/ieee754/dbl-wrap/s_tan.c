#include "dbl-wrap.h"

wrap_type_t WRAP_FUNC (tan) (wrap_type_t);

double
tan (double x)
{
  return (double) WRAP_FUNC (tan) ((wrap_type_t) x);
}

#ifdef NO_LONG_DOUBLE
weak_alias (tan, tanl)
#endif
