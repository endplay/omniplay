#ifndef DXPC_H_HEADERS_H_
# define DXPC_H_HEADERS_H_

# if !defined(__CYGWIN32__) && !defined(__MINGW32__)
#  include <X11/X.h>
#  include <X11/Xproto.h>
#  include <X11/Xatom.h>
# else
#  include "X-mingw.h"
#  include "Xproto-cygwin.h"
#  include "Xatom-mingw.h"
# endif

#endif
