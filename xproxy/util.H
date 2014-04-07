#ifndef util_H
# define util_H

# include "dxpcconf.h"
#include "XRender.H"
#include "XRandr.H"
#include "XIproto.H"
#include "XKB.h"
#include "xfixes.h"
#include "Xsync.h"
#include <stdarg.h>
#define MAGIC_SIZE 1000000
//#define FILE_REPLAY
//#define CONVERT
#define PRINT_DEBUG 0
extern unsigned int convert_log;

extern unsigned int GetUINT(unsigned const char *, int bigEndian);
extern unsigned int GetULONG(unsigned const char *, int bigEndian);
extern void PutUINT(unsigned int, unsigned char *, int bigEndian);
extern void PutULONG(unsigned int, unsigned char *, int bigEndian);
extern unsigned int RoundUp4(unsigned int);

extern void PrintVersionInfo();

extern void DumpMessage(const unsigned char *data, unsigned int length);

extern const char *GetArg(int &argi, int argc, const char **argv);

extern int WriteAll(int fd, const unsigned char *data, unsigned int length);
extern void printMessage (unsigned const char* buf, int size, int num, ...);
extern void printString (const unsigned char* buf, int size);
extern void detailedCompare (unsigned char* buf1, int size1, unsigned char* buf2, int size2);

extern OSTREAM *logofs;

// globals in main.C
extern int compressImages;
extern int wantBackingStore;

//define extension opcode
/*extension opcode for virtual machines*/
#define XE_EVENT_EXTENSION 129
#define XE_SHAPE 130
#define XE_MIT_SHM 131
#define XE_XInputExtension 132
#define XE_BIG_REQUESTS 134
#define XE_SYNC 135
#define XE_XKEYBOARD 136
#define XE_XFIXES 139
#define XE_RENDER 140
#define XE_RANDR 141
#define XE_XINERAMA 142
#define XE_Composite 143
#define XE_DAMAGE 144
#define XE_DRI2 153
#define XE_SGI_GLX 154

//extension opcode for host machines
/*#define XE_EVENT_EXTENSION 128
#define XE_SHAPE 129
#define XE_MIT_SHM 130
#define XE_XInputExtension 131
#define XE_BIG_REQUESTS 133
#define XE_SYNC 134
#define XE_XKEYBOARD 135
#define XE_XFIXES 138
#define XE_RENDER 139
#define XE_RANDR 140
#define XE_XINERAMA 141
#define XE_Composite 142
#define XE_DAMAGE 143
#define XE_DRI2 152
#define XE_SGI_GLX 153*/
//end for extension code

//x shape extension request
#define X_ShapeQueryVersion             0
#define X_ShapeRectangles               1
#define X_ShapeMask                     2
#define X_ShapeCombine                  3
#define X_ShapeOffset                   4
#define X_ShapeQueryExtents             5
#define X_ShapeSelectInput              6
#define X_ShapeInputSelected            7
#define X_ShapeGetRectangles            8

//x shm request
#define X_ShmQueryVersion               0
#define X_ShmAttach                     1
#define X_ShmDetach                     2
#define X_ShmPutImage                   3
#define X_ShmGetImage                   4
#define X_ShmCreatePixmap               5

//ATOM
#define ATOM_WINDOW 33

#endif /* util_H */
