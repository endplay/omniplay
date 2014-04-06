/*

Copyright 1991, 1993, 1994, 1998  The Open Group

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of The Open Group shall not be
used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from The Open Group.

*/

/***********************************************************
Copyright 1991,1993 by Digital Equipment Corporation, Maynard, Massachusetts,
and Olivetti Research Limited, Cambridge, England.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the names of Digital or Olivetti
not be used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

DIGITAL AND OLIVETTI DISCLAIM ALL WARRANTIES WITH REGARD TO THIS
SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL THEY BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

******************************************************************/

#ifndef _SYNCPROTO_H_
#define _SYNCPROTO_H_


#define X_SyncInitialize		0
#define X_SyncListSystemCounters	1
#define X_SyncCreateCounter		2
#define X_SyncSetCounter		3
#define X_SyncChangeCounter		4
#define X_SyncQueryCounter              5
#define X_SyncDestroyCounter		6
#define X_SyncAwait			7
#define X_SyncCreateAlarm               8
#define X_SyncChangeAlarm	        9
#define X_SyncQueryAlarm	       10
#define X_SyncDestroyAlarm	       11
#define X_SyncSetPriority   	       12
#define X_SyncGetPriority   	       13
#define X_SyncCreateFence	       14
#define X_SyncTriggerFence	       15
#define X_SyncResetFence	       16
#define X_SyncDestroyFence	       17
#define X_SyncQueryFence	       18
#define X_SyncAwaitFence	       19




#endif /* _SYNCPROTO_H_ */
