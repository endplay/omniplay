/* X11R5 version of Xproto.h stripped down for CygWin 32 environment. */

/*
 *	$XConsortium: Xproto.h,v 1.85 91/04/06 12:57:05 rws Exp $
 */

/* Definitions for the X window system used by server and c bindings */

/*
 * This packet-construction scheme makes the following assumptions:
 *
 * 1. The compiler is able
 * to generate code which addresses one- and two-byte quantities.
 * In the worst case, this would be done with bit-fields.  If bit-fields
 * are used it may be necessary to reorder the request fields in this file,
 * depending on the order in which the machine assigns bit fields to
 * machine words.  There may also be a problem with sign extension,
 * as K+R specify that bitfields are always unsigned.
 *
 * 2. 2- and 4-byte fields in packet structures must be ordered by hand
 * such that they are naturally-aligned, so that no compiler will ever
 * insert padding bytes.
 *
 * 3. All packets are hand-padded to a multiple of 4 bytes, for
 * the same reason.
 */

#ifndef XPROTO_H
#define XPROTO_H

/***********************************************************
Copyright 1987 by Digital Equipment Corporation, Maynard, Massachusetts,
and the Massachusetts Institute of Technology, Cambridge, Massachusetts.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the names of Digital or MIT not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

DIGITAL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
DIGITAL BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/


/* Reply codes */

#define X_Reply		1		/* Normal reply */
#define X_Error		0		/* Error */

/* Request codes */

#define X_CreateWindow                  1              
#define X_ChangeWindowAttributes        2        
#define X_GetWindowAttributes           3     
#define X_DestroyWindow                 4
#define X_DestroySubwindows             5   
#define X_ChangeSaveSet                 6
#define X_ReparentWindow                7
#define X_MapWindow                     8
#define X_MapSubwindows                 9
#define X_UnmapWindow                  10
#define X_UnmapSubwindows              11  
#define X_ConfigureWindow              12  
#define X_CirculateWindow              13  
#define X_GetGeometry                  14
#define X_QueryTree                    15
#define X_InternAtom                   16
#define X_GetAtomName                  17
#define X_ChangeProperty               18 
#define X_DeleteProperty               19 
#define X_GetProperty                  20
#define X_ListProperties               21 
#define X_SetSelectionOwner            22    
#define X_GetSelectionOwner            23    
#define X_ConvertSelection             24   
#define X_SendEvent                    25
#define X_GrabPointer                  26
#define X_UngrabPointer                27
#define X_GrabButton                   28
#define X_UngrabButton                 29
#define X_ChangeActivePointerGrab      30          
#define X_GrabKeyboard                 31
#define X_UngrabKeyboard               32 
#define X_GrabKey                      33
#define X_UngrabKey                    34
#define X_AllowEvents                  35       
#define X_GrabServer                   36      
#define X_UngrabServer                 37        
#define X_QueryPointer                 38        
#define X_GetMotionEvents              39           
#define X_TranslateCoords              40                
#define X_WarpPointer                  41       
#define X_SetInputFocus                42         
#define X_GetInputFocus                43         
#define X_QueryKeymap                  44       
#define X_OpenFont                     45    
#define X_CloseFont                    46     
#define X_QueryFont                    47
#define X_QueryTextExtents             48     
#define X_ListFonts                    49  
#define X_ListFontsWithInfo    	       50 
#define X_SetFontPath                  51 
#define X_GetFontPath                  52 
#define X_CreatePixmap                 53        
#define X_FreePixmap                   54      
#define X_CreateGC                     55    
#define X_ChangeGC                     56    
#define X_CopyGC                       57  
#define X_SetDashes                    58     
#define X_SetClipRectangles            59             
#define X_FreeGC                       60  
#define X_ClearArea                    61             
#define X_CopyArea                     62    
#define X_CopyPlane                    63     
#define X_PolyPoint                    64     
#define X_PolyLine                     65    
#define X_PolySegment                  66       
#define X_PolyRectangle                67         
#define X_PolyArc                      68   
#define X_FillPoly                     69    
#define X_PolyFillRectangle            70             
#define X_PolyFillArc                  71       
#define X_PutImage                     72    
#define X_GetImage                     73 
#define X_PolyText8                    74     
#define X_PolyText16                   75      
#define X_ImageText8                   76      
#define X_ImageText16                  77       
#define X_CreateColormap               78          
#define X_FreeColormap                 79        
#define X_CopyColormapAndFree          80               
#define X_InstallColormap              81           
#define X_UninstallColormap            82             
#define X_ListInstalledColormaps       83                  
#define X_AllocColor                   84      
#define X_AllocNamedColor              85           
#define X_AllocColorCells              86           
#define X_AllocColorPlanes             87            
#define X_FreeColors                   88      
#define X_StoreColors                  89       
#define X_StoreNamedColor              90           
#define X_QueryColors                  91       
#define X_LookupColor                  92       
#define X_CreateCursor                 93        
#define X_CreateGlyphCursor            94             
#define X_FreeCursor                   95      
#define X_RecolorCursor                96         
#define X_QueryBestSize                97         
#define X_QueryExtension               98          
#define X_ListExtensions               99          
#define X_ChangeKeyboardMapping        100
#define X_GetKeyboardMapping           101
#define X_ChangeKeyboardControl        102                
#define X_GetKeyboardControl           103             
#define X_Bell                         104
#define X_ChangePointerControl         105
#define X_GetPointerControl            106
#define X_SetScreenSaver               107          
#define X_GetScreenSaver               108          
#define X_ChangeHosts                  109       
#define X_ListHosts                    110     
#define X_SetAccessControl             111               
#define X_SetCloseDownMode             112
#define X_KillClient                   113 
#define X_RotateProperties	       114
#define X_ForceScreenSaver	       115
#define X_SetPointerMapping            116
#define X_GetPointerMapping            117
#define X_SetModifierMapping	       118
#define X_GetModifierMapping	       119
#define X_NoOperation                  127

#define X_TCP_PORT 6000


#endif /* XPROTO_H */
