#ifndef ClientCache_H
# define ClientCache_H

# include "constants.H"
# include "EncodeBuffer.H"
# include "IntCache.H"
# include "CharCache.H"
# include "TextCompressor.H"
# include "HuffmanCoder.H"
# include "PixelCache.H"
# include "LastPixels.H"


static const unsigned int PUT_IMAGE_PIXEL_CACHE_SIZE = 251;
static const unsigned int CLIENT_TEXT_CACHE_SIZE = 9999;


class ClientCache
{
  public:
    ClientCache();
    ~ClientCache();

    // General-purpose caches:
    CharCache textCache[CLIENT_TEXT_CACHE_SIZE];
    IntCache cursorCache;
    IntCache gcCache;
    IntCache drawableCache;
    IntCache windowCache;
    IntCache colormapCache;
    IntCache visualCache;
    CharCache depthCache;
    unsigned int lastFont;
    unsigned int lastRequestSequenceNum;

    // Opcode prediction caches (predict next opcode based on previous one)
    CharCache opcodeCache[256];
    unsigned char lastOpcode;

    // AllocColor request
    IntCache *allocColorRGBCache[3];

    // ChangeProperty request
    CharCache changePropertyFormatCache;
    IntCache changePropertyPropertyCache;
    IntCache changePropertyTypeCache;
    IntCache changePropertyData32Cache;
    TextCompressor changePropertyTextCompressor;

    // ClearArea request
    IntCache *clearAreaGeomCache[4];

    // ConfigureWindow request
    IntCache configureWindowBitmaskCache;
    IntCache *configureWindowAttrCache[7];

    // ConvertSelection request
    IntCache convertSelectionRequestorCache;
    IntCache *convertSelectionAtomCache[3];
    unsigned int convertSelectionLastTimestamp;

    // CopyArea request
    IntCache *copyAreaGeomCache[6];

    // CopyPlane request
    IntCache *copyPlaneGeomCache[6];
    IntCache copyPlaneBitPlaneCache;

    // CreateGC request
    IntCache createGCBitmaskCache;
    IntCache *createGCAttrCache[23];

    // CreatePixmap request
    unsigned int createPixmapLastPixmap;
    IntCache createPixmapXCache;
    IntCache createPixmapYCache;

    // CreateWindow request
    IntCache *createWindowGeomCache[6];
    IntCache createWindowBitmaskCache;
    IntCache *createWindowAttrCache[15];

    // FillPoly request
    IntCache fillPolyNumPointsCache;
    IntCache *fillPolyXRelCache[FILL_POLY_MAX_POINTS];
    IntCache *fillPolyXAbsCache[FILL_POLY_MAX_POINTS];
    IntCache *fillPolyYRelCache[FILL_POLY_MAX_POINTS];
    IntCache *fillPolyYAbsCache[FILL_POLY_MAX_POINTS];
    unsigned int fillPolyRecentX[8];
    unsigned int fillPolyRecentY[8];
    unsigned int fillPolyIndex;

    // GetSelectionOwner request
    IntCache getSelectionOwnerSelectionCache;

    // GrabButton request
    // (also used for GrabPointer)
    IntCache grabButtonEventMaskCache;
    IntCache grabButtonConfineCache;
    CharCache grabButtonButtonCache;
    IntCache grabButtonModifierCache;

    // GrabKeyboard request
    unsigned int grabKeyboardLastTimestamp;

    // ImageText8 request
    unsigned int imageText8LastX;
    unsigned int imageText8LastY;
    IntCache imageText8CacheX;
    IntCache imageText8CacheY;
    TextCompressor imageText8TextCompressor;

    // InternAtom request
    TextCompressor internAtomTextCompressor;

    // OpenFont request
    TextCompressor openFontTextCompressor;

    // PolyFillRectangle request
    IntCache *polyFillRectangleCacheX[2];
    IntCache *polyFillRectangleCacheY[2];
    IntCache *polyFillRectangleCacheWidth[2];
    IntCache *polyFillRectangleCacheHeight[2];

    // PolyLine request
    IntCache *polyLineCacheX[2];
    IntCache *polyLineCacheY[2];

    // PolyPoint request
    IntCache *polyPointCacheX[2];
    IntCache *polyPointCacheY[2];

    // PolyRectangle request
    IntCache *polyRectangleGeomCache[4];

    // PolySegment request
    IntCache polySegmentCacheX;
    IntCache polySegmentCacheY;
    unsigned int polySegmentLastX[2];
    unsigned int polySegmentLastY[2];
    unsigned int polySegmentCacheIndex;

    // PolyText8 request
    unsigned int polyText8LastX;
    unsigned int polyText8LastY;
    IntCache polyText8CacheX;
    IntCache polyText8CacheY;
    IntCache polyText8FontCache;
    CharCache polyText8DeltaCache;
    TextCompressor polyText8TextCompressor;

    // PutImage request
    IntCache putImageWidthCache;
    IntCache putImageHeightCache;
    unsigned int putImageLastX;
    unsigned int putImageLastY;
    IntCache putImageXCache;
    IntCache putImageYCache;
    CharCache putImageOffsetCache;
    HuffmanCoder putImagePixel0Coder;
    HuffmanCoder putImagePixel1Coder;
    HuffmanCoder putImageDiffCoder;
    PixelCache putImagePixelCache[PUT_IMAGE_PIXEL_CACHE_SIZE];
    LastPixels putImageLastPixels;
    HuffmanCoder columnPixel0Coder;
    HuffmanCoder columnPixel1Coder;
    unsigned int *putImageReferenceLine;
    unsigned int *putImageCodingLine;
    unsigned int putImageLineSize;
    CharCache putImageByteCache;

    // QueryColors request
    unsigned int queryColorsLastPixel;

    // SetClipRectangles request
    IntCache setClipRectanglesXCache;
    IntCache setClipRectanglesYCache;
    IntCache *setClipRectanglesGeomCache[4];

    // SetDashes request
    IntCache setDashesLengthCache;
    IntCache setDashesOffsetCache;
    CharCache setDashesDashCache_[2];

    // SetSelectionOwner request
    IntCache setSelectionOwnerCache;
    IntCache setSelectionOwnerTimestampCache;

    // TranslateCoords request
    IntCache translateCoordsSrcCache;
    IntCache translateCoordsDestCache;
    IntCache translateCoordsXCache;
    IntCache translateCoordsYCache;
};


// Codes for representing patterns between scan lines of a compressed bitmap:
enum ScanlineDiff
{
    SD_VERTICAL_0, SD_VERTICAL_PLUS_1, SD_VERTICAL_MINUS_1,
    SD_HORIZONTAL, SD_PASS, SD_VERTICAL_MINUS_2,
    SD_VERTICAL_PLUS_2, SD_NUM_CODES
};

#endif /* ClientCache_H */
