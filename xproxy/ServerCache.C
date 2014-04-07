#include "ServerCache.H"


// Some global caches used to store information common to all X connections...
BlockCache ServerCache::lastInitReply;
BlockCache ServerCache::lastKeymap;
unsigned char ServerCache::getKeyboardMappingLastKeysymsPerKeycode = 0;
BlockCache ServerCache::getKeyboardMappingLastMap;
BlockCache ServerCache::getModifierMappingLastMap;
BlockCache ServerCache::xResources;
BlockCacheSet ServerCache::queryFontFontCache(16);


ServerCache::ServerCache():
lastSequenceNum(0), replySequenceNumCache(6), eventSequenceNumCache(6),
lastTimestamp(0), visualCache(8), colormapCache(8),
lastOpcode(0),
errorMinorCache(8),
colormapNotifyWindowCache(8), colormapNotifyColormapCache(8),
createNotifyWindowCache(8), createNotifyLastWindow(0),
exposeWindowCache(12),
focusInWindowCache(8),
keyPressLastKey(0),
mapNotifyEventCache(8), mapNotifyWindowCache(8),
motionNotifyTimestampCache(8), motionNotifyLastRootX(0),
motionNotifyLastRootY(0), motionNotifyRootXCache(8),
motionNotifyRootYCache(8), motionNotifyEventXCache(8),
motionNotifyEventYCache(8), motionNotifyStateCache(8),
noExposeDrawableCache(8), noExposeMinorCache(8),
propertyNotifyWindowCache(8), propertyNotifyAtomCache(8),
reparentNotifyWindowCache(8),
selectionClearWindowCache(8), selectionClearAtomCache(8),
visibilityNotifyWindowCache(8),
getGeometryRootCache(8),
getInputFocusWindowCache(8),
getKeyboardMappingKeysymCache(8),
getPropertyTypeCache(8),
getPropertyTextCompressor(textCache, SERVER_TEXT_CACHE_SIZE),
getSelectionOwnerCache(8),
getWindowAttributesClassCache(8), getWindowAttributesPlanesCache(8),
getWindowAttributesPixelCache(8), getWindowAttributesAllEventsCache(8),
getWindowAttributesYourEventsCache(8),
getWindowAttributesDontPropagateCache(8),
queryPointerRootCache(8), queryPointerChildCache(8),
translateCoordsChildCache(8), translateCoordsXCache(8),
translateCoordsYCache(8)
{
    unsigned int i;

    for (i = 0; i < 3; i++)
        configureNotifyWindowCache[i] = new IntCache(8);
    for (i = 0; i < 5; i++)
        configureNotifyGeomCache[i] = new IntCache(8);

    for (i = 0; i < 5; i++)
        exposeGeomCache[i] = new IntCache(8);

    for (i = 0; i < 3; i++)
        motionNotifyWindowCache[i] = new IntCache(8);

    for (i = 0; i < 5; i++)
        getGeometryGeomCache[i] = new IntCache(8);

    for (i = 0; i < 23; i++)
        keyPressCache[i] = 0;

    for (i = 0; i < 6; i++)
    {
        queryFontCharInfoCache[i] = new IntCache(8);
        queryFontLastCharInfo[i] = 0;
    }
}


ServerCache::~ServerCache()
{
    unsigned int i;

    for (i = 0; i < 3; i++)
        delete configureNotifyWindowCache[i];

    for (i = 0; i < 5; i++)
        delete configureNotifyGeomCache[i];

    for (i = 0; i < 5; i++)
        delete exposeGeomCache[i];

    for (i = 0; i < 3; i++)
        delete motionNotifyWindowCache[i];

    for (i = 0; i < 5; i++)
        delete getGeometryGeomCache[i];

    for (i = 0; i < 6; i++)
        delete queryFontCharInfoCache[i];
}
