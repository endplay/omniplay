#include <linux/time.h>
#ifndef SERVERCACHE_H
#define SERVERCACHE_H
struct IntCache
{
	unsigned int size;
	unsigned int length;
	unsigned int *buffer;
	unsigned int lastValueInserted;
	unsigned int lastDiff;
	unsigned int predictedBlockSize;
};


int intcache_lookup(struct IntCache* cache, unsigned int *value, unsigned int *index, unsigned int mask, unsigned int *sameDiff);
unsigned int intcache_get(struct IntCache* cache, unsigned int i);
void intcache_insert(struct IntCache* cache, unsigned int * value, unsigned int mask);
void intcache_init(struct IntCache* cache, unsigned int size);
void intcache_free(struct IntCache* cache);

struct CharCache
{
	unsigned char length;
	unsigned char buffer[7];
};

int charcache_lookup(struct CharCache* cache, unsigned char value, unsigned int* index);
unsigned int charcache_get(struct CharCache* cache, unsigned int i);
void charcache_insert(struct CharCache* cache, unsigned char value);
void charcache_init(struct CharCache* cache);


struct BlockCache
{
	unsigned char* buffer;
	unsigned int size;
	unsigned int checksum;
};

void blockcache_init(struct BlockCache *cache);
void blockcache_free(struct BlockCache* cache);
int blockcache_compare(struct BlockCache* cache, unsigned int size, char* data, int overwrite);
void blockcache_set(struct BlockCache* cache, unsigned int size, const unsigned char* data);
unsigned int blockcache_checksum(unsigned int size, const unsigned char* data);


struct BlockCacheSet
{
	struct BlockCache** caches;
	unsigned int size;
	unsigned int length;
};

void blockcacheset_init(struct BlockCacheSet *cache, unsigned int numCaches);
void blockcacheset_free(struct BlockCacheSet* cache);

int blockcacheset_lookup(struct BlockCacheSet* cache, unsigned int dataLength, const unsigned char* data, unsigned int* index);
void blockcacheset_get(struct BlockCacheSet* cache, unsigned index, unsigned int *size, const unsigned char** data);
void blockcacheset_set(struct BlockCacheSet* cache, unsigned int dataLength, const unsigned char* data);


#define SERVER_TEXT_CACHE_SIZE 9999;

struct serverCache{

// General-purpose cachesy
struct CharCache textCache[9999];
unsigned int lastSequenceNum;
struct IntCache replySequenceNumCache;
struct IntCache eventSequenceNumCache;
unsigned int lastTimestamp;
struct CharCache depthCache;
struct IntCache visualCache;
struct IntCache colormapCache;

// Opcode prediction caches (predict next opcode based on previous one)
struct CharCache opcodeCache[256];
unsigned char lastOpcode;

// X connection startup
struct BlockCache lastInitReply;

// X errors
struct CharCache errorCodeCache;
struct IntCache errorMinorCache;
struct CharCache errorMajorCache;

// ButtonPress and ButtonRelease events
struct CharCache buttonCache;

// ColormapNotify event
struct IntCache colormapNotifyWindowCache;
struct IntCache colormapNotifyColormapCache;

// ConfigureNotify event
struct IntCache configureNotifyWindowCache[3];
struct IntCache configureNotifyGeomCache[5];

// CreateNotify event
struct IntCache createNotifyWindowCache;
unsigned int createNotifyLastWindow;

// Expose event
struct IntCache exposeWindowCache;
struct IntCache exposeGeomCache[5];

// FocusIn event
// (also used for FocusOut)
struct IntCache focusInWindowCache;

// KeymapNotify event
struct BlockCache lastKeymap;

// KeyPress event
unsigned char keyPressLastKey;
unsigned char keyPressCache[23];

// MapNotify event
// (also used for UnmapNotify)
struct IntCache mapNotifyEventCache;
struct IntCache mapNotifyWindowCache;

// MotionNotify event
// (also used for KeyPress, KeyRelease, ButtonPress, ButtonRelease,
//  EnterNotify, and LeaveNotify events and QueryPointer reply)
struct IntCache motionNotifyTimestampCache;
unsigned int motionNotifyLastRootX;
unsigned int motionNotifyLastRootY;
struct IntCache motionNotifyRootXCache;
struct IntCache motionNotifyRootYCache;
struct IntCache motionNotifyEventXCache;
struct IntCache motionNotifyEventYCache;
struct IntCache motionNotifyStateCache;
struct IntCache motionNotifyWindowCache[3];

// NoExpose event
struct IntCache noExposeDrawableCache;
struct IntCache noExposeMinorCache;
struct CharCache noExposeMajorCache;

// PropertyNotify event
struct IntCache propertyNotifyWindowCache;
struct IntCache propertyNotifyAtomCache;

// ReparentNotify event
struct IntCache reparentNotifyWindowCache;

// SelectionClear event
struct IntCache selectionClearWindowCache;
struct IntCache selectionClearAtomCache;

// VisibilityNotify event
struct IntCache visibilityNotifyWindowCache;


// GetGeometry reply
struct IntCache getGeometryRootCache;
struct IntCache getGeometryGeomCache[5];

// GetInputFocus reply
struct IntCache getInputFocusWindowCache;

// GetKeyboardMapping reply
unsigned char getKeyboardMappingLastKeysymsPerKeycode;
struct BlockCache getKeyboardMappingLastMap;
struct IntCache getKeyboardMappingKeysymCache;
struct CharCache getKeyboardMappingLastByteCache;

// GetModifierMapping reply
struct BlockCache getModifierMappingLastMap;

// GetProperty reply
struct CharCache getPropertyFormatCache;
struct IntCache getPropertyTypeCache;
//TextCompressor getPropertyTextCompressor;
struct BlockCache xResources;

// GetSelection reply
struct IntCache getSelectionOwnerCache;

// GetWindowAttributes reply
struct IntCache getWindowAttributesClassCache;
struct CharCache getWindowAttributesBitGravityCache;
struct CharCache getWindowAttributesWinGravityCache;
struct IntCache getWindowAttributesPlanesCache;
struct IntCache getWindowAttributesPixelCache;
struct IntCache getWindowAttributesAllEventsCache;
struct IntCache getWindowAttributesYourEventsCache;
struct IntCache getWindowAttributesDontPropagateCache;

// QueryColors reply
struct BlockCache queryColorsLastReply;

// QueryFont reply
struct BlockCacheSet queryFontFontCache;
struct IntCache queryFontCharInfoCache[6];
unsigned int queryFontLastCharInfo[6];

// QueryPointer reply
struct IntCache queryPointerRootCache;
struct IntCache queryPointerChildCache;

// TranslateCoords reply
struct IntCache translateCoordsChildCache;
struct IntCache translateCoordsXCache;
struct IntCache translateCoordsYCache;

//X_GrabButton event
struct IntCache grabButtonGrabWindow;
struct IntCache grabButtonConfineTo;
struct IntCache grabButtonCursor;

};

struct syscallCache
{
	//poll
	struct IntCache poll_fd;
	struct IntCache poll_events;
	struct IntCache poll_revents;
	struct IntCache poll_size;

	//gettimeofday
	time_t tv_sec;
	suseconds_t tv_usec;
	int tz_minuteswest;
	int tz_dsttime;

	//clock_gettime
	struct timespec tp;
	
	//newuname
	struct BlockCache utsname;

	//socket_recv
	struct IntCache recv_call;
};

void init_caches(struct serverCache* c);
void free_caches(struct serverCache* c);

void init_syscall_cache (struct syscallCache* c);
void free_syscall_cache (struct syscallCache* c);


/*

struct imageCache
{
        unsigned char* buffer;
        unsigned int size;
        unsigned int checksum;
};

struct imageCacheSet
{
        struct imageCache** caches;
        unsigned int size;
        unsigned int length;
};


inline void imagecache_init(struct imageCache *cache);

inline void imagecache_free(struct imageCache* cache);
inline unsigned int imagecache_checksum(unsigned int size, const unsigned char* data) ;
inline int imagecache_compare(struct imageCache* cache, unsigned int size, char* data);

inline void imagecache_set(struct imageCache* cache, unsigned int size,
            const unsigned char* data);
//note!!! different meaning with the image cache set in x_compress algorithm
void imagecacheset_init(struct imageCacheSet *cache, unsigned int numCaches) ;

void imagecacheset_free(struct imageCacheSet* cache) ;

void imagecacheset_insert(struct imageCacheSet *cacheset, char* data, unsigned int size);

int imagecacheset_lookup(struct imageCacheSet* cache, unsigned int dataLength,
                                char* data) ;
*/
#endif
