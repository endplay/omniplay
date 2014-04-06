#include <linux/c_cache.h>
#include <linux/slab.h>

static const unsigned char SIZE = 7;
void intcache_init(struct IntCache* cache, unsigned int size) {
	cache->size = size;
	cache->length = 0;
	cache->buffer = kmalloc(sizeof(unsigned int) * size, GFP_KERNEL);
	cache->lastValueInserted = 0;
	cache->lastDiff = 0;
	cache->predictedBlockSize = 0;
}

void intcache_free(struct IntCache* cache) {
	kfree(cache->buffer);
}

int intcache_lookup(struct IntCache* cache, unsigned int *value,
		unsigned int *index, unsigned int mask, unsigned int *sameDiff) {
	unsigned int i;
	unsigned int target;
	unsigned int insertionPoint;
	unsigned int start;
	unsigned int k;
	unsigned int diff;
	unsigned int lastChangeIndex;
	unsigned int lastBitIsOne;
	unsigned int j;
	unsigned int nextMask;
	unsigned int nextBitIsOne;

	for (i = 0; i < cache->length; i++)
		if (*value == cache->buffer[i]) {
			*index = i;
			if (i) {
				target = (i >> 1);

				do {
					cache->buffer[i] = cache->buffer[i - 1];
					i--;
				} while (i > target);
				cache->buffer[target] = *value;
			}
			return 1;
		}
	if (2 >= cache->length)
		insertionPoint = cache->length;
	else
		insertionPoint = 2;
	if (cache->length >= cache->size)
		start = cache->size - 1;
	else {
		start = cache->length;
		cache->length++;
	}
	for (k = start; k > insertionPoint; --k)
		cache->buffer[k] = cache->buffer[k - 1];
	cache->buffer[insertionPoint] = *value;
	diff = *value - cache->lastValueInserted;
	cache->lastValueInserted = (*value & mask);
	*value = (diff & mask);
	*sameDiff = (*value == cache->lastDiff);
	if (!(*sameDiff)) {
		cache->lastDiff = *value;
		lastChangeIndex = 0;
		lastBitIsOne = (cache->lastDiff & 0x1);
		j = 1;
		for (nextMask = 0x2; nextMask & mask; nextMask <<= 1) {
			nextBitIsOne = (cache->lastDiff & nextMask);
			if (nextBitIsOne) {
				if (!lastBitIsOne) {
					lastChangeIndex = j;
					lastBitIsOne = nextBitIsOne;
				}
			} else {
				if (lastBitIsOne) {
					lastChangeIndex = j;
					lastBitIsOne = nextBitIsOne;
				}
			}
			j++;
		}
		cache->predictedBlockSize = lastChangeIndex + 1;
		if (cache->predictedBlockSize < 2)
			cache->predictedBlockSize = 2;
	}
	return 0;
}

unsigned int intcache_get(struct IntCache* cache, unsigned int index) {
	unsigned int result = cache->buffer[index];
	unsigned int i;
	unsigned int target;

	if (index != 0) {
		i = index;
		target = (i >> 1);
		do {
			cache->buffer[i] = cache->buffer[i - 1];
			--i;
		} while (i > target);
		cache->buffer[target] = result;
	}
	return result;
}

void intcache_insert(struct IntCache* cache, unsigned int * value,
		unsigned int mask) {
	unsigned int insertionPoint;
	unsigned int start;
	unsigned int k;
	unsigned int lastChangeIndex;
	unsigned int lastBitIsOne;
	unsigned int j;
	unsigned int nextMask;
	unsigned int nextBitIsOne;

	if (2 >= cache->length)
		insertionPoint = cache->length;
	else
		insertionPoint = 2;
	if (cache->length >= cache->size)
		start = cache->size - 1;
	else {
		start = cache->length;
		cache->length++;
	}
	for (k = start; k > insertionPoint; --k)
		cache->buffer[k] = cache->buffer[k - 1];
	if (cache->lastDiff != *value) {
		cache->lastDiff = *value;
		lastChangeIndex = 0;
		lastBitIsOne = (cache->lastDiff & 0x1);
		j = 1;
		for (nextMask = 0x2; nextMask & mask; nextMask <<= 1) {
			nextBitIsOne = (cache->lastDiff & nextMask);
			if (nextBitIsOne) {
				if (!lastBitIsOne) {
					lastChangeIndex = j;
					lastBitIsOne = nextBitIsOne;
				}
			} else {
				if (lastBitIsOne) {
					lastChangeIndex = j;
					lastBitIsOne = nextBitIsOne;
				}
			}
			j++;
		}
		cache->predictedBlockSize = lastChangeIndex + 1;
		if (cache->predictedBlockSize < 2)
			cache->predictedBlockSize = 2;
	}
	cache->lastValueInserted += *value;
	cache->lastValueInserted &= mask;
	cache->buffer[insertionPoint] = cache->lastValueInserted;
	*value = cache->lastValueInserted;
}

int charcache_lookup(struct CharCache* cache, unsigned char value,
		unsigned int* index) {
	unsigned int i;
	unsigned int target;
	for (i = 0; i < cache->length; ++i) {
		if (value == cache->buffer[i]) {
			*index = i;
			if (i) {
				target = (i >> 1);
				do {
					cache->buffer[i] = cache->buffer[i - 1];
					--i;
				} while (i > target);
				cache->buffer[target] = value;
			}
			return 1;
		}
	}
	charcache_insert(cache, value);
	return 0;
}

unsigned int charcache_get(struct CharCache* cache, unsigned int index) {
	unsigned char result = cache->buffer[index];
	unsigned int i;
	unsigned int target;

	if (index != 0) {
		i = index;
		target = (i >> 1);

		do {
			cache->buffer[i] = cache->buffer[i - 1];
			--i;
		} while (i > target);
		cache->buffer[target] = result;
	}
	return (unsigned int) result;
}

void charcache_init(struct CharCache* cache) {
	cache->length = 0;
}

void charcache_insert(struct CharCache* cache, unsigned char value) {
	unsigned int insertionPoint;
	unsigned int start;
	unsigned int k;

	if (2 >= cache->length)
		insertionPoint = cache->length;
	else
		insertionPoint = 2;

	if (cache->length >= SIZE)
		start = SIZE - 1;
	else {
		start = cache->length;
		++cache->length;
	}
	for (k = start; k > insertionPoint; --k)
		cache->buffer[k] = cache->buffer[k - 1];
	cache->buffer[insertionPoint] = value;

}

void blockcache_init(struct BlockCache *cache) {
	cache->size = 0;
	cache->checksum = 0;
	cache->buffer = NULL;
}

void blockcache_free(struct BlockCache* cache) {
	if (cache->buffer)
		kfree(cache->buffer);
	//kfree(cache);
}

int blockcache_compare(struct BlockCache* cache, unsigned int size, char* data,
		int overwrite) {
	//overwrite = 1
	int match = 0;
	int i;
	if (size == cache->size) {
		match = 1;
		for (i = 0; i < cache->size; ++i)
			if (data[i] != cache->buffer[i]) {
				match = 0;
				break;
			}
	}
	if (!match && overwrite)
		blockcache_set(cache, size, data);
	return match;
}

void blockcache_set(struct BlockCache* cache, unsigned int size,
		const unsigned char* data) {
	if (cache->size < size) {
		kfree(cache->buffer);
		cache->buffer = kmalloc(size, GFP_KERNEL);
	}
	cache->size = size;
	memcpy(cache->buffer, data, size);
	cache->checksum = blockcache_checksum(size, data);
}

unsigned int blockcache_checksum(unsigned int size, const unsigned char* data) {
	unsigned int sum = 0;
	unsigned int shift = 0;
	const unsigned char*next = data;
	unsigned int i;
	unsigned int value;

	for (i = 0; i < size; ++i) {
		value = (unsigned int) *next++;
		sum += (value << shift);
		++shift;
		if (shift == 8)
			shift = 0;
	}
	return sum;
}

void blockcacheset_init(struct BlockCacheSet *cache, unsigned int numCaches) {
	int i = 0;
	cache->size = numCaches;
	cache->caches = kmalloc(sizeof(struct BlockCache*) * numCaches, GFP_KERNEL);
	for (i = 0; i < numCaches; ++i) {
		cache->caches[i] = kmalloc(sizeof(struct BlockCache), GFP_KERNEL);
		blockcache_init(cache->caches[i]);
	}
}

void blockcacheset_free(struct BlockCacheSet* cache) {
	int i = 0;
	for (i = 0; i < cache->size; ++i)
		blockcache_free(cache->caches[i]);
	kfree(cache->caches);
}

int blockcacheset_lookup(struct BlockCacheSet* cache, unsigned int dataLength,
		const unsigned char* data, unsigned int* index) {
	unsigned int checksum;
	unsigned int i;
	struct BlockCache* save;
	unsigned int target;
	unsigned int insertionPoint;
	unsigned int start;
	unsigned int k;

	checksum = blockcache_checksum(dataLength, data);
	for (i = 0; i < cache->length; ++i) {
		if ((cache->caches[i]->checksum == checksum) && (blockcache_compare(
				cache->caches[i], dataLength, data, 0))) {
			//match
			*index = i;
			if (i) {
				save = cache->caches[i];
				target = (i >> 1);
				do {
					cache->caches[i] = cache->caches[i - 1];
					--i;
				} while (i > target);
				cache->caches[target] = save;
			}
			return 1;
		}
	}
	//no match
	insertionPoint = (cache->length >> 1);
	if (cache->length >= cache->size)
		start = cache->size - 1;
	else {
		start = cache->length;
		cache->length++;
	}
	save = cache->caches[start];

	for (k = start; k > insertionPoint; --k) {
		cache->caches[k] = cache->caches[k - 1];
	}
	cache->caches[insertionPoint] = save;
	blockcache_set(save, dataLength, data);
	return 0;
}

void blockcacheset_get(struct BlockCacheSet* cache, unsigned index,
		unsigned int *size, const unsigned char** data) {
	struct BlockCache* save;
	unsigned int target;

	*size = cache->caches[index]->size;
	*data = cache->caches[index]->buffer;
	if (index) {
		save = cache->caches[index];
		target = (index >> 1);
		do {
			cache->caches[index] = cache->caches[index - 1];
			--index;
		} while (index > target);
		cache->caches[target] = save;
	}
}

void blockcacheset_set(struct BlockCacheSet* cache, unsigned int dataLength,
		const unsigned char* data) {
	unsigned int insertionPoint;
	unsigned int start;
	struct BlockCache *save;
	unsigned int k;

	insertionPoint = (cache->length >> 1);
	if (cache->length >= cache->size)
		start = cache->size - 1;
	else {
		start = cache->length;
		cache->length++;
	}
	save = cache->caches[start];
	for (k = start; k > insertionPoint; --k) {
		cache->caches[k] = cache->caches[k - 1];
	}
	cache->caches[insertionPoint] = save;
	blockcache_set(save, dataLength, data);

}

void init_caches(struct serverCache* c) {
	int i = 0;

	for (i = 0; i < 9999; ++i)
		charcache_init(&c->textCache[i]);
	c->lastSequenceNum = 0;
	intcache_init(&c->replySequenceNumCache, 6);
	intcache_init(&c->eventSequenceNumCache, 6);
	c->lastTimestamp = 0;
	charcache_init(&c->depthCache);
	intcache_init(&c->visualCache, 8);
	intcache_init(&c->colormapCache, 8);

	for (i = 0; i < 256; ++i)
		charcache_init(&c->opcodeCache[i]);
	c->lastOpcode = 0;

	blockcache_init(&c->lastInitReply);

	charcache_init(&c->errorCodeCache);
	charcache_init(&c->errorMajorCache);
	intcache_init(&c->errorMinorCache, 8);

	charcache_init(&c->buttonCache);
	charcache_init(&c->noExposeMajorCache);
	charcache_init(&c->getKeyboardMappingLastByteCache);
	charcache_init(&c->getPropertyFormatCache);
	charcache_init(&c->getWindowAttributesBitGravityCache);
	charcache_init(&c->getWindowAttributesWinGravityCache);

	intcache_init(&c->colormapNotifyColormapCache, 8);
	intcache_init(&c->colormapNotifyWindowCache, 8);
	for (i = 0; i < 3; ++i)
		intcache_init(&c->configureNotifyWindowCache[i], 8);
	for (i = 0; i < 5; ++i)
		intcache_init(&c->configureNotifyGeomCache[i], 8);

	intcache_init(&c->createNotifyWindowCache, 8);
	c->createNotifyLastWindow = 0;

	intcache_init(&c->exposeWindowCache, 12);
	for (i = 0; i < 5; ++i)
		intcache_init(&c->exposeGeomCache[i], 8);

	intcache_init(&c->focusInWindowCache, 8);

	blockcache_init(&c->lastKeymap);

	c->keyPressLastKey = 0;
	for (i = 0; i < 23; ++i)
		c->keyPressCache[i] = 0;

	intcache_init(&c->mapNotifyWindowCache, 8);
	intcache_init(&c->mapNotifyEventCache, 8);

	intcache_init(&c->motionNotifyTimestampCache, 8);
	c->motionNotifyLastRootX = 0;
	c->motionNotifyLastRootY = 0;
	intcache_init(&c->motionNotifyRootXCache, 8);
	intcache_init(&c->motionNotifyRootYCache, 8);
	intcache_init(&c->motionNotifyEventXCache, 8);
	intcache_init(&c->motionNotifyEventYCache, 8);
	intcache_init(&c->motionNotifyStateCache, 8);
	for (i = 0; i < 3; ++i)
		intcache_init(&c->motionNotifyWindowCache[i], 8);

	intcache_init(&c->noExposeDrawableCache, 8);
	intcache_init(&c->noExposeMinorCache, 8);

	intcache_init(&c->propertyNotifyWindowCache, 8);
	intcache_init(&c->propertyNotifyAtomCache, 8);

	intcache_init(&c->reparentNotifyWindowCache, 8);

	intcache_init(&c->selectionClearWindowCache, 8);
	intcache_init(&c->selectionClearAtomCache, 8);

	intcache_init(&c->visibilityNotifyWindowCache, 8);

	intcache_init(&c->getGeometryRootCache, 8);
	for (i = 0; i < 5; ++i)
		intcache_init(&c->getGeometryGeomCache[i], 8);

	intcache_init(&c->getInputFocusWindowCache, 8);

	c->getKeyboardMappingLastKeysymsPerKeycode = 0;
	blockcache_init(&c->getKeyboardMappingLastMap);
	intcache_init(&c->getKeyboardMappingKeysymCache, 8);

	blockcache_init(&c->getModifierMappingLastMap);

	intcache_init(&c->getPropertyTypeCache, 8);
	blockcache_init(&c->xResources);

	intcache_init(&c->getSelectionOwnerCache, 8);

	intcache_init(&c->getWindowAttributesClassCache, 8);
	intcache_init(&c->getWindowAttributesPlanesCache, 8);
	intcache_init(&c->getWindowAttributesPixelCache, 8);
	intcache_init(&c->getWindowAttributesAllEventsCache, 8);
	intcache_init(&c->getWindowAttributesYourEventsCache, 8);
	intcache_init(&c->getWindowAttributesDontPropagateCache, 8);

	blockcache_init(&c->queryColorsLastReply);

	blockcacheset_init(&c->queryFontFontCache, 16);
	for (i = 0; i < 6; ++i)
		intcache_init(&c->queryFontCharInfoCache[i], 8);
	for (i = 0; i < 6; ++i)
		c->queryFontLastCharInfo[i] = 0;

	intcache_init(&c->queryPointerRootCache, 8);
	intcache_init(&c->queryPointerChildCache, 8);

	intcache_init(&c->translateCoordsChildCache, 8);
	intcache_init(&c->translateCoordsXCache, 8);
	intcache_init(&c->translateCoordsYCache, 8);

	intcache_init(&c->grabButtonGrabWindow, 8);
	intcache_init(&c->grabButtonConfineTo, 8);
	intcache_init(&c->grabButtonCursor, 8);

}

void free_caches(struct serverCache* c) {
	int i = 0;

	c->lastSequenceNum = 0;
	intcache_free(&c->replySequenceNumCache);
	intcache_free(&c->eventSequenceNumCache);
	c->lastTimestamp = 0;
	intcache_free(&c->visualCache);
	intcache_free(&c->colormapCache);

	c->lastOpcode = 0;

	blockcache_free(&c->lastInitReply);

	intcache_free(&c->errorMinorCache);

	intcache_free(&c->colormapNotifyColormapCache);
	intcache_free(&c->colormapNotifyWindowCache);
	for (i = 0; i < 3; ++i)
		intcache_free(&c->configureNotifyWindowCache[i]);
	for (i = 0; i < 5; ++i)
		intcache_free(&c->configureNotifyGeomCache[i]);

	intcache_free(&c->createNotifyWindowCache);
	c->createNotifyLastWindow = 0;

	intcache_free(&c->exposeWindowCache);
	for (i = 0; i < 5; ++i)
		intcache_free(&c->exposeGeomCache[i]);

	intcache_free(&c->focusInWindowCache);

	blockcache_free(&c->lastKeymap);

	c->keyPressLastKey = 0;
	for (i = 0; i < 23; ++i)
		c->keyPressCache[i] = 0;

	intcache_free(&c->mapNotifyWindowCache);
	intcache_free(&c->mapNotifyEventCache);

	intcache_free(&c->motionNotifyTimestampCache);
	c->motionNotifyLastRootX = 0;
	c->motionNotifyLastRootY = 0;
	intcache_free(&c->motionNotifyRootXCache);
	intcache_free(&c->motionNotifyRootYCache);
	intcache_free(&c->motionNotifyEventXCache);
	intcache_free(&c->motionNotifyEventYCache);
	intcache_free(&c->motionNotifyStateCache);
	for (i = 0; i < 3; ++i)
		intcache_free(&c->motionNotifyWindowCache[i]);

	intcache_free(&c->noExposeDrawableCache);
	intcache_free(&c->noExposeMinorCache);

	intcache_free(&c->propertyNotifyWindowCache);
	intcache_free(&c->propertyNotifyAtomCache);

	intcache_free(&c->reparentNotifyWindowCache);

	intcache_free(&c->selectionClearWindowCache);
	intcache_free(&c->selectionClearAtomCache);

	intcache_free(&c->visibilityNotifyWindowCache);

	intcache_free(&c->getGeometryRootCache);
	for (i = 0; i < 5; ++i)
		intcache_free(&c->getGeometryGeomCache[i]);

	intcache_free(&c->getInputFocusWindowCache);

	c->getKeyboardMappingLastKeysymsPerKeycode = 0;
	blockcache_free(&c->getKeyboardMappingLastMap);
	intcache_free(&c->getKeyboardMappingKeysymCache);

	blockcache_free(&c->getModifierMappingLastMap);

	intcache_free(&c->getPropertyTypeCache);
	blockcache_free(&c->xResources);

	intcache_free(&c->getSelectionOwnerCache);

	intcache_free(&c->getWindowAttributesClassCache);
	intcache_free(&c->getWindowAttributesPlanesCache);
	intcache_free(&c->getWindowAttributesPixelCache);
	intcache_free(&c->getWindowAttributesAllEventsCache);
	intcache_free(&c->getWindowAttributesYourEventsCache);
	intcache_free(&c->getWindowAttributesDontPropagateCache);

	blockcache_free(&c->queryColorsLastReply);

	blockcacheset_free(&c->queryFontFontCache);
	for (i = 0; i < 6; ++i)
		intcache_free(&c->queryFontCharInfoCache[i]);
	for (i = 0; i < 6; ++i)
		c->queryFontLastCharInfo[i] = 0;

	intcache_free(&c->queryPointerRootCache);
	intcache_free(&c->queryPointerChildCache);

	intcache_free(&c->translateCoordsChildCache);
	intcache_free(&c->translateCoordsXCache);
	intcache_free(&c->translateCoordsYCache);

	intcache_free(&c->grabButtonGrabWindow);
	intcache_free(&c->grabButtonConfineTo);
	intcache_free(&c->grabButtonCursor);

}

void init_syscall_cache(struct syscallCache* cache){
	intcache_init(&cache->poll_events, 8);
	intcache_init(&cache->poll_fd, 8);
	intcache_init(&cache->poll_revents, 8);
	intcache_init(&cache->poll_size, 8);

	//for socket_recv
	intcache_init (&cache->recv_call, 8);
	
	cache->tv_sec=0;
	cache->tv_usec=0;
	cache->tz_minuteswest=0;
	cache->tz_dsttime=0;

	cache->tp.tv_sec = 0;
	cache->tp.tv_nsec = 0;

	blockcache_init(&cache->utsname);

}

void free_syscall_cache(struct syscallCache* cache)
{
	intcache_free(&cache->poll_events);
	intcache_free(&cache->poll_fd);
	intcache_free(&cache->poll_revents);
	intcache_free(&cache->poll_size);

	//for socket_recv
	intcache_free (&cache->recv_call);

	blockcache_free(&cache->utsname);

}
/*
inline void imagecache_init(struct imageCache *cache) {
        cache->size = 0;
        cache->checksum = 0;
        cache->buffer = NULL;
}

inline void imagecache_free(struct imageCache* cache) {
        if(cache->buffer)
                free(cache->buffer);
        if(cache)
                free(cache);
}
inline unsigned int imagecache_checksum(unsigned int size, const unsigned char* data) {
        unsigned int sum = 0;
        unsigned int shift = 0;
        const unsigned char*next = data;
        unsigned int i;
        unsigned int value;

        for (i = 0; i < size; ++i) {
                value = (unsigned int) *next++;
                sum += (value << shift);
                ++shift;
                if (shift == 8)
                        shift = 0;
        }
        return sum;
}
inline int imagecache_compare(struct imageCache* cache, unsigned int size, char* data) {
        int match = 0;
        int i;
        if (size == cache->size) {
                match = 1;
                for (i = 0; i < cache->size; ++i)
                    if (data[i] != cache->buffer[i]) {
                            match = 0;
                            break;
                    }
    }
    return match;
}

inline void imagecache_set(struct imageCache* cache, unsigned int size,
            const unsigned char* data) {
    if (cache->size < size) {
            if(cache->buffer)
                    kfree(cache->buffer);
            cache->buffer = kmalloc(size);
    }
    cache->size = size;
    memcpy(cache->buffer, data, size);
    cache->checksum = imagecache_checksum(size, data);
}



//note!!! different meaning with the image cache set in x_compress algorithm
void imagecacheset_init(struct imageCacheSet *cache, unsigned int numCaches) {
    cache->size = numCaches;
    cache->length=0;
    cache->caches = kmalloc(sizeof(struct imageCache*) * numCaches);
}

void imagecacheset_free(struct imageCacheSet* cache) {
    int i = 0;
    for (i = 0; i < cache->length; ++i)
            imagecache_free(cache->caches[i]);
    kfree(cache->caches);
}

void imagecacheset_insert(struct imageCacheSet *cacheset, char* data, unsigned int size)
{
        struct imageCache **tmp;
        struct imageCache* cache = kmalloc(sizeof(struct imageCache)) ;

        imagecache_init(cache);
        imagecache_set(cache, size, data);
        if(cacheset->length==size){
                cacheset->size*=2;
                tmp = kmalloc(sizeof(struct imageCache*)*cacheset->size) ;
                memcpy(tmp, cacheset->caches, sizeof(struct imageCache*)*cacheset->length);
                free(cacheset->caches);
                cacheset->caches=tmp;
        }
        cacheset->caches[cacheset->length]=cache;
        ++cacheset->length;

}

int imagecacheset_lookup(struct imageCacheSet* cache, unsigned int dataLength,
                                char* data) {
        unsigned int checksum;
        unsigned int i;

        checksum=imagecache_checksum(dataLength, data);
        for(i=0;i<cache->length;++i)
        {
                if((cache->caches[i]->checksum==checksum) && (imagecache_compare(cache->caches[i], dataLength, data)))
                {
                        return i;
                }

        }
        return -1;

}
*/

