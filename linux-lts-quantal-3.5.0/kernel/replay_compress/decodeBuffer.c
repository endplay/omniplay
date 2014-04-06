/*
 * decodeBuffer.c
 *
 *  Created on: Mar 22, 2013
 *      Author: xdou
 */

#ifndef DECODEBUFFER_C_
#define DECODEBUFFER_C_
#define log_compress_debug 1 

#include <linux/decodeBuffer.h>
#include <linux/c_constants.h>
#include <asm/bug.h>

void decodebuffer_init(unsigned char *data, unsigned int length, struct clog_node *node) {
	node->head = data;
	node->end = node->head + length;
	node->pos = node->head;
	node->freeBitsInDest = 8;
}

//unsigned int blockSize = 0, int endOkay = 0
int decodeValue(unsigned int *value, unsigned int numBits,
		unsigned int blockSize, int endOkay, struct clog_node *node) {
	unsigned int remainingBits = numBits;
	unsigned int numBlocks = 0;
	unsigned int result = 0;

	BUG_ON(numBits > (sizeof(unsigned) * 8));
	BUG_ON(numBits == 0);
	BUG_ON(blockSize > numBits);

	if (blockSize == 0)
		blockSize = numBits;

	if ((blockSize == numBits) || (numBits < 3)) {
		// No use for block compression.
		return decodeDirect(value, numBits, endOkay, node);
	}

	do {
		unsigned int bitsToRead = blockSize > remainingBits ? remainingBits
				: blockSize;
		unsigned int block;

		if (!decodeDirect(&block, bitsToRead, endOkay, node)) {
			return 0;
		}

		result = result | (block << (numBits - remainingBits));
		remainingBits -= bitsToRead;

		if (remainingBits) {
			unsigned marker;

			// Now read the marker bit.
			if (!decodeDirect(&marker, 1, endOkay, node)) {
				return 0;
			}

			if (!marker) {
				// The remainder of the value is all the same as the most significant bit
				// of the last block we read.
				unsigned lastBit = block & (1 << (bitsToRead - 1));

				if (lastBit) {
					// We need to build a mask of doom.
					unsigned mask = PARTIAL_INT_MASK[remainingBits];

					mask <<= (numBits - remainingBits);

					//DBG("Mask of ones = 0x%08x\n", mask);

					result |= mask;
				}
				// No need to extend zeros.
				// Break out of outer loop, we're done.
				remainingBits = 0;
			}
		}

		if (++numBlocks >= 4) {
			blockSize = numBits;
		} else if (blockSize > 2) {
			blockSize >>= 1;
		}
	} while (remainingBits);

	//DBG("decodeValue: value = 0x%08x\n", value);

	*value = result;
	return 1;
}

//unsigned int blockSize = 0, int endOkay = 0
int decodeCachedValue(unsigned int *value, unsigned int numBits,
		struct IntCache *cache, unsigned int blockSize, int endOkay, struct clog_node *node) {
	unsigned int index;

	if (!countLeadingZeros(&index, endOkay, node)) {
		return 0;
	}

	if (index == 2) {
		unsigned int sameDiff;

		decodeDirect(&sameDiff, 1, 0, node);

		if (sameDiff) {
			*value = cache->lastDiff;
			intcache_insert(cache, value, PARTIAL_INT_MASK[numBits]);
			return 1;
		}

		blockSize = cache->predictedBlockSize;

		if (!decodeValue(value, numBits, blockSize, endOkay, node)) {
			return 0;
		}

		intcache_insert(cache, value, PARTIAL_INT_MASK[numBits]);
		return 1;
	}

	if (index > 2)
		index--;
	if (index > cache->length) {
		printk(
				"Assertion 2 failed in DecodeCachedValue: index=%d, cache size=%d\n",
				index, cache->size);
		if (log_compress_debug) BUG();
	}
	*value = intcache_get(cache, index);
	return 1;
}

//unsigned int blockSize = 0,int endOkay = 0
int decodeCachedCharValue(unsigned char *value, unsigned int numBits,
		struct CharCache * cache, unsigned int blockSize, int endOkay, struct clog_node *node) {
	unsigned int index;

	if (!countLeadingZeros(&index, endOkay, node)) {
		return 0;
	}

	if (index == 2) {
		unsigned int val;

		if (decodeValue(&val, numBits, blockSize, endOkay, node)) {
			*value = (unsigned char) val;
			charcache_insert(cache, *value);
			return 1;
		}
		return 0;
	}
	if (index > 2)
		index--;
	if (index > cache->length) {
		printk(
				"Assertion 4 failed in DecodeCachedValue: index=%d, cache size=%d\n",
				index, cache->length);
		BUG();
	}
	*value = charcache_get(cache, index);
	return 1;
}

//const unsigned char *decodeRawMem(unsigned int len);

//int endOkay = 0
int decodeDirect(unsigned int *value, unsigned int numBits, int endOkay, struct clog_node *node) {
	unsigned remainingBits = numBits;
	unsigned destShift = 0;
	unsigned readBits;

	*value = 0;

	BUG_ON(numBits > (sizeof(unsigned) * 8));
	BUG_ON(numBits == 0);

	while (remainingBits) {
		if (node->pos >= node->end) {
			if (!endOkay) {
				printk("DecodeBuffer::decodeDirect: assertation failed\n");
				BUG ();
			}
			return 0;
		}

		if (node->freeBitsInDest > remainingBits) {
			// We must shift the bits into place.
			readBits = *node->pos >> (node->freeBitsInDest - remainingBits);

			*value |= (readBits & PARTIAL_INT_MASK[remainingBits]) << destShift;
			node->freeBitsInDest -= remainingBits;
			remainingBits = 0;
		} else {
			unsigned readBits = *node->pos & PARTIAL_INT_MASK[node->freeBitsInDest];
			*value |= readBits << destShift;
			destShift += node->freeBitsInDest;
			remainingBits -= node->freeBitsInDest;

			node->pos++;
			node->freeBitsInDest = 8;
		}
	}

	//DBG("value = 0x%08x\n", value);
	return 1;
}

int countLeadingZeros(unsigned *value, int endOkay, struct clog_node *node) {
	unsigned ix = 0;

	BUG_ON(node->freeBitsInDest == 0);

	while (node->pos < node->end) {
		unsigned mask = 1U << (node->freeBitsInDest - 1);

		while (node->freeBitsInDest) {
			if ((*node->pos) & mask) {

				// consume the 1 bit.
				node->freeBitsInDest--;
				if (!node->freeBitsInDest) {
					node->freeBitsInDest = 8;
					node->pos++;
				}
				*value = ix;
				return 1;
			}
			ix++;
			mask >>= 1;
			node->freeBitsInDest--;
		}
		node->pos++;
		node->freeBitsInDest = 8;
	}

	if (!endOkay) {
		printk("DecodeBuffer::countLeadingZeros: assertion failed.\n");
		BUG();
	}
	return 0;
}



#endif /* DECODEBUFFER_C_ */
