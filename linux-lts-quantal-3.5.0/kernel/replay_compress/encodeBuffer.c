#include <linux/encodebuffer.h>
#include <linux/c_constants.h>
#include <asm/bug.h>
#include <linux/slab.h>

#define PREFIX_SIZE 16
#define INITIAL_BUFFER_SIZE 256
void init_encode_buffer(struct clog_node* node){
	/*encodebuffer_size = INITIAL_BUFFER_SIZE;
	encode_buffer = kmalloc(encodebuffer_size + PREFIX_SIZE, GFP_KERNEL);
	encode_buffer += PREFIX_SIZE;
	node->end = encode_buffer + encodebuffer_size;
	size__=0;
	reset();*/
	node->end = node->head + node->size;
	node->freeBitsInDest = 8;
	node->cumulativeBits = 0;
	*node->pos = 0;
}

void free_buffer(struct clog_node* node){
	//kfree(encode_buffer-PREFIX_SIZE);
	vfree (node->head);
}

void reset(struct clog_node* node) {
	node->pos = node->head;
	node->freeBitsInDest = 8;
	node->cumulativeBits = 0;
	*node->pos = 0;
}

void encodeDirect(unsigned int value, unsigned int numBits, struct clog_node* node) {
	unsigned remainingBits = numBits;
	//size__+=numBits;

	// need a better way to grow up the buffer
	if (node->end - node->pos < 8) {
		//growBuffer(8, node);
		BUG ();
	}

	// Copy a byte at a time, least significant bits first.
	while (remainingBits) {
		if (node->freeBitsInDest > remainingBits) {
			// We must left shift the value into place.
			value = value & PARTIAL_INT_MASK[remainingBits];
			value <<= (node->freeBitsInDest - remainingBits);
			*node->pos |= value;
			node->freeBitsInDest -= remainingBits;
			remainingBits = 0;
		} else {
			// We're using all available bits in nextDest, no shift needed.
			*node->pos |= value & PARTIAL_INT_MASK[node->freeBitsInDest];
			//printk ("%u, %u\n", value & PARTIAL_INT_MASK[node->freeBitsInDest], value & (node->freeBitsInDest-1));
			value >>= node->freeBitsInDest;

			remainingBits -= node->freeBitsInDest;

			*(++node->pos) = 0;
			node->freeBitsInDest = 8;
		}
	}
}

void growBuffer(unsigned int minumumFreeSpaceAfterGrow, struct clog_node* node) {
	unsigned int nextDestOffset = node->pos - node->head;
	unsigned int newSize = node->size + node->size;
	unsigned char *newBuffer = kmalloc(newSize + PREFIX_SIZE, GFP_KERNEL) + PREFIX_SIZE;

	// Make sure the new size will accomodate the required minumum free
	// space.
	BUG ();
	if (minumumFreeSpaceAfterGrow < 2) {
		minumumFreeSpaceAfterGrow = 2;
	}
	if (newSize - nextDestOffset < minumumFreeSpaceAfterGrow) {
		newSize = nextDestOffset + minumumFreeSpaceAfterGrow;
	}

	memcpy(newBuffer, node->head, nextDestOffset + 1);
	newBuffer[nextDestOffset + 1] = 0;
	if (!(node->head - PREFIX_SIZE))
		kfree(node->head - PREFIX_SIZE);
	node->head = newBuffer;
	node->size = newSize;
	node->end = node->head + node->size;
	node->pos = node->head + nextDestOffset;
}

unsigned int getDataLength(struct clog_node* node) {
	unsigned int length = node->pos - node->head;

	if (node->freeBitsInDest != 8)
		length++;
	return length;
}

unsigned int getDataLengthInBits(struct clog_node* node) {
	unsigned int length = node->pos - node->head;

	return length * 8 + (8 - node->freeBitsInDest);
}

unsigned char *getData(struct clog_node* node) {
	return node->head;
}

unsigned int getCumulativeBitsWritten(struct clog_node* node) {
	unsigned int bitsWritten = getDataLengthInBits(node);

	unsigned int diff = bitsWritten - node->cumulativeBits;

	node->cumulativeBits = bitsWritten;
	return diff;
}

void encodeIndex(unsigned index, int isEscape, struct clog_node* node) {
	//size__+=index;
	if (index > 1 && !isEscape)
		++index;
	//write n leading zeros followed by a 1.
	while (index) {
		if (node->freeBitsInDest <= index) {
			if (++node->pos == node->end)
				growBuffer(0, node);
			*node->pos = 0;
			index -= node->freeBitsInDest;
			node->freeBitsInDest = 8;
		} else {
			node->freeBitsInDest -= index;
			index = 0;
		}
	}
	//now write the trailing one.
	encodeDirect(1, 1, node);
}

void encodeEscapeIndex(struct clog_node* node) {
	//write the magic index 2, which is encoded as 001
	encodeIndex(2, 1, node);
}

void encodeValue(unsigned int value, unsigned int numBits,
		unsigned int blockSize, struct clog_node* node) {
	unsigned int remainingBits = numBits;
	unsigned int numBlocks = 0;

	BUG_ON(numBits > (sizeof(unsigned) * 8));
	BUG_ON(numBits == 0);
	BUG_ON(blockSize > numBits);

	//printf("EncodeBuffer::encodeValue: bits %d, blockSize %d, node->freeBitsInDest = %d, value = 0x%08x\n", numBits, blockSize, node->freeBitsInDest, value);

	if (blockSize == 0)
		blockSize = numBits;

	if ((blockSize == numBits) || (numBits < 3)) {
		// Don't bother with trying block compression.
		encodeDirect(value, numBits, node);
		return;
	}

	do {
		unsigned int bitsToWrite = blockSize > remainingBits ? remainingBits
				: blockSize;
		unsigned int block;

		// Grab the bitsToWrite least significant bits.
		block = value & PARTIAL_INT_MASK[bitsToWrite];
		value >>= bitsToWrite;

		// Store 'em.
		encodeDirect(block, bitsToWrite, node);

		remainingBits -= bitsToWrite;

		if (remainingBits) {
			unsigned int lastBit;
			unsigned int mask = PARTIAL_INT_MASK[remainingBits];

			// See if all remaining bits match the most significant bit of the
			//             // block just written.
			lastBit = block & (1 << (bitsToWrite - 1));


			if ((lastBit && ((value & mask) == mask)) || (!lastBit && ((value
					& mask) == 0))) {
				// Remaining bits all match the last bit.
				//                 // Write a zero marker and we're outta here.

				//DBG("All remaining bits match last bit written (%d) " "(mask = 0x%08x, value = 0x%08x, remainingBits = %d)\n",lastBit ? 1 : 0, mask, value, remainingBits);
				encodeDirect(0, 1, node);
				remainingBits = 0;
			} else {
				//DBG("Need more blocks (lastBit = %d, value = 0x%08x, mask = 0x%08x, remainingBits = %d\n", lastBit ? 1 : 0, value, mask, remainingBits);
				// We need more blocks. Write a one marker and go on.
				encodeDirect(1, 1, node);
			}
		}

		if (++numBlocks >= 4) {
			blockSize = numBits;
		} else if (blockSize > 2) {
			blockSize >>= 1;
		}
	} while (remainingBits);
}

void encodeCachedValue(unsigned int value, unsigned int numBits,
		struct IntCache* cache, unsigned int blockSize, struct clog_node* node) {
	unsigned int newBlockSize = cache->predictedBlockSize;
	unsigned int index;
	unsigned int sameDiff;

	if (intcache_lookup(cache, &value, &index, PARTIAL_INT_MASK[numBits],
			&sameDiff))
		encodeIndex(index, 0, node);
	else {
		encodeEscapeIndex(node);
		if (sameDiff)
			encodeDirect(1, 1, node);
		else {
			encodeDirect(0, 1, node);
			encodeValue(value, numBits, newBlockSize, node);
		}
	}
}

void encodeCachedCharValue(unsigned char value, unsigned int numBits,
		struct CharCache* cache, unsigned int blockSize, struct clog_node* node) {
	unsigned int index;
	if (charcache_lookup(cache, value, &index))
		encodeIndex(index, 0, node);
	else {
		encodeEscapeIndex(node);
		encodeValue(value, numBits, blockSize, node);
	}
}
