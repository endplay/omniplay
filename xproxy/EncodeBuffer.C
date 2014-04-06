#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include "dxpcconf.h"
#include "EncodeBuffer.H"
#include "IntCache.H"
#include "CharCache.H"
#include "PixelCache.H"
#include "HuffmanCoder.H"
#include "constants.H"

// #define DEBUG
#ifdef DEBUG
# define DBG(fmt, ...) printf(fmt, __VA_ARGS__)
#else
# define DBG(fmt,...)
#endif

static const int INITIAL_BUFFER_SIZE = 256;
static const int PREFIX_SIZE = 16;

EncodeBuffer::EncodeBuffer()
{
    size = INITIAL_BUFFER_SIZE;
    buffer = new unsigned char[size + PREFIX_SIZE];
    buffer += PREFIX_SIZE;
    end = buffer + size;
    reset();
}

EncodeBuffer::~EncodeBuffer()
{
    delete[](buffer - PREFIX_SIZE);
}

void EncodeBuffer::reset()
{
    nextDest = buffer;
    freeBitsInDest = 8;
    cumulativeBits = 0;
    *nextDest = 0;
}

void EncodeBuffer::encodeDirect(unsigned int value,
                               unsigned int numBits)
{
    unsigned remainingBits = numBits;

    assert(numBits <= (sizeof(unsigned) * 8));
    assert(numBits != 0);

    if (end - nextDest < 8)
    {
        growBuffer(8);
    }

    DBG("EncodeBuffer::encodeDirect: bits %d, freeBitsInDest = %d, value = 0x%08x\n",
         numBits, freeBitsInDest, value);

    // Copy a byte at a time, least significant bits first.
    while (remainingBits)
    {
        if (freeBitsInDest > remainingBits)
        {
            // We must left shift the value into place.
            value = value & PARTIAL_INT_MASK[remainingBits];
            value <<= (freeBitsInDest - remainingBits);
            *nextDest |= value;
            freeBitsInDest -= remainingBits;
            remainingBits = 0;
        }
        else
        {
            // We're using all available bits in nextDest, no shift needed.
            *nextDest |= value & PARTIAL_INT_MASK[freeBitsInDest];
            value >>= freeBitsInDest;

            remainingBits -= freeBitsInDest;

            *(++nextDest) = 0;
            freeBitsInDest = 8;
        }
    }
}

void EncodeBuffer::encodeValue(unsigned int value,
                               unsigned int numBits,
                               unsigned int blockSize)
{
    unsigned int remainingBits = numBits;
    unsigned int numBlocks = 0;

    assert(numBits <= (sizeof(unsigned) * 8));
    assert(numBits != 0);
    assert(blockSize <= numBits);

    DBG("EncodeBuffer::encodeValue: bits %d, blockSize %d, freeBitsInDest = %d, value = 0x%08x\n",
         numBits, blockSize, freeBitsInDest, value);

    if (blockSize == 0)
        blockSize = numBits;

    if ((blockSize == numBits) || (numBits < 3))
    {
        // Don't bother with trying block compression.
        encodeDirect(value, numBits);
        return;
    }

    do
    {
        unsigned int bitsToWrite = blockSize > remainingBits ? remainingBits : blockSize;
        unsigned int block;

        // Grab the bitsToWrite least significant bits.
        block = value & PARTIAL_INT_MASK[bitsToWrite];
        value >>= bitsToWrite;

        // Store 'em.
        encodeDirect(block, bitsToWrite);

        remainingBits -= bitsToWrite;

        if (remainingBits)
        {
            unsigned int lastBit;

            // See if all remaining bits match the most significant bit of the
            // block just written.
            lastBit = block & (1 << (bitsToWrite - 1));

            unsigned int mask = PARTIAL_INT_MASK[remainingBits];

            if ((lastBit && ((value & mask) == mask))
             || (!lastBit && ((value & mask) == 0)))
            {
                // Remaining bits all match the last bit.
                // Write a zero marker and we're outta here.

                DBG("All remaining bits match last bit written (%d) "
                       "(mask = 0x%08x, value = 0x%08x, remainingBits = %d)\n",
                       lastBit ? 1 : 0, mask, value, remainingBits);
                encodeDirect(0, 1);
                remainingBits = 0;
            }
            else
            {
                DBG("Need more blocks (lastBit = %d, value = 0x%08x, mask = 0x%08x, remainingBits = %d\n",
                       lastBit ? 1 : 0, value, mask, remainingBits);
                // We need more blocks. Write a one marker and go on.
                encodeDirect(1, 1);
            }
        }

        if (++numBlocks >= 4)
        {
            blockSize = numBits;
        }
        else if (blockSize > 2)
        {
            blockSize >>= 1;
        }
    } while (remainingBits);
}

unsigned int EncodeBuffer::getDataLength() const
{
    unsigned int length = nextDest - buffer;

    if (freeBitsInDest != 8)
        length++;
    return length;
}

unsigned int EncodeBuffer::getDataLengthInBits() const
{
    unsigned int length = nextDest - buffer;

    return length * 8 + (8 - freeBitsInDest);
}

unsigned char *EncodeBuffer::getData()
{
    return buffer;
}

unsigned int EncodeBuffer::getCumulativeBitsWritten()
{
    unsigned int bitsWritten = getDataLengthInBits();

    unsigned int diff = bitsWritten - cumulativeBits;

    cumulativeBits = bitsWritten;
    return diff;
}

void EncodeBuffer::growBuffer(unsigned int minumumFreeSpaceAfterGrow)
{
    unsigned int nextDestOffset = nextDest - buffer;
    unsigned int newSize = size + size;

    // Make sure the new size will accomodate the required minumum free
    // space.
    if (minumumFreeSpaceAfterGrow < 2)
    {
        minumumFreeSpaceAfterGrow = 2;
    }
    if (newSize - nextDestOffset < minumumFreeSpaceAfterGrow)
    {
        newSize = nextDestOffset + minumumFreeSpaceAfterGrow;
    }

    unsigned char *newBuffer = new unsigned char[newSize + PREFIX_SIZE] +
        PREFIX_SIZE;
    memcpy(newBuffer, buffer, nextDestOffset + 1);
    newBuffer[nextDestOffset + 1] = 0;
    delete[](buffer - PREFIX_SIZE);
    buffer = newBuffer;
    size = newSize;
    end = buffer + size;
    nextDest = buffer + nextDestOffset;
}

void EncodeBuffer::forceBufferToByteBoundary()
{
    if (freeBitsInDest != 8)
    {
        freeBitsInDest = 8;

        if (++nextDest == end)
        {
            growBuffer();
        }
        *nextDest = 0;
    }
}

void EncodeBuffer::encodeIndex(unsigned index, int isEscape)
{

    if (index > 1 && !isEscape)
        index++;

    DBG("EncodeBuffer::encodeIndex: writing %d\n", index);

    // Write n leading zeros followed by a 1.
    while (index)
    {
        if (freeBitsInDest <= index)
        {
            if (++nextDest == end)
            {
                growBuffer();
            }
            *nextDest = 0;
            index -= freeBitsInDest;
            freeBitsInDest = 8;
        }
        else
        {
            freeBitsInDest -= index;
            index = 0;
        }
    }
    // Now write the trailing one.
    encodeDirect(1,1);
}

void EncodeBuffer::encodeEscapeIndex(void)
{
    DBG("EncodeBuffer::encodeEscapeIndex\n");
    // Write the magic index 2, which is encoded as '001'.
    encodeIndex(2, 1);
}

void EncodeBuffer::encodeCachedValue(unsigned int value,
                                     unsigned int numBits,
                                     IntCache & cache,
                                     unsigned int blockSize)
{
    (void)blockSize;

    unsigned int newBlockSize = cache.getBlockSize(numBits);
    unsigned int index;
    unsigned int sameDiff;

    // The index is encoded as the number of leading zeros before a 1
    // bit. The index value 2 is a magic escape code.

    DBG("encodeIntCache.\n");

    if (cache.lookup(value, index, PARTIAL_INT_MASK[numBits], sameDiff))
    {
        encodeIndex(index);
    }
    else
    {
        encodeEscapeIndex();
        if (sameDiff)
            encodeDirect(1, 1);
        else
        {
            encodeDirect(0, 1);
            encodeValue(value, numBits, newBlockSize);
        }
    }
}

void EncodeBuffer::encodeCachedValue(unsigned char value,
                                     unsigned int numBits,
                                     CharCache & cache,
                                     unsigned int blockSize)
{
    unsigned int index;

    DBG("encodeCharCache.\n");

    if (cache.lookup(value, index))
    {
        encodeIndex(index);
    }
    else
    {
        encodeEscapeIndex();
        encodeValue(value, numBits, blockSize);
    }
}

void EncodeBuffer::encodeCachedValue(unsigned int value,
                                     unsigned int numBits,
                                     PixelCache & cache,
                                     HuffmanCoder & escapeCoder0,
                                     HuffmanCoder & escapeCoder1)
{
    unsigned int index;

    DBG("encodePixelCache.\n");

    if (cache.lookup(value, index))
    {
        encodeIndex(index);
    }
    else
    {
        encodeEscapeIndex();
        // To transmit the value, use run-length coding with the static
        // Huffman code implemented by the supplied "escapeCoder" object
        //X encodeValue(value, numBits, numBits);
        unsigned int srcMask = 0x1;
        unsigned int pixelValue = ((value & srcMask) ? 1 : 0);

        encodeDirect(pixelValue, 1);
        for (unsigned int x = 0; x < numBits;)
        {
            unsigned int runStart = x;

            if (pixelValue)
            {
                while (x < numBits)
                {
                    if (!(value & srcMask))
                        break;
                    srcMask <<= 1;
                    x++;
                }
            }
            else
            {
                while (x < numBits)
                {
                    if (value & srcMask)
                        break;
                    srcMask <<= 1;
                    x++;
                }
            }
            unsigned int runLength = x - runStart;

            if (pixelValue)
            {
                escapeCoder1.encode(runLength - 1, *this);
                pixelValue = 0;
            }
            else
            {
                escapeCoder0.encode(runLength - 1, *this);
                pixelValue = 1;
            }
        }
    }
}

void EncodeBuffer::encodeRawMem(const unsigned char *buffer, unsigned int len)
{
    forceBufferToByteBoundary();

    if (end - nextDest < (ptrdiff_t) len)
    {
        growBuffer(len);
    }

    memcpy(nextDest, buffer, len);
    nextDest += len;

    if (nextDest == end)
    {
        growBuffer();
    }
    else if (nextDest > end)
    {
        CERR << "EncodeBuffer::encodeRawMem overrun" << ENDL;
        abort();
    }
    *nextDest = 0;
}
