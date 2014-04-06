#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include "DecodeBuffer.H"
#include "IntCache.H"
#include "CharCache.H"
#include "PixelCache.H"
#include "HuffmanCoder.H"
#include "constants.H"

#include <iostream>
#include <fstream>
#define OSTREAM std::ostream
#define OFSTREAM std::ofstream
#define COUT std::cout
#define CERR std::cerr
#define ENDL std::endl
#define IOS_OUT std::ios::out

//#define DEBUG
#ifdef DEBUG
# define DBG(fmt, ...) printf(fmt, __VA_ARGS__)
#else
# define DBG(fmt,...)
#endif

DecodeBuffer::DecodeBuffer(const unsigned char *data, unsigned int length)
{
    buffer = data;
    end = buffer + length;
    nextSrc = buffer;
    availableBitsInSrc = 8;
}

int DecodeBuffer::countLeadingZeros(unsigned &value, int endOkay)
{
    unsigned ix = 0;

    assert(availableBitsInSrc != 0);

    DBG("DecodeBuffer::countLeadingZeros: availableBitsInSrc = %d, *src = 0x%08x\n",
        availableBitsInSrc, *nextSrc);

    while (nextSrc < end)
    {
        unsigned mask = 1U << (availableBitsInSrc - 1);

        while (availableBitsInSrc)
        {
            if ((*nextSrc) & mask)
            {
                DBG("DecodeBuffer::countLeadingZeros: got %d\n", ix);

                // consume the 1 bit.
                availableBitsInSrc--;
                if (!availableBitsInSrc)
                {
                    availableBitsInSrc = 8;
                    nextSrc++;
                }
                value = ix;
                return 1;
            }
            ix++;
            mask >>= 1;
            availableBitsInSrc--;
        }
        nextSrc++;
        availableBitsInSrc = 8;
    }

    if (!endOkay)
    {
        CERR << "DecodeBuffer::countLeadingZeros: assertion failed." << ENDL;
        abort();
    }
    return 0;
}

int DecodeBuffer::decodeDirect(unsigned int &value,
                               unsigned int numBits,
                               int          endOkay)
{
    unsigned remainingBits = numBits;
    unsigned destShift = 0;

    value = 0;

    assert(numBits <= (sizeof(unsigned) * 8));
    assert(numBits != 0);

    DBG("DecodeBuffer::decodeDirect: %d bits,  availableBitsInSrc = %d, remaining = %d: ",
        numBits, availableBitsInSrc, end-nextSrc);

    while (remainingBits)
    {
        if (nextSrc >= end)
        {
            if (!endOkay)
            {
                CERR << "DecodeBuffer::decodeDirect: assertation failed" << ENDL;
            }
            return 0;
        }

        if (availableBitsInSrc > remainingBits)
        {
            // We must shift the bits into place.
            unsigned readBits = *nextSrc >> (availableBitsInSrc - remainingBits);

            value |= (readBits & PARTIAL_INT_MASK[remainingBits]) << destShift;
            availableBitsInSrc -= remainingBits;
            remainingBits = 0;
        }
        else
        {
            unsigned readBits = *nextSrc & PARTIAL_INT_MASK[availableBitsInSrc];
            value |= readBits << destShift;
            destShift += availableBitsInSrc;
            remainingBits -= availableBitsInSrc;

            nextSrc++;
            availableBitsInSrc = 8;
        }
    }

    DBG("value = 0x%08x\n", value);
    return 1;
}

int DecodeBuffer::decodeValue(unsigned int &value,
                              unsigned int numBits,
                              unsigned int blockSize,
                              int          endOkay)
{
    unsigned int remainingBits = numBits;
    unsigned int numBlocks = 0;
    unsigned int result = 0;

    DBG("DecodeBuffer::decodeValue: %d bits, %d blocksize\n",
           numBits, blockSize);

    assert(numBits <= (sizeof(unsigned) * 8));
    assert(numBits != 0);
    assert(blockSize <= numBits);

    if (blockSize == 0)
        blockSize = numBits;

    if ((blockSize == numBits) || (numBits < 3))
    {
        // No use for block compression.
        return decodeDirect(value, numBits, endOkay);
    }

    do
    {
        unsigned int bitsToRead = blockSize > remainingBits ? remainingBits : blockSize;
        unsigned int block;

        if (!decodeDirect(block, bitsToRead, endOkay))
        {
            return 0;
        }

        result = result | (block << (numBits - remainingBits));
        remainingBits -= bitsToRead;

        if (remainingBits)
        {
            unsigned marker;

            // Now read the marker bit.
            if (!decodeDirect(marker, 1, endOkay))
            {
                return 0;
            }

            if (!marker)
            {
                // The remainder of the value is all the same as the most significant bit
                // of the last block we read.
                unsigned lastBit = block & (1 << (bitsToRead - 1));

                DBG("decodeBuffer: got block compression (lastBit = %d, remainingBits = %d)\n",
                       lastBit ? 1 : 0, remainingBits);

                if (lastBit)
                {
                    // We need to build a mask of doom.
                    unsigned mask = PARTIAL_INT_MASK[remainingBits];

                    mask <<= (numBits - remainingBits);

                    DBG("Mask of ones = 0x%08x\n", mask);

                    result |= mask;
                }
                // No need to extend zeros.
                // Break out of outer loop, we're done.
                remainingBits = 0;
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

    DBG("decodeValue: value = 0x%08x\n", value);

    value = result;
    return 1;
}

// Simply returns a pointer to the correct spot in the internal
// buffer. If the caller needs this data to last beyond the lifetime
// of the internal buffer, they must copy the data.
const unsigned char *DecodeBuffer::decodeRawMem(unsigned int len)
{
    const unsigned char *retVal;

    // Force ourselves to a byte boundary.
    if (availableBitsInSrc != 8)
    {
        availableBitsInSrc = 8;
        nextSrc++;
    }

    retVal = nextSrc;

    if (end - nextSrc < (ptrdiff_t) len)
    {
        CERR << "DecodeBuffer::decodeRawMem called with " << len
            << " length with only " << end - nextSrc
            << " bytes remaining." << ENDL;
        abort();
    }

    nextSrc += len;
    return retVal;
}

int DecodeBuffer::decodeCachedValue(unsigned int &value,
                                    unsigned int numBits,
                                    IntCache     &cache,
                                    unsigned int blockSize,
                                    int          endOkay)
{
    unsigned int index;

    if (!countLeadingZeros(index, endOkay))
    {
        return 0;
    }

    if (index == 2)
    {
        unsigned int sameDiff;

        decodeDirect(sameDiff, 1);

        if (sameDiff)
        {
            value = cache.getLastDiff(PARTIAL_INT_MASK[numBits]);
            cache.insert(value, PARTIAL_INT_MASK[numBits]);
            return 1;
        }

        blockSize = cache.getBlockSize(numBits);

        if (!decodeValue(value, numBits, blockSize, endOkay))
        {
            return 0;
        }

        cache.insert(value, PARTIAL_INT_MASK[numBits]);
        return 1;
    }

    if (index > 2)
        index--;
    if (index > cache.getSize())
    {
        CERR << "Assertion 2 failed in DecodeCachedValue: index=" << index
            << ", cache size=" << cache.getSize() << ENDL;
        abort();
    }
    value = cache.get(index);
    return 1;
}

int DecodeBuffer::decodeCachedValue(unsigned char &value,
                                    unsigned int  numBits,
                                    CharCache     &cache,
                                    unsigned int  blockSize,
                                    int           endOkay)
{
    unsigned int index;

    if (!countLeadingZeros(index, endOkay))
    {
        return 0;
    }

    if (index == 2)
    {
        unsigned int val;

        if (decodeValue(val, numBits, blockSize, endOkay))
        {
            value = (unsigned char) val;
            cache.insert(value);
            return 1;
        }
        return 0;
    }
    if (index > 2)
        index--;
    if (index > cache.getSize())
    {
        CERR << "Assertion 4 failed in DecodeCachedValue: index=" << index
            << ", cache size=" << cache.getSize() << ENDL;
        abort();
    }
    value = cache.get(index);
    return 1;
}

int DecodeBuffer::decodeCachedValue(unsigned int &value, unsigned int numBits,
                                    PixelCache & cache,
                                    HuffmanCoder & escapeCoder0,
                                    HuffmanCoder & escapeCoder1, int endOkay)
{
    unsigned int index = 0;

    if (!countLeadingZeros(index, endOkay))
    {
        return 0;
    }

    if (index == 2)
    {
        value = 0;
        unsigned int pixelValue;

        if (!decodeDirect(pixelValue, 1, endOkay))
            return 0;
        unsigned int mask = 0x1;

        for (unsigned int x = 0; x < numBits;)
        {
            unsigned int runLength;

            if (pixelValue)
            {
                runLength = escapeCoder1.decode(*this) + 1;
                for (unsigned int i = runLength; i; i--)
                {
                    value |= mask;
                    mask <<= 1;
                }
                pixelValue = 0;
            }
            else
            {
                runLength = escapeCoder0.decode(*this) + 1;
                mask <<= runLength;
                pixelValue = 1;
            }
            x += runLength;
        }
        cache.insert(value);
        return 1;
    }
    if (index > 2)
        index--;
    if (index > cache.getSize())
    {
        CERR << "Assertion 6 failed in DecodeCachedValue: index=" << index
            << ", cache size=" << cache.getSize() << ENDL;
        abort();
    }
    value = cache.get(index);
    return 1;
}
