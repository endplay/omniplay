#ifndef EncodeBuffer_H
# define EncodeBuffer_H

class IntCache;
class CharCache;
class PixelCache;
class HuffmanCoder;

class EncodeBuffer
{
  public:
    EncodeBuffer();
    ~EncodeBuffer();

    void reset();
    void encodeValue(unsigned int value, unsigned int numBits,
                     unsigned int blockSize = 0);
    void encodeCachedValue(unsigned int value, unsigned int numBits,
                           IntCache & cache, unsigned int blockSize = 0);
    void encodeCachedValue(unsigned char value, unsigned int numBits,
                           CharCache & cache, unsigned int blockSize = 0);
    void encodeCachedValue(unsigned int value, unsigned int numBits,
                           PixelCache & cache, HuffmanCoder & escapeCoder0,
                           HuffmanCoder & escapeCoder1);
    void encodeRawMem(const unsigned char *buffer, unsigned int len);
    void encodeDirect(unsigned int value, unsigned int numBits);

    unsigned char *getData();
    unsigned int getDataLength() const;
    unsigned int getDataLengthInBits() const;
    unsigned int getCumulativeBitsWritten();

  private:
    void growBuffer(unsigned int minimumFreeSpaceAfterGrow = 0);
    void forceBufferToByteBoundary();

    void encodeIndex(unsigned index, int isEscape = 0);
    void encodeEscapeIndex(void);

    unsigned int size;
    unsigned char *buffer;
    unsigned char *end;
    unsigned char *nextDest;
    unsigned int freeBitsInDest;
    unsigned int cumulativeBits;
};

#endif /* EncodeBuffer_H */
