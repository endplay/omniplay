#ifndef DecodeBuffer_H
# define DecodeBuffer_H

class IntCache;
class CharCache;
class PixelCache;
class HuffmanCoder;

class DecodeBuffer
{
  public:
    DecodeBuffer(const unsigned char *data, unsigned int length);

    int decodeValue(unsigned int &value, unsigned int numBits,
                    unsigned int blockSize = 0, int endOkay = 0);
    int decodeCachedValue(unsigned int &value, unsigned int numBits,
                          IntCache & cache, unsigned int blockSize = 0,
                          int endOkay = 0);
    int decodeCachedValue(unsigned char &value, unsigned int numBits,
                          CharCache & cache, unsigned int blockSize = 0,
                          int endOkay = 0);
    int decodeCachedValue(unsigned int &value, unsigned int numBits,
                          PixelCache & cache, HuffmanCoder & escapeCoder0,
                          HuffmanCoder & escapeCoder1, int endOkay = 0);
    const unsigned char *decodeRawMem(unsigned int len);
    int decodeDirect(unsigned int &value, unsigned int numBits, int endOkay = 0);

  private:
    const unsigned char *buffer;
    const unsigned char *end;
    const unsigned char *nextSrc;
    unsigned int   availableBitsInSrc;
    int countLeadingZeros(unsigned &value, int endOkay);
};

#endif /* DecodeBuffer_H */
