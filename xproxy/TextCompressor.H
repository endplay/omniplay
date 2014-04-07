#ifndef TextCompressor_H
# define TextCompressor_H

# include "CharCache.H"

class EncodeBuffer;
class DecodeBuffer;

class TextCompressor
{
  public:
    TextCompressor(CharCache * cache, unsigned int cacheSize):cache_(cache),
        cacheSize_(cacheSize), key_(0)
    {
    }

    void encodeChar(unsigned char ch, EncodeBuffer &);
    unsigned char decodeChar(DecodeBuffer &);
    void reset(unsigned int newKey = 0)
    {
        key_ = newKey;
    }

  private:
    CharCache * cache_;
    unsigned int cacheSize_;
    unsigned int key_;
};

#endif /* TextCompressor_H */
