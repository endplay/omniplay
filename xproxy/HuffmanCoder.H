#ifndef HuffmanCoder_H
# define HuffmanCoder_H


class EncodeBuffer;
class DecodeBuffer;

class EncodeNode;

class HuffmanCoder
{
  public:
    HuffmanCoder(unsigned int histogramLength, const unsigned int *histogram,
                 unsigned int overflowCount = 0);
      HuffmanCoder(unsigned int numCodes, const char **codes);
     ~HuffmanCoder();

    void encode(unsigned int value, EncodeBuffer &);
    unsigned int decode(DecodeBuffer &);

  private:
      EncodeNode * root_;
    unsigned int numTokens_;
    EncodeNode **tokens_;
};

#endif /* HuffmanCoder_H */
