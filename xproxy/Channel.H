#ifndef Channel_H
# define Channel_H
#include "ResourceID.H"
#include "EventQueue.H"
class SequenceNumQueue;
class EncodeBuffer;


class Channel
{
  public:
    Channel():framingBitsOut_(0)
    {
    }
    virtual ~ Channel()
    {
    }

    virtual int doRead(EncodeBuffer &, SequenceNumQueue&, EventQueue &eventQueue_, int, int, int) = 0;
    virtual int doWrite(const unsigned char *message, unsigned int length, SequenceNumQueue &) =
        0;

    void recordFramingBits(unsigned int numBits)
    {
        framingBitsOut_ += numBits;
    }

  protected:
    unsigned int framingBitsOut_;
    ResourceID *idMap;
    int file_replay;
    unsigned int *outputLength_;
};

#endif /* Channel_H */
