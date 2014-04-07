#ifndef WriteBuffer_H
# define WriteBuffer_H

class WriteBuffer
{
  public:
    WriteBuffer(unsigned int size = 1024);
     ~WriteBuffer();
    unsigned char *addMessage(unsigned int numBytes);
    unsigned char *getData()
    {
        return buffer_;
    }
    unsigned int getLength() const
    {
        return numBytesInBuffer_;
    }
    void reset()
    {
        numBytesInBuffer_ = 0;
    }

    void registerPointer(unsigned char **ptr)
    {
        index_ = ptr;
    }
    void unregisterPointer()
    {
        index_ = 0;
    }


  private:
    unsigned int bufferSize_;
    unsigned int numBytesInBuffer_;
    unsigned char *buffer_;
    unsigned char **index_;
};

#endif /* WriteBuffer_H */
