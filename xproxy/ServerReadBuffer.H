#ifndef ServerReadBuffer_H
# define ServerReadBuffer_H

# include "ReadBuffer.H"

class ServerChannel;

class ServerReadBuffer:public ReadBuffer
{
  public:
    ServerReadBuffer(int fd, ServerChannel * channel):ReadBuffer(fd, 256),
        firstMessage_(1), channel_(channel)
    {
    }
    virtual ~ ServerReadBuffer()
    {
    }

    void setBigEndian(int flag)
    {
        bigEndian_ = flag;
    }

  protected:
    virtual int locateMessage(const unsigned char *start,
                              const unsigned char *end,
                              unsigned int &headerLength,
                              unsigned int &dataLength,
                              unsigned int &trailerLength);

    int firstMessage_;
    int bigEndian_;
    ServerChannel *channel_;
};

#endif /* ServerReadBuffer_H */
