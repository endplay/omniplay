#ifndef ProxyReadBuffer_H
# define ProxyReadBuffer_H

# include "ReadBuffer.H"


class ProxyReadBuffer:public ReadBuffer
{
  public:
    ProxyReadBuffer(int fd) :  ReadBuffer(fd)
    {
    }
    virtual ~ ProxyReadBuffer()
    {
    }

  protected:
    virtual int locateMessage(const unsigned char *start,
                              const unsigned char *end,
                              unsigned int &headerLength,
                              unsigned int &dataLength,
                              unsigned int &trailerLength);
};

#endif /* ProxyReadBuffer_H */
