#ifndef ClientReadBuffer_H
# define ClientReadBuffer_H

# include "ReadBuffer.H"

class ClientChannel;

class ClientReadBuffer:public ReadBuffer
{
  public:
    ClientReadBuffer(int fd, ClientChannel * channel):ReadBuffer(fd),
        firstMessage_(1), channel_(channel)
    {
    }
    virtual ~ ClientReadBuffer()
    {
    }
    int hasCompleteMessage ();

  protected:
    virtual int locateMessage(const unsigned char *start,
                              const unsigned char *end,
                              unsigned int &headerLength,
                              unsigned int &dataLength,
                              unsigned int &trailerLength);

    int firstMessage_;
    int bigEndian_;
    ClientChannel *channel_;
};

#endif /* ClientReadBuffer_H */
