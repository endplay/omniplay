#ifndef ReadBuffer_H
# define ReadBuffer_H
#include <stdio.h>
#include "util.H"
class ReadBuffer
{
  public:
    ReadBuffer(int fd, unsigned int maxReadSize = 0);
      virtual ~ ReadBuffer();

    int doRead();

    unsigned char *getMessage(unsigned int &dataLength);
    
    const unsigned char* getBufferStart ();
    const unsigned char* getBuffer ();
    
    int setReplay (char* filename);
    void stopReplay ();
    void rollBack (int offset);
    int getConvertLogFD ();
    unsigned int getLength () {
    	return length_;
    }
    int getConvertPos () {
    	return convertPos;
    }

  protected:
      virtual int locateMessage(const unsigned char *start,
                                const unsigned char *end,
                                unsigned int &headerLength,
                                unsigned int &dataLength,
                                unsigned int &trailerLength) = 0;
    int fd_;
    FILE* file;
    unsigned char *buffer_;
    unsigned int length_;
    unsigned int size_;
    unsigned int start_;
    unsigned int maxReadSize_;
    int server_replay_;
    int convertPos;
};

#endif /* ReadBuffer_H */
