#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "WriteBuffer.H"

WriteBuffer::WriteBuffer(unsigned int size) :
    bufferSize_(size), 
    numBytesInBuffer_(0), 
    buffer_(new unsigned char[size]),
    index_(NULL)
{
    memset(buffer_, 0, size);
}


WriteBuffer::~WriteBuffer()
{
    delete[]buffer_;
}


unsigned char *WriteBuffer::addMessage(unsigned int numBytes)
{
    if (numBytesInBuffer_ + numBytes > bufferSize_)
    {
        unsigned int indexOffset = 0;

        if (index_ && *index_)
            indexOffset = *index_ - buffer_;
        bufferSize_ = numBytesInBuffer_ + numBytes;
        unsigned char *newBuffer = new unsigned char[bufferSize_];

        memset(newBuffer, 0, bufferSize_);
        memcpy(newBuffer, buffer_, numBytesInBuffer_);
        delete[]buffer_;
        buffer_ = newBuffer;
        if (index_ && *index_)
            *index_ = buffer_ + indexOffset;
    }
    unsigned char *result = buffer_ + numBytesInBuffer_;

    numBytesInBuffer_ += numBytes;
    return result;
}
