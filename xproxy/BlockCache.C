#include <string.h>
#include "BlockCache.H"


int BlockCache::compare(unsigned int size, const unsigned char *data,
                        int overwrite)
{
    int match = 0;

    if (size == size_)
    {
        match = 1;
        for (unsigned int i = 0; i < size_; i++)
            if (data[i] != buffer_[i])
            {
                match = 0;
                break;
            }
    }
    if (!match && overwrite)
        set(size, data);
    return match;
}


void BlockCache::set(unsigned int size, const unsigned char *data)
{
    if (size_ < size)
    {
        delete[]buffer_;
        buffer_ = new unsigned char[size];
    }
    size_ = size;
    memcpy(buffer_, data, size);
    checksum_ = checksum(size, data);
}


unsigned int
    BlockCache::checksum(unsigned int size, const unsigned char *data)
{
    unsigned int sum = 0;
    unsigned int shift = 0;
    const unsigned char *next = data;

    for (unsigned int i = 0; i < size; i++)
    {
        unsigned int value = (unsigned int) *next++;

        sum += (value << shift);
        shift++;
        if (shift == 8)
            shift = 0;
    }
    return sum;
}
