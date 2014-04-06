#include "dxpcconf.h"
#include "PixelCache.H"

static const unsigned int PXC_SIZE = 7;

int PixelCache::lookup(unsigned int value, unsigned int &index)
{
    for (unsigned int i = 0; i < length_; i++)
        if (value == buffer_[i])
        {
            index = i;
            if (i)
            {
                unsigned int target = (i >> 1);

                do
                {
                    buffer_[i] = buffer_[i - 1];
                    i--;
                }
                while (i > target);
                buffer_[target] = value;
            }
            return 1;
        }

    insert(value);
    return 0;
}


unsigned int PixelCache::get(unsigned int index)
{
    unsigned int result = buffer_[index];

    if (index != 0)
    {
        unsigned int i = index;
        unsigned int target = (i >> 1);

        do
        {
            buffer_[i] = buffer_[i - 1];
            i--;
        }
        while (i > target);
        buffer_[target] = result;
    }

    return (unsigned int) result;
}


void PixelCache::insert(unsigned int value)
{
    unsigned int insertionPoint;

    if (2 >= length_)
        insertionPoint = length_;
    else
        insertionPoint = 2;
    unsigned int start;

    if (length_ >= PXC_SIZE)
        start = PXC_SIZE - 1;
    else
    {
        start = length_;
        length_++;
    }
    for (unsigned int k = start; k > insertionPoint; k--)
        buffer_[k] = buffer_[k - 1];
    buffer_[insertionPoint] = value;
}
