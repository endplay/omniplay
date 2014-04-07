#include "IntCache.H"


IntCache::IntCache(unsigned int size):
    size_(size), 
    length_(0), 
    buffer_(new unsigned int[size]),
    lastValueInserted_(0), 
    lastDiff_(0), 
    predictedBlockSize_(0)
{
}


int IntCache::lookup(unsigned int &value, unsigned int &index,
                     unsigned int mask, unsigned int &sameDiff)
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
    unsigned int insertionPoint;

    if (2 >= length_)
        insertionPoint = length_;
    else
        insertionPoint = 2;
    unsigned int start;

    if (length_ >= size_)
        start = size_ - 1;
    else
    {
        start = length_;
        length_++;
    }
    for (unsigned int k = start; k > insertionPoint; k--)
        buffer_[k] = buffer_[k - 1];
    buffer_[insertionPoint] = value;
    unsigned int diff = value - lastValueInserted_;

    lastValueInserted_ = (value & mask);
    value = (diff & mask);
    sameDiff = (value == lastDiff_);
    if (!sameDiff)
    {
        lastDiff_ = value;

        unsigned int lastChangeIndex = 0;
        unsigned int lastBitIsOne = (lastDiff_ & 0x1);
        unsigned int j = 1;

        for (unsigned int nextMask = 0x2; nextMask & mask; nextMask <<= 1)
        {
            unsigned int nextBitIsOne = (lastDiff_ & nextMask);

            if (nextBitIsOne)
            {
                if (!lastBitIsOne)
                {
                    lastChangeIndex = j;
                    lastBitIsOne = nextBitIsOne;
                }
            }
            else
            {
                if (lastBitIsOne)
                {
                    lastChangeIndex = j;
                    lastBitIsOne = nextBitIsOne;
                }
            }
            j++;
        }
        predictedBlockSize_ = lastChangeIndex + 1;
        if (predictedBlockSize_ < 2)
            predictedBlockSize_ = 2;
    }
    return 0;
}


unsigned int IntCache::get(unsigned int index)
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
    return result;
}


void IntCache::insert(unsigned int &value, unsigned int mask)
{
    unsigned int insertionPoint;

    if (2 >= length_)
        insertionPoint = length_;
    else
        insertionPoint = 2;
    unsigned int start;

    if (length_ >= size_)
        start = size_ - 1;
    else
    {
        start = length_;
        length_++;
    }
    for (unsigned int k = start; k > insertionPoint; k--)
        buffer_[k] = buffer_[k - 1];
    if (lastDiff_ != value)
    {
        lastDiff_ = value;
        unsigned int lastChangeIndex = 0;
        unsigned int lastBitIsOne = (lastDiff_ & 0x1);
        unsigned int j = 1;

        for (unsigned int nextMask = 0x2; nextMask & mask; nextMask <<= 1)
        {
            unsigned int nextBitIsOne = (lastDiff_ & nextMask);

            if (nextBitIsOne)
            {
                if (!lastBitIsOne)
                {
                    lastChangeIndex = j;
                    lastBitIsOne = nextBitIsOne;
                }
            }
            else
            {
                if (lastBitIsOne)
                {
                    lastChangeIndex = j;
                    lastBitIsOne = nextBitIsOne;
                }
            }
            j++;
        }
        predictedBlockSize_ = lastChangeIndex + 1;
        if (predictedBlockSize_ < 2)
            predictedBlockSize_ = 2;
    }
    lastValueInserted_ += value;
    lastValueInserted_ &= mask;
    buffer_[insertionPoint] = lastValueInserted_;
    value = lastValueInserted_;
}
