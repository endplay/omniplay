#include "CharCache.H"

static const unsigned char SIZE = 7;

int CharCache::lookup(unsigned char value, unsigned int &index)
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


unsigned int CharCache::get(unsigned int index)
{
    unsigned char result = buffer_[index];

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


void CharCache::insert(unsigned char value)
{
    unsigned int insertionPoint;

    if (2 >= length_)
        insertionPoint = length_;
    else
        insertionPoint = 2;
    unsigned int start;

    if (length_ >= SIZE)
        start = SIZE - 1;
    else
    {
        start = length_;
        length_++;
    }
    for (unsigned int k = start; k > insertionPoint; k--)
        buffer_[k] = buffer_[k - 1];
    buffer_[insertionPoint] = value;
}
