#include "LastPixels.H"

LastPixels::LastPixels(unsigned int num):
    size_(num), 
    index_(0),
    buffer_(new unsigned int[num])
{
    for (unsigned int i = 0; i < num; i++)
        buffer_[i] = 0;
}


unsigned int LastPixels::getValue() const
{
    unsigned int sum = 0;
    unsigned int i;

    for (i = index_; i < size_; i++)
    {
        sum <<= 1;
        sum += buffer_[i];
    }
    for (i = 0; i < index_; i++)
    {
        sum <<= 1;
        sum += buffer_[i];
    }
    return sum;
}


void LastPixels::reset()
{
    for (unsigned int i = 0; i < size_; i++)
        buffer_[i] = 0;
}
