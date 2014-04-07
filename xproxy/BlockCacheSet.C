#include "dxpcconf.h"

#include "BlockCacheSet.H"


BlockCacheSet::BlockCacheSet(unsigned int numCaches):
    caches_(new BlockCache *[numCaches]), 
    size_(numCaches), 
    length_(0)
{
    for (unsigned int i = 0; i < numCaches; i++)
        caches_[i] = new BlockCache();
}


BlockCacheSet::~BlockCacheSet()
{
    for (unsigned int i = 0; i < size_; i++)
        delete caches_[i];

    delete[]caches_;
}


int BlockCacheSet::lookup(unsigned int dataLength, const unsigned char *data,
                          unsigned int &index)
{
    unsigned int checksum = BlockCache::checksum(dataLength, data);

    for (unsigned int i = 0; i < length_; i++)
        if ((caches_[i]->getChecksum() == checksum) &&
            (caches_[i]->compare(dataLength, data, 0)))
        {
            // match
            index = i;
            if (i)
            {
                BlockCache *save = caches_[i];
                unsigned int target = (i >> 1);

                do
                {
                    caches_[i] = caches_[i - 1];
                    i--;
                }
                while (i > target);
                caches_[target] = save;
            }
            return 1;
        }
    // no match
    unsigned int insertionPoint = (length_ >> 1);
    unsigned int start;

    if (length_ >= size_)
        start = size_ - 1;
    else
    {
        start = length_;
        length_++;
    }
    BlockCache *save = caches_[start];

    for (unsigned int k = start; k > insertionPoint; k--)
        caches_[k] = caches_[k - 1];
    caches_[insertionPoint] = save;
    save->set(dataLength, data);
    return 0;
}


void BlockCacheSet::get(unsigned index, unsigned int &size,
                        const unsigned char *&data)
{
    size = caches_[index]->getLength();
    data = caches_[index]->getData();
    if (index)
    {
        BlockCache *save = caches_[index];
        unsigned int target = (index >> 1);

        do
        {
            caches_[index] = caches_[index - 1];
            index--;
        }
        while (index > target);
        caches_[target] = save;
    }
}



void BlockCacheSet::set(unsigned int dataLength, const unsigned char *data)
{
    unsigned int insertionPoint = (length_ >> 1);
    unsigned int start;

    if (length_ >= size_)
        start = size_ - 1;
    else
    {
        start = length_;
        length_++;
    }
    BlockCache *save = caches_[start];

    for (unsigned int k = start; k > insertionPoint; k--)
        caches_[k] = caches_[k - 1];
    caches_[insertionPoint] = save;
    save->set(dataLength, data);
}
