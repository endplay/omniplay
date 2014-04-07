#ifndef IntCache_H
# define IntCache_H

class IntCache
{
  public:
    IntCache(unsigned int size);
     ~IntCache()
    {
        delete[]buffer_;
    }
    unsigned int getSize() const
    {
        return length_;
    }
    int lookup(unsigned int &value, unsigned int &index, unsigned int mask,
               unsigned int &sameDiff);
    unsigned int get(unsigned int i);
    void insert(unsigned int &value, unsigned int mask);
    unsigned int getLastDiff(unsigned int mask) const
    {
        mask = 0;
        return lastDiff_;
    }
    unsigned int getBlockSize(unsigned int max) const
    {
        max = 0;
        return predictedBlockSize_;
    }

  private:
    unsigned int size_;
    unsigned int length_;
    unsigned int *buffer_;
    unsigned int lastValueInserted_;

    unsigned int lastDiff_;
    unsigned int predictedBlockSize_;
};

#endif /* IntCache_H */
