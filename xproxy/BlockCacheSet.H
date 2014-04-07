#ifndef BlockCacheSet_H
# define BlockCacheSet_H

# include "BlockCache.H"


class BlockCacheSet
{
  public:
    BlockCacheSet(unsigned int numCaches);
     ~BlockCacheSet();

    int lookup(unsigned int size, const unsigned char *data,
               unsigned int &index);
    void get(unsigned int index, unsigned int &size,
             const unsigned char *&data);
    void set(unsigned int size, const unsigned char *data);

  private:
      BlockCache ** caches_;
    unsigned int size_;
    unsigned int length_;
};

#endif /* BlockCacheSet_H */
