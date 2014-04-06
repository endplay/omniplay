#ifndef BlockCache_H
# define BlockCache_H


// Cache to hold an arbitrary-length block of bytes

class BlockCache
{
  public:
    BlockCache():buffer_(0), size_(0), checksum_(0)
    {
    }
     ~BlockCache()
    {
        delete[]buffer_;
    }
    int compare(unsigned int size, const unsigned char *data,
                int overwrite = 1);
    void set(unsigned int size, const unsigned char *data);

    unsigned int getLength() const
    {
        return size_;
    }
    unsigned int getChecksum() const
    {
        return checksum_;
    }
    const unsigned char *getData() const
    {
        return buffer_;
    }

    static unsigned int checksum(unsigned int size,
                                 const unsigned char *data);

  private:
    unsigned char *buffer_;
    unsigned int size_;
    unsigned int checksum_;
};

#endif /* BlockCache_H */
