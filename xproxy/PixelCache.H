#ifndef PixelCache_H
# define PixelCache_H

class PixelCache
{
  public:
    PixelCache():length_(0)
    {
    }
    unsigned int getSize() const
    {
        return (unsigned int) length_;
    }
    int lookup(unsigned int value, unsigned int &index);
    unsigned int get(unsigned int i);
    void insert(unsigned int value);

  private:
    unsigned int length_;
    unsigned int buffer_[7];
};

#endif /* PixelCache_H */
