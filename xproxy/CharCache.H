#ifndef CharCache_H
# define CharCache_H

// CharCache is a counterpart of IntCache that is
// optimized for use in compressing text composed
// of 8-bit characters.  (There used to be an
// abstract class Cache from which CharCache and
// IntCache were derived.  This has been eliminated,
// however, since the use of virtual functions
// increased the size of each CharCache by 50%
// (not a good thing when TextCompressor has an
// array of several thousand CharCaches :-)

class CharCache
{
  public:
    CharCache():length_(0)
    {
    }
     ~CharCache()
    {
    }
    unsigned int getSize() const
    {
        return (unsigned int) length_;
    }
    int lookup(unsigned char value, unsigned int &index);
    unsigned int get(unsigned int i);
    void insert(unsigned char value);

  private:
    unsigned char length_;
    unsigned char buffer_[7];   // limit to 7 chars so object will fit in 8 bytes

};

#endif /* CharCache_H */
