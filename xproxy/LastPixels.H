#ifndef LastPixels_H
# define LastPixels_H

class LastPixels
{
  public:
    LastPixels(unsigned int num);
     ~LastPixels()
    {
        delete[]buffer_;
    }
    void add(unsigned int value)
    {
        buffer_[index_++] = value;
        if (index_ == size_)
            index_ = 0;
    }
    unsigned int getValue() const;
    void reset();

  private:
    unsigned int size_;
    unsigned int index_;
    unsigned int *buffer_;
};


#endif /* LastPixels_H */
