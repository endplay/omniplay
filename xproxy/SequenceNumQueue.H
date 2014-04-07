#ifndef SequenceNumQueue_H
# define SequenceNumQueue_H


// List of outstanding request messages, used to correlate request
// sequence numbers to their message types

class SequenceNumQueue
{
  public:
    SequenceNumQueue();
    virtual ~ SequenceNumQueue();

    void push(unsigned short int sequenceNum, unsigned char requestOpcode,
              unsigned int data1 = 0, unsigned int data2 = 0,
              unsigned int data3 = 0);
    int peek(unsigned short int &sequenceNum, unsigned char &requestOpcode);
    int pop(unsigned short int &sequenceNum, unsigned char &requestOpcode,
            unsigned int &data1, unsigned int &data2, unsigned int &data3);
    int pop(unsigned short int &sequenceNum, unsigned char &requestOpcode)
    {
        unsigned int data1, data2, data3;
          return pop(sequenceNum, requestOpcode, data1, data2, data3);
    }
    int getLength () {
    	return length_;
    }

  private:
    struct RequestSequenceNum
    {
        unsigned short int sequenceNum;
        unsigned char requestOpcode;
        unsigned int data1, data2, data3;
    };
    RequestSequenceNum *queue_;
    unsigned int size_;
    unsigned int length_;
    unsigned int startIndex_;
    unsigned int endIndex_;
};

#endif /* SequenceNumQueue_H */
