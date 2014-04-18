#include "SequenceNumQueue.H"
#include <stdio.h>
#include <iostream>
using namespace std;

static const unsigned int INITIALSIZE_ = 16;
static const unsigned int GROWTH_INCREMENT = 16;
#define seq_debug 0

SequenceNumQueue::SequenceNumQueue():
    queue_(new RequestSequenceNum[INITIALSIZE_]),
    size_(INITIALSIZE_),
    length_(0),
    startIndex_(0),
    endIndex_(0)
{
}

SequenceNumQueue::~SequenceNumQueue()
{
    delete[]queue_;
}

void SequenceNumQueue::push(unsigned short int sequenceNum,
                            unsigned char opcode, unsigned int data1,
                            unsigned int data2, unsigned int data3)
{
    if (length_ == 0)
    {
        startIndex_ = endIndex_ = 0;
        queue_[0].sequenceNum = sequenceNum;
        queue_[0].requestOpcode = opcode;
        queue_[0].data1 = data1;
        queue_[0].data2 = data2;
        queue_[0].data3 = data3;
        length_ = 1;
        if (seq_debug) cout <<" push "<<sequenceNum<<":"<<(unsigned int)opcode<<endl;
        return;
    }
    if (length_ == size_)
    {
        size_ += GROWTH_INCREMENT;
        RequestSequenceNum *newQueue = new RequestSequenceNum[size_];

        for (int i = startIndex_; (unsigned int) i < length_; i++)
            newQueue[i - startIndex_] = queue_[i];
        for (int i1 = 0; (unsigned int) i1 < startIndex_; i1++)
            newQueue[i1 + length_ - startIndex_] = queue_[i1];
        delete[]queue_;
        queue_ = newQueue;
        startIndex_ = 0;
        endIndex_ = length_ - 1;
    }
    endIndex_++;
    if (endIndex_ == size_)
        endIndex_ = 0;
    queue_[endIndex_].sequenceNum = sequenceNum;
    queue_[endIndex_].requestOpcode = opcode;
    queue_[endIndex_].data1 = data1;
    queue_[endIndex_].data2 = data2;
    queue_[endIndex_].data3 = data3;

    if (seq_debug) cout <<" push "<<sequenceNum<<":"<<(unsigned int)opcode<<endl;
    length_++;
}

int SequenceNumQueue::peek(unsigned short int &sequenceNum,
                           unsigned char &requestOpcode)
{
    if (length_ == 0)
        return 0;
    else
    {
        sequenceNum = queue_[startIndex_].sequenceNum;
        requestOpcode = queue_[startIndex_].requestOpcode;
        return 1;
    }
}

int SequenceNumQueue::pop(unsigned short int &sequenceNum,
                          unsigned char &requestOpcode, unsigned int &data1,
                          unsigned int &data2, unsigned int &data3)
{
    if (length_ == 0)
        return 0;
    else
    {
        sequenceNum = queue_[startIndex_].sequenceNum;
        requestOpcode = queue_[startIndex_].requestOpcode;
        data1 = queue_[startIndex_].data1;
        data2 = queue_[startIndex_].data2;
        data3 = queue_[startIndex_].data3;
        startIndex_++;
        if (startIndex_ == size_)
            startIndex_ = 0;
        length_--;
	if (seq_debug) std::cout <<" pop "<<sequenceNum<<":"<<(unsigned int)requestOpcode<<std::endl;
	
        return 1;
    }
}
