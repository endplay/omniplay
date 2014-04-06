#include "dxpcconf.h"
#include <stddef.h>
#include "HuffmanCoder.H"
#include "EncodeBuffer.H"
#include "DecodeBuffer.H"


class EncodeNode
{
  public:
    EncodeNode(unsigned int v, unsigned int f):
        value_(v), 
        frequency_(f),
        encoding_(NULL), 
        codeLength_(0), 
        left_(NULL), 
        right_(NULL)
    {
    }
    EncodeNode(EncodeNode * left, EncodeNode * right,
               unsigned int f):
        value_(0), 
        frequency_(f), 
        encoding_(NULL),
        codeLength_(0), 
        left_(left), 
        right_(right)
    {
    }
    ~EncodeNode()
    {
        delete[]encoding_;
        delete left_;
        delete right_;
    }

    unsigned int getValue() const
    {
        return value_;
    }
    unsigned int getFrequency() const
    {
        return frequency_;
    }
    void setCode(unsigned char *code, unsigned int length);
    unsigned int getCodeLength() const
    {
        return codeLength_;
    }
    const unsigned char *getCode() const
    {
        return encoding_;
    }
    EncodeNode *addCode(unsigned int v, const char *code);

    unsigned int decode(DecodeBuffer &);

  private:
    unsigned int value_;
    unsigned int frequency_;
    unsigned char *encoding_;
    unsigned int codeLength_;   // in bits

    EncodeNode *left_;
    EncodeNode *right_;
};


void EncodeNode::setCode(unsigned char *code, unsigned int length)
{
    if (encoding_)
        delete[]encoding_;
    encoding_ = code;
    codeLength_ = length;
    unsigned int nextCodeLength = codeLength_ + 1;

    if (left_ != NULL)
    {
        unsigned char *leftCode = new unsigned char[nextCodeLength];
        unsigned int i = 0;

        for (; i < codeLength_; i++)
            leftCode[i] = encoding_[i];
        leftCode[i] = 0;
        left_->setCode(leftCode, nextCodeLength);
    }
    if (right_ != NULL)
    {
        unsigned char *rightCode = new unsigned char[nextCodeLength];
        unsigned int i = 0;

        for (; i < codeLength_; i++)
            rightCode[i] = encoding_[i];
        rightCode[i] = 1;
        right_->setCode(rightCode, nextCodeLength);
    }
}


unsigned int EncodeNode::decode(DecodeBuffer & decodeBuffer)
{
    if ((left_ == NULL) && (right_ == NULL))
        return value_;
    unsigned int nextBit;

    decodeBuffer.decodeValue(nextBit, 1);
    if (nextBit == 0)
        return left_->decode(decodeBuffer);
    else
        return right_->decode(decodeBuffer);
}


EncodeNode *EncodeNode::addCode(unsigned int value, const char *code)
{
    if (*code == 0)
    {
        value_ = value;
        return this;
    }
    else if (*code == '0')
    {
        if (left_ == NULL)
            left_ = new EncodeNode(NULL, NULL, 0);
        return left_->addCode(value, code + 1);
    }
    else
    {
        if (right_ == NULL)
            right_ = new EncodeNode(NULL, NULL, 0);
        return right_->addCode(value, code + 1);
    }
}


class Heap
{
  public:
    Heap(unsigned int maxSize);
    ~Heap();
    void insert(EncodeNode *);
    EncodeNode *pop();
    unsigned int size() const
    {
        return numElements_;
    }

  private:
    unsigned int numElements_;
    unsigned int size_;
    EncodeNode **heap_;
};





Heap::Heap(unsigned int maxSize):
    numElements_(0), 
    size_(maxSize),
    heap_(new EncodeNode *[maxSize])
{
}


Heap::~Heap()
{
    delete[]heap_;
}


void Heap::insert(EncodeNode * node)
{
    unsigned int location = numElements_++;
    unsigned int parent = ((location - 1) >> 1);

    while (location && (heap_[parent]->getFrequency() > node->getFrequency()))
    {
        heap_[location] = heap_[parent];
        location = parent;
        parent = ((location - 1) >> 1);
    }
    heap_[location] = node;
}


EncodeNode *Heap::pop()
{
    if (numElements_ == 0)
        return NULL;
    EncodeNode *result = heap_[0];

    numElements_--;
    EncodeNode *node = heap_[numElements_];
    unsigned int location = 0;

    do
    {
        unsigned int left = (location << 1) + 1;

        if (left >= numElements_)
            break;
        unsigned int nodeToSwap = left;
        unsigned int right = left + 1;

        if (right < numElements_)
            if (heap_[right]->getFrequency() < heap_[left]->getFrequency())
                nodeToSwap = right;
        if (heap_[nodeToSwap]->getFrequency() < node->getFrequency())
        {
            heap_[location] = heap_[nodeToSwap];
            location = nodeToSwap;
        }
        else
            break;
    }
    while (location < numElements_);
    heap_[location] = node;
    return result;
}



HuffmanCoder::HuffmanCoder(unsigned int histogramLength, 
                           const unsigned int *histogram, 
                           unsigned int overflowCount):
    numTokens_(histogramLength), 
    tokens_(new EncodeNode *[histogramLength + 1])
{
    Heap heap(histogramLength + 1);

    for (unsigned int i = 0; i < histogramLength; i++)
        heap.insert(tokens_[i] = new EncodeNode(i, histogram[i]));
    heap.insert(tokens_[histogramLength] =
                new EncodeNode(histogramLength, overflowCount));
    while (heap.size() > 1)
    {
        EncodeNode *node1 = heap.pop();
        EncodeNode *node2 = heap.pop();
        EncodeNode *newNode =
            new EncodeNode(node1, node2,
                           node1->getFrequency() + node2->getFrequency());
        heap.insert(newNode);
    }

    root_ = heap.pop();
    root_->setCode(NULL, 0);
}


HuffmanCoder::HuffmanCoder(unsigned int numCodes,
                           const char **codes):
    numTokens_(numCodes),
    tokens_(new EncodeNode *[numCodes])
{
    root_ = new EncodeNode(NULL, NULL, 0);
    for (unsigned int i = 0; i < numCodes; i++)
        tokens_[i] = root_->addCode(i, codes[i]);
    root_->setCode(NULL, 0);
}


HuffmanCoder::~HuffmanCoder()
{
    delete root_;

    delete[]tokens_;
}


void HuffmanCoder::encode(unsigned int value, EncodeBuffer & encodeBuffer)
{
    unsigned int index = value;

    if (index >= numTokens_)
        index = numTokens_;
    const EncodeNode *node = tokens_[index];
    const unsigned char *code = node->getCode();
    unsigned int codeLength = node->getCodeLength();

    for (unsigned int i = 0; i < codeLength; i++)
        encodeBuffer.encodeValue(code[i], 1);
    if (value >= numTokens_)
        encodeBuffer.encodeValue(value, 16, 8);
}


unsigned int HuffmanCoder::decode(DecodeBuffer & decodeBuffer)
{
    unsigned int result = root_->decode(decodeBuffer);

    if (result >= numTokens_)
        decodeBuffer.decodeValue(result, 16, 8);
    return result;
}
