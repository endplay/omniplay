#include "ProxyReadBuffer.H"


int ProxyReadBuffer::locateMessage(const unsigned char *start,
                                   const unsigned char *end,
                                   unsigned int &headerLength,
                                   unsigned int &dataLength,
                                   unsigned int &trailerLength)
{
    unsigned int lengthLength = 0;

    dataLength = 0;
    const unsigned char *nextSrc = start;
    unsigned char next;

    do
    {
        if (nextSrc >= end)
            return 0;
        next = *nextSrc++;
        dataLength <<= 7;
        dataLength |= (unsigned int) (next & 0x7f);
        lengthLength++;
    }
    while (next & 0x80);

    trailerLength = 0;

    headerLength = (dataLength == 0) ? 3 : lengthLength;

    unsigned int totalLength = headerLength + dataLength + trailerLength;

    if (start + totalLength > end)
        return 0;
    else
        return 1;
}
