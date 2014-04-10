#include "ServerReadBuffer.H"
#include "ServerChannel.H"
#include "util.H"


int ServerReadBuffer::locateMessage(const unsigned char *start,
                                    const unsigned char *end,
                                    unsigned int &headerLength,
                                    unsigned int &dataLength,
                                    unsigned int &trailerLength)
{
    unsigned int size = end - start;

    if (size < 8)
        return 0;
    if (firstMessage_) {
        dataLength = 8 + (GetUINT(start + 6, bigEndian_) << 2);
    }
    else
    {
        if (*start == 1 || *start == 35)
            dataLength = 32 + (GetULONG(start + 4, bigEndian_) << 2);
        else {
            dataLength = 32;
        }
    }

    if (size < dataLength)
        return 0;

    firstMessage_ = 0;
    headerLength = 0;
    trailerLength = 0;
    return 1;
}
