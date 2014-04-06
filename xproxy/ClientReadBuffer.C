#include "ClientReadBuffer.H"
#include "ClientChannel.H"
#include "util.H"

int ClientReadBuffer::hasCompleteMessage () {
	unsigned int headerLength, dataLength, trailerLength;
	return locateMessage (buffer_ + start_, buffer_ + start_ + length_,
			headerLength, dataLength, trailerLength);
}

int ClientReadBuffer::locateMessage(const unsigned char *start,
                                    const unsigned char *end,
                                    unsigned int &headerLength,
                                    unsigned int &dataLength,
                                    unsigned int &trailerLength)
{
    unsigned int size = end - start;

    if (size < 4)
        return 0;
    if (firstMessage_)
    {
        if (size < 12)
            return 0;
        if (*start == 0x42)
            bigEndian_ = 1;
        else
            bigEndian_ = 0;
        channel_->setBigEndian(bigEndian_);
        dataLength = 12 + RoundUp4(GetUINT(start + 6, bigEndian_)) +
            RoundUp4(GetUINT(start + 8, bigEndian_));
    }
    else
    {
        dataLength = (GetUINT(start + 2, bigEndian_) << 2);
    }

    if (size < dataLength)
        return 0;

    firstMessage_ = 0;
    headerLength = 0;
    trailerLength = 0;
    return 1;
}
