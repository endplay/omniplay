#ifndef ServerChannel_H
# define ServerChannel_H

# include "Channel.H"
# include "ServerReadBuffer.H"
# include "WriteBuffer.H"
# include "ClientCache.H"
# include "ServerCache.H"
# include "SequenceNumQueue.H"
# include "Stats.H"
#include "dxpcconf.h"
#include "EventQueue.H"
#include "util.H"

# include "Decompresser.H"

using namespace std;

class ServerChannel : public Channel {
public:
	ServerChannel(int xServerFD, unsigned int statisticsLevel,
			ResourceID *idMap, unsigned int *, char*, int);
	virtual ~ ServerChannel();

	virtual int doRead(EncodeBuffer &, SequenceNumQueue &,
			EventQueue &eventQueue_, int, int, int);
	virtual int doWrite(const unsigned char *message, unsigned int length,
			SequenceNumQueue & sequenceNumQueue_);

	void setBigEndian(int flag);

	ServerReadBuffer* getReadBuffer() {
		return &readBuffer_;
	}
	
	fstream* getReplyFile () {
		return &replyFile_;
	}
	
	int setConvertMode (char* filename);
	void setConvertPos (int pos) {
		convertPos = pos;
	}
	
	int getConvertPos () {
		return convertPos;
	}
protected:
	void encodeCharInfo_(const unsigned char *nextSrc, EncodeBuffer &);

	ServerReadBuffer readBuffer_;
	int fd_;
	WriteBuffer writeBuffer_;
	int firstRequest_;
	int firstReply_;

	ClientCache clientCache_;
	ServerCache serverCache_;

	int bigEndian_;
	unsigned int imageByteOrder_;
	unsigned int bitmapBitOrder_;
	unsigned int scanlineUnit_;
	unsigned int scanlinePad_;

	unsigned int statisticsLevel_;
	Stats stats_;
	Stats replyStats_;

	Decompresser *decompresser;
	fstream replyFile_;
	
	int convertPos;

};

#endif /* ServerChannel_H */
