#ifndef ClientChannel_H
# define ClientChannel_H

# include "Channel.H"
# include "ClientReadBuffer.H"
# include "WriteBuffer.H"
# include "ClientCache.H"
# include "ServerCache.H"
# include "SequenceNumQueue.H"
# include "Stats.H"
#include "dxpcconf.h"
#include "util.H"

# include "Compresser.H"
using namespace std;

class DecodeBuffer;

class ClientChannel : public Channel {
public:
	ClientChannel(int xClientFD, unsigned int statisticsLevel,
			ResourceID *idMap, unsigned int *, char*, int);
	virtual ~ ClientChannel();

	virtual int doRead(EncodeBuffer &, SequenceNumQueue&,
			EventQueue &eventQueue_, int, int, int);
	virtual int doWrite(const unsigned char *message, unsigned int length,
			SequenceNumQueue &);

	void setBigEndian(int flag);

	ClientReadBuffer* getReadBuffer() {
		return &readBuffer_;
	}

	int getConvertPos() {
		return convertPos;
	}
#ifdef FILE_REPLAY
	void getNextRequest ();
	void setupFileReplay (int appFD);
#endif

#ifdef CONVERT
	bool hasBufferredMessage();
	int getReadBufferLength() {
		return readBuffer_.getLength();
	}
#endif

protected:
	void decodeCharInfo_(DecodeBuffer &, unsigned char *);

	ClientReadBuffer readBuffer_;
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

	Compresser *compresser;
	fstream logFile_;

	int convertPos;

#ifdef FILE_REPLAY
	char requestBuffer_[1024*1024];
	unsigned int requestPos_;
	unsigned int requestSize_;
	FILE* requestFile_;
#endif

};

#endif /* ClientChannel_H */
