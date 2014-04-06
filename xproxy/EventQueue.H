#ifndef EVENTQUEUE_H_
#define EVENTQUEUE_H_
#define EVENT_QUEUE_SIZE 32
#include <iostream>
#include "dxpcconf.h"
#include "util.H"
using namespace std;
class EventQueue {
public:
	EventQueue(char* evenFilename, char* replyFilename, char* errorFilename,
			int replay);
	virtual ~EventQueue();
	unsigned int getEventPos();

	void recordEvent(unsigned int, unsigned char*);
	void replayEvent();
	unsigned char* getEventBuffer() {
		return eventBuffer;
	}

	unsigned char* getReplyBuffer() {
		return replyBuffer;
	}
	void recordReply(unsigned char*, unsigned int);
	unsigned int replayReply();

	void recordError(unsigned char*, unsigned int);
	void replayError();
	void nextError();
	unsigned char* getErrorBuffer() {
		if (errorCount < 0)
			return NULL;
		else
			return errorBuffer;
	}

private:
	fstream eventLogFile;
	fstream replyLogFile;
	fstream errorLogFile;

	int eventCount;
	unsigned int eventPos;
	unsigned char eventBuffer [32];
	void nextEvent();

	unsigned char* replyBuffer;
	unsigned int replyBufferSize;

	unsigned char errorBuffer[32];
	int errorCount;
	char* errorFileName;
	int errorFileOpened;
};

#endif /*EVENTQUEUE_H_*/
