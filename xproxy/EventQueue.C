#include "EventQueue.H"
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <string.h>
#include <stdio.h>
using namespace std;

EventQueue::EventQueue(char* evenFilename, char* replyFilename,
		char* errorFilename, int replay) {
	errorFileName = errorFilename;
	errorFileOpened = 0;
	errorCount = -1;
	eventPos = -1;
	eventCount = -1;
	if (replay) {
		//open event log file
		struct stat stat_buf;
		int rc = stat(evenFilename, &stat_buf);
		if (rc == 0)
			rc = stat_buf.st_size;
		if (rc > 0) {
			eventLogFile.open(evenFilename, ios::in | ios::out | ios::app
					| ios::binary);
			eventLogFile.exceptions(fstream::failbit | fstream::badbit);
			eventCount = rc / 36;
			if (PRINT_DEBUG) cout <<" Event Queue init: size is:"<<eventCount<<endl;
			nextEvent();
			--eventCount;
		} else
			if (PRINT_DEBUG) cout <<"Different: Event log size is 0"<<endl;

		//open error log file, if any
		rc = stat(errorFileName, &stat_buf);
		if (rc == 0)
			rc = stat_buf.st_size;
		if (rc > 0) {
			errorLogFile.open(errorFileName, ios::in | ios::out | ios::app
					| ios::binary);
			errorLogFile.exceptions(fstream::failbit | fstream::badbit);
			errorCount = rc / 32;
			if (PRINT_DEBUG) cout <<" Error Queue init: size is:"<<errorCount<<endl;
			nextError();
			--errorCount;
		} else
			if (PRINT_DEBUG) cout <<"No error messages recorded."<<endl;

		//open reply log file
		replyLogFile.open(replyFilename, ios::in | ios::out | ios::app
				| ios::binary);
		replyLogFile.exceptions(fstream::failbit | fstream::badbit);
	} else {
#ifdef FILE_REPLAY
		eventLogFile.open(evenFilename, ios::in | ios::out | ios::trunc
				| ios::binary);
		replyLogFile.open(replyFilename, ios::in | ios::out | ios::trunc
				| ios::binary);
#else
		eventLogFile.open(evenFilename, ios::in | ios::out | ios::app | ios::binary);
		replyLogFile.open(replyFilename, ios::in | ios::out | ios::app | ios::binary);
#endif
		eventLogFile.exceptions(fstream::failbit | fstream::badbit);
		replyLogFile.exceptions(fstream::failbit | fstream::badbit);
	}
	// init reply buffer
	replyBufferSize = 64;
	replyBuffer = new unsigned char[replyBufferSize];
}

EventQueue::~EventQueue() {
	eventLogFile.close();
	replyLogFile.close();
}

unsigned int EventQueue::getEventPos() {
	return eventPos;
}

void EventQueue::recordEvent(unsigned int pos, unsigned char* buffer) {
	try {
		eventLogFile.write ((char*)&pos, sizeof (unsigned int));
		eventLogFile.write ((char*) buffer, 32);
	} catch (fstream::failure e) {
		cerr << "Different: Failed to write into event.log"<<endl;
	}
}

void EventQueue::recordReply(unsigned char* buffer, unsigned int size) {
	try {
		replyLogFile.write ((char*)&size, sizeof (unsigned int));
		replyLogFile.write ((char*) buffer, size);
	} catch (fstream::failure e) {
		cerr << "Different: Failed to write into reply.log"<<endl;
	}
}

unsigned int EventQueue::replayReply() {
	unsigned int size = 0;
	try {
		replyLogFile.read ((char*)&size, sizeof (unsigned int));
		if (size> replyBufferSize) {
			replyBufferSize = size;
			delete [] replyBuffer;
			replyBuffer = new unsigned char[replyBufferSize];
			memset(replyBuffer, 0, replyBufferSize);
		}
		replyLogFile.read ((char*)replyBuffer, size);
	} catch (fstream::failure e) {
		cerr << "Different: Failed to read from reply.log"<<endl;
	}
	return size;
}

void EventQueue::recordError(unsigned char* buffer, unsigned int size) {
	if (!errorFileOpened) {
		cout <<"open error.log first."<<endl;
#ifdef FILE_REPLAY
		errorLogFile.open(errorFileName, ios::in | ios::out | ios::trunc
				| ios::binary);
#else
		errorLogFile.open(errorFileName, ios::in | ios::out | ios::app | ios::binary);
#endif
		errorLogFile.exceptions(fstream::failbit | fstream::badbit);
		errorFileOpened = 1;
	}
	try {
		errorLogFile.write ((char*) buffer, size);
	} catch (fstream::failure e) {
		cerr << "Different: Failed to write into error.log"<<endl;
	}
}

void EventQueue::nextError() {
	try {
		errorLogFile.read ((char*)errorBuffer, 32);
	} catch (fstream::failure e) {
		cerr << "Different: Failed to read from error.log"<<endl;
	}
}

void EventQueue::replayError() {
	if (errorCount == 0) {
		//last event in record
		errorCount = -1;
	} else if (errorCount == -1) {
		cerr <<"Different : We run out of errors in our log!"<<endl;
	} else {
		nextError();
		--errorCount;
	}
}

void EventQueue::nextEvent() {
	try {
		eventLogFile.read ((char*)&eventPos, sizeof (unsigned int));
		eventLogFile.read ((char*)eventBuffer, 32);
		if (PRINT_DEBUG) cout << "Next event in eventQueue: pos:"<<eventPos<<", opcode:"<<eventBuffer[0]<<endl;
	} catch (fstream::failure e) {
		cerr << "Different: Failed to read from event.log"<<endl;
	}
}

void EventQueue::replayEvent() {
	if (eventCount == 0) {
		//last event in record
		eventCount = -1;
		eventPos = -1;
	} else if (eventCount == -1) {
		cerr <<"Different : We run out of events in our log!"<<endl;
	} else {
		nextEvent();
		--eventCount;
	}

}
