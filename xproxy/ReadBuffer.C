#include "dxpcconf.h"
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include "ReadBuffer.H"

static const unsigned int INITIAL_BUFFER_SIZE = 512;
using namespace std;
#define replay_debug 1

ReadBuffer::ReadBuffer(int fd, unsigned int maxReadSize) :
	fd_(fd), buffer_(new unsigned char[INITIAL_BUFFER_SIZE]), length_(0),
			size_(INITIAL_BUFFER_SIZE), start_(0), maxReadSize_(maxReadSize) {
	memset(buffer_, 0, INITIAL_BUFFER_SIZE);
	server_replay_ = 0;
}

ReadBuffer::~ReadBuffer() {
	delete[]buffer_;
}

int ReadBuffer::setReplay(char* filename) {
	if (server_replay_ == 0) {
		server_replay_ = 1;
		file = fopen(filename, "r");
		cout <<"**** replay is opened."<<endl;
		convertPos = 0;
	}
	return getConvertLogFD();
}

int ReadBuffer::getConvertLogFD() {
	return fileno(file);
}

void ReadBuffer::rollBack(int offset) {
	//long cur = ftell (file);
	//fseek (file, cur - offset, SEEK_SET);
	start_ -= offset;
	length_ += offset;
}

void ReadBuffer::stopReplay() {
	if (server_replay_ == 1)
		server_replay_ = 0;
}

int ReadBuffer::doRead() {
#ifdef CONVERT
	if (server_replay_) {
		/*if ((start_ != 0) && (length_ != 0)) {
		 // if any bytes are left over from last time (due to partial message),
		 // shift them to the start of the buffer
		 unsigned char *nextDest = buffer_;
		 unsigned char *nextSrc = buffer_ + start_;

		 for (unsigned int i = 0; i < length_; i++)
		 *nextDest++ = *nextSrc++;
		 } else if (length_ == size_) {
		 // The buffer is full; double its size so that we can read some more
		 unsigned char *newBuffer = new unsigned char[size_ << 1];

		 cout <<"current size is "<<size_<<endl;
		 memset(newBuffer, 0, size_ << 1);
		 memcpy(newBuffer, buffer_, size_);
		 delete[]buffer_;
		 buffer_ = newBuffer;
		 size_ <<= 1;
		 }*/
		if (length_ > 0) {
			return convertPos;
		}
		int pos;
		int readLength;

		start_ = 0;

		int bytesRead;
		if (replay_debug)
			cout <<" read from file, current length before read:"<<length_<<endl;
		bytesRead = fread((char*)&pos, sizeof(char), sizeof(int), file);
		convertPos = pos;
		fread((char*) &readLength, sizeof(char), sizeof(int), file);
		if ((int)size_ < readLength) {
			cout <<"size need to be remalloced, size:"<<size_<<", readLength:"
					<<readLength<<endl;
			unsigned char *newBuffer = new unsigned char[readLength];
			memset(newBuffer, 0, readLength);
			memcpy(newBuffer, buffer_, size_);
			delete[]buffer_;
			buffer_ = newBuffer;
			size_ = readLength;
		}
		if (replay_debug)
			cout <<"We need read "<<readLength<<" bytes now"<<endl;
		if (readLength != 0) {
			bytesRead
					= fread(buffer_ + length_, sizeof(char), readLength, file);
			if (replay_debug)
				cout << "trying to read from file, readLength:"<<readLength
						<<" bytesRead:"<<bytesRead<<endl;
			for (int i = 0; i<bytesRead; ++i)
				if (replay_debug)
					cout <<(unsigned int)(buffer_+length_)[i]<<",";
			if (replay_debug)
				cout <<endl;

			//-1 means we cannot read more from the file, but we might still have messages bufferred
			if (bytesRead <= 0) {
				if (length_<=0) {
					cout <<"consume all buffer and end of file"<<endl;
					return 0;
				} else {
					cout <<"cannot read more from file, remaining length:"
							<<length_<<endl;
					return -1;
				}
			}
			length_ += bytesRead;
		}
		if (ftell(file) == SEEK_END) {
			cout <<"end of file"<<endl;
			return -1;
		}

		return pos;
	} else {
		if ((start_ != 0) && (length_ != 0)) {
			// if any bytes are left over from last time (due to partial message),
			// shift them to the start of the buffer
			unsigned char *nextDest = buffer_;
			unsigned char *nextSrc = buffer_ + start_;

			for (unsigned int i = 0; i < length_; i++)
				*nextDest++ = *nextSrc++;
		} else if (length_ == size_) {
			// The buffer is full; double its size so that we can read some more
			unsigned char *newBuffer = new unsigned char[size_ << 1];

			cout <<"current size is "<<size_<<endl;
			memset(newBuffer, 0, size_ << 1);
			memcpy(newBuffer, buffer_, size_);
			delete[]buffer_;
			buffer_ = newBuffer;
			size_ <<= 1;
		}
		start_ = 0;

		// Read as much data as is available
		unsigned int readLength = size_ - length_;

		if (maxReadSize_ && (readLength> maxReadSize_))
			readLength = maxReadSize_;
		int bytesRead;
		bytesRead = SOCKREAD(fd_, buffer_ + length_, readLength);

		if (bytesRead <= 0)
			return 0;
		length_ += bytesRead;

		return 1;
	}
#else 
	if ((start_ != 0) && (length_ != 0)) {
		// if any bytes are left over from last time (due to partial message),
		// shift them to the start of the buffer
		unsigned char *nextDest = buffer_;
		unsigned char *nextSrc = buffer_ + start_;

		for (unsigned int i = 0; i < length_; i++)
		*nextDest++ = *nextSrc++;
	} else if (length_ == size_) {
		// The buffer is full; double its size so that we can read some more
		unsigned char *newBuffer = new unsigned char[size_ << 1];

		if (PRINT_DEBUG) cout <<"current size is "<<size_<<endl;
		memset(newBuffer, 0, size_ << 1);
		memcpy(newBuffer, buffer_, size_);
		delete[]buffer_;
		buffer_ = newBuffer;
		size_ <<= 1;
	}
	start_ = 0;

	// Read as much data as is available
	unsigned int readLength = size_ - length_;

	if (maxReadSize_ && (readLength> maxReadSize_))
	readLength = maxReadSize_;
	int bytesRead;
	bytesRead = SOCKREAD(fd_, buffer_ + length_, readLength);

	if (bytesRead <= 0)
	return 0;
	length_ += bytesRead;

	return 1;
#endif
}

unsigned char *ReadBuffer::getMessage(unsigned int &messageLength) {
	unsigned int headerLength, dataLength, trailerLength;
	if (locateMessage(buffer_ + start_, buffer_ + start_ + length_,
			headerLength, dataLength, trailerLength)) {
		unsigned char *result = buffer_ + start_;

		messageLength = dataLength;
		if (dataLength)
			result += headerLength;
		else {
			// probably this application is using big request extension
			// we need to get the new request size; but read more bytes first
			
			messageLength += headerLength;
			return NULL;
		}
		start_ += (headerLength + dataLength + trailerLength);
		length_ -= (headerLength + dataLength + trailerLength);
		return result;
	} else {
		// No more complete messages remain in buffer
		return NULL;
	}
}

const unsigned char* ReadBuffer::getBufferStart() {
	return buffer_ + start_;
}

const unsigned char* ReadBuffer::getBuffer() {
	return buffer_;
}
