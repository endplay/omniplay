#include <string.h>
#include "X-headers.H"
#include "ClientChannel.H"
#include "EncodeBuffer.H"
#include "DecodeBuffer.H"
#include "util.H"

#include <stdio.h>
using namespace std;

ClientChannel::ClientChannel(int xClientFD, unsigned int
statisticsLevel, ResourceID *IdMap, unsigned int* outputLength, char* filename,
		int fileReplay) :
	readBuffer_(xClientFD, this), fd_(xClientFD), firstRequest_(1),
			firstReply_(1), statisticsLevel_(statisticsLevel) {
	if (compressImages) {
		compresser = new Compresser(compressImages);
	} else {
		compresser = 0;
	}
	idMap = IdMap;
	outputLength_ = outputLength;
#ifdef FILE_REPLAY
	if (!fileReplay)
	logFile_.open(filename, ios::in | ios::out | ios::binary | ios::trunc);
	else
	logFile_.open(filename, ios::in | ios::out | ios::binary | ios::app);
#else
	logFile_.open(filename, ios::in | ios::out | ios::binary | ios::app);
#endif
	logFile_.exceptions(fstream::failbit | fstream::badbit);
	file_replay = fileReplay;
	convertPos = 0;
}

ClientChannel::~ClientChannel() {
	if (statisticsLevel_ > 0) {
		*logofs << "\n*** dxpc Client-side Compression Statistics ***\n";
		if (statisticsLevel_ >= 2) {
			*logofs << "\nCompression of requests by message type:\n";
		}
		unsigned int bitsIn, bitsOut;

		stats_.summarize(bitsIn, bitsOut, (statisticsLevel_ >= 2));

		if (statisticsLevel_ >= 2) {
			*logofs << '\n' << framingBitsOut_
					<< " bits used for dxpc message framing and multiplexing\n";
		}
		bitsOut += framingBitsOut_;

		*logofs << "\nOverall compression:" << ENDL << "  " << bitsIn
				<< " bits compressed to " << bitsOut << ENDL;
		if (bitsOut > 0) {
			*logofs << "  (" << (float) bitsIn / (float) bitsOut
					<< ":1 compression ratio)" << ENDL << ENDL;
		}
	}

	if (compresser) {
		delete compresser;

		compresser = 0;
	}
	cout << "Logging all request messages..."<<endl;
	logFile_.close();
}

#ifdef FILE_REPLAY
void ClientChannel::setupFileReplay(int appFD) {
	requestFile_ = fdopen(appFD, "r+");
	getNextRequest();
}

void ClientChannel::getNextRequest() {
	try {
		fread((char*)&requestPos_, sizeof(char), sizeof(unsigned int), requestFile_);
		fread((char*)&requestSize_, sizeof(char), sizeof(unsigned int),
				requestFile_);
		fread((char*)requestBuffer_, sizeof(char), requestSize_, requestFile_);
	} catch (fstream::failure e) {
		cerr << "Getnextrequest fails"<<endl;
	}
	cout << "new Request, pos:"<<requestPos_<<", size:"<<requestSize_<<endl;
}
#endif

#ifdef CONVERT
bool ClientChannel::hasBufferredMessage () {
	if (readBuffer_.getLength())
	return true;
	else
	return false;
}
#endif

int ClientChannel::doRead(EncodeBuffer & encodeBuffer,
		SequenceNumQueue & sequenceNumQueue_, EventQueue &eventQueue_,
		int appFD, int serverFD, int replay) {
#ifdef FILE_REPLAY
	if (!replay)
#endif
#ifdef CONVERT
	if (!readBuffer_.doRead() && readBuffer_.getLength() == 0)
	return 0;
#else
	if (!readBuffer_.doRead())
		return 0;
#endif

	unsigned char *buffer;
	unsigned int size;
	//unsigned int specialRequest = 0;
#ifndef FILE_REPLAY
	unsigned char* replayBuffer;
#endif

#ifdef FILE_REPLAY
	while ((replay && requestPos_ <= *outputLength_) || (!replay && (buffer
							= readBuffer_.getMessage(size)) != 0)) {

		if (replay) {
			buffer = (unsigned char*) requestBuffer_;
			size = requestSize_;
		}
#else
	while ((buffer = readBuffer_.getMessage(size)) != 0) {
#endif
		if (replay) {
#ifndef FILE_REPLAY
			//replay
			try {

				if (PRINT_DEBUG) {
					replayBuffer = new unsigned char[size];
					//dummy read for file replay mode
					logFile_.read ((char*)replayBuffer, sizeof (unsigned int) *2);
					//real read
					logFile_.read((char*)replayBuffer, size);
					if (memcmp(buffer, replayBuffer, size) != 0) {
						cout << " Different request message with recording! error"
						<<endl;
						cout <<"		From log:";
						for (unsigned int i = 0; i < size; ++i)
						cout <<(unsigned int) replayBuffer[i] <<",";
						cout <<endl;
						cout <<"		From x server:";
						for (unsigned int i = 0; i < size; ++i)
						cout <<(unsigned int) buffer[i] <<",";
						cout <<endl;
						detailedCompare (replayBuffer, size, buffer, size);
					}
				}

			} catch (fstream::failure e) {
				cerr << "Exception reading files in ClientChannel.c"<<endl;
			}
#endif
		} else {
			// recording
			try {
				//#ifdef FILE_REPLAY
				//recording into file
				if (PRINT_DEBUG) {
					logFile_.write((char*)(outputLength_), sizeof (unsigned int));
					logFile_.write ((char*)&size, sizeof (unsigned int));
					//#endif
					logFile_.write ((char*)buffer, size);
				}

			} catch (fstream::failure e) {
				cerr << "Exception writing files in ClientChannel.c"<<endl;
			}
		}
		//		*outputLength_ += size;
		*outputLength_ += 1;
#ifdef CONVERT
		if (convert_log) {
			convertPos += size;
		}
#endif

		if (firstRequest_) {
			for (unsigned int i = 0; i < size; i++) {
				encodeBuffer.encodeValue((unsigned int) buffer[i], 8);
			}
			firstRequest_ = 0;
			if (PRINT_DEBUG)
				cout<< "first request, size:"<<size<<endl;
			if (convert_log) {
				//put a dummy sequence number for converting log mode
				sequenceNumQueue_.push(0, 1);
			}
			printMessage(buffer, size, 7, 1, 1+MAGIC_SIZE, 2, 2, 2, 2, 2
					+MAGIC_SIZE);
		} else {
			clientCache_.lastRequestSequenceNum++;
			unsigned char opcode = *buffer;

			if ((opcode == X_PolyFillRectangle) && (GetUINT(buffer + 2,
					bigEndian_) == 3)) {
				opcode = X_NoOperation;
			}
			if (PRINT_DEBUG)
				cout <<"request  opcode:"<<(unsigned int)opcode<<"  sequence:"
						<<clientCache_.lastRequestSequenceNum<<"  size:"<<size
						<<endl;

			encodeBuffer.encodeCachedValue(opcode, 8, clientCache_.
			opcodeCache[clientCache_.
			lastOpcode]);
			clientCache_.lastOpcode = opcode;

			switch (opcode) {
			case X_AllocColor: {
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.colormapCache, 9);
				const unsigned char *nextSrc = buffer + 8;
				unsigned int colorData[3];

				for (unsigned int i = 0; i < 3; i++) {
					unsigned int value = GetUINT(nextSrc, bigEndian_);

					encodeBuffer.encodeCachedValue(value, 16, *(clientCache_.
					allocColorRGBCache
					[i]), 4);
					colorData[i] = value;
					nextSrc += 2;
				}
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode, colorData[0], colorData[1],
						colorData[2]);
				printMessage(buffer, size, 8, 1, 1+MAGIC_SIZE, 2, 4, 2, 2, 2,
						-1);
			}
				break;
			case X_ChangeProperty: {
				unsigned char format = buffer[16];

				unsigned int dataLength = GetULONG(buffer + 20, bigEndian_);
				if (replay) {
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer+4, bigEndian_);
					//atom
					PutULONG(idMap->atomMapToNew(GetULONG(buffer + 8,
							bigEndian_)), buffer+ 8, bigEndian_);
					PutULONG(idMap->atomMapToNew(GetULONG(buffer + 12,
							bigEndian_)), buffer+ 12, bigEndian_);
				}
				printMessage(buffer, size, 11, 1, 1, 2, 4, 4, 4, 1, 3
						+MAGIC_SIZE, 4, (format == 8 ? dataLength
						: (format==16 ? dataLength*2 : dataLength*4)), -1);
			}
				break;
			case X_ChangeWindowAttributes: {
				encodeBuffer.encodeValue((size - 12) >> 2, 4);
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.windowCache, 9);
				unsigned int bitmask = GetULONG(buffer + 8, bigEndian_);

				encodeBuffer.encodeCachedValue(bitmask, 15, clientCache_.
				createWindowBitmaskCache);
				unsigned char *nextSrc = buffer + 12;
				unsigned int mask = 0x1;

				for (unsigned int j = 0; j < 15; j++) {
					if (bitmask & mask) {
						switch (j) {
						case 0:
						case 2:
						case 13:
						case 14: {
							if (replay)
								PutULONG(idMap->mapToNewNonWindow(GetULONG(
										nextSrc, bigEndian_)), nextSrc,
										bigEndian_);
						}
							break;
						}
						nextSrc += 4;
					}
					mask <<= 1;
				}
				if (replay) {
					// 4- 8, window id
					PutULONG(idMap->mapToNewSpecial(GetULONG(buffer + 4,
							bigEndian_)), buffer + 4, bigEndian_);
				}
				printMessage(buffer, size, 5, 1, 1+MAGIC_SIZE, 2, 4, 4);
			}
				break;
			case X_ClearArea: {
				encodeBuffer.encodeValue((unsigned int) buffer[1], 1);
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.windowCache, 9);
				const unsigned char *nextSrc = buffer + 8;

				for (unsigned int i = 0; i < 4; i++) {
					encodeBuffer.encodeCachedValue(
							GetUINT(nextSrc, bigEndian_), 16, *clientCache_.
							clearAreaGeomCache[i], 8);
					nextSrc += 2;
				}
				if (replay) {
					// 4- 8, gc id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
				}
				printMessage(buffer, size, 8, 1, 1, 2, 4, 2, 2, 2, 2);
			}
				break;
			case X_CloseFont: {
				if (replay) {
					// 4- 8, font id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
				}
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_ConfigureWindow: {
				unsigned int bitmask = GetUINT(buffer + 8, bigEndian_);
				unsigned int mask = 0x1;
				unsigned char *nextSrc = buffer + 12;
				for (unsigned int i = 0; i < 7; i++) {
					if (bitmask & mask) {
						/*if ((mask & 0x0020) && replay) {
						 PutULONG(idMap->mapToNew(GetULONG(nextSrc,
						 bigEndian_)), nextSrc, bigEndian_);
						 }*/
						if (mask & 0x0020)
							break;
						nextSrc += 4;
					}
					mask <<= 1;
				}
				if ((bitmask & 0x0020) && replay) {
					// put this window on the top of the stack anyway, ignore the siblings
					//change bit mask
					bitmask -= 0x0020;
					PutUINT(bitmask, buffer + 8, bigEndian_);
					//change the size of the message
					unsigned int request_length = GetUINT(buffer + 2,
							bigEndian_);
					PutUINT(request_length - 1, buffer + 2, bigEndian_);
					size -= 4;
					// change the value list
					if (bitmask & 0x0040) {
						PutULONG(GetULONG(nextSrc + 4, bigEndian_), nextSrc,
								bigEndian_);
					}

				}
				if (replay) {
					// 4- 8, window id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
				}
				printMessage(buffer, size, 6, 1, 1+MAGIC_SIZE, 2, 4, 2, 2
						+MAGIC_SIZE);
			}
				break;
			case X_ConvertSelection: {
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.
						convertSelectionRequestorCache, 9);
				const unsigned char *nextSrc = buffer + 8;

				for (unsigned int i = 0; i < 3; i++) {
					encodeBuffer.
					encodeCachedValue(GetULONG(nextSrc, bigEndian_), 29,
							*(clientCache_.
							convertSelectionAtomCache[i]), 9);
					nextSrc += 4;
				}
				unsigned int timestamp = GetULONG(nextSrc, bigEndian_);

				encodeBuffer.encodeValue(timestamp - clientCache_.
				convertSelectionLastTimestamp, 32, 4);
				clientCache_.convertSelectionLastTimestamp = timestamp;
				cout << "not compressed (error message)"<<endl;
				if (!PRINT_DEBUG) printString (buffer, size);
				printMessage(buffer, size, 8, 1, 1+MAGIC_SIZE, 2, 4, 4, 4, 4, 4);
			}
				break;
			case X_CopyArea: {
				if (replay) {
					// 4- 8, 8-12, drawable, 12 gc id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
					PutULONG(
							idMap->mapToNew(GetULONG(buffer + 12, bigEndian_)),
							buffer + 12, bigEndian_);
				}
				printMessage(buffer, size, 12, 1, 1+MAGIC_SIZE, 2, 4, 4, 4, 2,
						2, 2, 2, 2, 2);
			}
				break;
			case X_CopyGC: {
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.gcCache, 9);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
						clientCache_.gcCache, 9);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 12, bigEndian_), 23,
						clientCache_.createGCBitmaskCache);
				printMessage(buffer, size, 6, 1, 1+MAGIC_SIZE, 2, 4, 4, 4);

			}
				break;
			case X_CopyPlane: {
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.drawableCache, 9);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
						clientCache_.drawableCache, 9);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 12, bigEndian_), 29,
						clientCache_.gcCache, 9);
				const unsigned char *nextSrc = buffer + 16;

				for (unsigned int i = 0; i < 6; i++) {
					encodeBuffer.encodeCachedValue(
							GetUINT(nextSrc, bigEndian_), 16, *clientCache_.
							copyPlaneGeomCache[i], 8);
					nextSrc += 2;
				}
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 28, bigEndian_), 32, clientCache_.
						copyPlaneBitPlaneCache, 10);
				printMessage(buffer, size, 13, 1, 1+MAGIC_SIZE, 2, 4, 4, 4, 2,
						2, 2, 2, 2, 2, 4);
			}
				break;
			case X_CreateGC:
			case X_ChangeGC: {
				if (replay) {
					// change pos:4-8, gcontext id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer+4, bigEndian_);
					unsigned char* nextSrc;
					//change pos: 8-12, drawable id; for CreateGC
					unsigned int valueMask;
					if (opcode == X_CreateGC) {
						PutULONG(idMap->mapToNew(GetULONG(buffer + 8,
								bigEndian_)), buffer+8, bigEndian_);
						valueMask = GetULONG(buffer + 12, bigEndian_);
						nextSrc = buffer + 16;
					} else {
						valueMask= GetULONG(buffer + 8, bigEndian_);
						nextSrc = buffer + 12;
					}

					unsigned int mask = 0x1;
					for (unsigned int j = 0; j < 23; j++) {
						if (valueMask & mask) {
							switch (j) {
							case 10:
							case 11:
							case 14:
							case 19: {
								if (replay)
									PutULONG(idMap->mapToNew(GetULONG(nextSrc,
											bigEndian_)), nextSrc, bigEndian_);
							}
								break;
							}
							nextSrc += 4;
						}
						mask <<= 1;
					}
				}
				printMessage(buffer, size, 6, 1, 1+MAGIC_SIZE, 2, 4, 4, 4);
			}
				break;
			case X_CreatePixmap: {
				if (replay) {
					// 4-8, pixmap id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					// 8-12, drawable id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
				}
				printMessage(buffer, size, 7, 1, 1, 2, 4, 4, 2, 2);
			}
				break;
			case X_CreateWindow: {
				encodeBuffer.encodeCachedValue((unsigned int) buffer[1], 8,
						clientCache_.depthCache);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
						clientCache_.windowCache, 9);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.windowCache, 9);
				unsigned char *nextSrc = buffer + 12;

				for (unsigned int i = 0; i < 6; i++) {
					encodeBuffer.encodeCachedValue(
							GetUINT(nextSrc, bigEndian_), 16, *clientCache_.
							createWindowGeomCache
							[i], 8);
					nextSrc += 2;
				}
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 24, bigEndian_), 29,
						clientCache_.visualCache);
				unsigned int bitmask = GetULONG(buffer + 28, bigEndian_);

				encodeBuffer.encodeCachedValue(bitmask, 15, clientCache_.
				createWindowBitmaskCache);
				nextSrc = buffer + 32;
				unsigned int mask = 0x1;

				for (unsigned int j = 0; j < 15; j++) {
					if (bitmask & mask) {
						switch (j) {
						case 0:
						case 2:
						case 13:
						case 14: {
							if (replay)
								PutULONG(idMap->mapToNewNonWindow(GetULONG(
										nextSrc, bigEndian_)), nextSrc,
										bigEndian_);
						}
							break;
						}
						nextSrc += 4;
					}
					mask <<= 1;
				}
				if (replay) {
					// 4-8, window id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					// 8-12, window id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
				}
				printMessage(buffer, size, 13, 1, 1, 2, 4, 4, 2, 2, 2, 2, 2, 2,
						4, 4);
			}
				break;
			case X_DeleteProperty: {
				if (replay) {
					// 4, src window
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					//atom
					PutULONG(idMap->atomMapToNew(GetULONG(buffer + 8,
							bigEndian_)), buffer+ 8, bigEndian_);
				}
				printMessage(buffer, size, 5, 1, 1+MAGIC_SIZE, 2, 4, 4);
			}
				break;
			case X_FillPoly: {
				unsigned int numPoints = ((size - 16) >> 2);

				encodeBuffer.encodeCachedValue(numPoints, 14, clientCache_.
				fillPolyNumPointsCache, 4);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.drawableCache, 9);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
						clientCache_.gcCache, 9);
				encodeBuffer.encodeValue((unsigned int) buffer[12], 2);
				encodeBuffer.encodeValue((unsigned int) buffer[13], 1);
				int relativeCoordMode = (buffer[13] != 0);
				const unsigned char *nextSrc = buffer + 16;
				unsigned int pointIndex = 0;

				for (unsigned int i = 0; i < numPoints; i++) {
					if (relativeCoordMode) {
						encodeBuffer.encodeCachedValue(GetUINT(nextSrc,
								bigEndian_), 16, *clientCache_.
						fillPolyXRelCache
						[pointIndex], 8);
						nextSrc += 2;
						encodeBuffer.encodeCachedValue(GetUINT(nextSrc,
								bigEndian_), 16, *clientCache_.
						fillPolyYRelCache
						[pointIndex], 8);
						nextSrc += 2;
					} else {
						unsigned int x = GetUINT(nextSrc, bigEndian_);

						nextSrc += 2;
						unsigned int y = GetUINT(nextSrc, bigEndian_);

						nextSrc += 2;
						unsigned int j;

						for (j = 0; j < 8; j++)
							if ((x == clientCache_.fillPolyRecentX[j]) && (y
									== clientCache_.fillPolyRecentY[j]))
								break;
						if (j < 8) {
							encodeBuffer.encodeValue(1, 1);
							encodeBuffer.encodeValue(j, 3);
						} else {
							encodeBuffer.encodeValue(0, 1);
							encodeBuffer.encodeCachedValue(x, 16,
									*clientCache_.
									fillPolyXAbsCache
									[pointIndex], 8);
							encodeBuffer.encodeCachedValue(y, 16,
									*clientCache_.
									fillPolyYAbsCache
									[pointIndex], 8);
							clientCache_.fillPolyRecentX[clientCache_.
							fillPolyIndex] = x;
							clientCache_.fillPolyRecentY[clientCache_.
							fillPolyIndex] = y;
							clientCache_.fillPolyIndex++;
							if (clientCache_.fillPolyIndex == 8)
								clientCache_.fillPolyIndex = 0;
						}
					}
					if (pointIndex + 1 < FILL_POLY_MAX_POINTS)
						pointIndex++;
				}
				printMessage(buffer, size, 8, 1, 1+MAGIC_SIZE, 2, 4, 4, 1, 1, 2
						+MAGIC_SIZE);
			}
				break;
			case X_FreeColors: {
				unsigned int numPixels = GetUINT(buffer + 2, bigEndian_) - 3;
				encodeBuffer.encodeValue(numPixels, 16, 4);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.colormapCache, 9);
				encodeBuffer.encodeValue(GetULONG(buffer + 8, bigEndian_), 32,
						4);
				const unsigned char *nextSrc = buffer + 12;

				while (numPixels) {
					encodeBuffer.
					encodeValue(GetULONG(nextSrc, bigEndian_), 32, 8);
					nextSrc += 4;
					numPixels--;
				}
				printMessage(buffer, size, 5, 1, 1+MAGIC_SIZE, 2, 4, 4);
			}
				break;
			case X_FreeCursor: {
				if (replay) {
					// 4- 8, window id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
				}
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_FreeGC: {
				if (replay) {
					// 4- 8, gc id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
				}
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_FreePixmap: {
				unsigned int pixmap = GetULONG(buffer + 4, bigEndian_);
				unsigned int diff = pixmap
						- clientCache_.createPixmapLastPixmap;
				if (diff == 0)
					encodeBuffer.encodeValue(1, 1);
				else {
					encodeBuffer.encodeValue(0, 1);
					clientCache_.createPixmapLastPixmap = pixmap;
					encodeBuffer.encodeValue(diff, 29, 4);
				}
				if (replay) {
					// 4- 8, gc id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
				}
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_GetAtomName: {
				encodeBuffer.encodeValue(GetULONG(buffer + 4, bigEndian_), 29,
						9);
				if (replay)
					//atom
					PutULONG(idMap->atomMapToNew(GetULONG(buffer + 4,
							bigEndian_)), buffer+ 4, bigEndian_);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
				//cout<<"************GetAtomName***********"<<endl;
			}
				break;
			case X_GetGeometry: {

				//this could be buggy; as it may query on other windows
				if (replay) {
					PutULONG(idMap->mapToNewSpecial(GetULONG(buffer + 4,
							bigEndian_)), buffer + 4, bigEndian_);
				}
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_GetInputFocus:
			case X_GetModifierMapping: {
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 3, 1, 1+MAGIC_SIZE, 2);
			}
				break;
			case X_GetKeyboardMapping: {
				encodeBuffer.encodeValue((unsigned int) buffer[4], 8);
				encodeBuffer.encodeValue((unsigned int) buffer[5], 8);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 6, 1, 1+MAGIC_SIZE, 2, 1, 1, -1);
			}
				break;
			case X_GetProperty: {
				unsigned int window = GetULONG(buffer + 4, bigEndian_);
				unsigned int newWindow;
				int outOfRange = 0;
				if (replay) {
					if (idMap->checkRangeOld(window) == false) {
						// the new window may be not accessible at this time, as it is not from our application
						outOfRange = 1;
						if (window != idMap->getOldRootWindow()) {
							// we should send a dummy request to x server
							if (PRINT_DEBUG)
								cout <<"GetProperty before dummy modification"
										<<endl;
							printMessage(buffer, size, 8, 1, 1, 2, 4, 4, 4, 4,
									4);
							buffer[1] = 0;
							PutULONG(idMap->getNewRootWindow(), buffer+4,
									bigEndian_);
							PutULONG(23, buffer + 8, bigEndian_);
							PutULONG(31, buffer + 12, bigEndian_);
							PutULONG(0, buffer + 16, bigEndian_);
							PutULONG(0, buffer + 20, bigEndian_);
						} else {
							if (PRINT_DEBUG)
								cout <<"GetProperty on root window."<<endl;
							PutULONG(idMap->getNewRootWindow(), buffer+4,
									bigEndian_);
						}

					} else {
						newWindow = idMap->mapToNew(window);
						PutULONG(newWindow, buffer + 4, bigEndian_);
						//atom
						PutULONG(idMap->atomMapToNew(GetULONG(buffer + 8,
								bigEndian_)), buffer+ 8, bigEndian_);
						PutULONG(idMap->atomMapToNew(GetULONG(buffer + 12,
								bigEndian_)), buffer+ 12, bigEndian_);
					}
				} else {
					if (idMap->checkRangeOld(window) == false)
						outOfRange = 1;
				}
				if (outOfRange) {
					if (PRINT_DEBUG)
						cout <<" GetProperty: window is out of range."<<endl;
				}
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode, outOfRange);
				printMessage(buffer, size, 8, 1, 1, 2, 4, 4, 4, 4, 4);
			}
				break;
			case X_GetSelectionOwner: {
				if (replay)
					//atom
					PutULONG(idMap->atomMapToNew(GetULONG(buffer + 4,
							bigEndian_)), buffer+ 4, bigEndian_);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_GrabButton:
			case X_GrabPointer: {
				if (replay) {
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(
							idMap->mapToNew(GetULONG(buffer + 12, bigEndian_)),
							buffer + 12, bigEndian_);
					PutULONG(
							idMap->mapToNew(GetULONG(buffer + 16, bigEndian_)),
							buffer + 16, bigEndian_);
				}

				if (opcode == X_GrabButton) {
					printMessage(buffer, size, 12, 1, 1, 2, 4, 2, 1, 1, 4, 4,
							1, 1, 2);
				} else {
					//unsigned int timestamp = GetULONG(buffer + 20, bigEndian_);
					sequenceNumQueue_.push(clientCache_.
					lastRequestSequenceNum, opcode);
					if (replay) {
						// this could be buggy, set the time to be current time
						PutULONG(0, buffer + 20, bigEndian_);
					}
					printMessage(buffer, size, 10, 1, 1, 2, 4, 2, 1, 1, 4, 4, 4);
				}
			}
				break;
			case X_GrabKeyboard: {
				encodeBuffer.encodeValue((unsigned int) buffer[1], 1);
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.windowCache, 9);
				unsigned int timestamp = GetULONG(buffer + 8, bigEndian_);

				encodeBuffer.encodeValue(timestamp - clientCache_.
				grabKeyboardLastTimestamp, 32, 4);
				clientCache_.grabKeyboardLastTimestamp = timestamp;
				encodeBuffer.encodeValue((unsigned int) buffer[12], 1);
				encodeBuffer.encodeValue((unsigned int) buffer[13], 1);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 8, 1, 1, 2, 4, 4, 1, 1, -1);
			}
				break;
			case X_GrabServer:
			case X_UngrabServer:
			case X_NoOperation: {
				printMessage(buffer, size, 3, 1, 1+MAGIC_SIZE, 2);
			}
				break;
			case X_ImageText8: {
				unsigned int textLength = (unsigned int) buffer[1];

				encodeBuffer.encodeValue(textLength, 8);
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.drawableCache, 9);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
						clientCache_.gcCache, 9);
				unsigned int x = GetUINT(buffer + 12, bigEndian_);
				int xDiff = x - clientCache_.imageText8LastX;

				clientCache_.imageText8LastX = x;
				encodeBuffer.encodeCachedValue(xDiff, 16, clientCache_.
				imageText8CacheX, 8);
				unsigned int y = GetUINT(buffer + 14, bigEndian_);
				int yDiff = y - clientCache_.imageText8LastY;

				clientCache_.imageText8LastY = y;
				encodeBuffer.encodeCachedValue(yDiff, 16, clientCache_.
				imageText8CacheY, 8);
				const unsigned char *nextSrc = buffer + 16;

				clientCache_.imageText8TextCompressor.reset();
				for (unsigned int j = 0; j < textLength; j++)
					clientCache_.imageText8TextCompressor.
					encodeChar(*nextSrc++, encodeBuffer);
				printMessage(buffer, size, 9, 1, 1, 2, 4, 4, 2, 2, textLength,
						-1);
			}
				break;
			case X_InternAtom: {
				unsigned int nameLength = GetUINT(buffer + 4, bigEndian_);

				encodeBuffer.encodeValue(nameLength, 16, 6);
				encodeBuffer.encodeValue((unsigned int) buffer[1], 1);
				const unsigned char *nextSrc = buffer + 8;

				clientCache_.internAtomTextCompressor.reset();
				for (unsigned int i = 0; i < nameLength; i++)
					clientCache_.internAtomTextCompressor.
					encodeChar(*nextSrc++, encodeBuffer);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 7, 1, 1, 2, 2, 2+MAGIC_SIZE,
						nameLength, -1);
				if (PRINT_DEBUG) {
					cout <<"********InternAtom request********"<<endl;
					for (unsigned i = 0; i < nameLength; ++i)
						cout << (char) buffer[8+i];
					cout <<endl;
				}
			}
				break;
			case X_ListExtensions: {
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 3, 1, 1+MAGIC_SIZE, 2);
			}
				break;
			case X_ListFonts: {
				unsigned int textLength = GetUINT(buffer + 6, bigEndian_);

				encodeBuffer.encodeValue(textLength, 16, 6);
				encodeBuffer.encodeValue(GetUINT(buffer + 4, bigEndian_), 16, 6);
				const unsigned char *nextSrc = buffer + 8;

				clientCache_.polyText8TextCompressor.reset();
				for (unsigned int i = 0; i < textLength; i++)
					clientCache_.polyText8TextCompressor.
					encodeChar(*nextSrc++, encodeBuffer);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 7, 1, 1+MAGIC_SIZE, 2, 2, 2,
						textLength, -1);

			}
				break;
			case X_LookupColor:
			case X_AllocNamedColor: {
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				unsigned int textLength = GetUINT(buffer + 8, bigEndian_);

				encodeBuffer.encodeValue(textLength, 16, 6);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.colormapCache, 9);
				const unsigned char *nextSrc = buffer + 12;

				clientCache_.polyText8TextCompressor.reset();
				for (unsigned int i = 0; i < textLength; i++)
					clientCache_.polyText8TextCompressor.
					encodeChar(*nextSrc++, encodeBuffer);
				printMessage(buffer, size, 8, 1, 1+MAGIC_SIZE, 2, 4, 2, 2,
						textLength, -1);

			}
				break;
			case X_MapWindow:
			case X_UnmapWindow:
			case X_MapSubwindows:
			case X_GetWindowAttributes:
			case X_DestroyWindow:
			case X_DestroySubwindows: {
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.windowCache, 9);
				if (opcode == X_GetWindowAttributes) {
					sequenceNumQueue_.push(clientCache_.
					lastRequestSequenceNum, opcode);
				}

				if (replay) {
					// 4- 8, window id
					/*if (opcode == X_GetWindowAttributes)
					 PutULONG(idMap->mapToNewSpecial(GetULONG(buffer + 4,
					 bigEndian_)), buffer + 4, bigEndian_);
					 else*/
					PutULONG(idMap->mapToNewSpecial(GetULONG(buffer + 4,
							bigEndian_)), buffer + 4, bigEndian_);
				}
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_QueryTree: {
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.windowCache, 9);
				if (opcode == X_QueryTree) {
					sequenceNumQueue_.push(clientCache_.
					lastRequestSequenceNum, opcode);
				}

				if (replay) {
					// 4- 8, window id
					unsigned window = GetULONG(buffer + 4, bigEndian_);
					unsigned int newWindow;
					if (idMap->checkRangeOld(window) == false) {
						//The window may not exist any more
						if (PRINT_DEBUG) {
							if (window != idMap->getOldRootWindow())
								cout
										<<"QueryTree is modified to query on root window instead."
										<<endl;
							else
								cout <<"QueryTree queries on root window."
										<<endl;
						}
						PutULONG(idMap->getNewRootWindow(), buffer + 4,
								bigEndian_);
					} else {
						newWindow = idMap->mapToNew(window);
						PutULONG(newWindow, buffer + 4, bigEndian_);
					}
				}
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_QueryPointer: {
				unsigned int window = GetULONG(buffer + 4, bigEndian_);
				if (replay && window) {
					// 4- 8, window id
					PutULONG(idMap->mapToNewSpecial(window), buffer + 4,
							bigEndian_);
				}
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_OpenFont: {
				unsigned int nameLength = GetUINT(buffer + 8, bigEndian_);
				if (replay) {
					//font id , 4-8
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
				}
				printMessage(buffer, size, 8, 1, 1+MAGIC_SIZE, 2, 4, 2, 2
						+MAGIC_SIZE, nameLength, -1);
			}
				break;
			case X_PolyFillRectangle: {
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.drawableCache, 9);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
						clientCache_.gcCache, 9);
				unsigned int index = 0;
				unsigned int lastX = 0, lastY = 0;
				unsigned int lastWidth = 0, lastHeight = 0;

				for (unsigned int i = 12; i < size;) {
					unsigned int x = GetUINT(buffer + i, bigEndian_);
					unsigned int newX = x;

					x -= lastX;
					lastX = newX;
					encodeBuffer.encodeCachedValue(x, 16, *clientCache_.
					polyFillRectangleCacheX
					[index], 8);
					i += 2;
					unsigned int y = GetUINT(buffer + i, bigEndian_);
					unsigned int newY = y;

					y -= lastY;
					lastY = newY;
					encodeBuffer.encodeCachedValue(y, 16, *clientCache_.
					polyFillRectangleCacheY
					[index], 8);
					i += 2;
					unsigned int width = GetUINT(buffer + i, bigEndian_);
					unsigned int newWidth = width;

					width -= lastWidth;
					lastWidth = newWidth;
					encodeBuffer.encodeCachedValue(width, 16, *clientCache_.
					polyFillRectangleCacheWidth
					[index], 8);
					i += 2;
					unsigned int height = GetUINT(buffer + i, bigEndian_);
					unsigned int newHeight = height;

					height -= lastHeight;
					lastHeight = newHeight;
					encodeBuffer.encodeCachedValue(height, 16, *clientCache_.
					polyFillRectangleCacheHeight
					[index], 8);
					i += 2;
					index = 1;

					encodeBuffer.encodeValue(((i < size) ? 1 : 0), 1);
				}
				if (replay) {
					// 4- 8, drawable id, 8-12 gc id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
				}
				printMessage(buffer, size, 5, 1, 1+MAGIC_SIZE, 2, 4, 4);
			}
				break;
			case X_PolyPoint: {
				encodeBuffer.encodeValue(GetUINT(buffer + 2, bigEndian_) - 3,
						16, 4);
				encodeBuffer.encodeValue((unsigned int) buffer[1], 1);
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.drawableCache, 9);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
						clientCache_.gcCache, 9);
				const unsigned char *nextSrc = buffer + 12;
				unsigned int index = 0;
				unsigned int lastX = 0, lastY = 0;

				for (unsigned int i = 12; i < size; i += 4) {
					unsigned int x = GetUINT(nextSrc, bigEndian_);

					nextSrc += 2;
					unsigned int tmp = x;

					x -= lastX;
					lastX = tmp;
					encodeBuffer.encodeCachedValue(x, 16, *clientCache_.
					polyPointCacheX[index], 8);
					unsigned int y = GetUINT(nextSrc, bigEndian_);

					nextSrc += 2;
					tmp = y;
					y -= lastY;
					lastY = tmp;
					encodeBuffer.encodeCachedValue(y, 16, *clientCache_.
					polyPointCacheY[index], 8);
					index = 1;
				}
				printMessage(buffer, size, 5, 1, 1, 2, 4, 4);
			}
				break;
			case X_PolyLine: {
				encodeBuffer.encodeValue(GetUINT(buffer + 2, bigEndian_) - 3,
						16, 4);
				encodeBuffer.encodeValue((unsigned int) buffer[1], 1);
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.drawableCache, 9);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
						clientCache_.gcCache, 9);
				const unsigned char *nextSrc = buffer + 12;
				unsigned int index = 0;
				unsigned int lastX = 0, lastY = 0;

				for (unsigned int i = 12; i < size; i += 4) {
					unsigned int x = GetUINT(nextSrc, bigEndian_);

					nextSrc += 2;
					unsigned int tmp = x;

					x -= lastX;
					lastX = tmp;
					encodeBuffer.encodeCachedValue(x, 16, *clientCache_.
					polyLineCacheX[index], 8);
					unsigned int y = GetUINT(nextSrc, bigEndian_);

					nextSrc += 2;
					tmp = y;
					y -= lastY;
					lastY = tmp;
					encodeBuffer.encodeCachedValue(y, 16, *clientCache_.
					polyLineCacheY[index], 8);
					index = 1;
				}

				printMessage(buffer, size, 5, 1, 1, 2, 4, 4);
			}
				break;
			case X_PolyRectangle: {
				if (replay) {
					// 4- 8, drawable id, 8-12 gc id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
				}
				printMessage(buffer, size, 5, 1, 1, 2, 4, 4);
			}
				break;
			case X_PolySegment: {
				if (replay) {
					// 4- 8, drawable id, 8-12 gc id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
				}
				printMessage(buffer, size, 5, 1, 1, 2, 4, 4);
			}
				break;
			case X_PolyText8: {
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.drawableCache, 9);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
						clientCache_.gcCache, 9);
				unsigned int x = GetUINT(buffer + 12, bigEndian_);
				int xDiff = x - clientCache_.polyText8LastX;

				clientCache_.polyText8LastX = x;
				encodeBuffer.encodeCachedValue(xDiff, 16, clientCache_.
				polyText8CacheX, 8);
				unsigned int y = GetUINT(buffer + 14, bigEndian_);
				int yDiff = y - clientCache_.polyText8LastY;

				clientCache_.polyText8LastY = y;
				encodeBuffer.encodeCachedValue(yDiff, 16, clientCache_.
				polyText8CacheY, 8);
				const unsigned char *end = buffer + size - 1;
				const unsigned char *nextSrc = buffer + 16;

				while (nextSrc < end) {
					unsigned int textLength = (unsigned int) *nextSrc++;

					encodeBuffer.encodeValue(1, 1);
					encodeBuffer.encodeValue(textLength, 8);
					if (textLength == 255) {
						encodeBuffer.
						encodeCachedValue(GetULONG(nextSrc, 1), 29,
								clientCache_.
								polyText8FontCache);
						nextSrc += 4;
					} else {
						encodeBuffer.encodeCachedValue(*nextSrc++, 8,
								clientCache_.
								polyText8DeltaCache);
						clientCache_.polyText8TextCompressor.reset();
						//cout <<"text is: "<<endl;
						for (unsigned int i = 0; i < textLength; i++) {
							//cerr <<*nextSrc;
							clientCache_.polyText8TextCompressor.
							encodeChar(*nextSrc++, encodeBuffer);
						}
						//cerr <<endl;
					}
				}
				encodeBuffer.encodeValue(0, 1);
				if (replay) {
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
				}
				printMessage(buffer, size, 7, 1, 1+MAGIC_SIZE, 2, 4, 4, 2, 2);

			}
				break;
			case X_PutImage: {
				if (replay) {
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
				}
				printMessage(buffer, size, 12, 1, 1, 2, 4, 4, 2, 2, 2, 2, 1, 1,
						2+MAGIC_SIZE);
			}
				break;
			case X_QueryBestSize: {
				encodeBuffer.encodeValue((unsigned int) buffer[1], 2);
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.drawableCache, 9);
				encodeBuffer.encodeValue(GetUINT(buffer + 8, bigEndian_), 16, 8);
				encodeBuffer.encodeValue(GetUINT(buffer + 10, bigEndian_), 16,
						8);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 6, 1, 1, 2, 4, 2, 2);
			}
				break;
			case X_QueryColors: {
				unsigned int colormap = GetULONG(buffer + 4, bigEndian_);
				int outOfRange = 0;
				if (replay) {
					if (idMap->checkRangeOld(colormap) == false) {
						//see GetProperty for reference
						//this could be buggy as the id for the root colormap can be different; safe for now
						outOfRange = 1;
					} else {
						unsigned int newColormap = idMap->mapToNew(colormap);
						PutULONG(newColormap, buffer + 4, bigEndian_);
					}
				} else {
					if (idMap->checkRangeOld(colormap) == false)
						outOfRange = 1;
				}
				if (outOfRange) {
					if (PRINT_DEBUG)
						cout <<"QueryColors queries on outside colormap."<<endl;
				}

				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode, outOfRange);
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_QueryExtension: {
				unsigned int nameLength = GetUINT(buffer + 4, bigEndian_);
				printMessage(buffer, size, 7, 1, 1+MAGIC_SIZE, 2, 2, 2
						+MAGIC_SIZE, nameLength, -1);

				encodeBuffer.encodeValue(nameLength, 16, 6);
				const unsigned char *nextSrc = buffer + 8;

				for (; nameLength; nameLength--)
					encodeBuffer.encodeValue((unsigned int) *nextSrc++, 8);
				int hideExtension = 0;
				if (!strncmp((char *) buffer + 8, "MIT-SHM", 7)) {
					if (PRINT_DEBUG)
						cout << "hiding MIT-SHM!"<<endl;
					hideExtension = 1;
				}
				if (!strncmp((char*) buffer + 8, "RANDR", 5)) {
					if (PRINT_DEBUG)
						cout << "hiding xrandr!"<<endl;
					hideExtension = 1;
				}

				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode, hideExtension);
			}
				break;
			case X_QueryFont: {
				if (replay) {
					// font id, 4-8
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
				}
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_SetClipRectangles: {
				if (replay) {
					// 4, gc id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
				}
				printMessage(buffer, size, 6, 1, 1, 2, 4, 2, 2);
			}
				break;
			case X_SetDashes: {
				unsigned int numDashes = GetUINT(buffer + 10, bigEndian_);

				encodeBuffer.encodeCachedValue(numDashes, 16, clientCache_.
				setDashesLengthCache, 5);
				encodeBuffer.
				encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.gcCache, 9);
				encodeBuffer.
				encodeCachedValue(GetUINT(buffer + 8, bigEndian_), 16,
						clientCache_.setDashesOffsetCache, 5);
				const unsigned char *nextSrc = buffer + 12;

				for (unsigned int i = 0; i < numDashes; i++)
					encodeBuffer.encodeCachedValue(*nextSrc++, 8, clientCache_.
					setDashesDashCache_[i &
					1], 5);
				printMessage(buffer, size, 6, 1, 1+MAGIC_SIZE, 2, 4, 2, 2);
			}
				break;
			case X_SetSelectionOwner: {
				if (replay) {
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					//atom
					PutULONG(idMap->atomMapToNew(GetULONG(buffer + 8,
							bigEndian_)), buffer+ 8, bigEndian_);
					// this could be buggy, config-timestamp
					PutULONG(0, buffer + 12, bigEndian_);
				}
				printMessage(buffer, size, 6, 1, 1+MAGIC_SIZE, 2, 4, 4, 4);

			}
				break;
			case X_TranslateCoords: {
				if (replay) {
					// 4, src window; 8 dst window
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
				}
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
				printMessage(buffer, size, 7, 1, 1+MAGIC_SIZE, 2, 4, 4, 2, 2);
			}
				break;
				//starting point for additional request support, already compressed
			case X_CreateColormap: {
				if (replay) {
					// 4, colormap; 8 window
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
				}
				printMessage(buffer, size, 6, 1, 1, 2, 4, 4, 4);
			}
				break;
			case X_FreeColormap: {
				encodeBuffer.encodeCachedValue(
						GetULONG(buffer + 4, bigEndian_), 29,
						clientCache_.colormapCache, 9);
				printMessage(buffer, size, 4, 1, 1+MAGIC_SIZE, 2, 4);
			}
				break;
			case X_SetInputFocus: {
				if (replay) {
					// 4, colormap; 8 window
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					//this could be buggy with the timestamp
					PutULONG(0, buffer + 8, bigEndian_);
				}
				printMessage(buffer, size, 5, 1, 1, 2, 4, 4);

			}
				break;
			case X_ListFontsWithInfo: {
				printMessage(buffer, size, 3, 1, 1, 2);
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode);
			}
				break;
			case X_PolyFillArc: {
				if (replay) {
					// drawable id, 4-8; gc id 8-12
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
				}
				printMessage(buffer, size, 5, 1, 1+MAGIC_SIZE, 2, 4, 4);
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode);
			}
				break;
			case X_SendEvent: {
				if (replay)
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);

				switch (buffer[12]) {
				case ClientMessage: {
					if (replay) {
						PutULONG(idMap->mapToNew(GetULONG(buffer + 16,
								bigEndian_)), buffer + 16, bigEndian_);
						//atom 
						PutULONG(idMap->atomMapToNew(GetULONG(buffer + 20,
								bigEndian_)), buffer + 20, bigEndian_);
					}
				}
					break;
				case UnmapNotify: {
					if (replay) {
						// drawable id, 4-8; gc id 8-12
						PutULONG(idMap->mapToNew(GetULONG(buffer + 16,
								bigEndian_)), buffer + 16, bigEndian_);
						PutULONG(idMap->mapToNew(GetULONG(buffer + 20,
								bigEndian_)), buffer + 20, bigEndian_);
					}
				}
					break;
				default: {
					if (PRINT_DEBUG)
						cout <<"          *** not compressed"<<endl;
				}
				}
				printMessage(buffer, size, 6, 1, 1, 2, 4, 4, 32);
				if (PRINT_DEBUG)
					cout <<" event included in sendEvent request: opcode:"
							<<(unsigned int)buffer[12]<<endl;
			}
				break;
			case X_GetImage: {
				printMessage(buffer, size, 9, 1, 1, 2, 4, 2, 2, 2, 2, 4);
				if (replay) {
					// drawable id, 4-8
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
				}
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode);
			}
				break;
			case X_ReparentWindow: {
				if (replay) {
					//window id
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
				}
				printMessage(buffer, size, 7, 1, 1, 2, 4, 4, 2, 2);
			}
				break;
			case X_CreateCursor: {
				if (replay) {
					PutULONG(idMap->mapToNew(GetULONG(buffer + 4, bigEndian_)),
							buffer + 4, bigEndian_);
					PutULONG(idMap->mapToNew(GetULONG(buffer + 8, bigEndian_)),
							buffer + 8, bigEndian_);
					PutULONG(
							idMap->mapToNew(GetULONG(buffer + 12, bigEndian_)),
							buffer + 12, bigEndian_);

				}
				printMessage(buffer, size, 14, 1, 1, 2, 4, 4, 4, 2, 2, 2, 2, 2,
						2, 2, 2);
			}
				break;
			case X_UngrabPointer: {
				if (replay) {
					// this could be buggy
					PutULONG(0, buffer + 4, bigEndian_);
				}
				printMessage(buffer, size, 4, 1, 1, 2, 4);
			}
				break;
				// starting point for x extensions parsing
				//compressed
			case XE_BIG_REQUESTS: {
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
				//starting point for addtional message support
				//request not compressed yet

			case XE_Composite:
			case XE_DAMAGE:
			case XE_XINERAMA:
			case XE_DRI2:
			case XE_SGI_GLX: {
				if (PRINT_DEBUG)
					cout <<"          *** not compressed"<<endl;
				printMessage(buffer, size, 3, 1, 1, 2);
				encodeBuffer.encodeValue((unsigned int) buffer[1], 8);
				encodeBuffer.encodeValue(GetUINT(buffer + 2, bigEndian_), 16, 8);
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode);
				const unsigned char *nextSrc = buffer + 4;

				for (unsigned int i = 4; i < size; i++)
					encodeBuffer.encodeValue((unsigned int) *nextSrc++, 8);
			}
				break;
				//extension requests parsed in details
			case XE_SYNC: {
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode, (unsigned int) buffer[1]);
				switch (buffer[1]) {
				case X_SyncInitialize: {
					//do nothing
				}
					break;
				case X_SyncCreateCounter:
				case X_SyncDestroyCounter: {
					if (replay)
						//windows id 
						PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
								bigEndian_)), buffer + 4, bigEndian_);
				}
					break;
				default: {
					if (PRINT_DEBUG)
						cout <<"          *** not compressed"<<endl;
				}
				}
				printMessage(buffer, size, 3, 1, 1, 2);
			}
				break;
			case XE_XFIXES: {
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode, (unsigned int) buffer[1]);
				switch (buffer[1]) {
				case X_XFixesQueryVersion: {
					//do nothing
				}
					break;
				case X_XFixesSelectSelectionInput: {
					if (replay) {
						//windows id ; containing atom
						PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
								bigEndian_)), buffer + 4, bigEndian_);
						PutULONG(idMap->atomMapToNew(GetULONG(buffer + 8,
								bigEndian_)), buffer + 8, bigEndian_);
					}
				}
					break;
				case X_XFixesSetCursorName: {
					if (replay) {
						//windows id 
						PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
								bigEndian_)), buffer + 4, bigEndian_);
					}
				}
					break;
				default: {
					if (PRINT_DEBUG)
						cout <<"          *** not compressed"<<endl;
				}
				}
				printMessage(buffer, size, 3, 1, 1, 2);
			}
				break;
			case XE_MIT_SHM: {
				switch (buffer[1]) {
				case X_ShmQueryVersion: {
					//nothing
				}
					break;
				case X_ShmAttach: {
					if (replay)
						//shmseg id
						PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
								bigEndian_)), buffer + 4, bigEndian_);
				}
					break;
				default: {
					if (PRINT_DEBUG)
						cout <<"          *** not compressed"<<endl;
				}
				}
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode, (unsigned int) buffer[1]);
				printMessage(buffer, size, 3, 1, 1, 2);
			}
				break;
			case XE_XKEYBOARD: {
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode, (unsigned int) buffer[1]);
				switch (buffer[1]) {
				case X_kbUseExtension:
				case X_kbSelectEvents:
				case X_kbGetMap:
				case X_kbGetNames:
				case X_kbPerClientFlags: {
					//do nothing
				}
					break;
				default: {
					if (PRINT_DEBUG)
						cout <<"          *** not compressed"<<endl;
				}
				}
				printMessage(buffer, size, 3, 1, 1, 2);
			}
				break;
			case XE_XInputExtension: {
				switch (buffer[1]) {
				case X_GetExtensionVersion:
				case X_ListInputDevices:
				case X_OpenDevice: {
					//do nothing
				}
					break;
				case X_SelectExtensionEvent: {
					if (replay)
						//windows id 
						PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
								bigEndian_)), buffer + 4, bigEndian_);

				}
					break;
				default: {
					if (PRINT_DEBUG)
						cout <<"          *** not compressed"<<endl;
				}
				}
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode, (unsigned int) buffer[1]);

				printMessage(buffer, size, 3, 1, 1, 2);

			}
				break;
			case XE_SHAPE: {
				switch (buffer[1]) {
				case X_ShapeQueryVersion: {
					//do nothing
				}
					break;
				case X_ShapeMask: {
					if (replay) {
						// window id, 8; pixmap, 16 
						PutULONG(idMap->mapToNew(GetULONG(buffer + 8,
								bigEndian_)), buffer + 8, bigEndian_);
						PutULONG(idMap->mapToNew(GetULONG(buffer + 16,
								bigEndian_)), buffer + 16, bigEndian_);
					}
				}
					break;
				default: {
					if (PRINT_DEBUG)
						cout <<"          *** not compressed"<<endl;
				}
				}
				printMessage(buffer, size, 3, 1, 1, 2);
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode, (unsigned int) buffer[1]);
			}
				break;
			case XE_EVENT_EXTENSION: {
				printMessage(buffer, size, 6, 1, 1, 2, 2, 2, -1);
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode);
			}
				break;
			case XE_RANDR: {
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode, (unsigned int) (buffer[1]));
				switch (buffer[1]) {
				case X_RRQueryVersion: {
					//do nothing

				}
					break;
				case X_RRSelectInput:
				case X_RRGetScreenSizeRange:
				case X_RRListOutputProperties:
				case X_RRDestroyMode:
				case X_RRGetScreenResourcesCurrent:
				case X_RRGetOutputPrimary: {
					if (replay) {
						// window id, 4-8
						PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
								bigEndian_)), buffer + 4, bigEndian_);
					}
				}
					break;
					/*case X_RRGetScreenInfo: {
					 if (replay) {
					 // window id, 4-8
					 PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
					 bigEndian_)), buffer + 4, bigEndian_);
					 }
					 printMessage(buffer, size, 3, 1, 1, 2);
					 sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
					 opcode);
					 }
					 break;*/

				case X_RRGetOutputInfo:
				case X_RRGetCrtcInfo: {
					if (replay) {
						// window id, 4-8
						PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
								bigEndian_)), buffer + 4, bigEndian_);
						//not sure about timestamp in this request
					}
				}
					break;
				default: {
					if (PRINT_DEBUG)
						cout <<"          *** not compressed"<<endl;
				}
				}
				printMessage(buffer, size, 3, 1, 1, 2);

			}
				break;
			case XE_RENDER: {
				switch (buffer[1]) {
				case X_RenderQueryVersion:
				case X_RenderQueryPictFormats: {
					sequenceNumQueue_.push(clientCache_.
					lastRequestSequenceNum, opcode, (unsigned int) buffer[1]);
				}
					break;
				case X_RenderCreatePicture:
				case X_RenderCreateCursor: {
					if (replay) {
						//4 picture pid; 8 drawable; 12 is for format, don't change
						PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
								bigEndian_)), buffer + 4, bigEndian_);
						PutULONG(idMap->mapToNew(GetULONG(buffer + 8,
								bigEndian_)), buffer + 8, bigEndian_);
					}
				}
					break;
				case X_RenderCreateGlyphSet:
				case X_RenderFreeGlyphSet:
				case X_RenderAddGlyphs: {
					if (replay) {
						//4 gsid
						PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
								bigEndian_)), buffer + 4, bigEndian_);
					}
				}
					break;
				case X_RenderFillRectangles: {
					if (replay) {
						//8 picture pid; not fully sure about this
						PutULONG(idMap->mapToNew(GetULONG(buffer + 8,
								bigEndian_)), buffer + 8, bigEndian_);
					}
				}
					break;

				case X_RenderTrapezoids: {
					if (replay) {
						//8 picture pid, 12 picture; not sure about this format as the protocol specification is not clear
						PutULONG(idMap->mapToNew(GetULONG(buffer + 8,
								bigEndian_)), buffer + 8, bigEndian_);
						PutULONG(idMap->mapToNew(GetULONG(buffer + 12,
								bigEndian_)), buffer + 12, bigEndian_);
					}
				}
					break;
				case X_RenderComposite: {
					if (replay) {
						//8 picture pid, 12 picture; 16 picture
						PutULONG(idMap->mapToNew(GetULONG(buffer + 8,
								bigEndian_)), buffer + 8, bigEndian_);
						PutULONG(idMap->mapToNew(GetULONG(buffer + 12,
								bigEndian_)), buffer + 12, bigEndian_);
						PutULONG(idMap->mapToNew(GetULONG(buffer + 16,
								bigEndian_)), buffer + 16, bigEndian_);
					}
				}
					break;
				case X_RenderCompositeGlyphs8:
				case X_RenderCompositeGlyphs16:
				case X_RenderCompositeGlyphs32: {
					if (replay) {
						//8:picutre id; 12: picture id; 16 don't change; 20 gsid
						PutULONG(idMap->mapToNew(GetULONG(buffer + 8,
								bigEndian_)), buffer + 8, bigEndian_);
						PutULONG(idMap->mapToNew(GetULONG(buffer + 12,
								bigEndian_)), buffer + 12, bigEndian_);
						PutULONG(idMap->mapToNew(GetULONG(buffer + 20,
								bigEndian_)), buffer + 20, bigEndian_);
					}
				}
					break;
				case X_RenderSetPictureClipRectangles:
				case X_RenderCreateSolidFill:
				case X_RenderFreePicture:
				case X_RenderSetPictureFilter:
				case X_RenderSetPictureTransform:
				case X_RenderChangePicture: {
					if (replay) {
						//4 picture pid
						PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
								bigEndian_)), buffer + 4, bigEndian_);
					}
				}
					break;
				case X_RenderCreateAnimCursor: {
					if (replay) {
						//4 picture pid
						PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
								bigEndian_)), buffer + 4, bigEndian_);
						for (unsigned int i = 8; i < size; i += 8) {
							PutULONG(idMap->mapToNew(GetULONG(buffer + i,
									bigEndian_)), buffer + i, bigEndian_);
						}
					}
				}
					break;
				default: {
					if (PRINT_DEBUG)
						cout <<"          *** not compressed"<<endl;
					sequenceNumQueue_.push(clientCache_.
					lastRequestSequenceNum, opcode, (unsigned int) buffer[1]);
				}
					break;
				}
				printMessage(buffer, size, 3, 1, 1, 2);
			}
				break;
			default: {
				cout
						<<"         other non-recognized request --- not compressed (error message)"
						<<endl;
				if (!PRINT_DEBUG) printString (buffer, size);
				encodeBuffer.encodeValue((unsigned int) buffer[1], 8);
				encodeBuffer.encodeValue(GetUINT(buffer + 2, bigEndian_), 16, 8);
				const unsigned char *nextSrc = buffer + 4;

				for (unsigned int i = 4; i < size; i++)
					encodeBuffer.encodeValue((unsigned int) *nextSrc++, 8);
			}

			} // end switch

			stats_.add(*buffer, size << 3,
					encodeBuffer.getCumulativeBitsWritten());
		}

		// end non-initial request

		if (!convert_log) {
			//no matter whether we are replaying or not, send the messages from applications directly to x server
			// note: replayBuffer is only for debugging, never send it to x server!
			if ((unsigned int) SOCKWRITE (serverFD, buffer, size) != size)
				cerr << "Cannot write to x server."<<endl;
			if (replay) {
#ifdef FILE_REPLAY
				getNextRequest();
#endif
				// we may need to replay several event messages in a row
				while (eventQueue_.getEventPos() == *outputLength_) {
					if (eventQueue_.getEventBuffer()[0] == 1)
						break;
					if (PRINT_DEBUG)
						cout
								<<"Different: Insert event message from our log, opcode:"
								<<(unsigned int) eventQueue_.getEventBuffer()[0]<<endl;
					if (PRINT_DEBUG)
						printString(eventQueue_.getEventBuffer(), 32);
#ifndef FILE_REPLAY
					if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getEventBuffer(), 32) != 32)
						cerr << "Cannot write to application."<<endl;
#endif
					eventQueue_.replayEvent();
					//					*outputLength_ += 32;
					*outputLength_ += 1;
				}

			}
		} else {
			return 2;
		}

	}
	return 1;
}

int ClientChannel::doWrite(const unsigned char *message, unsigned int length,
		SequenceNumQueue & sequenceNumQueue_) {
	writeBuffer_.reset();

	// uncompress messages
	DecodeBuffer decodeBuffer(message, length);

	if (firstReply_) {
		unsigned int opcode;

		decodeBuffer.decodeValue(opcode, 8);
		unsigned int secondByte;

		decodeBuffer.decodeValue(secondByte, 8);
		unsigned int major;

		decodeBuffer.decodeValue(major, 16);
		unsigned int minor;

		decodeBuffer.decodeValue(minor, 16);
		unsigned int extraLength;

		decodeBuffer.decodeValue(extraLength, 16);
		unsigned int outputLength = 8 + (extraLength << 2);
		unsigned char *outputMessage = writeBuffer_.addMessage(outputLength);

		*outputMessage = (unsigned char) opcode;
		outputMessage[1] = (unsigned char) secondByte;
		PutUINT(major, outputMessage + 2, bigEndian_);
		PutUINT(minor, outputMessage + 4, bigEndian_);
		PutUINT(extraLength, outputMessage + 6, bigEndian_);
		unsigned char *nextDest = outputMessage + 8;
		unsigned int cached;

		decodeBuffer.decodeValue(cached, 1);
		if (cached)
			memcpy(nextDest, ServerCache::lastInitReply.getData(), outputLength
					- 8);
		else {
			for (unsigned i = 8; i < outputLength; i++) {
				unsigned int nextByte;

				decodeBuffer.decodeValue(nextByte, 8);
				*nextDest++ = (unsigned char) nextByte;
				cout <<"i:"<<i<<endl;
			}
			ServerCache::lastInitReply.set(outputLength - 8, outputMessage + 8);
		}
		imageByteOrder_ = outputMessage[30];
		bitmapBitOrder_ = outputMessage[31];
		scanlineUnit_ = outputMessage[32];
		scanlinePad_ = outputMessage[33];
		firstReply_ = 0;
	} else {
		unsigned char opcode;

		while (decodeBuffer.decodeCachedValue(opcode, 8, serverCache_.
		opcodeCache[serverCache_.
		lastOpcode], 8, 1)) {
			serverCache_.lastOpcode = opcode;

			unsigned char *outputMessage= NULL;
			unsigned int outputLength = 0;
			unsigned int value; // general-purpose temp variable for decoding ints

			unsigned char cValue; // general-purpose temp variable for decoding chars

			if (opcode == 1) {
				// reply
				unsigned int sequenceNumDiff;

				decodeBuffer.decodeCachedValue(sequenceNumDiff, 16,
						serverCache_.
						replySequenceNumCache, 7);
				unsigned int sequenceNum = serverCache_.lastSequenceNum
						+ sequenceNumDiff;
				sequenceNum &= 0xffff;
				serverCache_.lastSequenceNum = sequenceNum;
				unsigned short int nextSequenceNum;
				unsigned char nextOpcode;
				//the same with kernel
				if (sequenceNumQueue_.peek(nextSequenceNum, nextOpcode)) {
					while (sequenceNum> nextSequenceNum) {
						if (sequenceNumQueue_.pop(nextSequenceNum, nextOpcode)
								== 0) {
							cout
									<< "consume all sequence numbers??????????????????"
									<<endl;
							break;
						}
						sequenceNumQueue_.peek(nextSequenceNum, nextOpcode);
					}
				}

				if (sequenceNumQueue_.peek(nextSequenceNum, nextOpcode)
						&& (nextSequenceNum == sequenceNum)) {
					unsigned int requestData[3];
					//cout<<"decoding seq:"<<nextSequenceNum<<" opcode:"<<(unsigned int)nextOpcode<<endl;

					sequenceNumQueue_.pop(nextSequenceNum, nextOpcode,
							requestData[0], requestData[1], requestData[2]);
					switch (nextOpcode) {
					case X_AllocColor: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						unsigned char *nextDest = outputMessage + 8;

						for (unsigned int i = 0; i < 3; i++) {
							decodeBuffer.decodeValue(value, 1);
							if (value)
								PutUINT(requestData[i], nextDest, bigEndian_);
							else {
								decodeBuffer.decodeValue(value, 16, 6);
								PutUINT(requestData[i] + value, nextDest,
										bigEndian_);
							}
							nextDest += 2;
						}
						decodeBuffer.decodeValue(value, 32, 9);
						PutULONG(value, outputMessage + 16, bigEndian_);
					}
						break;
					case X_GetAtomName: {
						unsigned int nameLength;

						decodeBuffer.decodeValue(nameLength, 16, 6);
						outputLength = RoundUp4(nameLength) + 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						PutUINT(nameLength, outputMessage + 8, bigEndian_);
						unsigned char *nextDest = outputMessage + 32;

						clientCache_.internAtomTextCompressor.reset();
						for (unsigned int i = 0; i < nameLength; i++) {
							*nextDest++
									= clientCache_.internAtomTextCompressor.
									decodeChar(decodeBuffer);
						}
					}
						break;
					case X_GetGeometry: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						decodeBuffer.decodeCachedValue(cValue, 8, serverCache_.
						depthCache);
						outputMessage[1] = cValue;
						decodeBuffer.decodeCachedValue(value, 29, serverCache_.
						getGeometryRootCache, 9);
						PutULONG(value, outputMessage + 8, bigEndian_);
						unsigned char *nextDest = outputMessage + 12;

						for (unsigned int i = 0; i < 5; i++) {
							decodeBuffer.decodeCachedValue(value, 16,
									*serverCache_.
									getGeometryGeomCache
									[i], 8);
							PutUINT(value, nextDest, bigEndian_);
							nextDest += 2;
						}
					}
						break;
					case X_GetInputFocus: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						decodeBuffer.decodeValue(value, 2);
						outputMessage[1] = (unsigned char) value;
						decodeBuffer.decodeCachedValue(value, 29, serverCache_.
						getInputFocusWindowCache, 9);
						PutULONG(value, outputMessage + 8, bigEndian_);
					}
						break;
					case X_GetKeyboardMapping: {
						decodeBuffer.decodeValue(value, 1);
						if (value) {
							unsigned int dataLength =
									ServerCache::getKeyboardMappingLastMap.
									getLength();
							outputLength = 32 + dataLength;
							outputMessage
									= writeBuffer_.addMessage(outputLength);
							outputMessage[1]
									= ServerCache::getKeyboardMappingLastKeysymsPerKeycode;
							memcpy(outputMessage + 32,
									ServerCache::getKeyboardMappingLastMap.
									getData(), dataLength);
							break;
						}
						unsigned int numKeycodes;

						decodeBuffer.decodeValue(numKeycodes, 8);
						unsigned int keysymsPerKeycode;

						decodeBuffer.decodeValue(keysymsPerKeycode, 8, 4);
						ServerCache::getKeyboardMappingLastKeysymsPerKeycode
								= keysymsPerKeycode;
						outputLength = 32 + numKeycodes * keysymsPerKeycode * 4;
						outputMessage = writeBuffer_.addMessage(outputLength);
						outputMessage[1] = (unsigned char) keysymsPerKeycode;
						unsigned char *nextDest = outputMessage + 32;
						unsigned char previous = 0;

						for (unsigned int count = numKeycodes
								* keysymsPerKeycode; count; --count) {
							decodeBuffer.decodeValue(value, 1);
							if (value)
								PutULONG((unsigned int) NoSymbol, nextDest,
										bigEndian_);
							else {
								unsigned int keysym;

								decodeBuffer.decodeCachedValue(keysym, 24,
										serverCache_.
										getKeyboardMappingKeysymCache, 9);
								decodeBuffer.decodeCachedValue(cValue, 8,
										serverCache_.
										getKeyboardMappingLastByteCache, 5);
								previous += cValue;
								PutULONG((keysym << 8) | previous, nextDest,
										bigEndian_);
							}
							nextDest += 4;
						}
						ServerCache::getKeyboardMappingLastMap.
						set(outputLength - 32, outputMessage + 32);
					}
						break;
					case X_GetModifierMapping: {
						unsigned int keycodesPerModifier;

						decodeBuffer.decodeValue(keycodesPerModifier, 8);
						outputLength = 32 + (keycodesPerModifier << 3);
						outputMessage = writeBuffer_.addMessage(outputLength);
						outputMessage[1] = (unsigned char) keycodesPerModifier;
						unsigned char *nextDest = outputMessage + 32;

						decodeBuffer.decodeValue(value, 1);
						if (value) {
							memcpy(outputMessage + 32,
									ServerCache::getModifierMappingLastMap.
									getData(),
									ServerCache::getModifierMappingLastMap.
									getLength());
							break;
						}
						for (unsigned int count = outputLength - 32; count; count--) {
							decodeBuffer.decodeValue(value, 1);
							if (value)
								*nextDest++ = 0;
							else {
								decodeBuffer.decodeValue(value, 8);
								*nextDest++ = value;
							}
						}
						ServerCache::getModifierMappingLastMap.
						set(outputLength - 32, outputMessage + 32);
					}
						break;
					case X_GetProperty: {
						unsigned char format;

						decodeBuffer.decodeCachedValue(format, 8, serverCache_.
						getPropertyFormatCache);
						unsigned int length;

						decodeBuffer.decodeValue(length, 32, 9);
						unsigned int numBytes = length;

						if (format == 16)
							numBytes <<= 1;
						else if (format == 32)
							numBytes <<= 2;
						outputLength = 32 + RoundUp4(numBytes);
						outputMessage = writeBuffer_.addMessage(outputLength);
						outputMessage[1] = format;
						PutULONG(length, outputMessage + 16, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 29, serverCache_.
						getPropertyTypeCache, 9);
						PutULONG(value, outputMessage + 8, bigEndian_);
						decodeBuffer.decodeValue(value, 32, 9);
						PutULONG(value, outputMessage + 12, bigEndian_);
						unsigned char *nextDest = outputMessage + 32;

						if (format == 8) {
							if (requestData[0] == XA_RESOURCE_MANAGER) {
								decodeBuffer.decodeValue(value, 1);
								if (value) {
									memcpy(nextDest, ServerCache::xResources.
									getData(), ServerCache::xResources.
									getLength());
									break;
								}
							}
							serverCache_.getPropertyTextCompressor.
							reset();
							for (unsigned int i = 0; i < numBytes; i++) {
								unsigned char nextChar;

								nextChar = *nextDest++ = serverCache_.
								getPropertyTextCompressor.
								decodeChar(decodeBuffer);
								if (nextChar == 10) {
									serverCache_.
									getPropertyTextCompressor.
									reset(nextChar);
								}
							}
							if (requestData[0] == XA_RESOURCE_MANAGER)
								ServerCache::xResources.set(numBytes,
										outputMessage + 32);
						} else {
							for (unsigned int i = 0; i < numBytes; i++) {
								decodeBuffer.decodeValue(value, 8);
								*nextDest++ = (unsigned char) value;
							}
						}
					}
						break;
					case X_GetSelectionOwner: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						decodeBuffer.decodeCachedValue(value, 29, serverCache_.
						getSelectionOwnerCache, 9);
						PutULONG(value, outputMessage + 8, bigEndian_);
					}
						break;
					case X_GetWindowAttributes: {
						outputLength = 44;
						outputMessage = writeBuffer_.addMessage(outputLength);
						decodeBuffer.decodeValue(value, 2);
						outputMessage[1] = (unsigned char) value;
						decodeBuffer.decodeCachedValue(value, 29, serverCache_.
						visualCache, 9);
						PutULONG(value, outputMessage + 8, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						getWindowAttributesClassCache, 3);
						PutUINT(value, outputMessage + 12, bigEndian_);
						decodeBuffer.decodeCachedValue(cValue, 8, serverCache_.
						getWindowAttributesBitGravityCache);
						outputMessage[14] = cValue;
						decodeBuffer.decodeCachedValue(cValue, 8, serverCache_.
						getWindowAttributesWinGravityCache);
						outputMessage[15] = cValue;
						decodeBuffer.decodeCachedValue(value, 32, serverCache_.
						getWindowAttributesPlanesCache, 9);
						PutULONG(value, outputMessage + 16, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 32, serverCache_.
						getWindowAttributesPixelCache, 9);
						PutULONG(value, outputMessage + 20, bigEndian_);
						decodeBuffer.decodeValue(value, 1);
						outputMessage[24] = (unsigned char) value;
						decodeBuffer.decodeValue(value, 1);
						outputMessage[25] = (unsigned char) value;
						decodeBuffer.decodeValue(value, 2);
						outputMessage[26] = (unsigned char) value;
						decodeBuffer.decodeValue(value, 1);
						outputMessage[27] = (unsigned char) value;
						decodeBuffer.decodeCachedValue(value, 29, serverCache_.
						colormapCache, 9);
						PutULONG(value, outputMessage + 28, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 32, serverCache_.
						getWindowAttributesAllEventsCache);
						PutULONG(value, outputMessage + 32, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 32, serverCache_.
						getWindowAttributesYourEventsCache);
						PutULONG(value, outputMessage + 36, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						getWindowAttributesDontPropagateCache);
						PutUINT(value, outputMessage + 40, bigEndian_);
					}
						break;
					case X_GrabKeyboard:
					case X_GrabPointer: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						decodeBuffer.decodeValue(value, 3);
						outputMessage[1] = (unsigned char) value;
					}
						break;
					case X_InternAtom: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						decodeBuffer.decodeValue(value, 29, 9);
						PutULONG(value, outputMessage + 8, bigEndian_);
					}
						break;
					case X_ListExtensions: {
						decodeBuffer.decodeValue(value, 32, 8);
						outputLength = 32 + (value << 2);
						outputMessage = writeBuffer_.addMessage(outputLength);
						unsigned int numExtensions;

						decodeBuffer.decodeValue(numExtensions, 8);
						outputMessage[1] = (unsigned char) numExtensions;
						unsigned char *nextDest = outputMessage + 32;

						for (; numExtensions; numExtensions--) {
							unsigned int length;

							decodeBuffer.decodeValue(length, 8);
							*nextDest++ = (unsigned char) length;
							for (; length; length--) {
								decodeBuffer.decodeValue(value, 8);
								*nextDest++ = value;
							}
						}
					}
						break;
					case X_ListFonts: {
						decodeBuffer.decodeValue(value, 32, 8);
						outputLength = 32 + (value << 2);
						outputMessage = writeBuffer_.addMessage(outputLength);
						unsigned int numFonts;

						decodeBuffer.decodeValue(numFonts, 16, 6);
						PutUINT(numFonts, outputMessage + 8, bigEndian_);
						unsigned char *nextDest = outputMessage + 32;

						for (; numFonts; numFonts--) {
							unsigned int length;

							decodeBuffer.decodeValue(length, 8);
							*nextDest++ = (unsigned char) length;
							serverCache_.getPropertyTextCompressor.
							reset();
							for (; length; length--)
								*nextDest++ = serverCache_.
								getPropertyTextCompressor.
								decodeChar(decodeBuffer);
						}
					}
						break;
					case X_LookupColor:
					case X_AllocNamedColor: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						unsigned char *nextDest = outputMessage + 8;

						if (nextOpcode == X_AllocNamedColor) {
							decodeBuffer.decodeValue(value, 32, 9);
							PutULONG(value, nextDest, bigEndian_);
							nextDest += 4;
						}
						unsigned int count = 3;

						do {
							decodeBuffer.decodeValue(value, 16, 9);
							PutUINT(value, nextDest, bigEndian_);
							unsigned int visualColor;

							decodeBuffer.decodeValue(visualColor, 16, 5);
							visualColor += value;
							visualColor &= 0xffff;
							PutUINT(visualColor, nextDest + 6, bigEndian_);
							nextDest += 2;
						} while (--count);
					}
						break;
					case X_QueryBestSize: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						decodeBuffer.decodeValue(value, 16, 8);
						PutUINT(value, outputMessage + 8, bigEndian_);
						decodeBuffer.decodeValue(value, 16, 8);
						PutUINT(value, outputMessage + 10, bigEndian_);
					}
						break;
					case X_QueryColors: {
						unsigned int cached;

						decodeBuffer.decodeValue(cached, 1, 1);
						if (cached) {
							unsigned int numColors =
									serverCache_.queryColorsLastReply.
									getLength() / 6;
							outputLength = 32 + (numColors << 3);
							outputMessage
									= writeBuffer_.addMessage(outputLength);
							PutUINT(numColors, outputMessage + 8, bigEndian_);
							const unsigned char *nextSrc =
									serverCache_.queryColorsLastReply.
									getData();
							unsigned char *nextDest = outputMessage + 32;

							for (; numColors; numColors--) {
								for (unsigned int i = 0; i < 6; i++)
									*nextDest++ = *nextSrc++;
								nextDest += 2;
							}
						} else {
							unsigned int numColors;

							decodeBuffer.decodeValue(numColors, 16, 5);
							outputLength = 32 + (numColors << 3);
							outputMessage
									= writeBuffer_.addMessage(outputLength);
							PutUINT(numColors, outputMessage + 8, bigEndian_);
							unsigned char *nextDest = outputMessage + 32;

							for (unsigned int c = 0; c < numColors; c++) {
								for (unsigned int i = 0; i < 3; i++) {
									decodeBuffer.decodeValue(value, 16);
									PutUINT(value, nextDest, bigEndian_);
									nextDest += 2;
								}
							}
							serverCache_.queryColorsLastReply.
							set(numColors * 6, outputMessage + 32);
							const unsigned char *nextSrc = nextDest - 1;

							nextDest = outputMessage + 32 + ((numColors - 1)
									<< 3) + 5;
							for (; numColors> 1; numColors--) {
								for (unsigned int i = 0; i < 6; i++)
									*nextDest-- = *nextSrc--;
								nextDest -= 2;
							}
						}
					}
						break;
					case X_QueryExtension: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						decodeBuffer.decodeValue(value, 1);
						outputMessage[8] = (unsigned char) value;
						decodeBuffer.decodeValue(value, 8);
						outputMessage[9] = (unsigned char) value;
						decodeBuffer.decodeValue(value, 8);
						outputMessage[10] = (unsigned char) value;
						decodeBuffer.decodeValue(value, 8);
						outputMessage[11] = (unsigned char) value;
					}
						break;
					case X_QueryFont: {
						unsigned int numProperties;
						unsigned int numCharInfos;

						decodeBuffer.decodeValue(numProperties, 16, 8);
						decodeBuffer.decodeValue(numCharInfos, 32, 10);
						outputLength = 60 + numProperties * 8 + numCharInfos
								* 12;
						outputMessage = writeBuffer_.addMessage(outputLength);
						PutUINT(numProperties, outputMessage + 46, bigEndian_);
						PutULONG(numCharInfos, outputMessage + 56, bigEndian_);
						decodeCharInfo_(decodeBuffer, outputMessage + 8);
						decodeCharInfo_(decodeBuffer, outputMessage + 24);
						decodeBuffer.decodeValue(value, 16, 9);
						PutUINT(value, outputMessage + 40, bigEndian_);
						decodeBuffer.decodeValue(value, 16, 9);
						PutUINT(value, outputMessage + 42, bigEndian_);
						decodeBuffer.decodeValue(value, 16, 9);
						PutUINT(value, outputMessage + 44, bigEndian_);
						decodeBuffer.decodeValue(value, 1);
						outputMessage[48] = (unsigned char) value;
						decodeBuffer.decodeValue(value, 8);
						outputMessage[49] = (unsigned char) value;
						decodeBuffer.decodeValue(value, 8);
						outputMessage[50] = (unsigned char) value;
						decodeBuffer.decodeValue(value, 1);
						outputMessage[51] = (unsigned char) value;
						decodeBuffer.decodeValue(value, 16, 9);
						PutUINT(value, outputMessage + 52, bigEndian_);
						decodeBuffer.decodeValue(value, 16, 9);
						PutUINT(value, outputMessage + 54, bigEndian_);
						unsigned char *nextDest = outputMessage + 60;

						decodeBuffer.decodeValue(value, 1);
						if (value) {
							unsigned int index;

							decodeBuffer.decodeValue(index, 4);
							unsigned int length;
							const unsigned char *data;

							ServerCache::queryFontFontCache.get(index, length,
									data);
							memcpy(nextDest, data, length);
							break;
						}
						unsigned char *saveDest = nextDest;
						unsigned int length = numProperties * 8 + numCharInfos
								* 12;
						for (; numProperties; numProperties--) {
							decodeBuffer.decodeValue(value, 32, 9);
							PutULONG(value, nextDest, bigEndian_);
							decodeBuffer.decodeValue(value, 32, 9);
							PutULONG(value, nextDest + 4, bigEndian_);
							nextDest += 8;
						}
						for (; numCharInfos; numCharInfos--) {
							decodeCharInfo_(decodeBuffer, nextDest);
							nextDest += 12;
						}
						ServerCache::queryFontFontCache.set(length, saveDest);
					}
						break;
					case X_QueryPointer: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						decodeBuffer.decodeValue(value, 1);
						outputMessage[1] = (unsigned char) value;
						decodeBuffer.decodeCachedValue(value, 29, serverCache_.
						queryPointerRootCache, 9);
						PutULONG(value, outputMessage + 8, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 29, serverCache_.
						queryPointerChildCache, 9);
						PutULONG(value, outputMessage + 12, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						motionNotifyRootXCache, 8);
						serverCache_.motionNotifyLastRootX += value;
						PutUINT(serverCache_.motionNotifyLastRootX,
								outputMessage + 16, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						motionNotifyRootYCache, 8);
						serverCache_.motionNotifyLastRootY += value;
						PutUINT(serverCache_.motionNotifyLastRootY,
								outputMessage + 18, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						motionNotifyEventXCache, 8);
						PutUINT(serverCache_.motionNotifyLastRootX + value,
								outputMessage + 20, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						motionNotifyEventYCache, 8);
						PutUINT(serverCache_.motionNotifyLastRootY + value,
								outputMessage + 22, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						motionNotifyStateCache);
						PutUINT(value, outputMessage + 24, bigEndian_);
					}
						break;
					case X_QueryTree: {
						unsigned int secondByte;

						decodeBuffer.decodeValue(secondByte, 8);
						unsigned int replyLength;

						decodeBuffer.decodeValue(replyLength, 32);
						outputLength = 32 + (replyLength << 2);
						outputMessage = writeBuffer_.addMessage(outputLength);
						outputMessage[1] = (unsigned char) secondByte;
						unsigned char *nextDest = outputMessage + 8;

						for (unsigned int i = 8; i < outputLength; i++) {
							unsigned int nextByte;

							decodeBuffer.decodeValue(nextByte, 8);
							*nextDest++ = (unsigned char) nextByte;
						}
					}
						break;
					case X_TranslateCoords: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						decodeBuffer.decodeValue(value, 1);
						outputMessage[1] = (unsigned char) value;
						decodeBuffer.decodeCachedValue(value, 29, serverCache_.
						translateCoordsChildCache, 9);
						PutULONG(value, outputMessage + 8, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						translateCoordsXCache, 8);
						PutUINT(value, outputMessage + 12, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						translateCoordsYCache, 8);
						PutUINT(value, outputMessage + 14, bigEndian_);
					}
						break;
						//starting point for addtional message support
						//these are not compressed yet
					case XE_XKEYBOARD:
					case XE_RENDER:
					case XE_RANDR:
					case XE_XFIXES:
					case XE_Composite:
					case XE_DAMAGE:
					case XE_SHAPE:
					case XE_SYNC:
					case XE_XInputExtension:
					case XE_XINERAMA:
					case XE_EVENT_EXTENSION:
					case XE_DRI2:
					case XE_SGI_GLX:

					case X_ListFontsWithInfo:
					case X_GetImage: {
						unsigned int secondByte;

						decodeBuffer.decodeValue(secondByte, 8);
						unsigned int replyLength;
						if (nextOpcode == X_ListFontsWithInfo && secondByte)
							sequenceNumQueue_.push(sequenceNum, nextOpcode);

						decodeBuffer.decodeValue(replyLength, 32);
						outputLength = 32 + (replyLength << 2);
						outputMessage = writeBuffer_.addMessage(outputLength);
						outputMessage[1] = (unsigned char) secondByte;
						unsigned char *nextDest = outputMessage + 8;

						for (unsigned int i = 8; i < outputLength; i++) {
							unsigned int nextByte;

							decodeBuffer.decodeValue(nextByte, 8);
							*nextDest++ = (unsigned char) nextByte;
						}
					}
						break;
						//starting point for x extensions parsing
						//compressed
					case XE_BIG_REQUESTS: {
						outputLength = 32;
						outputMessage = writeBuffer_.addMessage(outputLength);
						unsigned int requestLength;
						decodeBuffer.decodeValue(requestLength, 32);
						PutULONG(0, outputMessage + 4, bigEndian_);
						PutULONG(requestLength, outputMessage + 8, bigEndian_);
					}
						break;
					default: {
						CERR <<
						"assertion failed in ClientProxyReader::processMessage():\n"
						<<
						" no matching request for reply with sequence number "
						<< sequenceNum <<" opcode:"<<(unsigned int)nextOpcode<< ENDL;
					}
					}
				} else {
					unsigned int secondByte;

					decodeBuffer.decodeValue(secondByte, 8);
					unsigned int replyLength;

					decodeBuffer.decodeValue(replyLength, 32);
					outputLength = 32 + (replyLength << 2);
					outputMessage = writeBuffer_.addMessage(outputLength);
					outputMessage[1] = (unsigned char) secondByte;
					unsigned char *nextDest = outputMessage + 8;

					for (unsigned int i = 8; i < outputLength; i++) {
						unsigned int nextByte;

						decodeBuffer.decodeValue(nextByte, 8);
						*nextDest++ = (unsigned char) nextByte;
					}
				}
				PutULONG((outputLength - 32) >> 2, outputMessage + 4,
						bigEndian_);
			} else {
				// event or error
				unsigned int sequenceNumDiff;

				decodeBuffer.decodeCachedValue(sequenceNumDiff, 16,
						serverCache_.
						eventSequenceNumCache, 7);
				serverCache_.lastSequenceNum += sequenceNumDiff;
				serverCache_.lastSequenceNum &= 0xffff;

				outputLength = 32;
				outputMessage = writeBuffer_.addMessage(outputLength);

				// check if this is an error that matches a sequence number for
				// which we were expecting a reply
				unsigned short int dummySequenceNum;
				unsigned char dummyOpcode;
				//cout<<"decoding event seq:"<<serverCache_.lastSequenceNum <<" opcode:"<<(unsigned int )opcode<<endl;

				if (sequenceNumQueue_.peek(dummySequenceNum, dummyOpcode)
						&& ((unsigned int) dummySequenceNum
								== serverCache_.lastSequenceNum))
					sequenceNumQueue_.pop(dummySequenceNum, dummyOpcode);

				switch (opcode) {
				case 0: {
					unsigned char code;

					decodeBuffer.decodeCachedValue(code, 8, serverCache_.
					errorCodeCache);
					outputMessage[1] = code;
					if ((code != 11) && (code != 8) && (code != 15) && (code
							!= 1)) {
						decodeBuffer.decodeValue(value, 32, 16);
						PutULONG(value, outputMessage + 4, bigEndian_);
					}
					if (code >= 18) {
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						errorMinorCache);
						PutUINT(value, outputMessage + 8, bigEndian_);
					}
					decodeBuffer.decodeCachedValue(cValue, 8, serverCache_.
					errorMajorCache);
					outputMessage[10] = cValue;
					if (code >= 18) {
						unsigned char *nextDest = outputMessage + 11;

						for (unsigned int i = 11; i < 32; i++) {
							decodeBuffer.decodeValue(value, 8);
							*nextDest++ = (unsigned char) cValue;
						}
					}
				}
					break;
				case ButtonPress:
				case ButtonRelease:
				case KeyPress:
				case KeyRelease:
				case MotionNotify:
				case EnterNotify:
				case LeaveNotify: {
					if (opcode == MotionNotify)
						decodeBuffer.decodeValue(value, 1);
					else if ((opcode == EnterNotify) || (opcode == LeaveNotify))
						decodeBuffer.decodeValue(value, 3);
					else if (opcode == KeyRelease) {
						decodeBuffer.decodeValue(value, 1);
						if (value)
							value = serverCache_.keyPressLastKey;
						else
							decodeBuffer.decodeValue(value, 8);
					} else if ((opcode == ButtonPress) || (opcode
							== ButtonRelease)) {
						decodeBuffer.decodeCachedValue(cValue, 8, serverCache_.
						buttonCache);
						value = (unsigned int) cValue;
					} else
						decodeBuffer.decodeValue(value, 8);
					outputMessage[1] = (unsigned char) value;
					decodeBuffer.decodeCachedValue(value, 32, serverCache_.
					motionNotifyTimestampCache, 9);
					serverCache_.lastTimestamp += value;
					PutULONG(serverCache_.lastTimestamp, outputMessage + 4,
							bigEndian_);
					unsigned char *nextDest = outputMessage + 8;
					int skipRest = 0;

					if (opcode == KeyRelease) {
						decodeBuffer.decodeValue(value, 1);
						if (value) {
							for (unsigned int i = 0; i < 23; i++)
								*nextDest++ = serverCache_.keyPressCache[i];
							skipRest = 1;
						}
					}
					if (!skipRest) {
						for (unsigned int i = 0; i < 3; i++) {
							decodeBuffer.decodeCachedValue(value, 29,
									*serverCache_.
									motionNotifyWindowCache
									[i], 6);
							PutULONG(value, nextDest, bigEndian_);
							nextDest += 4;
						}
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						motionNotifyRootXCache, 6);
						serverCache_.motionNotifyLastRootX += value;
						PutUINT(serverCache_.motionNotifyLastRootX,
								outputMessage + 20, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						motionNotifyRootYCache, 6);
						serverCache_.motionNotifyLastRootY += value;
						PutUINT(serverCache_.motionNotifyLastRootY,
								outputMessage + 22, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						motionNotifyEventXCache, 6);
						PutUINT(serverCache_.motionNotifyLastRootX + value,
								outputMessage + 24, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						motionNotifyEventYCache, 6);
						PutUINT(serverCache_.motionNotifyLastRootY + value,
								outputMessage + 26, bigEndian_);
						decodeBuffer.decodeCachedValue(value, 16, serverCache_.
						motionNotifyStateCache);
						PutUINT(value, outputMessage + 28, bigEndian_);
						if ((opcode == EnterNotify) || (opcode == LeaveNotify))
							decodeBuffer.decodeValue(value, 2);
						else
							decodeBuffer.decodeValue(value, 1);
						outputMessage[30] = (unsigned char) value;
						if ((opcode == EnterNotify) || (opcode == LeaveNotify)) {
							decodeBuffer.decodeValue(value, 2);
							outputMessage[31] = (unsigned char) value;
						} else if (opcode == KeyPress) {
							serverCache_.keyPressLastKey = outputMessage[1];
							for (unsigned int i = 8; i < 31; i++) {
								serverCache_.keyPressCache[i - 8]
										= outputMessage[i];
							}
						}
					}
				}
					break;
				case ColormapNotify: {
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					colormapNotifyWindowCache, 8);
					PutULONG(value, outputMessage + 4, bigEndian_);
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					colormapNotifyColormapCache, 8);
					PutULONG(value, outputMessage + 8, bigEndian_);
					decodeBuffer.decodeValue(value, 1);
					outputMessage[12] = (unsigned char) value;
					decodeBuffer.decodeValue(value, 1);
					outputMessage[13] = (unsigned char) value;
				}
					break;
				case ConfigureNotify: {
					unsigned char *nextDest = outputMessage + 4;

					for (unsigned int i = 0; i < 3; i++) {
						decodeBuffer.decodeCachedValue(value, 29,
								*serverCache_.
								configureNotifyWindowCache
								[i], 9);
						PutULONG(value, nextDest, bigEndian_);
						nextDest += 4;
					}
					for (unsigned int j = 0; j < 5; j++) {
						decodeBuffer.decodeCachedValue(value, 16,
								*serverCache_.
								configureNotifyGeomCache
								[j], 8);
						PutUINT(value, nextDest, bigEndian_);
						nextDest += 2;
					}
					decodeBuffer.decodeValue(value, 1);
					*nextDest = value;
				}
					break;
				case CreateNotify: {
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					createNotifyWindowCache, 9);
					PutULONG(value, outputMessage + 4, bigEndian_);
					decodeBuffer.decodeValue(value, 29, 5);
					serverCache_.createNotifyLastWindow += value;
					serverCache_.createNotifyLastWindow &= 0x1fffffff;
					PutULONG(serverCache_.createNotifyLastWindow, outputMessage
							+ 8, bigEndian_);
					unsigned char *nextDest = outputMessage + 12;

					for (unsigned int i = 0; i < 5; i++) {
						decodeBuffer.decodeValue(value, 16, 9);
						PutUINT(value, nextDest, bigEndian_);
						nextDest += 2;
					}
					decodeBuffer.decodeValue(value, 1);
					*nextDest = (unsigned char) value;
				}
					break;
				case Expose: {
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					exposeWindowCache, 9);
					PutULONG(value, outputMessage + 4, bigEndian_);
					unsigned char *nextDest = outputMessage + 8;

					for (unsigned int i = 0; i < 5; i++) {
						decodeBuffer.decodeCachedValue(value, 16,
								*serverCache_.
								exposeGeomCache[i], 6);
						PutUINT(value, nextDest, bigEndian_);
						nextDest += 2;
					}
				}
					break;
				case FocusIn:
				case FocusOut: {
					decodeBuffer.decodeValue(value, 3);
					outputMessage[1] = (unsigned char) value;
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					focusInWindowCache, 9);
					PutULONG(value, outputMessage + 4, bigEndian_);
					decodeBuffer.decodeValue(value, 2);
					outputMessage[8] = (unsigned char) value;
				}
					break;
				case KeymapNotify: {
					decodeBuffer.decodeValue(value, 1);
					if (value)
						memcpy(outputMessage + 1,
								ServerCache::lastKeymap.getData(), 31);
					else {
						unsigned char *nextDest = outputMessage + 1;

						for (unsigned int i = 1; i < 32; i++) {
							decodeBuffer.decodeValue(value, 8);
							*nextDest++ = (unsigned char) value;
						}
						ServerCache::lastKeymap.set(31, outputMessage + 1);
					}
				}
					break;
				case MapNotify:
				case UnmapNotify:
				case DestroyNotify: {
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					mapNotifyEventCache, 9);
					PutULONG(value, outputMessage + 4, bigEndian_);
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					mapNotifyWindowCache, 9);
					PutULONG(value, outputMessage + 8, bigEndian_);
					if ((opcode == MapNotify) || (opcode == UnmapNotify)) {
						decodeBuffer.decodeValue(value, 1);
						outputMessage[12] = (unsigned char) value;
					}
				}
					break;
				case NoExpose: {
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					noExposeDrawableCache, 9);
					PutULONG(value, outputMessage + 4, bigEndian_);
					decodeBuffer.decodeCachedValue(value, 16, serverCache_.
					noExposeMinorCache);
					PutUINT(value, outputMessage + 8, bigEndian_);
					decodeBuffer.decodeCachedValue(cValue, 8, serverCache_.
					noExposeMajorCache);
					outputMessage[10] = cValue;
				}
					break;
				case PropertyNotify: {
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					propertyNotifyWindowCache, 9);
					PutULONG(value, outputMessage + 4, bigEndian_);
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					propertyNotifyAtomCache, 9);
					PutULONG(value, outputMessage + 8, bigEndian_);
					decodeBuffer.decodeValue(value, 32, 9);
					serverCache_.lastTimestamp += value;
					PutULONG(serverCache_.lastTimestamp, outputMessage + 12,
							bigEndian_);
					decodeBuffer.decodeValue(value, 1);
					outputMessage[16] = (unsigned char) value;
				}
					break;
				case ReparentNotify: {
					unsigned char *nextDest = outputMessage + 4;

					for (unsigned int i = 0; i < 3; i++) {
						decodeBuffer.decodeCachedValue(value, 29, serverCache_.
						reparentNotifyWindowCache, 9);
						PutULONG(value, nextDest, bigEndian_);
						nextDest += 4;
					}
					decodeBuffer.decodeValue(value, 16, 6);
					PutUINT(value, nextDest, bigEndian_);
					decodeBuffer.decodeValue(value, 16, 6);
					PutUINT(value, nextDest + 2, bigEndian_);
					decodeBuffer.decodeValue(value, 1);
					outputMessage[20] = (unsigned char) value;
				}
					break;
				case SelectionClear: {
					decodeBuffer.decodeValue(value, 32, 9);
					serverCache_.lastTimestamp += value;
					PutULONG(serverCache_.lastTimestamp, outputMessage + 4,
							bigEndian_);
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					selectionClearWindowCache, 9);
					PutULONG(value, outputMessage + 8, bigEndian_);
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					selectionClearAtomCache, 9);
					PutULONG(value, outputMessage + 12, bigEndian_);
				}
					break;
				case SelectionRequest: {
					decodeBuffer.decodeValue(value, 32, 9);
					serverCache_.lastTimestamp += value;
					PutULONG(serverCache_.lastTimestamp, outputMessage + 4,
							bigEndian_);
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					selectionClearWindowCache, 9);
					PutULONG(value, outputMessage + 8, bigEndian_);
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					selectionClearWindowCache, 9);
					PutULONG(value, outputMessage + 12, bigEndian_);
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					selectionClearAtomCache, 9);
					PutULONG(value, outputMessage + 16, bigEndian_);
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					selectionClearAtomCache, 9);
					PutULONG(value, outputMessage + 20, bigEndian_);
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					selectionClearAtomCache, 9);
					PutULONG(value, outputMessage + 24, bigEndian_);
				}
					break;
				case VisibilityNotify: {
					decodeBuffer.decodeCachedValue(value, 29, serverCache_.
					visibilityNotifyWindowCache, 9);
					PutULONG(value, outputMessage + 4, bigEndian_);
					decodeBuffer.decodeValue(value, 2);
					outputMessage[8] = (unsigned char) value;
				}
					break;
				default: {
					unsigned int secondByte;

					decodeBuffer.decodeValue(secondByte, 8);
					outputMessage[1] = secondByte;
					unsigned char *nextDest = outputMessage + 4;

					for (unsigned int i = 4; i < outputLength; i++) {
						unsigned int nextByte;

						decodeBuffer.decodeValue(nextByte, 8);
						*nextDest++ = (unsigned char) nextByte;
					}
				}
				}
			}
			*outputMessage = (unsigned char) opcode;
			PutUINT(serverCache_.lastSequenceNum, outputMessage + 2, bigEndian_);
		}
	}

	if (WriteAll(fd_, writeBuffer_.getData(), writeBuffer_.getLength()) < 0) {
		return 0;
	}
	return 1;
}

void ClientChannel::setBigEndian(int flag) {
	bigEndian_ = flag;
}

void ClientChannel::decodeCharInfo_(DecodeBuffer & decodeBuffer,
		unsigned char *nextDest) {
	unsigned int value;

	decodeBuffer.decodeCachedValue(value, 32,
			*serverCache_.queryFontCharInfoCache[0], 6);
	PutUINT(value & 0xffff, nextDest, bigEndian_);
	PutUINT(value >> 16, nextDest + 10, bigEndian_);
	nextDest += 2;
	for (unsigned int i = 1; i < 5; i++) {
		unsigned int value;

		decodeBuffer.decodeCachedValue(value, 16, *serverCache_.
		queryFontCharInfoCache[i], 6);
		PutUINT(value, nextDest, bigEndian_);
		nextDest += 2;
	}
}
