#include "dxpcconf.h"
#include <string.h>
#include "X-headers.H"
#include "ServerChannel.H"
#include "EncodeBuffer.H"
#include "DecodeBuffer.H"
#include "util.H"
#include <fcntl.h>

#define replay_debug 0
using namespace std;
ServerChannel::ServerChannel(int xServerFD, unsigned int
statisticsLevel, ResourceID *IdMap, unsigned int* outputLength, char* filename,
		int fileReplay) :
	readBuffer_(xServerFD, this), fd_(xServerFD), firstRequest_(1),
			firstReply_(1), statisticsLevel_(statisticsLevel) {
	if (compressImages) {
		decompresser = new Decompresser(compressImages);
	} else {
		decompresser = 0;
	}
	outputLength_ = outputLength;
	idMap = IdMap;
#ifdef FILE_REPLAY
	if (!fileReplay)
	replyFile_.open(filename, ios::in | ios::out | ios::binary | ios::trunc);
	else
	replyFile_.open(filename, ios::in | ios::out | ios::binary | ios::app);
#else
	if (PRINT_DEBUG)
		replyFile_.open(filename, ios::in | ios::out | ios::binary | ios::app);
#endif
	if (PRINT_DEBUG)
		replyFile_.exceptions(fstream::failbit | fstream::badbit);
	file_replay = fileReplay;
	convertPos = 0;
}

int ServerChannel::setConvertMode(char* filename) {
	return readBuffer_.setReplay(filename);
}

ServerChannel::~ServerChannel() {
	if (statisticsLevel_ > 0) {
		*logofs << "\n*** dxpc Server-side Compression Statistics ***\n";
		unsigned int replyBitsIn, replyBitsOut;

		if (statisticsLevel_ >= 2) {
			*logofs << "\nCompression of replies by request message type:\n";
		}
		replyStats_.summarize(replyBitsIn, replyBitsOut,
				(statisticsLevel_ >= 2));

		if (statisticsLevel_ >= 2) {
			*logofs << "\nCompression of events and errors by message type:\n";
		}
		unsigned int bitsIn, bitsOut;

		stats_.summarize(bitsIn, bitsOut, (statisticsLevel_ >= 2));

		if (statisticsLevel_ >= 2) {
			*logofs << '\n' << framingBitsOut_
					<< " bits used for dxpc message framing and multiplexing\n";
		}

		unsigned int totalBitsIn = bitsIn + replyBitsIn;
		unsigned int totalBitsOut = bitsOut + replyBitsOut + framingBitsOut_;

		*logofs << "\nOverall compression:" << ENDL << "  " << totalBitsIn
				<< " bits compressed to " << totalBitsOut << ENDL;
		if (totalBitsOut > 0) {
			*logofs << "  (" << (float) totalBitsIn / (float) totalBitsOut
					<< ":1 compression ratio)" << ENDL << ENDL;
		}
	}

	if (decompresser) {
		delete decompresser;

		decompresser = 0;
	}
	if (PRINT_DEBUG)
		replyFile_.close();
	cout <<"logging all reply and event messages"<<endl;
}

int ServerChannel::doRead(EncodeBuffer & encodeBuffer,
		SequenceNumQueue &sequenceNumQueue_, EventQueue &eventQueue_,
		int appFD, int serverFD, int replay) {
#ifdef CONVERT
	int pos = readBuffer_.doRead();
	if (pos <= 0)
	return pos;
	cout <<"serverChannel inside pos:"<<pos <<endl;
	if (pos> convertPos)
	return pos;
#else
	if (!readBuffer_.doRead())
		return 0;
#endif

	unsigned char *buffer;
	unsigned int size;
	unsigned char* replayBuffer;

	while ((buffer = readBuffer_.getMessage(size)) != 0) {
		int specialReply = 0;
		if (firstReply_) {
			imageByteOrder_ = buffer[30];
			bitmapBitOrder_ = buffer[31];
			scanlineUnit_ = buffer[32];
			scanlinePad_ = buffer[33];
			firstReply_ = 0;
			encodeBuffer.encodeValue((unsigned int) buffer[0], 8);
			encodeBuffer.encodeValue((unsigned int) buffer[1], 8);
			encodeBuffer.encodeValue(GetUINT(buffer + 2, bigEndian_), 16);
			encodeBuffer.encodeValue(GetUINT(buffer + 4, bigEndian_), 16);
			encodeBuffer.encodeValue(GetUINT(buffer + 6, bigEndian_), 16);
			if (ServerCache::lastInitReply.compare(size - 8, buffer + 8))
				encodeBuffer.encodeValue(1, 1);
			else {
				encodeBuffer.encodeValue(0, 1);
				for (unsigned int i = 8; i < size; i++)
					encodeBuffer.encodeValue((unsigned int) buffer[i], 8);
			}
			if (PRINT_DEBUG)
				cout << "first reply, size:"<<size<<endl;
			if (PRINT_DEBUG) printMessage(buffer, size, 21, 1, 1+MAGIC_SIZE, 2, 2, 2, 4, 4, 4,
					4, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 4+MAGIC_SIZE, -1);
			int vendorSize = GetUINT(buffer + 24, bigEndian_);
			if (PRINT_DEBUG)
				cout <<"	first reply: vendor (40-"<<vendorSize<<"):";
			if (PRINT_DEBUG)
				printString(buffer + 40, vendorSize);
			int formatNum = (unsigned int) (buffer[29]);
			int screenNum = (unsigned int) buffer[28];
			int pad = ((40 + vendorSize + 3)/4) *4;
			for (int i = 0; i<formatNum; ++i) {
				if (PRINT_DEBUG)
					cout << "	first reply: format, total num:"<<formatNum<<endl;
				if (PRINT_DEBUG) printMessage(buffer + pad + 8*i, 8, 4, 1, 1, 1, -1);
			}
			if (screenNum != 1) {
				cerr <<"multi screens are found! may cause bugs during replaying"<<endl;
			} else {
				if (PRINT_DEBUG)
					cout <<"	first reply: screen"<<endl;
				if (PRINT_DEBUG) printMessage(buffer + pad + 8*formatNum, size - (40 + pad + 8
						*formatNum), 16, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2, 4, 1,
						1, 1, 1);
			}

			specialReply = 1;
			//replay log
			if (replay) {
				//replay
				/*try {
				 replayBuffer = new unsigned char[size];
				 replyFile_.read((char*)replayBuffer, size);
				 //					*outputLength_ += size;
				 } catch (fstream::failure e) {
				 cerr << "Exception reading files in ServerChannel.c"<<endl;
				 }*/
				unsigned int aSize = eventQueue_.replayReply();
				if (PRINT_DEBUG)
					cout
							<< "This is a special reply, send recorded message to the application instead. First Reply:recorded size:"
							<<aSize<< ", actual size:"<<size <<endl;
				replayBuffer = eventQueue_.getReplyBuffer();
				*outputLength_ += 1;

				//init resource id maps
				idMap->initOld(GetULONG(replayBuffer + 12, bigEndian_),
						GetULONG(replayBuffer + 16, bigEndian_));
				idMap->initNew(GetULONG(buffer + 12, bigEndian_), GetULONG(
						buffer + 16, bigEndian_));
				idMap->setRootWindow(GetULONG(replayBuffer + pad + 8*formatNum,
						bigEndian_), GetULONG(buffer + pad + 8*formatNum,
						bigEndian_));
#ifndef FILE_REPLAY
				// this is buggy, as we shouldn't send replayBuffer back; same with QueryTrees
				if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getReplyBuffer(), aSize) != aSize)
					cerr << "Cannot write to application."<<endl;
#endif
				if (PRINT_DEBUG)
					cout
							<< "This is a special reply, send recorded message to the application instead. First Reply:recorded size:"
							<<aSize<< ", actual size:"<<size <<endl;

			} else {
				// recording
				/*try {
				 replyFile_.write((char*)buffer, size);
				 } catch (fstream::failure e) {
				 cerr << "Exception writing files in ServerChannel.c"<<endl;
				 }*/
				eventQueue_.recordReply(buffer, size);
				*outputLength_ += 1;
				//used by getproperty message
				idMap->initOld(GetULONG(buffer + 12, bigEndian_), GetULONG(
						buffer + 16, bigEndian_));
				idMap->setRootWindow(GetULONG(buffer + pad + 8*formatNum,
						bigEndian_), -1);
			}
			if (convert_log) {
				unsigned short int dummyNum;
				unsigned char dummyOpcode;
				//consume the dummy sequence number here
				sequenceNumQueue_.pop(dummyNum, dummyOpcode);
			}
		} else {
			if (buffer[0] == 1) {
				// reply
				unsigned int sequenceNum = GetUINT(buffer + 2, bigEndian_);
				unsigned int sequenceNumDiff = sequenceNum
						- serverCache_.lastSequenceNum;
				serverCache_.lastSequenceNum = sequenceNum;

				unsigned char opcode = *buffer;

				encodeBuffer.encodeCachedValue(opcode, 8, serverCache_.
				opcodeCache[serverCache_.
				lastOpcode]);
				serverCache_.lastOpcode = opcode;
				encodeBuffer.encodeCachedValue(sequenceNumDiff, 16,
						serverCache_.
						replySequenceNumCache, 7);

				unsigned short int nextSequenceNum;
				unsigned int requestOpcode = 256;
				unsigned char nextOpcode;
				//the same with kernel
				if (sequenceNumQueue_.peek(nextSequenceNum, nextOpcode)) {
					while (sequenceNum > nextSequenceNum) {
						if (sequenceNumQueue_.pop(nextSequenceNum, nextOpcode)
								== 0) {
							/*							if (convert_log) {
							 readBuffer_.rollBack(size);
							 cout <<"need to roll back, we need seq:"
							 <<sequenceNum<<" cur seq:"
							 <<nextSequenceNum<<endl;
							 return 1;
							 }
							 */cout
									<< "consume all sequence numbers??????????????????"
									<<endl;
							break;
						}
						sequenceNumQueue_.peek(nextSequenceNum, nextOpcode);
					}
				}/* else {
				 if (convert_log) {
				 readBuffer_.rollBack(size);
				 cout <<"need to roll back, we need seq:"<<sequenceNum
				 <<" cur seq:"<<nextSequenceNum<<endl;
				 return 1;
				 }
				 }*/

				if (sequenceNumQueue_.peek(nextSequenceNum, nextOpcode)
						&& (nextSequenceNum == sequenceNum)) {
					// we've found the request that generated this reply, so it's
					// possible to compress the reply based on the request type
					unsigned int requestData[3];

					sequenceNumQueue_.pop(nextSequenceNum, nextOpcode,
							requestData[0], requestData[1], requestData[2]);
					requestOpcode = nextOpcode;
					if (PRINT_DEBUG)
						cout <<"reply  opcode:"<<(unsigned int)nextOpcode
								<<"  sequence:"<<nextSequenceNum<<"  size:"
								<<size <<" outputLength:"<<*outputLength_
								<<endl;

					/*					if (replay) {
					 if (nextOpcode == X_QueryTree) {
					 unsigned char* tmp;
					 replyFile_.read((char*)replayBuffer, 32);
					 unsigned int num = GetULONG(replayBuffer + 4,
					 bigEndian_);
					 cout << "QueryTree replay, real size:"<<size
					 <<", recorded size:"<<num*4 + 32<<endl;
					 tmp = new unsigned char[num*4 + 32];
					 memcpy(tmp, replayBuffer, 32);
					 delete[] replayBuffer;
					 replayBuffer = tmp;
					 //always remeber to fix the outputLength!!
					 //							*outputLength_ = *outputLength_ - size + num*4 + 32;
					 size = num*4 + 32;

					 replyFile_.read((char*)replayBuffer + 32, size - 32);
					 } else
					 replyFile_.read((char*)replayBuffer, size);
					 }
					 */switch (nextOpcode) {
					case X_AllocColor: {
						const unsigned char *nextSrc = buffer + 8;

						for (unsigned int i = 0; i < 3; i++) {
							unsigned int colorValue = GetUINT(nextSrc,
									bigEndian_);
							nextSrc += 2;
							if (colorValue == requestData[i])
								encodeBuffer.encodeValue(1, 1);
							else {
								encodeBuffer.encodeValue(0, 1);
								encodeBuffer.encodeValue(colorValue
										- colorValue, 16, 6);
							}
						}
						unsigned int pixel = GetULONG(buffer + 16, bigEndian_);
						encodeBuffer.encodeValue(pixel, 32, 9);
						if (PRINT_DEBUG) printMessage(buffer, size, 10, 1, 1+MAGIC_SIZE, 2, 4,
								2, 2, 2, 2, 4, -1);
					}
						break;
					case X_GetAtomName: {
						unsigned int nameLength = GetUINT(buffer + 8,
								bigEndian_);
						encodeBuffer.encodeValue(nameLength, 16, 6);
						const unsigned char *nextSrc = buffer + 32;

						clientCache_.internAtomTextCompressor.reset();
						for (unsigned int i = 0; i < nameLength; i++)
							clientCache_.internAtomTextCompressor.
							encodeChar(*nextSrc++, encodeBuffer);
						if (PRINT_DEBUG) printMessage(buffer, size, 6, 1, 1+MAGIC_SIZE, 2, 4, 2,
								22+MAGIC_SIZE);
					}
						break;
					case X_GetGeometry: {
						encodeBuffer.encodeCachedValue(buffer[1], 8,
								serverCache_.
								depthCache);
						encodeBuffer.
						encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
								serverCache_.
								getGeometryRootCache, 9);
						const unsigned char *nextSrc = buffer + 12;

						for (unsigned int i = 0; i < 5; i++) {
							encodeBuffer.
							encodeCachedValue(GetUINT(nextSrc, bigEndian_), 16,
									*serverCache_.
									getGeometryGeomCache[i], 8);
							nextSrc += 2;
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 11, 1, 1, 2, 4, 4, 2, 2, 2,
								2, 2, -1);
					}
						break;
					case X_GetInputFocus: {
						specialReply = 1;
						if (!replay) {
							eventQueue_.recordReply(buffer, size);
						} else {
							eventQueue_.replayReply();
#ifndef FILE_REPLAY
							if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getReplyBuffer(), 32) != 32)
								cerr << "Cannot write to application."<<endl;
#endif
							if (PRINT_DEBUG)
								cout <<"recorded message is "<<endl;
							if (PRINT_DEBUG) printMessage(eventQueue_.getReplyBuffer(), size, 6,
									1, 1, 2, 4, 4, -1);
							if (PRINT_DEBUG)
								cout
										<< "This is a special reply, send recorded message to the application instead."
										<<endl;
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 6, 1, 1, 2, 4, 4, -1);
					}
						break;
					case X_GetKeyboardMapping: {
						specialReply = 1;
						if (!replay) {
							eventQueue_.recordReply(buffer, size);
						} else {
							//this is different, we will send the original reply back to the application, and remember the mapped window id
							unsigned int asize = eventQueue_.replayReply();
#ifndef FILE_REPLAY
							if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getReplyBuffer(), asize) != asize)
								cerr << "Cannot write to application."<<endl;
#endif
							if (PRINT_DEBUG)
								cout <<"recorded message is "<<endl;
							if (PRINT_DEBUG) printMessage(eventQueue_.getReplyBuffer(), size, 6,
									1, 1+MAGIC_SIZE, 2, 4, 4, -1);
							if (PRINT_DEBUG)
								cout
										<< "This is a special reply, send recorded message to the application instead."
										<<endl;
						}

						if (PRINT_DEBUG) printMessage(buffer, size, 5, 1, 1, 2, 4, 24+MAGIC_SIZE);
					}
						break;
					case X_GetModifierMapping: {
						encodeBuffer.encodeValue((unsigned int) buffer[1], 8);
						const unsigned char *nextDest = buffer + 32;

						if (ServerCache::getModifierMappingLastMap.
						compare(size - 32, nextDest)) {
							encodeBuffer.encodeValue(1, 1);
							break;
						}
						encodeBuffer.encodeValue(0, 1);
						for (unsigned int count = size - 32; count; count--) {
							unsigned char next = *nextDest++;

							if (next == 0)
								encodeBuffer.encodeValue(1, 1);
							else {
								encodeBuffer.encodeValue(0, 1);
								encodeBuffer.encodeValue(next, 8);
							}
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 5, 1, 1, 2, 4, 24+MAGIC_SIZE);
					}
						break;
					case X_GetProperty: {
						unsigned char format = (unsigned int) buffer[1];

						encodeBuffer.encodeCachedValue(format, 8, serverCache_.
						getPropertyFormatCache);
						unsigned int numBytes = GetULONG(buffer + 16,
								bigEndian_);
						encodeBuffer.encodeValue(numBytes, 32, 9);
						if (format == 16)
							numBytes <<= 1;
						else if (format == 32)
							numBytes <<= 2;
						encodeBuffer.
						encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
								serverCache_.
								getPropertyTypeCache, 9);
						encodeBuffer.
						encodeValue(GetULONG(buffer + 12, bigEndian_), 32, 9);
						const unsigned char *nextSrc = buffer + 32;

						if (format == 8) {
							if (requestData[0] == XA_RESOURCE_MANAGER) {
								if (ServerCache::xResources.
								compare(numBytes, buffer + 32)) {
									encodeBuffer.encodeValue(1, 1);
									break;
								}
								encodeBuffer.encodeValue(0, 1);
							}
							serverCache_.getPropertyTextCompressor.
							reset();
							for (unsigned int i = 0; i < numBytes; i++) {
								unsigned char nextChar;

								serverCache_.getPropertyTextCompressor.
								encodeChar(nextChar = *nextSrc++, encodeBuffer);
								if (nextChar == 10) {
									serverCache_.
									getPropertyTextCompressor.
									reset(nextChar);
								}
							}
						} else {
							for (unsigned int i = 0; i < numBytes; i++)
								encodeBuffer.
								encodeValue((unsigned int) *nextSrc++, 8);
						}
						unsigned int atom = GetULONG(buffer + 8, bigEndian_);

						if (requestData[0]) {
							specialReply = 1;
							if (!replay) {
								if (PRINT_DEBUG)
									cout <<" Special GetProperty reply."<<endl;
								// record this reply as this window may not be accessible
								eventQueue_.recordReply(buffer, size);
							} else {
								unsigned int aSize;
								aSize = eventQueue_.replayReply();
#ifndef FILE_REPLAY
								if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getReplyBuffer(), aSize) != aSize)
									cerr
											<< "Cannot write to x app for special getproperty."
											<<endl;
#endif
								if (PRINT_DEBUG)
									cout
											<< "This is a special reply, send recorded message to the application instead. GetProperty:recorded size:"
											<<aSize<< ", actual size:"<<size
											<<endl;
								//dummy read; consume the rest unread bytes in reply.log.debug
								if (PRINT_DEBUG)
									cout <<"recorded message is "<<endl;
								if (PRINT_DEBUG) printMessage(eventQueue_.getReplyBuffer(),
										aSize, 8, 1, 1, 2, 4, 4, 4, 4, 12
												+MAGIC_SIZE);
								//the atom could be window
								if (atom == ATOM_WINDOW) {
									idMap->addSpecialMap(GetULONG(
											eventQueue_.getReplyBuffer()+32,
											bigEndian_), GetULONG(buffer+32,
											bigEndian_));
								}
							}
						} else {
							if (replay) {
								//the atom could be window
								if (atom == ATOM_WINDOW) {
									PutULONG(idMap->mapToOld(GetULONG(
											buffer+32, bigEndian_)), buffer+32,
											bigEndian_);
								}
								//atom map
								PutULONG(idMap->atomMapToOld(atom), buffer+ 8,
										bigEndian_);
							}
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 8, 1, 1, 2, 4, 4, 4, 4, 12
								+MAGIC_SIZE);
					}
						break;
					case X_GetSelectionOwner: {
						specialReply = 1;
						if (!replay) {
							eventQueue_.recordReply(buffer, size);
						} else {
							//this is different, we will send the original reply back to the application, and remember the mapped window id
							eventQueue_.replayReply();
#ifndef FILE_REPLAY
							if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getReplyBuffer(), 32) != 32)
								cerr << "Cannot write to application."<<endl;
#endif
							if (PRINT_DEBUG)
								cout <<"recorded message is "<<endl;
							if (PRINT_DEBUG) printMessage(eventQueue_.getReplyBuffer(), size, 6,
									1, 1+MAGIC_SIZE, 2, 4, 4, -1);
							int owner = GetULONG(eventQueue_.getReplyBuffer()
									+ 8, bigEndian_);
							if (owner) {
								idMap->addSpecialMap(owner, GetULONG(
										buffer + 8, bigEndian_));
							}
							if (PRINT_DEBUG)
								cout
										<< "This is a special reply, send recorded message to the application instead."
										<<endl;
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 6, 1, 1+MAGIC_SIZE, 2, 4, 4,
								-1);
					}
						break;
					case X_GetWindowAttributes: {
						encodeBuffer.encodeValue((unsigned int) buffer[1], 2);
						encodeBuffer.
						encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
								serverCache_.visualCache, 9);
						encodeBuffer.
						encodeCachedValue(GetUINT(buffer + 12, bigEndian_), 16,
								serverCache_.
								getWindowAttributesClassCache, 3);
						encodeBuffer.encodeCachedValue(buffer[14], 8,
								serverCache_.
								getWindowAttributesBitGravityCache);
						encodeBuffer.encodeCachedValue(buffer[15], 8,
								serverCache_.
								getWindowAttributesWinGravityCache);
						encodeBuffer.
						encodeCachedValue(GetULONG(buffer + 16, bigEndian_),
								32, serverCache_.
								getWindowAttributesPlanesCache, 9);
						encodeBuffer.
						encodeCachedValue(GetULONG(buffer + 20, bigEndian_),
								32, serverCache_.
								getWindowAttributesPixelCache, 9);
						encodeBuffer.
						encodeValue((unsigned int) buffer[24], 1);
						encodeBuffer.
						encodeValue((unsigned int) buffer[25], 1);
						encodeBuffer.
						encodeValue((unsigned int) buffer[26], 2);
						encodeBuffer.
						encodeValue((unsigned int) buffer[27], 1);
						encodeBuffer.
						encodeCachedValue(GetULONG(buffer + 28, bigEndian_),
								29, serverCache_.colormapCache, 9);
						encodeBuffer.
						encodeCachedValue(GetULONG(buffer + 32, bigEndian_),
								32, serverCache_.
								getWindowAttributesAllEventsCache);
						encodeBuffer.
						encodeCachedValue(GetULONG(buffer + 36, bigEndian_),
								32, serverCache_.
								getWindowAttributesYourEventsCache);
						encodeBuffer.
						encodeCachedValue(GetUINT(buffer + 40, bigEndian_), 16,
								serverCache_.
								getWindowAttributesDontPropagateCache);
						if (PRINT_DEBUG) printMessage(buffer, size, 1, 1, 2, 4, 4, 2, 1, 1, 4,
								4, 1, 1, 1, 1, 4, 4, 4, 2, -1);
					}
						break;
					case X_GrabKeyboard:
					case X_GrabPointer: {
						encodeBuffer.encodeValue((unsigned int) buffer[1], 3);
						if (PRINT_DEBUG) printMessage(buffer, size, 5, 1, 1, 2, 4, -1);
					}
						break;
					case X_InternAtom: {
						specialReply = 1;
						if (!replay) {
							eventQueue_.recordReply(buffer, size);
						} else {
							eventQueue_.replayReply();
#ifndef FILE_REPLAY
							if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getReplyBuffer(), 32) != 32)
								cerr << "Cannot write to application."<<endl;
#endif
							if (PRINT_DEBUG)
								cout <<"recorded message is"<<endl;
							if (PRINT_DEBUG) printMessage(eventQueue_.getReplyBuffer(), size, 6,
									1, 1+MAGIC_SIZE, 2, 4, 4, -1);
							// add atom map
							idMap->addAtomMap(GetULONG(
									eventQueue_.getReplyBuffer() + 8,
									bigEndian_), GetULONG(buffer + 8,
									bigEndian_));
							if (PRINT_DEBUG)
								cout
										<< "This is a special reply, send recorded message to the application instead."
										<<endl;
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 6, 1, 1+MAGIC_SIZE, 2, 4, 4,
								-1);
					}
						break;
					case X_ListExtensions: {
						encodeBuffer.
						encodeValue(GetULONG(buffer + 4, bigEndian_), 32, 8);
						unsigned int numExtensions = (unsigned int) buffer[1];
						encodeBuffer.encodeValue(numExtensions, 8);
						const unsigned char *nextSrc = buffer + 32;

						for (; numExtensions; numExtensions--) {
							unsigned int length = (unsigned int) (*nextSrc++);
							encodeBuffer.encodeValue(length, 8);
							if (!strncmp((char *) nextSrc, "MIT-SHM", 7))
								memcpy((unsigned char *) nextSrc, "NOT-SHM", 7);
							for (; length; length--)
								encodeBuffer.
								encodeValue((unsigned int) (*nextSrc++), 8);
							if (PRINT_DEBUG)
								cout <<" not compressed, error message"<<endl;
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 5, 1, 1, 2, 4, 24+MAGIC_SIZE);
					}
						break;
					case X_ListFonts: {
						encodeBuffer.
						encodeValue(GetULONG(buffer + 4, bigEndian_), 32, 8);
						unsigned int numFonts = GetUINT(buffer + 8, bigEndian_);
						encodeBuffer.encodeValue(numFonts, 16, 6);
						const unsigned char *nextSrc = buffer + 32;

						for (; numFonts; numFonts--) {
							unsigned int length = (unsigned int) (*nextSrc++);
							encodeBuffer.encodeValue(length, 8);
							serverCache_.getPropertyTextCompressor.
							reset();
							for (; length; length--)
								serverCache_.getPropertyTextCompressor.
								encodeChar(*nextSrc++, encodeBuffer);
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 6, 1+MAGIC_SIZE, 1, 2, 4, 2,
								22+MAGIC_SIZE);

					}
						break;
					case X_LookupColor:
					case X_AllocNamedColor: {
						const unsigned char *nextSrc = buffer + 8;

						if (nextOpcode == X_AllocNamedColor) {
							encodeBuffer.
							encodeValue(GetULONG(nextSrc, bigEndian_), 32, 9);
							nextSrc += 4;
						}
						unsigned int count = 3;

						do {
							unsigned int exactColor = GetUINT(nextSrc,
									bigEndian_);
							encodeBuffer.encodeValue(exactColor, 16, 9);
							unsigned int visualColor = GetUINT(nextSrc + 6,
									bigEndian_) - exactColor;
							encodeBuffer.encodeValue(visualColor, 16, 5);
							nextSrc += 2;
						} while (--count);
						if (nextOpcode == X_LookupColor)
							if (PRINT_DEBUG) printMessage(buffer, size, 11, 1, 1+MAGIC_SIZE, 2,
									4, 2, 2, 2, 2, 2, 2, -1);
						else
							if (PRINT_DEBUG) printMessage(buffer, size, 12, 1, 1+MAGIC_SIZE, 2,
									4, 4, 2, 2, 2, 2, 2, 2, -1);
					}
						break;
					case X_QueryBestSize: {
						encodeBuffer.
						encodeValue(GetUINT(buffer + 8, bigEndian_), 16, 8);
						encodeBuffer.
						encodeValue(GetUINT(buffer + 10, bigEndian_), 16, 8);
						if (PRINT_DEBUG) printMessage(buffer, size, 7, 1, 1+MAGIC_SIZE, 2, 4, 2,
								2, -1);
					}
						break;
					case X_QueryColors: {
						unsigned int numColors = ((size - 32) >> 3);
						const unsigned char *nextSrc = buffer + 40;
						unsigned char *nextDest = (unsigned char *) buffer + 38;
						for (unsigned int c = 1; c < numColors; c++) {
							for (unsigned int i = 0; i < 6; i++)
								*nextDest++ = *nextSrc++;
							nextSrc += 2;
						}
						unsigned int colorsLength = numColors * 6;

						if (serverCache_.queryColorsLastReply.
						compare(colorsLength, buffer + 32))
							encodeBuffer.encodeValue(1, 1);
						else {
							const unsigned char *nextSrc = buffer + 32;

							encodeBuffer.encodeValue(0, 1);
							encodeBuffer.encodeValue(numColors, 16, 5);
							for (numColors *= 3; numColors; numColors--) {
								encodeBuffer.
								encodeValue(GetUINT(nextSrc, bigEndian_), 16);
								nextSrc += 2;
							}
						}
						if (requestData[0]) {
							specialReply = 1;
							if (!replay) {
								if (PRINT_DEBUG)
									cout <<"Special QueryColors reply."<<endl;
								eventQueue_.recordReply(buffer, size);
							} else {
								unsigned int aSize;
								aSize = eventQueue_.replayReply();
#ifndef FILE_REPLAY
								if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getReplyBuffer(), aSize) != aSize)
									cerr
											<< "Cannot write to x app for special queryColor."
											<<endl;
#endif
								if (PRINT_DEBUG)
									cout
											<< "This is a special reply, send recorded message to the application instead. GetProperty:recorded size:"
											<<aSize<< ", actual size:"<<size
											<<endl;
								if (PRINT_DEBUG)
									cout <<"recorded message is "<<endl;
								if (PRINT_DEBUG) printMessage(eventQueue_.getReplyBuffer(),
										aSize, 8, 1, 1, 2, 4, 4, 4, 4, 12
												+MAGIC_SIZE);

							}
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 6, 1, 1+MAGIC_SIZE, 2, 4, 2,
								22+MAGIC_SIZE);
					}
						break;
					case X_QueryExtension: {
						// requestData[0] will be nonzero if the request is for
						// an extension that dxpc should hide, like MIT-SHM
						if (requestData[0]) {
							buffer[8] = 0;
							buffer[9] = 0;
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 9, 1, 1+MAGIC_SIZE, 2, 4, 1,
								1, 1, 1, 20+MAGIC_SIZE);
					}
						break;
					case X_QueryFont: {
						unsigned int numProperties = GetUINT(buffer + 46,
								bigEndian_);
						unsigned int numCharInfos = GetULONG(buffer + 56,
								bigEndian_);
						encodeBuffer.encodeValue(numProperties, 16, 8);
						encodeBuffer.encodeValue(numCharInfos, 32, 10);
						encodeCharInfo_(buffer + 8, encodeBuffer);
						encodeCharInfo_(buffer + 24, encodeBuffer);
						encodeBuffer.
						encodeValue(GetUINT(buffer + 40, bigEndian_), 16, 9);
						encodeBuffer.
						encodeValue(GetUINT(buffer + 42, bigEndian_), 16, 9);
						encodeBuffer.
						encodeValue(GetUINT(buffer + 44, bigEndian_), 16, 9);
						encodeBuffer.
						encodeValue((unsigned int) buffer[48], 1);
						encodeBuffer.
						encodeValue((unsigned int) buffer[49], 8);
						encodeBuffer.
						encodeValue((unsigned int) buffer[50], 8);
						encodeBuffer.
						encodeValue((unsigned int) buffer[51], 1);
						encodeBuffer.
						encodeValue(GetUINT(buffer + 52, bigEndian_), 16, 9);
						encodeBuffer.
						encodeValue(GetUINT(buffer + 54, bigEndian_), 16, 9);
						unsigned char *nextSrc = buffer + 60;
						unsigned int index;

						if (ServerCache::queryFontFontCache.
						lookup(numProperties * 8 + numCharInfos * 12, nextSrc,
								index)) {
							encodeBuffer.encodeValue(1, 1);
							encodeBuffer.encodeValue(index, 4);
							break;
						}
						encodeBuffer.encodeValue(0, 1);
						for (; numProperties; numProperties--) {
							if (replay)
								//atom
								PutULONG(idMap->atomMapToOld(GetULONG(nextSrc,
										bigEndian_)), nextSrc, bigEndian_);
							nextSrc += 8;
						}
						for (; numCharInfos; numCharInfos--) {
							encodeCharInfo_(nextSrc, encodeBuffer);
							nextSrc += 12;
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 19, 1, 1+MAGIC_SIZE, 2, 4,
								12, 4+MAGIC_SIZE, 12, 4+MAGIC_SIZE, 2, 2, 2, 2,
								1, 1, 1, 1, 2, 2, 4);

					}
						break;
					case X_QueryPointer: {
						specialReply = 1;
						unsigned int child = GetULONG(buffer + 12, bigEndian_);
						if (!replay) {
							eventQueue_.recordReply(buffer, size);
						} else {
							eventQueue_.replayReply();
#ifndef FILE_REPLAY
							if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getReplyBuffer(), 32) != 32)
								cerr << "Cannot write to application."<<endl;
#endif
							if (child) {
								idMap->addSpecialMap(GetULONG(
										eventQueue_.getReplyBuffer() + 12,
										bigEndian_), child);
							}
							if (PRINT_DEBUG)
								cout
										<< "This is a special reply (QueryPointer), send recorded message to the application instead."
										<<endl;
							if (PRINT_DEBUG)
								cout <<"recorded message is"<<endl;
							if (PRINT_DEBUG) printMessage(eventQueue_.getReplyBuffer(), 32, 12,
									1, 1, 2, 4, 4, 4, 2, 2, 2, 2, 2, -1);
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 12, 1, 1, 2, 4, 4, 4, 2, 2,
								2, 2, 2, -1);
					}
						break;
					case X_QueryTree: {
						specialReply = 1;

						if (replay) {
							unsigned int aSize = eventQueue_.replayReply();
#ifndef FILE_REPLAY
							// this is buggy, as we shouldn't send replayBuffer back
							if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getReplyBuffer(), aSize) != aSize)
								cerr << "Cannot write to application."<<endl;
#endif
							if (PRINT_DEBUG)
								cout <<"This is a special reply, queryTree"
										<<endl;
							if (PRINT_DEBUG)
								cout <<"the recorded message is "<<endl;
							if (PRINT_DEBUG) printMessage(eventQueue_.getReplyBuffer(), aSize,
									8, 1, 1+MAGIC_SIZE, 2, 4, 4, 4, 2, 14
											+MAGIC_SIZE);

							PutULONG(idMap->mapToOld(GetULONG(buffer + 8,
									bigEndian_)), buffer + 8, bigEndian_);
							PutULONG(idMap->mapToOld(GetULONG(buffer + 12,
									bigEndian_)), buffer + 12, bigEndian_);
							/*for (unsigned int i = 32; i < size; i+=4)
							 PutULONG(idMap->mapToOld(GetULONG(buffer + i,
							 bigEndian_)), buffer + i, bigEndian_);*/

						} else {
							eventQueue_.recordReply(buffer, size);
						}

						if (PRINT_DEBUG) printMessage(buffer, size, 8, 1, 1+MAGIC_SIZE, 2, 4, 4,
								4, 2, 14+MAGIC_SIZE);
					}
						break;
					case X_TranslateCoords: {
						specialReply = 1;

						unsigned int child = GetULONG(buffer + 8, bigEndian_);
						if (replay & child) {
							idMap->addSpecialMap(GetULONG(
									eventQueue_.getReplyBuffer() + 8,
									bigEndian_), child);
						}
						if (!replay) {
							eventQueue_.recordReply(buffer, size);
						} else {
							eventQueue_.replayReply();
#ifndef FILE_REPLAY
							if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getReplyBuffer(), 32) != 32)
								cerr << "Cannot write to application."<<endl;
#endif
							if (PRINT_DEBUG)
								cout <<"recorded message is"<<endl;
							if (PRINT_DEBUG) printMessage(eventQueue_.getReplyBuffer(), size, 8,
									1, 1, 2, 4, 4, 2, 2, -1);
							if (PRINT_DEBUG)
								cout
										<< "This is a special reply, send recorded message to the application instead."
										<<endl;
						}

						if (PRINT_DEBUG) printMessage(buffer, size, 8, 1, 1, 2, 4, 4, 2, 2, -1);
					}
						break;
						//starting point for additional message support 
						//reply not compressed yet
					case X_ListFontsWithInfo: {
						if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2, 4);
						// this is not the last reply in series, so add more sequence number here. 
						if (nextOpcode == X_ListFontsWithInfo && buffer[1])
							sequenceNumQueue_.push(sequenceNum, nextOpcode);
					}
						break;
					case X_GetImage: {
						if (replay)
							PutULONG(idMap->mapToOld(GetULONG(buffer + 8,
									bigEndian_)), buffer + 8, bigEndian_);
						if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2, 4);
					}
						break;

					case XE_Composite:
					case XE_DAMAGE:
					case XE_XINERAMA:
					case XE_DRI2:
					case XE_SGI_GLX: {
						if (PRINT_DEBUG)
							cout<<"           ***not compressed"<<endl;
						if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2, 4);
					}
						break;
						//starting point for x extensions parsing
						//compressed
					case XE_SHAPE: {
						switch (requestData[0]) {
						case X_ShapeQueryVersion: {
							//do nothing
						}
							break;
						default: {
							if (PRINT_DEBUG)
								cout<<"           ***not compressed"<<endl;
						}
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2, 4);
					}
						break;
					case XE_SYNC: {
						switch (requestData[0]) {
						case X_SyncInitialize:
						case X_SyncDestroyCounter: {
							// do nothing
						}
							break;
						default: {
							if (PRINT_DEBUG)
								cout<<"           ***not compressed"<<endl;
						}
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2);
					}
						break;
					case XE_XFIXES: {
						switch (requestData[0]) {
						case X_XFixesQueryVersion: {
							// do nothing
						}
							break;
						default: {
							if (PRINT_DEBUG)
								cout<<"           ***not compressed"<<endl;
						}
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2);
					}
						break;
					case XE_MIT_SHM: {
						//cout <<"          *** not compressed"<<endl;
						if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2, 4);
					}
						break;
					case XE_XKEYBOARD: {
						switch (requestData[0]) {
						case X_kbUseExtension:
						case X_kbSelectEvents:
						case X_kbGetNames:
						case X_kbPerClientFlags: {
							// do nothing
						}
							break;

						case X_kbGetMap: {
							specialReply = 1;
							if (!replay) {
								eventQueue_.recordReply(buffer, size);
							} else {
								//this is different, we will send the original reply back to the application, and remember the mapped window id
								unsigned int asize = eventQueue_.replayReply();
#ifndef FILE_REPLAY
								if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getReplyBuffer(), asize) != asize)
									cerr << "Cannot write to application."<<endl;
#endif
								if (PRINT_DEBUG)
									cout <<"recorded message is "<<endl;
								if (PRINT_DEBUG) printMessage(eventQueue_.getReplyBuffer(), size, 6,
										1, 1+MAGIC_SIZE, 2, 4, 4, -1);
								if (PRINT_DEBUG)
									cout
										<< "This is a special reply, send recorded message to the application instead."
										<<endl;
							}

						}
								 break;
						default: {
							if (PRINT_DEBUG)
								cout<<"           ***not compressed"<<endl;
						}
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2);
					}
						break;

					case XE_EVENT_EXTENSION: {
						if (PRINT_DEBUG) printMessage(buffer, size, 5, 1, 1, 2, 2, 2);
					}
						break;

					case XE_XInputExtension: {
						switch (requestData[0]) {
						case X_GetExtensionVersion:
						case X_ListInputDevices:
						case X_OpenDevice: {
							//do nothing
							// not sure about opendevice
						}
							break;
						default: {
							if (PRINT_DEBUG)
								cout<<"           ***not compressed"<<endl;
						}
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2, 4);

					}
						break;
					case XE_BIG_REQUESTS: {
						encodeBuffer.encodeValue(GetULONG(buffer + 8,
								bigEndian_), 32);
						if (PRINT_DEBUG) printMessage(buffer, size, 6, 1, 1+MAGIC_SIZE, 2, 4, 4,
								-1);
					}
						break;
					case XE_RENDER: {
						switch (requestData[0]) {
						case X_RenderQueryVersion:
						case X_RenderQueryPictFormats: {
							// do nothing
						}
							break;
						default: {
							if (PRINT_DEBUG)
								cout<<"           ***not compressed"<<endl;
						}
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2);
					}
						break;
					case XE_RANDR: {
						switch (requestData[0]) {
						case X_RRQueryVersion:
						case X_RRGetScreenSizeRange:
						case X_RRListOutputProperties: {
							//do nothing
						}
							break;
							/*case X_RRGetScreenInfo: {
							 if (replay) {
							 // window id, 4-8
							 PutULONG(idMap->mapToNew(GetULONG(buffer + 4,
							 bigEndian_)), buffer + 4, bigEndian_);
							 }
							 if (PRINT_DEBUG) printMessage(buffer, size, 3, 1, 1, 2);
							 }
							 break;*/
						case X_RRGetOutputInfo:
						case X_RRGetCrtcInfo:
						case X_RRGetScreenResourcesCurrent: {
							if (PRINT_DEBUG)
								cout
										<< "X_RRGetOutputInfo/X_RRGetCrtcInfo/X_RRGetScreenResourcesCurrent, may be an error."
										<<endl;
						}
							break;
						case X_RRGetOutputPrimary: {
							if (replay)
								PutULONG(idMap->mapToOld(GetULONG(buffer + 8,
										bigEndian_)), buffer + 8, bigEndian_);
						}
							break;
						default: {
							if (PRINT_DEBUG)
								cout<<"           ***not compressed"<<endl;
							if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2, 4);
						}
						}
						if (PRINT_DEBUG) printMessage(buffer, size, 4, 1, 1, 2, 4);
					}
						break;
					default: {
						CERR <<
						"assertion failed in ServerXReader::processMessage():\n"
						<<
						" no matching request for reply with sequence number "
						<< sequenceNum << ENDL;
					}
					}
				} else {
					cout
							<<"reply (non-recognized not compressed) (error message) sequence:"
							<<sequenceNum <<" size:"<<size<<endl;
					if (!PRINT_DEBUG)
						printString(buffer, size);
					encodeBuffer.encodeValue(buffer[1], 8);
					encodeBuffer.encodeValue(GetULONG(buffer + 4, bigEndian_),
							32);
					for (unsigned int i = 8; i < size; i++)
						encodeBuffer.encodeValue((unsigned int) buffer[i], 8);
				}
				if (!specialReply) {
					//replay log
					if (replay) {
						//replay
						try {
							if (PRINT_DEBUG) replayBuffer = new unsigned char[size];
							if (PRINT_DEBUG) replyFile_.read((char*)replayBuffer, size);
						} catch (fstream::failure e) {
							cerr << "Exception reading files in ServerChannel.c"<<endl;
						}
					} else {
						// recording
						try {
							if (PRINT_DEBUG) replyFile_.write ((char*) buffer, size);
						} catch (fstream::failure e) {
							cerr << "Exception writing files in ServerChannel.c"<<endl;
						}
						//			*outputLength_ += size;
					}
				}
				*outputLength_ += 1;
				replyStats_.add(requestOpcode, size << 3,
						encodeBuffer.getCumulativeBitsWritten());
			} else {
				// event or error
				unsigned int sequenceNum = GetUINT(buffer + 2, bigEndian_);
				unsigned int sequenceNumDiff = sequenceNum
						- serverCache_.lastSequenceNum;
				serverCache_.lastSequenceNum = sequenceNum;
				unsigned int opcode = (unsigned int) *buffer;

				encodeBuffer.encodeCachedValue(opcode, 8, serverCache_.
				opcodeCache[serverCache_.
				lastOpcode]);
				serverCache_.lastOpcode = opcode;
				encodeBuffer.encodeCachedValue(sequenceNumDiff, 16,
						serverCache_.
						eventSequenceNumCache, 7);

				// check if this is an error that matches a sequence number for
				// which we were expecting a reply

				unsigned short int dummySequenceNum;
				unsigned char dummyOpcode;

				/*				if (convert_log) {
				 sequenceNumQueue_.peek(dummySequenceNum, dummyOpcode);
				 if (dummySequenceNum < sequenceNum) {
				 readBuffer_.rollBack(size);
				 cout <<"event need to roll back, we need seq:"
				 <<sequenceNum<<" cur seq:"
				 <<dummySequenceNum<<endl;
				 return 1;
				 }
				 }
				 */
				if (buffer[0] == 0) {
					cout <<"Got An error message from x server."<<endl;
					if (PRINT_DEBUG) printMessage (buffer, size, 7, 1, 1, 2, 4, 2, 1, -1);
					if (sequenceNumQueue_.peek(dummySequenceNum, dummyOpcode)
							&& ((unsigned int) dummySequenceNum == sequenceNum))
						sequenceNumQueue_.pop(dummySequenceNum, dummyOpcode);
				}
				if (PRINT_DEBUG) {
					cout <<"event   opcode:"<<opcode<<"  sequence:"
							<<sequenceNum <<"  size:"<<size<<endl;
					printString (buffer, size);
				}

				//replay log
				if (replay) {
					//replay
					try {
						if (buffer[0] == 0) {
							int errorSeq = GetUINT (buffer + 2, bigEndian_);
							int recordedSeq;
							if (eventQueue_.getErrorBuffer())
							recordedSeq = GetUINT (eventQueue_.getErrorBuffer() + 2, bigEndian_);
							else
							recordedSeq = -1;
							if (recordedSeq == errorSeq) {
								cout <<"Get an recorded error message."<<endl;
#ifndef FILE_REPLAY
								if ((unsigned int) SOCKWRITE (appFD, eventQueue_.getErrorBuffer(), 32) != 32)
								cerr << "Cannot write to application."<<endl;
#endif
								eventQueue_.replayError();
								if (PRINT_DEBUG) printMessage (buffer, size, 7, 1, 1, 2, 4, 2, 1, -1);
								*outputLength_ += 1;
							} else {
								cout <<"Get an error message from x server!"<<endl;
								cerr << "Get an error message from x server!"<<endl;
								if (!PRINT_DEBUG) printString (buffer, size);
								if (PRINT_DEBUG) printMessage (buffer, size, 7, 1, 1, 2, 4, 2, 1, -1);
							}
						} else {
							if (PRINT_DEBUG) cout <<"Get an event message from x server, skip. outputLength:"<<*outputLength_<<", current pos:"<<eventQueue_.getEventPos()<<endl;
							if (PRINT_DEBUG) printString (buffer, size);
							//outputLength_ += size;
						}
					} catch (fstream::failure e) {
						cerr << "Exception reading files in ServerChannel.c"<<endl;
					}

				} else {
					// recording
					try {
						if (buffer[0] != 0) {
							eventQueue_.recordEvent (*outputLength_, buffer);
						} else {
							eventQueue_.recordError(buffer, size);
						}
					} catch (fstream::failure e) {
						cerr << "Exception writing files in ServerChannel.c"<<endl;
					}
					*outputLength_ += 1;
				}

				switch (*buffer) {
				case 0: {
					unsigned char code = buffer[1];

					encodeBuffer.encodeCachedValue(code, 8, serverCache_.
					errorCodeCache);
					if ((code != 11) && (code != 8) && (code != 15) && (code
							!= 1))
						encodeBuffer.
						encodeValue(GetULONG(buffer + 4, bigEndian_), 32, 16);
					if (code >= 18)
						encodeBuffer.
						encodeCachedValue(GetUINT(buffer + 8, bigEndian_), 16,
								serverCache_.
								errorMinorCache);
					encodeBuffer.encodeCachedValue(buffer[10], 8, serverCache_.
					errorMajorCache);
					if (code >= 18) {
						const unsigned char *nextSrc = buffer + 11;

						for (unsigned int i = 11; i < 32; i++)
							encodeBuffer.encodeValue(*nextSrc++, 8);
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
					unsigned char detail = buffer[1];

					if (*buffer == MotionNotify)
						encodeBuffer.encodeValue((unsigned int) detail, 1);
					else if ((*buffer == EnterNotify) || (*buffer
							== LeaveNotify))
						encodeBuffer.encodeValue((unsigned int) detail, 3);
					else if (*buffer == KeyRelease) {
						if (detail == serverCache_.keyPressLastKey)
							encodeBuffer.encodeValue(1, 1);
						else {
							encodeBuffer.encodeValue(0, 1);
							encodeBuffer.
							encodeValue((unsigned int) detail, 8);
						}
					} else if ((*buffer == ButtonPress) || (*buffer
							== ButtonRelease))
						encodeBuffer.encodeCachedValue(detail, 8, serverCache_.
						buttonCache);
					else
						encodeBuffer.encodeValue((unsigned int) detail, 8);
					unsigned int timestamp = GetULONG(buffer + 4, bigEndian_);
					unsigned int timestampDiff = timestamp
							- serverCache_.lastTimestamp;
					serverCache_.lastTimestamp = timestamp;
					encodeBuffer.encodeCachedValue(timestampDiff, 32,
							serverCache_.
							motionNotifyTimestampCache, 9);
					int skipRest = 0;

					if (*buffer == KeyRelease) {
						skipRest = 1;
						for (unsigned int i = 8; i < 31; i++) {
							if (buffer[i] != serverCache_.keyPressCache[i - 8]) {
								skipRest = 0;
								break;
							}
						}
						encodeBuffer.encodeValue(skipRest, 1);
					}
					if (!skipRest) {
						const unsigned char *nextSrc = buffer + 8;

						for (unsigned int i = 0; i < 3; i++) {
							encodeBuffer.
							encodeCachedValue(GetULONG(nextSrc, bigEndian_),
									29, *serverCache_.
									motionNotifyWindowCache
									[i], 6);
							nextSrc += 4;
						}
						unsigned int rootX = GetUINT(buffer + 20, bigEndian_);
						unsigned int rootY = GetUINT(buffer + 22, bigEndian_);
						unsigned int eventX = GetUINT(buffer + 24, bigEndian_);
						unsigned int eventY = GetUINT(buffer + 26, bigEndian_);
						eventX -= rootX;
						eventY -= rootY;
						encodeBuffer.encodeCachedValue(rootX - serverCache_.
						motionNotifyLastRootX, 16, serverCache_.
						motionNotifyRootXCache, 6);
						serverCache_.motionNotifyLastRootX = rootX;
						encodeBuffer.encodeCachedValue(rootY - serverCache_.
						motionNotifyLastRootY, 16, serverCache_.
						motionNotifyRootYCache, 6);
						serverCache_.motionNotifyLastRootY = rootY;
						encodeBuffer.encodeCachedValue(eventX, 16,
								serverCache_.
								motionNotifyEventXCache, 6);
						encodeBuffer.encodeCachedValue(eventY, 16,
								serverCache_.
								motionNotifyEventYCache, 6);
						encodeBuffer.
						encodeCachedValue(GetUINT(buffer + 28, bigEndian_), 16,
								serverCache_.
								motionNotifyStateCache);
						if ((*buffer == EnterNotify)
								|| (*buffer == LeaveNotify))
							encodeBuffer.
							encodeValue((unsigned int) buffer[30], 2);
						else
							encodeBuffer.
							encodeValue((unsigned int) buffer[30], 1);
						if ((*buffer == EnterNotify)
								|| (*buffer == LeaveNotify))
							encodeBuffer.
							encodeValue((unsigned int) buffer[31], 2);
						else if (*buffer == KeyPress) {
							serverCache_.keyPressLastKey = detail;
							for (unsigned int i = 8; i < 31; i++) {
								serverCache_.keyPressCache[i - 8] = buffer[i];
							}
						}
					}
					/*if (PRINT_DEBUG) printMessage (buffer, size, 14, 1, 1, 2, 4, 4, 
					 4, 4, 2, 2, 2, 
					 2, 2, 1, 1);*/

				}
					break;
				case ColormapNotify: {
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
							serverCache_.
							colormapNotifyWindowCache, 8);
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
							serverCache_.
							colormapNotifyColormapCache, 8);
					encodeBuffer.encodeValue((unsigned int) buffer[12], 1);
					encodeBuffer.encodeValue((unsigned int) buffer[13], 1);
				}
					break;
				case ConfigureNotify: {
					const unsigned char *nextSrc = buffer + 4;

					for (unsigned int i = 0; i < 3; i++) {
						encodeBuffer.
						encodeCachedValue(GetULONG(nextSrc, bigEndian_), 29,
								*serverCache_.
								configureNotifyWindowCache
								[i], 9);
						nextSrc += 4;
					}
					for (unsigned int j = 0; j < 5; j++) {
						encodeBuffer.
						encodeCachedValue(GetUINT(nextSrc, bigEndian_), 16,
								*serverCache_.
								configureNotifyGeomCache[j], 8);
						nextSrc += 2;
					}
					encodeBuffer.encodeValue(*nextSrc, 1);
					/*if (PRINT_DEBUG) printMessage (buffer, size, 13, 1, 1+MAGIC_SIZE, 2, 4, 4, 
					 4, 2, 2, 2, 2, 
					 2, 1, -1);*/
				}
					break;
				case CreateNotify: {
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
							serverCache_.
							createNotifyWindowCache, 9);
					unsigned int window = GetULONG(buffer + 8, bigEndian_);
					encodeBuffer.encodeValue(window - serverCache_.
					createNotifyLastWindow, 29, 5);
					serverCache_.createNotifyLastWindow = window;
					const unsigned char *nextSrc = buffer + 12;

					for (unsigned int i = 0; i < 5; i++) {
						encodeBuffer.
						encodeValue(GetUINT(nextSrc, bigEndian_), 16, 9);
						nextSrc += 2;
					}
					encodeBuffer.encodeValue((unsigned int) *nextSrc, 1);
				}
					break;
				case Expose: {
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
							serverCache_.exposeWindowCache, 9);
					const unsigned char *nextSrc = buffer + 8;

					for (unsigned int i = 0; i < 5; i++) {
						encodeBuffer.
						encodeCachedValue(GetUINT(nextSrc, bigEndian_), 16,
								*serverCache_.
								exposeGeomCache[i], 6);
						nextSrc += 2;
					}
					/*if (PRINT_DEBUG) printMessage (buffer, size, 10, 1, 1+MAGIC_SIZE, 2, 4, 2, 
					 2, 2, 2, 2, -1);*/
				}
					break;
				case FocusIn:
				case FocusOut: {
					encodeBuffer.encodeValue((unsigned int) buffer[1], 3);
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
							serverCache_.focusInWindowCache, 9);
					encodeBuffer.encodeValue((unsigned int) buffer[8], 2);
				}
					break;
				case KeymapNotify: {
					if (ServerCache::lastKeymap.compare(31, buffer + 1))
						encodeBuffer.encodeValue(1, 1);
					else {
						encodeBuffer.encodeValue(0, 1);
						const unsigned char *nextSrc = buffer + 1;

						for (unsigned int i = 1; i < 32; i++)
							encodeBuffer.
							encodeValue((unsigned int) *nextSrc++, 8);
					}
				}
					break;
				case MapNotify:
				case UnmapNotify:
				case DestroyNotify: {
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
							serverCache_.
							mapNotifyEventCache, 9);
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
							serverCache_.
							mapNotifyWindowCache, 9);
					if ((*buffer == MapNotify) || (*buffer == UnmapNotify))
						encodeBuffer.
						encodeValue((unsigned int) buffer[12], 1);
					/*if (*buffer == UnmapNotify)
					 if (PRINT_DEBUG) printMessage (buffer, size, 7, 1, 1+MAGIC_SIZE, 2, 4, 4, 
					 1, -1);
					 else if (*buffer == MapNotify)
					 if (PRINT_DEBUG) printMessage (buffer, size, 4, 1, 1+MAGIC_SIZE, 2, -1);*/
				}
					break;
				case NoExpose: {
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
							serverCache_.
							noExposeDrawableCache, 9);
					encodeBuffer.
					encodeCachedValue(GetUINT(buffer + 8, bigEndian_), 16,
							serverCache_.
							noExposeMinorCache);
					encodeBuffer.encodeCachedValue(buffer[10], 8, serverCache_.
					noExposeMajorCache);
				}
					break;
				case PropertyNotify: {
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
							serverCache_.
							propertyNotifyWindowCache, 9);
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
							serverCache_.
							propertyNotifyAtomCache, 9);
					unsigned int timestamp = GetULONG(buffer + 12, bigEndian_);
					unsigned int timestampDiff = timestamp
							- serverCache_.lastTimestamp;
					serverCache_.lastTimestamp = timestamp;
					encodeBuffer.encodeValue(timestampDiff, 32, 9);
					encodeBuffer.encodeValue((unsigned int) buffer[16], 1);
					/*if (PRINT_DEBUG) printMessage (buffer, size, 8, 1, 1+MAGIC_SIZE, 2, 4, 4, 
					 4, 1, -1);*/
				}
					break;
				case ReparentNotify: {
					const unsigned char *nextSrc = buffer + 4;

					for (unsigned int i = 0; i < 3; i++) {
						encodeBuffer.
						encodeCachedValue(GetULONG(nextSrc, bigEndian_), 29,
								serverCache_.
								reparentNotifyWindowCache, 9);
						nextSrc += 4;
					}
					encodeBuffer.encodeValue(GetUINT(nextSrc, bigEndian_), 16,
							6);
					encodeBuffer.
					encodeValue(GetUINT(nextSrc + 2, bigEndian_), 16, 6);
					encodeBuffer.encodeValue((unsigned int) buffer[20], 1);
					/*if (PRINT_DEBUG) printMessage (buffer, size, 10, 1, 1+MAGIC_SIZE, 2, 4, 4, 
					 4, 2, 2, 1, -1);*/
				}
					break;
				case SelectionClear: {
					unsigned int timestamp = GetULONG(buffer + 4, bigEndian_);
					unsigned int timestampDiff = timestamp
							- serverCache_.lastTimestamp;
					serverCache_.lastTimestamp = timestamp;
					encodeBuffer.encodeValue(timestampDiff, 32, 9);
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
							serverCache_.
							selectionClearWindowCache, 9);
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 12, bigEndian_), 29,
							serverCache_.
							selectionClearAtomCache, 9);
				}
					break;
				case SelectionRequest: {
					unsigned int timestamp = GetULONG(buffer + 4, bigEndian_);
					unsigned int timestampDiff = timestamp
							- serverCache_.lastTimestamp;
					serverCache_.lastTimestamp = timestamp;
					encodeBuffer.encodeValue(timestampDiff, 32, 9);
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 8, bigEndian_), 29,
							serverCache_.
							selectionClearWindowCache, 9);
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 12, bigEndian_), 29,
							serverCache_.
							selectionClearWindowCache, 9);
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 16, bigEndian_), 29,
							serverCache_.
							selectionClearAtomCache, 9);
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 20, bigEndian_), 29,
							serverCache_.
							selectionClearAtomCache, 9);
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 24, bigEndian_), 29,
							serverCache_.
							selectionClearAtomCache, 9);
				}
					break;
				case VisibilityNotify: {
					encodeBuffer.
					encodeCachedValue(GetULONG(buffer + 4, bigEndian_), 29,
							serverCache_.
							visibilityNotifyWindowCache, 9);
					encodeBuffer.encodeValue((unsigned int) buffer[8], 2);
				}
					break;
				default: {
					encodeBuffer.encodeValue(buffer[1], 8);
					for (unsigned int i = 4; i < size; i++)
						encodeBuffer.encodeValue((unsigned int) buffer[i], 8);
				}
				}
				stats_.add(*buffer, size << 3,
						encodeBuffer.getCumulativeBitsWritten());
			}
		}
		if (replay) {
			// set up resource mask and base
			if (buffer[0] == 1) {
				if (!specialReply) {
#ifndef FILE_REPLAY

					if ((unsigned int) SOCKWRITE (appFD, buffer, size) != size)
						cerr << "Cannot write to application."<<endl;
#endif
					if (PRINT_DEBUG) {
						if (memcmp(buffer, replayBuffer, size) != 0) {
							cout
									<< " Different reply message with recording! error"
									<<endl;
							cout <<"		From log:";
							for (unsigned int i = 0; i < (firstReply_ ? 40
									: size); ++i)
								cout <<(unsigned int) replayBuffer[i] <<",";
							cout <<endl;
							cout <<"		From x server:";
							for (unsigned int i = 0; i < (firstReply_ ? 40
									: size); ++i)
								cout <<(unsigned int) buffer[i] <<",";
							cout <<endl;
							detailedCompare(replayBuffer, size, buffer, size);
						}
					}
				}

			} else {
				// we don't send event messages to the application as we have the event queue;
				// but remember to sent the application the recorded error messages!
				//cout <<"This is an event message from x server, don't send to application."<<endl;
			}
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
		} else {
#ifdef CONVERT
			unsigned int ret;
			unsigned int count = 0;
			if (size> 512) {
				//the socket may block
				int flags = fcntl(appFD, F_GETFL, 0);
				if (flags < 0)
				cerr<<"fcntl fails"<<endl;
				flags = flags &~O_NONBLOCK;
				fcntl(appFD, F_SETFL, flags);
				if (flags < 0)
				cerr<<"fcntl fails"<<endl;
				if ((ret = (unsigned int) SOCKWRITE (appFD, buffer, size)) != size)
				cerr << "Cannot write to application, expected:"<<size
				<<"returned:"<<ret<<endl;
				flags = flags | O_NONBLOCK;
				fcntl(appFD, F_SETFL, flags);
				if (flags < 0)
				cerr<<"fcntl fails"<<endl;
			} else {
				if ((ret = (unsigned int) SOCKWRITE (appFD, buffer, size)) != size)
				cerr << "Cannot write to application, expected:"<<size
				<<"returned:"<<ret<<endl;
			}
			/*while (count < size) {
			 ret = (unsigned int) SOCKWRITE (appFD, buffer + count, size - count);
			 if (ret > 0)
			 count += ret;
			 if (count != size)
			 cerr << "Cannot write to application, try again expected:"
			 <<size <<"returned:"<<ret<<endl;
			 }*/
#else
			unsigned int ret;
			if ((ret = (unsigned int) SOCKWRITE (appFD, buffer, size)) != size)
				cerr << "Cannot write to application, expected:"<<size
						<<"returned:"<<ret<<endl;
#endif
		}
	}
	return 1;
}

int ServerChannel::doWrite(const unsigned char *message, unsigned int length,
		SequenceNumQueue & sequenceNumQueue_) {
	writeBuffer_.reset();

	// uncompress messages
	DecodeBuffer decodeBuffer(message, length);

	if (firstRequest_) {
		unsigned char *outputMessage = writeBuffer_.addMessage(length);
		unsigned char *nextDest = outputMessage;

		for (unsigned int i = 0; i < length; i++) {
			unsigned int nextByte;

			decodeBuffer.decodeValue(nextByte, 8);
			*nextDest++ = (unsigned char) nextByte;
		}
		if (*outputMessage == 0x42)
			setBigEndian(1);
		else
			setBigEndian(0);
		firstRequest_ = 0;
		if (replay_debug)
			cout <<"first request message size:"<<length<<endl;
	} else {
		unsigned char opcode;

		while (decodeBuffer.decodeCachedValue(opcode, 8, clientCache_.
		opcodeCache[clientCache_.
		lastOpcode], 8, 1)) {
			clientCache_.lastOpcode = opcode;
			clientCache_.lastRequestSequenceNum++;
			unsigned char *outputMessage;
			unsigned int outputLength;
			unsigned int value; // general-purpose temp variable for decoding ints

			unsigned char cValue; // general-purpose temp variable for decoding chars

			switch (opcode) {
			case X_AllocColor: {
				outputLength = 16;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.colormapCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				unsigned char *nextDest = outputMessage + 8;
				unsigned int colorData[3];

				for (unsigned int i = 0; i < 3; i++) {
					decodeBuffer.decodeCachedValue(value, 16, *(clientCache_.
					allocColorRGBCache
					[i]), 4);
					PutUINT(value, nextDest, bigEndian_);
					colorData[i] = value;
					nextDest += 2;
				}
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode, colorData[0], colorData[1],
						colorData[2]);
			}
				break;
			case X_ChangeProperty: {
				unsigned char format;

				decodeBuffer.decodeCachedValue(format, 8, clientCache_.
				changePropertyFormatCache);
				unsigned int dataLength;

				decodeBuffer.decodeValue(dataLength, 32, 6);
				outputLength = 24 + RoundUp4(dataLength * (format >> 3));
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 2);
				outputMessage[1] = (unsigned char) value;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.
				changePropertyPropertyCache, 9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.
				changePropertyTypeCache, 9);
				PutULONG(value, outputMessage + 12, bigEndian_);
				outputMessage[16] = format;
				PutULONG(dataLength, outputMessage + 20, bigEndian_);
				unsigned char *nextDest = outputMessage + 24;

				if (format == 8) {
					clientCache_.changePropertyTextCompressor.reset();
					for (unsigned int i = 0; i < dataLength; i++)
						*nextDest++
								= clientCache_.changePropertyTextCompressor.
								decodeChar(decodeBuffer);
				} else if (format == 32) {
					for (unsigned int i = 0; i < dataLength; i++) {
						decodeBuffer.decodeCachedValue(value, 32, clientCache_.
						changePropertyData32Cache);
						PutULONG(value, nextDest, bigEndian_);
						nextDest += 4;
					}
				} else {
					for (unsigned int i = 0; i < dataLength; i++) {
						decodeBuffer.decodeValue(value, 16);
						PutUINT(value, nextDest, bigEndian_);
						nextDest += 2;
					}
				}
			}
				break;
			case X_ChangeWindowAttributes: {
				unsigned int numAttrs;

				decodeBuffer.decodeValue(numAttrs, 4);
				outputLength = 12 + (numAttrs << 2);
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				unsigned int bitmask;

				decodeBuffer.decodeCachedValue(bitmask, 15, clientCache_.
				createWindowBitmaskCache);
				PutULONG(bitmask, outputMessage + 8, bigEndian_);
				unsigned char *nextDest = outputMessage + 12;
				unsigned int mask = 0x1;

				for (unsigned int i = 0; i < 15; i++) {
					if (bitmask & mask) {
						decodeBuffer.decodeCachedValue(value, 32,
								*clientCache_.
								createWindowAttrCache
								[i]);
						PutULONG(value, nextDest, bigEndian_);
						nextDest += 4;
					}
					mask <<= 1;
				}
			}
				break;
			case X_ClearArea: {
				outputLength = 16;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 1);
				outputMessage[1] = (unsigned char) value;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				unsigned char *nextDest = outputMessage + 8;

				for (unsigned int i = 0; i < 4; i++) {
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					clearAreaGeomCache[i], 8);
					PutUINT(value, nextDest, bigEndian_);
					nextDest += 2;
				}
			}
				break;
			case X_CloseFont: {
				outputLength = 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 29, 5);
				clientCache_.lastFont += value;
				clientCache_.lastFont &= 0x1fffffff;
				PutULONG(clientCache_.lastFont, outputMessage + 4, bigEndian_);
			}
				break;
			case X_ConfigureWindow: {
				outputLength = 12;
				outputMessage = writeBuffer_.addMessage(outputLength);
				writeBuffer_.registerPointer(&outputMessage);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				unsigned int bitmask;

				decodeBuffer.decodeCachedValue(bitmask, 7, clientCache_.
				configureWindowBitmaskCache);
				PutUINT(bitmask, outputMessage + 8, bigEndian_);
				unsigned int mask = 0x1;

				for (unsigned int i = 0; i < 7; i++) {
					if (bitmask & mask) {
						unsigned char *nextDest = writeBuffer_.addMessage(4);
						outputLength += 4;
						decodeBuffer.decodeCachedValue(value,
								CONFIGUREWINDOW_FIELD_WIDTH
								[i], *clientCache_.
								configureWindowAttrCache
								[i], 8);
						PutULONG(value, nextDest, bigEndian_);
						nextDest += 4;
					}
					mask <<= 1;
				}
				writeBuffer_.unregisterPointer();
			}
				break;
			case X_ConvertSelection: {
				outputLength = 24;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.
				convertSelectionRequestorCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				unsigned char *nextDest = outputMessage + 8;

				for (unsigned int i = 0; i < 3; i++) {
					decodeBuffer.decodeCachedValue(value, 29, *(clientCache_.
					convertSelectionAtomCache
					[i]), 9);
					PutULONG(value, nextDest, bigEndian_);
					nextDest += 4;
				}
				decodeBuffer.decodeValue(value, 32, 4);
				clientCache_.convertSelectionLastTimestamp += value;
				PutULONG(clientCache_.convertSelectionLastTimestamp, nextDest,
						bigEndian_);
			}
				break;
			case X_CopyArea: {
				outputLength = 28;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 12, bigEndian_);
				unsigned char *nextDest = outputMessage + 16;

				for (unsigned int i = 0; i < 6; i++) {
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					copyAreaGeomCache[i], 8);
					PutUINT(value, nextDest, bigEndian_);
					nextDest += 2;
				}
			}
				break;
			case X_CopyGC: {
				outputLength = 16;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 23, clientCache_.
				createGCBitmaskCache);
				PutULONG(value, outputMessage + 12, bigEndian_);
			}
				break;
			case X_CopyPlane: {
				outputLength = 32;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 12, bigEndian_);
				unsigned char *nextDest = outputMessage + 16;

				for (unsigned int i = 0; i < 6; i++) {
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					copyPlaneGeomCache[i], 8);
					PutUINT(value, nextDest, bigEndian_);
					nextDest += 2;
				}
				decodeBuffer.decodeCachedValue(value, 32, clientCache_.
				copyPlaneBitPlaneCache, 10);
				PutULONG(value, outputMessage + 28, bigEndian_);
			}
				break;
			case X_CreateGC:
			case X_ChangeGC: {
				outputLength = 12;
				if (opcode == X_CreateGC)
					outputLength += 4;
				outputMessage = writeBuffer_.addMessage(outputLength);
				writeBuffer_.registerPointer(&outputMessage);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				unsigned int offset = 8;

				if (opcode == X_CreateGC) {
					decodeBuffer.decodeCachedValue(value, 29, clientCache_.
					drawableCache, 9);
					PutULONG(value, outputMessage + offset, bigEndian_);
					offset += 4;
				}
				unsigned int bitmask;

				decodeBuffer.decodeCachedValue(bitmask, 23, clientCache_.
				createGCBitmaskCache);
				PutULONG(bitmask, outputMessage + offset, bigEndian_);
				unsigned int mask = 0x1;

				for (unsigned int i = 0; i < 23; i++) {
					if (bitmask & mask) {
						unsigned char *nextDest = writeBuffer_.addMessage(4);
						outputLength += 4;
						unsigned int fieldWidth = CREATEGC_FIELD_WIDTH[i];

						if (fieldWidth <= 4)
							decodeBuffer.decodeValue(value, fieldWidth);
						else
							decodeBuffer.decodeCachedValue(value, fieldWidth,
									*clientCache_.
									createGCAttrCache
									[i]);
						PutULONG(value, nextDest, bigEndian_);
					}
					mask <<= 1;
				}
				writeBuffer_.unregisterPointer();
				//if(replay_debug) if (PRINT_DEBUG) printMessage (outputMessage, outputLength, 6, 1, 1+MAGIC_SIZE, 2, 4, 4, 4);
			}
				break;
			case X_CreatePixmap: {
				outputLength = 16;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(cValue, 8,
						clientCache_.depthCache);
				outputMessage[1] = cValue;
				decodeBuffer.decodeValue(value, 1);
				if (!value) {
					decodeBuffer.decodeValue(value, 29, 4);
					clientCache_.createPixmapLastPixmap += value;
					clientCache_.createPixmapLastPixmap &= 0x1fffffff;
				}
				PutULONG(clientCache_.createPixmapLastPixmap,
						outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				createPixmapXCache, 8);
				PutUINT(value, outputMessage + 12, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				createPixmapYCache, 8);
				PutUINT(value, outputMessage + 14, bigEndian_);
			}
				break;
			case X_CreateWindow: {
				outputLength = 32;
				outputMessage = writeBuffer_.addMessage(outputLength);
				writeBuffer_.registerPointer(&outputMessage);
				decodeBuffer.decodeCachedValue(cValue, 8,
						clientCache_.depthCache);
				outputMessage[1] = cValue;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				unsigned char *nextDest = outputMessage + 12;
				unsigned int i;

				for (i = 0; i < 6; i++) {
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					createWindowGeomCache
					[i], 8);
					PutUINT(value, nextDest, bigEndian_);
					nextDest += 2;
				}
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.visualCache);
				PutULONG(value, outputMessage + 24, bigEndian_);
				unsigned int bitmask;

				decodeBuffer.decodeCachedValue(bitmask, 15, clientCache_.
				createWindowBitmaskCache);
				unsigned int newbitmask = bitmask;

				int addBackingStore = 0;
				int wantBackingStore = 0;
				if ((wantBackingStore != NotUseful) && !(bitmask
						& CWBackingStore)) {
					addBackingStore = 1;
					newbitmask |= CWBackingStore;
				}
				PutULONG(newbitmask, outputMessage + 28, bigEndian_);
				unsigned int mask = 0x1;

				for (i = 0; i < 15; i++) {
					if (bitmask & mask) {
						nextDest = writeBuffer_.addMessage(4);
						outputLength += 4;
						decodeBuffer.decodeCachedValue(value, 32,
								*clientCache_.
								createWindowAttrCache
								[i]);
						PutULONG(value, nextDest, bigEndian_);
					} else if (mask == CWBackingStore && addBackingStore) {
						nextDest = writeBuffer_.addMessage(4);
						outputLength += 4;
						PutULONG(wantBackingStore, nextDest, bigEndian_);
					}
					mask <<= 1;
				}
				writeBuffer_.unregisterPointer();
			}
				break;
			case X_DeleteProperty: {
				outputLength = 12;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeValue(value, 29, 9);
				PutULONG(value, outputMessage + 8, bigEndian_);
			}
				break;
			case X_FillPoly: {
				unsigned int numPoints;

				decodeBuffer.decodeCachedValue(numPoints, 14, clientCache_.
				fillPolyNumPointsCache, 4);
				outputLength = 16 + (numPoints << 2);
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeValue(value, 2);
				outputMessage[12] = (unsigned char) value;
				unsigned int relativeCoordMode;

				decodeBuffer.decodeValue(relativeCoordMode, 1);
				outputMessage[13] = (unsigned char) relativeCoordMode;
				unsigned char *nextDest = outputMessage + 16;
				unsigned int pointIndex = 0;

				for (unsigned int i = 0; i < numPoints; i++) {
					if (relativeCoordMode) {
						decodeBuffer.decodeCachedValue(value, 16,
								*clientCache_.
								fillPolyXRelCache
								[pointIndex], 8);
						PutUINT(value, nextDest, bigEndian_);
						nextDest += 2;
						decodeBuffer.decodeCachedValue(value, 16,
								*clientCache_.
								fillPolyYRelCache
								[pointIndex], 8);
						PutUINT(value, nextDest, bigEndian_);
						nextDest += 2;
					} else {
						unsigned int x, y;

						decodeBuffer.decodeValue(value, 1);
						if (value) {
							decodeBuffer.decodeValue(value, 3);
							x = clientCache_.fillPolyRecentX[value];
							y = clientCache_.fillPolyRecentY[value];
						} else {
							decodeBuffer.decodeCachedValue(x, 16,
									*clientCache_.
									fillPolyXAbsCache
									[pointIndex], 8);
							decodeBuffer.decodeCachedValue(y, 16,
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
						PutUINT(x, nextDest, bigEndian_);
						nextDest += 2;
						PutUINT(y, nextDest, bigEndian_);
						nextDest += 2;
					}
					if (pointIndex + 1 < FILL_POLY_MAX_POINTS)
						pointIndex++;
				}
			}
				break;
			case X_FreeColors: {
				unsigned int numPixels;

				decodeBuffer.decodeValue(numPixels, 16, 4);
				outputLength = 12 + (numPixels << 2);
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.colormapCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeValue(value, 32, 4);
				PutULONG(value, outputMessage + 8, bigEndian_);
				unsigned char *nextDest = outputMessage + 12;

				while (numPixels) {
					decodeBuffer.decodeValue(value, 32, 8);
					PutULONG(value, nextDest, bigEndian_);
					nextDest += 4;
					numPixels--;
				}
			}
				break;
			case X_FreeCursor: {
				outputLength = 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.cursorCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
			}
				break;
			case X_FreeGC: {
				outputLength = 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 4, bigEndian_);
			}
				break;
			case X_FreePixmap: {
				outputLength = 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 1);
				if (!value) {
					decodeBuffer.decodeValue(value, 29, 4);
					clientCache_.createPixmapLastPixmap += value;
					clientCache_.createPixmapLastPixmap &= 0x1fffffff;
				}
				PutULONG(clientCache_.createPixmapLastPixmap,
						outputMessage + 4, bigEndian_);
			}
				break;
			case X_GetAtomName: {
				outputLength = 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 29, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_GetGeometry: {
				outputLength = 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_GetInputFocus:
			case X_GetModifierMapping: {
				outputLength = 4;
				outputMessage = writeBuffer_.addMessage(outputLength);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_GetKeyboardMapping: {
				outputLength = 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 8);
				outputMessage[4] = value;
				decodeBuffer.decodeValue(value, 8);
				outputMessage[5] = value;
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_GetProperty: {
				outputLength = 24;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 1);
				outputMessage[1] = (unsigned char) value;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				unsigned int property;

				decodeBuffer.decodeValue(property, 29, 9);
				PutULONG(property, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeValue(value, 29, 9);
				PutULONG(value, outputMessage + 12, bigEndian_);
				decodeBuffer.decodeValue(value, 32, 2);
				PutULONG(value, outputMessage + 16, bigEndian_);
				decodeBuffer.decodeValue(value, 32, 8);
				PutULONG(value, outputMessage + 20, bigEndian_);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode, property);
			}
				break;
			case X_GetSelectionOwner: {
				outputLength = 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.
				getSelectionOwnerSelectionCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_GrabButton:
			case X_GrabPointer: {
				outputLength = 24;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 1);
				outputMessage[1] = (unsigned char) value;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				grabButtonEventMaskCache);
				PutUINT(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeValue(value, 1);
				outputMessage[10] = (unsigned char) value;
				decodeBuffer.decodeValue(value, 1);
				outputMessage[11] = (unsigned char) value;
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.
				grabButtonConfineCache, 9);
				PutULONG(value, outputMessage + 12, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.cursorCache, 9);
				PutULONG(value, outputMessage + 16, bigEndian_);
				if (opcode == X_GrabButton) {
					decodeBuffer.decodeCachedValue(cValue, 8, clientCache_.
					grabButtonButtonCache);
					outputMessage[20] = cValue;
					decodeBuffer.decodeCachedValue(value, 16, clientCache_.
					grabButtonModifierCache);
					PutUINT(value, outputMessage + 22, bigEndian_);
				} else {
					decodeBuffer.decodeValue(value, 32, 4);
					clientCache_.grabKeyboardLastTimestamp += value;
					PutULONG(clientCache_.grabKeyboardLastTimestamp,
							outputMessage + 20, bigEndian_);
					sequenceNumQueue_.push(clientCache_.
					lastRequestSequenceNum, opcode);
				}
			}
				break;
			case X_GrabKeyboard: {
				outputLength = 16;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 1);
				outputMessage[1] = (unsigned char) value;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeValue(value, 32, 4);
				clientCache_.grabKeyboardLastTimestamp += value;
				PutULONG(clientCache_.grabKeyboardLastTimestamp, outputMessage
						+ 8, bigEndian_);
				decodeBuffer.decodeValue(value, 1);
				outputMessage[12] = (unsigned char) value;
				decodeBuffer.decodeValue(value, 1);
				outputMessage[13] = (unsigned char) value;
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_GrabServer:
			case X_UngrabServer:
			case X_NoOperation: {
				outputLength = 4;
				outputMessage = writeBuffer_.addMessage(outputLength);
			}
				break;
			case X_ImageText8: {
				unsigned int textLength;

				decodeBuffer.decodeValue(textLength, 8);
				outputLength = 16 + RoundUp4(textLength);
				outputMessage = writeBuffer_.addMessage(outputLength);
				outputMessage[1] = (unsigned char) textLength;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				imageText8CacheX, 8);
				clientCache_.imageText8LastX += value;
				clientCache_.imageText8LastX &= 0xffff;
				PutUINT(clientCache_.imageText8LastX, outputMessage + 12,
						bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				imageText8CacheY, 8);
				clientCache_.imageText8LastY += value;
				clientCache_.imageText8LastY &= 0xffff;
				PutUINT(clientCache_.imageText8LastY, outputMessage + 14,
						bigEndian_);
				unsigned char *nextDest = outputMessage + 16;

				clientCache_.imageText8TextCompressor.reset();
				while (textLength) {
					*nextDest++ = clientCache_.imageText8TextCompressor.
					decodeChar(decodeBuffer);
					textLength--;
				}
			}
				break;
			case X_InternAtom: {
				unsigned int nameLength;

				decodeBuffer.decodeValue(nameLength, 16, 6);
				outputLength = RoundUp4(nameLength) + 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				PutUINT(nameLength, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeValue(value, 1);
				outputMessage[1] = (unsigned char) value;
				unsigned char *nextDest = outputMessage + 8;

				clientCache_.internAtomTextCompressor.reset();
				for (unsigned int i = 0; i < nameLength; i++)
					*nextDest++ = clientCache_.internAtomTextCompressor.
					decodeChar(decodeBuffer);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_ListExtensions: {
				outputLength = 4;
				outputMessage = writeBuffer_.addMessage(outputLength);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_ListFonts: {
				unsigned int textLength;

				decodeBuffer.decodeValue(textLength, 16, 6);
				outputLength = 8 + RoundUp4(textLength);
				outputMessage = writeBuffer_.addMessage(outputLength);
				PutUINT(textLength, outputMessage + 6, bigEndian_);
				decodeBuffer.decodeValue(value, 16, 6);
				PutUINT(value, outputMessage + 4, bigEndian_);
				unsigned char *nextDest = outputMessage + 8;

				clientCache_.polyText8TextCompressor.reset();
				for (unsigned int i = 0; i < textLength; i++)
					*nextDest++ = clientCache_.polyText8TextCompressor.
					decodeChar(decodeBuffer);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_LookupColor:
			case X_AllocNamedColor: {
				unsigned int textLength;

				decodeBuffer.decodeValue(textLength, 16, 6);
				outputLength = 12 + RoundUp4(textLength);
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.colormapCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				PutUINT(textLength, outputMessage + 8, bigEndian_);
				unsigned char *nextDest = outputMessage + 12;

				clientCache_.polyText8TextCompressor.reset();
				for (unsigned int i = 0; i < textLength; i++)
					*nextDest++ = clientCache_.polyText8TextCompressor.
					decodeChar(decodeBuffer);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_MapWindow:
			case X_UnmapWindow:
			case X_MapSubwindows:
			case X_GetWindowAttributes:
			case X_DestroyWindow:
			case X_DestroySubwindows:
			case X_QueryPointer:
			case X_QueryTree: {
				outputLength = 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				if ((opcode == X_QueryPointer) || (opcode
						== X_GetWindowAttributes) || (opcode == X_QueryTree))
					sequenceNumQueue_.push(clientCache_.
					lastRequestSequenceNum, opcode);
			}
				break;
			case X_OpenFont: {
				unsigned int nameLength;

				decodeBuffer.decodeValue(nameLength, 16, 7);
				outputLength = RoundUp4(12 + nameLength);
				outputMessage = writeBuffer_.addMessage(outputLength);
				PutUINT(nameLength, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeValue(value, 29, 5);
				clientCache_.lastFont += value;
				clientCache_.lastFont &= 0x1fffffff;
				PutULONG(clientCache_.lastFont, outputMessage + 4, bigEndian_);
				unsigned char *nextDest = outputMessage + 12;

				clientCache_.openFontTextCompressor.reset();
				for (; nameLength; nameLength--)
					*nextDest++ = clientCache_.openFontTextCompressor.
					decodeChar(decodeBuffer);
			}
				break;
			case X_PolyFillRectangle: {
				outputLength = 12;
				outputMessage = writeBuffer_.addMessage(outputLength);
				writeBuffer_.registerPointer(&outputMessage);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 8, bigEndian_);

				unsigned int index = 0;
				unsigned int lastX = 0, lastY = 0, lastWidth = 0, lastHeight =
						0;
				unsigned int numRectangles = 0;

				for (;;) {
					outputLength += 8;
					writeBuffer_.addMessage(8);
					unsigned char *nextDest = outputMessage + 12
							+ (numRectangles << 3);
					numRectangles++;
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					polyFillRectangleCacheX
					[index], 8);
					value += lastX;
					PutUINT(value, nextDest, bigEndian_);
					lastX = value;
					nextDest += 2;
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					polyFillRectangleCacheY
					[index], 8);
					value += lastY;
					PutUINT(value, nextDest, bigEndian_);
					lastY = value;
					nextDest += 2;
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					polyFillRectangleCacheWidth
					[index], 8);
					value += lastWidth;
					PutUINT(value, nextDest, bigEndian_);
					lastWidth = value;
					nextDest += 2;
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					polyFillRectangleCacheHeight
					[index], 8);
					value += lastHeight;
					PutUINT(value, nextDest, bigEndian_);
					lastHeight = value;
					nextDest += 2;
					index = 1;

					decodeBuffer.decodeValue(value, 1);
					if (!value)
						break;
				}
				writeBuffer_.unregisterPointer();
			}
				break;
			case X_PolyPoint: {
				unsigned int numPoints;

				decodeBuffer.decodeValue(numPoints, 16, 4);
				outputLength = (numPoints << 2) + 12;
				outputMessage = writeBuffer_.addMessage(outputLength);
				unsigned int relativeCoordMode;

				decodeBuffer.decodeValue(relativeCoordMode, 1);
				outputMessage[1] = (unsigned char) relativeCoordMode;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				unsigned char *nextDest = outputMessage + 12;
				unsigned int index = 0;
				unsigned int lastX = 0, lastY = 0;

				for (unsigned int i = 0; i < numPoints; i++) {
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					polyPointCacheX[index], 8);
					lastX += value;
					PutUINT(lastX, nextDest, bigEndian_);
					nextDest += 2;
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					polyPointCacheY[index], 8);
					lastY += value;
					PutUINT(lastY, nextDest, bigEndian_);
					nextDest += 2;
					index = 1;
				}
			}
				break;
			case X_PolyLine: {
				unsigned int numPoints;

				decodeBuffer.decodeValue(numPoints, 16, 4);
				outputLength = (numPoints << 2) + 12;
				outputMessage = writeBuffer_.addMessage(outputLength);
				unsigned int relativeCoordMode;

				decodeBuffer.decodeValue(relativeCoordMode, 1);
				outputMessage[1] = (unsigned char) relativeCoordMode;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				unsigned char *nextDest = outputMessage + 12;
				unsigned int index = 0;
				unsigned int lastX = 0, lastY = 0;

				for (unsigned int i = 0; i < numPoints; i++) {
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					polyLineCacheX[index], 8);
					lastX += value;
					PutUINT(lastX, nextDest, bigEndian_);
					nextDest += 2;
					decodeBuffer.decodeCachedValue(value, 16, *clientCache_.
					polyLineCacheY[index], 8);
					lastY += value;
					PutUINT(lastY, nextDest, bigEndian_);
					nextDest += 2;
					index = 1;
				}
			}
				break;
			case X_PolyRectangle: {
				unsigned int numRectangles;

				decodeBuffer.decodeValue(numRectangles, 16, 3);
				outputLength = (numRectangles << 3) + 12;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				unsigned char *nextDest = outputMessage + 12;

				for (unsigned int i = 0; i < numRectangles; i++)
					for (unsigned int k = 0; k < 4; k++) {
						decodeBuffer.decodeCachedValue(value, 16,
								*clientCache_.
								polyRectangleGeomCache
								[k], 8);
						PutUINT(value, nextDest, bigEndian_);
						nextDest += 2;
					}
			}
				break;
			case X_PolySegment: {
				unsigned int numSegments;

				decodeBuffer.decodeValue(numSegments, 16, 4);
				outputLength = (numSegments << 3) + 12;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				unsigned char *nextDest = outputMessage + 12;

				for (numSegments *= 2; numSegments; numSegments--) {
					unsigned int index;

					decodeBuffer.decodeValue(index, 1);
					unsigned int x;

					decodeBuffer.decodeCachedValue(x, 16, clientCache_.
					polySegmentCacheX, 6);
					x += clientCache_.polySegmentLastX[index];
					PutUINT(x, nextDest, bigEndian_);
					nextDest += 2;

					unsigned int y;

					decodeBuffer.decodeCachedValue(y, 16, clientCache_.
					polySegmentCacheY, 6);
					y += clientCache_.polySegmentLastY[index];
					PutUINT(y, nextDest, bigEndian_);
					nextDest += 2;

					clientCache_.polySegmentLastX[clientCache_.
					polySegmentCacheIndex] = x;
					clientCache_.polySegmentLastY[clientCache_.
					polySegmentCacheIndex] = y;

					if (clientCache_.polySegmentCacheIndex == 1)
						clientCache_.polySegmentCacheIndex = 0;
					else
						clientCache_.polySegmentCacheIndex = 1;
				}
			}
				break;
			case X_PolyText8: {
				outputLength = 16;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				polyText8CacheX, 8);
				clientCache_.polyText8LastX += value;
				clientCache_.polyText8LastX &= 0xffff;
				PutUINT(clientCache_.polyText8LastX, outputMessage + 12,
						bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				polyText8CacheY, 8);
				clientCache_.polyText8LastY += value;
				clientCache_.polyText8LastY &= 0xffff;
				PutUINT(clientCache_.polyText8LastY, outputMessage + 14,
						bigEndian_);
				unsigned int addedLength = 0;

				writeBuffer_.registerPointer(&outputMessage);
				for (;;) {
					decodeBuffer.decodeValue(value, 1);
					if (!value)
						break;
					unsigned int textLength;

					decodeBuffer.decodeValue(textLength, 8);
					if (textLength == 255) {
						addedLength += 5;
						unsigned char *nextSegment = writeBuffer_.addMessage(5);
						*nextSegment = (unsigned char) textLength;
						decodeBuffer.decodeCachedValue(value, 29, clientCache_.
						polyText8FontCache);
						PutULONG(value, nextSegment + 1, 1);
					} else {
						addedLength += (textLength + 2);
						unsigned char *nextSegment =
								writeBuffer_.addMessage(textLength + 2);
						*nextSegment = (unsigned char) textLength;
						unsigned char *nextDest = nextSegment + 1;

						decodeBuffer.decodeCachedValue(cValue, 8, clientCache_.
						polyText8DeltaCache);
						*nextDest++ = cValue;
						clientCache_.polyText8TextCompressor.reset();
						while (textLength) {
							*nextDest++ = clientCache_.polyText8TextCompressor.
							decodeChar(decodeBuffer);
							textLength--;
						}
					}
				}
				outputLength += addedLength;
				unsigned int mod4 = (addedLength & 0x3);

				if (mod4) {
					unsigned int extra = 4 - mod4;
					unsigned char *nextDest = writeBuffer_.addMessage(extra);
					for (unsigned int i = 0; i < extra; i++)
						*nextDest++ = 0;
					outputLength += extra;
				}
				writeBuffer_.unregisterPointer();
			}
				break;
			case X_PutImage: {
				decodeBuffer.decodeValue(value, 16, 8);
				outputLength = (value << 2);
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 2);
				outputMessage[1] = (unsigned char) value;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				unsigned int width;

				decodeBuffer.decodeCachedValue(width, 16, clientCache_.
				putImageWidthCache, 8);
				PutUINT(width, outputMessage + 12, bigEndian_);
				unsigned int height;

				decodeBuffer.decodeCachedValue(height, 16, clientCache_.
				putImageHeightCache, 8);
				PutUINT(height, outputMessage + 14, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				putImageXCache, 8);
				clientCache_.putImageLastX += value;
				clientCache_.putImageLastX &= 0xffff;
				PutUINT(clientCache_.putImageLastX, outputMessage + 16,
						bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				putImageYCache, 8);
				clientCache_.putImageLastY += value;
				clientCache_.putImageLastY &= 0xffff;
				PutUINT(clientCache_.putImageLastY, outputMessage + 18,
						bigEndian_);
				decodeBuffer.decodeCachedValue(cValue, 8, clientCache_.
				putImageOffsetCache);
				outputMessage[20] = cValue;
				decodeBuffer.decodeCachedValue(cValue, 8,
						clientCache_.depthCache);
				outputMessage[21] = cValue;
				unsigned char *nextDest = outputMessage + 24;

				decodeBuffer.decodeValue(value, COMPRESSION_TYPE_BITS);

				CompressionType compressionType = (CompressionType) value;

				if (decompresser && compressionType != NO_STREAM_COMPRESSION) {
					decompresser->decompressBuffer(compressionType, nextDest,
							decodeBuffer);
				} else if ((outputMessage[1] == 0) && (height <= 32) && (width
						> height * PUT_IMAGE_MIN_ASPECT_RATIO)) {
					// bitmap that probably contains text; encode using a variant of
					// text-compression algorithm
					unsigned int widthInBits = ((width / scanlinePad_)
							* scanlinePad_);
					if (widthInBits < width)
						widthInBits += scanlinePad_;
					unsigned int widthInBytes = (widthInBits >> 3);
					unsigned char *nextDest = outputMessage + 24;

					memset(nextDest, 0, outputLength - 24);
					unsigned char destMask = 0x80;

					clientCache_.putImageLastPixels.reset();
					for (unsigned int xCoord = 0; xCoord < width; xCoord++) {
						unsigned int modelNum =
								clientCache_.putImageLastPixels.getValue();
						unsigned int columnValue;

						decodeBuffer.decodeCachedValue(columnValue, height,
								clientCache_.
								putImagePixelCache
								[modelNum %
								PUT_IMAGE_PIXEL_CACHE_SIZE], clientCache_.
								columnPixel0Coder, clientCache_.
								columnPixel1Coder);
						unsigned char *next = nextDest;
						unsigned int mask = (1 << (height - 1));

						for (unsigned int h = 0; h < height; h++) {
							if (columnValue & mask)
								*next |= destMask;
							next += widthInBytes;
							mask >>= 1;
						}
						destMask >>= 1;
						if (destMask == 0) {
							destMask = 0x80;
							nextDest++;
						}
						clientCache_.putImageLastPixels.add(columnValue);
					}
					if ((imageByteOrder_ == 0) && (bitmapBitOrder_ == 0)) {
						unsigned char *next = outputMessage + 24;

						for (unsigned int i = 24; i < outputLength; i++) {
							*next = REVERSED_BYTE[*next];
							next++;
						}
					}
				} else if (outputMessage[1] == 0) {
					// bitmap--use "Modified-Modified-Read" FAX coding
					if (width + 2 > clientCache_.putImageLineSize) {
						delete[]clientCache_.putImageReferenceLine;
						delete[]clientCache_.putImageCodingLine;
						clientCache_.putImageLineSize = width + 2;
						clientCache_.putImageReferenceLine
								= new unsigned int[width + 2];
						clientCache_.putImageCodingLine
								= new unsigned int[width + 2];
					}
					unsigned int widthInBits = ((width / scanlinePad_)
							* scanlinePad_);
					if (widthInBits < width)
						widthInBits += scanlinePad_;
					unsigned int widthInBytes = (widthInBits >> 3);
					unsigned int lastPixelValue = 0;

					for (unsigned int h = 0; h < height; h++) {
						unsigned int codingLineLength = 0;
						unsigned char *nextDest = outputMessage + 24 + h
								* widthInBytes;
						*nextDest = 0;
						unsigned char destMask = 0x80;

						if (h == 0) {
							unsigned int pixelValue;

							decodeBuffer.decodeValue(pixelValue, 1);
							for (unsigned int xCoord = 0; xCoord < width;) {
								if (pixelValue) {
									if (pixelValue != lastPixelValue)
										clientCache_.
										putImageCodingLine
										[codingLineLength++] = xCoord;
									unsigned int runLength =
											clientCache_.putImagePixel1Coder.
											decode(decodeBuffer);
									while (runLength--) {
										*nextDest |= destMask;
										destMask >>= 1;
										if (destMask == 0) {
											destMask = 0x80;
											nextDest++;
											if (xCoord + 1 < width)
												*nextDest = 0;
										}
										xCoord++;
									}
									pixelValue = 0;
									lastPixelValue = 1;
								} else {
									if (pixelValue != lastPixelValue)
										clientCache_.
										putImageCodingLine
										[codingLineLength++] = xCoord;
									unsigned int runLength =
											clientCache_.putImagePixel0Coder.
											decode(decodeBuffer);
									while (runLength--) {
										destMask >>= 1;
										if (destMask == 0) {
											destMask = 0x80;
											nextDest++;
											if (xCoord + 1 < width)
												*nextDest = 0;
										}
										xCoord++;
									}
									pixelValue = 1;
									lastPixelValue = 0;
								}
							}
							clientCache_.
							putImageCodingLine[codingLineLength++] = width;
						} else {
							unsigned int lastX = 0;
							unsigned int nextReferenceIndex = 0;

							while (lastX < width) {
								ScanlineDiff diffCode =
										(ScanlineDiff) clientCache_.
										putImageDiffCoder.
										decode(decodeBuffer);
								switch (diffCode) {
								case SD_VERTICAL_0: {
									lastX = clientCache_.
									putImageCodingLine
									[codingLineLength++] = clientCache_.
									putImageReferenceLine
									[nextReferenceIndex++];
								}
									break;
								case SD_VERTICAL_PLUS_1: {
									lastX = clientCache_.
									putImageCodingLine
									[codingLineLength++] = clientCache_.
									putImageReferenceLine
									[nextReferenceIndex++] + 1;
								}
									break;
								case SD_VERTICAL_PLUS_2: {
									lastX = clientCache_.
									putImageCodingLine
									[codingLineLength++] = clientCache_.
									putImageReferenceLine
									[nextReferenceIndex++] + 2;
								}
									break;
								case SD_VERTICAL_MINUS_1: {
									lastX = clientCache_.
									putImageCodingLine
									[codingLineLength++] = clientCache_.
									putImageReferenceLine
									[nextReferenceIndex++] - 1;
								}
									break;
								case SD_VERTICAL_MINUS_2: {
									lastX = clientCache_.
									putImageCodingLine
									[codingLineLength++] = clientCache_.
									putImageReferenceLine
									[nextReferenceIndex++] - 2;
								}
									break;
								case SD_PASS: {
									nextReferenceIndex += 2;
								}
									break;
								case SD_HORIZONTAL: {
									unsigned int diff;

									if (codingLineLength & 1)
										diff = clientCache_.
										putImagePixel0Coder.
										decode(decodeBuffer);
									else
										diff = clientCache_.
										putImagePixel1Coder.
										decode(decodeBuffer);
									lastX += diff;
									lastX &= 0xffff;
									clientCache_.
									putImageCodingLine
									[codingLineLength++] = lastX;
									if (codingLineLength & 1)
										diff = clientCache_.
										putImagePixel0Coder.
										decode(decodeBuffer);
									else
										diff = clientCache_.
										putImagePixel1Coder.
										decode(decodeBuffer);
									lastX += diff;
									lastX &= 0xffff;
									clientCache_.
									putImageCodingLine
									[codingLineLength++] = lastX;
								}
								default: {
								}
								}
							}
						}

						clientCache_.
						putImageCodingLine[codingLineLength++] = width;
						unsigned int pixelValue = 0;
						unsigned int lastPixelChange = 0;
						unsigned int *nextPixelChange =
								clientCache_.putImageCodingLine;
						for (unsigned int xCoord = 0; xCoord < width;) {
							unsigned int count = *nextPixelChange
									- lastPixelChange;
							lastPixelChange = *nextPixelChange++;
							for (; count; count--) {
								if (pixelValue)
									*nextDest |= destMask;
								destMask >>= 1;
								if (destMask == 0) {
									destMask = 0x80;
									nextDest++;
									if (xCoord + 1 < width)
										*nextDest = 0;
								}
								xCoord++;
							}
							if (pixelValue)
								pixelValue = 0;
							else
								pixelValue = 1;
						}

						unsigned int *tmp = clientCache_.putImageReferenceLine;
						clientCache_.putImageReferenceLine
								= clientCache_.putImageCodingLine;
						clientCache_.putImageCodingLine = tmp;
					}
					const unsigned char *end = outputMessage + outputLength;
					if ((imageByteOrder_ == 0) && (bitmapBitOrder_ == 0)) {
						for (unsigned char *next = outputMessage + 24; next
								< end; next++)
							*next = REVERSED_BYTE[*next];
					}
					unsigned char *next = outputMessage + 24 + widthInBytes;
					const unsigned char *prev = outputMessage + 24;

					for (; next < end;)
						*next++ ^= *prev++;
				} else {
					// pixmap
					if (outputMessage[21] == 8) {
						for (unsigned int i = 24; i < outputLength; i++) {
							decodeBuffer.decodeCachedValue(cValue, 8,
									clientCache_.
									putImageByteCache, 4);
							*nextDest++ = cValue;
						}
					} else {
						for (unsigned int i = 24; i < outputLength; i++) {
							decodeBuffer.decodeValue(value, 8);
							*nextDest++ = (unsigned char) value;
						}
					}
				}
			}
				if (replay_debug)
					if (PRINT_DEBUG) printMessage(outputMessage, outputLength, 12, 1, 1, 2, 4,
							4, 2, 2, 2, 2, 1, 1, 2);
				break;
			case X_QueryBestSize: {
				outputLength = 12;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 2);
				outputMessage[1] = (unsigned char) value;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.drawableCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeValue(value, 16, 8);
				PutUINT(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeValue(value, 16, 8);
				PutUINT(value, outputMessage + 10, bigEndian_);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_QueryColors: {
				unsigned int numColors;

				decodeBuffer.decodeValue(numColors, 16, 5);
				outputLength = (numColors << 2) + 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.colormapCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				unsigned char *nextDest = outputMessage + 8;
				unsigned int predictedPixel = clientCache_.queryColorsLastPixel;
				for (unsigned int i = 0; i < numColors; i++) {
					unsigned int pixel;

					decodeBuffer.decodeValue(value, 1);
					if (value)
						pixel = predictedPixel;
					else
						decodeBuffer.decodeValue(pixel, 32, 9);
					PutULONG(pixel, nextDest, bigEndian_);
					if (i == 0)
						clientCache_.queryColorsLastPixel = pixel;
					predictedPixel = pixel + 1;
					nextDest += 4;
				}
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_QueryExtension: {
				unsigned int nameLength;

				decodeBuffer.decodeValue(nameLength, 16, 6);
				outputLength = 8 + RoundUp4(nameLength);
				outputMessage = writeBuffer_.addMessage(outputLength);
				PutUINT(nameLength, outputMessage + 4, bigEndian_);
				unsigned char *nextDest = outputMessage + 8;

				for (unsigned int i = 0; i < nameLength; i++) {
					decodeBuffer.decodeValue(value, 8);
					*nextDest++ = (unsigned char) value;
				}
				unsigned int hideExtension = 0;

				if (!strncmp((char *) outputMessage + 8, "MIT-SHM", 7)) {
					cout << "hiding MIT-SHM!";
					hideExtension = 1;
				}
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode, hideExtension);
			}
				break;
			case X_QueryFont: {
				outputLength = 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 29, 5);
				clientCache_.lastFont += value;
				clientCache_.lastFont &= 0x1fffffff;
				PutULONG(clientCache_.lastFont, outputMessage + 4, bigEndian_);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
			case X_SetClipRectangles: {
				unsigned int numRectangles;

				decodeBuffer.decodeValue(numRectangles, 13, 4);
				outputLength = (numRectangles << 3) + 12;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 2);
				outputMessage[1] = (unsigned char) value;
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				setClipRectanglesXCache, 8);
				PutUINT(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				setClipRectanglesYCache, 8);
				PutUINT(value, outputMessage + 10, bigEndian_);
				unsigned char *nextDest = outputMessage + 12;

				for (unsigned int i = 0; i < numRectangles; i++) {
					for (unsigned int k = 0; k < 4; k++) {
						decodeBuffer.decodeCachedValue(value, 16,
								*clientCache_.
								setClipRectanglesGeomCache
								[k], 8);
						PutUINT(value, nextDest, bigEndian_);
						nextDest += 2;
					}
				}
			}
				break;
			case X_SetDashes: {
				unsigned int numDashes;

				decodeBuffer.decodeCachedValue(numDashes, 16, clientCache_.
				setDashesLengthCache, 5);
				outputLength = 12 + RoundUp4(numDashes);
				outputMessage = writeBuffer_.addMessage(outputLength);
				PutUINT(numDashes, outputMessage + 10, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.gcCache,
						9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				setDashesOffsetCache, 5);
				PutUINT(value, outputMessage + 8, bigEndian_);
				unsigned char *nextDest = outputMessage + 12;

				for (unsigned int i = 0; i < numDashes; i++) {
					decodeBuffer.decodeCachedValue(cValue, 8, clientCache_.
					setDashesDashCache_[i &
					1], 5);
					*nextDest++ = cValue;
				}
			}
				break;
			case X_SetSelectionOwner: {
				outputLength = 16;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.
				setSelectionOwnerCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.
				getSelectionOwnerSelectionCache, 9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 32, clientCache_.
				setSelectionOwnerTimestampCache, 9);
				PutULONG(value, outputMessage + 12, bigEndian_);
			}
				break;
			case X_TranslateCoords: {
				outputLength = 16;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.
				translateCoordsSrcCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29, clientCache_.
				translateCoordsDestCache, 9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				translateCoordsXCache, 8);
				PutUINT(value, outputMessage + 12, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 16, clientCache_.
				translateCoordsYCache, 8);
				PutUINT(value, outputMessage + 14, bigEndian_);
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);
			}
				break;
				//starting point for additional request support
			case X_CreateColormap: {
				outputLength = 16;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 1);
				if (value)
					outputMessage[1] = 1;
				else
					outputMessage[1] = 0;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.colormapCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 8, bigEndian_);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.visualCache, 9);
				PutULONG(value, outputMessage + 12, bigEndian_);

			}
				break;
			case X_FreeColormap: {
				outputLength = 8;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.colormapCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
			}
				break;
			case X_SetInputFocus: {
				outputLength = 12;
				outputMessage = writeBuffer_.addMessage(outputLength);
				decodeBuffer.decodeValue(value, 2);
				outputMessage[1] = value;
				decodeBuffer.decodeCachedValue(value, 29,
						clientCache_.windowCache, 9);
				PutULONG(value, outputMessage + 4, bigEndian_);
				decodeBuffer.decodeValue(value, 32);
				PutULONG(value, outputMessage + 8, bigEndian_);
			}
				break;
				//starting point for x extensions parsing
				//compressed
			case XE_BIG_REQUESTS: {
				outputLength = 4;
				outputMessage = writeBuffer_.addMessage(outputLength);
				outputMessage[1] = 0;
				sequenceNumQueue_.push(clientCache_.
				lastRequestSequenceNum, opcode);

			}
				break;
				//starting point for additional message support
				// request not compressed yet
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
			case X_GetImage:
			case X_SendEvent: {
				unsigned int secondByte;

				decodeBuffer.decodeValue(secondByte, 8);
				decodeBuffer.decodeValue(outputLength, 16, 8);
				outputLength <<= 2;
				outputMessage = writeBuffer_.addMessage(outputLength);
				outputMessage[1] = (unsigned char) secondByte;
				unsigned char *nextDest = outputMessage + 4;

				for (unsigned int i = 4; i < outputLength; i++) {
					unsigned int nextByte;

					decodeBuffer.decodeValue(nextByte, 8);
					*nextDest++ = (unsigned char) nextByte;
				}
				sequenceNumQueue_.push(clientCache_.lastRequestSequenceNum,
						opcode);

			}
				break;
				//other non-recognized requests
			default: {
				unsigned int secondByte;

				decodeBuffer.decodeValue(secondByte, 8);
				decodeBuffer.decodeValue(outputLength, 16, 8);
				outputLength <<= 2;
				outputMessage = writeBuffer_.addMessage(outputLength);
				outputMessage[1] = (unsigned char) secondByte;
				unsigned char *nextDest = outputMessage + 4;

				for (unsigned int i = 4; i < outputLength; i++) {
					unsigned int nextByte;

					decodeBuffer.decodeValue(nextByte, 8);
					*nextDest++ = (unsigned char) nextByte;
				}

			}

			}
			*outputMessage = (unsigned char) opcode;
			PutUINT(outputLength >> 2, outputMessage + 2, bigEndian_);
			if (replay_debug)
				cout <<"request opcode:"<<(unsigned int)opcode<<" size:"
						<<outputLength<<endl;
		}
	}

	if (WriteAll(fd_, writeBuffer_.getData(), writeBuffer_.getLength()) < 0)
		return 0;
	else
		return 1;
}

void ServerChannel::setBigEndian(int flag) {
	bigEndian_ = flag;
	readBuffer_.setBigEndian(flag);
}

void ServerChannel::encodeCharInfo_(const unsigned char *nextSrc,
		EncodeBuffer & encodeBuffer) {
	unsigned int value = GetUINT(nextSrc, bigEndian_) | (GetUINT(nextSrc + 10,
			bigEndian_) << 16);
	encodeBuffer.encodeCachedValue(value, 32,
			*serverCache_.queryFontCharInfoCache[0], 6);
	nextSrc += 2;
	for (unsigned int i = 1; i < 5; i++) {
		unsigned int value = GetUINT(nextSrc, bigEndian_);

		nextSrc += 2;
		encodeBuffer.encodeCachedValue(value, 16, *serverCache_.
		queryFontCharInfoCache[i], 6);
	}
}

