#include <linux/c_cache.h>

#ifndef ENCODEBUFFER_H
#define ENCODEBUFFER_H

#ifndef CLOG_NODE_DEF
#define CLOG_NODE_DEF
struct clog_node { 
	unsigned char*          head;
	unsigned char*          pos;
	unsigned int            size;
	struct list_head        list;
	unsigned char*          end;
	unsigned int            freeBitsInDest;
	unsigned int            cumulativeBits;
	int done;
	unsigned int args_size;
};
#endif
/*unsigned int encodebuffer_size;
unsigned char *encode_buffer;
unsigned char *encodebuffer_end;
unsigned char *encodebuffer_nextDest;
unsigned int freeBitsInDest;
unsigned int cumulativeBits;
unsigned int size__;
*/
void reset(struct clog_node *node);
void encodeDirect(unsigned int value, unsigned int numBits, struct clog_node* node);
void init_encode_buffer(struct clog_node* node);
void free_buffer(struct clog_node* node);
void growBuffer(unsigned int minumumFreeSpaceAfterGrow, struct clog_node* node);
unsigned int getDataLength(struct clog_node* node);
unsigned int getDataLengthInBits(struct clog_node* node);
unsigned char* getData(struct clog_node* node);
unsigned int getCumulativeBitsWritten(struct clog_node* node);
void encodeIndex(unsigned index, int isEscape, struct clog_node* node);
void encodeEscapeIndex(struct clog_node* node);
void encodeValue(unsigned int value, unsigned int numBits, unsigned int blockSize, struct clog_node* node);
void encodeCachedValue(unsigned int value, unsigned int numBits, struct IntCache* cache, unsigned int blockSize, struct clog_node* node);
void encodeCachedCharValue(unsigned char value, unsigned int numBits, struct CharCache* cache, unsigned int blockSize, struct clog_node* node);
//void encodeCharInfo_(const unsigned char* nextSrc, struct clog_node* node);
#endif
