/*
 * decodeBuffer.h
 *
 *  Created on: Mar 22, 2013
 *      Author: xdou
 */

#ifndef DECODEBUFFER_H_
#define DECODEBUFFER_H_

#include <linux/c_cache.h>

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

/*const unsigned char *buffer;
const unsigned char *end;
const unsigned char *nextSrc;
unsigned int availableBitsInSrc;
*/
void decodebuffer_init(unsigned char *data, unsigned int length, struct clog_node *node);

//unsigned int blockSize = 0, int endOkay = 0
int decodeValue(unsigned int *value, unsigned int numBits,
		unsigned int blockSize, int endOkay, struct clog_node *node);

//unsigned int blockSize = 0, int endOkay = 0
int decodeCachedValue(unsigned int *value, unsigned int numBits,
		struct IntCache *cache, unsigned int blockSize,
		int endOkay, struct clog_node *node);

//unsigned int blockSize = 0,int endOkay = 0
int decodeCachedCharValue(unsigned char *value, unsigned int numBits,
		struct CharCache * cache, unsigned int blockSize ,
		int endOkay, struct clog_node *node);


const unsigned char *decodeRawMem(unsigned int len, struct clog_node *node);

//int endOkay = 0
int decodeDirect(unsigned int *value, unsigned int numBits, int endOkay, struct clog_node *node);


int countLeadingZeros(unsigned *value, int endOkay, struct clog_node *node);

#endif /* DECODEBUFFER_H_ */
