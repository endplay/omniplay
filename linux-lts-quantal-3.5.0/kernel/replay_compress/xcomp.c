//for x proto compression
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/xcomp.h>
#include <asm/bug.h>
#include <linux/slab.h>
#include <linux/encodebuffer.h>
#include <linux/c_cache.h>
#include <linux/c_constants.h>
#include <linux/values_cache.h>
#include <linux/decodeBuffer.h>
#include "X11/X.h"
#include "X11/Xproto.h"
#include "X11/Xatom.h"

#define ENCODE
#define DECODE
#define DECODE_BUFFER_SIZE 1024

int x_detail = 1;

//char* put_image_buf;
//int put_image_size=0;


/*struct BlockCacheSet *image_cache_set;

inline void blockcache_init(struct BlockCache *cache) {
	cache->size = 0;
	cache->checksum = 0;
	cache->buffer = NULL;
}

inline void blockcache_free(struct BlockCache* cache) {
	if(cache->buffer)
		vfree(cache->buffer);
	if(cache)
		kfree(cache);
}
inline unsigned int blockcache_checksum(unsigned int size, const unsigned char* data) {
	unsigned int sum = 0;
	unsigned int shift = 0;
	const unsigned char*next = data;
	unsigned int i;
	unsigned int value;

	for (i = 0; i < size; ++i) {
		value = (unsigned int) *next++;
		sum += (value << shift);
		++shift;
		if (shift == 8)
			shift = 0;
	}
	return sum;
}
inline int blockcache_compare(struct BlockCache* cache, unsigned int size, unsigned char* data) {
	//overwrite = 1
	int match = 0;
	int i;
	if (size == cache->size) {
		match = 1;
		for (i = 0; i < cache->size; ++i){
			//	printk("blockcache_compare:%d\n, %d:%d", i, data[i], cache->buffer[i]);
			if (data[i] != cache->buffer[i]) {
				match = 0;
				break;
			}
		}
	}
	return match;
}

inline void blockcache_set(struct BlockCache* cache, unsigned int size,
		const unsigned char* data) {
	if (cache->size < size) {
		if(cache->buffer)
			vfree(cache->buffer);
		cache->buffer = vmalloc(size);
	}
	cache->size = size;
	memcpy(cache->buffer, data, size);
	cache->checksum = blockcache_checksum(size, data);
}



//note!!! different meaning with the block cache set in x_compress algorithm
void blockcacheset_init(struct BlockCacheSet *cache, unsigned int numCaches) {
	cache->size = numCaches;
	cache->length=0;
	cache->caches = kmalloc(sizeof(struct BlockCache*) * numCaches, GFP_KERNEL);
}

void blockcacheset_free(struct BlockCacheSet* cache) {
	int i = 0;
	if(cache==NULL)
		return;
	for (i = 0; i < cache->length; ++i){
		printk("%d\n",i);
		blockcache_free(cache->caches[i]);
	}
	kfree(cache->caches);
	cache=NULL;
}

void blockcacheset_insert(struct BlockCacheSet *cacheset, unsigned char* data, unsigned int size)
{
	struct BlockCache **tmp;
	struct BlockCache* cache; 
	char change;
	int i;
	//if(cacheset->length>=32)
	//	return;
	cache = kmalloc(sizeof(struct BlockCache), GFP_KERNEL) ;
	blockcache_init(cache);
	blockcache_set(cache, size, data);
	for(i=0;i<size;i+=4)
	{
		change=cache->buffer[i];
		cache->buffer[i]=cache->buffer[i+2];
		cache->buffer[i+2]=change;
	}
	if(cacheset->length==cacheset->size){
		cacheset->size*=2;
		tmp = kmalloc(sizeof(struct BlockCache*)*cacheset->size,GFP_KERNEL) ;
		memcpy(tmp, cacheset->caches, sizeof(struct BlockCache*)*cacheset->length);
		kfree(cacheset->caches);
		cacheset->caches=tmp;
	}
	cacheset->caches[cacheset->length]=cache;
	++(cacheset->length);

}

int blockcacheset_lookup(struct BlockCacheSet* cache, unsigned int dataLength,
		unsigned char* data) {
	unsigned int checksum;
	unsigned int i;

	checksum=blockcache_checksum(dataLength, data);
	for(i=0;i<cache->length;++i)
	{
		printk("index:%d\n", i);
		if((cache->caches[i]->checksum==checksum) && (blockcache_compare(cache->caches[i], dataLength, data)))
		{
			printk("match @%d, check:%d, %d\n", i, cache->caches[i]->checksum, checksum);
			return i;
		}

	}
	return -1;

}*/


inline void init_x_comp(struct x_struct *x) {
        int i = 0;
        while (i<16) {
            x->xfds[i] = -1;
            x->actual_xfds[i] = -1;
            ++i;
        }
        x->xfds_length = 0;
	//x->xfd = -1;
        x->last_fd = -1;
	//x->xauth_fd = -1;
	x->firstMessage_req = 1;
	x->firstMessage_reply = 1;
	x->connection_times = 0;

	x->seq_num_start = 0;
	x->seq_num_end = 0;
	x->cur_seq = 0;

	//for request message
	x->buffer_message_req = 0;
	x->buffer_size_req = 0;
	x->buffer_start_req = 0;
	x->buffer_req = vmalloc (DECODE_BUFFER_SIZE);
	x->buffer_reply = vmalloc (DECODE_BUFFER_SIZE);
	//for reply message
	x->buffer_message_reply = 0;
	x->buffer_size_reply = 0;
	x->buffer_start_reply = 0;

	// image_cache_set=kmalloc( sizeof(struct BlockCacheSet), GFP_KERNEL);
	// blockcacheset_init(image_cache_set, 32);
	// printk("the image cache length:%d, size:%d\n", image_cache_set->length, image_cache_set->size);

	x->decode_buffer = vmalloc (DECODE_BUFFER_SIZE);
	memset (x->decode_buffer, 0, DECODE_BUFFER_SIZE);
	x->decode_buffer_start = x->decode_buffer;
	x->decode_buffer_end = x->decode_buffer;

	//init_caches (&x->serverCache_);
}

inline int is_x_fd (struct x_struct *x, int fd) {
    int i = 0;
    for (; i<x->xfds_length; ++i) {
        if (x->xfds[i] == fd)
            return 1;
    }
    return 0;
}

inline int is_x_fd_replay (struct x_struct *x, int fd) {
    int i = 0;
    for (; i<x->xfds_length; ++i) {
        if (x->xfds[i] == fd)
            return x->actual_xfds[i];
    }
    return 0;
}

inline void add_x_fd (struct x_struct *x, int fd) {
    x->xfds[x->xfds_length] = fd;
    ++ x->xfds_length;
    BUG_ON (x->xfds_length == xfds_size);
}

inline void remove_x_fd (struct x_struct* x, int fd) {
    int i = 0;
    for (; i< x->xfds_length; ++i)
        if (x->xfds[i] == fd)
           break; 
    x->xfds[i] = -1;
    for (; i+1 < x->xfds_length; ++i)
        x->xfds[i] = x->xfds[i+1];
    --x->xfds_length;
}

inline void add_x_fd_replay (struct x_struct *x, int fd, int actual_fd) {
    x->xfds[x->xfds_length] = fd;
    x->actual_xfds[x->xfds_length] = actual_fd;
    ++ x->xfds_length;
    BUG_ON (x->xfds_length == xfds_size);
}

inline void remove_x_fd_replay (struct x_struct* x, int fd) {
    int i = 0;
    for (; i< x->xfds_length; ++i)
        if (x->xfds[i] == fd)
           break; 
    x->xfds[i] = -1;
    x->actual_xfds[i] = -1;
    for (; i+1 < x->xfds_length; ++i) {
        x->xfds[i] = x->xfds[i+1];
        x->actual_xfds[i] = x->actual_xfds[i+1];
    }
    --x->xfds_length;
}

inline void free_x_comp(struct x_struct *x)
{
	// blockcacheset_free(image_cache_set);
	//if(image_cache_set)
	//	kfree(image_cache_set);
	//image_cache_set=NULL;
	vfree (x->buffer_req);
	vfree (x->buffer_reply);
	vfree (x->decode_buffer);
	//free_caches (&x->serverCache_);
}



inline unsigned int GetUINT (char* buffer) {
	unsigned int result;
	char num[4];
	num[0] = buffer[0];
	num[1] = buffer[1];
	num[2] = 0;
	num[3] = 0;
	result = (*(unsigned int*)num);
	return result;
}

inline unsigned int GetULONG (char* buffer){
	unsigned int result = *((unsigned int*)buffer);
	return result;
}

unsigned char* addMessage(unsigned int numBytes, struct x_struct *x) {
	x->decode_buffer_end += numBytes;
	BUG_ON (x->decode_buffer_end > x->decode_buffer + DECODE_BUFFER_SIZE);
	// memset can be eliminated as it doesn't affect correctness
	memset (x->decode_buffer_end - numBytes, 0, numBytes);
	return x->decode_buffer_end - numBytes;
}

void PutUINT(unsigned int value, unsigned char* buffer) {
	char num[4];
	*((unsigned int*) num) = value;
	buffer[0] = num[0];
	buffer[1] = num[1];
}

void PutULONG(unsigned int value, unsigned char* buffer) {
	/*
	 int i;
	 buffer+=3;
	 for (i = 4; i; i--) {
	 *buffer-- = (unsigned char) (value & 0xff);
	 value >>= 8;
	 }
	 */
	unsigned char buf[4];
	*((unsigned int*) buf) = value;
	memcpy(buffer, buf, 4);
}


inline void seq_push (unsigned char opcode, unsigned char request_data, struct x_struct *x)
{
	x->sequence_nums[x->seq_num_end].sequence = x->cur_seq;
	++ x->cur_seq;
	x->sequence_nums[x->seq_num_end].opcode = opcode;
	x->sequence_nums[x->seq_num_end].request_data = request_data;
	++ x->seq_num_end;
	if (x_detail) printk ("sequence number:%u\n", x->cur_seq - 1);
	if (x->seq_num_end == SEQUENCE_NUM_BUFFER_SIZE)
		x->seq_num_end = 0;
	if (x->seq_num_end == x->seq_num_start) {
		printk ("error: wrap around for sequence number queue.\n");	
		BUG ();
	}
}

inline int seq_peek (unsigned short int* sequence, unsigned char* opcode, struct x_struct *x) {
	if (x->seq_num_start == x->seq_num_end)
		return 0;
	*sequence = x->sequence_nums[x->seq_num_start].sequence;
	*opcode = x->sequence_nums[x->seq_num_start].opcode;
	return 1;	
}

inline int seq_pop (struct x_struct *x) {
	if(x->seq_num_start == x->seq_num_end)
		return 0;
	++x->seq_num_start;
	if(x->seq_num_start == SEQUENCE_NUM_BUFFER_SIZE)
		x->seq_num_start=0;
	return 1;
}

inline unsigned int roundup4 (unsigned int x) {
	unsigned int y=x/4;
	y*=4;
	if(y!=x)
		y+=4;
	return y;
}

inline void consume_decode_buffer (int size, struct x_struct* x) {
	x->decode_buffer_start += size;
	if (x->decode_buffer_start == x->decode_buffer_end) {
		x->decode_buffer_start = x->decode_buffer;
		x->decode_buffer_end = x->decode_buffer;
	}
}

inline void validate_decode_buffer (char* buffer, int size, struct x_struct* x) {
	if (strncmp (x->decode_buffer_start, buffer, size)) {
		printk ("Validate for decode buffer fails.\n");
		BUG ();
	}
	/*int i = 0;
	for (; i<size; ++i) {
		if (buffer[i] != x->decode_buffer_start[i])
			printk ("validate:%d, %d, %d\n", i, buffer[i], x->decode_buffer_start[i]);
	}*/
}

int locateMessage_req (int* dataLength, char* buf, int size, struct x_struct *x) {
	if (size < 4)
		return 0;	
	if (x->firstMessage_req) {
		if (size < 12)
			return 0;
		*dataLength=12+roundup4(GetUINT(buf+6))+roundup4(GetUINT(buf+8));
		if (x_detail) printk("First message request, size:%d\n", *dataLength);
		//*dataLength = 48;
	}
	else {
		*dataLength = (GetUINT (buf+2) << 2);
	}
	//printk("%d\n",*dataLength);
	if (*dataLength > DECODE_BUFFER_SIZE || *dataLength<0){
		//TODO
		//WHY???
		printk ("%d,size:%d,*buf:%d\n", *dataLength, size, *buf);
		*dataLength = size;
	}
	if (size < *dataLength)
		return 0;
	if (x_detail) printk ("request:\tdatalength:%d \t", *dataLength);
	return 1;

}

int locateMessage_reply (int* dataLength, char* buf, int size, struct x_struct *x) {
	if (size < 8)
		return 0;	
	if (x->firstMessage_reply) {
		//*dataLength = 332;
		*dataLength = 8 + (GetUINT(buf+6) << 2);
		printk ("first reply message should be %d long\n", *dataLength);
	}
	else {
		if (*buf == 1)
			*dataLength = 32 + ((*(unsigned int*)(buf+4))<<2);
		else 
			*dataLength = 32;
	}
	//printk("%d\n",*dataLength);
	if (*dataLength > DECODE_BUFFER_SIZE || *dataLength<0) {
		//TODO
		//WHY???
		printk ("%d,size:%d,*buf:%d\n", *dataLength, size, *buf);
		*dataLength = size;
	}
	if (size < *dataLength)
		return 0;
	if (x_detail) printk ("reply:\tdatalength:%d \t", *dataLength);
	return 1;
}

int getMessage_req (const char* buf, int size, struct x_struct *x) {
	int dataLength = 0;
	int complete_message = 0;
	if (x->buffer_message_req == 0) {
		if(buf != NULL) {	
			copy_from_user (x->buffer_req, buf, size);
			x->buffer_size_req = size;		
		}
		//printk("here\n");
		if (locateMessage_req (&dataLength, x->buffer_req + x->buffer_start_req, x->buffer_size_req - x->buffer_start_req, x) == 0) {
			//buffer the message until completed
			x->buffer_message_req = 1;
		}
		else {
			complete_message = 1;
		}
	}
	else {
		if (buf != NULL) {
			copy_from_user (x->buffer_req + x->buffer_size_req, buf, size);
			x->buffer_size_req += size;
		}
		if (locateMessage_req (&dataLength, x->buffer_req + x->buffer_start_req, x->buffer_size_req - x->buffer_start_req, x) == 1) {
			//memset(buffer,0,buffer_size);
			//buffer_size=0;
			x->buffer_message_req = 0;
			complete_message = 1;			
		}
		if (dataLength >= DECODE_BUFFER_SIZE) {
			printk ( "message too long!\n");
			x->buffer_message_req = 0;
			complete_message = 1;
			BUG ();
			return 0;
		}
		if (dataLength >= 128000)
			printk ("long message >128000, dateLenght:%d, pos:%d\n", dataLength, x->buffer_size_req);

	}
	if (complete_message && x->firstMessage_req) x->firstMessage_req = 0;
	if (complete_message) {
		//memcpy (x->message_req, x->buffer_req + x->buffer_start_req, dataLength);
		return dataLength;
	}
	else
		return 0;

}

int getMessage_reply (char* buf, int size, struct x_struct *x) {
	int dataLength = 0;
	int complete_message = 0;
	if (x->buffer_message_reply == 0) {
		if (buf != NULL) {	
			memcpy(x->buffer_reply, buf, size);
			x->buffer_size_reply = size;		
		}
		//printk("here\n");
		if (locateMessage_reply (&dataLength, x->buffer_reply + x->buffer_start_reply, x->buffer_size_reply - x->buffer_start_reply, x) == 0) {
			//buffer the message until completed
			x->buffer_message_reply = 1;
		}
		else {
			complete_message=1;
		}
	}
	else {
		if (buf != NULL) {
			memcpy (x->buffer_reply + x->buffer_size_reply, buf, size);
			x->buffer_size_reply += size;
		}
		if (locateMessage_reply (&dataLength, x->buffer_reply + x->buffer_start_reply, x->buffer_size_reply - x->buffer_start_reply, x) == 1){
			//memset(buffer,0,buffer_size);
			//buffer_size=0;
			x->buffer_message_reply = 0;
			complete_message = 1;			
		}
		if (dataLength >= DECODE_BUFFER_SIZE) {
			printk("message too long!\n");
			x->buffer_message_reply = 0;
			complete_message = 1;
			return 0;
		}
		if (dataLength >= 128000)
			printk("long message >128000, %d\n", dataLength);

	}
	//if(complete_message && current->record_thrd->rp_clog.firstMessage_reply) current->record_thrd->rp_clog.firstMessage_reply=0;
	if (complete_message) {
		//memcpy (x->message_reply, x->buffer_reply + x->buffer_start_reply, dataLength);
		return dataLength;
	}
	else
		return 0;

}

void x_compress_req (const char* __user buf, int size, struct x_struct *x) {
	int dataLength = 0;
	unsigned char* message = NULL;
	//int lookup;

	while (1) {
		if (size < 0)
			printk ("the size <0!/n");
		dataLength = getMessage_req (buf, size, x);

		//dumpMessage(message, dataLength);	
		if (dataLength > 0) {
			message = (unsigned char*) (x->buffer_req + x->buffer_start_req);
			if(x_detail) printk("opcode:%s, dataLength:%u ", *message < 128? XPROTO_TABLE[*message]: "other", dataLength);
			seq_push (*message, message[1], x);
			/*if (*message_req==72)			
			{	
				//blockcacheset_insert(image_cache_set, message_req+24, dataLength-24);
				//printk("putimage message, content length:%d, cache_length:%d\n", dataLength-24, image_cache_set->length);
			}
			//if(*message_req==73)
			//{
			//	lookup=blockcacheset_lookup(image_cache_set, dataLength-32, message_req+32);
			//	printk("getimage message, index:%d\n", lookup);
			//}*/
		}

		if (dataLength == 0) {
			return;
		}
		else if (dataLength > x->buffer_size_req - x->buffer_start_req)
			printk ("uncomplete message here.\n");
		else if (dataLength < x->buffer_size_req - x->buffer_start_req) {
			if(x_detail) printk ("\t\t\tdata Length exceeds.\n");
			x->buffer_start_req += dataLength;
			//x_compress_req(NULL,0);
			buf = NULL;
			size = 0;
			continue;
		}
		else {
			x->buffer_start_req = 0;
		}
		break;
	}
}

void encodeCharInfo_(unsigned char* nextSrc, struct x_struct *x, struct clog_node *node) {
	unsigned int value = GetUINT(nextSrc) | (GetUINT(nextSrc + 10) << 16);
	unsigned int i = 1;
	encodeCachedValue(value, 32, &x->serverCache_.queryFontCharInfoCache[0], 6, node);
	nextSrc += 2;
	for (i = 1; i < 5; ++i) {
		value = GetUINT(nextSrc);
		nextSrc += 2;
		encodeCachedValue(value, 16, &x->serverCache_.queryFontCharInfoCache[i], 6, node);
	}
}

void decodeCharInfo_(unsigned char *nextDest, struct x_struct *x, struct clog_node* node) {
	unsigned int value;
	unsigned int i;

	decodeCachedValue(&value, 32, &x->serverCache_.queryFontCharInfoCache[0], 6, 0, node);
	PutUINT(value & 0xffff, nextDest);
	PutUINT(value >> 16, nextDest + 10);
	nextDest += 2;
	for (i = 1; i < 5; i++) {
		unsigned int value;

		decodeCachedValue(&value, 16, &x->serverCache_. queryFontCharInfoCache[i], 6, 0, node);
		PutUINT(value, nextDest);
		nextDest += 2;
	}
}

int x_compress_reply (char* buf, int size, struct x_struct *x, struct clog_node *node) {
	unsigned int dataLength = 0;
	unsigned short int nextSequenceNum = 0;
	unsigned char opcode = 0;
	unsigned char nextOpcode = 0;
	unsigned int sequenceNum = -1;
	unsigned char* message = NULL;
	// int lookup=-1;
	int retval = 0;

	while (1) {

	dataLength = getMessage_reply (buf, size, x);
	if (dataLength > 0) {
		message = (unsigned char*) (x->buffer_reply + x->buffer_start_reply);
		size = dataLength;
		if (x->firstMessage_reply) {
			if (x_detail) printk("first message reply.\n");
			x->firstMessage_reply = 0;

#ifdef ENCODE
			encodeValue((unsigned int) message[0], 8, 0, node);
			encodeValue((unsigned int) message[1], 8, 0, node);
			encodeValue(GetUINT((char*)(message + 2)), 16, 0, node);
			encodeValue(GetUINT((char*)(message + 4)), 16, 0, node);
			encodeValue(GetUINT((char*)(message + 6)), 16, 0, node);
			if (blockcache_compare(&x->serverCache_.lastInitReply, size - 8, message + 8, 1))
				encodeValue(1, 1, 0, node);
			else {
				unsigned int i;
				encodeValue(0, 1, 0, node);
				for (i = 8; i < size; i++)
					encodeValue((unsigned int) message[i], 8, 0, node);
			}
#endif

		}
		else {
			if (message[0] == 1) {
				//unsigned char request_data;
				unsigned int sequenceNumDiff;
				unsigned int requestOpcode = 256;

				sequenceNum = GetUINT (message + 2);
				opcode= *(message);
#ifdef ENCODE
				sequenceNumDiff = sequenceNum - x->serverCache_.lastSequenceNum;
				x->serverCache_.lastSequenceNum = sequenceNum;
				encodeCachedCharValue(opcode, 8, &x->serverCache_.opcodeCache[x->serverCache_.lastOpcode], 0, node);
				encodeCachedValue(sequenceNumDiff, 16, &x->serverCache_.replySequenceNumCache, 7, node);
				x->serverCache_.lastOpcode = opcode;
#endif
				if (seq_peek (&nextSequenceNum, &nextOpcode, x)) {
					//printk ("sequence:%d, next:%d\n", sequenceNum, nextSequenceNum);
					while (sequenceNum>=nextSequenceNum) {
						//printk ("sequence:%d, next:%d\n", sequenceNum, nextSequenceNum);
						if (sequenceNum == nextSequenceNum) {
							break;
						}
						if (seq_pop(x) == 0) {
							printk ("consume all sequence numbers??, sequenceNum:%d, next:%d, start:%d, end:%d\n", sequenceNum, nextSequenceNum, x->seq_num_start, x->seq_num_end);
							//BUG ();
							break;
						}
						seq_peek (&nextSequenceNum, &nextOpcode, x);
					}

				}
				if (sequenceNum == nextSequenceNum) {
					if (x_detail)
						printk("   Reply: %s, Sequence number:%u, dataLength:%u, opcode:%u\n", nextOpcode < 128 ? XPROTO_TABLE[nextOpcode]: "other", GetUINT(message + 2), dataLength, nextOpcode);
#ifdef ENCODE
					requestOpcode = nextOpcode;
					//we have found the request
					//unsigned int requestData[3];
					//note:::we haven't deal with the request data here, only can deal with that in the runtime
					switch (nextOpcode) {
						case X_GetGeometry: 
							{
								char *nextSrc = message + 12;
								unsigned int i = 0;

								encodeCachedCharValue(message[1], 8,
										&x->serverCache_.depthCache, 0, node);
								encodeCachedValue(GetULONG(message + 8), 29,
										&x->serverCache_.getGeometryRootCache, 9, node);
								for (i = 0; i < 5; i++) {
									encodeCachedValue(GetUINT(nextSrc), 16,
											&x->serverCache_.getGeometryGeomCache[i], 8, node);
									nextSrc += 2;
								}
								memset(message + 22, 0, 10);
							}
							break;
						case X_GetInputFocus: 
							{
								encodeValue((unsigned int) message[1], 2, 0, node);
								encodeCachedValue(GetULONG(message + 8), 29,
										&x->serverCache_.getInputFocusWindowCache, 9, node);
								memset(message + 12, 0, 20);
							}
							break;
						case X_GetKeyboardMapping: 
							{
								unsigned int keysymsPerKeycode = (unsigned int) message[1];
								unsigned int numKeycodes;
								char *nextSrc = message + 32;
								unsigned char previous = 0;
								unsigned int count;

								if (blockcache_compare(&x->serverCache_.getKeyboardMappingLastMap, size	- 32, message + 32, 1)
										&& (keysymsPerKeycode == x->serverCache_.getKeyboardMappingLastKeysymsPerKeycode)) {
									encodeValue(1, 1, 0, node);
									break;
								}
								x->serverCache_. getKeyboardMappingLastKeysymsPerKeycode
									= keysymsPerKeycode;
								encodeValue(0, 1, 0, node);
								numKeycodes = (((size - 32)
											/ keysymsPerKeycode) >> 2);
								encodeValue(numKeycodes, 8, 0, node);
								encodeValue(keysymsPerKeycode, 8, 4, node);
								for (count = numKeycodes * keysymsPerKeycode; count; --count) {
									unsigned int keysym = GetULONG(nextSrc);
									nextSrc += 4;
									if (keysym == NoSymbol)
										encodeValue(1, 1, 0, node);
									else {
										unsigned int first3Bytes = (keysym >> 8);
										unsigned char lastByte = (unsigned char) (keysym & 0xff);
										encodeValue(0, 1, 0, node);

										encodeCachedValue(
												first3Bytes,
												24,
												&x->serverCache_.getKeyboardMappingKeysymCache,
												9, node);
										encodeCachedCharValue(
												lastByte - previous,
												8,
												&x->serverCache_.getKeyboardMappingLastByteCache,
												5, node);
										previous = lastByte;
									}
								}
								memset(message + 8, 0, 24);
							}
							break;
						case X_GetModifierMapping: 
							{
								char *nextDest = message + 32;
								unsigned int count;
								encodeValue((unsigned int) message[1], 8, 0, node);

								if (blockcache_compare(
											&x->serverCache_.getModifierMappingLastMap, size
											- 32, nextDest, 1)) {
									encodeValue(1, 1, 0, node);
									break;
								}
								encodeValue(0, 1, 0, node);
								for (count = size - 32; count; count--) {
									unsigned char next = *nextDest++;

									if (next == 0)
										encodeValue(1, 1, 0, node);
									else {
										encodeValue(0, 1, 0, node);
										encodeValue(next, 8, 0, node);
									}
								}
							}
							break;
						case X_GetSelectionOwner: 
							{

								encodeCachedValue(GetULONG(message + 8), 29,
										&x->serverCache_.getSelectionOwnerCache, 9, node);
								message[1] = 0;
								memset(message + 12, 0, 20);
							}
							break;
						case X_GetWindowAttributes: 
							{
								encodeValue((unsigned int) message[1], 2, 0, node);
								encodeCachedValue(GetULONG(message + 8), 29,
										&x->serverCache_.visualCache, 9, node);
								encodeCachedValue(GetUINT(message + 12), 16,
										&x->serverCache_.getWindowAttributesClassCache, 3, node);
								encodeCachedCharValue(
										message[14],
										8,
										&x->serverCache_.getWindowAttributesBitGravityCache,
										0, node);
								encodeCachedCharValue(
										message[15],
										8,
										&x->serverCache_.getWindowAttributesWinGravityCache,
										0, node);
								encodeCachedValue(GetULONG(message + 16), 32,
										&x->serverCache_.getWindowAttributesPlanesCache, 9, node);
								encodeCachedValue(GetULONG(message + 20), 32,
										&x->serverCache_.getWindowAttributesPixelCache, 9, node);
								encodeValue((unsigned int) message[24], 1, 0, node);
								encodeValue((unsigned int) message[25], 1, 0, node);
								encodeValue((unsigned int) message[26], 2, 0, node);
								encodeValue((unsigned int) message[27], 1, 0, node);
								encodeCachedValue(GetULONG(message + 28), 29,
										&x->serverCache_.colormapCache, 9, node);
								encodeCachedValue(
										GetULONG(message + 32),
										32,
										&x->serverCache_.getWindowAttributesAllEventsCache,
										0, node);
								encodeCachedValue(
										GetULONG(message + 36),
										32,
										&x->serverCache_.getWindowAttributesYourEventsCache,
										0, node);
								encodeCachedValue(
										GetUINT(message + 40),
										16,
										&x->serverCache_.getWindowAttributesDontPropagateCache,
										0, node);
								memset(message + 42, 0, 2);

							}
							break;
						case X_GrabKeyboard:
						case X_GrabPointer: 
							{
								encodeValue((unsigned int) message[1], 3, 0, node);
								memset(message + 8, 0, 24);
							}
							break;
						case X_InternAtom: 
							{

								encodeValue(GetULONG(message + 8), 32, 9, node);
								if (x_detail)
									printk("%u\n", GetULONG(message + 8));
								//print_string(message + 8, 4);
								message[1] = 0;
								memset(message + 12, 0, 20);
							}
							break;
						case X_ListExtensions: 
							{
								unsigned int numExtensions = (unsigned int) message[1];
								char *nextSrc = message + 32;
								encodeValue(GetULONG(message + 4), 32, 8, node);
								encodeValue(numExtensions, 8, 0, node);

								for (; numExtensions; numExtensions--) {
									unsigned int length = (unsigned int) (*nextSrc++);
									encodeValue(length, 8, 0, node);
									if (!strncmp((char *) nextSrc, "MIT-SHM", 7))
										memcpy((unsigned char *) nextSrc, "NOT-SHM", 7);
									for (; length; length--)
										encodeValue((unsigned
													int) (*nextSrc++), 8, 0, node);
								}
								memset(message + 8, 0, 24);
							}
							break;
						case X_LookupColor:
						case X_AllocNamedColor: 
							{
								char *nextSrc = message + 8;
								unsigned int count = 3;

								if (nextOpcode == X_AllocNamedColor) {
									encodeValue(GetULONG(nextSrc), 32, 9, node);
									nextSrc += 4;
								}

								do {
									unsigned int exactColor = GetUINT(nextSrc);
									unsigned int visualColor;
									encodeValue(exactColor, 16, 9, node);
									visualColor = GetUINT(nextSrc + 6)
										- exactColor;
									encodeValue(visualColor, 16, 5, node);
									nextSrc += 2;
								} while (--count);
								message[1] = 0;
								if (nextOpcode == X_AllocNamedColor)
									memset(message + 24, 0, 8);
								else
									memset(message + 20, 0, 12);
							}
							break;
						case X_QueryBestSize: 
							{
								encodeValue(GetUINT(message + 8), 16, 8, node);
								encodeValue(GetUINT(message + 10), 16, 8, node);
								message[1] = 0;
								memset(message + 12, 0, 20);
							}
							break;
						case X_QueryColors: 
							{
								unsigned int numColors = ((size - 32) >> 3);
								char *nextSrc = message + 40;
								unsigned char *nextDest = (unsigned char *) message
									+ 38;
								unsigned int c;
								unsigned int i;
								unsigned int colorsLength = numColors * 6;
								for (c = 1; c < numColors; c++) {
									for (i = 0; i < 6; i++)
										*nextDest++ = *nextSrc++;
									nextSrc += 2;
								}

								if (blockcache_compare(
											&x->serverCache_.queryColorsLastReply,
											colorsLength, message + 32, 1))
									encodeValue(1, 1, 0, node);
								else {
									char *nextSrc = message + 32;

									encodeValue(0, 1, 0, node);
									encodeValue(numColors, 16, 5, node);
									for (numColors *= 3; numColors; numColors--) {
										encodeValue(GetUINT(nextSrc), 16, 0, node);
										nextSrc += 2;
									}
								}
								message[1] = 0;
								memset(message + 10, 0, 22);

							}
							break;
						case X_QueryFont: 
							{
								unsigned int numProperties = GetUINT(message + 46);
								unsigned int numCharInfos = GetULONG(message + 56);
								char *nextSrc = message + 60;
								unsigned int index;
								encodeValue(numProperties, 16, 8, node);
								encodeValue(numCharInfos, 32, 10, node);
								encodeCharInfo_(message + 8, x, node);
								encodeCharInfo_(message + 24, x, node);
								encodeValue(GetUINT(message + 40), 16, 9, node);
								encodeValue(GetUINT(message + 42), 16, 9, node);
								encodeValue(GetUINT(message + 44), 16, 9, node);
								encodeValue((unsigned int) message[48], 1, 0, node);
								encodeValue((unsigned int) message[49], 8, 0, node);
								encodeValue((unsigned int) message[50], 8, 0, node);
								encodeValue((unsigned int) message[51], 1, 0, node);
								encodeValue(GetUINT(message + 52), 16, 9, node);
								encodeValue(GetUINT(message + 54), 16, 9, node);

								if (blockcacheset_lookup(
											&x->serverCache_.queryFontFontCache, numProperties
											* 8 + numCharInfos * 12, nextSrc,
											&index)) {
									encodeValue(1, 1, 0, node);
									encodeValue(index, 4, 0, node);
									break;
								}
								encodeValue(0, 1, 0, node);
								for (; numProperties; numProperties--) {
									encodeValue(GetULONG(nextSrc), 32, 9, node);
									encodeValue(GetULONG(nextSrc + 4), 32, 9, node);
									nextSrc += 8;
								}
								for (; numCharInfos; numCharInfos--) {
									encodeCharInfo_(nextSrc, x, node);
									nextSrc += 12;
								}
								message[1] = 0;
								memset(message + 28, 0, 4);
							}
							break;
						case X_QueryPointer: 
							{
								unsigned int rootX = GetUINT(message + 16);
								unsigned int rootY = GetUINT(message + 18);
								unsigned int eventX = GetUINT(message + 20);
								unsigned int eventY = GetUINT(message + 22);

								encodeValue((unsigned int) message[1], 1, 0, node);
								encodeCachedValue(GetULONG(message + 8), 29,
										&x->serverCache_.queryPointerRootCache, 9, node);
								encodeCachedValue(GetULONG(message + 12), 29,
										&x->serverCache_.queryPointerChildCache, 9, node);
								eventX -= rootX;
								eventY -= rootY;
								encodeCachedValue(rootX
										- x->serverCache_.motionNotifyLastRootX, 16,
										&x->serverCache_.motionNotifyRootXCache, 8, node);
								x->serverCache_.motionNotifyLastRootX = rootX;
								encodeCachedValue(rootY
										- x->serverCache_.motionNotifyLastRootY, 16,
										&x->serverCache_.motionNotifyRootYCache, 8, node);
								x->serverCache_.motionNotifyLastRootY = rootY;
								encodeCachedValue(eventX, 16,
										&x->serverCache_.motionNotifyEventXCache, 8, node);
								encodeCachedValue(eventY, 16,
										&x->serverCache_.motionNotifyEventYCache, 8, node);
								encodeCachedValue(GetUINT(message + 24), 16,
										&x->serverCache_.motionNotifyStateCache, 0, node);
								memset(message + 26, 0, 6);
							}
							break;
						case X_QueryTree: 
							{
								unsigned int i;
								//encodeValue(message[1], 8, 0);
								encodeValue(GetULONG(message + 4), 32, 8, node);
								for (i = 8; i < 16; ++i)
									encodeValue((unsigned int) message[i], 8, 0, node);
								encodeValue (GetUINT (message + 16), 16, 0, node);
								for (i = 32; i < size; i++)
									encodeValue((unsigned int) message[i], 8, 0, node);
								message[1] = 0;
								memset(message + 18, 0, 14);
							}
							break;
						case X_TranslateCoords:
							{
								encodeValue((unsigned int) message[1], 1, 0, node);
								memset (message + 4, 0, 4);
								encodeCachedValue(GetULONG(message + 8), 29,
										&x->serverCache_.translateCoordsChildCache, 9, node);
								encodeCachedValue(GetUINT(message + 12), 16,
										&x->serverCache_.translateCoordsXCache, 8, node);
								encodeCachedValue(GetUINT(message + 14), 16,
										&x->serverCache_.translateCoordsYCache, 8, node);
								memset(message + 16, 0, 16);
							}
							break;
							
						default:
							{
								int i = 8;
								if (x_detail)
									printk(
											"assertion failed in processMessage:\n no matching request for reply with sequence number , opcode:%u\n",
											nextOpcode);
								//knows nothing about opcode
								if (nextOpcode != X_GetImage) {
									encodeValue(message[1], 8, 0, node);
									encodeValue(*((unsigned int*) (message + 4)), 32, 0, node);
									for (i = 8; i < dataLength; ++i)
										encodeValue((unsigned int) message[i], 8, 0, node);
								}
							}

					}
#endif
				} else {
					int i = 8;
					//knows nothing about opcode
					printk("knows nothing about opcode\n");
#ifdef ENCODE
					encodeValue(message[1], 8, 0, node);
					encodeValue(*((unsigned int*) (message + 4)), 32, 0, node);
					for (i = 8; i < dataLength; ++i)
						encodeValue((unsigned int) message[i], 8, 0, node);
#endif
				}
				if(x_detail) printk("			written Bits:%u\n", getCumulativeBitsWritten(node));

			}
			else {
				unsigned int sequenceNumDiff;
				sequenceNum = GetUINT (message+2);
				opcode = *message;
				if(x_detail) printk("event:%u, sequence number:%u\n", opcode, sequenceNum);
				sequenceNumDiff = sequenceNum - x->serverCache_.lastSequenceNum;
#ifdef ENCODE
				x->serverCache_.lastSequenceNum = sequenceNum;
				encodeCachedCharValue(opcode, 8,
						&x->serverCache_. opcodeCache[x->serverCache_. lastOpcode], 0, node);
				x->serverCache_.lastOpcode = opcode;
				encodeCachedValue(sequenceNumDiff, 16,
						&x->serverCache_. eventSequenceNumCache, 7, node);
				switch (opcode) {
					case 0: 
						{
							unsigned char code = message[1];

							encodeCachedCharValue(code, 8,
									&x->serverCache_. errorCodeCache, 0, node);
							if ((code != 11) && (code != 8) && (code != 15) && (code
										!= 1))

								encodeValue(GetULONG(message + 4), 32, 16, node);
							if (code >= 18)

								encodeCachedValue(GetUINT(message + 8), 16,
										&x->serverCache_. errorMinorCache, 0, node);
							encodeCachedCharValue(message[10], 8,
									&x->serverCache_. errorMajorCache, 0, node);
							if (code >= 18) {
								char *nextSrc = message + 11;
								int i;
								for (i = 11; i < 32; i++)
									encodeValue(*nextSrc++, 8,0, node);
							}
						}
						break;
					case ButtonPress:
					case ButtonRelease:
					case KeyPress:
					case KeyRelease:
					case MotionNotify:
					case EnterNotify:
					case LeaveNotify: 
						{
							unsigned char detail = message[1];
							int skipRest = 0;
							unsigned int timestamp = GetULONG(message + 4);
							unsigned int timestampDiff;

							if (*message == MotionNotify)
								encodeValue((unsigned int) detail, 1, 0, node);
							else if ((*message == EnterNotify) || (*message
										== LeaveNotify))
								encodeValue((unsigned int) detail, 3, 0, node);
							else if (*message == KeyRelease) {
								if (detail == x->serverCache_.keyPressLastKey)
									encodeValue(1, 1, 0, node);
								else {
									encodeValue(0, 1, 0, node);

									encodeValue((unsigned int) detail, 8, 0, node);
								}
							} else if ((*message == ButtonPress) || (*message
										== ButtonRelease))
								encodeCachedCharValue(detail, 8,
										&x->serverCache_. buttonCache, 0, node);
							else
								encodeValue((unsigned int) detail, 8, 0, node);
							timestampDiff = timestamp
								- x->serverCache_.lastTimestamp;
							x->serverCache_.lastTimestamp = timestamp;
							encodeCachedValue(timestampDiff, 32,
									&x->serverCache_. motionNotifyTimestampCache, 9, node);

							if (*message == KeyRelease) {
								unsigned int i;
								skipRest = 1;
								for (i = 8; i < 31; i++) {
									if (message[i] != x->serverCache_.keyPressCache[i - 8]) {
										skipRest = 0;
										break;
									}
								}
								encodeValue(skipRest, 1, 0, node);
							}
							if (!skipRest) {
								char *nextSrc = message + 8;
								unsigned int i;
								unsigned int rootX = GetUINT(message + 20);
								unsigned int rootY = GetUINT(message + 22);
								unsigned int eventX = GetUINT(message + 24);
								unsigned int eventY = GetUINT(message + 26);

								for (i = 0; i < 3; i++) {

									encodeCachedValue(GetULONG(nextSrc), 29,
											&x->serverCache_. motionNotifyWindowCache[i],
											6, node);
									nextSrc += 4;
								}
								eventX -= rootX;
								eventY -= rootY;
								encodeCachedValue(rootX
										- x->serverCache_. motionNotifyLastRootX, 16,
										&x->serverCache_. motionNotifyRootXCache, 6, node);
								x->serverCache_.motionNotifyLastRootX = rootX;
								encodeCachedValue(rootY
										- x->serverCache_. motionNotifyLastRootY, 16,
										&x->serverCache_. motionNotifyRootYCache, 6, node);
								x->serverCache_.motionNotifyLastRootY = rootY;
								encodeCachedValue(eventX, 16,
										&x->serverCache_. motionNotifyEventXCache, 6, node);
								encodeCachedValue(eventY, 16,
										&x->serverCache_. motionNotifyEventYCache, 6, node);

								encodeCachedValue(GetUINT(message + 28), 16,
										&x->serverCache_. motionNotifyStateCache, 0, node);
								if ((*message == EnterNotify) || (*message
											== LeaveNotify))

									encodeValue((unsigned int) message[30], 2, 0, node);
								else

									encodeValue((unsigned int) message[30], 1, 0, node);
								if ((*message == EnterNotify) || (*message
											== LeaveNotify)) {
									encodeValue((unsigned int) message[31], 2, 0, node);
									message[31] &= 3;
								} else if (*message == KeyPress) {
									unsigned int i;
									x->serverCache_.keyPressLastKey = detail;
									for (i = 8; i < 31; i++) {
										x->serverCache_.keyPressCache[i - 8] = message[i];
									}
									message[31] = 0;
								} else
									message[31] = 0;
								if (nextOpcode == ButtonRelease)
									message[31] = 0;
							}
							if (x_detail)
								printk("		timstamp:%d\n", timestamp);
						}

						break;
					case ColormapNotify: 
						{

							encodeCachedValue(GetULONG(message + 4), 29,
									&x->serverCache_. colormapNotifyWindowCache, 8, node);

							encodeCachedValue(GetULONG(message + 8), 29,
									&x->serverCache_. colormapNotifyColormapCache, 8, node);
							encodeValue((unsigned int) message[12], 1, 0, node);
							encodeValue((unsigned int) message[13], 1, 0, node);
							message[1] = 0;
							memset(message + 14, 0, 18);
						}
						break;
					case ConfigureNotify: 
						{
							char *nextSrc = message + 4;
							unsigned int i;
							unsigned int j;
							for (i = 0; i < 3; i++) {

								encodeCachedValue(GetULONG(nextSrc), 29,
										&x->serverCache_. configureNotifyWindowCache[i], 9, node);
								nextSrc += 4;
							}
							for (j = 0; j < 5; j++) {

								encodeCachedValue(GetUINT(nextSrc), 16,
										&x->serverCache_. configureNotifyGeomCache[j], 8, node);
								nextSrc += 2;
							}
							encodeValue(*nextSrc, 1, 0, node);
							message[1] = 0;
							memset(message + 27, 0, 5);
						}
						break;
					case CreateNotify: 
						{
							unsigned int window = GetULONG(message + 8);
							char *nextSrc = message + 12;
							unsigned int i;

							encodeCachedValue(GetULONG(message + 4), 29,
									&x->serverCache_. createNotifyWindowCache, 9, node);
							encodeValue(window - x->serverCache_. createNotifyLastWindow,
									29, 5, node);
							x->serverCache_.createNotifyLastWindow = window;
							for (i = 0; i < 5; i++) {

								encodeValue(GetUINT(nextSrc), 16, 9, node);
								nextSrc += 2;
							}
							encodeValue((unsigned int) *nextSrc, 1, 0, node);
							message[1] = 0;
							memset(message + 23, 0, 9);
						}
						break;
					case Expose: 
						{

							char *nextSrc = message + 8;
							unsigned int i;
							encodeCachedValue(GetULONG(message + 4), 29,
									&x->serverCache_.exposeWindowCache, 9, node);
							for (i = 0; i < 5; i++) {

								encodeCachedValue(GetUINT(nextSrc), 16,
										&x->serverCache_. exposeGeomCache[i], 6, node);
								nextSrc += 2;
							}
							message[1] = 0;
							memset(message + 18, 0, 14);
							//printk("		x:%u, y:%u, width:%u, height:%u, count:%u\n", GetUINT(message+8), GetUINT(message+10),  GetUINT(message+12),  GetUINT(message+14),  GetUINT(message+16));
						}
						break;
					case FocusIn:
					case FocusOut: 
						{
							encodeValue((unsigned int) message[1], 3, 0, node);

							encodeCachedValue(GetULONG(message + 4), 29,
									&x->serverCache_.focusInWindowCache, 9, node);
							encodeValue((unsigned int) message[8], 2, 0, node);
							memset(message + 9, 0, 23);
						}
						break;
					case KeymapNotify: 
						{
							if (blockcache_compare(&x->serverCache_.lastKeymap, 31,
										message + 1, 1))
								encodeValue(1, 1, 0, node);
							else {
								char *nextSrc = message + 1;
								unsigned int i;
								encodeValue(0, 1, 0, node);
								for (i = 1; i < 32; i++)

									encodeValue((unsigned int) *nextSrc++, 8, 0, node);
							}
						}
						break;
					case MapNotify:
					case UnmapNotify:
					case DestroyNotify: 
						{
							message[1] = 0;

							encodeCachedValue(GetULONG(message + 4), 29,
									&x->serverCache_. mapNotifyEventCache, 9, node);

							encodeCachedValue(GetULONG(message + 8), 29,
									&x->serverCache_. mapNotifyWindowCache, 9, node);
							if ((*message == MapNotify) || (*message == UnmapNotify))

								encodeValue((unsigned int) message[12], 1, 0, node);
							else
								message[12] = 0;
							memset(message + 13, 0, 19);
						}
						if (x_detail)
							printk("		eventwindow:%u, window:%u\n", GetULONG(
										message + 4), GetULONG(message + 8));
						break;
					case NoExpose: 
						{

							encodeCachedValue(GetULONG(message + 4), 29,
									&x->serverCache_. noExposeDrawableCache, 9, node);

							encodeCachedValue(GetUINT(message + 8), 16,
									&x->serverCache_. noExposeMinorCache, 0, node);
							encodeCachedCharValue(message[10], 8,
									&x->serverCache_. noExposeMajorCache, 0, node);
							message[1] = 0;
							memset(message + 11, 0, 21);
						}
						break;
					case PropertyNotify: 
						{
							unsigned int timestamp = GetULONG(message + 12);
							unsigned int timestampDiff;
							message[1] = 0;
							memset(message + 17, 0, 15);
							encodeCachedValue(GetULONG(message + 4), 29,
									&x->serverCache_. propertyNotifyWindowCache, 9, node);

							encodeCachedValue(GetULONG(message + 8), 29,
									&x->serverCache_. propertyNotifyAtomCache, 9, node);
							timestampDiff = timestamp
								- x->serverCache_.lastTimestamp;
							x->serverCache_.lastTimestamp = timestamp;
							encodeValue(timestampDiff, 32, 9, node);
							encodeValue((unsigned int) message[16], 1, 0, node);
							message[1] = 0;
							memset(message + 17, 0, 15);
							if (x_detail)
								printk("		Windows:%d, Atom:%d, timstamp:%d\n",
										GetULONG(message + 4), GetULONG(message + 8),
										timestamp);
						}
						break;
					case ReparentNotify: 
						{
							char *nextSrc = message + 4;
							unsigned int i;
							for (i = 0; i < 3; i++) {

								encodeCachedValue(GetULONG(nextSrc), 29,
										&x->serverCache_. reparentNotifyWindowCache, 9, node);
								nextSrc += 4;
							}
							encodeValue(GetUINT(nextSrc), 16, 6, node);

							encodeValue(GetUINT(nextSrc + 2), 16, 6, node);
							encodeValue((unsigned int) message[20], 1, 0, node);
							message[1] = 0;
							memset(message + 21, 0, 11);
						}
						break;
					case SelectionClear: 
						{
							unsigned int timestamp = GetULONG(message + 4);
							unsigned int timestampDiff = timestamp
								- x->serverCache_.lastTimestamp;
							x->serverCache_.lastTimestamp = timestamp;
							encodeValue(timestampDiff, 32, 9, node);

							encodeCachedValue(GetULONG(message + 8), 29,
									&x->serverCache_. selectionClearWindowCache, 9, node);

							encodeCachedValue(GetULONG(message + 12), 29,
									&x->serverCache_. selectionClearAtomCache, 9, node);
							if (x_detail)
								printk("		Timestamp:%u, windows:%u, atom:%u\n",
										timestamp, GetULONG(message + 8), GetULONG(
											message + 12));
							message[1] = 0;
							memset(message + 16, 0, 16);
						}
						break;
					case SelectionRequest: 
						{
							unsigned int timestamp = GetULONG(message + 4);
							unsigned int timestampDiff = timestamp
								- x->serverCache_.lastTimestamp;
							x->serverCache_.lastTimestamp = timestamp;
							encodeValue(timestampDiff, 32, 9, node);

							encodeCachedValue(GetULONG(message + 8), 29,
									&x->serverCache_. selectionClearWindowCache, 9, node);

							encodeCachedValue(GetULONG(message + 12), 29,
									&x->serverCache_. selectionClearWindowCache, 9, node);

							encodeCachedValue(GetULONG(message + 16), 29,
									&x->serverCache_. selectionClearAtomCache, 9, node);

							//TODO
							message[1] = 0;
							memset(message + 28, 0, 4);
							if (x_detail)
								printk(
										"		Windows:%d, Window:%d, Atom:%d, timstamp:%d\n",
										GetULONG(message + 8), GetULONG(message + 12),
										GetULONG(message + 16), timestamp);
						}
						break;
					case VisibilityNotify: 
						{

							encodeCachedValue(GetULONG(message + 4), 29,
									&x->serverCache_. visibilityNotifyWindowCache, 9, node);
							encodeValue((unsigned int) message[8], 2, 0, node);
							message[1] = 0;
							memset(message + 9, 0, 23);
						}
						break;
						/*
						   case X_GrabButton: {

						   if (message[1] == 0)
						   encodeValue(0, 1, 0, node);
						   else
						   encodeValue(1, 1, 0, node);
						   encodeCachedValue(GetULONG(message + 4), 32,
						   &x->serverCache_.grabButtonGrabWindow, 8, node);
						   encodeValue(GetUINT(message + 8), 16, 4, node);
						   if (message[10])
						   encodeValue(0, 1, 0, node);
						   else
						   encodeValue(1, 1, 0, node);
						   if (message[11])
						   encodeValue(0, 1, 0, node);
						   else
						   encodeValue(1, 1, 0, node);
						   encodeCachedValue(GetULONG(message + 12), 32,
						   &x->serverCache_.grabButtonConfineTo, 8, node);
						   encodeCachedValue(GetULONG(message + 16), 32,
						   &x->serverCache_.grabButtonCursor, 8, node);
						   encodeValue((unsigned int)message[21], 8, 4, node);
						   message[22]=0;
						   encodeValue(GetUINT(message+23), 16, 4, node);

						   }
						   break;
						 */
					default: 
						{
							unsigned int i;
							encodeValue(message[1], 8, 0, node);
							for (i = 4; i < size; i++)
								encodeValue((unsigned int) message[i], 8, 0, node);
						}
				}
#endif
			}
		}
	}
	if (dataLength == 0) {
		return retval;
	}
	else if (dataLength > x->buffer_size_reply - x->buffer_start_reply)
		printk("uncomplete message here.\n");
	else if (dataLength < x->buffer_size_reply-x->buffer_start_reply) {
		if (retval == 1) printk ("data Length exceeds for reply message!!!.\n");
		//printk("datalength:%d, buffer_start:%d, buffer_size:%d\n", dataLength, buffer_start_reply, buffer_size_reply);
		x->buffer_start_reply += dataLength;
		buf = NULL;
		size = 0;
		continue;
		//x_compress_reply (NULL,0, x, node);
	}
	else {
		x->buffer_start_reply = 0;
	}
	return retval;
	}
}

void x_decompress_reply (int size, struct x_struct *x, struct clog_node *node) {
	int size_count = x->decode_buffer_end - x->decode_buffer_start;
	printk ("size_count:%d, start:%d, end:%d, size:%d\n", size_count, x->decode_buffer_start - x->decode_buffer, x->decode_buffer_end - x->decode_buffer, size);
	while (size_count < size) {

		if (x->firstMessage_reply) {
			unsigned int opcode;
			unsigned int secondByte;
			unsigned int major;
			unsigned int minor;
			unsigned int extraLength;
			unsigned int outputLength;
			unsigned char *outputMessage;
			unsigned char *nextDest;
			unsigned int cached;
			unsigned int i = 0;

			decodeValue(&opcode, 8, 0, 0, node);

			decodeValue(&secondByte, 8, 0, 0, node);

			decodeValue(&major, 16, 0, 0, node);

			decodeValue(&minor, 16, 0, 0, node);

			decodeValue(&extraLength, 16, 0, 0, node);
			outputLength = 8 + (extraLength << 2);
			outputMessage = addMessage(outputLength, x);

			*outputMessage = (unsigned char) opcode;
			outputMessage[1] = (unsigned char) secondByte;
			PutUINT(major, outputMessage + 2);
			PutUINT(minor, outputMessage + 4);
			PutUINT(extraLength, outputMessage + 6);

			nextDest = outputMessage + 8;

			decodeValue(&cached, 1, 0, 0, node);
			if (cached)
				memcpy(nextDest, x->serverCache_.lastInitReply.buffer,
						outputLength - 8);
			else {

				for (i = 8; i < outputLength; i++) {
					unsigned int nextByte;

					decodeValue(&nextByte, 8, 0, 0, node);
					*nextDest++ = (unsigned char) nextByte;
				}
				blockcache_set(&x->serverCache_.lastInitReply, outputLength - 8,
						outputMessage + 8);
			}
			//imageByteOrder_ = outputMessage[30];
			//bitmapBitOrder_ = outputMessage[31];
			//scanlineUnit_ = outputMessage[32];
			//scanlinePad_ = outputMessage[33];
			printk("first reply message, size:%d\n", outputLength);
			x->firstMessage_reply  = 0;
			size_count += outputLength;
		} else {
			unsigned int i = 0;
			unsigned char opcode;


			unsigned char *outputMessage = NULL;
			unsigned int outputLength = 0;
			unsigned int value; // general-purpose temp variable for decoding ints

			unsigned char cValue; // general-purpose temp variable for decoding chars

			decodeCachedCharValue(&opcode, 8,&x->serverCache_. opcodeCache[x->serverCache_. lastOpcode], 8, 1, node);
			x->serverCache_.lastOpcode = opcode;


			if (opcode == 1) {
				//reply
				unsigned int sequenceNumDiff;
				unsigned int sequenceNum;
				unsigned short int nextSequenceNum = 0;
				unsigned char nextOpcode = 255;
				unsigned int requestOpcode = 256;

				unsigned int count = 0;

				decodeCachedValue(&sequenceNumDiff, 16,
						&x->serverCache_. replySequenceNumCache, 7, 0, node);
				sequenceNum = x->serverCache_.lastSequenceNum
					+ sequenceNumDiff;
				sequenceNum &= 0xffff;
				x->serverCache_.lastSequenceNum = sequenceNum;
				//reply
				if (seq_peek(&nextSequenceNum, &nextOpcode, x)) {

					while (sequenceNum >= nextSequenceNum) {
						//printk("test, cur:%u, seq:%u\n",cur_seq,sequence);
						if (sequenceNum == nextSequenceNum) {
							printk(
									"   Sequence number:%u, nextOpcode:%u, Opname:%s\n",
									sequenceNum, nextOpcode, nextOpcode<128?XPROTO_TABLE[nextOpcode]:"other");
							break;
						}
						if (seq_pop(x) == 0) {
							printk ("consume all sequence numbers??, sequenceNum:%d, next:%d, start:%d, end:%d\n", sequenceNum, nextSequenceNum, x->seq_num_start, x->seq_num_end);
							break;
						}

						seq_peek(&nextSequenceNum, &nextOpcode, x);
					}
				}


				if (sequenceNum == nextSequenceNum) {
					requestOpcode = nextOpcode;

					switch (nextOpcode)
					{

						case X_GetGeometry: 
							{
								unsigned char *nextDest;
								outputLength = 32;
								outputMessage = addMessage(outputLength, x);
								decodeCachedCharValue(&cValue, 8,
										&x->serverCache_. depthCache, 0, 0, node);
								outputMessage[1] = cValue;
								decodeCachedValue(&value, 29,
										&x->serverCache_. getGeometryRootCache, 9, 0, node);
								PutULONG(value, outputMessage + 8);

								nextDest = outputMessage + 12;

								for (i = 0; i < 5; i++) {
									decodeCachedValue(&value, 16,
											&x->serverCache_. getGeometryGeomCache[i],
											8, 0, node);
									PutUINT(value, nextDest);
									nextDest += 2;
								}
							}
							break;
						case X_GetInputFocus: 
							{
								outputLength = 32;
								outputMessage = addMessage(outputLength, x);
								decodeValue(&value, 2, 0, 0, node);
								outputMessage[1] = (unsigned char) value;
								if (!decodeCachedValue(&value, 29,
											&x->serverCache_. getInputFocusWindowCache, 9,
											0, node))
									printk ("error\n");
								PutULONG(value, outputMessage + 8);
							}
							break;
						case X_GetKeyboardMapping: 
							{
								unsigned int numKeycodes;
								unsigned int keysymsPerKeycode;
								unsigned char *nextDest;
								unsigned char previous = 0;
								decodeValue(&value, 1, 0, 0, node);
								if (value) {
									unsigned int dataLength = x->serverCache_.getKeyboardMappingLastMap. size;
									outputLength = 32 + dataLength;
									outputMessage = addMessage(outputLength, x);
									outputMessage[1] = x->serverCache_. getKeyboardMappingLastKeysymsPerKeycode;
									memcpy(
											outputMessage + 32,
											x->serverCache_.getKeyboardMappingLastMap. buffer,
											dataLength);
									break;
								}

								decodeValue(&numKeycodes, 8, 0, 0, node);

								decodeValue(&keysymsPerKeycode, 8, 4, 0, node);
								x->serverCache_. getKeyboardMappingLastKeysymsPerKeycode
									= keysymsPerKeycode;
								outputLength = 32 + numKeycodes * keysymsPerKeycode
									* 4;
								outputMessage = addMessage(outputLength, x);
								outputMessage[1]
									= (unsigned char) keysymsPerKeycode;
								nextDest = outputMessage + 32;
								for (count = numKeycodes * keysymsPerKeycode; count; --count) {
									decodeValue(&value, 1, 0, 0, node);
									if (value)
										PutULONG((unsigned int) NoSymbol, nextDest);
									else {
										unsigned int keysym;

										decodeCachedValue(
												&keysym,
												24,
												&x->serverCache_. getKeyboardMappingKeysymCache,
												9, 0, node);
										decodeCachedCharValue(
												&cValue,
												8,
												&x->serverCache_. getKeyboardMappingLastByteCache,
												5, 0, node);
										previous += cValue;
										PutULONG((keysym << 8) | previous, nextDest);
									}
									nextDest += 4;
								}
								blockcache_set(
										&x->serverCache_.getKeyboardMappingLastMap,
										outputLength - 32, outputMessage + 32);
							}
							break;
						case X_GetModifierMapping: 
							{
								unsigned int keycodesPerModifier;
								unsigned char *nextDest;

								decodeValue(&keycodesPerModifier, 8, 0, 0, node);
								outputLength = 32 + (keycodesPerModifier << 3);
								outputMessage = addMessage(outputLength, x);
								outputMessage[1]
									= (unsigned char) keycodesPerModifier;
								nextDest = outputMessage + 32;

								decodeValue(&value, 1, 0, 0, node);
								if (value) {
									memcpy(
											outputMessage + 32,
											x->serverCache_.getModifierMappingLastMap. buffer,
											x->serverCache_.getModifierMappingLastMap. size);
									break;
								}
								for (count = outputLength - 32; count; count--) {
									decodeValue(&value, 1, 0, 0, node);
									if (value)
										*nextDest++ = 0;
									else {
										decodeValue(&value, 8, 0, 0, node);
										*nextDest++ = value;
									}
								}
								blockcache_set(
										&x->serverCache_.getModifierMappingLastMap,
										outputLength - 32, outputMessage + 32);
							}
							break;
						case X_GetSelectionOwner: 
							{
								outputLength = 32;
								outputMessage = addMessage(outputLength, x);
								decodeCachedValue(&value, 29,
										&x->serverCache_. getSelectionOwnerCache, 9, 0, node);
								PutULONG(value, outputMessage + 8);
							}
							break;
						case X_GetWindowAttributes: 
							{
								outputLength = 44;
								outputMessage = addMessage(outputLength, x);
								decodeValue(&value, 2, 0, 0, node);
								outputMessage[1] = (unsigned char) value;
								decodeCachedValue(&value, 29,
										&x->serverCache_. visualCache, 9, 0, node);
								PutULONG(value, outputMessage + 8);
								decodeCachedValue(
										&value,
										16,
										&x->serverCache_. getWindowAttributesClassCache,
										3, 0, node);
								PutUINT(value, outputMessage + 12);
								decodeCachedCharValue(
										&cValue,
										8,
										&x->serverCache_. getWindowAttributesBitGravityCache,
										0, 0, node);
								outputMessage[14] = cValue;
								decodeCachedCharValue(
										&cValue,
										8,
										&x->serverCache_. getWindowAttributesWinGravityCache,
										0, 0, node);
								outputMessage[15] = cValue;
								decodeCachedValue(
										&value,
										32,
										&x->serverCache_. getWindowAttributesPlanesCache,
										9, 0, node);
								PutULONG(value, outputMessage + 16);
								decodeCachedValue(
										&value,
										32,
										&x->serverCache_. getWindowAttributesPixelCache,
										9, 0, node);
								PutULONG(value, outputMessage + 20);
								decodeValue(&value, 1, 0, 0, node);
								outputMessage[24] = (unsigned char) value;
								decodeValue(&value, 1, 0, 0, node);
								outputMessage[25] = (unsigned char) value;
								decodeValue(&value, 2, 0, 0, node);
								outputMessage[26] = (unsigned char) value;
								decodeValue(&value, 1, 0, 0, node);
								outputMessage[27] = (unsigned char) value;
								decodeCachedValue(&value, 29,
										&x->serverCache_. colormapCache, 9, 0, node);
								PutULONG(value, outputMessage + 28);
								decodeCachedValue(
										&value,
										32,
										&x->serverCache_. getWindowAttributesAllEventsCache,
										0, 0, node);
								PutULONG(value, outputMessage + 32);
								decodeCachedValue(
										&value,
										32,
										&x->serverCache_. getWindowAttributesYourEventsCache,
										0, 0, node);
								PutULONG(value, outputMessage + 36);
								decodeCachedValue(
										&value,
										16,
										&x->serverCache_. getWindowAttributesDontPropagateCache,
										0, 0, node);
								PutUINT(value, outputMessage + 40);
							}
							break;
						case X_GrabKeyboard:
						case X_GrabPointer: 
							{
								outputLength = 32;
								outputMessage = addMessage(outputLength, x);
								decodeValue(&value, 3, 0, 0, node);
								outputMessage[1] = (unsigned char) value;
							}
							break;
						case X_InternAtom: 
							{
								outputLength = 32;
								outputMessage = addMessage(outputLength, x);
								decodeValue(&value, 32, 9, 0, node);
								printk("%u\n", value);

								PutULONG(value, outputMessage + 8);
								//print_string(outputMessage + 8, 4);
							}
							break;
						case X_ListExtensions: 
							{unsigned int numExtensions;
								unsigned char *nextDest;
								decodeValue(&value, 32, 8, 0, node);
								outputLength = 32 + (value << 2);
								outputMessage = addMessage(outputLength, x);


								decodeValue(&numExtensions, 8, 0, 0, node);
								outputMessage[1] = (unsigned char) numExtensions;
								nextDest = outputMessage + 32;

								for (; numExtensions; numExtensions--) {
									unsigned int length;

									decodeValue(&length, 8, 0, 0, node);
									*nextDest++ = (unsigned char) length;
									for (; length; length--) {
										decodeValue(&value, 8, 0, 0, node);
										*nextDest++ = value;
									}
								}
							}
							break;
						case X_LookupColor:
						case X_AllocNamedColor: 
							{
								unsigned char *nextDest;
								unsigned int count = 3;
								outputLength = 32;
								outputMessage = addMessage(outputLength, x);
								nextDest = outputMessage + 8;

								if (nextOpcode == X_AllocNamedColor) {
									decodeValue(&value, 32, 9, 0, node);
									PutULONG(value, nextDest);
									nextDest += 4;
								}

								do {
									unsigned int visualColor;
									decodeValue(&value, 16, 9, 0, node);
									PutUINT(value, nextDest);

									decodeValue(&visualColor, 16, 5, 0, node);
									visualColor += value;
									visualColor &= 0xffff;
									PutUINT(visualColor, nextDest + 6);
									nextDest += 2;
								} while (--count);
							}
							break;
						case X_QueryBestSize: 
							{
								outputLength = 32;
								outputMessage = addMessage(outputLength, x);
								decodeValue(&value, 16, 8, 0, node);
								PutUINT(value, outputMessage + 8);
								decodeValue(&value, 16, 8, 0, node);
								PutUINT(value, outputMessage + 10);
							}
							break;
						case X_QueryColors: 
							{
								unsigned int cached;

								decodeValue(&cached, 1, 1, 0, node);
								if (cached) {
									unsigned int numColors =
										x->serverCache_.queryColorsLastReply.size / 6;
									const unsigned char *nextSrc;
									unsigned char *nextDest;
									outputLength = 32 + (numColors << 3);
									outputMessage = addMessage(outputLength, x);
									PutUINT(numColors, outputMessage + 8);
									nextSrc = x->serverCache_.queryColorsLastReply.buffer;
									nextDest = outputMessage + 32;

									for (; numColors; numColors--) {
										for (i = 0; i < 6; i++)
											*nextDest++ = *nextSrc++;
										nextDest += 2;
									}
								} else {
									unsigned int numColors;
									unsigned char *nextDest;
									unsigned int c;
									const unsigned char *nextSrc;

									decodeValue(&numColors, 16, 5, 0, node);
									outputLength = 32 + (numColors << 3);
									outputMessage = addMessage(outputLength, x);
									PutUINT(numColors, outputMessage + 8);
									nextDest = outputMessage + 32;
									for (c = 0; c < numColors; c++) {
										for (i = 0; i < 3; i++) {
											decodeValue(&value, 16, 0, 0, node);
											PutUINT(value, nextDest);
											nextDest += 2;
										}
									}
									blockcache_set(
											&x->serverCache_.queryColorsLastReply,
											numColors * 6, outputMessage + 32);
									nextSrc = nextDest - 1;

									nextDest = outputMessage + 32
										+ ((numColors - 1) << 3) + 5;
									for (; numColors > 1; numColors--) {
										for (i = 0; i < 6; i++)
											*nextDest-- = *nextSrc--;
										nextDest -= 2;
									}
								}
							}
							break;
						case X_QueryFont: 
							{
								unsigned int numProperties;
								unsigned int numCharInfos;
								unsigned char *nextDest;
								unsigned char *saveDest;
								unsigned int length;


								decodeValue(&numProperties, 16, 8, 0, node);
								decodeValue(&numCharInfos, 32, 10, 0, node);
								outputLength = 60 + numProperties * 8
									+ numCharInfos * 12;
								outputMessage = addMessage(outputLength, x);
								PutUINT(numProperties, outputMessage + 46);
								PutULONG(numCharInfos, outputMessage + 56);
								decodeCharInfo_(outputMessage + 8, x, node);
								decodeCharInfo_(outputMessage + 24, x, node);
								decodeValue(&value, 16, 9, 0, node);
								PutUINT(value, outputMessage + 40);
								decodeValue(&value, 16, 9, 0, node);
								PutUINT(value, outputMessage + 42);
								decodeValue(&value, 16, 9, 0, node);
								PutUINT(value, outputMessage + 44);
								decodeValue(&value, 1, 0, 0, node);
								outputMessage[48] = (unsigned char) value;
								decodeValue(&value, 8, 0, 0, node);
								outputMessage[49] = (unsigned char) value;
								decodeValue(&value, 8, 0, 0, node);
								outputMessage[50] = (unsigned char) value;
								decodeValue(&value, 1, 0, 0, node);
								outputMessage[51] = (unsigned char) value;
								decodeValue(&value, 16, 9, 0, node);
								PutUINT(value, outputMessage + 52);
								decodeValue(&value, 16, 9, 0, node);
								PutUINT(value, outputMessage + 54);
								nextDest = outputMessage + 60;

								decodeValue(&value, 1, 0, 0, node);
								if (value) {
									unsigned int index;
									unsigned int length;
									const unsigned char *data;

									decodeValue(&index, 4, 0, 0, node);

									blockcacheset_get(
											&x->serverCache_.queryFontFontCache,
											index, &length, &data);
									memcpy(nextDest, data, length);
									break;
								}
								saveDest = nextDest;
								length = numProperties * 8
									+ numCharInfos * 12;
								for (; numProperties; numProperties--) {
									decodeValue(&value, 32, 9, 0, node);
									PutULONG(value, nextDest);
									decodeValue(&value, 32, 9, 0, node);
									PutULONG(value, nextDest + 4);
									nextDest += 8;
								}
								for (; numCharInfos; numCharInfos--) {
									decodeCharInfo_(nextDest, x, node);
									nextDest += 12;
								}
								blockcacheset_set(&x->serverCache_.queryFontFontCache,
										length, saveDest);
							}
							break;
						case X_QueryPointer: 
							{
								outputLength = 32;
								outputMessage = addMessage(outputLength, x);
								decodeValue(&value, 1, 0, 0, node);
								outputMessage[1] = (unsigned char) value;
								decodeCachedValue(&value, 29,
										&x->serverCache_. queryPointerRootCache, 9, 0, node);
								PutULONG(value, outputMessage + 8);
								decodeCachedValue(&value, 29,
										&x->serverCache_. queryPointerChildCache, 9, 0, node);
								PutULONG(value, outputMessage + 12);
								decodeCachedValue(&value, 16,
										&x->serverCache_. motionNotifyRootXCache, 8, 0, node);
								x->serverCache_.motionNotifyLastRootX += value;
								PutUINT(x->serverCache_.motionNotifyLastRootX,
										outputMessage + 16);
								decodeCachedValue(&value, 16,
										&x->serverCache_. motionNotifyRootYCache, 8, 0, node);
								x->serverCache_.motionNotifyLastRootY += value;
								PutUINT(x->serverCache_.motionNotifyLastRootY,
										outputMessage + 18);
								decodeCachedValue(&value, 16,
										&x->serverCache_. motionNotifyEventXCache, 8,
										0, node);
								PutUINT(x->serverCache_.motionNotifyLastRootX + value,
										outputMessage + 20);
								decodeCachedValue(&value, 16,
										&x->serverCache_. motionNotifyEventYCache, 8,
										0, node);
								PutUINT(x->serverCache_.motionNotifyLastRootY + value,
										outputMessage + 22);
								decodeCachedValue(&value, 16,
										&x->serverCache_. motionNotifyStateCache, 0, 0, node);
								PutUINT(value, outputMessage + 24);
							}
							break;
						case X_QueryTree: 
							{
								unsigned int second;

								//decodeValue(&secondByte, 8, 0, 0);
								unsigned int replyLength;

								decodeValue(&replyLength, 32, 8, 0, node);
								outputLength = 32 + (replyLength << 2);
								outputMessage = addMessage(outputLength, x);
								PutULONG (replyLength, outputMessage + 4);
								//outputMessage[1] = (unsigned char) secondByte;

								for (i = 8; i < 16; i++) {
									unsigned int nextByte;

									decodeValue(&nextByte, 8, 0, 0, node);
									outputMessage[i] = (unsigned char) nextByte;
								}

								decodeValue (&second, 16, 0, 0, node);
								PutUINT (second, outputMessage + 16);

								for (i = 32; i < outputLength; ++i) {
									unsigned int nextByte;
									decodeValue(&nextByte, 8, 0, 0, node);
									outputMessage[i] = (unsigned char) nextByte;
								}
							}
							break;
						case X_TranslateCoords: 
							{
								outputLength = 32;
								outputMessage = addMessage(outputLength, x);
								decodeValue(&value, 1, 0, 0, node);
								outputMessage[1] = (unsigned char) value;
								decodeCachedValue(&value, 29,
										&x->serverCache_. translateCoordsChildCache,
										9, 0, node);
								PutULONG(value, outputMessage + 8);
								decodeCachedValue(&value, 16,
										&x->serverCache_. translateCoordsXCache, 8, 0, node);
								PutUINT(value, outputMessage + 12);
								decodeCachedValue(&value, 16,
										&x->serverCache_. translateCoordsYCache, 8, 0, node);
								PutUINT(value, outputMessage + 14);
							}
							break;
						default: 
							{
								//knows nothing about opcode
								unsigned int secondByte;
								unsigned int replyLength;
								unsigned char *nextDest;

								printk("assertion failed in ClientProxyReader::processMessage():\n no matching request for reply with sequence number %u, opcode:%u\n", sequenceNum, nextOpcode);
								decodeValue(&secondByte, 8, 0, 0, node);

								decodeValue(&replyLength, 32, 0, 0, node);
								outputLength = 32 + (replyLength << 2);
								outputMessage = addMessage(outputLength, x);
								outputMessage[1] = (unsigned char) secondByte;
								nextDest = outputMessage + 8;

								for (i = 8; i < outputLength; i++) {
									unsigned int nextByte;

									decodeValue(&nextByte, 8, 0, 0, node);
									*nextDest++ = (unsigned char) nextByte;
								}
								printk (" outputLength:%d\n", outputLength);
							}
					}
				} else {
					unsigned int secondByte;
					unsigned int replyLength;
					unsigned char *nextDest;

					decodeValue(&secondByte, 8, 0, 0, node);

					decodeValue(&replyLength, 32, 0, 0, node);
					outputLength = 32 + (replyLength << 2);
					outputMessage = addMessage(outputLength, x);
					outputMessage[1] = (unsigned char) secondByte;
					nextDest = outputMessage + 8;

					for (i = 8; i < outputLength; i++) {
						unsigned int nextByte;

						decodeValue(&nextByte, 8, 0, 0, node);
						*nextDest++ = (unsigned char) nextByte;
					}
				}
				PutULONG((outputLength - 32) >> 2, outputMessage + 4);
			} else {
				// event or error
				unsigned int sequenceNumDiff;
				printk("event:%d, name:%s\n", opcode, opcode<128?EVENT_TABLE[opcode]:"other");

				decodeCachedValue(&sequenceNumDiff, 16,
						&x->serverCache_.eventSequenceNumCache, 7, 0, node);
				x->serverCache_.lastSequenceNum += sequenceNumDiff;
				x->serverCache_.lastSequenceNum &= 0xffff;

				outputLength = 32;
				outputMessage = addMessage(outputLength, x);

				//TODO
				// check if this is an error that matches a sequence number for
				// which we were expecting a reply


				switch (opcode) 
				{
					case 0: 
						{
							unsigned char code;

							decodeCachedCharValue(&code, 8,
									&x->serverCache_. errorCodeCache, 0, 0, node);
							outputMessage[1] = code;
							if ((code != 11) && (code != 8) && (code != 15)
									&& (code != 1)) {
								decodeValue(&value, 32, 16, 0, node);
								PutULONG(value, outputMessage + 4);
							}
							if (code >= 18) {
								decodeCachedValue(&value, 16,
										&x->serverCache_. errorMinorCache, 0, 0, node);
								PutUINT(value, outputMessage + 8);
							}
							decodeCachedCharValue(&cValue, 8,
									&x->serverCache_. errorMajorCache, 0, 0, node);
							outputMessage[10] = cValue;
							if (code >= 18) {
								unsigned char *nextDest = outputMessage + 11;

								for (i = 11; i < 32; i++) {
									decodeValue(&value, 8, 0, 0, node);
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
					case LeaveNotify: 
						{
							unsigned char *nextDest;
							int skipRest = 0;
							if (opcode == MotionNotify)
								decodeValue(&value, 1, 0, 0, node);
							else if ((opcode == EnterNotify) || (opcode
										== LeaveNotify))
								decodeValue(&value, 3, 0, 0, node);
							else if (opcode == KeyRelease) {
								decodeValue(&value, 1, 0, 0, node);
								if (value)
									value = x->serverCache_.keyPressLastKey;
								else
									decodeValue(&value, 8, 0, 0, node);
							} else if ((opcode == ButtonPress) || (opcode
										== ButtonRelease)) {
								decodeCachedCharValue(&cValue, 8,
										&x->serverCache_. buttonCache, 0, 0, node);
								value = (unsigned int) cValue;
							} else
								decodeValue(&value, 8, 0, 0, node);
							outputMessage[1] = (unsigned char) value;
							decodeCachedValue(&value, 32,
									&x->serverCache_. motionNotifyTimestampCache, 9, 0, node);
							x->serverCache_.lastTimestamp += value;
							PutULONG(x->serverCache_.lastTimestamp, outputMessage + 4);
							nextDest = outputMessage + 8;

							if (opcode == KeyRelease) {
								decodeValue(&value, 1, 0, 0, node);
								if (value) {
									for (i = 0; i < 23; i++)
										*nextDest++ = x->serverCache_.keyPressCache[i];
									skipRest = 1;
								}
							}
							if (!skipRest) {
								for (i = 0; i < 3; i++) {
									decodeCachedValue(
											&value,
											29,
											&x->serverCache_. motionNotifyWindowCache[i],
											6, 0, node);
									PutULONG(value, nextDest);
									nextDest += 4;
								}
								decodeCachedValue(&value, 16,
										&x->serverCache_. motionNotifyRootXCache, 6, 0, node);
								x->serverCache_.motionNotifyLastRootX += value;
								PutUINT(x->serverCache_.motionNotifyLastRootX,
										outputMessage + 20);
								decodeCachedValue(&value, 16,
										&x->serverCache_. motionNotifyRootYCache, 6, 0, node);
								x->serverCache_.motionNotifyLastRootY += value;
								PutUINT(x->serverCache_.motionNotifyLastRootY,
										outputMessage + 22);
								decodeCachedValue(&value, 16,
										&x->serverCache_. motionNotifyEventXCache, 6,
										0, node);
								PutUINT(x->serverCache_.motionNotifyLastRootX + value,
										outputMessage + 24);
								decodeCachedValue(&value, 16,
										&x->serverCache_. motionNotifyEventYCache, 6,
										0, node);
								PutUINT(x->serverCache_.motionNotifyLastRootY + value,
										outputMessage + 26);
								decodeCachedValue(&value, 16,
										&x->serverCache_. motionNotifyStateCache, 0, 0, node);
								PutUINT(value, outputMessage + 28);
								if ((opcode == EnterNotify) || (opcode
											== LeaveNotify))
									decodeValue(&value, 2, 0, 0, node);
								else
									decodeValue(&value, 1, 0, 0, node);
								outputMessage[30] = (unsigned char) value;
								if ((opcode == EnterNotify) || (opcode
											== LeaveNotify)) {
									decodeValue(&value, 2, 0, 0, node);
									outputMessage[31] = (unsigned char) value;
								} else if (opcode == KeyPress) {
									x->serverCache_.keyPressLastKey = outputMessage[1];
									for (i = 8; i < 31; i++) {
										x->serverCache_.keyPressCache[i - 8]
											= outputMessage[i];
									}
								}
							}
						}
						break;
					case ColormapNotify: 
						{
							decodeCachedValue(&value, 29,
									&x->serverCache_. colormapNotifyWindowCache, 8, 0, node);
							PutULONG(value, outputMessage + 4);
							decodeCachedValue(&value, 29,
									&x->serverCache_. colormapNotifyColormapCache, 8,
									0, node);
							PutULONG(value, outputMessage + 8);
							decodeValue(&value, 1, 0, 0, node);
							outputMessage[12] = (unsigned char) value;
							decodeValue(&value, 1, 0, 0, node);
							outputMessage[13] = (unsigned char) value;
						}
						break;
					case ConfigureNotify: 
						{
							unsigned char *nextDest = outputMessage + 4;

							for (i = 0; i < 3; i++) {
								decodeCachedValue(
										&value,
										29,
										&x->serverCache_. configureNotifyWindowCache[i],
										9, 0, node);
								PutULONG(value, nextDest);
								nextDest += 4;
							}
							for (i = 0; i < 5; i++) {
								decodeCachedValue(&value, 16,
										&x->serverCache_. configureNotifyGeomCache[i],
										8, 0, node);
								PutUINT(value, nextDest);
								nextDest += 2;
							}
							decodeValue(&value, 1, 0, 0, node);
							*nextDest = value;
						}
						break;
					case CreateNotify: 
						{
							unsigned char *nextDest;

							decodeCachedValue(&value, 29,
									&x->serverCache_. createNotifyWindowCache, 9, 0, node);
							PutULONG(value, outputMessage + 4);
							decodeValue(&value, 29, 5, 0, node);
							x->serverCache_.createNotifyLastWindow += value;
							x->serverCache_.createNotifyLastWindow &= 0x1fffffff;
							PutULONG(x->serverCache_.createNotifyLastWindow,
									outputMessage + 8);
							nextDest = outputMessage + 12;

							for (i = 0; i < 5; i++) {
								decodeValue(&value, 16, 9, 0, node);
								PutUINT(value, nextDest);
								nextDest += 2;
							}
							decodeValue(&value, 1, 0, 0, node);
							*nextDest = (unsigned char) value;
						}
						break;
					case Expose: 
						{
							unsigned char *nextDest;
							decodeCachedValue(&value, 29,
									&x->serverCache_. exposeWindowCache, 9, 0, node);
							PutULONG(value, outputMessage + 4);
							nextDest = outputMessage + 8;

							for (i = 0; i < 5; i++) {
								decodeCachedValue(&value, 16,
										&x->serverCache_. exposeGeomCache[i], 6, 0, node);
								PutUINT(value, nextDest);
								nextDest += 2;
							}
						}
						break;
					case FocusIn:
					case FocusOut: 
						{
							decodeValue(&value, 3, 0, 0, node);
							outputMessage[1] = (unsigned char) value;
							decodeCachedValue(&value, 29,
									&x->serverCache_. focusInWindowCache, 9, 0, node);
							PutULONG(value, outputMessage + 4);
							decodeValue(&value, 2, 0, 0, node);
							outputMessage[8] = (unsigned char) value;
						}
						break;
					case KeymapNotify: 
						{
							decodeValue(&value, 1, 0, 0, node);
							if (value)
								memcpy(outputMessage + 1,
										x->serverCache_.lastKeymap.buffer, 31);
							else {
								unsigned char *nextDest = outputMessage + 1;

								for (i = 1; i < 32; i++) {
									decodeValue(&value, 8, 0, 0, node);
									*nextDest++ = (unsigned char) value;
								}
								blockcache_set(&x->serverCache_.lastKeymap, 31,
										outputMessage + 1);
							}
						}
						break;
					case MapNotify:
					case UnmapNotify:
					case DestroyNotify: 
						{
							decodeCachedValue(&value, 29,
									&x->serverCache_. mapNotifyEventCache, 9, 0, node);
							PutULONG(value, outputMessage + 4);
							decodeCachedValue(&value, 29,
									&x->serverCache_. mapNotifyWindowCache, 9, 0, node);
							PutULONG(value, outputMessage + 8);
							if ((opcode == MapNotify) || (opcode == UnmapNotify)) {
								decodeValue(&value, 1, 0, 0, node);
								outputMessage[12] = (unsigned char) value;
							}
						}
						break;
					case NoExpose: 
						{
							decodeCachedValue(&value, 29,
									&x->serverCache_. noExposeDrawableCache, 9, 0, node);
							PutULONG(value, outputMessage + 4);
							decodeCachedValue(&value, 16,
									&x->serverCache_. noExposeMinorCache, 0, 0, node);
							PutUINT(value, outputMessage + 8);
							decodeCachedCharValue(&cValue, 8,
									&x->serverCache_. noExposeMajorCache, 0, 0, node);
							outputMessage[10] = cValue;
						}
						break;
					case PropertyNotify: 
						{
							decodeCachedValue(&value, 29,
									&x->serverCache_. propertyNotifyWindowCache, 9, 0, node);
							PutULONG(value, outputMessage + 4);
							decodeCachedValue(&value, 29,
									&x->serverCache_. propertyNotifyAtomCache, 9, 0, node);
							PutULONG(value, outputMessage + 8);
							decodeValue(&value, 32, 9, 0, node);
							x->serverCache_.lastTimestamp += value;
							PutULONG(x->serverCache_.lastTimestamp, outputMessage + 12);
							decodeValue(&value, 1, 0, 0, node);
							outputMessage[16] = (unsigned char) value;
						}
						break;
					case ReparentNotify: 
						{
							unsigned char *nextDest = outputMessage + 4;

							for (i = 0; i < 3; i++) {
								decodeCachedValue(&value, 29,
										&x->serverCache_. reparentNotifyWindowCache,
										9, 0, node);
								PutULONG(value, nextDest);
								nextDest += 4;
							}
							decodeValue(&value, 16, 6, 0, node);
							PutUINT(value, nextDest);
							decodeValue(&value, 16, 6, 0, node);
							PutUINT(value, nextDest + 2);
							decodeValue(&value, 1, 0, 0, node);
							outputMessage[20] = (unsigned char) value;
						}
						break;
					case SelectionClear: 
						{
							decodeValue(&value, 32, 9, 0, node);
							x->serverCache_.lastTimestamp += value;
							PutULONG(x->serverCache_.lastTimestamp, outputMessage + 4);
							decodeCachedValue(&value, 29,
									&x->serverCache_. selectionClearWindowCache, 9, 0, node);
							PutULONG(value, outputMessage + 8);
							decodeCachedValue(&value, 29,
									&x->serverCache_. selectionClearAtomCache, 9, 0, node);
							PutULONG(value, outputMessage + 12);
						}
						break;
					case SelectionRequest: 
						{
							decodeValue(&value, 32, 9, 0, node);
							x->serverCache_.lastTimestamp += value;
							PutULONG(x->serverCache_.lastTimestamp, outputMessage + 4);
							decodeCachedValue(&value, 29,
									&x->serverCache_. selectionClearWindowCache, 9, 0, node);
							PutULONG(value, outputMessage + 8);
							decodeCachedValue(&value, 29,
									&x->serverCache_. selectionClearWindowCache, 9, 0, node);
							PutULONG(value, outputMessage + 12);
							decodeCachedValue(&value, 29,
									&x->serverCache_. selectionClearAtomCache, 9, 0, node);
							PutULONG(value, outputMessage + 16);
							decodeCachedValue(&value, 29,
									&x->serverCache_. selectionClearAtomCache, 9, 0, node);
							PutULONG(value, outputMessage + 20);
							decodeCachedValue(&value, 29,
									&x->serverCache_. selectionClearAtomCache, 9, 0, node);
							PutULONG(value, outputMessage + 24);
						}
						break;
					case VisibilityNotify: 
						{
							decodeCachedValue(&value, 29,
									&x->serverCache_. visibilityNotifyWindowCache, 9,
									0, node);
							PutULONG(value, outputMessage + 4);
							decodeValue(&value, 2, 0, 0, node);
							outputMessage[8] = (unsigned char) value;
						}
						break;
						/*case X_GrabButton: {
						  decodeValue(&value, 1, 0, 0);
						  if (value)
						  outputMessage[1] = 1;
						  else
						  outputMessage[1] = 0;
						  decodeCachedValue(&value, 32,
						  &x->serverCache_.grabButtonGrabWindow, 8, 0);
						  PutULONG(value, outputMessage + 4);
						  decodeValue(&value, 16, 4, 0);
						  PutUINT(value, message + 8);
						  decodeValue(&value, 1, 0, 0);
						  if (value)
						  outputMessage[10] = 1;
						  else
						  outputMessage[10] = 0;
						  decodeValue(&value, 1, 0, 0);
						  if (value)
						  outputMessage[11] = 1;
						  else
						  outputMessage[11] = 0;

						  decodeCachedValue(&value, 32,
						  &x->serverCache_.grabButtonConfineTo, 8, 0);
						  PutULONG(value, message + 12);
						  decodeCachedValue(&value, 32,
						  &x->serverCache_.grabButtonCursor, 8, 0);
						  PutULONG(value, message + 16);
						  decodeValue(&value, 8, 4, 0);
						  message[21] = (unsigned char) value;
						  decodeValue(&value, 16, 4, 0);
						  PutUINT(value, message + 23);

						  }
						  break;
						 */
					default: 
						{
							unsigned int secondByte;
							unsigned char *nextDest;
							unsigned int i;

							decodeValue(&secondByte, 8, 0, 0, node);
							outputMessage[1] = secondByte;
							nextDest = outputMessage + 4;
							for (i = 4; i < outputLength; i++) {
								unsigned int nextByte;

								decodeValue(&nextByte, 8, 0, 0, node);
								*nextDest++ = (unsigned char) nextByte;
							}
						}
				}

			}
			*outputMessage = (unsigned char) opcode;
			PutUINT(x->serverCache_.lastSequenceNum, outputMessage + 2);
			printk("   size:%u, size_count:%d\n", outputLength, size_count);
			size_count += outputLength;

		}

		//}
}
}
