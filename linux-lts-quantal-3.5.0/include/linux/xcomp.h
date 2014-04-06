#include <linux/compiler.h>
#include <linux/encodebuffer.h>

#define SEQUENCE_NUM_BUFFER_SIZE 10240

struct sequenceNumNode{
	unsigned char opcode;
	unsigned char request_data;
	unsigned short int sequence;
};

struct x_struct {
	//for x compression
	int xfd;
	int actual_xfd;
	int xauth_fd;
	int connected;
	int connection_times;
	int firstMessage_req;
	int firstMessage_reply;

	struct sequenceNumNode sequence_nums[SEQUENCE_NUM_BUFFER_SIZE];
	int seq_num_start;
	int seq_num_end;
	unsigned short int cur_seq;

	//for request message
	char* buffer_req;
	int buffer_message_req;
	int buffer_size_req;
	int buffer_start_req;
	//char message_req[256000];

	//for reply and event message
	char *buffer_reply;
	int buffer_message_reply;
	int buffer_size_reply;
	int buffer_start_reply;

	//decoded buffer
	char* decode_buffer;
	char* decode_buffer_start;
	char* decode_buffer_end;
	
	struct serverCache serverCache_;
};

inline void init_x_comp(struct x_struct *x);
inline void free_x_comp(struct x_struct *x);
inline unsigned int GetUINT(char* buffer);
inline unsigned int GetULONG(char* buffer);
inline void seq_push (unsigned char opcode, unsigned char request_data, struct x_struct *x);
inline int seq_peek (unsigned short int* sequence, unsigned char* opcode, struct x_struct *x);
inline int seq_pop (struct x_struct *x);
inline unsigned int roundup4 (unsigned int x);
int locateMessage_req (int* dataLength, char* buf, int size, struct x_struct *x);
int locateMessage_reply (int* dataLength, char* buf, int size, struct x_struct *x);
int getMessage_req (const char* __user buf, int size, struct x_struct *x);
int getMessage_reply (char* buf, int size, struct x_struct *x);
void x_compress_req (const char* __user buf, int size, struct x_struct *x);
int x_compress_reply (char* buf, int size, struct x_struct *x, struct clog_node* node);
void x_decompress_reply (int size, struct x_struct *x, struct clog_node* node);
inline void consume_decode_buffer (int size, struct x_struct *x);
inline void validate_decode_buffer (char* buffer, int size, struct x_struct* x);
