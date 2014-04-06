/*
 * status.h
 *
 *  Created on: Mar 20, 2013
 *      Author: xdou
 */

#ifndef STATUS_H_
#define STATUS_H_
# define STATS_OPCODE_MAX 512
struct status_info {
	unsigned int status_count_[STATS_OPCODE_MAX];
	unsigned int status_bitsIn_[STATS_OPCODE_MAX];
	unsigned int status_bitsOut_[STATS_OPCODE_MAX];
};

void status_init(struct status_info* s);
void status_add(struct status_info* s, unsigned int opcode, unsigned int bitsIn, unsigned int bitsOut);
void status_summarize(struct status_info* s, unsigned int *bitsIn, unsigned int *bitsOut);

#endif /* STATUS_H_ */
