/*
 * values_cache.h
 *
 *  Created on: Apr 9, 2013
 *      Author: xdou
 */

#ifndef VALUES_CACHE_H_
#define VALUES_CACHE_H_

struct value_cache {
	unsigned char opcode;
	unsigned char extension_opcode;
	unsigned int size;
	char* buffer;
};

struct value_cache* value_cache_from_data(unsigned int opcode,
		unsigned int e_opcode, unsigned int size, char* buffer);

struct value_cache* value_cache_read_from_file(int fd);

int value_cache_write_to_file(int fd, struct value_cache* cache);

void free_value_cache(struct value_cache* cache);
void value_cache_set_read(int fd);

void value_cache_set_write(int fd);
void value_cache_set_free(void);

int value_cache_insert(struct value_cache* cache);

int value_cache_lookup(unsigned char opcode, unsigned char e_opcode,
		char* buffer, int size);
#endif /* VALUES_CACHE_H_ */
