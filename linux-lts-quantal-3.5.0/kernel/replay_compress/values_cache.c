/*
 * values_caches.c
 *
 *  Created on: Apr 9, 2013
 *      Author: xdou
 */

#include <linux/values_cache.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/slab.h>

unsigned int value_cache_num;
struct value_cache* value_cache_set[64];

struct value_cache* value_cache_from_data(unsigned int opcode,
		unsigned int e_opcode, unsigned int size, char* buffer) {
	struct value_cache* cache = kmalloc(sizeof(struct value_cache), GFP_KERNEL);
	if (size <= 0) {
		kfree(cache);
		return NULL;
	}
	char* buffer_=kmalloc(size, GFP_KERNEL);
	memcpy(buffer_, buffer, size);
	cache-> opcode = opcode;
	cache->extension_opcode = e_opcode;
	cache->size = size;
	cache->buffer = buffer_;

	return cache;
}

struct value_cache* value_cache_read_from_file(int fd) {
	struct value_cache* cache;
	char* buffer;
	int rc;

	cache = kmalloc(sizeof(struct value_cache), GFP_KERNEL);
	rc = sys_read(fd, cache, sizeof(struct value_cache));
	if (rc < sizeof(struct value_cache)) {
		kfree(cache);
		return NULL;
	}

	buffer = kmalloc(cache->size, GFP_KERNEL);
	rc = sys_read(fd, buffer, cache->size);
	if (rc < cache->size) {
		kfree(buffer);
		kfree(cache);
		return NULL;
	}

	cache->buffer = buffer;
	return cache;
}

int value_cache_write_to_file(int fd, struct value_cache* cache) {
	int rc;
	rc = sys_write(fd, cache, sizeof(struct value_cache));
	if (rc < sizeof(struct value_cache))
		return -1;
	rc = sys_write(fd, cache->buffer, cache->size);
	if (rc < cache->size)
		return -1;
	return 1;

}

void free_value_cache(struct value_cache* cache) {
	kfree(cache->buffer);
	kfree(cache);
}

void value_cache_set_read(int fd) {
	int rc;
	int i = 0;

	rc = sys_read(fd, &value_cache_num, sizeof(unsigned int));
	if (rc < sizeof(unsigned int)) {
		value_cache_num = 0;
		printk("Error reading value-cache.\n");
	}
	for (i = 0; i < value_cache_num; ++i) {
		value_cache_set[i] = value_cache_read_from_file(fd);
	}

}

void value_cache_set_write(int fd) {
	int rc;
	int i = 0;

	rc = sys_write(fd, &value_cache_num, sizeof(unsigned int));
	if (rc < sizeof(unsigned int))
		printk("Error writing value-cache.\n");
	for (i = 0; i < value_cache_num; ++i) {
		rc = value_cache_write_to_file(fd, value_cache_set[i]);
		if (rc < 0)
			printk("Error writing value-cache-set.\n");
	}
}

void value_cache_set_free() {
	int i = 0;
	while (i < value_cache_num) {
		free_value_cache(value_cache_set[i]);
		++i;
	}
}

int value_cache_insert(struct value_cache* cache) {
	value_cache_set[value_cache_num] = cache;
	++value_cache_num;
	return value_cache_num-1;
}

int value_cache_lookup(unsigned char opcode, unsigned char e_opcode,
		char* buffer, int size) {
	int i = 0;
	for (; i < value_cache_num; ++i) {
		if (size != value_cache_set[i]->size)
			continue;
		if (value_cache_set[i]->opcode == opcode
				&& (value_cache_set[i]->extension_opcode == e_opcode
						|| value_cache_set[i]->extension_opcode == 0)) {
			//compare each byte
			if (memcmp(buffer, value_cache_set[i]->buffer, size) == 0)
				return i;
		}
	}
	return -1;
}

