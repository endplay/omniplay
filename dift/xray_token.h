#ifndef XRAY_TOKEN_H
#define XRAY_TOKEN_H

#include <stdlib.h>
#include <sys/file.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glib.h>
#include <string.h>
#include <assert.h>
#include "token.h"

#ifdef __cplusplus
extern "C" {
#endif

struct byte_result_header {
    int output_type;
    int output_fileno;
    uint64_t rg_id;
    int record_pid;
    int syscall_cnt;
    int size;
};

struct byte_result {
    int output_type;
    int output_fileno;
    uint64_t rg_id;
    int record_pid;
    int syscall_cnt;
    int offset;
    unsigned int token_num;
    char value;
};

/* Structures related to tracking taints to instructions executed */
struct track_result {
    unsigned long long inst_count;
    u_long inst;        // Current instruction
    u_long static_inst; // Static instruction
    char image_name[256];
    int dst;        // 0 if dst, 1 if src
};

/* Operations for tokens */
struct token* create_new_token (int type, u_long token_num, u_long size, int syscall_cnt, int byte_offset, uint64_t rg_id, int record_pid, int fileno);
void set_new_token (struct token* tok, int type, u_long token_num, u_long size, int syscall_cnt, int byte_offset, uint64_t rg_id, int record_pid, int fileno);
const char* get_token_type_string(int token_type);
void write_token_to_file(int outfd, struct token* token);
int read_token_from_file(FILE* fp, struct token* ptoken);

/* Operations for results of a byte */
struct byte_result* create_new_byte_result(int output_type, int output_fileno, uint64_t rg_id, int record_pid, int syscall_cnt, int offset, unsigned int token_num);
void new_byte_result(struct byte_result* result, int output_type, int output_fileno, uint64_t rg_id, int record_pid, int syscall_cnt, int offset, unsigned int token_num);
void write_byte_result_to_file(int fd, struct byte_result* byte_result);
int read_byte_result_from_file(int fd, struct byte_result* result);

void new_track_result(struct track_result* result, unsigned long long inst_count, u_long inst, u_long static_inst, char* image_name, int dst);

/* Operatins for filename mapping */
void write_filename_mapping(FILE* fp, int file_cnt, char* filename);
int read_filename_mapping(FILE* fp, int* file_cnt, char* filename);
void init_filename_mapping(FILE* fp);
void init_filename_stack_mapping(FILE* fp);

/* Operations for image mapping */
void write_image_mapping(FILE* fp, int img_cnt, char* imgname);
int read_image_mapping(FILE* fp, int* img_cnt, char* imgname);

/* Operations for stack info writing */
void write_filename_stack_mapping(FILE* fp, char* filename, long stack_hash, int stack_count, char* ext);
int read_filename_stack_mapping(FILE* fp, char* filename, long* hash_val, int* stack_count, char* ext);

/* For parsing and interpreting */
int read_filename_mappings(char* filename, GHashTable* filename_table);
int read_imgname_mappings(char* img_filename, GHashTable* imgname_table);
int read_filename_stack_mappings(char* filename, GHashTable* stack_table);
/* Read token info from file and place in HashTable */
int read_tokens(char* filename, GHashTable* option_info_table);

/* Write byte results in a different form */
struct byte_result_header* create_new_byte_result_header(int output_type, int output_fileno, uint64_t rg_id, int record_pid, int syscall_cnt, int size);
void write_byte_result_header_to_file(int fd, struct byte_result_header* header);
int read_byte_result_header_from_file(int fd, struct byte_result_header* header);
void write_offset_to_results(gpointer data, gpointer user_data);
int write_buffer_byte_results(int fd, GHashTable* taints_offset_table);
void read_buffer_bytes_results(int fd, FILE* output_f);

#ifdef CONFAID
struct token* create_new_named_token (unsigned int token_num, char* token_name);
#endif

#ifdef __cplusplus
}
#endif

#endif // XRAY_TOKEN_H
