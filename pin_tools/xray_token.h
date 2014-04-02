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

#ifdef __cplusplus
extern "C" {
#endif

#define FILENO_STDIN        0
#define FILENO_STDOUT       1
#define FILENO_STDERR       2
#define FILENO_NAME         3
#define FILENO_ARGS         4
#define FILENO_ENVP         5

/* starting fileno number, after constants */
#define FILENO_START        6

/* Token types, i.e. the source of the token */
#define TOK_READ 1
#define TOK_WRITE 2
#define TOK_EXEC 3
#define TOK_WRITEV 4
#define TOK_RECV 5

/* A token represents an input,
 * e.g. a byte from read
 *  	or a configuration token (in ConfAid's case) */
struct token {
    int type;               // See types above, the source of the input
    unsigned int token_num;
    int syscall_cnt;
    int byte_offset;
#ifdef CONFAID
    char config_token[256]; // Name of the config token
    int line_num;   // Line number
    char config_filename[256];  // Name of the config file
#else
    int fileno; // a mapping to the corresponding file/socket that this token came from
#endif
    uint64_t rg_id;
    int record_pid;
    /* The byte value that this token represents
     * TODO Make more general than just a byte, but for now do this
     * */
    char value;
};

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

/* Operations for tokens */
struct token* create_new_token (int type, unsigned int token_num, int syscall_cnt, int byte_offset, uint64_t rg_id, int record_pid, int fileno);
void set_new_token (struct token* tok, int type, unsigned int token_num, int syscall_cnt, int byte_offset, uint64_t rg_id, int record_pid, int fileno);
const char* get_token_type_string(int token_type);
void write_token_to_file(FILE* fp, struct token* token);
int read_token_from_file(FILE* fp, struct token* ptoken);

/* Operations for results of a byte */
struct byte_result* create_new_byte_result(int output_type, int output_fileno, uint64_t rg_id, int record_pid, int syscall_cnt, int offset, unsigned int token_num);
void new_byte_result(struct byte_result* result, int output_type, int output_fileno, uint64_t rg_id, int record_pid, int syscall_cnt, int offset, unsigned int token_num);
void write_byte_result_to_file(int fd, struct byte_result* byte_result);
int read_byte_result_from_file(int fd, struct byte_result* result);

/* Operatins for filename mapping */
void write_filename_mapping(FILE* fp, int file_cnt, char* filename);
int read_filename_mapping(FILE* fp, int* file_cnt, char* filename);
void init_filename_mapping(FILE* fp);

/* For parsing and interpreting */
int read_filename_mappings(char* filename, GHashTable* filename_table);
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
