#ifndef XRAY_TOKEN_H
#define XRAY_TOKEN_H

#include <stdlib.h>
#include <sys/file.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define TOK_READ 1
#define TOK_WRITE 2
#define TOK_EXEC 3
struct token {
    int type;
    int token_num;
    int syscall_cnt;
    int byte_offset;
#ifdef CONFAID
    char config_token[256];	// Name of the config token
    int line_num;		// Line number
    char config_filename[256];	// Name of the config file
#else
    char name[256];
#endif
    uint64_t rg_id;
    int record_pid;
};

struct byte_result {
    char output_type[256];
    char output_channel[256];
    uint64_t rg_id;
    int record_pid;
    int syscall_cnt;
    int offset;
    int token_num;
};

struct token* create_new_token (int type, int token_num, int syscall_cnt, int byte_offset, uint64_t rg_id, int record_pid, void* data)
{
    struct token* tok; 
    tok = (struct token *) malloc(sizeof(struct token));
    tok->type = type;
    tok->token_num = token_num;
    tok->syscall_cnt = syscall_cnt;
    tok->byte_offset = byte_offset;
    tok->rg_id = rg_id;
    tok->record_pid = record_pid;
#ifndef CONFAID
    if (data) {
        strncpy(tok->name, (char *)data, 256);
    } else {
        strncpy(tok->name, (char *) "NOTAFILE", 256);
    }
#endif
    return tok;
}

#ifdef CONFAID
struct token* create_new_named_token (int token_num, char* token_name)
{
    struct thread_data* ptdata = (struct thread_data *) PIN_GetThreadData(tls_key, PIN_ThreadId());

    struct token* tok; 
    tok = (struct token *) malloc(sizeof(struct token));
    tok->token_num = token_num;
    // not necessary for Confaid
    tok->syscall_cnt = 0;
    tok->byte_offset = 0;
    strncpy(tok->config_token, token_name, 256);
    // TODO token line num and config_filename
    tok->line_num = 0;
    strncpy(tok->config_filename, confaid_data->config_filename, 256);

    return tok;
}
#endif


const char* get_token_type_string(int token_type)
{
    if (token_type == TOK_READ) {
        return "READ";
    } else if (token_type == TOK_WRITE) {
        return "WRITE";
    } else if (token_type == TOK_EXEC) {
        return "EXEC";
    } else {
        return "UNK";
    }
}

void write_token_to_file(FILE* fp, struct token* token)
{
    int rc;
    if (flock(fileno(fp), LOCK_EX) == -1) {
        fprintf(stderr, "Could not grab lock for tokens file %d\n", errno);
    }

    rc = write(fileno(fp), token, sizeof(struct token));
    if (rc != sizeof(struct token)) {
        fprintf(stderr, "[ERROR] Could not write token to file, got %d\n", rc);
        assert (rc == sizeof(struct token)); // fail
    }
    fflush(fp);

    if (flock(fileno(fp), LOCK_UN) == -1) {
        fprintf(stderr, "Could not unlock tokens file %d\n", errno);
    }
}

int read_token_from_file(FILE* fp, struct token* ptoken)
{
    int rc;
    rc = read(fileno(fp), ptoken, sizeof(struct token));
    if (rc != sizeof(struct token)) {
        fprintf(stderr, "[ERROR] Could not read token from file, got %d\n", rc);
        return -1;
    }
    return 0;
}

struct byte_result* create_new_byte_result(char * output_type, char* output_channel, uint64_t rg_id, int record_pid, int syscall_cnt, int offset, int token_num) {
    struct byte_result* byte_result;
    byte_result = (struct byte_result *) malloc(sizeof(struct byte_result));

    strncpy(byte_result->output_type, output_type, 256);
    strncpy(byte_result->output_channel, output_channel, 256);
    byte_result->rg_id = rg_id;
    byte_result->record_pid = record_pid;
    byte_result->syscall_cnt = syscall_cnt;
    byte_result->offset = offset;
    byte_result->token_num = token_num;

    return byte_result;
}

void write_byte_result_to_file(FILE* fp, struct byte_result* byte_result)
{
    int rc;
    if (flock(fileno(fp), LOCK_EX) == -1) {
        fprintf(stderr, "Could not grab lock for results file %d\n", errno);
    }

    rc = write(fileno(fp), byte_result, sizeof(struct byte_result));
    if (rc != sizeof(struct byte_result)) {
        fprintf(stderr, "[ERROR] Could not write byte_result to file, got %d\n", rc);
        assert (rc == sizeof(struct byte_result)); // fail
    }
    fflush(fp);

    if (flock(fileno(fp), LOCK_UN) == -1) {
        fprintf(stderr, "Could not unlock results file %d\n", errno);
    }
}

int read_byte_result_from_file(FILE* fp, struct byte_result* result)
{
    int rc;
    rc = read(fileno(fp), result, sizeof(struct byte_result));
    if (rc != sizeof(struct byte_result)) {
        fprintf(stderr, "[ERROR] Could not read byte result from file, got %d\n", rc);
        return -1;
    }
    return 0;
}
#endif
