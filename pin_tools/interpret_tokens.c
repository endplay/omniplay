#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <glib-2.0/glib.h>
#include "xray_token.h"

int read_filename_mappings(char* filename, GHashTable* filename_table)
{
    int fd;
    int rc;
    struct stat buf;
    FILE* fp;
    off_t count = 0;

    fd = open(filename, O_RDONLY);
    if (fd <= 0) {
        fprintf(stderr, "could not open %s, %d\n", filename, fd);
        return -1;
    }

    rc = fstat(fd, &buf);
    if (rc < 0) {
        fprintf(stderr, "could not stat file, %d\n", fd);
        return -1;
    }

    assert (buf.st_size % (sizeof(int) + 256) == 0);

    fp = fdopen(fd, "r");
    if (!fp) {
        fprintf(stderr, "could not get file pointer\n");
        return -1;
    }

    while (count < buf.st_size) {
        int file_cnt;
        char* fname;
        fname = (char *) malloc(256);
        if (read_filename_mapping(fp, &file_cnt, fname)) {
            fprintf(stderr, "could not read filemapping, count is %lu\n", count);
            return -1;
        }
        g_hash_table_insert(filename_table, GINT_TO_POINTER(file_cnt), fname);
        count += (sizeof(int) + 256);
    }
    return 0;
}

/* Read token info from file and place in HashTable */
int read_tokens(char* filename, GHashTable* option_info_table)
{
    int fd;
    int rc;
    struct stat buf;
    FILE* fp;
    off_t count = 0;

    fd = open(filename, O_RDONLY);
    if (fd <= 0) {
        fprintf(stderr, "could not open %s, %d\n", filename, fd);
        return -1;
    }

    rc = fstat(fd, &buf);
    if (rc < 0) {
        fprintf(stderr, "could not stat file, %d\n", fd);
        return -1;
    }

    assert (buf.st_size % (sizeof(struct token)) == 0);

    fp = fdopen(fd, "r");
    if (!fp) {
        fprintf(stderr, "could not get file pointer\n");
        return -1;
    }

    while (count < buf.st_size) {
        struct token* token;
        token = (struct token *) malloc(sizeof(struct token));
        if (read_token_from_file(fp, token)) {
            fprintf(stderr, "could not read token, count is %lu\n", count);
        }
        g_hash_table_insert(option_info_table, GINT_TO_POINTER(token->token_num), token);
        count += sizeof(struct token);
    }
    return 0;
}

int interpret_output(char* byte_result_file, GHashTable* option_info_table, GHashTable* filename_table, char* output_file)
{
    int fd;
    int rc;
    struct stat buf;
    FILE* fp;
    off_t count = 0;
    FILE* output_f;

    output_f = fopen(output_file, "w");
    if (!output_f) {
        fprintf(stderr, "could not open %s\n", output_file);
        return -1;
    }

    fd = open(byte_result_file, O_RDONLY);
    if (fd <= 0) {
        fprintf(stderr, "could not open %s, %d\n", byte_result_file, fd);
        return -1;
    }

    rc = fstat(fd, &buf);
    if (rc < 0) {
        fprintf(stderr, "could not stat byte result file, %d\n", fd);
        return -1;
    }

    assert (buf.st_size % (sizeof(struct byte_result)) == 0);

    fp = fdopen(fd, "r");
    if (!fp) {
        fprintf(stderr, "could not get file pointer of byte result file\n");
        return -1;
    }

    while (count < buf.st_size) {
        struct byte_result* result;
        struct token* token;
        const char* token_type;
        const char* output_type;
        char* token_filename;
        char* output_channel;

        result = (struct byte_result *) malloc(sizeof(struct byte_result));
        assert(result);
        if (read_byte_result_from_file(fdopen(fd, "r"), result)) {
            fprintf(stderr, "could not read byte_result, count is %lu\n", count);
            return -1;
        }

        token = (struct token *) g_hash_table_lookup(option_info_table, GINT_TO_POINTER(result->token_num));
        
        token_type = get_token_type_string (token->type);
        output_type = get_token_type_string (result->output_type);

        if (result->output_fileno == -1) {
            output_channel = (char *) "--";
        } else {
            output_channel = (char *) g_hash_table_lookup(filename_table, GINT_TO_POINTER(result->output_fileno));
            assert (output_channel);
        }

        if (token->fileno == -1) {
            token_filename = (char *) "--";
        } else {
            token_filename = (char *) g_hash_table_lookup(filename_table, GINT_TO_POINTER(token->fileno));
            assert(token_filename);
        }

        fprintf(output_f, "%s %s %llu %d %d %d %s %s %llu %d %d %d\n",
               output_type,
               output_channel,
               result->rg_id,
               result->record_pid,
               result->syscall_cnt,
               result->offset,
               token_type,
               token_filename,
               token->rg_id,
               token->record_pid,
               token->syscall_cnt,
               token->byte_offset);
        fflush(output_f);

        count += sizeof(struct byte_result);
        free(result);
    }
    return 0;
}

int main(int argc, char** argv)
{
    GHashTable* option_info_table;
    GHashTable* filename_table;

    if (argc < 5) {
        fprintf(stderr, "usage: ./interpret_tokens [tokens file] [filenames file] [output file] [result]\n");
        return 1;
    }

    /* Create a new Hashtable to hold the info about tokens */
    option_info_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    filename_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (read_tokens(argv[1], option_info_table)) {
        fprintf(stderr, "problem reading tokens\n");
        return 1;
    }
    if (read_filename_mappings(argv[2], filename_table)) {
        fprintf(stderr, "problem reading filename file\n");
        return 1;
    }
    if (interpret_output(argv[3], option_info_table, filename_table, argv[4])) {
        fprintf(stderr, "problem interpretting output\n");
        return 1;
    }
}
