#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <glib-2.0/glib.h>
#include <errno.h>
#include "xray_token.h"

static int print_values = 0;

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

    if (buf.st_size % (sizeof(struct byte_result))) {
        fprintf(stderr, "file size is %ld, size of byte result %d\n", buf.st_size, sizeof(struct byte_result));
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
        if (read_byte_result_from_file(fd, result)) {
            fprintf(stderr, "could not read byte_result, count is %lu\n", count);
            return -1;
        }

        token = (struct token *) g_hash_table_lookup(option_info_table, GINT_TO_POINTER(result->token_num));
        if (!token) {
            fprintf(stderr, "could not find token num %d for result\n", result->token_num);
            fprintf(stderr, "count is %ld, size is %ld\n", count, buf.st_size);
            fprintf(stderr, "otput_type %d\n", result->output_type);
            fprintf(stderr, "otput_fileno %d\n", result->output_fileno);
            fprintf(stderr, "rg_id %llu\n", result->rg_id);
            fprintf(stderr, "record_pid %d\n", result->record_pid);
            fprintf(stderr, "syscall_cnt %d\n", result->record_pid);
            fprintf(stderr, "offset %d\n", result->record_pid);
        }
        assert(token);
        
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

        if (print_values) {
            fprintf(output_f, "%s %s %llu %d %d %d %c %s %s %llu %d %d %d %c\n",
               output_type,
               output_channel,
               result->rg_id,
               result->record_pid,
               result->syscall_cnt,
               result->offset,
               result->value,
               token_type,
               token_filename,
               token->rg_id,
               token->record_pid,
               token->syscall_cnt,
               token->byte_offset,
               token->value);
        } else {
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
        }
        fflush(output_f);

        count += sizeof(struct byte_result);
        free(result);
    }
    return 0;
}

void format()
{
    fprintf(stderr, "usage: ./interpret_tokens [-v] [tokens file] [filenames file] [output file] [result]\n");
    exit (1);
}

int main(int argc, char** argv)
{
    GHashTable* option_info_table;
    GHashTable* filename_table;

    int base;
    struct option long_options[] = {
        {0, 0, 0, 0}
    };

    // copying David's option parsing here
    while (1) {
        char opt;
        int option_index = 0;

		setenv("POSIXLY_CORRECT", "1", 1);
		opt = getopt_long(argc, argv, "v", long_options, &option_index);
		unsetenv("POSIXLY_CORRECT");

        if (opt == -1) {
            break;
        }

        switch(opt) {
            case 'v':
                print_values = 1;
                break;
            default:
                fprintf(stderr, "Unrecognized cmd line option\n");
                format();
                break;
        }
    }
    base = optind;

    /* Create a new Hashtable to hold the info about tokens */
    option_info_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    filename_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (read_tokens(argv[base], option_info_table)) {
        fprintf(stderr, "problem reading tokens, errno %d\n", errno);
        return 1;
    }
    if (read_filename_mappings(argv[base + 1], filename_table)) {
        fprintf(stderr, "problem reading filename file %d\n", errno);
        return 1;
    }
    if (interpret_output(argv[base + 2], option_info_table, filename_table, argv[base + 3])) {
        fprintf(stderr, "problem interpretting output, errno %d\n", errno);
        return 1;
    }
    return 0;
}
