#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <glib.h>

#include "xray_token.h"
#include "trace_x.h"

// usage: ./parse_xoutput [tokens file] [x output file]
//  Results printed to stdout
int main(int argc, char** argv)
{
    int fd;
    int rc;
    struct stat buf;
    off_t count = 0;
    GHashTable* option_info_table;

    option_info_table = g_hash_table_new(g_direct_hash, g_direct_equal);

    if (read_tokens(argv[1], option_info_table)) {
        fprintf(stderr, "problem reading tokens, ernno %d\n", errno);
        return 1;
    }

    fd = open(argv[2], O_RDONLY);
    if (fd <= 0) {
        fprintf(stderr, "could not open %s, errno %d\n", argv[1], errno);
        return 1;
    }

    rc = fstat(fd, &buf);
    if (rc < 0) {
        fprintf(stderr, "could not stat byte result file, errno %d\n", errno);
        return -1;
    }

    if (buf.st_size % (sizeof(struct x_byte_result)) != 0) {
        fprintf(stderr, "size of file is %lu\n", (unsigned long) buf.st_size);
        fprintf(stderr, "size of x_byte_result is %u\n", sizeof(struct x_byte_result));
        assert (buf.st_size % (sizeof(struct x_byte_result)) == 0);
    }
    assert (buf.st_size % (sizeof(struct x_byte_result)) == 0);

    while (count < buf.st_size) {
        int rc;
        struct x_byte_result result;
        struct token* token;
        const char* token_type;

        rc = read(fd, &result, sizeof(struct x_byte_result));
        if (rc != sizeof(struct x_byte_result)) {
            fprintf(stderr, "expected to read %d, got %d, errno %d\n", sizeof(struct x_byte_result), rc, errno);
            exit(1);
        }
        token = (struct token *) g_hash_table_lookup(option_info_table, GINT_TO_POINTER(result.token_num));
        if (!token) {
            fprintf(stderr, "could not find token num %d for result\n", result.token_num);
        }
        assert(token);
        token_type = get_token_type_string (token->type);

        fprintf(stdout, "%llu %d %d x,y: (%d, %d) %u %s %llu %d %d %d %c\n",
                result.rg_id,
                result.record_pid,
                result.syscall_cnt,
                result.x, result.y,
                result.token_num,
                token_type,
                token->rg_id,
                token->record_pid,
                token->syscall_cnt,
                token->byte_offset,
                token->value);

        count += rc;
    }
    return 0;
}
