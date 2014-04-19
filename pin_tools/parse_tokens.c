#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "xray_token.h"

int main(int argc, char** argv)
{
    int fd;
    int rc;
    struct stat buf;
    FILE* fp;
    off_t count = 0;

    fd = open(argv[1], O_RDONLY);
    if (fd <= 0) {
        fprintf(stderr, "could not open %s, %d\n", argv[1], fd);
        return 1;
    }

    rc = fstat(fd, &buf);
    if (rc < 0) {
        fprintf(stderr, "could not stat byte result file, %d\n", fd);
        return -1;
    }

    if (buf.st_size % (sizeof(struct token)) != 0) {
        assert (buf.st_size % (sizeof(struct token)));
    }

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
        fprintf(stdout, "%d %u %d %llu %d %d %d %c\n",
                token->type,
                token->token_num,
                token->fileno,
                token->rg_id,
                token->record_pid,
                token->syscall_cnt,
                token->byte_offset,
		token->value);
        free(token);
        count += (sizeof(struct token));
    }
    return 0;
}
