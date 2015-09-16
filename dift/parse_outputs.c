#include <stdio.h>
#include "xray_token.h"

void print_token(struct token* token) {
    fprintf(stdout, "%d %lu %lu %d %d %d %lld %d\n",
        token->type,
        token->token_num,
        token->size,
        token->syscall_cnt,
        token->byte_offset,
        token->fileno,
        token->rg_id,
        token->record_pid);
}

int read_tokens_file(char* filename) {
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

    if (buf.st_size % (sizeof(struct token))) {
        fprintf(stderr, "file size is %ld, token size is %d\n",
                buf.st_size, sizeof(struct token));
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
        if (token == NULL) {
            fprintf (stderr, "Unable to malloc token\n");
            assert (0);
        }
        if (read_token_from_file(fp, token)) {
            fprintf(stderr, "could not read token, count is %lu\n", count);
        }
	print_token(token);
        count += sizeof(struct token);
    }
    return 0;
}

int print_filename_mappings(char* filename)
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
	if (fname == NULL) {
	    fprintf (stderr, "Unable to malloc fname\n");
	    assert (0);
	}
        if (read_filename_mapping(fp, &file_cnt, fname)) {
            fprintf(stderr, "could not read filemapping, count is %lu\n", count);
            return -1;
        }
	fprintf(stdout, "%s %d\n", fname, file_cnt);
        count += (sizeof(int) + 256);
    }
    return 0;
}

int main(int argc, char** argv) {
    char* group_dir;
    char tokens_filename[256];
    char filenames_filename[256];

    if (argc < 2) {
        fprintf(stderr, "ERROR\n");
        return 1;
    }
    group_dir = argv[1];
    fprintf(stdout, "group dir is %s\n", group_dir);

    snprintf(tokens_filename, 256, "%s/tokens", group_dir);
    snprintf(filenames_filename, 256, "%s/filenames", group_dir);

    read_tokens_file(tokens_filename);
    print_filename_mappings(filenames_filename);

    return 0;
}
