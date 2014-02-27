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

    if (buf.st_size % (sizeof(int) + 256) != 0) {
        fprintf(stderr, "size of file is %lu\n", (unsigned long) buf.st_size);
        fprintf(stderr, "size of byte result is %u\n", sizeof(struct byte_result));
        assert (buf.st_size % (sizeof(struct byte_result)) == 0);
    }
    assert (buf.st_size % (sizeof(int) + 256) == 0);

    while (count < buf.st_size) {
        int file_cnt;
        char* filename;
        filename = (char *) malloc(256);
        assert(filename);
        if (read_filename_mapping(fdopen(fd, "r"), &file_cnt, filename)) {
            fprintf(stderr, "could not read, count is %lu\n", count);
        }
        fprintf(stdout, "%d %s\n", file_cnt, filename);
        free(filename);
        count += (sizeof(int) + 256);
    }
}
