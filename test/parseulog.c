#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#define __user
#include "../linux-lts-quantal-3.5.0/include/linux/pthread_log.h"

int main (int argc, char* argv[])
{
    struct pthread_log_data rec;
    int fd, rc;
    struct stat st;
    int bytes_read = 0;

    if (argc < 2) {
        printf ("Format: parseulog <log file>\n");
        exit (0);
    }

    rc = stat(argv[1], &st);
    if (rc < 0) {
        fprintf(stderr, "stat of %s failed with %d\n", argv[1], rc);
        perror("stat failed\n");
        return rc;
    }

    fd = open (argv[1], O_RDONLY);
    if (fd < 0) {
        perror ("open log file\n");
        return fd;
    }

    while (bytes_read < st.st_size) {

        if (bytes_read > st.st_size) {
            perror("bytes_read > st.st_size ???\n");
        }

	// mcc: Each user log segment now contains the number of entries before the entries
        int count = 0;
        int num_entries = 0;
        rc = read (fd, &num_entries, sizeof(int));
        if (rc != sizeof(int)) {
            perror("could not read the count read\n");
        }
        bytes_read += rc;

        for (count = 0; count < num_entries; count++) {
            rc = read (fd, &rec, sizeof(struct pthread_log_data));
            if (rc < 0) {
                perror ("read log record\n");
                return rc;
            }
            printf ("clock %lu type %lu check %lx retval %d (%x)\n", rec.clock, rec.type, rec.check, rec.retval, rec.retval);
            bytes_read += rc;
        }
    }

    close (fd);
    return 0;
}
