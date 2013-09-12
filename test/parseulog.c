#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#define __user
#include "../linux-lts-quantal-3.5.0/include/linux/pthread_log.h"

int main (int argc, char* argv[])
{
    int fd, rc;
    struct stat st;
    int bytes_read = 0;
#ifndef USE_DEBUG_LOG
    u_long total_clock = 0;
#endif

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
	int num_bytes;
        rc = read (fd, &num_bytes, sizeof(int));
        if (rc != sizeof(int)) {
		perror("Could not read the count\n");
		return -1;
        }
	printf ("** reading %d bytes ***\n", num_bytes);
        bytes_read += rc;

	while (count < num_bytes) {
#ifdef USE_DEBUG_LOG
	    struct pthread_log_data rec;
            rc = read (fd, &rec, sizeof(struct pthread_log_data));
            if (rc < 0) {
                perror ("read log record\n");
                return rc;
            }
            printf ("clock %lu type %lu check %lx retval %d (%x)\n", rec.clock, rec.type, rec.check, rec.retval, rec.retval);
	    count += rc;
            bytes_read += rc;
#else
	    u_long entry;
	    long i;
	    int skip, retval, fake_calls;

            rc = read (fd, &entry, sizeof(u_long));
            if (rc != sizeof(u_long)) {
                perror ("read log record\n");
                return rc;
            }
	    count += rc;
            bytes_read += rc;
            printf ("   entry %lx usual recs %ld non-zero retval? %d fake calls? %d skip? %d\n", entry, (entry&CLOCK_MASK), !!(entry&NONZERO_RETVAL_FLAG), !!(entry&FAKE_CALLS_FLAG), !!(entry&SKIPPED_CLOCK_FLAG));
	    for (i = 0; i < (entry&CLOCK_MASK); i++) {
		total_clock++;
		printf ("clock %lu fake calls 0 retval 0\n", total_clock-1);
	    }
	    if (entry&SKIPPED_CLOCK_FLAG) {
		rc = read (fd, &skip, sizeof(int));
		if (rc != sizeof(int)) {
		    perror ("read skip value\n");
		    return rc;
		}
		count += rc;
		bytes_read += rc;
		total_clock += skip + 1;
	    } else {
		total_clock++;
	    }
	    if (entry&NONZERO_RETVAL_FLAG) {
		rc = read (fd, &retval, sizeof(int));
		if (rc != sizeof(int)) {
		    perror ("read retval value\n");
		    return rc;
		}
		count += rc;
		bytes_read += rc;
	    } else {
		retval = 0;
	    }
	    if (entry&FAKE_CALLS_FLAG) {
		rc = read (fd, &fake_calls, sizeof(int));
		if (rc != sizeof(int)) {
		    perror ("read fake calls value\n");
		    return rc;
		}
		count += rc;
		bytes_read += rc;
	    } else {
		fake_calls = 0;
	    }
	    if (entry&(SKIPPED_CLOCK_FLAG|NONZERO_RETVAL_FLAG|FAKE_CALLS_FLAG)) {
		    printf ("clock %lu fake calls %d retval %d \n", total_clock-1, fake_calls, retval);
	    }
#endif
        }

    }

    close (fd);
    return 0;
}
