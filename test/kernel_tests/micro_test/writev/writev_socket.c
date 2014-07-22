#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#define TESTFILE "writev_testfile.txt"

#define NUM_IOS 3
#define NUM_LOOPS 3

int main(int argc, char **argv) {
	int fd;
	struct iovec ios[NUM_IOS];
	char *buffs[NUM_IOS];
	struct stat st;

	int rc;
	int i;
	int total_lines = 0;

	fd = open(TESTFILE, O_CREAT | O_RDWR, 0666);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < NUM_IOS; i++) {
		buffs[i] = malloc(0x100);
		assert(buffs[i] != NULL);
	}

	for (i = 0; i < NUM_LOOPS; i++) {
		int j;

		for(j = 0; j < NUM_IOS; j++, total_lines++) {
			snprintf(buffs[j], 0x100, "TestLine: %d\n", total_lines);

			ios[j].iov_base = buffs[j];
			ios[j].iov_len = strlen(buffs[j]);
		}

		rc = writev(fd, ios, NUM_IOS);
		if (rc <= 0) {
			perror("writev");
			exit(EXIT_FAILURE);
		}
	}

	close(fd);

	return EXIT_SUCCESS;
}

