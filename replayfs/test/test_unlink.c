#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>


int main(int argc, char **argv) {
	char *filename;
	int fd;
	
	/* Okay, step 1, verify our args */
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <test_filename>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	filename = argv[1];

	/* Okay, args in, now lets make our directory */
	fd = open(filename, O_CREAT | O_RDWR, 0777);

	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (close(fd)) {
		perror("close");
		exit(EXIT_FAILURE);
	}


	/* Now remove the directory */
	if (unlink(filename)) {
		perror("unlink");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}


