
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>


int main(int argc, char **argv) {
	char *dirname;
	
	/* Okay, step 1, verify our args */
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <test_dirname>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	dirname = argv[1];

	/* Okay, args in, now lets make our directory */
	if (mkdir(dirname, 0777)) {
		perror("mkdir");
		exit(EXIT_FAILURE);
	}

	/* Now remove the directory */
	if (rmdir(dirname)) {
		perror("rmdir");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}


