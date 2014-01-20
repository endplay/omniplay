#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>

const char *str1 = "test";
const char *str2 = "test2\n";

int main(int argc, char **argv) {
	int fd;
	int nwritten;

	if (argc != 2) {
		printf("Usage: %s filename\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	fd = open(argv[1], O_CREAT | O_RDWR, 0666);

	if (fd < 0) {
		perror("open: ");
		exit(EXIT_FAILURE);
	}

	nwritten = write(fd, str1, strlen(str1));
	if (nwritten != strlen(str1)) {
		perror("write (str1) ");
		exit(EXIT_FAILURE);
	}

	nwritten = write(fd, str2, strlen(str2));
	if (nwritten != strlen(str2)) {
		perror("write (str2) ");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return EXIT_SUCCESS;
}

