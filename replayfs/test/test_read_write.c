#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

const char *str1 = "test";
const char *str2 = "test2\n";

int main(int argc, char **argv) {
	int fd;
	int nwritten;
	char *buf;
	struct stat st;

	if (argc != 3) {
		printf("Usage: %s read_filename write_filename\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	fd = open(argv[1], O_RDONLY);

	if (fd < 0) {
		perror("open: ");
		exit(EXIT_FAILURE);
	}

	if (fstat(fd, &st)) {
		perror("stat");
		exit(EXIT_FAILURE);
	}

	buf = malloc(st.st_size);
	if (buf == NULL) {
		fprintf(stderr, "allocation failure with size %d\n", st.st_size);
		exit(EXIT_FAILURE);
	}

	nwritten = read(fd, buf, st.st_size);
	if (nwritten != st.st_size) {
		perror("read");
		exit(EXIT_FAILURE);
	}

	close(fd);

	fd = open(argv[2], O_CREAT | O_RDWR, 0666);
	if (fd < 0) {
		perror("open (writing)");
		exit(EXIT_FAILURE);
	}

	nwritten = write(fd, buf, st.st_size);
	if (nwritten != st.st_size) {
		perror("write");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return EXIT_SUCCESS;
}

