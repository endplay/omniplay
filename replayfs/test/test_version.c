#include "replayfs_fs.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

struct args {
	char *file_name;
	int do_long;
	loff_t file_version;
};

void print_usage(const char *bin) {
	printf("Usage: %s [-lh] <file_name> <version_number>\n", bin);
}

void print_help(const char *bin) {
	print_usage(bin);
	printf("Options are:\n");
	printf("\tl     -- List file metadata\n");
	printf("\th     -- Display this help prompt\n");
}

int parse_opts(int argc, char **argv, struct args *options) {
	char opt;
	int rc;

	opt = getopt(argc, argv, "h");
	while (opt != -1) {
		switch (opt) {
			case 'h':
				print_help(argv[0]);
				exit(EXIT_SUCCESS);
				break;
			default:
				printf("Unrecognized option: %c\n");
				print_usage(argv[0]);
				return -1;
		}

		opt = getopt(argc, argv, "lh");
	}

	if (argc - optind != 2) {
		print_usage(argv[0]);
		return -1;
	}

	options->file_name = argv[optind];

	rc = sscanf(argv[optind+1], "%llu", &options->file_version);
	if (rc != 1) {
		printf("The file version doesn't appear to be an integer\n");
		print_usage(argv[0]);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv) {
	int current_fd;
	/* The versioned file descriptor */
	int fd;
	int nwritten;
	int rc;
	struct args args;

	struct stat st;
	char buffer[512];

	if (parse_opts(argc, argv, &args)) {
		exit(EXIT_FAILURE);
	}

	current_fd = open(args.file_name, O_RDONLY);
	if (current_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	fd = ioctl(current_fd, REPLAYFS_IOCTL_SET_VERSION, &args.file_version);
	if (fd < 0) {
		perror("ioctl ");
		exit(EXIT_FAILURE);
	}

	printf("set_version success!, new fd is %d\n", fd);

	/* Read the entire file */
	if (fstat(fd, &st)) {
		perror("stat ");
		exit(EXIT_FAILURE);
	}

	if (S_ISDIR(st.st_mode)) {
		struct dirent *dirp;
		DIR *dir;

		dir = (DIR *)fdopendir(fd);
		if (dir == NULL) {
			perror("fdopendir");
			exit(EXIT_FAILURE);
		}

		printf("Printing out all directories in %s:\n", argv[1]);
		do {
			dirp = readdir(dir);
			if (dirp != NULL) {
				printf("\t%s\n", dirp->d_name);
			}
		} while (dirp != NULL);


		closedir(dir);
	} else {

		printf("fstat done, size is %d\n", st.st_size);

		printf("Now printing out the entire contents of %s version %llu:\n", argv[1],
				args.file_version);

		nwritten = 0;
		while (nwritten < st.st_size) {
			int ntoread;
			int nread;
			int ntowrite;
			char *buf_pos;

			ntoread = st.st_size - nwritten;
			if (ntoread > 512) {
				ntoread = 512;
			}

			printf("ntoread is %d\n", ntoread);
			ntowrite = read(fd, buffer, ntoread);

			printf("ntowrite is %d\n", ntowrite);

			if (ntowrite < 0) {
				perror("read ");
				exit(EXIT_FAILURE);
			}

			/* 
			 * We're going to keep trying until we succeed, so we can assume we've
			 * written out all of the bytes here
			 */
			nwritten += ntowrite;

			/* Make sure we write out everything */
			rc = 0;
			buf_pos = buffer;
			while (ntowrite > 0) {
				rc = write(1, buf_pos, ntowrite);
				if (rc < 0) {
					perror("write ");
					exit(EXIT_FAILURE);
				}
				buf_pos += rc;
				ntowrite -= rc;
			}
		}

		close(fd);
	}

	close(current_fd);

	return EXIT_SUCCESS;
}

