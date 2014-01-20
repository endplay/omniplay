#include "replayfs_fs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>

#define DEBUG

#ifdef DEBUG
#define debugf(...) printf(__VA_ARGS__)
#else
#define debugf(...)
#endif

static const char *argstr = "hv:";

struct args {
	char *file_name;
	int do_long;
	int show_hidden;
	int show_all;
	int show_versions;
	loff_t file_version;
};

static void print_file(int fd, const char *filename, struct args *args);

void print_usage(const char *bin) {
	printf("Usage: %s [-%s] <file_name>\n", bin, argstr);
}

void print_help(const char *bin) {
	print_usage(bin);
	printf("Options are:\n");
	printf("\tv <version>    -- Specify the version to show\n");
	printf("\th              -- Display this help prompt\n");
}

int parse_opts(int argc, char **argv, struct args *options) {
	char opt;
	int rc;

	memset(options, 0, sizeof(struct args));
	options->file_version = -1;

	opt = getopt(argc, argv, argstr);
	while (opt != -1) {
		switch (opt) {
			case 'v':
				rc = sscanf(optarg, "%llu", &options->file_version);

				if (rc != 1) {
					printf("The file version doesn't appear to be an integer\n");
					print_usage(argv[0]);
					return -1;
				}

				break;
			case 'h':
				print_help(argv[0]);
				exit(EXIT_SUCCESS);
				break;
			default:
				printf("Unrecognized option: %c\n");
				print_usage(argv[0]);
				return -1;
		}

		opt = getopt(argc, argv, argstr);
	}

	if (argc - optind > 1) {
		printf("Too many arguments passed in\n");
		print_usage(argv[0]);
		return -1;
	}

	if (argc - optind == 1) {
		options->file_name = argv[optind];
	} else {
		options->file_name = "~";
	}

	return 0;
}

int main(int argc, char **argv) {
	unsigned long long  version;
	int current_fd;
	/* The versioned file descriptor */
	int fd;
	int subdir;
	int nwritten;
	int rc;
	struct args args;

	struct stat st;
	char buffer[512];

	debugf("Parsing args\n");
	if (parse_opts(argc, argv, &args)) {
		exit(EXIT_FAILURE);
	}
	debugf("done parsing args\n");

	current_fd = open(".", O_RDONLY);
	if (current_fd < 0) {
		fprintf(stderr, "Could not open dir: %s\n", ".");
		exit(EXIT_FAILURE);
	}

	debugf("Opened orig fd of %d\n", current_fd);
	/* We need to do the current version */
	if (args.file_version == -1) {
		args.file_version = ioctl(current_fd, REPLAYFS_IOCTL_GET_VERSION,
				&args.file_version);
	}

	debugf("Updated file_version to %lld\n", args.file_version);
	fd = ioctl(current_fd, REPLAYFS_IOCTL_SET_VERSION, &args.file_version);
	if (fd < 0) {
		perror("ioctl ");
		exit(EXIT_FAILURE);
	}

	debugf("set_version success!, new fd is %d\n", fd);

	/* Now, set our current directory to be that file */
	subdir = ioctl(fd, REPLAYFS_IOCTL_GET_SUBDIR, args.file_name);
	if (subdir < 0) {
		fprintf(stderr, "Could not open dir %s\n", args.file_name);
		perror("ioctl REPLAYFS_IOCTL_GET_SUBDIR");
		exit(EXIT_FAILURE);
	}

	if (fchdir(subdir)) {
		perror("fchdir");
		exit(EXIT_FAILURE);
	}

	close(subdir);

	close(fd);

	close(current_fd);

	return EXIT_SUCCESS;
}

