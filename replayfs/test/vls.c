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

#ifdef DEBUG
#define debugf(...) printf(__VA_ARGS__)
#else
#define debugf(...)
#endif

static const char *argstr = "lhaAVv:";

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
	printf("\tl              -- List file metadata\n");
	printf("\tA              -- Show hidden directories\n");
	printf("\ta              -- Show all directories\n");
	printf("\tV              -- Show all availabe versions\n");
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
			case 'a':
				options->show_all = 1;
				break;
			case 'A':
				options->show_hidden = 1;
				break;
			case 'l':
				options->do_long = 1;
				break;
			case 'v':
				rc = sscanf(optarg, "%llu", &options->file_version);

				if (rc != 1) {
					printf("The file version doesn't appear to be an integer\n");
					print_usage(argv[0]);
					return -1;
				}

				break;
			case 'V':
				options->show_versions = 1;
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
		options->file_name = ".";
	}

	return 0;
}

int main(int argc, char **argv) {
	unsigned long long  version;
	int current_fd;
	/* The versioned file descriptor */
	int fd;
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

	current_fd = open(args.file_name, O_RDONLY);
	if (current_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	debugf("Opened orig fd of %d\n", fd);
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

	/* Read the entire file */
	if (fstat(fd, &st)) {
		perror("stat ");
		exit(EXIT_FAILURE);
	}

	debugf("Stat done %lld\n", args.file_version);

	if (S_ISDIR(st.st_mode)) {
		struct dirent *dirp;
		DIR *dir;

		dir = (DIR *)fdopendir(fd);
		if (dir == NULL) {
			perror("fdopendir");
			exit(EXIT_FAILURE);
		}

		debugf("Printing out all directories in %s:\n", args.file_name);
		do {
			dirp = readdir(dir);
			if (dirp != NULL) {
				int dir_fd;
				
				dir_fd = ioctl(fd, REPLAYFS_IOCTL_GET_SUBDIR,
						dirp->d_name);
				if (dir_fd < 0) {
					perror("dir_open ioctl");
					exit(EXIT_FAILURE);
				}

				print_file(dir_fd, dirp->d_name, &args);

				close(dir_fd);
			}
		} while (dirp != NULL);

		closedir(dir);
	} else {
		print_file(fd, args.file_name, &args);

		close(fd);
	}

	close(current_fd);

	return EXIT_SUCCESS;
}

/* 
 * Actually do the printing, lets decide on a format...
 *   <mode> <owner> <group> <size> <mtime> <filename> <max_version>
 */

static void str_long_mode(mode_t mode, char *str) {
	if (mode & 1) {
		str[2] = 'x';
	} else {
		str[2] = '-';
	}

	if (mode & 2) {
		str[1] = 'w';
	} else {
		str[1] = '-';
	}

	if (mode & 4) {
		str[0] = 'r';
	} else {
		str[0] = '-';
	}
}

static void print_file(int fd, const char *filename, struct args *args) {
	/* First, filter non displayed files */
	/* Check to see if its . or .. */
	if ((!args->show_all) && 
			(
				(strlen(filename) == 1 && filename[0] == '.') ||
				(strlen(filename) == 2 && filename[0] == '.' && filename[1] == '.')
			)
		 ) {
		return;
	}

	/* Now check for hidden files */
	if ((!args->show_hidden && !args->show_all) && 
			(filename[0] == '.')
		 ) {
		return;
	}

	if (args->do_long) {
		char long_mode[12];
		char *time;
		struct stat st;
		struct group *group;
		struct passwd *owner;

		if (fstat(fd, &st)) {
			perror("dir fstat");
			exit(EXIT_FAILURE);
		}

		long_mode[11] = '\0';
		if (S_ISDIR(st.st_mode)) {
			long_mode[0] = 'd';
		} else {
			long_mode[0] = '-';
		}

		str_long_mode(st.st_mode>>0, long_mode+7);
		str_long_mode(st.st_mode>>3, long_mode+4);
		str_long_mode(st.st_mode>>6, long_mode+1);
		long_mode[10] = '.';

		group = getgrgid(st.st_gid);
		if (group == NULL) {
			perror("getgrgid");
			exit(EXIT_FAILURE);
		}

		owner = getpwuid(st.st_uid);
		if (owner == NULL) {
			perror("getpwnam");
			exit(EXIT_FAILURE);
		}

		time = ctime(&st.st_mtime);
		time[strlen(time)-1] = '\0';

		/* Print long opts */
		printf("%s %d %s %s %d %s ", long_mode, st.st_nlink, owner->pw_name,
				group->gr_name,
				st.st_size, time);
	}

	/* Print filename */
	printf("%s", filename);

	if (args->show_versions) {
		loff_t max_version;

		/* Print version */
		if (ioctl(fd, REPLAYFS_IOCTL_MAX_VERSION, &max_version)) {
			perror("ioctl REPLAYFS_IOCTL_MAX_VERSION");
			exit(EXIT_FAILURE);
		}

		printf(" %lld", max_version);
	}

	/* Print return */
	printf("\n");
}

