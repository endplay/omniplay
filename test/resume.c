// A simple program to resume a recorded execution
#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#include <assert.h>

#include <sys/types.h>

void print_help(const char *program) {
    fprintf (stderr, "format: %s <logdir> [-p] [-f] [-m] [--pthread libdir]\n",
	    program);
}

int main (int argc, char* argv[])
{
    int fd, rc, attach_pin = 0;
    char* libdir = NULL;
    pid_t pid;
    char ldpath[4096];
    int base;
    int follow_splits = 0;
    int save_mmap = 0;

    struct option long_options[] = {
	{"pthread", required_argument, 0, 0},
	{0, 0, 0, 0}
    };

    /*
    do {
	int i;
	for (i = 0; i < argc; i++) {
	    printf("Got input arg of %s\n", argv[i]);
	}
    } while (0);
    */

    while (1) {
	char opt;
	int option_index = 0;

	opt = getopt_long(argc, argv, "fpmh", long_options, &option_index);
	//printf("getopt_long returns %c (%d)\n", opt, opt);

	if (opt == -1) {
	    break;
	}

	switch(opt) {
	    case 0:
		switch(option_index) {
		    case 0: //printf("pthread libdir is %s\n", optarg);
			libdir = optarg;
			break;
		    default:
			assert(0);
		}
		break;
	    case 'm':
		//printf("save_mmap is on");
		save_mmap = 1;
		break;
	    case 'f':
		//printf("follow_splits is on");
		follow_splits = 1;
		break;
	    case 'p':
		//printf("attach_pin is on");
		attach_pin = 1;
		break;
	    case 'h':
		print_help(argv[0]);
		exit(EXIT_SUCCESS);
		break;
	    default:
		fprintf(stderr, "Unrecognized option\n");
		print_help(argv[0]);
		exit(EXIT_FAILURE);
		break;
	}
    }
    base = optind;

    /* David D. Replaced with proper getopts */
    /*
    for (base = 2; base < argc; base++) {
	if (!strcmp(argv[base], "-p")) {
	    attach_pin = 1;
	} else if (!strcmp(argv[base], "-f")) {
	    follow_splits = 1;
	} else if (!strcmp(argv[base], "-m")) {
	    save_mmap = 1;
	} else if (argc > base+1 && !strncmp(argv[base], "--pthread", 8)) {
	    libdir = argv[base+1];
	    base++;
	} else {
	    break; // unrecognized arg 
	}
    } 
    */

    /*
    do {
	int i;
	for (i = base; i < argc; i++) {
	    printf("Got non-opt arg: %s\n", argv[i]);
	}
    } while (0);
    */

    if (argc-base != 1) {
	fprintf(stderr, "Invalid non-arg arguments!\n");
	print_help(argv[0]);
	exit(EXIT_FAILURE);
    }

    if (attach_pin && save_mmap) {
	fprintf(stderr, "Attaching pin (-p) and saving mmaps (-m) shouldn't both be enabled!\n");
	exit(EXIT_FAILURE);
    }

    if (libdir) {
	strcpy (ldpath, libdir);
	strcat (ldpath, "/ld-linux.so.2");
	libdir = ldpath;
    }

    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror ("open /dev/spec0");
	exit(EXIT_FAILURE);
    }
    pid = getpid();
    printf("libdir: %s, ldpath: %s\n", libdir, ldpath);
    printf("resume pid %d follow %d\n", pid, follow_splits);
    rc = resume (fd, attach_pin, follow_splits, save_mmap, argv[base], libdir);
    if (rc < 0) {
	perror ("resume");
	return -1;
    }
    fprintf (stderr, "resume should not return\n");
    return -1;
}
