// A simple program to launch a recorded execution
#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "util.h"

extern char** environ;

void format ()
{
	fprintf (stderr, "format: launcher [--logdir logdir] [--pthread libdir] [-m] program [args]\n");
	exit (1);
}

int main (int argc, char* argv[])
{
	int fd, rc, i;
	int link_debug = 0; // flag if we should debug linking
	char* libdir = NULL;
	char* logdir = NULL;
	int base;
	char ldpath[4096];
	char* linkpath = NULL;
	int save_mmap = 0;

	struct option long_options[] = {
		{"logdir", required_argument, 0, 0},
		{"pthread", required_argument, 0, 0},
		{0, 0, 0, 0}
	};

	/*
	for (i = 0; i < argc; i++) {
		printf("Got input arg of %s\n", argv[i]);
	}
	*/

	while (1) {
		char opt;
		int option_index = 0;

		setenv("POSIXLY_CORRECT", "1", 1);
		opt = getopt_long(argc, argv, "mh", long_options, &option_index);
		unsetenv("POSIXLY_CORRECT");
		//printf("getopt_long returns %c (%d)\n", opt, opt);

		if (opt == -1) {
			break;
		}

		switch(opt) {
			case 0:
				switch(option_index) {
					case 0:
						//printf("logdir is %s\n", optarg);
						logdir = optarg;
						assert(optarg != NULL);
						break;
					case 1:
						//printf("pthread libdir is %s\n", optarg);
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
			case 'h':
				format();
				break;
			default:
				fprintf(stderr, "Unrecognized option\n");
				format();
				break;
		}
	}
	base = optind;

	/* David D. Replaced with proper getopts */
	/*
	for (base = 1; base < argc; base++) {
		if (argc > base+1 && !strncmp(argv[base], "--pthread", 8)) {
			libdir = argv[base+1];
			base++;
		} else if (argc > base+1 && !strncmp(argv[base], "--logdir", 8)) {
			logdir = argv[base+1];
			base++;
		} else if (!strncmp(argv[base], "--link-debug", 8)) {
			link_debug = 1;
		} else if (!strncmp(argv[base], "-m", 2)) {
			save_mmap = 1;
		} else {
			break; // unrecognized arg - should be logdir
		}
	}
	*/


	if (argc-base < 1) {
		fprintf(stderr, "Program name not specified");
		format();
	}

	/*
	for (i = base; i < argc; i++) {
		printf("Got non-opt arg: %s\n", argv[i]);
	}
	*/

	fd = open ("/dev/spec0", O_RDWR);
	if (fd < 0) {
		perror ("open /dev/spec0");
		return -1;
	}

	if (libdir) { 
		strcpy (ldpath, libdir);
		for (i = 0; i < strlen(ldpath); i++) {
			if (ldpath[i] == ':') {
				ldpath[i] = '\0';
				break;
			}
		}
		strcat (ldpath, "/");
		strcat (ldpath, "ld-linux.so.2");
		argv[base-1] = ldpath;
		linkpath = ldpath;

		setenv("LD_LIBRARY_PATH", libdir, 1);
	}
	if (link_debug) setenv("LD_DEBUG", "libs", 1);

	printf("linkpath: %s, ldpath: %s\n", linkpath, ldpath);
	rc = replay_fork (fd, (const char**) &argv[base], (const char **) environ, linkpath, logdir, save_mmap);

	// replay_fork should never return if it succeeds
	fprintf (stderr, "replay_fork failed, rc = %d\n", rc);
	return rc;

}
