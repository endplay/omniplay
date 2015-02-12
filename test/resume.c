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
    fprintf (stderr, "format: %s <logdir> [-p] [-f] [-m] [-g] [--pthread libdir]\n",
            program);
}

int main (int argc, char* argv[])
{
    int fd, rc, attach_pin = 0, attach_gdb = 0;
    loff_t attach_index = -1;
    int attach_pid = -1;

    char* libdir = NULL;
    pid_t pid;
    char ldpath[4096];
    int base;
    int follow_splits = 0;
    int save_mmap = 0;

    struct option long_options[] = {
        {"pthread", required_argument, 0, 0},
        {"attach_pin_later", optional_argument, 0, 0},
        {"attach_offset", optional_argument, 0, 0},
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

        opt = getopt_long(argc, argv, "fpmhg", long_options, &option_index);
        //printf("getopt_long returns %c (%d)\n", opt, opt);

        if (opt == -1) {
            break;
        }

        switch(opt) {
            case 0:
                switch(option_index) {
		    /* --pthread */
                    case 0: printf("pthread libdir is %s\n", optarg);
                        libdir = optarg;
                        break;
		    /* --attach_offset or --attach_pin_later */
		    case 1: case 2:
			if (sscanf(optarg, "%d,%lld", &attach_pid, &attach_index)
				!= 2) {
			    fprintf(stderr, "ERROR: expected format: --attach_offset <pid>,<sysnum>\n");
			    exit(EXIT_FAILURE);
			}
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
                printf("attach_pin is on\n");
                attach_pin = 1;

                break;
            case 'h':
                print_help(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'g':
                printf("attach_gdb is on\n");
                attach_gdb = 1;
                break;
            default:
                fprintf(stderr, "Unrecognized option\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
                break;
        }
    }
    base = optind;

    printf("argc = %d, base = %d\n", argc, base);
    if (argc-base != 1) {
        fprintf(stderr, "Invalid non-arg arguments!\n");
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (attach_pin && save_mmap) {
        fprintf(stderr, "Attaching pin (-p) and saving mmaps (-m) shouldn't both be enabled!\n");
        exit(EXIT_FAILURE);
    }

    if (attach_pin && attach_gdb) {
        fprintf(stderr, "Cannot attach both pin (-p) and gdb (-g).\n");
        exit(EXIT_FAILURE);
    }

    if (libdir) {
        strcpy(ldpath, libdir);
        strcat(ldpath, "/ld-linux.so.2");
        libdir = ldpath;
    }

    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
        perror("open /dev/spec0");
        exit(EXIT_FAILURE);
    }
    pid = getpid();
    printf("libdir: %s, ldpath: %s\n", libdir, ldpath);
    printf("resume pid %d follow %d\n", pid, follow_splits);
    printf("resume(%d, %d, %d, %d, %s, %s, %lld, %d)\n", fd, attach_pin,
	    follow_splits, save_mmap, argv[base], libdir, attach_index,
	    attach_pid);
    rc = resume(fd, attach_pin, follow_splits, save_mmap, argv[base], libdir,
	    attach_index, attach_pid);
    if (rc < 0) {
        perror("resume");
        return -1;
    }
    fprintf(stderr, "resume should not return\n");
    return -1;
}
