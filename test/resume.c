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
	fprintf (stderr, "format: %s <logdir> [-p] [-f] [-m] [-g] [--pthread libdir] [--attach_offset=pid,sysnum] [--ckpt_at=replay_clock_val] [--from_ckpt=replay_clock-val] [--fake_calls=c1,c2...] \n",
			program);
}

int main (int argc, char* argv[])
{
	int fd, cfd, rc, attach_pin = 0, attach_gdb = 0;
	loff_t attach_index = -1;
	int attach_pid = -1;
	char* libdir = NULL;
	pid_t pid;
	char ldpath[4096];
	int base;
	int follow_splits = 0;
	int save_mmap = 0;
	int ckpt_at = 0;
	int from_ckpt = 0;
	int record_timing = 0;
	char filename[4096], pathname[4096];
	u_long proc_count, i;
	u_long nfake_calls = 0;
	u_long* fake_calls = NULL;

	struct option long_options[] = {
		{"pthread", required_argument, 0, 0},
		{"attach_pin_later", optional_argument, 0, 0},
		{"attach_offset", optional_argument, 0, 0},
		{"ckpt_at", required_argument, 0, 0},
		{"from_ckpt", required_argument, 0, 0},
		{"fake_calls", required_argument, 0, 0},
		{0, 0, 0, 0}
	};

	while (1) {
		char opt;
		int option_index = 0;

		opt = getopt_long(argc, argv, "fpmhgt", long_options, &option_index);
		//printf("getopt_long returns %c (%d)\n", opt, opt);

		if (opt == -1) {
			break;
		}

		switch(opt) {
		case 0:
			switch(option_index) {
				/* --pthread */
			case 0: 
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
			case 3:
				ckpt_at = atoi(optarg);
				printf ("Checkpointing at %d\n", ckpt_at);
				break;
			case 4:
				from_ckpt = atoi(optarg);
				break;	
			case 5:
			{
				char* p, *last;
				u_long i = 0;

				nfake_calls = 1;
				for (p = optarg; *p != '\0'; p++) {
					if (*p == ',') nfake_calls++;
				}
				fake_calls = malloc(nfake_calls*sizeof(u_long));
				if (fake_calls == NULL) {
					fprintf (stderr, "Cannot allocate fake calls\n");
					return -1;
				}
				last = optarg;
				for (p = optarg; *p != '\0'; p++) {
					if (*p == ',') {
						*p++ = '\0';
						fake_calls[i++] = atoi(last);
						last = p;
					}
				}
				fake_calls[i++] = atoi(last);
				break;
			}
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
			//printf("attach_pin is on\n");
			attach_pin = 1;
			
			break;
		case 'h':
			print_help(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 'g':
			//printf("attach_gdb is on\n");
			attach_gdb = 1;
			break;
		case 't':
			//printf("record timing is on\n");
			record_timing = 1;
			break;

		default:
			fprintf(stderr, "Unrecognized option\n");
			print_help(argv[0]);
			exit(EXIT_FAILURE);
			break;
		}
	}
	base = optind;

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
#if 0
	printf("libdir: %s, ldpath: %s\n", libdir, ldpath);
	printf("resume pid %d follow %d\n", pid, follow_splits);
	printf("resume(%d, %d, %d, %d, %s, %s, %lld, %d)\n", fd, attach_pin,
		follow_splits, save_mmap, argv[base], libdir, attach_index,
		attach_pid);
#endif
	if (from_ckpt > 0) {
		sprintf (filename, "ckpt.%d", from_ckpt);
		sprintf (pathname, "%s/ckpt.%d", argv[base], from_ckpt);
		printf ("restoring from %s\n", pathname);
		cfd = open (pathname, O_RDONLY);
		if (cfd < 0) {
			perror ("open checkpoint file");
			return cfd;
		}
		rc = read (cfd, &proc_count, sizeof(proc_count));
		if (rc != sizeof(proc_count)) {
			perror ("read proc count");
			return rc;
		}
		close(cfd);
		for (i = 1; i < proc_count; i++) {
			pid = fork ();
			if (pid == 0) {
				rc = resume_proc_after_ckpt (fd, argv[base], filename);
				if (rc < 0) {
					perror ("resume after ckpt");
					exit (-1);
				}
			}
		}
		rc = resume_after_ckpt (fd, attach_pin, attach_gdb, follow_splits, save_mmap, argv[base], libdir, filename,
					attach_index, attach_pid);
	} else {
		rc = resume_with_ckpt (fd, attach_pin, attach_gdb, follow_splits, save_mmap, argv[base], libdir,
				       attach_index, attach_pid, ckpt_at, record_timing, nfake_calls, fake_calls);
	}
	if (rc < 0) {
		perror("resume");
		return -1;
	}
	fprintf(stderr, "resume should not return\n");
	return -1;
}

