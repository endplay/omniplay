// A simple program to resume a recorded execution
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "util.h"

#include <sys/types.h>

int main (int argc, char* argv[])
{
    int fd, rc, attach_pin = 0;
    char* libdir = NULL;
    pid_t pid;
    char ldpath[4096];
    int base;
    int follow_splits = 0;

    for (base = 2; base < argc; base++) {
	if (!strcmp(argv[base], "-p")) {
	    attach_pin = 1;
	} else if (!strcmp(argv[base], "-f")) {
	    follow_splits = 1;
	} else if (argc > base+1 && !strncmp(argv[base], "--pthread", 8)) {
	    libdir = argv[base+1];
	    base++;
	} else {
	    break; // unrecognized arg 
	}
    } 

    if (argc-base != 0) {
	fprintf (stderr, "format: resume logdir [-p] [-f] [--pthread libdir]\n");
	return -1;
    }

    if (libdir) {
	strcpy (ldpath, libdir);
	strcat (ldpath, "/ld-linux.so.2");
	libdir = ldpath;
    }

    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror ("open /dev/spec0");
	return -1;
    }
    pid = getpid();
    printf("resume pid %d\n", pid);
    rc = resume (fd, attach_pin, follow_splits, argv[1], libdir);
    if (rc < 0) {
	perror ("resume");
	return -1;
    }
    fprintf (stderr, "resume should not return\n");
    return -1;
}
