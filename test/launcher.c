// A simple program to launch a recorded execution
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"

int main (int argc, char* argv[])
{
    int fd, rc, i;
    unsigned int uid;
    int have_uid = 0; // flag to see if we should change the uid
    int link_debug = 0; // flag if we should debug linking
    char* libdir = NULL;
    int base;

    for (base = 1; base < argc; base++) {
	if (argc > base+1 && !strncmp(argv[base], "--uid", 5)) {
	    rc = sscanf(argv[base+1], "%u", &uid);
	    if (!rc) {
		fprintf (stderr, "format: launcher [--uid UID] [--pthread libdir] logdir program args\n");
		fprintf (stderr, "invalid uid\n");
		return -1;
	    }
	    have_uid = 1;
	    base++;
	} else if (argc > base+1 && !strncmp(argv[base], "--pthread", 8)) {
	    libdir = argv[base+1];
	    printf ("libdir is %s\n", libdir);
	    base++;
	} else if (!strncmp(argv[base], "--link-debug", 8)) {
	    link_debug = 1;
	} else {
	    break; // unrecognized arg - should be logdir
	}
    }
	
    printf ("argc: %d base: %d\n", argc, base);
    if (argc-base < 2) {
	fprintf (stderr, "format: launcher [--uid UID] [--pthread libdir] logdir program args\n");
	return -1;
    }

    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror ("open /dev/spec0");
	return -1;
    }
    rc = replay_fork (fd, 0, argv[base]);
    if (rc < 0) {
	perror ("replay_fork");
	return -1;
    }

    // set the program to run as a user if we have a uid
    if (have_uid) {
        rc = setuid(uid);
        if (rc) {
            fprintf (stderr, "Error setting uid to %d\n", uid);
            return -1;
        }
    }

    printf ("Execing %s\n", argv[base+1]);
    if (libdir) { 
	char ldpath[4096];
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
	if (set_linker (fd, ldpath) < 0) {
	    fprintf (stderr, "Cannot set linker path\n");
	    return -1;
	}
	if (link_debug) setenv("LD_DEBUG", "libs", 1);
	setenv("LD_LIBRARY_PATH", libdir, 1);
    }
    close (fd);

    rc = execv (argv[base+1], &argv[base+1]);
    if (rc < 0) {
	perror ("execv");
	return -1;
    }
    return 0;
}
