// A simple program to launch a recorded execution
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"

extern char** environ;

void format ()
{
    fprintf (stderr, "format: launcher [--uid UID] [--logdir logdir] [--pthread libdir] program [args]\n");
    exit (1);
}

int main (int argc, char* argv[])
{
    int fd, rc, i;
    unsigned int uid = 0; // set to non-zero if uid changed by command line
    int link_debug = 0; // flag if we should debug linking
    char* libdir = NULL;
    char* logdir = NULL;
    int base;
    char ldpath[4096];
    char* linkpath = NULL;

    for (base = 1; base < argc; base++) {
	if (argc > base+1 && !strncmp(argv[base], "--uid", 5)) {
	    rc = sscanf(argv[base+1], "%u", &uid);
	    if (!rc) format ();
	    base++;
	} else if (argc > base+1 && !strncmp(argv[base], "--pthread", 8)) {
	    libdir = argv[base+1];
	    base++;
	} else if (argc > base+1 && !strncmp(argv[base], "--logdir", 8)) {
	    logdir = argv[base+1];
	    base++;
	} else if (!strncmp(argv[base], "--link-debug", 8)) {
	    link_debug = 1;
	} else {
	    break; // unrecognized arg - should be logdir
	}
    }
	
    if (argc-base < 1) format();

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

    rc = replay_fork (fd, (const char**) &argv[base], (const char **) environ, uid, linkpath, logdir);

    // replay_fork should never return if it succeeds
    fprintf (stderr, "replay_fork failed, rc = %d\n", rc);
    return rc;

}
