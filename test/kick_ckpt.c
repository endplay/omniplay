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
    fprintf (stderr, "format: %s [pid]\n", program);
}

int main (int argc, char* argv[])
{
    int fd, rc;
    pid_t pid;

    if (argc != 2) print_help (argv[0]);

    pid = atoi(argv[1]);

    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror("open /dev/spec0");
	return fd;
    }
    rc = get_ckpt_status (fd, pid);
    if (rc != 1) {
	return -1;
    }
    
    close (fd);
    return 0;
}

