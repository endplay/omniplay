// Shell program for running a sequential multi-stage DIFT
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "util.h"

int main (int argc, char* argv[]) 
{
    struct timeval tv_start, tv_attach, tv_tool_done, tv_done;
    char cpids[80], tmpdir[80];
    char* dirname;
    pid_t cpid, mpid, ppid;
    int fd, rc, status, filter_syscall = 0;
    
    if (argc < 2) {
	fprintf (stderr, "format: seqtt <replay dir> [filter syscall]\n");
	return -1;
    }

    dirname = argv[1];
    if (argc == 3) {
	filter_syscall = atoi(argv[2]);
    }

    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror("open /dev/spec0");
	return fd;
    }

    gettimeofday (&tv_start, NULL);

    cpid = fork ();
    if (cpid == 0) {
	rc = execl("./resume", "resume", "-p", dirname, "--pthread", "../eglibc-2.15/prefix/lib", NULL);
	fprintf (stderr, "execl of resume failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    } 
    
    do {
	// Wait until we can attach pin
	rc = get_attach_status (fd, cpid);
    } while (rc != 1);
    
    gettimeofday (&tv_attach, NULL);

    mpid = fork();
    if (mpid == 0) {
	sprintf (cpids, "%d", cpid);
	if (filter_syscall) {
	    rc = execl ("../../../pin/pin", "pin", "-pid", cpids, "-t", "../dift/obj-ia32/linkage_data.so", "-ofs", argv[2], NULL);
	} else {
	    rc = execl ("../../../pin/pin", "pin", "-pid", cpids, "-t", "../dift/obj-ia32/linkage_data.so", NULL);
	}
	fprintf (stderr, "execl of pin tool failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    // Wait for cpid to complete
    rc = waitpid (cpid, &status, 0);
    if (rc < 0) {
	fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, cpid);
    }

    gettimeofday (&tv_tool_done, NULL);

    // Now post-process the results
    ppid = fork();
    if (ppid == 0) {
	sprintf (tmpdir, "/tmp/%d", cpid);
	rc = execl ("../dift/obj-ia32/postprocess_linkage", "postprocess_linkage", "-m", tmpdir, NULL);
	fprintf (stderr, "execl of postprocess_linkage failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    // Wait for analysis to complete
    rc = waitpid (ppid, &status, 0);
    if (rc < 0) {
	fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, cpid);
    }

    gettimeofday (&tv_done, NULL);
    
    close (fd);

    printf ("Start time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("Attach time: %ld.%06ld\n", tv_attach.tv_sec, tv_attach.tv_usec);
    printf ("Tool done time: %ld.%06ld\n", tv_tool_done.tv_sec, tv_tool_done.tv_usec);
    printf ("End time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);

    return 0;
}
