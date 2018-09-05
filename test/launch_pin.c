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
#include <sys/mman.h>
#include <string.h>
#include "util.h"

#define MAX_PROCESSES  2
#define BUFFER_SIZE 1024

void print_usage()
{
  fprintf (stderr, "format: launch_pin <replay dir> <pin_tool_name>\n");
}

int main (int argc, char* argv[]) 
{
    struct timeval tv_start, tv_attach, tv_tool_done, tv_done;
    char cpids[80], tmpdir[80], lscmd[80];
    char* dirname;
    char* pin_tool;

    pid_t cpid, mpid, ppid;
    int fd, rc, status;

    int next_child = 0, i;
    size_t n = BUFFER_SIZE;
    FILE* fp; 

    if (argc < 3) {
        print_usage();
	return -1;
    }

    dirname = argv[1];
    pin_tool = argv[2];

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
    } while (rc <= 0);
    
    gettimeofday (&tv_attach, NULL);

    mpid = fork();
    if (mpid == 0) {
	const char* args[256];
	char tool_path[256];
	sprintf(tool_path, "../pin_tools/obj-ia32/%s", pin_tool);
	u_int argcnt = 0;

	args[argcnt++] = "pin";
	args[argcnt++] = "-pid";
	sprintf (cpids, "%d", cpid);
	args[argcnt++] = cpids;
	args[argcnt++] = "-t";
	args[argcnt++] = tool_path;


	if (argc > 3) {
	  printf("adding extra args\n");
	  for (i = 3; i < argc; ++i) {
	    args[argcnt++] = argv[i];
	    printf("%s\n", args[argcnt-1]);
	  }
	}


	args[argcnt++] = NULL;
	rc = execv ("../../../pin/pin", (char **) args);
	fprintf (stderr, "execv of pin tool failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    // Wait for cpid to complete

    rc = wait_for_replay_group(fd, cpid);
    rc = waitpid (cpid, &status, 0);
    if (rc < 0) {
	fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, cpid);
    }

    gettimeofday (&tv_tool_done, NULL);

    printf("TOOL finished\n");
    gettimeofday (&tv_done, NULL);
    
    close (fd);

    printf ("Start time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("Attach time: %ld.%06ld\n", tv_attach.tv_sec, tv_attach.tv_usec);
    printf ("End time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);

    long diff_usec = tv_done.tv_usec - tv_start.tv_usec;  
    long carryover = 0;
    if(diff_usec < 0) { 
	carryover = -1;
	diff_usec = 1 - diff_usec;
    }
    long diff_sec = tv_done.tv_sec - tv_start.tv_sec - carryover; 

    printf ("Start -> End: %ld.%06ld\n", diff_sec,diff_usec);
    

    return 0;
}
