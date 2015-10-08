// Shell program for running a sequential stream-based DIFT
// Files used for communication
// This is really for testing purposes only

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "util.h"

#include <atomic>

using namespace std;

//#define DETAILS

#define STATUS_INIT 0
#define STATUS_STARTING 1
#define STATUS_EXECUTING 2
#define STATUS_STREAM 3
#define STATUS_DONE 4

struct epoch {
    // Info from description file
    pid_t  start_pid;
    u_long start_syscall;
    u_long stop_syscall;
    u_long filter_syscall;
    char   hostname[256];

    // This is runtime info
    int    status;
    pid_t  cpid;
    pid_t  apid;
    pid_t  spid;
    char   outfile[256];
    char   infile[256];

    // For timings
    struct timeval tv_start;
    struct timeval tv_start_dift;
    struct timeval tv_start_stream;
    struct timeval tv_done;
};

#define MAX_EPOCHS 1024

int main (int argc, char* argv[]) 
{
    FILE* file;
    struct timeval tv_start, tv_start_merge, tv_done;
    char dirname[80];
    int fd, rc, status, epochs, i;
    struct epoch* epoch;
    u_long merge_entries = 0;

    if (argc != 2) {
	fprintf (stderr, "format: streamtt <epoch description file>\n");
	return -1;
    }
    
    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror("open /dev/spec0");
	return fd;
    }

    file = fopen(argv[1], "r");
    if (file == NULL) {
	fprintf (stderr, "Unable to open epoch description file %s, errno=%d\n", argv[1], errno);
	return -1;
    }
    rc = fscanf (file, "%79s\n", dirname);
    if (rc != 1) {
	fprintf (stderr, "Unable to parse header line of epoch descrtion file, rc=%d\n", rc);
	return -1;
    }
    epoch = (struct epoch *) calloc(MAX_EPOCHS, sizeof(struct epoch));
    if (epoch == NULL) {
	fprintf (stderr, "Unable to allocate epoch array\n");
	return -1;
    }
    i = 0;
    while (!feof(file)) {
	char line[256];
	if (fgets (line, 255, file)) {
	    if (!strncmp(line, "merge entries ", 14)) {
		merge_entries = atoi(line+14);
	    } else if (!strncmp(line, "group by ", 9)) {
	    } else {
		if (i == MAX_EPOCHS) {
		    fprintf (stderr, "Too many epochs\n");
		    return -1;
		}

		rc = sscanf (line, "%d %lu %lu %lu %s\n", &epoch[i].start_pid, &epoch[i].start_syscall, 
			     &epoch[i].stop_syscall, &epoch[i].filter_syscall, epoch[i].hostname);
		if (rc < 3) {
		    fprintf (stderr, "Unable to parse line of epoch descrtion file: %s\n", line);
		    return -1;
		} else if (rc == 3) {
		    epoch[i].filter_syscall = 0;
		}
		i++;
	    }
	}
    }
    epochs = i;
    fclose(file);

    gettimeofday (&tv_start, NULL);

    // Go throught epochs one-at-a-time backwards
    for (i = epochs-1; i >= 0; i--) {
	printf ("doing epoch %d\n", i);
	epoch[i].cpid = fork ();
	if (epoch[i].cpid == 0) {
	    if (i > 0) {
		char attach[80];
		sprintf (attach, "--attach_offset=%d,%lu", epoch[i].start_pid, epoch[i].start_syscall);
		rc = execl("./resume", "resume", "-p", dirname, "--pthread", "../eglibc-2.15/prefix/lib", attach, NULL);
	    } else {
		rc = execl("./resume", "resume", "-p", dirname, "--pthread", "../eglibc-2.15/prefix/lib", NULL);
	    }
	    fprintf (stderr, "execl of resume failed, rc=%d, errno=%d\n", rc, errno);
	    return -1;
	} else {
	    gettimeofday (&epoch[i].tv_start, NULL);
	    epoch[i].status = STATUS_STARTING;
	}

	// Now attach pin 
	do {
	    if (epoch[i].status == STATUS_STARTING) {
		rc = get_attach_status (fd, epoch[i].cpid);
		if (rc > 0) {
		    printf ("attach pid is %d cpid is %d\n", rc, epoch[i].cpid);
		    epoch[i].apid = rc;
		    sprintf (epoch[i].outfile, "/tmp/%d/stream-outs", epoch[i].cpid);
		    sprintf (epoch[i].infile, "/tmp/%d/stream-ins", epoch[i].cpid);

		    pid_t mpid = fork();
		    if (mpid == 0) {
			char cpids[80], syscalls[80], output_filter[80];
			const char* args[256];
			int argcnt = 0;
			
			args[argcnt++] = "pin";
			args[argcnt++] = "-pid";
			sprintf (cpids, "%d", rc);
			args[argcnt++] = cpids;
			args[argcnt++] = "-t";
			args[argcnt++] = "../dift/obj-ia32/linkage_data.so";
			if (i < epochs-1) {
			    sprintf (syscalls, "%ld", epoch[i].stop_syscall);
			    args[argcnt++] = "-l";
			    args[argcnt++] = syscalls;
			    args[argcnt++] = "-ao"; // Last epoch does not need to trace to final addresses
			}
			if (i > 0) {
			    args[argcnt++] = "-so";
			} 
			if (epoch[i].filter_syscall) {
			    sprintf (output_filter, "%lu", epoch[i].filter_syscall);
			    args[argcnt++] = "-ofs";
			    args[argcnt++] = output_filter;
			}
			if (merge_entries) {
			    char me[256];
			    args[argcnt++] = "-me";
			    sprintf (me, "%lu", merge_entries);
			    args[argcnt++] = me;
			}
			args[argcnt++] = NULL;
			rc = execv ("../../../pin/pin", (char **) args);
			fprintf (stderr, "execv of pin tool failed, rc=%d, errno=%d\n", rc, errno);
			return -1;
		    } else {
			gettimeofday (&epoch[i].tv_start_dift, NULL);
			epoch[i].status = STATUS_EXECUTING;
			break;
		    }
		}
	    }
	    usleep(1);
	} while (1);
	
	// Wait for children to complete
	do {
	    pid_t wpid = waitpid (-1, &status, 0);
	    if (wpid < 0) {
		fprintf (stderr, "waitpid returns %d, errno %d\n", rc, errno);
		return wpid;
	    } else {
		if (wpid == epoch[i].cpid) {
#ifdef DETAILS
		    printf ("DIFT of epoch %d is done\n", i);
#endif
		    epoch[i].spid = fork ();
		    if (epoch[i].spid == 0) {
			// Now start up a stream processor for this epoch
			const char* args[256];
			char dirname[80];
			int argcnt = 0;
			
			if (i < epochs-1) {
			    rc = symlink (epoch[i+1].outfile, epoch[i].infile);
			    if (rc < 0) perror ("symlink");
			}

			args[argcnt++] = "streamf";
			sprintf (dirname, "/tmp/%d", epoch[i].cpid);
			args[argcnt++] = dirname;
			if (i == epochs-1) {
			    args[argcnt++] = "-f";
			}
			if (i == 0) {
			    args[argcnt++] = "-s";
			}
			args[argcnt++] = NULL;
			
			rc = execv ("../dift/obj-ia32/streamf", (char **) args);
			fprintf (stderr, "execv of streamf failed, rc=%d, errno=%d\n", rc, errno);
			return -1;
		    } else {
			gettimeofday (&epoch[i].tv_start_stream, NULL);
			epoch[i].status = STATUS_STREAM;
		    }
		} else if (wpid == epoch[i].spid) {
		    gettimeofday (&epoch[i].tv_done, NULL);
		    epoch[i].status = STATUS_DONE;
		    if (i < epochs-1) {
			rc = unlink (epoch[i+1].outfile);
			if (rc < 0) perror ("unlink outfile");
			rc = unlink (epoch[i].infile);
			if (rc < 0) perror ("unlink infile");
		    }
		    break;
		}
	    }
	} while (1);
    }

    gettimeofday (&tv_done, NULL);
    
    close (fd);

    printf ("Overall:\n");
    printf ("\tStart time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("\tTool done time: %ld.%06ld\n", tv_start_merge.tv_sec, tv_start_merge.tv_usec);
    printf ("\tEnd time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);
    for (i = 0; i < epochs; i++) {
	printf ("Epoch %d:\n", i); 
	printf ("\tEpoch start time: %ld.%06ld\n", epoch[i].tv_start.tv_sec, epoch[i].tv_start.tv_usec);
	printf ("\tDIFT start time: %ld.%06ld\n", epoch[i].tv_start_dift.tv_sec, epoch[i].tv_start_dift.tv_usec);
	printf ("\tStream start time: %ld.%06ld\n", epoch[i].tv_start_stream.tv_sec, epoch[i].tv_start_stream.tv_usec);
	printf ("\tEpoch end time: %ld.%06ld\n", epoch[i].tv_done.tv_sec, epoch[i].tv_done.tv_usec);
   }

    return 0;
}
