// Shell program for running a sequential multi-stage DIFT
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <semaphore.h>
#include "util.h"

//#define DETAILS

#define STATUS_INIT 0
#define STATUS_STARTING 1
#define STATUS_EXECUTING 2
#define STATUS_SPLICING 3
#define STATUS_MAPPING 4
#define STATUS_DONE 5

struct epoch {
    // Info from description file
    pid_t  start_pid;
    u_long start_syscall;
    u_long stop_syscall;
    u_long filter_syscall;
    // This is runtime info
    int    status;
    pid_t  cpid;
    pid_t  spid;
    pid_t  mpid;
    char   semname[80];
    sem_t* sem;
    // For timings
    struct timeval tv_start;
    struct timeval tv_start_dift;
    struct timeval tv_start_splice;
    struct timeval tv_start_map;
    struct timeval tv_done;
};

#define MAX_EPOCHS 256

int main (int argc, char* argv[]) 
{
    FILE* file;
    struct timeval tv_start, tv_start_merge, tv_done;
    char dirname[80];
    int fd, rc, status, epochs, gstart, gend, i, executing, epochs_done;
    struct epoch* epoch;
    
    pid_t ppid;
    u_long merge_entries = 0;
    int group_by = 0;

    if (argc != 2) {
	fprintf (stderr, "format: partt <epoch description file>\n");
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
		group_by = atoi(line+9);
	    } else {
		if (i == MAX_EPOCHS) {
		    fprintf (stderr, "Too many epochs\n");
		    return -1;
		}

		rc = sscanf (line, "%d %lu %lu %lu\n", &epoch[i].start_pid, &epoch[i].start_syscall, 
			     &epoch[i].stop_syscall, &epoch[i].filter_syscall);
		if (rc < 3) {
		    fprintf (stderr, "Unable to parse line of epoch descrtion file: %s\n", line);
		    return -1;
		} else if (rc == 3) {
		    epoch[i].filter_syscall = 0;
		}
#if 0
		printf ("%d %lu %lu %lu\n", epoch[i].start_pid, epoch[i].start_syscall, 
			epoch[i].stop_syscall, epoch[i].filter_syscall);
#endif
		i++;
	    }
	}
    }
    epochs = i;
    fclose(file);

    // Generate semaphores for epoch coordination
    for (i = 0; i < epochs; i++) {
	sprintf (epoch[i].semname, "/splicesem.%d", i);
	epoch[i].sem = sem_open (epoch[i].semname, O_CREAT|O_EXCL, 0666, 0);
	if (epoch[i].sem == NULL && errno == EEXIST) {
	    // Leftover - delete it first?
	  int val;
	  epoch[i].sem = sem_open (epoch[i].semname, 0, 0666, 0);
	  if (epoch[i].sem) {
	    rc = sem_getvalue(epoch[i].sem, &val);
	    printf ("semaphore %s rc %d value %d\n", epoch[i].semname, rc, val);
	    sem_close (epoch[i].sem);
	  }
	   
	    sem_unlink (epoch[i].semname);
	    epoch[i].sem = sem_open (epoch[i].semname, O_CREAT|O_EXCL, 0666, 0);
	}
	if (epoch[i].sem == NULL) {
	    fprintf (stderr, "Unable to create semaphore %s, errno=%d\n", epoch[i].semname, errno);
	    return -1;
	}
    }

    gettimeofday (&tv_start, NULL);

    gend = epochs;
    do {
	if (group_by) {
	    if (gend - group_by > 0) {
		gstart = gend - group_by;
	    } else {
		gstart = 0;
	    }
	} else {
	    gstart = 0; // do em all at once
	    group_by = epochs;
	}
	printf ("Doing epochs %d to %d in this group\n", gstart, gend-1);

	// Start all the epochs at once
	for (i = gstart; i < gend; i++) {
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
	}

	// Now attach pin to all of the epoch processes
	executing = 0;
	do {
	    for (i = gstart; i < gend; i++) {
		if (epoch[i].status == STATUS_STARTING) {
		    rc = get_attach_status (fd, epoch[i].cpid);
		    if (rc == 1) {
			pid_t mpid = fork();
			if (mpid == 0) {
			    char cpids[80], splice_file[80], syscalls[80], output_filter[80];
			    char* args[256];
			    int argcnt = 0;
			    
			    args[argcnt++] = "pin";
			    args[argcnt++] = "-pid";
			    sprintf (cpids, "%d", epoch[i].cpid);
			    args[argcnt++] = cpids;
			    args[argcnt++] = "-t";
			    args[argcnt++] = "../dift/obj-ia32/linkage_data.so";
			    if (i > 0) {
				args[argcnt++] = "-so";
			    } 
			    if (i < epochs-1) {
				sprintf (splice_file, "/tmp/%d/splice", epoch[i+1].cpid);
				args[argcnt++] = "-si";
				args[argcnt++] = splice_file;
				args[argcnt++] = "-sem";
				args[argcnt++] = epoch[i+1].semname;
				if (i == 0) {
				    sprintf (syscalls, "%ld", epoch[i].stop_syscall);
				} else {
				    sprintf (syscalls, "%ld", epoch[i].stop_syscall-epoch[i].start_syscall+1);
				}
				args[argcnt++] = "-l";
				args[argcnt++] = syscalls;
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
			    rc = execv ("../../../pin/pin", args);
			    fprintf (stderr, "execv of pin tool failed, rc=%d, errno=%d\n", rc, errno);
			    return -1;
			} else {
			    gettimeofday (&epoch[i].tv_start_dift, NULL);
			    epoch[i].status = STATUS_EXECUTING;
			    executing++;
#ifdef DETAILS			    
			    printf ("%d/%d epochs executing\n", executing, gend-gstart);
#endif
			}
		    }
		}
	    }
	    usleep(1);
	} while (executing < (gend-gstart));
	
	// Wait for children to complete
	epochs_done = 0;
	do {
	    pid_t wpid = waitpid (-1, &status, 0);
	    if (wpid < 0) {
		fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, epoch[i].cpid);
		return wpid;
	    } else {
		for (i = gstart; i < gend; i++) {
		    if (wpid == epoch[i].cpid) {
			if (i > 0) {
#ifdef DETAILS
			    printf ("DIFT of epoch %d is done\n", i);
#endif
			    epoch[i].spid = fork ();
			    if (epoch[i].spid == 0) {
				char outname[80];
				sprintf (outname, "/tmp/%d", epoch[i].cpid);
				rc = execl ("../dift/obj-ia32/mksplice", "mksplice", outname, NULL);
				//rc = execl ("../dift/obj-ia32/mkmultisplice", "mkmultisplice", outname, NULL);
				fprintf (stderr, "execl of mksplice failed, rc=%d, errno=%d\n", rc, errno);
				return -1;
			    } else {
				gettimeofday (&epoch[i].tv_start_splice, NULL);
				epoch[i].status = STATUS_SPLICING;
			    }
			} else {
			    // No splice file so just create map file
			    epoch[i].mpid = fork ();
			    if (epoch[i].mpid == 0) {
				char outname[80];
				sprintf (outname, "/tmp/%d", epoch[i].cpid);
				rc = execl ("../dift/obj-ia32/mkmap", "mkmap", outname, NULL);
				fprintf (stderr, "execl of mlmap failed, rc=%d, errno=%d\n", rc, errno);
				return -1;
			    } else {
				gettimeofday (&epoch[i].tv_start_map, NULL);
				epoch[i].status = STATUS_MAPPING;
			    }
			}
		    } else if (wpid == epoch[i].spid) {
#ifdef DETAILS
			printf ("Splice of epoch %d is done\n", i);
#endif
			rc = sem_post (epoch[i].sem);
			if (rc < 0) {
			    fprintf (stderr, "unable to post on semaphore %s, errno=%d\n", epoch[i].semname, errno);
			    return rc;
			}
			epoch[i].mpid = fork ();
			if (epoch[i].mpid == 0) {
			    char outname[80];
			    sprintf (outname, "/tmp/%d", epoch[i].cpid);
			    rc = execl ("../dift/obj-ia32/mkmap", "mkmap", outname, NULL);
			    fprintf (stderr, "execl of mlmap failed, rc=%d, errno=%d\n", rc, errno);
			    return -1;
			} else {
			    gettimeofday (&epoch[i].tv_start_map, NULL);
			    epoch[i].status = STATUS_MAPPING;
			}
		    } else if (wpid == epoch[i].mpid) {
#ifdef DETAILS
			printf ("Map of epoch %d is done\n", i);
#endif
			gettimeofday (&epoch[i].tv_done, NULL);
			epoch[i].status = STATUS_DONE;
			epochs_done++;
		    }
		}
	    }
	} while (epochs_done < (gend-gstart));
	gend -= group_by;
    } while (gend > 0);

    gettimeofday (&tv_start_merge, NULL);

    // Now post-process the results
    ppid = fork();
    if (ppid == 0) {
	char** args = malloc((epochs + 2)*sizeof (char *));
	if (args == NULL) {
	    fprintf (stderr, "Unable to allocate merge arguments");
	    return -1;
	}
	args[0] = "splice_merge";
	for (i = 0; i < epochs; i++) {
	    args[i+1] = malloc(20);
	    if (args[i+1] == NULL) {
		fprintf (stderr, "Unable to allocate merge argument %d", i);
		return -1;
	    }
	    sprintf (args[i+1], "%d", epoch[i].cpid);
	}
	rc = execv ("../dift/obj-ia32/splice_merge", args);
	fprintf (stderr, "execv of splice_merge failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    // Wait for analysis to complete
    rc = waitpid (ppid, &status, 0);
    if (rc < 0) {
	fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, ppid);
	return rc;
    }

    gettimeofday (&tv_done, NULL);
    
    close (fd);

    for (i = 0; i < epochs; i++) {
	sem_close (epoch[i].sem);
	sem_unlink (epoch[i].semname);
    }

    printf ("Overall:\n");
    printf ("\tStart time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("\tTool done time: %ld.%06ld\n", tv_start_merge.tv_sec, tv_start_merge.tv_usec);
    printf ("\tEnd time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);
    for (i = 0; i < epochs; i++) {
	printf ("Epoch %d:\n", i); 
	printf ("\tEpoch start time: %ld.%06ld\n", epoch[i].tv_start.tv_sec, epoch[i].tv_start.tv_usec);
	printf ("\tDIFT start time: %ld.%06ld\n", epoch[i].tv_start_dift.tv_sec, epoch[i].tv_start_dift.tv_usec);
	if (i > 0) printf ("\tSplice start time: %ld.%06ld\n", epoch[i].tv_start_splice.tv_sec, epoch[i].tv_start_splice.tv_usec);
	printf ("\tMap start time: %ld.%06ld\n", epoch[i].tv_start_map.tv_sec, epoch[i].tv_start_map.tv_usec);
	printf ("\tEpoch end time: %ld.%06ld\n", epoch[i].tv_done.tv_sec, epoch[i].tv_done.tv_usec);
   }

    return 0;
}
