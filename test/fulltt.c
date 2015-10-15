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
#include "util.h"

//#define SEQ_MERGE
//#define DETAILS

#define STATUS_INIT 0
#define STATUS_STARTING 1
#define STATUS_EXECUTING 2
#define STATUS_MAPPING 4
#define STATUS_DONE 5

struct epoch {
    // Info from description file
    pid_t  start_pid;
    u_long start_syscall;
    u_long stop_syscall;
    u_long filter_syscall;
    u_long use_ckpt;
    // This is runtime info
    int    status;
    pid_t  cpid;
    pid_t  mpid;
    // For timings
    struct timeval tv_start;
    struct timeval tv_start_dift;
    struct timeval tv_start_map;
    struct timeval tv_done;
};

#define MAX_EPOCHS 1024

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
#ifndef SEQ_MERGE
    struct timeval tv_mergestart, tv_mergeend;
    int merge_by;
#endif

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

		rc = sscanf (line, "%d %lu %lu %lu %lu\n", &epoch[i].start_pid, &epoch[i].start_syscall, 
			     &epoch[i].stop_syscall, &epoch[i].filter_syscall, &epoch[i].use_ckpt);
		if (rc < 3) {
		    fprintf (stderr, "Unable to parse line of epoch descrtion file: %s\n", line);
		    return -1;
		} else if (rc == 3) {
		    epoch[i].filter_syscall = 0;
		    epoch[i].use_ckpt = 0;
		} 
		i++;
	    }
	}
    }
    epochs = i;
    fclose(file);

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
		char* args[256];
		int argcnt = 0;
		char attach[80], ckpt[80];

		args[argcnt++] = "resume";
		args[argcnt++] = "-p";
		args[argcnt++] = dirname;
		args[argcnt++] = "--pthread";
		args[argcnt++] = "../eglibc-2.15/prefix/lib";
		if (i > 0) {
		    sprintf (attach, "--attach_offset=%d,%lu", epoch[i].start_pid, epoch[i].start_syscall);
		    args[argcnt++] = attach;
		}
		if (epoch[i].use_ckpt) {
		    args[argcnt++] = "--from_ckpt";
		    sprintf (ckpt, "%lu", epoch[i].use_ckpt);
		    args[argcnt++] = ckpt;
		}
		args[argcnt++] = NULL;
		rc = execv ("./resume", args);
		fprintf (stderr, "execv of resume failed, rc=%d, errno=%d\n", rc, errno);
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
		    if (rc > 0) {
			pid_t mpid = fork();
			if (mpid == 0) {
			    char cpids[80], syscalls[80], output_filter[80];
			    char* args[256];
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
			    }
			    if (i > 0) {
				args[argcnt++] = "-so";
			    }
			    if (i < epochs-1) {
				args[argcnt++] = "-ao"; // Last epoch does not need to trace to final addresses
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
#ifdef DETAILS
			printf ("DIFT of epoch %d is done\n", i);
#endif
			epoch[i].mpid = fork ();
			if (epoch[i].mpid == 0) {
			    char outname[80];
			    sprintf (outname, "/tmp/%d", epoch[i].cpid);
			    if (i == 0) {
				rc = execl ("../dift/obj-ia32/mkmerge", "mkmerge", outname, "-s", NULL);
			    } else {
				rc = execl ("../dift/obj-ia32/mkmerge", "mkmerge", outname, NULL);
			    }
			    fprintf (stderr, "execl of mkmerge failed, rc=%d, errno=%d\n", rc, errno);
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

#ifdef SEQ_MERGE
    // Now post-process the results
    ppid = fork();
    if (ppid == 0) {
	char** args = malloc((epochs + 2)*sizeof (char *));
	if (args == NULL) {
	    fprintf (stderr, "Unable to allocate merge arguments");
	    return -1;
	}
	args[0] = "merge_merge";
	for (i = 0; i < epochs; i++) {
	    args[i+1] = malloc(20);
	    if (args[i+1] == NULL) {
		fprintf (stderr, "Unable to allocate merge argument %d", i);
		return -1;
	    }
	    sprintf (args[i+1], "%d", epoch[i].cpid);
	}
	rc = execv ("../dift/obj-ia32/merge_merge", args);
	fprintf (stderr, "execv of merge_merge failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    // Wait for analysis to complete
    rc = waitpid (ppid, &status, 0);
    if (rc < 0) {
	fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, ppid);
	return rc;
    }
#else
    merge_by = 1;
    do {
	merge_by = merge_by * 2;
	for (i = 0; i < epochs; i += merge_by) {
	    int start1 = i;
	    int start2 = i + merge_by/2;
	    int finish1 = start2 - 1;
	    int finish2 = i + merge_by - 1;
	    if (start2 >= epochs) continue; // Odd number so no merge this round
	    if (finish2 >= epochs) finish2 = epochs-1;
	    printf ("Merging [%d,%d] and [%d,%d]\n", start1, finish1, start2, finish2);
	    gettimeofday (&tv_mergestart, NULL);
	    printf ("Merge %d %d start %ld.%06ld\n", start1, finish2, tv_mergestart.tv_sec, tv_mergestart.tv_usec);
	    ppid = fork();
	    if (ppid == 0) {
		char* args[9];
		char dir1[80], dir2[80], inname1[80], inname2[80], outname[80], parnum[80];
		int argcnt = 0;
		args[argcnt++] = "merge3";
		sprintf (dir1, "%d", epoch[start1].cpid);
		args[argcnt++] = dir1;
		if (start1 == finish1) {
		    args[argcnt++] = "merge";
		} else {
		    sprintf (inname1, "merge.%d.%d", start1, finish1);
		    args[argcnt++] = inname1;
		}
		sprintf (dir2, "%d", epoch[start2].cpid);
		args[argcnt++] = dir2;
		if (start2 == finish2) {
		    args[argcnt++] = "merge";
		} else {
		    sprintf (inname2, "merge.%d.%d", start2, finish2);
		    args[argcnt++] = inname2;
		}
		sprintf (outname, "merge.%d.%d", start1, finish2);
		args[argcnt++] = outname;
		if (start1 == 0) args[argcnt++] = "-s";
		if (finish2 == epochs-1) args[argcnt++] = "-f";
		if (merge_by < 8) {
		    sprintf (parnum, "%d", merge_by);
		} else {
		    sprintf (parnum, "%d", 8);
		}
		args[argcnt++] = "-p";
		args[argcnt++] = parnum;
		args[argcnt++] = NULL;

		rc = execv ("../dift/obj-ia32/merge3", args);
		fprintf (stderr, "execv of merge3 failed, rc=%d, errno=%d\n", rc, errno);
		return -1;
	    }
	    
	    // Wait for analysis to complete
	    rc = waitpid (ppid, &status, 0);
	    if (rc < 0) {
		fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, ppid);
		return rc;
	    }
	    gettimeofday (&tv_mergeend, NULL);
	    printf ("Merge %d %d stop %ld.%06ld\n", start1, finish2, tv_mergeend.tv_sec, tv_mergeend.tv_usec);
	}
    } while (merge_by < epochs);
#endif

    gettimeofday (&tv_done, NULL); 
   
    close (fd);

    printf ("Overall:\n");
    printf ("\tStart time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("\tTool done time: %ld.%06ld\n", tv_start_merge.tv_sec, tv_start_merge.tv_usec);
    printf ("\tEnd time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);
    for (i = 0; i < epochs; i++) {
	printf ("Epoch %d:\n", i); 
	printf ("\tPid: %d\n", epoch[i].cpid);
	printf ("\tEpoch start time: %ld.%06ld\n", epoch[i].tv_start.tv_sec, epoch[i].tv_start.tv_usec);
	printf ("\tDIFT start time: %ld.%06ld\n", epoch[i].tv_start_dift.tv_sec, epoch[i].tv_start_dift.tv_usec);
	printf ("\tMap start time: %ld.%06ld\n", epoch[i].tv_start_map.tv_sec, epoch[i].tv_start_map.tv_usec);
	printf ("\tEpoch end time: %ld.%06ld\n", epoch[i].tv_done.tv_sec, epoch[i].tv_done.tv_usec);
   }

    return 0;
}
