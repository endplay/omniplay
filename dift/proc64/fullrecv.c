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

//#define DETAILS

#define STATUS_INIT 0
#define STATUS_STARTING 1
#define STATUS_EXECUTING 2
#define STATUS_MAPPING 4
#define STATUS_DONE 5

#define EPOCH_PORT_START 10000

struct epoch {
    // This is runtime info
    int    status;
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
    struct epoch* epoch;
    int i, merge_by, rc, status, epochs_done, epochs;
    struct timeval tv_start, tv_start_merge, tv_mergestart, tv_mergeend, tv_done;
    pid_t ppid;
    char* dirname;

    if (argc != 3) {
	fprintf (stderr, "format: fullrecv <dir> [epoch #]\n");
	return -1;
    }
    
    dirname = argv[1];
    epochs = atoi(argv[2]);

    epoch = (struct epoch *) calloc(epochs, sizeof(struct epoch));
    if (epoch == NULL) {
	fprintf (stderr, "Unable to allocate epoch array\n");
	return -1;
    }

    gettimeofday (&tv_start, NULL);

    // Start all the epochs at once
    for (i = 0; i < epochs; i++) {
	epoch[i].mpid = fork ();
	if (epoch[i].mpid == 0) {
	    const char* args[256];
	    int argcnt = 0;
	    char port[80], dir[80];
	    
	    args[argcnt++] = "mkmerge";
	    sprintf (dir, "%s/%d", dirname, i);
	    args[argcnt++] = dir;
	    sprintf (port, "%d", EPOCH_PORT_START+i);
	    args[argcnt++] = port;
	    if (i == 0) args[argcnt++] = "-s";
	    args[argcnt++] = NULL;
	    rc = execv ("./mkmerge", (char **) args);
	    fprintf (stderr, "execv of mkmerge failed, rc=%d, errno=%d\n", rc, errno);
	    return -1;
	} else {
	    gettimeofday (&epoch[i].tv_start, NULL);
	    epoch[i].status = STATUS_STARTING;
	}
    }

    // Wait for merges to complete
    epochs_done = 0;
    do {
	pid_t wpid = waitpid (-1, &status, 0);
	if (wpid < 0) {
	    fprintf (stderr, "waitpid returns %d, errno %d\n", wpid, errno);
	    return wpid;
	} else {
	    for (i = 0; i < epochs; i++) {
		if (wpid == epoch[i].mpid) {
#ifdef DETAILS
		    printf ("Merge of epoch %d is done\n", i);
#endif
		    gettimeofday (&epoch[i].tv_done, NULL);
		    epoch[i].status = STATUS_DONE;
		    epochs_done++;
		}
	    }
	}
    } while (epochs_done < epochs);

    gettimeofday (&tv_start_merge, NULL);

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
		const char* args[256];
		char dir1[80], dir2[80], inname1[80], inname2[80], outname[80], parnum[80];
		int argcnt = 0;
		args[argcnt++] = "merge3";
		args[argcnt++] = dirname;
		sprintf (dir1, "%d", start1);
		args[argcnt++] = dir1;
		if (start1 == finish1) {
		    args[argcnt++] = "merge";
		} else {
		    sprintf (inname1, "merge.%d.%d", start1, finish1);
		    args[argcnt++] = inname1;
		}
		sprintf (dir2, "%d", start2);
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

		rc = execv ("./merge3", (char **) args);
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

    gettimeofday (&tv_done, NULL); 
   
    printf ("Overall:\n");
    printf ("\tStart time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("\tTool done time: %ld.%06ld\n", tv_start_merge.tv_sec, tv_start_merge.tv_usec);
    printf ("\tEnd time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);
    for (i = 0; i < epochs; i++) {
	printf ("Epoch %d:\n", i); 
	printf ("\tEpoch start time: %ld.%06ld\n", epoch[i].tv_start.tv_sec, epoch[i].tv_start.tv_usec);
	printf ("\tDIFT start time: %ld.%06ld\n", epoch[i].tv_start_dift.tv_sec, epoch[i].tv_start_dift.tv_usec);
	printf ("\tMap start time: %ld.%06ld\n", epoch[i].tv_start_map.tv_sec, epoch[i].tv_start_map.tv_usec);
	printf ("\tEpoch end time: %ld.%06ld\n", epoch[i].tv_done.tv_sec, epoch[i].tv_done.tv_usec);
   }

    return 0;
}
