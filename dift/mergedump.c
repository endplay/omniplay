#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>
#include <fcntl.h>

#include "taint_interface/taint_creation.h"
#include "maputil.h"

int main(int argc, char** argv)
{
    char resmergefile[80], mergefile[80], taintfile[80];
    int resmergefd, mergefd, taintfd;
    u_long resmergedatasize, resmergemapsize, mergedatasize, mergemapsize, taintdatasize, taintmapsize;
    char* resmergebuf, *mergebuf, *taintbuf;
    int i, rc;
    int epoch_cnt = 0, zeros = 0, values = 0, resolved = 0;
    u_long addr;
    u_long* mgbuf, *tout;

    if (argc != 2) {
	printf ("format: mergedump <dir #>\n");
	exit (0);
    }
    
    sprintf (mergefile, "/tmp/%s/merge-outputs", argv[1]);
    sprintf (resmergefile, "/tmp/%s/dataflow.result", argv[1]);
    sprintf (taintfile, "/tmp/%s/taint_structures", argv[1]);

    rc = map_file (resmergefile, &resmergefd, &resmergedatasize, &resmergemapsize, &resmergebuf);
    if (rc < 0) return rc;

    rc = map_file (mergefile, &mergefd, &mergedatasize, &mergemapsize, &mergebuf);
    if (rc < 0) return rc;

    rc = map_file (taintfile, &taintfd, &taintdatasize, &taintmapsize, &taintbuf);
    if (rc < 0) return rc;

    mgbuf = (u_long *) mergebuf;
    while ((u_long) mgbuf < (u_long) mergebuf + mergedatasize) {
	epoch_cnt++;
	if (*mgbuf == 0) zeros++;
	do {
	    if (*mgbuf) {
		values++;
		if (*mgbuf > 0xc0000000) {
		    resolved++;
		} else {
		    printf ("%lx\n", *mgbuf);
		}
		mgbuf++;
	    } else {
		mgbuf++;
		break;
	    }
	} while (1);
    }

    printf ("%d out of %d are zeros, %d values, %d resolved\n", zeros, epoch_cnt, values, resolved);
    zeros = epoch_cnt = 0;
    unmap_file ((char *) mergebuf, mergefd, mergemapsize);
    
    
    sprintf (mergefile, "/tmp/%s/merge-addrs", argv[1]);
    rc = map_file (mergefile, &mergefd, &mergedatasize, &mergemapsize, &mergebuf);
    if (rc < 0) return rc;

    mgbuf = (u_long *) mergebuf;
    tout = (u_long *) taintbuf;
    for (i = 0; i < taintdatasize/(sizeof(u_long)*2); i++) {
	addr = tout[2*i];
	//value = tout[2*i+1];
	epoch_cnt++;
	printf ("addr %lx %lx\n", addr, *mgbuf);
	mgbuf++;
	if (*mgbuf == 0) zeros++;
	do {
	    if (*mgbuf) {
		mgbuf++;
	    } else {
		mgbuf++;
		break;
	    }
	} while (1);
    }
    printf ("%d out of %d are zeros\n", zeros, epoch_cnt);
    return 1;
}
