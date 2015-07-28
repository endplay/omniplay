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
    char* pout;
    struct taint_creation_info* tci;
    u_long buf_size;
    int i, rc;
    int epoch_cnt = 0;
    u_long TARGET, addr, value;
    u_long* mgbuf, *tout;

    if (argc != 3) {
	printf ("format: mergedump <dir #> <target output token>\n");
	exit (0);
    }
    TARGET = strtoul(argv[2], NULL, 0);
    
    sprintf (mergefile, "/tmp/%s/merge", argv[1]);
    sprintf (resmergefile, "/tmp/%s/dataflow.result", argv[1]);
    sprintf (taintfile, "/tmp/%s/taint_structures", argv[1]);

    rc = map_file (resmergefile, &resmergefd, &resmergedatasize, &resmergemapsize, &resmergebuf);
    if (rc < 0) return rc;

    rc = map_file (mergefile, &mergefd, &mergedatasize, &mergemapsize, &mergebuf);
    if (rc < 0) return rc;

    rc = map_file (taintfile, &taintfd, &taintdatasize, &taintmapsize, &taintbuf);
    if (rc < 0) return rc;

    pout = resmergebuf;
    mgbuf = (u_long *) mergebuf;
    while ((char *) pout < resmergebuf + resmergedatasize) {
	tci = (struct taint_creation_info*) pout;
	pout += sizeof(struct taint_creation_info);
	pout += sizeof(u_long); // skip bufaddr
	buf_size = *((u_long *) pout);
	pout += sizeof(u_long);
	if (tci->syscall_cnt) {
	    for (i = 0; i < buf_size; i++) {
		epoch_cnt++;
		if (epoch_cnt == TARGET) {
		    addr = *((u_long *) pout);
		    value = *((u_long *) (pout+sizeof(u_long)));
		    printf ("syscall %lu byte %d addr %lx value %lx mgbuf %p\n", tci->syscall_cnt, i, addr, value, mgbuf);
		}
		do {
		    if (*mgbuf) {
			if (epoch_cnt == TARGET) {
			    printf ("merge value %lx\n", *mgbuf);
			}
			mgbuf++;
		    } else {
			mgbuf++;
			break;
		    }
		} while (1);
    		pout += sizeof(u_long);
		pout += sizeof(u_long);
	    }
	}
    }

    tout = (u_long *) taintbuf;
    for (i = 0; i < taintdatasize/(sizeof(u_long)*2); i++) {
	addr = tout[2*i];
	value = tout[2*i+1];
	//if (addr == TARGET) {
	    printf ("entry %d: addr %lx, target %lx mgbuf %p offset %lx\n", i, addr, value, mgbuf, (u_long) mgbuf - (u_long) mergebuf);
	    //}
	do {
	    if (*mgbuf) {
	      //if (addr == TARGET) {
		    printf ("\tmerge value %lx\n", *mgbuf);
		    //}
		mgbuf++;
	    } else {
		mgbuf++;
		break;
	    }
	} while (1);
    }
    return 1;
}
