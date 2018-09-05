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
    char resmapfile[80], mapfile[80];
    int resmergefd, mergefd;
    u_long resmergedatasize, resmergemapsize, mergedatasize, mergemapsize;
    char* resmergebuf, *mergebuf;
    char* pout;
    struct taint_creation_info* tci;
    u_long buf_size;
    int i, rc;
    int epoch_cnt = 0;
    u_long TARGET, addr, value;
    u_long* mgbuf;

    if (argc != 3) {
	printf ("format: mapdump <dir #> <target output token>\n");
	exit (0);
    }
    TARGET = strtoul(argv[2], NULL, 0);
    
    sprintf (mapfile, "/tmp/%s/map", argv[1]);
    sprintf (resmapfile, "/tmp/%s/dataflow.result", argv[1]);

    rc = map_file (resmapfile, &resmergefd, &resmergedatasize, &resmergemapsize, &resmergebuf);
    if (rc < 0) return rc;

    rc = map_file (mapfile, &mergefd, &mergedatasize, &mergemapsize, &mergebuf);
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
		    printf ("syscall %lu byte %d addr %lx value %lx\n", (u_long) tci->syscall_cnt, i, addr, value);
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
	} else {
	    for (i = 0; i < buf_size; i++) {
		addr = *((u_long *) pout);
		value = *((u_long *) (pout+sizeof(u_long)));
		if (addr == TARGET) {
		    printf ("Entry %d addr %lx value %lx\n", i, addr, value);
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

    return 1;
}
