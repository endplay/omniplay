#include <stdio.h>
#include <stdlib.h>

#include "taint_interface/taint.h"
#include "taint_interface/taint_creation.h"
#include "xray_token.h"
#include "maputil.h"

int main (int argc, char* argv[])
{
    char tokfile[80], outfile[80], mergefile[80];
    int tfd, ofd, mfd;
    u_long tdatasize, odatasize, mdatasize, tmapsize, omapsize, mmapsize;
    char* tbuf, *obuf, *mbuf, *dir;
    u_long* mptr;
    u_long buf_size, i;
    long rc;
    u_long ocnt = 0;

    if (argc != 2) {
	fprintf (stderr, "format: showall <dirno>\n");
	return -1;
    }

    dir = argv[1];
    sprintf (tokfile, "/tmp/%s/tokens", dir);
    sprintf (outfile, "/tmp/%s/dataflow.result", dir);
    sprintf (mergefile, "/tmp/%s/mergeout", dir);

    rc = map_file (tokfile, &tfd, &tdatasize, &tmapsize, &tbuf);
    if (rc < 0) return rc;
    rc = map_file (outfile, &ofd, &odatasize, &omapsize, &obuf);
    if (rc < 0) return rc;
    rc = map_file (mergefile, &mfd, &mdatasize, &mmapsize, &mbuf);
    if (rc < 0) return rc;

    mptr = (u_long *) mbuf;
    while ((u_long) mptr < (u_long) mbuf + mdatasize) {
	struct taint_creation_info* tci = (struct taint_creation_info *) obuf;
	u_long syscall = tci->syscall_cnt;
	int record_pid = tci->record_pid;
	obuf += sizeof(struct taint_creation_info);
	obuf += sizeof(u_long); 
	buf_size = *((u_long *) obuf);
	obuf += sizeof(u_long);
	for (i = 0; i < buf_size; i++) {
	    do {
		if (*mptr) {
		    u_long tokval = *mptr;
		    printf ("output pid/syscall %u/%lu offset %lu (%lx) <- (%lx)", record_pid, syscall, i, ocnt, *mptr);
		    struct token* ptok = (struct token *) tbuf;
		    while (tokval > ptok->size) {
			tokval -= ptok->size;
			ptok++;
		    } 
		    printf ("input pid/syscall %d/%d offset %lu\n", ptok->record_pid, ptok->syscall_cnt, tokval);
		    mptr++;
		} else {
		    mptr++;
		    break;
		}
	    } while (1);
	    obuf += sizeof(u_long) + sizeof(taint_t);
	    ocnt++;
	}
    }

    return 0;
    
}
