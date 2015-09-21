#include <stdio.h>
#include <stdlib.h>

#include "taint_interface/taint_creation.h"
#include "xray_token.h"
#include "maputil.h"


#define MAX_INPUT_SYSCALLS 128

int main (int argc, char* argv[])
{
    char tokfile[80], outfile[80], mergefile[80];
    int tfd, ofd, mfd;
    u_long tdatasize, odatasize, mdatasize, tmapsize, omapsize, mmapsize;
    char* tbuf, *obuf, *mbuf, *dir, *pid, opt;
    u_long* mptr;
    u_long buf_size, i;
    long rc;

    while (1) 
    {
	opt = getopt(argc, argv, "p:");
	if (opt == -1) 
	{
	    //we can parse for dir here! 
	    if(optind < argc) 
	    {
		dir = argv[optind];
		break;
	    }
	    else 
	    { 
		fprintf (stderr, "format: showall <dirno> [-p pid]\n");
		return -1;
	    }
	}
	switch(opt) 
	{
	case 'p': 
	    pid = optarg;
	    break;
	default:
	    fprintf(stderr, "Unrecognized option\n");
	    break;
	}
    }
    if(pid == NULL)
    { 
	sprintf (tokfile, "%s/tokens", dir);
	sprintf (outfile, "%s/dataflow.result", dir);
	sprintf (mergefile, "%s/mergeout", dir);
    }
    else 
    {
	sprintf (tokfile, "%s/tokens.%s", dir, pid);
	sprintf (outfile, "%s/dataflow.result.%s", dir, pid);
	sprintf (mergefile, "%s/mergeout.%s", dir, pid);

    }

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
	int input_syscalls[MAX_INPUT_SYSCALLS];
	int input_syscalls_index = 0;

	obuf += sizeof(struct taint_creation_info);
	obuf += sizeof(u_long); 
	buf_size = *((u_long *) obuf);
	obuf += sizeof(u_long);
	for (i = 0; i < buf_size; i++) {
	    do {
		if (*mptr) {
		    int found = 0, j;
		    u_long tokval = *mptr;
		    
                    //printf ("output syscall %lu offset %lu <- ", syscall, i);
		    struct token* ptok = (struct token *) tbuf;
		    while (tokval > ptok->size) {
			tokval -= ptok->size;
			ptok++;
		    } 
//		    printf ("input syscall %d offset %lu\n", ptok->syscall_cnt, tokval);
		    
		    //search through the input_syscalls to see if this is a new syscall mapping:
		    for(j = 0; j < input_syscalls_index; j++) {
			if(input_syscalls[j] == ptok->syscall_cnt) 
			{
				found = 1;
			}
		    }
		    if (!found) {
			input_syscalls[input_syscalls_index] = ptok->syscall_cnt;
			input_syscalls_index += 1;

			printf ("output syscall %d,%lu offset %lu <- ", record_pid, syscall, i);
			printf ("input syscall %d,%d offset %lu\n", ptok->record_pid, ptok->syscall_cnt, tokval);
		    }
		    mptr++;
		} else {
		    mptr++;
		    break;
		}
	    } while (1);
	    obuf += sizeof(u_long) * 2;
	}
    }

    return 0;
    
}

