#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "maputil.h"

#include <set>
using namespace std;

#include "taint_interface/taint_creation.h"

//#define TARGET 0x1cfef
//#define ITARGET 0x201e42

#define ALLOW_DUPS

#define BUFSIZE 100000

int cmp (const void* p1, const void* p2)
{
    u_long* pl1 = (u_long *) p1;
    u_long* pl2 = (u_long *) p2;
    return *pl1 - *pl2;
}

int main (int argc, char* argv[])
{
    char mfile[256], ofile[256], dfile[256];
    u_long mdatasize, mmapsize, odatasize, omapsize, ddatasize, dmapsize;
    char afile[256];
    u_long output_token, input_token;
    int afd;
    u_long output_tokens = 0, input_tokens = 0, otoken = 0;
    int mfd, ofd, dfd;
    char* mbuf, *obuf, *dbuf, *dptr;
    u_long* mptr, *optr;
    u_long buf_cnt, buf_size;
    set<pair<u_long,u_long>> mapping, omapping;
    set<pair<u_long,u_long>>::iterator miter, oiter;
    long rc;

    if (argc < 3) {
	fprintf (stderr, "format: out2mergecmp.c <mergeout dir> <list of output dirs>\n");
	return -1;
    }

    sprintf (mfile, "/tmp/%s/mergeout", argv[1]);
    rc = map_file (mfile, &mfd, &mdatasize, &mmapsize, &mbuf);
    if (rc < 0) return rc;

    sprintf (dfile, "/tmp/%s/dataflow.result", argv[1]);
    rc = map_file (dfile, &dfd, &ddatasize, &dmapsize, &dbuf);
    if (rc < 0) return rc;

    mptr = (u_long *) mbuf;
    dptr = dbuf;
#ifdef TARGET
    struct taint_creation_info* tci = (struct taint_creation_info *) dbuf;
#endif
    dptr += sizeof(struct taint_creation_info) + sizeof(u_long);
    buf_size = *((u_long *) dptr);
    dptr += sizeof(u_long);
    buf_cnt = 0;
    while ((u_long) mptr < (u_long) mbuf + mdatasize) {
	while (*mptr) {
#ifdef TARGET
	    if (otoken == TARGET) {
		printf ("Output %lx -> input %lx syscall %lu offset %lu out of %lu\n", otoken, *mptr, tci->syscall_cnt, buf_cnt, buf_size);
	    }
#endif
#ifdef ITARGET
	    if (*mptr == ITARGET) {
		printf ("Output %lx -> input %lx syscall %lu offset %lu out of %lu\n", otoken, *mptr, tci->syscall_cnt, buf_cnt, buf_size);
	    }
#endif
	    mapping.insert(make_pair(otoken,*mptr));
	    mptr++;
	}
	otoken++;
	mptr++;
	buf_cnt++;
	dptr += sizeof(u_long) * 2;
	while (buf_cnt == buf_size) {
	    dptr += sizeof(struct taint_creation_info) + sizeof(u_long);
	    buf_size = *((u_long *) dptr);
	    dptr += sizeof(u_long);
	    buf_cnt = 0;
	}
    }

    unmap_file (mbuf, mfd, mmapsize);
    unmap_file (dbuf, dfd, dmapsize);

    // Now handle the output files 
    for (int i = 2; i < argc; i++) {
	sprintf (ofile, "/tmp/%s/merge-outputs-resolved", argv[i]);
	rc = map_file (ofile, &ofd, &odatasize, &omapsize, &obuf);
	if (rc < 0) return rc;	

	optr = (u_long *) obuf;
	while ((u_long) optr < (u_long) obuf + odatasize) {
	    u_long otoken = *optr;
	    optr++;
	    while (*optr) {
#ifdef TARGET
		if (otoken+output_tokens == TARGET) {
		    printf ("Output %lx this epoch %lx past %lx -> input %lx this epoch %lx past %lx, epoch %s offset %lx\n",
			    otoken+output_tokens, otoken, output_tokens, *optr+input_tokens, *optr, input_tokens, argv[i], (u_long) optr - (u_long) obuf);
		}
#endif
#ifdef ITARGET
		if (*optr+input_tokens == ITARGET) {
		    printf ("Output %lx this epoch %lx past %lx -> input %lx this epoch %lx past %lx, epoch %s\n",
			    otoken+output_tokens, otoken, output_tokens, *optr+input_tokens, *optr, input_tokens, argv[i]);
		}
#endif
		omapping.insert(make_pair(otoken+output_tokens,*optr+input_tokens));
		optr++;
	    }
	    optr++;
	}
	
	unmap_file (obuf, ofd, omapsize);

	sprintf (afile, "/tmp/%s/merge-addrs", argv[i]);
	afd = open(afile, O_RDONLY);
	if (afd < 0) {
	    fprintf (stderr, "Cannot open %s\n", afile);
	    return afd;
	}

	rc = read (afd, &output_token, sizeof(output_token));
	if (rc != sizeof(output_token)) {
	    fprintf (stderr, "Unable to read output token from %s, rc=%ld, errno=%d\n", afile, rc, errno);
	    return rc;
	}
	rc = read (afd, &input_token, sizeof(input_token));
	if (rc != sizeof(input_token)) {
	    fprintf (stderr, "Unable to read input token from %s, rc=%ld, errno=%d\n", afile, rc, errno);
	    return rc;
	}
	if (i > 2) input_tokens -= 0xc0000000;
	output_tokens += output_token;
	input_tokens += input_token;
#ifdef TARGET
	printf ("epoch %d, output tokens %lx input tokens %lx\n", i-1, output_tokens, input_tokens);
#endif
	close (afd);
    }

    miter = mapping.begin();
    oiter = omapping.begin();
    int cnt = 0;
    while (miter != mapping.end() && oiter != omapping.end()) {
	cnt++;
	if (miter->first != oiter->first || miter->second != oiter->second) {
	    printf ("Entry in mapping %d differs\n", cnt);
	    printf ("mergeout <%lx,%lx>, outputs <%lx,%lx>\n", 
		    miter->first, miter->second, oiter->first, oiter->second);
	    return 1;
	}
	miter++;
	oiter++;
    }
    if (miter != mapping.end()) {
	printf ("mergeout has entries remaining but output files do not\n");
	return 1;
    }
    if (oiter != omapping.end()) {
	printf ("output files have entries remaining but mergeout does not\n");
	return 1;
    }
    printf ("compared OK\n");
    return 0;
}
