#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "../maputil.h"

#include <set>
#include <vector>
using namespace std;

#include "../taint_interface/taint.h"
#include "../taint_interface/taint_creation.h"
#include "../../test/streamserver.h"

//#define TARGET(x) ((x)==0x119)
//#define ITARGET(x) ((x)==0||(x)==0x7e5751)
#define ALLOW_DUPS

#define BUFSIZE 100000
//#define OUTPUT_CMP

#ifdef OUTPUT_CMP
struct output_info {
    uint32_t tokval;
    int32_t record_pid;
    uint32_t syscall;
    uint32_t buf_size;
};
vector<output_info> outputs;
#endif

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
    uint32_t output_token, input_token;
    int afd;
    uint32_t output_tokens = 0, input_tokens = 0, otoken = 0;
    int mfd, ofd, dfd;
    char* mbuf, *obuf, *dbuf, *dptr;
    uint32_t *mptr, *optr;
    uint32_t buf_cnt, buf_size;
    set<pair<uint32_t,uint32_t>> mapping, omapping;
    set<pair<uint32_t,uint32_t>>::iterator miter, oiter;
    long rc;
    int out_start;
    const char* out_dir;
    int dir_start = 3;
    int show_all = 0;
#ifdef OUTPUT_CMP
    struct output_info oi;
#endif

    if (argc < 4) {
	fprintf (stderr, "format: out2mergecmp.c [thread #] <mergeout dir> [-p pid] [-d dir] <list of output dirs>\n");
	return -1;
    }
    
    if (!strcmp(argv[3], "-p")) {
	dir_start = 5;
	sprintf (mfile, "%s/mergeout.%s", argv[2], argv[4]);
	sprintf (dfile, "%s/dataflow.result.%s", argv[2], argv[4]);
    } 
    else { 
	sprintf (mfile, "%s/mergeout", argv[2]);
	sprintf (dfile, "%s/dataflow.result", argv[2]);
    }
    int parallelize = atoi(argv[1]);


    rc = map_file (mfile, &mfd, &mdatasize, &mmapsize, &mbuf);
    if (rc < 0) return rc;
    rc = map_file (dfile, &dfd, &ddatasize, &dmapsize, &dbuf);
    if (rc < 0) return rc;


    if (!strcmp(argv[dir_start], "-d")) {
        out_dir = argv[dir_start+1];
	out_start = dir_start+2;
    } else {
	out_dir = "/tmp";
	out_start = dir_start;
    }

#ifdef OUTPUT_CMP      
    uint32_t tokval = 0;
#endif
    mptr = (uint32_t *) mbuf;
    dptr = dbuf;
#if defined(TARGET) || defined(OUTPUT_CMP)
    struct taint_creation_info* tci = (struct taint_creation_info *) dbuf;
#endif
    dptr += sizeof(struct taint_creation_info) + sizeof(uint32_t);
    buf_size = *((uint32_t *) dptr);

#ifdef OUTPUT_CMP
    printf ("outputs %x-%x: record pid %d syscall %d size %d\n", tokval, tokval+buf_size, tci->record_pid, tci->syscall_cnt, buf_size);
    oi.tokval = tokval;
    oi.record_pid = tci->record_pid;
    oi.syscall = tci->syscall_cnt;
    oi.buf_size = buf_size;
    outputs.push_back(oi);
    tokval += buf_size;
#endif

    dptr += sizeof(uint32_t) + buf_size*(sizeof(taint_t) + sizeof(uint32_t));

    buf_cnt = 0;
    while ((u_long) mptr < (u_long) mbuf + mdatasize) {
	while (*mptr) {
#ifdef TARGET
	    if (TARGET(otoken)) {
		printf ("Output %x -> input %x pid %d syscall %u offset %u out of %u\n", otoken, *mptr, tci->record_pid, tci->syscall_cnt, buf_cnt, buf_size);
	    }
#endif
#ifdef ITARGET
	    if (ITARGET(*mptr)) {
		printf ("Output %x -> input %x syscall %u offset %u out of %u\n", otoken, *mptr, tci->syscall_cnt, buf_cnt, buf_size);
	    }
#endif
	    mapping.insert(make_pair(otoken,*mptr));
	    mptr++;
	}
	otoken++;
	mptr++;
	buf_cnt++;

#if defined(TARGET) || defined(OUTPUT_CMP)
	while (buf_cnt == buf_size && (u_long) mptr < (u_long) mbuf + mdatasize) {
	    tci = (struct taint_creation_info *) dptr;
	    dptr += sizeof(struct taint_creation_info) + sizeof(uint32_t);
	    buf_size = *((uint32_t *) dptr);
#ifdef OUTPUT_CMP
	    if (buf_size > 0) {
		printf ("outputs %x-%x: record pid %d syscall %d size %d\n", tokval, tokval+buf_size, tci->record_pid, tci->syscall_cnt, buf_size);
	    }
	    oi.tokval = tokval;
	    oi.record_pid = tci->record_pid;
	    oi.syscall = tci->syscall_cnt;
	    oi.buf_size = buf_size;
	    outputs.push_back(oi);
	    tokval += buf_size;
#endif
	    buf_cnt = 0;
	    dptr += sizeof(uint32_t) + buf_size*(sizeof(taint_t) + sizeof(uint32_t));
	}
#endif

    }

    unmap_file (mbuf, mfd, mmapsize);
    unmap_file (dbuf, dfd, dmapsize);

    // Now handle the output files 
#ifdef OUTPUT_CMP
    tokval = 0;
    int ocnt = 0;
#endif
    for (int i = out_start; i < argc; i++) {
#ifdef OUTPUT_CMP
	char dffile[256];
	int dffd;
	u_long dfdatasize, dfmapsize;
	char* dfbuf;

	sprintf (dffile, "%s/%s/dataflow.results", out_dir, argv[i]);
	rc = map_file (dffile, &dffd, &dfdatasize, &dfmapsize, &dfbuf);
	if (rc < 0) return rc;	

	char* dfptr = dfbuf;
	while ((u_long) dfptr < (u_long) dfbuf + dfdatasize) {
	    struct taint_creation_info* tci = (taint_creation_info *) dfptr;
	    dfptr += sizeof(taint_creation_info);
	    uint32_t* psize = (uint32_t *) dfptr;
	    dfptr += sizeof(uint32_t);
	    printf ("outputs %x-%x: record pid %d syscall %d size %d\n", tokval, tokval+*psize, tci->record_pid, tci->syscall_cnt, *psize);
	    oi = outputs[ocnt];
	    if (tokval != oi.tokval || tci->record_pid != oi.record_pid || *psize != oi.buf_size) {
		printf ("!!! was %x-%x: record pid %d syscall %d size %d\n", oi.tokval, oi.tokval+oi.buf_size, oi.record_pid, oi.syscall, oi.buf_size);
		//exit (0);
	    } 
	    ocnt++;
	    tokval += *psize;
	}
#endif
	for (int j = 0; j < parallelize; j++) {
	    sprintf (ofile, "%s/%s/merge-outputs-resolved-%d", out_dir, argv[i], j);
	    rc = map_file (ofile, &ofd, &odatasize, &omapsize, &obuf);
	    if (rc < 0) return rc;	

	    optr = (uint32_t *) obuf;
	    while ((u_long) optr < (u_long) obuf + odatasize) {
		uint32_t otoken = *optr++;
#ifdef TARGET
		if (TARGET(otoken+output_tokens)) {
		    printf ("Output %x this epoch %x past %x -> input %x this epoch %x past %x, epoch %s,thread %d offset %lx\n",
			    otoken+output_tokens, otoken, output_tokens, *optr+input_tokens, *optr, input_tokens, argv[i], j,
			    (u_long) optr - (u_long) obuf);
		}
#endif
#ifdef ITARGET
		if (ITARGET(*optr+input_tokens)) {
		    printf ("Output %x this epoch %x past %x -> input %x this epoch %x past %x, epoch %s\n",
			    otoken+output_tokens, otoken, output_tokens, *optr+input_tokens, *optr, input_tokens, argv[i]);
		}
#endif
		omapping.insert(make_pair(otoken+output_tokens,*optr+input_tokens));
		optr++;
	    }
	    unmap_file (obuf, ofd, omapsize);
	}

	sprintf (afile, "%s/%s/merge-addrs", out_dir, argv[i]);
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
	if (i > out_start) input_tokens -= 0xc0000000;
	output_tokens += output_token;
	input_tokens += input_token;
#ifdef TARGET
	printf ("epoch %d, output tokens %x input tokens %x\n", i-out_start, output_tokens, input_tokens);
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
	    printf ("mergeout <%x,%x>, outputs <%x,%x>\n", 
		    miter->first, miter->second, oiter->first, oiter->second);
	    if (!show_all) exit (0);
	    if (*miter < *oiter) {
		miter++;
	    } else {
		oiter++;
	    }
	} else {
	    miter++;
	    oiter++;
	}
    }
    if (miter != mapping.end()) {
	printf ("mergeout has entries remaining but output files do not\n");
	printf ("At mapping %d\n", cnt);
	printf ("extra outputs <%x,%x>\n", miter->first, miter->second);
	return 1;
    }
    if (oiter != omapping.end()) {
	printf ("output files have entries remaining but mergeout does not\n");
	printf ("At mapping %d\n", cnt);
	printf ("extra outputs <%x,%x>\n", oiter->first, oiter->second);
	return 1;
    }
    printf ("compared OK\n");
    return 0;
}
