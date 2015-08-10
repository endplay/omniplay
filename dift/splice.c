#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <glib-2.0/glib.h>

#include "linkage_common.h"
#include "maputil.h"
#include "taint_interface/taint_creation.h"
#include "taint_interface/taint_interface.h"

extern u_long* pregs;
extern u_long merge_total_count;

#define OUTBUFSIZE 1000000
u_long outbuf[OUTBUFSIZE];
u_long outindex = 0;

static void flush_outbuf(int outfd)
{
    long rc = write (outfd, outbuf, outindex*sizeof(u_long));
    if (rc != (long) (outindex*sizeof(u_long))) {
	fprintf (stderr, "write of segment failed, rc=%ld, errno=%d\n", rc, errno);
	exit (rc);
    }
    outindex = 0;
}

static inline void write_value (u_long value, int outfd) 
{
    if (outindex == OUTBUFSIZE) flush_outbuf(outfd);
    outbuf[outindex++] = value;
}

long splice_after_segment (const char* splice_input_filename, const char* semname, int outfd)
{
    struct taint_creation_info tci;
    long rc;
    u_long bufsize, i, addr, value, idatasize, imapsize;
    u_long* ibuf;
    int ifd, val = 0;
    sem_t* sem;
    struct timeval tv;

    if (semname) {
	// Wait on this semaphore before accessing splice file
	sem = sem_open (semname, 0);
	if (sem == NULL) {
	    printf ("splice_after_segment: cannot open semaphore %s, errno=%d\n", semname, errno);
	    return -1;
	}
	// This is hideous - but Pin deadlocks if we make a blocking sem_wait here (sigh)
	gettimeofday(&tv, NULL);
	printf ("Waiting on semaphore %s time %ld.%ld\n", semname, tv.tv_sec, tv.tv_usec);
	do {
	    rc = sem_getvalue (sem, &val);
	    if (rc < 0) {
		fprintf (stderr, "splice_after_segment: waiting on semaphore %s, errno=%d\n", semname, errno);
		return -1;
	    }
	    if (val < 1) usleep (100);
	} while (val < 1);
	gettimeofday(&tv, NULL);
	printf ("Done waiting on semaphore %s time %ld.%ld\n", semname, tv.tv_sec, tv.tv_usec);
	sem_close (sem);
    }

    //printf ("Merge entries: %lu\n", merge_total_count - 0xe0000000);

    rc = map_file (splice_input_filename, &ifd, &idatasize, &imapsize, (char **) &ibuf);
    printf ("Open of input file %s returns %ld\n", splice_input_filename, rc);
    if (rc < 0) return rc;

    tci.type = 0;
    tci.rg_id = 0;
    tci.record_pid = 0; 
    tci.syscall_cnt = 0; // We'll use this to indicate address space taints for now - structure is somewhat broken
    tci.offset = 0;
    tci.fileno = 0;
    tci.data = NULL;

    rc = write(outfd, &tci, sizeof(tci));
    if (rc != sizeof(tci)) {
        fprintf(stderr, "splice_after_segment: header write returned %ld, errno=%d\n", rc, errno);
        return rc;
    }

    write_value (0, outfd);
    bufsize = idatasize / sizeof(u_long);
    write_value (bufsize, outfd);
    
    for (i = 0; i < bufsize; i++) {
	addr = ibuf[i];
	if (addr < NUM_REGS * REG_SIZE) {
	    value = pregs[addr];
	} else {
	    taint_t* mem_taint = get_mem_taints(addr, 1);
	    if (mem_taint) {
		value = *mem_taint;
	    } else {
		value = 0;
	    }
	}
	if (value > 0 && value <= NUM_REGS*REG_SIZE) value--;  // Reg taint offset by 1 to allow zero taint
	write_value(addr, outfd);
	write_value(value, outfd);
    }
    flush_outbuf (outfd);

    return 0;
}
