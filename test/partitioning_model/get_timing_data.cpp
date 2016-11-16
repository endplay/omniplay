#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <dirent.h>
#include <cstdint>
#include <math.h>
#include <map>
#include <queue>
#include <set>
#include <algorithm>
#include <limits>


#include "../mkpartition_utils.h"
using namespace std;

struct ckpt ckpts[MAX_CKPT_CNT];
int ckpt_cnt = 0;

int filter_syscall = 0;
int use_ckpt = 0, do_split = 0, details = 0, do_repartition = 0;
int lowmem = 0;
double ut_arg = 0.0;
double ui_arg = 0.0;
my_map ninsts; //the number of instructions based on trace_id


void format ()
{
    fprintf (stderr, "Format: mkpartition <timing dir> [-v verbose] [--stop stop_tracking_clock] [-fork fork_flags] <list of processes in replay>\n");
    exit (22);
}

bool mycmp(struct timing_data t, struct timing_data u) {return t.start_clock < u.start_clock;}

int main (int argc, char* argv[])
{
    char filename[256];
    struct replay_timing* timings;
    struct stat st;
    int fd, rc, num, i;
    char following[256];   
    unordered_set<pid_t> procs;
    FILE *file;

    u_long stop_clock = 0;
    
    if (argc < 2) {
	format ();
    }
    following[0] = 0; 
    sprintf (filename, "%s/timings", argv[1]);
    for (i = 2; i < argc; i++) {
	if(!strcmp(argv[i], "--fork")) { 
	    i++;
	    if (i < argc) {
		strcpy(following,argv[i]);
	    } else {
		format();
	    }	
	}
	else if (!strcmp(argv[i], "-v")) {
	    details = 1;
	}
	else if(!strcmp(argv[i], "--stop")) { 
	    i++;
	    if (i < argc) {
		stop_clock = atoi(argv[i]);
	    } else {
		format();
	    }	
	}
	else { 
	    //the assumption is that if we get to this point that its listing of the procs now
	    procs.insert(atoi(argv[i]));
	}
    }

    fd = open (filename, O_RDONLY);
    assert(fd >= 0);
    rc = fstat (fd, &st);
    assert(rc >= 0);
    timings = (struct replay_timing *) malloc (st.st_size);
    assert(timings != NULL);
    rc = read (fd, timings, st.st_size);
    assert(rc >= st.st_size);
    num = st.st_size / sizeof(struct replay_timing);
    vector<struct timing_data> td(num); 

    /*
     * start by populating the td vector with all of the exiting
     * timings_info. 
     */

    for ( i = 0; i < num; i++) { 
	
	struct timing_data next_td;
	next_td.pid = timings[i].pid;
	next_td.index = timings[i].index;
	next_td.syscall = timings[i].syscall;
	next_td.start_clock = numeric_limits<u_long>::max();
	next_td.ut = timings[i].ut;
	next_td.taint_in = 0;
	next_td.taint_out = 0;	
	next_td.imisses = 0;
	next_td.num_merges = 0;
	next_td.cache_misses = timings[i].cache_misses;
	next_td.forked_pid = -1; //just assume that syscalls don't have forked_pids. this will get fixed later if we're wrong
	next_td.should_track = false; //assume that we don't track it, it will be fixed if we should
	next_td.can_attach = true; //set it to be true first
	td[i] = next_td; 
   
    }
    free(timings); //free all dem memories

    sprintf (filename, "%s/timings.cloudlab", argv[1]);
    fd = open (filename, O_RDONLY);
    assert(fd >=0);
    rc = fstat (fd, &st);
    assert(rc >=0);
    timings = (struct replay_timing *) malloc (st.st_size);
    assert(timings);
    rc = read (fd, timings, st.st_size);
    assert(rc >= st.st_size);
    num = st.st_size / sizeof(struct replay_timing);
    for ( i = 0; i < num; i++) { 	
	td[i].fft  = timings[i].ut;
    }
    free(timings); //free all dem memories

   
    sprintf(filename, "%s/instructions",argv[1]);
    file = fopen (filename, "r");
    if (file == NULL) { 
	fprintf (stderr, "Cannot open instructions file %s,  errno=%d\n", filename, errno);
	return -1;
    }

    rc = parse_klogs(td, stop_clock,argv[1], following, procs);
    rc = parse_ulogs(td, argv[1]);     
    rc = parse_timing_data(td);

    sort (td.begin(), td.end(), mycmp); //do this before I assign can_attach
   
    for (auto t : td) { 
	printf ("%d %lu %hd %hhd %hd %hhd %lu %lu %lu %lf %lf\n", 
		t.pid, t.index, t.syscall, t.can_attach,
		t.blocking_syscall, t.should_track, t.start_clock,
		t.stop_clock, t.aindex, t.dtiming, t.ftiming);
    }
    return 0;
}
