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


#include "mkpartition_utils.h"
using namespace std;

struct ckpt ckpts[MAX_CKPT_CNT];
int ckpt_cnt = 0;

static int group_by = 0;
int filter_syscall = 0;
int use_ckpt = 0, do_split = 0, details = 0, do_repartition = 0;
int lowmem = 0;
double ut_arg = 0.0;
double ui_arg = 0.0;
my_map ninsts; //the number of instructions based on trace_id


void format ()
{
    fprintf (stderr, "Format: mkpartition <timing dir> <# of partitions> [-g group_by] [-f filter syscall] [-s split at user-level] [-v verbose] [--stop stop_tracking_clock] [-r pin_trace_dir pin_trace_epochs] [-fork fork_flags] <list of processes in replay>\n");
    exit (22);
}

int cmp (const void* a, const void* b)
{
    const struct ckpt* c1 = (const struct ckpt *) a;
    const struct ckpt* c2 = (const struct ckpt *) b;
    return c1->rp_clock - c2->rp_clock;
}

long read_ckpts (char* dirname)
{
    char filename[80];
    DIR* dir;
    struct dirent* de;
    int fd;
    struct ckpt_proc_data cpd;
    long rc;

    dir = opendir (dirname);
    if (dir == NULL) {
	fprintf (stderr, "Cannot open dir %s\n", dirname);
	return -1;
    }
    
    while ((de = readdir (dir)) != NULL) {
	if (!strncmp(de->d_name, "ckpt.", 5)) {
	    sprintf (filename, "%s/%s", dirname, de->d_name);
	    fd = open (filename, O_RDONLY);
	    if (fd < 0) {
		fprintf (stderr, "Cannot open %s, rc=%ld, errno=%d\n", filename, rc, errno);
		return fd;
	    }
	    rc = pread (fd, &cpd, sizeof(cpd), sizeof(struct ckpt_data));
	    if (rc != sizeof(cpd)) {
		fprintf (stderr, "Cannot read ckpt_data, rc=%ld, errno=%d\n", rc, errno);
		return rc;
	    }
	    strcpy (ckpts[ckpt_cnt].name, de->d_name+5);
	    ckpts[ckpt_cnt].index = cpd.outptr;
	    sscanf(ckpts[ckpt_cnt].name, "%lu", &(ckpts[ckpt_cnt].rp_clock));
	    ckpt_cnt++;

	    close (fd);
	}
    }
    
    qsort (ckpts, ckpt_cnt, sizeof(struct ckpt), cmp);
    closedir (dir);
    return 0;
}


static long ms_diff (struct timeval tv1, struct timeval tv2)
{
    return ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000);
}

bool mycmp(struct timing_data t, struct timing_data u) {return t.start_clock < u.start_clock;}

int main (int argc, char* argv[])
{
    char filename[256];
    struct replay_timing* timings;
    struct stat st;
    int fd, rc, num, i, parts;
    char following[256];   
    unordered_set<pid_t> procs;
    FILE *file;
    struct timeval start_tv, read_and_copy_tv, pklog_tv, pulog_tv, ptiming_tv, gen_timings_tv, pinst_tv;

    u_long stop_clock = 0;
    char *pin_dir = NULL;
    u_int  pin_epochs = -1;
    
    gettimeofday(&start_tv, NULL);

    if (argc < 3) {
	format ();
    }
    following[0] = 0; 
    sprintf (filename, "%s/timings", argv[1]);
    parts = atoi(argv[2]);
    for (i = 3; i < argc; i++) {
	if (!strcmp(argv[i], "-g")) {
	    i++;
	    if (i < argc) {
		group_by = atoi(argv[i]);
	    } else {
		format();
	    }
	}
	else if(!strcmp(argv[i], "-fork")) { 
	    i++;
	    if (i < argc) {
		strcpy(following,argv[i]);
	    } else {
		format();
	    }
	
	}
	else if (!strcmp(argv[i], "-f")) {
	    i++;
	    if (i < argc) {
		filter_syscall = atoi(argv[i]);
	    } else {
		format();
	    }
	}
	else if (!strcmp(argv[i], "-v")) {
	    details = 1;
	}
	else if (!strcmp(argv[i], "-c")) {
	    use_ckpt = 1;
	}
	else if (!strcmp(argv[i], "-s")) {
	    do_split = 1;
	}
	else if (!strcmp(argv[i], "-lowmem")) {
	    lowmem = 1;
	}
	else if (!strcmp(argv[i], "-ut_arg")) {
	    i++;
	    ut_arg = atof(argv[i]);

	}
	else if (!strcmp(argv[i], "-ui_arg")) {
	    i++;
	    ui_arg = atof(argv[i]);
	}
	else if(!strcmp(argv[i], "--stop")) { 
	    i++;
	    if (i < argc) {
		stop_clock = atoi(argv[i]);
		fprintf(stderr, "stop clock is %lu\n",stop_clock);
	    } else {
		format();
	    }	
	}
	else if (!strcmp(argv[i],"-r")){
	    i++;

	    //these are the reasonable defaults, based on our model
	    ut_arg = 211;
	    ui_arg = .08;

	    if (i < argc) {
		pin_dir = argv[i];
		i++;
		if (i < argc) {
		    pin_epochs = atoi(argv[i]);
		    do_repartition = 1;
		} else {
		    format();
		}
	    } else {
		format();
	    }
	}
	else { 
	    //the assumption is that if we get to this point that its listing of the procs now
	    procs.insert(atoi(argv[i]));
	}
    }

    if (use_ckpt) read_ckpts(argv[1]);



    fd = open (filename, O_RDONLY);
    if (fd < 0) {
	fprintf (stderr, "Cannot open timing file %s, rc=%d, errno=%d\n", filename, fd, errno);
	return -1;
    }

    rc = fstat (fd, &st);
    if (rc < 0) {
	fprintf (stderr, "Cannot stat timing file, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    timings = (struct replay_timing *) malloc (st.st_size);
    if (timings == NULL) {
	fprintf (stderr, "Unable to allocate timings buffer of size %lu\n", st.st_size);
	return -1;
    }
    
    rc = read (fd, timings, st.st_size);
    if (rc < st.st_size) {
	fprintf (stderr, "Unable to read timings, rc=%d, expected %ld\n", rc, st.st_size);
	return -1;
    }
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


    gettimeofday(&read_and_copy_tv, NULL);
   
    sprintf(filename, "%s/instructions",argv[1]);
    file = fopen (filename, "r");
    if (file == NULL) { 
	fprintf (stderr, "Cannot open instructions file %s,  errno=%d\n", filename, errno);
	return -1;
    }

    rc = parse_klogs(td, stop_clock,argv[1], following, procs);
    gettimeofday(&pklog_tv, NULL);

    fprintf(stderr, "parsing utimes\n");
    rc = parse_ulogs(td, argv[1]);     
    gettimeofday(&pulog_tv, NULL);
    fprintf(stderr, "beginning the sort\n");
    rc = parse_timing_data(td);

    sort (td.begin(), td.end(), mycmp); //do this before I assign can_attach
    fprintf(stderr, "finished sorting, parsing td\n");

    if (use_ckpt){
	fprintf(stderr, "adjusting for ckpts\n");
	adjust_for_ckpts(td, ckpts, ckpt_cnt);
    }

    gettimeofday(&ptiming_tv, NULL);
    if (!do_repartition) { 
	rc = parse_instructions(td, file); //parses the instruction logs
	gettimeofday(&pinst_tv, NULL);
    }
    else { 
	rc = parse_pin_instructions(ninsts,pin_dir, pin_epochs);
	if (!lowmem)
	    rc = parse_pin_traces(td, pin_dir, pin_epochs);
	gettimeofday(&pinst_tv, NULL);
    }
    
//    if(details) {
//	for (auto t : td) { 
//	    printf ("%d, %lu, %lf\n", t.pid, t.stop_clock, t.ftiming);
//	    if (!t.can_attach) fprintf(stderr,"\t can't attach b/c %d %d\n",t.blocking_syscall, t.blocking_pid);
//	    fflush(stdout);
//	}
//    }

//    return 0;
    fprintf(stderr, "starting gen_timings\n");
    printf ("%s\n", argv[1]);
    generate_timings(td, parts, following,pin_dir, pin_epochs);
    gettimeofday(&gen_timings_tv, NULL);

    fprintf(stderr, "read_and_copy_time %ld\n",ms_diff(read_and_copy_tv, start_tv));    
    fprintf(stderr, "pklog_time %ld\n",ms_diff(pklog_tv, read_and_copy_tv));
    fprintf(stderr, "pulog_time %ld\n",ms_diff(pulog_tv, pklog_tv));
    fprintf(stderr, "ptiming_time %ld\n",ms_diff(ptiming_tv, pulog_tv));
    fprintf(stderr, "pinst_time %ld\n",ms_diff(pinst_tv, ptiming_tv));
    fprintf(stderr, "gen_timings_time %ld\n",ms_diff(gen_timings_tv, pinst_tv));

    return 0;
}


