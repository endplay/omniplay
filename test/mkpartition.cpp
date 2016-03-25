#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <dirent.h>
#include <cstdint>
#include <math.h>
#include <map>
#include <vector>
#include <queue>
#include <set>
#include <limits>
#include <unordered_set>

#include "parseklib.h"
#include "../linux-lts-quantal-3.5.0/include/linux/pthread_log.h"
using namespace std;

unordered_set<short> bad_syscalls({192, 91, 120, 174, 125});


//used simply for the read from the file system
struct replay_timing {
    pid_t     pid;
    u_long    index;
    short     syscall;
    u_int     ut;
    uint64_t  cache_misses;
};

//used everywhere else
struct timing_data {
    pid_t     pid;
    u_long    index;
    short     syscall;
    u_int     ut;      //should I not include this as it is only used to calculate dtiming? 

    bool      can_attach; 
    pid_t     forked_pid; //the pid of the forked process (if applicable).
    bool      should_track; //should I track this rp_timing? 
    u_long    call_clock;   //the clock value of the most recent sync operation before this syscall is called. 
    u_long    start_clock;  //when the syscall starts
    u_long    stop_clock;   //when the syscall is done running
    u_long    aindex;

    //used to estimate dift time
    double    dtiming;
    uint64_t  cache_misses;
    u_long    taint_in; //the amount of taint that we've gotten in at this point
    u_long    taint_out; //the amount of taint that we've output at this point
};

struct ckpt_data {
    u_long proc_count;
    unsigned long long  rg_id;
    int    clock;
};

struct ckpt_proc_data {
	pid_t  record_pid;
	long   retval;
	loff_t logpos;
	u_long outptr;
	u_long consumed;
	u_long expclock;
};

#define MAX_CKPT_CNT 1024
struct ckpt {
    char   name[20];
    u_long clock;
};
struct ckpt ckpts[MAX_CKPT_CNT];
int ckpt_cnt = 0;

static int group_by = 0, filter_syscall = 0, details = 0, use_ckpt = 0, do_split = 0;


void format ()
{
    fprintf (stderr, "Format: mkpartition <timing dir> <# of partitions> [-g group_by] [-f filter syscall] [-s split at user-level] [-v verbose] <list of pids to track >\n");
    exit (22);
}

static long ms_diff (struct timeval tv1, struct timeval tv2)
{
    return ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000);
}


static int cnt_interval (vector<struct timing_data> &td, int start, int end)
{
    int last_aindex = 0;
    for (int i = end; i > start; --i) { 
	if (td[i].aindex > 0) {
	    last_aindex = td[i].aindex;
	    break;
	}
    }
    return last_aindex - td[start].aindex;
}


static inline void print_utimings (vector<struct timing_data> &td, int start, int end, u_int split, int intvl, char* fork_flags)
{ 
    u_long ndx = td[start].start_clock;
    u_long next_ndx = ndx + intvl;
    printf ("%5d k %6lu u %6lu       0       0 ", td[start].pid, ndx, next_ndx);
    if (strnlen(fork_flags, 128) > 0)
	printf (" %s\n", fork_flags);
    else {
	printf (" 0\n");
    }
    for (u_int i = 0; i < split-2; i++) {
	ndx = next_ndx;
	next_ndx = ndx+intvl;
	printf ("%5d u %6lu u %6lu       0       0 ", td[start].pid, ndx, next_ndx);
	if (strnlen(fork_flags, 128) > 0)
	    printf (" %s\n", fork_flags);
	else {
	    printf (" 0\n");
	}
    }
    printf ("%5d u %6lu k %6lu       0       0 ", td[start].pid, next_ndx, td[end].start_clock);
    if (strnlen(fork_flags, 128) > 0)
	printf (" %s\n", fork_flags);
    else {
	printf (" 0\n");
    }

}


//model created by correlation analysis
static double estimate_dift(vector<struct timing_data> &td, int i, int j)
{ 
    double utime = td[j].dtiming - td[i].dtiming;
    u_long taint_out = td[j].taint_out - td[i].taint_out; 
    u_long cache_misses = td[j].cache_misses - td[i].cache_misses; 

    double rtn_val = (220 * utime) + ( 0.000241 * taint_out) + (.594 * cache_misses) ;

    return rtn_val;
}

inline static void print_timing (vector<struct timing_data> &td, int start, int end, char* fork_flags)
{ 
    printf ("%5d k %6lu k %6lu ", td[start].pid, td[start].start_clock, td[end].start_clock);

    //what does this do? 
    if (filter_syscall > 0) {
	if ((u_long) filter_syscall > td[start].index && (u_long) filter_syscall <= td[end].index) {
	    printf (" %6lu", filter_syscall-td[start].index+1);
	} else {
	    printf (" 999999");
	}
    } else {
	printf ("      0");
    }
    if (use_ckpt > 0) {
	int i;
	for (i = 0; i < ckpt_cnt; i++) {
	    if (td[start].index <= ckpts[i].clock) {
		if (i > 0) {
		    printf (" %6s", ckpts[i-1].name);
		} else {
		    printf ("      0");
		}
		break;
	    }
	}
	printf (" %6s", ckpts[i-1].name);
    } else {
	printf ("       0");
    }
    if (strnlen(fork_flags, 128) > 0)
	printf (" %s\n", fork_flags);
    else {
	printf (" 0\n");
    }
}

int gen_timings (vector<timing_data> &td,
		 int start, 
		 int end, 
		 int partitions, 
		 char* fork_flags){

    double biggest_gap = 0.0, goal;
    int gap_start, gap_end, last, i, new_part;

    assert (start < end); 
    assert (partitions <= cnt_interval(td,start, end));

    if (partitions == 1) {
	print_timing (td, start, end, fork_flags);
	return 0;
    }

    double total_time = estimate_dift(td, start, end);
    // find the largest gap
    if (details) {
	printf ("Consider [%d,%d]: %d partitions %.3f time\n", start, end, partitions, total_time);
    }

    last = start;
    gap_start = start;
    gap_end = start + 1;
	
    for (i = start+1; i < end; i++) {
	if (td[i].can_attach){
	    double gap = estimate_dift(td, last, i);
	    if (gap > biggest_gap) {
		gap_start = last;
		gap_end = i;
		biggest_gap = gap;
	    }
	    last = i;
	}
    }

    if (details) {
	printf ("Biggest gap from %d to %d is %.3f\n", gap_start, gap_end, biggest_gap);
    }
    if (partitions > 2 && biggest_gap >= total_time/partitions) {
	// Pivot on this gap
	u_int split = 1;
	int intvl = 1;
	if (do_split && biggest_gap >= 2*total_time/partitions) {
	    split = biggest_gap*partitions/total_time-1;
	    if (partitions-split < 2) {
		split = partitions-2;
	    }
	    if (details) {
		printf ("would like to split this gap into %d partitions\n", split);
		printf ("begins at clock %lu ends at clock %lu\n", td[gap_start].start_clock, td[gap_end].start_clock);
	    }
	    if (td[gap_end].start_clock-td[gap_start].start_clock < split) split = td[gap_end].start_clock - td[gap_start].start_clock;
	    intvl = (td[gap_end].start_clock-td[gap_start].start_clock)/split;
	    if (details) {
		printf ("Interval is %d\n", intvl);
	    }
	} 
	total_time -= biggest_gap;
	partitions -= split;
	if (gap_start == start) {
	    if (split > 1) {
		print_utimings (td, gap_start, gap_end, split, intvl, fork_flags);
	    } else {
		print_timing (td, gap_start, gap_end, fork_flags);
	    }
	    return gen_timings (td, gap_end, end, partitions, fork_flags);
	}

	double front_gap = estimate_dift(td, start, gap_start);

	new_part = 0.5 + (partitions * front_gap) / total_time;
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	if (partitions - new_part > cnt_interval(td, gap_end, end)) new_part = partitions-cnt_interval(td, gap_end, end);
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	if (new_part > cnt_interval(td, start, gap_start)) new_part = cnt_interval(td, start, gap_start);
	if (new_part < 1) new_part = 1;
	if (new_part > partitions-1) new_part = partitions-1;
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	
	gen_timings (td, start, gap_start, new_part, fork_flags);
	if (split > 1) {
	    print_utimings (td, gap_start, gap_end, split, intvl, fork_flags);
	} else {
	    print_timing (td, gap_start, gap_end, fork_flags);
	}
	return gen_timings (td, gap_end, end, partitions - new_part, fork_flags);
    } else {
	// Allocate first interval
	goal = total_time/partitions;
	if (details) {
	    printf ("step: goal is %.3f\n", goal);
	}
	for (i = start+1; i < end; i++) {
	    if (td[i].can_attach) {
		double gap = estimate_dift(td, start, i);
		if (gap > goal || cnt_interval(td, i, end) == partitions-1) {	
		    fprintf(stderr, "gap %lf goal %lf\n", gap, goal);
		    print_timing (td,  start, i, fork_flags);
		    return gen_timings(td, i, end, partitions-1, fork_flags);
		}
	    }
	}
    }
    return -1;
}


//populate timings_data with info from the res log:
void pop_with_kres(vector<struct timing_data> &td, 
		   u_long &call_clock,
		   const u_int index,
		   const klog_result *res) { 

    td[index].start_clock = res->start_clock;
    td[index].stop_clock = res->stop_clock;
    td[index].should_track = true;

    td[index].call_clock = call_clock;
    call_clock = res->stop_clock;

    if (res->retval > 0) { 
	//input syscalls
	if(res->psr.sysnum == 3 || res->psr.sysnum == 180) { 
	    td[index].taint_in = res->retval;
	}
	//output syscalls 
	if (res->psr.sysnum == 4 || res->psr.sysnum == 146) { 
	    td[index].taint_out = res->retval;
	}
	//socketcall a special case b/c its very complicated
	if (res->psr.sysnum == 102) { 
	    if (res->retparams) { 
		int call = *((int *)(res->retparams));
		if (call == SYS_RECV || call == SYS_RECVFROM || call == SYS_RECVMSG){
		    td[index].taint_in = res->retval;
		}		    
		else if (call == SYS_SENDMSG || call == SYS_SEND) { 		
		    td[index].taint_out = res->retval;			
		}	
	    }
	}    
    }
}

class my_comp
{
public:
    bool operator() (const pair<u_long,u_long>& lhs, const pair<u_long,u_long>&rhs) const
	{
	    return lhs.second < rhs.second;
	}
};


// There seems to be a better way of doing this by keeping multiple klog
// files open at the same time. Then we only iterate through the timings list once. 
int parse_klogs(vector<struct timing_data> &td,
		const char* dir, 
		const char* fork_flags, 
		const set<pid_t> procs)
{
    struct klog_result* res;
    u_int lindex = 0;
    u_int stop_looking_index = numeric_limits<u_long>::max();
    u_long most_recent_clock = 0;
    pid_t pid = 0;
    u_int ff_index = 0;
    
    char path[1024];

    priority_queue<pair<pid_t, u_long>> pids_to_track;
    pair<pid_t, u_long> new_pair = make_pair(td[0].pid, 0);
    pids_to_track.push(new_pair);

    while(!pids_to_track.empty()) { 
	pair<pid_t, u_long> pid_pair = pids_to_track.top();
	pids_to_track.pop();
	most_recent_clock = 0; //indicates that we've found the first record for a process
	pid = pid_pair.first;
	if (most_recent_clock >= stop_looking_index) stop_looking_index = numeric_limits<u_long>::max();

	sprintf (path, "%s/klog.id.%d", dir, pid);	
	struct klogfile* log = parseklog_open(path);
	if (!log) {
	    fprintf(stderr, "%s doesn't appear to be a valid klog file!\n", path);
	    return -1;
	}
	lindex = 0;

	//our first pid has its record_timings off by one b/c we don't have timings data on exec
	if (pid == td[0].pid) { 
	    res = parseklog_get_next_psr(log); 
	}

	while ((res = parseklog_get_next_psr(log)) != NULL && lindex < td.size()) {
	    while (td[lindex].pid != pid && lindex < td.size()) {
		lindex++;
	    }
	    if (lindex >= td.size() || td[lindex].start_clock > stop_looking_index) break;

	    pop_with_kres(td, most_recent_clock, lindex, res);

	    //we found a fork
	    if (res->psr.sysnum == 120 && procs.count(res->retval) > 0) { 
		if (fork_flags[ff_index] == '1') { 
		    //stop tracking this pid, already covered all of its traced syscalls
		    td[lindex].forked_pid = res->retval; //this is important for can_attach logic
		    stop_looking_index = res->start_clock; 
		    pair<pid_t, u_long> new_pair = make_pair(res->retval, res->start_clock);
		    pids_to_track.push(new_pair);
		    break; 
		}
		ff_index++;
	    }
	    //found a thread_fork
	    else if (res->psr.sysnum == 120) { 
		td[lindex].forked_pid = res->retval; //this is important for can_attach logic
		pair<pid_t, u_long> new_pair = make_pair(res->retval, res->start_clock);
		pids_to_track.push(new_pair);		    
	    }
	    lindex++;
	}    
	parseklog_close(log);
    }
    return 0;
}

class ulog_data { 
public: 
    ulog_data(int f, u_long tc): fd(f), total_clock(tc) {};
    ulog_data(): fd(0), total_clock(0) {};
    int fd;
    u_long total_clock; //current clock_index w/in the ulog
}; 

int open_ulog(const pid_t pid,
	      const char *dir) 
{ 
    char path[1024]; 
    int unused; 
    int fd;
    int rc;

    sprintf (path, "%s/ulog.id.%d", dir, pid);	    
    fd = open(path, O_RDONLY);
    if (fd < 0) { 
	fprintf(stderr, "couldn't open ulog: %s\n",path);
	return -1;
    }
    //we don't care about num_bytes, but just need to skip it in this fd:
    rc = read(fd, &unused, sizeof(int)); 
    (void) rc;
    return fd;
}

int pop_with_ulog(vector<struct timing_data> &td, u_int td_index, ulog_data &udata) 
{ 
    u_long entry;    
    u_long i;
    int skip, unused, rc;
    
    int fd = udata.fd;

    u_long last_pthread_block = 0; 

    //as long as udata.total_clock < start_clock, then they're user ops that ran
    //between the prev syscall and the current one. 

    while (udata.total_clock < td[td_index].start_clock) 
    { 
	rc = read (fd, &entry, sizeof(u_long));
	for (i = 0; i < (entry&CLOCK_MASK); i++) {
	    udata.total_clock++; 
	}
	
	//if this happens, it means that we call into the kernel
	if (entry&SKIPPED_CLOCK_FLAG) {
	    rc = read (fd, &skip, sizeof(int));
	    udata.total_clock += skip + 1;
	    if (udata.total_clock < td[td_index].start_clock) {
		last_pthread_block = udata.total_clock - 1; //the last clock val we are blocking
	    }
	} else {
	    udata.total_clock++;
	}
	if (entry&NONZERO_RETVAL_FLAG) {
	    rc = read (fd, &unused, sizeof(int));
	}
	if (entry&ERRNO_CHANGE_FLAG) {
	    rc = read (fd, &unused, sizeof(int));
	}
	if (entry&FAKE_CALLS_FLAG) {
	    rc = read (fd, &unused, sizeof(int));
	}
    }    
    if (last_pthread_block > td[td_index].call_clock) 
    { 
	td[td_index].call_clock = last_pthread_block;
    }
    
    (void) rc;
    return 0;
}

int parse_ulogs(vector<struct timing_data> &td, const char* dir)
{
    map<pid_t, ulog_data> pid_fd_map; 
    u_int i; 
    for (i = 0; i < td.size(); i ++) { 
	if (pid_fd_map.count(td[i].pid) == 0) { 
	    int fd = open_ulog(td[i].pid, dir);
	    ulog_data u(fd, 0);
	    pid_fd_map[td[i].pid] = u;
	}
	pop_with_ulog(td, i, pid_fd_map[td[i].pid]);       
    }
    return 0;
}

void inline update_ut( vector<struct timing_data> &td, 
		       u_int &total_time,
		       map<pid_t, u_int> &last_time,
		       const u_int td_index) 
{ 
    pid_t pid = td[td_index].pid;
    auto iter = last_time.find(pid);
    if (iter == last_time.end()) {
	total_time += td[td_index].ut;
    } else {
	total_time += td[td_index].ut - iter->second;
    }
    last_time[pid] = td[td_index].ut;
    td[td_index].ut = total_time;
}

void inline update_cache_misses( vector<struct timing_data> &td, 
				 uint64_t &total_cache_misses,
				 const u_int td_index) 
{
    //update the number of cache misses
    total_cache_misses += td[td_index].cache_misses;
    td[td_index].cache_misses = total_cache_misses;
    
    if(total_cache_misses > UINTMAX_MAX) { 
	fprintf(stderr, "whoops, way to many cache_misses\n");
    }    
}

void inline update_taint_stats( vector<struct timing_data> &td, 
				u_int &total_taint_in, 
				u_int &total_taint_out, 
				const u_int td_index) 
{
    /*
     * since we associate taint_in and taint_out ops with reads and writes, the taint they
     * create is actually added after the syscall's start_clock.
     */
    
    int curr_total_in = total_taint_in;
    int curr_total_out = total_taint_out; 
    total_taint_in += td[td_index].taint_in;
    total_taint_out += td[td_index].taint_out;       
    td[td_index].taint_in = curr_total_in;
    td[td_index].taint_out = curr_total_out;    
}
//this is an n^2 algorithm, but it probably isn't really n^2, depends on the number of 
// bad_syscalls, and how common they are. 

void inline update_can_attach( vector<struct timing_data> &td, 
			       const u_int td_index) 
{
    if (bad_syscalls.count(td[td_index].syscall))
    {
	assert(td[td_index].call_clock && "bad_syscall happens on first syscall?");
	for (auto &t : td) 
	{
	    //if the record's attach clock occurs during this syscall
	    if (t.start_clock > td[td_index].call_clock &&
		t.start_clock < td[td_index].stop_clock) 
	    { 
		t.can_attach = false;
	    }
	}
    }

    //special case for the forked child
    if (td[td_index].syscall == 120) 
    {
	u_long call_clock = td[td_index].start_clock; 
	u_int  forked_index = td_index+1;

	//update forked_index until we find the first entry of the child
	while (td[forked_index].pid != td[td_index].forked_pid) forked_index++;
	for (auto &t : td) 
	{
	    //if the record's attach clock occurs during the child's ret from fork
	    if (t.start_clock > call_clock &&
		t.start_clock < td[forked_index].start_clock)
	    { 
		t.can_attach = false;
	    }
	}       
    }   
}

int parse_timing_data( vector<struct timing_data> &td) 
{
    u_int total_time = 0;
    u_int total_taint_in = 0; 
    u_int total_taint_out = 0;
    uint64_t total_cache_misses = 0;
    map<pid_t,u_int> last_time;    
    u_int i, j, k; 

    for (i = 0; i < td.size(); i++) {
	if (! td[i].should_track) { 
	    td[i].can_attach = false; //mark it as not attachable, and continue
	    continue; 
	}

	update_ut(td, total_time, last_time, i);
	update_cache_misses(td, total_cache_misses, i);
	update_taint_stats(td, total_taint_in, total_taint_out, i);
	update_can_attach(td, i);
    }

    u_long aindex = 1;
    for (auto &t : td) {
	if (t.can_attach) { 
	    t.aindex = aindex++;
	} else {
	    t.aindex = 0;
	}
    }


    // interpolate timing vals when incrememnt is small 
    for (i = 0; i < td.size(); i++) {
	for (j = i+1; j < td.size(); j++) {
	    if (td[i].ut != td[j].ut) break;
	}
	for (k = i; k < j; k++) {
	    td[k].dtiming = (double) td[k].ut + (double) (k-i) / (double) (j-i);
	}
	i = j-1;
    }
    return 0;
}

int main (int argc, char* argv[])
{
    char filename[256];
    struct replay_timing* timings;
    struct extra_data* edata;
    struct stat st;
    int fd, rc, num, i, parts;
    char following[256];   
    set<pid_t> procs;
    struct timeval start_tv, read_and_copy_tv, pklog_tv, pulog_tv, ptiming_tv, gen_timings_tv;
    
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
	else if (!strcmp(argv[i], "-s")) {
	    do_split = 1;
	}
	else { 
	    //the assumption is that if we get to this point that its listing of the procs now
	    procs.insert(atoi(argv[i]));
	}
    }
    
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
    
    edata = (struct extra_data *) malloc (st.st_size);
    if (edata == NULL) {
	fprintf (stderr, "Unable to allocate extra data array of size %lu\n", st.st_size);
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
	next_td.ut = timings[i].ut;
	next_td.taint_in = 0;
	next_td.taint_out = 0;

	next_td.cache_misses = timings[i].cache_misses;
	next_td.can_attach = true; //set it to be true first
	td[i] = next_td; 

    }
    gettimeofday(&read_and_copy_tv, NULL);
    
    rc = parse_klogs(td, argv[1], following, procs);
    gettimeofday(&pklog_tv, NULL);

    rc = parse_ulogs(td, argv[1]);     
    gettimeofday(&pulog_tv, NULL);

    rc = parse_timing_data(td);
    gettimeofday(&ptiming_tv, NULL);


/*
    for (auto t : td) { 
	if (bad_syscalls.count(t.syscall) > 0 && t.should_track) { 
	    for (auto t2 : td) { 
		if (t2.start_clock > t.call_clock && t2.start_clock < t.stop_clock) { 
		    assert(!t2.can_attach);//step one
		}
	    }
	}
    }
*/

    if(details) {
	for (auto t : td) { 
	    printf ("%d %lu %lu, %lu, (%lf %lu %lu %llu), %d\n", t.pid, t.call_clock, t.start_clock, t.stop_clock, t.dtiming, t.taint_in, t.taint_out, t.cache_misses, t.should_track);
	    if (!t.can_attach) printf("\t can't attach\n");
	}
    }

    printf ("%s\n", argv[1]);
    gen_timings(td, 0, td.size() - 1, parts, following);
    gettimeofday(&gen_timings_tv, NULL);

    fprintf(stderr, "read_and_copy_time %ld\n",ms_diff(read_and_copy_tv, start_tv));
    fprintf(stderr, "pklog_time %ld\n",ms_diff(pklog_tv, read_and_copy_tv));
    fprintf(stderr, "pulog_time %ld\n",ms_diff(pulog_tv, pklog_tv));
    fprintf(stderr, "ptiming_time %ld\n",ms_diff(ptiming_tv, pulog_tv));
    fprintf(stderr, "gen_timings_time %ld\n",ms_diff(gen_timings_tv, ptiming_tv));

    return 0;
}


