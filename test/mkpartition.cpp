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

#include "parseklib.h"
#include <map>
#include <vector>
#include <set>
using namespace std;

struct replay_timing {
    pid_t     pid;
    u_long    index;
    short     syscall;
    u_int     ut;
    uint64_t  cache_misses;
};

struct extra_data {
    double   dtiming;
    u_long   aindex;
    u_long   start_clock;
    u_long   retval; //the return value of the syscall.. used entirely for fork. 
    u_long   taint_in; //the amount of taint that we've gotten in at this point
    u_long   taint_out; //the amount of taint that we've output at this point
    map<u_int, short> *rpg_syscalls;
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

int cmp (const void* a, const void* b)
{
    const struct ckpt* c1 = (const struct ckpt *) a;
    const struct ckpt* c2 = (const struct ckpt *) b;
    return c1->clock - c2->clock;
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
	    ckpts[ckpt_cnt].clock = cpd.outptr;
	    ckpt_cnt++;

	    close (fd);
	}
    }
    
    qsort (ckpts, ckpt_cnt, sizeof(struct ckpt), cmp);
    closedir (dir);
    return 0;
}

void print_utimings (struct replay_timing* timings, struct extra_data* edata, int start, int end, u_int split, int intvl, char* fork_flags)
{ 
    u_long ndx = edata[start].start_clock;
    u_long next_ndx = ndx + intvl;
    printf ("%5d k %6lu u %6lu       0       0 ", timings[start].pid, ndx, next_ndx);
    if (strnlen(fork_flags, 128) > 0)
	printf (" %s\n", fork_flags);
    else {
	printf (" 0\n");
    }
    for (u_int i = 0; i < split-2; i++) {
	ndx = next_ndx;
	next_ndx = ndx+intvl;
	printf ("%5d u %6lu u %6lu       0       0 ", timings[start].pid, ndx, next_ndx);
	if (strnlen(fork_flags, 128) > 0)
	    printf (" %s\n", fork_flags);
	else {
	    printf (" 0\n");
	}
    }
    printf ("%5d u %6lu k %6lu       0       0 ", timings[start].pid, next_ndx, edata[end].start_clock);
    if (strnlen(fork_flags, 128) > 0)
	printf (" %s\n", fork_flags);
    else {
	printf (" 0\n");
    }

}

void print_timing (struct replay_timing* timings, struct extra_data* edata, int start, int end, char* fork_flags)
{ 
    printf ("%5d k %6lu k %6lu ", timings[start].pid, edata[start].start_clock, edata[end].start_clock);

    if (filter_syscall > 0) {
	if ((u_long) filter_syscall > timings[start].index && (u_long) filter_syscall <= timings[end].index) {
	    printf (" %6lu", filter_syscall-timings[start].index+1);
	} else {
	    printf (" 999999");
	}
    } else {
	printf ("      0");
    }
    if (use_ckpt > 0) {
	int i;
	for (i = 0; i < ckpt_cnt; i++) {
	    if (timings[start].index <= ckpts[i].clock) {
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

static int can_attach (map<u_int, short> *syscalls) 
{
    bool attach = true;
    for (auto iter = syscalls->begin(); iter != syscalls->end(); ++iter){ 
	auto val = iter->second;
	if (val == 192 || val == 91 || val == 120 || val == -1 || val == 174){
	    attach = false;
	}	
    }
    return attach;
}

static int cnt_interval (struct extra_data* edata, int start, int end)
{
//    printf ("cnt_interval, %d, %lu, %d, %lu\n",start, edata[start].aindex, end, edata[end].aindex);
    int last_aindex = 0;
    for (int i = end; i > start; --i) { 
	if (edata[i].aindex > 0) {
	    last_aindex = edata[i].aindex;
	    break;
	}
    }
    return last_aindex - edata[start].aindex;//
    

}

//model created by correlation analysis
inline static double estimate_gap(struct replay_timing* timings, struct extra_data* edata, int i, int j)
{ 
    double utime = edata[j].dtiming - edata[i].dtiming;
//    int taint_in = edata[j].taint_in - edata[i].taint_in;
    u_long taint_out = edata[j].taint_out - edata[i].taint_out; 
    u_long cache_misses = timings[j].cache_misses - timings[i].cache_misses; 

//    int rtn_val = (261 * utime) - (0.00121 * taint_in) + ( 0.000932 * taint_out) + (.531 * cache_misses) ;
//    fprintf(stderr, "\t %lf %lu %lu\n", utime, taint_out, cache_misses);
    int rtn_val = (220 * utime) + ( 0.000241 * taint_out) + (.594 * cache_misses) ;

    return rtn_val;

}


int gen_timings (struct replay_timing* timings, 
		 struct extra_data* edata, 
		 int start, 
		 int end, 
		 int partitions, 
		 char* fork_flags){

    double biggest_gap = 0.0, goal;
    int gap_start, gap_end, last, i, new_part;

    assert (start < end); 
    assert (partitions <= cnt_interval(edata, start, end));

    if (partitions == 1) {
//	double gap = estimate_gap(timings, edata, start, end);
//	fprintf(stderr,"2:s %d, i %d, gap %lf\n",start, end, gap);	

	print_timing (timings, edata, start, end, fork_flags);
	return 0;
    }

    double total_time = estimate_gap(timings, edata, start, end);
//    fprintf(stderr,"2:s %d, i %d tt %lf\n",start, end,total_time);
//    double total_time = edata[end].dtiming - edata[start].dtiming;

    // find the largest gap
    if (details) {
	printf ("Consider [%d,%d]: %d partitions %.3f time\n", start, end, partitions, total_time);
    }

    last = start;
    for (i = start+1; i < end; i++) {
	if (can_attach(edata[i].rpg_syscalls)) {
//	    double gap = edata[i].dtiming - edata[last].dtiming;
//	    fprintf(stderr, "calling eg w/ %d %d\n", last , i);
	    double gap = estimate_gap(timings, edata, last, i);
	    if (gap > biggest_gap) {
		gap_start = last;
		gap_end = i;
		biggest_gap = gap;
	    }
	    last = i;
	}
    }
    double gap = estimate_gap(timings, edata, gap_start, gap_end);

    if (details) {
//	printf ("Biggest gap from %d to %d is %.3f\n", gap_start, gap_end, edata[gap_end].dtiming - edata[gap_start].dtiming);
	printf ("Biggest gap from %d to %d is %.3f\n", gap_start, gap_end, gap);
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
		printf ("begins at clock %lu ends at clock %lu\n", edata[gap_start].start_clock, edata[gap_end].start_clock);
	    }
	    if (edata[gap_end].start_clock-edata[gap_start].start_clock < split) split = edata[gap_end].start_clock - edata[gap_start].start_clock;
	    intvl = (edata[gap_end].start_clock-edata[gap_start].start_clock)/split;
	    if (details) {
		printf ("Interval is %d\n", intvl);
	    }
	} 
//	total_time -= (edata[gap_end].dtiming - edata[gap_start].dtiming);
	total_time -= gap;
	partitions -= split;
	if (gap_start == start) {
	    if (split > 1) {
		print_utimings (timings, edata, gap_start, gap_end, split, intvl, fork_flags);
	    } else {
		print_timing (timings, edata, gap_start, gap_end, fork_flags);
	    }
	    return gen_timings (timings, edata, gap_end, end, partitions, fork_flags);
	}
//here
//	new_part = 0.5 + (partitions * (edata[gap_start].dtiming - edata[start].dtiming)) / total_time;
	new_part = 0.5 + (partitions * gap) / total_time;
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	if (partitions - new_part > cnt_interval(edata, gap_end, end)) new_part = partitions-cnt_interval(edata, gap_end, end);
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	if (new_part > cnt_interval(edata, start, gap_start)) new_part = cnt_interval(edata, start, gap_start);
	if (new_part < 1) new_part = 1;
	if (new_part > partitions-1) new_part = partitions-1;
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	
	gen_timings (timings, edata, start, gap_start, new_part, fork_flags);
	if (split > 1) {
	    print_utimings (timings, edata, gap_start, gap_end, split, intvl, fork_flags);
	} else {
	    print_timing (timings, edata, gap_start, gap_end, fork_flags);
	}
	return gen_timings (timings, edata, gap_end, end, partitions - new_part, fork_flags);
    } else {
	// Allocate first interval
	goal = total_time/partitions;
	if (details) {
	    printf ("step: goal is %.3f\n", goal);
	}
	for (i = start+1; i < end; i++) {
	    if (can_attach(edata[i].rpg_syscalls)) {
		double gap = estimate_gap(timings, edata, start, i);
//		if (edata[i].dtiming-edata[start].dtiming > goal || cnt_interval(edata, i, end) == partitions-1) {
		if (gap > goal || cnt_interval(edata, i, end) == partitions-1) {	
		    /*
		     * this means that we've gone *just* past our goal. If we follow this policy in the 
		     * long run we wind up having shorted epochs at the end of our replay. we can do two things: 
		     * 1. Since we have seq passes, we acutally want later epochs to be slightly longer, so 
		     *    we can instead favor slightly smaller epochs 
		     * 2. we can just try to pick epochs that get us closest to our goal here. 

		     * I opt for the 1st, but we should probably look into it more. 
		     */

		    double act_gap; 
		    int new_i = i - 1; //start one behind, go until you can attach. stop if you went too far
		    while (new_i > start + 1 && !can_attach(edata[new_i].rpg_syscalls)) { 
			new_i --;			
		    }

		    if (new_i > start + 1) {
			i = new_i;
			act_gap = estimate_gap(timings, edata, start, i); 
		    }
		    else {
			act_gap = gap;
		    }

		    (void) act_gap;
//		    fprintf(stderr,"2:s %d, i %d tt %lf, part %d, goal %lf, gap %lf, act_gap %lf\n",start, i,total_time, partitions, goal, gap, act_gap);	

		    print_timing (timings, edata,  start, i, fork_flags);
		    return gen_timings(timings, edata, i, end, partitions-1, fork_flags);
		}
	    }
	}
    }
    return -1;
}

int find_processes(map<u_int,u_int> &pid_to_index, 
		   map<u_int,u_int> &fork_process,
		   map<u_int,u_int> &fork_offset,
		   map<pair<u_int,u_int>, u_int> &forks,
		   map<pair<u_int,u_int>, u_int> &taint_in,
		   map<pair<u_int,u_int>, u_int> &taint_out,
		   const char* dir, 
		   const struct replay_timing* timings,
		   const u_int num, 
		   const set<int> procs)
{
    char klog_filename[256];
    int timings_map_index = 0; 
    map<u_int,bool> pid_found;

    for (u_int i = 0; i < num; i++) {
	pid_found[timings[i].pid] = false; 
    }
    
    //I think the first thing run is always the first pid... right? 
    pid_to_index[timings[0].pid] = 0;
    fork_process[timings[0].pid] = -1; //sentinal value for no fork
    fork_offset[timings[0].pid] = -1; //sentinal value for no fork
    timings_map_index++;

    /*
     * here we go through all of the klogs to figure out which pids are processes and which are 
     * threads: 
     * 1 for each of the pids found, we open its klog
     * 2 for each record in the klog, we see if its a clone,
     * 3 if the record is a clone then we update the datastructures
    */
    for(auto pid_iter = pid_found.begin(); pid_iter != pid_found.end(); pid_iter++) {
	sprintf (klog_filename, "%s/klog.id.%d", dir, pid_iter->first);	
	struct klogfile *log = parseklog_open(klog_filename);
	struct klog_result *res = NULL;

	while((res = parseklog_get_next_psr(log)) != NULL) {
            //input syscalls
	    if(res->psr.sysnum == 3 || res->psr.sysnum == 180) { 
		auto p = make_pair(pid_iter->first, res->index);
		taint_in[p] = res->retval;
	    }

            //output syscalls 
	    if (res->psr.sysnum == 4 || res->psr.sysnum == 146) { 
		auto p = make_pair(pid_iter->first, res->index);
		taint_out[p] = res->retval;
	    }

	    //socketcall a special case b/c its very complicated
	    if (res->psr.sysnum == 102) { 
		char *retparams = (char *) res->retparams; 
		if (retparams) { 
		    int call = *((int *)retparams);
		    if (call == SYS_RECV || call == SYS_RECVFROM || 
			call == SYS_RECVMSG){
			
			auto p = make_pair(pid_iter->first, res->index);
			taint_in[p] = res->retval;			
		    }		    
		    else if (call == SYS_SENDMSG) { 
			auto p = make_pair(pid_iter->first, res->index);
			taint_out[p] = res->retval;			
		    }	
		}
	    }

	    if(res->psr.sysnum == 120 ) {           
		auto p = make_pair(pid_iter->first, res->index);
		forks[p] = res->retval;
 	       
		if(procs.count(res->retval) > 0) 
		{ 
		    //this is a fork! 
		    pid_found[res->retval] = true; 
		    pid_to_index[res->retval] = timings_map_index; 
		    
		    fork_process[res->retval] = pid_iter->first;
		    fork_offset[res->retval] = res->index;

		    timings_map_index++; 
		}
		else 
		{ 		 
		    //this is a thread_fork:
		    pid_to_index[res->retval] = pid_to_index[pid_iter->first];
		    pid_found[res->retval] = true;
		}
	    }
	}
    }
    return 0;
}

int get_num_per_process(vector<u_int> &num_el,
			map<u_int,u_int> &pid_index,
			map<u_int, map<u_int,u_int>> pid_intervals,
			const struct replay_timing *timings,
			const int num) { 

    //first initialize the num_el to 0
    u_int max = 0;
    vector<u_int> total_time_proc;
    map<u_int,u_int> last_time;        

    for(auto pid_iter = pid_index.begin(); pid_iter != pid_index.end(); pid_iter++) { 
	if(pid_iter->second > max) 
	    max = pid_iter->second;
    }

    for(u_int i = 0; i <= max; i++){ 
	num_el.push_back(0);
	total_time_proc.push_back(0);
    }

    for(int i = 0; i < num; i++) {
	u_int timings_pid = timings[i].pid;
	u_int timings_index = timings[i].index;
	u_int time_passed = timings[i].ut;

	auto iter = last_time.find(timings_pid);
	if(iter != last_time.end()) { 
	    time_passed -= iter->second;
	}
	for(auto it = pid_intervals.begin(); it != pid_intervals.end(); it++) { 
	    u_int curr_pid = it->first;
	    u_int curr_pid_index = pid_index[curr_pid];
	    map<u_int,u_int> interval = it->second;
	
	    /*
	     * there are two times that things need to be considered as part of the replay:
	     * 1. if the index of the current pid in the index_inclusion is the same as the index of
	     *    the current pid of the timings entry (means same proc, possibly diff threads)
	     * 2. if the current pid is in the interval map, and the current index is less than the
	     *    index from the interval map for that current pid. Note: this won't work for multi-
	     *    threaded processes that fork processes... 
	     */
	    if(curr_pid_index == pid_index[timings_pid] || 
	       (interval.count(timings_pid) && timings_index <= interval[timings_pid])) {
		total_time_proc[curr_pid_index] += time_passed;
		num_el[curr_pid_index]++;
	    }
	}
	last_time[timings_pid] = timings[i].ut;		
    }

    return 0;
}

int allocate_multiprocess_ds(vector<struct replay_timing *> &timings_vect,
			     vector<struct extra_data *> &edata_vect,
			     vector<char *> &fork_flags,
			     const vector<u_int> &num_el){

    
    for(auto index_iter = num_el.begin(); index_iter != num_el.end(); index_iter++) { 

	//add in a spot for the fork_flags!
	char* fork_flag = (char *) malloc(sizeof(char) * 128);
	fork_flag[0] = 0;//add a null terminator to the beginning
	fork_flags.push_back(fork_flag);	

	timings_vect.push_back((struct replay_timing *) malloc(sizeof(replay_timing) * (*index_iter)));
	if (timings_vect.back() == NULL) {
	    fprintf (stderr, "Unable to allocate timings buffer of size %u\n", sizeof(replay_timing) * (*index_iter));
	    return -1;
	}

	edata_vect.push_back((struct extra_data *) malloc(sizeof(extra_data) * (*index_iter)));
	if (edata_vect.back() == NULL) {
	    fprintf (stderr, "Unable to allocate edata of size %u\n",sizeof(extra_data) * (*index_iter));
	    return -1;
	}
    }
    return 0;
}

int split_timings(vector<struct replay_timing *> &timings_vect,
		  map<u_int,u_int> &pid_to_index_map,		  
		  map<u_int, map<u_int,u_int>> pid_intervals,
		  const struct replay_timing *timings, 
		  const int num)
{
    //initialize a map that stores the current # of elements in each timings map
    int i;
    
    vector<u_int> timings_index_to_curr_offset; 
    for(auto timings_vect_iter = timings_vect.begin(); timings_vect_iter != timings_vect.end(); timings_vect_iter++) { 
	timings_index_to_curr_offset.push_back(0);
    }

    //For each of the elements in timings, let it go find its home! 
    for (i = 0; i < num; i ++) {
	for(auto it = pid_intervals.begin(); it != pid_intervals.end(); it++) { 

	    u_int curr_pid = it->first;
	    u_int curr_pid_index = pid_to_index_map[curr_pid];
	    map<u_int,u_int> interval = it->second;
	    
	    u_int timings_pid = timings[i].pid;
	    u_int curr_offset = timings_index_to_curr_offset[curr_pid_index];
	    struct replay_timing* curr_timings = timings_vect[curr_pid_index];	    
	    u_int timings_index = timings[i].index;


//	    printf("%i split timings, curr_pid %d, curr_pid_index %d, timings_pid %d curr_offset %d, timings_index %d\n",
//		   i, curr_pid, curr_pid_index, timings_pid, curr_offset, timings_index);
		   
	
	    /*
	     * there are two times that things need to be considered as part of the replay:
	     * 1. if the index of the current pid in the index_inclusion is the same as the index of
	     *    the current pid of the timings entry (means same proc, possibly diff threads)
	     * 2. if the current pid is in the interval map, and the current index is less than the
	     *    index from the interval map for that current pid. Note: this won't work for multi-
	     *    threaded processes that fork processes... 
	     */
	    if(curr_pid_index == pid_to_index_map[timings_pid] || 
	       (interval.count(timings_pid) && timings_index <= interval[timings_pid])) {
	
		curr_timings[curr_offset] = timings[i]; 
		timings_index_to_curr_offset[curr_pid_index]++; //increment the index for this timings_map		
	    }
	}
    }
    return 0;
}


int build_intervals(map<u_int, u_int> &fork_process,
		    map<u_int, u_int> &fork_offset, 
		    map<u_int, u_int> &pid_to_index,
		    map<u_int, map<u_int, u_int>> &index_inclusions)
{
    for(auto proc_iter = fork_process.begin(); proc_iter != fork_process.end(); proc_iter++) 
    {
	map<u_int,u_int> intervals;
	
	int curr_pid = fork_process[proc_iter->first];
	u_int curr_offset = fork_offset[proc_iter->first];
	while(curr_pid != -1) 
	{
	    intervals[curr_pid] = curr_offset;

	    curr_offset = fork_offset[curr_pid];
	    curr_pid = fork_process[curr_pid];	    
	}
	index_inclusions[proc_iter->first] =  intervals;
    }

    if(details) { 
	printf("fork_process\n");
	for(auto it = fork_process.begin(); it != fork_process.end(); it++) 
	    printf("(%d,%d)\n",it->first,it->second);

	for(auto it = index_inclusions.begin(); it != index_inclusions.end(); it++) 
	{
	    printf("intervals for %d\n",it->first);
	    for(auto it2 = it->second.begin(); it2 != it->second.end(); it2++) 
	    {
		printf("(%d,%d),",it2->first,it2->second);
	    }
	    printf("\n");
	}
    }
   
    return 0;
} 
int populate_start_clock(vector<struct replay_timing *> &timings_vect,
			 vector<struct extra_data *> &edata_vect,
			 vector<u_int> &num_el,
			 const struct replay_timing* timings, 
			 const u_int num, 
			 const char* dir){

    // Fill in start clock time from klogs - start with parent process

    char path[256];
    sprintf (path, "%sklog.id.%d", dir, timings[0].pid);

    struct klogfile* log = parseklog_open(path);
    if (!log) {
	fprintf(stderr, "%s doesn't appear to be a valid klog file!\n", path);
	return -1;
    }

    struct klog_result* res = parseklog_get_next_psr(log); // exec
    u_int lindex = 0;
    vector<pid_t> children;
    vector<u_int> timings_index; 
    for(auto i : timings_vect) { 
	(void)i;
	timings_index.push_back(0);
    }

    while ((res = parseklog_get_next_psr(log)) != NULL) {
	while (timings[lindex].pid != timings[0].pid) {
	    if (timings[lindex].index == 0) children.push_back(timings[lindex].pid);
	    lindex++;
	    if (lindex >= num) break;
	}

	if (lindex >= num) break;
	for(u_int i = 0; i < timings_index.size(); i++) { 

	    if(timings_index[i] == num_el[i]) continue;
	    struct replay_timing* curr_timings = timings_vect[i];
	    struct extra_data* curr_edata = edata_vect[i];
	    
	    curr_edata[timings_index[i]].start_clock = res->start_clock;
	    //advance the timings_index forward until we get to the next record with this pid
	    do{ 
		timings_index[i]++;
	    }while(curr_timings[timings_index[i]].pid != timings[0].pid && 
		   timings_index[i] != num_el[i]);
	}
	lindex++;
	if (lindex >= num) break;
    }
    parseklog_close(log);

    // Now do children
    for (auto iter = children.begin(); iter != children.end(); iter++) {
	sprintf (path, "%sklog.id.%d", dir, *iter);	
	struct klogfile* log = parseklog_open(path);
	if (!log) {
	    fprintf(stderr, "%s doesn't appear to be a valid klog file!\n", path);
	    return -1;
	}

	lindex = 0;
	//fixup the values in timings_index
	for(u_int i = 0; i < timings_index.size(); i++) { 
	    struct replay_timing* curr_timings = timings_vect[i];
	    timings_index[i] = 0;
	    do{ 
		timings_index[i]++;
	    }while(curr_timings[timings_index[i]].pid != *iter && 
		   timings_index[i] != num_el[i]);
	}

	while ((res = parseklog_get_next_psr(log)) != NULL) {
	    while (timings[lindex].pid != *iter) {
		lindex++;
		if (lindex >= num) break;
	    }
	    if (lindex >= num) break;
	    for(u_int i = 0; i < timings_index.size(); i++) { 

		if(timings_index[i] == num_el[i]) continue;
		struct replay_timing* curr_timings = timings_vect[i];
		struct extra_data* curr_edata = edata_vect[i];
	    
		curr_edata[timings_index[i]].start_clock = res->start_clock;
		//advance the timings_index forward until we get to the next record with this pid
		do{ 
		    timings_index[i]++;
		}while(curr_timings[timings_index[i]].pid != *iter && 
		       timings_index[i] != num_el[i]);
	    }
	    if (lindex >= num) break;
	}
	parseklog_close(log);
    }
    return 0;
}
int populate_retval(vector<struct replay_timing *> &timings_vect, 
		     vector<struct extra_data*> &edata_vect, 
		     vector<u_int> &num_el, 
		     map<pair<u_int,u_int>,u_int> &forks,
		     map<pair<u_int,u_int>,u_int> &taint_in,
		     map<pair<u_int,u_int>,u_int> &taint_out) { 

    for (u_int i = 0; i < timings_vect.size(); ++i) { 
	auto timings = timings_vect[i];
	auto edata = edata_vect[i];
	auto num = num_el[i];

	for (u_int j = 0; j < num; ++j) { 
	    auto curr_timing = timings[j];
	    if(curr_timing.syscall == 120) { 
		auto p = make_pair(curr_timing.pid, curr_timing.index);
		edata[j].retval = forks[p];
	    }

	    //input syscalls
	    else if(curr_timing.syscall == 3   || curr_timing.syscall == 180) { 
		auto p = make_pair(curr_timing.pid, curr_timing.index);
		edata[j].taint_in = taint_in[p];
	
	    }

            //output syscalls 
	    else if (curr_timing.syscall == 4   || curr_timing.syscall == 146) {  
		auto p = make_pair(curr_timing.pid, curr_timing.index);
		edata[j].taint_out = taint_out[p];
	
	    }	

	    //socketcall
	    else if (curr_timing.syscall == 102) { 
		auto p = make_pair(curr_timing.pid, curr_timing.index);
		if (taint_out.count(p) > 0) { 
		    edata[j].taint_out = taint_out[p];		    
		    edata[j].taint_in = 0;
		}
		else { 
		    edata[j].taint_in = taint_in[p];
		    edata[j].taint_out = 0;
		}
	    }
	}
    }
    return 0;
}

int build_fork_flags(vector<char*> &fork_flags,
		     map<u_int,u_int> &pid_to_index,
		     map<u_int,map<u_int,u_int>> &index_interval_inclusions,
		     map<u_int,u_int> &fork_process,
		     map<u_int,u_int> &fork_offset,
		     const struct replay_timing *timings,
		     const int num){
    for(int i = 0; i < num; i++) { 
	struct replay_timing curr_timing = timings[i];
	if (curr_timing.syscall == 120) { 
	    //we might have a fork, so iterate through all indexes and see if any
	    //procs stop including this proc at exactly this point in time
	    for(auto proc_gp : index_interval_inclusions) {

		bool is_fork = false; 
		//see if this is a fork
		for(auto proc : fork_process) { 
		    if (proc.second == (u_long)curr_timing.pid) { 
			if (fork_offset[proc.first] == curr_timing.index) { 
			    is_fork = true;
			}
		    }		    
		}

		if (!is_fork) { 
		    continue;
		}
	       
		//I'm not sure what the rationality is behind this if conditional? 
		if(proc_gp.first == (u_int)curr_timing.pid) { 
		    int index = pid_to_index[proc_gp.first];
		    strcat(fork_flags[index],"0");		    
		}

		for(auto interval : proc_gp.second){
		    if(interval.first == (u_int)curr_timing.pid &&
		       interval.second == curr_timing.index) { 
			int index = pid_to_index[proc_gp.first];
			strcat(fork_flags[index],"1");
		    }
		    else if (interval.first == (u_int) curr_timing.pid &&
			     interval.second > curr_timing.index) { 
			int index = pid_to_index[proc_gp.first];
			strcat(fork_flags[index],"0");
		    }
		}		
	    }	    
	}
    }	
    return 0;
}
//right now we have three parallel vectors... these could conceivably be structs. (probably should)
int create_multiprocess_ds(vector<u_int> &num_el,
			   vector<struct replay_timing *> &timings_vect,
			   vector<struct extra_data *> &edata_vect,			      
			   vector<char*> &fork_flags,
			   const struct replay_timing *timings,
			   const char* dir,
			   const int num,
			   const set<int> procs){
    
    int rc = 0;
    map<u_int, u_int> pid_to_index;
    map<u_int, u_int> fork_process; //maps from index to fork process id
    map<u_int, u_int> fork_offset; //maps from index to fork offset
    map<u_int, map<u_int,u_int>> index_interval_inclusions;

    map<pair<u_int,u_int>, u_int> retvals; //an index from (proc,index) -> child_pid
    map<pair<u_int,u_int>, u_int> taint_in; //an index from (proc,index) -> child_pid
    map<pair<u_int,u_int>, u_int> taint_out; //an index from (proc,index) -> child_pid


    rc = find_processes(pid_to_index, fork_process, fork_offset, retvals, taint_in, taint_out, dir, timings, num, procs);
    if(rc) { 
	printf("could not find_processes, rc %d\n", rc);
	return rc;
    }
    
    rc = build_intervals(fork_process, fork_offset, pid_to_index, index_interval_inclusions); 
    if(rc) { 
	printf("could not build_intervals, rc %d\n", rc);
	return rc;
    }

    rc = get_num_per_process(num_el, pid_to_index,  index_interval_inclusions, timings, num);
    if(rc) { 
	printf("could not get_num_per_process, rc %d\n", rc);
	return rc;
    }

    rc = allocate_multiprocess_ds(timings_vect, edata_vect, fork_flags, num_el);
    if(rc) { 
	printf("could not allocate_multiprocess_ds, rc %d\n", rc);
	return rc;
    }

    rc = build_fork_flags(fork_flags, pid_to_index, index_interval_inclusions, fork_process, fork_offset, timings, num);
    if(rc) { 
	printf("could not build fork_flags, rc %d\n",rc);
	return rc;
    }


    rc = split_timings(timings_vect, pid_to_index, index_interval_inclusions, timings, num);
    if(rc) { 
	printf("could not split_timings, rc %d\n", rc);
	return rc;
    }

    rc = populate_start_clock(timings_vect, edata_vect, num_el,timings, num, dir);
    if(rc) { 
	printf("could not split_timings, rc %d\n", rc);
	return rc;
    }

    rc = populate_retval(timings_vect, edata_vect, num_el,retvals, taint_in, taint_out);
    if(rc) { 
	printf("could not split_timings, rc %d\n", rc);
	return rc;
    }


    return 0; // on success
}

void generate_timings_for_process(struct replay_timing *timings,
				  struct extra_data* edata,				 
				  const u_int num_partitions,
				  const u_int num,
				  const char* dir,
				  char* fork_flags)
{
    // First, need to sum times for all threads to get totals for this group
    /*
     * while we're iterating through the timings list, I'm also going to track the syscall that
     * other processes are waiting on
     */

    int total_time = 0;
    int total_taint_in = 0; 
    int total_taint_out = 0;
    int child_pid;
    u_int i, j, k; 
    uint64_t total_cache_misses = 0;
    map<u_int,u_int> last_time;    
    map<u_int,short> latest_syscall;    


    for (i = 0; i < num; i++) {
	u_int pid = timings[i].pid;
	auto iter = last_time.find(pid);
	if (iter == last_time.end()) {
	    total_time += timings[i].ut;
	} else {
	    total_time += timings[i].ut - iter->second;
	}
	last_time[pid] = timings[i].ut;
	timings[i].ut = total_time;

	//update the number of cache misses
	total_cache_misses += timings[i].cache_misses;
	timings[i].cache_misses = total_cache_misses;

	if(total_cache_misses > UINTMAX_MAX) { 
	    fprintf(stderr, "holy shit, way to many cache_misses\n");
	}

	
	/*
	 * since we associate taint_in and taint_out ops with reads and writes, the taint they 
	 * create is actually added AFTER the syscall. For this reason, we assign the current 
	 * total_in and total_out to the current syscall, and incremenet the totals for subsequent
	 * syscalls
	 */

	int curr_total_in = total_taint_in;
	int curr_total_out = total_taint_out; 
	
        //input syscalls
	if(timings[i].syscall == 3 || timings[i].syscall == 180) { 
	    total_taint_in += edata[i].taint_in;	    
	}

        //output syscalls
	if(timings[i].syscall == 4 || timings[i].syscall == 146) { 
	    total_taint_out += edata[i].taint_out;	    
	}
	
	//socketcall a special case b/c its very complicated
	if (timings[i].syscall == 102) { 
	    total_taint_in += edata[i].taint_in;
	    total_taint_out += edata[i].taint_out;
	}

	edata[i].taint_in = curr_total_in;
	edata[i].taint_out = curr_total_out;


	//when we see a fork, we need to add the child to the list right?  
	if (timings[i].syscall == 120) { 
	    child_pid = edata[i].retval;
	    latest_syscall[child_pid] = -1; //to indicate that the child just started
	}

	latest_syscall[pid] = timings[i].syscall;  //update the latest_syscall of this pid to be this syscall
	for (auto pair : latest_syscall) { 
	    edata[i].rpg_syscalls = new map<u_int, short>();
	    (*edata[i].rpg_syscalls)[pair.first] = pair.second;
	}
    }

    // Next interpolate values where increment is small
    for (i = 0; i < num; i++) {
	for (j = i+1; j < num; j++) {
	    if (timings[i].ut != timings[j].ut) break;
	}
	for (k = i; k < j; k++) {
	    edata[k].dtiming = (double) timings[k].ut + (double) (k-i) / (double) (j-i);
	}
	i = j-1;
    }

    // Calculate index in terms of system calls we can attach to 
    u_long aindex = 1;
    for (i = 0; i < num; i++) {
	if (can_attach(edata[i].rpg_syscalls)) {
	    edata[i].aindex = aindex++;
	} else {
	    edata[i].aindex = 0;
	}
    }

    if (details) {
	for (i = 0; i < num; i++) {
	    printf ("%d: pid %d syscall %lu type %d ut %u %.3f\n", i, timings[i].pid, timings[i].index, timings[i].syscall, timings[i].ut, edata[i].dtiming);
	}
	printf ("----------------------------------------\n");
    }
/*
    for (i = 0; i < num; i++) {
	fprintf (stderr, "%d %lu %.3f %lu %lu %llu\n", timings[i].pid, edata[i].start_clock, edata[i].dtiming, edata[i].taint_in, edata[i].taint_out, timings[i].cache_misses);
    }
*/
	
    gen_timings (timings, edata, 0, num-1, num_partitions, fork_flags);
}

int main (int argc, char* argv[])
{
    char filename[256];
    struct replay_timing* timings;
    struct extra_data* edata;
    struct stat st;
    int fd, rc, num, i, parts;
    char following[256];   
    set<int> procs;

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


    /*
     * all of the datastructures for the multiprocess case. Each of these vectors are 
     * made in parallel, where there are entries for each of separate processes in the 
     * replay group. timings_vect and edata_vect are both vectors of arrays of structs.
     * num_el gives the number of elements in the arrays for that particular process.
     */

    vector<u_int> num_el;
    vector<struct replay_timing *> timings_vect;
    vector<struct extra_data *> edata_vect;
    vector<char*> fork_flags;


    num = st.st_size/sizeof(struct replay_timing); 
    create_multiprocess_ds(num_el, timings_vect, edata_vect, fork_flags,timings, argv[1], num, procs);
  


    if(details) { 
	for(u_int i = 0; i < num_el.size(); i++ ) 
	{	
	    struct replay_timing* curr_timings = timings_vect[i];
	    struct extra_data* curr_edata = edata_vect[i];
	
	    printf("num_el %d\n", num_el[i]);
	    printf("timing info (edata has not yet been determined)\n");

	    for (u_int j = 0; j < num_el[i]; j++) {
		printf ("%d: pid %d syscall %lu type %d ut %u misses %llu %.3f\n",j,
			curr_timings[j].pid, curr_timings[j].index, curr_timings[j].syscall, 
			curr_timings[j].ut, curr_timings[j].cache_misses, curr_edata[j].dtiming);
	    }
	    printf ("----------------------------------------\n");
	}
    }

    printf ("%s\n", argv[1]);
    if (group_by > 0) printf ("group by %d\n", group_by);

    for(u_int i = 0; i < num_el.size(); i++ ) {
	if (strlen(following) == 0 || !strcmp(fork_flags[i],following))
	    generate_timings_for_process(timings_vect[i], edata_vect[i], parts, num_el[i], argv[1], fork_flags[i]);
    }
    
    
    //cleanup_memory();  not implemented... muahaha, just deal with it kernel. 
    return 0;
}


