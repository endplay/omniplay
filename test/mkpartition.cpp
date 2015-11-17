#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <dirent.h>

#include "parseklib.h"
#include <map>
#include <vector>
using namespace std;

struct replay_timing {
    pid_t     pid;
    u_long    index;
    short     syscall;
    u_int     ut;
};

struct extra_data {
    double   dtiming;
    u_long   aindex;
    u_long   start_clock;
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

static int group_by = 0, filter_syscall = 0, details = 0, use_ckpt = 0;


void format ()
{
    fprintf (stderr, "Format: mkpartition <timing dir> <# of partitions> [-g group_by] [-f filter syscall] [-v]\n");
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



void print_timing (struct replay_timing* timings, struct extra_data* edata, int start, int end, int process_index)
{ 
    //printf ("%d %5d %6lu %5d %6d ", process_index, timings[start].pid, timings[start].index, timings[end].pid, end-start);
    printf ("%d %5d %6lu %5d %6lu ", process_index, timings[start].pid, timings[start].index, timings[end].pid, edata[end].start_clock);


    if (filter_syscall > 0) {
	if ((long) filter_syscall > timings[start].index && (long) filter_syscall <= timings[end].index) {
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
		    printf (" %6s\n", ckpts[i-1].name);
		} else {
		    printf ("      0\n");
		}
		return;
	    }
	}
	printf (" %6s\n", ckpts[i-1].name);
    } else {
	printf ("       0\n");
    }
}

static int can_attach (short syscall) 
{
    return (syscall != 192 && syscall != 91);
}

static int cnt_interval (struct extra_data* edata, int start, int end)
{
    return edata[end].aindex - edata[start].aindex;
}

int gen_timings (struct replay_timing* timings, 
		 struct extra_data* edata, 
		 int start, 
		 int end, 
		 int partitions, 
		 int process_index){

    double biggest_gap = 0.0, goal;
    int gap_start, gap_end, last, i, new_part;

    assert (start < end); 
    assert (partitions <= cnt_interval(edata, start, end));

    if (partitions == 1) {
	print_timing (timings, edata, start, end, process_index);
	return 0;
    }

    double total_time = edata[end].dtiming - edata[start].dtiming;

    // find the largest gap
    if (details) {
	printf ("Consider [%d,%d]: %d partitions %.3f time\n", start, end, partitions, total_time);
    }

    last = start;
    for (i = start+1; i < end; i++) {
	if (can_attach(timings[i].syscall)) {
	    double gap = edata[i].dtiming - edata[last].dtiming;
	    if (gap > biggest_gap) {
		gap_start = last;
		gap_end = i;
		biggest_gap = gap;
	    }
	    last = i;
	}
    }
    if (details) {
	printf ("Biggest gap from %d to %d is %.3f\n", gap_start, gap_end, edata[gap_end].dtiming - edata[gap_start].dtiming);
    }
    if (partitions > 2 && biggest_gap >= total_time/partitions) {
	// Pivot on this gap
	total_time -= (edata[gap_end].dtiming - edata[gap_start].dtiming);
	partitions--;
	if (gap_start == start) {

	    print_timing (timings, edata, gap_start, gap_end, process_index);
	    return gen_timings (timings, edata, gap_end, end, partitions, process_index);
	}

	new_part = 0.5 + (partitions * (edata[gap_start].dtiming - edata[start].dtiming)) / total_time;
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

	gen_timings (timings, edata, start, gap_start, new_part, process_index);
	print_timing (timings, edata,  gap_start, gap_end, process_index);
	return gen_timings (timings, edata, gap_end, end, partitions - new_part, process_index);
    } else {
	// Allocate first interval
	goal = total_time/partitions;
	if (details) {
	    printf ("step: goal is %.3f\n", goal);
	}
	for (i = start+1; i < end; i++) {
	    if (can_attach(timings[i].syscall)) {
		if (edata[i].dtiming-edata[start].dtiming > goal || cnt_interval(edata, i, end) == partitions-1) {
		    print_timing (timings, edata,  start, i, process_index);
		    return gen_timings(timings, edata, i, end, partitions-1, process_index);
		}
	    }
	}
    }
    return -1;
}

int find_processes(map<u_int,u_int> &pid_to_index, 
		   map<u_int,u_int> &fork_process,
		   map<u_int,u_int> &fork_offset,
		   const char* dir, 
		   const struct replay_timing* timings,
		   const u_int num)
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

	//we're searching for calls to the clone() syscall
	while((res = parseklog_get_next_psr(log)) != NULL) {
	    if(res->psr.sysnum == 120 ) { 
		if(res->psr.flags == 0x14) 
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
		    //we're assuming it is a thread_fork in this case: 
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
			vector<u_int> &num_parts,			
			map<u_int, map<u_int,u_int>> pid_intervals,
			const struct replay_timing *timings,
			const int parts,
			const int num) { 

    //first initialize the num_el to 0
    u_int max = 0;
    double sum_of_times = 0;
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

    /* we assume that each partition takes 1 additional ut that was originally calculated 
     * this is the assumption that seems to be built into our calculation of edata (check generate_*)
     * and also makes it so that we have no negative sized partitions
     */

    for(auto iter = total_time_proc.begin(); iter != total_time_proc.end(); iter++) 
    { 
	(*iter)++;
	sum_of_times += *iter;
    }
    
    /*
     * The algorithm works as follows: we start by assigning each process 1 partition. Then, for each 
     * of the remaing partions (extra_parts), we assign partitions based upon a processes' weight,
     * which is just the process_time / total_time. We take the floor (int division), so any remaining
     * partions are assigned to the first however many processes. This isn't perfect, but it works
     */

    int extra_parts = parts - total_time_proc.size();
    int parts_left = extra_parts;

    for(auto iter = total_time_proc.begin(); iter != total_time_proc.end(); iter++) 
    {
	int curr_parts = (*iter / sum_of_times) * extra_parts;

	num_parts.push_back(1 + curr_parts);
	parts_left -= curr_parts;
    }

    /*
     * There is probably a much better way to do this here. We could do a priority queue 
     * which would give the bigger epochs even more weight. This might matter esp. at low 
     * numbers of partitions. 
     */
    for(auto iter = num_parts.begin(); iter != num_parts.end(); iter++) 
    {
	if(parts_left == 0) break;
	(*iter) += 1;
	parts_left --;
    }


    return 0;
}

int allocate_multiprocess_ds(vector<struct replay_timing *> &timings_vect,
			     vector<struct extra_data *> &edata_vect,
			     const vector<u_int> &num_el){

    
    for(auto index_iter = num_el.begin(); index_iter != num_el.end(); index_iter++) { 
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
    //fill index_inclusions with default values:  
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
//right now we have three parallel vectors... these could conceivably be structs. (probably should)
int create_multiprocess_ds(vector<u_int> &num_el,
			   vector<struct replay_timing *> &timings_vect,
			   vector<struct extra_data *> &edata_vect,			      
			   vector<u_int> &num_parts,
			   const struct replay_timing *timings,
			   const char* dir,
			   const int parts,
			   const int num){
    
    int rc = 0;
    map<u_int,u_int> pid_to_index;
    map<u_int, u_int> fork_process; //maps from index to fork process id
    map<u_int, u_int> fork_offset; //maps from index to fork offset
    map<u_int, map<u_int,u_int>> index_interval_inclusions;


    rc = find_processes(pid_to_index, fork_process, fork_offset, dir, timings, num);
    if(rc) { 
	printf("could not find_processes, rc %d\n", rc);
	return rc;
    }
    
    rc = build_intervals(fork_process, fork_offset, pid_to_index, index_interval_inclusions); 
    if(rc) { 
	printf("could not build_intervals, rc %d\n", rc);
	return rc;
    }

    rc = get_num_per_process(num_el, pid_to_index, num_parts, index_interval_inclusions, timings, parts, num);
    if(rc) { 
	printf("could not get_num_per_process, rc %d\n", rc);
	return rc;
    }

    rc = allocate_multiprocess_ds(timings_vect, edata_vect, num_el);
    if(rc) { 
	printf("could not allocate_multiprocess_ds, rc %d\n", rc);
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



    return 0; // on success
}

void generate_timings_for_process( struct replay_timing *timings,
				  struct extra_data* edata,
				  const u_int num_partitions,
				  const u_int num,
				  const char* dir, 
				  int process_index)
{
    // First, need to sum times for all threads to get totals for this group
    int total_time = 0;
    u_int i, j, k; 
    map<u_int,u_int> last_time;    

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
	if (can_attach(timings[i].syscall)) {
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
    gen_timings (timings, edata, 0, num-1, num_partitions, process_index);
}

int main (int argc, char* argv[])
{
    char filename[256];
    struct replay_timing* timings;
    struct extra_data* edata;
    struct stat st;
    int fd, rc, num, i, parts;

    if (argc < 3) {
	format ();
    }

    sprintf (filename, "%s/timings", argv[1]);
    parts = atoi(argv[2]);
//    if (parts < 2) {
//	fprintf (stderr, "Number of partitions must be greater than 1\n");
//	return -1;
//    }
    for (i = 3; i < argc; i++) {
	if (!strcmp(argv[i], "-g")) {
	    i++;
	    if (i < argc) {
		group_by = atoi(argv[i]);
	    } else {
		format();
	    }
	}
	if (!strcmp(argv[i], "-f")) {
	    i++;
	    if (i < argc) {
		filter_syscall = atoi(argv[i]);
	    } else {
		format();
	    }
	}
	if (!strcmp(argv[i], "-v")) {
	    details = 1;
	}
	if (!strcmp(argv[i], "-c")) {
	    use_ckpt = 1;
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
    vector<u_int> num_parts;
    vector<struct replay_timing *> timings_vect;
    vector<struct extra_data *> edata_vect;

    num = st.st_size/sizeof(struct replay_timing); 
    create_multiprocess_ds(num_el, timings_vect, edata_vect, num_parts, timings, argv[1], parts, num);
  
    if(details) { 
	for(u_int i = 0; i < num_el.size(); i++ ) 
	{	
	    struct replay_timing* curr_timings = timings_vect[i];
	    struct extra_data* curr_edata = edata_vect[i];
	
	    printf("num_parts %d\n", num_parts[i]);
	    printf("num_el %d\n", num_el[i]);
	    printf("timing info (edata has not yet been determined)\n");

	    if(details) {
		for (u_int j = 0; j < num_el[i]; j++) {
		    printf ("%d: pid %d syscall %lu type %d ut %u %.3f\n",j,
			    curr_timings[j].pid, curr_timings[j].index, curr_timings[j].syscall, 
			    curr_timings[j].ut, curr_edata[j].dtiming);
		}
	    }
	    printf ("----------------------------------------\n");
	}
    }

    printf ("%s\n", argv[1]);
    if (group_by > 0) printf ("group by %d\n", group_by);

    for(u_int i = 0; i < num_el.size(); i++ ) {
	generate_timings_for_process(timings_vect[i], edata_vect[i], num_parts[i], num_el[i], argv[1], i);
    }
    
    
    //cleanup_memory();  not implemented... muahaha, just deal with it kernel. 
    return 0;
}


