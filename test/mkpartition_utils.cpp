#include <sys/mman.h>
#include <cstdint>
#include "parseklib.h"
#include "../linux-lts-quantal-3.5.0/include/linux/pthread_log.h"


#include "mkpartition_utils.h"

using namespace std;

//#define DETAILS

unordered_set<short> bad_syscalls({120, 174, 125, 45}); 
///////////
//code to pull in the sampled instructions during recording
///////////
int static next_syscall(my_vect &v, u_long &im, FILE *f) 
{
    u_int curr_inst, rc;
    do { 
	rc = fread((void *)&curr_inst, sizeof(u_int), 1, f);
	if (im == 0) { 
	    im = curr_inst;
	}
	else if (curr_inst != 0) 
	    v.push_back(curr_inst);
    }while( rc > 0 && curr_inst != 0);    
    return rc;
}

int parse_instructions(vector<struct timing_data> &td, FILE *file){
    int rc;
    int count = -1;
    for (auto &t : td) { 
	count += 1;
	rc = next_syscall(t.sampled_insts, t.imisses, file);
	if (rc == 0 ) { 
	    assert(0 && "oh no, finished reading file?\n");
	}
    }
    return 0;
}


//////////
//code to pull in the trace data gathered from pin
//////////
static int map_next_file(char * filename, u_long* &log, u_long &data_size, u_long &mapsize, int &fd) { 

    struct stat64 st;
    fd = open(filename, O_RDONLY, 0644);
    
    if (fd < 0) {
	fprintf(stderr, "could not open trace shmem %s, errno %d\n", filename, errno);
	return fd;
    }
    
    u_long rc = fstat64(fd, &st);
    if (rc < 0) {
	fprintf(stderr, "could not stat %s, errno %d\n", filename, errno);
	return rc;
    }
    
    mapsize = st.st_size;
    if (mapsize%4096) mapsize += 4096-(mapsize%4096);
    
    log = (u_long *) mmap (0, mapsize, PROT_READ, MAP_SHARED, fd, 0);
    if (log == MAP_FAILED) {
	fprintf(stderr, "could not map %s, errno %d\n", filename, errno);
	return rc;
    }
    data_size = (u_long) log + st.st_size;
    return 0;
}

int parse_pin_instructions(my_map &ninsts, char* dir, u_int epochs)
{
    char filename[1024];
    u_long *log;
    u_long endat;
    u_long mapsize;
    int fd;
    int rc;

    for (u_int i = 0; i < epochs; i++) {
	sprintf (filename, "%s/trace-inst-%d",dir, i);
	rc = map_next_file(filename, log, endat, mapsize,fd);
	if (rc) { 
	    assert(0 && "couldn't map inst file!");
	}
	while ((u_long) log < endat) {
	    u_long insts = *log++;
	    u_long trace = *log++;
	    my_map::const_iterator found = ninsts.find(trace);
	    if (found != ninsts.end() && found->second != insts) { 		
		fprintf(stderr, "found 0x%lx already,but has %lu instead of %lu insts\n",trace,found->second,insts);
	    }
	    ninsts[trace] = insts;
	}
	munmap(log, mapsize);
	close(fd);
    }    
    return 0;
}
int parse_pin_traces(vector<struct timing_data> &td, char* dir, u_int epochs) { 

    char filename[1024];
    u_long *log;
    u_long endat;
    u_long mapsize;
    int fd;
    int rc;
    u_long syscall_cnt = 0;
    u_long cnt = 0;
    u_long num_merges = 0;
    u_long td_merges = 0; //current number of merges
	
    for (u_int i = 0; i < epochs; i++) {
	sprintf (filename, "%s/trace-exec-%d",dir, i);
	rc = map_next_file(filename, log, endat, mapsize,fd);
	cnt = 0;
	num_merges += td_merges;
	if (rc) { 
	    assert(0 && "couldn't map exec file!");
	}

	if (*log++) {
	    fprintf(stderr, "expect first entry to be 0\n");
	    return -1;
	}

	do {
	    u_long pid = *log++; // pid
	    u_long clock = *log++; // clock
	    u_long sysnum = *log++; //syscallnumber
	    td_merges = *log++; // num_merges
	    cnt++;

	    //update syscall_cnt
	    if (syscall_cnt > 0 && clock > td[syscall_cnt].start_clock) {

		syscall_cnt++;
		while(syscall_cnt < td.size() && (!td[syscall_cnt].should_track || td[syscall_cnt].start_clock < clock )) { 
		    fprintf(stderr, "this is irregular...");
		    fprintf(stderr, "(%lu, %lu %lu %lu), td: (%d %d, %lu %lu) %u\n", pid, clock, sysnum, td_merges, 
			    td[syscall_cnt].syscall, td[syscall_cnt].pid, td[syscall_cnt].start_clock, td[syscall_cnt].stop_clock, td[syscall_cnt].pin_traces.size());
		    td[syscall_cnt].num_merges = td[syscall_cnt-1].num_merges; //assume same num_merges as the previous

		    syscall_cnt++;

		}

		if (syscall_cnt == td.size()) {
		    fprintf(stderr, "better be the last one\n");
		    while (*log) {
			*log++;
		    }   
		    log++;
		    continue;
		}

		td[syscall_cnt].pin_traces.reserve(1024);
	    }

	    //update num_merges
	    td[syscall_cnt].num_merges = td_merges + num_merges; 
	    
	    //update pin_traces
	    while (*log) {
		u_long trace = *log++;
		td[syscall_cnt].pin_traces.push_back(trace);		
	    }
	
//	    fprintf(stderr, "(%lu, %lu %lu %lu), td: (%d %d, %lu %lu) %u\n", pid, clock, sysnum, td_merges, 
///		    td[syscall_cnt].syscall, td[syscall_cnt].pid, td[syscall_cnt].start_clock, td[syscall_cnt].stop_clock, td[syscall_cnt].pin_traces.size());
	
	    log++;
	    if (syscall_cnt == 0) syscall_cnt++; //weird caveat b/c first case if different

	} while ((u_long) log < endat);
	fprintf(stderr,"we found %lu entries syscalls, last index %lu\n",cnt, syscall_cnt);
	munmap(log, mapsize);
	close(fd);
    }    

    if (syscall_cnt < td.size()) { 
	fprintf(stderr, "huh, we only did %lu out of %u, cnt %lu\n",syscall_cnt, td.size(), cnt);
    }

    return 0;
}

static int map_next_file_part( struct pin_trace_iter &pti) { 

    char filename[1024];
    sprintf (filename, "%s/trace-exec-%d",pti.dir, pti.curr_epoch);

    struct stat64 st;
    pti.fd = open(filename, O_RDONLY, 0644);
    assert(pti.fd > 0);
    u_long rc = fstat64(pti.fd, &st);
    assert (rc == 0);

    pti.mapsize = (10 *1024 * 1024); //10MB
    pti.log = (u_long *) mmap (0, pti.mapsize, PROT_READ, MAP_SHARED, pti.fd, 0);
    assert(pti.log != MAP_FAILED);

    pti.filedone = st.st_size; 
    pti.fileoffset = 0;

    pti.bufstart = (u_long) pti.log;

    return 0;
}


static void increment_iter(struct pin_trace_iter &pti, bool fixunmap) { 
    //map in next region
    pti.log++;
//    fprintf(stderr, "log : %p, start %lx, left %lx (%lx)\n",pti.log, pti.bufstart, ((u_long)pti.log - pti.bufstart),pti.mapsize);

    if ( (u_long)pti.log - pti.bufstart >= pti.mapsize) { 
	if (fixunmap) { 
//	    fprintf(stderr, "ugly fixunmap logic!\n");
	    u_long old_offset = (u_long)pti.ctraces - pti.bufstart; //the old offset of ctraces
	    munmap((u_long*)pti.bufstart, pti.mapsize);

	    u_long oo_page = old_offset / 4096;
	    oo_page *=4096; //ugly math which is just rounding old_offset down to the nearest page. 
	    
	    pti.fileoffset += oo_page; //go to the nearest page
	
	    pti.log = (u_long *) mmap (0, pti.mapsize, PROT_READ, MAP_SHARED, pti.fd, pti.fileoffset);
	    pti.bufstart = (u_long) pti.log;	    
	    pti.ctraces = (u_long*)((u_long)pti.log + (old_offset - oo_page));  //old_offset - oo_page is the num of bytes past the page boundry

	    pti.log = (u_long *)(pti.bufstart + (pti.mapsize - oo_page));
	    
//	    fprintf(stderr, "old offset %lx, oo_page %lx, mapsize %lx, diff %lx bufstart %lx, ctraces %p, log %p\n",old_offset, oo_page, pti.mapsize, (pti.mapsize - oo_page), pti.bufstart, pti.ctraces, pti.log);

//	    Fprintf, "log mapping from (%lx %lx) of %lx\n",pti.fileoffset, pti.fileoffset + pti.mapsize - 1, pti.filedone);	    
	    assert(pti.log != MAP_FAILED);	
	
	}
	else {
	    munmap((u_long*)pti.bufstart, pti.mapsize);
	    pti.fileoffset += pti.mapsize;
	    pti.mapsize = (10 * 1024 * 1024); //reset this to a sane value
	    pti.log = (u_long *) mmap (0, pti.mapsize, PROT_READ, MAP_SHARED, pti.fd, pti.fileoffset);	    
	    pti.bufstart = (u_long) pti.log;
	    
	    assert(pti.log != MAP_FAILED);	
	}
    }
}

////////////        ///////////
//low memory api of the above//
///////////         ///////////
u_long pin_trace_iter_next( struct pin_trace_iter &pti)
{
    if (pti.fileoffset + ((u_long)pti.log - pti.bufstart) >= pti.filedone){ 
	if (pti.curr_epoch >= pti.epochs) return -1;
	int rc = 0;
	char filename[1024];

	munmap((u_long*)pti.bufstart, pti.mapsize);
	close(pti.fd);
	pti.num_merges += pti.cnmerges;

	pti.curr_epoch++;
	sprintf (filename, "%s/trace-exec-%d",pti.dir, pti.curr_epoch);
	rc = map_next_file_part(pti);
	assert (!rc);
	assert(!*pti.log);
	increment_iter(pti,false);
    }

    pti.cpid = *(pti.log); // pid
    increment_iter(pti,false);
    pti.cclock = *(pti.log); // clock
    increment_iter(pti,false);
    pti.csysnum = *(pti.log); //syscallnumber
    increment_iter(pti,false);
    pti.cnmerges = *(pti.log); // num_merges
    increment_iter(pti,false);
    pti.cnmerges += pti.num_merges; // add in the offset number of merges
    pti.ctraces = pti.log; // ctraces

    //iterate until next entry 
    while (*(pti.log)){
	increment_iter(pti,true);
    }

    increment_iter(pti,false);
   
    return 0;
}

int init_pin_trace_iter(struct pin_trace_iter &pti, 
			char *dir, 
			u_int epochs) { 
    
    pti.dir = dir;
    pti.epochs = epochs;
    pti.curr_epoch = 0;
    pti.num_merges = 0;

    //zero out all of the current values
    pti.cpid = pti.cclock = pti.csysnum = pti.cnmerges = 0;

    int rc = 0;
    rc = map_next_file_part(pti);
    assert (!rc);
    assert(!(*pti.log));
    
    pti.log++;
    return 0;	
}

int destroy_pin_trace_iter(struct pin_trace_iter &pti) { 
    munmap((u_long *)pti.bufstart, pti.mapsize);
    close(pti.fd);
}





/////////
//code which pulls in the data from the kres
/////////
static void pop_with_kres(vector<struct timing_data> &td, 
			  u_long &call_clock,
			  const u_int index,
			  const klog_result *res) { 

    td[index].start_clock = res->start_clock;
    td[index].stop_clock = res->stop_clock;

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
		const u_long stop_clock,
		const char* dir, 
		const char* fork_flags, 
		const unordered_set<pid_t> procs)
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
	pid = pid_pair.first;
	if (most_recent_clock >= stop_looking_index) stop_looking_index = numeric_limits<u_long>::max();
	most_recent_clock = 0; //indicates that we've found the first record for a process

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
	    if (lindex >= td.size()) { 
#ifdef DETAILS
		fprintf(stderr, "done looking for %d, lindex %u, size %u, sli %u, sc %lu\n",pid,lindex, td.size(), stop_looking_index,td[lindex].start_clock);
#endif
		break;
	    }

	    pop_with_kres(td, most_recent_clock, lindex, res);

	    if(td[lindex].start_clock > stop_looking_index){
#ifdef DETAILS
		fprintf(stderr, "done looking for %d, lindex %u, size %u, sli %u, sc %lu\n",pid,lindex, td.size(), stop_looking_index,td[lindex].start_clock);
#endif
		break;
	    }
	    td[lindex].should_track = true;

	    if (stop_clock && td[lindex].start_clock > stop_clock) {		
		td[lindex].should_track = false; 	       
	    }




	    //we found a fork
	    if (res->psr.sysnum == 120 && procs.count(res->retval) > 0) { 
#ifdef DETAILS		
		    fprintf(stderr,"%d, %lu (%u) forking %lu\n", td[lindex].pid, res->start_clock, lindex, res->retval);
#endif

		if (fork_flags[ff_index] == '1') { 
#ifdef DETAILS
		    fprintf(stderr, "we need to follow it!\n");
#endif
		    //stop tracking this pid, already covered all of its traced syscalls
		    td[lindex].forked_pid = res->retval; //this is important for can_attach logic
		    stop_looking_index = res->start_clock; 
		    pair<pid_t, u_long> new_pair = make_pair(res->retval, res->start_clock);
		    pids_to_track.push(new_pair);
		    ff_index++; // in what world does this not need to happen?
		    break; 
		}
		ff_index++;
	    }
	    //found a thread_fork
	    else if (res->psr.sysnum == 120) { 
#ifdef DETAILS
		    fprintf(stderr,"%d, %lu (%u) forking %lu\n", td[lindex].pid, res->start_clock, lindex, res->retval);
#endif
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
///////////
//code which pulls in data from the ulog
///////////
class ulog_data { 
public: 
    ulog_data(int f, u_long tc): fd(f), total_clock(tc) {};
    ulog_data(): fd(0), total_clock(0) {};
    int fd;
    u_long total_clock; //current clock_index w/in the ulog
}; 

static int open_ulog(const pid_t pid,
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

static int pop_with_ulog(vector<struct timing_data> &td, u_int td_index, ulog_data &udata) 
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
	if (!td[i].should_track) continue; //skip untracked calls
	if (td[i].start_clock == numeric_limits<u_long>::max()) { 
	    fprintf(stderr,"what have we here? index %d %d, (%lu, %lu)\n",
		    i,td[i].pid,td[i].start_clock, td[i].stop_clock);

	    }
	if (pid_fd_map.count(td[i].pid) == 0) { 
	    int fd = open_ulog(td[i].pid, dir);
	    ulog_data u(fd, 0);
	    pid_fd_map[td[i].pid] = u;
	}
	if (pid_fd_map[td[i].pid].fd > 0) 
	    pop_with_ulog(td, i, pid_fd_map[td[i].pid]);       

    }
    return 0;
}
////////////
//code that pulls in statistics from the timings file
////////////
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

void inline update_fft( vector<struct timing_data> &td, 
		       u_int &total_time,
		       map<pid_t, u_int> &last_time,
		       const u_int td_index) 
{ 
    pid_t pid = td[td_index].pid;
    auto iter = last_time.find(pid);
    if (iter == last_time.end()) {
	total_time += td[td_index].fft;
    } else {
	total_time += td[td_index].fft - iter->second;
    }
    last_time[pid] = td[td_index].fft;
    td[td_index].fft = total_time;
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
	//this means we have a bad syscall on the very first syscall, which evidently can happen (evince has this with a brk)
	//since the logic around the original fork covers from fork-> this sysall, we just need to block out things from the
	//start_clock onwards
	if (!td[td_index].call_clock) { 
	    td[td_index].call_clock = td[td_index].start_clock;	   
	}
	int i = 0;
	for (auto &t : td) 
	{
	    //if the record's attach clock occurs during this syscall
	    if (t.start_clock > td[td_index].call_clock &&
		t.start_clock < td[td_index].stop_clock) 
	    { 
//		fprintf(stderr, "flipping (%lu, %lu)'s can_attach b/c of %d at (%lu,%lu)\n",td[i].start_clock, td[i].stop_clock,td[td_index].syscall,td[td_index].call_clock,td[td_index].stop_clock);
		t.can_attach = false;
		t.blocking_syscall = td[td_index].syscall;
		t.blocking_pid = td[td_index].pid;
	    }
	    i++;
	}
    }

    //special case for the forked child. we check to make sure that forked_pid > 0, 
    //b/c if we aren't tracking this fork then it won't be above 0

    if (td[td_index].syscall == 120 && td[td_index].forked_pid > 0) 
    {
	u_long call_clock = td[td_index].start_clock; 
	u_int  forked_index = td_index+1;

	//update forked_index until we find the first entry of the child
	while (td[forked_index].pid != td[td_index].forked_pid) forked_index++;
	int i = 0;
	for (auto &t : td) 
	{

	    //if the record's attach clock occurs during the child's ret from fork
	    if (t.start_clock > call_clock &&
		t.start_clock < td[forked_index].start_clock)
	    { 
//		fprintf(stderr, "flipping %d's can_attach b/c of fork at (%lu,%lu)\n",i,call_clock,td[forked_index].start_clock);
		t.can_attach = false;
		t.blocking_syscall = 120; //b/c of a clone! 

	    }
	    i++;
	}       
    }   
}


int adjust_for_ckpts(vector<struct timing_data> &td,
		     struct ckpt *ckpts,
		     int ckpt_cnt){

    double ckpt_time = 0.0;
    int ckpt_index = 0;

    for (auto &t : td) { 
	if (t.start_clock >= ckpts[ckpt_index].rp_clock && 
	    ckpt_index < ckpt_cnt) { 
	    ckpt_index++;
	    ckpt_time = t.ftiming; 
	}
	t.ftiming -= ckpt_time;
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

    u_int total_fftime = 0;
    map<pid_t,u_int> last_fftime;    

    for (i = 0; i < td.size(); i++) {
	if (!td[i].should_track) { 
	    td[i].can_attach = false; //mark it as not attachable, and continue
	    continue; //critical
	}

	update_ut(td, total_time, last_time, i);
	update_fft(td, total_fftime, last_fftime, i);
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

    for (i = 0; i < td.size(); i++) {
	for (j = i+1; j < td.size(); j++) {
	    if (td[i].fft != td[j].fft) break;
	}
	for (k = i; k < j; k++) {
	    td[k].ftiming = (double) td[k].fft + (double) (k-i) / (double) (j-i);
	}
	i = j-1;
    }

    return 0;
}
