#include <limits>
#include <sys/time.h>
#include <gperftools/profiler.h>

#include "generate_splits_utils.h"
#include "bitmap.h"
using namespace std;


vector<struct ckpt> ckpts;
static int group_by = 0;
int filter_syscall = 0;
int use_ckpt = 0, do_split = 0, details = 0, do_repartition = 0;
int lowmem = 0;
double ut_arg = 0.0;
double ui_arg = 0.0;
my_map ninsts; //the number of instructions based on trace_id

#define MAX_ADDR 0xc0000000
#define PAGE_BITS 4096

typedef PagedBitmap<MAX_ADDR,PAGE_BITS> bitmap;
void format ()
{
    fprintf (stderr, "Format: generage_splits <replay_file> <# of partitions> <timing data file>\
[-f filter syscall] [-s split at user-level] [-v verbose]\
[-c ckpt_file] [-ut_arg user_time_arg] [-ui_arg instructions_arg]\
[-r pin_trace_dir pin_trace_epochs] [-i sampled_instructions_file] [--fork fork_flags] \n");
    exit (22);
}


//model created by correlation analysis
static double estimate_dift(vector<struct timing_data> &td, int i, int j)
{ 

    double utime = td[j].dtiming - td[i].dtiming;
    u_long num_merges = td[j].num_merges - td[i].num_merges;
    double rv; 
    std::unique_ptr<bitmap> uinsts(new bitmap);
    int    uinsts_cnt = 0;
    u_long total_count = 0;
    u_long unique_count = 0;
    

    if (do_repartition) {
	for (int tdi = i; tdi < j; ++tdi) {
	    total_count += td[tdi].pin_traces.size();
	    
	    for (auto &inst : td[tdi].pin_traces) {
		if (uinsts->testAndSet(inst)) { 
		    unique_count ++;
		    uinsts_cnt += ninsts[inst]; //maybe this is slow? 
		} 
	    }
	}
	rv = (2.5 * td[i].ftiming) + (ut_arg * utime) + 
	    (ui_arg * uinsts_cnt) + (.000058 * num_merges);
    }
    else {   
	for (int tdi = i; tdi < j; ++tdi) { 
	    for (auto inst : td[tdi].sampled_insts) { 
		if (uinsts->testAndSet(inst)) { 
		    uinsts_cnt ++; //added another one! 
		}
	    }
	}

	rv = (2.5 * td[i].ftiming) + (ut_arg * utime) + (ui_arg * uinsts_cnt);
    }

    return rv;
}

static double estimate_dift(vector<struct timing_data> &td, 
			    int i, 
			    int j,
			    int uinsts_cnt)
{ 
    double utime = td[j].dtiming - td[i].dtiming;    
    u_long num_merges = td[j].num_merges - td[i].num_merges;
    double rv = -1;
    if (do_repartition) { 
	rv = (2.5 * td[i].ftiming) + (ut_arg * utime) + (ui_arg * uinsts_cnt) + (.000058 * num_merges);	
    }
    else { 
	rv = (2.5 * td[i].ftiming) + (ut_arg * utime) + (ui_arg * uinsts_cnt);
    }

    return rv;
}

static void add_syscall(vector<struct timing_data> &td, 
			int i, 
			bitmap &uinsts,
			int &uinsts_cnt){

    int rc = 0;
    if (do_repartition) { 
	for (auto inst : td[i].pin_traces) { 
	    if (uinsts.testAndSet(inst)) {
		uinsts_cnt += ninsts[inst];
	    } 
	}   
    }
    else {
	for (auto inst : td[i].sampled_insts) { 
	    if (uinsts.testAndSet(inst)) { 
		uinsts_cnt ++;
	    } 
	}   
    }
}


static void print_parts(vector<struct timing_data> &td, vector<struct partition> &parts, char *fork_flags) 
{
    int count = 0;
    for (auto p : parts) { 
	printf ("%5d %s %6lu %s %6lu ",p.pid, p.start_level, p.start_clock,p.stop_level,p.stop_clock);
	++count;

	//handle filter syscall (not sure how this works) 
	if (filter_syscall > 0) {
	    if ((u_long) filter_syscall > td[p.start_i].index && (u_long) filter_syscall <= td[p.stop_i].index) {
		printf (" %6lu", filter_syscall-td[p.start_i].index+1);
		fprintf (stderr," %6lu", filter_syscall-td[p.start_i].index+1);
	    } else {
		printf (" 999999");
		fprintf (stderr," 999999");
	    }
	} else {
	    printf ("      0");
	}
	
	//handle using ckpts
	if (use_ckpt > 0) {
	    int i;
	    for (i = 0; i < ckpts.size(); i++) {
		if (p.start_clock <= ckpts[i].rp_clock) {
		    break;
		}
	    }
	    if (i > 0) {
		printf (" %lu", ckpts[i-1].rp_clock);
	    } else {
		printf ("      0");
	    }	    
	} else {
	    printf ("       0");
	}
	
	//handle fork flags
	if (strnlen(fork_flags, 128) > 0){
	    printf (" %s\n", fork_flags);
	}
	else {
	    printf (" 0\n");
	}
       		
	fprintf(stderr, "\n");



    }
}

static double get_total(vector<struct timing_data> &td, 
			vector<struct partition> &parts, 
			u_int start,
			u_int stop) 
{
    double total = 0;
    for (u_int i = start; i < stop; ++i) {
	struct partition &p = parts[i];
	
	//only count user-level runs once
	if (!strcmp(p.stop_level, "k")) { 
	    double dift = estimate_dift(td, p.start_i, p.stop_i);	
//	    fprintf(stderr, "%u (%lu,%lu): %lf\n",i,td[p.start_i].start_clock, td[p.stop_i].start_clock,dift);
	    total += dift;
	}
    }

    return total;
}


static u_int cnt_interval (vector<struct timing_data> &td, int start, int end)
{
    u_int last_aindex = 0;
    for (int i = end; i > start; --i) { 
	if (td[i].aindex > 0) {
	    last_aindex = td[i].aindex;
	    break;
	}
    }
    return last_aindex - td[start].aindex;
}

static void add_part(pid_t pid,
		     u_long start_clock, 
		     const char* start_level,
		     u_long stop_clock, 
		     const char* stop_level,
		     u_int start,
		     u_int stop,
		     vector<struct partition> &s) {

    struct partition newp;

    if(start > stop) { 
	fprintf(stderr, "hmm, how'd we get here?\n");
    }
    assert(start < stop);
    assert(start_clock < stop_clock);
	

    newp.pid = pid;
    newp.start_clock = start_clock;
    newp.stop_clock = stop_clock;
    sprintf(newp.start_level,"%s",start_level);
    sprintf(newp.stop_level,"%s",stop_level);



    newp.start_i = start;
    newp.stop_i = stop;


//    fprintf(stderr,"add_part number %lu \n", s.size());

    s.push_back(newp);
}

static void add_kpart(vector<struct timing_data> &td, 		      
		      u_long start, 
		      u_long end, 
		      vector<struct partition> &s) {

    add_part(td[start].pid, td[start].start_clock, "k",td[end].start_clock,"k",start,end, s);
}

static void add_uparts(vector<struct timing_data> &td, 
		       u_long start,
		       u_long end,
		       u_int num_splits,
		       vector<struct partition> &s) { 

    //floor of number of clock ticks per split
    u_long intvl = (td[end].start_clock - td[start].start_clock) / num_splits;
    u_long this_clock;

    fprintf(stderr, "splitting into %u piecs, intvl is %lu\n",num_splits,intvl);

    add_part(td[start].pid, td[start].start_clock, "k", td[start].start_clock + intvl, "u",start,end,s);
    this_clock = td[start].start_clock + intvl;

    for (u_int i = 1; i < num_splits - 1; ++i) { 
	add_part(td[start].pid, this_clock, "u", this_clock + intvl, "u",start,end,s);
	this_clock += intvl;
    }
    add_part(td[start].pid, this_clock, "u", td[end].start_clock, "k",start,end,s);
    

}
static void add_big_part(vector<struct timing_data> &td, 
			 u_long start,
			 u_long stop,
			 double goal,
			 vector<struct partition> &s) 
{
    double est = estimate_dift(td, start, stop);
    fprintf(stderr, "%lf :(%lu (%lu) ,%lu (%lu)) blocked cuz",est,start, td[start].start_clock,stop,td[stop].start_clock);
    //print out reason for block
    for (u_int k = start+1; k < stop; ++k) {
	if (!td[k].can_attach) 
	    fprintf(stderr, " %d",td[k].blocking_syscall);
	else if (!td[k].should_track){ 
	    fprintf(stderr, " we aren't tracking!");
	}
	else {
	    fprintf(stderr, " (%d,huh?)",k);
	}
    }
    fprintf(stderr, "\n");


    // maybe we can split this sucker
    if(do_split) { 
	if (stop > start + 1) { 
	    fprintf(stderr, "this is more than one syscall... careful if this is multithreaded!\n");
	}
	u_int split = (est / goal)+1; //take the ceil of the number of parititions this *should* have assigned to it
	
	if (split > 1) add_uparts(td,start,stop,split,s);
	else add_kpart(td, start, stop,s);		       
    }
    else { 
	add_kpart(td, start, stop,s);		       
    }
}

static void fi_rest(vector<struct timing_data> &td,
		    u_int partitions,
		    u_int i,
		    vector<struct partition> &s){ 

//    fprintf(stderr, "fi_rest\n");
    u_int lasti = td.size() - 1;
    while(!td[lasti].aindex && lasti >= 0) { 
	--lasti;
    }

    if (!partitions - s.size()) { 
	//shoot... I guess just throw it all in
	add_kpart(td, i,lasti, s);
	return;
    }
    
    u_int num_sys_left = lasti;
    u_int intv = num_sys_left / (partitions - s.size()); 
    u_int num_parts_left = partitions - s.size();
    u_int curr_index = i;


    for (uint j = 0; j < (num_parts_left - 1); ++j) { 
	add_kpart(td, curr_index, curr_index + intv, s);
	curr_index += intv;
    }
    add_kpart(td, curr_index, lasti, s);
   
}

static double do_iteration(vector<struct timing_data> &td,
			   u_int partitions,
			   double total_time,
			   vector<struct partition> &s)
{  

    u_int i = 0, estart = 0, last_syscall = 0;
    std::unique_ptr<bitmap> uinsts(new bitmap);
    int uinsts_cnt = 0; 

    double gap = 0.0, last_gap = 0.0;
    double goal = total_time / partitions;
    
    double max_est = 0.0;

    u_int lasti = td.size() - 1;
    while(!td[lasti].aindex && lasti >= 0) { 
	--lasti;
    }

    do { 
	if (td[i].can_attach && td[i].should_track &&
	    td[estart].start_clock < td[i].start_clock ) { //you wouldn't think I have to specify that last one... but for some reason, yes. yes I do
	    last_gap = gap;
	    gap = estimate_dift(td, estart, i, uinsts_cnt);
	    
	    /*
	     * do the logic for big syscalls here!
	     * this means that we just added more than a goal's worth
	     */
	    if (gap - last_gap > goal) { /*might want a fract (like .8) on that goal val*/
		if (do_split || estart >= last_syscall) { 
		    add_big_part(td, estart,i,goal, s); //add in the big partitions	
		    total_time -= gap;
		}
		else { 
		    add_kpart(td, estart, last_syscall, s); //add the last piece as an epoch

		    add_big_part(td, last_syscall,i,goal, s); //add in the big partitions
		    total_time -= estimate_dift(td, estart, last_syscall);
		    total_time -= estimate_dift(td, last_syscall,i);
		    
		}

		uinsts->clear();
		uinsts_cnt = 0;
		
		
		if (total_time < 0) {
		    max_est = numeric_limits<double>::max();
		    fi_rest(td, partitions, i, s);
		    estart = lasti; //signal that we're done 
		}


		goal = total_time / (partitions - s.size());
		estart = i;
	    }
	    
	    else if (gap > goal || cnt_interval(td, i, lasti) == partitions - 1) {

		//figure out if the last split or this split is closer to the goal:
		double ldiff = goal - last_gap;
		double tdiff = gap - goal; 
		//need to find last positibe attach point
		u_int oldi = i-1; 
		while(oldi >= estart && !td[oldi].aindex) { 
		    --oldi;		    
		}
		
		if (oldi > estart && ldiff < tdiff) { 
		    //we should use the last gap
		    i  = oldi;
		    gap = last_gap; 
		}
	       
		add_kpart(td,  estart, i, s);

		//update our goal and total_time
		total_time -= gap;
		if (total_time < 0) {
		    max_est = numeric_limits<double>::max();
		    fi_rest(td, partitions,i, s);
		    estart = lasti; //signal that we're done 
		}
		goal = total_time / (partitions - s.size());
//		fprintf(stderr, "\t(%lu,%lu): (%lf %lf %d) gap %lf, new goal %lf, size %lu, remaining %u\n",td[estart].start_clock,td[i].start_clock, td[i].ftiming, td[i].dtiming-td[estart].dtiming,uinsts_cnt, gap, goal, s.size(), partitions);

		//prepare for next round!
		if (gap > max_est){
		    max_est = gap;
		}						
		uinsts->clear();
		uinsts_cnt = 0;
		gap = 0;
		estart = i;
	    }
	    last_syscall = i;
	}

	//if this syscall matters, add it to the current count
	if (td[i].should_track){
	    add_syscall(td, i, *(uinsts),uinsts_cnt);
	}
	++i;
    }while (i < lasti+1 && s.size() < partitions - 1);

    if (estart < lasti){//s.size() < partitions) {
//	fprintf(stderr, "\tlast one (%lu,%lu)\n",td[estart].start_clock,td[lasti].start_clock);
	add_kpart(td, estart, lasti,s);
	gap = estimate_dift(td,estart,lasti); //doesn't use add_syscall.. it should
	if (gap > max_est){
	    max_est = gap;
	}
    }
    return max_est;
}



int generate_timings(vector<struct timing_data> &td,
		     u_int num_parts,
		     char *fork_flags)
{        
    u_int lasti = td.size() - 1;
    while(!td[lasti].aindex && lasti >= 0) { 
	--lasti;
    }
    
    double curr_est = estimate_dift(td, 0, lasti);
    fprintf(stderr, "estmated dift?\n");
    double goal = curr_est / num_parts;
    double min_big = numeric_limits<double>::max();
    vector<struct partition> parts;
    vector<struct partition> best_parts;

    for (int j = 0; j < 30; ++j){
	parts.clear();

	fprintf(stderr, "iteration %d\n",j);
//	exit(2);
	double curr_max = do_iteration(td, num_parts, curr_est, parts);       

	if (curr_max < min_big && j > 5 && parts.size() == num_parts){
	    min_big = curr_max;
	    best_parts = parts;
//	    fprintf(stderr, "new best! %lf\n",min_big);
	}
	
	curr_est = get_total(td,parts, 0, parts.size());    

	goal = curr_est / num_parts;
//	fprintf(stderr, "ce %lf, num %lu, ave %lf, goal %lf, cm %lf\n",curr_est, 
//		parts.size(), curr_est / parts.size(), goal, curr_max);


    }

    print_parts(td,best_parts, fork_flags);   
    return 0;
}



int main (int argc, char* argv[])
{
    struct stat st;
    int fd, rc, num, i, parts;
    char following[256];   
    FILE *file;
    
    char timing_fname[256];    //filename where the timing data is stored
    char inst_fname[256];      //filename where the instruction data is stored (recording metrics)
    char ckpt_fname[256];      //filename where a list of ckpts are storedtion data is stored (recording metrics)
    

    char  trace_dir[256];     //directory where the pin gathered traces are stored
    u_int trace_epochs = -1;  //number of files for the pin gathered traces 
    
    vector<struct timing_data> td; //how big is this... can it not fit on the stack? 


    if (argc < 3) {
	format ();
    }
    following[0] = 0; //assume this isn't provided, fix it if it is. 

    
    parts = atoi(argv[2]);
    sprintf (timing_fname, "%s", argv[3]);

    for (i = 4; i < argc; i++) {
	if (!strcmp(argv[i], "-f")) {
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
	    i++;
	    if (i < argc) {
		strcpy(ckpt_fname,argv[i]);
		use_ckpt = 1;
	    } else {
		format();
	    }
//	    i++;
	}
	else if(!strcmp(argv[i], "--fork")) { 
	    i++;
	    if (i < argc) {
		strcpy(following,argv[i]);
	    } else {
		format();
	    }	
	}
	else if (!strcmp(argv[i], "-s")) {
	    do_split = 1;
	}
	else if (!strcmp(argv[i], "--ut_arg")) {
	    i++;
	    ut_arg = atof(argv[i]);
	}
	else if (!strcmp(argv[i], "--ui_arg")) {
	    i++;
	    ui_arg = atof(argv[i]);
	}
	else if (!strcmp(argv[i],"-r")){	    
	    i++;
	    if (i < argc) {
		strcpy(trace_dir,argv[i]);
		i++;
		if (i < argc) {
		    trace_epochs = atoi(argv[i]);
		    do_repartition = 1;
		} else {
		    format();
		}
	    } else {
		format();
	    }
	}
	else if (!strcmp(argv[i],"-i")){
	    i++;
	    if (i < argc) {
		strcpy(inst_fname,argv[i]);
		i++;
	    } else {
		format();
	    }
	}
    }

    file = fopen (timing_fname, "r");
    if (file == NULL) { 
	fprintf (stderr, "Cannot open timings file %s,  errno=%d\n", 
		 timing_fname, errno);
	return -1;
    }
    rc = read_timing_data(td, file);



    if (use_ckpt) { 
	file = fopen (ckpt_fname, "r");
	if (file == NULL) { 
	    fprintf (stderr, "Cannot open ckpt file %s,  errno=%d\n", 
		     ckpt_fname, errno);
	    return -1;
	}
	rc = read_ckpts(ckpts, file);
	adjust_for_ckpts(td,ckpts);
    }


    if (!do_repartition) { 
	file = fopen (inst_fname,  "r");
	if (file == NULL) { 
	    fprintf (stderr, "Cannot open instructions file %s,  errno=%d\n", 
		     inst_fname, errno);
	    return -1;
	}

	rc = parse_instructions(td, file); //parses the instruction logs
    }
    else { 
	rc = parse_pin_instructions(ninsts,trace_dir, trace_epochs);
	rc = parse_pin_traces(td,trace_dir, trace_epochs);
    }
       
//    fprintf(stderr, "starting gen_timings\n");
    printf ("%s\n", argv[1]);
    generate_timings(td, parts, following);


    return 0;
}

