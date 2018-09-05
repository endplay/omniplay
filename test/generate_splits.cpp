#include <limits>
#include "mkpartition_utils.h"


using namespace std;

extern int use_ckpt, do_split, details;
extern int ckpt_cnt;
extern int lowmem;
extern struct ckpt ckpts[MAX_CKPT_CNT];
extern int filter_syscall;
extern int do_repartition;
extern my_map ninsts;

extern double ut_arg;
extern double ui_arg;


struct pin_trace_iter pti;

static void clear_pt(vector<struct timing_data> &td, int start, int end)
{
    for (int tdi = start; tdi < end; ++tdi) { 
	vector<u_int>().swap(td[tdi].pin_traces); //clear away all those instructions. 
//	td[tdi].pin_traces.clear();
    }
}


struct myHash {                                                                                                        
    size_t operator() (const uint32_t &a) const {                                                                      
	size_t rtn = a ^ (a >> 11);                                                                                    
	return rtn;                                                                                                
    }                                                                                                      
};  

//model created by correlation analysis
static double estimate_dift(vector<struct timing_data> &td, int i, int j)
{ 

    double utime = td[j].dtiming - td[i].dtiming;
    u_long num_merges = td[j].num_merges - td[i].num_merges;
    double rv; 
    int rc = 0;
    unordered_set<uint32_t,myHash> uinsts(36228);
    int    uinsts_cnt = 0;

    u_long total_count = 0; 

    if (do_repartition) {
	for (int tdi = i; tdi < j; ++tdi) { 
	    if(lowmem) {
		if(td[tdi].pin_traces.empty()) {
		    while (!rc && pti.cclock <= td[tdi].start_clock) { 
			while (*(pti.ctraces)) {
//			    td[tdi].pin_traces.push_back(*(pti.ctraces)); //add them to our local set
			    total_count += 1;
			    if (uinsts.insert(*(pti.ctraces)).second) { //add them to global set
				uinsts_cnt += ninsts[*(pti.ctraces)];
			    }
			    pti.ctraces++;
			}	    
			rc = pin_trace_iter_next(pti);
			if (rc) fprintf(stderr, "we're done with pti!\n");
		    }
		}
		else { 
		    fprintf(stderr, "using cached pin_traces\n");
		    for (auto inst : td[tdi].pin_traces) { 
			if (uinsts.insert(inst).second) { 
			    uinsts_cnt += ninsts[inst]; //maybe this is slow? 
			} 
		    }		    
		}
	    }
	    else {
		for (auto inst : td[tdi].pin_traces) { 
		    if (uinsts.insert(inst).second) { 
			uinsts_cnt += ninsts[inst]; //maybe this is slow? 
		    } 
		}
	    }
	}
	rv = (2.5 * td[i].ftiming) + (ut_arg * utime) + (ui_arg * uinsts_cnt) + (.000058 * num_merges);	;	
    }
    else {   
	for (int tdi = i; tdi < j; ++tdi) { 
	    for (auto inst : td[tdi].sampled_insts) { 
		uinsts.insert(inst);
	    }
	}

	rv = (2.5 * td[i].ftiming) + (ut_arg * utime) + (ui_arg * uinsts.size());	
    }
    
    fprintf(stderr,"total_count %lu ucount %u lf %lf mlf %lf bc %u mbc %u\n",total_count, uinsts.size(), uinsts.load_factor(), uinsts.max_load_factor(), uinsts.bucket_count(), uinsts.max_bucket_count());

    return rv;
}



static double estimate_dift_urun(vector<struct timing_data> &td, 
				 int i,
				 int j, 
				 int urun){

    double utime = td[j].dtiming - td[i].dtiming;
    u_long num_merges = td[j].num_merges - td[i].num_merges;
    double rv; 
    int rc = 0;
    my_set uinsts(1024);
    int    uinsts_cnt = 0;

    u_long total_count; 

    if (do_repartition) {
	for (int tdi = i; tdi < j; ++tdi) { 
	    if(lowmem) {
		if(td[tdi].pin_traces.empty()) {
		    while (!rc && pti.cclock <= td[tdi].start_clock) { 
			while (*(pti.ctraces)) {
//			    td[tdi].pin_traces.push_back(*(pti.ctraces)); //add them to our local set
			    total_count += 1;
			    if (uinsts.insert(*(pti.ctraces)).second) { //add them to global set
				uinsts_cnt += ninsts[*(pti.ctraces)];
			    }
			    pti.ctraces++;
			}	    
			rc = pin_trace_iter_next(pti);
			if (rc) fprintf(stderr, "we're done with pti!\n");
		    }
		}
		else { 
		    fprintf(stderr, "using cached pin_traces\n");
		    for (auto inst : td[tdi].pin_traces) { 
			if (uinsts.insert(inst).second) { 
			    uinsts_cnt += ninsts[inst]; //maybe this is slow? 
			} 
		    }		    
		}
	    }
	    else {
		for (auto inst : td[tdi].pin_traces) { 
		    if (uinsts.insert(inst).second) { 
			uinsts_cnt += ninsts[inst]; //maybe this is slow? 
		    } 
		}
	    }
	}
//	fprintf(stderr, "ftiming %lf, utime %lf, uinsts_cnt %d, num_merges %lu\n",td[i].ftiming, utime, uinsts_cnt, num_merges); 
	rv = (2.5 * td[i].ftiming) + (ut_arg * utime) + (ui_arg * uinsts_cnt * urun) + (.000058 * num_merges);
    }
    else {   
	for (int tdi = i; tdi < j; ++tdi) { 
	    for (auto inst : td[tdi].sampled_insts) { 
		uinsts.insert(inst);
	    }
	}
	rv = (2.5 * td[i].ftiming) + (ut_arg * utime) + (ui_arg * uinsts.size() * urun);	
    }
    return rv;
}


static double get_instrumentation_est(vector<struct timing_data> &td, 
				      int i, 
				      int j) {

    double rv; 
    my_set uinsts(1024);
    int    uinsts_cnt = 0;

    if (do_repartition) {
	for (int tdi = i; tdi < j; ++tdi) { 
	    for (auto inst : td[tdi].pin_traces) { 
		if (uinsts.insert(inst).second) { 
		    uinsts_cnt += ninsts[inst]; //maybe this is slow? 
		} 
	    }
	}
    	rv = (ui_arg * uinsts_cnt);
    }
    else {   
	for (int tdi = i; tdi < j; ++tdi) { 
	    for (auto inst : td[tdi].sampled_insts) { 
		uinsts.insert(inst);
	    }
	}
	rv = ui_arg * uinsts.size();
    }
    return rv;
}




static double estimate_dift(vector<struct timing_data> &td, 
			    int i, 
			    int j,
			    int uinsts_cnt)
{ 
    double utime = td[j].dtiming - td[i].dtiming;    
    u_long num_merges = td[j].num_merges - td[i].num_merges; //ah-ha!
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
			my_set &uinsts,
			int &uinsts_cnt){

    int rc = 0;
    if (do_repartition) { 
	    if(lowmem) {
		if(td[i].pin_traces.empty()) {
		    while (!rc && pti.cclock <= td[i].start_clock) { 
			while (*(pti.ctraces)) {
			    td[i].pin_traces.push_back(*(pti.ctraces)); //add them to our local set
			    if (uinsts.insert(*(pti.ctraces)).second) { 
				uinsts_cnt += ninsts[*(pti.ctraces)];
			    }
			    (pti.ctraces)++;
			}	    
			rc = pin_trace_iter_next(pti);
			if (rc) fprintf(stderr, "we're done with pti!\n");
		    }
		}
		else { 
		    fprintf(stderr, "%d (%lu): using cached pin_traces pti %lu\n", i, td[i].start_clock,pti.cclock);
		    for (auto inst : td[i].pin_traces) { 
			if (uinsts.insert(inst).second) { 
			    uinsts_cnt += ninsts[inst]; //maybe this is slow? 
			} 
		    }		    		    
		}
	    }

	for (auto inst : td[i].pin_traces) { 
	    if (uinsts.insert(inst).second) { 
		uinsts_cnt += ninsts[inst];
	    } 
	}   
    }
    else {
	for (auto inst : td[i].sampled_insts) { 
	    if (uinsts.insert(inst).second) { 
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
	fprintf (stderr,"%d %5d %s %6lu %s %6lu ",count,p.pid, p.start_level, p.start_clock,p.stop_level,p.stop_clock);
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
	    fprintf (stderr,"      0");
	}
	
	//handle using ckpts
	if (use_ckpt > 0) {
	    int i;
	    for (i = 0; i < ckpt_cnt; i++) {
		if (p.start_clock <= ckpts[i].rp_clock) {
		    break;
		}
	    }
	    if (i > 0) {
		printf (" %6s", ckpts[i-1].name);
	    } else {
		printf ("      0");
	    }	    
	} else {
	    printf ("       0");
	}
	
	//handle fork flags
	if (strnlen(fork_flags, 128) > 0){
	    printf (" %s\n", fork_flags);
	    fprintf (stderr," %s", fork_flags);
	}
	else {
	    printf (" 0\n");
	    fprintf (stderr," 0");
	}
	
	my_set uinsts(1024); 
	int uinsts_cnt = 0;
	if (!lowmem) { 
	    for (int tdi = p.start_i; tdi < p.stop_i; ++tdi) { 
		for (auto inst : td[tdi].pin_traces) { 
		    if (uinsts.insert(inst).second) { 
			uinsts_cnt += ninsts[inst];
		    } 
		}
	    }
	}
	double utime = td[p.stop_i].dtiming - td[p.start_i].dtiming;
	u_long num_merges = td[p.stop_i].num_merges - td[p.start_i].num_merges; //ah-ha!
    }


}

static double get_total(vector<struct timing_data> &td, 
			vector<struct partition> &parts, 
			u_int start,
			u_int stop) 
{
    
    int urun = 0;

    double total = 0;
    if(lowmem)	clear_pt(td, 0, parts[stop -1].stop_i); //always clear away all of our cached_pin_traces
    for (u_int i = start; i < stop; ++i) {
	struct partition &p = parts[i];

	

	//only count user-level runs once
	if (!strcmp(p.stop_level, "k")) { 
	    double dift;
	    if(urun) { 
		urun++; //add in this one
		fprintf(stderr, "found %d uruns!\n", urun);
		dift = estimate_dift_urun(td, p.start_i, p.stop_i, urun);
		urun = 0;
	    }
	    else { 
		dift = estimate_dift(td, p.start_i, p.stop_i);	
	    }
	    total += dift;
	}
	else { 
	    urun++;
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
    s.push_back(newp);
}

static void add_kpart(vector<struct timing_data> &td, 		      
		      u_long start, 
		      u_long end, 
		      vector<struct partition> &s) {


    add_part(td[start].pid, td[start].start_clock, "k",td[end].start_clock,"k",start,end, s);
    //clear out the pin_insts if we're on lowmem
    if (lowmem) { 
	clear_pt(td, start, end);
    }

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
static double add_big_part(vector<struct timing_data> &td, 
			 u_long start,
			 u_long stop,
			 double goal,
			 int max_parts,
			 vector<struct partition> &s) 
{
    int  splits = 1;
    double est, epoch_time;

    // maybe we can split this sucker
    if(do_split) { 

	//iterate through splits until we can split such that we're less than the goal!
	if (get_instrumentation_est(td, start, stop) > goal) { 
	    fprintf(stderr, "whoops, itime %lf is greater than our goal %lf!\n", 
		    get_instrumentation_est(td,start,stop),
		    goal);

	    est = estimate_dift(td, start,stop);
	    splits = est / goal + 1; 
	}
	else { 
	    do { 
		splits++;
		est = estimate_dift_urun(td, start, stop, splits);
		epoch_time = (est / splits);
		
	    }while (splits < max_parts - s.size() -1 && epoch_time > goal);
	}
	add_uparts(td,start,stop,splits,s);
    }
    else { 
	add_kpart(td, start, stop,s);		       
    }
    return est;
}

static void fi_rest(vector<struct timing_data> &td,
		    u_int partitions,
		    u_int i,
		    vector<struct partition> &s){ 

    fprintf(stderr, "fi_rest\n");
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
    my_set uinsts;
    int uinsts_cnt = 0; 

    double gap = 0.0, last_gap = 0.0;
    double goal = total_time / partitions;
    
    double max_est = 0.0;
    u_int last_attach_point = 0;

    u_int lasti = td.size() - 1;
    while(!td[lasti].aindex && lasti >= 0) { 
	--lasti;
    }


    fprintf(stderr, "do_iteration, total_time %lf, goal %lf\n",total_time, goal);

    do { 
	if (td[i].can_attach && td[i].should_track &&
	    td[estart].start_clock < td[i].start_clock ) { //you wouldn't think I have to specify that last one... but for some reason, yes. yes I do
	    last_gap = gap;
	    gap = estimate_dift(td, estart, i, uinsts_cnt); //need here
	    
	    /*
	     * do the logic for big syscalls here!
	     * this means that we just added more than a goal's worth
	     */
	    if (gap - last_gap > goal) { 
		if (do_split || estart >= last_syscall) { 
		    gap         = add_big_part(td, estart,i,goal, partitions,s); //add in the big partitions	
		    total_time -= gap;
		}
		else { 
		    add_kpart(td, estart, last_syscall, s); //add the last piece as an epoch
		    add_big_part(td, last_syscall,i,goal, partitions, s); //add in the big partitions
		    if(!lowmem){
			total_time -= estimate_dift(td, estart, last_syscall);
			total_time -= estimate_dift(td, last_syscall,i);
		    }
		    else{
			total_time -= gap; //we can't look at past est_difts if we're in lowmem mode.
		    }
		}

		uinsts.clear();
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

		//we can't do this if we're using lowmem b/c the iteration through the pti is strictly forward
//		if (!lowmem) { 
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
//		}
	       
		add_kpart(td,  estart, i, s);


		//update our goal and total_time
		total_time -= gap;
		if (total_time < 0) {
		    max_est = numeric_limits<double>::max();
		    fi_rest(td, partitions,i, s);
		    estart = lasti; //signal that we're done 
		}
		goal = total_time / (partitions - s.size());

		//prepare for next round!
		if (gap > max_est){
		    max_est = gap;
		}						
		uinsts.clear();
		uinsts_cnt = 0;
		gap = 0;
		estart = i;
	    }
	    last_syscall = i;
	}

	//so... lets see now. 
	if (td[i].should_track){
	    if (lowmem && last_attach_point != i && td[i].can_attach) { 
		clear_pt(td, last_attach_point, i); //clear from the last attach point to this one. 
		last_attach_point = i;//this is the new last attach point.
	    }
	    add_syscall(td, i, uinsts,uinsts_cnt);
	}
	++i;
    }while (i < lasti+1 && s.size() < partitions - 1);

    if (estart < lasti){//s.size() < partitions) {
	add_kpart(td, estart, lasti,s);
	gap = estimate_dift(td,estart,lasti); //doesn't use add_syscall.. it should
	if (gap > max_est){
	    max_est = gap;
	}

    }

    return max_est;
}



int generate_timings(vector<struct timing_data> td,
		     u_int num_parts,
		     char *fork_flags,
		     char *pin_dir,
		     int   pin_epochs) { 
    
    u_int lasti = td.size() - 1;
    while(!td[lasti].aindex && lasti >= 0) { 
	--lasti;
    }
    
    if (lowmem){
	init_pin_trace_iter(pti,pin_dir, pin_epochs);
	pin_trace_iter_next(pti); //we need to get the first one started! 
    }	
    double curr_est = estimate_dift(td, 0, lasti);
    if (lowmem){
	destroy_pin_trace_iter(pti); //we need to get the first one started! 
    }

    exit(2);

    double goal = curr_est / num_parts;
    double min_big = numeric_limits<double>::max();
    vector<struct partition> parts;
    vector<struct partition> best_parts;;
    if (do_repartition) fprintf(stderr, "we're doing the repartition!\n");


    for (int j = 0; j < 30; ++j){
	parts.clear();
	if (lowmem) { 
	    init_pin_trace_iter(pti,pin_dir, pin_epochs);
	    pin_trace_iter_next(pti); //we need to get the first one started! 
	}

	
	fprintf(stderr, "iteration %d\n",j);
	double curr_max = do_iteration(td, num_parts, curr_est, parts);       
	if (lowmem) 
	    destroy_pin_trace_iter(pti);

	fprintf(stderr, "parts.size() %d\n",parts.size());

	if (curr_max < min_big && j > 5 && parts.size() == num_parts){
	    min_big = curr_max;
	    best_parts = parts;
	    fprintf(stderr, "new best! %lf\n",min_big);
	}
	if (lowmem){
	    init_pin_trace_iter(pti,pin_dir, pin_epochs);
	    pin_trace_iter_next(pti); //we need to get the first one started! 
	}
	
	curr_est = get_total(td,parts, 0, parts.size());
	if (lowmem){
	    destroy_pin_trace_iter(pti); //we need to get the first one started! 
	}    
	goal = curr_est / num_parts;
    }
    if (lowmem){
	init_pin_trace_iter(pti,pin_dir, pin_epochs);
	pin_trace_iter_next(pti); //we need to get the first one started! 
    }	

    print_parts(td,best_parts, fork_flags);

    
    return 0;
}		   
