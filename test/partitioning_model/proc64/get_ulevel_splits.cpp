#include <limits>
#include <sys/time.h>
#include "generate_splits_utils.h"


using namespace std;


unordered_map<struct ckpt,double> ckpt_times;
vector<struct ckpt> ckpts;

static int group_by = 0;
int filter_syscall = 0;
int use_ckpt = 0, do_split = 0, details = 0, do_repartition = 0;
int lowmem = 0;
double ut_arg = 0.0;
double ui_arg = 0.0;
my_map ninsts; //the number of instructions based on trace_id


static void
pop_ckpt_times(vector<struct timing_data> &td) { 

    auto c = ckpts.begin(); 

    for (auto &t : td) {
	if (t.start_clock >= c->rp_clock) { 
	    ckpt_times[*c] = t.ftiming; //this is the time that the ckpt takes place
	    ++c; 
	}
    }

    for (auto &c : ckpt_times) { 
	fprintf(stderr, "ckpt %lu has time %lf\n",c.first.rp_clock, c.second);

    }
}



static void
combine_vect(my_set &base, my_vect &to_add) { 
    for(auto i : to_add) { 
	base.insert(i);
    }
}

static void
combine_trace(my_set &base, u_long* traces) { 

    while (*traces) {
	base.insert(*traces);
	traces++;
    }
}

static u_long
calc_unique_insts(my_set &traces) { 
    u_long count = 0;
    for (auto t:traces) { 
	count += ninsts[t];
    }

    return count;
}


void format ()
{
    fprintf (stderr, "Format: mkpartition <timing dir> <# of partitions> [-g group_by] [-f filter syscall] [-s split at user-level] [-v verbose] [--stop stop_tracking_clock] [-r pin_trace_dir pin_trace_epochs] [-fork fork_flags] <list of processes in replay>\n");
    exit (22);
}
    
int analyze_parts(vector<struct timing_data> &td, 
		  vector<struct partition> &epochs)
{


    int count = 0;
    u_int current = 0, start;
    my_set  uinsts;
    my_set utraces;
    u_long  imisses;
//    u_int   tindex = 0;

    bool user_level_split = false; //is there currently a run of user_level splits? 
    vector<u_long> user_split_clocks; //the clock values of the user level splits in a run

    for (auto e: epochs) { 
	start = current; 

	//we hit a new user-level split block
	if(!strncmp(e.stop_level,"u",1) && !user_level_split) { 
	    user_level_split = true;
	    user_split_clocks.push_back(e.start_clock); //save off the start
	}
	
	//there's another epoch in this split! 
	else if(!strncmp(e.stop_level,"u",1) && user_level_split) { 
	    user_split_clocks.push_back(e.start_clock);
	}
	//we've reached the end of a run! 
	else if (!strncmp(e.stop_level, "k",1) && user_level_split) { 

	    user_split_clocks.push_back(e.start_clock); 

	    while (current < td.size()) { 
		if (td[current].start_clock == e.stop_clock) { 
		    break;
		}	
		if (td[current].should_track) { 
		    combine_vect(uinsts, td[current].sampled_insts);
		    combine_vect(utraces, td[current].pin_traces);
		    imisses += td[current].imisses;
		}
		current++;
	    }

	    double total_time = td[current].dtiming - td[start].dtiming;
	    u_int num_merges = td[current].num_merges - td[start].num_merges;
	    int usize = uinsts.size();
	    u_int pin_usize = calc_unique_insts(utraces);
	    double ftiming = td[start].ftiming;

	    //adjust ftiming for ckpt
	    if (e.ckpt != 0) { 
		struct ckpt c; 
		c.rp_clock = e.ckpt;
		ftiming -= ckpt_times[c];
	    }

	    //we make simplifying assumption that each user-level split gets equal share 
	    //of the stats
	    u_long prev_clock = user_split_clocks[0];
	    for (u_int i = 1; i < user_split_clocks.size(); ++i) { 
		printf("%lu %lu %lf %lf %lu %lu %lu %lu %lu u\n",prev_clock,
		       user_split_clocks[i],
		       total_time / user_split_clocks.size(),
		       ftiming,
		       usize / user_split_clocks.size(),
		       imisses / user_split_clocks.size(),
		       pin_usize / user_split_clocks.size(),
		       utraces.size() / user_split_clocks.size(),
		       num_merges / user_split_clocks.size());

		prev_clock = user_split_clocks[i];		       
	    }	   

	    //now print the current 
	    printf("%lu %lu %lf %lf %lu %lu %lu %lu %lu u\n",prev_clock,
		   e.stop_clock,
		   total_time / user_split_clocks.size(),
		   ftiming,
		   usize / user_split_clocks.size(),
		   imisses / user_split_clocks.size(),
		   pin_usize / user_split_clocks.size(),
		   utraces.size() / user_split_clocks.size(),
		   num_merges / user_split_clocks.size());


	    //finally, clear out the user_split data:
	    user_split_clocks.clear();
	    user_level_split = false;	    
	    uinsts.clear();
	    utraces.clear();
	    imisses = 0;


	}
	else {
	    while (current < td.size()) { 
		if (td[current].start_clock == e.stop_clock) {
		    break;
		}
		if (td[current].should_track) { 
		    combine_vect(uinsts, td[current].sampled_insts);
		    combine_vect(utraces, td[current].pin_traces);
		    imisses += td[current].imisses;
		}
		current++;
	    }
	    
	    double total_time = td[current].dtiming - td[start].dtiming;
	    u_int num_merges = td[current].num_merges - td[start].num_merges;
	    u_int num_saved = td[current].num_saved - td[start].num_saved;
	    int usize = uinsts.size();
	    u_int pin_usize = calc_unique_insts(utraces);

	    double ftiming = td[start].ftiming;

	    //adjust ftiming for ckpt
	    if (e.ckpt != 0) { 
		struct ckpt c; 
		c.rp_clock = e.ckpt;
		ftiming -= ckpt_times[c];
	    }

	    printf("%lu %lu %lf %lf %d %lu %u %lu %u k\n",
		   e.start_clock, e.stop_clock,total_time,ftiming, usize,imisses, 
		   pin_usize, utraces.size(), num_merges);



	    uinsts.clear();
	    utraces.clear();
	    imisses = 0;
	}
    }
    return 0;
}

static double estimate_dift(vector<struct timing_data> td,
			    int i,
			    int j,
			    double ftiming,
			    int uinsts_cnt) { 


    double utime = td[j].dtiming - td[i].dtiming;    
    u_long num_merges = td[j].num_merges - td[i].num_merges;

    return  (2.5 * ftiming) + (211 * utime) + (.08 * uinsts_cnt) + (.000058 * num_merges);	

}


int print_estimates(vector<struct timing_data> &td, 
		  vector<struct partition> &epochs)
{
	
    u_int current = 0, start;
    my_set  uinsts;
    my_set utraces;
    u_long  imisses;

    for (auto e: epochs) { 
	start = current; 

	while (current < td.size()) { 
	    if (td[current].start_clock == e.stop_clock) {
		break;
	    }
	    if (td[current].should_track) { 
		combine_vect(uinsts, td[current].sampled_insts);
		combine_vect(utraces, td[current].pin_traces);
		imisses += td[current].imisses;
	    }
	    current++;
	}
	    
	double total_time = td[current].dtiming - td[start].dtiming;
	u_int num_merges = td[current].num_merges - td[start].num_merges;
	u_int num_saved = td[current].num_saved - td[start].num_saved;
	int usize = uinsts.size();
	u_int pin_usize = calc_unique_insts(utraces);
	
	double ftiming = td[start].ftiming;
	
	//adjust ftiming for ckpt
	if (e.ckpt != 0) { 
	    struct ckpt c; 
	    c.rp_clock = e.ckpt;
	    ftiming -= ckpt_times[c];
	}
	
	
	
	printf("%lu %lu %lf %lf %u %u %lf\n",e.start_clock,
	       e.stop_clock,total_time,ftiming, pin_usize, num_merges,
	       estimate_dift(td,start, current,ftiming,pin_usize));

	
	uinsts.clear();
	utraces.clear();
	imisses = 0;
    }
    return 0;
}




int main (int argc, char* argv[])
{
    struct stat st;
    int fd, rc, num, i;
    char following[256];   
    FILE *file;
    
    char timing_fname[256];    //filename where the timing data is stored
    char parts_fname[256];    //filename where the timing data is stored
    char inst_fname[256];      //filename where the instruction data is stored (recording metrics)
    char ckpt_fname[256];      //filename where a list of ckpts are storedtion data is stored (recording metrics)
    

    char  trace_dir[256];     //directory where the pin gathered traces are stored
    u_int trace_epochs = -1;  //number of files for the pin gathered traces 

    vector<struct partition> parts;
    vector<struct timing_data> td;

    if (argc < 3) {
	format ();
    }
    following[0] = 0; //assume this isn't provided, fix it if it is. 
    
    sprintf (timing_fname, "%s", argv[1]);
    sprintf (parts_fname, "%s", argv[2]);


    for (i = 2; i < argc; i++) {
	if (!strcmp(argv[i], "-c")) {
	    i++;
	    if (i < argc) {
		strcpy(ckpt_fname,argv[i]);
		use_ckpt = 1;
	    } else {
		format();
	    }
	    i++;
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
    fclose(file);

    file = fopen(parts_fname, "r");
    if (file == NULL) {
	fprintf (stderr, "Unable to open epoch description file %s, errno=%d\n", parts_fname, errno);
	return -1;
    }
    char line[256];
    if(!fgets(line, 255, file)) fprintf(stderr,"hmm.. failed to read first line?\n"); 
    while (!feof(file)) {
	if (fgets (line, 255, file)) {
	    struct partition e;
	    struct ckpt c; 
	    u_int fork_flags;
	    u_int filter_syscall;

	    rc = sscanf (line, "%d %c %lu %c %lu %u %lu %u\n", &e.pid, e.start_level, &e.start_clock, e.stop_level, &e.stop_clock, &filter_syscall, &e.ckpt, &fork_flags);
	    if (rc != 8) {
		fprintf (stderr, "Unable to parse line of epoch descrtion file: %s\n", line);
		return -1;
	    }
	    parts.push_back(e);

	    //deal with the ckpts
	    if (e.ckpt != 0) {
		c.rp_clock = e.ckpt; 
		ckpts.push_back(c);
	    }
	}
    }
    fclose(file);

    file = fopen (inst_fname,  "r");
    if (file == NULL) { 
	fprintf (stderr, "Cannot open instructions file %s,  errno=%d\n", 
		 inst_fname, errno);
	return -1;
    }
    
    if (ckpts.size()) { 
	pop_ckpt_times(td); //populates the ckpt_times map
    }

    rc = parse_instructions(td, file); //parses the instruction logs
    rc = parse_pin_instructions(ninsts,trace_dir, trace_epochs);
    rc = parse_pin_traces(td,trace_dir, trace_epochs);
      

    analyze_parts(td, parts);

//    print_estimates(td, parts);
    return 0;
}

