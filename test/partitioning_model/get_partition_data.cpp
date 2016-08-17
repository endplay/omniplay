#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <dirent.h>
#include <cstdint>
#include <algorithm>
#include <vector>
#include <limits>
#include <unordered_set>
#include <unordered_map>
#include <array>
#include "../mkpartition_utils.h"

using namespace std;

static my_map insts;
int details; 
int lowmem = 0;
int nosort = 0;
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
/*
static void
combine_list(my_set &base, my_ll &to_add) { 
    for(auto i : to_add) { 
	base.insert(i);
    }
    }*/


static u_long
calc_unique_insts(my_set &traces) { 
    u_long count = 0;
    for (auto t:traces) { 
	count += insts[t];
    }

    return count;
}

void format ()
{
    fprintf (stderr, "Format: get_partition_data <timing dir> <parts_file > [-fork following] [-v verbose] [-r pin_trace_dir pin_trace_epochs] <list of pids to track >\n");
    exit (22);
}


int analyze_parts_lowmem(vector<struct timing_data> &td, 
			 vector<struct partition> &epochs,
			 char *dir,
			 int nume){

    u_int current = 0, start;
    my_set uinsts;
    my_set utraces;
    u_long num_merges_start = 0;
    u_long num_merges_curr = 0;
    u_long imisses = 0;
    int rc = 0; 
    struct pin_trace_iter pti;

    init_pin_trace_iter(pti, dir, nume);
    pin_trace_iter_next(pti); //we need to get the first one started! 

    for (auto e: epochs) { 
	start = current; 
	while (current < td.size()) { 
//	    fprintf(stderr, "doing it for e (%lu,%lu) current %lu\n",e.start_clock, e.stop_clock, td[current].start_clock);
	    if (td[current].start_clock == e.stop_clock) {
		fprintf(stderr,"breaking b/c %lu == %lu\n",td[current].start_clock, e.stop_clock);
		break;
	    }
	    if (td[current].should_track) { 
		imisses += td[current].imisses;

		    //if the current iterator is between the last syscall and this one, we need to add the info
		while (!rc && pti.cclock <= td[current].start_clock) {  		    
		    num_merges_curr = pti.cnmerges; 
		    combine_trace(utraces, pti.ctraces); 

//		    fprintf(stderr, "(%lu %lu %lu %lu), td: (%d %d, %lu %lu) %u %lu\n", pti.cpid, pti.cclock, pti.csysnum,  pti.cnmerges, td[current].syscall, td[current].pid, td[current].start_clock,   td[current].stop_clock, utraces.size(), num_merges_curr);

		    rc = pin_trace_iter_next(pti); //advance the iterator forward. 		    
		    if (rc) { 
			fprintf(stderr, "we're done with the pin_instructions! (lets hope we're done with the td)\n");
		    }
		}		
	    }
	    current++;
	}
	fprintf(stderr, "made it here!!\n");
	

	double total_time = td[current].dtiming - td[start].dtiming;
	int taint_in = td[current].taint_in - td[start].taint_in;
	int taint_out = td[current].taint_out - td[start].taint_out;
	int usize = uinsts.size();
	u_long num_merges = num_merges_curr - num_merges_start;
	num_merges_start = num_merges_curr;
	u_int pin_usize = calc_unique_insts(utraces);
	    
	fprintf(stdout,"%lu %lu %lf %lf %d %d %d %lu %u %u %lu\n",e.start_clock,e.stop_clock,total_time,td[current].ftiming,taint_in, taint_out, usize,imisses, pin_usize, utraces.size(), num_merges);       
	fprintf(stderr,"%lu %lu %lf %d %d %d %lu %u %u %lu\n",e.start_clock,e.stop_clock,total_time, taint_in, taint_out, usize, (u_long)0, pin_usize, utraces.size(), num_merges);

	utraces.clear();
	num_merges = 0;
	imisses = 0;
    }
    return 0;
}



    
int analyze_parts(vector<struct timing_data> &td, 
		  vector<struct partition> &epochs,
		  FILE *ifile){
	
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

	    int taint_in = td[current].taint_in - td[start].taint_in;
	    int taint_out = td[current].taint_out - td[start].taint_out;	    
	    u_int num_merges = td[current].num_merges - td[start].num_merges;
	    int usize = uinsts.size();
	    u_int pin_usize = calc_unique_insts(utraces);


	    //we make simplifying assumption that each user-level split gets equal share 
	    //of the stats
	    u_long prev_clock = user_split_clocks[0];
	    for (u_int i = 1; i < user_split_clocks.size(); ++i) { 
		printf("%lu %lu %lf %lf  %d %d %d %lu %u %u %u\n",prev_clock,
		       user_split_clocks[i],
		       total_time / user_split_clocks.size(),
		       td[current].ftiming,
		       taint_in / user_split_clocks.size(),
		       taint_out / user_split_clocks.size(),
		       usize / user_split_clocks.size(),
		       imisses / user_split_clocks.size(),
		       pin_usize / user_split_clocks.size(),
		       utraces.size() / user_split_clocks.size(),
		       num_merges / user_split_clocks.size());

		prev_clock = user_split_clocks[i];		       
	    }	   

	    //now print the current 
	    printf("%lu %lu %lf %lf %d %d %d %lu %u %u %u\n",prev_clock,
		   e.stop_clock,
		   total_time / user_split_clocks.size(),
		   td[current].ftiming,
		   taint_in / user_split_clocks.size(),
		   taint_out / user_split_clocks.size(),
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
//		    combine_vect(utraces,td[current].pin_traces); //I'm inadvertantly double counting these I think...
		    break;
		}
		if (td[current].should_track) { 
		    combine_vect(uinsts, td[current].sampled_insts);
//		    if (current != start) 
			combine_vect(utraces, td[current].pin_traces);
		    imisses += td[current].imisses;
		}
		current++;
	    }
	    
	    double total_time = td[current].dtiming - td[start].dtiming;
	    int taint_in = td[current].taint_in - td[start].taint_in;
	    int taint_out = td[current].taint_out - td[start].taint_out;
	    u_int num_merges = td[current].num_merges - td[start].num_merges;
	    u_int num_saved = td[current].num_saved - td[start].num_saved;
	    int usize = uinsts.size();
	    u_int pin_usize = calc_unique_insts(utraces);

	    printf("%lu %lu %lf %lf %d %d %d %lu %u %u %u %u\n",e.start_clock,e.stop_clock,total_time,td[current].ftiming,taint_in, taint_out, usize,imisses, pin_usize, utraces.size(), num_merges, num_saved);

	    uinsts.clear();
	    utraces.clear();
	    imisses = 0;
	}
    }
    return 0;
}

bool mycmp(struct timing_data t, struct timing_data u) {return t.start_clock < u.start_clock;}


int main(int argc, char* argv[]) {

    char timingsfile[256];
    char instfile[256];
    char partsfile[256];  
    char following[256];
    int pin_epochs = -1; 
    u_long stop_clock = 0;
    char* pin_dir = NULL;
    unordered_set<pid_t> procs;

    int rc, fd, i;
    FILE* file;
    struct stat st;

    struct replay_timing* timings;    
    int num_timings;


    vector<struct partition> parts; 

    if (argc < 3) { 
	format();
	return -1;
    }

    sprintf (timingsfile, "%s/timings", argv[1]);
    sprintf (partsfile, "%s", argv[2]);

    for (i = 3; i < argc; i++) {
	if(!strcmp(argv[i], "-fork")) { 
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
	else if (!strcmp(argv[i], "-lowmem")) {
	    lowmem = 1;
	    fprintf(stderr, "doing lowmem\n");
	}
	else if (!strcmp(argv[i], "-nosort")) {
	    nosort = 1;
	    fprintf(stderr, "doing nosort\n");
	}

	else if (!strcmp(argv[i],"-r")){
	    i++;
	    if (i < argc) {
		pin_dir = argv[i];
		i++;
		if (i < argc) {
		    pin_epochs = atoi(argv[i]);
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


    file = fopen(partsfile, "r");
    if (file == NULL) {
	fprintf (stderr, "Unable to open epoch description file %s, errno=%d\n", partsfile, errno);
	return -1;
    }
    char line[256];
    if(!fgets(line, 255, file)) fprintf(stderr,"hmm.. failed to read first line?\n"); //skip the first line in the file

    while (!feof(file)) {
	if (fgets (line, 255, file)) {
	    struct partition e;
	    u_int ckpt;
	    u_int fork_flags;
	    u_int filter_syscall;

	    rc = sscanf (line, "%d %c %lu %c %lu %u %u %u\n", &e.pid, e.start_level, &e.start_clock, e.stop_level, &e.stop_clock, &filter_syscall, &ckpt, &fork_flags);
	    if (rc != 8) {
		fprintf (stderr, "Unable to parse line of epoch descrtion file: %s\n", line);
		return -1;
	    }
	    parts.push_back(e);
	}
    }
    fclose(file);

    fprintf(stderr, "partitions: \n");
    for (auto e : parts){ 
	fprintf(stderr,"(%lu, %lu)\n",e.start_clock, e.stop_clock);
    }

    fd = open (timingsfile, O_RDONLY);
    if (fd < 0) {
	fprintf (stderr, "Cannot open timing file %s, rc=%d, errno=%d\n", timingsfile, fd, errno);
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
    num_timings = st.st_size / sizeof(struct replay_timing);
    vector<struct timing_data> td(num_timings);

    for ( i = 0; i < num_timings; i++) { 	
	struct timing_data next_td;
	next_td.pid = timings[i].pid;
	next_td.index = timings[i].index;
	next_td.syscall = timings[i].syscall;
	next_td.start_clock = numeric_limits<u_long>::max();;
	next_td.ut = timings[i].ut;
	next_td.taint_in = 0;
	next_td.taint_out = 0;	
	next_td.imisses = 0;
	next_td.forked_pid = -1; //just assume that syscalls don't have forked_pids. this will get fixed later if we're wrong
	next_td.should_track = false; //assume that we don't track it, it will be fixed if we should
	next_td.can_attach = true; //set it to be true first
	td[i] = next_td;
    }
    free(timings); //free all dem memories


    sprintf (timingsfile, "%s/timings.cloudlab", argv[1]);
    fd = open (timingsfile, O_RDONLY);
    assert(fd >=0);
    rc = fstat (fd, &st);
    assert(rc >=0);
    timings = (struct replay_timing *) malloc (st.st_size);
    assert(timings);
    rc = read (fd, timings, st.st_size);
    assert(rc >= st.st_size);
    num_timings = st.st_size / sizeof(struct replay_timing);
    for ( i = 0; i < num_timings; i++) { 	
	td[i].fft  = timings[i].ut;
    }
    free(timings); //free all dem memories




    fprintf(stderr, "starting parsing klogs\n");
    rc = parse_klogs(td, stop_clock, argv[1], following, procs);
    fprintf(stderr, "starting parsing ulogs\n");
    rc = parse_ulogs(td, argv[1]);     
    fprintf(stderr, "starting parsing timing_data\n");
    rc = parse_timing_data(td);
    
    fprintf(stderr, "finished with parsing timing_data\n");
    fprintf(stderr, "sorting!\n");
    sort (td.begin(), td.end(), mycmp);



    if (pin_epochs > 0) {
	parse_pin_instructions(insts, pin_dir, pin_epochs);
	if (!lowmem) parse_pin_traces(td, pin_dir, pin_epochs);
    }

    if (!lowmem) {
	sprintf(instfile, "%s/instructions",argv[1]);
	file = fopen (instfile, "r");
	if (file == NULL) { 
	    fprintf (stderr, "Cannot open instructions file %s,  errno=%d\n", instfile, errno);
	    return -1;
	}
	file = fopen(instfile, "r");       
	parse_instructions(td, file);
    }

    if(details) {
	for (auto t : td) { 
	    fprintf (stderr,"%d %lu %lu, %lu, (%lf %lu %lu %u %lu %lu %lu), %d\n", t.pid, t.call_clock, t.start_clock, t.stop_clock, t.dtiming, t.taint_in, t.taint_out, t.pin_traces.size(), t.imisses, t.num_merges,t.num_saved,t.should_track);
	    if (!t.can_attach) printf("\t can't attach b/c %d\n",t.blocking_syscall);
	}
    }

    if (!lowmem) analyze_parts(td,parts, file);  
    else  analyze_parts_lowmem(td,parts, pin_dir, pin_epochs);  


    return 0;
}
