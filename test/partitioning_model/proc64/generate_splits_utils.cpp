#include <sys/mman.h>
#include <cstdint>

#include "generate_splits_utils.h"

//#define DETAILS

using namespace std;

//////////
// utilities used througout
//////////
int ckpt_cmp (const void* a, const void* b)
{
    const struct ckpt* c1 = (const struct ckpt *) a;
    const struct ckpt* c2 = (const struct ckpt *) b;
    return c1->rp_clock - c2->rp_clock;
}

int read_ckpts (std::vector<struct ckpt> &ckpts,  FILE* file)
{

    long rc;    
    char line[256];

    while (!feof(file)) {
	if (fgets (line, 255, file)) {
	    struct ckpt c ;
	    rc = sscanf (line, "%lu\n", &(c.rp_clock));
	    if (rc != 1) { 
		fprintf(stderr, "couldn't read in rp_clock from ckpt\n");
		return -1;
	    }
	    ckpts.push_back(c);
	}
    }

    fclose(file);
    return 0;
}

int adjust_for_ckpts(vector<struct timing_data> &td,
		     vector<struct ckpt> &ckpt){

    double ckpt_time = 0.0;
    auto tdi = ckpt.begin(); //something like this? 

    for (auto &t : td) { 
	if (t.start_clock >= tdi->rp_clock && (tdi+1) != ckpt.end()) {
	    ++tdi;
	    ckpt_time = t.ftiming; 
	}
	t.ftiming -= ckpt_time;
    }
}


long ms_diff (struct timeval tv1, struct timeval tv2)
{
    return ((tv1.tv_sec - tv2.tv_sec) * 1000 + 
	    (tv1.tv_usec - tv2.tv_usec) / 1000);
}


int read_timing_data(std::vector<struct timing_data> &td, FILE *file){
    
    char line[256];
    long rc;
    while (!feof(file)) {
	if (fgets (line, 255, file)) {
	    struct timing_data t; 
	    rc = sscanf (line, "%d %lu %hd %hhd %hd %hhd %lu %lu %lu %lf %lf\n",
			 &t.pid, &t.index,&t.syscall, &t.can_attach, 
			 &t.blocking_syscall, &t.should_track, &t.start_clock,
			 &t.stop_clock,  &t.aindex, &t.dtiming, &t.ftiming);
	    if (rc != 11) { 
		fprintf(stderr, "couldn't read in td data\n");
		return -1;
	    }
	    td.push_back(t);
	}
    }
}



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
    for (auto &t : td) { 
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
static int map_next_file(char * filename, uint32_t* &log, u_long &data_size, u_long &mapsize, int &fd) { 

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
    
    log = (uint32_t *) mmap (0, mapsize, PROT_READ, MAP_SHARED, fd, 0);
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
    uint32_t *log, *lstart;
    u_long endat;
    u_long mapsize;
    int fd;
    int rc;

    for (u_int i = 0; i < epochs; i++) {
	sprintf (filename, "%s/trace-inst-%d",dir, i);
	rc = map_next_file(filename, log, endat, mapsize,fd);
	lstart = log; 
	assert(!rc && "couldn't map inst file!");
	close(fd);

	while ((u_long) log < endat) {
	    uint32_t insts = *log++;
	    uint32_t trace = *log++;
	    my_map::const_iterator found = ninsts.find(trace);
	    if (found != ninsts.end() && found->second != insts) { 		
		fprintf(stderr, "found 0x%x already,but has %u instead of %u insts\n",trace,found->second,insts);
	    }
	    ninsts[trace] = insts;
	}
	munmap(lstart, mapsize);	
    }    
    return 0;
}
int parse_pin_traces(vector<struct timing_data> &td, char* dir, u_int epochs) { 

    char filename[1024];
    uint32_t *log;
    uint32_t *lstart;
    u_long endat;
    u_long mapsize;
    int fd;
    int rc;
    uint32_t syscall_cnt = 0;
    uint32_t cnt = 0;
    uint32_t num_merges = 0;
    uint32_t td_merges = 0; //current number of merges

	
    for (u_int i = 0; i < epochs; i++) {
	sprintf (filename, "%s/trace-exec-%d",dir, i);
	rc = map_next_file(filename, log, endat, mapsize,fd);
	lstart = log;
	fprintf(stderr,"mmaped from 0x%p to 0x%lx (endat 0x%lx)\n",log, (u_long)log + mapsize, endat);

	close(fd);

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
	    uint32_t pid = *log++; // pid
	    uint32_t clock = *log++; // clock
	    uint32_t sysnum = *log++; //syscallnumber
	    td_merges = *log++; // num_merges
	    cnt++;

	    //update syscall_cnt
	    if (clock > td[syscall_cnt].start_clock) {
		syscall_cnt++;
		while(syscall_cnt < td.size() && (!td[syscall_cnt].should_track || 
						  td[syscall_cnt].start_clock < clock )) { 

#ifdef DETAILS
		    fprintf(stderr, "this is irregular...");
		    fprintf(stderr, "(%u, %u %u %u), td: (%d %d, %lu %lu) %lu\n", 
			    pid, clock, sysnum, td_merges, td[syscall_cnt].syscall, 
			    td[syscall_cnt].pid, td[syscall_cnt].start_clock, 
			    td[syscall_cnt].stop_clock, td[syscall_cnt].pin_traces.size());
#endif
		    td[syscall_cnt].num_merges = td[syscall_cnt-1].num_merges;
		    syscall_cnt++;
		}		
		//we updated pin-traces... do the reservation here
//		td[syscall_cnt].pin_traces.reserve(1024);	    		
	    }

	    //update num_merges
	    td[syscall_cnt].num_merges = td_merges + num_merges; 
	    //update pin_traces
	    while (*log) {
		uint32_t trace = *log++; 
		td[syscall_cnt].pin_traces.push_back(trace);		
	    }
#ifdef DETAILS	
	    fprintf(stderr, "(%u %u %u %u), td: (%d %lu %hd)\n", 
		    pid, clock, sysnum, td_merges, 
		    td[syscall_cnt].pid, td[syscall_cnt].start_clock, 
		    td[syscall_cnt].syscall);
#endif
	
	    log++;
	} while ((u_long) log < endat);
	fprintf(stderr,"mummapping from 0x%p to 0x%lx (endat 0x%lx) \n",lstart, (u_long)lstart + mapsize, endat);
	munmap(lstart, mapsize);

    }    

    if (syscall_cnt + 1 < td.size()) { 
	fprintf(stderr, "huh, we only did %u out of %lu, cnt %u\n",syscall_cnt, td.size(), cnt);
    }


    return 0;
}

