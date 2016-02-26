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
#include <vector>

#include "get_stats.h"
using namespace std;


    
int analyze_parts(vector<struct my_stats> &stats, vector<struct epoch >&epochs) {

    u_int current = 0, start;
    for (auto e: epochs) { 
	start = current; 
	
	while (current < stats.size()) { 
	    if (stats[current].start_clock == e.stop_clock) { 
		break;
	    }
	    current++;
	}
	double total_time = stats[current].timing - stats[start].timing;
	int taint_in = stats[current].taint_in - stats[start].taint_in;
	int taint_out = stats[current].taint_out - stats[start].taint_out;
	uint64_t cmisses = stats[current].cmisses - stats[start].cmisses;

	printf("%lf %d %d %llu\n",total_time, taint_in, taint_out, cmisses);
    }



    return 0;
}

int main(int argc, char* argv[]) {

    char filename[256];
    char partsfile[256];  
    int rc;
    FILE* file;
    
    vector<struct my_stats> stats;
    vector<struct epoch >epochs;
    if (argc < 3) { 
	printf("problems\n");
	return -1;
    }

    sprintf (filename, "%s", argv[1]);
    sprintf (partsfile, "%s", argv[2]);

    file = fopen (filename, "r");
    if (file == NULL) { 
	fprintf (stderr, "unable to open file %s, errno %d\n", filename, errno);
    }

    while (!feof(file)) {
	char line[256];
	if (fgets (line, 255, file)) {
	    struct my_stats s;

	    rc = sscanf (line, "%d %lu %lf %lu %lu %llu\n", &s.pid, &s.start_clock, &s.timing, &s.taint_in, &s.taint_out, &s.cmisses);
	    if (rc != 6) {
		fprintf (stderr, "Unable to parse line of epoch descrtion file: %s\n", line);
		return -1;
	    }
	    stats.push_back(s);
	}
    }
    fclose(file);


     file = fopen(partsfile, "r");
    if (file == NULL) {
	fprintf (stderr, "Unable to open epoch description file %s, errno=%d\n", partsfile, errno);
	return -1;
   }
    char dirname[256];
    rc = fscanf (file, "%79s\n", dirname);
    if (rc != 1) {
	fprintf (stderr, "Unable to parse header line of epoch descrtion file, rc=%d\n", rc);
	return -1;
    }

    while (!feof(file)) {
	char line[256];
	if (fgets (line, 255, file)) {
	    struct epoch e;

	    rc = sscanf (line, "%d %c %u %c %u %u %u %u\n", &e.start_pid, &e.start_level, &e.start_clock, &e.stop_level, &e.stop_clock, &e.filter_syscall, &e.ckpt, &e.fork_flags);
	    if (rc != 8) {
		fprintf (stderr, "Unable to parse line of epoch descrtion file: %s\n", line);
		return -1;
	    }
	    epochs.push_back(e);
	}
    }
    fclose(file);

    
    analyze_parts(stats, epochs);
   
    return 0;
}




