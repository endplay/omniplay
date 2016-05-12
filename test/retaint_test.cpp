// Shell program for running a sequential multi-stage DIFT
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"

#include <vector>
#include <assert.h>
#include <iostream>
#include <sstream>


using namespace std;

#define MAX_PROCESSES  2
#define BUFFER_SIZE 1024



int get_retaint_points(char *epoch_desc_file, stringstream &retaints, u_long &eclock) {

    char dirname[BUFFER_SIZE]; //doesn't matter, who cares
    vector<u_long> clocks;
    u_long end_clock;

    // Read in the epoch file
    FILE* file = fopen(epoch_desc_file, "r");
    assert(file);
    int rc = fscanf (file, "%79s\n", dirname);
    assert(rc == 1);

    while (!feof(file)) {
	char line[256];
	if (fgets (line, 255, file)) {
	    u_int unused;
	    char cunused;
	    u_long clock;
	    rc = sscanf (line, "%u %c %lu %c %lu %u %u %u\n", &unused, &cunused, &clock, &cunused, &end_clock, &unused, &unused, &unused);
	    assert(rc == 8);
	    clocks.push_back(clock);
	}
    }
    fclose(file);

    //skip the first clock value, it is just the first retaint point  
    retaints << clocks[1];
    if (clocks.size() > 2) { 
	for (auto cl = clocks.begin() + 2; cl != clocks.end(); ++cl){
	    retaints << ",";
	    retaints << *cl;
	}
    }
    eclock = end_clock;
    
    cout << "get_retaint_points is " <<retaints.str() <<endl;
    
    return 0;
}


int main (int argc, char* argv[]) 
{
    struct timeval tv_start, tv_attach, tv_done;
    char cpids[80];
    char eclock[80];
    char fork_flags[80];
    char retaint_chars[4096];

    stringstream retaints;
    char* dirname;
    char* epoch_desc_file;
    char* following = NULL;

    pid_t cpid, mpid;
    int fd, rc, status, filter_inet = 0;
    u_long filter_output_after = 0;
    u_long end_clock = 0;
    char* filter_output_after_str = NULL;
    char* filter_partfile = NULL;

    if (argc < 3) {
	fprintf (stderr, "format: retaint_test <replay dir> <epoch_desc_file> [filter syscall] [-filter_inet] [-filter_partfile xxx] [-filter_output_after clock]\n");
	return -1;
    }

    dirname = argv[1];
    epoch_desc_file = argv[2];
    if (argc > 2) {
	int index = 3;
	while (index < argc) { 
	    if (!strncmp(argv[index],"-filter_inet",BUFFER_SIZE)) {
		filter_inet = 1;
		index++;
	    } else if (!strncmp(argv[index],"-filter_partfile",BUFFER_SIZE)) {
		filter_partfile = argv[index+1];
		index += 2;
	    } else if (!strncmp(argv[index],"-following",BUFFER_SIZE)) {
		following = argv[index+1];
		index += 2;
	    } else if (!strncmp(argv[index],"-filter_output_after",BUFFER_SIZE)) {
		filter_output_after_str = argv[index+1];
		filter_output_after = atoi(argv[index+1]);
		index += 2;
	    } else {
		fprintf (stderr, "format: seqtt <replay dir> [filter syscall] [-filter_inet] [-filter_partfile xxx] [-filter_output_after clock]\n");
		return -1;
	    }
	}
    }
    fprintf(stderr,"following %s\n",following);
    get_retaint_points(epoch_desc_file, retaints,end_clock);


    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror("open /dev/spec0");
	return fd;
    }

    gettimeofday (&tv_start, NULL);
    cpid = fork ();
    if (cpid == 0) {
	rc = execl("./resume", "resume", "-p", dirname, "--pthread", "../eglibc-2.15/prefix/lib", NULL);
	fprintf (stderr, "execl of resume failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    } 
    
    do {
	// Wait until we can attach pin
	rc = get_attach_status (fd, cpid);
    } while (rc <= 0);
    
    gettimeofday (&tv_attach, NULL);

    mpid = fork();
    if (mpid == 0) {
	const char* args[256];
	u_int argcnt = 0;


	args[argcnt++] = "pin";
	args[argcnt++] = "-pid";
	sprintf (cpids, "%d", cpid);
	args[argcnt++] = cpids;
	args[argcnt++] = "-t";
	args[argcnt++] = "../dift/obj-ia32/linkage_data.so";
	args[argcnt++] = "-retaint";
	sprintf(retaint_chars, "%s",retaints.str().c_str());
	args[argcnt++] = retaint_chars;
	args[argcnt++] = "-l";
	sprintf(eclock, "%lu",end_clock);
	args[argcnt++] = eclock;
	if (following) { 
	    sprintf (fork_flags, "%s", following);
	    args[argcnt++] = "-fork_flags";
	    args[argcnt++] = fork_flags;		       		
	}

	cout <<"retaint at "<<retaint_chars << endl;;

	if (filter_output_after) {
	    args[argcnt++] = "-ofb";
	    args[argcnt++] = filter_output_after_str;
	} 
	if (filter_inet) {
	    args[argcnt++] = "-i";
	    args[argcnt++] = "-f";
	    args[argcnt++] = "inetsocket";
	} else if (filter_partfile) {
	    args[argcnt++] = "-i";
	    args[argcnt++] = "-e";
	    args[argcnt++] = filter_partfile;
	}

	args[argcnt++] = NULL;
	rc = execv ("../../../pin/pin", (char **) args);
	fprintf (stderr, "execv of pin tool failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    // Wait for cpid to complete

    rc = wait_for_replay_group(fd, cpid);
    rc = waitpid (cpid, &status, 0);
    if (rc < 0) {
	fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, cpid);
    }

    gettimeofday (&tv_done, NULL);
    
    close (fd);

    printf ("Start time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("Attach time: %ld.%06ld\n", tv_attach.tv_sec, tv_attach.tv_usec);
    printf ("End time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);
    

    return 0;
}
