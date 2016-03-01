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
#include "util.h"

#define MAX_PROCESSES  2
#define BUFFER_SIZE 1024
int main (int argc, char* argv[]) 
{
    struct timeval tv_start, tv_attach, tv_tool_done, tv_done;
    char cpids[80], tmpdir[80], lscmd[80];
    char* lscmd_output;
    char* dirname;
//    char shmemname[256];
    char cache_dir[BUFFER_SIZE] = "";

    pid_t cpid, mpid, ppid;
    int fd, rc, status, filter_syscall = 0;
    int next_child = 0, i;
    size_t n = BUFFER_SIZE;
    FILE* fp; 

    int post_process_pids[MAX_PROCESSES];

    if (argc < 2) {
	fprintf (stderr, "format: seqtt <replay dir> [filter syscall] [--cache_dir cache_dir]\n");
	return -1;
    }

    dirname = argv[1];
    if (argc > 2) {
	int index = 2;
	while (index < argc) { 
	    //if the current argument is cache_dir, then save the cache_dir
	    if(!strncmp(argv[index],"--cache_dir",BUFFER_SIZE)) {
		strncpy(cache_dir,argv[index + 1],BUFFER_SIZE); 
		index++;
	    }	   
	    else { 
		filter_syscall = atoi(argv[index]);
	    }
	    index++;
	}
    }


    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror("open /dev/spec0");
	return fd;
    }

    gettimeofday (&tv_start, NULL);
    cpid = fork ();
    if (cpid == 0) {
	if(strncmp(cache_dir,"",BUFFER_SIZE)) { 
	    rc = execl("./resume", "resume", "-p", dirname, "--pthread", "../eglibc-2.15/prefix/lib", "--cache_dir",cache_dir,NULL);
	}
	else {
	    rc = execl("./resume", "resume", "-p", dirname, "--pthread", "../eglibc-2.15/prefix/lib", NULL);
	}
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
	sprintf (cpids, "%d", cpid);
	if (filter_syscall) {
	    rc = execl ("../../../pin/pin", "pin", "-pid", cpids, "-t", "../dift/obj-ia32/linkage_data.so", "-ofs", argv[2], NULL);
	} else {
	    rc = execl ("../../../pin/pin", "pin", "-pid", cpids, "-t", "../dift/obj-ia32/linkage_data.so", "-i", "-f", "inetsocket", "-l", "8655850", NULL);
	  //	    rc = execl ("../../../pin/pin", "pin", "-pid", cpids, "-t", "../dift/obj-ia32/linkage_data.so", NULL);
	}
	fprintf (stderr, "execl of pin tool failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    // Wait for cpid to complete

    rc = wait_for_replay_group(fd, cpid);
    rc = waitpid (cpid, &status, 0);
    if (rc < 0) {
	fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, cpid);
    }

    gettimeofday (&tv_tool_done, NULL);

    // Now post-process the results
    //do some magic to get all of the underling's pids. 
    
    printf("DIFT finished\n");
    sprintf(tmpdir, "/tmp/%d",cpid);
    sprintf(lscmd, "/bin/ls %s/dataflow.result*", tmpdir);
    fp = popen(lscmd, "r");
    if(fp == NULL) { 
	fprintf(stderr, "popen failed: errno %d", errno);
	return -1;
    }

    lscmd_output = malloc(n); 
    while((rc = getline(&lscmd_output, &n, fp)) > 0) 
    { 
	char* pid;
	//the output will be like /tmp/%d/dataflow.results.%d all we want is the last %d
//	fprintf(stderr,"line lscmd_output %s", lscmd_output);
	strtok(lscmd_output, "."); 
	strtok(NULL, "."); 
	pid = strtok(NULL, "."); 
	if(pid == NULL) { 
	    continue;
	}

	pid = strtok(pid, "\n");

	post_process_pids[next_child] = fork(); 
	if (post_process_pids[next_child] == 0) {
	    sprintf(tmpdir, "/tmp/%d",cpid);
	    rc = execl ("../dift/obj-ia32/postprocess_linkage", "postprocess_linkage", "-m", tmpdir, "-p", pid, NULL);
	    fprintf (stderr, "execl of postprocess_linkage failed, rc=%d, errno=%d\n", rc, errno);
	    return -1;
	}
	next_child+=1;
    }
    free(lscmd_output); 

    ppid = fork();
    if (ppid == 0) {
	sprintf(tmpdir, "/tmp/%d",cpid);
	rc = execl ("../dift/obj-ia32/postprocess_linkage", "postprocess_linkage", "-m", tmpdir, NULL);
	fprintf (stderr, "execl of postprocess_linkage failed, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }


    // Wait for analysis to complete

    for(i = 0; i < next_child; i++) 
    { 
	rc = waitpid (post_process_pids[i], &status, 0);
	if (rc < 0) {
	    fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, cpid);
	}
    }
    rc = waitpid (ppid, &status, 0);
    if (rc < 0) {
	fprintf (stderr, "waitpid returns %d, errno %d for pid %d\n", rc, errno, cpid);
    }


    gettimeofday (&tv_done, NULL);
    
    close (fd);

    printf ("Start time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("Attach time: %ld.%06ld\n", tv_attach.tv_sec, tv_attach.tv_usec);
    printf ("Tool done time: %ld.%06ld\n", tv_tool_done.tv_sec, tv_tool_done.tv_usec);
    printf ("End time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);

    long diff_usec = tv_done.tv_usec - tv_tool_done.tv_usec;  
    long carryover = 0;
    if(diff_usec < 0) { 
	carryover = -1;
	diff_usec = 1 - diff_usec;
    }    
    long diff_sec = tv_done.tv_sec - tv_tool_done.tv_sec - carryover; 

    printf ("Tool -> End: %ld.%06ld\n", diff_sec,diff_usec);

    diff_usec = tv_done.tv_usec - tv_start.tv_usec;  
    carryover = 0;
    if(diff_usec < 0) { 
	carryover = -1;
	diff_usec = 1 - diff_usec;
    }
    diff_sec = tv_done.tv_sec - tv_start.tv_sec - carryover; 

    printf ("Start -> End: %ld.%06ld\n", diff_sec,diff_usec);
    

    //need to unlink the shared memroy region... need to 'recreate' tmpdir b/c it was not done in the parent
//    sprintf (tmpdir, "/tmp/%d", cpid);
//    snprintf(shmemname, 256, "/node_nums_shm%s/node_nums", tmpdir);
//    for (i = 1; i < strlen(shmemname); i++) {
//	if (shmemname[i] == '/') shmemname[i] = '.';
//    }
//    shmemname[strlen(shmemname)-10] = '\0';
//    rc = shm_unlink (shmemname); 
//    if (rc < 0) perror ("shmem_unlink");

    return 0;
}
