// Shell program for running a sequential multi-stage DIFT
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>

#include <vector>
#include <atomic>
using namespace std;

#include "../../test/streamserver.h"
#include "../../test/util.h"
#include "streamnw.h"

//#define DETAILS

#define STATUS_INIT 0
#define STATUS_STARTING 1
#define STATUS_EXECUTING 2
#define STATUS_STREAM 3
#define STATUS_DONE 4

int agg_port = -1;

struct epoch_ctl {
    int    status;
    char   inputqhname[256];
    char   inputqbname[256];
    pid_t  cpid;
    pid_t  spid;
    pid_t  attach_pid;
    pid_t  waiting_on_rp_group; //ARQUINN -> added

    // For timings
    struct timeval tv_start;
    struct timeval tv_start_dift;
    struct timeval tv_done;
};
int sync_logfiles (int s)
{
    u_long fcnt, ccnt;
    bool* freply = NULL;
    bool* creply = NULL;
    vector<struct replay_path> dirs;
    
    int rc = safe_read (s, &fcnt, sizeof(fcnt));
    if (rc != sizeof(fcnt)) {
	fprintf (stderr, "Cannot recieve file count,rc=%d\n", rc);
	return -1;
    }
    
    if (fcnt) {
	freply = (bool *) malloc(sizeof(bool)*fcnt);
	if (freply == NULL) {
	    fprintf (stderr, "Cannot allocate file reply array of size %lu\n", fcnt);
	    return -1;
	}
	
	for (u_long i = 0; i < fcnt; i++) {
	    replay_path fpath;
	    rc = safe_read (s, &fpath, sizeof(fpath));
	    if (rc != sizeof(fpath)) {
		fprintf (stderr, "Cannot recieve file path,rc=%d\n", rc);
		return -1;
	    }
	    
	    // Does this file exist?
	    struct stat st;
	    rc = stat (fpath.path, &st);
	    if (rc == 0) {
		freply[i] = false;
	    } else {
		freply[i] = true;
		
		// Make sure directory exists
		for (int i = strlen(fpath.path); i >= 0; i--) {
		    if (fpath.path[i] == '/') {
			fpath.path[i] = '\0';
			rc = mkdir (fpath.path, 0777);
			if (rc < 0 && errno != EEXIST) {
			    printf ("mkdir of %s returns %d\n", fpath.path, rc);
			}
			break;
		    }
		}
		dirs.push_back(fpath);
	    }
	}
	
	// Send back response
	rc = safe_write (s, freply, sizeof(bool)*fcnt);
	if (rc != (int) (sizeof(bool)*fcnt)) {
	    fprintf (stderr, "Cannot send file check reply,rc=%d\n", rc);
	    return -1;
	}
    }
    
    rc = safe_read (s, &ccnt, sizeof(ccnt));
    if (rc != sizeof(fcnt)) {
	fprintf (stderr, "Cannot recieve cache count,rc=%d\n", rc);
	return -1;
    }
    
    struct cache_info* ci = new cache_info[ccnt];
    
    if (ccnt) {
	creply = (bool *) malloc(sizeof(bool)*ccnt);
	if (creply == NULL) {
	    fprintf (stderr, "Cannot allocate cache reply array of size %lu\n", ccnt);
	    return -1;
	}
	
	rc = safe_read (s, ci, sizeof(struct cache_info)*ccnt);
	if (rc != (long) (sizeof(struct cache_info)*ccnt)) {
	    fprintf (stderr, "Cannot recieve cache info,rc=%d\n", rc);
	    return -1;
	}
	
	for (u_long i = 0; i < ccnt; i++) {
	    // Does this file exist?
	    char cname[PATHLEN], cmname[PATHLEN];
	    struct stat64 st;
	    
	    sprintf (cname, "/replay_cache/%x_%x", ci[i].dev, ci[i].ino);
	    rc = stat64 (cname, &st);
	    if (rc == 0) {
		// Is this the right version?
		if (st.st_mtim.tv_sec == ci[i].mtime.tv_sec && st.st_mtim.tv_nsec == ci[i].mtime.tv_nsec) {
		    creply[i] = false;
		} else {
		    // Nope - but maybe we have it?
		    sprintf (cmname, "/replay_cache/%x_%x_%lu_%lu", ci[i].dev, ci[i].ino, ci[i].mtime.tv_sec, ci[i].mtime.tv_nsec);
		    rc = stat64 (cmname, &st);
		    if (rc == 0) {
			creply[i] = false;
		    } else {
			creply[i] = true;
		    }
		}
	    } else {
		// No versions at all
		creply[i] = true;
	    }
	}
	
	// Send back response
	rc = safe_write (s, creply, sizeof(bool)*ccnt);
	if (rc != (int) (sizeof(bool)*ccnt)) {
	    fprintf (stderr, "Cannot send cache info check reply,rc=%d\n", rc);
	    return -1;
	}
    }
    
    // Now receive the files we requested
    u_long dcnt = 0;
    for (u_long i = 0; i < fcnt; i++) {
	if (freply[i]) {
	    rc = fetch_file (s, dirs[dcnt++].path);
	    if (rc < 0) return rc;
	}
    } 
    
    u_long ffcnt = 0;
    for (u_long i = 0; i < ccnt; i++) {
	if (creply[i]) {
	    rc = fetch_file (s, "/replay_cache");
	    if (rc < 0) return rc;
	    
	    // Now rename the file to the correct version - must check to see where to put it
	    char cname[PATHLEN], crname[PATHLEN], newname[PATHLEN];
	    struct stat64 st;
	    sprintf (cname, "/replay_cache/%x_%x", ci[i].dev, ci[i].ino);
	    rc = stat64 (cname, &st);
	    if (rc == 0) {
		if (st.st_mtim.tv_sec > ci[i].mtime.tv_sec || 
		    (st.st_mtim.tv_sec == ci[i].mtime.tv_sec && st.st_mtim.tv_nsec > ci[i].mtime.tv_nsec)) {
		    // Exists and new file is past version 
		    sprintf (newname, "/replay_cache/%x_%x_%lu_%lu", ci[i].dev, ci[i].ino, ci[i].mtime.tv_sec, ci[i].mtime.tv_nsec);
		    rc = rename ("/replay_cache/rename_me", newname);
		    if (rc < 0) {
			fprintf (stderr, "Cannot rename temp cache file to %s, rc=%d\n", newname, rc);
			return rc;
		    }
		} else {
		    // Exists and new file is more recent version
		    sprintf (crname, "/replay_cache/%x_%x_%lu_%lu", ci[i].dev, ci[i].ino, st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
		    rc = rename (cname, crname);
		    if (rc < 0) {
			fprintf (stderr, "Cannot rename cache file %s to %s, rc=%d\n", cname, crname, rc);
			return rc;
		    }
		    rc = rename ("/replay_cache/rename_me", cname);
		    if (rc < 0) {
			fprintf (stderr, "Cannot rename temp cache file to %s, rc=%d\n", cname, rc);
			return rc;
		    }
		}
	    } else {
		// Does not exist
		rc = rename ("/replay_cache/rename_me", cname);
		if (rc < 0) {
		    fprintf (stderr, "Cannot rename temp cache file to %s, rc=%d\n", cname, rc);
		    return rc;
		}
	    }
	    ffcnt++;
	}
    } 
    
    free (freply);
    free (creply);
    delete [] ci;

    return 0;
}

void do_dift (int s, struct epoch_hdr& ehdr) 
{
#ifndef BUILD_64
    int rc;
    struct timeval tv_start, tv_done;
    gettimeofday (&tv_start, NULL);

    int fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror("open /dev/spec0");
	return;
    }

    u_long epochs = ehdr.epochs;

    struct epoch_data edata[epochs];
    struct epoch_ctl ectl[epochs];


    rc = safe_read (s, edata, sizeof(struct epoch_data)*epochs);
    if (rc != (int) (sizeof(struct epoch_data)*epochs)) {
	fprintf (stderr, "Cannot recieve epochs,rc=%d\n", rc);
	fprintf(stderr, "expecting %lu epochs, size %lu\n",epochs,sizeof(struct epoch_data)*epochs);
	return;
    }

    if (ehdr.flags&SYNC_LOGFILES) {
	rc = sync_logfiles (s);
	if (rc < 0) return;
    }

    // Start all the epochs at once
    for (u_long i = 0; i < epochs; i++) {
	ectl[i].cpid = fork ();
	if (ectl[i].cpid == 0) {
	    const char* args[256];
	    char attach[80];
	    char fake[80];
	    char ckpt[80];
	    int argcnt = 0;
	    
	    args[argcnt++] = "resume";
	    args[argcnt++] = "-p";
	    args[argcnt++] = ehdr.dirname;
	    args[argcnt++] = "--pthread";
	    args[argcnt++] = "../../eglibc-2.15/prefix/lib";
	    if (i > 0 || !ehdr.start_flag) {
		sprintf (attach, "--attach_offset=%d,%u", edata[i].start_pid, edata[i].start_clock);
		args[argcnt++] = attach;
	    }


	    if (edata[i].ckpt != 0) { 
		sprintf (ckpt, "--from_ckpt=%u", edata[i].ckpt);
		args[argcnt++] = ckpt;
		fprintf(stderr, "ckpt: %s\n",ckpt);
	    }
	    if (edata[i].start_level == 'u' && edata[i].stop_level == 'u') {
		sprintf (fake, "--fake_calls=%u,%u", edata[i].start_clock, edata[i].stop_clock);
		args[argcnt++] = fake;
	    } else if (edata[i].start_level == 'u') {
		sprintf (fake, "--fake_calls=%u", edata[i].start_clock);
		args[argcnt++] = fake;
	    } else if (edata[i].stop_level == 'u') {
		sprintf (fake, "--fake_calls=%u", edata[i].stop_clock);
		args[argcnt++] = fake;
	    }
	    args[argcnt++] = NULL;
		
	    rc = execv ("../../test/resume", (char **) args);
	    fprintf (stderr, "execl of resume failed, rc=%d, errno=%d\n", rc, errno);
	    return;
	} else {
	    ectl[i].status = STATUS_STARTING;
	    //create our listening process
	    ectl[i].waiting_on_rp_group = fork(); 
	    if(ectl[i].waiting_on_rp_group == 0) { 
		close(s);
		s = -99999;
		rc = -1;
		while(rc < 0){
		    rc = wait_for_replay_group(fd,ectl[i].cpid);
		}
		return;
	    }	    
	    gettimeofday (&ectl[i].tv_start, NULL);
	}
    }

    // Now attach pin to all of the epoch processes
    u_long executing = 0; 
    do {
	for (u_long i = 0; i < epochs; i++) {

	    rc = -1;
	    if (ectl[i].status == STATUS_STARTING) {
		
		rc = get_attach_status (fd, ectl[i].cpid);
		if (rc > 0) {
		    //sometimes we attach pin to a different process. 
		    //When we do this, we need to save the rc in case we are getting stats		   		    
		    ectl[i].attach_pid = rc; 


		    pid_t mpid = fork();
		    if (mpid == 0) {
			char cpids[80], syscalls[80], port[80], fork_flags[80];
			const char* args[256];
			int argcnt = 0;
			
			args[argcnt++] = "pin";
			args[argcnt++] = "-pid";
			sprintf (cpids, "%d", rc);
			args[argcnt++] = cpids;
			args[argcnt++] = "-t";
			args[argcnt++] = "../obj-ia32/linkage_data.so";

			/*
			 * I pulled this out b/c in multiproc case we might be 
			 * tracing a process that doesn't go all the way to the end
			 */
			sprintf (syscalls, "%d", edata[i].stop_clock);
			args[argcnt++] = "-l";
			args[argcnt++] = syscalls;

			sprintf (fork_flags, "%d", edata[i].fork_flags);
			args[argcnt++] = "-fork_flags";
			args[argcnt++] = fork_flags;		       			     
			  
			if (i < epochs-1 || !ehdr.finish_flag) {
			    args[argcnt++] = "-ao"; // Last epoch does not need to trace to final addresses
			}
			if (i > 0 || !ehdr.start_flag) {
			    args[argcnt++] = "-so";
			} 

			printf ("%lu: hostname %s port %d\n", i, edata[i].hostname, edata[i].port);
			args[argcnt++] = "-host";
			args[argcnt++] = edata[i].hostname;
			args[argcnt++] = "-port";
			sprintf (port, "%d", edata[i].port);
			args[argcnt++] = port;
			if (ehdr.filter_flags) args[argcnt++] = "-i";
			if (ehdr.filter_flags&FILTER_INET) {
			    args[argcnt++] = "-f";
			    args[argcnt++] = "inetsocket";
			} 
			if (ehdr.filter_flags&FILTER_PART) {
			    args[argcnt++] = "-e";
			    args[argcnt++] = ehdr.filter_part;
			}
			if (ehdr.filter_flags&FILTER_OUT) {
			    args[argcnt++] = "-ofb";
			    args[argcnt++] = ehdr.filter_output_after;
			}
			if (ehdr.record_trace) {
			    args[argcnt++] = "-rectrace";
			}
			args[argcnt++] = NULL;
			rc = execv ("../../../../pin/pin", (char **) args);
			fprintf (stderr, "execv of pin tool failed, rc=%d, errno=%d\n", rc, errno);
			return;
		    } else {
			gettimeofday (&ectl[i].tv_start_dift, NULL);			
			ectl[i].status = STATUS_EXECUTING;
			executing++;
#ifdef DETAILS			    
			printf ("%lu/%lu epochs executing\n", executing, epochs);
#endif
		    }
		}
	    }
	}
    } while (executing < epochs);


	
    // Wait for all children to complete
    u_long epochs_done = 0;
    for (u_long i = 0; i < epochs; i++) { 
	int status;
	pid_t wpid = waitpid (ectl[i].waiting_on_rp_group, &status, 0);
	if (wpid < 0) {
	    fprintf (stderr, "waitpid returns %d, errno %d\n", rc, errno);
	    return;
	} else {
#ifdef DETAILS
	    printf ("DIFT of epoch %lu is done\n", i);
#endif
	    gettimeofday (&ectl[i].tv_done, NULL);			
	    ectl[i].status = STATUS_DONE;
	    epochs_done++;	
	}
    }

    gettimeofday (&tv_done, NULL);
    printf ("Dift start time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("Dift end time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);

    for (u_long i = 0; i < epochs; i++) { 
	printf ("epoch %lu resume start  time: %ld.%06ld\n",i, ectl[i].tv_start.tv_sec, ectl[i].tv_start.tv_usec);
	printf ("epoch %lu pin start  time: %ld.%06ld\n", i, ectl[i].tv_start_dift.tv_sec, ectl[i].tv_start_dift.tv_usec);
	printf ("epoch %lu done  time: %ld.%06ld\n", i, ectl[i].tv_done.tv_sec, ectl[i].tv_done.tv_usec);
	gettimeofday (&ectl[i].tv_start_dift, NULL);			

    }


    if (tv_done.tv_usec >= tv_start.tv_usec) {
	printf ("Dift time: %ld.%06ld second\n", tv_done.tv_sec-tv_start.tv_sec, tv_done.tv_usec-tv_start.tv_usec);
    } else {
	printf ("Dift time: %ld.%06ld second\n", tv_done.tv_sec-tv_start.tv_sec-1, tv_done.tv_usec+1000000-tv_start.tv_usec);
    }
    
    fflush(stdout);


    if (ehdr.flags&SEND_ACK) {
	long retval = 0;
	rc = send (s, &retval, sizeof(retval), 0);
	if (rc != sizeof(retval)) {
	    fprintf (stderr, "Cannot send ack,rc=%d, errno %d\n", rc, errno);
	}
    }

    // send stats if requested
    if (ehdr.flags&SEND_STATS) {
	for (u_long i = 0; i < epochs; i++) {
	    char pathname[PATHLEN]; 
	    sprintf (pathname, "/tmp/%d/taint_stats", ectl[i].cpid);
	    if (send_file (s, pathname, "taint-stats") < 0) { 
		fprintf (stderr,"couldn't find /tmp/%d, howabout /tmp/%d?\n",ectl[i].cpid, ectl[i].attach_pid);
		sprintf (pathname, "/tmp/%d/taint_stats", ectl[i].attach_pid);
		send_file (s, pathname, "taint-stats");
	    }
	}
    }

    // Send trace recordings if requested
    if (ehdr.record_trace) {
	for (u_long i = 0; i < epochs; i++) {
	    char pathname[PATHLEN];
	    sprintf (pathname, "/trace_exec_.tmp.%d", ectl[i].cpid);
	    fprintf(stderr, "sending %s for %lu trace\n",pathname, i);
	    if (send_shmem (s, pathname, "trace_exec") < 0) { 
		fprintf (stderr,"couldn't find /trace_exec_.tmp.%d, howabout /trace_exec_.tmp.%d?\n",
			 ectl[i].cpid, ectl[i].attach_pid);
		sprintf (pathname, "/trace_exec_.tmp.%d", ectl[i].attach_pid);
		send_shmem (s, pathname, "trace_exec");
	    }


	    sprintf (pathname, "/trace_inst_.tmp.%d", ectl[i].cpid);
	    fprintf(stderr, "sending %s for %lu trace\n",pathname, i);	   
	    if (send_shmem (s, pathname, "trace_inst") < 0) { 
		fprintf (stderr,"couldn't find /trace_inst_.tmp.%d, howabout /trace_inst_.tmp.%d?\n",
			 ectl[i].cpid, ectl[i].attach_pid);
		sprintf (pathname, "/trace_inst_.tmp.%d", ectl[i].attach_pid);
		send_shmem (s, pathname, "trace_inst");
	    }

	}
    }


    close (s);
    close (fd);
#endif
}

void do_stream (int s, struct epoch_hdr& ehdr)
{
    int rc;
    struct timeval tv_start, tv_done;
    gettimeofday (&tv_start, NULL);

    u_long epochs = ehdr.epochs;
    struct epoch_ctl ectl[epochs];

    // Set up shared memory regions for queues
    u_long qcnt = epochs+1;  
    if (ehdr.finish_flag) qcnt--;
    for (u_long i = 0; i < qcnt; i++) {
	if (i == 0 && ehdr.start_flag) continue; // No queue needed
	sprintf(ectl[i].inputqhname, "/input_queue_hdr%lu", i);
	int iqfd = shm_open (ectl[i].inputqhname, O_CREAT|O_RDWR|O_TRUNC, 0644);	
	if (iqfd < 0) {
	    fprintf (stderr, "Cannot create input queue header %s,errno=%d\n", ectl[i].inputqhname, errno);
	    return;
	} 
	rc = ftruncate(iqfd, TAINTQHDRSIZE);
	if (rc < 0) {
	    fprintf (stderr, "Cannot truncate input queue header %s,errno=%d\n", ectl[i].inputqhname, errno);
	    return;
	}
	struct taintq_hdr* qh = (struct taintq_hdr *) mmap (NULL, TAINTQHDRSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, iqfd, 0);
	if (qh == MAP_FAILED) {
	    fprintf (stderr, "Cannot map input queue, errno=%d\n", errno);
	    return;
	}
	rc = sem_init(&(qh->epoch_sem), 1, 0);
	if (rc < 0) {
	    fprintf (stderr, "sem_init returns %d, errno=%d\n", rc, errno);
	    return;
	}

	pthread_mutexattr_t sharedm;
	pthread_mutexattr_init(&sharedm);
	pthread_mutexattr_setpshared(&sharedm, PTHREAD_PROCESS_SHARED);
	rc = pthread_mutex_init (&(qh->lock), &sharedm);
	if (rc < 0) {
	    fprintf (stderr, "pthread_mutex_init returns %d, errno=%d\n", rc, errno);
	    return;
	}
	pthread_condattr_t sharedc;
	pthread_condattr_init(&sharedc);
	pthread_condattr_setpshared(&sharedc, PTHREAD_PROCESS_SHARED);
	pthread_condattr_setclock(&sharedc,CLOCK_MONOTONIC);  //added for the timeouts
	rc = pthread_cond_init (&(qh->full), &sharedc);
	if (rc < 0) {
	    fprintf (stderr, "pthread_mutex_init returns %d, errno=%d\n", rc, errno);
	    return;
	}
	rc = pthread_cond_init (&(qh->empty), &sharedc);
	if (rc < 0) {
	    fprintf (stderr, "pthread_mutex_init returns %d, errno=%d\n", rc, errno);
	    return;
	}

	munmap(qh,TAINTQHDRSIZE);
	close (iqfd);

	sprintf(ectl[i].inputqbname, "/input_queue%lu", i);
	iqfd = shm_open (ectl[i].inputqbname, O_CREAT|O_RDWR|O_TRUNC, 0644);	
	if (iqfd < 0) {
	    fprintf (stderr, "Cannot create input queue %s,errno=%d\n", ectl[i].inputqbname, errno);
	    return;
	} 
	rc = ftruncate(iqfd, TAINTQSIZE);
	if (rc < 0) {
	    fprintf (stderr, "Cannot truncate input queue %s,errno=%d\n", ectl[i].inputqbname, errno);
	    return;
	}
	close (iqfd);

    }

    // Start a stream processor for all epochs at once
    if (!ehdr.start_flag) {
	if (fork() == 0) {
	    const char* args[256];
	    char parstring[80];
	    int argcnt = 0;
			    
	    args[argcnt++] = "stream";
	    args[argcnt++] = "NULL";
	    args[argcnt++] = "NULL";
	    args[argcnt++] = "-oq";
	    args[argcnt++] = ectl[0].inputqhname;
	    args[argcnt++] = ectl[0].inputqbname;
	    args[argcnt++] = "-oh";
	    args[argcnt++] = ehdr.prev_host;
	    if (ehdr.cmd_type == AGG_TYPE_SEQ) {
		args[argcnt++] = "-seq";
	    }
	    if (ehdr.cmd_type == AGG_TYPE_SEQ_PPL) {
		args[argcnt++] = "-seq";
		args[argcnt++] = "-ppl";
	    }
	    if (ehdr.cmd_type == AGG_TYPE_SEQ_PPG) {
		args[argcnt++] = "-seq";
		args[argcnt++] = "-ppg";
	    }
	    if (ehdr.flags&NW_COMPRESS) {
		args[argcnt++] = "-compress";
	    }
	    if (ehdr.flags&STREAM_LS) {
		args[argcnt++] = "-streamls";
	    }
	    args[argcnt++] = "-par";
	    sprintf (parstring, "%d", ehdr.parallelize);
	    args[argcnt++] = parstring;
	    args[argcnt++] = NULL;
	    
	    rc = execv ("./stream", (char **) args);
	    fprintf (stderr, "execv of stream failed, rc=%d, errno=%d\n", rc, errno);
	    return;
	}
    }
    if (!ehdr.finish_flag) {
	if (fork() == 0) {
	    const char* args[256];
	    char parstring[80];
	    int argcnt = 0;
			    
	    args[argcnt++] = "stream";
	    args[argcnt++] = "NULL";
	    args[argcnt++] = "NULL";
	    args[argcnt++] = "-iq";
	    args[argcnt++] = ectl[epochs].inputqhname;
	    args[argcnt++] = ectl[epochs].inputqbname;
	    args[argcnt++] = "-ih";
	    if (ehdr.cmd_type == AGG_TYPE_SEQ) {
		args[argcnt++] = "-seq";
	    }
	    if (ehdr.cmd_type == AGG_TYPE_SEQ_PPL) {
		args[argcnt++] = "-seq";
		args[argcnt++] = "-ppl";
	    }
	    if (ehdr.cmd_type == AGG_TYPE_SEQ_PPG) {
		args[argcnt++] = "-seq";
		args[argcnt++] = "-ppg";
	    }
	    if (ehdr.flags&NW_COMPRESS) {
		args[argcnt++] = "-compress";
	    }
	    if (ehdr.flags&STREAM_LS) {
		args[argcnt++] = "-streamls";
	    }
	    args[argcnt++] = "-par";
	    sprintf (parstring, "%d", ehdr.parallelize);
	    args[argcnt++] = parstring;
	    args[argcnt++] = NULL;
	    
	    rc = execv ("./stream", (char **) args);
	    fprintf (stderr, "execv of stream failed, rc=%d, errno=%d\n", rc, errno);
	    return;
	}
    }
    for (u_long i = 0; i < epochs; i++) {
	
	ectl[i].spid = fork ();
	if (ectl[i].spid == 0) {
	    // Now start up a stream processor for this epoch
	    const char* args[256];
	    char dirname[80], port[80], parstring[80];
	    int argcnt = 0;
			    
	    args[argcnt++] = "stream";
	    sprintf (dirname, "/tmp/%ld",i);
	    args[argcnt++] = dirname;
	    sprintf (port, "%ld", AGG_BASE_PORT+(i)); 
	    args[argcnt++] = port;
	    if (i < epochs-1 || !ehdr.finish_flag) {
		args[argcnt++] = "-iq";
		args[argcnt++] = ectl[i+1].inputqhname;
		args[argcnt++] = ectl[i+1].inputqbname;
	    }
	    if (i > 0 || !ehdr.start_flag) {
		args[argcnt++] = "-oq";
		args[argcnt++] = ectl[i].inputqhname;
		args[argcnt++] = ectl[i].inputqbname;
	    }
	    if (ehdr.cmd_type == AGG_TYPE_SEQ) {
		args[argcnt++] = "-seq";
	    }
	    if (ehdr.cmd_type == AGG_TYPE_SEQ_PPL) {
		args[argcnt++] = "-seq";
		args[argcnt++] = "-ppl";
	    }
	    if (ehdr.cmd_type == AGG_TYPE_SEQ_PPG) {
		args[argcnt++] = "-seq";
		args[argcnt++] = "-ppg";
	    }
	    if (ehdr.flags&LOW_MEMORY) {
		args[argcnt++] = "-lowmem";
	    }
	    if (ehdr.flags&STREAM_LS) {
		args[argcnt++] = "-streamls";
	    }
	    args[argcnt++] = "-par";
	    sprintf (parstring, "%d", ehdr.parallelize);
	    args[argcnt++] = parstring;
	    args[argcnt++] = NULL;
	    
	    rc = execv ("./stream", (char **) args);
	    fprintf (stderr, "execv of stream failed, rc=%d, errno=%d\n", rc, errno);
	    return;
	} else {
	    ectl[i].status = STATUS_STREAM;
	}
    }

    for (int i = (int)(epochs-1); i >= 0; i--) {
	int status;
	pid_t wpid = waitpid (ectl[i].spid, &status, 0);
	if (wpid < 0) {
	    fprintf (stderr, "waitpid of %d/%d returns %d, errno %d\n", i, ectl[i].spid, rc, errno);
	    return;
	} else {
	    ectl[i].status = STATUS_DONE;
	}
    } 

    gettimeofday (&tv_done, NULL);
    if (ehdr.flags&SEND_ACK) {
	uint32_t retval = 0;
	rc = send (s, &retval, sizeof(retval), 0);
	if (rc != sizeof(retval)) {
	    fprintf (stderr, "Cannot send ack,rc=%d\n", rc);
	}
    }

    // Clean up shared memory regions for queues
    for (u_long i = 0; i < qcnt; i++) {
	if (i == 0 && ehdr.start_flag) continue; // No queue needed
	rc = shm_unlink (ectl[i].inputqhname);
	if (rc < 0) {
	    fprintf (stderr, "Cannot unlink input queue %s,errno=%d\n", ectl[i].inputqhname, errno);
	    return;
	}
	rc = shm_unlink (ectl[i].inputqbname);
	if (rc < 0) {
	    fprintf (stderr, "Cannot unlink input queue %s,errno=%d\n", ectl[i].inputqbname, errno);
	    return;
	}
    }

    printf ("Stream start time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("Stream end time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);
    if (tv_done.tv_usec >= tv_start.tv_usec) {
	printf ("Stream time: %ld.%06ld second\n", tv_done.tv_sec-tv_start.tv_sec, tv_done.tv_usec-tv_start.tv_usec);
    } else {
	printf ("Stream time: %ld.%06ld second\n", tv_done.tv_sec-tv_start.tv_sec-1, tv_done.tv_usec+1000000-tv_start.tv_usec);
    }
    
    fflush(stdout);
    // send results if requeted
    if (ehdr.flags&SEND_RESULTS) {
	for (u_long i = 0; i < epochs; i++) {
	    char pathname[PATHLEN];
	    sprintf (pathname, "/tmp/%ld/merge-addrs", i);
	    send_shmem (s, pathname, "merge-addrs");
	    for (int j = 0; j < ehdr.parallelize; j++) {
		char filename[256];
		sprintf (pathname, "/tmp/%ld/merge-outputs-resolved-%d", i, j);
		sprintf (filename, "merge-outputs-resolved-%d", j);
		send_shmem (s, pathname, filename);
	    }
	    sprintf (pathname, "/tmp/%ld/tokens", i);
	    send_shmem (s, pathname, "tokens");
	    sprintf (pathname, "/tmp/%ld/dataflow.results", i);
	    send_shmem (s, pathname, "dataflow.results");
	}
    }
    
    // send stats if requested
    if (ehdr.flags&SEND_STATS) {
	for (u_long i = 0; i < epochs; i++) {
	    char pathname[PATHLEN];
	    sprintf (pathname, "/tmp/%ld/stream-stats", i);
	    send_file (s, pathname, "stream-stats");
	}
    }

    close (s);
}

void* do_request (void* arg) 
{
    long s = (long) arg;

    // Receive control data
    struct epoch_hdr ehdr;
    int rc = safe_read (s, &ehdr, sizeof(ehdr));
    if (rc != sizeof(ehdr)) {
	fprintf (stderr, "Cannot recieve header,rc=%d\n", rc);
	return NULL;
    }
    if (ehdr.cmd_type == DO_DIFT) {
	do_dift (s, ehdr);
    } else {
	do_stream (s, ehdr);
    }
    return NULL;
}

int main (int argc, char* argv[]) 
{
    int rc; 
    if(argc > 1)
	agg_port = atoi(argv[1]);   

    // Listen for incoming commands
    int c = socket (AF_INET, SOCK_STREAM, 0);
    if (c < 0) {
	fprintf (stderr, "Cannot create listening socket, errno=%d\n", errno);
	return c;
    }

    int on = 1;
    rc = setsockopt (c, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (rc < 0) {
	fprintf (stderr, "Cannot set socket option, errno=%d\n", errno);
	return rc;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    if(agg_port > 0)
	addr.sin_port = htons(agg_port);
    else 
	addr.sin_port = htons(STREAMSERVER_PORT);

    addr.sin_addr.s_addr = INADDR_ANY;
    rc = bind (c, (struct sockaddr *) &addr, sizeof(addr));
    if (rc < 0) {
	fprintf (stderr, "in streamserver, agg_port %d\n", agg_port);
	fprintf (stderr, "Cannot bind socket, errno=%d\n", errno);
	return rc;
    }

    rc = listen (c, 5);
    if (rc < 0) {
	fprintf (stderr, "Cannot listen on socket, errno=%d\n", errno);
	return rc;
    }

    while (1) {
      
	long s = accept (c, NULL, NULL);
	if (s < 0) {
	    fprintf (stderr, "Cannot accept connection, errno=%d\n", errno);
	    return s;
	}
	
	// Spawn a thread to handle this request
	pthread_t tid;
 	rc = pthread_create (&tid, NULL, do_request, (void *) s);
	if (rc < 0) {
	    fprintf (stderr, "Cannot spawn stream thread,rc=%d\n", rc);
	}
    }

    return 0;
}
