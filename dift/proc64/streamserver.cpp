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
    char   inputqname[256];
    pid_t  cpid;
    pid_t  spid;
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
	    if (i > 0 || !ehdr.start_flag) {
		char attach[80];
		sprintf (attach, "--attach_offset=%d,%u", edata[i].start_pid, edata[i].start_syscall);
		rc = execl("../../test/resume", "resume", "-p", ehdr.dirname, "--pthread", "../../eglibc-2.15/prefix/lib", attach, NULL);
	    } else {
		rc = execl("../../test/resume", "resume", "-p", ehdr.dirname, "--pthread", "../../eglibc-2.15/prefix/lib", NULL);
	    }
	    fprintf (stderr, "execl of resume failed, rc=%d, errno=%d\n", rc, errno);
	    return;
	} else {
	    ectl[i].status = STATUS_STARTING;
	}
    }

    // Now attach pin to all of the epoch processes
    u_long executing = 0; 
    do {
	for (u_long i = 0; i < epochs; i++) {
	    if (ectl[i].status == STATUS_STARTING) {
		rc = get_attach_status (fd, ectl[i].cpid);
		if (rc > 0) {
		    pid_t mpid = fork();
		    if (mpid == 0) {
			char cpids[80], syscalls[80], output_filter[80], port[80];
			const char* args[256];
			int argcnt = 0;
			
			args[argcnt++] = "pin";
			args[argcnt++] = "-pid";
			sprintf (cpids, "%d", rc);
			args[argcnt++] = cpids;
			args[argcnt++] = "-t";
			args[argcnt++] = "../obj-ia32/linkage_data.so";
			if (i < epochs-1 || !ehdr.finish_flag) {
			    sprintf (syscalls, "%d", edata[i].stop_syscall);
			    args[argcnt++] = "-l";
			    args[argcnt++] = syscalls;
			    args[argcnt++] = "-ao"; // Last epoch does not need to trace to final addresses
			}
			if (i > 0 || !ehdr.start_flag) {
			    args[argcnt++] = "-so";
			} 
			if (edata[i].filter_syscall) {
			    sprintf (output_filter, "%u", edata[i].filter_syscall);
			    args[argcnt++] = "-ofs";
			    args[argcnt++] = output_filter;
			}
			printf ("%lu: hostname %s port %d\n", i, edata[i].hostname, edata[i].port);
			args[argcnt++] = "-host";
			args[argcnt++] = edata[i].hostname;
			args[argcnt++] = "-port";
			sprintf (port, "%d", edata[i].port);
			args[argcnt++] = port;
			args[argcnt++] = NULL;
			args[argcnt++] = NULL;
			rc = execv ("../../../../pin/pin", (char **) args);
			fprintf (stderr, "execv of pin tool failed, rc=%d, errno=%d\n", rc, errno);
			return;
		    } else {
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
    for (u_long i = 0; i < epochs; i++) {
	int status;
	pid_t wpid = waitpid (ectl[i].cpid, &status, 0);
	if (wpid < 0) {
	    fprintf (stderr, "DIFT waitpid for %d returns %d, errno %d\n", ectl[i].cpid, wpid, errno);
	    return;
	} else {
	    ectl[i].status = STATUS_DONE;
	}
    }

    gettimeofday (&tv_done, NULL);

    if (ehdr.flags&SEND_ACK) {
	long retval = 0;
	rc = send (s, &retval, sizeof(retval), 0);
	if (rc != sizeof(retval)) {
	    fprintf (stderr, "Cannot send ack,rc=%d\n", rc);
	}
    }

    printf ("Dift start time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("Dift end time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);
    if (tv_done.tv_usec >= tv_start.tv_usec) {
	printf ("Dift time: %ld.%06ld second\n", tv_done.tv_sec-tv_start.tv_sec, tv_done.tv_usec-tv_start.tv_usec);
    } else {
	printf ("Dift time: %ld.%06ld second\n", tv_done.tv_sec-tv_start.tv_sec-1, tv_done.tv_usec+1000000-tv_start.tv_usec);
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
	sprintf(ectl[i].inputqname, "/input_queue%d.%lu",agg_port, i);
	int iqfd = shm_open (ectl[i].inputqname, O_CREAT|O_RDWR|O_TRUNC, 0644);	
	if (iqfd < 0) {
	    fprintf (stderr, "Cannot create input queue %s,errno=%d\n", ectl[i].inputqname, errno);
	    return;
	} 
	rc = ftruncate(iqfd, TAINTQSIZE);
	if (rc < 0) {
	    fprintf (stderr, "Cannot truncate input queue %s,errno=%d\n", ectl[i].inputqname, errno);
	    return;
	}
	struct taintq* q = (struct taintq *) mmap (NULL, TAINTQSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, iqfd, 0);
	if (q == MAP_FAILED) {
	    fprintf (stderr, "Cannot map input queue, errno=%d\n", errno);
	    return;
	}
	rc = sem_init(&(q->epoch_sem), 1, 0);
	if (rc < 0) {
	    fprintf (stderr, "sem_init returns %d, errno=%d\n", rc, errno);
	    return;
	}
	munmap(q,TAINTQSIZE);
	close (iqfd);
    }

    // Start a stream processor for all epochs at once
    printf ("Starting %ld epochs\n", epochs);
    printf ("dir %s\n", ehdr.dirname);
    for (u_long i = 0; i < epochs; i++) {
	
	ectl[i].spid = fork ();
	if (ectl[i].spid == 0) {
	    // Now start up a stream processor for this epoch
	    const char* args[256];
	    char dirname[80], port[80];
	    int argcnt = 0;
			    
	    args[argcnt++] = "stream";
	    sprintf (dirname, "/tmp/%d.%ld", agg_port,i);
	    args[argcnt++] = dirname;
	    sprintf (port, "%ld", agg_port+(i+1));
	    args[argcnt++] = port;
	    if (i < epochs-1 || !ehdr.finish_flag) {
		args[argcnt++] = "-iq";
		args[argcnt++] = ectl[i+1].inputqname;
	    }
	    if (i == epochs-1 && !ehdr.finish_flag) {
		args[argcnt++] = "-ih";
	    }
	    if (i > 0 || !ehdr.start_flag) {
		args[argcnt++] = "-oq";
		args[argcnt++] = ectl[i].inputqname;
	    }
	    if (i == 0 && !ehdr.start_flag) {
		args[argcnt++] = "-oh";
		args[argcnt++] = ehdr.prev_host;
		printf ("Setting up output queue to %s\n", ehdr.prev_host);
	    }
	    if (ehdr.cmd_type == AGG_TYPE_SEQ) {
		args[argcnt++] = "-seq";
	    }
	    args[argcnt++] = NULL;
	    
	    rc = execv ("./stream", (char **) args);
	    fprintf (stderr, "execv of stream failed, rc=%d, errno=%d\n", rc, errno);
	    return;
	} else {
	    ectl[i].status = STATUS_STREAM;
	}
    }

    for (int i = (int) epochs-1; i >= 0; i--) {
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
	rc = shm_unlink (ectl[i].inputqname);
	if (rc < 0) {
	    fprintf (stderr, "Cannot unlink input queue %s,errno=%d\n", ectl[i].inputqname, errno);
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
	diff_usec = ectl[i].tv_done.tv_usec - ectl[i].tv_start_stream.tv_usec;
        carryover = 0;
        if(diff_usec < 0) {
	    carryover = -1;
	    diff_usec = 1 - diff_usec;
	}
        diff_sec = ectl[i].tv_done.tv_sec - ectl[i].tv_start_stream.tv_sec - carryover;
	printf ("\tStart -> End: %ld.%06ld\n", diff_sec,diff_usec);


   }
    
    fflush(stdout);
    // send results if requeted
    if (ehdr.flags&SEND_RESULTS) {
	for (u_long i = 0; i < epochs; i++) {
	    char pathname[PATHLEN];

//  Changes so that we can have a separate agg_port... not sure that we need these. 

	    sprintf (pathname, "/tmp/%d.%d/merge-addrs", agg_port, ectl[i].cpid);
	    send_file (s, pathname, "merge-addrs");
	    sprintf (pathname, "/tmp/%d.%d/merge-outputs-resolved", agg_port, ectl[i].cpid);
	    send_file (s, pathname, "merge-outputs-resolved");
	    sprintf (pathname, "/tmp/%d.%d/tokens", agg_port, ectl[i].cpid);
	    send_file (s, pathname, "tokens");
	    sprintf (pathname, "/tmp/%d.%d/dataflow.result", agg_port,ectl[i].cpid);
/*
	    sprintf (pathname, "/tmp/%ld/merge-addrs", i);
	    send_file (s, pathname, "merge-addrs");
	    sprintf (pathname, "/tmp/%ld/merge-outputs-resolved", i);
	    send_file (s, pathname, "merge-outputs-resolved");
	    sprintf (pathname, "/tmp/%ld/tokens", i);
	    send_file (s, pathname, "tokens");
	    sprintf (pathname, "/tmp/%ld/dataflow.results", i);
	    send_file (s, pathname, "dataflow.results");	    
*/
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
    printf ("Recevied command %d\n", ehdr.cmd_type);
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
      
	printf ("About to accept\n");
	long s = accept (c, NULL, NULL);
	printf ("Accept returns %ld\n", s);
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
