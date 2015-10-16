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

#include "streamserver.h"
#include "streamnw.h"

//#define DETAILS

#define STATUS_INIT 0
#define STATUS_STARTING 1
#define STATUS_EXECUTING 2
#define STATUS_STREAM 3
#define STATUS_DONE 4

struct epoch_ctl {
    int    status;
    char   inputqname[256];
    pid_t  cpid;
    pid_t  spid;

    // For timings
    struct timeval tv_start_stream;
    struct timeval tv_done;
};

// May eventually want to support >1 taint tracking at the same time, but not for now.
void* do_stream (void* arg) 
{
    long s = (long) arg;
    int rc;
    struct timeval tv_start, tv_done;

    gettimeofday (&tv_start, NULL);

    // Receive control data
    struct epoch_hdr ehdr;
    rc = safe_read (s, &ehdr, sizeof(ehdr));
    if (rc != sizeof(ehdr)) {
	fprintf (stderr, "Cannot recieve header,rc=%d\n", rc);
	return NULL;
    }
    u_long epochs = ehdr.epochs;

    struct epoch_ctl ectl[epochs];

    // Set up shared memory regions for queues
    u_long qcnt = epochs+1;  
    if (ehdr.finish_flag) qcnt--;
    for (u_long i = 0; i < qcnt; i++) {
	if (i == 0 && ehdr.start_flag) continue; // No queue needed
	sprintf(ectl[i].inputqname, "/input_queue%lu", i);
	int iqfd = shm_open (ectl[i].inputqname, O_CREAT|O_RDWR|O_TRUNC, 0644);	
	if (iqfd < 0) {
	    fprintf (stderr, "Cannot create input queue %s,errno=%d\n", ectl[i].inputqname, errno);
	    return NULL;
	} 
	rc = ftruncate(iqfd, TAINTQSIZE);
	if (rc < 0) {
	    fprintf (stderr, "Cannot truncate input queue %s,errno=%d\n", ectl[i].inputqname, errno);
	    return NULL;
	}
	close (iqfd);
    }

    // Start a stream processor for all epochs at once
    printf ("Starting %ld epochs\n", epochs);
    for (u_long i = 0; i < epochs; i++) {
	
	ectl[i].spid = fork ();
	if (ectl[i].spid == 0) {
	    // Now start up a stream processor for this epoch
	    const char* args[256];
	    char dirname[80], port[80];
	    int argcnt = 0;
			    
	    args[argcnt++] = "stream";
	    sprintf (dirname, "/tmp/%ld", i);
	    args[argcnt++] = dirname;
	    sprintf (port, "%ld", 10000+i);
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
		args[argcnt++] = ehdr.next_host;
	    }
	    args[argcnt++] = NULL;
	    
	    rc = execv ("./stream", (char **) args);
	    fprintf (stderr, "execv of stream failed, rc=%d, errno=%d\n", rc, errno);
	    return NULL;
	} else {
	    gettimeofday (&ectl[i].tv_start_stream, NULL);
	    ectl[i].status = STATUS_STREAM;
	}
    }

    uint32_t epochs_done = 0;
    do {
	int status;
	pid_t wpid = waitpid (-1, &status, 0);
	if (wpid < 0) {
	    fprintf (stderr, "waitpid returns %d, errno %d\n", rc, errno);
	    return NULL;
	} else {
	    for (uint32_t i = 0; i < epochs; i++) {
		if (wpid == ectl[i].spid) {
		    gettimeofday (&ectl[i].tv_done, NULL);
		    ectl[i].status = STATUS_DONE;
		    epochs_done++;
		}
	    }
	}
    } while (epochs_done < epochs);

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
	    return NULL;
	}
    }

    printf ("Overall:\n");
    printf ("\tStart time: %ld.%06ld\n", tv_start.tv_sec, tv_start.tv_usec);
    printf ("\tEnd time: %ld.%06ld\n", tv_done.tv_sec, tv_done.tv_usec);
    for (u_long i = 0; i < epochs; i++) {
	printf ("Epoch %lu:\n", i); 
	printf ("\tStream start time: %ld.%06ld\n", ectl[i].tv_start_stream.tv_sec, ectl[i].tv_start_stream.tv_usec);
	printf ("\tEpoch end time: %ld.%06ld\n", ectl[i].tv_done.tv_sec, ectl[i].tv_done.tv_usec);
   }

    // send results if requeted
    if (ehdr.flags&SEND_RESULTS) {
	for (u_long i = 0; i < epochs; i++) {
	    char pathname[PATHLEN];
	    sprintf (pathname, "/tmp/%d/merge-addrs", ectl[i].cpid);
	    send_file (s, pathname, "merge-addrs");
	    sprintf (pathname, "/tmp/%d/merge-outputs-resolved", ectl[i].cpid);
	    send_file (s, pathname, "merge-outputs-resolved");
	    sprintf (pathname, "/tmp/%d/tokens", ectl[i].cpid);
	    send_file (s, pathname, "tokens");
	    sprintf (pathname, "/tmp/%d/dataflow.result", ectl[i].cpid);
	    send_file (s, pathname, "dataflow.results");
	}
    }

    close (s);
    return NULL;
}

int main (int argc, char* argv[]) 
{
    int rc; 

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
    addr.sin_port = htons(STREAMSERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    rc = bind (c, (struct sockaddr *) &addr, sizeof(addr));
    if (rc < 0) {
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
 	rc = pthread_create (&tid, NULL, do_stream, (void *) s);
	if (rc < 0) {
	    fprintf (stderr, "Cannot spawn stream thread,rc=%d\n", rc);
	}
    }

    return 0;
}
