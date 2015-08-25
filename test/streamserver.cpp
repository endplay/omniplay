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

#include <atomic>
using namespace std;

#include "util.h"
#include "streamserver.h"


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
    struct timeval tv_start;
    struct timeval tv_start_dift;
    struct timeval tv_start_stream;
    struct timeval tv_done;
};

int fd; // Persistent descriptor for replay device

// May eventually want to support >1 taint tracking at the same time, but not for now.
void* do_stream (void* arg) 
{
    int s = (int) arg;
    int rc;
    struct timeval tv_start, tv_done;

    gettimeofday (&tv_start, NULL);

    // Receive control data
    struct epoch_hdr ehdr;
    rc = read (s, &ehdr, sizeof(ehdr));
    if (rc != sizeof(ehdr)) {
	fprintf (stderr, "Cannot recieve header,rc=%d\n", rc);
	return NULL;
    }
    u_long epochs = ehdr.epochs;

    struct epoch_data edata[epochs];
    struct epoch_ctl ectl[epochs];

    rc = read (s, edata, sizeof(struct epoch_data)*epochs);
    if (rc != sizeof(struct epoch_data)*epochs) {
	fprintf (stderr, "Cannot recieve epochs,rc=%d\n", rc);
	return NULL;
    }

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

    // Start all the epochs at once
    for (u_long i = 0; i < epochs; i++) {
	ectl[i].cpid = fork ();
	if (ectl[i].cpid == 0) {
	    if (i > 0) {
		char attach[80];
		sprintf (attach, "--attach_offset=%d,%lu", edata[i].start_pid, edata[i].start_syscall);
		rc = execl("./resume", "resume", "-p", ehdr.dirname, "--pthread", "../eglibc-2.15/prefix/lib", attach, NULL);
	    } else {
		rc = execl("./resume", "resume", "-p", ehdr.dirname, "--pthread", "../eglibc-2.15/prefix/lib", NULL);
	    }
	    fprintf (stderr, "execl of resume failed, rc=%d, errno=%d\n", rc, errno);
	    return NULL;
	} else {
	    gettimeofday (&ectl[i].tv_start, NULL);
	    ectl[i].status = STATUS_STARTING;
	}
    }

    // Now attach pin to all of the epoch processes
    u_long executing = 0; 
    do {
	for (u_long i = 0; i < epochs; i++) {
	    if (ectl[i].status == STATUS_STARTING) {
		rc = get_attach_status (fd, ectl[i].cpid);
		if (rc == 1) {
		    pid_t mpid = fork();
		    if (mpid == 0) {
			char cpids[80], syscalls[80], output_filter[80];
			const char* args[256];
			int argcnt = 0;
			
			args[argcnt++] = "pin";
			args[argcnt++] = "-pid";
			sprintf (cpids, "%d", ectl[i].cpid);
			args[argcnt++] = cpids;
			args[argcnt++] = "-t";
			args[argcnt++] = "../dift/obj-ia32/linkage_data.so";
			if (i < epochs-1) {
			    if (i == 0) {
				sprintf (syscalls, "%ld", edata[i].stop_syscall);
			    } else {
				sprintf (syscalls, "%ld", edata[i].stop_syscall-edata[i].start_syscall+1);
			    }
			args[argcnt++] = "-l";
			args[argcnt++] = syscalls;
			args[argcnt++] = "-ao"; // Last epoch does not need to trace to final addresses
			}
			if (i > 0) {
			    args[argcnt++] = "-so";
			} 
			if (edata[i].filter_syscall) {
			    sprintf (output_filter, "%lu", edata[i].filter_syscall);
			    args[argcnt++] = "-ofs";
			    args[argcnt++] = output_filter;
			}
			args[argcnt++] = NULL;
			rc = execv ("../../../pin/pin", (char **) args);
			fprintf (stderr, "execv of pin tool failed, rc=%d, errno=%d\n", rc, errno);
		    return NULL;
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
	
    // Wait for children to complete
    u_long epochs_done = 0;
    do {
	int status;
	pid_t wpid = waitpid (-1, &status, 0);
	if (wpid < 0) {
	    fprintf (stderr, "waitpid returns %d, errno %d\n", rc, errno);
	    return NULL;
	} else {
	    for (u_long i = 0; i < epochs; i++) {
		if (wpid == ectl[i].cpid) {
#ifdef DETAILS
		    printf ("DIFT of epoch %lu is done\n", i);
#endif
		    ectl[i].spid = fork ();
		    if (ectl[i].spid == 0) {
			// Now start up a stream processor for this epoch
			const char* args[256];
			char dirname[80];
			int argcnt = 0;
			    
			args[argcnt++] = "stream";
			sprintf (dirname, "/tmp/%d", ectl[i].cpid);
			args[argcnt++] = dirname;
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
			
			rc = execv ("../dift/obj-ia32/stream", (char **) args);
			fprintf (stderr, "execv of stream failed, rc=%d, errno=%d\n", rc, errno);
			return NULL;
		    } else {
			gettimeofday (&ectl[i].tv_start_stream, NULL);
			ectl[i].status = STATUS_STREAM;
		    }
		} else if (wpid == ectl[i].spid) {
		    gettimeofday (&ectl[i].tv_done, NULL);
		    ectl[i].status = STATUS_DONE;
		    epochs_done++;
		}
	    }
	}
    } while (epochs_done < epochs);

    gettimeofday (&tv_done, NULL);
    
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
	printf ("\tEpoch start time: %ld.%06ld\n", ectl[i].tv_start.tv_sec, ectl[i].tv_start.tv_usec);
	printf ("\tDIFT start time: %ld.%06ld\n", ectl[i].tv_start_dift.tv_sec, ectl[i].tv_start_dift.tv_usec);
	printf ("\tStream start time: %ld.%06ld\n", ectl[i].tv_start_stream.tv_sec, ectl[i].tv_start_stream.tv_usec);
	printf ("\tEpoch end time: %ld.%06ld\n", ectl[i].tv_done.tv_sec, ectl[i].tv_done.tv_usec);
   }

    return NULL;
}

int main (int argc, char* argv[]) 
{
    struct timeval tv_start, tv_start_merge, tv_done;
    char dirname[80];
    int rc, status, epochs, gstart, gend, i, executing, epochs_done;
    struct epoch* epoch;
    
    pid_t ppid;
    u_long merge_entries = 0;
    int group_by = 0;

    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror("open /dev/spec0");
	return fd;
    }

    // Listen for incoming commands
    int c = socket (AF_INET, SOCK_STREAM, 0);
    if (c < 0) {
	fprintf (stderr, "Cannot create listening socket, errno=%d\n", errno);
	return c;
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
      
	int s = accept (c, NULL, NULL);
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
