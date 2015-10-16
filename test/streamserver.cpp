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

#include "util.h"
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
    rc = safe_read (s, &ehdr, sizeof(ehdr));
    if (rc != sizeof(ehdr)) {
	fprintf (stderr, "Cannot recieve header,rc=%d\n", rc);
	return NULL;
    }
    u_long epochs = ehdr.epochs;

    struct epoch_data edata[epochs];
    struct epoch_ctl ectl[epochs];

    rc = safe_read (s, edata, sizeof(struct epoch_data)*epochs);
    if (rc != (int) (sizeof(struct epoch_data)*epochs)) {
	fprintf (stderr, "Cannot recieve epochs,rc=%d\n", rc);
	return NULL;
    }

    if (ehdr.flags&SYNC_LOGFILES) {
	u_long fcnt, ccnt;
	bool* freply = NULL;
	bool* creply = NULL;
	vector<struct replay_path> dirs;
	vector<struct replay_path> future_filenames;

	rc = safe_read (s, &fcnt, sizeof(fcnt));
	if (rc != sizeof(fcnt)) {
	    fprintf (stderr, "Cannot recieve file count,rc=%d\n", rc);
	    return NULL;
	}
	
	if (fcnt) {
	    freply = (bool *) malloc(sizeof(bool)*fcnt);
	    if (freply == NULL) {
		fprintf (stderr, "Cannot allocate file reply array of size %lu\n", fcnt);
		return NULL;
	    }

	    for (u_long i = 0; i < fcnt; i++) {
		replay_path fpath;
		rc = safe_read (s, &fpath, sizeof(fpath));
		if (rc != sizeof(fpath)) {
		    fprintf (stderr, "Cannot recieve file path,rc=%d\n", rc);
		    return NULL;
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
		return NULL;
	    }
	}

	rc = safe_read (s, &ccnt, sizeof(ccnt));
	if (rc != sizeof(fcnt)) {
	    fprintf (stderr, "Cannot recieve cache count,rc=%d\n", rc);
	    return NULL;
	}

	if (ccnt) {
	    creply = (bool *) malloc(sizeof(bool)*ccnt);
	    if (creply == NULL) {
		fprintf (stderr, "Cannot allocate cache reply array of size %lu\n", ccnt);
		return NULL;
	    }

	    for (u_long i = 0; i < ccnt; i++) {
		struct cache_info ci;
		rc = safe_read (s, &ci, sizeof(ci));
		if (rc != sizeof(ci)) {
		    fprintf (stderr, "Cannot recieve cache info,rc=%d\n", rc);
		    return NULL;
		}
		
		// Does this file exist?
		char cname[PATHLEN], cmname[PATHLEN], crname[PATHLEN];
		struct stat64 st;
		struct replay_path future_filename;

		sprintf (cname, "/replay_cache/%x_%x", ci.dev, ci.ino);
		rc = stat64 (cname, &st);
		if (rc == 0) {
		    // Is this the right version?
		    if (st.st_mtim.tv_sec == ci.mtime.tv_sec && st.st_mtim.tv_nsec == ci.mtime.tv_nsec) {
			creply[i] = false;
		    } else {
			// Nope - but maybe we have it?
			sprintf (cmname, "/replay_cache/%x_%x_%lu_%lu", ci.dev, ci.ino, ci.mtime.tv_sec, ci.mtime.tv_nsec);
			rc = stat64 (cmname, &st);
			if (rc == 0) {
			    creply[i] = false;
			} else {
			    creply[i] = true;
			    if (st.st_mtim.tv_sec > ci.mtime.tv_sec || 
				(st.st_mtim.tv_sec == ci.mtime.tv_sec && st.st_mtim.tv_nsec > ci.mtime.tv_nsec)) {
				// New file is past version 
				strcpy (future_filename.path, cmname);
				future_filenames.push_back(future_filename);
			    } else {
				// Existing file is past version
				sprintf (crname, "/replay_cache/%x_%x_%lu_%lu", ci.dev, ci.ino, st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
				rc = rename (cname, crname);
				if (rc < 0) {
				    fprintf (stderr, "Cannot rename cache file %s to %s, rc=%d\n", cname, crname, rc);
				    return NULL;
				}
				strcpy (future_filename.path, cname);
				future_filenames.push_back(future_filename);
			    }
			}
		    }
		} else {
		    // No versions at all
		    creply[i] = true;
		    strcpy (future_filename.path, cname);
		    future_filenames.push_back(future_filename);
		}
	    }
	    
	    // Send back response
	    rc = safe_write (s, creply, sizeof(bool)*ccnt);
	    if (rc != (int) (sizeof(bool)*ccnt)) {
		fprintf (stderr, "Cannot send cache info check reply,rc=%d\n", rc);
		return NULL;
	    }
	}

	// Now receive the files we requested
	u_long dcnt = 0;
	for (u_long i = 0; i < fcnt; i++) {
	    if (freply[i]) {
		rc = fetch_file (s, dirs[dcnt++].path);
		if (rc < 0) return NULL;
	    }
	} 

	u_long ffcnt = 0;
	for (u_long i = 0; i < ccnt; i++) {
	    if (creply[i]) {
		rc = fetch_file (s, "/replay_cache");
		if (rc < 0) return NULL;

		// Now rename the file to the correct version
		rc = rename ("/replay_cache/rename_me", future_filenames[ffcnt].path);
		if (rc < 0) {
		    fprintf (stderr, "Cannot rename temp cache file to %s, rc=%d\n", future_filenames[ffcnt].path, rc);
		    return NULL;
		}
		ffcnt++;
	    }
	} 

	free (freply);
	free (creply);
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
	    if (i > 0 || !ehdr.start_flag) {
		char attach[80];
		sprintf (attach, "--attach_offset=%d,%u", edata[i].start_pid, edata[i].start_syscall);
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
		      char cpids[80], syscalls[80], output_filter[80], port[80];
			const char* args[256];
			int argcnt = 0;
			
			args[argcnt++] = "pin";
			args[argcnt++] = "-pid";
			sprintf (cpids, "%d", ectl[i].cpid);
			args[argcnt++] = cpids;
			args[argcnt++] = "-t";
			args[argcnt++] = "../dift/obj-ia32/linkage_data.so";
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
			args[argcnt++] = "-host";
			args[argcnt++] = edata[i].hostname;
			args[argcnt++] = "-port";
			sprintf (port, "%d", edata[i].port);
			args[argcnt++] = port;
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
		    gettimeofday (&ectl[i].tv_done, NULL);
		    ectl[i].status = STATUS_DONE;
		    epochs_done++;
		}
	    }
	}
    } while (epochs_done < epochs);

    gettimeofday (&tv_done, NULL);
    if (ehdr.flags&SEND_ACK) {
	long retval = 0;
	rc = send (s, &retval, sizeof(retval), 0);
	if (rc != sizeof(retval)) {
	    fprintf (stderr, "Cannot send ack,rc=%d\n", rc);
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

    close (s);
    return NULL;
}

// This is for a 32-bit DIFT sending to a 64-bit taint aggregator
void* do_fullsend (void* arg) 
{
    int s = (int) arg;
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

    struct epoch_data edata[epochs];
    struct epoch_ctl ectl[epochs];

    rc = safe_read (s, edata, sizeof(struct epoch_data)*epochs);
    if (rc != (int) (sizeof(struct epoch_data)*epochs)) {
	fprintf (stderr, "Cannot recieve epochs,rc=%d\n", rc);
	return NULL;
    }

    if (ehdr.flags&SYNC_LOGFILES) {
	uint32_t fcnt, ccnt;
	bool* freply = NULL;
	bool* creply = NULL;
	vector<struct replay_path> dirs;
	vector<struct replay_path> future_filenames;

	rc = safe_read (s, &fcnt, sizeof(fcnt));
	if (rc != sizeof(fcnt)) {
	    fprintf (stderr, "Cannot recieve file count,rc=%d\n", rc);
	    return NULL;
	}
	
	if (fcnt) {
	    freply = (bool *) malloc(sizeof(bool)*fcnt);
	    if (freply == NULL) {
		fprintf (stderr, "Cannot allocate file reply array of size %u\n", fcnt);
		return NULL;
	    }

	    for (u_long i = 0; i < fcnt; i++) {
		replay_path fpath;
		rc = safe_read (s, &fpath, sizeof(fpath));
		if (rc != sizeof(fpath)) {
		    fprintf (stderr, "Cannot recieve file path,rc=%d\n", rc);
		    return NULL;
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
		return NULL;
	    }
	}

	rc = safe_read (s, &ccnt, sizeof(ccnt));
	if (rc != sizeof(fcnt)) {
	    fprintf (stderr, "Cannot recieve cache count,rc=%d\n", rc);
	    return NULL;
	}

	if (ccnt) {
	    creply = (bool *) malloc(sizeof(bool)*ccnt);
	    if (creply == NULL) {
		fprintf (stderr, "Cannot allocate cache reply array of size %u\n", ccnt);
		return NULL;
	    }

	    for (u_long i = 0; i < ccnt; i++) {
		struct cache_info ci;
		rc = safe_read (s, &ci, sizeof(ci));
		if (rc != sizeof(ci)) {
		    fprintf (stderr, "Cannot recieve cache info,rc=%d\n", rc);
		    return NULL;
		}
		
		// Does this file exist?
		char cname[PATHLEN], cmname[PATHLEN], crname[PATHLEN];
		struct stat64 st;
		struct replay_path future_filename;

		sprintf (cname, "/replay_cache/%x_%x", ci.dev, ci.ino);
		rc = stat64 (cname, &st);
		if (rc == 0) {
		    // Is this the right version?
		    if (st.st_mtim.tv_sec == ci.mtime.tv_sec && st.st_mtim.tv_nsec == ci.mtime.tv_nsec) {
			creply[i] = false;
		    } else {
			// Nope - but maybe we have it?
			sprintf (cmname, "/replay_cache/%x_%x_%lu_%lu", ci.dev, ci.ino, ci.mtime.tv_sec, ci.mtime.tv_nsec);
			rc = stat64 (cmname, &st);
			if (rc == 0) {
			    creply[i] = false;
			} else {
			    creply[i] = true;
			    if (st.st_mtim.tv_sec > ci.mtime.tv_sec || 
				(st.st_mtim.tv_sec == ci.mtime.tv_sec && st.st_mtim.tv_nsec > ci.mtime.tv_nsec)) {
				// New file is past version 
				strcpy (future_filename.path, cmname);
				future_filenames.push_back(future_filename);
			    } else {
				// Existing file is past version
				sprintf (crname, "/replay_cache/%x_%x_%lu_%lu", ci.dev, ci.ino, st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
				rc = rename (cname, crname);
				if (rc < 0) {
				    fprintf (stderr, "Cannot rename cache file %s to %s, rc=%d\n", cname, crname, rc);
				    return NULL;
				}
				strcpy (future_filename.path, cname);
				future_filenames.push_back(future_filename);
			    }
			}
		    }
		} else {
		    // No versions at all
		    creply[i] = true;
		    strcpy (future_filename.path, cname);
		    future_filenames.push_back(future_filename);
		}
	    }
	    
	    // Send back response
	    rc = safe_write (s, creply, sizeof(bool)*ccnt);
	    if (rc != (int) (sizeof(bool)*ccnt)) {
		fprintf (stderr, "Cannot send cache info check reply,rc=%d\n", rc);
		return NULL;
	    }
	}

	// Now receive the files we requested
	u_long dcnt = 0;
	for (u_long i = 0; i < fcnt; i++) {
	    if (freply[i]) {
		rc = fetch_file (s, dirs[dcnt++].path);
		if (rc < 0) return NULL;
	    }
	} 

	u_long ffcnt = 0;
	for (u_long i = 0; i < ccnt; i++) {
	    if (creply[i]) {
		rc = fetch_file (s, "/replay_cache");
		if (rc < 0) return NULL;

		// Now rename the file to the correct version
		rc = rename ("/replay_cache/rename_me", future_filenames[ffcnt].path);
		if (rc < 0) {
		    fprintf (stderr, "Cannot rename temp cache file to %s, rc=%d\n", future_filenames[ffcnt].path, rc);
		    return NULL;
		}
		ffcnt++;
	    }
	} 

	free (freply);
	free (creply);
    }

    // Start all the epochs at once
    for (u_long i = 0; i < epochs; i++) {
	ectl[i].cpid = fork ();
	if (ectl[i].cpid == 0) {
	    if (i > 0 || !ehdr.start_flag) {
		char attach[80];
		sprintf (attach, "--attach_offset=%d,%u", edata[i].start_pid, edata[i].start_syscall);
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
		if (rc > 0) {
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
    if (ehdr.flags&SEND_ACK) {
	long retval = 0;
	rc = send (s, &retval, sizeof(retval), 0);
	if (rc != sizeof(retval)) {
	    fprintf (stderr, "Cannot send ack,rc=%d\n", rc);
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

    // send results if requete
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
