
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

#define TRANSFER_PORT 33333

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
    addr.sin_port = htons(TRANSFER_PORT);
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
      
    long s = accept (c, NULL, NULL);
    if (s < 0) {
	fprintf (stderr, "Cannot accept connection, errno=%d\n", errno);
	return s;
    }
	
    rc = sync_logfiles(s);
    if (rc < 0) { 
	fprintf(stderr, "something failed with sync_logfiles\n");
    }
       

    return 0;
}
