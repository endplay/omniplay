#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <atomic>
#include <vector>
#include <dirent.h>
#include <unordered_set>
#include <string>

using namespace std;

#include "streamserver.h"
#include "parseklib.h"
#include "streamnw.h"

#define TRANSFER_PORT 33333

bool test_and_set(vector<struct cache_info> &cfiles, struct cache_info &cinfo){
    bool found = false;
    for(struct cache_info c : cfiles) { 	
	if (c.dev == cinfo.dev && c.ino == cinfo.ino && 
	    c.mtime.tv_sec == cinfo.mtime.tv_sec &&
	    c.mtime.tv_nsec == cinfo.mtime.tv_nsec) 
	    found = true;
    }
    if (!found) cfiles.push_back(cinfo);
    return found;
}

int connect_to_server (const char* hostname, int port)
{
    // Connect to streamserver
    struct hostent* hp = gethostbyname (hostname);
    if (hp == NULL) {
	fprintf (stderr, "Invalid host %s, errno=%d\n", hostname, h_errno);
	return -1;
    }
    
    int s = socket (AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	fprintf (stderr, "Cannot create socket, errno=%d\n", errno);
	return s;
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy (&addr.sin_addr, hp->h_addr, hp->h_length);
    
    // Receiver may not be started, so spin until connection is accepted
    long rc = connect (s, (struct sockaddr *) &addr, sizeof(addr));
    if (rc < 0) {
	fprintf (stderr, "Cannot connect to %s:%d, errno=%d\n", hostname, port, errno);
	return rc;
    }
    return s;
}


int get_needed_files(struct vector<struct replay_path> &log_files, 
		     struct vector<struct cache_info> &cache_files,
		     const char *dirname) { 
    // First build up a list of files that are needed for this replay
    struct dirent* de;
    DIR* dir = opendir(dirname);
    if (dir == NULL) {
	fprintf (stderr, "Cannot open replay dir %s\n", dirname);
	return -1;
    }
    while ((de = readdir(dir)) != NULL) {
	if (!strncmp(de->d_name, "ckpt",4) || !strcmp(de->d_name, "mlog") || !strncmp(de->d_name, "ulog", 4)) {
	    struct replay_path pathname;
	    sprintf (pathname.path, "%s/%s", dirname, de->d_name);
	    log_files.push_back(pathname);
	} else if (!strncmp(de->d_name, "klog", 4)) {
	    struct klogfile *log;
	    struct klog_result *res;
	    struct replay_path pathname;
	    struct cache_info cinfo;
	    
	    sprintf (pathname.path, "%s/%s", dirname, de->d_name);
	    log_files.push_back(pathname);
	    // Parse to look for more cache files
	    log = parseklog_open(pathname.path);
	    if (!log) {
		fprintf(stderr, "%s doesn't appear to be a valid klog file!\n", pathname.path);
		return -1;
	    }
	    while ((res = parseklog_get_next_psr(log)) != NULL) {
		if (res->psr.sysnum == 5) {
		    struct open_retvals* pretvals = (struct open_retvals *) res->retparams;
		    if (pretvals) {
			cinfo.dev = pretvals->dev;
			cinfo.ino = pretvals->ino;
			cinfo.mtime = pretvals->mtime;
			test_and_set(cache_files, cinfo);
//			cache_files.push_back(cinfo);
		    }
		} else if (res->psr.sysnum == 11) {
		    struct execve_retvals* pretvals = (struct execve_retvals *) res->retparams;
		    if (pretvals) {
			cinfo.dev = pretvals->data.same_group.dev;
			cinfo.ino = pretvals->data.same_group.ino;
			cinfo.mtime = pretvals->data.same_group.mtime;
			test_and_set(cache_files, cinfo);
//			cache_files.push_back(cinfo);
		    }
		} else if (res->psr.sysnum == 86 || res->psr.sysnum == 192) {
		    struct mmap_pgoff_retvals* pretvals = (struct mmap_pgoff_retvals *) res->retparams;
		    if (pretvals) {
			cinfo.dev = pretvals->dev;
			cinfo.ino = pretvals->ino;
			cinfo.mtime = pretvals->mtime;
			test_and_set(cache_files, cinfo);
//			cache_files.push_back(cinfo);
		    }
		}
	    }
	    parseklog_close(log);
	} 
    }
    closedir(dir);
    return 0;
}

void format ()
{
    fprintf (stderr, "format: sync_files <replay_dir> <server_name>\n");
    exit (0);
}

int main (int argc, char* argv[]) 
{
    int rc, socket;
    struct vector<struct replay_path> log_files;
    struct vector<struct cache_info> cache_files;

    if (argc < 3) {
	format();
    }

    const char* replay_dir = argv[1];
    const char* server_name = argv[2];

    if (get_needed_files(log_files, cache_files, replay_dir) < 0) { 
	fprintf(stderr, "something wrong with get_needed_files\n");
    }

    socket = connect_to_server (server_name, TRANSFER_PORT);
    if (socket < 0) return socket;
    
    // First send count of log files
    uint32_t cnt = log_files.size();
    rc = safe_write (socket, &cnt, sizeof(cnt));
    if (rc != sizeof(cnt)) {
	fprintf (stderr, "Cannot send log file count to streamserver, rc=%d\n", rc);
	return rc;
    }

    // Next send log files
    for (auto iter = log_files.begin(); iter != log_files.end(); iter++) {
	struct replay_path p = *iter;
	rc = safe_write (socket, &p, sizeof(struct replay_path));
	if (rc != sizeof(struct replay_path)) {
	    fprintf (stderr, "Cannot send log file to streamserver, rc=%d\n", rc);
	    return rc;
	}
    }
	    
    // Next send count of cache files
    cnt = cache_files.size();
    rc = safe_write (socket, &cnt, sizeof(cnt));
    if (rc != sizeof(cnt)) {
	fprintf (stderr, "Cannot send cache file count to streamserver, rc=%d\n", rc);
	return rc;
    }

    
    // And finally the cache files
    for (auto iter = cache_files.begin(); iter != cache_files.end(); iter++) {
	struct cache_info c = *iter;
	rc = safe_write (socket, &c, sizeof(struct cache_info));
	if (rc != sizeof(struct cache_info)) {
	    fprintf (stderr, "Cannot send cache file to streamserver, rc=%d\n", rc);
	    return rc;
	}
    }
    
    // Get back response
    bool response[log_files.size()+cache_files.size()];
    rc = safe_read (socket, response, sizeof(bool)*(log_files.size()+cache_files.size()));
    if (rc != (long) (sizeof(bool)*(log_files.size()+cache_files.size()))) {
	fprintf (stderr, "Cannot read sync results, rc=%d\n", rc);
	return rc;
    }
    
    // Send requested files
    u_long l, j;
    for (l = 0; l < log_files.size(); l++) {
	if (response[l]) {
	    char* filename = NULL;
	    for (int j = strlen(log_files[l].path); j >= 0; j--) {
		if (log_files[l].path[j] == '/') {
		    filename = &log_files[l].path[j+1];
		    break;
		} 
	    }
	    if (filename == NULL) {
		fprintf (stderr, "Bad path name: %s\n", log_files[l].path);
		return -1;
	    }
	    rc = send_file (socket, log_files[l].path, filename);
	    if (rc < 0) {
		fprintf (stderr, "Unable to send log file %s\n", log_files[l].path);
		return rc;
	    }
	    fprintf (stderr,"<send %ld/%d log file>\n", l, log_files.size());
	}
    }
    for (j = 0; j < cache_files.size(); j++) {
	if (response[l+j]) {
	    char cname[PATHLEN];
	    struct stat64 st;
	    
	    // Find the cache file locally
	    sprintf (cname, "/replay_cache/%x_%x", cache_files[j].dev, cache_files[j].ino);
	    rc = stat64 (cname, &st);
	    if (rc < 0) {
		fprintf (stderr, "cannot stat cache file %s, rc=%d\n", cname, rc);
		return rc;
	    }
	    
	    if (st.st_mtim.tv_sec != cache_files[j].mtime.tv_sec || st.st_mtim.tv_nsec != cache_files[j].mtime.tv_nsec) {
		// if times do not match, open a past version
		sprintf (cname, "/replay_cache/%x_%x_%lu_%lu", cache_files[j].dev, cache_files[j].ino, 
			 cache_files[j].mtime.tv_sec, cache_files[j].mtime.tv_nsec);
	    }
	    
	    // Send the file to streamserver
	    rc = send_file (socket, cname, "rename_me");
	    fprintf (stderr,"<send %ld/%d cache file>\n", j, cache_files.size());
	}
    }
}
