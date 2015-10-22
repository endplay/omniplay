#define __USE_LARGEFILE64

#include <sys/stat.h>
#include <sys/types.h>
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

using namespace std;

#include "streamserver.h"
#include "parseklib.h"
#include "streamnw.h"

// One for each streamserver
struct epoch_ctl {
    u_long start;
    u_long num;
    int    s;
};

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
	fprintf (stderr, "Cannot connect to %s, errno=%d\n", hostname, errno);
	return rc;
    }
    return s;
}

int fetch_results (char* top_dir, struct epoch_ctl ectl)
{
    char dir[512];

    for (u_long i = 0; i < ectl.num; i++) {
	sprintf (dir, "%s/%lu", top_dir, ectl.start+i);
	long rc = mkdir (dir, 0755);
	if (rc < 0) {
	    fprintf (stderr, "Cannot make dir %s\n", dir);
	    return rc;
	}
	// Fetch 4 files: results, addresses, input and output tokens
	for (int j = 0; j < 4; j++) {
	    if (fetch_file(ectl.s, dir) < 0) return -1;
	}
    }
    return 0;
}

void format ()
{
    fprintf (stderr, "format: streamctl <epoch description file> <aggregation host> [-w] [-s] [-v dest_dir cmp_no] [-seq]\n");
    exit (0);
}

int main (int argc, char* argv[]) 
{
    int rc;
    char dirname[80];
    struct epoch_data epoch;
    vector<struct epoch_data> epochs;
    vector<struct epoch_ctl> epochctls;
    unordered_set<int> conns;
    int wait_for_response = 0, validate = 0, sync_files = 0;
    char* dest_dir, *cmp_dir;
    u_long epochno = 0, last_epochno = 0;
    struct vector<struct replay_path> log_files;
    struct vector<struct cache_info> cache_files;
    u_char agg_type = AGG_TYPE_STREAM;

    if (argc < 3) {
	format();
    }

    const char* epoch_filename = argv[1];
    const char* agg_hostname = argv[2];

    for (int i = 3; i < argc; i++) {
	if (!strcmp (argv[i], "-w")) {
	    wait_for_response = 1;
	} else if (!strcmp (argv[i], "-s")) {
	    sync_files = 1;
	} else if (!strcmp (argv[i], "-v")) {
	    i++;
	    if (i < argc) {
		dest_dir = argv[i];
		i++;
		if (i < argc) {
		    cmp_dir = argv[i];
		    validate = 1;
		} else {
		    format();
		}
	    } else {
		format();
	    }
	} else if (!strcmp (argv[i], "-s")) {
	    agg_type = AGG_TYPE_SEQ;
	} else {
	    format();
	}
    }

    if (validate) {
	// Create directory for results files
	rc = mkdir (dest_dir, 0755);
	if (rc < 0) {
	    fprintf (stderr, "Cannot make dir %s\n", dest_dir);
	    return rc;
	}
    }

    // Read in the epoch file
    FILE* file = fopen(epoch_filename, "r");
    if (file == NULL) {
	fprintf (stderr, "Unable to open epoch description file %s, errno=%d\n", epoch_filename, errno);
	return -1;
    }
    rc = fscanf (file, "%79s\n", dirname);
    if (rc != 1) {
	fprintf (stderr, "Unable to parse header line of epoch descrtion file, rc=%d\n", rc);
	return -1;
    }

    while (!feof(file)) {
	char line[256];
	if (fgets (line, 255, file)) {
	    rc = sscanf (line, "%d %u %u %u %u %s\n", &epoch.start_pid, &epoch.start_syscall, 
			 &epoch.stop_syscall, &epoch.filter_syscall, &epoch.ckpt, epoch.hostname);
	    if (rc != 6) {
		fprintf (stderr, "Unable to parse line of epoch descrtion file: %s\n", line);
		return -1;
	    }
	    epochs.push_back(epoch);
	}
    }

    fclose(file);

    if (sync_files) {
	// First build up a list of files that are needed for this replay
	struct dirent* de;
	DIR* dir = opendir(dirname);
	if (dir == NULL) {
	    fprintf (stderr, "Cannot open replay dir %s\n", dirname);
	    return -1;
	}
	while ((de = readdir(dir)) != NULL) {
	    if (!strcmp(de->d_name, "ckpt") || !strcmp(de->d_name, "mlog") || !strncmp(de->d_name, "ulog", 4)) {
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
			    cache_files.push_back(cinfo);
			}
		    } else if (res->psr.sysnum == 11) {
			struct execve_retvals* pretvals = (struct execve_retvals *) res->retparams;
			if (pretvals) {
			    cinfo.dev = pretvals->data.same_group.dev;
			    cinfo.ino = pretvals->data.same_group.ino;
			    cinfo.mtime = pretvals->data.same_group.mtime;
			    cache_files.push_back(cinfo);
			}
		    } else if (res->psr.sysnum == 86 || res->psr.sysnum == 192) {
			struct mmap_pgoff_retvals* pretvals = (struct mmap_pgoff_retvals *) res->retparams;
			if (pretvals) {
			    cinfo.dev = pretvals->dev;
			    cinfo.ino = pretvals->ino;
			    cinfo.mtime = pretvals->mtime;
			    cache_files.push_back(cinfo);
			}
		    }
		}
		parseklog_close(log);
	    } 
	}
	closedir(dir);
    }

    // If this is a split processing, set up the 64-bit aggregator first
    // Assume 1 aggregator for now
    struct epoch_hdr ehdr;
    ehdr.flags = 0;
    if (wait_for_response) ehdr.flags |= SEND_ACK;
    if (validate) ehdr.flags |= SEND_RESULTS;
    strcpy (ehdr.dirname, dirname);
    ehdr.epochs = epochs.size();
    ehdr.start_flag = true;
    ehdr.finish_flag = true;
    ehdr.agg_type = agg_type;

    int sa = connect_to_server (agg_hostname, STREAMSERVER_PORT);
    if (sa < 0) return sa;

    rc = safe_write (sa, &ehdr, sizeof(ehdr));
    if (rc != sizeof(ehdr)) {
	fprintf (stderr, "Cannot send header to streamserver, rc=%d\n", rc);
	return rc;
    }

    // Now contact the individual servers and send them the epoch data
    // Assumption is that the epochs handled by a server are contiguous
    auto estart = epochs.begin();
    bool start_flag = true;
    char* prev_hostname;
    while (estart != epochs.end()) {
	auto efinish = estart;
	u_long ecnt = 0;
	while (efinish != epochs.end() && !strcmp(efinish->hostname, estart->hostname)) {
	    ecnt++;
	    efinish++;
	}
	if (ecnt) {

	    int sd = connect_to_server (estart->hostname, STREAMSERVER_PORT);
	    if (sd < 0) return sd;

	    struct epoch_hdr ehdr;
	    ehdr.flags = 0;
	    if (sync_files) ehdr.flags |= SYNC_LOGFILES;
	    strcpy (ehdr.dirname, dirname);
	    ehdr.epochs = ecnt;
	    ehdr.start_flag = start_flag;
	    start_flag = false;
	    ehdr.finish_flag = (efinish == epochs.end());
	    if (!ehdr.start_flag) {
		strcpy (ehdr.next_host, prev_hostname);
	    }
	    prev_hostname = estart->hostname;

	    rc = safe_write (sd, &ehdr, sizeof(ehdr));
	    if (rc != sizeof(ehdr)) {
		fprintf (stderr, "Cannot send header to streamserver, rc=%d\n", rc);
		return rc;
	    }

	    for (; estart != efinish; estart++) {
		struct epoch_data tmp = *estart;
		strcpy (tmp.hostname, agg_hostname);
		tmp.port = AGG_BASE_PORT+epochno;
		rc = safe_write (sd, &tmp, sizeof(struct epoch_data));
		if (rc != sizeof(struct epoch_data)) {
		    fprintf (stderr, "Cannot send epoch data to streamserver, rc=%d\n", rc);
		    return rc;
		}
		epochno++;
	    }

	    if (sync_files) {
		// First send count of log files
		u_long cnt = log_files.size();
		rc = safe_write (sd, &cnt, sizeof(cnt));
		if (rc != sizeof(cnt)) {
		    fprintf (stderr, "Cannot send log file count to streamserver, rc=%d\n", rc);
		    return rc;
		}
		
		// Next send log files
		for (auto iter = log_files.begin(); iter != log_files.end(); iter++) {
		    struct replay_path p = *iter;
		    rc = safe_write (sd, &p, sizeof(struct replay_path));
		    if (rc != sizeof(struct replay_path)) {
			fprintf (stderr, "Cannot send log file to streamserver, rc=%d\n", rc);
			return rc;
		    }
		}

		// Next send count of cache files
		cnt = cache_files.size();
		rc = safe_write (sd, &cnt, sizeof(cnt));
		if (rc != sizeof(cnt)) {
		    fprintf (stderr, "Cannot send cache file count to streamserver, rc=%d\n", rc);
		    return rc;
		}

		// And finally the cache files
		for (auto iter = cache_files.begin(); iter != cache_files.end(); iter++) {
		    struct cache_info c = *iter;
		    rc = safe_write (sd, &c, sizeof(struct cache_info));
		    if (rc != sizeof(struct cache_info)) {
			fprintf (stderr, "Cannot send cache file to streamserver, rc=%d\n", rc);
			return rc;
		    }
		}

		// Get back response
		bool response[log_files.size()+cache_files.size()];
		rc = safe_read (sd, response, sizeof(bool)*(log_files.size()+cache_files.size()));
		if (rc != (long) (sizeof(bool)*(log_files.size()+cache_files.size()))) {
		    fprintf (stderr, "Cannot read sync results, rc=%d\n", rc);
		    return rc;
		}
		
		// Send requested files
		u_long i, j;
		for (i = 0; i < log_files.size(); i++) {
		    if (response[i]) {
			char* filename = NULL;
			for (int j = strlen(log_files[i].path); j >= 0; j--) {
			    if (log_files[i].path[j] == '/') {
				filename = &log_files[i].path[j+1];
				break;
			    } 
			}
			if (filename == NULL) {
			    fprintf (stderr, "Bad path name: %s\n", log_files[i].path);
			    return -1;
			}
			rc = send_file (sd, log_files[i].path, filename);
			if (rc < 0) {
			    fprintf (stderr, "Unable to send log file %s\n", log_files[i].path);
			    return rc;
			}
		    }
		}
		for (j = 0; j < cache_files.size(); j++) {
		    if (response[i+j]) {
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
			rc = send_file (sd, cname, "rename_me");
		    }
		}
	    }

	    struct epoch_ctl ectl;
	    ectl.start = last_epochno;
	    ectl.num = epochno-last_epochno;
	    ectl.s = sd;
	    epochctls.push_back(ectl);
	    last_epochno = epochno;

	    //printf ("%lu epochs to %s\n", ecnt, estart->hostname);
	    conns.insert(sd);
	}
    }

    if (wait_for_response) {
	struct epoch_ack ack;
	rc = recv (sa, &ack, sizeof(ack), 0);
	if (rc != sizeof(ack)) {
	    fprintf (stderr, "Cannot recv ack,rc=%d\n", rc);
	}
	printf ("done reval is %d\n", ack.retval);
    }

    if (validate) {
	// Fetch the files into each directory 
	char rdir[512];
	for (u_long i = 0; i < epochs.size(); i++) {
	    sprintf (rdir, "%s/%lu", dest_dir, i);
	    long rc = mkdir (rdir, 0755);
	    if (rc < 0) {
		fprintf (stderr, "Cannot make dir %s\n", rdir);
		return rc;
	    }
	    // Fetch 4 files: results, addresses, input and output tokens
	    for (int j = 0; j < 4; j++) {
		if (fetch_file(sa, rdir) < 0) return -1;
	    }
	}

	// Now actually do the comaprison
	char cmd[512];
	sprintf (cmd, "../dift/obj-ia32/out2mergecmp %s -d %s", cmp_dir, dest_dir);
	for (u_long i = 0; i < epochs.size(); i++) {
	    char add[64];
	    sprintf (add, " %lu", i);
	    strcat (cmd, add);
	}
	system (cmd);
     }

    return 0;
}
