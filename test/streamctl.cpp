#define __USE_LARGEFILE64

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

/* An aggregation server */
struct aggregator {
    char  hostname[256];  /* hostname for this aggregator */
    uint32_t port;
    u_int num_epochs;     /* how many epochs it will handle */
    int   s;              /* socket used for communication */
};

/* A dift server */
struct dift {
    char  hostname[256];
    u_int num_epochs;
    int   s;
};

/* An individual epoch */
struct epoch {
    struct aggregator* pagg;
    struct dift* pdift;
    struct epoch_data data;
};

/* All the configuration data */
struct config {
    vector<dift *> difts;
    vector<aggregator *> aggregators;
    vector<epoch> epochs;
};
	
// One for each streamserver
struct epoch_ctl {
    u_long start;
    u_long num;
    int    s;
    pid_t wait_pid;
};

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
    fprintf (stderr, "format: streamctl <epoch description file> <host config file> [-w] [-s] [-c] [-lowmem]\n");
    fprintf (stderr, "                  [-filter_inet] [-v dest_dir cmp_dir] [-stats] [-seq/-seqpp]\n");
    exit (0);
}

int main (int argc, char* argv[]) 
{
    int rc;
    char dirname[80];
    int wait_for_response = 0, validate = 0, get_stats = 0, sync_files = 0, nw_compress = 0, low_memory = 0, filter_inet = 0, stream_ls = 0;
    bool record_trace = false;
    char* filter_part = NULL;
    char* filter_output_after = NULL;
    char* dest_dir, *cmp_dir;
    struct vector<struct replay_path> log_files;
    struct vector<struct cache_info> cache_files;
    u_char agg_type = AGG_TYPE_STREAM;
    struct config conf;
    int parallelize = 1; 

    if (argc < 3) {
	format();
    }

    const char* host_suffix; 

    const char* epoch_filename = argv[1];
    const char* config_filename = argv[2];

    for (int i = 3; i < argc; i++) {
	if (!strcmp (argv[i], "-w")) {
	    wait_for_response = 1;
	} else if (!strcmp (argv[i], "-s")) {
	    sync_files = 1;
	} else if (!strcmp (argv[i], "-c")) {
	    nw_compress = 1;
	} else if (!strcmp (argv[i], "-lowmem")) {
	    low_memory = 1;
	} else if (!strcmp (argv[i], "-streamls")) {
	    stream_ls = 1;
	} else if (!strcmp (argv[i], "-filter_inet")) {
	    filter_inet = 1;
	} else if (!strcmp (argv[i], "-filter_part")) {
	    filter_part = argv[i+1];
	    i++;
	} else if (!strcmp (argv[i], "-filter_output_after")) {
	    filter_output_after = argv[i+1];
	    i++;
	} else if (!strcmp (argv[i], "-stats")) {
	    get_stats = 1;
	} else if (!strcmp (argv[i], "-hs")) {
	  host_suffix = argv[i+1];
	  i++;
	} else if (!strcmp (argv[i], "-record_trace")) {
	    record_trace = true;
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
	} else if (!strcmp (argv[i], "-seq")) {
	    agg_type = AGG_TYPE_SEQ;
	} else if (!strcmp (argv[i], "-seqppl")) {
	    agg_type = AGG_TYPE_SEQ_PPL;
	} else if (!strcmp (argv[i], "-seqppg")) {
	    agg_type = AGG_TYPE_SEQ_PPG;
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
	    struct epoch e;
	    u_int unused;
	    rc = sscanf (line, "%d %c %u %c %u %u %u %u\n", &e.data.start_pid, &e.data.start_level, &e.data.start_clock, &e.data.stop_level, &e.data.stop_clock, &unused, &e.data.ckpt, &e.data.fork_flags);
	    if (rc != 8) {
		fprintf (stderr, "Unable to parse line of epoch descrtion file: %s\n", line);
		return -1;
	    }
	    conf.epochs.push_back(e);
	}
    }
    fclose(file);

    // Read in the host configuration file
    file = fopen(config_filename, "r");
    if (file == NULL) {
	fprintf (stderr, "Unable to open host configuration file %s, errno=%d\n", epoch_filename, errno);
	return -1;
    }

    // Now parse the configuration file
    // Stop if # of epochs is exceeded (config is generic so may work for more epochs) 
    struct dift* prev_dift = NULL;
    struct aggregator* prev_agg = NULL;
    u_int epoch_cnt = 0;
    while (!feof(file) && epoch_cnt < conf.epochs.size()) {
	char line[256];
	if (fgets (line, 255, file)) {
	    int num_epochs;
	    char dift_host[256];
	    char agg_host[256];
	    rc = sscanf (line, "%d %s %s\n", &num_epochs, dift_host, agg_host);
	    if (rc != 3) {
		fprintf (stderr, "Unable to parse line of epoch descrtion file: %s\n", line);
		return -1;
	    }
	    if (epoch_cnt + num_epochs > conf.epochs.size()) {
		// Will not use all the epochs in this row
		num_epochs -= (epoch_cnt + num_epochs) - conf.epochs.size();
		printf ("Truncated num_epochs to %d\n", num_epochs);
	    }
	    struct dift* d;
	    if (!prev_dift || strcmp(dift_host, prev_dift->hostname)) {
		d = new dift;
		strcpy (d->hostname, dift_host);
		d->num_epochs = num_epochs;
		d->s = -1;
		conf.difts.push_back(d);
		prev_dift = d;
	    } else {
		d = prev_dift;
		d->num_epochs += num_epochs;
	    }

	    struct aggregator* a;
	    if (!prev_agg || strcmp(agg_host, prev_agg->hostname)) {
		a = new aggregator;
		strcpy (a->hostname, agg_host);
		a->num_epochs = num_epochs;
		a->port = STREAMSERVER_PORT; //needs to be changed
		a->s = -1;
		conf.aggregators.push_back(a);
		prev_agg = a;
	    } else {
		a = prev_agg;
		a->num_epochs += num_epochs;
	    }

	    for (auto i = 0; i < num_epochs; i++) {
		conf.epochs[epoch_cnt].pdift = d;
		conf.epochs[epoch_cnt].pagg = a;
		epoch_cnt++;
	    }
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
	//unordered set of already seen cache files (optimizatino for nginx, which stinks because there are like, 100k files)

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
#if 0
			    printf ("open cache file dev %x ino %x mtime %lx.%lx log %s\n", 
				    cinfo.dev, cinfo.ino, cinfo.mtime.tv_sec, cinfo.mtime.tv_nsec, de->d_name);
#endif
			}
		    } else if (res->psr.sysnum == 11) {
			struct execve_retvals* pretvals = (struct execve_retvals *) res->retparams;
			if (pretvals && !pretvals->is_new_group) {
			    cinfo.dev = pretvals->data.same_group.dev;
			    cinfo.ino = pretvals->data.same_group.ino;
			    cinfo.mtime = pretvals->data.same_group.mtime;
			    test_and_set(cache_files, cinfo);
#if 0
			    printf ("exec cache file dev %x ino %x mtime %lx.%lx log %s\n", 
				    cinfo.dev, cinfo.ino, cinfo.mtime.tv_sec, cinfo.mtime.tv_nsec, de->d_name);
#endif
			}
		    } else if (res->psr.sysnum == 86 || res->psr.sysnum == 192) {
			struct mmap_pgoff_retvals* pretvals = (struct mmap_pgoff_retvals *) res->retparams;
			if (pretvals) {
			    cinfo.dev = pretvals->dev;
			    cinfo.ino = pretvals->ino;
			    cinfo.mtime = pretvals->mtime;
			    test_and_set(cache_files, cinfo);
#if 0
			    printf ("mmap cache file dev %x ino %x mtime %lx.%lx log %s\n", 
				    cinfo.dev, cinfo.ino, cinfo.mtime.tv_sec, cinfo.mtime.tv_nsec, de->d_name);
#endif
			}
		    }
		}
		parseklog_close(log);
	    } 
	}
	closedir(dir);
    }        
    fprintf(stderr, "found that we need %d files\n", cache_files.size());
    

    // Set up the aggregators first
    for (u_int i = 0; i < conf.aggregators.size(); i++) {
	struct epoch_hdr ehdr;
	ehdr.flags = 0;
	if (wait_for_response) ehdr.flags |= SEND_ACK;
	if (validate) ehdr.flags |= SEND_RESULTS;
	if (get_stats) ehdr.flags |= SEND_STATS;
	if (nw_compress) ehdr.flags |= NW_COMPRESS;
	if (low_memory) ehdr.flags |= LOW_MEMORY;
	if (stream_ls) ehdr.flags |= STREAM_LS;
	
	ehdr.filter_flags = 0;
	if (filter_inet) ehdr.filter_flags |= FILTER_INET;
	if (filter_part) {
	    ehdr.filter_flags |= FILTER_PART;
	    strcpy (ehdr.filter_part, filter_part);
	}
	if (filter_output_after) {
	    ehdr.filter_flags |= FILTER_OUT;
	    strcpy (ehdr.filter_output_after, filter_output_after);
	}

	strcpy (ehdr.dirname, dirname);
	ehdr.epochs = conf.aggregators[i]->num_epochs;
	if (i == 0) {
	    ehdr.start_flag = true;
	} else {
	    ehdr.start_flag = false;
	    strcpy (ehdr.prev_host, conf.aggregators[i-1]->hostname);
	}
	if (i == conf.aggregators.size()-1) {
	    ehdr.finish_flag = true; 
	} else {
	    ehdr.finish_flag = false;
	    strcpy (ehdr.next_host, conf.aggregators[i+1]->hostname);
	}
	ehdr.cmd_type = agg_type;
	ehdr.parallelize = conf.aggregators[i]->num_epochs;
	if (ehdr.parallelize > parallelize) parallelize = ehdr.parallelize;

	char real_host[1024];
	if (host_suffix && strstr(conf.aggregators[i]->hostname, ".net") == NULL) 
	  sprintf(real_host,"%s%s",conf.aggregators[i]->hostname,host_suffix);
	else
	  sprintf(real_host,"%s",conf.aggregators[i]->hostname);


	    conf.aggregators[i]->s = connect_to_server (real_host, conf.aggregators[i]->port);
	if (conf.aggregators[i]->s < 0) return conf.aggregators[i]->s;

	rc = safe_write (conf.aggregators[i]->s, &ehdr, sizeof(ehdr));
	if (rc != sizeof(ehdr)) {
	    fprintf (stderr, "Cannot send header to streamserver, rc=%d\n", rc);
	    return rc;
	}
    }

    // Now contact the individual DIFT servers and send them the epoch data
    // Assumption is that the epochs handled by a server are contiguous
    epoch_cnt = 0;
    u_int agg_cnt = 0;
    u_int cur_agg_epochs = 0;
    for (u_int i = 0; i < conf.difts.size(); i++) {
	char real_host[1024];
	if (host_suffix && strstr(conf.difts[i]->hostname, ".net") == NULL) 
	  sprintf(real_host,"%s%s",conf.difts[i]->hostname,host_suffix);
	else
	  sprintf(real_host,"%s",conf.difts[i]->hostname);

	conf.difts[i]->s = connect_to_server (real_host, STREAMSERVER_PORT);
	if (conf.difts[i]->s < 0) return conf.difts[i]->s;

	struct epoch_hdr ehdr;
	ehdr.cmd_type = DO_DIFT;
	ehdr.flags = 0;
	if (sync_files) ehdr.flags |= SYNC_LOGFILES;
	if (get_stats) ehdr.flags |= SEND_STATS;
	ehdr.record_trace = record_trace;
	strcpy (ehdr.dirname, dirname);
	ehdr.epochs = conf.difts[i]->num_epochs;
	if (i == 0) {
	    ehdr.start_flag = true;
	} else {
	    ehdr.start_flag = false;
	    strcpy (ehdr.prev_host, conf.difts[i-1]->hostname);
	}
	if (i == conf.difts.size()-1) {
	    ehdr.finish_flag = true;
	} else {
	    ehdr.finish_flag = false;
	    strcpy (ehdr.next_host, conf.difts[i+1]->hostname);
	}
	
	rc = safe_write (conf.difts[i]->s, &ehdr, sizeof(ehdr));
	if (rc != sizeof(ehdr)) {
	    fprintf (stderr, "Cannot send header to streamserver, rc=%d\n", rc);
	    return rc;
	}
	
	for (u_int j = 0; j < conf.difts[i]->num_epochs; j++) {
	    strcpy (conf.epochs[epoch_cnt].data.hostname, conf.aggregators[agg_cnt]->hostname);
	    conf.epochs[epoch_cnt].data.port = AGG_BASE_PORT+cur_agg_epochs;
	    rc = safe_write (conf.difts[i]->s, &conf.epochs[epoch_cnt].data, sizeof(struct epoch_data));
	    if (rc != sizeof(struct epoch_data)) {
		fprintf (stderr, "Cannot send epoch data to streamserver, rc=%d\n", rc);
		return rc;
	    }
	    cur_agg_epochs++;
	    epoch_cnt++;
	    if (cur_agg_epochs == conf.aggregators[agg_cnt]->num_epochs) {
		// Move to next aggregator
		agg_cnt++;
		cur_agg_epochs = 0;
	    }
	}
	
	if (sync_files) {
	    // First send count of log files
	    uint32_t cnt = log_files.size();
	    rc = safe_write (conf.difts[i]->s, &cnt, sizeof(cnt));
	    if (rc != sizeof(cnt)) {
		fprintf (stderr, "Cannot send log file count to streamserver, rc=%d\n", rc);
		return rc;
	    }

	    // Next send log files
	    for (auto iter = log_files.begin(); iter != log_files.end(); iter++) {
		struct replay_path p = *iter;
		rc = safe_write (conf.difts[i]->s, &p, sizeof(struct replay_path));
		if (rc != sizeof(struct replay_path)) {
		    fprintf (stderr, "Cannot send log file to streamserver, rc=%d\n", rc);
		    return rc;
		}
	    }
	    
	    // Next send count of cache files
	    cnt = cache_files.size();
	    rc = safe_write (conf.difts[i]->s, &cnt, sizeof(cnt));
	    if (rc != sizeof(cnt)) {
		fprintf (stderr, "Cannot send cache file count to streamserver, rc=%d\n", rc);
		return rc;
	    }
	    fprintf(stderr, "we have %u cache files to send to %s\n", cnt, conf.difts[i]->hostname);
	    
	    // And finally the cache files
	    for (auto iter = cache_files.begin(); iter != cache_files.end(); iter++) {
		struct cache_info c = *iter;
		rc = safe_write (conf.difts[i]->s, &c, sizeof(struct cache_info));
		if (rc != sizeof(struct cache_info)) {
		    fprintf (stderr, "Cannot send cache file to streamserver, rc=%d\n", rc);
		    return rc;
		}
	    }

	    // Get back response
	    bool response[log_files.size()+cache_files.size()];
	    rc = safe_read (conf.difts[i]->s, response, sizeof(bool)*(log_files.size()+cache_files.size()));
	    if (rc != (long) (sizeof(bool)*(log_files.size()+cache_files.size()))) {
		fprintf (stderr, "Cannot read sync results, rc=%d\n", rc);
		return rc;
	    }
	    
	    // Send requested files
	    u_long l, j;
	    for (l = 0; l < log_files.size(); l++) {
		if (response[l]) {
		    fprintf (stderr,"%ld of %d log files requested\n", l, log_files.size());
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
		    rc = send_file (conf.difts[i]->s, log_files[l].path, filename);
		    if (rc < 0) {
			fprintf (stderr, "Unable to send log file %s\n", log_files[l].path);
			return rc;
		    }
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
		    rc = send_file (conf.difts[i]->s, cname, "rename_me");
		}
	    }
	}
    }
    if (wait_for_response) {
	for (u_int i = 0; i < conf.aggregators.size(); i++) {
	    struct epoch_ack ack;
	    rc = safe_read (conf.aggregators[i]->s, &ack, sizeof(ack));
	    if (rc != sizeof(ack)) {
		fprintf (stderr, "Cannot recv ack,rc=%d,errno=%d\n", rc, errno);
	    }
	}
    }


    if (validate) {
	// Fetch the files into each directory 
	char rdir[512];
	for (u_long i = 0; i < conf.epochs.size(); i++) {
	    sprintf (rdir, "%s/%lu", dest_dir, i);
	    long rc = mkdir (rdir, 0755);
	    if (rc < 0) {
		fprintf (stderr, "Cannot make dir %s\n", rdir);
		return rc;
	    }

	    // Fetch n+3 files: results, addresses, input and output tokens
	    for (int j = 0; j < parallelize+3; j++) {
		if (fetch_file(conf.epochs[i].pagg->s, rdir) < 0) return -1;
	    }
	}

	// Now actually do the comaprison
	char cmd[512];
	sprintf (cmd, "../dift/proc64/out2mergecmp %d %s -d %s", parallelize, cmp_dir, dest_dir);
	for (u_long i = 0; i < conf.epochs.size(); i++) {
	    char add[64];
	    sprintf (add, " %lu", i);
	    strcat (cmd, add);
	}
	system (cmd);
    }

    if (get_stats) {
	// Fetch the stats files into the tmp directory
	for (u_long i = 0; i < conf.epochs.size(); i++) {
	    char statfile[256];
	    sprintf (statfile, "/tmp/stream-stats-%lu", i);
	    if (fetch_file(conf.epochs[i].pagg->s, "/tmp") < 0) return -1;
	    rc = rename ("/tmp/stream-stats", statfile);
	    if (rc < 0) printf ("Unable to rename aggregator stats file, rc=%d, errno=%d\n", rc, errno);

	    sprintf (statfile, "/tmp/taint-stats-%lu", i);
	    if (fetch_file(conf.epochs[i].pdift->s, "/tmp") < 0) return -1;
	    rc = rename ("/tmp/taint-stats", statfile);
	    if (rc < 0) printf ("Unable to rename dift stats file, rc=%d, errno=%d\n", rc, errno);
	}
    }

    if (record_trace) {
	// Fetch trace files into the tmp directory
	for (u_long i = 0; i < conf.epochs.size(); i++) {
	    char statfile[256];
	    sprintf (statfile, "/tmp/trace-exec-%lu", i);
	    if (fetch_file(conf.epochs[i].pdift->s, "/tmp") < 0) return -1;
	    rc = rename ("/tmp/trace_exec", statfile);
	    if (rc < 0) printf ("Unable to rename trace execution file, rc=%d, errno=%d\n", rc, errno);

	    sprintf (statfile, "/tmp/trace-inst-%lu", i);
	    if (fetch_file(conf.epochs[i].pdift->s, "/tmp") < 0) return -1;
	    rc = rename ("/tmp/trace_inst", statfile);
	    if (rc < 0) printf ("Unable to rename trace instruction count file, rc=%d, errno=%d\n", rc, errno);
	}
    }

    return 0;
}
