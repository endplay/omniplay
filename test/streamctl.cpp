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
#include <unordered_set>

using namespace std;

#include "streamserver.h"

// One for each streamserver
struct epoch_ctl {
    u_long start;
    u_long num;
    int    s;
};

long fetch_file (int s, char* dest_dir)
{
    char buf[1024*1024];
    char filename[256];
    struct stat st;
    u_long bytes_read;
    long rc;

    // Get the filename
    rc = read (s, filename, sizeof(filename));
    if (rc != sizeof(filename)) {
	fprintf (stderr, "fetch_file: cannot read filename, rc=%ld, errno=%d\n", rc, errno);
	return rc;
    }

    // Get the file stats
    rc = read (s, &st, sizeof(st));
    if (rc != sizeof(st)) {
	fprintf (stderr, "fetch_file: cannot read file %s stats, rc=%ld, errno=%d\n", filename, rc, errno);
	return rc;
    }
	
    // Open the new file
    char pathname[256];
    sprintf (pathname, "%s/%s", dest_dir, filename);
    int fd = open (pathname, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) {
	fprintf (stderr, "fetch_file: cannot create %s, rc=%ld, errno=%d\n", pathname, rc, errno);
	return rc;
    }
	
    // Get the file data and write it out
    while (bytes_read < st.st_size) {
	u_long to_read = st.st_size - bytes_read;
	if (to_read > sizeof(buf)) to_read = sizeof(buf);
	rc = read (s, buf, to_read);
	if (rc <= 0) {
	    fprintf (stderr, "fetch_file: read of %s returns %ld, errno=%d\n", filename, rc, errno);
	    break;
	}
	long wrc = write(fd, buf, rc);
	if (wrc != rc) {
	    fprintf (stderr, "fetch_file: write of %s returns %ld, errno=%d\n", filename, rc, errno);
	    break;
	}
	bytes_read += rc;
    }

    return rc;
}

int fetch_results (char* top_dir, struct epoch_ctl ectl)
{
    char dir[512];

    for (int i = 0; i < ectl.num; i++) {
	sprintf (dir, "%s/%lu", top_dir, ectl.start+i);
	long rc = mkdir (dir, 0644);
	if (rc < 0) {
	    fprintf (stderr, "Cannot make dir %s\n", dir);
	    return rc;
	}
	// Fetch 4 files: results, addresses, input and output tokens
	for (int j = 0; j < 4; j++) {
	    fetch_file(ectl.s, dir);
	}
    }
    return 0;
}

void format ()
{
    fprintf (stderr, "format: streamctl <epoch description file> [-w]\n");
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
    int wait_for_response = 0, validate = 0;
    char* dest_dir;
    u_long epochno = 0, last_epochno = 0;

    if (argc < 2) {
	format();
    }

    for (int i = 2; i < argc; i++) {
	if (!strcmp (argv[i], "-w")) {
	    wait_for_response = 1;
	} else if (!strcmp (argv[i], "-v")) {
	    i++;
	    if (i < argc) {
		dest_dir = argv[i];
		validate = 1;
	    } else {
		format();
	    }
	} else {
	    format();
	}
    }

    // Read in the epoch file
    FILE* file = fopen(argv[1], "r");
    if (file == NULL) {
	fprintf (stderr, "Unable to open epoch description file %s, errno=%d\n", argv[1], errno);
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
	    rc = sscanf (line, "%d %lu %lu %lu %lu %s\n", &epoch.start_pid, &epoch.start_syscall, 
			 &epoch.stop_syscall, &epoch.filter_syscall, &epoch.ckpt, epoch.hostname);
	    if (rc != 6) {
		fprintf (stderr, "Unable to parse line of epoch descrtion file: %s\n", line);
		return -1;
	    }
	    epochs.push_back(epoch);
	}
    }

    fclose(file);

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
	    // Connect to streamserver
	    struct hostent* hp = gethostbyname (estart->hostname);
	    if (hp == NULL) {
		fprintf (stderr, "Invalid host %s, errno=%d\n", estart->hostname, h_errno);
		return -1;
	    }
	    
	    int s = socket (AF_INET, SOCK_STREAM, 0);
	    if (s < 0) {
		fprintf (stderr, "Cannot create socket, errno=%d\n", errno);
		return s;
	    }

	    struct sockaddr_in addr;
	    addr.sin_family = AF_INET;
	    addr.sin_port = htons(STREAMSERVER_PORT);
	    memcpy (&addr.sin_addr, hp->h_addr, hp->h_length);
	    
	    rc = connect (s, (struct sockaddr *) &addr, sizeof(addr));
	    if (rc < 0) {
		fprintf (stderr, "Cannot connect to %s, errno=%d\n", estart->hostname, errno);
		return rc;
	    }

	    struct epoch_hdr ehdr;
	    ehdr.flags = 0;
	    if (wait_for_response) ehdr.flags |= SEND_ACK;
	    if (validate) ehdr.flags |= SEND_RESULTS;
	    strcpy (ehdr.dirname, dirname);
	    ehdr.epochs = ecnt;
	    ehdr.start_flag = start_flag;
	    start_flag = false;
	    ehdr.finish_flag = (efinish == epochs.end());
	    if (!ehdr.start_flag) {
		strcpy (ehdr.next_host, prev_hostname);
	    }
	    prev_hostname = estart->hostname;

	    rc = write (s, &ehdr, sizeof(ehdr));
	    if (rc != sizeof(ehdr)) {
		fprintf (stderr, "Cannot send header to streamserver, rc=%d\n", rc);
		return rc;
	    }

	    for (; estart != efinish; estart++) {
		struct epoch_data tmp = *estart;
		rc = write (s, &tmp, sizeof(struct epoch_data));
		if (rc != sizeof(struct epoch_data)) {
		    fprintf (stderr, "Cannot send epoch data to streamserver, rc=%d\n", rc);
		    return rc;
		}
		epochno++;
	    }

	    struct epoch_ctl ectl;
	    ectl.start = last_epochno;
	    ectl.num = epochno-last_epochno;
	    ectl.s = s;
	    epochctls.push_back(ectl);
	    last_epochno = epochno;

	    printf ("%lu epochs to %s\n", ecnt, estart->hostname);
	    conns.insert(s);
	}
    }

    if (wait_for_response) {
	while (conns.size()) {
	    struct pollfd fds[conns.size()];
	    int n = 0;
	    for (auto iter = conns.begin(); iter != conns.end(); iter++) {
		fds[n].fd = *iter;
		fds[n].events = POLLIN;
		n++;
	    }
	    rc = poll (fds, n, -1);
	    if (rc < 0) {
		fprintf (stderr, "poll failed, rc=%d\n", rc);
		return rc;
	    }
	    for (int i = 0; i < n; i++) {
		if (fds[i].revents) {
		    if (fds[i].revents&POLLIN) {
			long retval;
			rc = recv (fds[i].fd, &retval, sizeof(retval), 0);
			if (rc != sizeof(retval)) {
			    fprintf (stderr, "Cannot recv ack,rc=%d\n", rc);
			}
			printf ("done reval is %ld!\n", retval);
		    } else {
			printf ("done with poll error %x\n", fds[i].revents);
		    }
		    conns.erase(fds[i].fd);
		}
	    }
	}
    }

    if (validate) {
	// Create directory for results files
	rc = mkdir (dest_dir, 0644);
	if (rc < 0) {
	    fprintf (stderr, "Cannot make dir %s\n", dest_dir);
	    return rc;
	}

	// Fetch the files into each directory 
	for (auto iter = epochctls.begin(); iter != epochctls.end(); iter++) {
	    fetch_results (dest_dir, *iter);
	}
    }

    return 0;
}
