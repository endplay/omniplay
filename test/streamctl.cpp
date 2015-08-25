#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>

#include <atomic>
#include <vector>
#include <unordered_set>

using namespace std;

#include "streamserver.h"

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
    unordered_set<int> conns;
    int wait_for_response = 0;

    if (argc < 2) {
	format();
    }

    for (int i = 2; i < argc; i++) {
	if (!strcmp (argv[i], "-w")) {
	    wait_for_response = 1;
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
	    }
	    printf ("%lu epochs to %s\n", ecnt, estart->hostname);
	    if (wait_for_response) {
		conns.insert(s);
	    } else {
		close (s);
	    }
	}
    }

    if (wait_for_response) {
	while (conns.size()) {
	    struct pollfd fds[conns.size()];
	    int n = 0;
	    for (auto iter = conns.begin(); iter != conns.end(); iter++) {
		fds[n].fd = *iter;
		fds[n].events = POLLIN;
	    }
	    rc = poll (fds, n, -1);
	    if (rc < 0) {
		fprintf (stderr, "poll failed, rc=%d\n", rc);
		return rc;
	    }
	    for (int i = 0; i < n; i++) {
		if (fds[i].revents) {
		    long retval;
		    rc = recv (fds[i].fd, &retval, sizeof(retval), 0);
		    if (rc != sizeof(retval)) {
			fprintf (stderr, "Cannot send ack,rc=%d\n", rc);
		    }
		    printf ("done reval is %ld!\n", retval);
		    conns.erase(i);
		}
	    }
	}
    }

    return 0;
}
