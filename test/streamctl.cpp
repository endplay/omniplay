#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>

#include <atomic>
#include <vector>

using namespace std;

#include "streamserver.h"

int main (int argc, char* argv[]) 
{
    int rc;
    char dirname[80];
    struct epoch_data epoch;
    vector<struct epoch_data> epochs;

    if (argc != 2) {
	fprintf (stderr, "format: streamctl <epoch description file>\n");
	return -1;
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
	    
	    // Receiver may not be started, so spin until connection is accepted
	    rc = connect (s, (struct sockaddr *) &addr, sizeof(addr));
	    if (rc < 0) {
		fprintf (stderr, "Cannot connect to %s, errno=%d\n", estart->hostname, errno);
		return rc;
	    }

	    struct epoch_hdr ehdr;
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
	    close (s); // No more data to send
	}
    }

    return 0;
}
