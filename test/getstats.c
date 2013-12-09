// A simple program to print out replay stats
// Currently cannot record/replay this program because it uses /dev/spec0 - is this important?

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "util.h"

#include <sys/types.h>

int main (int argc, char* argv[])
{
    int fd, rc;
    struct replay_stat_data stats;

    fd = open ("/dev/spec0", O_RDWR);
    if (fd < 0) {
	perror ("open /dev/spec0");
	return -1;
    }
    rc = get_replay_stats (fd, &stats);
    if (rc < 0) {
	perror ("resume");
	return -1;
    }

    printf ("replays started:  %d\n",   stats.started);
    printf ("replays finished: %d\n",   stats.finished);
    printf ("replays w/mismatch: %d\n", stats.mismatched);

    return 0;
}
