#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <dirent.h>

#include "parseklib.h"

#include <map>
#include <vector>
using namespace std;

struct replay_timing {
    pid_t     pid;
    u_long    index;
    short     syscall;
    u_int     ut;
};

struct extra_data {
    double   dtiming;
    u_long   aindex;
    u_long   start_clock;
};

struct ckpt_data {
	u_long proc_count;
	unsigned long long  rg_id;
	int    clock;
};

struct ckpt_proc_data {
	pid_t  record_pid;
	long   retval;
	loff_t logpos;
	u_long outptr;
	u_long consumed;
	u_long expclock;
};

#define MAX_CKPT_CNT 1024
struct ckpt {
    char   name[20];
    u_long clock;
};
struct ckpt ckpts[MAX_CKPT_CNT];
int ckpt_cnt = 0;

static int group_by = 0, filter_syscall = 0, details = 0, use_ckpt = 0, do_split = 0;


void format ()
{
    fprintf (stderr, "Format: mkpartition <timing dir> <# of partitions> [-g group_by] [-f filter syscall] [-s split at user-level] [-v verbose]\n");
    exit (22);
}

int cmp (const void* a, const void* b)
{
    const struct ckpt* c1 = (const struct ckpt *) a;
    const struct ckpt* c2 = (const struct ckpt *) b;
    return c1->clock - c2->clock;
}

long read_ckpts (char* dirname)
{
    char filename[80];
    DIR* dir;
    struct dirent* de;
    int fd;
    struct ckpt_proc_data cpd;
    long rc;

    dir = opendir (dirname);
    if (dir == NULL) {
	fprintf (stderr, "Cannot open dir %s\n", dirname);
	return -1;
    }
    
    while ((de = readdir (dir)) != NULL) {
	if (!strncmp(de->d_name, "ckpt.", 5)) {
	    sprintf (filename, "%s/%s", dirname, de->d_name);
	    fd = open (filename, O_RDONLY);
	    if (fd < 0) {
		fprintf (stderr, "Cannot open %s, rc=%ld, errno=%d\n", filename, rc, errno);
		return fd;
	    }
	    rc = pread (fd, &cpd, sizeof(cpd), sizeof(struct ckpt_data));
	    if (rc != sizeof(cpd)) {
		fprintf (stderr, "Cannot read ckpt_data, rc=%ld, errno=%d\n", rc, errno);
		return rc;
	    }
	    strcpy (ckpts[ckpt_cnt].name, de->d_name+5);
	    ckpts[ckpt_cnt].clock = cpd.outptr;
	    ckpt_cnt++;

	    close (fd);
	}
    }
    
    qsort (ckpts, ckpt_cnt, sizeof(struct ckpt), cmp);
    closedir (dir);
    return 0;
}

void print_utimings (struct replay_timing* timings, struct extra_data* edata, int start, int end, u_int split, int intvl)
{ 
    u_long ndx = edata[start].start_clock;
    u_long next_ndx = ndx + intvl;
    printf ("%5d k %6lu u %6lu       0       0\n", timings[start].pid, ndx, next_ndx);
    for (u_int i = 0; i < split-2; i++) {
	ndx = next_ndx;
	next_ndx = ndx+intvl;
	printf ("%5d u %6lu u %6lu       0       0\n", timings[start].pid, ndx, next_ndx);
    }
    printf ("%5d u %6lu k %6lu       0       0\n", timings[start].pid, next_ndx, edata[end].start_clock);
}

void print_timing (struct replay_timing* timings, struct extra_data* edata, int start, int end)
{ 
    printf ("%5d k %6lu k %6lu ", timings[start].pid, edata[start].start_clock, edata[end].start_clock);

    if (filter_syscall > 0) {
	if ((long) filter_syscall > timings[start].index && (long) filter_syscall <= timings[end].index) {
	    printf (" %6lu", filter_syscall-timings[start].index+1);
	} else {
	    printf (" 999999");
	}
    } else {
	printf ("      0");
    }
    if (use_ckpt > 0) {
	int i;
	for (i = 0; i < ckpt_cnt; i++) {
	    if (timings[start].index <= ckpts[i].clock) {
		if (i > 0) {
		    printf (" %6s\n", ckpts[i-1].name);
		} else {
		    printf ("      0\n");
		}
		return;
	    }
	}
	printf (" %6s\n", ckpts[i-1].name);
    } else {
	printf ("       0\n");
    }
}

static int can_attach (short syscall) 
{
    return (syscall != 192 && syscall != 91);
}

static int cnt_interval (struct extra_data* edata, int start, int end)
{
    return edata[end].aindex - edata[start].aindex;
}

int gen_timings (struct replay_timing* timings, struct extra_data* edata, int start, int end, int partitions)
{
    double biggest_gap = 0.0, goal;
    int gap_start, gap_end, last, i, new_part;

    assert (start < end);
    assert (partitions <= cnt_interval(edata, start, end));

    if (partitions == 1) {
	print_timing (timings, edata, start, end);
	return 0;
    }

    double total_time = edata[end].dtiming - edata[start].dtiming;

    // find the largest gap
    if (details) {
	printf ("Consider [%d,%d]: %d partitions %.3f time\n", start, end, partitions, total_time);
    }
    last = start;
    for (i = start+1; i < end; i++) {
	if (can_attach(timings[i].syscall)) {
	    double gap = edata[i].dtiming - edata[last].dtiming;
	    if (gap > biggest_gap) {
		gap_start = last;
		gap_end = i;
		biggest_gap = gap;
	    }
	    last = i;
	}
    }
    if (details) {
	printf ("Biggest gap from %d to %d is %.3f\n", gap_start, gap_end, edata[gap_end].dtiming - edata[gap_start].dtiming);
    }
    if (partitions > 2 && biggest_gap >= total_time/partitions) {
	// Pivot on this gap
	u_int split = 1;
	int intvl = 1;
	if (do_split && biggest_gap >= 2*total_time/partitions) {
	    split = biggest_gap*partitions/total_time-1;
	    if (partitions-split < 2) {
		split = partitions-2;
	    }
	    printf ("would like to split this gap into %d partitions\n", split);
	    printf ("begins at clock %lu ends at clock %lu\n", edata[gap_start].start_clock, edata[gap_end].start_clock);
	    if (edata[gap_end].start_clock-edata[gap_start].start_clock < split) split = edata[gap_end].start_clock - edata[gap_start].start_clock;
	    intvl = (edata[gap_end].start_clock-edata[gap_start].start_clock)/split;
	    printf ("Interval is %d\n", intvl);
	} 
	total_time -= (edata[gap_end].dtiming - edata[gap_start].dtiming);
	partitions -= split;
	if (gap_start == start) {
	    if (split > 1) {
		print_utimings (timings, edata, gap_start, gap_end, split, intvl);
	    } else {
		print_timing (timings, edata, gap_start, gap_end);
	    }
	    return gen_timings (timings, edata, gap_end, end, partitions);
	}

	new_part = 0.5 + (partitions * (edata[gap_start].dtiming - edata[start].dtiming)) / total_time;
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	if (partitions - new_part > cnt_interval(edata, gap_end, end)) new_part = partitions-cnt_interval(edata, gap_end, end);
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	if (new_part > cnt_interval(edata, start, gap_start)) new_part = cnt_interval(edata, start, gap_start);
	if (new_part < 1) new_part = 1;
	if (new_part > partitions-1) new_part = partitions-1;
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	gen_timings (timings, edata, start, gap_start, new_part);
	if (split > 1) {
	    print_utimings (timings, edata, gap_start, gap_end, split, intvl);
	} else {
	    print_timing (timings, edata, gap_start, gap_end);
	}
	return gen_timings (timings, edata, gap_end, end, partitions - new_part);
    } else {
	// Allocate first interval
	goal = total_time/partitions;
	if (details) {
	    printf ("step: goal is %.3f\n", goal);
	}
	for (i = start+1; i < end; i++) {
	    if (can_attach(timings[i].syscall)) {
		if (edata[i].dtiming-edata[start].dtiming > goal || cnt_interval(edata, i, end) == partitions-1) {
		    print_timing (timings, edata, start, i);
		    return gen_timings(timings, edata, i, end, partitions-1);
		}
	    }
	}
    }
    return -1;
}

int main (int argc, char* argv[])
{
    char filename[256];
    struct replay_timing* timings;
    struct extra_data* edata;
    struct stat st;
    int fd, rc, num, i, j, k, parts;

    if (argc < 3) {
	format ();
    }

    sprintf (filename, "%s/timings", argv[1]);
    parts = atoi(argv[2]);
    if (parts < 2) {
	fprintf (stderr, "Number of partitions must be greater than 1\n");
	return -1;
    }
    for (i = 3; i < argc; i++) {
	if (!strcmp(argv[i], "-g")) {
	    i++;
	    if (i < argc) {
		group_by = atoi(argv[i]);
	    } else {
		format();
	    }
	}
	if (!strcmp(argv[i], "-f")) {
	    i++;
	    if (i < argc) {
		filter_syscall = atoi(argv[i]);
	    } else {
		format();
	    }
	}
	if (!strcmp(argv[i], "-v")) {
	    details = 1;
	}
	if (!strcmp(argv[i], "-s")) {
	    do_split = 1;
	}
	if (!strcmp(argv[i], "-c")) {
	    use_ckpt = 1;
	}
    }
		
    if (use_ckpt) read_ckpts(argv[1]);
    
    fd = open (filename, O_RDONLY);
    if (fd < 0) {
	fprintf (stderr, "Cannot open timing file %s, rc=%d, errno=%d\n", filename, fd, errno);
	return -1;
    }

    rc = fstat (fd, &st);
    if (rc < 0) {
	fprintf (stderr, "Cannot stat timing file, rc=%d, errno=%d\n", rc, errno);
	return -1;
    }

    timings = (struct replay_timing *) malloc (st.st_size);
    if (timings == NULL) {
	fprintf (stderr, "Unable to allocate timings buffer of size %lu\n", st.st_size);
	return -1;
    }

    edata = (struct extra_data *) malloc (st.st_size);
    if (edata == NULL) {
	fprintf (stderr, "Unable to allocate extra data array of size %lu\n", st.st_size);
	return -1;
    }

    rc = read (fd, timings, st.st_size);
    if (rc < st.st_size) {
	fprintf (stderr, "Unable to read timings, rc=%d, expected %ld\n", rc, st.st_size);
	return -1;
    }
    
    // First, need to sum times for all threads to get totals for this group
    num = st.st_size/sizeof(struct replay_timing);
    int total_time = 0;
    map<u_int,u_int> last_time;
    for (i = 0; i < num; i++) {
	u_int pid = timings[i].pid;
	auto iter = last_time.find(pid);
	if (iter == last_time.end()) {
	    total_time += timings[i].ut;
	} else {
	    total_time += timings[i].ut - iter->second;
	}
	last_time[pid] = timings[i].ut;
	timings[i].ut = total_time;
    }

    // Next interpolate values where increment is small
    for (i = 0; i < num; i++) {
	for (j = i+1; j < num; j++) {
	    if (timings[i].ut != timings[j].ut) break;
	}
	for (k = i; k < j; k++) {
	    edata[k].dtiming = (double) timings[k].ut + (double) (k-i) / (double) (j-i);
	}
	i = j-1;
    }

    // Calculate index in terms of system calls we can attach to 
    u_long aindex = 1;
    for (i = 0; i < num; i++) {
	if (can_attach(timings[i].syscall)) {
	    edata[i].aindex = aindex++;
	} else {
	    edata[i].aindex = 0;
	}
    }

    // Fill in start clock time from klogs - start with parent process
    char path[256];
    sprintf (path, "%sklog.id.%d", argv[1], timings[0].pid);
    struct klogfile* log = parseklog_open(path);
    if (!log) {
	fprintf(stderr, "%s doesn't appear to be a valid klog file!\n", path);
	return -1;
    }

    struct klog_result* res = parseklog_get_next_psr(log); // exec
    int lindex = 0;
    vector<pid_t> children;
    while ((res = parseklog_get_next_psr(log)) != NULL) {
	while (timings[lindex].pid != timings[0].pid) {
	    if (timings[lindex].index == 0) children.push_back(timings[lindex].pid);
	    lindex++;
	}
	edata[lindex++].start_clock = res->start_clock;
	if (lindex >= num) break;
    }
    parseklog_close(log);

    // Now do children
    for (auto iter = children.begin(); iter != children.end(); iter++) {
	sprintf (path, "%sklog.id.%d", argv[1], *iter);	
	struct klogfile* log = parseklog_open(path);
	if (!log) {
	    fprintf(stderr, "%s doesn't appear to be a valid klog file!\n", path);
	    return -1;
	}
	lindex = 0;
	while ((res = parseklog_get_next_psr(log)) != NULL) {
	    while (timings[lindex].pid != *iter) {
		lindex++;
		if (lindex >= num) break;
	    }
	    if (lindex >= num) break;
	    edata[lindex++].start_clock = res->start_clock;
	    if (lindex >= num) break;
	}
	parseklog_close(log);
    }

    if (details) {
	for (i = 0; i < num; i++) {
	    printf ("%d: pid %d syscall %lu type %d sc %lu ut %u %.3f\n", i, timings[i].pid, timings[i].index, timings[i].syscall, edata[i].start_clock, timings[i].ut, edata[i].dtiming);
	}
	printf ("----------------------------------------\n");
    }

    printf ("%s\n", argv[1]);
    if (group_by > 0) printf ("group by %d\n", group_by);
    
    gen_timings (timings, edata, 0, num-1, parts);

    return 0;
}


