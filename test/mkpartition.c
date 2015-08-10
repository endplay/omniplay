#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <dirent.h>

struct replay_timing {
    pid_t     pid;
    u_long    index;
    short     syscall;
    u_int     ut;
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

static int group_by = 0, filter_syscall = 0, details = 0, use_ckpt = 0;


void format ()
{
    fprintf (stderr, "Format: mkpartition <timing dir> <# of partitions> [-g group_by] [-f filter syscall]\n");
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

void print_timing (struct replay_timing* timings, int start, int end)
{ 
    printf ("%5d %6lu %6lu", timings[start].pid, timings[start].index, timings[end].index);
    if (filter_syscall > 0) {
	if (filter_syscall > timings[start].index && filter_syscall <= timings[end].index) {
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

int can_attach (short syscall) 
{
    return (syscall != 192 && syscall != 91);
}

int gen_timings (struct replay_timing* timings, double* dtimings, int start, int end, int partitions)
{
    double biggest_gap = 0.0, goal;
    int gap_start, gap_end, last, i, new_part;

    assert (start < end);

    if (partitions == 1) {
	print_timing (timings, start, end);
	return 0;
    }

    double total_time = dtimings[end] - dtimings[start];

    // find the largest gap
    if (details) {
	printf ("Consider [%d,%d]: %d partitions %.3f time\n", start, end, partitions, total_time);
    }
    last = start;
    for (i = start+1; i < end; i++) {
	if (can_attach(timings[i].syscall)) {
	    double gap = dtimings[i] - dtimings[last];
	    if (gap > biggest_gap) {
		gap_start = last;
		gap_end = i;
		biggest_gap = gap;
	    }
	    last = i;
	}
    }
    if (details) {
	printf ("Biggest gap from %d to %d is %.3f\n", gap_start, gap_end, dtimings[gap_end] - dtimings[gap_start]);
    }
    if (partitions > 2 && biggest_gap >= total_time/partitions) {
	// Pivot on this gap
	total_time -= (dtimings[gap_end] - dtimings[gap_start]);
	partitions--;
	if (gap_start == start) {
	    print_timing (timings, gap_start, gap_end);
	    return gen_timings (timings, dtimings, gap_end, end, partitions);
	}

	new_part = 0.5 + (partitions * (dtimings[gap_start] - dtimings[start])) / total_time;
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	if (partitions - new_part > (end-gap_end)) new_part = partitions-(end-gap_end);
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	if (new_part > gap_start-start) new_part = gap_start-start;
	if (new_part < 1) new_part = 1;
	if (new_part > partitions-1) new_part = partitions-1;
	if (details) {
	    printf ("gap - new part %d\n", new_part);
	}
	gen_timings (timings, dtimings, start, gap_start, new_part);
	print_timing (timings, gap_start, gap_end);
	return gen_timings (timings, dtimings, gap_end, end, partitions - new_part);
    } else {
	// Allocate first interval
	goal = total_time/partitions;
	if (details) {
	    printf ("step: goal is %.3f\n", goal);
	}
	for (i = start+1; i < end; i++) {
	    if (can_attach(timings[i].syscall)) {
		if (dtimings[i]-dtimings[start] > goal) {
		    print_timing (timings, start, i);
		    return gen_timings(timings, dtimings, i, end, partitions-1);
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
    double* dtimings;
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

    dtimings = (double *) malloc (st.st_size);
    if (dtimings == NULL) {
	fprintf (stderr, "Unable to allocate timings buffer of size %lu\n", st.st_size);
	return -1;
    }

    rc = read (fd, timings, st.st_size);
    if (rc < st.st_size) {
	fprintf (stderr, "Unable to read timings, rc=%d, expected %ld\n", rc, st.st_size);
	return -1;
    }
    
    num = st.st_size/sizeof(struct replay_timing);
    for (i = 0; i < num; i++) {
	for (j = i+1; j < num; j++) {
	    if (timings[i].ut != timings[j].ut) break;
	}
	for (k = i; k < j; k++) {
	    dtimings[k] = (double) timings[k].ut + (double) (k-i) / (double) (j-i);
	}
	i = j-1;
    }


    if (details) {
      for (i = 0; i < num; i++) {
	  printf ("%d: pid %d syscall %lu type %d ut %u %.3f\n", i, timings[i].pid, timings[i].index, timings[i].syscall, timings[i].ut, dtimings[i]);
      }
      printf ("----------------------------------------\n");
    }

    printf ("%s\n", argv[1]);
    if (group_by > 0) printf ("group by %d\n", group_by);
    
    gen_timings (timings, dtimings, 0, num-1, parts);

    return 0;
}


