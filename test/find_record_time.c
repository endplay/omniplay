#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <sys/resource.h>

// redefined from the kernel
#define _NSIGS 64
struct k_sigaction {
	unsigned long sa_handler;
	unsigned long sa_flags;
	unsigned long sa_restorer;
	unsigned long sa_mask;
	unsigned long ka_restorer;
};

struct checkpoint {
    pid_t record_pid;
    uint64_t rg_id;
    uint64_t parent_rg_id;
    long len;
    char filename[4096];
    struct rlimit rlimits[RLIM_NLIMITS];
    struct k_sigaction sighands[_NSIGS];
    long args_cnt;
    long env_cnt;
    struct timespec start_time;
};

int parse_ckpt (char * ckpt_name, struct checkpoint* ckpt)
{
    int i;
    int ckpt_fd;
    long copyed;

    if (!ckpt) {
        fprintf(stderr, "Not a valid ckpt structure\n");
        return -1;
    }

    ckpt_fd = open(ckpt_name, O_RDONLY);

    if (ckpt_fd < 0) {
        fprintf(stderr, "Could not open ckpt file %s\n", ckpt_name);
        return errno;
    }

    copyed = read(ckpt_fd, (char *) &(ckpt->record_pid), sizeof(ckpt->record_pid));
    if (copyed != sizeof(ckpt->record_pid)) {
        printf ("parseckpt: tried to read record pid, got rc %ld\n", copyed);
        return -1;
    }

    copyed = read(ckpt_fd, (char *) &(ckpt->rg_id), sizeof((ckpt->rg_id)));
    if (copyed != sizeof(ckpt->rg_id)) {
        printf ("parseckpt: tried to read rg_id, got %ld\n", copyed);
        return -1;
    }

    copyed = read(ckpt_fd, (char *) &(ckpt->parent_rg_id), sizeof(ckpt->parent_rg_id));
    if (copyed != sizeof(ckpt->parent_rg_id)) {
        printf ("parseckpt: tried to read parent_rg_id, got %ld\n", copyed);
        return -1;
    }

    
    copyed = read(ckpt_fd, (char *) &(ckpt->len), sizeof(ckpt->len));
    if (copyed != sizeof(ckpt->len)) {
        printf ("parseckpt: tried to read filename size, got rc %ld\n", copyed);
        return -1;
    }
    copyed = read(ckpt_fd, &(ckpt->filename), ckpt->len);
    if (copyed != ckpt->len) {
        printf ("parseckpt: tried to read filename, got rc %ld\n", copyed);
        return -1;
    }

    copyed = read(ckpt_fd, (char *) &ckpt->rlimits, sizeof(ckpt->rlimits));
    if (copyed != sizeof(ckpt->rlimits)) {
	printf ("parseckpt: tried to read rlimits, got rc %ld\n", copyed);
	return -1;
    }

    // Next, read the sighands
    copyed = read(ckpt_fd, (char *) &ckpt->sighands, sizeof(struct k_sigaction) * _NSIGS);
    if (copyed != (64 * 20)) {
        printf ("parseckpt: tried to read sighands, got %ld", copyed);
        return -1;
    }

    // Next, read the number of arguments
    copyed = read(ckpt_fd, (char *) &ckpt->args_cnt, sizeof(ckpt->args_cnt));
    if (copyed != sizeof(ckpt->args_cnt)) {
	printf ("parseckpt: tried to read record pid, got rc %ld\n", copyed);
	return -1;
    }
	
    // Now read in each argument
    for (i = 0; i < ckpt->args_cnt; i++) {
        char buf[4096];
	long len; // argument len
	copyed = read(ckpt_fd, (char *) &len, sizeof(len));
	if (copyed != sizeof(len)) {
	    printf ("parseckpt: tried to read argument %d len, got rc %ld\n", i, copyed);
	    return -1;
	}
	copyed = read(ckpt_fd, buf, len);
	if (copyed != len) {
	    printf ("parseckpt: tried to read argument %d, got rc %ld\n", i, copyed);
	    return -1;
	}
    }

    // Next, read the number of env. objects
    copyed = read(ckpt_fd, (char *) &ckpt->env_cnt, sizeof(ckpt->env_cnt));
    if (copyed != sizeof(ckpt->env_cnt)) {
	printf ("parseckpt: tried to read record pid, got rc %ld\n", copyed);
	return -1;
    }

    // Now read in each env. object
    for (i = 0; i < ckpt->env_cnt; i++) {
	char buf[4096];
	long len;
	copyed = read(ckpt_fd, (char *) &len, sizeof(len));
	if (copyed != sizeof(len)) {
	    printf ("parseckpt: tried to read env. %d len, got rc %ld\n", i, copyed);
	    return -1;
	}
	copyed = read(ckpt_fd, buf, len);
	if (copyed != len) {
	    printf ("parseckpt: tried to read env. %d, got rc %ld\n", i, copyed);
	    return -1;
	}
    }

    copyed = read(ckpt_fd, (char *) &(ckpt->start_time), sizeof(ckpt->start_time));
    if (copyed != sizeof(ckpt->start_time)) {
        printf ("parseckpt: tried to read time, got %ld\n", copyed);
        return -1;
    }

    close(ckpt_fd);
    return 0;
}

// Returns 1 if time1 > time2, 0 if time1 == time2, -1 if time1 < time2
int timespec_compare(struct timespec* time1, struct timespec* time2)
{
   if (time1->tv_sec > time2->tv_sec) {
       return 1;
   } else if (time1->tv_sec < time2->tv_sec) {
       return -1;
   } else {
       if (time1->tv_nsec > time2->tv_nsec) {
           return 1;
       } else if (time1->tv_nsec < time2->tv_nsec) {
           return -1;
       } 
   }
   // fall through, they're equal
   return 0;
}

/* Subtracts two timespec values, puts the result in result */
int timespec_sub(struct timespec* time1, struct timespec* time2, struct timespec* result)
{
    struct timespec* larger;
    struct timespec* smaller;

    assert (result != NULL);
    if (!result) {
        return -1;
    }

    if (timespec_compare(time1, time2) == 1) {
        larger = time1;
        smaller = time2;
    } else if (timespec_compare(time1, time2) == -1) {
        larger = time2;
        smaller = time1;
    } else {
        result->tv_sec = 0;
        result->tv_nsec = 0;
    }

    if (larger->tv_sec == smaller->tv_sec) {
        result->tv_sec = 0;
        result->tv_nsec = (larger->tv_nsec - smaller->tv_nsec);
    } else {
        if (larger->tv_nsec >= smaller->tv_sec) {
            result->tv_sec = larger->tv_sec - smaller->tv_sec;
            result->tv_nsec = larger->tv_nsec - smaller->tv_nsec;
        } else {
            result->tv_sec = larger->tv_sec - smaller->tv_sec - 1;
            // XXX overflow?
            result->tv_nsec = 1000000000 + larger->tv_nsec - smaller->tv_nsec;
        }
    }

    return 0;
}

int main(int argc, char** argv)
{
    struct checkpoint ckpt;
    char ckptname[256];
    DIR *dp;
    struct dirent *ep;
    struct stat buf;
    struct timespec last_modified_time;
    struct timespec result;

    if (argc < 2) {
        fprintf(stderr, "usage: ./find_record_time [record directory]");
        return -1;
    }

    snprintf(ckptname, 256, "%s/ckpt", argv[1]);
    memset(&last_modified_time, 0, sizeof(last_modified_time));
    if (parse_ckpt(ckptname, &ckpt)) {
        fprintf(stderr, "There was problem parsing the ckpt\n");
        return -1;
    }

    dp = opendir(argv[1]);
    if (dp != NULL) {
        while ((ep = readdir(dp))) {
            if (ep->d_type == DT_REG) {
                int rc;
                char filename[256];
                struct timespec* file_timespec;

                snprintf(filename, 256, "%s/%s", argv[1], ep->d_name);
                rc = stat(filename, &buf);
                if (rc < 0) {
                    fprintf(stderr, "problem statting file %s\n", filename);
                    continue;
                }
                file_timespec = (struct timespec *) &(buf.st_mtime);
                // if this file's time is most recent modified time that we've seen
                if (timespec_compare(file_timespec, &last_modified_time) == 1) {
                    memcpy(&last_modified_time, file_timespec, sizeof(struct timespec));
                }
            }
        }
    } else {
        fprintf(stderr, "Could not open record directory %s\n", argv[1]);
        return -1;
    }

    // now subtract time from the start time from the checkpoint and print the record time
    timespec_sub(&ckpt.start_time, &last_modified_time, &result);
    fprintf(stdout, "%ld sec %ld nsec\n", result.tv_sec, result.tv_nsec);

    return 0;
}
