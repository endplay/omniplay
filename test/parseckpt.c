#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>

int main (int argc, char* argv[])
{
    char buf[4096];
    long copyed, args_cnt, env_cnt, len;
    int fd, i;
    pid_t record_pid;
    struct rlimit rlimits[RLIM_NLIMITS];

    if (argc != 2) {
	printf ("format: parseckpt <dir>\n");
	return -1;
    }
    
    sprintf (buf, "%s/ckpt", argv[1]);
    fd = open (buf, O_RDONLY);
    if (fd < 0) {
	perror ("open");
	return fd;
    }
    
    copyed = read(fd, (char *) &record_pid, sizeof(record_pid));
    if (copyed != sizeof(record_pid)) {
	printf ("parseckpt: tried to read record pid, got rc %ld\n", copyed);
	return -1;
    }
    printf ("record pid: %d\n", record_pid);

    copyed = read(fd, (char *) &rlimits, sizeof(rlimits));
    if (copyed != sizeof(rlimits)) {
	printf ("parseckpt: tried to read rlimits, got rc %ld\n", copyed);
	return -1;
    }
    printf ("record pid: %d\n", record_pid);

    // Next, read the number of arguments
    copyed = read(fd, (char *) &args_cnt, sizeof(args_cnt));
    if (copyed != sizeof(args_cnt)) {
	printf ("parseckpt: tried to read record pid, got rc %ld\n", copyed);
	return -1;
    }
	
    // Now read in each argument
    for (i = 0; i < args_cnt; i++) {
	copyed = read(fd, (char *) &len, sizeof(len));
	if (copyed != sizeof(len)) {
	    printf ("parseckpt: tried to read argument %d len, got rc %ld\n", i, copyed);
	    return -1;
	}
	copyed = read(fd, buf, len);
	if (copyed != len) {
	    printf ("parseckpt: tried to read argument %d, got rc %ld\n", i, copyed);
	    return -1;
	}
	printf ("Argument %d is %s\n", i, buf);
    }

    // Next, read the number of env. objects
    copyed = read(fd, (char *) &env_cnt, sizeof(env_cnt));
    if (copyed != sizeof(env_cnt)) {
	printf ("parseckpt: tried to read record pid, got rc %ld\n", copyed);
	return -1;
    }

    // Now read in each env. object
    for (i = 0; i < env_cnt; i++) {
	copyed = read(fd, (char *) &len, sizeof(len));
	if (copyed != sizeof(len)) {
	    printf ("parseckpt: tried to read env. %d len, got rc %ld\n", i, copyed);
	    return -1;
	}
	copyed = read(fd, buf, len);
	if (copyed != len) {
	    printf ("parseckpt: tried to read env. %d, got rc %ld\n", i, copyed);
	    return -1;
	}
	printf ("Env. var. %d is %s\n", i, buf);
    }

    close (fd);
    return 0;
}
