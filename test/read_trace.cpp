#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include <unordered_map>
#include <unordered_set>
using namespace std;

int main (int argc, char* argv[])
{
    struct stat64 st;
    unordered_map<u_long,u_long> num_instructions;
    unordered_set<u_long> unique_traces;
    u_long instructions_instrumented = 0;
    char filename[256];

    if (argc != 3) {
	fprintf (stderr, "read_trace [goal] [epochs]\n");
	exit (0);
    }

    u_int goal = atoi(argv[1]);
    u_int epochs = atoi(argv[2]);
    
    u_long syscall = 0;
    u_long max_instrumented = 0;
    u_long syscall_cnt = 0;

    for (u_int i = 0; i < epochs; i++) {
	sprintf (filename, "/tmp/trace-inst-%d", i);
	int fd = open(filename, O_RDONLY, 0644);
	if (fd < 0) {
	    fprintf(stderr, "could not open trace shmem %s, errno %d\n", filename, errno);
	    return fd;
	}
	
	u_long rc = fstat64(fd, &st);
	if (rc < 0) {
	    fprintf(stderr, "could not stat %s, errno %d\n", filename, errno);
	    return rc;
	}
	
	u_long mapsize = st.st_size;
	if (mapsize%4096) mapsize += 4096-(mapsize%4096);
	
	u_long* log = (u_long *) mmap (0, mapsize, PROT_READ, MAP_SHARED, fd, 0);
	if (log == MAP_FAILED) {
	    fprintf(stderr, "could not map %s, errno %d\n", filename, errno);
	    return rc;
	}
	u_long endat = (u_long) log + st.st_size;
	while ((u_long) log < endat) {
	    u_long insts = *log++;
	    u_long trace = *log++;
	    num_instructions[trace] = insts;
	}

	close(fd);

	sprintf (filename, "/tmp/trace-exec-%d", i);
	fd = open(filename, O_RDONLY, 0644);
	if (fd < 0) {
	    fprintf(stderr, "could not open trace shmem %s, errno %d\n", filename, errno);
	    return fd;
	}

	rc = fstat64(fd, &st);
	if (rc < 0) {
	    fprintf(stderr, "could not stat %s, errno %d\n", filename, errno);
	    return rc;
	}
	
	mapsize = st.st_size;
	if (mapsize%4096) mapsize += 4096-(mapsize%4096);
	
	log = (u_long *) mmap (0, mapsize, PROT_READ, MAP_SHARED, fd, 0);
	if (log == MAP_FAILED) {
	    fprintf(stderr, "could not map %s, errno %d\n", filename, errno);
	    return rc;
	}
	endat = (u_long) log + st.st_size;
	if (*log++) {
	    fprintf(stderr, "expect first entry to be 0\n");
	    return -1;
	}
	if (i != 0) {
	    log++; // syscall number = 0
	    log++; // syscall restart
	    if (*log++) {
		fprintf(stderr, "expect next entry to be 0\n");
		return -1;
	    }
	}

	do {
	    log++;
	    syscall = syscall_cnt++;
	    //printf ("Syscall %lu\n", syscall);
	    if (instructions_instrumented > goal) {
		printf ("Break epoch at syscall %lu - instructions %lu\n", syscall, instructions_instrumented);
		if (instructions_instrumented > max_instrumented) max_instrumented = instructions_instrumented;
		unique_traces.clear();
		instructions_instrumented = 0;
	    }
	    while (*log) {
		u_long trace = *log++;
		if (unique_traces.insert(trace).second) {
		    //printf ("Trace: %lx %ld\n", trace, num_instructions[trace]);
		    instructions_instrumented += num_instructions[trace];
		} else {
		    //printf ("Already seen %lx\n", trace);
		}
	    }
	    log++;
	} while ((u_long) log < endat);
	//printf ("Saw %lu system calls\n", syscall);
	close (fd);
    }

    if (instructions_instrumented > max_instrumented) max_instrumented = instructions_instrumented;
    printf ("Last epoch at syscall %lu - instructions %lu\n", syscall, instructions_instrumented);
    printf ("Largest epoch: %lu\n", max_instrumented);
	
    return 0;
}
