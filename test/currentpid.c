//#include <fcntl.h>
//#include <sys/ioctl.h>
//#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>

//#define __user 
//#include "dev/devspec.h"
#include "util.h"

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		printf("ERROR\n");
		printf("Wrong number of arguments\n");
		return -1;
	}

	pid_t pid = atoi(argv[1]);

	//printf("Pid: %i\n", pid);
	
	int fd;
	if (devspec_init(&fd))
	{
		printf("ERROR\n");
		return -1;
	}
	
	pid_t record_pid = get_current_record_pid(fd, pid);

	if (record_pid < 0)
	{
		printf("ERROR\n");
		printf("get_current_record_pid failed\n");
		return -1;
	}

	printf("%i\n", record_pid);

	return 0;
	
}
