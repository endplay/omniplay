//Gets the current recorded pid given the pid of the replaying process
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>

#include "util.h"

void print_help(const char* program)
{
	fprintf(stderr, "Usage: %s <replay_pid> [-h]\n", program);
}

int main(int argc, char** argv)
{
	int c;
	while ((c = getopt(argc, argv, "h")) != -1)
	{
		switch (c)
		{
			case 'h':
			default:
				print_help(argv[0]);
				return -1;
		}
	}

	if (argc != 2)
	{
		printf("ERROR\n");
		printf("Wrong number of arguments\n");
		print_help(argv[0]);
		return -1;
	}

	pid_t pid = atoi(argv[1]);
	
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
