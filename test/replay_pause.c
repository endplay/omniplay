#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <linux/kernel.h>

#define COMMAND_LENGTH 1024
#define CLOCK_MAX -1

void print_command () {
	printf ("----------------------------\n");
	printf ("Replay pausing tool\n");
	printf ("  	contact Xianzheng if you have any problem\n\n");
	printf ("Command list \n");
        printf ("r (or run)           :run the process. The process will be fully replayed unless you set up a break clock by break command;\n");
	printf ("c (or continue)      :continue to run the process after a break clock\n");
	printf ("b (or break) [clock] :set up a clock at which the replay process will pause\n");
	printf ("n (or next)   	     :the process will continue to run until {step_clock} clocks have passed. step_clock is a variable that can be set by set command;\n");
	printf ("s (or set) [step]    :Change the step_clock to be the new value\n");
	printf ("h (or help)   	     :Print help information\n");
	printf ("q (or quit)          :quit replay pausing tool\n");
	printf ("----------------------------\n");
}

int main(int argc, char *argv[])
{
	int fd;
	unsigned long *map;  /* mmapped array of int's */
	unsigned long pause_clock = 0;
	char filename[1024];
	long rc;
	unsigned long step = 1;
	int replay = 1;

	if (argc != 2) {
		printf ("Usage: replay_pause pid\n");
	}
	memset (filename, 0, 1024);
	sprintf (filename, "/dev/shm/uclock%s", argv[1]);


	fd = open(filename, O_RDWR);
	if (fd == -1) {
		perror("Error opening file for reading, cannot find the process");
		exit(-1);
	}

	map = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		close(fd);
		perror("Error mmapping the file");
		exit(-1);
	}

	pause_clock = CLOCK_MAX;

	while (replay) {
		char command[COMMAND_LENGTH];
		printf ("(replay_pause tool): ");
		scanf ("%s", command);
		switch (command[0]) {
			case 'c':
			case 'n':
			case 'r': {
				printf ("process running now\n");
				if (command[0] == 'n') {
					pause_clock = map[0] + step;
					printf ("Next to break at %lu (step = %lu)\n", pause_clock, step);
				}
				map[1] = pause_clock;
				rc = syscall (223, atoi (argv[1]));

				//printf ("rc:%ld, errno:%d\n", rc, errno);
				if (!rc) {
					printf ("Cannot wakeup sleeping process.\n");
					break;
				}

				while (1) {
					//waiting until replay exits or break at a given clock
					if (map[1] == 0) {
						printf ("The replay is over now. Exit.\n");
						replay = 0;
						break;
					} else if (map[0] >= map[1]) {
						printf ("Break at clock %lu (scheduled to break at %lu)\n", map[0], map[1]);
						break;
					} else {
						//sleep 100 ms and check later
						usleep (100000);
					}
				}
				continue;

			}
			break;
			case 'b': {
				scanf ("%s", command);
				pause_clock = atoi (command);
				while (pause_clock == 0) {
					printf ("please enter a clock value greater than 0\n");
					pause_clock = CLOCK_MAX;
					scanf ("%s", command);
					pause_clock = atoi (command);
				}
				printf ("Will break at clock %lu, now is %lu\n", pause_clock, map[0]);
				map[1] = pause_clock;				
				continue;
			}
			break;
			case 's': {
				scanf ("%s", command);
				step = atoi (command);
				printf ("Step break step to %lu\n", step);
				continue;
			}
			break;
			case 'q': {
				printf ("Exit now.\n");
				break;
			}
			break;
			case 'h': {
				print_command ();
				continue;
			}
			default: {
				printf ("Non-recognized command.\n");
				print_command ();
				continue;
			}
		}
		break;
		
	}

	if (munmap(map, 4096) == -1) {
		perror("Error un-mmapping the file\n");
	}
	close(fd);
	return 0;
}
