// A simple program to resume a recorded execution
#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <pthread.h> 

#include "util.h"

#include <assert.h>

#include <sys/types.h>
#include <sys/queue.h>

#include <vector>
#include <map>

#define MAX_THREADS 128 //arbitrary... but works


//#define USEMEM //use a ramfs? 

void print_help(const char *program) {
	fprintf (stderr, "format: %s <logdir> [-p] [-f] [-m] [-g] [--pthread libdir] [--attach_offset=pid,sysnum] [--ckpt_at=replay_clock_val] [--from_ckpt=replay_clock-val] [--fake_calls=c1,c2...] \n",
			program);
}
struct ckpt_data { 
    int fd;
    int attach_pin;
    int attach_gdb; 
    int follow_splits;
    int save_mmap;   
    char logdir[4096];
    char libdir[4096];
    char filename[4096];
    char uniqueid[4096];       
    loff_t attach_index; 
    int attach_pid; 
    u_long nfake_calls; 
    u_long *fake_calls;
    int ckpt_pos; 
};

//used to read in the header from the ckpt file
struct ckpt_hdr{ 
    u_long proc_count;
    unsigned long long rg_id;
    int clock;
};

//used to read in the processes from the header of the ckpt file
struct process_data { 
    int ppid;
    int rpid;
    int is_thread;
    int main_thread;
    int ckpt_pos; 
};

class Ckpt_Proc {            
public: 
    int pid;
    int main_thread;
    int ckpt_pos;
    std::vector<Ckpt_Proc *> threads;
    std::vector<Ckpt_Proc *> children;
    Ckpt_Proc(int p) { pid = p;};
};

std::map<int, Ckpt_Proc*> ckpt_procs; 

Ckpt_Proc * get_ckpt_proc(int pid) {
    std::map<int, Ckpt_Proc*>::iterator i =  ckpt_procs.find(pid);
    if (i == ckpt_procs.end()) { 
	ckpt_procs[pid] = new Ckpt_Proc(pid);
    }
    return ckpt_procs[pid];   
}


void *start_thread(void *td) {
    int rc;
    struct ckpt_data *cd = (struct ckpt_data *) td;
    
    rc = resume_proc_after_ckpt (cd->fd, cd->logdir, cd->filename, cd->uniqueid, cd->ckpt_pos);
    if (rc < 0) {
	perror ("resume proc after ckpt");
	exit (-1);
    }
    return NULL;
}

void *start_main_thread(void *td) {
    int rc;
    struct ckpt_data *cd = (struct ckpt_data *) td;
    
    rc = resume_after_ckpt (cd->fd, cd->attach_pin, cd->attach_gdb, cd->follow_splits, 
			    cd->save_mmap, cd->logdir, cd->libdir, cd->filename, cd->uniqueid,
			    cd->attach_index, cd->attach_pid, cd->nfake_calls, cd->fake_calls);

    if (rc < 0) {
	perror ("resume after ckpt");
	exit (-1);
    }
    return NULL;
}


int parse_process_map(int pcount, int fd) { 
    int i, copyed, first_proc = -1;
    struct process_data curr_pdata; 
    Ckpt_Proc *parent, *current; 

    for (i = 0; i < pcount; ++i) { 
	copyed = read(fd,&curr_pdata, sizeof(curr_pdata));
	if (copyed != sizeof(curr_pdata)) { 
	    perror("couldn't read curr_pdata");
	    return copyed; 
	}
	
	current = get_ckpt_proc(curr_pdata.rpid); 
	current->main_thread = curr_pdata.main_thread;
	current->ckpt_pos = curr_pdata.ckpt_pos;

	if (curr_pdata.ppid == -1) { 
	    first_proc = curr_pdata.rpid;	    
	}
	else { 
	    parent = get_ckpt_proc(curr_pdata.ppid);
	    if (curr_pdata.is_thread) { 
		parent->threads.push_back(current);
	    }
	    else { 
		parent->children.push_back(current);
	    }	    
	}       
    }
    return first_proc;
}

int restart_all_procs(Ckpt_Proc *current, struct ckpt_data *cd, pthread_t *thread, u_long &i) {

    struct ckpt_data *thread_cd; 
    int rc = 0;

    for (auto t : current->threads) { 
	if (t->main_thread) { 
	    rc = pthread_create(&thread[i++], NULL, start_main_thread,(void *)cd);
	    
	    if (rc) { 
		printf("hmm... what rc is %d\n",rc);
		exit(-1);		
	    }

	}
	else { 
	    thread_cd = (struct ckpt_data *) malloc(sizeof(struct ckpt_data)); 
	    memcpy(thread_cd, cd, sizeof(struct ckpt_data));
	    thread_cd->ckpt_pos = t->ckpt_pos;
	    rc = pthread_create(&thread[i++], NULL, start_thread,(void *)thread_cd);
	    if (rc) { 
		printf("hmm... what rc is %d\n",rc);
		exit(-1);		
	    }

	}
    }
    for (auto c : current->children) {
	if (!fork()) { 
	    return restart_all_procs(c, cd, thread, i);
	}
    }
    if (current->main_thread){ 
	rc = resume_after_ckpt (cd->fd, cd->attach_pin, cd->attach_gdb, cd->follow_splits, 
				cd->save_mmap, cd->logdir, cd->libdir, cd->filename, cd->uniqueid,
				cd->attach_index, cd->attach_pid, cd->nfake_calls, cd->fake_calls);
	if (rc) { 
	    printf("hmm... what rc is %d\n",rc);
	    exit(-1);		
	}

    }
    else { 
	rc = resume_proc_after_ckpt (cd->fd, cd->logdir, cd->filename, cd->uniqueid, current->ckpt_pos);
	if (rc) { 
	    printf("hmm... what rc is %d\n",rc);
	    exit(-1);		
	}	
    }
    return 0;
}


int main (int argc, char* argv[])
{
	int fd, cfd, rc, attach_pin = 0, attach_gdb = 0;
	loff_t attach_index = -1;
	int attach_pid = -1;
	char* libdir = NULL;
	pid_t pid;
	char ldpath[4096];
	int base;
	int follow_splits = 0;
	int save_mmap = 0;
	int ckpt_at = 0;
	int from_ckpt = 0;
	int record_timing = 0;
	int first_proc = -1;
	char filename[4096], pathname[4096], uniqueid[4096];

	u_long i = 0;
	u_long nfake_calls = 0;
	u_long* fake_calls = NULL;

	struct ckpt_hdr hdr;
	struct ckpt_data cd; 
	pthread_t thread[MAX_THREADS];

	sprintf(uniqueid,"%d",getpid()); //use the parent's pid as the uniqueid

	struct option long_options[] = {
		{"pthread", required_argument, 0, 0},
		{"attach_pin_later", optional_argument, 0, 0},
		{"attach_offset", optional_argument, 0, 0},
		{"ckpt_at", required_argument, 0, 0},
		{"from_ckpt", required_argument, 0, 0},
		{"fake_calls", required_argument, 0, 0},
		{0, 0, 0, 0}
	};

	while (1) {
		char opt;
		int option_index = 0;

		opt = getopt_long(argc, argv, "fpmhgt", long_options, &option_index);
		//printf("getopt_long returns %c (%d)\n", opt, opt);

		if (opt == -1) {
			break;
		}

		switch(opt) {
		case 0:
			switch(option_index) {
				/* --pthread */
			case 0: 
				libdir = optarg;
				break;
				/* --attach_offset or --attach_pin_later */
			case 1: case 2:
				if (sscanf(optarg, "%d,%lld", &attach_pid, &attach_index)
				    != 2) {
					fprintf(stderr, "ERROR: expected format: --attach_offset <pid>,<sysnum>\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 3:
				ckpt_at = atoi(optarg);
				printf ("Checkpointing at %d\n", ckpt_at);
				break;
			case 4:
				from_ckpt = atoi(optarg);
				break;	
			case 5:
			{
				char* p, *last;
				u_long i = 0;

				nfake_calls = 1;
				for (p = optarg; *p != '\0'; p++) {
					if (*p == ',') nfake_calls++;
				}
				fake_calls = (u_long *)malloc(nfake_calls*sizeof(u_long));
				if (fake_calls == NULL) {
					fprintf (stderr, "Cannot allocate fake calls\n");
					return -1;
				}
				last = optarg;
				for (p = optarg; *p != '\0'; p++) {
					if (*p == ',') {
						*p++ = '\0';
						fake_calls[i++] = atoi(last);
						last = p;
					}
				}
				fake_calls[i++] = atoi(last);
				break;
			}
			default:
				assert(0);
			}
			break;
		case 'm':
			//printf("save_mmap is on");
			save_mmap = 1;
			break;
		case 'f':
			//printf("follow_splits is on");
			follow_splits = 1;
			break;
		case 'p':
			//printf("attach_pin is on\n");
			attach_pin = 1;
			
			break;
		case 'h':
			print_help(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 'g':
			//printf("attach_gdb is on\n");
			attach_gdb = 1;
			break;
		case 't':
			//printf("record timing is on\n");
			record_timing = 1;
			break;

		default:
			fprintf(stderr, "Unrecognized option\n");
			print_help(argv[0]);
			exit(EXIT_FAILURE);
			break;
		}
	}

	base = optind;

	if (argc-base != 1) {
		fprintf(stderr, "Invalid non-arg arguments!\n");
		print_help(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (attach_pin && save_mmap) {
		fprintf(stderr, "Attaching pin (-p) and saving mmaps (-m) shouldn't both be enabled!\n");
		exit(EXIT_FAILURE);
	}

	if (attach_pin && attach_gdb) {
		fprintf(stderr, "Cannot attach both pin (-p) and gdb (-g).\n");
		exit(EXIT_FAILURE);
	}

	if (libdir) {
		strcpy(ldpath, libdir);
		strcat(ldpath, "/ld-linux.so.2");
		libdir = ldpath;
	}
	
	fd = open ("/dev/spec0", O_RDWR);
	if (fd < 0) {
		perror("open /dev/spec0");
		exit(EXIT_FAILURE);
	}
	pid = getpid();

#if 0
	printf("libdir: %s, ldpath: %s\n", libdir, ldpath);
	printf("resume pid %d follow %d\n", pid, follow_splits);
	printf("resume(%d, %d, %d, %d, %s, %s, %lld, %d)\n", fd, attach_pin,
		follow_splits, save_mmap, argv[base], libdir, attach_index,
		attach_pid);
#endif
	if (from_ckpt > 0) {
	    
		sprintf (filename, "ckpt.%d", from_ckpt);
#ifdef USEMEM
		sprintf (pathname, "%s/7/ckpt.%d", argv[base], from_ckpt);
#else
		sprintf (pathname, "%s/ckpt.%d", argv[base], from_ckpt);
#endif

		printf ("restoring from %s\n", pathname);
		cfd = open (pathname, O_RDONLY);
		if (cfd < 0) {
			perror ("open checkpoint file");
			return cfd;
		}
		rc = read (cfd, &hdr, sizeof(hdr)); 
		if (rc != sizeof(hdr)) {
			perror ("read proc count");
			return rc;
		}
		if (hdr.proc_count > MAX_THREADS) { 
		    perror("we need more threads!");
		    return -1;
		}


		first_proc = parse_process_map(hdr.proc_count, cfd);
		
		close(cfd);
		cd.fd = fd;
		cd.attach_pin = attach_pin;
		cd.attach_gdb = attach_gdb;
		cd.follow_splits = follow_splits;
		cd.save_mmap = save_mmap;		    
		strcpy(cd.logdir, argv[base]);
		strcpy(cd.libdir, libdir);
		strcpy(cd.filename, filename);
		strcpy(cd.uniqueid,uniqueid);
		cd.attach_index = attach_index;
		cd.attach_pid = attach_pid;
		cd.nfake_calls = nfake_calls;
		cd.fake_calls = fake_calls;
		restart_all_procs(get_ckpt_proc(first_proc), &cd, thread, i);
/*
 		if (use_threads) {

		    for (i = 1; i < hdr.proc_count; i++) {
			rc = pthread_create(&thread[i], NULL, start_thread,(void *)&cd);
			if (rc) { 
			    printf("hmm... what rc is %d\n",rc);
			    exit(-1);		
			}

		    }
		}
		else {
		    for (i = 1; i < hdr.proc_count; i++) {
			pid = fork ();
			if (pid == 0) {
			    rc = resume_proc_after_ckpt (fd, argv[base], filename, uniqueid, 0);
			    if (rc < 0) {
				perror ("resume after ckpt");
					exit (-1);
			    }
			}
		    }
		}

		rc = resume_after_ckpt (fd, attach_pin, attach_gdb, follow_splits, save_mmap, argv[base], libdir, filename, uniqueid,attach_index, attach_pid,nfake_calls,fake_calls);
*/
	} else {
		rc = resume_with_ckpt (fd, attach_pin, attach_gdb, follow_splits, save_mmap, argv[base], libdir,
				       attach_index, attach_pid, ckpt_at, record_timing, nfake_calls, fake_calls);
	}
	if (rc < 0) {
		perror("resume");
		return -1;
	}
	fprintf(stderr, "resume should not return\n");
	return -1;
}

