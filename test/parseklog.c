#include <sys/socket.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#define __USE_LARGEFILE64
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <linux/net.h>
#include <linux/utsname.h>
#include <linux/ipc.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/statfs.h>
#include <asm/ldt.h>
#define __USE_LARGEFILE64
#include <fcntl.h>
#include <sys/resource.h>

#define REPLAY_MAX_THREADS 16
//#define USE_HPC
#define USE_ARGSALLOC
#define USE_DISK_CKPT

//#define PRINT_STATISTICS

struct repsignal {
	int signr;
	siginfo_t info;
	struct /* k_ */ sigaction ka;
	sigset_t blocked;
	sigset_t real_blocked;
	struct repsignal* next;
};

struct syscall_result {
#ifdef USE_HPC
	unsigned long long	hpc_begin;	// Time-stamp counter value when system call started
	unsigned long long	hpc_end;	// Time-stamp counter value when system call finished
#endif
	short			sysnum;		// system call number executed
	long			retval;		// return code from the system call
	struct repsignal*	signal;		// Set if sig should be delivered
	void*			retparams;	// system-call-specific return data
	void*			args;		// system-call-specific arguments
	long                    start_clock;    // total order over start
        long                    stop_clock;     // and stop of all system calls
};

#define REPLAY_MAX_RANDOM_VALUES 6
struct rvalues {
	int cnt;
	long val[REPLAY_MAX_RANDOM_VALUES];
};

struct waitpid_retvals {
	int status;
};

struct gettimeofday_retvals {
	short           has_tv;
	short           has_tz;
	struct timeval  tv;
	struct timezone tz;
};

struct select_retvals {
	char           has_inp;
	char           has_outp;
	char           has_exp;
	char           has_tv;
	fd_set         inp;
	fd_set         outp;
	fd_set         exp;
	struct timeval tv;
};

struct mmap_pgoff_args {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long pgoff;
};

struct rt_sigaction_args {
	int sig;
	const struct sigaction* act;
	struct sigaction* kact;
	struct sigaction sa;
	struct sigaction* oact;
	size_t sigsetsize;
};

struct rt_sigprocmask_args {
	int how;
	sigset_t set;
	char* kset;
	sigset_t oset;
	size_t sigsetsize;
};

#define atomic_t int

struct generic_socket_retvals {
	atomic_t refcnt;
	int call;
};

struct accept_retvals {
	atomic_t refcnt;
	int call;
	int addrlen;
	char addr; // Variable length buffer follows
};

struct socketpair_retvals {
	atomic_t refcnt;
	int call;
	int sv0;
	int sv1;
};

struct recvfrom_retvals {
	atomic_t refcnt;
	int call;
	struct sockaddr addr;
	int addrlen;
	char buf;  // Variable length buffer follows 
};

struct getxattr_retvals {
	char value; // Variable length buffer follows
};

struct sendfile64_retvals {
	atomic_t refcnt;
	loff_t offset;
};
/* XXX- recvmsg_retvals should save whole data structures
	that are pointed by the fields in struct msghdr,
	but for simplicity, assume and check
	msg_namelen <= 32
	msg_iovlen <= 1
	msg_controllen <= 32
*/
#define SIMPLE_MSGHDR_SIZE 32
struct recvmsg_retvals {
	atomic_t refcnt;
	int call;
	char msg_name[SIMPLE_MSGHDR_SIZE];	//assume <=32
	int msg_namelen;
	char msg_control[SIMPLE_MSGHDR_SIZE];	//assume <=32
	int msg_controllen;
	unsigned int msg_flags;
	int iov_len;
	char iov_base;  			// Variable length buffer follows 
};

struct getsockopt_retvals {
	atomic_t refcnt;
	int call;
	int optlen;
	char optval; // Variable length buffer follows
};

// generic ipc retvals
struct ipc_retvals {
	int call;
};

// semaphore ipc retvals
struct sem_retvals {
	struct ipc_retvals ipc_rv;
};

// retvals for shmat, since we need to save additional information
struct shmat_retvals {
	struct ipc_retvals ipc_rv;
	u_long addr;
	int size;
};

struct set_thread_area_retvals {
	struct user_desc u_info;
};

struct mmap_pgoff_retvals {
	u_long          dev;
	u_long          ino;
	struct timespec mtime; 
};

u_long scount[512];
u_long bytes[512];

/* 
 * epoll_wait_retvals should save whole data structures
 * that are pointed to by the fields in struct epoll_event,
 * for simplicity, assuming union epoll_data is not void*
 * 
 */
struct epoll_wait_retvals {
	atomic_t refcnt;
	// struct epoll_event
	struct epoll_event event;		// Variable length
};

/* grabbed from asm/stat.h - ick - cannot include */
/* for 32bit emulation and 32 bit kernels */
struct __old_kernel_stat {
	unsigned short st_dev;
	unsigned short st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned short st_rdev;
#ifdef __i386__
	unsigned long  xst_size;
  	unsigned long  xst_atime;
  	unsigned long  xst_mtime;
  	unsigned long  xst_ctime;
#else
	unsigned int  st_size;
	unsigned int  st_atime;
	unsigned int  st_mtime;
	unsigned int  st_ctime;
#endif
};

struct wait4_retvals {
	int           stat_addr;
	struct rusage ru;
};

int main (int argc, char* argv[])
{
	struct syscall_result psr;
	struct syscall_result* psrs;
	//struct repsignal sig;
	char sig[172];
	int dfd, fd, rc, size, call, print_recv = 0, dump_recv = 0;
	char buf[65536*16];
	int count, i, rcv_total = 0;
	int stats = 0;
	//int count, i;
	int index = 0;
#ifdef USE_HPC
	// calibration to determine how long a tick is
	unsigned long long hpc1;
	unsigned long long hpc2;
	struct timeval tv1;
	struct timeval tv2;
#endif

	// hack to look at ipc retvals
	int ipc_call = 0;

	if (argc < 2) {
		printf ("format: parselog <filename> [-r] [-f] [-s]\n");
		return -1;
	}
	if (argc == 3 && !strcmp(argv[2], "-r")) print_recv = 1;
	if (argc == 3 && !strcmp(argv[2], "-f")) dump_recv = 1;
	if (argc == 3 && !strcmp(argv[2], "-s")) stats = 1;

	if (stats) {
		memset (scount, 0, sizeof(scount));
		memset (bytes, 0, sizeof(bytes));
	}

	fd = open (argv[1], O_RDONLY);
	if (fd < 0) {
		perror ("open");
		return fd;
	}

	if (dump_recv) {
		dfd = open ("recvdata", O_CREAT | O_TRUNC | O_WRONLY, 0644);;
		if (dfd < 0) {
			perror ("open dumpfile");
			return dfd;
		}
	}

	while (1) {
#ifdef USE_HPC
		rc = read (fd, &hpc1, sizeof(unsigned long long));
		if (rc == 0) { // should have reached the end of the log(s) here
			break;
		}
		rc = read (fd, &tv1, sizeof(struct timeval));
		rc = read (fd, &hpc2, sizeof(unsigned long long));
		rc = read (fd, &tv2, sizeof(struct timeval));
		double usecs1 = (double)tv1.tv_sec * 1000000 + (double)tv1.tv_usec;
		double usecs2 = (double)tv2.tv_sec * 1000000 + (double)tv2.tv_usec;
                printf ("%Lu ticks = %f usecs\n", hpc1, usecs1);
		printf ("%Lu ticks = %f usecs\n", hpc2, usecs2);
#endif


		rc = read (fd, &count, sizeof(count));
		if (rc == 0) { // should have reached the end of the log(s) here
			break;
		}

		if (rc != sizeof(count)) {
			printf ("read returns %d, expected %d, errno = %d\n", rc, sizeof(count), errno);
			return rc;
		}
		
		psrs = malloc (sizeof(struct syscall_result)*count);
		if (!psrs) {
			printf ("Cound not malloc %d bytes\n", sizeof(struct syscall_result)*count);
			return -ENOMEM;
		}
		rc = read (fd, psrs, sizeof(struct syscall_result)*count);
		printf("read of psrs returns %d, count %d\n", rc, count);
		if (rc != sizeof(struct syscall_result)*count) {
			printf ("read of psrs returns %d, expected %d, errno = %d\n", rc, sizeof(struct syscall_result)*count, errno);
			return rc;
		}
		for (i = 0; i < count; i++) {
			psr = psrs[i];
			if (stats) {
				scount[psr.sysnum]++;
				bytes[psr.sysnum] += sizeof(struct syscall_result);
			}
			printf ("%6d: sysnum %3d retval %ld (%lx) begin %lu end %lu", index++, psr.sysnum, psr.retval, psr.retval, psr.start_clock, psr.stop_clock);
#ifdef USE_HPC
			printf (" %Lu", psr.hpc_begin);
			printf (" %Lu ticks ", (psr.hpc_end - psr.hpc_begin));
#endif
			printf ("\n");

                        if (psr.args) {
                                switch (psr.sysnum) {
				// mcc: struct sigaction is defined differently in the kernel and
				// in user-space so we need to hard-code the size to be 40 
				case 174: size = 20 /* sizeof(struct sigaction)*/; break;
				case 175: size = sizeof (struct rt_sigprocmask_args); break;
                                case 192: size = sizeof (struct mmap_pgoff_args); break;
				default: 
					size = 0;
					printf ("write_log_data: unrecognized syscall %d\n", psr.sysnum);
				}
				rc = read (fd, buf, size);
				if (rc != size) {
					printf ("read of args returns %d, errno = %d\n", rc, errno);
					return rc;
				}
				if (stats) {
					bytes[psr.sysnum] += size;
				}
				printf ("\t%d bytes of args included\n", size);
				if (psr.sysnum == 192) {
					struct mmap_pgoff_args *args;
					args = (struct mmap_pgoff_args *) buf;
					printf ("\tmmap_pgoff_args: addr %lx, len %lu, fd %lu, pgoff %lu\n", args->addr, args->len, args->fd, args->pgoff);
				}
                        }
			if (psr.retparams) {
				switch (psr.sysnum) {
				case 3: size = psr.retval; break;
				case 7: size = sizeof(struct waitpid_retvals); break;
				case 11: size = sizeof(struct rvalues); break;
				case 18: size = sizeof(struct __old_kernel_stat); break;
				case 28: size = sizeof(struct __old_kernel_stat); break;
				case 42: size = 2*sizeof(int); break;
				case 43: size = sizeof(struct tms); break;
				case 54: {
					rc = read (fd, &size, sizeof(int));
					if (stats) {
						bytes[psr.sysnum] += sizeof(int);
					}
					if (rc != sizeof(int)) {
						printf ("cannot read ioctl value\n");
						return rc;
					}
					printf("ioctl rc = %d, size = %d\n", rc, size);
					break;
				}
				case 55: size = sizeof(struct flock); break;
				case 77: size = sizeof(struct rusage); break;
				case 78: size = sizeof(struct gettimeofday_retvals); break;
				case 85: size = psr.retval; break;
				case 99: size = sizeof(struct statfs); break;
				case 100: size = sizeof(struct statfs); break;
				case 102: {
					// peel off atomic_t refcnt and int all from retvals structs
					atomic_t atom;
					rc = read (fd, &atom, sizeof(atomic_t));
					if (rc != sizeof(atomic_t)) {
						printf ("cannot read refcnt value\n");
						return rc;
					}
					if (stats) {
						bytes[psr.sysnum] += sizeof(atomic_t);
					}
					rc = read (fd, &call, sizeof(int));
					if (rc != sizeof(int)) {
						printf ("cannot read call value\n");
						return rc;
					}
					if (stats) {
						bytes[psr.sysnum] += sizeof(int);
					}
					printf ("\tsocketcall %d\n", call);
					// socketcall retvals specific
					switch (call) {
					case SYS_ACCEPT: 
					case SYS_GETSOCKNAME:
					case SYS_GETPEERNAME:
					{
						struct accept_retvals avr;
						rc = read (fd, ((char *) &avr) + sizeof(atomic_t) + sizeof(int), 
							   sizeof(struct accept_retvals) - sizeof(atomic_t) - sizeof(int));
						if (rc != sizeof(struct accept_retvals)-sizeof(atomic_t) - sizeof(int)) {
							printf ("cannot read accept value\n");
							return rc;
						}
						if (stats) {
							bytes[psr.sysnum] += sizeof(struct accept_retvals) - sizeof(atomic_t) - sizeof(int);
						}
						size = avr.addrlen; 
						break;
					}	
					case SYS_RECV:
						size = sizeof(struct recvfrom_retvals) -sizeof(atomic_t) - sizeof(int) + psr.retval; 
						break;
					case SYS_RECVFROM:
						size = sizeof(struct recvfrom_retvals) -sizeof(atomic_t) - sizeof(int) + psr.retval-1; 
						break;
					case SYS_RECVMSG:
						size = sizeof(struct recvmsg_retvals) - sizeof(atomic_t) - sizeof(int) + psr.retval-1; 
						break;
					case SYS_SOCKETPAIR:
						size = sizeof(struct socketpair_retvals) - sizeof(atomic_t) - sizeof(int);
						break;
					case SYS_GETSOCKOPT:
					{
						struct getsockopt_retvals sor;
						rc = read (fd, ((char *) &sor) + sizeof(atomic_t) + sizeof(int),
								sizeof(struct getsockopt_retvals) - sizeof(atomic_t) - sizeof(int));
						if (rc != sizeof(struct getsockopt_retvals)-sizeof(atomic_t)-sizeof(int)) {
							printf("cannot read getsockopt value\n");
							return rc;
						}
						if (stats) {
							bytes[psr.sysnum] += sizeof(struct getsockopt_retvals) - sizeof(atomic_t) - sizeof(int);
						}
						break;
					}
					default:
						size = 0; //sizeof(generic_retvals) - sizeof(atomic_t) - sizeof(int) = 0
					}
					break;
				}
				case 104: size = sizeof(struct itimerval); break;
				case 114: size = sizeof(struct wait4_retvals); break;
				case 116: size = sizeof(struct sysinfo); break;
				case 117:
				{
					// peel off ipc_retvals
					struct ipc_retvals ipc_rv;
					rc = read (fd, &ipc_rv, sizeof(struct ipc_retvals));
					if (rc != sizeof(struct ipc_retvals)) {
						printf ("cannot read ipc_retvals\n");
						return rc;
					}
					if (stats) {
						bytes[psr.sysnum] += sizeof(struct ipc_retvals);
					}
					ipc_call = ipc_rv.call;
					//printf ("ipc call is %d\n", ipc_call);
					// ipc call specific retvals
					switch (ipc_rv.call) {
						case SHMAT:
							size = sizeof(struct shmat_retvals) - sizeof(struct ipc_retvals);
							break;
						case SEMCTL:
						case SEMOP:
						case SEMTIMEDOP:
							size = sizeof(struct sem_retvals) - sizeof(struct ipc_retvals);
							break;
						default:
							size = 0;
					}
					//printf ("ipc call size %d\n", size);
					break;
				}
				case 122: size = sizeof(struct new_utsname); break;
				case 126: size = sizeof(unsigned long); break; // old_sigset_t - def in asm/signal.h but cannot include
				case 140: size = sizeof(loff_t); break;
				case 141: size = psr.retval; break;
				case 142: size = sizeof(struct select_retvals); break;
				case 145: size = psr.retval; break;
				case 155: size = sizeof(struct sched_param); break;
				case 162: size = sizeof(struct timespec); break;
				case 168: {
					rc = read (fd, &size, sizeof(int));
					if (rc != sizeof(int)) {
						printf ("cannot read 168 value\n");
						return rc;
					}
					if (stats) {
						bytes[psr.sysnum] += sizeof(int);
					}
					break;
				}
				case 174: size = 20 /* sizeof(struct sigaction)*/; break;
				case 175: 
				{
					size_t sigsetsize;
				        rc = read (fd, &sigsetsize, sizeof(size_t));
					if (rc != sizeof(size_t)) {
						printf ("cannot read 175 value\n");
						return rc;
					}
					if (stats) {
						bytes[psr.sysnum] += sizeof(size_t);
					}
					//printf ("sigsetsize is %d\n", sigsetsize);
					size =  sigsetsize;
					break;
					
				} 
				//case 175: size = *((size_t *)psr.retparams)+sizeof(size_t); printf("175size: %d\n", size); break;
				case 177: {
					size_t val;
					rc = read (fd, &val, sizeof(size_t));
					if (rc != sizeof(size_t)) {
						printf ("cannot read 177 value\n");
						return rc;
					}
					if (stats) {
						bytes[psr.sysnum] += sizeof(size_t);
					}
					size = val;
					break;
				}
				case 180: size = psr.retval; break;
				case 183: size = psr.retval; break;
				case 187: size = sizeof(off_t); break;
				case 191: size = sizeof(struct rlimit); break;
				case 192: size = sizeof(struct mmap_pgoff_retvals); break;
				case 195: size = sizeof(struct stat64); break;
				case 196: size = sizeof(struct stat64); break;
				case 197: size = sizeof(struct stat64); break;
			        case 205: size = (psr.retval > 0) ? sizeof(gid_t)*psr.retval : 0; break;
				case 209: size = (psr.retval >= 0) ? (sizeof(uid_t)*3) : 0; break;
				case 211: size = (psr.retval >= 0) ? sizeof(gid_t)*3 : 0; break;
				case 220: size = psr.retval; break;
				case 221: size = sizeof(struct flock64); break;
				case 229: size = (psr.retval > 0) ? psr.retval : 0; break;
				case 230: size = (psr.retval > 0) ? psr.retval : 0; break;
				case 239: size = sizeof(struct sendfile64_retvals); break;
				case 242: size = sizeof(cpu_set_t); break;
				case 243: size = sizeof(struct set_thread_area_retvals); break;
				case 256: size = sizeof(struct epoll_wait_retvals) + ((psr.retval)-1)*sizeof(struct epoll_event); break;
				case 265: size = sizeof(struct timespec); break;
				case 266: size = sizeof(struct timespec); break;
				//case 268: size = sizeof(struct statfs64); break; 
				case 268: size = 84; break; 
				case 300: size = sizeof(struct stat64); break;
			        case 340: size = sizeof(struct rlimit64); break;
				default: 
					size = 0;
					printf ("write_log_data: unrecognized syscall %d\n", psr.sysnum);
				}

				rc = read (fd, buf, size);
				if (rc != size) {
					printf ("read of retparams returns %d, errno = %d, size is %d\n", rc, errno, size);
					return rc;
				} 
				if (stats) {
					bytes[psr.sysnum] += size;
				}
				printf ("\t%d bytes of return parameters included\n", size);
				//printf ("\t%d syscall number in retparams\n", *(short *) buf);
				
				if (psr.sysnum == 197) {
					struct stat64* pst = (struct stat64 *) buf;
					printf ("stat64 size %Ld blksize %lx blocks %Ld ino %Ld\n", 
						pst->st_size, pst->st_blksize, pst->st_blocks, pst->st_ino);
				}

				if (psr.sysnum == 117) {
					if (ipc_call == SHMAT) {
						//printf ("\tSHMAT addr %lx, size %d\n", *(u_long *) buf, *((int *)(buf + sizeof(u_long))));
					} else if (ipc_call == SEMCTL || ipc_call == SEMOP || ipc_call == SEMTIMEDOP) {
						//printf ("\tstart_clock %d end_clock %d\n", *(int *)buf, *((int *)(buf + sizeof(int))));
					}
				}

				
				if (psr.sysnum == 78) {
					struct gettimeofday_retvals* gttd = (struct gettimeofday_retvals*) buf;
					printf ("gettimeofday has_tv %d, has_tz %d, tv_sec %ld, tv_usec %ld\n", 
							gttd->has_tv, gttd->has_tz, gttd->tv.tv_sec, gttd->tv.tv_usec);
				}

				if (psr.sysnum == 142) {
					struct select_retvals* srtval = (struct select_retvals*) buf;
					printf ("select tv.tv_sec %ld, tv.tv_usec %ld\n", srtval->tv.tv_sec, srtval->tv.tv_usec);
				}

				if (psr.sysnum == 7) {
					printf ("status is %d\n", *(buf));
				}
				
			}

			if (psr.signal) {
				do {
					//rc = read (fd, &sig, sizeof(sig));
					rc = read (fd, &sig, 172);
					if (rc != 172) {
						printf ("read of signal returns %d, errno = %d\n", rc, errno);
						return -1;
					}
					if (stats) {
						bytes[psr.sysnum] += 172;
					}
					//printf ("\tsignal %d info included, next ptr is %p\n", sig.signr, sig.next);
					printf ("\tsignal %d info included, next ptr is %p\n", *(int *)sig, *(char **)(sig+168));
				} while (*(char **)(sig+168));
			}

			if (print_recv && psr.sysnum == 102 && call == SYS_RECV) {
				char* data = buf + sizeof(struct recvfrom_retvals) - sizeof(int)*3;
				int i;
				for (i = 0; i < psr.retval; i++) {
					printf ("%c", data[i]);
				}
				printf ("\n");
			}
			if (dump_recv && psr.sysnum == 102 && call == SYS_RECV && psr.retval > 0) {
				char* data = buf + sizeof(struct recvfrom_retvals) - sizeof(int)*3;
				if (write (dfd, data, psr.retval) != psr.retval) {
					perror ("write dumpfile");
				}
			}
			if (psr.sysnum == 102 && call == SYS_RECV && psr.retval > 0) {
				rcv_total += psr.retval;
				printf ("Received %d bytes total\n", rcv_total);
			}
			if (psr.sysnum == 183) {
				printf ("\tpath has %d bytes\n", size);
				if (size > 0) {
					printf ("\tpath is %s\n", buf);
				}
			}
			if (psr.sysnum == 192) {
				if (psr.retparams) {
					printf ("\tdev is %lx\n", ((struct mmap_pgoff_retvals *)buf)->dev);
					printf ("\tino is %lx\n", ((struct mmap_pgoff_retvals *)buf)->ino);
					printf ("\tmtime is %lx.%lx\n", ((struct mmap_pgoff_retvals *)buf)->mtime.tv_sec, ((struct mmap_pgoff_retvals *)buf)->mtime.tv_nsec);
				}
			}
			
			
			
		}
	}

	if (stats) {
		for (i = 0; i < 512; i++) {
			if (scount[i]) {
				printf ("syscall %3d: count %5lu bytes %8lu\n", i, scount[i], bytes[i]);
			}
		}
	}

	close (fd);
	if (dump_recv) close (dfd);
	return 0;
}
