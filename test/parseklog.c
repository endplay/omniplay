#include <sys/socket.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/timex.h>
#include <sys/quota.h>
#define __USE_LARGEFILE64
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ustat.h>
#include <time.h>
#include <mqueue.h>

#include <linux/net.h>
#include <linux/utsname.h>
#include <linux/ipc.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/statfs.h>
#include <linux/capability.h>
#include <asm/ldt.h>
#define __USE_LARGEFILE64
#include <fcntl.h>
#include <sys/resource.h>

#include "replay_headers/include/linux/replay_configs.h"

#define REPLAY_MAX_THREADS 16
//#define USE_HPC
#define USE_ARGSALLOC
#define USE_DISK_CKPT

//#define PRINT_STATISTICS

#if defined(TRACE_PIPE_READ_WRITE) && !defined(TRACE_READ_WRITE)
#  error "TRACE_PIPE_READ_WRITE without TRACE_READ_WRITE not supporetd"
#endif

#if defined(TRACE_SOCKET_READ_WRITE) && !defined(TRACE_PIPE_READ_WRITE)
#  error "TRACE_SOCKET_READ_WRITE without TRACE_PIPE_READ_WRITE not supporetd"
#endif

#ifdef TRACE_READ_WRITE
struct replayfs_syscache_id {
	loff_t unique_id : 48; 
	loff_t pid : 16; 
	loff_t sysnum : 56; 
	loff_t mod : 8;
} __attribute__((aligned(16)));

struct replayfs_btree_value {
	struct replayfs_syscache_id id;

	size_t buff_offs;
};

struct replayfs_filemap_value {
	struct replayfs_btree_value bval;

	loff_t offset;
	size_t size;
	size_t read_offset;
};

struct replayfs_filemap_entry {
	int num_elms;
	struct replayfs_filemap_value elms[0];
};
#endif

#define CACHE_MASK 1

#ifdef TRACE_PIPE_READ_WRITE
#  define IS_PIPE 2
#  define IS_PIPE_WITH_DATA 4
#endif

struct repsignal {
	int signr;
	siginfo_t info;
	struct /* k_ */ sigaction ka;
	sigset_t blocked;
	sigset_t real_blocked;
	struct repsignal* next;
};

#define SR_HAS_RETPARAMS        0x1 
#define SR_HAS_SIGNAL           0x2
#define SR_HAS_START_CLOCK_SKIP 0x4
#define SR_HAS_STOP_CLOCK_SKIP  0x8
#define SR_HAS_NONZERO_RETVAL   0x10
#define SR_HAS_SPECIAL_FIRST	0x20
#define SR_HAS_SPECIAL_SECOND	0x40

struct syscall_result {
#ifdef USE_HPC
	unsigned long long	hpc_begin;	// Time-stamp counter value when system call started
	unsigned long long	hpc_end;	// Time-stamp counter value when system call finished
#endif
	short			sysnum;		// system call number executed
	u_char			flags;          // See defs above
};

#define REPLAY_MAX_RANDOM_VALUES 10
struct rvalues {
	int cnt;
	long val[REPLAY_MAX_RANDOM_VALUES];
};

struct open_retvals {
	u_long           dev;
	u_long          ino;
	struct timespec mtime;
};

struct gettimeofday_retvals {
	short           has_tv;
	short           has_tz;
	struct timeval  tv;
	struct timezone tz;
};

struct pselect6_retvals {
	char            has_inp;
	char            has_outp;
	char            has_exp;
	char            has_tsp;
	fd_set          inp;
	fd_set          outp;
	fd_set          exp;
	struct timespec tsp;
};

struct generic_socket_retvals {
	int call;
};

struct accept_retvals {
	int call;
	int addrlen;
	char addr; // Variable length buffer follows
};

struct exec_values {
	int uid;
	int euid;
	int gid;
	int egid; 
	int secureexec;
};

struct execve_retvals {
	u_char is_new_group;
	union {
		struct {
			struct rvalues     rvalues;
			struct exec_values evalues;
			u_long             dev;
			u_long             ino;
			struct timespec    mtime;
		} same_group;
		struct {
			__u64           log_id;
		} new_group;
	} data;
};

struct socketpair_retvals {
	int call;
	int sv0;
	int sv1;
};

struct recvfrom_retvals {
	int call;
	struct sockaddr addr;
	int addrlen;
	char buf;  // Variable length buffer follows 
};

struct getxattr_retvals {
	char value; // Variable length buffer follows
};

struct sendfile64_retvals {
	loff_t offset;
};

struct recvmsg_retvals {
	int          call;
	int          msg_namelen;
	long         msg_controllen;
	unsigned int msg_flags;
};
// Followed by msg_namelen bytes of msg_name, msg_controllen bytes of msg_control and rc of data

struct getsockopt_retvals {
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
	int    call;
	u_long size;
	u_long raddr;
};

struct set_thread_area_retvals {
	struct user_desc u_info;
};

struct mmap_pgoff_retvals {
	u_long          dev;
	u_long          ino;
	struct timespec mtime; 
};

struct splice_retvals {
	loff_t off_in;
	loff_t off_out;
};

u_long scount[512];
u_long bytes[512];
u_long clock_bytes[512];
u_long retval_bytes[512];
u_long cut_out [512];

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

struct waitid_retvals {
	struct siginfo info;
	struct rusage  ru;
};

struct get_robust_list_retvals {
	struct robust_list_head * head_ptr;
	size_t                    len;
};

struct file_handle
{
  unsigned int handle_bytes;
  int handle_type;
  /* File identifier.  */
  unsigned char f_handle[0];
};

struct name_to_handle_at_retvals {
	struct file_handle handle;
	int                mnt_id;
};

//#define MORE_CONVERT
int convert = 0;
inline void copy_to_convert_buffer (char* convert_buffer, int *offset, void* src, ssize_t size) {
	memcpy (convert_buffer + *offset, src, size);
	*offset += size;
}

static u_long varsize (int fd, int stats, struct syscall_result* psr, char* convert_buffer, int *offset)
{
	u_long val;
	if (read (fd, &val, sizeof(u_long)) != sizeof(u_long)) {
		printf ("cannot read variable length field\n");
		return -1;
	}
	if (convert) {
		if (convert_buffer) copy_to_convert_buffer (convert_buffer, offset, &val, sizeof (u_long));
	}
	printf ("\t4 bytes of variable length field header included\n");
	if (stats) {
		bytes[psr->sysnum] += sizeof(u_long);
	}
	printf ("\t%lu variable bytes\n", val);
	return val;
}

int main (int argc, char* argv[])
{
	struct syscall_result psr;
	struct syscall_result* psrs;
	char sig[172];
	int dfd, fd, rc, size, call, print_recv = 0, dump_recv = 0;
	int convert_fd, x_fd = 0, connection_times = 0;
	char buf[65536*16];
	int count, i, ndx, rcv_total = 0;
	int stats = 0;
	int index = 0;
	int graph_only = 0;
	int pipe_write_only = 0;
	u_long data_size, start_clock, stop_clock, clock, expected_clock = 0;
	long retval;
	int extra_bytes = 0;
	u_int is_cache_read;
#ifdef USE_HPC
	// calibration to determine how long a tick is
	unsigned long long hpc1;
	unsigned long long hpc2;
	struct timeval tv1;
	struct timeval tv2;
#endif

	/* FIXME: Hacky... really hacky... I'll fix this later */
#define printf(...) if (!graph_only && !pipe_write_only) printf(__VA_ARGS__);
#define always_print(...) \
	do { \
		int graph_only_tmp = graph_only; \
		int pipe_write_only_tmp = pipe_write_only; \
		pipe_write_only = 0; graph_only = 0; \
		\
		printf(__VA_ARGS__); \
		\
		graph_only = graph_only_tmp; \
		pipe_write_only = pipe_write_only_tmp;\
	} while (0);

	// hack to look at ipc retvals
	int ipc_call = 0;

	if (argc < 2) {
		printf ("format: parselog <filename> [-r] [-f] [-s] [-c]\n");
		return -1;
	}
	if (argc == 3 && !strcmp(argv[2], "-r")) print_recv = 1;
	if (argc == 3 && !strcmp(argv[2], "-f")) dump_recv = 1;
	if (argc == 3 && !strcmp(argv[2], "-s")) stats = 1;
	if (argc == 3 && !strcmp(argv[2], "-g")) graph_only = 1;
	if (argc == 3 && !strcmp(argv[2], "-p")) pipe_write_only = 1;
	if (argc == 4 && !strcmp(argv[2], "-c")) convert = 1;

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

	if (convert) {
		char convert_filename[1024];
		memset (convert_filename, 0, 1024);
		sprintf (convert_filename, "%s.convert", argv[1]);
		convert_fd = open (convert_filename, O_RDWR | O_TRUNC | O_CREAT, 0644);
	}
	char* x_buffer = NULL;
	int x_buffer_length = 0;
	int x_buffer_size = 4096;
	int x_first_time = 1;
	int x_request_pos = 0;
	if (convert) {
		x_buffer = malloc (x_buffer_size);
	}


	while (1) {
		int xbytes_count = 0;
		char* convert_buffer = NULL;
		int convert_offset = 0;

#ifdef USE_HPC
		rc = read (fd, &hpc1, sizeof(unsigned long long));
		if (rc == 0) { // should have reached the end of the log(s) here
			break;
		}
		rc = read (fd, &tv1, sizeof(struct timeval));
		rc = read (fd, &hpc2, sizeof(unsigned long long));
		rc = read (fd, &tv2, sizeof(struct timeval));
		if (convert) {
			rc = write (convert_fd, (char*) &hpc1, sizeof (unsigned long long));
			rc = write (convert_fd, (char*) &tv1, sizeof(struct timeval));
			rc = write (convert_fd, (char*) &hpc2, sizeof(unsigned long long));
			rc = write (convert_fd, (char*) &tv2, sizeof(struct timeval));
		}
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
		if (convert) {
			rc = write (convert_fd, (char*) &count, sizeof (count));
			if (rc != sizeof (count)) {
				printf ("write returns %d, expected %d, errno = %d\n", rc, sizeof(count), errno);
				return rc;
			}
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
		if (convert) {
			rc = write (convert_fd, (char*)psrs, sizeof (struct syscall_result)*count);
			if (rc != sizeof (struct syscall_result)*count) {
				printf ("write returns %d, expected %d, errno = %d\n", rc, sizeof(struct syscall_result)*count, errno);
				return rc;
			}
		}
		rc = read (fd, &data_size, sizeof(data_size));
		if (rc != sizeof(data_size)) {
			printf ("read returns %d, expected %d, errno = %d\n", rc, sizeof(data_size), errno);
			return rc;
		}
		if (convert) {
			//alloc the write buffer now
			convert_buffer = malloc (sizeof (data_size) + data_size);
			copy_to_convert_buffer (convert_buffer, &convert_offset, &data_size, sizeof (data_size));

		}
		for (ndx = 0; ndx < count; ndx++) {
			psr = psrs[ndx];
			if (stats) {
				scount[psr.sysnum]++;
				bytes[psr.sysnum] += sizeof(struct syscall_result);
			}

			start_clock = expected_clock;
			if ((psr.flags & SR_HAS_START_CLOCK_SKIP) != 0) {
				rc = read (fd, &clock, sizeof(u_long));
				if (rc != sizeof(u_long)) {
					printf ("cannot read start clock value\n");
					return rc;
				}
				start_clock += clock;
				bytes[psr.sysnum] += sizeof(u_long);
				clock_bytes[psr.sysnum] += sizeof(u_long);
#ifdef MORE_CONVERT
				//don't copy
				cut_out[1] += sizeof(u_long);
#else
				if (convert) {
					copy_to_convert_buffer (convert_buffer, &convert_offset, (char*) &clock, sizeof (u_long));
				}
#endif
			}
			expected_clock = start_clock+1;

			if ((psr.flags & SR_HAS_NONZERO_RETVAL) == 0) {
				retval = 0;
			} else {
				rc = read (fd, &retval, sizeof(long));
				if (rc != sizeof(long)) {
					printf ("cannot read return value\n");
					return rc;
				}
				bytes[psr.sysnum] += sizeof (long);
				retval_bytes[psr.sysnum] += sizeof (long);
#ifdef MORE_CONVERT
				cut_out[2] += sizeof(long);
#else
				if (convert) {
					copy_to_convert_buffer (convert_buffer, &convert_offset, (char*) &retval, sizeof (long));
				}
#endif
			}

			stop_clock = expected_clock;
			if ((psr.flags & SR_HAS_STOP_CLOCK_SKIP) != 0) {
				rc = read (fd, &clock, sizeof(u_long));
				if (rc != sizeof(u_long)) {
					printf ("cannot read stop clock value\n");
					return rc;
				}
				stop_clock += clock;
				bytes[psr.sysnum] += sizeof(u_long);
				clock_bytes[psr.sysnum] += sizeof (u_long);
#ifdef MORE_CONVERT
				cut_out[3] +=sizeof (u_long);
#else
				if (convert) {
					copy_to_convert_buffer (convert_buffer, &convert_offset, (char*) &clock, sizeof (clock));
				}
#endif
			}
			expected_clock = stop_clock+1;

			printf ("%6d: sysnum %3d flags %x retval %ld (%lx) begin %lu end %lu", index, psr.sysnum, psr.flags, retval, retval, start_clock, stop_clock);
#ifdef USE_HPC
			printf (" %Lu", psr.hpc_begin);
			printf (" %Lu ticks ", (psr.hpc_end - psr.hpc_begin));
#endif
			printf ("\n");

			if (psr.flags & SR_HAS_SPECIAL_SECOND && psr.sysnum == 146) {
				if (x_first_time) {
					x_first_time = 0;
					x_request_pos = 0;
				} else {
					if (x_fd > 0) {
						rc = write (x_fd, (char*) &x_request_pos, sizeof (x_request_pos));
						if (rc != sizeof (x_request_pos)) {
							printf ("cannot write out x_request_pos\n");
						}	
						rc = write (x_fd, (char*) &x_buffer_length, sizeof (x_buffer_length));
						if (rc != sizeof (x_buffer_length)) {
							printf ("cannot write out x_buffer_length\n");
						}						
						rc = write (x_fd, x_buffer, x_buffer_length);
						if (rc != x_buffer_length) 
							printf ("cannot write out x_buffer\n");
						printf ("write out %d bytes x messages, pos:%d\n", x_buffer_length, x_request_pos);
						x_buffer_length = 0;
					}
				}
				x_request_pos += retval;
			}
			

			if ((psr.flags & SR_HAS_RETPARAMS) != 0) {
				long loc;
				switch (psr.sysnum) {
				case 3: {
					rc = read (fd, &is_cache_read, sizeof(u_int));
					if (rc != sizeof(u_int)) {
						printf ("cannot read is_cache value\n");
						return rc;
					}
					if (convert) {
						copy_to_convert_buffer (convert_buffer, &convert_offset, (char*) &is_cache_read, sizeof (u_int));
					}

					printf ("\tis_cache_file: %d\n", is_cache_read);
					if (is_cache_read & CACHE_MASK) {

						size = sizeof (loff_t);

#ifdef TRACE_READ_WRITE
						do {
							off_t orig_pos;
							struct replayfs_filemap_entry entry;
							loff_t bleh;

							orig_pos = lseek(fd, 0, SEEK_CUR);
							rc = read(fd, &bleh, sizeof(loff_t));
							rc = read(fd, &entry, sizeof(struct replayfs_filemap_entry));
							lseek(fd, orig_pos, SEEK_SET);

							if (rc != sizeof(struct replayfs_filemap_entry)) {
								printf ("cannot read entry\n");
								return rc;
							}

							extra_bytes += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
							size += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
						} while (0);
#endif
#ifdef TRACE_PIPE_READ_WRITE
					} else if (is_cache_read & IS_PIPE) {
						if (is_cache_read & IS_PIPE_WITH_DATA) {
							off_t orig_pos;
							struct replayfs_filemap_entry entry;

							orig_pos = lseek(fd, 0, SEEK_CUR);
							rc = read(fd, &entry, sizeof(struct replayfs_filemap_entry));
							lseek(fd, orig_pos, SEEK_SET);

							if (rc != sizeof(struct replayfs_filemap_entry)) {
								printf ("cannot read entry\n");
								return rc;
							}

							size = sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
						} else {
							size = sizeof(uint64_t) + sizeof(int);
						}

						size += retval;
#endif
					} else {
						size = retval; 
					}
					break;
				}
#ifdef TRACE_PIPE_READ_WRITE
				case 4: size = sizeof(int); break;
#endif
				case 5: size = sizeof(struct open_retvals); break;
				case 7: size = sizeof(int); break;
				case 11: size = sizeof(struct execve_retvals); break;
				case 13: size = sizeof(time_t); break;
				case 18: size = sizeof(struct __old_kernel_stat); break;
				case 28: size = sizeof(struct __old_kernel_stat); break;
				case 42: size = 2*sizeof(int); break;
				case 43: size = sizeof(struct tms); break;
				case 54: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 55: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 59: size = sizeof(struct oldold_utsname); break;
				case 62: size = sizeof(struct ustat); break;
				case 67: size = sizeof(struct sigaction); break;
				case 73: size = sizeof(sigset_t); break;
				case 76: size = sizeof(struct rlimit); break;
				case 77: size = sizeof(struct rusage); break;
				case 78: size = sizeof(struct gettimeofday_retvals); break;
				case 80: size = sizeof(u_short)*retval; break;
				case 84: size = sizeof(struct __old_kernel_stat); break;
				case 85: size = retval; break;
				case 86: size = sizeof(struct mmap_pgoff_retvals); break;
				case 89: size = 266; break; /* sizeof old_linux_dirent??? */
				case 99: size = sizeof(struct statfs); break;
				case 100: size = sizeof(struct statfs); break;
				case 102: {
					rc = read (fd, &call, sizeof(int));
					if (rc != sizeof(int)) {
						printf ("cannot read call value\n");
						return rc;
					}
					if (convert) {
#ifdef MORE_CONVERT
						//do nothing
#else
						copy_to_convert_buffer (convert_buffer, &convert_offset, (char*) &call, sizeof (int));
#endif
					}
					if (stats) {
						bytes[psr.sysnum] += sizeof(int);
					}
					printf ("\tsocketcall %d\n", call);
					// socketcall retvals specific
					switch (call) {
#ifdef TRACE_SOCKET_READ_WRITE
					case SYS_SEND:
					case SYS_SENDTO:
						{
							if (retval >= 0) {
								u_int shared;

								shared = 0;
								rc = read(fd, &shared, sizeof(u_int));
								if (rc != sizeof(shared)) {
									printf("%d: read %d\n", __LINE__, rc);
									return EXIT_FAILURE;
								}

								printf("\tRead shared variable of %d\n", shared);

								if (shared & IS_PIPE_WITH_DATA) {
								} else if (shared & IS_PIPE) {
									int pipe_id;

									rc = read(fd, &pipe_id, sizeof(int));
									if (rc != sizeof(pipe_id)) {
										printf("%d: read: %d\n", __LINE__, rc);
										return EXIT_FAILURE;
									}

									if (!pipe_write_only) {
										printf("\tWrite is part of pipe: %d\n", pipe_id);
									} else {
										always_print("%d, %ld, %lu, %d\n", pipe_id, retval,
												start_clock, ndx);
									}
								}
							}
							size = 0;
							break;
						}
#endif
					case SYS_ACCEPT: 
					case SYS_ACCEPT4:
					case SYS_GETSOCKNAME:
					case SYS_GETPEERNAME: {
						struct accept_retvals avr;
						rc = read (fd, ((char *) &avr) + sizeof(int), 
							   sizeof(struct accept_retvals) - sizeof(int));
						if (rc != sizeof(struct accept_retvals) - sizeof(int)) {
							printf ("cannot read accept value\n");
							return rc;
						}
						if (convert) {
							copy_to_convert_buffer (convert_buffer, &convert_offset, ((char *) &avr) + sizeof(int), sizeof(struct accept_retvals) - sizeof(int));
						}
						if (stats) {
							bytes[psr.sysnum] += sizeof(struct accept_retvals) - sizeof(int);
						}
						size = avr.addrlen; 
						break;
					}	
					case SYS_RECV:
						size = sizeof(struct recvfrom_retvals) - sizeof(int) + retval; 
#ifdef TRACE_SOCKET_READ_WRITE
						if (retval >= 0) {
							u_int is_cached;
							off_t orig_pos;
							orig_pos = lseek(fd, 0, SEEK_CUR);
							rc = lseek(fd, size, SEEK_CUR);
							if (rc == (off_t)-1) {
								printf("%d: lseek: %d\n", __LINE__, rc);
								return rc;
							}
							rc = read(fd, &is_cached, sizeof(u_int));
							if (rc != sizeof(is_cached)) {
								printf("%d: Couldn't read is_cached\n", __LINE__);
								return rc;
							}

							printf("\tSocket is_cached is %d\n", is_cached);

							if (is_cached & IS_PIPE_WITH_DATA) {
								off_t orig_pos2;
								int entry_size;
								struct replayfs_filemap_entry entry;
								struct replayfs_filemap_entry *real_entry;

								orig_pos2 = lseek(fd, 0, SEEK_CUR);
								rc = read(fd, &entry, sizeof(struct replayfs_filemap_entry));

								if (rc != sizeof(struct replayfs_filemap_entry)) {
									printf ("cannot read entry\n");
									return rc;
								}
								lseek(fd, orig_pos2, SEEK_SET);

								entry_size = sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
								size += entry_size;
								real_entry = malloc(entry_size);
								if (real_entry == NULL) {
									printf("Cannot alloc real_entry\n");
									return EXIT_FAILURE;
								}

								rc = read(fd, real_entry, entry_size);
								if (!graph_only) {
									printf ("\tPiped writes sourcing this read: %d\n",
											real_entry->num_elms);

									for (i = 0; i < real_entry->num_elms; i++) {
										printf ("\t\tSource %d is {id, pid, syscall_num} {%lld %d %lld}\n", i,
												(loff_t)real_entry->elms[i].bval.id.unique_id, real_entry->elms[i].bval.id.pid,
												(loff_t)real_entry->elms[i].bval.id.sysnum);
									}
								} else {
									for (i = 0; i < real_entry->num_elms; i++) {
										always_print ("pipe: %d %d %d {%lld, %d, %lld, %d, %ld}\n",
												ndx, real_entry->elms[i].bval.buff_offs, real_entry->elms[i].size,
												(loff_t)real_entry->elms[i].bval.id.unique_id, real_entry->elms[i].bval.id.pid,
												(loff_t)real_entry->elms[i].bval.id.sysnum,
												real_entry->elms[i].read_offset, retval);
									}
								}
							} else if (is_cached & IS_PIPE) {
								/* Just a simple one-to-one data entry */
								uint64_t writer;
								int pipe_id;
								rc = read(fd, &writer, sizeof(uint64_t));
								if (rc != sizeof(writer)) {
									printf("%d: read: %d\n", __LINE__, rc);
									return rc;
								}
								rc = read(fd, &pipe_id, sizeof(int));
								if (rc != sizeof(pipe_id)) {
									printf("%d: read: %d\n", __LINE__, rc);
									return rc;
								}

								if (!graph_only) {
									printf("\tUnix socket is a pipe sourced by id %llu, %d\n",
											writer, pipe_id);
								} else {
									uint64_t id = writer;
									always_print("pipe: %lld, %d, %d {%ld} {%lu}\n", id, pipe_id,
											ndx, retval, start_clock);
								}

								size += sizeof(is_cached) + sizeof(writer) + sizeof(pipe_id);
							} else {
								size += sizeof(is_cached);
							}

							lseek(fd, orig_pos, SEEK_SET);
						}
#endif
						break;
					case SYS_RECVFROM:
						size = sizeof(struct recvfrom_retvals) - sizeof(int) + retval-1; 
#ifdef TRACE_SOCKET_READ_WRITE
						if (retval >= 0) {
							u_int is_cached;
							off_t orig_pos;
							orig_pos = lseek(fd, 0, SEEK_CUR);
							rc = lseek(fd, size, SEEK_CUR);
							if (rc == (off_t)-1) {
								printf("%d: lseek: %d\n", __LINE__, rc);
								return rc;
							}
							rc = read(fd, &is_cached, sizeof(u_int));
							if (rc != sizeof(is_cached)) {
								printf("%d: Couldn't read is_cached\n", __LINE__);
								return rc;
							}

							printf("\tSocket is_cached is %d\n", is_cached);

							if (is_cached & IS_PIPE_WITH_DATA) {
								off_t orig_pos2;
								int entry_size;
								struct replayfs_filemap_entry entry;
								struct replayfs_filemap_entry *real_entry;

								orig_pos2 = lseek(fd, 0, SEEK_CUR);
								rc = read(fd, &entry, sizeof(struct replayfs_filemap_entry));

								if (rc != sizeof(struct replayfs_filemap_entry)) {
									printf ("cannot read entry\n");
									return rc;
								}
								lseek(fd, orig_pos2, SEEK_SET);

								entry_size = sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
								size += entry_size;
								real_entry = malloc(entry_size);
								if (real_entry == NULL) {
									printf("Cannot alloc real_entry\n");
									return EXIT_FAILURE;
								}

								rc = read(fd, real_entry, entry_size);
								if (!graph_only) {
									printf ("\tPiped writes sourcing this read: %d\n",
											real_entry->num_elms);

									for (i = 0; i < real_entry->num_elms; i++) {
										printf ("\t\tSource %d is {id, pid, syscall_num} {%lld %d %lld}\n", i,
												(loff_t)real_entry->elms[i].bval.id.unique_id, real_entry->elms[i].bval.id.pid,
												(loff_t)real_entry->elms[i].bval.id.sysnum);
									}
								} else {
									for (i = 0; i < real_entry->num_elms; i++) {
										always_print ("pipe: %d %d %d {%lld, %d, %lld, %d, %ld}\n",
												ndx, real_entry->elms[i].bval.buff_offs, real_entry->elms[i].size,
												(loff_t)real_entry->elms[i].bval.id.unique_id, real_entry->elms[i].bval.id.pid,
												(loff_t)real_entry->elms[i].bval.id.sysnum,
												real_entry->elms[i].read_offset, retval);
									}
								}
							} else if (is_cached & IS_PIPE) {
								/* Just a simple one-to-one data entry */
								uint64_t writer;
								int pipe_id;
								rc = read(fd, &writer, sizeof(uint64_t));
								if (rc != sizeof(writer)) {
									printf("%d: read: %d\n", __LINE__, rc);
									return rc;
								}
								rc = read(fd, &pipe_id, sizeof(int));
								if (rc != sizeof(pipe_id)) {
									printf("%d: read: %d\n", __LINE__, rc);
									return rc;
								}

								if (!graph_only) {
									printf("\tUnix socket is a pipe sourced by id %llu, %d\n",
											writer, pipe_id);
								} else {
									uint64_t id = writer;
									always_print("pipe: %lld, %d, %d {%ld} {%lu}\n", id, pipe_id,
											ndx, retval, start_clock);
								}

								size += sizeof(is_cached) + sizeof(writer) + sizeof(pipe_id);
							} else {
								/* Add sizeof is_cached... */
								size += sizeof(u_int);
							}

							lseek(fd, orig_pos, SEEK_SET);
						}
#endif
						break;
					case SYS_RECVMSG: {
						struct recvmsg_retvals msg;
						rc = read(fd, ((char *)&msg) + sizeof(int), sizeof(struct recvmsg_retvals) - sizeof(int));
						if (rc != sizeof(struct recvmsg_retvals) - sizeof(int)) {
							printf ("cannot read recvfrom values\n");
							return rc;
						}
						if (convert) {
							copy_to_convert_buffer (convert_buffer, &convert_offset, ((char *)&msg) + sizeof(int), sizeof(struct recvmsg_retvals) - sizeof(int));
						}
						printf ("\trecvmsg: msgnamelen %d msg_controllen %ld msg_flags %x\n", msg.msg_namelen, msg.msg_controllen, msg.msg_flags);
						if (stats) {
							bytes[psr.sysnum] += sizeof(struct recvfrom_retvals) - sizeof(int);
						}
						size = msg.msg_namelen + msg.msg_controllen + retval; 
						break;
					}
					case SYS_RECVMMSG: {
						if (retval > 0) {
							long len;
							rc = read(fd, ((char *)&len), sizeof(long));
							if (rc != sizeof(long)) {
								printf ("cannot read recvmmsg value\n");
								return rc;
							}
							if (convert) {
								copy_to_convert_buffer (convert_buffer, &convert_offset, (char*) &len, sizeof (long));
							}
							if (stats) bytes[psr.sysnum] += sizeof(long);
							size = len;
						} else {
							size = 0;
						}
						break;
					}
					case SYS_SOCKETPAIR:
						size = sizeof(struct socketpair_retvals) - sizeof(int);
						break;
					case SYS_GETSOCKOPT: {
						struct getsockopt_retvals sor;
						rc = read (fd, ((char *) &sor) + sizeof(int),
								sizeof(struct getsockopt_retvals) - sizeof(int));
						if (rc != sizeof(struct getsockopt_retvals)-sizeof(int)) {
							printf("cannot read getsockopt value\n");
							return rc;
						}
						if (convert) {
							copy_to_convert_buffer (convert_buffer, &convert_offset, ((char *) &sor) + sizeof(int), sizeof(struct getsockopt_retvals) - sizeof(int));
						}
						if (stats) {
							bytes[psr.sysnum] += sizeof(struct getsockopt_retvals) - sizeof(int);
						}
						size = sor.optlen;
						//size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size;
						break;
					}
					case SYS_CONNECT: {
						size = 0;
						if (convert && (psr.flags & SR_HAS_SPECIAL_FIRST)) {
							char x_filename[1024];
							memset (x_filename, 0, 1024);
							++ connection_times;
							sprintf (x_filename, "./%s.x.%d", argv[3], connection_times);
							if (x_fd > 0) {
								//write out the remaining x buffer
								if (x_first_time) {
									x_first_time = 0;
									x_request_pos = 0;
								} else {
									if (x_fd > 0) {
										rc = write (x_fd, (char*) &x_request_pos, sizeof (x_request_pos));
										if (rc != sizeof (x_request_pos)) {
											printf ("cannot write out x_request_pos\n");
										}	
										rc = write (x_fd, (char*) &x_buffer_length, sizeof (x_buffer_length));
										if (rc != sizeof (x_buffer_length)) {
											printf ("cannot write out x_buffer_length\n");
										}						
										rc = write (x_fd, x_buffer, x_buffer_length);
										if (rc != x_buffer_length) 
											printf ("cannot write out x_buffer\n");
										printf ("write out %d bytes x messages, pos:%d\n", x_buffer_length, x_request_pos);
										x_buffer_length = 0;
									}
								}
								x_request_pos += retval;
								close (x_fd);
							}
							x_fd = open (x_filename, O_RDWR | O_TRUNC | O_CREAT, 0644);
							x_first_time = 1;
						}
						break;
					}

					default:
						size = 0; 
					}
					break;
				}
				case 103: size = retval; break;
				case 104: size = sizeof(struct itimerval); break;
				case 105: size = sizeof(struct itimerval); break;
				case 106: size = sizeof(struct stat); break;
				case 107: size = sizeof(struct stat); break;
				case 108: size = sizeof(struct stat); break;
				case 109: size = sizeof(struct old_utsname); break;
				case 114: size = sizeof(struct wait4_retvals); break;
				case 116: size = sizeof(struct sysinfo); break;
				case 117: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 122: size = sizeof(struct new_utsname); break;
				case 124: size = sizeof(struct timex); break;
				case 126: size = sizeof(unsigned long); break; // old_sigset_t - def in asm/signal.h but cannot include
				case 131: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset);  if (size < 0) return size; break;
				case 134: size = sizeof(long); break;
				case 135: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 140: size = sizeof(loff_t); break;
				case 141: size = retval; break;
				case 142: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 145: size = retval; break;
#ifdef TRACE_PIPE_READ_WRITE
				case 146: size = sizeof(u_int); break;
#endif
				case 149: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 155: size = sizeof(struct sched_param); break;
				case 161: size = sizeof(struct timespec); break;
				case 162: size = sizeof(struct timespec); break;
				case 165: size = sizeof(u_short)*3; break;
#ifdef MORE_CONVERT
				case 168: cut_out[168] += sizeof(long); size = varsize(fd, stats, &psr, NULL, &convert_offset); if (size < 0) return size; break;
#else
				case 168: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
#endif
				case 171: size = sizeof(u_short)*3; break;
				case 172: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 174: size = 20 /* sizeof(struct sigaction)*/; break;
				case 175: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 176: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 177: size = sizeof(siginfo_t); break;
				case 180: {
						  rc = read (fd, &is_cache_read, sizeof(u_int));
						  if (rc != sizeof(u_int)) {
							  printf ("cannot read is_cache value\n");
							  return rc;
						  }
						  if (convert) {
							  copy_to_convert_buffer (convert_buffer, &convert_offset, (char*) &is_cache_read, sizeof (u_int));
						  }

						  printf ("\tis_cache_file: %d\n", is_cache_read);
						  if (is_cache_read & CACHE_MASK) {

							  size = sizeof (loff_t);

#ifdef TRACE_READ_WRITE
							  do {
								  off_t orig_pos;
								  struct replayfs_filemap_entry entry;
								  loff_t bleh;

								  orig_pos = lseek(fd, 0, SEEK_CUR);
								  rc = read(fd, &bleh, sizeof(loff_t));
								  rc = read(fd, &entry, sizeof(struct replayfs_filemap_entry));
								  lseek(fd, orig_pos, SEEK_SET);

								  if (rc != sizeof(struct replayfs_filemap_entry)) {
									  printf ("cannot read entry\n");
									  return rc;
								  }

								  extra_bytes += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
								  size += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
							  } while (0);
#endif
#ifdef TRACE_PIPE_READ_WRITE
						  } else if (is_cache_read & IS_PIPE) {
							  if (is_cache_read & IS_PIPE_WITH_DATA) {
								  off_t orig_pos;
								  struct replayfs_filemap_entry entry;

								  orig_pos = lseek(fd, 0, SEEK_CUR);
								  rc = read(fd, &entry, sizeof(struct replayfs_filemap_entry));
								  lseek(fd, orig_pos, SEEK_SET);

								  if (rc != sizeof(struct replayfs_filemap_entry)) {
									  printf ("cannot read entry\n");
									  return rc;
								  }

								  size = sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
							  } else {
								  size = sizeof(uint64_t) + sizeof(int);
							  }

							  size += retval;
#endif
						  } else {
							  size = retval; 
						  }
						  break;
					  }
				case 183: size = retval; break;
				case 184: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 185: size = sizeof(struct __user_cap_header_struct); break;
				case 187: size = sizeof(off_t); break;
				case 191: size = sizeof(struct rlimit); break;
				case 192: size = sizeof(struct mmap_pgoff_retvals); break;
				case 195: size = sizeof(struct stat64); break;
				case 196: size = sizeof(struct stat64); break;
				case 197: size = sizeof(struct stat64); break;
				case 205: size = sizeof(gid_t)*retval; break;
				case 209: size = sizeof(uid_t)*3; break;
				case 211: size = sizeof(gid_t)*3; break;
				case 218: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 220: size = retval; break;
				case 221: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 229: size = retval; break;
				case 230: size = retval; break;
				case 231: size = retval; break;
				case 232: size = retval; break;
				case 233: size = retval; break;
				case 234: size = retval; break;
				case 239: size = sizeof(struct sendfile64_retvals); break;
				case 242: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 245: size = sizeof(u_long); break;
				case 247: size = retval*32; break; /* struct ioevents */
				case 249: size = 32; break; /* struct ioevent */
				case 253: size = retval; break;
				case 256: size = retval*sizeof(struct epoll_event); break;
				case 259: size = sizeof(timer_t); break;
				case 260: size = sizeof(struct itimerspec); break;
				case 261: size = sizeof(struct itimerspec); break;
				case 265: size = sizeof(struct timespec); break;
				case 266: size = sizeof(struct timespec); break;
				case 267: size = sizeof(struct timespec); break;
				case 268: size = 84; break; /* statfs 64 */
				case 269: size = 84; break; /* statfs 64 */
				case 275: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 280: size = retval; break;
				case 282: size = sizeof(struct mq_attr); break;
				case 284: size = sizeof(struct waitid_retvals); break;
				case 288: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 300: size = sizeof(struct stat64); break;
				case 305: size = retval; break;
				case 308: size = sizeof(struct pselect6_retvals); break;
				case 309: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 312: size = sizeof(struct get_robust_list_retvals); break;
				case 313: size = sizeof(struct splice_retvals); break;
				case 317: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 318: size = sizeof(unsigned)*2; break;
				case 319: size = retval*sizeof(struct epoll_event); break;
				case 325: size = sizeof(struct itimerspec); break;
				case 326: size = sizeof(struct itimerspec); break;
				case 331: size = 2*sizeof(int); break;
				case 333: size = retval; break;
				case 337: size = varsize(fd, stats, &psr, convert_buffer, &convert_offset); if (size < 0) return size; break;
				case 340: size = sizeof(struct rlimit64); break;
				case 341: size = sizeof(struct name_to_handle_at_retvals); break;
				case 343: size = sizeof(struct timex); break;
				default: 
						  size = 0;
						  printf ("write_log_data: unrecognized syscall %d\n", psr.sysnum);
				}

				loc = lseek(fd, 0, SEEK_CUR);
				rc = read (fd, buf, size);
				if (rc != size) {
					printf ("read of retparams returns %d, errno = %d, size is %d\n", rc, errno, size);
					return rc;
				} 
				if (convert) {
					int xsize = 0;


					if (psr.flags & SR_HAS_SPECIAL_SECOND && (psr.sysnum==3 || psr.sysnum==102 || psr.sysnum==145)) {
						int offset;
						switch (psr.sysnum) {
							case 3:
							case 145:
								xsize = size;
								offset = 0;
								break;
							case 102:
								if (call == SYS_RECV) {
									offset = sizeof(struct recvfrom_retvals) - sizeof(int) - 4;
									xsize = retval;
								} else if (call == SYS_RECVMSG) {
									offset = size - retval - 4;
									xsize = retval;
								}
								break;
						}
						printf ("Reply from x, size:%d, %d, %d, %ld\n", xsize, offset, size, retval);
						xbytes_count += xsize;
						//x_compress (buf + offset , xsize);
						//copy x messages to x_buffer
						while (x_buffer_length + xsize > x_buffer_size) {
							char* tmp_buffer = malloc (x_buffer_size * 2);
							memcpy (tmp_buffer, x_buffer, x_buffer_length);
							free (x_buffer);
							x_buffer_size *= 2;
							x_buffer = tmp_buffer;
						}
						memcpy (x_buffer + x_buffer_length, buf + offset, xsize);
						x_buffer_length += xsize;
					}
#ifdef MORE_CONVERT
					if ((psr.sysnum == 102 && call == SYS_RECV && psr.flags & SR_HAS_SPECIAL_SECOND) || psr.sysnum == 168 || psr.sysnum == 78 || psr.sysnum == 265) {
						//don't copy	
						cut_out[psr.sysnum] += size - xsize;
					} else
#endif
						copy_to_convert_buffer (convert_buffer, &convert_offset, (char*) &buf, size - xsize);
				}
				if (stats) {
					bytes[psr.sysnum] += size;
				}
				printf ("\t%d bytes of return parameters included (from loc %ld)\n",
						size, loc);
				//printf ("\t%d syscall number in retparams\n", *(short *) buf);

				if (psr.sysnum == 5) {
					if ((psr.flags & SR_HAS_RETPARAMS) != 0) {
						struct open_retvals *oret = (struct open_retvals *)buf;

						/* dev, ino, mtime */
						printf("\tOpen dev is %lX, ino %lX\n", oret->dev, oret->ino);
					}
				}
				
				if (psr.sysnum == 11) {
					if ((psr.flags & SR_HAS_RETPARAMS) != 0) {
						struct execve_retvals* per = (struct execve_retvals *) buf;
						if (per->is_new_group) {
							printf ("\tnew group id: %lld\n", per->data.new_group.log_id);
						} else {
							printf ("\tnumber of random values is %d\n", per->data.same_group.rvalues.cnt);
							for (i = 0; i < per->data.same_group.rvalues.cnt; i++) {
								printf ("\t\trandom values %d is %lx\n", i, per->data.same_group.rvalues.val[i]);
							}
							printf ("\tdev is %lx\n", per->data.same_group.dev);
							printf ("\tino is %lx\n", per->data.same_group.ino);
							printf ("\tmtime is %lx.%lx\n", per->data.same_group.mtime.tv_sec, per->data.same_group.mtime.tv_nsec);
							printf ("\tuid is %d\n", per->data.same_group.evalues.uid);
							printf ("\teuid is %d\n", per->data.same_group.evalues.euid);
							printf ("\tgid is %d\n", per->data.same_group.evalues.gid);
							printf ("\tegid is %d\n", per->data.same_group.evalues.egid);
							printf ("\tAT_SECURE is %d\n", per->data.same_group.evalues.secureexec);
						}
					}
				}

				if (psr.sysnum == 242) {
					printf ("\tresult: ");
					u_char* p = (u_char *) buf;
					for (i = 0; i < size; i++) {
						printf ("%02x ", p[i]);
					}
					printf ("\n");
				}

				if (psr.sysnum == 195 || psr.sysnum == 196 || psr.sysnum == 197) {
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

				if (psr.sysnum == 42) {
					printf ("pipe returns (%d,%d)\n", *buf, *(buf+4));
				}

				if (psr.sysnum == 7) {
					printf ("status is %d\n", *(buf));
				}

				if (psr.sysnum == 3) {
					if (is_cache_read & CACHE_MASK) {
						printf ("\toffset is %llx\n", *((long long int *) buf));
#ifdef TRACE_READ_WRITE
							do {
								struct replayfs_filemap_entry *entry;
								int i;
								entry = (struct replayfs_filemap_entry *)(buf + sizeof(long long int));
								if (!graph_only) {
									printf ("\tNumber of writes sourcing this read: %d\n",
											entry->num_elms);

									for (i = 0; i < entry->num_elms; i++) {
										printf ("\t\tSource %d is {id, pid, syscall_num} {%lld %d %lld}\n", i,
												(loff_t)entry->elms[i].bval.id.unique_id, entry->elms[i].bval.id.pid,
												(loff_t)entry->elms[i].bval.id.sysnum);
									}
								} else {
									for (i = 0; i < entry->num_elms; i++) {
										always_print ("%d %lld %d {%lld, %d, %lld, %d, %d}\n",
												index, entry->elms[i].offset - entry->elms[0].offset, entry->elms[i].size,
												(loff_t)entry->elms[i].bval.id.unique_id, entry->elms[i].bval.id.pid,
												(loff_t)entry->elms[i].bval.id.sysnum,
												entry->elms[i].read_offset, entry->elms[i].size);
									}
								}
							} while (0);
#endif
#ifdef TRACE_PIPE_READ_WRITE
					} else if (is_cache_read & IS_PIPE) {
						if (is_cache_read & IS_PIPE_WITH_DATA) {
							struct replayfs_filemap_entry *entry;
							int i;
							/* Get data... */
							entry = (struct replayfs_filemap_entry *)(buf);
							if (!graph_only) {
								printf ("\tPiped writes sourcing this read: %d\n",
										entry->num_elms);

								for (i = 0; i < entry->num_elms; i++) {
									printf ("\t\tSource %d is {id, pid, syscall_num} {%lld %d %lld}\n", i,
											(loff_t)entry->elms[i].bval.id.unique_id, entry->elms[i].bval.id.pid,
											(loff_t)entry->elms[i].bval.id.sysnum);
								}
							} else {
								for (i = 0; i < entry->num_elms; i++) {
									always_print ("pipe: %d %d %d {%lld, %d, %lld, %d, %ld}\n",
											ndx, entry->elms[i].bval.buff_offs, entry->elms[i].size,
											(loff_t)entry->elms[i].bval.id.unique_id, entry->elms[i].bval.id.pid,
											(loff_t)entry->elms[i].bval.id.sysnum,
											entry->elms[i].read_offset, retval);
								}
							}
						} else {
							if (!graph_only) {
								printf("\tFile is a pipe sourced by id %llu, pipe id %d\n",
										*((uint64_t *)buf), 
										/* Yeah, I went there */
										*((int *)((uint64_t *)buf + 1)));
							} else {
								uint64_t id = *((uint64_t *)buf);
								int pipe_id = *(int *)(((uint64_t *)buf) + 1);
								always_print("pipe: %lld, %d, %d {%ld} {%lu}\n", id, pipe_id,
										ndx, retval, start_clock);
							}
						}
#endif
					}
				}
			}

#ifdef TRACE_PIPE_READ_WRITE
			if (psr.sysnum == 4 && (psr.flags & SR_HAS_RETPARAMS)) {
				if (!pipe_write_only) {
					printf("\tWrite is part of pipe: %d\n", *((int *)buf));
				} else {
					always_print("%d, %ld, %lu, %d\n", *((int *)buf), retval,
							start_clock, ndx);
				}
			}
			if (psr.sysnum == 146 && (psr.flags & SR_HAS_RETPARAMS)) {
				if (!pipe_write_only) {
					printf("\tWritev is part of pipe: %d\n", *((int *)buf));
				} else {
					always_print("%d, %ld, %lu, %d\n", *((int *)buf), retval, start_clock, ndx);
				}
			}
#endif

			if ((psr.flags & SR_HAS_SIGNAL) != 0) {
				do {
					//rc = read (fd, &sig, sizeof(sig));
					rc = read (fd, &sig, 172);
					if (rc != 172) {
						printf ("read of signal returns %d, errno = %d\n", rc, errno);
						return -1;
					}
					if (convert) {
						copy_to_convert_buffer (convert_buffer, &convert_offset, (char*) &sig, 172);
					}
					if (stats) {
						scount[511]++;
						bytes[511] += 172; // Special for signals
					}
					//printf ("\tsignal %d info included, next ptr is %p\n", sig.signr, sig.next);
					printf ("\tsignal %d info included, next ptr is %p\n", *(int *)sig, *(char **)(sig+168));
				} while (*(char **)(sig+168));
			}

			if (print_recv && psr.sysnum == 102 && call == SYS_RECV) {
				char* data = buf + sizeof(struct recvfrom_retvals) - sizeof(int)*3;
				int i;
				for (i = 0; i < retval; i++) {
					printf ("%c", data[i]);
				}
				printf ("\n");
			}
			if (dump_recv && psr.sysnum == 102 && call == SYS_RECV && retval > 0) {
				char* data = buf + sizeof(struct recvfrom_retvals) - sizeof(int)*3;
				if (write (dfd, data, retval) != retval) {
					perror ("write dumpfile");
				}
			}
			if (psr.sysnum == 174) {
				if ((psr.flags & SR_HAS_RETPARAMS) != 0) {
					struct sigaction* sa = (struct sigaction *)buf;
					printf ("sa handler is %lx\n", (unsigned long) sa->sa_handler);
				}
			}
			if (psr.sysnum == 102 && call == SYS_RECV && retval > 0) {
				rcv_total += retval;
				printf ("Received %d bytes total\n", rcv_total);
			}
			if (psr.sysnum == 183) {
				printf ("\tpath has %d bytes\n", size);
				if (size > 0) {
					printf ("\tpath is %s\n", buf);
				}
			}

			if (psr.sysnum == 265 && (psr.flags & SR_HAS_RETPARAMS)) {
				struct timespec* time = (struct timespec*) buf;
				printf ("clock_gettime tv_sec:%ld, tv_nsec:%ld\n", time->tv_sec, time->tv_nsec);
			}

			if (psr.sysnum == 192) {
				if ((psr.flags & SR_HAS_RETPARAMS) != 0) {
					printf ("\tdev is %lx\n", ((struct mmap_pgoff_retvals *)buf)->dev);
					printf ("\tino is %lx\n", ((struct mmap_pgoff_retvals *)buf)->ino);
					printf ("\tmtime is %lx.%lx\n", ((struct mmap_pgoff_retvals *)buf)->mtime.tv_sec, ((struct mmap_pgoff_retvals *)buf)->mtime.tv_nsec);
				}
			}
			// next system call
			index++;
		}
		if (convert) {
			//change the data_size now
			//u_long final_size = data_size - xbytes_count;
			u_long final_size = convert_offset - sizeof(data_size);
			printf ("x messages consume %d bytes\n", xbytes_count);
			memcpy (convert_buffer, &final_size, sizeof (u_long));
			rc = write (convert_fd, convert_buffer, convert_offset);
			if (rc != convert_offset) {
				printf ("Convert_buffer cannot be written.\n");
				return -1;
			}
		}
	}

	if (stats) {
		for (i = 0; i < 511; i++) {
			if (scount[i]) {
				printf ("syscall %3d: count %5lu bytes %8lu clock %8lu retval %8lu\n", i, scount[i], bytes[i], clock_bytes[i], retval_bytes[i]);
			}
		}
		if (scount[511]) {
			printf ("signals    : count %5lu bytes %8lu\n", scount[511], bytes[511]);
		}
		printf("Extra bytes added by replay_graph: %d\n", extra_bytes);
	}
	if (convert) {
		for (i = 0; i < 511; ++i) {
			if (cut_out[i])
				printf ("%d, %lu\n", i, cut_out[i]);
		}
	}

#undef printf

	close (fd);
	if (convert) {
		close (convert_fd);
		if (x_fd > 0) {
			//write out the remaining x buffer
			if (x_first_time) {
				x_first_time = 0;
				x_request_pos = 0;
			} else {
				if (x_fd > 0) {
					rc = write (x_fd, (char*) &x_request_pos, sizeof (x_request_pos));
					if (rc != sizeof (x_request_pos)) {
						printf ("cannot write out x_request_pos\n");
					}	
					rc = write (x_fd, (char*) &x_buffer_length, sizeof (x_buffer_length));
					if (rc != sizeof (x_buffer_length)) {
						printf ("cannot write out x_buffer_length\n");
					}						
					rc = write (x_fd, x_buffer, x_buffer_length);
					if (rc != x_buffer_length) 
						printf ("cannot write out x_buffer\n");
					printf ("write out %d bytes x messages\n", x_buffer_length);
					x_buffer_length = 0;
				}
			}
			x_request_pos += retval;
			close (x_fd);
		}
	}
	if (dump_recv) close (dfd);
	return 0;
}

