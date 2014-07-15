#include "parseklib.h"

#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <getopt.h>

#include <assert.h>

static void empty_printfcn(FILE *out, struct klog_result *res) {
}

static void print_write_pipe(FILE *out, struct klog_result *res) {
	char *retparams = res->retparams;

	if (retparams) {
		fprintf(out, "%d, %ld, %lu, %lld\n", *((int *)retparams), res->retval,
				res->start_clock, res->index);
	}
}

static void print_socketcall_pipe(FILE *out, struct klog_result *res) {
	char *retparams = res->retparams;

	if (retparams) {
		u_int shared;
		int call = *((int *)retparams);
		retparams += sizeof(int);

		switch (call) {
			case SYS_SEND:
			case SYS_SENDTO:
				shared = *((u_int *)retparams);
				if (shared & IS_PIPE) {
					int pipe_id;

					pipe_id = *((int *)retparams);
					retparams += sizeof(int);

					fprintf(out, "%d, %ld, %lu, %lld\n", pipe_id, res->retval,
							res->start_clock, res->index);
					break;
				}
		}
	}
}

static void do_print_graph(FILE *out, struct klog_result *res, char *retparams,
		u_int is_cached) {
	int i;

	if (is_cached & CACHE_MASK) {
		struct replayfs_filemap_entry *entry;
		entry = (struct replayfs_filemap_entry *)retparams;

		for (i = 0; i < entry->num_elms; i++) {
			fprintf(out, "%lld %lld %d {%lld, %d, %lld, %d, %d}\n",
					res->index, entry->elms[i].offset - entry->elms[0].offset, entry->elms[i].size,
					(loff_t)entry->elms[i].bval.id.unique_id, entry->elms[i].bval.id.pid,
					(loff_t)entry->elms[i].bval.id.sysnum,
					entry->elms[i].read_offset, entry->elms[i].size);
		}
	} else if (is_cached & IS_PIPE_WITH_DATA) {
		struct replayfs_filemap_entry *entry;
		entry = (struct replayfs_filemap_entry *)retparams;


		for (i = 0; i < entry->num_elms; i++) {
			fprintf(out, "pipe: %lld %d %d {%lld, %d, %lld, %d, %ld}\n",
					res->index, entry->elms[i].bval.buff_offs, entry->elms[i].size,
					(loff_t)entry->elms[i].bval.id.unique_id, entry->elms[i].bval.id.pid,
					(loff_t)entry->elms[i].bval.id.sysnum,
					entry->elms[i].read_offset, res->retval);
		}
	} else if (is_cached & IS_PIPE) {
		uint64_t writer;
		int pipe_id;
		writer = *((uint64_t *)retparams);
		retparams += sizeof(uint64_t);
		pipe_id = *((int *)retparams);
		fprintf(out, "pipe: %lld, %d, %lld {%ld} {%lu}\n", writer, pipe_id,
				res->index, res->retval, res->start_clock);
	}
}

static void print_socketcall_graph(FILE *out, struct klog_result *res) {
	char *retparams = res->retparams;

	if (retparams) {
		int call = *((int *)retparams);
		u_int is_cached;
		retparams += sizeof(int);

		switch (call) {
			case SYS_RECV:
				retparams += sizeof(struct recvfrom_retvals) - sizeof(int) + res->retval;
				is_cached = *((u_int *)retparams);
				is_cached += sizeof(u_int);
				do_print_graph(out, res, retparams, is_cached);
				break;
			case SYS_RECVFROM:
				retparams += sizeof(struct recvfrom_retvals) - sizeof(int) + res->retval-1; 
				is_cached = *((u_int *)retparams);
				is_cached += sizeof(u_int);
				do_print_graph(out, res, retparams, is_cached);
				break;
		}
	}
}

static void print_read_graph(FILE *out, struct klog_result *res) {
	char *retparams = res->retparams;

	if (retparams) {
		u_int is_cached;
		is_cached = *((u_int *)retparams);
		retparams += sizeof(u_int);

		if (is_cached) {
			/* Fast forward past offset */
			if (is_cached & CACHE_MASK) {
				retparams += sizeof (long long int);
			}
			do_print_graph(out, res, retparams, is_cached);
		}
	}
}

static void print_socketcall(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;

	parseklog_default_print(out, res);

	if (psr->flags & SR_HAS_RETPARAMS) {
		int call = *((int *)res->retparams);
		fprintf(out, "         Socketcall is %d\n", call);
	}
}

static void print_rt_sigaction(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;

	parseklog_default_print(out, res);

	if (psr->flags & SR_HAS_RETPARAMS) {
		struct sigaction* sa = (struct sigaction *)res->retparams;
		fprintf(out, "         sa handler is %lx\n", (unsigned long) sa->sa_handler);
	}
}

static void print_getcwd(FILE *out, struct klog_result *res) {

	parseklog_default_print(out, res);

	fprintf(out, "         path has %d bytes\n", res->retparams_size-sizeof(int));
	if (res->retparams_size-sizeof(int) > 0) {
		fprintf(out, "         path is %s\n", ((char *)res->retparams)+sizeof(int));
	}
}

static void print_clock_gettime(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;

	parseklog_default_print(out, res);

	if (psr->flags & SR_HAS_RETPARAMS) {
		struct timespec* time = (struct timespec*)res->retparams;
		fprintf(out, "clock_gettime tv_sec:%ld, tv_nsec:%ld\n", time->tv_sec, time->tv_nsec);
	}
}

static void print_mmap(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;

	parseklog_default_print(out, res);

	if (psr->flags & SR_HAS_RETPARAMS) {
		fprintf(out, "         dev is %lx\n",
				((struct mmap_pgoff_retvals *)res->retparams)->dev);
		fprintf(out, "         ino is %lx\n",
				((struct mmap_pgoff_retvals *)res->retparams)->ino);
		fprintf(out, "         mtime is %lx.%lx\n",
				((struct mmap_pgoff_retvals *)res->retparams)->mtime.tv_sec,
				((struct mmap_pgoff_retvals *)res->retparams)->mtime.tv_nsec);
	}
}

static void print_open(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;

	parseklog_default_print(out, res);

	if (psr->flags & SR_HAS_RETPARAMS) {
		struct open_retvals *oret = res->retparams;
		fprintf(out, "         Open dev is %lX, ino %lX\n", oret->dev, oret->ino);
	}
}

static void print_write(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;

	parseklog_default_print(out, res);

#ifdef TRACE_PIPE_READ_WRITE
	if (psr->flags & SR_HAS_RETPARAMS) {
		fprintf(out, "         Write is part of pipe: %d\n", *((int *)res->retparams));
	}
#endif
}

static void print_read(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;

	parseklog_default_print(out, res);

	if (psr->flags & SR_HAS_RETPARAMS) {
		char *buf = res->retparams;

		int is_cache_read = *((int *)buf);

		if (is_cache_read & READ_NEW_CACHE_FILE) {
			struct open_retvals *orets = (void *)(buf + sizeof(int) + sizeof(loff_t));
			fprintf(out, "         Updating cache file to {%lu, %lu, (%ld, %ld)}",
					orets->dev, orets->ino, orets->mtime.tv_sec, orets->mtime.tv_nsec);
		}

		if (is_cache_read & CACHE_MASK) {
			fprintf(out, "         offset is %llx\n", *((long long int *) buf));
#ifdef TRACE_READ_WRITE
				do {
					struct replayfs_filemap_entry *entry;
					int i;
					entry = (struct replayfs_filemap_entry *)(buf + sizeof(long long int));
					fprintf(out, "         Number of writes sourcing this read: %d\n",
							entry->num_elms);

					for (i = 0; i < entry->num_elms; i++) {
						fprintf(out, "         \tSource %d is {id, pid, syscall_num} {%lld %d %lld}\n", i,
								(loff_t)entry->elms[i].bval.id.unique_id, entry->elms[i].bval.id.pid,
								(loff_t)entry->elms[i].bval.id.sysnum);
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
				fprintf(out, "         Piped writes sourcing this read: %d\n",
						entry->num_elms);

				for (i = 0; i < entry->num_elms; i++) {
					fprintf(out, "         \tSource %d is {id, pid, syscall_num} {%lld %d %lld}\n", i,
							(loff_t)entry->elms[i].bval.id.unique_id, entry->elms[i].bval.id.pid,
							(loff_t)entry->elms[i].bval.id.sysnum);
				}
			} else {
				fprintf(out, "         File is a pipe sourced by id %llu, pipe id %d\n",
						*((uint64_t *)buf), 
						/* Yeah, I went there */
						*((int *)((uint64_t *)buf + 1)));
			}
#endif
		}
	}
}

static void print_waitpid(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;
	int *buf = res->retparams;
	parseklog_default_print(out, res);

	if (psr->flags & SR_HAS_RETPARAMS) {
		fprintf(out, "         Status is %d\n", *buf);
	}
}

static void print_pipe(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;
	int *buf = res->retparams;

	parseklog_default_print(out, res);

	if (psr->flags & SR_HAS_RETPARAMS) {
		fprintf(out, "         pipe returns (%d,%d)\n", buf[0], buf[1]);
	}
}

static void print_gettimeofday(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;
	parseklog_default_print(out, res);

	if (psr->flags & SR_HAS_RETPARAMS) {
		struct gettimeofday_retvals* gttd =
			(struct gettimeofday_retvals*) res->retparams;
		fprintf(out, "         gettimeofday has_tv %d, has_tz %d, tv_sec %ld, tv_usec %ld\n", 
				gttd->has_tv, gttd->has_tz, gttd->tv.tv_sec, gttd->tv.tv_usec);
	}
}

static void print_stat(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;
	parseklog_default_print(out, res);

	if (psr->flags & SR_HAS_RETPARAMS) {
		struct stat64* pst = (struct stat64 *) res->retparams;

		fprintf(out, "         stat64 size %Ld blksize %lx blocks %Ld ino %Ld\n", 
			pst->st_size, pst->st_blksize, pst->st_blocks, pst->st_ino);
	}
}

static void print_execve(FILE *out, struct klog_result *res) {
	struct syscall_result *psr = &res->psr;

	parseklog_default_print(out, res);

	if ((psr->flags & SR_HAS_RETPARAMS) != 0) {
		struct execve_retvals* per = (struct execve_retvals *) res->retparams;
		if (per->is_new_group) {
			fprintf(out, "\tnew group id: %lld\n", per->data.new_group.log_id);
		} else {
			int i;
			fprintf(out, "\tnumber of random values is %d\n", per->data.same_group.rvalues.cnt);
			for (i = 0; i < per->data.same_group.rvalues.cnt; i++) {
				fprintf(out, "\t\trandom values %d is %lx\n", i, per->data.same_group.rvalues.val[i]);
			}
			fprintf(out, "\tdev is %lx\n", per->data.same_group.dev);
			fprintf(out, "\tino is %lx\n", per->data.same_group.ino);
			fprintf(out, "\tmtime is %lx.%lx\n", per->data.same_group.mtime.tv_sec, per->data.same_group.mtime.tv_nsec);
			fprintf(out, "\tuid is %d\n", per->data.same_group.evalues.uid);
			fprintf(out, "\teuid is %d\n", per->data.same_group.evalues.euid);
			fprintf(out, "\tgid is %d\n", per->data.same_group.evalues.gid);
			fprintf(out, "\tegid is %d\n", per->data.same_group.evalues.egid);
			fprintf(out, "\tAT_SECURE is %d\n", per->data.same_group.evalues.secureexec);
		}
	}
}

enum printtype {
	BASE = 0,
	PIPE,
	GRAPH
};

void print_usage(FILE *out, char *progname) {
	fprintf(out, "Usage: %s [-p] [-g] [-h] logfile\n", progname);
}

void print_help(char *progname) {
	print_usage(stdout, progname);
	printf(" -h       Prints this dialog\n");
	printf(" -g       Only prints file graph information\n");
	printf(" -p       Only prints pipe write information\n");
}

int main(int argc, char **argv) {
	struct klogfile *log;
	struct klog_result *res;

	enum printtype type = BASE;

	int opt;

	while ((opt = getopt(argc, argv, "gp")) != -1) {
		switch (opt) {
			case 'g':
				type = GRAPH;
				break;
			case 'p':
				type = PIPE;
				break;
			case 'h':
				print_help(argv[0]);
				exit(EXIT_SUCCESS);
			default:
				print_usage(stderr, argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (argc - optind != 1) {
		print_usage(stderr, argv[0]);
		exit(EXIT_FAILURE);
	}

	log = parseklog_open(argv[optind]);
	if (!log) {
		fprintf(stderr, "%s doesn't appear to be a valid log file!\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (type == BASE) {
		parseklog_set_printfcn(log, print_read, 3);
		parseklog_set_printfcn(log, print_write, 4);
		parseklog_set_printfcn(log, print_open, 5);
		parseklog_set_printfcn(log, print_waitpid, 7);
		parseklog_set_printfcn(log, print_execve, 11);
		parseklog_set_printfcn(log, print_pipe, 42);
		parseklog_set_printfcn(log, print_gettimeofday, 78);
		parseklog_set_printfcn(log, print_socketcall, 102);
		parseklog_set_printfcn(log, print_write, 146);
		parseklog_set_printfcn(log, print_rt_sigaction, 174);
		parseklog_set_printfcn(log, print_getcwd, 182);
		parseklog_set_printfcn(log, print_mmap, 192);
		parseklog_set_printfcn(log, print_stat, 195);
		parseklog_set_printfcn(log, print_stat, 196);
		parseklog_set_printfcn(log, print_stat, 197);
		parseklog_set_printfcn(log, print_clock_gettime, 265);
	} else if (type == GRAPH) {
		parseklog_set_default_printfcn(log, empty_printfcn);
		parseklog_set_signalprint(log, empty_printfcn);

		parseklog_set_printfcn(log, print_read_graph, 3);
		parseklog_set_printfcn(log, print_socketcall_graph, 102);
	} else if (type == PIPE) {
		parseklog_set_default_printfcn(log, empty_printfcn);
		parseklog_set_signalprint(log, empty_printfcn);

		parseklog_set_printfcn(log, print_write_pipe, 4);
		parseklog_set_printfcn(log, print_write_pipe, 146);
		parseklog_set_printfcn(log, print_socketcall_pipe, 102);
	}

	while ((res = parseklog_get_next_psr(log)) != NULL) {
		klog_print(stdout, res);
	}

	parseklog_close(log);

	return EXIT_SUCCESS;
}

