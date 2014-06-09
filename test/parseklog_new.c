#include "parseklib.h"

#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <getopt.h>

#include <assert.h>

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

int main(int argc, char **argv) {
	struct klogfile *log;
	struct klog_result *res;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <logfile>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	log = parseklog_open(argv[1]);
	if (!log) {
		fprintf(stderr, "%s doesn't appear to be a valid log file!\n", argv[0]);
	}

	parseklog_set_printfcn(log, print_read, 3);
	parseklog_set_printfcn(log, print_write, 4);
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

	while ((res = parseklog_get_next_psr(log)) != NULL) {
		klog_print(stdout, res);
	}

	parseklog_close(log);

	return EXIT_SUCCESS;
}

