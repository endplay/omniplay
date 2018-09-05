#include "parseklib.h"

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

#include <assert.h>

#define REPLAY_MAX_THREADS 16
#define USE_ARGSALLOC
#define USE_DISK_CKPT

//#define DEBUG_PRINT

#ifdef DEBUG_PRINT
#define debugf(...) printf(__VA_ARGS__)
#else
#define debugf(...)
#endif



static __attribute__((const)) char *syscall_name(int nr);
static void default_printfcn(FILE *out, struct klog_result *res) {
	char idx[10];
	char spacing[10];
	int len;
	int i;

	sprintf(idx, "%lld", res->index);
	len = strlen(idx);
	for (i = 0; i < 5-len; i++) {
		spacing[i] = ' ';
	}
	spacing[i] = '\0';

	fprintf(out, "%s:%ssyscall %-12s (%3d) flags %2x retval %11ld (%08lx) begin %lu end %lu\n",
			idx, spacing,
			syscall_name(res->psr.sysnum), res->psr.sysnum, res->psr.flags, res->retval, res->retval,
			res->start_clock, res->stop_clock);

	/*
	if (res->retparams_size > 0) {
		fprintf(out, "         %d bytes of return parameters included\n", res->retparams_size);
	}
	*/
}

static void default_signal_printfcn(FILE *out, struct klog_result *res) {
	struct repsignal *sig;
	sig = &res->signal->sig;

	while (sig) {
		fprintf(out, "         !!-- Has signal %d --!!\n", sig->signr);
		sig = sig->next;
	}
}

static void free_active_psrs(struct klogfile *log) {
	int i;
	for (i = 0; i < log->active_num_psrs; i++) {
		struct klog_result *apsr = &log->active_psrs[i];
		struct klog_signal *sig = apsr->signal;
		if (apsr->retparams) {
			free(apsr->retparams);
		}

		while (sig) {
			struct klog_signal *n;
			n = sig->next;
			free(sig);
			sig = n;
		}
	}
	free(log->active_psrs);
	log->active_psrs = NULL;
}

static u_long getretparamsize(struct klogfile *log,
		struct klog_result *res) {
	u_long ret = 0;
	struct syscall_result *psr = &res->psr;

	if (res->psr.flags & SR_HAS_RETPARAMS) {
		assert(log->parse_rules[psr->sysnum]);
		if (log->parse_rules[psr->sysnum]->get_retparamsize) {
			ret = log->parse_rules[psr->sysnum]->get_retparamsize(log, res);
		} else {
			ret = log->parse_rules[psr->sysnum]->retparamsize;
		}
		assert(ret >= 0);
	}

	return ret;
}

static int read_psr_chunk(struct klogfile *log) {
	int ret = -1;
	int count;
	u_long data_size;
	int i;
	long rc, bytes_read;
	struct syscall_result *psrs;

	/* Read header */
	debugf("Reading count\n");
	/* Now get how many records there are here */
	rc = read(log->fd, &count, sizeof(count));
	if (rc == 0) { // should have reached the end of the log(s) here
		/* We're at the end, return success, we just didn't read anything */
		return 0;
	}

	if (rc != sizeof(count)) {
		fprintf(stderr, "read returns %ld, expected %d, errno = %d\n", rc, sizeof(count), errno);
		goto out;
	}

	/* Read the records... eventually */
	psrs = malloc(sizeof(struct syscall_result) * count);
	if (!psrs) {
		fprintf(stderr, "Cound not malloc %d bytes\n", sizeof(struct syscall_result)*count);
		goto out;
	}

	if (log->active_psrs) {
		free_active_psrs(log);
	}

	log->active_psrs = malloc(sizeof(struct klog_result) * count);
	if (!log->active_psrs) {
		fprintf(stderr, "Could not malloc %d bytes\n", sizeof(struct klog_result) * count);
		goto out_free;
	}

	rc = read(log->fd, psrs, sizeof(struct syscall_result) * count);
	if (rc != sizeof(struct syscall_result) * count) {
		fprintf(stderr, "Could not read psrs from log\n");
		goto out_free;
	}

	rc = read(log->fd, &data_size, sizeof(data_size));
	if (rc != sizeof(data_size)) {
		fprintf(stderr, "Could not read data_size from log\n");
		goto out_free;
	}

	debugf("Read %d active psrs\n", count);

	for (i = 0; i < count; i++) {
		/*
		printf("Copying: sysnum %3d flags %x\n",
				psrs[i].sysnum, psrs[i].flags);
				*/
		memcpy(&log->active_psrs[i].psr, &psrs[i], sizeof(struct syscall_result));
	}

	log->active_start_idx += log->active_num_psrs;
	log->active_num_psrs = count;

	/* Now handle each psr */
	for (i = 0; i < count; i++) {
		struct klog_result *apsr = &log->active_psrs[i];
		apsr->retparams = NULL;
	}

	for (i = 0; i < count; i++) {
		struct klog_result *apsr = &log->active_psrs[i];
		apsr->log = log;
		apsr->index = log->active_start_idx + i;

		if (log->printfcns[apsr->psr.sysnum]) {
			apsr->printfcn = log->printfcns[apsr->psr.sysnum];
		} else {
			apsr->printfcn = log->default_printfcn;
		}

		debugf("Parsing psr %d with flags 0x%x\n", i, apsr->psr.flags);

		apsr->start_clock = log->expected_clock;
		if ((apsr->psr.flags & SR_HAS_START_CLOCK_SKIP) != 0) {
			u_long clock;
			rc = read (log->fd, &clock, sizeof(u_long));
			if (rc != sizeof(u_long)) {
				fprintf(stderr, "cannot read start clock value\n");
				return rc;
			}

			apsr->start_clock += clock;
		}
		log->expected_clock = apsr->start_clock + 1;

		if ((apsr->psr.flags & SR_HAS_NONZERO_RETVAL) == 0) {
			apsr->retval = 0;
		} else {
			debugf("Reading retval\n");
			rc = read(log->fd, &apsr->retval, sizeof(long));
			if (rc != sizeof(long)) {
				fprintf(stderr, "cannot read return value\n");
				return -1;
			}
		}

		apsr->stop_clock = log->expected_clock;
		if ((apsr->psr.flags & SR_HAS_STOP_CLOCK_SKIP) != 0) {
			u_long clock;
			rc = read (log->fd, &clock, sizeof(u_long));
			if (rc != sizeof(u_long)) {
				fprintf(stderr, "cannot read start clock value\n");
				return rc;
			}

			apsr->stop_clock += clock;
		}
		log->expected_clock = apsr->stop_clock + 1;

		apsr->retparams_size = getretparamsize(log, apsr);
		assert(apsr->retparams_size >= 0);
		debugf("Got retparams_size %d\n", apsr->retparams_size);

		if (apsr->retparams_size > 0) {
			long rc;
			apsr->retparams = malloc(apsr->retparams_size);
			/* FIXME: should fail nicely... */
			assert(apsr->retparams);

			rc = lseek(log->fd, 0, SEEK_CUR);
			debugf("Reading retparams (%d) from %ld\n", apsr->retparams_size, rc);
			bytes_read = 0;
			do {
				rc = read(log->fd, apsr->retparams+bytes_read, apsr->retparams_size-bytes_read);
				if (rc != apsr->retparams_size) {
					fprintf(stderr, "could not read apsr->retparams (rc=%ld, size=%d)!\n", rc, apsr->retparams_size);
					if (rc <= 0) {
						apsr->retparams_size = 0;
						klog_print(stderr, apsr);
						
						free_active_psrs(log);
						goto out_free;
					}
				}
				bytes_read += rc;
			} while (bytes_read != apsr->retparams_size);
		}

		if (apsr->psr.flags & SR_HAS_SIGNAL) {
			struct klog_signal *n;
			do {
				n = apsr->signal;
				apsr->signal = malloc(sizeof(struct klog_signal));
				/* FIXME: exit cleanly */
				assert(apsr->signal);

				if (n == NULL) {
					apsr->signal->sig.next = NULL;
				} else {
					apsr->signal->sig.next = &n->sig;
				}
				apsr->signal->next = n;

				debugf("Reading signal\n");
				rc = read(log->fd, &apsr->signal->raw, 172);
				if (rc != 172) {
					fprintf (stderr, "read of signal returns %ld, errno = %d\n", rc, errno);
					goto out_free;
				}
				apsr->signal->sig.signr = *(int *)apsr->signal->raw;
			} while (*(char **)(apsr->signal->raw+168));
		} else {
			apsr->signal = NULL;
		}
	}

	ret = 0;

out_free:
	free(psrs);

out:
	return ret;
}

static void add_default_parse_rule_exceptions(struct klogfile *log);
struct klogfile *parseklog_open(const char *filename) {
	struct klogfile *ret = NULL;

	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		goto out;
	}

	/* Set up the parse rules */
	memset(ret->parse_rules, 0, sizeof(ret->parse_rules));

	add_default_parse_rule_exceptions(ret);

	/* Set up the print functions */
	memset(ret->printfcns, 0, sizeof(ret->printfcns));
	ret->default_printfcn = default_printfcn;
	ret->signal_print = default_signal_printfcn;

	/* Open the file and initialize the fd */
	ret->fd = open(filename, O_RDONLY);
	if (ret->fd < 0) {
		perror("open: ");
		goto out_free;
	}

	ret->active_psrs = NULL;

	ret->active_start_idx = 0;
	ret->active_num_psrs = 0;

	ret->num_psrs = 0;
	ret->cur_idx = 0;

	ret->expected_clock = 0;

out:
	return ret;

out_free:
	free(ret);
	ret = NULL;
	goto out;
}


void parseklog_close(struct klogfile *log) {
	close(log->fd);
	free(log);
}

struct klog_result *parseklog_get_next_psr(struct klogfile *log) {
	struct klog_result *ret = NULL;
	loff_t prev_idx;

	prev_idx = log->active_start_idx;

	if (log->cur_idx == log->active_num_psrs) {
		debugf("Reading psr chunk\n");
		if (read_psr_chunk(log)) {
			fprintf(stderr, "Error populating psrs, aborting\n");
			return NULL;
		}
		if (prev_idx != log->active_start_idx) {
			log->cur_idx = 0;
		}
	}

	if (log->cur_idx != log->active_num_psrs) {
		ret = &log->active_psrs[log->cur_idx];
		log->cur_idx++;
	}

	return ret;
}

struct klog_result *parseklog_get_psr(struct klogfile *log, loff_t idx) {
	assert(0 && "Unimplemented");
	return NULL;
}

int parseklog_read_next_chunk(struct klogfile *log) {
	return read_psr_chunk(log);
}

int parseklog_cur_chunk_size(struct klogfile *log) {
	return log->active_num_psrs;
}

int parseklog_do_write_chunk(int count, struct klog_result *psrs, int destfd) {
	int i;
	int rc;
	u_long data_size;
	/* Write the count */
	rc = write(destfd, &count, sizeof(int));
	if (rc != sizeof(int)) {
		fprintf(stderr, "Couldn't record count\n");
		return -1;
	}

	data_size = 0;
	/* Write the psrs */
	/* Calculate the data size... */
	for (i = 0; i < count; i++) {
		struct syscall_result *apsr = &psrs[i].psr;
		rc = write(destfd, apsr, sizeof(struct syscall_result));
		if (rc != sizeof(struct syscall_result)) {
			fprintf(stderr, "Couldn't syscall_result\n");
			return -1;
		}

		if (apsr->flags & SR_HAS_START_CLOCK_SKIP) {
			data_size += sizeof(u_long);
		}
		if (apsr->flags & SR_HAS_NONZERO_RETVAL) {
			data_size += sizeof(long);
		}
		if (apsr->flags & SR_HAS_STOP_CLOCK_SKIP) {
			data_size += sizeof(u_long);
		}
		if (apsr->flags & SR_HAS_SIGNAL) {
			struct klog_signal *n = psrs[i].signal;
			do {
				data_size += 172;
			} while (n->next);
		}

		data_size += psrs[i].retparams_size;
	}

	rc = write(destfd, &data_size, sizeof(data_size));
	if (rc != sizeof(data_size)) {
		fprintf(stderr, "Couldn't record data_size\n");
		return -1;
	}

	/* For each psr */
	for (i = 0; i < count; i++) {
		u_long prev_start_clock;
		u_long prev_stop_clock;
		struct syscall_result *apsr = &psrs[i].psr;
		struct klog_result *res = &psrs[i];

		/* If (has clock) write clock */
		if (apsr->flags & SR_HAS_START_CLOCK_SKIP) {
			/* The 2 is magic... */
			u_long record_clock = res->start_clock-prev_start_clock-2;
			rc = write(destfd, &record_clock, sizeof(u_long));
			if (rc != sizeof(u_long)) {
				fprintf(stderr, "Couldn't record start_clock\n");
				return -1;
			}
		}
		/* If (has retval) write retval */
		if (apsr->flags & SR_HAS_NONZERO_RETVAL) {
			rc = write(destfd, &res->retval, sizeof(long));
			if (rc != sizeof(long)) {
				fprintf(stderr, "Couldn't record retval\n");
				return -1;
			}
		}
		if (apsr->flags & SR_HAS_STOP_CLOCK_SKIP) {
			/* The 2 is magic... */
			u_long record_clock = res->stop_clock-prev_stop_clock-2;
			rc = write(destfd, &record_clock, sizeof(u_long));
			if (rc != sizeof(u_long)) {
				fprintf(stderr, "Couldn't record start_clock\n");
				return -1;
			}
		}
		/* If (has retparams) write retparams */
		if (res->retparams_size) {
			rc = write(destfd, res->retparams, res->retparams_size);
			if (rc != res->retparams_size) {
				fprintf(stderr, "Couldn't record retparams_size\n");
				return -1;
			}
		}

		if (apsr->flags & SR_HAS_SIGNAL) {
			struct klog_signal *n = res->signal;
			do {
				write(destfd, n->raw, 172);
			if (rc != sizeof(long)) {
				fprintf(stderr, "Couldn't record raw signal\n");
				return -1;
			}
			} while (n->next);
		}

		prev_stop_clock = res->stop_clock;
		prev_start_clock = res->start_clock;
	}

	return 0;
}

int parseklog_write_chunk(struct klogfile *log, int destfd) {
	long rc;

	/* Write the header */
	rc = parseklog_do_write_chunk(log->active_num_psrs, log->active_psrs, destfd);

	return rc;
}

void parseklog_set_signalprint(struct klogfile *log,
		void (*printfcn)(FILE *, struct klog_result *)) {
	log->signal_print = printfcn;
}

void parseklog_set_default_printfcn(struct klogfile *log,
		void (*printfcn)(FILE *, struct klog_result *)) {
	log->default_printfcn = printfcn;
}

void parseklog_set_printfcn(struct klogfile *log,
		void (*printfcn)(FILE *, struct klog_result *), int sysnum) {
	log->printfcns[sysnum] = printfcn;
}

int klog_print(FILE *out, struct klog_result *result) {
	result->printfcn(out, result);
	if (result->signal && result->log->signal_print) {
		result->log->signal_print(out, result);
	}
	return 0;
}

static u_long varsize(struct klogfile *klog, struct klog_result *res) {
	u_long val;
	long orig_pos;

	orig_pos = lseek(klog->fd, 0, SEEK_CUR);

	if (read (klog->fd, &val, sizeof(u_long)) != sizeof(u_long)) {
		fprintf (stderr, "cannot read variable length field\n");
		return -1;
	}
	debugf("\t4 bytes of variable length field header included\n");
	/*
	if (stats) {
		bytes[psr->sysnum] += sizeof(u_long);
	}
	*/
	debugf("\t%lu variable bytes\n", val);
	lseek(klog->fd, orig_pos, SEEK_SET);
	return val + sizeof(u_long);
}

static u_long getretparams_retval(struct klogfile *klog,
		struct klog_result *res) {
	return res->retval;
}

/* Exceptions */
/*{{{*/
static u_long getretparams_read(struct klogfile *log,
		struct klog_result *res) {
	long rc;
	u_long size = 0;
	int extra_bytes = 0;
	long return_pos;
	u_int is_cache_read;

	return_pos = lseek(log->fd, 0, SEEK_CUR);

	rc = read(log->fd, &is_cache_read, sizeof(u_int));
	if (rc != sizeof(u_int)) {
		fprintf (stderr, "cannot read is_cache value\n");
		return -1;
	}
	size += sizeof(u_int);

	debugf("\tis_cache_file: %d\n", is_cache_read);
	if (is_cache_read & CACHE_MASK) {
		size += sizeof(loff_t);

#ifdef TRACE_READ_WRITE
		do {
			off_t orig_pos;
			struct replayfs_filemap_entry entry;
			loff_t bleh;

			orig_pos = lseek(log->fd, 0, SEEK_CUR);
			rc = read(log->fd, &bleh, sizeof(loff_t));
			rc = read(log->fd, &entry, sizeof(struct replayfs_filemap_entry));
			lseek(log->fd, orig_pos, SEEK_SET);

			if (rc != sizeof(struct replayfs_filemap_entry)) {
				fprintf(stderr, "cannot read entry\n");
				return -1;
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

			orig_pos = lseek(log->fd, 0, SEEK_CUR);
			rc = read(log->fd, &entry, sizeof(struct replayfs_filemap_entry));
			lseek(log->fd, orig_pos, SEEK_SET);

			if (rc != sizeof(struct replayfs_filemap_entry)) {
				fprintf(stderr, "cannot read entry\n");
				return -1;
			}

			size += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
		} else {
			size += sizeof(uint64_t) + sizeof(int);
		}

		size += res->retval;
#endif
	} else {
		size += res->retval; 
	}

	lseek(log->fd, return_pos, SEEK_SET);

	return size;
}

static u_long getretparams_write(struct klogfile *klog,
		struct klog_result *res) {
	long return_pos;
	long rc;
	u_long size = 0;
	int is_shared;

	return_pos = lseek(klog->fd, 0, SEEK_CUR);

	size += sizeof(int);
	rc = read(klog->fd, &is_shared, sizeof(int));
	if (rc != sizeof(int)) {
		fprintf(stderr, "cannot read \"write\" value\n");
		return -1;
	}

	switch (is_shared) {
		case NORMAL_FILE:
			size += sizeof(int64_t);
			break;
		default:
			size += sizeof(int);;
	}

	if (lseek(klog->fd, return_pos, SEEK_SET) == (off_t)-1) {
		fprintf(stderr, "lseek failed to go to return_pos in write\n");
		return -1;
	}

	return size;
}

static u_long getretparams_getgroups(struct klogfile *klog,
		struct klog_result *res) {
	return sizeof(u_short) * res->retval;
}

static u_long getretparams_getgroups32(struct klogfile *klog,
		struct klog_result *res) {
	return sizeof(gid_t) * res->retval;
}

static u_long getretparams_io_getevents(struct klogfile *klog,
		struct klog_result *res) {
	return res->retval * 32;
}

static u_long getretparams_epoll_wait(struct klogfile *klog,
		struct klog_result *res) {
	return res->retval * sizeof(struct epoll_event);
}

static u_long getretparams_socketcall(struct klogfile *log,
		struct klog_result *res) {
	int call;
	long rc;
	u_long size = 0;
	long return_pos;

	
	return_pos = lseek(log->fd, 0, SEEK_CUR);

	rc = read(log->fd, &call, sizeof(int));
	if (rc != sizeof(int)) {
		fprintf(stderr, "cannot read call value\n");
		return -1;
	}
	size += sizeof(int);

	debugf("\tsocketcall %d\n", call);
	assert(call > 0 && call <= 20);

	// socketcall retvals specific
	switch (call) {
#ifdef TRACE_SOCKET_READ_WRITE
		case SYS_SEND:
		case SYS_SENDTO:
			{
				if (res->retval >= 0) {
					u_int shared;

					shared = 0;
					rc = read(log->fd, &shared, sizeof(u_int));
					if (rc != sizeof(shared)) {
						fprintf(stderr, "%d: read %ld\n", __LINE__, rc);
						return -1;
					}
					size += sizeof(u_int);

					debugf("\tRead shared variable of %d\n", shared);

					if (shared & IS_PIPE_WITH_DATA) {
					} else if (shared & IS_PIPE) {
						int pipe_id;

						rc = read(log->fd, &pipe_id, sizeof(int));
						if (rc != sizeof(int)) {
							fprintf(stderr, "%d: read: %ld\n", __LINE__, rc);
							return -1;
						}
						size += sizeof(int);

						/*
						if (!pipe_write_only) {
							printf("\tWrite is part of pipe: %d\n", pipe_id);
						} else {
							always_print("%d, %ld, %lu, %d\n", pipe_id, retval,
									start_clock, ndx);
						}
						*/
					}
				}
				break;
			}
#endif
		case SYS_ACCEPT: 
		case SYS_ACCEPT4:
		case SYS_GETSOCKNAME:
		case SYS_GETPEERNAME: {
			struct accept_retvals avr;
			rc = read(log->fd, ((char *) &avr) + sizeof(int), 
					 sizeof(struct accept_retvals) - sizeof(int));
			if (rc != sizeof(struct accept_retvals) - sizeof(int)) {
				fprintf(stderr, "cannot read accept value\n");
				return -1;
			}
			size += sizeof(struct accept_retvals) - sizeof(int);

			size += avr.addrlen; 
			break;
		}

		case SYS_RECV:
			size += sizeof(struct recvfrom_retvals) - sizeof(int) + res->retval;
#ifdef TRACE_SOCKET_READ_WRITE
			if (res->retval >= 0) {
				u_int is_cached;
				off_t orig_pos;
				orig_pos = lseek(log->fd, 0, SEEK_CUR);
				rc = lseek(log->fd,
						sizeof(struct recvfrom_retvals) - sizeof(int) + res->retval, SEEK_CUR);
				if (rc == (off_t)-1) {
					fprintf(stderr, "%d: lseek: %ld\n", __LINE__, rc);
					return -1;
				}
				rc = read(log->fd, &is_cached, sizeof(u_int));
				if (rc != sizeof(is_cached)) {
					fprintf(stderr, "%d: Couldn't read is_cached\n", __LINE__);
					return -1;
				}

				debugf("\tSocket is_cached is %d\n", is_cached);

				if (is_cached & IS_PIPE_WITH_DATA) {
					off_t orig_pos2;
					int entry_size;
					struct replayfs_filemap_entry entry;
					struct replayfs_filemap_entry *real_entry;

					orig_pos2 = lseek(log->fd, 0, SEEK_CUR);
					rc = read(log->fd, &entry, sizeof(struct replayfs_filemap_entry));

					if (rc != sizeof(struct replayfs_filemap_entry)) {
						fprintf(stderr, "cannot read entry\n");
						return -1;
					}
					lseek(log->fd, orig_pos2, SEEK_SET);

					entry_size = sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
					size += entry_size;
					real_entry = malloc(entry_size);
					if (real_entry == NULL) {
						fprintf(stderr, "Cannot alloc real_entry\n");
						return -1;
					}

					rc = read(log->fd, real_entry, entry_size);
				} else if (is_cached & IS_PIPE) {
					/* Just a simple one-to-one data entry */
					uint64_t writer;
					int pipe_id;
					rc = read(log->fd, &writer, sizeof(uint64_t));
					if (rc != sizeof(writer)) {
						fprintf(stderr, "%d: read: %ld\n", __LINE__, rc);
						return -1;
					}
					rc = read(log->fd, &pipe_id, sizeof(int));
					if (rc != sizeof(pipe_id)) {
						fprintf(stderr, "%d: read: %ld\n", __LINE__, rc);
						return -1;
					}

					size += sizeof(is_cached) + sizeof(writer) + sizeof(pipe_id);
				} else {
					size += sizeof(is_cached);
				}

				lseek(log->fd, orig_pos, SEEK_SET);
			}
#endif
			break;

		case SYS_RECVFROM:
			size += sizeof(struct recvfrom_retvals) - sizeof(int) + res->retval-1; 
#ifdef TRACE_SOCKET_READ_WRITE
			if (res->retval >= 0) {
				u_int is_cached;
				off_t orig_pos;
				orig_pos = lseek(log->fd, 0, SEEK_CUR);
				rc = lseek(log->fd,
						sizeof(struct recvfrom_retvals)-sizeof(int)+res->retval-1, SEEK_CUR);
				if (rc == (off_t)-1) {
					fprintf(stderr, "%d: lseek: %ld\n", __LINE__, rc);
					return -1;
				}
				rc = read(log->fd, &is_cached, sizeof(u_int));
				if (rc != sizeof(is_cached)) {
					fprintf(stderr, "%d: Couldn't read is_cached\n", __LINE__);
					return -1;
				}

				debugf("\tSocket is_cached is %d\n", is_cached);

				if (is_cached & IS_PIPE_WITH_DATA) {
					off_t orig_pos2;
					int entry_size;
					struct replayfs_filemap_entry entry;
					struct replayfs_filemap_entry *real_entry;

					orig_pos2 = lseek(log->fd, 0, SEEK_CUR);
					rc = read(log->fd, &entry, sizeof(struct replayfs_filemap_entry));

					if (rc != sizeof(struct replayfs_filemap_entry)) {
						fprintf(stderr, "cannot read entry\n");
						return -1;
					}
					lseek(log->fd, orig_pos2, SEEK_SET);

					entry_size = sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
					size += entry_size;
					real_entry = malloc(entry_size);
					if (real_entry == NULL) {
						fprintf(stderr, "Cannot alloc real_entry\n");
						return -1;
					}

					rc = read(log->fd, real_entry, entry_size);
				} else if (is_cached & IS_PIPE) {
					/* Just a simple one-to-one data entry */
					uint64_t writer;
					int pipe_id;
					rc = read(log->fd, &writer, sizeof(uint64_t));
					if (rc != sizeof(writer)) {
						fprintf(stderr, "%d: read: %ld\n", __LINE__, rc);
						return -1;
					}
					rc = read(log->fd, &pipe_id, sizeof(int));
					if (rc != sizeof(pipe_id)) {
						fprintf(stderr, "%d: read: %ld\n", __LINE__, rc);
						return -1;
					}

					size += sizeof(is_cached) + sizeof(writer) + sizeof(pipe_id);
				} else {
					size += sizeof(is_cached);
				}

				lseek(log->fd, orig_pos, SEEK_SET);
			}
#endif
			break;

		case SYS_RECVMSG: {
			struct recvmsg_retvals msg;
			rc = read(log->fd, ((char *)&msg) + sizeof(int), sizeof(struct recvmsg_retvals) - sizeof(int));
			if (rc != sizeof(struct recvmsg_retvals) - sizeof(int)) {
				fprintf(stderr, "cannot read recvfrom values\n");
				return -1;
			}
			size += sizeof(struct recvmsg_retvals) - sizeof(int);
			debugf("\trecvmsg: msgnamelen %d msg_controllen %ld msg_flags %x\n", msg.msg_namelen, msg.msg_controllen, msg.msg_flags);
			/*
			if (stats) {
				bytes[psr.sysnum] += sizeof(struct recvfrom_retvals) - sizeof(int);
			}
			*/
			size += msg.msg_namelen + msg.msg_controllen + res->retval; 
			break;
		}

		case SYS_RECVMMSG: {
			if (res->retval > 0) {
				long len;
				rc = read(log->fd, ((char *)&len), sizeof(long));
				if (rc != sizeof(long)) {
					fprintf(stderr, "cannot read recvmmsg value\n");
					return -1;
				}
				size += sizeof(long);
				size += len;
			} else {
				size += 0;
			}
			break;
		}

		case SYS_SOCKETPAIR:
			size += sizeof(struct socketpair_retvals) - sizeof(int);
			break;
		case SYS_GETSOCKOPT: {
			struct getsockopt_retvals sor;
			rc = read (log->fd, ((char *) &sor) + sizeof(int),
					sizeof(struct getsockopt_retvals) - sizeof(int));
			if (rc != sizeof(struct getsockopt_retvals)-sizeof(int)) {
				fprintf(stderr, "cannot read getsockopt value\n");
				return -1;
			}
			size += sizeof(struct getsockopt_retvals) - sizeof(int);
			/*
			if (stats) {
				bytes[psr.sysnum] += sizeof(struct getsockopt_retvals) - sizeof(int);
			}
			*/

			size += sor.optlen;
			break;
		}
		default:
			size += 0; 
	}

	lseek(log->fd, return_pos, SEEK_SET);

	return size;
}

static u_long getretparams_pread64 (struct klogfile *log, struct klog_result *res) 
{
	long rc;
	u_long size = 0;
	int extra_bytes = 0;
	long return_pos;
	u_int is_cache_read;

	return_pos = lseek(log->fd, 0, SEEK_CUR);

	rc = read(log->fd, &is_cache_read, sizeof(u_int));
	if (rc != sizeof(u_int)) {
		fprintf (stderr, "cannot read is_cache value\n");
		return -1;
	}
	size += sizeof(u_int);

	debugf(stderr, "\tis_cache_file: %d\n", is_cache_read);
	if (is_cache_read & CACHE_MASK) {
		size += sizeof(loff_t);

#ifdef TRACE_READ_WRITE
		do {
			off_t orig_pos;
			struct replayfs_filemap_entry entry;
			loff_t bleh;

			orig_pos = lseek(log->fd, 0, SEEK_CUR);
			rc = read(log->fd, &bleh, sizeof(loff_t));
			rc = read(log->fd, &entry, sizeof(struct replayfs_filemap_entry));
			lseek(log->fd, orig_pos, SEEK_SET);

			if (rc != sizeof(struct replayfs_filemap_entry)) {
				fprintf(stderr, "cannot read entry\n");
				return -1;
			}

			extra_bytes += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
			size += sizeof(struct replayfs_filemap_entry) + entry.num_elms * sizeof(struct replayfs_filemap_value);
		} while (0);
#endif
	} else {
		size += res->retval; 
	}

	lseek(log->fd, return_pos, SEEK_SET);

	return size;
}


/*}}}*/

/* Rules for klog parsing */
/*{{{*/
#define _DEFRULE(sysnr, default, fcn) \
	static struct parse_rules exception_##sysnr = { \
		.get_retparamsize = (fcn), \
		.retparamsize = (default) \
	}

#define DEFRULE(sysnr, size) _DEFRULE(sysnr, size, NULL)
#define DEFRULE_FCN(sysnr, fcn) _DEFRULE(sysnr, 0, fcn)

#define ADDRULE(sysnr, log) log->parse_rules[sysnr]=&exception_##sysnr
DEFRULE_FCN(3, getretparams_read);
DEFRULE_FCN(4, getretparams_write);
DEFRULE(5, sizeof(struct open_retvals));
DEFRULE(7, sizeof(int));
DEFRULE(11, sizeof(struct execve_retvals));
DEFRULE(13, sizeof(time_t));
DEFRULE(18, sizeof(struct __old_kernel_stat));
DEFRULE(28, sizeof(struct __old_kernel_stat));
DEFRULE(42, 2*sizeof(int));
DEFRULE(43, sizeof(struct tms));
DEFRULE_FCN(54, varsize);
DEFRULE_FCN(55, varsize);
DEFRULE(59, sizeof(struct oldold_utsname));
DEFRULE(62, sizeof(struct sigaction));
DEFRULE(67, sizeof(struct sigaction));
DEFRULE(73, sizeof(sigset_t));
DEFRULE(76, sizeof(struct rlimit));
DEFRULE(77, sizeof(struct rusage));
DEFRULE(78, sizeof(struct gettimeofday_retvals));
DEFRULE_FCN(80, getretparams_getgroups);
DEFRULE(84, sizeof(struct __old_kernel_stat));
DEFRULE_FCN(85, getretparams_retval);
DEFRULE(86, sizeof(struct mmap_pgoff_retvals));
DEFRULE(89, 266); /* sizeof old_linux_dirent??? */
DEFRULE(99, sizeof(struct statfs));
DEFRULE(100, sizeof(struct statfs));
DEFRULE_FCN(102, getretparams_socketcall);
DEFRULE_FCN(103, getretparams_retval);
DEFRULE(104, sizeof(struct itimerval));
DEFRULE(105, sizeof(struct itimerval));
DEFRULE(106, sizeof(struct stat));
DEFRULE(107, sizeof(struct stat));
DEFRULE(108, sizeof(struct stat));
DEFRULE(109, sizeof(struct old_utsname));
DEFRULE(114, sizeof(struct wait4_retvals));
DEFRULE(116, sizeof(struct sysinfo));
DEFRULE_FCN(117, varsize);
DEFRULE(122, sizeof(struct new_utsname));
DEFRULE(124, sizeof(struct timex));
DEFRULE(126, sizeof(unsigned long)); // old_sigset_t - def in asm/signal.h but cannot include
DEFRULE_FCN(131, varsize);
DEFRULE(134, sizeof(long));
DEFRULE_FCN(135, varsize);
DEFRULE(140, sizeof(loff_t));
DEFRULE_FCN(141, getretparams_retval);
DEFRULE_FCN(142, varsize);
DEFRULE_FCN(145, getretparams_retval);
DEFRULE_FCN(149, varsize);
DEFRULE(155, sizeof(struct sched_param));
DEFRULE(161, sizeof(struct timespec));
DEFRULE(162, sizeof(struct timespec));
DEFRULE(165, sizeof(u_short)*3);
DEFRULE_FCN(168, varsize);
DEFRULE(171, sizeof(u_short)*3);
DEFRULE_FCN(172, varsize);
DEFRULE(174, 20); /* sizeof(struct sigaction)*/
DEFRULE_FCN(175, varsize);
DEFRULE_FCN(176, varsize);
DEFRULE(177, sizeof(siginfo_t));
DEFRULE_FCN(180, getretparams_pread64);
DEFRULE_FCN(183, getretparams_retval);
DEFRULE_FCN(184, varsize);
DEFRULE(185, sizeof(struct __user_cap_header_struct));
DEFRULE(187, sizeof(off_t));
DEFRULE(191, sizeof(struct rlimit));
DEFRULE(192, sizeof(struct mmap_pgoff_retvals));
DEFRULE(195, sizeof(struct stat64));
DEFRULE(196, sizeof(struct stat64));
DEFRULE(197, sizeof(struct stat64));
DEFRULE_FCN(205, getretparams_getgroups32);
DEFRULE(209, sizeof(uid_t)*3);
DEFRULE(211, sizeof(gid_t)*3);
DEFRULE_FCN(218, varsize);
DEFRULE_FCN(220, getretparams_retval);
DEFRULE_FCN(221, varsize);
DEFRULE_FCN(229, getretparams_retval);
DEFRULE_FCN(230, getretparams_retval);
DEFRULE_FCN(231, getretparams_retval);
DEFRULE_FCN(232, getretparams_retval);
DEFRULE_FCN(233, getretparams_retval);
DEFRULE_FCN(234, getretparams_retval);
DEFRULE(239, sizeof(struct sendfile64_retvals));
DEFRULE_FCN(242, varsize);
DEFRULE(245, sizeof(u_long));
DEFRULE_FCN(247, getretparams_io_getevents);
DEFRULE(249, 32);/* struct ioevent */
DEFRULE_FCN(253, getretparams_retval);
DEFRULE_FCN(256, getretparams_epoll_wait);
DEFRULE(259, sizeof(timer_t));
DEFRULE(260, sizeof(struct itimerspec));
DEFRULE(261, sizeof(struct itimerspec));
DEFRULE(265, sizeof(struct timespec));
DEFRULE(266, sizeof(struct timespec));
DEFRULE(267, sizeof(struct timespec));
DEFRULE(268, 84); /* statfs 64 */
DEFRULE(269, 84); /* statfs 64 */
DEFRULE_FCN(275, varsize);
DEFRULE_FCN(280, getretparams_retval);
DEFRULE(282, sizeof(struct mq_attr));
DEFRULE(284, sizeof(struct waitid_retvals));
DEFRULE_FCN(288, varsize);
DEFRULE(300, sizeof(struct stat64));
DEFRULE_FCN(305, getretparams_retval);
DEFRULE(308, sizeof(struct pselect6_retvals));
DEFRULE_FCN(309, varsize);
DEFRULE(312, sizeof(struct get_robust_list_retvals));
DEFRULE(313, sizeof(struct splice_retvals));
DEFRULE_FCN(317, varsize);
DEFRULE(318, sizeof(unsigned)*2);
DEFRULE_FCN(319, getretparams_epoll_wait);
DEFRULE(325, sizeof(struct itimerspec));
DEFRULE(326, sizeof(struct itimerspec));
DEFRULE(331, 2*sizeof(int));
DEFRULE_FCN(333, getretparams_retval);
DEFRULE_FCN(337, varsize);
DEFRULE(340, sizeof(struct rlimit64));
DEFRULE(341, sizeof(struct name_to_handle_at_retvals));
DEFRULE(343, sizeof(struct timex));
/*}}}*/

/* Adding rules to the excepiton list */
/*{{{*/
static void add_default_parse_rule_exceptions(struct klogfile *log) {
	ADDRULE(3, log);
	ADDRULE(4, log);
	ADDRULE(5, log);
	ADDRULE(7, log);
	ADDRULE(11, log);
	ADDRULE(13, log);
	ADDRULE(18, log);
	ADDRULE(28, log);
	ADDRULE(42, log);
	ADDRULE(43, log);
	ADDRULE(54, log);
	ADDRULE(55, log);
	ADDRULE(59, log);
	ADDRULE(62, log);
	ADDRULE(67, log);
	ADDRULE(73, log);
	ADDRULE(76, log);
	ADDRULE(77, log);
	ADDRULE(78, log);
	ADDRULE(80, log);
	ADDRULE(84, log);
	ADDRULE(85, log);
	ADDRULE(86, log);
	ADDRULE(89, log);
	ADDRULE(99, log);
	ADDRULE(100, log);
	ADDRULE(102, log);
	ADDRULE(103, log);
	ADDRULE(104, log);
	ADDRULE(105, log);
	ADDRULE(106, log);
	ADDRULE(107, log);
	ADDRULE(108, log);
	ADDRULE(109, log);
	ADDRULE(114, log);
	ADDRULE(116, log);
	ADDRULE(117, log);
	ADDRULE(122, log);
	ADDRULE(124, log);
	ADDRULE(126, log);
	ADDRULE(131, log);
	ADDRULE(134, log);
	ADDRULE(135, log);
	ADDRULE(140, log);
	ADDRULE(141, log);
	ADDRULE(142, log);
	ADDRULE(145, log);
	ADDRULE(149, log);
	ADDRULE(155, log);
	ADDRULE(161, log);
	ADDRULE(162, log);
	ADDRULE(165, log);
	ADDRULE(168, log);
	ADDRULE(171, log);
	ADDRULE(172, log);
	ADDRULE(174, log);
	ADDRULE(175, log);
	ADDRULE(176, log);
	ADDRULE(177, log);
	ADDRULE(180, log);
	ADDRULE(183, log);
	ADDRULE(184, log);
	ADDRULE(185, log);
	ADDRULE(187, log);
	ADDRULE(191, log);
	ADDRULE(192, log);
	ADDRULE(195, log);
	ADDRULE(196, log);
	ADDRULE(197, log);
	ADDRULE(205, log);
	ADDRULE(209, log);
	ADDRULE(211, log);
	ADDRULE(218, log);
	ADDRULE(220, log);
	ADDRULE(221, log);
	ADDRULE(229, log);
	ADDRULE(230, log);
	ADDRULE(231, log);
	ADDRULE(232, log);
	ADDRULE(233, log);
	ADDRULE(234, log);
	ADDRULE(239, log);
	ADDRULE(242, log);
	ADDRULE(245, log);
	ADDRULE(247, log);
	ADDRULE(249, log);
	ADDRULE(253, log);
	ADDRULE(256, log);
	ADDRULE(259, log);
	ADDRULE(260, log);
	ADDRULE(261, log);
	ADDRULE(265, log);
	ADDRULE(266, log);
	ADDRULE(267, log);
	ADDRULE(268, log);
	ADDRULE(269, log);
	ADDRULE(275, log);
	ADDRULE(280, log);
	ADDRULE(282, log);
	ADDRULE(284, log);
	ADDRULE(288, log);
	ADDRULE(300, log);
	ADDRULE(305, log);
	ADDRULE(308, log);
	ADDRULE(309, log);
	ADDRULE(312, log);
	ADDRULE(313, log);
	ADDRULE(317, log);
	ADDRULE(318, log);
	ADDRULE(319, log);
	ADDRULE(325, log);
	ADDRULE(326, log);
	ADDRULE(331, log);
	ADDRULE(333, log);
	ADDRULE(337, log);
	ADDRULE(340, log);
	ADDRULE(341, log);
	ADDRULE(343, log);
}
/*}}}*/

/* Parsing syscall number to syscall name */
/*{{{*/
static __attribute__((const)) char *syscall_name(int nr) {
	char *ret;

	switch(nr) {
		case 0: ret = "restart_syscall"; break;
		case 1: ret = "exit"; break;
		case 2: ret = "fork"; break;
		case 3: ret = "read"; break;
		case 4: ret = "write"; break;
		case 5: ret = "open"; break;
		case 6: ret = "close"; break;
		case 7: ret = "waitpid"; break;
		case 8: ret = "creat"; break;
		case 9: ret = "link"; break;
		case 10: ret = "unlink"; break;
		case 11: ret = "execve"; break;
		case 12: ret = "chdir"; break;
		case 13: ret = "time"; break;
		case 14: ret = "mknod"; break;
		case 15: ret = "chmod"; break;
		case 16: ret = "lchown"; break;
		case 17: ret = "break"; break;
		case 18: ret = "oldstat"; break;
		case 19: ret = "lseek"; break;
		case 20: ret = "getpid"; break;
		case 21: ret = "mount"; break;
		case 22: ret = "umount"; break;
		case 23: ret = "setuid"; break;
		case 24: ret = "getuid"; break;
		case 25: ret = "stime"; break;
		case 26: ret = "ptrace"; break;
		case 27: ret = "alarm"; break;
		case 28: ret = "oldfstat"; break;
		case 29: ret = "pause"; break;
		case 30: ret = "utime"; break;
		case 31: ret = "stty"; break;
		case 32: ret = "gtty"; break;
		case 33: ret = "access"; break;
		case 34: ret = "nice"; break;
		case 35: ret = "ftime"; break;
		case 36: ret = "sync"; break;
		case 37: ret = "kill"; break;
		case 38: ret = "rename"; break;
		case 39: ret = "mkdir"; break;
		case 40: ret = "rmdir"; break;
		case 41: ret = "dup"; break;
		case 42: ret = "pipe"; break;
		case 43: ret = "times"; break;
		case 44: ret = "prof"; break;
		case 45: ret = "brk"; break;
		case 46: ret = "setgid"; break;
		case 47: ret = "getgid"; break;
		case 48: ret = "signal"; break;
		case 49: ret = "geteuid"; break;
		case 50: ret = "getegid"; break;
		case 51: ret = "acct"; break;
		case 52: ret = "umount2"; break;
		case 53: ret = "lock"; break;
		case 54: ret = "ioctl"; break;
		case 55: ret = "fcntl"; break;
		case 56: ret = "mpx"; break;
		case 57: ret = "setpgid"; break;
		case 58: ret = "ulimit"; break;
		case 59: ret = "oldolduname"; break;
		case 60: ret = "umask"; break;
		case 61: ret = "chroot"; break;
		case 62: ret = "ustat"; break;
		case 63: ret = "dup2"; break;
		case 64: ret = "getppid"; break;
		case 65: ret = "getpgrp"; break;
		case 66: ret = "setsid"; break;
		case 67: ret = "sigaction"; break;
		case 68: ret = "sgetmask"; break;
		case 69: ret = "ssetmask"; break;
		case 70: ret = "setreuid"; break;
		case 71: ret = "setregid"; break;
		case 72: ret = "sigsuspend"; break;
		case 73: ret = "sigpending"; break;
		case 74: ret = "sethostname"; break;
		case 75: ret = "setrlimit"; break;
		case 76: ret = "getrlimit"; break;
		case 77: ret = "getrusage"; break;
		case 78: ret = "gettimeofday"; break;
		case 79: ret = "settimeofday"; break;
		case 80: ret = "getgroups"; break;
		case 81: ret = "setgroups"; break;
		case 82: ret = "select"; break;
		case 83: ret = "symlink"; break;
		case 84: ret = "oldlstat"; break;
		case 85: ret = "readlink"; break;
		case 86: ret = "uselib"; break;
		case 87: ret = "swapon"; break;
		case 88: ret = "reboot"; break;
		case 89: ret = "readdir"; break;
		case 90: ret = "mmap"; break;
		case 91: ret = "munmap"; break;
		case 92: ret = "truncate"; break;
		case 93: ret = "ftruncate"; break;
		case 94: ret = "fchmod"; break;
		case 95: ret = "fchown"; break;
		case 96: ret = "getpriority"; break;
		case 97: ret = "setpriority"; break;
		case 98: ret = "profil"; break;
		case 99: ret = "statfs"; break;
		case 100: ret = "fstatfs"; break;
		case 101: ret = "ioperm"; break;
		case 102: ret = "socketcall"; break;
		case 103: ret = "syslog"; break;
		case 104: ret = "setitimer"; break;
		case 105: ret = "getitimer"; break;
		case 106: ret = "stat"; break;
		case 107: ret = "lstat"; break;
		case 108: ret = "fstat"; break;
		case 109: ret = "olduname"; break;
		case 110: ret = "iopl"; break;
		case 111: ret = "vhangup"; break;
		case 112: ret = "idle"; break;
		case 113: ret = "vm86old"; break;
		case 114: ret = "wait4"; break;
		case 115: ret = "swapoff"; break;
		case 116: ret = "sysinfo"; break;
		case 117: ret = "ipc"; break;
		case 118: ret = "fsync"; break;
		case 119: ret = "sigreturn"; break;
		case 120: ret = "clone"; break;
		case 121: ret = "setdomainname"; break;
		case 122: ret = "uname"; break;
		case 123: ret = "modify_ldt"; break;
		case 124: ret = "adjtimex"; break;
		case 125: ret = "mprotect"; break;
		case 126: ret = "sigprocmask"; break;
		case 127: ret = "create_module"; break;
		case 128: ret = "init_module"; break;
		case 129: ret = "delete_module"; break;
		case 130: ret = "get_kernel_syms"; break;
		case 131: ret = "quotactl"; break;
		case 132: ret = "getpgid"; break;
		case 133: ret = "fchdir"; break;
		case 134: ret = "bdflush"; break;
		case 135: ret = "sysfs"; break;
		case 136: ret = "personality"; break;
		case 137: ret = "afs_syscall"; break;
		case 138: ret = "setfsuid"; break;
		case 139: ret = "setfsgid"; break;
		case 140: ret = "_llseek"; break;
		case 141: ret = "getdents"; break;
		case 142: ret = "_newselect"; break;
		case 143: ret = "flock"; break;
		case 144: ret = "msync"; break;
		case 145: ret = "readv"; break;
		case 146: ret = "writev"; break;
		case 147: ret = "getsid"; break;
		case 148: ret = "fdatasync"; break;
		case 149: ret = "_sysctl"; break;
		case 150: ret = "mlock"; break;
		case 151: ret = "munlock"; break;
		case 152: ret = "mlockall"; break;
		case 153: ret = "munlockall"; break;
		case 154: ret = "sched_setparam"; break;
		case 155: ret = "sched_getparam"; break;
		case 156: ret = "sched_setscheduler"; break;
		case 157: ret = "sched_getscheduler"; break;
		case 158: ret = "sched_yield"; break;
		case 159: ret = "sched_get_priority_max"; break;
		case 160: ret = "sched_get_priority_min"; break;
		case 161: ret = "sched_rr_get_interval"; break;
		case 162: ret = "nanosleep"; break;
		case 163: ret = "mremap"; break;
		case 164: ret = "setresuid"; break;
		case 165: ret = "getresuid"; break;
		case 166: ret = "vm86"; break;
		case 167: ret = "query_module"; break;
		case 168: ret = "poll"; break;
		case 169: ret = "nfsservctl"; break;
		case 170: ret = "setresgid"; break;
		case 171: ret = "getresgid"; break;
		case 172: ret = "prctl"; break;
		case 173: ret = "rt_sigreturn"; break;
		case 174: ret = "rt_sigaction"; break;
		case 175: ret = "rt_sigprocmask"; break;
		case 176: ret = "rt_sigpending"; break;
		case 177: ret = "rt_sigtimedwait"; break;
		case 178: ret = "rt_sigqueueinfo"; break;
		case 179: ret = "rt_sigsuspend"; break;
		case 180: ret = "pread64"; break;
		case 181: ret = "pwrite64"; break;
		case 182: ret = "chown"; break;
		case 183: ret = "getcwd"; break;
		case 184: ret = "capget"; break;
		case 185: ret = "capset"; break;
		case 186: ret = "sigaltstack"; break;
		case 187: ret = "sendfile"; break;
		case 188: ret = "getpmsg"; break;
		case 189: ret = "putpmsg"; break;
		case 190: ret = "vfork"; break;
		case 191: ret = "ugetrlimit"; break;
		case 192: ret = "mmap2"; break;
		case 193: ret = "truncate64"; break;
		case 194: ret = "ftruncate64"; break;
		case 195: ret = "stat64"; break;
		case 196: ret = "lstat64"; break;
		case 197: ret = "fstat64"; break;
		case 198: ret = "lchown32"; break;
		case 199: ret = "getuid32"; break;
		case 200: ret = "getgid32"; break;
		case 201: ret = "geteuid32"; break;
		case 202: ret = "getegid32"; break;
		case 203: ret = "setreuid32"; break;
		case 204: ret = "setregid32"; break;
		case 205: ret = "getgroups32"; break;
		case 206: ret = "setgroups32"; break;
		case 207: ret = "fchown32"; break;
		case 208: ret = "setresuid32"; break;
		case 209: ret = "getresuid32"; break;
		case 210: ret = "setresgid32"; break;
		case 211: ret = "getresgid32"; break;
		case 212: ret = "chown32"; break;
		case 213: ret = "setuid32"; break;
		case 214: ret = "setgid32"; break;
		case 215: ret = "setfsuid32"; break;
		case 216: ret = "setfsgid32"; break;
		case 217: ret = "pivot_root"; break;
		case 218: ret = "mincore"; break;
		case 219: ret = "madvise"; break;
		//case 219: ret = "madvise1"; break;
		case 220: ret = "getdents64"; break;
		case 221: ret = "fcntl64"; break;
/* 223 is unused */
		case 224: ret = "gettid"; break;
		case 225: ret = "readahead"; break;
		case 226: ret = "setxattr"; break;
		case 227: ret = "lsetxattr"; break;
		case 228: ret = "fsetxattr"; break;
		case 229: ret = "getxattr"; break;
		case 230: ret = "lgetxattr"; break;
		case 231: ret = "fgetxattr"; break;
		case 232: ret = "listxattr"; break;
		case 233: ret = "llistxattr"; break;
		case 234: ret = "flistxattr"; break;
		case 235: ret = "removexattr"; break;
		case 236: ret = "lremovexattr"; break;
		case 237: ret = "fremovexattr"; break;
		case 238: ret = "tkill"; break;
		case 239: ret = "sendfile64"; break;
		case 240: ret = "futex"; break;
		case 241: ret = "sched_setaffinity"; break;
		case 242: ret = "sched_getaffinity"; break;
		case 243: ret = "set_thread_area"; break;
		case 244: ret = "get_thread_area"; break;
		case 245: ret = "io_setup"; break;
		case 246: ret = "io_destroy"; break;
		case 247: ret = "io_getevents"; break;
		case 248: ret = "io_submit"; break;
		case 249: ret = "io_cancel"; break;
		case 250: ret = "fadvise64"; break;
/* 251 is available for reuse (was briefly sys_set_zone_reclaim) */
		case 252: ret = "exit_group"; break;
		case 253: ret = "lookup_dcookie"; break;
		case 254: ret = "epoll_create"; break;
		case 255: ret = "epoll_ctl"; break;
		case 256: ret = "epoll_wait"; break;
		case 257: ret = "remap_file_pages"; break;
		case 258: ret = "set_tid_address"; break;
		case 259: ret = "timer_create"; break;
		case 260: ret = "timer_settime"; break;
		case 261: ret = "timer_gettime"; break;
		case 262: ret = "timer_getoverrun"; break;
		case 263: ret = "timer_delete"; break;
		case 264: ret = "clock_settime"; break;
		case 265: ret = "clock_gettime"; break;
		case 266: ret = "clock_getres"; break;
		case 267: ret = "clock_nanosleep"; break;
		case 268: ret = "statfs64"; break;
		case 269: ret = "fstatfs64"; break;
		case 270: ret = "tgkill"; break;
		case 271: ret = "utimes"; break;
		case 272: ret = "fadvise64_64"; break;
		case 273: ret = "vserver"; break;
		case 274: ret = "mbind"; break;
		case 275: ret = "get_mempolicy"; break;
		case 276: ret = "set_mempolicy"; break;
		case 277: ret = "mq_open"; break;
		case 278: ret = "mq_unlink"; break;
		case 279: ret = "mq_timedsend"; break;
		case 280: ret = "mq_timedreceive"; break;
		case 281: ret = "mq_notify"; break;
		case 282: ret = "mq_getsetattr"; break;
		case 283: ret = "kexec_load"; break;
		case 284: ret = "waitid"; break;
/* #define __NR_sys_setaltroot	285 */
		case 286: ret = "add_key"; break;
		case 287: ret = "request_key"; break;
		case 288: ret = "keyctl"; break;
		case 289: ret = "ioprio_set"; break;
		case 290: ret = "ioprio_get"; break;
		case 291: ret = "inotify_init"; break;
		case 292: ret = "inotify_add_watch"; break;
		case 293: ret = "inotify_rm_watch"; break;
		case 294: ret = "migrate_pages"; break;
		case 295: ret = "openat"; break;
		case 296: ret = "mkdirat"; break;
		case 297: ret = "mknodat"; break;
		case 298: ret = "fchownat"; break;
		case 299: ret = "futimesat"; break;
		case 300: ret = "fstatat64"; break;
		case 301: ret = "unlinkat"; break;
		case 302: ret = "renameat"; break;
		case 303: ret = "linkat"; break;
		case 304: ret = "symlinkat"; break;
		case 305: ret = "readlinkat"; break;
		case 306: ret = "fchmodat"; break;
		case 307: ret = "faccessat"; break;
		case 308: ret = "pselect6"; break;
		case 309: ret = "ppoll"; break;
		case 310: ret = "unshare"; break;
		case 311: ret = "set_robust_list"; break;
		case 312: ret = "get_robust_list"; break;
		case 313: ret = "splice"; break;
		case 314: ret = "sync_file_range"; break;
		case 315: ret = "tee"; break;
		case 316: ret = "vmsplice"; break;
		case 317: ret = "move_pages"; break;
		case 318: ret = "getcpu"; break;
		case 319: ret = "epoll_pwait"; break;
		case 320: ret = "utimensat"; break;
		case 321: ret = "signalfd"; break;
		case 322: ret = "timerfd_create"; break;
		case 323: ret = "eventfd"; break;
		case 324: ret = "fallocate"; break;
		case 325: ret = "timerfd_settime"; break;
		case 326: ret = "timerfd_gettime"; break;
		case 327: ret = "signalfd4"; break;
		case 328: ret = "eventfd2"; break;
		case 329: ret = "epoll_create1"; break;
		case 330: ret = "dup3"; break;
		case 331: ret = "pipe2"; break;
		case 332: ret = "inotify_init1"; break;
		case 333: ret = "preadv"; break;
		case 334: ret = "pwritev"; break;
		case 335: ret = "rt_tgsigqueueinfo"; break;
		case 336: ret = "perf_event_open"; break;
		case 337: ret = "recvmmsg"; break;
		case 338: ret = "fanotify_init"; break;
		case 339: ret = "fanotify_mark"; break;
		case 340: ret = "prlimit64"; break;
		case 341: ret = "name_to_handle_at"; break;
		case 342: ret = "open_by_handle_at"; break;
		case 343: ret = "clock_adjtime"; break;
		case 344: ret = "syncfs"; break;
		case 345: ret = "sendmmsg"; break;
		case 346: ret = "setns"; break;
		case 347: ret = "process_vm_readv"; break;
		case 348: ret = "process_vm_writev"; break;
		default: ret = "unknown";
	}

	return ret;
}
/*}}}*/
