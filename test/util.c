#include <sys/ioctl.h> // ioctl
#include <sys/stat.h>  // open
#include <sys/types.h> // fork, wait
#include <sys/wait.h>  // wait
#include <sys/mman.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>   // malloc
#include <string.h>    // memset
#include <errno.h>     // errno
#include <fcntl.h>     // open
#include <unistd.h>   // write, close
#include <stdarg.h>
#include <errno.h>
#include "util.h"
#define __user 
#include "dev/devspec.h" 

int debugLevel = 0;

#define PAGE_SIZE 4096

#define SUCPRINT(x,...)

#ifndef AUTOBASH_OPT
void DPRINT(int lvl, char* fmt,...)
{
    va_list ap;
    if (lvl <= debugLevel) {
	va_start(ap,fmt);
	vfprintf(stderr,fmt,ap);
	fprintf(stderr,"\n");
	va_end(ap);
    }
}
#endif

void EPRINT(char* fmt,...) 
{
    va_list ap; 
    time_t    now = time(NULL);
    struct tm tmnow;
    localtime_r (&now, &tmnow);
    fprintf (stderr, "%02d/%02d %02d:%02d:%02d ", tmnow.tm_mon, tmnow.tm_mday,
	     tmnow.tm_hour, tmnow.tm_min, tmnow.tm_sec);
    va_start(ap,fmt); 
    vfprintf(stderr,fmt,ap); 
    fprintf(stderr,", errno=%d\n", errno);
    va_end(ap); 
}

int devspec_init (int* fd_spec) 
{
    // yysu: prepare for speculation
    *fd_spec = open (SPEC_DEV, O_RDWR);
    if (*fd_spec < 0) {
	EPRINT ("cannot open spec device");
	return errno;
    }

    return 0;
}

int replay_fork (int fd_spec, const char** args, const char** env,
    char* linkpath, char* logdir, int save_mmap, int pipe_fd)
{
    struct record_data data;
    data.args = args;
    data.env = env;
    data.linkpath = linkpath;
    data.save_mmap = save_mmap;
    data.fd = fd_spec;
    data.logdir = logdir;
    data.pipe_fd = pipe_fd;
    return ioctl (fd_spec, SPECI_REPLAY_FORK, &data);
}

int resume_with_ckpt (int fd_spec, int pin, int gdb, int follow_splits, int save_mmap, 
		      char* logdir, char* linker, loff_t attach_index, int attach_pid, int ckpt_at,
		      int record_timing, u_long nfake_calls, u_long* fake_calls)
{
    struct wakeup_data data;
    data.pin = pin;
    data.gdb = gdb;
    data.logdir = logdir;
    data.linker = linker;
    data.fd = fd_spec;
    data.follow_splits = follow_splits;
    data.save_mmap = save_mmap;
    data.attach_index = attach_index;
    data.attach_pid = attach_pid;
    data.ckpt_at = ckpt_at;
    data.record_timing = record_timing;
    data.nfake_calls = nfake_calls;
    data.fake_calls = fake_calls;
    return ioctl (fd_spec, SPECI_RESUME, &data);    
}

int resume (int fd_spec, int pin, int gdb, int follow_splits, int save_mmap, 
	    char* logdir, char* linker, loff_t attach_index, int attach_pid, int record_timing,
	    u_long nfake_calls, u_long* fake_calls)
{
    return resume_with_ckpt (fd_spec, pin, gdb, follow_splits, save_mmap, logdir, linker, 
			     attach_index, attach_pid, 0, record_timing, nfake_calls, fake_calls);
}

int resume_after_ckpt (int fd_spec, int pin, int gdb, int follow_splits, int save_mmap, 
		       char* logdir, char* linker, char* filename, loff_t attach_index, int attach_pid)
{
    fprintf(stderr, "calling resume_after_ckpt\n");
    struct wakeup_ckpt_data data;
    data.pin = pin;
    data.gdb = gdb;
    data.logdir = logdir;
    data.filename = filename;
    data.linker = linker;
    data.fd = fd_spec;
    data.follow_splits = follow_splits;
    data.save_mmap = save_mmap;
    data.attach_index = attach_index;
    data.attach_pid = attach_pid;
    return ioctl (fd_spec, SPECI_CKPT_RESUME, &data);    

}

int resume_proc_after_ckpt (int fd_spec, char* logdir, char* filename)
{
    struct wakeup_ckpt_data data;
    data.logdir = logdir;
    data.filename = filename;
    data.fd = fd_spec;
    return ioctl (fd_spec, SPECI_CKPT_PROC_RESUME, &data);    
}

int set_pin_addr (int fd_spec, u_long app_syscall_addr, void* pthread_data, void** pcurthread, int* pattach_ndx)
{
    struct set_pin_address_data data;
    long rc;

    data.pin_address = app_syscall_addr;
    data.pthread_data = (u_long) pthread_data;
    data.pcurthread = (u_long *) pcurthread;
    rc = ioctl (fd_spec, SPECI_SET_PIN_ADDR, &data);
    *pattach_ndx = data.attach_ndx;
    return rc;
}

int check_clock_before_syscall (int fd_spec, int syscall)
{
    return ioctl (fd_spec, SPECI_CHECK_BEFORE, &syscall);
}

int check_clock_after_syscall (int fd_spec)
{
    return ioctl (fd_spec, SPECI_CHECK_AFTER);
}

long check_for_redo (int fd_spec)
{
    return ioctl (fd_spec, SPECI_CHECK_FOR_REDO);
}

long redo_mmap (int fd_spec, u_long* prc, u_long* plen) 
{
    struct redo_mmap_data redo;
    long retval =  ioctl (fd_spec, SPECI_REDO_MMAP, &redo);
    *prc = redo.rc;
    *plen = redo.len;
    return retval;
}
long redo_munmap (int fd_spec) 
{
    long retval =  ioctl (fd_spec, SPECI_REDO_MUNMAP);
    return retval;
}

int get_log_id (int fd_spec)
{
    return ioctl (fd_spec, SPECI_GET_LOG_ID);
}

long get_clock_value (int fd_spec)
{
    return ioctl (fd_spec, SPECI_GET_CLOCK_VALUE);
}

int get_used_addresses (int fd_spec, struct used_address* paddrs, int naddrs)
{
    struct get_used_addr_data data;
    data.plist = paddrs;
    data.nlist = naddrs;
    return ioctl (fd_spec, SPECI_GET_USED_ADDR, &data);
}

int get_replay_stats (int fd_spec, struct replay_stat_data* stats)
{
    return ioctl (fd_spec, SPECI_GET_REPLAY_STATS, stats);
}

unsigned long get_replay_args (int fd_spec)
{
    return ioctl (fd_spec, SPECI_GET_REPLAY_ARGS);
}

unsigned long get_env_vars (int fd_spec)
{
    return ioctl (fd_spec, SPECI_GET_ENV_VARS);
}

int get_record_group_id (int fd_spec, uint64_t* rg_id)
{
    return ioctl (fd_spec, SPECI_GET_RECORD_GROUP_ID, rg_id);
}

int get_num_filemap_entries (int fd_spec, int fd, loff_t offset, int size)
{
    struct filemap_num_entry fnentry;
    fnentry.fd = fd;
    fnentry.offset = offset;
    fnentry.size = size;
    return ioctl (fd_spec, SPECI_GET_NUM_FILEMAP_ENTRIES, &fnentry);
}

int get_filemap (int fd_spec, int fd, loff_t offset, int size, void* entries, int num_entries) 
{
    struct filemap_entry fentry;
    fentry.fd = fd;
    fentry.offset = offset;
    fentry.size = size;
    fentry.entries = entries;
    fentry.num_entries = num_entries;
    return ioctl (fd_spec, SPECI_GET_FILEMAP, &fentry);
}

int get_open_fds (int fd_spec, struct open_fd* entries, int num_entries) 
{
    struct open_fds_data oentry;
    oentry.entries = entries;
    oentry.num_entries = num_entries;
    return ioctl (fd_spec, SPECI_GET_OPEN_FDS, &oentry);
}

long reset_replay_ndx(int fd_spec)
{
    return ioctl (fd_spec, SPECI_RESET_REPLAY_NDX);
}

pid_t get_current_record_pid(int fd_spec, pid_t nonrecord_pid)
{
    struct get_record_pid_data data;
    data.nonrecordPid = nonrecord_pid;
    return ioctl(fd_spec, SPECI_GET_CURRENT_RECORD_PID, &data);
}

long get_attach_status(int fd_spec, pid_t pid)
{
    return ioctl (fd_spec, SPECI_GET_ATTACH_STATUS, &pid);
}

int wait_for_replay_group(int fd_spec, pid_t pid) 
{
    return ioctl(fd_spec,SPECI_WAIT_FOR_REPLAY_GROUP, &pid);
}

long try_to_exit(int fd_spec, pid_t pid)
{
    return ioctl (fd_spec, SPECI_TRY_TO_EXIT, &pid);
}


pid_t get_replay_pid(int fd_spec, pid_t parent_pid, pid_t record_pid)
{
    struct get_replay_pid_data data;
    data.parent_pid = parent_pid;
    data.record_pid = record_pid;

    return ioctl (fd_spec, SPECI_GET_REPLAY_PID, &data);
}

int is_pin_attaching(int fd_spec)
{
    return ioctl (fd_spec, SPECI_IS_PIN_ATTACHING);
}


u_long* map_shared_clock (int fd_spec)
{
    u_long* clock;

    int fd = ioctl (fd_spec, SPECI_MAP_CLOCK);
    if (fd < 0) {
	fprintf (stderr, "map_shared_clock: iotcl returned %d, errno=%d\n", fd, errno);
	return NULL;
    }

    clock = mmap (0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (clock == MAP_FAILED) {
	fprintf (stderr, "Cannot setup shared page for clock\n");
	return NULL;
    }

    close (fd);
    return clock;
}
