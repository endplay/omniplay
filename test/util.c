#include <sys/ioctl.h> // ioctl
#include <sys/stat.h>  // open
#include <sys/types.h> // fork, wait
#include <sys/wait.h>  // wait
#include <time.h>
#include <stdio.h>
#include <stdlib.h>   // malloc
#include <string.h>    // memset
#include <errno.h>     // errno
#include <fcntl.h>     // open
#include <unistd.h>   // write, close
#include <stdarg.h>
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

int replay_fork (int fd_spec, const char** args, const char** env, char* linkpath, char* logdir, int save_mmap)
{
    struct record_data data;
    data.args = args;
    data.env = env;
    data.linkpath = linkpath;
    data.save_mmap = save_mmap;
    data.fd = fd_spec;
    data.logdir = logdir;
    return ioctl (fd_spec, SPECI_REPLAY_FORK, &data);
}

int resume (int fd_spec, int pin, int follow_splits, int save_mmap, char* logdir, char* linker)
{
    struct wakeup_data data;
    data.pin = pin;
    data.logdir = logdir;
    data.linker = linker;
    data.fd = fd_spec;
    data.follow_splits = follow_splits;
    data.save_mmap = save_mmap;
    return ioctl (fd_spec, SPECI_RESUME, &data);    
}

int set_pin_addr (int fd_spec, u_long app_syscall_addr)
{
    return ioctl (fd_spec, SPECI_SET_PIN_ADDR, &app_syscall_addr);
}

int check_clock_before_syscall (int fd_spec, int syscall)
{
    return ioctl (fd_spec, SPECI_CHECK_BEFORE, &syscall);
}

int check_clock_after_syscall (int fd_spec)
{
    return ioctl (fd_spec, SPECI_CHECK_AFTER);
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
