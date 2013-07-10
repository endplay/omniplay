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

// For some reason, the kernel does nos seem to resotre %ebp when the
// regular ioctl function is resumed.  I don't know why this is.  This
// function explicitly saves and restores this register, so we don't 
// have to rely on the kenrel.
int my_ioctl (int fd, int code, void* addr)
{
    register int var;
    __asm__ volatile ("movl $0x36, %%eax\n\tint $0x80" :"=a"(var):"b"(fd), "c" (code), "d" (addr));
    return var;
}

int replay_fork (int fd_spec, u_long app_syscall_addr, char* logdir)
{
    struct record_data data;
    data.app_syscall_addr = app_syscall_addr;
    data.logdir = logdir;
    return my_ioctl (fd_spec, SPECI_REPLAY_FORK, &data);
}

int resume (int fd_spec, int pin, char* logdir, char* linker)
{
    struct wakeup_data data;
    data.pin = pin;
    data.logdir = logdir;
    data.linker = linker;
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

int get_used_addresses (int fd_spec, struct used_address* paddrs, int naddrs)
{
    struct get_used_addr_data data;
    data.plist = paddrs;
    data.nlist = naddrs;
    return my_ioctl (fd_spec, SPECI_GET_USED_ADDR, &data);
}

int set_linker (int fd_spec, char* linker)
{
    return my_ioctl (fd_spec, SPECI_SET_LINKER, linker);
}
