#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "pthreadP.h"
#include "pthread_log.h"
#include <fcntl.h>

// Turns debugging on and off
//#define DPRINT pthread_log_debug
#define DPRINT(x,...)

// Globals for user-level replay
int pthread_log_status = PTHREAD_LOG_NONE;

// System calls we added for this
#define __NR_pthread_print 	   17
#define __NR_pthread_dumbass_link  58

void (*pthread_log_record_hook) (int, unsigned long, unsigned long, int);
int  (*pthread_log_replay_hook) (unsigned long, unsigned long);

// Wait until record/replay has been setup.  After this happens, we will know record/replay status as well as
// the addresses of record and replay functions
int check_recording (void) 
{
    INTERNAL_SYSCALL_DECL(__err);
    INTERNAL_SYSCALL(pthread_dumbass_link,__err,3,&pthread_log_status,&pthread_log_record_hook,&pthread_log_replay_hook);
    
    return pthread_log_status;
}

// This is in lieu of actually dynamic linking.  The dumbassery is because I cannot figure out the
// obscurities of how to get the dynamic linking to work among glib libraries (aaargghhh!)
void
pthread_log_record (int retval, unsigned long type, unsigned long check, int is_entry)
{
    (*pthread_log_record_hook) (retval, type, check, is_entry);
}

int 
pthread_log_replay (unsigned long type, unsigned long check)
{
    return (*pthread_log_replay_hook) (type, check);
}

