#ifndef REENTRY_LOCK_H
#define REENTRY_LOCK_H
#include "pin.H"

struct my_reentry_lock {
    PIN_LOCK lock;
    int threadid;
    int count;
};

typedef struct my_reentry_lock REENTRY_LOCK ;

void init_reentry_lock (REENTRY_LOCK* relock) {
    relock = (REENTRY_LOCK *) malloc(sizeof(REENTRY_LOCK));

    relock->threadid = -1;
    relock->count = 0;

    PIN_InitLock(&relock->lock);
}
    
void release_reentry_lock (REENTRY_LOCK* relock, int threadid) {
    PIN_GetLock(&relock->lock, threadid+1);

    assert (relock->threadid == threadid);
    relock->count = relock->count - 1;
    //if (monitor_print_inst) { fprintf(log_f, "relock count is %d\n", relock->count); fflush(log_f); }

    PIN_ReleaseLock(&relock->lock);
}

void get_reentry_lock (REENTRY_LOCK* relock, int threadid) {
    PIN_GetLock(&relock->lock, threadid+1);

    if (relock->count == 0) {
        relock->threadid = threadid;
        relock->count = 1;
        //if (monitor_print_inst) { fprintf(log_f, "Thread %d got relock, count is %d\n", relock->threadid, relock->count); fflush(log_f); }
    } else if (relock->threadid == threadid) {
        relock->count = relock->count + 1;
        //if (monitor_print_inst) { fprintf(log_f, "Thread %d relock count is %d\n", relock->threadid, relock->count); fflush(log_f); }
    } else {
        PIN_ReleaseLock(&relock->lock);
        while (1) {
            PIN_GetLock(&relock->lock, threadid+1);
            if (relock->count == 0) {
                break;
            }
            PIN_ReleaseLock(&relock->lock);
        }
        //if (monitor_print_inst) { fprintf(log_f, "Thread %d changed relock, count is %d\n", relock->threadid, relock->count); fflush(log_f); }
        relock->count = 1;
        relock->threadid = threadid;
    }

    PIN_ReleaseLock(&relock->lock);
}
#endif // end include guard REENTRY_LOCK_H 
