#ifndef __PTHREAD_LOG_H__
#define __PTHREAD_LOG_H__

/* Note: must update both user-level and kernel headers together */

// Debug log uses uncompressed format
//#define USE_DEBUG_LOG

// This creates a separate log for debugging
//#define USE_EXTRA_DEBUG_LOG

#define DEFAULT_STACKSIZE        32768 

#ifdef USE_DEBUG_LOG
struct pthread_log_data {
	unsigned long clock;
	int           retval;
	int           errno;
	unsigned long type;
	unsigned long check;
};

struct pthread_log_head {
	struct pthread_log_data* next;
	struct pthread_log_data* end;
	int ignore_flag;
	int need_fake_calls;
	u_long old_stackp;
	char stack[DEFAULT_STACKSIZE];
};
#else
struct pthread_log_head {
	char* next;
	char* end;
	int ignore_flag;
	int need_fake_calls;
	unsigned long expected_clock;
	unsigned long num_expected_records;
	int save_errno; // Tracks whether errno changes in an ignored region
	u_long old_stackp;
	char stack[DEFAULT_STACKSIZE];
};

#define NONZERO_RETVAL_FLAG 0x80000000
#define FAKE_CALLS_FLAG     0x40000000
#define SKIPPED_CLOCK_FLAG  0x20000000
#define ERRNO_CHANGE_FLAG   0x10000000
#define CLOCK_MASK          0x0fffffff

#endif

#ifdef USE_EXTRA_DEBUG_LOG
struct pthread_extra_log_head {
	char* next;
	char* end;
};
#endif


#define PTHREAD_LOG_SIZE (10*1024*1024)

#define PTHREAD_LOG_NONE           0
#define PTHREAD_LOG_RECORD         1
#define PTHREAD_LOG_REPLAY         2
#define PTHREAD_LOG_OFF            3
#define PTHREAD_LOG_REP_AFTER_FORK 4

/* Mutex operations */
#define PTHREAD_MUTEX_LOCK_ENTER              1
#define PTHREAD_MUTEX_LOCK_EXIT               2
#define PTHREAD_MUTEX_UNLOCK_ENTER            3
#define PTHREAD_MUTEX_UNLOCK_EXIT             4
#define PTHREAD_MUTEX_TRYLOCK_ENTER           5
#define PTHREAD_MUTEX_TRYLOCK_EXIT            6
#define PTHREAD_MUTEX_TIMEDLOCK_ENTER         7
#define PTHREAD_MUTEX_TIMEDLOCK_EXIT          8
#define PTHREAD_MUTEX_DESTROY_ENTER           9
#define PTHREAD_MUTEX_DESTROY_EXIT           10
#define PTHREAD_MUTEX_CONSISTENT_ENTER       11
#define PTHREAD_MUTEX_CONSISTENT_EXIT        12
#define PTHREAD_MUTEX_GETPRIOCEILING_ENTER   13
#define PTHREAD_MUTEX_GETPRIOCEILING_EXIT_1  14
#define PTHREAD_MUTEX_GETPRIOCEILING_EXIT_2  15
#define PTHREAD_MUTEX_SETPRIOCEILING_ENTER   16
#define PTHREAD_MUTEX_SETPRIOCEILING_EXIT_1  17
#define PTHREAD_MUTEX_SETPRIOCEILING_EXIT_2  18

/* Condition operations */
#define PTHREAD_COND_WAIT_ENTER              21
#define PTHREAD_COND_WAIT_EXIT               22
#define PTHREAD_COND_TIMEDWAIT_ENTER         23
#define PTHREAD_COND_TIMEDWAIT_EXIT          24
#define PTHREAD_COND_SIGNAL_ENTER            25
#define PTHREAD_COND_SIGNAL_EXIT             26
#define PTHREAD_COND_BROADCAST_ENTER         27
#define PTHREAD_COND_BROADCAST_EXIT          28
#define PTHREAD_COND_DESTROY_ENTER           29
#define PTHREAD_COND_DESTROY_EXIT            30

/* Barrier operations */
#define PTHREAD_BARRIER_WAIT_ENTER           31
#define PTHREAD_BARRIER_WAIT_EXIT            32
#define PTHREAD_BARRIER_DESTROY_ENTER        33
#define PTHREAD_BARRIER_DESTROY_EXIT         34

/* Rwlock operations */
#define PTHREAD_RWLOCK_RDLOCK_ENTER           41
#define PTHREAD_RWLOCK_RDLOCK_EXIT            42
#define PTHREAD_RWLOCK_WRLOCK_ENTER           43
#define PTHREAD_RWLOCK_WRLOCK_EXIT            44
#define PTHREAD_RWLOCK_UNLOCK_ENTER           45
#define PTHREAD_RWLOCK_UNLOCK_EXIT            46
#define PTHREAD_RWLOCK_TRYRDLOCK_ENTER        47
#define PTHREAD_RWLOCK_TRYRDLOCK_EXIT         48
#define PTHREAD_RWLOCK_TRYWRLOCK_ENTER        49
#define PTHREAD_RWLOCK_TRYWRLOCK_EXIT         50
#define PTHREAD_RWLOCK_TIMEDRDLOCK_ENTER      51
#define PTHREAD_RWLOCK_TIMEDRDLOCK_EXIT       52
#define PTHREAD_RWLOCK_TIMEDWRLOCK_ENTER      53
#define PTHREAD_RWLOCK_TIMEDWRLOCK_EXIT       54

/* Spinlock operations */
#define PTHREAD_SPIN_LOCK_ENTER               61
#define PTHREAD_SPIN_LOCK_EXIT                62
#define PTHREAD_SPIN_UNLOCK_ENTER             63
#define PTHREAD_SPIN_UNLOCK_EXIT              64
#define PTHREAD_SPIN_TRYLOCK_ENTER            65
#define PTHREAD_SPIN_TRYLOCK_EXIT             66

/* Semaphore operations */
#define SEM_POST_ENTER                        71
#define SEM_POST_EXIT                         72
#define SEM_WAIT_ENTER                        73
#define SEM_WAIT_EXIT                         74
#define SEM_TRYWAIT_ENTER                     75
#define SEM_TRYWAIT_EXIT                      76
#define SEM_TIMEDWAIT_ENTER                   77
#define SEM_TIMEDWAIT_EXIT                    78

/* Atomic operations */
#define PTHREAD_JOINID_ENTER                  81
#define PTHREAD_JOINID_EXIT                   82

/* App specific ops */
#define APP_VALUE_ENTER                       85
#define APP_VALUE_EXIT                        86

/* Sync. operations */
#define SYNC_ADD_AND_FETCH_ENTER              91
#define SYNC_ADD_AND_FETCH_EXIT               92
#define SYNC_BOOL_COMPARE_AND_SWAP_ENTER      93
#define SYNC_BOOL_COMPARE_AND_SWAP_EXIT       94
#define SYNC_FETCH_AND_ADD_ENTER              95
#define SYNC_FETCH_AND_ADD_EXIT               96
#define SYNC_FETCH_AND_SUB_ENTER              97
#define SYNC_FETCH_AND_SUB_EXIT               98
#define SYNC_LOCK_TEST_AND_SET_ENTER          99
#define SYNC_LOCK_TEST_AND_SET_EXIT          100
#define SYNC_SUB_AND_FETCH_ENTER             101
#define SYNC_SUB_AND_FETCH_EXIT              102
#define SYNC_VAL_COMPARE_AND_SWAP_ENTER      103
#define SYNC_VAL_COMPARE_AND_SWAP_EXIT       104
#define SYNC_READ_ENTER                      105
#define SYNC_READ_EXIT                       106

/* Misc. operations */
#define PTHREAD_CANCELHANDLING_ENTER         109
#define PTHREAD_CANCELHANDLING_EXIT          110
#define PTHREAD_ONCE_ENTER                   111
#define PTHREAD_ONCE_EXIT                    112
#define LLL_LOCK_ENTER                       113
#define LLL_LOCK_EXIT                        114
#define LLL_UNLOCK_ENTER                     115
#define LLL_UNLOCK_EXIT                      116
#define LLL_WAIT_TID_ENTER                   117
#define LLL_WAIT_TID_EXIT                    118
#define LLL_TIMEDWAIT_TID_ENTER              119
#define LLL_TIMEDWAIT_TID_EXIT               120

/* Low-level locking from glibc */
#define LIBC_LOCK_LOCK_ENTER                 121
#define LIBC_LOCK_LOCK_EXIT                  122
#define LIBC_LOCK_TRYLOCK_ENTER              123
#define LIBC_LOCK_TRYLOCK_EXIT               124
#define LIBC_LOCK_UNLOCK_ENTER               125
#define LIBC_LOCK_UNLOCK_EXIT                126

/* Special operation to insert syscalls */
#define FAKE_SYSCALLS                        127

extern struct pthread_log_head * allocate_log (void);
#ifdef USE_EXTRA_DEBUG_LOG
extern struct pthread_extra_log_head * allocate_extra_log (void);
int pthread_log_msg (char* msg, int len);
#endif

extern void free_log (void); 
extern void register_log (void);
extern int check_recording (void);
extern void pthread_log_record (int retval, unsigned long type, unsigned long check, int is_entry);
extern int  pthread_log_replay (unsigned long type, unsigned long check);

extern int pthread_log_status;
extern int pthread_log_ignore_syscalls;

static inline int is_recording (void)
{ 
    if (pthread_log_status == PTHREAD_LOG_RECORD) return 1; 
    if (pthread_log_status == PTHREAD_LOG_REPLAY) return 0;
    if (pthread_log_status == PTHREAD_LOG_OFF)    return 0;
    if (check_recording () == PTHREAD_LOG_RECORD) return 1;
    return 0;
}

static inline int is_replaying (void)
{
    if (pthread_log_status == PTHREAD_LOG_REPLAY) return 1;
    return 0;
}

extern int get_pthread_log_status (void);
extern void lcok_ignore_address (void);

void pthread_log_lll_lock (int* plock, int type);
void pthread_log_lll_unlock (int* plock, int type);
void pthread_log_lll_wait_tid (int* ptid);
int pthread_log_lll_timedwait_tid (int* ptid, const struct timespec* abstime);

#endif
