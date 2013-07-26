/* Kernel sport's for multithreaded replay
   
   Jason Flinn 
   Ed Nightingale */

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm-generic/syscalls.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/times.h>
#include <linux/utime.h>
#include <linux/futex.h>
#include <linux/scatterlist.h>
#include <linux/ds_list.h>
#include <linux/replay.h>
#include <linux/replay_maps.h>
#include <linux/pthread_log.h>
#include <linux/poll.h>
#include <linux/mman.h>
#include <linux/sort.h>
#include <linux/file.h>
#include <linux/tty.h>
#include <linux/fdtable.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/utsname.h>
#include <linux/eventpoll.h>
#include <linux/sysctl.h>
#include <linux/blkdev.h>
#include <linux/audit.h>
#include <linux/security.h>
#include <linux/cgroup.h>
#include <linux/delayacct.h>
#include <linux/mount.h>
#include <linux/limits.h>
#include <linux/utsname.h>
#include <asm/atomic.h>
#include <asm/ldt.h>
#include <asm/syscall.h>
#include <linux/statfs.h>
#include <linux/workqueue.h>
#include <linux/ipc_namespace.h>
#include <linux/delay.h>

// mcc: fix this later
//#define MULTI_COMPUTER

//#define REPLAY_PARANOID
#define REPLAY_MAX_THREADS 1024
// how long we wait on the wait_queue before timing out
#define SCHED_TO 1000000

#define DPRINT if(replay_debug) printk
//#define DPRINT(x,...)
#define MPRINT if(replay_debug || replay_min_debug) printk
//#define MPRINT(x,...)
#define MCPRINT

//#define KFREE(x) my_kfree(x, __LINE__)
//#define KMALLOC(size, flags) my_kmalloc(size, flags, __LINE__)

// our own allocator for signals/args/retparams
#define USE_ARGSALLOC

#ifdef USE_ARGSALLOC
#define ARGSVMALLOC(size) argsalloc(size)
#define ARGSKMALLOC(size, flags) argsalloc(size)
#define ARGSKFREE(ptr, size) argsfree(ptr, size)
#define ARGSVFREE(ptr, size) argsfree(ptr, size)
#else
#define ARGSVMALLOC(size) vmalloc(size)
#define ARGSKMALLOC(size, flags) kmalloc(size, flags)
#define ARGSVFREE(ptr, size) vfree(ptr)
#define ARGSKFREE(ptr, size) kfree(ptr)
#endif

// write out the kernel logs asynchronously
//#define WRITE_ASYNC

#ifdef REPLAY_PARANOID
static int malloc_init = 0;
struct ds_list_t* malloc_hash[1023];
DEFINE_MUTEX(repmalloc_mutex);
// Intended to check for double frees
void* KMALLOC(size_t size, gfp_t flags) 
{
	void* ptr;
	int i;

	mutex_lock (&repmalloc_mutex);	
	if (!malloc_init) {
		malloc_init = 1;
		for (i = 0; i < 1023; i++) {
			malloc_hash[i] = ds_list_create (NULL, 0, 0);
		}
	}

	ptr = kmalloc (size, flags);
	if (ptr) {
		u_long addr = (u_long) ptr;
		ds_list_insert (malloc_hash[addr%1023], ptr);
	}
	mutex_unlock (&repmalloc_mutex);	
	return ptr;
}


void KFREE (const void* ptr) 
{
	int i;

	mutex_lock (&repmalloc_mutex);	
	if (!malloc_init) {
		malloc_init = 1;
		for (i = 0; i < 1023; i++) {
			malloc_hash[i] = ds_list_create (NULL, 0, 0);
		}
	}
	if (ptr) {
		u_long addr = (u_long) ptr;
		void* tmp;
		tmp = ds_list_remove (malloc_hash[addr%1023], (void *) ptr);
		if (tmp == NULL) {
			printk ("Cannot remove address %p\n", ptr);
			BUG();
		}
	}
	mutex_unlock (&repmalloc_mutex);	
	
	kfree (ptr);
}

atomic_t vmalloc_cnt = ATOMIC_INIT(0);
#define VMALLOC(size) vmalloc(size); atomic_inc(&vmalloc_cnt);
#define VFREE(x) atomic_dec(&vmalloc_cnt); vfree(x);

#else

#define KFREE kfree
#define KMALLOC kmalloc
#define VMALLOC vmalloc
#define VFREE vfree

#endif

//#ifdef REPLAY_PARANOID
//#define REPLAY_LOCK_DEBUG 
//#endif

/* Constant defintions */
#define MAX_PREALLOC_SIZE 20480
#define KMALLOC_THRESHOLD 16384 /* Threshold in record_read, when over it uses VMALLOC instead of KMALLOC */

#define SIGNAL_WHILE_SYSCALL_IGNORED 53

/* Variables configurable via /proc file system */
unsigned int syslog_recs = 200000;
unsigned int replay_debug = 0;
unsigned int replay_min_debug = 0;
unsigned long argsalloc_size = 2097152;

/* struct definitions */
struct replay_group;
struct record_group;
struct syscall_result;

/* Data structures */
struct repsignal {
	int signr;
	siginfo_t info;
	struct k_sigaction ka;
	sigset_t blocked;
	sigset_t real_blocked;
	struct repsignal* next;
};

// This saves record context from when signal was delivered
struct repsignal_context {
	int                       ignore_flag;
	struct repsignal_context* next;
};

// This structure records the result of a system call
struct syscall_result {
#ifdef USE_HPC
	unsigned long long	hpc_begin;	// Time-stamp counter value when system call started
	unsigned long long	hpc_end;	// Time-stamp counter value when system call finished
#endif
	short			sysnum;		// system call number executed
	long			retval;		// return code from the system call
	struct repsignal*	signal;		// Set if sig should be delivered
	void*			retparams;	// system-call-specific return data
	void*			args;		// system-call-specific arguments
	long                    start_clock;    // total order over start
        long                    stop_clock;     // and stop of all system calls
};

// This holds a memory range that should be preallocated
struct reserved_mapping {
	u_long m_begin;
	u_long m_end;
};

struct mmap_pgoff_args {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long pgoff;
};

struct record_group {
#ifdef REPLAY_LOCK_DEBUG
	pid_t rg_locker;
	struct semaphore rg_sem; 
#else
	struct mutex rg_mutex;      // Protect all structures for group
#endif
	atomic_t rg_refcnt;         // Refs to this structure

	/* Deals with logid assignmanet */
	struct mutex rg_logid_mutex;	// Used to logid assignment
	short* rg_free_logids;		// Free log ids

	int rg_log_opened[REPLAY_MAX_THREADS];  // If file for this log has been opened
	atomic_t rg_krecord_clock;   // Recording clock - used only until user-level clock is initialized
	char rg_logdir[MAX_LOGDIR_STRLEN+1]; // contains the directory to which we will write the log
	char rg_shmpath[MAX_LOGDIR_STRLEN+1]; // contains the path of the shared-memory file that we will use for the user-clock
	atomic_t rg_shmpath_set; // flag to indicate whether or not a shared memory page has been set up
	char rg_linker[MAX_LOGDIR_STRLEN+1]; // contains the name of a special linker to use - for user level pthread library

	char rg_mismatch_flag;  // Set when an error has occurred and we want to abandon ship
};

// This structure has task-specific replay data
struct replay_group {
	struct record_group* rg_rec_group; // Pointer to record group
	ds_list_t* rg_replay_threads; // List of replay threads for this group
	atomic_t rg_refcnt;         // Refs to this structure
	u_long rg_kreplay_clock;    // Clock for sync. ops such as ipc sems
	ds_list_t* rg_reserved_mem_list; // List of addresses we should preallocate to keep pin from using them
	u_long rg_max_brk;          // Maximum value of brk address
	ds_list_t* rg_used_address_list; // List of addresses that will be used by the application (and hence, not by pin)
};

struct argsalloc_node {
	void* head;
	void* pos;
	struct list_head list;
};

struct sysv_mapping {
	int record_id;
	int replay_id;
	struct list_head list;
};

#define CHECK_K_PTR(x) if ((u_long) (x) < 0xc0000000) { printk ("Bad pointer %p\n", (x)); BUG(); }

#ifdef REPLAY_LOCK_DEBUG
static void rg_lock(struct record_group* prg)
{
#ifdef REPLAY_PARANOID
	if (!write_can_lock(&tasklist_lock)) {
		MPRINT ("replay: pid %d cannot lock tasklist, prg %p, rg_locker %d\n", current->pid, prg, prg->rg_locker);
		write_lock_irq(&tasklist_lock);
		write_unlock_irq(&tasklist_lock);
		MPRINT ("tasklist lock succeeded anyway\n");
	}
	while (down_timeout(&(prg)->rg_sem, 125)) {
		MPRINT ("pid %d cannot get replay lock %p - last locker was pid %d\n", current->pid, prg, prg->rg_locker);
	}
	prg->rg_locker = current->pid;
#else
	down(&(prg)->rg_sem);
#endif
}

static void rg_unlock(struct record_group* prg) 
{
#ifdef REPLAY_PARANOID
	if (current->pid != prg->rg_locker) {
		printk ("pid %d locked and pid %d unlocked\n", prg->rg_locker, 
			current->pid);
	}
	prg->rg_locker = 0;
#endif
	up(&(prg)->rg_sem);
#ifdef REPLAY_PARANOID
	if (prg->rg_sem.count > 1) {
		printk ("ERROR: pid %d sees semcount %d\n", current->pid, prg->rg_sem.count);
	}
#endif
}
#else
#define rg_lock(prg) mutex_lock(&(prg)->rg_mutex); 
#define rg_unlock(prg) mutex_unlock(&(prg)->rg_mutex);
#endif

static atomic_t rp_cloned_next = ATOMIC_INIT(1);

static __always_inline u_long tv_diff(const struct timeval *tv1, const struct timeval *tv2)
{
	return (tv1->tv_sec - tv2->tv_sec)*USEC_PER_SEC + (tv1->tv_usec - tv2->tv_usec);
}

typedef void (*rb_free_fn)(void);

static inline void*
my_kmalloc(size_t size, gfp_t flags, int line)
{
	void *ptr;
	ptr = kmalloc(size, flags);

	DPRINT ("Pid %d allocated %p\n", current->pid, ptr);
	return ptr;
}

static inline void
my_kfree(const void *ptr, int line)
{
	DPRINT ("Pid %d freeing %p\n", current->pid, ptr);

	CHECK_K_PTR (ptr);
	kfree(ptr);
}

/* static inline */ void
check_KFREE(const void *x)
{
	if (x && !IS_ERR(x)) {
		if ((u_long) x < 0xc0000000) {
			printk("  ERROR: freeing obviously bogus value %p\n", x);
			BUG_ON(1);
		} else {
			KFREE (x);
		}
	}
}

static inline void
check_putname(const char* name)
{
	if (name && !IS_ERR(name)) {
		if ((u_long) name < 0xc0000000) {
			printk("  ERROR: bogus name: %p\n", name);
			BUG_ON(1);
		} else {
			putname(name);
		}
	}
}

static long 
rm_cmp (void* rm1, void* rm2) 
{
	struct reserved_mapping* prm1 = rm1;
	struct reserved_mapping* prm2 = rm2;
	return prm1->m_begin - prm2->m_begin;
}

// This structure records/replays random values generated by the kernel
// Only used for the execve system call right now - is it needed elsewhere?
#define REPLAY_MAX_RANDOM_VALUES 6
struct rvalues {
	int    cnt;
	u_long val[REPLAY_MAX_RANDOM_VALUES];
};

//This has record thread specific data
struct record_thread {
	struct record_group* rp_group; // Points to record group
	struct record_thread* rp_next_thread; // Circular record thread list

	atomic_t rp_refcnt;            // Reference count for this object
	short rp_logid;                // Map thread to pthread log
	pid_t rp_record_pid;           // Pid of recording task (0 if not set)
	long rp_cloned_id;             // Unique id for new record thread
	short rp_clone_status;         // Prevent rec task from exiting
	                               // before rep task is created 
	                               // (0:init,1:cloning,2:completed)
	long rp_sysrc;                 // Return code for replay_prefork

  	/* Recording log */
  	struct syscall_result* rp_log;  // Logs system calls per thread
	u_long rp_in_ptr;               // Next record to insert

	loff_t rp_read_log_pos;		// The current position in the log file that is being read
#ifdef USE_ARGSALLOC
	struct list_head rp_argsalloc_list;	// kernel linked list head pointing to linked list of argsalloc_nodes
#endif
	u_long rp_user_log_addr;        // Where the user log info is stored 
	int __user * rp_ignore_flag_addr;     // Where the ignore flag is stored

	struct rvalues random_values;   // Tracks kernel randomness during syscalls (currently execve only) 

	atomic_t* rp_precord_clock;     // Points to the recording clock in use

	int rp_ulog_opened;		// Flag that says whether or not the user log has been opened 
	loff_t rp_read_ulog_pos;	// The current position in the ulog file that is being read
	struct repsignal_context* rp_repsignal_context_stack;  // Saves replay context on signal delivery
	u_long rp_record_hook;          // Used for dumbass linking in glibc
	struct repsignal *rp_signals;   // Stores delayed signals
};

#define REPLAY_STATUS_RUNNING         0 // I am the running thread - should only be one of these per group
#define REPLAY_STATUS_ELIGIBLE        1 // I could run now
#define REPLAY_STATUS_WAIT_CLOCK      2 // Cannot run because waiting for an event
#define REPLAY_STATUS_DONE            3 // Exiting

// This has replay thread specific data
struct replay_thread {
	struct replay_group* rp_group; // Points to replay group
	struct replay_thread* rp_next_thread; // Circular replay thread list
	struct record_thread* rp_record_thread; // Points to record thread

	atomic_t rp_refcnt;            // Reference count for this object
	pid_t rp_replay_pid;           // Pid of replaying task (0 if not set)
	u_long rp_out_ptr;             // Next record to read
	short rp_replay_exit;          // Set after a rollback
	struct repsignal *rp_signals;  // Set if sig should be delivered
	u_long app_syscall_addr;       // Address in user-land that is set when the syscall should be replayed

	int rp_status;                  // One of the replay statuses above
	u_long rp_wait_clock;           // Valid if waiting for kernel or user-level clock according to rp_status
	wait_queue_head_t rp_waitq;     // Waiting on this queue if in one of the waiting states

	long rp_saved_rc;               // Stores syscall result when blocking in syscall conflicts with a pin lock
	char* rp_saved_retparams;       // Stores syscall results when blocking in syscall conflicts with a pin lock
	char* rp_saved_args;
	struct syscall_result* rp_saved_psr; // Stores syscall info when blocking in syscall conflicts with a pin lock
	struct rvalues random_values;   // Tracks kernel randomness during syscalls (currently execve only) 

	u_long* rp_preplay_clock;   // Points to the replay clock in use
	struct list_head rp_sysv_list;	// List of mappings from replay SYSV IDs to reocrd SYSV IDs
	int __user * rp_status_addr; // Address of status flag
	u_long rp_replay_hook;          // Used for dumbass linking in glibc
};

/* Prototypes */
struct file* init_log_write (struct record_thread* prect, int logid, loff_t* ppos, int* pfd);
void term_log_write (struct file* file, int fd);
int read_log_data (struct record_thread* prt);
int read_log_data_internal (struct record_thread* prect, struct syscall_result* psr, int logid, int* syscall_count, loff_t* pos);
static ssize_t write_log_data(struct file* file, loff_t* ppos, struct record_thread* prect, struct syscall_result* psr, int count, int log);
static void destroy_record_group (struct record_group *prg);
static void destroy_replay_group (struct replay_group *prepg);
static void __destroy_replay_thread (struct replay_thread* prp);
static void free_kernel_log(struct record_thread *prect);
static void free_kernel_log_internal(struct syscall_result* psr, int syscall_count);
void write_begin_log (struct file* file, loff_t* ppos, struct record_thread* prect);
static void write_and_free_kernel_log(struct record_thread *prect);
#ifdef USE_ARGSALLOC
static struct argsalloc_node* new_argsalloc_node (void* slab);
static int add_argsalloc_node (struct record_thread *prect, void* slab);
#endif
//static int add_sysv_mapping (struct replay_thread* prt, int record_id, int replay_id);
//static int find_sysv_mapping (struct replay_thread* prt, int record_id);
static void delete_sysv_mappings (struct replay_thread* prt);
#ifdef WRITE_ASYNC
static void write_and_free_kernel_log_async(struct record_thread *prect);
static void write_and_free_handler (struct work_struct *work);
#endif
static int record_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs);
static int replay_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs);

/* Return values for complex system calls */
struct gettimeofday_retvals {
	short           has_tv;
	short           has_tz;
	struct timeval  tv;
	struct timezone tz;
};

struct select_retvals {
	char           has_inp;
	char           has_outp;
	char           has_exp;
	char           has_tv;
	fd_set         inp;
	fd_set         outp;
	fd_set         exp;
	struct timeval tv;
};

struct generic_socket_retvals {
	atomic_t refcnt;
	int call;
};

// mcc: This should probably be fixed since it allocated an extra 4 bytes
struct accept_retvals {
	atomic_t refcnt;
	int call;
	int addrlen;
	char addr; // Variable length buffer follows
};

struct socketpair_retvals {
	atomic_t refcnt;
	int call;
	int sv0;
	int sv1;
};

struct recvfrom_retvals {
	atomic_t refcnt;
	int call;
	struct sockaddr addr;
	int addrlen;
	char buf;  // Variable length buffer follows 
};

/* XXX- recvmsg_retvals should save whole data structures
	that are pointed by the fields in struct msghdr,
	but for simplicity, assume and check
	msg_namelen <= 32
	msg_iovlen <= 1
	msg_controllen <= 32
*/
#define SIMPLE_MSGHDR_SIZE 32
struct recvmsg_retvals {
	atomic_t refcnt;
	int call;
	char msg_name[SIMPLE_MSGHDR_SIZE];	//assume <=32
	int msg_namelen;
	char msg_control[SIMPLE_MSGHDR_SIZE];	//assume <=32
	int msg_controllen;
	unsigned int msg_flags;
	int iov_len;
	char iov_base;  			// Variable length buffer follows 
};

struct getsockopt_retvals {
	atomic_t refcnt;
	int call;
	int optlen;
	char optval; // Variable length buffer follows
};

struct sendfile64_retvals {
	atomic_t refcnt;
	loff_t offset;
};

/* 
 * epoll_wait_retvals should save whole data structures
 * that are pointed to by the fields in struct epoll_event,
 * for simplicity, assuming union epoll_data is not void*
 * 
 */
struct epoll_wait_retvals {
	atomic_t refcnt;
	struct epoll_event event; 	// Variable length array follows
					// array of struct epoll_event[rc]
};

struct ipc_retvals {
	int call;
};

// semaphore ipc retvals
struct sem_retvals {
	struct ipc_retvals ipc_rv;
};

// retvals for shmat, since we need to save additional information
struct shmat_retvals {
	struct ipc_retvals ipc_rv;
	u_long addr;
	int size;
};

// retvals for mmap_pgoff - needed to find cached files for non-COW filesystems
struct mmap_pgoff_retvals {
	dev_t           dev;
	u_long          ino;
	struct timespec mtime; 
};

/* Which syscalls use reference-counted retvals? */
static inline int retval_uses_ref(int sysnum) {
	return sysnum == 102 || sysnum == 239 || sysnum == 256;
}

static inline void
get_replay_group (struct replay_group* prg)
{
	atomic_inc(&prg->rg_refcnt);
}

static inline void
put_replay_group (struct replay_group* prg)
{
	DPRINT ("put_replay_group %p refcnt %d\n", prg, atomic_read(&prg->rg_refcnt));
	if (atomic_dec_and_test(&prg->rg_refcnt))
		destroy_replay_group(prg);
}

static inline void
get_record_group (struct record_group* prg)
{
	atomic_inc(&prg->rg_refcnt);
}

static inline void
put_record_group (struct record_group* prg)
{
	if (atomic_dec_and_test(&prg->rg_refcnt)) destroy_record_group(prg);
}

static inline int 
test_app_syscall(int number)
{
	struct replay_thread* prt = current->replay_thrd;
	if (prt->app_syscall_addr == 1) return 0; // PIN not yet attached
	return (prt->app_syscall_addr == 0) || (*(int*)(prt->app_syscall_addr) == number);
}

static inline int
is_pin_attached (void)
{
	return current->replay_thrd->app_syscall_addr != 0;
}

#ifdef USE_HPC
static inline long long rdtsc(void) {
	union {
		struct {
			unsigned int l;  /* least significant word */
			unsigned int h;  /* most significant word */
		} w32;
		unsigned long long w64;
	} v;
	__asm __volatile (".byte 0xf; .byte 0x31     # RDTSC instruction"
			: "=a" (v.w32.l), "=d" (v.w32.h) :);
	return v.w64;
}
#endif

void print_memory_areas (void) 
{
	struct vm_area_struct *existing_mmap;
	if (current->mm) {
		existing_mmap = current->mm->mmap;
	}
	else {
		existing_mmap = 0;
	}
	printk ("Pid %d let's print out the memory mappings:\n", current->pid);
	while (existing_mmap) {
		// vm_area's are a singly-linked list
		printk ("  addr: %#lx, len %lu\n", existing_mmap->vm_start, existing_mmap->vm_end - existing_mmap->vm_start);
		existing_mmap = existing_mmap->vm_next;
	}
}

/* Creates a new replay group for the replaying process info */
static struct replay_group*
new_replay_group (struct record_group* prec_group)
{
	struct replay_group* prg;

	prg = KMALLOC (sizeof(struct replay_group), GFP_KERNEL);
	if (prg == NULL) {
		printk ("Cannot allocate replay_group\n");
		goto err;
	}
	DPRINT ("new_replay_group: %p\n", prg);

	prg->rg_rec_group = prec_group;

	// PARSPEC
	prg->rg_replay_threads = ds_list_create(NULL, 0, 1);
	if (prg->rg_replay_threads == NULL) {
		printk ("Cannot create replay_group rg_replay_threads\n");
		goto err_replaythreads;
	}

	atomic_set (&prg->rg_refcnt, 0);

	prg->rg_kreplay_clock = 0;

	prg->rg_reserved_mem_list = ds_list_create (rm_cmp, 0, 1);
	prg->rg_used_address_list = NULL;

	// Record group should not be destroyed before replay group
	get_record_group (prec_group);

	return prg;

err_replaythreads:
	KFREE (prg);
err:
	return NULL;
}

/* Creates a new record group for the recording process info */
static struct record_group*
new_record_group (char* logdir)
{
	struct record_group* prg;
	int i;

	MPRINT ("new_record_group: entered\n");

	prg = KMALLOC (sizeof(struct record_group), GFP_KERNEL);
	if (prg == NULL) {
		printk ("Cannot allocate record_group\n");
		goto err;
	}

#ifdef REPLAY_LOCK_DEBUG
	sema_init(&prg->rg_sem, 1);
#else
	mutex_init (&prg->rg_mutex);
#endif	
	atomic_set(&prg->rg_refcnt, 0);

	mutex_init (&prg->rg_logid_mutex);
	prg->rg_free_logids = KMALLOC (sizeof(short)*REPLAY_MAX_THREADS, GFP_KERNEL);
	if (prg->rg_free_logids == NULL) {
		printk ("Unable to allocate free logids \n");
		goto err_logids;
	}
	for(i = 0 ; i < REPLAY_MAX_THREADS ; i++) {
		prg->rg_free_logids[i]=0;
	}

	for (i = 0; i < REPLAY_MAX_THREADS; i++) {
		prg->rg_log_opened[i] = 0;
	}
	atomic_set (&prg->rg_krecord_clock, 0);

	strncpy (prg->rg_logdir, logdir, MAX_LOGDIR_STRLEN+1);
	memset (prg->rg_shmpath, 0, MAX_LOGDIR_STRLEN+1);
	atomic_set(&prg->rg_shmpath_set, 0);
	memset (prg->rg_linker, 0, MAX_LOGDIR_STRLEN+1);

	prg->rg_mismatch_flag = 0;

	MPRINT ("new_record_group: exited\n");
	return prg;

err_logids:
	KFREE(prg);
err:
	return NULL;
}

static void
destroy_replay_group (struct replay_group *prepg)
{
	struct replay_thread *prt;
	struct reserved_mapping* pmapping;

	MPRINT ("Pid %d destroy replay group %p: enter\n", current->pid, prepg);

	// Destroy replay_threads list
	if (prepg->rg_replay_threads) {
		while (ds_list_count(prepg->rg_replay_threads)) {
			prt = ds_list_first(prepg->rg_replay_threads);
			__destroy_replay_thread(prt);
		}
		ds_list_destroy (prepg->rg_replay_threads);
	}

	// Free all of the mappings
	while ((pmapping = ds_list_get_first (prepg->rg_reserved_mem_list)) != NULL) {
		KFREE (pmapping);
	}
	ds_list_destroy (prepg->rg_reserved_mem_list);

	if (is_pin_attached()) {
		// And the used-address list (if it exists) 
		if (prepg->rg_used_address_list) {
			while ((pmapping = ds_list_get_first (prepg->rg_used_address_list)) != NULL) {
				KFREE (pmapping);
			}
			ds_list_destroy (prepg->rg_used_address_list);
		}
	}

	// Put record group so it can be destroyed
	put_record_group (prepg->rg_rec_group);

	// Free the replay group
	KFREE (prepg);
	printk ("Goodbye, cruel lamp!  This replay is over\n");
	MPRINT ("Pid %d destroy replay group %p: exit\n", current->pid, prepg);
}

// PARSPEC: eventually: want to make sure that all replay groups are destroyed
static void
destroy_record_group (struct record_group *prg)
{
	MPRINT ("Pid %d destroying record group %p\n", current->pid, prg);

	// Destroy free_logids
	if (prg->rg_free_logids) KFREE (prg->rg_free_logids);

	KFREE (prg);
#ifdef REPLAY_PARANOID
	printk ("vmalloc cnt: %d\n", atomic_read(&vmalloc_cnt));
#endif
}

/* Creates a new record thread */
static struct record_thread* 
new_record_thread (struct record_group* prg, u_long recpid, int logid)
{
	struct record_thread* prp;
	int i;

	prp = KMALLOC (sizeof(struct record_thread), GFP_KERNEL);
	if (prp == NULL) {
		printk ("Cannot allocate record_thread\n");
		return NULL;
	}

	prp->rp_group = prg;
	prp->rp_next_thread = prp;

	atomic_set(&prp->rp_refcnt, 1);

	// rp_logid init
	mutex_lock (&prg->rg_logid_mutex);
	if (logid >= 0) {
		if (logid < REPLAY_MAX_THREADS && 
		    prg->rg_free_logids[logid]==0) {
			prp->rp_logid = logid;
			prg->rg_free_logids[logid] = 1;
		} else {
			printk ("Pid %d: logid %d already taken\n",
				current->pid, logid);
			logid = -1; /* Try to find a free one anyway */
		}
	}
	if (logid < 0) {
		for(i = 0 ; i < REPLAY_MAX_THREADS ; i++) {
			if(prg->rg_free_logids[i]==0) {
				prp->rp_logid = i;
				prg->rg_free_logids[i] = 1;
				break;
			}
		}
		if(i == REPLAY_MAX_THREADS) {
			printk("[ERROR]Cannot allocate free logid\n");
			mutex_unlock (&prg->rg_logid_mutex);
			KFREE(prp);
			return NULL;
		}
	}
	mutex_unlock (&prg->rg_logid_mutex);

	MPRINT ("Pid %d creates new record thread: %p, recpid %lu, logid: %d\n", current->pid, prp, recpid, prp->rp_logid);

	prp->rp_record_pid = recpid;
	prp->rp_cloned_id = 0;
	prp->rp_clone_status = 0;
	prp->rp_sysrc = 0;

	// Recording log inits
	// mcc: current in-memory log segment; the log can be bigger than what we hold in memory,
	// so we just flush it out to disk when this log segment is full and reset the rp_in_ptr
	prp->rp_log = VMALLOC(sizeof(struct syscall_result)*syslog_recs);
	BUG_ON(prp->rp_log==NULL);
	prp->rp_in_ptr = 0;
	prp->rp_read_log_pos = 0;

#ifdef USE_ARGSALLOC
	// Args allocator init
	INIT_LIST_HEAD(&prp->rp_argsalloc_list);
#endif

	prp->rp_user_log_addr = 0;

	// init the clock for this thread to be kernel clock
	prp->rp_precord_clock = &prp->rp_group->rg_krecord_clock;
	
	prp->rp_ulog_opened = 0;			
	prp->rp_read_ulog_pos = 0;	
	prp->rp_repsignal_context_stack = NULL;
	prp->rp_record_hook = 0;
	prp->rp_signals = NULL;

	// XXX refcounts are probably buggy!
	get_record_group(prg);
	return prp;
}

/* Creates a new replay thread */
static struct replay_thread* 
new_replay_thread (struct replay_group* prg, struct record_thread* prec_thrd, u_long reppid, u_long out_ptr)
{
	struct replay_thread* prp = KMALLOC (sizeof(struct replay_thread), GFP_KERNEL);
	if (prp == NULL) {
		printk ("Cannot allocate replay_thread\n");
		return NULL;
	}

	MPRINT ("New replay thread %p prg %p reppid %ld\n", prp, prg, reppid);

	prp->app_syscall_addr = 0;

	prp->rp_group = prg;
	prp->rp_next_thread = prp;
	prp->rp_record_thread = prec_thrd;

	atomic_set(&prp->rp_refcnt, 1);
	prp->rp_replay_pid = reppid;
	prp->rp_out_ptr = out_ptr;
	prp->rp_replay_exit = 0;

	prp->rp_signals = NULL;

	prp->rp_saved_psr = NULL;

	prp->rp_status = REPLAY_STATUS_ELIGIBLE; // We should be able to run immediately
	init_waitqueue_head (&prp->rp_waitq);

	// Increment the refcnt of the record thread so the log isn't
	// deallocated when the record thread's done
	atomic_inc(&prp->rp_record_thread->rp_refcnt);
	MPRINT (" refcnt for record_thread %p pid %d now %d\n",
		prp->rp_record_thread,
		prp->rp_record_thread->rp_record_pid,
		atomic_read(&prp->rp_record_thread->rp_refcnt));

	// PARSPEC: add replay thread to replay_group's ds_list
	ds_list_append(prg->rg_replay_threads, prp);
	
	// init clocks
        prp->rp_preplay_clock = &prp->rp_group->rg_kreplay_clock;

	// init the sys v id mappings list
	INIT_LIST_HEAD(&prp->rp_sysv_list);

	prp->rp_status_addr = NULL;
	prp->rp_replay_hook = 0;

	get_replay_group(prg);

	return prp;
}

/* Deallocates record per-thread data and per-process data if refcnt = 0 */
static void
__destroy_record_thread (struct record_thread* prp)
{
	struct record_thread* prev;
	struct repsignal* psig;

	DPRINT ("      Pid %d __destroy_record_thread: %p\n", current->pid, prp);

	if (!atomic_dec_and_test(&prp->rp_refcnt)) {
		MPRINT ("        pid %d don't destroy record thread! pid = %d, prp = %p, refcnt=%d\n", 
			current->pid, prp->rp_record_pid, prp, atomic_read(&prp->rp_refcnt));
		return;
	}

	MPRINT ("        pid %d !YES! destroy record thread! pid = %d, prp = %p, refcnt=%d\n",
		current->pid, prp->rp_record_pid, prp, atomic_read(&prp->rp_refcnt));

	DPRINT (" destroy_record_thread freeing log %p: start\n", prp->rp_log);
	free_kernel_log (prp);
	VFREE (prp->rp_log); 
	DPRINT ("       destroy_record_thread freeing log %p: end\n", prp->rp_log);

	while (prp->rp_signals) {
		psig = prp->rp_signals;
		prp->rp_signals = psig->next;
		KFREE (psig);
	}

	for (prev = prp; prev->rp_next_thread != prp;
	     prev = prev->rp_next_thread);
	prev->rp_next_thread = prp->rp_next_thread;

	// XXX refcounts are probably buggy!
	put_record_group (prp->rp_group);

	KFREE (prp);
	MPRINT ("      Pid %d __destroy_record_thread: exit!\n", current->pid);
}

/* Deallocates replay per-thread data and per-process data iff refcnt
 * is 0.  Call with rg_lock held. */
void
__destroy_replay_thread (struct replay_thread* prp)
{
	struct replay_thread* prev;

	MPRINT ("  Pid %d enters destroy_replay_thread: pid %d, prp = %p, refcnt=%d\n", 
		current->pid, prp->rp_replay_pid, prp, atomic_read(&prp->rp_refcnt));

	if (!atomic_dec_and_test(&prp->rp_refcnt)) {
		DPRINT ("  -> pid %d don't destroy replay prp = %p, refcnt=%d!!\n", 
			current->pid, prp, atomic_read(&prp->rp_refcnt));
		return;
	}

	for (prev = prp; prev->rp_next_thread != prp;
	     prev = prev->rp_next_thread);
	prev->rp_next_thread = prp->rp_next_thread;

	// remove sys mappings
	delete_sysv_mappings (prp);

	BUG_ON (ds_list_remove(prp->rp_group->rg_replay_threads, prp) == NULL);

	// Decrement the record thread's refcnt and maybe destroy it.
	__destroy_record_thread (prp->rp_record_thread);

	MPRINT ("  Pid %d exits destroy_replay_thread: pid %d, prp = %p\n", 
		current->pid, prp->rp_replay_pid, prp);

	KFREE (prp);
}

struct task_struct *
copy_process (unsigned long clone_flags, unsigned long stack_start, 
	      struct pt_regs *regs, unsigned long stack_size,
	      int __user *child_tidptr, struct pid* pid); /* In fork.c */

asmlinkage void ret_from_fork_2(void) __asm__("ret_from_fork_2");
void set_tls_desc(struct task_struct *p, int idx, const struct user_desc *info, int n); /* In tls.c */
void fill_user_desc(struct user_desc *info, int idx, const struct desc_struct *desc); /* In tls.c */

struct pt_regs* 
get_pt_regs(struct task_struct* tsk)
{
	u_long regs;

	if (tsk == NULL) {
		regs = (u_long) &tsk;
	} else {
		regs = (u_long) (tsk->thread.sp);
	}
	regs &= (~(THREAD_SIZE - 1));
	regs += THREAD_SIZE;
	regs -= (8 + sizeof(struct pt_regs));
	return (struct pt_regs *) regs;
}

void
dump_user_stack (void)
{
	u_long __user * p;
	u_long a, v;
	int i = 0;

	struct pt_regs* regs = get_pt_regs (NULL);
	printk ("sp is %lx\n", regs->sp);
	p = (u_long __user *) regs->sp;
	do {
		get_user (v, p);
		get_user (a, p+1);
		printk ("frame %d (%p) address 0x%08lx\n", i, p, a);
		if (v <= (u_long) p) {
			printk ("ending stack trace, v=0x%07lx\n", v);
			p = 0;
		} else {
			p = (u_long __user *) v;
			i++;
		}
	} while (p);
	p = (u_long __user *) regs->sp;
	for (i = 0; i < 250; i++) {
		get_user (v, p);
		printk ("value at address %p is 0x%08lx\n", p, v);
		p++;
	}
}

static void 
__syscall_mismatch (struct record_group* precg)
{
	precg->rg_mismatch_flag = 1;
	rg_unlock (precg);
	// Try to dump user stack
	//dump_user_stack ();
	printk ("SYSCALL MISMATCH\n");
	sys_exit_group(0);
}

long syscall_mismatch (void)
{
	struct record_group* prg = current->replay_thrd->rp_group->rg_rec_group;
	rg_lock (prg);
	__syscall_mismatch(prg);
	return 0; // Should never actually return
}

void
print_vmas (struct task_struct* tsk)
{
	struct vm_area_struct* mpnt;

	printk ("vmas for task %d mm %p\n", tsk->pid, tsk->mm);
	down_read (&tsk->mm->mmap_sem);
	for (mpnt = tsk->mm->mmap; mpnt; mpnt = mpnt->vm_next) {
		printk ("VMA start %lx end %lx\n", mpnt->vm_start, mpnt->vm_end);
	}
	up_read (&tsk->mm->mmap_sem);
}

static void
create_used_address_list (void)
{
	struct vm_area_struct* mpnt;
	struct reserved_mapping* pmapping;

	current->replay_thrd->rp_group->rg_used_address_list = ds_list_create (NULL, 0, 1);
	down_read (&current->mm->mmap_sem);
	for (mpnt = current->mm->mmap; mpnt; mpnt = mpnt->vm_next) {
		pmapping = KMALLOC(sizeof(struct reserved_mapping), GFP_KERNEL);
		if (pmapping == NULL) {
			printk ("Cannot allocate new reserved mapping\n");
			return;
		}
		pmapping->m_begin = mpnt->vm_start;
		pmapping->m_end = mpnt->vm_end;
		if (mpnt->vm_start <= current->mm->start_brk && mpnt->vm_end >= current->mm->brk) {
			DPRINT ("Heap runs from %lx to %lx\n", mpnt->vm_start, mpnt->vm_end);
			DPRINT ("Expanding end to %lx\n", current->replay_thrd->rp_group->rg_max_brk);
			pmapping->m_end = current->replay_thrd->rp_group->rg_max_brk;
		}
		ds_list_append (current->replay_thrd->rp_group->rg_used_address_list, pmapping);
	}
	up_read (&current->mm->mmap_sem);
}

void ret_from_fork_replay (void)
{
	struct replay_thread* prept = current->replay_thrd;
	int ret;

	/* Nothing to do unless we need to support multiple threads */
	MPRINT ("Pid-%d ret_from_fork_replay\n", current->pid);
	ret = wait_event_interruptible_timeout (prept->rp_waitq, prept->rp_status == REPLAY_STATUS_RUNNING, SCHED_TO);
	if (ret == 0) printk ("Replay pid %d timed out waiting for cloned thread to go\n", current->pid);
	if (ret == -ERESTARTSYS) printk ("Pid %d: ret_from_fork_replay cannot wait due to signal - try again\n", current->pid);
	if (prept->rp_status != REPLAY_STATUS_RUNNING) {
		MPRINT ("Replay pid %d woken up during clone but not running.  We must want it to die\n", current->pid);
		sys_exit (0);
	}
	MPRINT ("Pid %d-done with ret_from_fork_replay\n", current->pid);
}

long
get_used_addresses (struct used_address __user * plist, int listsize)
{
	struct reserved_mapping* pmapping;
	ds_list_iter_t* iter;
	long rc = 0;
	
	if (current->replay_thrd == NULL || current->replay_thrd->rp_group->rg_used_address_list == NULL) return -EINVAL;

	iter = ds_list_iter_create (current->replay_thrd->rp_group->rg_used_address_list);
	while ((pmapping = ds_list_iter_next (iter)) != NULL) {
		if (listsize > 0) {
			put_user (pmapping->m_begin, &plist->start);
			put_user (pmapping->m_end, &plist->end);
			plist++;
			listsize--;
			rc++;
		} else {
			printk ("get_used_addresses: not enough room to return all mappings\n");
			rc = -EINVAL;
		}
	}
	ds_list_iter_destroy (iter);
	return rc;
}
EXPORT_SYMBOL(get_used_addresses);

static void
reserve_memory (u_long addr, u_long len)
{
	struct reserved_mapping* pmapping, *nmapping;
	ds_list_iter_t* iter;

	len = (len % PAGE_SIZE == 0) ? len : len - (len % PAGE_SIZE) + PAGE_SIZE; // pad to nearest page size
	MPRINT ("Inserting reserved memory from %lx to %lx\n", addr, addr+len);

	iter = ds_list_iter_create (current->replay_thrd->rp_group->rg_reserved_mem_list);
	while ((pmapping = ds_list_iter_next (iter)) != NULL) {
		MPRINT ("Mapping: %08lx-%08lx\n", pmapping->m_begin, pmapping->m_end);
		if (pmapping->m_end >= addr && pmapping->m_begin <= addr+len) {
			MPRINT ("Overlap - merge the two regions\n");
			if (addr < pmapping->m_begin) pmapping->m_begin = addr;
			if (addr + len > pmapping->m_end) pmapping->m_end = addr + len;
			// Check if subsequent regions need to be merged
			while ((nmapping = ds_list_iter_next (iter)) != NULL) {
				MPRINT ("Next mapping: %08lx-%08lx\n", nmapping->m_begin, nmapping->m_end);
				if (nmapping->m_begin <= pmapping->m_end) {
					MPRINT ("Subsumed - join it\n");
					if (nmapping->m_end > pmapping->m_end) pmapping->m_end = nmapping->m_end;
					ds_list_remove (current->replay_thrd->rp_group->rg_reserved_mem_list, nmapping);
				} else {
					break;
				}
			}
			ds_list_iter_destroy (iter);
			return;
		} else if (pmapping->m_begin > addr+len) {
			MPRINT ("No need to look further\n");
			break;
		}
	}
	ds_list_iter_destroy (iter);

	// No conflicts - add a new mapping
	pmapping = KMALLOC(sizeof(struct reserved_mapping), GFP_KERNEL);
	if (pmapping == NULL) {
		printk ("Cannot allocate new reserved mapping\n");
		return;
	}
	pmapping->m_begin = addr;
	pmapping->m_end = addr + len;
	ds_list_insert (current->replay_thrd->rp_group->rg_reserved_mem_list, pmapping);
}

/* Reads all the replay logs (including children and populates the list of memory to preallocate */
static long 
read_prealloc_info (struct record_thread* prect, int root_pid)
{
	struct syscall_result* psr; // buffer we will use to read in the logs
	ds_list_t* log_queue;
	int log_pid, syscall_count, rc, i;
	loff_t pos;
	u_long max_brk = 0, brk_val;

	psr = VMALLOC (sizeof(struct syscall_result)*syslog_recs);
	if (psr == NULL) {
		printk ("read_prealloc_info: cannot allocate syscall buffer\n");
		return -ENOMEM;
	}

	log_queue = ds_list_create (NULL, 0, 1);
	if (log_queue == NULL) {
		printk ("read_prealloc_info: cannot create log queue\n");
		return -ENOMEM;
	}
	ds_list_insert (log_queue, (void *) root_pid);

	// traverse log
	while ((log_pid = (int) ds_list_get_first (log_queue)) != 0) {

		pos = 0;
		do {
			rc = read_log_data_internal (prect, psr, log_pid, &syscall_count, &pos);
			MPRINT ("Read %d syscalls for record pid %d into in-memory buffer, pos at %ld\n", syscall_count, log_pid, (long) pos);
			if (syscall_count > 0) {

				// this while loop reads an in-memory segment of the log
				for (i = 0; i < syscall_count; i++) {
					if (psr[i].sysnum == 120) { // Clone
						MPRINT ("\tsysnum 120 with rc %ld clock (%ld,%ld)\n", psr[i].retval, psr[i].start_clock, psr[i].stop_clock);
						if (psr[i].retval > 0) ds_list_insert (log_queue, (void *) psr[i].retval);
					} else 	if (psr[i].sysnum == 192) { // mmap
						struct mmap_pgoff_args* args = psr[i].args;
						MPRINT ("\tsysnum 192 addr %lx len %lx clock (%ld,%ld)\n", (u_long) psr[i].retval, args->len, psr[i].start_clock, psr[i].stop_clock);
						if (((u_long) psr[i].retval) > 0) reserve_memory (psr[i].retval, args->len);
					} else if (psr[i].sysnum == 45) { // brk
						brk_val = psr[i].retval;
						if (brk_val > max_brk) max_brk = brk_val;
					} else if (psr[i].sysnum == 117) { // ipc
						struct shmat_retvals* retparams = (struct shmat_retvals *) psr[i].retparams;
						if (retparams->ipc_rv.call == SHMAT) {
							DPRINT ("\tsysnum 117 shmat addr %lx len %x clock (%ld,%ld)\n", retparams->addr, retparams->size, psr[i].start_clock, psr[i].stop_clock);
							reserve_memory (retparams->addr, retparams->size);
						}
					}
				}
				free_kernel_log_internal (psr, syscall_count);
			}
		} while (syscall_count > 0);
	}
	ds_list_destroy (log_queue);
	DPRINT ("Max break is %lx\n", max_brk);
	current->replay_thrd->rp_group->rg_max_brk = max_brk;
	VFREE (psr);

	return 0;
}

// Actually preallocates a region of memory
static long
do_preallocate (u_long start, u_long end)
{
	u_long retval;

	MPRINT ("preallocating mmap_pgoff with address %lx and len %lx\n", start, end-start);
	retval = sys_mmap_pgoff (start, end-start, 1, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
	if (start != retval) {
		printk ("preallocating mmap_pgoff returns different value %lx than %lx\n", retval, start);
		return -1;
	}
	
	return 0;
}

// Preallocate any reserved regions that do not conflict with the existing mappings
static void 
preallocate_memory (void)
{
	struct vm_area_struct* vma;
	ds_list_iter_t* iter;
	struct reserved_mapping* pmapping;
	u_long begin_at;

	iter = ds_list_iter_create (current->replay_thrd->rp_group->rg_reserved_mem_list);
	while ((pmapping = ds_list_iter_next (iter)) != NULL) {
		MPRINT ("Considering pre-allocation from %lx to %lx\n", pmapping->m_begin, pmapping->m_end);

		// Any conflicting VMAs?
		down_read (&current->mm->mmap_sem);
		begin_at = pmapping->m_begin;
		for (vma = current->mm->mmap; vma; vma = vma->vm_next) {
			MPRINT ("\tConsider vma from %lx to %lx\n", vma->vm_start, vma->vm_end);
			if (vma->vm_start > pmapping->m_end) {
				up_read (&current->mm->mmap_sem);
				do_preallocate (begin_at, pmapping->m_end);  // No more mappings that will conflict
				down_read (&current->mm->mmap_sem);
				break;
			}
			if (vma->vm_end > begin_at && vma->vm_start < pmapping->m_end) {
				MPRINT ("\tConflict\n");
				if (vma->vm_start > begin_at) {
					up_read (&current->mm->mmap_sem);
					do_preallocate (begin_at, vma->vm_start); // Allocate region before VM region
					down_read (&current->mm->mmap_sem);
				}
				if (vma->vm_end < pmapping->m_end) { 
					begin_at = vma->vm_end; // Consider area after VM region only
					MPRINT ("\tConsidering only from %lx now\n", begin_at);
				} else {
					break;
				}
			}
		}	
		up_read (&current->mm->mmap_sem);
	}
	ds_list_iter_destroy (iter);
}

// Need to re-establish preallcoations (if needed) after a deallocation such as a munmap
static void 
preallocate_after_munmap (u_long addr, u_long len)
{
	ds_list_iter_t* iter;
	struct reserved_mapping* pmapping;
	u_long begin, end;

	len = (len % PAGE_SIZE == 0) ? len : len - (len % PAGE_SIZE) + PAGE_SIZE; // pad to nearest page size
	MPRINT ("Re-allocating reserved memory as needed from %lx to %lx\n", addr, addr+len);

	iter = ds_list_iter_create (current->replay_thrd->rp_group->rg_reserved_mem_list);
	while ((pmapping = ds_list_iter_next (iter)) != NULL) {
		MPRINT ("pre-allocation from %lx to %lx\n", pmapping->m_begin, pmapping->m_end);
		if (pmapping->m_begin > addr+len) break; // No more mappings will matter
		if (pmapping->m_begin <= addr+len && pmapping->m_end >= addr) {
			MPRINT ("Overlap\n");
			begin = (pmapping->m_begin > addr) ? pmapping->m_begin : addr;
			end = (pmapping->m_end < addr+len) ? pmapping->m_end : addr+len;
			do_preallocate (begin, end);
		}
	}
	ds_list_iter_destroy (iter);
}

#ifdef USE_ARGSALLOC
static struct argsalloc_node* new_argsalloc_node (void* slab)
{
	struct argsalloc_node* new_node;
	new_node = KMALLOC (sizeof(struct argsalloc_node), GFP_KERNEL);
	if (new_node == NULL) {
		printk ("new_argalloc_node: Cannot allocate struct argsalloc_node\n");
		return NULL;
	}

	new_node->head = slab;
	new_node->pos = slab;
	//new_node->list should be init'ed in the calling function

	return new_node;
}

/*
 * Adds another slab for args/retparams/signals allocation,
 * if no slab exists, then we create one */ 
static int add_argsalloc_node (struct record_thread* prect, void* slab) { 
	struct argsalloc_node* new_node;
	new_node = new_argsalloc_node(slab);
	if (new_node == NULL) {
		printk("Pid %d add_argsalloc_node: could not create new argsalloc_node\n", prect->rp_record_pid);
		return -1;
	}

	// Add to front of the list
	MPRINT ("Pid %d add_argsalloc_node: adding an args slab to record_thread\n", prect->rp_record_pid);
	list_add(&new_node->list, &prect->rp_argsalloc_list);
	return 0;
}


static void* argsalloc (size_t size)
{
	void* ptr;
	struct record_thread* prect;
	struct argsalloc_node* node;
	prect = current->record_thrd;

#ifdef REPLAY_PARANOID
	if (size > argsalloc_size) {
		printk ("Pid %d size is %u but argsalloc_size is %d, try increasing argsalloc_size\n", current->pid, size, argsalloc_size);
		return NULL;
	}
#endif

	node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);

	// check to see if we've allocated a slab and if we have enough space left in the slab
	if (unlikely(list_empty(&prect->rp_argsalloc_list) || ((node->head + argsalloc_size - node->pos) < size))) {
		int rc;
		void* slab;

		MPRINT ("Pid %d argsalloc: not enough space left in slab, allocating new slab\n", current->pid);
		
		slab = VMALLOC(argsalloc_size);
		if (slab == NULL) {
			printk ("Pid %d argsalloc: couldn't alloc slab\n", current->pid);
			return NULL;
		}
		rc = add_argsalloc_node(current->record_thrd, slab);
		if (rc) {
			printk("Pid %d argalloc: problem adding argsalloc_node\n", current->pid);
			VFREE(slab);
			return NULL;
		}
		// get the new first node of the linked list
		node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
		ptr = node->pos;
		node->pos += size;
		return ptr;
	}

	// return pointer and then advance
	ptr = node->pos;
	node->pos += size;

	DPRINT ("Pid %d argsalloc: size %u, slab head %p, return ptr %p, new pos %p\n", current->pid, size, node->head, ptr, node->pos);

	return ptr;
}

/*
 * Adding support for freeing...
 * The only use case for this is in case of an error (like copying from user)
 * and the allocated memory needs to be freed
 */
static void argsfree (const void* ptr, size_t size)
{
	struct record_thread* prect;
	struct argsalloc_node* ra_node;
	prect = current->record_thrd;
	ra_node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
	
	if (ptr == NULL) 
		return;
	
	if (ra_node->head == ra_node->pos)
		return;

	// simply rollback allocation (there is the rare case where allocation has
	// created a new slab, but in that case we simply roll back the allocation 
	// and keep the slab since calling argsfree itself is rare)
	if ((ra_node->pos - size) >= ra_node->head) {
		ra_node->pos -= size;
		return;
	} else {
		printk("Pid %d argsfree: unhandled case\n", current->pid);
		return;
	}
}
#endif

#if 0
// functiosn to keep track of the sysv identifiers, since we always want to return the record identifier
static int add_sysv_mapping (struct replay_thread* prt, int record_id, int replay_id) { 
	struct sysv_mapping* tmp;
	tmp = KMALLOC(sizeof(struct sysv_mapping), GFP_KERNEL); 
	if (tmp == NULL) {
		printk("Pid %d (recpid %d) add_sysv_mapping: could not create new sysv_mapping\n", current->pid, prt->rp_record_thread->rp_record_pid);
		return -1;
	}
	tmp->record_id = record_id;
	tmp->replay_id = replay_id;

	// Add to front of the list
	MPRINT ("Pid %d (recpid %d) add_sysv_mapping: adding a SYS V ID mapping\n", current->pid, prt->rp_record_thread->rp_record_pid);
	list_add(&tmp->list, &prt->rp_sysv_list);
	return 0;
}

// returns -1 if there is no mapping
static int find_sysv_mapping (struct replay_thread* prt, int record_id) {
	struct sysv_mapping* tmp;
	list_for_each_entry (tmp, &prt->rp_sysv_list, list) {
		if (tmp->record_id == record_id) {
			DPRINT ("Pid %d (recpid %d) found sysv replay_id %d for sysv record_id %d\n", current->pid, prt->rp_record_thread->rp_record_pid, tmp->replay_id, record_id);
			return tmp->replay_id;
		}
	}
	return -1;
}
#endif

static void delete_sysv_mappings (struct replay_thread* prt) {
	struct sysv_mapping* tmp;
	struct sysv_mapping* tmp_safe;
	list_for_each_entry_safe (tmp, tmp_safe, &prt->rp_sysv_list, list) {
		list_del(&tmp->list);
		KFREE(tmp);
	}
}

/* A pintool uses this for specifying the start of the thread specific data structure.  The function returns the pid on success */
int set_pin_address (u_long pin_address)
{
	if (current->replay_thrd) {
		MPRINT ("set_pin_address: pin address is %lx\n", pin_address);
		current->replay_thrd->app_syscall_addr = pin_address;
		if (current->replay_thrd->rp_record_thread) {
			return current->replay_thrd->rp_record_thread->rp_record_pid;
		}
	}

	printk ("set_pin_address called for something that is not a replay process\n");
	return -EINVAL;
}
EXPORT_SYMBOL(set_pin_address);

long get_log_id (void)
{
	if (current->replay_thrd) {
		return current->replay_thrd->rp_record_thread->rp_record_pid;
	} else {
		printk ("get_log_id called by a non-replay process\n");
		return -EINVAL;
	}
}
EXPORT_SYMBOL(get_log_id);

/* This function forks off a separate process which replays the
   foreground task.*/
int fork_replay (char* logdir, const char __user *const __user *args, const char __user *const __user *env, u_int uid, char __user * linker, int fd)
{
	struct record_group* prg;
	long retval;
	char ckpt[MAX_LOGDIR_STRLEN+10];
	const char __user * pc;
	char* filename;
#ifdef USE_ARGSALLOC
	void* slab;
#endif

	MPRINT ("in fork_replay for pid %d\n", current->pid);

	if (atomic_read (&current->mm->mm_users) > 1) {
		printk ("fork with multiple threads is not currently supported\n");
		return -EINVAL;
	}

	// Create a record_group structure for this task
	prg = new_record_group (logdir);
	if (prg == NULL) return -ENOMEM;

	current->record_thrd = new_record_thread(prg, current->pid, -1);
	if (current->record_thrd == NULL) {
		destroy_record_group(prg);
		return -ENOMEM;
	}
#ifdef USE_ARGSALLOC
	// allocate a slab for retparams
	slab = VMALLOC (argsalloc_size);
	if (slab == NULL) return -ENOMEM;
	if (add_argsalloc_node(current->record_thrd, slab)) {
		VFREE (slab);
		destroy_record_group(prg);
		current->record_thrd = NULL;
		printk ("Pid %d fork_replay: error adding argsalloc_node\n", current->pid);
		return -ENOMEM;
	}
	MPRINT ("fork_replay added new slab %p to record_thread %p\n", slab, current->record_thrd);
#endif
	current->replay_thrd = NULL;
	MPRINT ("Record-Pid %d, tsk %p, prp %p\n", current->pid, current, current->record_thrd);

	if (linker) {
		strncpy (current->record_thrd->rp_group->rg_linker, linker, MAX_LOGDIR_STRLEN);
		MPRINT ("Set linker for record process to %s\n", linker);
	}

	if (uid) {
		retval = sys_setuid (uid);
		if (retval < 0) {
			printk ("replay_fork: unable to setuid to %d, rc=%ld\n", uid, retval);
		} else {
			MPRINT ("Set uid to %d\n", uid);
		}
	}

	retval = sys_close (fd);
	if (retval < 0) printk ("replay_fork: unable to close fd %d, rc=%ld\n", fd, retval);

	// Save reduced-size checkpoint with info needed for exec
	sprintf (ckpt, "%s/ckpt", prg->rg_logdir);
	retval = replay_checkpoint_to_disk (ckpt, args, env);
	if (retval) {
		printk ("replay_checkpoint_to_disk returns %ld\n", retval);
		return retval;
	}

	// Finally do exec from which we should not return
	get_user (pc, args);
	filename = getname(pc);
	if (IS_ERR(filename)) {
		printk ("fork_replay: unable to copy exec filname\n");
		return -EINVAL;
	}

	retval = record_execve (filename, args, env, get_pt_regs (NULL));
	if (retval) printk ("fork_replay: execve returns %ld\n", retval);
	return retval;
}

EXPORT_SYMBOL(fork_replay);

char*
get_linker (void)
{
	if (current->record_thrd) {
		return current->record_thrd->rp_group->rg_linker;
	} else if (current->replay_thrd) {
		return current->replay_thrd->rp_group->rg_rec_group->rg_linker;
	} else {
		printk ("Cannot get linker for non record/replay process\n");
		return NULL;
	}
}

long
replay_ckpt_wakeup (int attach_pin, char* logdir, char* linker, int fd)
{
	struct record_group* precg; 
	struct record_thread* prect;
	struct replay_group* prepg;
	struct replay_thread* prept;
	long record_pid, rc;
	char ckpt[MAX_LOGDIR_STRLEN+10];
	char** args;
	char** env;
	mm_segment_t old_fs = get_fs();

	MPRINT ("In replay_ckpt_wakeup\n");

	// First create a record group and thread for this replay
	precg = new_record_group (logdir);
	if (precg == NULL) return -ENOMEM;

	prect = new_record_thread(precg, 0, -1);
	if (prect == NULL) {
		destroy_record_group(precg);
		return -ENOMEM;
	}

	prepg = new_replay_group (precg);
	if (prepg == NULL) {
		destroy_record_group(precg);
		return -ENOMEM;
	}

	prept = new_replay_thread (prepg, prect, current->pid, 0);
	if (prept == NULL) {
		destroy_replay_group (prepg);
		destroy_record_group (precg);
		return -ENOMEM;
	}
	prept->rp_status = REPLAY_STATUS_RUNNING;
	// Since there is no recording going on, we need to dec record_thread's refcnt
	atomic_dec(&prect->rp_refcnt);
	
	// Restore the checkpoint
	strcpy (ckpt, logdir);
	strcat (ckpt, "/ckpt");

	record_pid = replay_resume_from_disk(ckpt, &args, &env);
	if (record_pid < 0) return record_pid;

	// Read in the log records 
	prect->rp_record_pid = record_pid;
	rc = read_log_data (prect);
	if (rc < 0) return rc;

	// Create a replay group and thread for this process
	current->replay_thrd = prept;
	current->record_thrd = NULL;

	if (linker) {
		strncpy (current->replay_thrd->rp_group->rg_rec_group->rg_linker, linker, MAX_LOGDIR_STRLEN);
		DPRINT ("Set linker for replay process to %s\n", linker);
	}

	// XXX mcc: if pin, set the process to sleep, so that we can manually attach pin
	// We would then have to wake up the process after pin has been attached.
	if (attach_pin) {
		prept->app_syscall_addr = 1;  // Will be set to actual value later
		
		read_prealloc_info (prect, record_pid); // Read in memory to be prealloated
		preallocate_memory (); // Actually do the prealloaction for this process

		printk ("Pid %d sleeping in order to let you attach pin\n", current->pid);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}

	rc = sys_close (fd);
	if (rc < 0) {
		printk ("replay_ckpt_wakeup: unable to close fd %d, rc=%ld\n", fd, rc);
	} else {
		MPRINT ("replay_ckpt_wakeup: closed fd %d\n", fd);
	}

	set_fs(KERNEL_DS);
	rc = replay_execve (args[0], (const char* const *) args, (const char* const *) env, get_pt_regs (NULL));
	set_fs(old_fs);
	if (rc < 0) printk ("replay_ckpt_wakeup: replay_execve of <%s> returns %ld\n", args[0], rc);
	return rc;
}
EXPORT_SYMBOL(replay_ckpt_wakeup);

static inline long
__new_syscall_enter (long sysnum, void* args)
{
	struct syscall_result* psr;
	struct record_thread* prt = current->record_thrd;


#ifdef MCPRINT
	if (replay_min_debug || replay_debug) {
		MPRINT ("Pid %d add syscall %ld enter\n", current->pid, sysnum);
	}
#endif

	if (unlikely (prt->rp_in_ptr == syslog_recs)) {
		/* Filled up log - write it out.  May be better to do this asynchronously */
		// mcc: Are there complications with doing this asynchronously?
		// I can think of a corner case with scheduling this asynchronously,
		// since two asychrnonously scheduled tasks are not guaranteed ordering,
		// we could potentially write out the log in the wrong order.
		// An even worse case of writing out asynchronously is that we only have
		// one syscall_result array in record_thread, so the next system call might
		// overwrite this log before the writout occurs
		MPRINT ("Pid %d - log is full - writing out %d syscalls\n", current->pid, syslog_recs);
		write_and_free_kernel_log (prt);
		prt->rp_in_ptr = 0;
	}

	psr = &prt->rp_log[prt->rp_in_ptr]; 
	psr->signal = NULL;
	psr->sysnum = sysnum;
	psr->args = args;
	psr->retparams = NULL;
	psr->retval = 0;
	psr->start_clock = atomic_add_return (1, prt->rp_precord_clock) - 1;
	psr->stop_clock = -1;
#ifdef USE_HPC
	psr->hpc_begin = rdtsc(); // minus cc_calibration
#endif

	return 0;
}

#define new_syscall_enter(s,a) __new_syscall_enter (s,NULL)

long new_syscall_enter_external (long sysnum)
{
	return __new_syscall_enter (sysnum, NULL);
}

static inline long
new_syscall_exit (long sysnum, long retval, void* retparams)
{
	struct syscall_result* psr;
	struct record_thread* prt = current->record_thrd;

	psr = &prt->rp_log[prt->rp_in_ptr];
	psr->retval = retval;
	psr->retparams = retparams;
#ifdef USE_HPC
	psr->hpc_end = rdtsc();
#endif
	psr->stop_clock = atomic_add_return (1, prt->rp_precord_clock) - 1;
	if (prt->rp_signals) signal_wake_up (current, 0); // we want to deliver signals when this syscall exits

#ifdef MCPRINT
	if (replay_min_debug || replay_debug) {
		MPRINT ("Pid %d add syscall %d exit\n", current->pid, psr->sysnum);
	}
#endif
	prt->rp_in_ptr += 1;
	return 0;
}

long new_syscall_exit_external (long sysnum, long retval, void* retparams)
{
	return new_syscall_exit (sysnum, retval, retparams);
}

int
get_record_pending_signal (siginfo_t* info)
{
	struct record_thread* prt = current->record_thrd;
	struct repsignal* psignal;
	int signr;

	if (!prt->rp_signals) {
		printk ("get_record_pending_signal: no signal to return\n");
		return 0;
	}
	MPRINT ("Delivering deferred signal now\n");
	psignal = prt->rp_signals;
	prt->rp_signals = psignal->next;
	memcpy (info, &psignal->info, sizeof (siginfo_t));
	signr = psignal->signr;
	KFREE(psignal);

	return signr;
}

// mcc: Called with current->sighand->siglock held and local interrupts disabled
long
record_signal_delivery (int signr, siginfo_t* info, struct k_sigaction* ka)
{
	struct record_thread* prt = current->record_thrd;
	struct repsignal* psignal, *tmp;
	struct syscall_result* psr = &prt->rp_log[(prt->rp_in_ptr-1)]; 
	struct repsignal_context* pcontext;
	struct pthread_log_head* phead = (struct pthread_log_head __user *) prt->rp_user_log_addr;
	int ignore_flag, need_fake_calls;
	int sysnum = syscall_get_nr(current, get_pt_regs(NULL));

	get_user (ignore_flag, current->record_thrd->rp_ignore_flag_addr); 
        MPRINT ("Pid %d recording signal delivery signr %d - clock is currently %d ignore flag %d handler %p\n", current->pid, signr, atomic_read(prt->rp_precord_clock), ignore_flag, ka->sa.sa_handler);

	if (ignore_flag) {
		// Signal delivered after an ignored syscall.  We need to add a "fake" syscall for sequencing.  
		__new_syscall_enter (SIGNAL_WHILE_SYSCALL_IGNORED, NULL); 
		new_syscall_exit (SIGNAL_WHILE_SYSCALL_IGNORED, 0, NULL);

                // Also, let the user-level know to make syscall on replay by incrementing count in ignore_flag
		get_user (need_fake_calls, &phead->need_fake_calls);
		need_fake_calls++;
		put_user (need_fake_calls, &phead->need_fake_calls);
		MPRINT ("record_signal inserts fake syscall - ignore_flag now %d, need_fake_calls now %d\n", ignore_flag, need_fake_calls); 
	}

	if (signr != 9 && sysnum != psr->sysnum) {
		// This is an unrecorded system call or a trap.  Since we cannot guarantee that the signal will not delivered
		// at this same place on replay, delay the delivery until we reach such a safe place.  Signals that immediately
		// terminate the program do not need to be delayed, however.
		MPRINT ("Not a safe place to record a signal - syscall is %d but last recorded syscall is %d\n", sysnum, psr->sysnum);
		psignal = KMALLOC(sizeof(struct repsignal), GFP_KERNEL); // XXX: this can block
		if (psignal == NULL) {
			printk ("Cannot allocate replay signal\n");
			return 0;  // Replay broken - but might as well let recording proceed
		}
		psignal->signr = signr;
		memcpy (&psignal->info, info, sizeof(siginfo_t));
		psignal->next = prt->rp_signals;
		prt->rp_signals = psignal;
		return -1;
	}

	// mcc: KMALLOC with REPLAY_PARANOID on grabs a mutex...
	psignal = ARGSKMALLOC(sizeof(struct repsignal), GFP_KERNEL); // XXX: this can block
	if (psignal == NULL) {
		printk ("Cannot allocate replay signal\n");
		return 0;  // Replay broken - but might as well let recording proceed
	}
	psignal->signr = signr;
	memcpy (&psignal->info, info, sizeof(siginfo_t));
	memcpy (&psignal->ka, ka, sizeof(struct k_sigaction)); 
	psignal->blocked = current->blocked;
	psignal->real_blocked = current->real_blocked;
	psignal->next = NULL;
	
	// Add signal to last record in log - will be delivered after syscall on replay
	if (psr->signal == NULL) 
		psr->signal = psignal;
	else {
		// Add to tail of list
		tmp = psr->signal;
		while (tmp->next != NULL) tmp = tmp->next;
		tmp->next = psignal;
	}

	if (ka->sa.sa_handler > SIG_IGN) {
		// Also save context from before signal
		pcontext = KMALLOC (sizeof(struct repsignal_context), GFP_ATOMIC);
		pcontext->ignore_flag = ignore_flag;
		pcontext->next = prt->rp_repsignal_context_stack;
		prt->rp_repsignal_context_stack = pcontext;
		// If we were in an ignore region, that is no longer the case
		put_user (0, prt->rp_ignore_flag_addr); 
	}

	return 0;
}

void
replay_signal_delivery (int* signr, siginfo_t* info)
{
	struct replay_thread* prt = current->replay_thrd;
	struct repsignal* psignal;
	
	if (prt->rp_signals == NULL) {
		MPRINT ("pid %d replay_signal called but no signals, signr is %d\n", 
			current->pid, *signr);
		*signr = 0;
		return;
	}
	psignal = prt->rp_signals;
	MPRINT ("Pid %d replaying signal delivery signo %d, clock %lu\n", current->pid, psignal->signr, *(prt->rp_preplay_clock));
	prt->rp_signals = psignal->next;

	*signr = psignal->signr;
	memcpy (info, &psignal->info, sizeof (siginfo_t));
	
	if (prt->app_syscall_addr == 0) {
		MPRINT ("Pid %d No Pin attached, so setting blocked signal mask to recorded mask, and copying k_sigaction\n", current->pid);
		memcpy (&current->sighand->action[psignal->signr-1],
			&psignal->ka, sizeof (struct k_sigaction));
		current->blocked = psignal->blocked;
		current->real_blocked = psignal->real_blocked;
	}
}

int replay_has_pending_signal (void) {
	if (current->replay_thrd) {
		if (current->replay_thrd->rp_signals) {
			DPRINT ("Pid %d replay_has_pending_signals", current->pid);
			return 1;
		}
	} else if (current->record_thrd) { // recording
		struct record_thread* prt = current->record_thrd;
		int sysnum = syscall_get_nr(current, get_pt_regs(NULL));
		if (current->record_thrd->rp_signals && (sysnum == prt->rp_log[(prt->rp_in_ptr-1)].sysnum)) {
			if (sysnum == 17 || sysnum == 110 || sysnum == 119 || sysnum == 186) {
				printk ("replay_has_pending_signal: non-intercepted syscall is not safe\n");
			} else {
				DPRINT ("safe to return pending signal\n");
				return 1;
			}
		}
	}
	return 0;
}

/* Free every individual syscall record */
static void
free_kernel_log (struct record_thread *prect)
{
#ifdef USE_ARGSALLOC
	struct argsalloc_node* node;
	struct argsalloc_node* next_node;

	MPRINT ("Pid %d free_kernel_log\n", current->pid);

	if (current->record_thrd) {
		list_for_each_entry_safe (node, next_node, &prect->rp_argsalloc_list, list) {
			VFREE(node->head);
			list_del(&node->list);
			KFREE(node);	
		}
	}
	
	// we don't use slabs during replay, and the args/signals/retparams are loaded separately 
	// so we need to free the old-fashioned way
	if (current->replay_thrd) {
		MPRINT ("Pid %d going to call free_kernel_log_internal, count: %lu\n", current->pid, prect->rp_in_ptr);
		free_kernel_log_internal (prect->rp_log, prect->rp_in_ptr);
	}
#else
	free_kernel_log_internal (prect->rp_log, prect->rp_in_ptr);
#endif
}

static void
write_and_free_kernel_log(struct record_thread *prect)
{
	int fd = 0;
	struct syscall_result* write_psr;
	loff_t pos;
	struct file* file = NULL;

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	file = init_log_write (prect, prect->rp_logid, &pos, &fd);
	if (file) {
		MPRINT ("Writing %lu records for log %d\n", prect->rp_in_ptr, prect->rp_logid);
		write_psr = &prect->rp_log[0];
		write_log_data (file, &pos, prect, write_psr, prect->rp_in_ptr, prect->rp_logid);
		term_log_write (file, fd);
	}
	set_fs(old_fs);

	free_kernel_log (prect);
}

#ifdef WRITE_ASYNC
// parameters to pass to the work queue thread
struct write_async_params {
	struct work_struct work;
	struct record_thread *prect;
};

/* Handler that is called when the kernel work queue event thread is run */
static void
write_and_free_handler (struct work_struct *work)
{
	int fd = 0;
	struct syscall_result* write_psr;
	loff_t pos;
	struct file* file = NULL;
	mm_segment_t old_fs;
	struct record_thread *prect;

	struct write_async_params* awp;
	awp = (struct write_async_params*) work;
	prect = awp->prect;
	old_fs = get_fs();

	MPRINT ("Pid %d write_and_free_handler called for record pid %d\n", current->pid, prect->rp_record_pid);

	set_fs(KERNEL_DS);
	file = init_log_write (prect, prect->rp_logid, &pos, &fd);
	if (file) {
		MPRINT ("Writing %lu records for log %d\n", prect->rp_in_ptr, prect->rp_logid);
		write_psr = &prect->rp_log[0];
		write_log_data (file, &pos, prect, write_psr, prect->rp_in_ptr, prect->rp_logid);
		term_log_write (file, fd);
	}
	set_fs(old_fs);

	free_kernel_log (prect);
	 __destroy_record_thread(prect);
	KFREE(awp);
	return;
}
	
/* Write and free the kernel log asynchronously by scheduling work on the kernel work queue */
static void
write_and_free_kernel_log_async (struct record_thread *prect)
{
	struct write_async_params* wap;
	wap = KMALLOC(sizeof(struct write_async_params), GFP_KERNEL);
	wap->prect = prect;

	// increment so that we don't destroy record thread until after the handler finishes
	atomic_inc(&prect->rp_refcnt);
	INIT_WORK((struct work_struct*) wap, write_and_free_handler);
	schedule_work((struct work_struct*) wap);
	MPRINT ("Pid %d scheduled write_and_free_handler\n", current->pid);
}
#endif

/* Writes out the user log - currently does not handle wraparound - so write in one big chunk */
long
write_user_log (struct record_thread* prect)
{
	struct pthread_log_head __user * phead = (struct pthread_log_head __user *) prect->rp_user_log_addr;
	struct pthread_log_head head;
	struct pthread_log_data __user *start;
	struct stat64 st;
	char filename[MAX_LOGDIR_STRLEN+20];
	struct file* file;
	int fd;
	mm_segment_t old_fs;
	long to_write, written;
	long rc = 0;

	// number of entries that we have seen so far
	int num_entries;

	DPRINT ("Pid %d: write_user_log %p\n", current->pid, phead);
	if (phead == 0) return 0; // Nothing to do

	if (copy_from_user (&head, phead, sizeof (struct pthread_log_head))) {
		printk ("Unable to get log head\n");
		return -EINVAL;
	}
	DPRINT ("Log current address is at %p\n", head.next); 
	start = (struct pthread_log_data __user *) ((char __user *) phead + sizeof (struct pthread_log_head));
	to_write = (char *) head.next - (char *) start;
	
	DPRINT ("Pid %d - need to write %ld bytes of user log\n", current->pid, to_write);
	if (to_write == 0) {
		printk ("Pid %d - no entries to write in ulog\n", current->pid);
		return 0;
	}

	sprintf (filename, "%s/ulog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	// see if we're appending to the user log data before
	if (prect->rp_ulog_opened) {
		DPRINT("Pid %d, ulog %s has been opened before, so we'll append\n", current->pid, filename);
		rc = sys_stat64(filename, &st);
		if (rc < 0) {
			printk ("Pid %d - write_log_data, can't append stat of file %s failed\n", current->pid, filename);
			return -EINVAL;
		}
		fd = sys_open(filename, O_RDWR|O_APPEND, 0777);
	} else {
		fd = sys_open(filename, O_RDWR|O_CREAT|O_TRUNC, 0777);
		if (fd > 0) {
			rc = sys_fchmod(fd, 0777);
			if (rc == -1) {
				printk("Pid %d fchmod failed\n", current->pid);
			}
		}
		prect->rp_ulog_opened = 1;
		rc = sys_stat64(filename, &st);
	}

	if (fd < 0) {
		printk ("Cannot open log file %s, rc =%d\n", filename, fd);
		return -EINVAL;
	}

	file = fget(fd);
	if (file == NULL) {
		printk ("write_user_log: invalid file\n");
		return -EINVAL;
	}

	// Before each user log segment, we write the number of log entries
	num_entries  = (to_write) / (sizeof(struct pthread_log_data));

	// verify that I did this right
	BUG_ON((num_entries * sizeof(struct pthread_log_data)) != (to_write));

	written = vfs_write(file, (char *) &num_entries, sizeof(int), &prect->rp_read_ulog_pos);
	set_fs(old_fs);

	if (written != sizeof(int)) {
		printk ("write_user_log: tried to write %d, got rc %ld\n", sizeof(int), written);
		rc = -EINVAL;
	}

	written = vfs_write(file, (char __user *) start, to_write, &prect->rp_read_ulog_pos);
	if (written != to_write) {
		printk ("write_user_log1: tried to write %ld, got rc %ld\n", written, to_write);
		rc = -EINVAL;
	}

	fput(file);
	DPRINT("Pid %d closing %s\n", current->pid, filename);
	sys_close (fd);

	return rc;
}

/* Reads in a user log - currently does not handle wraparound - so read in one big chunk */
long
read_user_log (struct record_thread* prect)
{
	struct pthread_log_head __user * phead = (struct pthread_log_head __user *) prect->rp_user_log_addr;
	struct pthread_log_data __user *start;
	struct stat64 st;
	char filename[MAX_LOGDIR_STRLEN+20];
	struct file* file;
	int fd;
	mm_segment_t old_fs;
	long copyed, rc = 0;

	// the number of entries in this segment
	int num_entries;

	DPRINT ("Pid %d: read_user_log %p\n", current->pid, phead);
	if (phead == 0) return -EINVAL; // Nothing to do

	start = (struct pthread_log_data __user *) ((char __user *) phead + sizeof (struct pthread_log_head));
	DPRINT ("Log start is at %p\n", start);
	
	sprintf (filename, "%s/ulog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	rc = sys_stat64(filename, &st);
	if (rc < 0) {
		printk ("Stat of file %s failed\n", filename);
		set_fs(old_fs);
		return rc;
	}
	fd = sys_open(filename, O_RDONLY, 0644);
	set_fs(old_fs);
	if (fd < 0) {
		printk ("Cannot open log file %s, rc =%d\n", filename, fd);
		return fd;
	}

	file = fget(fd);
	if (file == NULL) {
		printk ("read_user_log: invalid file\n");
		return -EINVAL;
	}

	// read how many entries that are in this segment
	set_fs(KERNEL_DS);	
	copyed = vfs_read (file, (char *) &num_entries, sizeof(int), &prect->rp_read_ulog_pos);
	set_fs(old_fs);
	if (copyed != sizeof(int)) {
		printk ("read_user_log: tried to read num entries %d, got rc %ld\n", sizeof(int), copyed);
		rc = -EINVAL;
		goto close_out;
	}

	// read the entire segment after we've read how many entries are in it
	copyed = vfs_read (file, (char __user *) start, num_entries * (sizeof(struct pthread_log_data)), &prect->rp_read_ulog_pos);
	if (copyed != num_entries * (sizeof(struct pthread_log_data))) {
		printk ("read_user_log: tried to read %d, got rc %ld\n", num_entries * (sizeof(struct pthread_log_data)), copyed);
		rc = -EINVAL;
	}

close_out:
	fput(file);
	sys_close (fd);

	return rc;
}

static inline long
get_next_syscall_enter (struct replay_thread* prt, struct replay_group* prg, int syscall, char** ppretparams, char** ppargs, struct syscall_result** ppsr)
{
	struct syscall_result* psr;
	struct replay_thread* tmp;
	long retval = 0;
	int ret;

#ifdef REPLAY_PARANOID
	if (current->replay_thrd == NULL) {
		printk ("Pid %d replaying but no log\n", current->pid);
		sys_exit(0);
	}
#endif

	rg_lock (prg->rg_rec_group);

	if (syscall == TID_WAKE_CALL && prg->rg_rec_group->rg_mismatch_flag) {
		// We are just trying to exit after a replay foul-up - just die
		*ppsr = NULL; // Lets caller know to skip the exit call.
		rg_unlock (prg->rg_rec_group);
		return 0;
	}

	MPRINT ("Replay pid %d, syscall %d\n", current->pid, syscall);
	while (prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr) {
		if (syscall == TID_WAKE_CALL) {
			// We did not record an exit so there is no record to consume - just ignore this and let the thread exit
			MPRINT ("pid %d recpid %d syscall mismatch during exit is OK - no more syscalls found\n", current->pid, prt->rp_record_thread->rp_record_pid);
			*ppsr = NULL; // Lets caller know to skip the exit call.
			rg_unlock (prg->rg_rec_group);
			return 0;
		}
		// log overflowed and we need to read in next batch of records
		printk ("Pid %d recpid %d syscall %d reached end of in-memory log -- first free the previous syscall records\n", current->pid, prt->rp_record_thread->rp_record_pid, syscall);
		free_kernel_log (prt->rp_record_thread);
		prt->rp_record_thread->rp_in_ptr = 0;
		MPRINT ("Pid %d reached end of in-memory log -- need to read in more syscall records\n", current->pid);
		read_log_data (prt->rp_record_thread);
		if (prt->rp_record_thread->rp_in_ptr == 0) {
			// There should be one record there at least
			printk ("Pid %d waiting for non-existant syscall record %d\n", current->pid, syscall);
			BUG();
		}
		prt->rp_out_ptr = 0;
	}

	psr = &prt->rp_record_thread->rp_log[prt->rp_out_ptr];

	MPRINT ("Replay Pid %d, index %ld sys %d\n", current->pid, prt->rp_out_ptr, psr->sysnum);

	if (unlikely(psr->sysnum != syscall)) {
		printk ("[ERROR]Pid %d record pid %d expected syscall %d in log, got %d, start clock %ld stop clock %ld logid %d\n", 
			current->pid, prt->rp_record_thread->rp_record_pid, syscall, 
			psr->sysnum, psr->start_clock, psr->stop_clock, prt->rp_record_thread->rp_logid);
		dump_stack();
		__syscall_mismatch (prg->rg_rec_group);
	}

	if (ppretparams) {
		*ppretparams = psr->retparams;
	} else if (unlikely(psr->retparams)) {
		printk ("Process %d not expecting return parameters, syscall %d\n", current->pid, syscall);
		__syscall_mismatch (prg->rg_rec_group);
	}
	retval = psr->retval;

	// Done with syscall record 
	prt->rp_out_ptr += 1;

	// Do this twice - once for syscall entry and once for exit
	while (*(prt->rp_preplay_clock) < psr->start_clock) {
		MPRINT ("Replay pid %d is waiting for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, psr->start_clock, *(prt->rp_preplay_clock));
		prt->rp_status = REPLAY_STATUS_WAIT_CLOCK;
		prt->rp_wait_clock = psr->start_clock;
		tmp = prt->rp_next_thread;
		do {
			DPRINT ("Consider thread %d status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock);
			if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= *(prt->rp_preplay_clock))) {
				tmp->rp_status = REPLAY_STATUS_RUNNING;
				wake_up (&tmp->rp_waitq);
				DPRINT ("Wake it up\n");
				break;
			}
			tmp = tmp->rp_next_thread;
			if (tmp == prt) {
				printk ("Pid %d (recpid %d): Crud! no elgible thread to run on syscall entry\n", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid);
				printk ("current clock value is %ld waiting for %lu\n", *(prt->rp_preplay_clock), psr->start_clock);
				dump_stack(); // how did we get here?
				// cycle around again and print
				tmp = tmp->rp_next_thread;
				while (tmp != current->replay_thrd) {
					printk("\t thread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
					tmp = tmp->rp_next_thread;
				}
				sys_exit_group (0);
			}
		} while (tmp != prt);

		while (!(prt->rp_status == REPLAY_STATUS_RUNNING || (prt->rp_replay_exit && prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr+1))) {	
			MPRINT ("Replay pid %d waiting for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, psr->start_clock, *(prt->rp_preplay_clock));
			rg_unlock (prg->rg_rec_group);
			ret = wait_event_interruptible_timeout (prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr+1), SCHED_TO);
			rg_lock (prg->rg_rec_group);
			if (ret == 0) printk ("Replay pid %d timed out waiting for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, psr->start_clock, *(prt->rp_preplay_clock));
			if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr+1))) {
				MPRINT ("Replay pid %d woken up to die on entrance in_ptr %lu out_ptr %lu\n", current->pid, prt->rp_record_thread->rp_in_ptr, prt->rp_out_ptr);
				rg_unlock (prg->rg_rec_group);
				sys_exit (0);
			}
			if (ret == -ERESTARTSYS) {
				printk ("Pid %d: entering syscall cannot wait due to signal - try again\n", current->pid);
				rg_unlock (prg->rg_rec_group);
				msleep (1000);
				rg_lock (prg->rg_rec_group);
			}
		}
	}
	(*prt->rp_preplay_clock)++;
	rg_unlock (prg->rg_rec_group);
        MPRINT ("Pid %d incremented replay clock on syscall %d entry to %ld\n", current->pid, psr->sysnum, *(prt->rp_preplay_clock));
	*ppsr = psr;
	return retval;
}

static inline void
get_next_syscall_exit (struct replay_thread* prt, struct replay_group* prg, struct syscall_result* psr)
{
	struct replay_thread* tmp;
	int ret;

	rg_lock (prg->rg_rec_group);
	while (*(prt->rp_preplay_clock) < psr->stop_clock) {
		MPRINT ("Replay pid %d is waiting for clock value %ld on syscall exit but current clock value is %ld\n", current->pid, psr->stop_clock, *(prt->rp_preplay_clock));
		prt->rp_status = REPLAY_STATUS_WAIT_CLOCK;
		prt->rp_wait_clock = psr->stop_clock;
		tmp = prt->rp_next_thread;
		do {
			DPRINT ("Consider thread %d status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock);
			if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= *(prt->rp_preplay_clock))) {
				tmp->rp_status = REPLAY_STATUS_RUNNING;
				wake_up (&tmp->rp_waitq);
				DPRINT ("Wake it up\n");
				break;
			}
			tmp = tmp->rp_next_thread;
			if (tmp == prt) {
				printk ("Pid %d: Crud! no eligible thread to run on syscall exit\n", current->pid);
				printk ("replay pid %d waiting for clock value %ld on syscall exit - current clock value is %ld\n", current->pid, psr->stop_clock, *(prt->rp_preplay_clock));
				sys_exit_group (0);
			}
		} while (tmp != prt);

		while (!(prt->rp_status == REPLAY_STATUS_RUNNING || (prt->rp_replay_exit && prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr+1))) {   
			MPRINT ("Replay pid %d waiting for clock value %ld on syscall exit but current clock value is %ld\n", current->pid, psr->stop_clock, *(prt->rp_preplay_clock));
			rg_unlock (prg->rg_rec_group);
			ret = wait_event_interruptible_timeout (prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr+1), SCHED_TO);
			rg_lock (prg->rg_rec_group);
			if (ret == 0) printk ("Replay pid %d timed out waiting for clock value %ld on syscall exit but current clock value is %ld\n", current->pid, psr->stop_clock, *(prt->rp_preplay_clock));
			if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr+1))) {
				rg_unlock (prg->rg_rec_group);
				MPRINT ("Replay pid %d woken up to die on exit\n", current->pid);
				sys_exit (0);
			}
			if (ret == -ERESTARTSYS) {
				printk ("Pid %d: exiting syscall cannot wait due to signal - try again\n", current->pid);
				rg_unlock (prg->rg_rec_group);
				msleep (1000);
				rg_lock (prg->rg_rec_group);
			}
		}
	}

	if (unlikely(psr->signal)) {
		MPRINT ("Pid %d set deliver signal flag before clock %ld incrment\n", current->pid, *(prt->rp_preplay_clock));
		prt->rp_signals = psr->signal;
		signal_wake_up (current, 0);
	}

	(*prt->rp_preplay_clock)++;
	MPRINT ("Pid %d incremented replay clock on syscall %d exit to %ld\n", current->pid, psr->sysnum, *(prt->rp_preplay_clock));

	rg_unlock (prg->rg_rec_group);
}

long
get_next_syscall_enter_external (int syscall, char** ppretparams, char** ppargs, struct syscall_result** ppsr)
{
	return get_next_syscall_enter (current->replay_thrd, current->replay_thrd->rp_group, syscall, ppretparams, ppargs, ppsr);
}

void
get_next_syscall_exit_external (struct syscall_result* psr)
{
	get_next_syscall_exit (current->replay_thrd, current->replay_thrd->rp_group, psr);
}

/* This function takes the next syscall of the current task's replay
   log, makes sure the syscall number matches, and returns the
   original return value and any optional data (if ppretparams is set).
   On an error, it calls sys_exit, and so never returns 
   */
static inline long
get_next_syscall (int syscall, char** ppretparams, char** ppargs)
{
	struct replay_thread* prt = current->replay_thrd;
	struct replay_group* prg = prt->rp_group;
	struct syscall_result* psr;
	long retval;

	retval = get_next_syscall_enter (prt, prg, syscall, ppretparams, ppargs, &psr);
	get_next_syscall_exit (prt, prg, psr);
	return retval;
}

void consume_remaining_records (void)
{
	struct syscall_result* psr;
	struct replay_thread* prt = current->replay_thrd;

	while (prt->rp_record_thread->rp_in_ptr != prt->rp_out_ptr) {
		psr = &prt->rp_record_thread->rp_log[prt->rp_out_ptr];
		MPRINT ("Pid %d recpid %d consuming unused record: sysnum %d start clock %lu stop clock %lu\n", 
			current->pid, prt->rp_record_thread->rp_record_pid, psr->sysnum, psr->start_clock, psr->stop_clock);
		get_next_syscall (psr->sysnum, NULL, NULL);
	}
	DPRINT ("Pid %d recpid %d done consuming unused records clock now %ld\n", current->pid, prt->rp_record_thread->rp_record_pid, *prt->rp_preplay_clock);
}

void record_randomness (u_long value)
{
	if (current->record_thrd->random_values.cnt < REPLAY_MAX_RANDOM_VALUES) {
		current->record_thrd->random_values.val[current->record_thrd->random_values.cnt++] = value;
	} else {
		printk ("record_randomness: exceeded maximum number of values\n");
	}
}

u_long replay_randomness (void)
{
	if (current->replay_thrd->random_values.cnt < REPLAY_MAX_RANDOM_VALUES) {
		return current->replay_thrd->random_values.val[current->replay_thrd->random_values.cnt++];
	} else {
		printk ("replay_randomness: exceeded maximum number of values\n");
		return -1;  
	}
}

/* These functions check the clock condition before and after a syscall, respectively.  We have to do this for syscalls for which
   Pin holds a lock throughout to avoid a deadlock. */
long check_clock_before_syscall (int syscall)
{
	struct replay_thread* prt = current->replay_thrd;
	int ignore_flag;

	// This should block until it is time to execute the syscall.  We must save the returned values for use in the actual system call
	DPRINT ("Pid %d pre-wait for syscall %d\n", current->pid, syscall);

	get_user (ignore_flag, current->replay_thrd->rp_record_thread->rp_ignore_flag_addr); 
	if (!ignore_flag) {						
		prt->rp_saved_rc = get_next_syscall_enter (prt, prt->rp_group, syscall, &prt->rp_saved_retparams, &prt->rp_saved_args, &prt->rp_saved_psr);
	}

	return 0;
}
EXPORT_SYMBOL(check_clock_before_syscall);

long check_clock_after_syscall (int syscall)
{
	struct replay_thread* prt = current->replay_thrd;
	int ignore_flag;

	get_user (ignore_flag, current->replay_thrd->rp_record_thread->rp_ignore_flag_addr);
	if (ignore_flag) return 0;

	// This should block until it is time to execute the syscall.  We must save the returned values for use in the actual system call
	if (prt->app_syscall_addr <= 1) {
		printk ("Pid %d calls check_clock_after_syscall, but thread not yet initialized\n", current->pid);
		return -EINVAL;
	}
	if (prt->rp_saved_psr == NULL) {
		printk ("Pid %d calls check_clock_after_syscall, but psr not saved\n", current->pid);
		return -EINVAL;
	}
	DPRINT ("Pid %d post-wait for syscall for syscall %d clock %ld\n", current->pid, prt->rp_saved_psr->sysnum, prt->rp_saved_psr->stop_clock);
	get_next_syscall_exit (prt, prt->rp_group, prt->rp_saved_psr);
	prt->rp_saved_psr = NULL;
	return 0;
}
EXPORT_SYMBOL(check_clock_after_syscall);

asmlinkage long
sys_pthread_print (const char __user * buf, size_t count)
{
	struct timeval tv;
	long clock;
	int ignore_flag;

	do_gettimeofday(&tv);
	
	if (current->replay_thrd) {
		clock = *(current->replay_thrd->rp_preplay_clock);
		printk("Pid %d recpid %5d PTHREAD:%ld:%ld.%06ld:%s", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid, clock, tv.tv_sec, tv.tv_usec, buf);
	} else if (current->record_thrd) {
		clock = atomic_read(current->record_thrd->rp_precord_clock);
		get_user (ignore_flag, current->record_thrd->rp_ignore_flag_addr); 
		printk("Pid %d recpid ----- PTHREAD:%ld:%ld.%06ld:%d:%s", current->pid, clock, tv.tv_sec, tv.tv_usec, ignore_flag, buf);
	} else {
		printk ("sys_pthread_print: pid %d is not a record/replay proces: %s\n", current->pid, buf);
		return -EINVAL;
	}

	return 0;
}

asmlinkage long
sys_pthread_init (int __user * status, u_long __user * replay_clock, u_long record_hook, u_long replay_hook)
{
	if (current->record_thrd) {
		struct record_thread* prt = current->record_thrd;
		MPRINT ("Pid %d pthread_init: User-level recording initialized to %d\n", current->pid, atomic_read(prt->rp_precord_clock));
		put_user (1, status);
		put_user (atomic_read(prt->rp_precord_clock),replay_clock);
		prt->rp_precord_clock = (atomic_t *) replay_clock;
		prt->rp_record_hook = record_hook;
		MPRINT ("Pid %d pthread_init: user clock set to %p, value is %d\n", current->pid, (replay_clock), atomic_read(prt->rp_precord_clock));
	} else if (current->replay_thrd) {
		struct replay_thread* prt = current->replay_thrd;
		MPRINT ("Pid %d pthread_init: User-level replay initialized to %ld\n", current->pid, *(prt->rp_preplay_clock));
		put_user (2, status);
		put_user (*(prt->rp_preplay_clock),replay_clock);
		prt->rp_preplay_clock = replay_clock;
		prt->rp_replay_hook = replay_hook;
	} else {
		printk ("Pid %d calls sys_pthread_init, but not a record/replay process\n", current->pid);
		return -EINVAL;
	}
	return 0;
}

asmlinkage long
sys_pthread_dumbass_link (int __user * status, u_long __user * record_hook, u_long __user * replay_hook)
{
	if (current->record_thrd) {
		struct record_thread* prt = current->record_thrd;
		if (prt->rp_record_hook) {
			put_user (1, status);
			put_user (prt->rp_record_hook, record_hook);
			MPRINT ("pid %d record hook %lx returned\n", current->pid, prt->rp_record_hook);
		}
	} else if (current->replay_thrd) {
		struct replay_thread* prt = current->replay_thrd;
		if (prt->rp_replay_hook) {
			put_user (2, status);
			put_user (prt->rp_replay_hook, replay_hook);
			MPRINT ("pid %d replay hook %lx returned\n", current->pid, prt->rp_replay_hook);
		}
	} else {
			put_user (3, status);		
	}
	return 0;
}

asmlinkage long
sys_pthread_log (u_long log_addr, int __user * ignore_addr)
{
	if (current->record_thrd) {
		current->record_thrd->rp_user_log_addr = log_addr;
		current->record_thrd->rp_ignore_flag_addr = ignore_addr;
		MPRINT ("User log info address for thread %d is %lx, ignore addr is %p\n", current->pid, log_addr, ignore_addr);
	} else if (current->replay_thrd) {
		current->replay_thrd->rp_record_thread->rp_user_log_addr = log_addr;
		current->replay_thrd->rp_record_thread->rp_ignore_flag_addr = ignore_addr;
		read_user_log (current->replay_thrd->rp_record_thread);
		MPRINT ("Read user log into address %lx for thread %d\n", log_addr, current->pid);
	} else {
		printk ("sys_prthread_log called by pid %d which is neither recording nor replaying\n", current->pid);
		return -EINVAL;
	}
	return 0;
}

asmlinkage long
sys_pthread_block (u_long clock)
{
	struct replay_thread* prt, *tmp;
	struct replay_group* prg;
	int ret;

	if (!current->replay_thrd) {
		printk ("sys_pthread_block called by non-replay process %d\n", current->pid);
		return -EINVAL;
	}
	prt = current->replay_thrd;
	prg = prt->rp_group;

	if (clock == INT_MAX) consume_remaining_records(); // Before we block forever, consume any remaining system call records

	while (*(prt->rp_preplay_clock) < clock) {
		MPRINT ("Replay pid %d is waiting for user clock value %ld but current clock value is %ld\n", current->pid, clock, *(prt->rp_preplay_clock));
		prt->rp_status = REPLAY_STATUS_WAIT_CLOCK;
		prt->rp_wait_clock = clock;
		tmp = prt->rp_next_thread;
		do {
			DPRINT ("Consider thread %d status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock);
			if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= *(prt->rp_preplay_clock))) {
				tmp->rp_status = REPLAY_STATUS_RUNNING;
				wake_up (&tmp->rp_waitq);
				break;
			}
			tmp = tmp->rp_next_thread;
			if (tmp == prt) {
				printk ("Pid %d: Crud! no elgible thread to run on user-level block\n", current->pid);
				printk ("Replay pid %d is waiting for user clock value %ld but current clock value is %ld\n", current->pid, clock, *(prt->rp_preplay_clock));
				tmp = prt->rp_next_thread;
				do {
					printk ("\tthread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
					tmp = tmp->rp_next_thread;
				} while (tmp != prt);
				sys_exit_group (0);
			}
		} while (tmp != prt);

		rg_lock (prg->rg_rec_group);
		while (!(prt->rp_status == REPLAY_STATUS_RUNNING || (prt->rp_replay_exit && prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr))) {
			MPRINT ("Replay pid %d waiting for user clock value %ld\n", current->pid, clock);
			
			rg_unlock (prg->rg_rec_group);
			ret = wait_event_interruptible_timeout (prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr), SCHED_TO);
			rg_lock (prg->rg_rec_group);
			if (ret == 0) printk ("Replay pid %d timed out waiting for user clock value %ld\n", current->pid, clock);
			if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr))) break; // exit condition below
			if (ret == -ERESTARTSYS) {
				printk ("Pid %d: blocking syscall cannot wait due to signal - try again\n", current->pid);
				rg_unlock (prg->rg_rec_group);
				msleep (1000);
				rg_lock (prg->rg_rec_group);
			}
		}
		if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr))) {
			rg_unlock (prg->rg_rec_group);
			MPRINT ("Replay pid %d woken up to die on block\n", current->pid);
			sys_exit (0);
		}
		rg_unlock (prg->rg_rec_group);
	}
        MPRINT ("Pid %d returning from user-level replay block\n", current->pid);
	return 0;
}

asmlinkage long sys_pthread_full (void)
{
	if (current->record_thrd) {
		write_user_log (current->record_thrd); 
		return 0;
	} else if (current->replay_thrd) {
		DPRINT ("Pid %d: Resetting user log\n", current->pid);
		read_user_log (current->replay_thrd->rp_record_thread);	
		return 0;
	} else {
		printk ("Pid %d: pthread_log_full only valid for replay processes\n", current->pid);
		return -EINVAL;
	}
}

asmlinkage long sys_pthread_status (int __user * status)
{
	if (current->record_thrd) {
		put_user (1, status);
	} else if (current->replay_thrd) {
		put_user (2, status);
		current->replay_thrd->rp_status_addr = status;
	} else {
		put_user (3, status);
	}
	return 0;
}

/* Asks the kernel to see if it has mapped the user-level page into
 * the user's address space yet (the kernel will have to map
 * the user-level page into the user's address space after
 * an exec, and the user needs to know whether or not the kernel
 * has done this yet). 
 *
 * If it has it returns 1 and sets usr_page.
 * If it hasn't it returns 0 and does nothing with usr_page
 */
asmlinkage long sys_pthread_get_clock (void __user ** usr_page)
{
	if (current->record_thrd) {
		if (atomic_read(&current->record_thrd->rp_group->rg_shmpath_set)) {
			MPRINT ("Pid %d (record) pthread_get_clock: has user clock %p\n", current->pid, (current->record_thrd->rp_precord_clock));
			copy_to_user(usr_page, &(current->record_thrd->rp_precord_clock), sizeof(atomic_t *));
			return 1;
		} else {
			MPRINT ("Pid %d (record) pthread_get_clock: does not have user clock set up yet\n", current->pid);
			return 0;
		}
	} else if (current->replay_thrd) {
		if (atomic_read(&current->replay_thrd->rp_record_thread->rp_group->rg_shmpath_set)) {
			MPRINT ("Pid %d (replay) pthread_get_clock: has user clock %p\n", current->pid, (current->replay_thrd->rp_preplay_clock));
			copy_to_user(usr_page, &(current->replay_thrd->rp_preplay_clock), sizeof(u_long *));
			return 1;
		}  else {
			MPRINT ("Pid %d (replay) pthread_get_clock: does not have user clock set up yet\n", current->pid);
			return 0;
		}
	} else {
		printk("[WARN]Pid %d, neither record/replay is asking for the user clock\n", current->pid);
		return -EINVAL;
	}
}

/* Returns the path of the shared memory page back to the user and returns the fd of the shm to be mmaped by the user
 *
 * Returns the fd and sets shm_path
 * */
asmlinkage long sys_pthread_shm_path (char __user * shm_path)
{
	if (current->record_thrd) {
		int fd;
		struct record_group* prg = current->record_thrd->rp_group;
		if (atomic_read(&prg->rg_shmpath_set)) {
			MPRINT ("Pid %d (record) returning existing shmpath %s\n", current->pid, prg->rg_shmpath);
			copy_to_user (shm_path, prg->rg_shmpath, MAX_LOGDIR_STRLEN+1);
			fd = sys_open(prg->rg_shmpath, O_RDWR | O_NOFOLLOW, 0644);
			return fd;
		} else {
			snprintf(prg->rg_shmpath, MAX_LOGDIR_STRLEN+1, "/dev/shm/uclock%d", current->pid);
			MPRINT ("Pid %d (record) returning new shmpath %s\n", current->pid, prg->rg_shmpath);
			copy_to_user (shm_path, prg->rg_shmpath, MAX_LOGDIR_STRLEN+1);
			fd = sys_open(shm_path, O_CREAT | O_RDWR | O_NOFOLLOW, 0644);
			if(sys_ftruncate(fd,4096) == -1) {
				printk ("Pid %d could not create new shm page of size 4096\n", current->pid);
				sys_exit_group (0);
			}	
			atomic_set(&prg->rg_shmpath_set, 1);
			return fd;
		}
	} else if (current->replay_thrd) {
		int fd;
		struct record_group* prg = current->replay_thrd->rp_group->rg_rec_group;
		if (atomic_read(&prg->rg_shmpath_set)) {
			MPRINT ("Pid %d (replay) returning existing shmpath %s\n", current->pid, prg->rg_shmpath);
			copy_to_user (shm_path, prg->rg_shmpath, MAX_LOGDIR_STRLEN+1);
			fd = sys_open(prg->rg_shmpath, O_RDWR | O_NOFOLLOW, 0644);
			return fd;
		} else {
			snprintf(prg->rg_shmpath, MAX_LOGDIR_STRLEN+1, "/dev/shm/uclock%d", current->replay_thrd->rp_record_thread->rp_record_pid);
			MPRINT ("Pid %d (replay) returning new shmpath %s\n", current->pid, prg->rg_shmpath);
			copy_to_user (shm_path, prg->rg_shmpath, MAX_LOGDIR_STRLEN+1);
			fd = sys_open(shm_path, O_CREAT | O_RDWR | O_NOFOLLOW, 0644);
			if(sys_ftruncate(fd,4096) == -1) {
				printk ("Pid %d could not create new shm page of size 4096\n", current->pid);
				sys_exit_group (0);
			}	
			atomic_set(&prg->rg_shmpath_set, 1);
			return fd;
		}
	} else {
		printk("[WARN]Pid %d, neither record/replay is asking for the shm_path???\n", current->pid);
		return -EINVAL;
	}
}

asmlinkage long sys_pthread_sysign (void)
{
	// This replays an ignored syscall which delivers a signal
	DPRINT ("In sys_pthread_sysign\n");
	return get_next_syscall (SIGNAL_WHILE_SYSCALL_IGNORED, NULL, NULL); 
}


/* Custom versions exist for:
 *	- exit
 *	- clone
 *	- exit_group
 *	- rt_sigaction
 *	- rt_sigprocmask
 *
 */
#define SHIM_CALL_MAIN(number, F_RECORD, F_REPLAY, F_SYS)	\
{ \
	int ignore_flag;						\
	if (current->record_thrd) {					\
		get_user (ignore_flag, current->record_thrd->rp_ignore_flag_addr); \
		if (ignore_flag) {					\
			if (number != 240) printk ("Pid %d ignoring syscall %d at user-level request (value %d address %p)\n", current->pid, number, ignore_flag, current->record_thrd->rp_ignore_flag_addr); \
			return F_SYS;					\
		}							\
		return F_RECORD;					\
	}								\
	if (current->replay_thrd && test_app_syscall(number)) {		\
		get_user (ignore_flag, current->replay_thrd->rp_record_thread->rp_ignore_flag_addr); \
		if (ignore_flag) {					\
			if (number != 240) printk ("Pid %d ignoring syscall %d at user-level request (value %d)\n", current->pid, number, ignore_flag); \
			return F_SYS;					\
		}							\
		return F_REPLAY;					\
	}								\
	return F_SYS;							\
}

#define SHIM_CALL(name, number, args...)					\
{ \
	SHIM_CALL_MAIN(number, record_##name(args), replay_##name(args),	\
		       sys_##name(args))    \
}

#define SHIM_NOOP_HEAD(name) \
	if (current->record_thrd || current->replay_thrd) {		\
	        printk ("[NOOP]replay %d: system call " #name " not handled\n", \
	        	current->pid); \
	}

#define SHIM_NOOP(name, args...) \
{ \
	SHIM_NOOP_HEAD(name); \
	return sys_##name (args); \
}

#define SHIM_OLD_NOOP(name, args...) \
{ \
	if (current->record_thrd || current->replay_thrd) {		\
		printk ("[NOOP]replay: system call old_" #name " not handled\n"); \
	} \
	return sys_old_##name (args); \
}

// Many record/replay stubs are essentially identical - use macro for these
#define GENERIC_REPLAY(name, number, args...) \
static asmlinkage long \
replay_##name (args) \
{ \
	return get_next_syscall (number, NULL, NULL); \
}

long 
replay_get_logid (struct task_struct* tsk)
{
	if (tsk->record_thrd) {
		return tsk->record_thrd->rp_logid;
	} else if (tsk->replay_thrd) {
		return tsk->replay_thrd->rp_record_thread->rp_logid;
	} else {
		return -1;
	}
}

asmlinkage long 
sys_get_logid (void)
{
	return replay_get_logid(current);
}

asmlinkage long shim_restart_syscall(void) SHIM_NOOP(restart_syscall);

/* Called on enter of do_exit() in kernel/exit.c 
 *
 * recplay_exit_start is called on enter of do_exit in kernel/exit.c
 * It records the global vector clock value and frees the record log.
 * 
 * No locks are held on entry or exit.
 * */
void 
recplay_exit_start(void)
{
	if (current->record_thrd) {
		struct record_thread* prt = current->record_thrd;
		MPRINT ("Record thread %d starting to exit\n", current->pid);
		write_user_log (prt); // Write this out before we destroy the mm
	}
}

void 
recplay_exit_middle(void)
{
	struct vm_area_struct* mpnt;
	struct page* page = NULL;
	struct replay_thread* tmp;
	struct task_struct* tsk;
	struct mm_struct* mm;
	u_long addr, clock;
	int num_blocked;
	pid_t pid = 0;
	u_long* p;

	if (current->record_thrd) {
		struct record_thread* prt = current->record_thrd;
		MPRINT ("Record thread %d in middle of exit\n", current->pid);
	
		// Write kernel log after we have updated the tid ptr
#ifdef WRITE_ASYNC
		write_and_free_kernel_log_async(prt);
#else
		write_and_free_kernel_log(prt); // Write out remaining records
#endif
	} else if (current->replay_thrd) {
		MPRINT ("Replay thread %d recpid %d in middle of exit\n", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid);	
		rg_lock (current->replay_thrd->rp_group->rg_rec_group);
		if (current->replay_thrd->rp_status != REPLAY_STATUS_RUNNING) {
			if (!current->replay_thrd->rp_replay_exit && !current->replay_thrd->rp_group->rg_rec_group->rg_mismatch_flag) { 
				// Usually get here by terminating when we see the exit flag and all records have been consumed
				printk ("Non-running pid %d is exiting with status %d - abnormal termination?\n", current->pid, current->replay_thrd->rp_status);
				dump_stack();
			}
			current->replay_thrd->rp_status = REPLAY_STATUS_DONE;  // Will run no more 
			rg_unlock (current->replay_thrd->rp_group->rg_rec_group);
			return;
		}

		// This is ugly - we want to read the user clock but cannot get it from this thread because we have already detached the address space
		// So, find a thead that has not exited, map the shared page, and read it from there (bleah)
		tmp = current->replay_thrd->rp_next_thread;
		while (tmp != current->replay_thrd) {
			MPRINT ("Pid %d: Replay pid %d record pid %d has status %d\n", current->pid, tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status);
			if (tmp->rp_status != REPLAY_STATUS_DONE) {
				tsk = find_task_by_vpid(tmp->rp_replay_pid);
				if (tsk == NULL) {
					MPRINT ("recplay_exit_middle: cannot find replay task %d\n", pid);
				} else {
					task_lock (tsk);
					if (tsk->mm == NULL) {
						MPRINT ("replay_exit_middle: task %d has no mm\n", pid);
						task_unlock (tsk);
					} else {
						// Make sure that mm doesn't go away on us
						mm = tsk->mm;
						down_read (&mm->mmap_sem);
						task_unlock (tsk);
						pid = tmp->rp_replay_pid; 
						break;
					}
				}
			}
			tmp = tmp->rp_next_thread;
		}
		if (pid == 0) {
			int rc;
			mm_segment_t old_fs;
			printk ("No non-exited threads left in replay group, so noone to wake up\n");

			// unlink shm path here
			if (atomic_read(&current->replay_thrd->rp_group->rg_rec_group->rg_shmpath_set)) {

				old_fs = get_fs();
				set_fs(KERNEL_DS);
				rc = sys_unlink(current->replay_thrd->rp_group->rg_rec_group->rg_shmpath);
				set_fs(old_fs);
				if (rc) {
					printk ("Pid %d could not unlink the shmpath %s, rc %d\n", current->pid, current->replay_thrd->rp_group->rg_rec_group->rg_shmpath, rc); 
				}
			}
			

			rg_unlock (current->replay_thrd->rp_group->rg_rec_group);
			return;
		} else { // mcc: added debugging
			MPRINT ("Pid %d, found another replay_thrd in group with pid %d\n", current->pid, pid);
		}

		// mcc: Checks to see if we've ever used a user-level clock
		// In the single-threaded case (using no pthread primitives, we may not have)
		addr = (u_long) tsk->replay_thrd->rp_preplay_clock;
		if (addr == (u_long) (&(tsk->replay_thrd->rp_group->rg_kreplay_clock))) {
			// just use the kernel clock
			clock = tsk->replay_thrd->rp_group->rg_kreplay_clock;
		} else {

			for (mpnt = mm->mmap; mpnt; mpnt = mpnt->vm_next) {
				if (mpnt->vm_start <= addr && mpnt->vm_end > addr) {
					page = follow_page (mpnt, addr, FOLL_GET);
					if (!page) {
						int ret = handle_mm_fault (mm, mpnt, addr, 0);
						if (ret & VM_FAULT_ERROR) BUG();
						page = follow_page (mpnt, addr, FOLL_GET);
					}
					if (IS_ERR(page) || !page) {
						printk ("recplay_exit_middle: cannot get page at addr %lx\n", addr);
						page = NULL;
					} 
					break;
				}
			}
			if (page == NULL) {
				printk ("recplay_exit_middle: could not retrieve page with user clock for addr %lx\n", addr);
				up_read (&mm->mmap_sem);
				rg_unlock (current->replay_thrd->rp_group->rg_rec_group);
				return;
			}
			p = (u_long *) kmap(page);
			clock = *p;
		}
		current->replay_thrd->rp_status = REPLAY_STATUS_DONE;  // Will run no more 	
		tmp = current->replay_thrd->rp_next_thread;
		num_blocked = 0;
		while (tmp != current->replay_thrd) {
			DPRINT ("Pid %d considers thread %d status %d clock %ld - clock is %ld\n", current->pid, tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock, clock);
			if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= clock)) {
				tmp->rp_status = REPLAY_STATUS_RUNNING;
				wake_up (&tmp->rp_waitq);
				break;
			} else if (tmp->rp_status != REPLAY_STATUS_DONE) {
				num_blocked++;
			}
			tmp = tmp->rp_next_thread;
			if (tmp == current->replay_thrd && num_blocked) {
				printk ("Pid %d (recpid %d): Crud! no elgible thread to run on exit, clock is %ld\n", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid, clock);
				dump_stack(); // how did we get here?
				// cycle around again and print
				tmp = tmp->rp_next_thread;
				while (tmp != current->replay_thrd) {
					printk("\t thread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
					tmp = tmp->rp_next_thread;
				}
			}
			
		} 

		// free the page, if we found a user page
		if (addr != (u_long) (&(tsk->replay_thrd->rp_group->rg_kreplay_clock))) {
			kunmap (page);
			put_page (page);
		}

		up_read (&mm->mmap_sem);
		rg_unlock (current->replay_thrd->rp_group->rg_rec_group);
	}
}

// PARSPEC: will have replay threads exiting when each epoch is over
void
recplay_exit_finish(void)
{
	if (current->record_thrd) {
		struct record_group* prg = current->record_thrd->rp_group;
		MPRINT ("Record thread %d has exited\n", current->pid);
		get_record_group(prg);

		rg_lock(prg);
		__destroy_record_thread (current->record_thrd);
		current->record_thrd = NULL;
		MPRINT ("Record Pid-%d, tsk %p, exiting!\n", current->pid, current);
		rg_unlock(prg);

		/* Hold a reference to prg through __destroy_record_thread()
		 * so it can be unlocked before it is freed. */
		put_record_group(prg);
	} else if (current->replay_thrd) {
		struct replay_thread* prt = current->replay_thrd;
		struct replay_group* prg = prt->rp_group;
		struct record_group* precg = prg->rg_rec_group;
#ifdef REPLAY_PARANOID
		BUG_ON (!prg);
		BUG_ON (!precg);
#endif
		get_record_group(precg);
		rg_lock(precg);

		MPRINT ("Replay Pid %d about to exit\n", current->pid);
		put_replay_group (prg);

		current->replay_thrd = NULL;

		rg_unlock(precg);

		/* Hold a reference to precg so it can be unlocked before it is freed. */
		put_record_group(precg);
	}
}

asmlinkage long 
record_exit (int error_code)
{
	return sys_exit (error_code);
}

asmlinkage long 
replay_exit(int error_code)
{
	return sys_exit (error_code);
}

asmlinkage long 
shim_exit(int error_code)
{
	if (current->record_thrd) {
		MPRINT ("Recording Pid %d naturally exiting\n", current->pid);
		return record_exit (error_code);
	}
	else if (current->replay_thrd && test_app_syscall(1)) {
		MPRINT ("Replaying Pid %d naturally exiting\n", current->pid);
		return replay_exit (error_code);
	}
	else return sys_exit (error_code);
}

long shim_fork(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
	if (current->record_thrd) printk ("Record pid %d calls shim_fork\n", current->pid);
	if (current->replay_thrd) printk ("Replay pid %d calls shim_fork\n", current->pid);
	return do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
}

static char*
copy_struct (const char __user * data, int len)
{
	char* tmp;

	if (len <= 0) {
		DPRINT ("copy_struct asked to allocate a %d byte stucture\n", len);
		return NULL;
	}

	if (data) {
#ifdef REPLAY_PARANOID
		do {
#endif
			tmp = KMALLOC(len, GFP_KERNEL);
#ifdef REPLAY_PARANOID
			if (tmp && (u_long) tmp < 0xc0000000) {
				printk ("KMALLOC of %d bytes returns %p\n", len, tmp);
				dump_stack();
			}
		} while (tmp && (u_long) tmp < 0xc0000000);
#endif
		if (tmp == NULL) {
			printk ("copy_struct: can't allocate memory\n");
			return ERR_PTR(-ENOMEM);
		}
		if (copy_from_user (tmp, data, len)) {
			printk ("copy_struct: can't copy from user\n");
			KFREE (tmp);
			return ERR_PTR(-EFAULT);
		}
		return tmp;
	} else {
		return NULL;
	}
}

/* Mostly like fd_install, except if a file is already in the table,
 * it is displaced by the new file.
 */
struct file* fd_replace(unsigned int fd, struct file *file)
{
	struct file *old_file;
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	int err;

	spin_lock(&files->file_lock);
	err = expand_files(files, fd);
	if (err < 0) {
		old_file = ERR_PTR(err);
		goto unlock;
	}
	fdt = files_fdtable(files);
	old_file = xchg(&fdt->fd[fd], file);	// rcu
unlock:
	spin_unlock(&files->file_lock);
	return old_file;
}

/* Try to undo an earlier fd_replace. Another thread could have
 * replaced our temp file with its own, so only swap back if it hasn't
 * changed. 'oldfile' should be the file returned by fd_replace().
 */
int fd_restore(unsigned int fd, struct file *oldfile, struct file *file)
{
	struct file *f;
	struct files_struct *files = current->files;
	struct fdtable *fdt;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	f = cmpxchg(&fdt->fd[fd], file, oldfile);	// rcu
	spin_unlock(&files->file_lock);
	return (f == file) ? 0 : -EAGAIN;
}

static asmlinkage ssize_t 
record_read (unsigned int fd, char __user * buf, size_t count)
{
	char* recbuf = NULL;
	ssize_t size;

	new_syscall_enter (3, NULL);
	size = sys_read (fd, buf, count);
	if (size > 0) {
		if (size > KMALLOC_THRESHOLD) {
			recbuf = ARGSVMALLOC(size);
		} else {
			recbuf = ARGSKMALLOC(size, GFP_KERNEL);
		}
		if (recbuf == NULL) {
			printk ("Unable to allocate read buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (recbuf, buf, size)) {
			printk ("Pid %d record_read copy_from_user failed\n", current->pid);
			if (size > KMALLOC_THRESHOLD) {
				ARGSVFREE (recbuf, size);
			} else {
				ARGSKFREE (recbuf, size);
			}
			return -EFAULT;
		}
	}
	new_syscall_exit (3, size, recbuf);

	return size;
}

static asmlinkage ssize_t 
replay_read (unsigned int fd, char __user * buf, size_t count)
{
	char* retparams = NULL;
	long rc = get_next_syscall (3, &retparams, NULL);

	if (retparams) {
		if (copy_to_user (buf, retparams, rc)) {
			printk ("Pid %d replay_read cannot copy to user\n", current->pid);
		}
	}

	return rc;
}

asmlinkage ssize_t 
shim_read (unsigned int fd, char __user * buf, size_t count)
SHIM_CALL(read, 3, fd, buf, count);

static asmlinkage ssize_t 
record_write (unsigned int fd, const char __user * buf, size_t count)
{
	ssize_t size;
	char kbuf[80];

	if (fd == 99999) {
		new_syscall_enter (4, NULL);
		memset (kbuf, 0, sizeof(kbuf));
		if (copy_from_user (kbuf, buf, count < 80 ? count : 79)) {
			printk ("record_write: cannot copy kstring\n");
		}
		printk ("Pid %d records: %s", current->pid, kbuf);
		new_syscall_exit (4, count, NULL);
		return count;
	}

	new_syscall_enter (4, NULL);
	size = sys_write (fd, buf, count);
	DPRINT ("Pid %d records write returning %d\n", current->pid,size);
	new_syscall_exit (4, size, NULL);


	return size;
}

static asmlinkage ssize_t 
replay_write (unsigned int fd, const char __user * buf, size_t count)
{
	ssize_t rc;
	char kbuf[80];

	if (fd == 99999) {
		memset (kbuf, 0, sizeof(kbuf));
		if (copy_from_user (kbuf, buf, count < 80 ? count : 79)) {
			printk ("record_write: cannot copy kstring\n");
		}
		printk ("Pid %d (recpid %d) replays: %s", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid, kbuf);
	}

	rc = get_next_syscall (4, NULL, NULL);
	DPRINT ("Pid %d replays write returning %d\n", current->pid,rc);

	return rc;
}


asmlinkage ssize_t 
shim_write (unsigned int fd, const char __user * buf, size_t count)
SHIM_CALL (write, 4, fd, buf, count);

static asmlinkage long 
record_open (const char __user *filename, int flags, int mode)
{
	long rc;

	new_syscall_enter (5, NULL);
	rc = sys_open (filename, flags, mode);
	DPRINT ("Pid %d records open(%s, %x, 0%o) returning %ld\n", current->pid, filename, flags, mode, rc);
	new_syscall_exit (5, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_open (const char __user *filename, int flags, int mode)
{
	long rc = get_next_syscall (5, NULL, NULL);
	DPRINT ("Pid %d replays open(%s, %x, 0%o) returning %ld\n", current->pid, filename, flags, mode, rc);
	return rc;
}

asmlinkage long 
shim_open (const char __user *filename, int flags, int mode)
SHIM_CALL(open, 5, filename, flags, mode);

static asmlinkage long 
record_close (unsigned int fd)
{
	long rc;

	new_syscall_enter (6, NULL);

	rc = sys_close (fd);
	DPRINT ("Pid %d records close of fd %d returning %ld\n", current->pid, fd, rc);
	
	new_syscall_exit (6, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_close (unsigned int fd)
{
	long rc = get_next_syscall (6, NULL, NULL);
	DPRINT ("pid %d: replay_close of fd %d returns %ld\n", current->pid, fd, rc);
	return rc;
}

asmlinkage long shim_close (unsigned int fd)
SHIM_CALL(close, 6, fd);

struct waitpid_retvals {
	int status;
};

static asmlinkage long 
record_waitpid (pid_t pid, int __user *stat_addr, int options)
{
	long rc;
	struct waitpid_retvals* retvals;

	new_syscall_enter (7, NULL);
	rc = sys_waitpid (pid, stat_addr, options);
	DPRINT ("Pid %d records waitpid returning %ld\n", current->pid, rc);

	retvals = ARGSKMALLOC(sizeof(struct waitpid_retvals), GFP_KERNEL);
	if (retvals == NULL) {
		printk("record_waitpid: can't allocate buffer\n");
		return -ENOMEM;
	}

	if (rc >= 0 && stat_addr) {
		if (copy_from_user (&retvals->status, stat_addr, sizeof(int))) {
			ARGSKFREE (retvals, sizeof(int));
			return -EFAULT;
		}
	} else {
		retvals->status = 0;
	}

	new_syscall_exit (7, rc, retvals);

	return rc;
}

static asmlinkage long 
replay_waitpid (pid_t pid, int __user *stat_addr, int options)
{
	char* retparams = NULL;
	struct waitpid_retvals* pretvals;
	long rc = get_next_syscall (7, &retparams, NULL);

	pretvals = (struct waitpid_retvals* ) retparams;
	
	if (rc >= 0 && stat_addr) {
		if (copy_to_user (stat_addr, &pretvals->status, sizeof(int))) {
			printk ("Pid %d replay_waitpid cannot copy to user\n", current->pid);
			return syscall_mismatch();
		}
	}

	DPRINT ("Pid %d replays waitpid returning %ld\n", current->pid, rc);
	return rc;
}

asmlinkage long shim_waitpid (pid_t pid, int __user *stat_addr, int options) SHIM_CALL(waitpid, 7, pid, stat_addr, options);

static asmlinkage long 
record_creat(const char __user * pathname, int mode)
{
	long rc;

	new_syscall_enter (8, NULL);

	rc = sys_creat (pathname, mode);
	DPRINT ("Pid %d records creat returning %ld\n", current->pid, rc);

	new_syscall_exit (8, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_creat(const char __user * pathname, int mode)
{
	return get_next_syscall (8, NULL, NULL);
}

asmlinkage long 
shim_creat(const char __user * pathname, int mode)
SHIM_CALL(creat, 8, pathname, mode);

static asmlinkage long 
record_link (const char __user *oldname, const char __user *newname)
{
	long rc;

	new_syscall_enter (9, NULL);

	rc = sys_link (oldname, newname);
	DPRINT ("Pid %d records link returning %ld\n", current->pid, rc);

	new_syscall_exit (9, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_link (const char __user *oldname, const char __user *newname)
{
	return get_next_syscall (9, NULL, NULL);
}

asmlinkage long 
shim_link (const char __user *oldname, const char __user *newname)
SHIM_CALL(link, 9, oldname, newname);

static asmlinkage long 
record_unlink (const char __user *pathname)
{
	long rc;

	new_syscall_enter (10, NULL);

	rc = sys_unlink (pathname);
	DPRINT ("Pid %d records unlink returning %ld\n", current->pid, rc);

	new_syscall_exit (10, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_unlink (const char __user *pathname)
{
	return get_next_syscall (10, NULL, NULL);
}

asmlinkage long 
shim_unlink (const char __user *pathname) 
SHIM_CALL(unlink, 10, pathname);

// Simply recording the fact that an execve takes place, we won't replay it
static int 
record_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs) 
{
	struct ravlues* pretval;
	char* shm_path;

	long rc;
	MPRINT ("Record pid %d performing execve\n", current->pid);
	new_syscall_enter (11, NULL);

	// Will be used to store random vars for address space layout
	pretval = ARGSKMALLOC(sizeof(struct rvalues), GFP_KERNEL);
	if (pretval == NULL) {
		printk ("Unable to allocate space for execve random vars\n");
		return -ENOMEM;
	}
	current->record_thrd->random_values.cnt = 0;

	// write out the user log before exec-ing
	write_user_log (current->record_thrd);

	rc = do_execve(filename, __argv, __envp, regs);
	memcpy (pretval, &current->record_thrd->random_values, sizeof (struct rvalues));

	// if we had set up the user-level clock before, set it back up before exiting
	
	shm_path = current->record_thrd->rp_group->rg_shmpath;
	// After an execve, we need to set back up the user clock if it was set up before
	if(atomic_read(&current->record_thrd->rp_group->rg_shmpath_set)) {
		int fd;
		mm_segment_t old_fs;
		u_long ppage;

		DPRINT ("Pid %d after an execve, need to set back up the user clock, shmpath %s\n", current->pid, shm_path);
		DPRINT ("Pid %d after an execve, user clock address is %p, kernel clock address is %p\n", current->pid, 
				current->record_thrd->rp_precord_clock, &(current->record_thrd->rp_group->rg_krecord_clock));

		old_fs = get_fs();
		set_fs(KERNEL_DS);
		fd = sys_open(shm_path, O_RDWR | O_NOFOLLOW, 0644);
		/* put the page back to where the clock page was before */
		ppage = sys_mmap_pgoff((unsigned long) current->record_thrd->rp_precord_clock, 4096, PROT_READ|PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);

		// set the user clock
		DPRINT("Pid %d after execve, the user clock value is %d\n", current->pid, atomic_read((atomic_t *)ppage));
		current->record_thrd->rp_precord_clock = (atomic_t *) ppage;

		set_fs(old_fs);
		sys_close(fd);
	}

	new_syscall_exit (11, rc, pretval);
	return rc;
}

// need to advance the record log past the execve, but we don't replay it
// We need to record that an exec happened in the log for knowing when to clear
// preallocated memory in a forked process
static int
replay_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs) 
{
	struct replay_thread* prt = current->replay_thrd;
	struct replay_group* prg = prt->rp_group;
	struct syscall_result* psr;
	char* shm_path;

	long rc;
	struct replay_thread* prp;
	struct rvalues* retparams = NULL;
	prp = current->replay_thrd;

	get_next_syscall_enter (prt, prg, 11, (char **) &retparams, NULL, &psr);  // Need to split enter/exit because of vfork/exec wait
	DPRINT("Replay pid %d performing execve of %s\n", current->pid, filename);
	memcpy (&current->replay_thrd->random_values, retparams, sizeof(struct rvalues));
	current->replay_thrd->random_values.cnt = 0;
	rc = do_execve(filename, __argv, __envp, regs);

	shm_path = prp->rp_record_thread->rp_group->rg_shmpath;
	/* After an execve, we need to set back up the user clock if it was set up before */
	if(atomic_read(&prp->rp_record_thread->rp_group->rg_shmpath_set)) {
		int fd;
		mm_segment_t old_fs;
		u_long ppage, clock;

	        DPRINT ("Pid %d after an execve, need to set back up the user clock, shmpath %s\n", current->pid, shm_path);
		DPRINT ("Pid %d after an execve, user clock address is %p, kernel clock address is %p\n", current->pid, 
			current->replay_thrd->rp_preplay_clock, &(current->replay_thrd->rp_group->rg_kreplay_clock));

		old_fs = get_fs();
		set_fs(KERNEL_DS);
		fd = sys_open(shm_path, O_RDWR | O_NOFOLLOW, 0644);
		ppage = sys_mmap_pgoff((unsigned long) current->replay_thrd->rp_preplay_clock, 4096, PROT_READ|PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);

		// set the user clock
		current->replay_thrd->rp_preplay_clock = (u_long *) ppage;
		get_user (clock, prt->rp_preplay_clock);

		set_fs(old_fs);
		sys_close(fd);
	}
	
	get_next_syscall_exit (prt, prg, psr);

	if (is_pin_attached()) {
		prp->app_syscall_addr = 1; /* We need to reattach the pin tool after exec */
		preallocate_memory (); /* And preallocate memory again - our previous preallocs were just destroyed */
		create_used_address_list ();
	}

	return rc;
}

int shim_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs) 
SHIM_CALL_MAIN(11, record_execve(filename, __argv, __envp, regs), replay_execve(filename, __argv, __envp, regs), do_execve(filename, __argv, __envp, regs))

static asmlinkage long 
record_chdir(const char __user * filename)
{
	long rc;

	new_syscall_enter (12, NULL);

	rc = sys_chdir (filename);
	DPRINT ("Pid %d records chdir returning %ld\n", current->pid, rc);

	new_syscall_exit (12, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_chdir(const char __user * filename)
{
	return get_next_syscall (12, NULL, NULL);
}

asmlinkage long 
shim_chdir(const char __user * filename) 
SHIM_CALL(chdir, 12, filename);

static asmlinkage long 
record_time(time_t __user * tloc)
{
	long rc;

	new_syscall_enter (13, NULL);

	rc = sys_time (tloc);
	DPRINT ("Pid %d records time returning %ld\n", current->pid, rc);

	new_syscall_exit (13, rc, NULL); /* tloc gets same value as rc */

	return rc;
}

static asmlinkage long 
replay_time(time_t __user * tloc)
{
	time_t rc = get_next_syscall (13, NULL, NULL);
	if (tloc) {
		if (copy_to_user(tloc, &rc, sizeof(time_t))) {
			printk ("Pid %d cannot copy time to user\n", current->pid);
			syscall_mismatch();
		}
	}
	
	return rc;
}

asmlinkage long shim_time(time_t __user * tloc) 
SHIM_CALL (time, 13, tloc);

static asmlinkage long 
record_mknod (const char __user *filename, int mode, unsigned dev)
{
	long rc;

	new_syscall_enter (14, NULL);

	rc = sys_mknod (filename, mode, dev);
	DPRINT ("Pid %d records mknod returning %ld\n", current->pid, rc);

	new_syscall_exit (14, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_mknod (const char __user *filename, int mode, unsigned dev)
{
	return get_next_syscall (14, NULL, NULL);
}

asmlinkage long 
shim_mknod (const char __user *filename, int mode, unsigned dev)
SHIM_CALL(mknod, 14, filename, mode, dev);

static asmlinkage long 
record_chmod (const char __user *filename, mode_t mode)
{
	long rc;

	new_syscall_enter (15, NULL);

	rc = sys_chmod (filename, mode);
	DPRINT ("Pid %d records chmod returning %ld\n", current->pid, rc);

	new_syscall_exit (15, rc, NULL); 

	return rc;
}

static asmlinkage long 
replay_chmod (const char __user *filename, mode_t mode)
{
	return get_next_syscall (15, NULL, NULL);
}

asmlinkage long 
shim_chmod (const char __user *filename, mode_t mode)
SHIM_CALL(chmod, 15, filename, mode);

static asmlinkage long 
record_lchown16(const char __user * filename, old_uid_t user, old_gid_t group)
{
	long rc;

	new_syscall_enter (16, NULL);

	rc = sys_lchown16 (filename, user, group);
	DPRINT ("Pid %d records lchown16 returning %ld\n", current->pid, rc);

	new_syscall_exit (16, rc, NULL); 

	return rc;
}

static asmlinkage long 
replay_lchown16(const char __user * filename, old_uid_t user, old_gid_t group)
{
	return get_next_syscall (16, NULL, NULL);
}

asmlinkage long 
shim_lchown16(const char __user * filename, old_uid_t user, old_gid_t group)
SHIM_CALL(lchown16, 16, filename, user, group);

static asmlinkage long 
record_stat (char __user * filename, struct __old_kernel_stat __user * statbuf)
{
	long rc;
	struct __old_kernel_stat* pretval = NULL;

	new_syscall_enter (18, NULL);

	rc = sys_stat (filename, statbuf);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct __old_kernel_stat), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_stat: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, statbuf, sizeof(struct __old_kernel_stat))) {
			ARGSKFREE (pretval, sizeof(struct __old_kernel_stat));
			return -EFAULT;
		}
	}

	DPRINT ("Pid %d records stat returning %ld\n", current->pid, rc);
	new_syscall_exit (18, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_stat (char __user * filename, struct __old_kernel_stat __user * statbuf)
{
	struct __old_kernel_stat* retparams = NULL;
	long rc = get_next_syscall (18, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (statbuf, retparams, sizeof(struct __old_kernel_stat))) {
			printk ("Pid %d cannot copy statbuf to user\n", current->pid);
		}
	}

	return rc;
}

asmlinkage long 
shim_stat (char __user * filename, struct __old_kernel_stat __user * statbuf)
SHIM_CALL(stat, 18, filename, statbuf);

static asmlinkage off_t 
record_lseek(unsigned int fd, off_t offset, unsigned int origin)
{
	long rc;

	new_syscall_enter (19, NULL);

	rc = sys_lseek (fd, offset, origin);
	DPRINT ("Pid %d records lseek returning %ld\n", current->pid, rc);

	new_syscall_exit (19, rc, NULL); 

	return rc;
}

static asmlinkage off_t 
replay_lseek(unsigned int fd, off_t offset, unsigned int origin)
{
	return get_next_syscall (19, NULL, NULL);
}

asmlinkage off_t 
shim_lseek(unsigned int fd, off_t offset, unsigned int origin)
SHIM_CALL(lseek, 19, fd, offset, origin);

static asmlinkage long 
record_getpid (void)
{
	long rc;

	new_syscall_enter (20, NULL);
	rc = sys_getpid();
	new_syscall_exit (20, rc, NULL);
	DPRINT ("Pid %d records getpid returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_getpid (void)
{
	return get_next_syscall (20, NULL, NULL);
}

asmlinkage long shim_getpid (void) SHIM_CALL(getpid, 20);

static asmlinkage long 
record_mount (char __user * dev_name, char __user * dir_name,  char __user * type, unsigned long flags, void __user * data)
{
	long rc;

	new_syscall_enter (21, NULL);

	rc = sys_mount (dev_name, dir_name, type, flags, data);
	DPRINT ("Pid %d records mount returning %ld\n", current->pid, rc);
	new_syscall_exit (21, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_mount (char __user * dev_name, char __user * dir_name, char __user * type, unsigned long flags, void __user * data)
{
	return get_next_syscall (21, NULL, NULL);
}

asmlinkage long 
shim_mount (char __user * dev_name, char __user * dir_name,
			  char __user * type, unsigned long flags,
			  void __user * data)
SHIM_CALL(mount, 21, dev_name, dir_name, type, flags, data);

static asmlinkage long 
record_oldumount (char __user * name)
{
	long rc;

	new_syscall_enter (22, NULL);

	rc = sys_oldumount (name);
	DPRINT ("Pid %d records oldumount returning %ld\n", current->pid, rc);

	new_syscall_exit (22, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_oldumount (char __user * name)
{
	return get_next_syscall (22, NULL, NULL);
}

asmlinkage long 
shim_oldumount (char __user * name) 
SHIM_CALL(oldumount, 22, name);

static asmlinkage long 
record_setuid16 (uid_t uid)
{
	long rc;

	new_syscall_enter (23, NULL);

	rc = sys_setuid16 (uid);
	DPRINT ("Pid %d records setuid16 returning %ld\n", current->pid, rc);
	
	new_syscall_exit (23, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_setuid16 (uid_t uid)
{
	return get_next_syscall (23, NULL, NULL);
}

asmlinkage long shim_setuid16 (uid_t uid) 
SHIM_CALL(setuid16, 23, uid)

static asmlinkage long 
record_getuid16 (void)
{
	long rc;

	new_syscall_enter (24, NULL);
	rc = sys_getuid16();
	new_syscall_exit (24, rc, NULL);
	DPRINT ("Pid %d records getuid16 returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_getuid16 (void)
{
	return get_next_syscall (24, NULL, NULL);
}

asmlinkage long shim_getuid16 (void) 
SHIM_CALL(getuid16, 24);

static asmlinkage long 
record_stime (time_t __user *tptr)
{
	long rc;
	new_syscall_enter (25, NULL);

	rc = sys_stime (tptr);
	DPRINT ("Pid %d records stime returning %ld\n", current->pid, rc);
	
	new_syscall_exit (25, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_stime (time_t __user* tptr)
{
	return get_next_syscall (25, NULL, NULL);
}

asmlinkage long shim_stime (time_t __user *tptr) 
SHIM_CALL(stime, 25, tptr);

asmlinkage long 
shim_ptrace (long request, long pid, long addr, long data)
SHIM_NOOP(ptrace, request, pid, addr, data)

static asmlinkage unsigned long 
record_alarm (unsigned int seconds)
{
	unsigned long rc;

	new_syscall_enter (27, NULL);

	rc = sys_alarm (seconds);
	DPRINT ("Pid %d records alarm returning %lu\n", current->pid, rc);

	new_syscall_exit (27, rc, NULL);

	return rc;
}

static asmlinkage unsigned long 
replay_alarm (unsigned int seconds)
{
	return get_next_syscall (27, NULL, NULL);
}

asmlinkage unsigned long
shim_alarm (unsigned int seconds) 
SHIM_CALL(alarm, 27, seconds);

static asmlinkage long 
record_fstat (unsigned int fd, struct __old_kernel_stat __user * statbuf)
{
	long rc;
	struct __old_kernel_stat* pretval = NULL;

	new_syscall_enter (28, NULL);

	rc = sys_fstat (fd, statbuf);
	DPRINT ("Pid %d records fstat returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct __old_kernel_stat), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_fstat: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, statbuf, sizeof(struct __old_kernel_stat))) {
			ARGSKFREE (pretval, sizeof(struct __old_kernel_stat));
			return -EFAULT;
		}
	}
		
	new_syscall_exit (28, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_fstat (unsigned int fd, struct __old_kernel_stat __user * statbuf)
{
	struct __old_kernel_stat* retparams = NULL;
	long rc = get_next_syscall (28, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (statbuf, retparams, sizeof(struct __old_kernel_stat))) {
			printk ("Pid %d cannot copy statbuf to user\n", current->pid);
			return syscall_mismatch();
		}
	}

	return rc;
}

asmlinkage long 
shim_fstat (unsigned int fd, struct __old_kernel_stat __user * statbuf)
SHIM_CALL (fstat, 28, fd, statbuf);

static asmlinkage long
record_pause (void)
{
	long rc;

	new_syscall_enter (29, NULL);
	rc = sys_pause ();
	new_syscall_exit (29, rc, NULL);
	DPRINT ("Pid %d records pause returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long
replay_pause (void)
{
	return get_next_syscall (29, NULL, NULL);
}

asmlinkage long shim_pause (void) 
SHIM_CALL (pause, 29);

static asmlinkage long 
record_utime (char __user *filename, struct utimbuf __user *times)
{
	long rc;

	new_syscall_enter (30, NULL);

	rc = sys_utime (filename, times);
	DPRINT ("Pid %d records utime returning %ld\n", current->pid, rc);

	new_syscall_exit (30, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_utime (char __user *filename, struct utimbuf __user *times)
{
	return get_next_syscall (30, NULL, NULL);
}

asmlinkage long 
shim_utime (char __user *filename, struct utimbuf __user *times)
SHIM_CALL (utime, 30, filename, times);

static asmlinkage long 
record_access (const char __user *filename, int mode)
{
	long rc;

	new_syscall_enter (33, NULL);

	rc = sys_access (filename, mode);
	DPRINT ("Pid %d records access returning %ld\n", current->pid, rc);

	new_syscall_exit (33, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_access (const char __user *filename, int mode)
{
	return get_next_syscall (33, NULL, NULL);
}

asmlinkage long 
shim_access (const char __user *filename, int mode) 
SHIM_CALL(access, 33, filename, mode);

static asmlinkage long 
record_nice (int increment)
{
	long rc;

	new_syscall_enter (34, NULL);

	rc = sys_nice (increment);
	DPRINT ("Pid %d records nice returning %ld\n", current->pid, rc);

	new_syscall_exit (34, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_nice (int increment)
{
	return get_next_syscall (34, NULL, NULL);
}

asmlinkage long shim_nice (int increment) 
SHIM_CALL(nice, 34, increment);

static asmlinkage long 
record_sync (void)
{
	long rc;

	new_syscall_enter (36, NULL);
	rc = sys_sync ();
	DPRINT ("Pid %d records sync returning %ld\n", current->pid, rc);
	new_syscall_exit (36, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_sync (void)
{
	return get_next_syscall (36, NULL, NULL);
}

asmlinkage long shim_sync (void) 
SHIM_CALL(sync, 36);

// we need a separate retvals for kill since psr->sigsnt will be overwritten if
// the signal attached is SIGTERM then recplay_exit_start will automatically overwrite
// it with the vector clock time of when the child terminated
static asmlinkage long
record_kill (int pid, int sig)
{
	long rc;

	new_syscall_enter (37, NULL);
	rc = sys_kill (pid, sig);
	DPRINT ("Pid %d records kill returning %ld\n", current->pid, rc);
	new_syscall_exit (37, rc, NULL);

	return rc;
}

// mcc: look for replay vector clocks in get_next_syscall since this needs to be processed before
// the signal being marked for delivery
static asmlinkage long
replay_kill (int pid, int sig)
{
	return get_next_syscall (37, NULL, NULL);
}

asmlinkage long shim_kill (int pid, int sig) 
SHIM_CALL(kill, 37, pid, sig);

static asmlinkage long 
record_rename (const char __user *oldname, const char __user *newname)
{
	long rc;

	new_syscall_enter (38, NULL);

	rc = sys_rename (oldname, newname);
	DPRINT ("Pid %d records rename returning %ld\n", current->pid, rc);

	new_syscall_exit (38, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_rename (const char __user *oldname, const char __user *newname)
{
	return get_next_syscall (38, NULL, NULL);
}

asmlinkage long 
shim_rename (const char __user *oldname, const char __user *newname)
SHIM_CALL(rename, 38, oldname, newname);

static asmlinkage long 
record_mkdir (const char __user *pathname, int mode)
{
	long rc;

	new_syscall_enter (39, NULL);

	rc = sys_mkdir (pathname, mode);
	DPRINT ("Pid %d records mkdir returning %ld\n", current->pid, rc);

	new_syscall_exit (39, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_mkdir (const char __user *pathname, int mode)
{
	return get_next_syscall (39, NULL, NULL);
}

asmlinkage long 
shim_mkdir (const char __user *pathname, int mode)
SHIM_CALL(mkdir, 39, pathname, mode);

static asmlinkage long 
record_rmdir (const char __user *pathname)
{
	long rc;

	new_syscall_enter (40, NULL);

	rc = sys_rmdir (pathname);
	DPRINT ("Pid %d records rmdir returning %ld\n", current->pid, rc);

	new_syscall_exit (40, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_rmdir (const char __user *pathname)
{
	return get_next_syscall (40, NULL, NULL);
}

asmlinkage long 
shim_rmdir (const char __user *pathname) 
SHIM_CALL(rmdir, 40, pathname);

static asmlinkage long 
record_dup (unsigned int fildes)
{
	long rc;

	new_syscall_enter (41, NULL);

	rc = sys_dup (fildes);
	DPRINT ("Pid %d records dup returning %ld\n", current->pid, rc);

	new_syscall_exit (41, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_dup (unsigned int fildes)
{
	return get_next_syscall (41, NULL, NULL);
}

asmlinkage long shim_dup (unsigned int fildes) 
SHIM_CALL(dup, 41, fildes);

/* Cannot find definition for sys_pipe in a header file */
asmlinkage long __weak sys_pipe (int __user *fildes);

asmlinkage long __weak 
record_pipe (int __user *fildes)
{
	long rc;
	int* pretval = NULL;

	new_syscall_enter (42, NULL);

	rc = sys_pipe (fildes);
	DPRINT ("Pid %d records pipe returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(2*sizeof(int), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_pipe: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, fildes, 2*sizeof(int))) {
			ARGSKFREE (pretval, 2*sizeof(int));
			return -EFAULT;
		}
	}

	new_syscall_exit (42, rc, pretval);

	return rc;
}

asmlinkage long __weak 
replay_pipe (int __user *fildes)
{
	int* retparams = NULL;
	long rc = get_next_syscall (42, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (fildes, retparams, 2*sizeof(int))) {
			printk ("Pid %d cannot copy fildes to user\n", current->pid);
			return syscall_mismatch();
		}
	}
	return rc;
}

asmlinkage long __weak shim_pipe (int __user *fildes) 
SHIM_CALL(pipe, 42, fildes);

static asmlinkage long 
record_times (struct tms __user * tbuf)
{
	long rc;
	struct tms* pretval = NULL;
	new_syscall_enter (43, NULL);

	rc = sys_times (tbuf);
	DPRINT ("Pid %d records times returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct tms), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_times: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, tbuf, sizeof(struct tms))) {
			ARGSKFREE (pretval, sizeof(struct tms));
			return -EFAULT;
		}
	}
		
	new_syscall_exit (43, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_times (struct tms __user * tbuf)
{
	struct tms* retparams = NULL;
	long rc = get_next_syscall (43, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (tbuf, retparams, sizeof(struct tms))) {
			printk ("Pid %d cannot copy fildes to user\n", current->pid);
		}
	}
	return rc;
}

asmlinkage long shim_times (struct tms __user * tbuf) 
SHIM_CALL (times, 43, tbuf);

static asmlinkage unsigned long 
record_brk (unsigned long brk)
{
	unsigned long rc;
	u_long oldbrk;

	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (45, NULL);
	oldbrk = current->mm->brk;
	rc = sys_brk (brk);
	DPRINT ("Pid %d records brk with address %lx returning %lx (oldbrk %lx)\n", current->pid, brk, rc, oldbrk);

	new_syscall_exit (45, rc, NULL);
	rg_unlock(current->record_thrd->rp_group);

	return rc;
}	

static asmlinkage unsigned long 
replay_brk (unsigned long brk)
{
	u_long retval, rc = get_next_syscall (45, NULL, NULL);
	retval = sys_brk(brk);
	MPRINT ("Pid %d replays brk with address %lx returning %lx\n", current->pid, brk, retval);
	if (rc != retval) {
		printk ("Replay brk returns different value %lx than %lx\n", retval, rc);
		printk ("Pid %d sleeping so that you can analyze\n", current->pid);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
		return syscall_mismatch();
	}
	return rc;
}

asmlinkage unsigned long shim_brk (unsigned long abrk) 
SHIM_CALL(brk, 45, abrk);

static asmlinkage long 
record_setgid16 (old_gid_t gid)
{
	long rc;

	new_syscall_enter (46, NULL);

	rc = sys_setgid16 (gid);
	DPRINT ("Pid %d records setgid16 returning %ld\n", current->pid, rc);
	
	new_syscall_exit (46, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_setgid16 (old_gid_t gid)
{
	return get_next_syscall (46, NULL, NULL);
}

asmlinkage long shim_setgid16 (old_gid_t gid) 
SHIM_CALL(setgid16, 46, gid);

static asmlinkage long 
record_getgid16 (void)
{
	long rc;

	new_syscall_enter (47, NULL);
	rc = sys_getgid16();
	new_syscall_exit (47, rc, NULL);
	DPRINT ("Pid %d records getgid16 returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_getgid16 (void)
{
	return get_next_syscall (47, NULL, NULL);
}

asmlinkage long shim_getgid16 (void) SHIM_CALL(getgid16, 47);

static asmlinkage unsigned long
record_signal (int sig, __sighandler_t handler)
{
	u_long rc;

	new_syscall_enter (48, NULL);

	rc = sys_signal (sig, handler);
	DPRINT ("Pid %d records signal returning %lu\n", current->pid, rc);

	new_syscall_exit (48, rc, NULL);

	return rc;
}	

static asmlinkage unsigned long
replay_signal (int sig, __sighandler_t handler)
{
	return get_next_syscall (48, NULL, NULL);
}

asmlinkage unsigned long
shim_signal (int sig, __sighandler_t handler) 
SHIM_CALL(signal, 48, sig, handler);

static asmlinkage long 
record_geteuid16 (void)
{
	long rc;
	
	new_syscall_enter (49, NULL);
	rc = sys_geteuid16 ();
	new_syscall_exit (49, rc, NULL);
	DPRINT ("Pid %d records geteuid16 returning %ld\n", current->pid, rc);

	return rc;
}	

static asmlinkage long 
replay_geteuid16 (void)
{
	return get_next_syscall (49, NULL, NULL);
}

asmlinkage long shim_geteuid16 (void) 
SHIM_CALL(geteuid16, 49);

static asmlinkage long 
record_getegid16 (void)
{
	long rc;

	new_syscall_enter (50, NULL);
	rc = sys_getegid16 ();
	new_syscall_exit (50, rc, NULL);
	DPRINT ("Pid %d records getegid16 returning %ld\n", current->pid, rc);

	return rc;
}	

static asmlinkage long 
replay_getegid16 (void)
{
	return get_next_syscall (50, NULL, NULL);
}

asmlinkage long shim_getegid16 (void) 
SHIM_CALL(getegid16, 50);

static asmlinkage long 
record_acct (char __user * name)
{
	long rc;

	new_syscall_enter (51, NULL);

	rc = sys_acct (name);
	DPRINT ("Pid %d records acct returning %ld\n", current->pid, rc);

	new_syscall_exit (51, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_acct (char __user * name)
{
	return get_next_syscall (51, NULL, NULL);
}

asmlinkage long 
shim_acct (char __user * name) 
SHIM_CALL(acct, 51, name);

static asmlinkage long 
record_umount (char __user * name, int flags)
{
	long rc;

	new_syscall_enter (52, NULL);

	rc = sys_umount (name, flags);
	DPRINT ("Pid %d records umount returning %ld\n", current->pid, rc);

	new_syscall_exit (52, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_umount (char __user * name, int flags)
{
	return get_next_syscall (52, NULL, NULL);
}

asmlinkage long 
shim_umount (char __user * name, int flags) 
SHIM_CALL(umount, 52, name, flags);

static asmlinkage long 
record_ioctl (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	char* recbuf = NULL;
	long rc = 0;
	int dir;
	int size;

	switch (cmd) {
 	case FIOCLEX:
	case FIONCLEX:
		dir = _IOC_NONE;
		size = 0;
		break;
	case FIONBIO:
	case FIOASYNC:
	case FIBMAP:
		dir = _IOC_READ;
		size = sizeof(int);
		break;
	case FIGETBSZ:
	case FIONREAD:
		dir = _IOC_WRITE;
		size = sizeof(int);
		break;
	case FIOQSIZE:
		dir = _IOC_WRITE;
		size = sizeof(loff_t);
		break;
	case TCGETS:
		/* TTY */
		dir = _IOC_WRITE;
		size = sizeof(struct termios);
		break;
	case TCSETS:
	case TCSETSW:
		dir = _IOC_READ;
		size = sizeof(struct termios);
		break;
	case TCXONC:
		dir = _IOC_READ;
		size = sizeof(int);
		break;
	case TIOCGPGRP:
		dir = _IOC_WRITE;
		size = sizeof(struct pid);
		break;
	case TIOCSPGRP:
		dir = _IOC_READ;
		size = sizeof(struct pid);
		break;
	case TIOCGWINSZ:
		dir = _IOC_WRITE;
		size = sizeof(struct winsize);
		break;
	case TIOCSWINSZ:
		dir = _IOC_READ;
		size = sizeof(struct winsize);
		break;
	default:
		/* Generic */
		MPRINT ("Pid %d recording generic ioctl fd %d cmd %x arg %lx\n", current->pid, fd, cmd, arg);
		dir  = _IOC_DIR(cmd);
		size = _IOC_SIZE(cmd);
		if (dir == _IOC_NONE || size == 0) {
			printk("*** Generic IOCTL cmd %x arg %lx has no data! This probably needs special handling!\n", cmd, arg);
			dir = _IOC_NONE;
			size = 0;
		}
		break;
	}

	new_syscall_enter (54, NULL);

	if (rc == 0) rc = sys_ioctl (fd, cmd, arg);

	DPRINT ("Pid %d records ioctl fd %d cmd 0x%x arg 0x%lx returning %ld\n", current->pid, fd, cmd, arg, rc);

	if (rc >= 0 && (dir & _IOC_WRITE)) {
		recbuf = ARGSKMALLOC(sizeof(int)+size, GFP_KERNEL);
		if (!recbuf) {
			printk ("record_ioctl: can't allocate return\n");
			rc = -ENOMEM;
		} else {
			if (copy_from_user(recbuf+sizeof(int), (void __user *)arg, size)) {
				printk("record_ioctl: faulted on readback\n");
				ARGSKFREE(recbuf, sizeof(int)+size);
				recbuf = NULL;
				rc = -EFAULT;
			}
			*((int *)recbuf) = size;
		}
	}

	new_syscall_exit (54, rc, recbuf);

	return rc;
}

static asmlinkage long 
replay_ioctl (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	char* retparams = NULL;
	int my_size;
	long rc = get_next_syscall (54, &retparams, NULL);
	if (retparams) {
		my_size = *((int *)retparams);
		if (copy_to_user((void __user *)arg, retparams+sizeof(int), my_size))
			printk("replay_ioctl: pid %d faulted\n", current->pid);
	}
	return rc;
}

asmlinkage long 
shim_ioctl (unsigned int fd, unsigned int cmd, unsigned long arg)
SHIM_CALL(ioctl, 54, fd, cmd, arg)

static asmlinkage long 
record_fcntl (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	struct flock* recbuf = NULL;
	long rc;

	new_syscall_enter (55, NULL);
	rc = sys_fcntl (fd, cmd, arg);
	DPRINT ("Pid %d records fcntl returning %ld\n", current->pid, rc);

	if (rc >= 0 && cmd == F_GETLK) {
		recbuf = ARGSKMALLOC(sizeof(struct flock), GFP_KERNEL);
		if (!recbuf) {
			printk ("record_fcntl: can't allocate return buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user(recbuf, (void __user *)arg, sizeof(struct flock))) {
			printk("record_fcntl: faulted on readback\n");
			KFREE(recbuf);
			return -EFAULT;
		}
	}

	new_syscall_exit (55, rc, recbuf);

	return rc;
}

static asmlinkage long 
replay_fcntl (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	char* retparams = NULL;
	long rc = get_next_syscall (55, &retparams, NULL);
	if (retparams) {
		if (copy_to_user((void __user *)arg, retparams, sizeof(struct flock))) return syscall_mismatch();
	}
	return rc;
}

asmlinkage long 
shim_fcntl (unsigned int fd, unsigned int cmd, unsigned long arg)
SHIM_CALL(fcntl, 55, fd, cmd, arg)

static asmlinkage long 
record_setpgid (pid_t pid, pid_t pgid)
{
	long rc;

	new_syscall_enter (57, NULL);

	rc = sys_setpgid (pid, pgid);
	DPRINT ("Pid %d records setpgid returning %ld\n", current->pid, rc);
	
	new_syscall_exit (57, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_setpgid (pid_t pid, pid_t pgid)
{
	return get_next_syscall (57, NULL, NULL);
}

asmlinkage long shim_setpgid (pid_t pid, pid_t ppgid) SHIM_CALL(setpgid, 57, pid, ppgid);

static asmlinkage long 
record_olduname(struct oldold_utsname __user * name)
{
	long rc;
	struct oldold_utsname* pretval = NULL;

	new_syscall_enter (59, NULL);

	rc = sys_olduname (name);
	DPRINT ("Pid %d records olduname returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct oldold_utsname), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_olduname: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, name, sizeof(struct oldold_utsname))) {
			ARGSKFREE (pretval, sizeof(struct oldold_utsname));
			return -EFAULT;
		}
	}
		
	new_syscall_exit (59, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_olduname(struct oldold_utsname __user * name)
{
	struct oldold_utsname* retparams = NULL;
	long rc = get_next_syscall (59, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (name, retparams, sizeof(struct oldold_utsname))) {
			printk ("Pid %d cannot copy oluname bufer to user\n", current->pid);
			return syscall_mismatch();
		}
	}

	return rc;
}

asmlinkage int shim_olduname (struct oldold_utsname __user * name) SHIM_CALL(olduname, 59, name)

static asmlinkage long 
record_umask (int mask)
{
	long rc;

	new_syscall_enter (60, NULL);

	rc = sys_umask (mask);
	DPRINT ("Pid %d records umask returning %ld\n", current->pid, rc);
	
	new_syscall_exit (60, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_umask (int mask)
{
	return get_next_syscall (60, NULL, NULL);
}

asmlinkage long shim_umask (int mask) 
SHIM_CALL(umask, 60, mask)

static asmlinkage long 
record_chroot (const char __user *filename)
{
	long rc;

	new_syscall_enter (61, NULL);

	rc = sys_chroot (filename);
	DPRINT ("Pid %d records chroot returning %ld\n", current->pid, rc);

	new_syscall_exit (61, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_chroot (const char __user *filename)
{
	return get_next_syscall (61, NULL, NULL);
}

asmlinkage long 
shim_chroot (const char __user *filename) 
SHIM_CALL(chroot, 61, filename);

static asmlinkage long 
record_ustat (unsigned dev, struct ustat __user * ubuf) 
{
	long rc;
	struct ustat* pretval = NULL;

	new_syscall_enter (62, NULL);

	rc = sys_ustat (dev, ubuf);
	DPRINT ("Pid %d records ustat returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct ustat), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_ustat: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, ubuf, sizeof(struct ustat))) {
			ARGSKFREE (pretval, sizeof(struct ustat));
			return -EFAULT;
		}
	}
		
	new_syscall_exit (62, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_ustat (unsigned dev, struct ustat __user * ubuf) 
{
	struct ustat* retparams = NULL;
	long rc = get_next_syscall (62, (char **) &retparams, NULL);

	if (retparams) {
		if (copy_to_user (ubuf, retparams, sizeof(struct ustat))) {
			printk ("Pid %d cannot copy ustat bufer to user\n", current->pid);
			return syscall_mismatch();
		}
	}

	return rc;
}

asmlinkage long 
shim_ustat (unsigned dev, struct ustat __user * ubuf) 
SHIM_CALL(ustat, 62, dev, ubuf)

static asmlinkage long 
record_dup2 (unsigned int oldfd, unsigned int newfd)
{
	long rc;

	new_syscall_enter (63, NULL);

	rc = sys_dup2 (oldfd, newfd);
	DPRINT ("Pid %d records dup2 returning %ld\n", current->pid, rc);

	new_syscall_exit (63, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_dup2 (unsigned int oldfd, unsigned int newfd)
{
	return get_next_syscall (63, NULL, NULL);
}

asmlinkage long 
shim_dup2 (unsigned int oldfd, unsigned int newfd)
SHIM_CALL(dup2, 63, oldfd, newfd);

static asmlinkage long 
record_getppid (void)
{
	long rc;

	new_syscall_enter (64, NULL);
	rc = sys_getppid();
	new_syscall_exit (64, rc, NULL);
	DPRINT ("Pid %d records getppid returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_getppid (void)
{
	return get_next_syscall (64, NULL, NULL);
}

asmlinkage long shim_getppid (void) SHIM_CALL(getppid, 64);

static asmlinkage long 
record_getpgrp (void)
{
	long rc;

	new_syscall_enter (65, NULL);
	rc = sys_getpgrp();
	new_syscall_exit (65, rc, NULL);
	DPRINT ("Pid %d records getpgrp returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_getpgrp (void)
{
	return get_next_syscall (65, NULL, NULL);
}

asmlinkage long shim_getpgrp (void) SHIM_CALL(getpgrp, 65);

static asmlinkage long
record_setsid (void)
{
	long rc;

	new_syscall_enter (66, NULL);
	rc = sys_setsid ();
	DPRINT ("Pid %d records sys_setsid(void) returning %ld\n", current->pid, rc);

	new_syscall_exit (66, rc, NULL);

	return rc;
}

static asmlinkage long
replay_setsid (void)
{
	return  get_next_syscall (66, NULL, NULL);
}

asmlinkage long shim_setsid (void) SHIM_CALL (setsid, 66)

/* No prototype for sys_sigaction */
asmlinkage int sys_sigaction(int sig, const struct old_sigaction __user *act,
			     struct old_sigaction __user *oact);
asmlinkage int
shim_sigaction (int sig, const struct old_sigaction __user *act,
		struct old_sigaction __user *oact)
SHIM_NOOP(sigaction, sig, act, oact)

static asmlinkage long 
record_sgetmask (void)
{
	long rc;

	new_syscall_enter (68, NULL);
	rc = sys_sgetmask();
	new_syscall_exit (68, rc, NULL);
	DPRINT ("Pid %d records sgetmask returning %lx\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_sgetmask (void)
{
	return get_next_syscall (68, NULL, NULL);
}

asmlinkage long shim_sgetmask (void) SHIM_CALL(sgetmask, 68);

asmlinkage long shim_ssetmask (int newmask) SHIM_NOOP(ssetmask, newmask)

static asmlinkage long 
record_setreuid16 (old_uid_t ruid, old_uid_t euid) 
{
	long rc;

	new_syscall_enter (70, NULL);

	rc = sys_setreuid (ruid, euid);
	DPRINT ("Pid %d records setreuid16 returning %ld\n", current->pid, rc);
	
	new_syscall_exit (70, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_setreuid16 (old_uid_t ruid, old_uid_t euid)
{
	return get_next_syscall (70, NULL, NULL);
}

asmlinkage long shim_setreuid16 (old_uid_t ruid, old_uid_t euid) SHIM_CALL(setreuid16, 70, ruid, euid);

static asmlinkage long 
record_setregid16 (old_uid_t rgid, old_uid_t egid) 
{
	long rc;

	new_syscall_enter (71, NULL);

	rc = sys_setregid (rgid, egid);
	DPRINT ("Pid %d records setregid16 returning %ld\n", current->pid, rc);
	
	new_syscall_exit (71, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_setregid16 (old_gid_t rgid, old_gid_t egid)
{
	return get_next_syscall (71, NULL, NULL);
}

asmlinkage long shim_setregid16 (old_gid_t rgid, old_gid_t egid) SHIM_CALL(setregid16, 71, rgid, egid);

/* No prototype for sys_sigsuspend */
asmlinkage int sys_sigsuspend(int history0, int history1, old_sigset_t mask);
asmlinkage int
shim_sigsuspend (int history0, int history1, old_sigset_t mask)
SHIM_NOOP(sigsuspend, history0, history1, mask)

static asmlinkage long 
record_sigpending (old_sigset_t __user * set)
{
	long rc;
	old_sigset_t* pretval = NULL;

	new_syscall_enter (73, NULL);

	rc = sys_sigpending (set);
	DPRINT ("Pid %d records sigpending returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(old_sigset_t), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_sigpending: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, set, sizeof(old_sigset_t))) {
			ARGSKFREE (pretval, sizeof(old_sigset_t));
			return -EFAULT;
		}
	}
		
	new_syscall_exit (73, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_sigpending (old_sigset_t __user * set)
{
	old_sigset_t* retparams = NULL;
	long rc = get_next_syscall (73, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (set, retparams, sizeof(old_sigset_t))) {
			printk ("Pid %d cannot copy ustat bufer to user\n", current->pid);
			return syscall_mismatch();
		}
	}

	return rc;
}

asmlinkage long shim_sigpending (old_sigset_t __user *set) SHIM_CALL(sigpending, 73, set)

static asmlinkage long 
record_sethostname (char __user *name, int len)
{
	long rc;

	new_syscall_enter (74, NULL);

	rc = sys_sethostname (name, len);
	DPRINT ("Pid %d records sethostname returning %ld\n", current->pid, rc);
	
	new_syscall_exit (74, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_sethostname (char __user *name, int len)
{
	return get_next_syscall (74, NULL, NULL);
}

asmlinkage long shim_sethostname (char __user *name, int len) SHIM_CALL(sethostname, 74, name, len)

static asmlinkage long 
record_setrlimit (unsigned int resource, struct rlimit __user *rlim)
{
	long rc;

	new_syscall_enter (75, NULL);
	rc = sys_setrlimit (resource, rlim);
	DPRINT ("Pid %d records setrlimit returning %ld\n", current->pid, rc);
	new_syscall_exit (75, rc, NULL);
	return rc;
}

static asmlinkage long 
replay_setrlimit (unsigned int resource, struct rlimit __user *rlim)
{
	long rc;
	long rc_orig = get_next_syscall (75, NULL, NULL);
	rc = sys_setrlimit (resource, rlim);
	if (rc != rc_orig) printk ("setrlim changed its return in replay\n");
	return rc_orig;
}

asmlinkage long 
shim_setrlimit (unsigned int resource, struct rlimit __user *rlim)
SHIM_CALL(setrlimit, 75, resource, rlim)

static asmlinkage long 
record_old_getrlimit (unsigned int resource, struct rlimit __user *rlim)
{
	long rc;
	struct rlimit *pretval = NULL;

	new_syscall_enter (76, NULL);

	rc = sys_old_getrlimit (resource, rlim);
	DPRINT ("Pid %d records old_getrlimit returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct rlimit), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_old_getrlimit: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, rlim, sizeof(struct rlimit))) { 
			ARGSKFREE (pretval, sizeof(struct rlimit));
			pretval = NULL;
			rc = -EFAULT;
		}
	}
		
	new_syscall_exit (76, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_old_getrlimit (unsigned int resource, struct rlimit __user *rlim)
{
	struct rlimit *retparams = NULL;
	long rc = get_next_syscall (76, (char **) &retparams, NULL);

	if (retparams) {
		if (copy_to_user (rlim, retparams, sizeof(struct rlimit))) printk ("Pid %d cannot copy to user\n", current->pid);
	}

	return rc;
}

asmlinkage long shim_old_getrlimit (unsigned int resource, struct rlimit __user *rlim) SHIM_CALL(old_getrlimit, 76, resource, rlim)

static asmlinkage long 
record_getrusage (int who, struct rusage __user *ru)
{
	long rc;
	struct getrusage *pretval = NULL;

	new_syscall_enter (77, NULL);

	rc = sys_getrusage (who, ru);
	DPRINT ("Pid %d records getrusage returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct rusage), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_getrusage: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, ru, sizeof(struct rusage))) { 
			ARGSKFREE (pretval, sizeof(struct rusage));
			pretval = NULL;
			rc = -EFAULT;
		}
	}
		
	new_syscall_exit (77, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_getrusage (int who, struct rusage __user *ru)
{
	struct rusage *retparams = NULL;
	long rc = get_next_syscall (77, (char **) &retparams, NULL);

	if (retparams) {
		if (copy_to_user (ru, retparams, sizeof(struct rusage))) printk ("Pid %d cannot copy to user\n", current->pid);
	}

	return rc;
}

asmlinkage long shim_getrusage (int who, struct rusage __user *ru) SHIM_CALL(getrusage, 77, who, ru)

static asmlinkage long 
record_gettimeofday (struct timeval __user *tv, struct timezone __user *tz)
{
	long rc;
	struct gettimeofday_retvals* pretvals = NULL;

	new_syscall_enter (78, NULL);

	rc = sys_gettimeofday (tv, tz);
	DPRINT ("Pid %d records gettimeofday(tv=%p,tz=%p) returning %ld\n", current->pid, tv, tz, rc);
	if (rc == 0) {
		pretvals = ARGSKMALLOC(sizeof(struct gettimeofday_retvals), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_gettimeofday: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (tv) {
			pretvals->has_tv = 1;
			if (copy_from_user (&pretvals->tv, tv, sizeof(struct timeval))) {
				printk ("Pid %d cannot copy tv from user\n", current->pid);
				ARGSKFREE (pretvals, sizeof(struct gettimeofday_retvals));
				return -EFAULT;
			}
		} else {
			pretvals->has_tv = 0;
		}
		if (tz) {
			pretvals->has_tz = 1;
			if (copy_from_user (&pretvals->tz, tz, sizeof(struct timezone))) {
				printk ("Pid %d cannot copy tz from user\n", current->pid);
				ARGSKFREE (pretvals, sizeof(struct gettimeofday_retvals));
				return -EFAULT;
			}
		} else {
			pretvals->has_tz = 0;
		}

	}

	new_syscall_exit (78, rc, pretvals);

	return rc;
}

static asmlinkage long 
replay_gettimeofday (struct timeval __user *tv, struct timezone __user *tz)
{
	struct gettimeofday_retvals* retparams = NULL;
	long rc = get_next_syscall (78, (char **) &retparams, NULL);

	DPRINT ("Pid %d replays gettimeofday(tv=%p,tz=%p) returning %ld\n", current->pid, tv, tz, rc);
	if (retparams) {
		if (retparams->has_tv && tv) {
			if (copy_to_user (tv, &retparams->tv, sizeof(struct timeval))) {
				printk ("Pid %d cannot copy tv to user\n", current->pid);
				return syscall_mismatch();
			}
		}
		if (retparams->has_tz && tz) {
			if (copy_to_user (tz, &retparams->tz, sizeof(struct timezone))) {
				printk ("Pid %d cannot copy tz to user\n", current->pid);
				return syscall_mismatch();
			}
		}
	}
	return rc;
}

asmlinkage long 
shim_gettimeofday (struct timeval __user *tv, struct timezone __user *tz)
SHIM_CALL(gettimeofday, 78, tv, tz);

asmlinkage long 
shim_settimeofday (struct timeval __user *tv, struct timezone __user *tz)
SHIM_NOOP(settimeofday, tv, tz)

asmlinkage long 
shim_getgroups16 (int gidsetsize, old_gid_t __user *grouplist)
SHIM_NOOP(getgroups16, gidsetsize, grouplist)

asmlinkage long 
shim_setgroups16 (int gidsetsize, old_gid_t __user *grouplist)
SHIM_NOOP(setgroups16, gidsetsize, grouplist)

struct sel_arg_struct; /* Forward declaration */
asmlinkage int 
shim_old_select (struct sel_arg_struct __user *arg) 
SHIM_NOOP(old_select, arg)

static asmlinkage long 
record_symlink (const char __user *oldname, const char __user *newname)
{
	long rc;

	new_syscall_enter (83, NULL);

	rc = sys_symlink (oldname, newname);
	DPRINT ("Pid %d records symlink returning %ld\n", current->pid, rc);

	new_syscall_exit (83, rc, NULL);

	return rc;
}

GENERIC_REPLAY(symlink, 83, const char __user *oldname, const char __user *newname);

asmlinkage long shim_symlink (const char __user *oldname, const char __user *newname) SHIM_CALL(symlink, 83, oldname, newname);

asmlinkage long 
shim_lstat (char __user * filename, struct __old_kernel_stat __user * statbuf)
SHIM_NOOP(lstat, filename, statbuf)

static asmlinkage long 
record_readlink (const char __user *path, char __user *buf, int bufsiz)
{
	char* recbuf = NULL;
	long rc;

	new_syscall_enter (85, NULL);

	rc = sys_readlink (path, buf, bufsiz);
	DPRINT ("Pid %d records readlink returning %ld\n", current->pid, rc);

	if (rc > 0) {
		recbuf = ARGSKMALLOC(rc, GFP_KERNEL);
		if (recbuf == NULL) {
			printk("record_readlink: can't allocate buffer(%ld)\n", rc);
			return -ENOMEM;
		}
		if (copy_from_user (recbuf, buf, rc)) {
			ARGSKFREE (recbuf, rc);
			return -EFAULT;
		}
	}

	new_syscall_exit (85, rc, recbuf);

	return rc;
}

static asmlinkage long 
replay_readlink (const char __user *path, char __user *buf, int bufsiz)
{
	char* retparams = NULL;
	long rc = get_next_syscall (85, &retparams, NULL);
	DPRINT ("Pid %d replays readlink of %s with rc %ld\n", current->pid, path, rc);
	if (retparams) {
		if (copy_to_user (buf, retparams, rc)) {
			printk ("Pid %d replay_readlink cannot copy to user\n", current->pid);
		}
	}
	return rc;
}

asmlinkage long 
shim_readlink (const char __user *path, char __user *buf, int bufsiz)
SHIM_CALL(readlink, 85, path, buf, bufsiz)

asmlinkage long 
shim_uselib (const char __user * library) SHIM_NOOP(uselib, library)

asmlinkage long 
shim_swapon (const char __user * specialfile, int swap_flags)
SHIM_NOOP(swapon, specialfile, swap_flags)

asmlinkage long 
shim_reboot (int magic1, int magic2, unsigned int cmd, void __user * arg)
SHIM_NOOP(reboot, magic1, magic2, cmd, arg)

asmlinkage long 
shim_old_readdir (unsigned int fd, struct old_linux_dirent __user * dirent, 
		  unsigned int count)
SHIM_NOOP(old_readdir, fd, dirent, count)

// old_mmap is a shim that calls sys_mmap_pgoff - we handle record/replay there instead

static asmlinkage long 
record_munmap (unsigned long addr, size_t len)
{
	long rc;

	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (91, NULL);

	rc = sys_munmap (addr, len);
	MPRINT ("Pid %d records munmap of addr %lx returning %ld\n", current->pid, addr, rc);

	new_syscall_exit (91, rc, NULL);
	rg_unlock(current->record_thrd->rp_group);

	return rc;
}

static asmlinkage long 
replay_munmap (unsigned long addr, size_t len)
{
	u_long retval, rc;

	if (current->replay_thrd->app_syscall_addr > 1) {
		rc = current->replay_thrd->rp_saved_rc;
		(*(int*)(current->replay_thrd->app_syscall_addr)) = 999;
	} else {
		rc = get_next_syscall (91, NULL, NULL);
	}

	retval = sys_munmap (addr, len);
	MPRINT ("Pid %d replays munmap of addr %lx len %d returning %ld\n", current->pid, addr, len, retval);
	if (rc != retval) {
		printk ("Replay munmap returns different value %lu than %lu\n",	retval, rc);
		return syscall_mismatch();
	}
	if (retval == 0 && current->replay_thrd->app_syscall_addr) preallocate_after_munmap (addr, len);
	
	return rc;
}

asmlinkage long 
shim_munmap (unsigned long addr, size_t len) 
SHIM_CALL(munmap, 91, addr, len);

asmlinkage long 
shim_truncate (const char __user * path, unsigned long length)
SHIM_NOOP(truncate, path, length)

static asmlinkage long 
record_ftruncate (unsigned int fd, unsigned long length)
{
	long rc;

	new_syscall_enter (93, NULL);
	rc = sys_ftruncate (fd, length);
	new_syscall_exit (93, rc, NULL);
	DPRINT ("Pid %d records ftruncate returning %ld\n", current->pid, rc);

	return rc;
}

GENERIC_REPLAY(ftruncate, 93, unsigned int fd, unsigned long length);

asmlinkage long shim_ftruncate (unsigned int fd, unsigned long length) SHIM_CALL(ftruncate, 93, fd, length);

static asmlinkage long 
record_fchmod (unsigned int fd, mode_t mode)
{
	long rc;

	new_syscall_enter (94, NULL);

	rc = sys_fchmod (fd, mode);
	MPRINT ("Pid %d record_fchmod rc %ld\n", current->pid, rc);

	new_syscall_exit (94, rc, NULL);

	return rc;
}

GENERIC_REPLAY(fchmod, 94, unsigned int fd, mode_t mode);

asmlinkage long shim_fchmod (unsigned int fd, mode_t mode) SHIM_CALL(fchmod, 94, fd, mode);

asmlinkage long 
shim_fchown16 (unsigned int fd, old_uid_t user, old_gid_t group)
SHIM_NOOP(fchown16, fd, user, group)

asmlinkage long 
shim_getpriority(int which, int who) SHIM_NOOP(getpriority, which, who)

asmlinkage long 
shim_setpriority (int which, int who, int niceval) 
SHIM_NOOP(setpriority, which, who, niceval)


struct statfs; // no protoype

asmlinkage long
record_statfs (const char __user * path, struct statfs __user *buf)
{
	long rc;
	struct statfs *pretval = NULL;
	
	new_syscall_enter (99, NULL);

	rc = sys_statfs (path, buf);
	DPRINT ("Pid %d records statfs returning %ld\n", current->pid, rc);

	if (rc == 0) {
		pretval = ARGSKMALLOC (sizeof(struct statfs), GFP_KERNEL);
		if (pretval == NULL) {
			printk ("record_statfs: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, buf, sizeof(struct statfs))) {
			ARGSKFREE(pretval, sizeof(struct statfs));
			pretval = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (99, rc, pretval);
	return rc;
}

asmlinkage long
replay_statfs (const char __user *path, struct statfs __user *buf)
{
	struct statfs *retparams = NULL;

	long rc = get_next_syscall (99, (char **) &retparams, NULL);

	if (retparams) {
		if (copy_to_user (buf, retparams, sizeof(struct statfs))) {
			printk ("Pid %d replay_statfs cannot copy to user\n", current->pid);
			return syscall_mismatch();
		}
	}
	return rc;
}

asmlinkage long 
shim_statfs (const char __user * path, struct statfs __user * buf)
SHIM_CALL(statfs, 99, path, buf)

asmlinkage long
record_fstatfs (unsigned int fd, struct statfs __user *buf)
{
	long rc;
	struct statfs *pretval = NULL;

	new_syscall_enter (100, NULL);
	
	rc = sys_fstatfs (fd, buf);
	DPRINT ("Pid %d records fstatfs returning %ld\n", current->pid, rc);

	if (rc == 0) {
		pretval = ARGSKMALLOC (sizeof(struct statfs), GFP_KERNEL);
		if (pretval == NULL) {
			printk ("record_fstatfs: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, buf, sizeof (struct statfs))) {
			ARGSKFREE(pretval, sizeof(struct statfs));
			pretval = NULL;
			rc = -EFAULT;
		}
	}
	
	new_syscall_exit (100, rc, pretval);
	return rc;
}

asmlinkage long
replay_fstatfs (unsigned int fd, struct statfs __user *buf)
{
	struct statfs *retparams = NULL;

	long rc = get_next_syscall (100, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (buf, retparams, sizeof(struct statfs))) {
			printk("Pid %d replay_fstatfs cannot copy to user\n", current->pid);
			return syscall_mismatch();
		}
	}
	return rc;
}

asmlinkage long 
shim_fstatfs (unsigned int fd, struct statfs __user * buf)
SHIM_CALL(fstatfs, 100, fd, buf)

/* No prototype for sys_ioperm */
asmlinkage long sys_ioperm(unsigned long from, unsigned long num, int turn_on);
asmlinkage long shim_ioperm (unsigned long from, unsigned long num, 
			     int turn_on)
SHIM_NOOP(ioperm, from, num, turn_on)

/* Copied from net/socket.c */
/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nargs[21] = {
	AL(0), AL(3), AL(3), AL(3), AL(2), AL(3),
	AL(3), AL(3), AL(4), AL(4), AL(4), AL(6),
	AL(6), AL(2), AL(5), AL(5), AL(3), AL(3),
	AL(4), AL(5), AL(4)
};

#undef AL

struct sendto_args {
	char* buf;
	char* to;
};

static asmlinkage long 
record_socketcall(int call, unsigned long __user *args)
{
	long rc;
	unsigned long a[6];
	unsigned int len;

	DPRINT ("Pid %d in record_socketcall(%d)\n", current->pid, call);

	if (call < 1 || call > SYS_RECVMSG) return -EINVAL;

	len = nargs[call];
	if (len > sizeof(a))
		return -EINVAL;

	if (copy_from_user (a, args, len)) {
		printk ("record_socketcall: cannot copy arguments\n");
		return -EFAULT;
	}

	new_syscall_enter (102, NULL);

	rc = sys_socketcall (call, args);

	DPRINT ("Pid %d records socketcall %d returning %ld\n", current->pid, call, rc);

	switch (call) {
	case SYS_CONNECT:
	{
#ifdef MULTI_COMPUTER
		// mcc: hack to get the host and host port of the connect
		if ((rc == 0) && (a[2]) && (a[2] == sizeof(struct sockaddr_in))) {
			int prc;
			mm_segment_t old_fs;
			int socket_fd = a[0];
			struct accept_retvals* pretvals = NULL;
			struct sockaddr_in* tmp;
			long addrlen;
			addrlen = a[2];
			pretvals = ARGSKMALLOC (sizeof(struct accept_retvals) + addrlen, GFP_KERNEL);
			if (pretvals == NULL) {
				printk("record_socketcall(connect): can't allocate buffer\n");
				return -ENOMEM;
			}
			pretvals->addrlen = addrlen;
			
			old_fs = get_fs();
			set_fs(KERNEL_DS);
			prc = sys_getsockname(socket_fd, (struct sockaddr *)(&pretvals->addr), (int *)(&pretvals->addrlen));
			set_fs(old_fs);

			if (prc < 0) {
				printk("Pid %d - record_socketcall(connect) - the extra getsockname call failed\n", current->pid);
				ARGSKFREE (pretvals, sizeof(struct accept_retvals) + addrlen);
				pretvals = NULL;
				new_syscall_exit(102, rc, pretvals);
				return rc;
			}

			tmp = (struct sockaddr_in*)(&pretvals->addr);

			pretvals->call = call;
			new_syscall_exit (102, rc, pretvals);
			return rc;
		} else {
			struct accept_retvals* pretvals = NULL;
			pretvals = ARGSKMALLOC(sizeof(struct accept_retvals), GFP_KERNEL);
			if (pretvals == NULL) {
				printk("record_socketcall(socket): can't allocate buffer\n");
				return -ENOMEM;
			}
			pretvals->call = call;
			atomic_set(&pretvals->refcnt, 1);
			pretvals->addrlen = 0;
			new_syscall_exit (102, rc, pretvals);
			return rc;
		}
#else
		struct generic_socket_retvals* pretvals = NULL;
		pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_socketcall(socket): can't allocate buffer\n");
			return -ENOMEM;
		}
		pretvals->call = call;
		atomic_set(&pretvals->refcnt, 1);
		new_syscall_exit (102, rc, pretvals);
		return rc;
#endif
	}
	case SYS_SOCKET:
	case SYS_BIND:
	case SYS_LISTEN:
	case SYS_SEND:
	case SYS_SENDTO:
	case SYS_SHUTDOWN:
	case SYS_SETSOCKOPT:
	case SYS_SENDMSG:
	{
		struct generic_socket_retvals* pretvals = NULL;
		pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_socketcall(socket): can't allocate buffer\n");
			return -ENOMEM;
		}
		pretvals->call = call;
		atomic_set(&pretvals->refcnt, 1);
		new_syscall_exit (102, rc, pretvals);
		return rc;
	}
#ifdef MULTI_COMPUTER
	case SYS_ACCEPT:
	{
		// if accept returns a valid socket, we'll call getpeername and get those retvals
		if (rc > 0) {
			if (a[1]) {
				int prc;
				struct accept_retvals* pretvals = NULL;
				long addrlen;
				mm_segment_t old_fs;
				long sock_addrlen;
				struct sockaddr_in6* sin6;

				addrlen = *((int *) a[2]);
				sock_addrlen = sizeof(struct sockaddr_in6);

				printk("Pid %d - record_socketcall(accept) wants retvals\n", current->pid);
				printk("Pid %d - record_socketcall(accept) addrlen is %lu\n", current->pid, addrlen);

				pretvals = ARGSKMALLOC(sizeof(struct accept_retvals) + addrlen + addrlen, GFP_KERNEL);
				if (pretvals == NULL) {
					printk("record_socketcall(accept): can't allocate buffer\n");
					return -ENOMEM;
				}
				pretvals->addrlen = addrlen;
				if (addrlen) {
					if (copy_from_user(&pretvals->addr, (char *) a[1], addrlen)) {
						printk("record_socketcall(accept): can't copy addr\n");
						ARGSKFREE (pretvals, sizeof(struct accept_retvals) + addrlen);
						return -EFAULT;
					}
				} 
				pretvals->call = call;
				atomic_set(&pretvals->refcnt, 1);

				printk("  Pid %d - record_socketcall(accept) sock_addrlen is %ld\n", current->pid, sock_addrlen);

				old_fs = get_fs();
				set_fs(KERNEL_DS);
				prc = sys_getsockname(rc, (struct sockaddr *)((char *)(&pretvals->addr) + addrlen), (int *)(&sock_addrlen));
				set_fs(old_fs);
				pretvals->addrlen = addrlen + sock_addrlen;
				
				sin6 = (struct sockaddr_in6 *)((char *)(&pretvals->addr) + addrlen);
				printk("  Pid %d - record_socketcall(accept) sock_addrlen is %ld\n", current->pid, sock_addrlen);
				printk("  Pid %d - record_socketcall(accept) pretvals->addrlen is %d\n", current->pid, pretvals->addrlen);
				printk("  Pid %d - ntohs(sin6->sin_port) %d\n", current->pid, ntohs(sin6->sin6_port));

				new_syscall_exit (102, rc, pretvals);
				return rc;
			} else { // we don't save them, so we'll have to save them
				int prc;
				mm_segment_t old_fs;
				struct accept_retvals* peer_retvals = NULL;
				long peerlen = sizeof(struct sockaddr_in);

				printk("Pid %d - record_socketcall(accept) does not save peer's retvals, we'll save them\n", current->pid);
				printk("Pid %d - record_socketcall(accept) we'll allocate %lu bytes of retvals, peerlen is %lu\n", current->pid, sizeof(struct accept_retvals) + peerlen, peerlen);

				peer_retvals = ARGSKMALLOC(sizeof(struct accept_retvals) + peerlen, GFP_KERNEL);
				if (peer_retvals == NULL) {
					printk("record_socketcall(accept): couldn't allocate peer_retvals\n");
					return -ENOMEM;
				}

				peer_retvals->addrlen = peerlen;

				old_fs = get_fs();
				set_fs(KERNEL_DS);
				prc = sys_getpeername(rc, (struct sockaddr *)(&peer_retvals->addr), (int *)(&peer_retvals->addrlen));
				set_fs(old_fs);
				
				printk("Pid %d - record_socketcall(accept) - getpeername returns addrlen %d\n", current->pid, peer_retvals->addrlen);
				if (prc < 0) {
					printk("Pid %d - record_socketcall(accept) - the extra getpeername call failed\n", current->pid);
					ARGSKFREE (peer_retvals, sizeof(struct accept_retvals) + peerlen);
					peer_retvals = NULL;
					new_syscall_exit(102, rc, peer_retvals);
					return rc;
				}

				peer_retvals->call = call;
				new_syscall_exit (102, rc, peer_retvals);
				return rc;
			}
		}
		printk("Pid %d - record_socketcall(accept) returned %d\n", current->pid, rc);
		new_syscall_exit (102, rc, NULL);
		return rc;
	}
#else
	case SYS_ACCEPT:
#endif
	case SYS_GETSOCKNAME:
	case SYS_GETPEERNAME:
	{
		struct accept_retvals* pretvals = NULL;
		long addrlen;
		DPRINT ("Pid %d record_socketcall %d\n", current->pid, call);
		if (rc >= 0) {
			if (a[1]) {
				addrlen = *((int *) a[2]);
			} else {
				addrlen = 0;
			}
			pretvals = ARGSKMALLOC(sizeof(struct accept_retvals) + addrlen, GFP_KERNEL);
			if (pretvals == NULL) {
				printk("record_socketcall(accept): can't allocate buffer\n");
				return -ENOMEM;
			}
			pretvals->addrlen = addrlen;
			if (addrlen) {
				if (copy_from_user(&pretvals->addr, (char *) a[1], addrlen)) {
					printk("record_socketcall(accept): can't copy addr\n");
					ARGSKFREE (pretvals, sizeof(struct accept_retvals) + addrlen);
					return -EFAULT;
				}
			} 
			pretvals->call = call;
			atomic_set(&pretvals->refcnt, 1);
		}
		new_syscall_exit (102, rc, pretvals);
		return rc;
	}
	case SYS_SOCKETPAIR:
	{
		
		struct socketpair_retvals* pretvals = NULL;
		int* sv;
		if (rc >= 0) {
			sv = (int *) a[3];
			pretvals = ARGSKMALLOC(sizeof(struct socketpair_retvals), GFP_KERNEL);
			if (pretvals == NULL) {
				printk("record_socketcall(socketpair): can't allocate buffer\n");
				return -ENOMEM;
			}
			pretvals->call = call;
			pretvals->sv0 = *(sv);
			pretvals->sv1 = *(sv+1);
			atomic_set(&pretvals->refcnt, 1);
		}
		new_syscall_exit (102, rc, pretvals);
		return rc;

	}
	case SYS_RECV: 
	{
		struct recvfrom_retvals* pretvals = NULL;
		if (rc >= 0) {
			pretvals = ARGSKMALLOC(sizeof(struct recvfrom_retvals) + rc, GFP_KERNEL);
			if (pretvals == NULL) {
				printk("record_socketcall(recv): can't allocate data buffer of size %ld\n", sizeof(struct recvfrom_retvals)+rc-1);
				return -ENOMEM;
			}
			if (copy_from_user (&pretvals->buf, (char *) a[1], rc)) {
				printk("record_socketcall(recv): can't copy data buffer of size %ld\n", rc);
				ARGSKFREE (pretvals, sizeof(struct recvfrom_retvals) + rc);
				return -EFAULT;
			}
			pretvals->call = call;
			atomic_set(&pretvals->refcnt, 1);
		}

		new_syscall_exit (102, rc, pretvals);
		return rc;
	}
	case SYS_RECVFROM: 
	{
		struct recvfrom_retvals* pretvals = NULL;
		if (rc >= 0) {

			pretvals = ARGSKMALLOC(sizeof(struct recvfrom_retvals)+rc-1, GFP_KERNEL);
			if (pretvals == NULL) {
				printk("record_socketcall(recvfrom): can't allocate buffer\n");
				return -ENOMEM;
			}

			if (copy_from_user (&pretvals->buf, (char *) a[1], rc)) {
				printk("record_socketcall(recvfrom): can't copy data buffer of size %ld\n", rc);
				ARGSKFREE (pretvals, sizeof(struct recvfrom_retvals)+rc-1);
				return -EFAULT;
			}
			if (a[4]) {
				pretvals->addrlen = *((int*)a[5]);
				if (pretvals->addrlen > sizeof(struct sockaddr)) {
					printk("record_socketcall(recvfrom): addr length %d too big\n", pretvals->addrlen);
					KFREE (pretvals);
					return -EFAULT;
				}
				if (copy_from_user(&pretvals->addr, (char *) args[4], pretvals->addrlen)) {
					printk("record_socketcall(recvfrom): can't copy addr\n");
					ARGSKFREE (pretvals, sizeof(struct recvfrom_retvals)+rc-1);
					return -EFAULT;
				}
			}
			pretvals->call = call;
			atomic_set(&pretvals->refcnt, 1);
		}

		new_syscall_exit (102, rc, pretvals);
		return rc;
	}
	case SYS_RECVMSG:
	{
		struct recvmsg_retvals* pretvals = NULL;
		if (rc >= 0) {
			struct msghdr *pmsghdr = (struct msghdr *) a[1];

			// check 
			if(pmsghdr->msg_namelen > SIMPLE_MSGHDR_SIZE || pmsghdr->msg_controllen > SIMPLE_MSGHDR_SIZE || pmsghdr->msg_iovlen > 1) {
				printk("[ERROR] record_socketcall(recvmsg): can't support recvmsg at this time... \n");
				return -EFAULT;
			}

			// record 
			pretvals = ARGSKMALLOC(sizeof(struct recvmsg_retvals)+rc-1, GFP_KERNEL);
			if (pretvals == NULL) {
				printk("record_socketcall(recvmsg): can't allocate buffer\n");
				return -ENOMEM;
			}
			if (copy_from_user (&pretvals->msg_name, (char *) pmsghdr->msg_name, pmsghdr->msg_namelen)) {
				printk("record_socketcall(recvmsg): can't copy msg_name of size %d\n", pmsghdr->msg_namelen);
				ARGSKFREE (pretvals, sizeof(struct recvmsg_retvals)+rc-1);
				return -EFAULT;
			}
			pretvals->msg_namelen = pmsghdr->msg_namelen;
			
			if (copy_from_user (&pretvals->msg_control, (char *) pmsghdr->msg_control, pmsghdr->msg_controllen)) {
				printk("record_socketcall(recvmsg): can't copy msg_control of size %d\n", pmsghdr->msg_controllen);
				ARGSKFREE (pretvals, sizeof(struct recvmsg_retvals)+rc-1);
				return -EFAULT;
			}
			pretvals->msg_controllen = pmsghdr->msg_controllen;

			if (copy_from_user (&pretvals->msg_flags, (char *) &pmsghdr->msg_flags, sizeof(unsigned int))) {
				printk("record_socketcall(recvmsg): can't copy msg_flags of size %d\n", sizeof(unsigned int));
				ARGSKFREE (pretvals, sizeof(struct recvmsg_retvals)+rc-1);
				return -EFAULT;
			}

			if (copy_from_user (&pretvals->iov_base, (char *) pmsghdr->msg_iov[0].iov_base, rc)) {
				printk("record_socketcall(recvfrom): can't copy msg_iov of size %ld\n", rc);
				ARGSKFREE (pretvals, sizeof(struct recvmsg_retvals)+rc-1);
				return -EFAULT;
			}
			pretvals->iov_len = pmsghdr->msg_iov[0].iov_len;
			pretvals->call = call;
			atomic_set(&pretvals->refcnt, 1);
		}

		new_syscall_exit (102, rc, pretvals);
		return rc;

	}
	case SYS_GETSOCKOPT: 
	{
		struct getsockopt_retvals* pretvals = NULL;
		long sockopt_size;
		if (rc >= 0) {
			sockopt_size = *((int*) a[4]);
			pretvals = ARGSKMALLOC(sizeof(struct getsockopt_retvals)+sockopt_size, GFP_KERNEL);
			if (a[3]) {
				if (copy_from_user (&pretvals->optval, (char *) a[3], sockopt_size)) {
					printk("record_socketcall(getsockopt): can't copy optval of size %ld\n", sockopt_size);
					ARGSKFREE (pretvals, sizeof(struct getsockopt_retvals)+sockopt_size);
					return -EFAULT;
				}
			} else {
				pretvals->optval = 0;
			}
			pretvals->call = call;
			pretvals->optlen = sockopt_size;
			atomic_set(&pretvals->refcnt, 1);	
		}
		new_syscall_exit (102, rc, pretvals);
		return rc;
	}
	default:
		printk ("Socketcall type %d not handled\n", call);
		return -EINVAL;
	}
}

static asmlinkage long 
replay_socketcall (int call, unsigned long __user *args)
{
	char* retparams = NULL;
	long rc;
	unsigned long kargs[6];
	unsigned int len;

	DPRINT ("Pid %d in replay_socketcall(%d)\n", current->pid, call);

	if (call < 1 || call > SYS_RECVMSG) return -EINVAL;

	len = nargs[call];
	if (len > sizeof(kargs)) return -EINVAL;

	if (copy_from_user (kargs, args, len)) return -EFAULT;

	rc = get_next_syscall (102, &retparams, NULL);

	DPRINT ("Pid %d, replay_socketcall %d, rc is %ld\n", current->pid, call, rc);

	switch (call) {
	case SYS_SOCKET:
	case SYS_CONNECT:
	case SYS_BIND:
	case SYS_LISTEN:
	case SYS_SEND:
	case SYS_SENDTO:
	case SYS_SHUTDOWN:
	case SYS_SETSOCKOPT:
	case SYS_SENDMSG:
		return rc;
	case SYS_ACCEPT:
		if (rc >= 0) {
			struct accept_retvals* retvals = (struct accept_retvals *) retparams;
			if (retvals == NULL) {
				printk ("[DIFF] Pid %d replay_socketcall(accept): no return parameters\n", current->pid);
				goto error;
			}
			if (kargs[1]) {
				*((int *) kargs[2]) = retvals->addrlen;
				if (copy_to_user ((char *) args[1], &retvals->addr, retvals->addrlen)) {
					printk ("Pid %d replay_socketcall_accept cannot copy to user\n", current->pid);
				}
			}
		}
		return rc;
	case SYS_GETSOCKNAME:
	case SYS_GETPEERNAME:
		if (rc >= 0) {
			struct accept_retvals* retvals = (struct accept_retvals *) retparams;
			if (retvals == NULL) {
				printk ("[DIFF]replay_socketcall(getsockname/getpeername): no return parameters\n");
				goto error;
			}
			*((int *) kargs[2]) = retvals->addrlen;
			if (copy_to_user ((char *) args[1], &retvals->addr, retvals->addrlen)) {
				printk ("Pid %d replay_socketcall_getpeername cannot copy to user\n", current->pid);
			}
		}
		return rc;
	case SYS_SOCKETPAIR:
		if (rc >= 0) {
			
			int* sv;
			struct socketpair_retvals* retvals = (struct socketpair_retvals *) retparams;
			if (retvals == NULL) {
				printk ("[DIFF]replay_socketcall(socketpair): no return parameters\n");
				goto error;
			}
			

			sv = (int *) KMALLOC(2 * sizeof(int), GFP_KERNEL);
			*sv = retvals->sv0;
			*(sv+1) = retvals->sv1;

			if (copy_to_user ((int *) args[3], sv, 2 * sizeof(int))) {
			       printk ("Pid %d replay_socketcall_socketpair cannot copy to user\n", current->pid);
			}	       

			KFREE(sv);
		}
		return rc;
		
	case SYS_RECV:
		if (rc >= 0) {
			struct recvfrom_retvals* retvals = (struct recvfrom_retvals *) retparams;
			if (retvals == NULL) {
				printk ("[DIFF]replay_socketcall(recv): no return parameters\n");
				goto error;
			}
			if (copy_to_user ((char *) kargs[1], &retvals->buf, rc)) {
				printk ("Pid %d replay_socketcall_recv cannot copy to user\n", current->pid);
			}
		}
		return rc;
	case SYS_RECVFROM:
		if (rc >= 0) {
			struct recvfrom_retvals* retvals = (struct recvfrom_retvals *) retparams;
			if (retvals == NULL) {
				printk ("[DIFF]replay_socketcall(recvfrom): no return parameters\n");
				goto error;
			}
			if (copy_to_user ((char *) kargs[1], &retvals->buf, rc)) {
				printk ("Pid %d replay_socketcall_recvfrom cannot copy to user\n", current->pid);
			}
			if (kargs[4]) {
				*((int *) kargs[5]) = retvals->addrlen;
				if (copy_to_user ((char *) kargs[4], &retvals->addr, retvals->addrlen)) {
					printk ("Pid %d cannot copy sockaddr from to user\n", current->pid);
				}

			}
		}
		return rc;
	case SYS_RECVMSG:
		if (rc >= 0) {
			struct recvmsg_retvals* retvals = (struct recvmsg_retvals *) retparams;
			struct msghdr *msg = (struct msghdr *)args[1];
			if (retvals == NULL) {
				printk ("[DIFF]replay_socketcall(recvmsg): no return parameters\n");
				goto error;
			}

			if (copy_to_user ((char *) msg->msg_name, &retvals->msg_name, retvals->msg_namelen)) {
				printk ("Pid %d cannot copy msg_name to user\n", current->pid);
			}

			if (copy_to_user ((char *) msg->msg_control, &retvals->msg_control, retvals->msg_controllen)) {
				printk ("Pid %d cannot copy msg_name to user\n", current->pid);
			}

			if (copy_to_user ((char *) &msg->msg_flags, &retvals->msg_flags, sizeof(unsigned int))) {
				printk ("Pid %d cannot copy msg_name to user\n", current->pid);
			}

			if (copy_to_user ((char *) msg->msg_iov[0].iov_base, &retvals->iov_base, rc)) {
				printk ("Pid %d cannot copy msg_name to user\n", current->pid);
			}
		}
		return rc;
	case SYS_GETSOCKOPT:
		if (rc >= 0) {
			struct getsockopt_retvals* retvals = (struct getsockopt_retvals *) retparams;
			if (retvals == NULL) {
				printk ("[DIFF]replay_socketcall(getsockopt): no return parameters\n");
				goto error;
			}

			if (copy_to_user ((char*) args[3], &retvals->optval, retvals->optlen)) {
				printk ("Pid %d cannot copy optval to user\n", current->pid);
			}

			if (copy_to_user ((char *) args[4], &retvals->optlen, sizeof(int))) {
				printk ("Pid %d cannot copy optlen to user\n", current->pid);
			}
		}
		return rc;
	}
error:
	return syscall_mismatch();
}

asmlinkage long 
shim_socketcall (int call, unsigned long __user *args)
SHIM_CALL(socketcall, 102, call, args)

asmlinkage long 
shim_syslog (int type, char __user *buf, int len) 
SHIM_NOOP(syslog, type, buf, len)

static asmlinkage long 
record_setitimer(int which, struct itimerval __user *value, struct itimerval __user *ovalue)
{
	struct itimerval* pretval = NULL;
	long rc;

	new_syscall_enter (104, NULL);

	rc = sys_setitimer (which, value, ovalue);
	DPRINT ("Pid %d records setitimer returning %ld\n", current->pid, rc);

	if (rc == 0 && ovalue) {
		pretval = ARGSKMALLOC(sizeof(struct itimerval), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_setitimer: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, ovalue, sizeof(struct itimerval))) {
			ARGSKFREE (pretval, sizeof(struct itimerval));
			return -EFAULT;
		}
	}

	new_syscall_exit (104, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_setitimer(int which, struct itimerval __user *value, struct itimerval __user *ovalue)
{
	char* retparams = NULL;
	long rc = get_next_syscall (104, &retparams, NULL);
	if (retparams) {
		if (copy_to_user (ovalue, retparams, sizeof(struct itimerval))) {
			printk ("Pid %d replay_setitimer cannot copy to user\n", current->pid);
		}
	}
	return rc;
}

asmlinkage long 
shim_setitimer (int which, struct itimerval __user *value, struct itimerval __user *ovalue)
SHIM_CALL(setitimer, 104, which, value, ovalue);

asmlinkage long 
shim_getitimer (int which, struct itimerval __user *value)
SHIM_NOOP(getitimer, which, value)

asmlinkage long 
shim_newstat (char __user *filename, struct stat __user *statbuf)
SHIM_NOOP(newstat, filename, statbuf)

asmlinkage long 
shim_newlstat (char __user *filename, struct stat __user *statbuf)
SHIM_NOOP(newlstat, filename, statbuf)

asmlinkage long 
shim_newfstat (unsigned int fd, struct stat __user *statbuf)
SHIM_NOOP(newfstat, fd, statbuf)

asmlinkage int 
shim_uname (struct old_utsname __user * name) SHIM_NOOP(uname, name)

// I believe ptregs_iopl is deterministic, so don't intercept it

asmlinkage long shim_vhangup (void) SHIM_NOOP(vhangup)

void do_sys_vm86(struct kernel_vm86_struct *info, struct task_struct *tsk); /* No prtototype - in vm86_32.c */

void shim_vm86old(struct kernel_vm86_struct *info, struct task_struct *tsk)
{
	if (current->record_thrd) printk ("Record pid %d calls vm86old\n", current->pid);
	if (current->replay_thrd) printk ("Replay pid %d calls vm86old\n", current->pid);
	return do_sys_vm86(info, tsk);
}

struct wait4_retvals {
	int           stat_addr;
	struct rusage ru;
};

static asmlinkage long 
record_wait4 (pid_t upid, int __user *stat_addr, int options, struct rusage __user *ru) 
{
	long rc;
	struct wait4_retvals* retvals = NULL;

	new_syscall_enter (114, NULL);
	rc = sys_wait4 (upid, stat_addr, options, ru);
	DPRINT ("Pid %d records wait4 returning %ld\n", current->pid, rc);

	if (rc >= 0) {
		retvals = ARGSKMALLOC(sizeof(struct wait4_retvals), GFP_KERNEL);
		if (retvals == NULL) {
			printk("record_wait4: can't allocate buffer\n");
			return -ENOMEM;
		}

		if (stat_addr) {
			if (copy_from_user (&retvals->stat_addr, stat_addr, sizeof(int))) {
				printk ("record_wait4: unable to copy status from user\n");
				ARGSKFREE (retvals, sizeof(struct wait4_retvals));
				return -EFAULT;
			}
		}
		if (ru) {
			if (copy_from_user (&retvals->ru, ru, sizeof(struct rusage))) {
				printk ("record_wait4: unable to copy rusage from user\n");
				ARGSKFREE (retvals, sizeof(struct wait4_retvals));
				return -EFAULT;
			}
		}
	}

	new_syscall_exit (114, rc, retvals);

	return rc;
}

static asmlinkage long 
replay_wait4 (pid_t upid, int __user *stat_addr, int options, struct rusage __user *ru) 
{
	struct wait4_retvals* pretvals;
	long rc = get_next_syscall (114, (char **) &pretvals, NULL);
	if (rc >= 0) {
		if (stat_addr) {
			if (copy_to_user (stat_addr, &pretvals->stat_addr, sizeof(int))) {
				printk ("Pid %d replay_wait4 cannot copy status to user\n", current->pid);
				return syscall_mismatch();
			}
		}
		if (ru) {
			if (copy_to_user (ru, &pretvals->ru, sizeof(struct rusage))) {
				printk ("Pid %d replay_wait4 cannot copy status to user\n", current->pid);
				return syscall_mismatch();
			}
		}
	}

	DPRINT ("Pid %d replays wait4 returning %ld\n", current->pid, rc);
	return rc;
}

asmlinkage long shim_wait4 (pid_t upid, int __user *stat_addr, int options, struct rusage __user *ru) SHIM_CALL(wait4, 114, upid, stat_addr, options, ru);

asmlinkage long 
shim_swapoff (const char __user * specialfile) SHIM_NOOP(swapoff, specialfile)

static asmlinkage long 
record_sysinfo (struct sysinfo __user * info)
{
	long rc;
	struct sysinfo* pretval = NULL;

	new_syscall_enter (116, NULL);

	rc = sys_sysinfo (info);
	DPRINT ("Pid %d records sysinfo returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct sysinfo), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_sysinfo: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, info, sizeof(struct sysinfo))) {
			ARGSKFREE (pretval, sizeof(struct sysinfo));
			return -EFAULT;
		}
	}

	new_syscall_exit (116, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_sysinfo (struct sysinfo __user * info)
{
	struct sysinfo* retparams = NULL;
	long rc = get_next_syscall (116, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (info, retparams, sizeof(struct sysinfo))) printk ("Pid %d cannot copy statbuf to user\n", current->pid);
	}
	DPRINT ("Pid %d sysinfo replay returns %ld\n", current->pid, rc);
	return rc;
}

asmlinkage long 
shim_sysinfo (struct sysinfo __user *info) SHIM_CALL(sysinfo, 116, info)

#if 0
// JNF - Need to clean up this implementation so as to remove Mike C's external refs that require kernel modification

static asmlinkage int
record_ipc (uint call, int first, int second, int third, void __user *ptr, long fifth)
{
	int rc;
	
	new_syscall_enter (117, NULL);

	DPRINT ("Pid %d about to call sys_ipc\n", current->pid);
	rc = sys_ipc (call, first, second, third, ptr, fifth);
	DPRINT ("Pid %d records ipc returning %d\n", current->pid, rc);

	switch (call) {
		case SHMAT:
		{
			struct shmat_retvals* pretvals = NULL;
			MPRINT ("Pid %d begin record_ipc(shmat) rc %d, first %d, second %d, third %d, ptr %p, fifth %lu\n", current->pid, rc, first, second, third, ptr, fifth);
			if (rc) {
				new_syscall_exit (117, rc, NULL);
				return rc;
			}
			pretvals = ARGSKMALLOC (sizeof(struct shmat_retvals), GFP_KERNEL);
			if (pretvals == NULL) {
				printk ("record_ipc(shmat) can't allocate buffer\n"); 
				return -ENOMEM;
			}
			pretvals->ipc_rv.call = call;
			pretvals->addr = *((ulong __user *) third);
			pretvals->size = get_shm_size(first);

			new_syscall_exit (117, rc, pretvals);

			DPRINT ("Pid %d end record_ipc(shmat) rc %d, addr %lx, size %d\n", current->pid, rc, pretvals->addr, pretvals->size);

			return rc;
			break;
		}
		case SHMGET:
		{
			struct ipc_retvals* pretvals = NULL;
			pretvals = ARGSKMALLOC (sizeof(struct ipc_retvals), GFP_KERNEL);
			pretvals->call = call;
			new_syscall_exit (117, rc, pretvals);
			MPRINT ("Pid %d record_ipc(shmget) call %d rc %d, first %d, second %d, third %d, ptr %p, fifth %lu\n", current->pid, call, rc, first, second, third, ptr, fifth);
			return rc;
		}
		case SEMOP:
		case SEMTIMEDOP:
		case SEMCTL:
		{
			struct sem_retvals* pretvals = NULL;
#ifndef IPC_SAVE
			pretvals = ARGSKMALLOC (sizeof(struct sem_retvals), GFP_KERNEL);
			pretvals->ipc_rv.call = call;
#endif
			new_syscall_exit (117, rc, pretvals);
			return rc;
		}
		case MSGSND: // XXX not tested/not guaranteed to work
		case MSGRCV: // XXX definitely doesn't work, will implement later
		case MSGGET: // XXX not tested/not guaranteed to work
		case MSGCTL: // XXX probably doesn't work right...
		{
			struct ipc_retvals* pretvals = NULL;
			pretvals = ARGSKMALLOC (sizeof(struct ipc_retvals), GFP_KERNEL);
			pretvals->call = call;
			new_syscall_exit (117, rc, pretvals);
			printk ("[NOOP]Pid %d record_ipc call %d not supporting, so use at your own peril!\n", current->pid, call);
			return rc;

		}
		case SEMGET:
		case SHMDT:
		case SHMCTL:
		default: {
			struct ipc_retvals* pretvals = NULL;
#ifndef IPC_SAVE
			pretvals = ARGSKMALLOC (sizeof(struct ipc_retvals), GFP_KERNEL);
			pretvals->call = call;
#endif
			new_syscall_exit (117, rc, pretvals);
			DPRINT ("Pid %d record_ipc call %d rc %d, first %d, second %d, third %d, ptr %p, fifth %lu\n", current->pid, call, rc, first, second, third, ptr, fifth);
			return rc;
		}
	}
}

// mcc: Note: System V IPC objects in the kernel are global. So you are most likely going
// to get different identifiers when you create new objects using get on record and replay.
// Therefore checking args and the return values (on some IPC syscalls) will fail.
// Don't check the return value for IPC syscalls that return an identifier, do check
// the return value for IPC syscalls that return an error.
static asmlinkage int
replay_ipc (uint call, int first, int second, int third, void __user *ptr, long fifth)
{
	int retval;
	char* retparams = NULL;
	ssize_t rc = get_next_syscall (117, &retparams, NULL);
	struct syscall_result* psr;
	struct replay_thread* prt;
	prt = current->replay_thrd;
	psr = &prt->rp_record_thread->rp_log[prt->rp_out_ptr - 1];

	switch (call) {
		case SHMAT:
		{
			// shmat is just like mmap, we'll give it the address it returned on record
			u_long raddr; 	// return address of do_mmap in do_shmat
			int sysv_rp_id;
			struct shmat_retvals* retvals;
			retvals = (struct shmat_retvals *) retparams;

			MPRINT ("Pid %d begin replay_ipc(shmat) rc %d, call %d, first %d, second %d, third %d, ptr %p, fifth %lu\n", current->pid, rc, call, first, second, third, ptr, fifth);

			if (retvals == NULL) {
				printk ("[DIFF]replay_ipc(shmat): no return parameters\n");
				return syscall_mismatch();
			}
			MPRINT ("Pid %d replay_ipc do_shmat first %d, addr %lx, size %d\n", current->pid, first, retvals->addr, second);
			
			// do_shmat checks to see if there are any existing mmaps in the region to be shmat'ed. So we'll have to munmap our preallocations for this region
			// before proceding.
			if (is_pin_attached()) {
				MPRINT ("  Pin is attached to pid %d - munmap preallocation at addr %lx size %d\n",
						current->pid, retvals->addr, retvals->size);
				retval = sys_munmap (retvals->addr, retvals->size);
				if (retval) {
					printk ("[WARN]Pid %d shmat failed to munmap the preallocation at addr %lx size %d\n",
							current->pid, retvals->addr, retvals->size);
				}

#ifdef REPLAY_PARANOID
				// because we're paranoid, we'll do the check for mmap before proceding
				if (find_vma_intersection(current->mm, retvals->addr, retvals->addr + retvals->size)) {
					printk ("[WARN]Pid %d shmat addr %lx size %d intersects with an existing memory mapping\n",
							current->pid, retvals->addr, retvals->addr + retvals->size);
				}
#endif
			}

			// redo the system call (which will do an actual mmap) with the return address from record
			// mcc: a bit messy, but need to cut through one-level of indirection
			sysv_rp_id = find_sysv_mapping (current->replay_thrd, first);
			printk("replay_ipc(shmat) will do shmat with id %d, instead of %d\n", sysv_rp_id, first);
			//retval = do_shmat (first, (char *) retvals->addr, second, &raddr);
			retval = do_shmat (sysv_rp_id, (char *) retvals->addr, second, &raddr);
			if (retval) {
				if (rc != retval) {
					printk ("replay_ipc(shmat) returns different value %d than %d\n", retval, rc);
					return syscall_mismatch();
				}
			}
			if (raddr != retvals->addr) {
				printk("replay_ipc(shmat) returns a different address 0x%lu even though we passed it 0x%lu retvals->addr\n", raddr, retvals->addr);
				return syscall_mismatch();
			}

			retval = put_user (raddr, (ulong *) third);

			if (rc != retval) {
				printk ("replay_ipc(shmat) returns different value after put_user %d than %d\n", retval, rc);
				return syscall_mismatch();
			}

			MPRINT ("Pid %d end replay_ipc(shmat) rc %d, addr %lx, size %d\n", current->pid, rc, retvals->addr, retvals->size);
			// if shmat succeed and pin is attached, preallocate_conflicts_shmat needs to be called since all shmat mmaps are fixed
			// mcc: We don't need to do this do a preallocate_conflict check here since the shmat system call automatically
			// checks to see if there are conflicting memory regions before putting down the shm
			rc = retval;
			break;
		}
		case SHMGET:
			retval = sys_ipc(call, first, second, third, ptr, fifth);
			if ((rc < 0 && retval >= 0) || (rc >= 0 && retval < 0)) {
				printk ("Pid %d replay_ipc SHMGET, on record we got %d, but replay we got %d\n", current->pid, rc, retval);
				return syscall_mismatch();
			}

			// put a mapping from the re-run replay identifier (pseudo), to the record one
			if (add_sysv_mapping (current->replay_thrd, rc, retval)) {
				printk ("Pid %d replay_ipc SHMGET, could not add replay identifier mapping, replay: %d, record %d\n", current->pid, retval, rc);
				return syscall_mismatch();
			}
			
			return rc; // return the record identifier to the app
		case SHMCTL:
		{
			int sysv_rp_id;
			sysv_rp_id = find_sysv_mapping (current->replay_thrd, first);
			//retval = sys_ipc(call, first, second, third, ptr, fifth);
			retval = sys_ipc(call, sysv_rp_id, second, third, ptr, fifth);
			DPRINT ("Pid %d replay_ipc rc %d, retval %d, call %d, first %d, second %d, third %d, ptr %p, fifth %lu\n", current->pid, rc, retval, call, first, second, third, ptr, fifth);
			return retval; // return the replay identifier, not the record one
		}
		case SHMDT:
                {
			// SHMDT does not use identifier
			int shm_size;
			shm_size = shm_size_from_addr((char __user*) ptr);

                        retval = sys_ipc(call, first, second, third, ptr, fifth);
                        if (retval != rc) {
                                printk("[DIFF]Pid %d replay_ipc(shmdt): returned %d, but expecting %d\n", current->pid, retval, rc);
                        }
                        if (!retval && current->replay_thrd->app_syscall_addr) preallocate_after_munmap ((unsigned long) ptr, shm_size);
                        rc = retval; // return re-executed call return code

                        break;

                }
#ifndef IPC_SAVE
                case SEMOP:
		case SEMCTL:
		case SEMTIMEDOP:
		{
			struct sem_retvals* retvals;
			retvals = (struct sem_retvals *) retparams;

			if (retvals == NULL) {
				printk ("[DIFF]replay_ipc(sem ipc): no return parameters\n");
				return syscall_mismatch();
			}
			DPRINT ("Pid %d simply replay SEM IPC call %d, rc %d\n", current->pid, call, rc);

			break;
		}
		case SEMGET:
			DPRINT ("Pid %d replay_rpc SEMGET replays rc %d\n", current->pid, rc);
			break;
#endif
		default:
		{
#ifndef IPC_SAVE
			struct ipc_retvals* retvals;
			retvals = (struct ipc_retvals *) retparams;

			if (retvals == NULL) {
				printk ("[DIFF]replay_ipc(default): no return parameters\n");
				return syscall_mismatch();
			}
#endif

			retval = sys_ipc (call, first, second, third, ptr, fifth);
			DPRINT ("Pid %d, record pid is %d replay_ipc rc %d, call %d, first %d, second %d, third %d, ptr %p, fifth %lu\n", 
					current->pid, current->replay_thrd->rp_record_thread->rp_record_pid, rc, call, first, second, third, ptr, fifth);
			// return the reexecuted call
			rc = retval;
			break;
		}
	}

	return rc;
}


asmlinkage int 
shim_ipc (uint call, int first, int second, int third, void __user *ptr, long fifth)
SHIM_CALL (ipc, 117, call, first, second, third, ptr, fifth)
#endif
asmlinkage long
shim_ipc (uint call, int first, int second, int third, void __user *ptr, long fifth)
SHIM_NOOP(ipc, call, first, second, third, ptr, fifth)

asmlinkage long
record_fsync (unsigned int fd) {
	long rc;
	new_syscall_enter (118, NULL);
	rc =  sys_fsync(fd);
	DPRINT ("Pid %d record_fsync rc %ld\n", current->pid, rc);
	new_syscall_exit (118, rc, NULL);
	return rc;
}

asmlinkage long
replay_fsync (unsigned int fd) {
	long rc = get_next_syscall (118, NULL, NULL);
	DPRINT ("Pid %d replay_fsync rc %ld\n", current->pid, rc);
	return rc;
}

asmlinkage long
shim_fsync (unsigned int fd)
SHIM_CALL (fsync, 118, fd)

/* We do not intercept sigreturn because we believe it to be deterministic */

static long 
record_clone(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
	struct pthread_log_head __user * phead = NULL;
	struct pthread_log_data __user * start, *old_start = NULL;
	struct record_group* prg;
	struct task_struct* tsk;
	long rc;
#ifdef USE_ARGSALLOC
	void* slab;
#endif

	prg = current->record_thrd->rp_group;

	new_syscall_enter (120, NULL);

	if (!(clone_flags&CLONE_VM)) {
		MPRINT ("This is a fork-style clone - reset the user log appropriately\n");
		/* The intent here is to change the next pointer for the child - the easiest way to do this is to change
		   the parent, fork, and then revert the parent */
		phead = (struct pthread_log_head __user *) current->record_thrd->rp_user_log_addr;
		start = (struct pthread_log_data __user *) ((char __user *) phead + sizeof (struct pthread_log_head));
		get_user (old_start, &phead->next);
		put_user (start, &phead->next);
	}

	rc = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
	MPRINT ("Pid %d records clone returning %ld\n", current->pid, rc);
	MPRINT ("Clone flags are %lx\n", clone_flags);

	rg_lock(prg);
	new_syscall_exit (120, rc, NULL);

	if (rc > 0) {
		// Create a record thread struct for the child
		tsk = pid_task(find_vpid(rc), PIDTYPE_PID);
		if (tsk == NULL) {
			printk ("record_clone: cannot find child\n");
			rg_unlock(prg);
			return -ECHILD;
		}

		tsk->record_thrd = new_record_thread (prg, tsk->pid, -1);
		if (tsk->record_thrd == NULL) {
			rg_unlock(prg);
			return -ENOMEM; 
		}
		tsk->replay_thrd = NULL;

		tsk->record_thrd->rp_cloned_id = atomic_add_return (1, &rp_cloned_next);
		DPRINT ("Pid %d assigned cloned_id %ld\n", current->pid, tsk->record_thrd->rp_cloned_id);

		tsk->record_thrd->rp_next_thread = current->record_thrd->rp_next_thread;
		current->record_thrd->rp_next_thread = tsk->record_thrd;
		
		if (!(clone_flags&CLONE_VM)) {
			tsk->record_thrd->rp_user_log_addr = current->record_thrd->rp_user_log_addr;
			tsk->record_thrd->rp_ignore_flag_addr = current->record_thrd->rp_ignore_flag_addr;
			put_user (old_start, &phead->next);
		}
		// also inherit the parent's pointer to the user-clock
		tsk->record_thrd->rp_precord_clock = current->record_thrd->rp_precord_clock;

#ifdef USE_ARGSALLOC
		// allocate a slab for retparams
		slab = VMALLOC (argsalloc_size);
		if (slab == NULL) return -ENOMEM;
		if (add_argsalloc_node(tsk->record_thrd, slab)) {
			VFREE (slab);
			printk ("Pid %d fork_replay: error adding argsalloc_node\n", current->pid);
			return -ENOMEM;
		}
#endif

		MPRINT ("Pid %d records clone returning Record Pid-%d, tsk %p, prp %p\n", current->pid, tsk->pid, tsk, tsk->record_thrd);

		// Now wake up the thread
		wake_up_new_task (tsk);
	}
	rg_unlock(prg);

	return rc;
}

static long 
replay_clone(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
	struct pthread_log_head __user * phead = NULL;
	struct pthread_log_data __user * start, *old_start = NULL;
	struct task_struct* tsk = NULL;
	struct replay_group* prg;
	struct replay_thread* prept;
	long rc;
	pid_t pid;
	ds_list_iter_t* iter;
	struct record_thread* prt;
	int old_status = 0;

	prg = current->replay_thrd->rp_group;

	if (!(clone_flags&CLONE_VM)) {
		phead = (struct pthread_log_head __user *) current->replay_thrd->rp_record_thread->rp_user_log_addr;
		start = (struct pthread_log_data __user *) ((char __user *) phead + sizeof (struct pthread_log_head) + sizeof(struct pthread_log_data) * PTHREAD_LOG_ENTRIES);
		get_user (old_start, &phead->next);
		put_user (start, &phead->next);
		if (current->replay_thrd->rp_status_addr) {
			get_user (old_status, current->replay_thrd->rp_status_addr);
			put_user (PTHREAD_LOG_REP_AFTER_FORK, current->replay_thrd->rp_status_addr);
		} else {
			printk ("No status addr for parent pid %d\n", current->pid);
		}
	}
	MPRINT ("Pid %d replay_clone sys_clone syscall enter\n", current->pid);
	if (current->replay_thrd->app_syscall_addr > 1) {
		rc = current->replay_thrd->rp_saved_rc;
		(*(int*)(current->replay_thrd->app_syscall_addr)) = 999;
	} else {
		rc = get_next_syscall (120, NULL, NULL);
	}

	DPRINT ("Pid %d replay_clone sys_clone syscall exit:rc=%ld\n", current->pid, rc);
	if (rc > 0) {
		// We need to keep track of whether or not a signal was attached
		// to this system call; sys_clone will clear the flag
		// so we need to be able to set it again at the end of the syscall
		int rp_sigpending = test_thread_flag (TIF_SIGPENDING);

		// We also need to create a clone here 
		pid = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
		MPRINT ("Pid %d in replay clone spawns child %d\n", current->pid, pid);
		if (pid < 0) {
			printk ("[DIFF]replay_clone: second clone failed, rc=%d\n", pid);
			return syscall_mismatch();
		}
		tsk = pid_task (find_vpid(pid), PIDTYPE_PID);
		if (!tsk) {
			printk ("[DIFF]replay_clone: cannot find replaying Pid %d\n", pid);
			return -EINVAL;
		}
	
		// Attach the replay thread struct to the child
		rg_lock(prg->rg_rec_group);

		/* Find the corresponding record thread based on pid.
		 * We used to find the last prt with replay_pid == 0,
		 * but it fails if child thread spawns another child thread.
		 * We should not assume that there is only one thread that
		 * spawns other threads.
		*/
		for (prt = current->replay_thrd->rp_record_thread->rp_next_thread;
		     prt != current->replay_thrd->rp_record_thread; prt = prt->rp_next_thread) {
			if (prt->rp_record_pid==rc) {
				DPRINT ("Pid %d find replay_thrd %p (rec_pid=%d,rep_pid=%d)\n", current->pid, prt, prt->rp_record_pid, pid);
				break;
			}
		}


		// if Pin is attached the record_thread could already exist (via preallocate_mem) so we need to check
		// to see if it exists first before creating
		if (prt == 0 || prt->rp_record_pid != rc) {	
			/* For replays resumed form disk checkpoint, there will be no record thread.  We should create it here. */
			prt = new_record_thread (prg->rg_rec_group, rc, -1);
			// Since there is no recording going on, we need to dec record_thread's refcnt
			atomic_dec(&prt->rp_refcnt);
			DPRINT ("Created new record thread %p\n", prt);
		}

		/* Ensure that no replay thread in this replay group points to this record thread */
		iter = ds_list_iter_create(prg->rg_replay_threads);
		while ((prept = ds_list_iter_next(iter)) != NULL) {
			if (prept->rp_record_thread == prt) {
				printk ("[DIFF]replay_clone: record thread already cloned?\n");
				ds_list_iter_destroy(iter);
				rg_unlock(prg->rg_rec_group);
				return syscall_mismatch();
			}
		}
		ds_list_iter_destroy(iter);

		/* Update our replay_thrd with this information */
		tsk->record_thrd = NULL;
		DPRINT ("Cloning new replay thread\n");
		tsk->replay_thrd = new_replay_thread(prg, prt, pid, 0);
		BUG_ON (!tsk->replay_thrd);

		// inherit the parent's app_syscall_addr
		tsk->replay_thrd->app_syscall_addr = current->replay_thrd->app_syscall_addr;

		MPRINT ("Pid %d, tsk->pid %d refcnt for replay thread %p now %d\n", current->pid, tsk->pid, tsk->replay_thrd,
			atomic_read(&tsk->replay_thrd->rp_refcnt));
		MPRINT ("Pid %d, tsk->pid %d refcnt for record thread pid %d now %d\n", current->pid, tsk->pid, prt->rp_record_pid,
			atomic_read(&prt->rp_refcnt));
		

		// Fix up the circular thread list
		tsk->replay_thrd->rp_next_thread = current->replay_thrd->rp_next_thread;
		current->replay_thrd->rp_next_thread = tsk->replay_thrd;

		// Fix up parent_tidptr to match recorded pid 
		if (clone_flags & CLONE_PARENT_SETTID) {
			int nr = rc;
			put_user(nr, parent_tidptr);
		}

		if (!(clone_flags&CLONE_VM)) {
			MPRINT ("This is a fork-style clone - reset the user log appropriately\n");
			tsk->replay_thrd->rp_record_thread->rp_user_log_addr = current->replay_thrd->rp_record_thread->rp_user_log_addr;
			tsk->replay_thrd->rp_record_thread->rp_ignore_flag_addr = current->replay_thrd->rp_record_thread->rp_ignore_flag_addr;
			put_user (old_start, &phead->next);
			if (current->replay_thrd->rp_status_addr) {
				tsk->replay_thrd->rp_status_addr = current->replay_thrd->rp_status_addr;
				put_user (old_status, current->replay_thrd->rp_status_addr);
			}
		}
		// also inherit the parent's pointer to the user-clock
		tsk->replay_thrd->rp_preplay_clock = current->replay_thrd->rp_preplay_clock;


		// read the rest of the log
		read_log_data (tsk->replay_thrd->rp_record_thread);

		prept = current->replay_thrd;
		tsk->replay_thrd->rp_status = REPLAY_STATUS_ELIGIBLE; // This lets the parent run first - will this make Pin happy?
		tsk->thread.ip = (u_long) ret_from_fork_2;
		rg_unlock(prg->rg_rec_group);

		// Now wake up the new thread and wait
		wake_up_new_task (tsk);

		// see above
		if (rp_sigpending) {
			DPRINT ("Pid %d sig was pending in clone!\n", current->pid);
			signal_wake_up (current, 0);
		}
	}
		
	if (rc > 0 && (clone_flags&CLONE_VM) && current->replay_thrd->app_syscall_addr) {
		MPRINT ("Return real child pid %d to Pin instead of recorded child pid %ld\n", tsk->pid, rc);
		return tsk->pid;
	}

	return rc;
}

long 
shim_clone(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{	
	struct task_struct* tsk;
	int child_pid;

	if (current->record_thrd) return record_clone(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
	if (current->replay_thrd) {
		if (test_app_syscall(120)) return replay_clone(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
		child_pid = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
		tsk = pid_task (find_vpid(child_pid), PIDTYPE_PID);
		if (!tsk) {
			printk ("[DIFF]shim_clone: cannot find replaying Pid %d\n", child_pid);
			return -EINVAL;
		}
		tsk->replay_thrd = NULL;
		return child_pid;
	}
	return do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
}

asmlinkage long
shim_setdomainname (char __user *name, int len) 
SHIM_NOOP(setdomainname, name, len)

static asmlinkage long 
record_newuname(struct new_utsname __user * name)
{
	struct new_utsname* pretval = NULL;
	long rc;

	new_syscall_enter (122, NULL);

	rc = sys_newuname (name);
	DPRINT ("Pid %d records newuname returning %ld\n", current->pid, rc);

	if (rc != -EFAULT) {
		pretval = ARGSKMALLOC(sizeof(struct new_utsname), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_newuname: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, name, sizeof(struct new_utsname))) {
			ARGSKFREE (pretval, sizeof(struct new_utsname));
			pretval = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (122, rc, pretval); /* tloc gets same value as rc */

	return rc;
}

static asmlinkage long 
replay_newuname(struct new_utsname __user * name)
{
	struct new_utsname* retparams = NULL;
	time_t rc = get_next_syscall (122, (char**) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (name, retparams, sizeof(struct new_utsname))) {
			printk ("Pid %d replay_newuname cannot copy to user\n", current->pid);
			syscall_mismatch();
		}
	}
	return rc;
}

asmlinkage long 
shim_newuname (struct new_utsname __user * name) 
SHIM_CALL(newuname, 122, name)

asmlinkage int sys_modify_ldt(int func, void __user *ptr, /* No prototype */
			      unsigned long bytecount);
asmlinkage int 
shim_modify_ldt (int func, void __user *ptr, unsigned long bytecount)
{
	return sys_modify_ldt (func, ptr, bytecount);
}

asmlinkage long 
shim_adjtimex (struct timex __user *txc_p) SHIM_NOOP(adjtimex, txc_p)

static asmlinkage long 
record_mprotect (unsigned long start, size_t len, unsigned long prot)
{
	long rc;

	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (125, NULL);
	rc = sys_mprotect (start, len, prot);
	DPRINT ("Pid %d records mprotect %lx for %lx-%lx returning %ld\n", current->pid, prot, start, start+len, rc);
	new_syscall_exit (125, rc, NULL);
	rg_unlock(current->record_thrd->rp_group);

	return rc;
}

static asmlinkage long 
replay_mprotect (unsigned long start, size_t len, unsigned long prot)
{
	u_long retval, rc;

	if (current->replay_thrd->app_syscall_addr > 1) {
		rc = current->replay_thrd->rp_saved_rc;
		(*(int*)(current->replay_thrd->app_syscall_addr)) = 999;
	} else {
		rc = get_next_syscall (125, NULL, NULL);
	}

	retval = sys_mprotect (start, len, prot);
	DPRINT ("Pid %d replays mprotect %lx for %lx-%lx returning %ld\n", current->pid, prot, start, start+len, retval);

	if (rc != retval) {
		printk ("Replay: mprotect returns diff. value %lu than %lu\n", retval, rc);
		return syscall_mismatch();
	}
	return rc;
}

asmlinkage long
shim_mprotect (unsigned long start, size_t len, unsigned long prot)
SHIM_CALL(mprotect, 125, start, len, prot)

static asmlinkage long 
record_sigprocmask (int how, old_sigset_t __user *set, old_sigset_t __user *oset)
{
	long rc;
	old_sigset_t* pretval = NULL;

	new_syscall_enter (126, NULL);

	rc = sys_sigprocmask (how, set, oset);
	DPRINT ("Pid %d records sigprocmask returning %ld\n", current->pid, rc);
	if (rc == 0 && oset) {
		pretval = ARGSKMALLOC(sizeof(old_sigset_t), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_sigprocmask: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, oset, sizeof(old_sigset_t))) {
			ARGSKFREE (pretval, sizeof(old_sigset_t));
			return -EFAULT;
		}
	}
		
	new_syscall_exit (126, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_sigprocmask (int how, old_sigset_t __user *set, old_sigset_t __user *oset)
{
	old_sigset_t* retparams = NULL;
	long rc = get_next_syscall (126, (char **) &retparams, NULL);
	if (rc == 0 && oset) {
		if (retparams) {
			if (copy_to_user (oset, retparams, sizeof(old_sigset_t))) {
				printk ("Pid %d cannot copy sigset to user\n", current->pid);
				return syscall_mismatch();
			}
		} else {
			printk ("Pid %d replay_sigprocmask expects old sigset but no values in log\n", current->pid);
			return syscall_mismatch();
		}
	}

	return rc;
}

asmlinkage long 
shim_sigprocmask (int how, old_sigset_t __user *set, old_sigset_t __user *oset)
SHIM_CALL (sigprocmask, 126, how, set, oset)

asmlinkage long
shim_init_module (void __user *umod, unsigned long len, 
		  const char __user *uargs)
SHIM_NOOP(init_module, umod, len, uargs)

asmlinkage long
shim_delete_module (const char __user *name_user, unsigned int flags)
SHIM_NOOP(delete_module, name_user, flags)

asmlinkage long 
shim_quotactl (unsigned int cmd, const char __user *special, qid_t id, void __user *addr)
SHIM_NOOP(quotactl, cmd, special, id, addr)

static asmlinkage long 
record_getpgid (pid_t pid)
{
	long rc;

	new_syscall_enter (132, NULL);

	rc = sys_getpgid (pid);
	DPRINT ("Pid %d records getpgid returning %ld\n", current->pid, rc);
	
	new_syscall_exit (132, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_getpgid (pid_t pid)
{
	return get_next_syscall (132, NULL, NULL);
}

asmlinkage long shim_getpgid (pid_t pid) SHIM_CALL(getpgid, 132, pid);

static asmlinkage long
record_fchdir (unsigned int fd)
{
	long rc;

	new_syscall_enter (133, NULL);

	rc = sys_fchdir (fd);
	DPRINT ("Pid %d records fchdir returning %ld\n", current->pid, rc);

	new_syscall_exit (133, rc, NULL);

	return rc;
}

static asmlinkage long
replay_fchdir (unsigned int fd)
{
	return get_next_syscall (133, NULL, NULL);
}

asmlinkage long shim_fchdir (unsigned int fd)
SHIM_CALL (fchdir, 133, fd)

asmlinkage long 
shim_bdflush (int func, long data) SHIM_NOOP(bdflush, func, data)

asmlinkage long 
shim_sysfs (int option, unsigned long arg1, unsigned long arg2)
SHIM_NOOP(sysfs, option, arg1, arg2)

asmlinkage long shim_personality (u_long parm) SHIM_NOOP(personality, parm)

asmlinkage long shim_setfsuid16 (old_uid_t uid) SHIM_NOOP(setfsuid, uid)

asmlinkage long shim_setfsgid16 (old_gid_t gid) SHIM_NOOP(setfsgid, gid)

static asmlinkage long 
record_llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user * result, unsigned int origin)
{
	long rc;
	loff_t* pretval = NULL;

	new_syscall_enter (140, NULL);

	rc = sys_llseek (fd, offset_high, offset_low, result, origin);
	DPRINT ("Pid %d records llseek returning %ld\n", current->pid, rc);

	if (rc == 0) {
		    pretval = ARGSKMALLOC(sizeof(loff_t), GFP_KERNEL);
		    if (pretval == NULL) {
			    printk("record_llseek: can't allocate buffer\n");
			    return -ENOMEM;
		    }
		    if (copy_from_user (pretval, result, sizeof(loff_t))) {
			    ARGSKFREE (pretval, sizeof(loff_t));
			    pretval = NULL;
			    rc = -EFAULT;
		    }
	}

	new_syscall_exit (140, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user * result, unsigned int origin)
{
	loff_t* retparams = NULL;
	long rc = get_next_syscall (140, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (result, retparams, sizeof(loff_t))) {
			printk ("Pid %d replay_llseek cannot copy to user\n", current->pid);
			return syscall_mismatch();
		}
	}
	return rc;
}

asmlinkage long 
shim_llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user * result, unsigned int origin)
SHIM_CALL(llseek, 140, fd, offset_high, offset_low, result, origin);

static asmlinkage long
record_getdents (unsigned int fd, struct linux_dirent __user * dirent, unsigned int count)
{
	long rc;
	char* buf = NULL;

	new_syscall_enter (141, NULL);

	rc = sys_getdents (fd, dirent, count);
	DPRINT ("Pid %d records getdents returning %ld\n", current->pid, rc);

	if (rc > 0) {
		buf = ARGSKMALLOC (rc, GFP_KERNEL);
		if (buf == NULL) {
			printk("record_getdents: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (buf, dirent, rc)) {
			ARGSKFREE (buf, rc);
			return -EFAULT;
		}
	}

	new_syscall_exit (141, rc, buf);
	return rc;
}

static asmlinkage long 
replay_getdents (unsigned int fd, struct linux_dirent __user * dirent, unsigned int count)
{
	char* retparams = NULL;
	long rc = get_next_syscall (141, &retparams, NULL);
	if (retparams) {
		if (copy_to_user (dirent, retparams, rc)) {
			printk ("Pid %d replay_getdents cannot copy dirent to user\n", current->pid);
		}
	}
	return rc; 
}

asmlinkage long 
shim_getdents (unsigned int fd, struct linux_dirent __user * dirent, unsigned int count)
SHIM_CALL(getdents, 141, fd, dirent, count)

static asmlinkage long 
record_select (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
{
	long rc;
	struct select_retvals* pretvals;

	new_syscall_enter (142, NULL);

	rc = sys_select (n, inp, outp, exp, tvp);

	/* Record user's memory regardless of return value in order to
	 * capture partial output.
	 */
	pretvals = ARGSKMALLOC(sizeof(struct select_retvals), GFP_KERNEL);
	if (pretvals == NULL) {
		printk("record_select: can't allocate buffer\n");
		return -ENOMEM;
	}
	memset(pretvals, 0, sizeof(struct select_retvals));
	if (inp && copy_from_user (&pretvals->inp, inp, sizeof(fd_set)) == 0)
		pretvals->has_inp = 1;
	if (outp && copy_from_user (&pretvals->outp, outp, sizeof(fd_set)) == 0)
		pretvals->has_outp = 1;
	if (exp && copy_from_user (&pretvals->exp, exp, sizeof(fd_set)) == 0)
		pretvals->has_exp = 1;
	if (tvp && copy_from_user (&pretvals->tv, tvp, sizeof(struct timeval)) == 0)
		pretvals->has_tv = 1;

	new_syscall_exit (142, rc, pretvals);
	DPRINT ("Pid %d records select returning %ld\n", current->pid, rc);

	return rc;
}

asmlinkage long 
replay_select (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
{
	struct select_retvals* retparams = NULL;
	long rc = get_next_syscall (142, (char **) &retparams, NULL);
	if (retparams->has_inp && copy_to_user (inp, &retparams->inp, sizeof(fd_set))) {
		printk ("Pid %d cannot copy inp to user\n", current->pid);
	}
	if (retparams->has_outp && copy_to_user (outp, &retparams->outp, sizeof(fd_set))) {
		printk ("Pid %d cannot copy outp to user\n", current->pid);
	}
	if (retparams->has_exp && copy_to_user (exp, &retparams->exp, sizeof(fd_set))) {
		printk ("Pid %d cannot copy exp to user\n", current->pid);
	}
	if (retparams->has_tv && copy_to_user (tvp, &retparams->tv, sizeof(struct timeval))) {
		printk ("Pid %d cannot copy tvp to user\n", current->pid);
	}
	
	return rc;
}

asmlinkage long 
shim_select (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
SHIM_CALL(select, 142, n, inp, outp, exp, tvp);

static asmlinkage long
record_flock (unsigned int fd, unsigned int cmd)
{
	long rc;

	new_syscall_enter (143, NULL);

	rc = sys_flock (fd, cmd);
	DPRINT ("Pid %d records flock(%d, %d) returning %ld\n", current->pid, fd, cmd, rc);

	new_syscall_exit (143, rc, NULL);

	return rc;
}

static asmlinkage long
replay_flock (unsigned int fd, unsigned int cmd)
{
	return get_next_syscall (143, NULL, NULL);
}

asmlinkage long 
shim_flock (unsigned int fd, unsigned int cmd) 
SHIM_CALL(flock, 143, fd, cmd)

asmlinkage long 
shim_msync (unsigned long start, size_t len, int flags) 
SHIM_NOOP(msync, start, len, flags)

static asmlinkage ssize_t 
record_readv (unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
	char* recbuf = NULL, *copyp;
	ssize_t size, rem_size, to_copy;
	struct iovec* kvec;
	int i;

	new_syscall_enter (145, NULL);
	size = sys_readv (fd, vec, vlen);
	if (size > 0) {
		if (size > KMALLOC_THRESHOLD) {
			recbuf = ARGSVMALLOC(size);
		} else {
			recbuf = ARGSKMALLOC(size, GFP_KERNEL);
		}
		if (recbuf == NULL) {
			printk ("Unable to allocate readv buffer\n");
			return -ENOMEM;
		}
		
		// readv verified args so we should just copy and use them
		kvec = KMALLOC(vlen*sizeof(struct iovec), GFP_KERNEL);
		if (kvec == NULL) {
			printk ("Pid %d record_readv allocation of vector failed\n", current->pid);
			goto free_and_out;
		}

		if (copy_from_user (kvec, vec, vlen*sizeof(struct iovec))) {
			printk ("Pid %d record_readv copy_from_user of vector failed\n", current->pid);
			goto free_vec_and_out;
		}
		rem_size = size;
		copyp = recbuf;
		for (i = 0; i < vlen; i++) {
			to_copy = kvec[i].iov_len;
			if (rem_size < to_copy) to_copy = rem_size;

			if (copy_from_user (copyp, kvec[i].iov_base, to_copy)) {
				printk ("Pid %d record_readv copy_from_user of data failed\n", current->pid);
				goto free_vec_and_out;
			}
			copyp += to_copy;
			rem_size -= to_copy;
			if (rem_size == 0) break;
		}
		KFREE (kvec);
	}
	new_syscall_exit (145, size, recbuf);

	return size;
free_vec_and_out:
	KFREE (kvec);
free_and_out:
	if (size > KMALLOC_THRESHOLD) {
		ARGSVFREE (recbuf, size);
	} else {
		ARGSKFREE (recbuf, size);
	}
	return -EFAULT;
}

static asmlinkage ssize_t 
replay_readv (unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
	char* retparams = NULL, *copyp;
	ssize_t rc = get_next_syscall (145, &retparams, NULL);
	ssize_t rem_size, to_copy;
	struct iovec* kvec;
	int i;

	if (retparams) {
		kvec = KMALLOC(vlen*sizeof(struct iovec), GFP_KERNEL);
		if (kvec == NULL) {
			printk ("Pid %d replay_readv allocation of vector failed\n", current->pid);
			return -ENOMEM;
		}
		
		if (copy_from_user (kvec, vec, vlen*sizeof(struct iovec))) {
			printk ("Pid %d replay_readv copy_from_user of vector failed\n", current->pid);
			goto free_vec_and_out;
		}
		rem_size = rc;
		copyp = retparams;
		for (i = 0; i < vlen; i++) {
			to_copy = kvec[i].iov_len;
			if (rem_size < to_copy) to_copy = rem_size;

			if (copy_to_user (kvec[i].iov_base, copyp, to_copy)) {
				printk ("Pid %d replay_readv copy_to_user of data failed\n", current->pid);
				goto free_vec_and_out;
			}
			copyp += to_copy;
			rem_size -= to_copy;
			if (rem_size == 0) break;
		}
		KFREE (kvec);
	}

	return rc;

free_vec_and_out:
	KFREE (kvec);
	return -EFAULT;
}

asmlinkage ssize_t 
shim_readv (unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
SHIM_CALL(readv, 145, fd, vec, vlen)

static asmlinkage ssize_t
record_writev (unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
	ssize_t size;

	new_syscall_enter (146, NULL);

	size = sys_writev (fd, vec, vlen);
	DPRINT ("Pid %d records writev returning %d\n", current->pid, size);

	new_syscall_exit (146, size, NULL);

	return size;
}

static asmlinkage ssize_t
replay_writev (unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
	return get_next_syscall (146, NULL, NULL);
}

asmlinkage ssize_t
shim_writev (unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
SHIM_CALL(writev, 146, fd, vec, vlen);

asmlinkage long shim_getsid (pid_t pid) SHIM_NOOP(getsid, pid)

static asmlinkage long 
record_fdatasync (int fd)
{
	long rc;

	new_syscall_enter (148, NULL);

	rc = sys_fdatasync (fd);
	DPRINT ("Pid %d records fdatasync returning %ld\n", current->pid, rc);
	
	new_syscall_exit (148, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_fdatasync (int fd)
{
	return get_next_syscall (148, NULL, NULL);
}

asmlinkage long shim_fdatasync (unsigned int fd) 
SHIM_CALL(fdatasync, 148, fd)

asmlinkage long 
shim_sysctl (struct __sysctl_args __user *args) SHIM_NOOP(sysctl, args)

asmlinkage long 
shim_mlock (unsigned long start, size_t len) SHIM_NOOP(mlock, start, len)

asmlinkage long 
shim_munlock (unsigned long start, size_t len) SHIM_NOOP(munlock, start, len)

asmlinkage long shim_mlockall (int flags) SHIM_NOOP(mlockall, flags)

asmlinkage long shim_munlockall (void) SHIM_NOOP(munlockall)

static asmlinkage long 
record_sched_setparam (pid_t pid, struct sched_param __user *param)
{
	long rc;

	new_syscall_enter (154, NULL);

	rc = sys_sched_setparam (pid, param);
	DPRINT ("Pid %d records sched_setparam returning %ld\n", current->pid, rc);
	
	new_syscall_exit (154, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_sched_setparam (pid_t pid, struct sched_param __user *param)
{
	return get_next_syscall (154, NULL, NULL);
}

asmlinkage long 
shim_sched_setparam (pid_t pid, struct sched_param __user *param)
SHIM_CALL(sched_setparam, 154, pid, param)

static asmlinkage long 
record_sched_getparam (pid_t pid, struct sched_param __user *param)
{
	long rc;
	struct sched_param *pretval = NULL;

	new_syscall_enter (155, NULL);

	rc = sys_sched_getparam (pid, param);
	DPRINT ("Pid %d records sched_getparam returning %ld\n", current->pid, rc);
	pretval = ARGSKMALLOC(sizeof(struct sched_param), GFP_KERNEL);
	if (pretval == NULL) {
		printk("record_sched_getparam: can't allocate buffer\n");
		return -ENOMEM;
	}
	if (copy_from_user (pretval, param, 
			    sizeof(struct sched_param))) { 
		ARGSKFREE (pretval, sizeof(struct sched_param));
		pretval = NULL;
		rc = -EFAULT;
	}

	new_syscall_exit (155, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_sched_getparam (pid_t pid, struct sched_param __user *param)
{
	struct sched_param *retparams = NULL;
	long rc = get_next_syscall (155, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (param, retparams, sizeof(struct sched_param))) {
			printk ("Pid %d replay_sched_getparam cannot copy to user\n", current->pid);
			return syscall_mismatch();
		}
	}

	return rc;
}

asmlinkage long 
shim_sched_getparam (pid_t pid, struct sched_param __user *param)
SHIM_CALL(sched_getparam, 155, pid, param)

static asmlinkage long 
record_sched_setscheduler (pid_t pid, int policy, struct sched_param __user *param) 
{
	long rc;

	new_syscall_enter (156, NULL);
	rc = sys_sched_setscheduler (pid, policy, param);
	DPRINT ("Pid %d records sched_setscheduler returning %ld\n", current->pid, rc);
	new_syscall_exit (156, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_sched_setscheduler (pid_t pid, int policy, struct sched_param __user *param) 
{
	return get_next_syscall (156, NULL, NULL);
}

asmlinkage long 
shim_sched_setscheduler (pid_t pid, int policy, struct sched_param __user *param) 
SHIM_CALL(sched_setscheduler, 156, pid, policy, param)

static asmlinkage long 
record_sched_getscheduler (pid_t pid)
{
	long rc;

	new_syscall_enter (157, NULL);
	rc = sys_sched_getscheduler (pid);
	DPRINT ("Pid %d records sched_getscheduler returning %ld\n", current->pid, rc);
	new_syscall_exit (157, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_sched_getscheduler (pid_t pid)
{
	return get_next_syscall (157, NULL, NULL);
}

asmlinkage long shim_sched_getscheduler (pid_t pid) 
SHIM_CALL(sched_getscheduler, 157, pid)

static asmlinkage long 
record_sched_yield (void)
{
	long rc;

	new_syscall_enter (158, NULL);
	rc = sys_sched_yield ();
	DPRINT ("Pid %d records sched_yield returning %ld\n", current->pid, rc);
	new_syscall_exit (158, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_sched_yield (void)
{
	return get_next_syscall (158, NULL, NULL);
}

asmlinkage long shim_sched_yield (void) 
{
	struct replay_thread* tmp;
	int ret;

	if (current->replay_thrd && !test_app_syscall(158)) {
		MPRINT ("Pid %d: pin appears to be calling sched yield\n", current->pid);

		// See if we can find another eligible thread
		tmp = current->replay_thrd->rp_next_thread;
		while (tmp != current->replay_thrd) {
			DPRINT ("Pid %d considers thread %d status %d clock %ld - clock is %ld\n", current->pid, tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock, *(current->replay_thrd->rp_preplay_clock));
			if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= *(current->replay_thrd->rp_preplay_clock))) {
				DPRINT ("Letting thread %d run - this may be non-deterministic\n", tmp->rp_replay_pid);
				current->replay_thrd->rp_status = REPLAY_STATUS_ELIGIBLE;
				tmp->rp_status = REPLAY_STATUS_RUNNING;
				wake_up (&tmp->rp_waitq);
				ret = wait_event_interruptible_timeout (current->replay_thrd->rp_waitq, current->replay_thrd->rp_status == REPLAY_STATUS_RUNNING || current->replay_thrd->rp_group->rg_rec_group->rg_mismatch_flag, SCHED_TO);
				if (ret == 0) printk ("Replay pid %d timed out waiting after yield\n", current->pid);
				if (ret == -ERESTARTSYS) {
					printk ("Pid %d: cannot wait due to yield - try again\n", current->pid);
					if (test_thread_flag(TIF_SIGPENDING)) {
						// this is really dumb
						while(current->replay_thrd->rp_status != REPLAY_STATUS_RUNNING) {
							printk ("Pid %d: cannot wait due to pending signal(s) - try again\n", current->pid);
							msleep(1000);
						}
					}
				}
				if (current->replay_thrd->rp_status != REPLAY_STATUS_RUNNING) {
					printk ("Replay pid %d woken up but not running.  We must want it to die\n", current->pid);
					do {
						printk ("\tthread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
						tmp = tmp->rp_next_thread;
					} while (tmp != current->replay_thrd);
					sys_exit (0);
				}
				DPRINT ("Pid %d running after yield\n", current->pid);
				return 0;
			}
			tmp = tmp->rp_next_thread;
			if (tmp == current->replay_thrd) {
				printk ("Pid %d: Crud! no elgible thread to run on sched_yield\n", current->pid);
				printk ("This is probably really bad...sleeping\n");
				msleep (1000);
			}
		} 
	}
	SHIM_CALL(sched_yield,158);
}

static asmlinkage long 
record_sched_get_priority_max (int policy)
{
	long rc;

	new_syscall_enter (159, NULL);
	rc = sys_sched_get_priority_max (policy);
	new_syscall_exit (159, rc, NULL);
	DPRINT ("Pid %d records sched_get_priority_max returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_sched_get_priority_max (int policy)
{
	return get_next_syscall (159, NULL, NULL);
}

asmlinkage long shim_sched_get_priority_max (int policy) 
SHIM_CALL(sched_get_priority_max, 159, policy);

static asmlinkage long 
record_sched_get_priority_min (int policy)
{
	long rc;

	new_syscall_enter (160, NLL);
	rc = sys_sched_get_priority_min (policy);
	new_syscall_exit (160, rc, NULL);
	DPRINT ("Pid %d records sched_get_priority_min returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_sched_get_priority_min (int policy)
{
	return get_next_syscall (160, NULL, NULL);
}

asmlinkage long shim_sched_get_priority_min (int policy) 
SHIM_CALL(sched_get_priority_min, 160, policy);

asmlinkage long 
shim_sched_rr_get_interval (pid_t pid, struct timespec __user *interval)
SHIM_NOOP(sched_rr_get_interval, pid, interval)

static asmlinkage long
record_nanosleep (struct timespec __user *rqtp, struct timespec __user *rmtp)
{
	struct timespec* pretval = NULL;
	long rc;

	new_syscall_enter (162, NULL);

	rc = sys_nanosleep (rqtp, rmtp);

	DPRINT ("Pid %d records nanosleep returning %ld\n", current->pid, rc);
	DPRINT ("nanosleep rmtp is %p\n", rmtp);

	if (rc == 0 && rmtp) {
		pretval = ARGSKMALLOC(sizeof(struct timespec), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_nanosleep: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, rmtp, sizeof(struct timespec))) {
			ARGSKFREE (pretval, sizeof(struct timespec));
			pretval = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (162, rc, pretval);

	return rc;
}

static asmlinkage long
replay_nanosleep (struct timespec __user *rqtp, struct timespec __user *rmtp)
{
	struct timespec* retparams = NULL;
	long rc = get_next_syscall (162, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (rmtp, retparams, sizeof(struct timespec))) {
			printk ("Pid %d cannot copy ts to user\n", current->pid);
		}
	}

	return rc;
}

asmlinkage long
shim_nanosleep (struct timespec __user *rqtp, struct timespec __user *rmtp)
SHIM_CALL(nanosleep, 162, rqtp, rmtp);

static asmlinkage unsigned long 
record_mremap (unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
	unsigned long rc;

	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (163, NULL);

	rc = sys_mremap (addr, old_len, new_len, flags, new_addr);
	DPRINT ("Pid %d records mremap with address %lx returning %lx\n", current->pid, addr, rc);

	new_syscall_exit (163, rc, NULL);
	rg_unlock(current->record_thrd->rp_group);
	
	return rc;
}

static asmlinkage unsigned long 
replay_mremap (unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
	u_long retval, rc = get_next_syscall (163, NULL, NULL);
	retval = sys_mremap (addr, old_len, new_len, flags, new_addr);
	DPRINT ("Pid %d replays mremap with address %lx returning %lx\n", current->pid, addr, retval);

	if (rc != retval) {
		printk ("Replay mremap returns different value %lu than %lu\n", retval, rc);
		return syscall_mismatch();
	}
	return rc;
}

asmlinkage unsigned long 
shim_mremap (unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
SHIM_CALL(mremap, 163, addr, old_len, new_len, flags, new_addr);

asmlinkage long 
shim_getresuid16 (old_uid_t __user *ruid, old_uid_t __user *euid, old_uid_t __user *suid)
SHIM_NOOP(getresuid16, ruid, euid, suid)

asmlinkage long 
shim_setresuid16 (old_uid_t ruid, old_uid_t euid, old_uid_t suid)
SHIM_NOOP(setresuid16, ruid, euid, suid)

int dummy_vm86(unsigned long cmd, unsigned long arg, struct pt_regs *regs); /* In vm86_32.c */

int shim_vm86(unsigned long cmd, unsigned long arg, struct pt_regs *regs)
{
	if (current->record_thrd) printk ("Record pid %d calls vm86old\n", current->pid);
	if (current->replay_thrd) printk ("Replay pid %d calls vm86old\n", current->pid);
	return dummy_vm86(cmd, arg, regs);
}

static asmlinkage long 
record_poll (struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs)
{
	long rc;
	char* pretvals;

	if (nfds > current->signal->rlim[RLIMIT_NOFILE].rlim_cur) return -EINVAL;

	new_syscall_enter (168, NULL);

	rc = sys_poll (ufds, nfds, timeout_msecs);

	/* Record user's memory regardless of return value in order to
	 * capture partial output.
	 */
	pretvals = ARGSKMALLOC(sizeof(int)+nfds*sizeof(struct pollfd), GFP_KERNEL);
	if (pretvals == NULL) {
		printk("record_poll: can't allocate buffer\n");
		return -ENOMEM;
	}
	*((int *)pretvals) = nfds*sizeof(struct pollfd);
	if (copy_from_user (pretvals+sizeof(int), ufds, nfds*sizeof(struct pollfd))) {
		printk ("record_poll: can't copy retvals\n");
		ARGSKFREE (pretvals,sizeof(int)+nfds*sizeof(struct pollfd));
		return -EFAULT;
	}
	
	new_syscall_exit (168, rc, pretvals);
	DPRINT ("Pid %d records poll returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_poll (struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs)
{
	char* retparams = NULL;
	long rc;

	if (nfds > current->signal->rlim[RLIMIT_NOFILE].rlim_cur) return syscall_mismatch();

	rc = get_next_syscall (168, (char **) &retparams, NULL);
	if (copy_to_user (ufds, retparams+sizeof(int), nfds*sizeof(struct pollfd))) {
		printk ("Pid %d cannot copy inp to user\n", current->pid);
	}

	DPRINT ("Pid %d replay poll returning %ld\n", current->pid, rc);

	return rc;
}

asmlinkage long 
shim_poll (struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs)
SHIM_CALL(poll, 168, ufds, nfds, timeout_msecs)

asmlinkage long 
shim_setresgid16 (old_gid_t rgid, old_gid_t egid, old_gid_t sgid)
SHIM_NOOP(setresgid16, rgid, egid, sgid)

asmlinkage long 
shim_getresgid16 (old_gid_t __user *rgid, old_gid_t __user *egid, old_gid_t __user *sgid)
SHIM_NOOP(getresgid16, rgid, egid, sgid)

asmlinkage long 
shim_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
SHIM_NOOP(prctl, option, arg2, arg3, arg4, arg5)

long dummy_rt_sigreturn(struct pt_regs *regs); /* In arch/x86/kernel/signal.c */

long shim_rt_sigreturn(struct pt_regs* regs)
{
	if (current->record_thrd) {
		struct repsignal_context* pcontext = current->record_thrd->rp_repsignal_context_stack;
		if (pcontext) {
			DPRINT ("Pid %d does rt_sigreturn - restoring ignore flag of %d\n ", current->pid, pcontext->ignore_flag);
			put_user (pcontext->ignore_flag, current->record_thrd->rp_ignore_flag_addr);
			current->record_thrd->rp_repsignal_context_stack = pcontext->next;
			KFREE (pcontext);
		} else {
			printk ("Pid %d does sigreturn but no context???\n", current->pid);
		}
	}

	return dummy_rt_sigreturn(regs);
}

/* Can't find a definition of this in header files */
asmlinkage long sys_rt_sigaction (int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize);

struct rt_sigaction_args {
	int sig;
	const struct sigaction __user *act;		// pointer to user-space struct
	struct sigaction *kact;				// pointer to the kernel memory struct
	struct sigaction sa;				// A copy of the struct (used to distinguish between replay and pin rt_sigactions)	
	struct sigaction __user *oact;
	size_t sigsetsize;
};

static asmlinkage long
record_rt_sigaction (int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize)
{
	long rc;
	struct sigaction* pargs = NULL;
	struct sigaction* pretval = NULL;
	
	if (act) {
		// Save sigaction which will be used later in case we attach Pin to diffentiate Pin calls from app calls
		pargs = ARGSKMALLOC (sizeof(struct sigaction), GFP_KERNEL);
		if (pargs == NULL) {			
			printk ("Pid %d record_rt_sigaction: can't allocate args\n", current->pid);
			return -ENOMEM;
		}
		if (copy_from_user (pargs, act, sizeof (struct sigaction))) {
			ARGSKFREE (pargs, sizeof(struct sigaction));
			printk("Pid %d record_rt_sigaction: can't copy sigaction from user\n", current->pid);
			return -ENOMEM;
		}
	}
	__new_syscall_enter (174, pargs);

	rc = sys_rt_sigaction (sig, act, oact, sigsetsize);

#ifdef MCPRINT
	DPRINT ("Record Pid %d rt_sigaction sig %d, act %p, oact %p, rc %ld\n", current->pid, sig, act,	oact, rc);
	if(act) {
		DPRINT ("\tact->sa_handler %p, act->sa_restorer %p, act->sa_mask.sig[0] %lx, act->sa_mask.sig[1] %lx, act->sa_flags %lx, SA_ONSTACK? %d, SA_SIGINFO? %d\n",
			act->sa_handler, act->sa_restorer, (act->sa_mask).sig[0], (act->sa_mask).sig[1], act->sa_flags, ((act->sa_flags) & SA_ONSTACK) == SA_ONSTACK, ((act->sa_flags) & SA_SIGINFO) == SA_SIGINFO);
	}
	if (oact) {
		DPRINT ("\toact->sa_handler %p, oact->sa_restorer %p, oact->sa_mask.sig[0] %lx, oact->sa_mask.sig[1] %lx, oact->sa_flags %lx, SA_ONSTACK? %d, SA_SIGINFO? %d\n",
			oact->sa_handler, oact->sa_restorer, (oact->sa_mask).sig[0], (oact->sa_mask).sig[1], oact->sa_flags, ((oact->sa_flags) & SA_ONSTACK) == SA_ONSTACK, ((oact->sa_flags) & SA_SIGINFO) == SA_SIGINFO);
	}
#endif
	if (rc == 0 && oact) {
		pretval = ARGSKMALLOC(sizeof(struct sigaction), GFP_KERNEL);
		if (pretval == NULL) {
			ARGSKFREE (pargs, sizeof(struct sigaction));
			printk("record_rt_sigaction: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, oact, sizeof(struct sigaction))) {
			ARGSKFREE (pargs, sizeof(struct sigaction));
			ARGSKFREE (pretval, sizeof(struct sigaction));
			pretval = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (174, rc, pretval);
	
	return rc;
}

static asmlinkage long
replay_rt_sigaction (int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize)
{
	long rc;
	struct sigaction* args;
	char* retparams = NULL;
	
	rc = get_next_syscall (174, &retparams, (char **) &args);

	if (retparams) {
		if (!oact) {
			// assuming this is a pin thing
			MPRINT ("[WARN] Pid %d replay_rt_sigaction: log contains retparams, replay syscall does not ask for oact\n", current->pid); 
		}
		else if (copy_to_user (oact, retparams, sizeof(struct sigaction))) {
			printk ("Pid %d replay_rt_sigaction cannot copy oact %p to user\n", current->pid, oact);
		}
	}

	// pass through to kernel so that it will save act in the task_struct
	// so that it can return it as an oact on a subsequent pin_rt_sigaction
	if (sys_rt_sigaction (sig, act, 0, sigsetsize))	printk ("Pid %d in replay_rt_sigaction: pass-thru sys_rt_sigaction failed WARNING\n", current->pid);
#ifdef MCPRINT
	DPRINT ("Replay Pid %d rt_sigaction sig %d, act %p, oact %p, rc %ld\n", current->pid, sig, act,	oact, rc);
	if(act) {
		DPRINT ("\tact->sa_handler %p, act->sa_restorer %p, act->sa_mask.sig[0] %lx, act->sa_mask.sig[1] %lx, act->sa_flags %lx, SA_ONSTACK? %d, SA_SIGINFO? %d\n",
			act->sa_handler, act->sa_restorer, (act->sa_mask).sig[0], (act->sa_mask).sig[1], act->sa_flags, ((act->sa_flags) & SA_ONSTACK) == SA_ONSTACK, ((act->sa_flags) & SA_SIGINFO) == SA_SIGINFO);
	}
	if (oact) {
		DPRINT ("\toact->sa_handler %p, oact->sa_restorer %p, oact->sa_mask.sig[0] %lx, oact->sa_mask.sig[1] %lx, oact->sa_flags %lx, SA_ONSTACK? %d, SA_SIGINFO? %d\n",
			oact->sa_handler, oact->sa_restorer, (oact->sa_mask).sig[0], (oact->sa_mask).sig[1], oact->sa_flags, ((oact->sa_flags) & SA_ONSTACK) == SA_ONSTACK, ((oact->sa_flags) & SA_SIGINFO) == SA_SIGINFO);
	}
#endif

	return rc;
}

/*
 * We need a custom shim function to multiplex between replay without pin and replay+pin.
 * Replay without pin: return the recorded syscall args, retvals, and return value
 * Replay with pin: actually execute the sigaction
 */
asmlinkage long
shim_rt_sigaction (int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize)
{
	struct syscall_result* psr;
	struct replay_thread* prt = current->replay_thrd;
	struct sigaction* record_act;
	struct sigaction* replay_act;

	if (current->record_thrd) return record_rt_sigaction(sig,act,oact,sigsetsize); 
	if (current->replay_thrd && test_app_syscall(174)) {

		// no Pin attached so just do an ordinary replay
		if (prt->app_syscall_addr == 0) return replay_rt_sigaction (sig, act, oact, sigsetsize);

		// if Pin is attached, we need to determine if this rt_sigaction is the application's or Pin's.
		// Checking test_app_syscall isn't enough, 
		// since Pin will issue another rt_sigaction with the app_syscall value set to 174
		psr = prt->rp_saved_psr;
		if(psr->sysnum != 174) return sys_rt_sigaction (sig, act, oact, sigsetsize);

		// checking the sigaction sa_handler
		// if it's not the same as record, then don't replay this sigaction
		// it probably belongs to pin
		replay_act = (struct sigaction*) copy_struct((const char __user *)act, sizeof(struct sigaction));
		record_act = (struct sigaction*) (psr->args);
		if (replay_act && record_act) {
			if (replay_act->sa_handler != record_act->sa_handler) {
				MPRINT ("Pid %d sa_handlers different replay_act->sa_handler %p, record_act->sa_handler %p\n", current->pid, replay_act->sa_handler, record_act->sa_handler);
				KFREE(replay_act);
				return sys_rt_sigaction (sig, act, oact, sigsetsize);	
			}
		} else if ((replay_act && !record_act) || (!replay_act && record_act)) {
			KFREE(replay_act);
			return sys_rt_sigaction (sig, act, oact, sigsetsize);
		}
		KFREE(replay_act);

		// done checking args, this is an application syscall (with Pin)
		(*(int*)(prt->app_syscall_addr)) = 999;
		// actually perform rt_sigaction
		return sys_rt_sigaction (sig, act, oact, sigsetsize);
	}
	if (current->replay_thrd && current->replay_thrd->app_syscall_addr != 0) {
		return sys_rt_sigaction (sig, act, oact, sigsetsize);
	}
	return sys_rt_sigaction (sig, act, oact, sigsetsize);
}

struct rt_sigprocmask_args {
	int how;
	sigset_t __user* set;
	char* kset;
	sigset_t __user* oset;
	size_t sigsetsize;
};

static asmlinkage long
record_rt_sigprocmask (int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
	long rc;
	char* buf = NULL;

	new_syscall_enter (175, args);

	rc = sys_rt_sigprocmask (how, set, oset, sigsetsize);
	DPRINT ("Pid %d records rt_sigprocmask returning %ld\n", current->pid, rc);

	if (rc == 0 && oset) {
		/* Buffer describes its own size */
		buf = ARGSKMALLOC(sizeof(size_t) + sigsetsize, GFP_KERNEL);
		if (buf == NULL) {
			printk("record_rt_sigprocmask: can't alloc buffer\n");
			return -ENOMEM;
		}
		*((size_t *) buf) = sigsetsize;
		if (copy_from_user (buf+sizeof(size_t), oset, sigsetsize)) {
			ARGSKFREE (buf, sizeof(size_t) + sigsetsize);
			buf = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (175, rc, buf);
	
	return rc;

}

static asmlinkage long
replay_rt_sigprocmask (int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
	struct rt_sigprocmask_args* args = NULL;
	char* retparams = NULL;
	size_t size;
	long rc = get_next_syscall (175, &retparams, (char**) &args);
	if (retparams) {
		size = *((size_t *) retparams);
		if (size != sigsetsize) printk ("Pid %d has diff sigsetsize %d than %d\n", current->pid, sigsetsize, size);
		if (copy_to_user (oset, retparams+sizeof(size_t), size)) printk ("Pid %d cannot copy to user\n", current->pid);
	}
	return rc;
}

/* Called on Replay+Pin */
asmlinkage long
pin_rt_sigprocmask (int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
	long rc;
	struct replay_thread* prt = current->replay_thrd;
	
	rc = sys_rt_sigprocmask (how, set, oset, sigsetsize);

	// Check to see if this system call was called by the application.
	// This needs to be done after the call to sys_rt_sigprocmask
	// or else the signal won't be delivered.
	if (prt->app_syscall_addr > 1 && (*(int*)(prt->app_syscall_addr) == 175)) {
		// Since Pin emulates sigprocmask and does not issue the
		// same sigprocmask as the application,
		// we check to see if the next log entry is 175,
		// if it is we simply pull the log entry, but we ignore it
		// since the args will be different. We just need to consume
		// the log entry so that we don't get a syscall mismatch.
		if (prt->rp_saved_psr) {
			if (prt->rp_saved_psr->sysnum == 175) {
				(*(int*)(prt->app_syscall_addr)) = 999;
			}
		}
	}

	return rc;
}

// record and replay rt_sigprocmask without Pin, with Pin, we'll just pass it through
asmlinkage long
shim_rt_sigprocmask (int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
	if (current->record_thrd) return record_rt_sigprocmask (how, set, oset, sigsetsize);
	if (current->replay_thrd) {
		struct replay_thread* prt = current->replay_thrd;
		if (prt->app_syscall_addr == 0) { // replay with no Pin attached
			return replay_rt_sigprocmask (how, set, oset, sigsetsize);
		} else {
			return pin_rt_sigprocmask (how, set, oset, sigsetsize);
		}
	}
	return sys_rt_sigprocmask (how, set, oset, sigsetsize);
}

asmlinkage long
shim_rt_sigpending (sigset_t __user *set, size_t sigsetsize)
SHIM_NOOP(rt_sigpending, set, sigsetsize)

static asmlinkage long
record_rt_sigtimedwait (const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize)
{
	long rc;
	char* buf = NULL;

	new_syscall_enter (177, NULL);

	rc = sys_rt_sigtimedwait (uthese, uinfo, uts, sigsetsize);
	DPRINT ("Pid %d records rt_sigtimedwait uthese %p uinfo %p returning %ld\n", current->pid, uthese, uinfo, rc);

	if (rc >= 0 && uinfo) {
		buf = ARGSKMALLOC(sizeof(siginfo_t), GFP_KERNEL);
		if (buf == NULL) {
			printk("record_rt_timedwait: can't alloc buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (buf, uinfo, sizeof(siginfo_t))) {
			ARGSKFREE (buf, sizeof(siginfo_t));
			buf = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (177, rc, buf);
	
	return rc;
}

static asmlinkage long
replay_rt_sigtimedwait (const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize)
{
	char* retparams = NULL;
	long rc = get_next_syscall (177, &retparams, NULL);
	if (retparams) {
		if (copy_to_user (uinfo, retparams, sizeof(siginfo_t))) printk ("Pid %d replay_rt_sigtimedwait cannot copy to user\n", current->pid);
	}
	return rc;
}

asmlinkage long
shim_rt_sigtimedwait (const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize)
SHIM_CALL(rt_sigtimedwait, 177, uthese, uinfo, uts, sigsetsize)

asmlinkage long
shim_rt_sigqueueinfo (int pid, int sig, siginfo_t __user *uinfo)
SHIM_NOOP(rt_sigqueueinfo, pid, sig, uinfo)

/* No prototype for sys_rt_sigsuspend */
//asmlinkage long sys_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize);

static asmlinkage long 
record_rt_sigsuspend (sigset_t __user *unewset, size_t sigsetsize) 
{
	long rc;

	new_syscall_enter (179, NULL);
	rc = sys_rt_sigsuspend (unewset, sigsetsize);
	new_syscall_exit (179, rc, NULL);
	DPRINT ("Pid %d records getpid returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_rt_sigsuspend (sigset_t __user *unewset, size_t sigsetsize) 
{
	// No need to suspend, I think, since we are faking the signal
	return get_next_syscall (179, NULL, NULL);
}

asmlinkage long shim_rt_sigsuspend (sigset_t __user *unewset, size_t sigsetsize) SHIM_CALL(rt_sigsuspend, 179, unewset, sigsetsize);

static asmlinkage ssize_t 
record_pread64 (unsigned int fd, char __user * buf, size_t count, loff_t pos)
{
	ssize_t size;
	char* recbuf = NULL;

	new_syscall_enter (180, NULL);

	size = sys_pread64 (fd, buf, count, pos);
	if (size > 0) {
		recbuf = ARGSKMALLOC(size, GFP_KERNEL);
		if (recbuf == NULL) {
			printk("record_pread64: can't allocate buffer(%d)\n", size);
			return -ENOMEM;
		}
		if (copy_from_user (recbuf, buf, size)) {
			ARGSKFREE (recbuf, size);
			return -EFAULT;
		}
	}

	new_syscall_exit (180, size, recbuf);

	DPRINT ("Pid %d records read returning %d\n", current->pid, size);

	return size;
}

static asmlinkage ssize_t 
replay_pread64 (unsigned int fd, char __user * buf, size_t count, loff_t pos)
{
	char* retparams = NULL;
	long rc = get_next_syscall (180, &retparams, NULL);
	if (retparams) {
		if (copy_to_user (buf, retparams, rc)) printk ("Pid %d replay_pread64 cannot copy to user\n", current->pid);
	}

	return rc;
}


asmlinkage ssize_t 
shim_pread64 (unsigned int fd, char __user *buf, size_t count, loff_t pos)
SHIM_CALL(pread64, 180, fd, buf, count, pos)

static asmlinkage ssize_t 
record_pwrite64 (unsigned int fd, const char __user *buf, size_t count, loff_t pos)
{
	ssize_t size;

	new_syscall_enter (181, NULL);

	size = sys_pwrite64 (fd, buf, count, pos);
	MPRINT ("Pid %d records pwrite64 returning %d\n", current->pid, size);

	new_syscall_exit (181, size, NULL);

	return size;
}

static asmlinkage ssize_t 
replay_pwrite64 (unsigned int fd, const char __user *buf, size_t count, loff_t pos)
{
	ssize_t rc = get_next_syscall (181, NULL, NULL);
	DPRINT ("Pid %d replays pwrite64 returning %d\n", current->pid,rc);
	return rc;
}

asmlinkage ssize_t 
shim_pwrite64 (unsigned int fd, const char __user *buf, size_t count, loff_t pos)
SHIM_CALL(pwrite64, 181, fd, buf, count, pos)

asmlinkage long 
shim_chown16 (const char __user * filename, old_uid_t user, old_gid_t group)
SHIM_NOOP(chown16, filename, user, group)

static asmlinkage long 
record_getcwd (char __user *buf, unsigned long size) 
{
	long rc;
	char *recbuf = NULL;

	new_syscall_enter (183, NULL);

	rc = sys_getcwd (buf, size);
	DPRINT ("Pid %d records getcwd returning %ld\n", current->pid, rc);
	if (rc >= 0) {
		recbuf = ARGSKMALLOC(rc, GFP_KERNEL);
		if (recbuf == NULL) {
			printk("record_getcwd: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (recbuf, buf, rc)) { 
			ARGSKFREE (recbuf, rc);
			recbuf = NULL;
			rc = -EFAULT;
		}
	}
		
	new_syscall_exit (183, rc, recbuf);

	return rc;
}

static asmlinkage long 
replay_getcwd (char __user *buf, unsigned long size) 
{
	char* retparams = NULL;
	long rc = get_next_syscall (183, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (buf, retparams, rc)) printk ("Pid %d replay_getcwd cannot copy to user\n", current->pid);
	}

	return rc;
}


asmlinkage long 
shim_getcwd (char __user *buf, unsigned long size) 
SHIM_CALL(getcwd, 183, buf, size)

asmlinkage long 
shim_capget (cap_user_header_t header, cap_user_data_t dataptr)
SHIM_NOOP(capget, header, dataptr)

asmlinkage long 
shim_capset (cap_user_header_t header, const cap_user_data_t data)
SHIM_NOOP(capset, header, data)

/* sigaltstack should be deterministic, so do not intercept */

static asmlinkage ssize_t 
record_sendfile (int out_fd, int in_fd, off_t __user *offset, size_t count)
{
	long rc;
	off_t* pretval = NULL;

	new_syscall_enter (187, NULL);

	rc = sys_sendfile (out_fd, in_fd, offset, count);
	DPRINT ("Pid %d records sendfile returning %ld\n", current->pid, rc);

	if (rc > 0) {
		pretval = ARGSKMALLOC(sizeof(off_t), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_sendfile: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, offset, sizeof(off_t))) {
			ARGSKFREE (pretval, sizeof(off_t));
			pretval = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (187, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_sendfile (int out_fd, int in_fd, off_t __user *offset, size_t count)
{
	off_t* retparams = NULL;
	long rc = get_next_syscall (187, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (offset, retparams, sizeof(off_t))) printk ("Pid %d replay_sendfile cannot copy to user\n", current->pid);
	}
	return rc;
}

asmlinkage ssize_t 
shim_sendfile (int out_fd, int in_fd, off_t __user *offset, size_t count)
SHIM_CALL (sendfile, 187, out_fd, in_fd, offset, count)

void 
record_vfork_handler (struct task_struct* tsk)
{
	struct record_group* prg = current->record_thrd->rp_group;
#ifdef USE_ARGSALLOC
	void* slab;
#endif

	DPRINT ("In record_vfork_handler\n");
	rg_lock(prg);
	tsk->record_thrd = new_record_thread (prg, tsk->pid, -1);
	if (tsk->record_thrd == NULL) {
		printk ("record_vfork_handler: cannot allocate record thread\n");
		rg_unlock(prg);
		return;
	}
	tsk->replay_thrd = NULL;

	tsk->record_thrd->rp_cloned_id = atomic_add_return (1, &rp_cloned_next);
	DPRINT ("Pid %d assigned cloned_id %ld\n", current->pid, tsk->record_thrd->rp_cloned_id);
	
	tsk->record_thrd->rp_next_thread = current->record_thrd->rp_next_thread;
	current->record_thrd->rp_next_thread = tsk->record_thrd;
	
	tsk->record_thrd->rp_user_log_addr = current->record_thrd->rp_user_log_addr;
	tsk->record_thrd->rp_ignore_flag_addr = current->record_thrd->rp_ignore_flag_addr;
	
	// also inherit the parent's pointer to the user-clock
	tsk->record_thrd->rp_precord_clock = current->record_thrd->rp_precord_clock;
	
#ifdef USE_ARGSALLOC
	// allocate a slab for retparams
	slab = VMALLOC (argsalloc_size);
	if (slab == NULL) {
		rg_unlock(prg);
		printk ("record_vfork_handler: no memory for slab\n");
		return;
	}
	if (add_argsalloc_node(tsk->record_thrd, slab)) {
		rg_unlock(prg);
		VFREE (slab);
		printk ("Pid %d record_vfork: error adding argsalloc_node\n", current->pid);
		return;
	}
#endif
	rg_unlock(prg);
	DPRINT ("Done with record_vfork_handler\n");
}

static long
record_vfork (unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
	long rc;

	new_syscall_enter (190, NULL);

	/* On clone, we reset the user log.  On, vfork we do not do this because the parent and child share one
           address space.  This sharing will get fixed on exec. */

	rc = do_fork (clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);		
	MPRINT ("Pid %d records vfork returning %ld\n", current->pid, rc);

	new_syscall_exit (190, rc, NULL);
	
	return rc;
}

void 
replay_vfork_handler (struct task_struct* tsk)
{
	struct replay_group* prg = current->replay_thrd->rp_group;
	struct record_thread* prt;
	struct replay_thread* prept;
	ds_list_iter_t* iter;
	long rc = current->replay_thrd->rp_record_thread->rp_log[current->replay_thrd->rp_out_ptr-1].retval;

	// Attach the replay thread struct to the child
	rg_lock(prg->rg_rec_group);
	
	/* Find the corresponding record thread based on pid.
	 * We used to find the last prt with replay_pid == 0,
	 * but it fails if child thread spawns another child thread.
	 * We should not assume that there is only one thread that
	 * spawns other threads.
	 */
	for (prt = current->replay_thrd->rp_record_thread->rp_next_thread;
	     prt != current->replay_thrd->rp_record_thread; prt = prt->rp_next_thread) {
		if (prt->rp_record_pid==rc) {
			DPRINT ("Pid %d find replay_thrd %p (rec_pid=%d,rep_pid=%d)\n", current->pid, prt, prt->rp_record_pid, tsk->pid);
			break;
		}
	}

	// if Pin is attached the record_thread could already exist (via preallocate_mem) so we need to check
	// to see if it exists first before creating
	if (prt == NULL || prt->rp_record_pid != rc) {	
		/* For replays resumed form disk checkpoint, there will be no record thread.  We should create it here. */
		prt = new_record_thread (prg->rg_rec_group, rc, -1);
		// Since there is no recording going on, we need to dec record_thread's refcnt
		atomic_dec(&prt->rp_refcnt);
		DPRINT ("Created new record thread %p\n", prt);
	}
	
	/* Ensure that no replay thread in this replay group points to this record thread */
	iter = ds_list_iter_create(prg->rg_replay_threads);
	while ((prept = ds_list_iter_next(iter)) != NULL) {
		if (prept->rp_record_thread == prt) {
			printk ("[DIFF]replay_vfork_handler: record thread already cloned?\n");
			ds_list_iter_destroy(iter);
			rg_unlock(prg->rg_rec_group);
			return;
		}
	}
	ds_list_iter_destroy(iter);
	
	/* Update our replay_thrd with this information */
	tsk->record_thrd = NULL;
	DPRINT ("Cloning new replay thread\n");
	tsk->replay_thrd = new_replay_thread(prg, prt, tsk->pid, 0);
	BUG_ON (!tsk->replay_thrd);
	
	// inherit the parent's app_syscall_addr
	tsk->replay_thrd->app_syscall_addr = current->replay_thrd->app_syscall_addr;
	
	MPRINT ("Pid %d, tsk->pid %d refcnt for replay thread %p now %d\n", current->pid, tsk->pid, tsk->replay_thrd,
		atomic_read(&tsk->replay_thrd->rp_refcnt));
	MPRINT ("Pid %d, tsk->pid %d refcnt for record thread pid %d now %d\n", current->pid, tsk->pid, prt->rp_record_pid,
		atomic_read(&prt->rp_refcnt));
	
	
	// Fix up the circular thread list
	tsk->replay_thrd->rp_next_thread = current->replay_thrd->rp_next_thread;
	current->replay_thrd->rp_next_thread = tsk->replay_thrd;
	
	// also inherit the parent's pointer to the user-clock
	tsk->replay_thrd->rp_preplay_clock = current->replay_thrd->rp_preplay_clock;
	
	// read the rest of the log
	read_log_data (tsk->replay_thrd->rp_record_thread);
	
	prept = current->replay_thrd;
	tsk->replay_thrd->rp_status = REPLAY_STATUS_RUNNING; // Child needs to run first to complete vfork
	tsk->thread.ip = (u_long) ret_from_fork_2;
	current->replay_thrd->rp_status = REPLAY_STATUS_ELIGIBLE; // So we need to wait
	rg_unlock(prg->rg_rec_group);
}

static long
replay_vfork (unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
	struct task_struct* tsk = NULL;
	struct replay_thread* prt = current->replay_thrd;
	struct replay_group* prg = prt->rp_group;
	struct syscall_result* psr = NULL;
	pid_t pid;
	long ret, rc;

	// See above comment about user log

	// This is presumably necessary for PIN handling
	MPRINT ("Pid %d replay_vfork syscall enter\n", current->pid);
	if (prt->app_syscall_addr > 1) {
		rc = prt->rp_saved_rc;
		(*(int*)(prt->app_syscall_addr)) = 999;
	} else {
		rc = get_next_syscall_enter (prt, prg, 190, NULL, NULL, &psr);
	}

	DPRINT ("Pid %d replay_vfork syscall exit:rc=%ld\n", current->pid, rc);
	if (rc > 0) {
		// We need to keep track of whether or not a signal was attached
		// to this system call; sys_clone_internal will clear the flag
		// so we need to be able to set it again at the end of the syscall
		int rp_sigpending = test_thread_flag (TIF_SIGPENDING);

		// We also need to create a child here 
		pid = do_fork (clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);		
		MPRINT ("Pid %d in replay_vfork spawns child %d\n", current->pid, pid);
		if (pid < 0) {
			printk ("[DIFF]replay_vfork: second vfork failed, rc=%d\n", pid);
			return syscall_mismatch();
		}
	
		// see above
		if (rp_sigpending) {
			DPRINT ("Pid %d sig was pending in clone!\n", current->pid);
			signal_wake_up (current, 0);
		}

		// Next, we have to wait while child runs 
		DPRINT ("replay_vfork: pid %d going to sleep\n", current->pid);
		ret = wait_event_interruptible_timeout (prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING, SCHED_TO);

		rg_lock(prg->rg_rec_group);
		if (ret == 0) printk ("Replay pid %d timed out waiting for vfork to complete\n", current->pid);
		if (prt->rp_status != REPLAY_STATUS_RUNNING) {
			MPRINT ("Replay pid %d woken up during vfork but not running.  We must want it to die\n", current->pid);
			rg_unlock(prg->rg_rec_group);
			sys_exit (0);
		}
		rg_unlock(prg->rg_rec_group);
	}
		
	if (prt->app_syscall_addr == 0) {
		get_next_syscall_exit (prt, prg, psr);
	}
	if (rc > 0 && prt->app_syscall_addr) {
		MPRINT ("Return real child pid %d to Pin instead of recorded child pid %ld\n", tsk->pid, rc);
		return tsk->pid;
	}

	return rc;
}

long 
shim_vfork(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
	if (current->record_thrd) return record_vfork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);		
	if (current->replay_thrd) return replay_vfork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);		
	return do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
}

static asmlinkage long 
record_getrlimit (unsigned int resource, struct rlimit __user *rlim)
{
	long rc;
	struct rlimit *pretval = NULL;

	new_syscall_enter (191, NULL);

	rc = sys_getrlimit (resource, rlim);
	DPRINT ("Pid %d records getrlimit resource %d rlim %p returning %ld\n", current->pid, resource, rlim, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct rlimit), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_getrlimit: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, rlim, sizeof(struct rlimit))) { 
			ARGSKFREE (pretval, sizeof(struct rlimit));
			pretval = NULL;
			rc = -EFAULT;
		}
	}
		
	new_syscall_exit (191, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_getrlimit (unsigned int resource, struct rlimit __user *rlim)
{
	struct rlimit *retparams = NULL;
	long rc = get_next_syscall (191, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (rlim, retparams, sizeof(struct rlimit))) printk ("Pid %d replay_getrlimit cannot copy to user\n", current->pid);
	}

	return rc;
}

asmlinkage long 
shim_getrlimit (unsigned int resource, struct rlimit __user *rlim)
SHIM_CALL(getrlimit, 191, resource, rlim)

static asmlinkage long 
record_mmap_pgoff (unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
	long rc;
	struct mmap_pgoff_retvals* recbuf = NULL;
	struct mmap_pgoff_args* args = ARGSKMALLOC (sizeof(struct mmap_pgoff_args), GFP_KERNEL);

	if (args == NULL) {
		printk ("record_mmap_pgoff: can't allocate args\n");
		return -ENOMEM;
	}
	args->addr = addr;
	args->len = len;
	args->prot = prot;
	args->flags = flags;
	args->fd = fd;
	args->pgoff = pgoff;

	rg_lock(current->record_thrd->rp_group);
	__new_syscall_enter (192, args);
	rc = sys_mmap_pgoff (addr, len, prot, flags, fd, pgoff);

	/* Good thing we have the extra synchronization and rg_lock
	 * held, since we need to store some return values of mmap
	 * with the argument list: the mapped file, and the memory
	 * region allocated (different from that requested).
	 */
	if ((rc > 0 || rc < -1024) && fd >= 0) {
		struct vm_area_struct *vma;
		struct mm_struct *mm = current->mm;
		down_read(&mm->mmap_sem);
		vma = find_vma(mm, rc);
		if (vma && rc >= vma->vm_start && vma->vm_file) {
			recbuf = ARGSKMALLOC(sizeof(struct mmap_pgoff_retvals), GFP_KERNEL);
			add_file_to_cache (vma->vm_file, &recbuf->dev, &recbuf->ino, &recbuf->mtime);
		}
		up_read(&mm->mmap_sem);
	}

	DPRINT ("Pid %d records mmap_pgoff with addr %lx len %lx prot %lx flags %lx fd %lu ret %lx\n", current->pid, addr, len, prot, flags, fd, rc);

	new_syscall_exit (192, rc, recbuf);
	rg_unlock(current->record_thrd->rp_group);

	return rc;
}

static asmlinkage long 
replay_mmap_pgoff (unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
	struct mmap_pgoff_args* args;
	u_long retval, rc;
	int given_fd = fd;
	struct mmap_pgoff_retvals* recbuf = NULL;
	struct replay_thread* prt = current->replay_thrd;
	struct syscall_result* psr;

	if (prt->app_syscall_addr > 1) {
		rc = prt->rp_saved_rc;
		recbuf = (struct mmap_pgoff_retvals *) prt->rp_saved_retparams;
		psr = prt->rp_saved_psr;
		(*(int*)(prt->app_syscall_addr)) = 999;
	} else {
		rc = get_next_syscall (192, (char **) &recbuf, (char **) &args);
	}

	if (recbuf) {
		rg_lock(prt->rp_record_thread->rp_group);
		given_fd = open_cache_file (recbuf->dev, recbuf->ino, recbuf->mtime, (prot&PROT_WRITE) && (flags&MAP_SHARED));
		rg_unlock(prt->rp_record_thread->rp_group);
		MPRINT ("replay_mmap_pgoff opens cache file %x %lx %lx.%lx, fd = %d\n", recbuf->dev, recbuf->ino, recbuf->mtime.tv_sec, recbuf->mtime.tv_nsec, given_fd);
		if (given_fd < 0) {
			printk ("replay_mmap_pgoff: can't open cache file, rc=%d\n", given_fd);
			syscall_mismatch();
		}
	} else if (given_fd >= 0) {
		printk ("replay_mmap_pgoff: fd is %d but there are no return values recorded\n", given_fd);
	}

	retval = sys_mmap_pgoff (rc, len, prot, (flags | MAP_FIXED), given_fd, pgoff);
	DPRINT ("Pid %d replays mmap_pgoff with address %lx len %lx input address %lx fd %d flags %lx prot %lx pgoff %lx returning %lx, flags & MAP_FIXED %lu\n", current->pid, addr, len, rc, given_fd, flags, prot, pgoff, retval, flags & MAP_FIXED);
	
	if (rc != retval) {
		printk ("Replay mmap_pgoff returns different value %lx than %lx\n", retval, rc);
		syscall_mismatch ();
	}

	if (recbuf && given_fd > 0) sys_close(given_fd);

	return rc;
}

asmlinkage long 
shim_mmap_pgoff (unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
SHIM_CALL(mmap_pgoff, 192, addr, len, prot, flags, fd, pgoff);

asmlinkage long 
shim_truncate64 (const char __user * path, loff_t length)
SHIM_NOOP(truncate64, path, length)

static asmlinkage long 
record_ftruncate64 (unsigned int fd, loff_t length)
{
	long rc;

	new_syscall_enter (194, NULL);
	rc = sys_ftruncate64 (fd, length);
	new_syscall_exit (194, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_ftruncate64 (unsigned int fd, loff_t length)
{
	return get_next_syscall  (194, NULL, NULL);
}

asmlinkage long 
shim_ftruncate64 (unsigned int fd, loff_t length) 
SHIM_CALL(ftruncate64, 194, fd, length)

static asmlinkage long 
record_stat64 (char __user * filename, struct stat64 __user * statbuf)
{
	long rc;
	struct stat64* pretval = NULL;

	new_syscall_enter (195, NULL);

	rc = sys_stat64 (filename, statbuf);
	DPRINT ("Pid %d records stat64 of %s returning %ld\n", current->pid, filename, rc);

	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct stat64), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_stat64: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, statbuf, sizeof(struct stat64))) {
			ARGSKFREE (pretval, sizeof(struct stat64));
			return -EFAULT;
		}
	}
		
	new_syscall_exit (195, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_stat64 (char __user * filename, struct stat64 __user * statbuf)
{
	struct stat* retparams = NULL;
	long rc = get_next_syscall (195, (char **) &retparams, NULL);
	DPRINT ("Pid %d replays stat64 of %s returning %ld\n", current->pid, filename, rc);
	if (retparams) {
		if (copy_to_user (statbuf, retparams, sizeof(struct stat64))) printk ("Pid %d cannot copy statbuf to user\n", current->pid);
	}
	return rc;
}

asmlinkage long 
shim_stat64 (char __user * filename, struct stat64 __user * statbuf)
SHIM_CALL(stat64, 195, filename, statbuf);

static asmlinkage long 
record_lstat64 (char __user * filename, struct stat64 __user * statbuf)
{
	long rc;
	struct stat64* pretval = NULL;

	new_syscall_enter (196, NULL);

	rc = sys_lstat64 (filename, statbuf);
	DPRINT ("Pid %d records lstat64 returning %ld\n", current->pid, rc);

	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct stat64), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_stat64: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, statbuf, sizeof(struct stat64))) {
			ARGSKFREE (pretval, sizeof(struct stat64));
			return -EFAULT;
		}
	}

	new_syscall_exit (196, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_lstat64 (char __user * filename, struct stat64 __user * statbuf)
{
	struct stat* retparams = NULL;
	long rc = get_next_syscall (196, (char**) &retparams, NULL);
	DPRINT ("Pid %d replay lstat64 of %s, rc=%ld\n", current->pid, filename, rc);
	if (retparams) {
		if (copy_to_user (statbuf, retparams, sizeof(struct stat64))) printk ("Pid %d cannot copy statbuf to user\n", current->pid);
	}
	return rc;
}

asmlinkage long 
shim_lstat64 (char __user * filename, struct stat64 __user * statbuf)
SHIM_CALL(lstat64, 196, filename, statbuf);

static asmlinkage long 
record_fstat64 (unsigned long fd, struct stat64 __user * statbuf)
{
	long rc;
	struct stat64* pretval = NULL;

	new_syscall_enter (197, NULL);

	rc = sys_fstat64 (fd, statbuf);
	DPRINT ("Pid %d records fstat64(fd=%lu,statbuf=%p) returning %ld\n", current->pid, fd, statbuf,rc);
	DPRINT ("st_blksize is %lx\n", statbuf->st_blksize);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct stat64), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_stat64: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, statbuf, sizeof(struct stat64))) {
			ARGSKFREE (pretval, sizeof(struct stat64));
			return -EFAULT;
		}
	}

	new_syscall_exit (197, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_fstat64 (unsigned long fd, struct stat64 __user * statbuf)
{
	struct stat64* retparams = NULL;
	long rc = get_next_syscall (197, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (statbuf, retparams, sizeof(struct stat64))) printk ("Pid %d cannot copy statbuf to user\n", current->pid);
	}
	DPRINT ("Pid %d fstat64 replay returns %ld\n", current->pid, rc);
	return rc;
}

asmlinkage long 
shim_fstat64 (unsigned long fd, struct stat64 __user * statbuf)
SHIM_CALL(fstat64, 197, fd, statbuf);

asmlinkage long 
shim_lchown (const char __user * filename, uid_t user, gid_t group)
SHIM_NOOP(lchown, filename, user, group)

static asmlinkage long 
record_getuid (void)
{
	long rc;

	new_syscall_enter (199, NULL);
	rc = sys_getuid();
	new_syscall_exit (199, rc, NULL);
	DPRINT ("Pid %d records getuid returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_getuid (void)
{
	return get_next_syscall (199, NULL, NULL);
}

asmlinkage long shim_getuid (void) 
SHIM_CALL(getuid, 199);

static asmlinkage long
record_getgid (void)
{
	long rc;

	new_syscall_enter (200, NULL);
	rc = sys_getgid ();
	new_syscall_exit (200, rc, NULL);
	DPRINT ("Pid %d records getgid return %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long
replay_getgid (void)
{
	return get_next_syscall (200, NULL, NULL);
}

asmlinkage long shim_getgid (void) SHIM_CALL(getgid, 200)

static asmlinkage long 
record_geteuid (void)
{
	long rc;
	
	new_syscall_enter (201, NULL);
	rc = sys_geteuid ();
	new_syscall_exit (201, rc, NULL);
	DPRINT ("Pid %d records geteuid returning %ld\n", current->pid, rc);

	return rc;
}	

static asmlinkage long 
replay_geteuid (void)
{
	return get_next_syscall (201, NULL, NULL);
}

asmlinkage long shim_geteuid (void) 
SHIM_CALL(geteuid, 201)

static asmlinkage long
record_getegid (void)
{
	long rc;

	new_syscall_enter (202, NULL);
	rc = sys_getegid ();
	new_syscall_exit (202, rc, NULL);
	DPRINT ("Pid %d records getegid returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long
replay_getegid (void)
{
	return get_next_syscall (202, NULL, NULL);
}

asmlinkage long shim_getegid (void) SHIM_CALL(getegid, 202)

asmlinkage long 
shim_setreuid (uid_t ruid, uid_t euid) SHIM_NOOP(setreuid, ruid, euid)

asmlinkage long 
shim_setregid (gid_t rgid, gid_t egid) SHIM_NOOP(setregid, rgid, egid)

static asmlinkage long 
record_getgroups (int gidsetsize, gid_t __user *grouplist)
{
	long rc;
	gid_t* pretval = NULL;

	new_syscall_enter (205, NULL);

	rc = sys_getgroups (gidsetsize, grouplist);
	DPRINT ("Pid %d records getgroups returning %ld\n", current->pid, rc);
	if (rc > 0) {
		pretval = ARGSKMALLOC(sizeof(gid_t)*rc, GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_getgroups: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, grouplist, sizeof(gid_t)*rc)) {
			ARGSKFREE (pretval, sizeof(gid_t)*rc);
			return -EFAULT;
		}
	}

	new_syscall_exit (205, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_getgroups (int gidsetsize, gid_t __user *grouplist)
{
	gid_t* retparams = NULL;
	long rc = get_next_syscall (205, (char **) &retparams, NULL);
	if (rc > 0) {
		if (retparams) {
			if (copy_to_user (grouplist, retparams, sizeof(gid_t)*rc)) printk ("Pid %d cannot copy groups to user\n", current->pid);
		} else {
			printk ("getgroups has return values but non-positive rc?\n");
		}
	}
	DPRINT ("Pid %d getgroups replay returns %ld\n", current->pid, rc);
	return rc;
}

asmlinkage long 
shim_getgroups (int gidsetsize, gid_t __user *grouplist)
SHIM_CALL(getgroups, 205, gidsetsize, grouplist)

static asmlinkage long
record_setgroups (int gidsetsize, gid_t __user * grouplist)
{
	long rc;

	if ((unsigned)gidsetsize > NGROUPS_MAX)	return -EINVAL;

	new_syscall_enter (206, NULL);

	rc = sys_setgroups (gidsetsize, grouplist);
	DPRINT ("Pid %d records setgroups returning %ld\n", current->pid, rc);

	new_syscall_exit (206, rc, NULL);

	return rc;
}

static asmlinkage ssize_t 
replay_setgroups (int gidsetsize, gid_t __user *grouplist)
{
	long rc;

	if ((unsigned)gidsetsize > NGROUPS_MAX)	return -EINVAL;

	rc = get_next_syscall (206, NULL, NULL);
	DPRINT ("Pid %d replays setgroups returning %ld\n", current->pid, rc);
	return rc;
}

asmlinkage long 
shim_setgroups (int gidsetsize, gid_t __user *grouplist)
SHIM_CALL(setgroups, 206, gidsetsize, grouplist)

static asmlinkage long
record_fchown (unsigned int fd, uid_t user, gid_t group)
{
	long rc;

	new_syscall_enter (207, NULL);

	rc = sys_fchown (fd, user, group);
	DPRINT ("Pid %d records fchown returning %ld\n", current->pid, rc);

	new_syscall_exit (207, rc, NULL);

	return rc;
}

static asmlinkage long
replay_fchown (unsigned int fd, uid_t user, gid_t group)
{
	return get_next_syscall (207, NULL, NULL);
}

asmlinkage long 
shim_fchown (unsigned int fd, uid_t user, gid_t group)
SHIM_CALL (fchown, 207, fd, user, group)

static asmlinkage long
record_setresuid (uid_t ruid, uid_t euid, uid_t suid) 
{
	long rc;

	new_syscall_enter (208, NULL);
	rc = sys_setresuid (ruid, euid, suid);
	DPRINT ("Pid %d records setresuid(%d, %d, %d) returning %ld\n", current->pid, ruid, euid, suid, rc);
	new_syscall_exit (208, rc, NULL);

	return rc;
}

static asmlinkage long
replay_setresuid (uid_t ruid, uid_t euid, uid_t suid) 
{
	return get_next_syscall (208, NULL, NULL);
}

asmlinkage long 
shim_setresuid (uid_t ruid, uid_t euid, uid_t suid) 
SHIM_CALL(setresuid, 208, ruid, euid, suid)

static asmlinkage long
record_getresuid (uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) 
{
	long rc;
	uid_t* pretval = NULL;

	new_syscall_enter (209, NULL);
	rc = sys_getresuid (ruid, euid, suid);
	if (rc >= 0) {
		pretval = ARGSKMALLOC(sizeof(uid_t)*3, GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_getresuid: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, ruid, sizeof(uid_t)) ||
		    copy_from_user (pretval+1, euid, sizeof(uid_t)) ||
		    copy_from_user (pretval+2, suid, sizeof(uid_t))) {
			ARGSKFREE (pretval, sizeof(uid_t)*3);
			return -EFAULT;
		}
	}

	DPRINT ("Pid %d records getresuid returning %ld\n", current->pid, rc);
	new_syscall_exit (209, rc, pretval);

	return rc;
}

static asmlinkage long
replay_getresuid (uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) 
{
	uid_t* retparams = NULL;
	long rc = get_next_syscall (209, (char **) &retparams, NULL);
	if (rc >= 0) {
		if (retparams) {
			if (copy_to_user (ruid, retparams, sizeof(uid_t)) ||
			    copy_to_user (euid, retparams+1, sizeof(uid_t)) ||
			    copy_to_user (suid, retparams+2, sizeof(uid_t))) {
				printk ("replay_getresuid: pid %d cannot copy uids to user\n", current->pid);
			}
		} else {
			printk ("getresuid has return values but non-negative rc?\n");
		}
	}
	return rc;
}

asmlinkage long 
shim_getresuid (uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid)
SHIM_CALL(getresuid, 209, ruid, euid, suid)

static asmlinkage long
record_setresgid (gid_t rgid, gid_t egid, gid_t sgid)
{
	long rc;

	new_syscall_enter (210, NULL);
	rc = sys_setresgid(rgid, egid, sgid);
	DPRINT ("Pid %d records setresgid(%d, %d, %d) returning %ld\n", current->pid, rgid, egid, sgid, rc);
	new_syscall_exit (210, rc, NULL);

	return rc;
}

static asmlinkage long
replay_setresgid (gid_t rgid, gid_t egid, gid_t sgid)
{
	return get_next_syscall (210, NULL, NULL);
}

asmlinkage long 
shim_setresgid (gid_t rgid, gid_t egid, gid_t sgid)
SHIM_CALL(setresgid, 210, rgid, egid, sgid)

static asmlinkage long
record_getresgid (gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) 
{
	long rc;
	gid_t* pretval = NULL;

	new_syscall_enter (211, NULL);
	rc = sys_getresgid (rgid, egid, sgid);
	if (rc >= 0) {
		pretval = ARGSKMALLOC(sizeof(gid_t)*3, GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_getresgid: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, rgid, sizeof(gid_t)) ||
		    copy_from_user (pretval+1, egid, sizeof(gid_t)) ||
		    copy_from_user (pretval+2, sgid, sizeof(gid_t))) {
			ARGSKFREE (pretval, sizeof(gid_t)*3);
			return -EFAULT;
		}
	}

	DPRINT ("Pid %d records getresgid returning %ld\n", current->pid, rc);
	new_syscall_exit (211, rc, pretval);

	return rc;
}

static asmlinkage long
replay_getresgid (gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) 
{
	gid_t* retparams = NULL;
	long rc = get_next_syscall (211, (char **) &retparams, NULL);
	if (rc >= 0) {
		if (retparams) {
			if (copy_to_user (rgid, retparams, sizeof(gid_t)) ||
			    copy_to_user (egid, retparams+1, sizeof(gid_t)) ||
			    copy_to_user (sgid, retparams+2, sizeof(gid_t))) {
				printk ("replay_getresgid: pid %d cannot copy gids to user\n", current->pid);
			}
		} else {
			printk ("getresgid has return values but non-negative rc?\n");
		}
	}
	return rc;
}

asmlinkage long 
shim_getresgid (gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid)
SHIM_CALL(getresgid, 211, rgid, egid, sgid)

static asmlinkage long 
record_chown (const char __user * filename, uid_t user, gid_t group)
{
	long rc;

	new_syscall_enter (212, NULL);

	rc = sys_chown (filename, user, group);
	DPRINT ("Pid %d records chown returning %ld\n", current->pid, rc);

	new_syscall_exit (212, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_chown (const char __user * filename, uid_t user, gid_t group)
{
	return get_next_syscall (212, NULL, NULL);
}

asmlinkage long 
shim_chown (const char __user * filename, uid_t user, gid_t group)
SHIM_CALL(chown, 212, filename, user, group);

static asmlinkage long 
record_setuid (uid_t uid)
{
	long rc;

	new_syscall_enter (213, NULL);

	rc = sys_setuid (uid);
	DPRINT ("Pid %d records setuid returning %ld\n", current->pid, rc);
	
	new_syscall_exit (213, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_setuid (uid_t uid)
{
	return get_next_syscall (213, NULL, NULL);
}

asmlinkage long shim_setuid (uid_t uid) 
SHIM_CALL(setuid, 213, uid)

static asmlinkage long 
record_setgid (gid_t gid)
{
	long rc;

	new_syscall_enter (214, NULL);

	rc = sys_setgid (gid);
	DPRINT ("Pid %d records setgid returning %ld\n", current->pid, rc);
	
	new_syscall_exit (214, rc, NULL);

	return rc;
}	

static asmlinkage long 
replay_setgid (gid_t gid)
{
	return get_next_syscall (214, NULL, NULL);
}

asmlinkage long shim_setgid (gid_t gid) 
SHIM_CALL(setgid, 214, gid)

static asmlinkage long
record_setfsuid (uid_t uid)
{
	long rc;

	new_syscall_enter (215, NULL);

	rc = sys_setfsuid (uid);
	DPRINT ("Pid %d records setfsuid returning %ld\n", current->pid, rc);

	new_syscall_exit (215, rc, NULL);

	return rc;
}

static asmlinkage long
replay_setfsuid (uid_t uid)
{
	return get_next_syscall (215, NULL, NULL);
}

asmlinkage long shim_setfsuid (uid_t uid) 
SHIM_CALL(setfsuid, 215, uid)

static asmlinkage long
record_setfsgid (gid_t gid)
{
	long rc;

	new_syscall_enter (216, NULL);

	rc = sys_setfsgid (gid);
	DPRINT ("Pid %d records setfsgid returning %ld\n", current->pid, rc);

	new_syscall_exit (216, rc, NULL);

	return rc;
}

static asmlinkage long
replay_setfsgid (gid_t gid)
{
	return get_next_syscall (216, NULL, NULL);
}

asmlinkage long shim_setfsgid (gid_t gid) 
SHIM_CALL(setfsgid, 216, gid)

asmlinkage long 
shim_pivot_root (const char __user * new_root, const char __user * put_old)
SHIM_NOOP(pivot_root, new_root, put_old)

asmlinkage long 
shim_mincore (unsigned long start, size_t len, unsigned char __user * vec)
SHIM_NOOP(mincore, start, len, vec)

static asmlinkage long 
record_madvise (unsigned long start, size_t len_in, int behavior)
{
	long rc;

	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (219, NULL);
	rc = sys_madvise (start, len_in, behavior);
	new_syscall_exit (219, rc, NULL);
	rg_unlock(current->record_thrd->rp_group);

	return rc;
}

static asmlinkage long 
replay_madvise (unsigned long start, size_t len_in, int behavior)
{
	long retval, rc = get_next_syscall (219, NULL, NULL);
	retval = sys_madvise (start, len_in, behavior);

	if (rc != retval) {
		printk ("Replay madvise returns different val %lu than %lu\n", retval, rc);
		syscall_mismatch();
	}

	return rc;
}

asmlinkage long 
shim_madvise (unsigned long start, size_t len_in, int behavior)
SHIM_CALL(madvise, 219, start, len_in, behavior)

static asmlinkage long 
record_getdents64 (unsigned int fd, struct linux_dirent64 __user * dirent, unsigned int count)
{
	long rc;
	char* buf = NULL;

	new_syscall_enter (220, NULL);

	rc = sys_getdents64 (fd, dirent, count);
	DPRINT ("Pid %d records getdents64 returning %ld\n", current->pid, rc);

	if (rc > 0) {
		buf = ARGSKMALLOC (rc, GFP_KERNEL);
		if (buf == NULL) {
			printk("record_getdents64: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (buf, dirent, rc)) {
			ARGSKFREE (buf, rc);
			return -EFAULT;
		}
	}

	new_syscall_exit (220, rc, buf);

	return rc;
}

static asmlinkage long 
replay_getdents64 (unsigned int fd, struct linux_dirent64 __user * dirent, unsigned int count)
{
	char* retparams = NULL;
	long rc = get_next_syscall (220, &retparams, NULL);
	if (retparams) {
		if (copy_to_user (dirent, retparams, rc)) 
			printk ("Pid %d replay_getdents64 cannot copy dirent to user\n", current->pid);
	}
	return rc;
}

asmlinkage long 
shim_getdents64 (unsigned int fd, struct linux_dirent64 __user * dirent, unsigned int count)
SHIM_CALL(getdents64, 220, fd, dirent, count);

static asmlinkage long 
record_fcntl64 (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	struct flock* recbuf = NULL;
	long rc;

	new_syscall_enter (221, NULL);
	rc = sys_fcntl64 (fd, cmd, arg);

	if (rc >= 0 && cmd == F_GETLK) {
		recbuf = ARGSKMALLOC(sizeof(struct flock64), GFP_KERNEL);
		if (!recbuf) {
			printk ("record_fcntl64: can't allocate return buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user(recbuf, (struct flock64 __user *)arg, sizeof(struct flock64))) {
			printk("record_fcntl64: faulted on readback\n");
			KFREE(recbuf);
			return -EFAULT;
		}
	}

	new_syscall_exit (221, rc, recbuf);

	DPRINT ("record fcntl64 fd: %d, cmd: %d, arg %ld, rc %ld\n", fd, cmd, arg, rc);

	return rc;
}

static asmlinkage long 
replay_fcntl64 (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	char* retparams = NULL;
	long rc = get_next_syscall (221, &retparams, NULL);
	if (retparams) {
		if (copy_to_user((void __user *)arg, retparams, sizeof(struct flock64))) return syscall_mismatch();
	}
	DPRINT ("replay fcntl64 fd: %d, cmd: %d, arg %ld, rc %ld\n", fd, cmd, arg, rc);
	return rc;
}

asmlinkage long 
shim_fcntl64 (unsigned int fd, unsigned int cmd, unsigned long arg)
SHIM_CALL(fcntl64, 221, fd, cmd, arg)

//asmlinkage long shim_gettid (void) SHIM_NOOP(gettid)
asmlinkage long shim_gettid (void) { return sys_gettid(); }

static asmlinkage ssize_t
record_readahead (int fd, loff_t offset, size_t count)
{
	long rc;

	new_syscall_enter (225, NULL);
	rc = sys_readahead(fd, offset, count);
	new_syscall_exit (225, rc, NULL);
	DPRINT ("Pid %d records readahead returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage ssize_t
replay_readahead (int fd, loff_t offset, size_t count)
{
	return get_next_syscall (225, NULL, NULL);
}

asmlinkage ssize_t shim_readahead (int fd, loff_t offset, size_t count)
SHIM_CALL(readahead, 225, fd, offset, count);

asmlinkage long
shim_setxattr (const char __user *path, const char __user *name,
	       const void __user *value, size_t size, int flags)
SHIM_NOOP(setxattr, path, name, value, size, flags)

asmlinkage long
shim_lsetxattr(const char __user *path, const char __user *name,
	       const void __user *value, size_t size, int flags)
SHIM_NOOP(lsetxattr, path, name, value, size, flags)

asmlinkage long
shim_fsetxattr (int fd, const char __user *name, const void __user *value,
		size_t size, int flags)
SHIM_NOOP(fsetxattr, fd, name, value, size, flags)

asmlinkage ssize_t
record_getxattr (const char __user *path, const char __user *name, void __user *value, size_t size)
{
	long rc;
	char *pretval = NULL;

	new_syscall_enter (229, NULL);

	rc = sys_getxattr (path, name, value, size);
	DPRINT ("Pid %d records getxattr returning %ld\n", current->pid, rc);

	if (rc > 0) {
		pretval = ARGSKMALLOC (rc, GFP_KERNEL);
		if (pretval == NULL) {
			printk ("record_getxattr: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user(pretval, value, rc)) {
			ARGSKFREE (pretval, rc);
			pretval = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (229, rc, pretval);
	return rc;
}

asmlinkage ssize_t
replay_getxattr (const char __user *path, const char __user *name, void __user *value, size_t size)
{
	struct getxattr_retvals *retparams = NULL;

	long rc = get_next_syscall (229, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (value, retparams, rc)) {
			printk("Pid %d replay_getxattr cannot copy to user\n", current->pid);
			return syscall_mismatch();
		}
	}
	return rc;
}

asmlinkage ssize_t
shim_getxattr (const char __user *path, const char __user *name, void __user *value, size_t size)
SHIM_CALL (getxattr, 229, path, name, value, size)

asmlinkage ssize_t
record_lgetxattr (const char __user *path, const char __user *name, void __user *value, size_t size)
{
	long rc;
	char *pretval = NULL;

	new_syscall_enter (230, NULL);

	rc = sys_lgetxattr (path, name, value, size);
	DPRINT ("Pid %d records lgetxattr returning %ld\n", current->pid, rc);

	if (rc > 0) {
		pretval = ARGSKMALLOC (rc, GFP_KERNEL);
		if (pretval == NULL) {
			printk ("record_lgetxattr: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user(pretval, value, rc)) {
			ARGSKFREE (pretval, rc);
			pretval = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (230, rc, pretval);
	return rc;
}

asmlinkage ssize_t
replay_lgetxattr (const char __user *path, const char __user *name, void __user *value, size_t size)
{
	struct getxattr_retvals *retparams = NULL;

	long rc = get_next_syscall (230, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (value, retparams, rc)) {
			printk("Pid %d replay_lgetxattr cannot copy to user\n", current->pid);
			return syscall_mismatch();
		}
	}
	return rc;
}

asmlinkage ssize_t
shim_lgetxattr (const char __user *path, const char __user *name, void __user *value, size_t size)
SHIM_CALL (lgetxattr, 230, path, name, value, size)

asmlinkage ssize_t
shim_fgetxattr (int fd, const char __user *name, void __user *value, 
		size_t size)
SHIM_NOOP(fgetxattr, fd, name, value, size)

asmlinkage ssize_t
shim_listxattr (const char __user *path, char __user *list, size_t size)
SHIM_NOOP(listxattr, path, list, size)

asmlinkage ssize_t
shim_llistxattr (const char __user *path, char __user *list, size_t size)
SHIM_NOOP(llistxattr, path, list, size)

asmlinkage ssize_t
shim_flistxattr (int fd, char __user *list, size_t size)
SHIM_NOOP(flistxattr, fd, list, size)

asmlinkage long 
shim_removexattr (const char __user *path, const char __user *name)
SHIM_NOOP(removexattr, path, name)

asmlinkage long
shim_lremovexattr (const char __user *path, const char __user *name)
SHIM_NOOP(lremovexattr, path, name)

asmlinkage long
shim_fremovexattr (int fd, const char __user *name)
SHIM_NOOP(fremovexattr, fd, name)

asmlinkage long shim_tkill (int pid, int sig) SHIM_NOOP(tkill, pid, sig)

static asmlinkage ssize_t 
record_sendfile64 (int out_fd, int in_fd, loff_t __user *offset, size_t count)
{
	long rc;
	struct sendfile64_retvals* pretvals = NULL;

	new_syscall_enter (239, NULL);

	rc = sys_sendfile64 (out_fd, in_fd, offset, count);
	DPRINT ("Pid %d records sendfile64 returning %ld\n", current->pid, rc);

	if (rc > 0) {
		pretvals = ARGSKMALLOC(sizeof(struct sendfile64_retvals), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_sendfile64: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (&pretvals->offset, offset, sizeof(loff_t))) {
			ARGSKFREE (pretvals, sizeof(struct sendfile64_retvals));
			pretvals = NULL;
			rc = -EFAULT;
		}
		atomic_set(&pretvals->refcnt,1);
	}

	new_syscall_exit (239, rc, pretvals);

	return rc;
}

static asmlinkage long 
replay_sendfile64 (int out_fd, int in_fd, loff_t __user *offset, size_t count)
{
	loff_t* retparams = NULL;
	long rc = get_next_syscall (239, (char **) &retparams, NULL);
	if (rc > 0) {
		struct sendfile64_retvals *retvals = (struct sendfile64_retvals *) retparams;
		if (retvals == NULL) printk ("[DIFF] replay_sendfile64: no return parameters\n");
		if (copy_to_user (offset, &retvals->offset, sizeof(loff_t))) printk ("Pid %d replay_sendfile64 cannot copy to user\n", current->pid);
	}
	return rc;
}

asmlinkage ssize_t 
shim_sendfile64 (int out_fd, int in_fd, loff_t __user *offset, size_t count)
SHIM_CALL(sendfile64, 239, out_fd, in_fd, offset, count)

static asmlinkage long 
record_futex (u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
	long rc;

	new_syscall_enter (240, NULL);
	rc = sys_futex (uaddr, op, val, utime, uaddr2, val3);
	new_syscall_exit (240, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_futex (u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
	struct pt_regs* pregs;
	long rc = get_next_syscall (240, NULL, NULL);
	pregs = get_pt_regs (NULL);
	// Really should not get here because it means we are missing synchronizations at user level
	printk ("Pid %d in replay futex uaddr=%p, op=%d, val=%d, ip=%lx, sp=%lx, bp=%lx\n", current->pid, uaddr, op, val, pregs->ip, pregs->sp, pregs->bp);
	return rc;
}

asmlinkage long 
shim_futex (u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
SHIM_CALL (futex, 240, uaddr, op, val, utime, uaddr2, val3)

asmlinkage long 
shim_sched_setaffinity (pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
SHIM_NOOP(sched_setaffinity, pid, len, user_mask_ptr)

static asmlinkage long 
record_sched_getaffinity (pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	long rc;
	cpumask_t* pretval = NULL;

	new_syscall_enter (242, NULL);

	rc = sys_sched_getaffinity (pid, len, user_mask_ptr);
	MPRINT ("Pid %d records sched_getaffinity returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(cpumask_t), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_sched_getaffinity: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, user_mask_ptr, sizeof(cpumask_t))) { 
			ARGSKFREE (pretval, sizeof(cpumask_t));
			pretval = NULL;
			rc = -EFAULT;
		}
	}
	new_syscall_exit (242, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_sched_getaffinity (pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	cpumask_t* retparams = NULL;
	long rc = get_next_syscall (242, (char **) &retparams, NULL);

	MPRINT ("Pid %d replays sched_getaffinity returning %ld retparams %p\n", current->pid, rc, retparams);
	if (retparams) {
		if (copy_to_user (user_mask_ptr, retparams, sizeof(cpumask_t))) printk ("replay_sched_getaffinity: pid %d cannot copy to user\n", current->pid);
	}

	return rc;
}

asmlinkage long shim_sched_getaffinity (pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr) SHIM_CALL(sched_getaffinity, 77, pid, len, user_mask_ptr)

// Pin virtualizes this system call but we need to replay the prior behavior.  So, we bypass Pin by using a different syscall number
asmlinkage long sys_fake_getaffinity (pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	return replay_sched_getaffinity (pid, len, user_mask_ptr);
}

/* In arch/x86/um/tls_32.c (no prototype) */
asmlinkage int sys_set_thread_area(struct user_desc __user *u_info);

struct set_thread_area_retvals {
	struct user_desc u_info;
};

asmlinkage int
record_set_thread_area (struct user_desc __user *u_info)
{
	int rc;
	struct set_thread_area_retvals* pretvals = NULL;
	
	new_syscall_enter (243, NULL);
	rc = sys_set_thread_area (u_info);
	if (rc == 0) {
		pretvals = ARGSKMALLOC (sizeof(struct set_thread_area_retvals), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_set_thread_area: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (&pretvals->u_info, u_info, sizeof(struct user_desc))) {
			ARGSKFREE (pretvals, sizeof(struct user_desc));
			pretvals = NULL;
			rc = -EFAULT;
		}
	}
	new_syscall_exit (243, rc, pretvals);

	return rc;
}

asmlinkage int
replay_set_thread_area (struct user_desc __user *u_info)
{
	int rc, retval;
	char* retparams = NULL;
	rc = get_next_syscall (243, (char **) &retparams, NULL);

	// XXX don't copy these back to user, just do a comparison and warn if they're different
	if (rc == 0) {
		struct set_thread_area_retvals* retvals = (struct set_thread_area_retvals *) retparams;
		if (retvals == NULL) printk ("[DIFF] replay_set_thread_area: no return parameters\n");
	}

	retval = sys_set_thread_area (u_info);

	return rc;
}

asmlinkage int 
shim_set_thread_area (struct user_desc __user *u_info)
SHIM_CALL(set_thread_area,243,u_info)

/* In tls.c (no prototype) */
asmlinkage int sys_get_thread_area(struct user_desc __user *u_info);

asmlinkage int
record_get_thread_area (struct user_desc __user *u_info)
{
	int rc;

	new_syscall_enter (244, NULL);
	rc = sys_get_thread_area (u_info);
	new_syscall_exit (244, rc, NULL);
	return rc;
}

asmlinkage int
replay_get_thread_area (struct user_desc __user *u_info)
{
	int rc;
	int retval;
	rc = get_next_syscall (244, NULL, NULL);

	// actually do the get_thread_area
	retval = sys_get_thread_area (u_info);
	if (rc != retval) {
		printk ("Replay get_thread_area returns different value %d than %d\n", retval, rc);
		return syscall_mismatch();
	}

	return rc;
}

asmlinkage int 
shim_get_thread_area (struct user_desc __user *u_info)
SHIM_CALL(get_thread_area,244,u_info)

asmlinkage long 
shim_io_setup(unsigned nr_events, aio_context_t __user *ctxp)
SHIM_NOOP(io_setup, nr_events, ctxp)

asmlinkage long shim_io_destroy(aio_context_t ctx) SHIM_NOOP(io_destroy, ctx)

asmlinkage long 
shim_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout)
SHIM_NOOP(io_getevents, ctx_id, min_nr, nr, events, timeout)

asmlinkage long 
shim_io_submit (aio_context_t ctx_id, long nr, struct iocb __user * __user *iocbpp)
SHIM_NOOP(io_submit, ctx_id, nr, iocbpp)

asmlinkage long 
shim_io_cancel (aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result)
SHIM_NOOP(io_cancel, ctx_id, iocb, result)

asmlinkage long 
shim_fadvise64 (int fd, loff_t offset, size_t len, int advice)
SHIM_NOOP(fadvise64, fd, offset, len, advice)

static asmlinkage void 
record_exit_group (int error_code)
{
	new_syscall_enter (252, NULL);
	new_syscall_exit (252, 0, NULL);

	MPRINT ("Pid %d recording exit group with code %d\n", current->pid, error_code);
	sys_exit_group (error_code);
}

static asmlinkage void
replay_exit_group (int error_code)
{
	struct replay_group* prg;
	struct task_struct* t;

	get_next_syscall (252, NULL, NULL);
	MPRINT ("Pid %d replaying exit group with code %d\n", current->pid, error_code);

	/* We need to force any other replay threads that are running and part of this process to exit */
	prg = current->replay_thrd->rp_group;
	rg_lock(prg->rg_rec_group);
	for (t = next_thread(current); t != current; t = next_thread(t)) {
		MPRINT ("exit_group considering thread %d\n", t->pid);
		if (t->replay_thrd) {
			t->replay_thrd->rp_replay_exit = 1;
			MPRINT ("told it to exit\n");
		} else {
			printk ("cannot tell thread %d to exit because it is not a replay thread???\n", t->pid);
		}
	}
	rg_unlock(prg->rg_rec_group);
	MPRINT ("replay_exit_group set all threads to exit\n");
	sys_exit_group (error_code); /* Signals should wake up any wakers */
	printk ("sys_exit_group returned?!?\n");
}

asmlinkage void
shim_exit_group (int error_code) 
{ 
	if (current->record_thrd) record_exit_group (error_code);
	if (current->replay_thrd && test_app_syscall(252)) replay_exit_group(error_code);
	sys_exit_group (error_code);					
}

asmlinkage long 
shim_lookup_dcookie (u64 cookie64, char __user * buf, size_t len)
SHIM_NOOP(lookup_dcookie, cookie64, buf, len)

static asmlinkage long 
record_epoll_create (int size)
{
	long rc;

	new_syscall_enter (254, NULL);

	rc = sys_epoll_create (size);
	DPRINT ("Pid %d records epoll_create(%d) returning %ld\n",
		current->pid, size, rc);

	new_syscall_exit (254, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_epoll_create (int size)
{
	return get_next_syscall (254, NULL, NULL);
}

asmlinkage long shim_epoll_create (int size) 
SHIM_CALL (epoll_create, 254, size)

static asmlinkage long 
record_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event)
{
	long rc;

	new_syscall_enter (255, NULL);

	rc = sys_epoll_ctl (epfd, op, fd, event);
	DPRINT ("Pid %d records epoll_ctl returning %ld\n", current->pid, rc);
	new_syscall_exit (255, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event)
{
	return get_next_syscall (255, NULL, NULL);
}

asmlinkage long 
shim_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event)
SHIM_CALL (epoll_ctl, 255, epfd, op, fd, event)

static asmlinkage long 
record_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout)
{
	long rc;
	struct epoll_wait_retvals* pretvals = NULL;

	new_syscall_enter (256, NULL);

	rc = sys_epoll_wait (epfd, events, maxevents, timeout);
	
	// events is a continuous list of epoll_events of size rc
	// need to copy every single one of these to pretvals

	if (rc > 0) {
		pretvals = ARGSKMALLOC (sizeof(struct epoll_wait_retvals) + ((rc-1) * (sizeof(struct epoll_event))), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_epoll_wait: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (&pretvals->event, events, rc * sizeof(struct epoll_event))) {
			ARGSKFREE (pretvals, sizeof(struct epoll_wait_retvals) + ((rc-1) * (sizeof(struct epoll_event))));
			pretvals = NULL;
			rc = -EFAULT;
		}
		atomic_set(&pretvals->refcnt,1);
	}

	DPRINT ("Pid %d records epoll_wait returning %ld\n", current->pid, rc);
	DPRINT ("record epoll_wait rc: %ld, epfd: %d, events: %p, maxevents %d, timeout %d\n", rc, epfd, events, maxevents, timeout);

	new_syscall_exit (256, rc, pretvals);

	return rc;
}

static asmlinkage long 
replay_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout)
{
	long rc;
	char* retparams = NULL;
	rc = get_next_syscall (256, &retparams, NULL);
	if (rc > 0) {
		struct epoll_wait_retvals *retvals = (struct epoll_wait_retvals*) retparams;	
		if (retvals == NULL) printk ("[DIFF] replay_epoll_wait: no return parameters\n");
		if (copy_to_user (events, &retvals->event, rc * sizeof(struct epoll_event)))
			printk ("Pid %d cannot copy epoll_wait_retvals to user\n", current->pid);
	}

	DPRINT ("replay epoll_wait rc: %ld epfd: %d, events: %p, maxevents %d, timeout %d\n", rc, epfd, events, maxevents, timeout);
	return rc;
}

asmlinkage long 
shim_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout)
SHIM_CALL (epoll_wait, 256, epfd, events, maxevents, timeout)

asmlinkage long 
shim_remap_file_pages (unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)
SHIM_NOOP(remap_file_pages, start, size, prot, pgoff, flags)

static asmlinkage long 
record_set_tid_address (int __user* tidptr)
{
	long rc;
	new_syscall_enter (258, NULL);
	rc = sys_set_tid_address(tidptr);
	new_syscall_exit (258, rc, NULL);
	MPRINT ("Pid %d records set_tid_address returning %ld\n", current->pid, rc);
	return rc;
}

static asmlinkage long 
replay_set_tid_address (int __user* tidptr)
{
	long rc;
	sys_set_tid_address(tidptr);
	rc = get_next_syscall (258, NULL, NULL);
	MPRINT ("Replay Pid %d set_tid_address returning %ld\n", current->pid, rc);
	return rc;
}

asmlinkage long shim_set_tid_address (int __user* tidptr) 
SHIM_CALL(set_tid_address, 258, tidptr);

asmlinkage long
shim_timer_create (const clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user * created_timer_id)
SHIM_NOOP(timer_create, which_clock, timer_event_spec, created_timer_id)

asmlinkage long
shim_timer_settime (timer_t timer_id, int flags, const struct itimerspec __user *new_setting, struct itimerspec __user *old_setting)
SHIM_NOOP(timer_settime, timer_id, flags, new_setting, old_setting)

asmlinkage long
shim_timer_gettime (timer_t timer_id, struct itimerspec __user *setting)
SHIM_NOOP(timer_gettime, timer_id, setting)

asmlinkage long
shim_timer_getoverrun (timer_t timer_id) SHIM_NOOP(timer_getoverrun, timer_id)

asmlinkage long 
shim_timer_delete (timer_t timer_id) SHIM_NOOP(timer_delete, timer_id)

asmlinkage long 
shim_clock_settime (const clockid_t which_clock, const struct timespec __user *tp)
SHIM_NOOP (clock_settime, which_clock, tp)

static asmlinkage long 
record_clock_gettime (const clockid_t which_clock, struct timespec __user *tp)
{
	long rc;
	struct timespec* pretvals = NULL;

	new_syscall_enter (265, NULL);

	rc = sys_clock_gettime (which_clock, tp);
	DPRINT ("Pid %d records clock_gettime returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretvals = ARGSKMALLOC(sizeof(struct timespec), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_clock_gettime: can't alloc buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretvals, tp, sizeof(struct timespec))) {
			printk ("Pid %d cannot copy tp from user\n", current->pid);
			ARGSKFREE (pretvals, sizeof(struct timespec));
			return -EFAULT;
		}
	}

	new_syscall_exit (265, rc, pretvals);

	return rc;
}

static asmlinkage long 
replay_clock_gettime (const clockid_t which_clock, struct timespec __user *tp)
{
	struct timespec* retparams = NULL;
	long rc = get_next_syscall (265, (char **) &retparams, NULL);
	DPRINT ("Pid %d replays clock_gettime returning %ld\n", current->pid, rc);
	if (rc == 0) {
		if (retparams) {
			if (copy_to_user (tp, retparams, sizeof(struct timespec))) printk ("Pid %d cannot copy tp to user\n", current->pid);
		} else {
			printk ("clock_gettime: no timespec to copy\n");
		}
	}
	return rc;
}

asmlinkage long
shim_clock_gettime (const clockid_t which_clock, struct timespec __user *tp)
SHIM_CALL(clock_gettime, 265, which_clock, tp);

static asmlinkage long 
record_clock_getres (const clockid_t which_clock, struct timespec __user *tp)
{
	long rc;
	struct timespec* pretvals = NULL;

	new_syscall_enter (266, NULL);

	rc = sys_clock_getres (which_clock, tp);
	DPRINT ("Pid %d records clock_getres returning %ld\n", current->pid, rc);
	if (rc == 0) {
		pretvals = ARGSKMALLOC(sizeof(struct timespec), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_clock_getres: can't alloc buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretvals, tp, sizeof(struct timespec))) {
			printk ("Pid %d cannot copy tp from user\n", current->pid);
			ARGSKFREE (pretvals, sizeof(struct timespec));
			return -EFAULT;
		}
	}

	new_syscall_exit (265, rc, pretvals);

	return rc;
}

static asmlinkage long 
replay_clock_getres (const clockid_t which_clock, struct timespec __user *tp)
{
	struct timespec* retparams = NULL;
	long rc = get_next_syscall (266, (char **) &retparams, NULL);
	DPRINT ("Pid %d replays clock_getres returning %ld\n", current->pid, rc);
	if (rc == 0) {
		if (retparams) {
			if (copy_to_user (tp, retparams, sizeof(struct timespec))) printk ("Pid %d cannot copy tp to user\n", current->pid);
		} else {
			printk ("replay_clock_getres: no timespec to copy\n");
		}
	}
	return rc;
}

asmlinkage long shim_clock_getres (const clockid_t which_clock, struct timespec __user *tp) SHIM_CALL(clock_getres, 266, which_clock, tp);

asmlinkage long
shim_clock_nanosleep (const clockid_t which_clock, int flags, const struct timespec __user *rqtp, struct timespec __user *rmtp)
SHIM_NOOP (clock_nanosleep, which_clock, flags, rqtp, rmtp)

struct statfs64; // no prototype

asmlinkage long
record_statfs64 (const char __user *path, size_t sz, struct statfs64 __user *buf)
{
	long rc;
	struct statfs64 *pretval = NULL;

	new_syscall_enter (268, NULL);

	rc = sys_statfs64 (path, sz, buf);
	DPRINT ("Pid %d records statfs64 returning %ld\n", current->pid, rc);

	if (rc == 0) {
		pretval = ARGSKMALLOC (sizeof(struct statfs64), GFP_KERNEL);
		if (pretval == NULL) {
			printk ("record_statfs64: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, buf, sizeof(struct statfs))) {
			ARGSKFREE (pretval, sizeof(struct statfs64));
			pretval = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (268, rc, pretval);
	return rc;
}

asmlinkage long
replay_statfs64 (const char __user *path, size_t sz, struct statfs64 __user *buf)
{
	struct statfs64 *retparams = NULL;

	long rc = get_next_syscall (268, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (buf, retparams, sizeof(struct statfs))) {
			printk ("Pid %d replay_statfs64 cannot copy to user\n", current->pid);
			return syscall_mismatch();
		}
	}
	return rc;
}

asmlinkage long 
shim_statfs64 (const char __user *path, size_t sz, struct statfs64 __user *buf)
SHIM_CALL(statfs64, 268, path, sz, buf);

asmlinkage long 
shim_fstatfs64 (unsigned int fd, size_t sz, struct statfs64 __user *buf)
SHIM_NOOP (fstatfs64, fd, sz, buf)

static asmlinkage long
record_tgkill (int tgid, int pid, int sig)
{
	long rc;

	new_syscall_enter (270, NULL);

	rc = sys_tgkill (tgid, pid, sig);
	DPRINT ("Pid %d records tgkill returning %ld\n", current->pid, rc);

	new_syscall_exit (270, rc, NULL);

	return rc;
}

static asmlinkage long
replay_tgkill (int tgid, int pid, int sig)
{
	return get_next_syscall (270, NULL, NULL);
}

asmlinkage long shim_tgkill(int tgid, int pid, int sig) SHIM_CALL (tgkill, 270, tgid, pid, sig);

static asmlinkage long 
record_utimes (char __user *filename, struct timeval __user *utimes)
{
	long rc;

	new_syscall_enter (271, NULL);
	rc = sys_utimes (filename, utimes);
	DPRINT ("Pid %d records utimes returning %ld\n", current->pid, rc);
	new_syscall_exit (271, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_utimes (char __user *filename, struct timeval __user *utimes)
{
	return get_next_syscall (271, NULL, NULL);
}

asmlinkage long shim_utimes (char __user *filename, struct timeval __user *utimes) SHIM_CALL (utimes, 271, filename, utimes);

static asmlinkage long
record_fadvise64_64 (int fd, loff_t offset, loff_t len, int advice)
{
	long rc;

	new_syscall_enter (272, NULL);
	rc = sys_fadvise64_64 (fd, offset, len, advice);
	DPRINT ("Pid %d records fadvise64_64 returning %ld\n", current->pid, rc);

	new_syscall_exit (272, rc, NULL);
	return rc;
}

static asmlinkage long
replay_fadvise64_64 (int fd, loff_t offset, loff_t len, int advice)
{
	return get_next_syscall (272, NULL, NULL);
}

asmlinkage long 
shim_fadvise64_64(int fd, loff_t offset, loff_t len, int advice)
SHIM_CALL (fadvise64_64, 272, fd, offset, len, advice)

asmlinkage long 
shim_mbind (unsigned long start, unsigned long len, unsigned long mode, unsigned long __user *nmask, unsigned long maxnode, unsigned flags)
SHIM_NOOP(mbind, start, len, mode, nmask, maxnode, flags)

asmlinkage long 
shim_get_mempolicy (int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags)
SHIM_NOOP(get_mempolicy, policy, nmask, maxnode, addr, flags)

asmlinkage long 
shim_set_mempolicy (int mode, unsigned long __user *nmask, unsigned long maxnode)
SHIM_NOOP(set_mempolicy, mode, nmask, maxnode)

asmlinkage long 
shim_mq_open (const char __user *u_name, int oflag, mode_t mode, struct mq_attr __user *u_attr)
SHIM_NOOP(mq_open, u_name, oflag, mode, u_attr)

asmlinkage long 
shim_mq_unlink (const char __user *u_name) SHIM_NOOP(mq_unlink, u_name)

asmlinkage long 
shim_mq_timedsend (mqd_t mqdes, const char __user *u_msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *u_abs_timeout)
SHIM_NOOP(mq_timedsend, mqdes, u_msg_ptr, msg_len, msg_prio, u_abs_timeout)

asmlinkage ssize_t 
shim_mq_timedreceive (mqd_t mqdes, char __user *u_msg_ptr, size_t msg_len, unsigned int __user *u_msg_prio, const struct timespec __user *u_abs_timeout)
SHIM_NOOP(mq_timedreceive, mqdes, u_msg_ptr, msg_len, u_msg_prio, u_abs_timeout)

asmlinkage long 
shim_mq_notify (mqd_t mqdes, const struct sigevent __user *u_notification)
SHIM_NOOP(mq_notify, mqdes, u_notification)

asmlinkage long 
shim_mq_getsetattr (mqd_t mqdes, const struct mq_attr __user *u_mqstat, struct mq_attr __user *u_omqstat)
SHIM_NOOP(mq_getsetattr, mqdes, u_mqstat, u_omqstat)

asmlinkage long 
shim_kexec_load (unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags)
SHIM_NOOP(kexec_load, entry, nr_segments, segments, flags)

asmlinkage long 
shim_waitid (int which, pid_t upid, struct siginfo __user *infop, int options, struct rusage __user *ru)
SHIM_NOOP(waitid, which, upid, infop, options, ru)

asmlinkage long 
shim_add_key (const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t ringid)
SHIM_NOOP(add_key, _type, _description, _payload, plen, ringid)

asmlinkage long 
shim_request_key (const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid)
SHIM_NOOP(request_key, _type, _description, _callout_info, destringid)

asmlinkage long 
shim_keyctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
SHIM_NOOP(keyctl, option, arg2, arg3, arg4, arg5)

asmlinkage long 
shim_ioprio_set (int which, int who, int ioprio) 
SHIM_NOOP(ioprio_set, which, who, ioprio)

asmlinkage long 
shim_ioprio_get (int which, int who) SHIM_NOOP(ioprio_get, which, who)

static asmlinkage long 
record_inotify_init (void)
{
	long rc;

	new_syscall_enter (291, NULL);
	rc = sys_inotify_init();
	new_syscall_exit (291, rc, NULL);
	DPRINT ("Pid %d records inotify_init returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_inotify_init (void)
{
	return get_next_syscall (291, NULL, NULL);
}

asmlinkage long shim_inotify_init (void) SHIM_CALL(inotify_init, 291);

static asmlinkage long 
record_inotify_add_watch (int fd, const char __user *path, u32 mask)
{
	long rc;

	new_syscall_enter (292, NULL);
	rc = sys_inotify_add_watch(fd, path, mask);
	new_syscall_exit (292, rc, NULL);
	DPRINT ("Pid %d records inotify_add_watch returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_inotify_add_watch (int fd, const char __user *path, u32 mask)
{
	return get_next_syscall (292, NULL, NULL);
}

asmlinkage long shim_inotify_add_watch (int fd, const char __user *path, u32 mask) SHIM_CALL(inotify_add_watch, 292, fd, path, mask);

asmlinkage long 
shim_inotify_rm_watch (int fd, u32 wd) SHIM_NOOP(inotify_rm_watch, fd, wd)

asmlinkage long 
shim_migrate_pages (pid_t pid, unsigned long maxnode, const unsigned long __user *old_nodes, const unsigned long __user *new_nodes)
SHIM_NOOP(migrate_pages, pid, maxnode, old_nodes, new_nodes)

asmlinkage long
record_openat(int dfd, const char __user *filename, int flags, int mode)
{
	long rc;

	new_syscall_enter(295, NULL);
	rc = sys_openat(dfd, filename, flags, mode);
	DPRINT("Pid %d records openat(%d, %s, %x, 0%o) returning %ld\n", current->pid, dfd, filename, flags, mode, rc);

	new_syscall_exit(295, rc, NULL);

	return rc;
}

asmlinkage long
replay_openat(int dfd, const char __user *filename, int flags, int mode)
{
	return get_next_syscall (295, NULL, NULL);
}		

asmlinkage long 
shim_openat (int dfd, const char __user *filename, int flags, int mode)
SHIM_CALL(openat, 295, dfd, filename, flags, mode);

asmlinkage long 
shim_mkdirat (int dfd, const char __user *pathname, int mode)
SHIM_NOOP(mkdirat, dfd, pathname, mode)

asmlinkage long 
shim_mknodat (int dfd, const char __user *filename, int mode, unsigned dev)
SHIM_NOOP(mknodat, dfd, filename, mode, dev)

asmlinkage long 
shim_fchownat (int dfd, const char __user *filename, uid_t user, gid_t group, int flag)
SHIM_NOOP(fchownat, dfd, filename, user, group, flag)

asmlinkage long 
shim_futimesat (int dfd, char __user *filename, struct timeval __user *utimes)
SHIM_NOOP(futimesat, dfd, filename, utimes);

static asmlinkage long 
record_fstatat64 (int dfd, char __user *filename,
		  struct stat64 __user *statbuf, int flag)
{
	long rc;
	struct stat64* pretval = NULL;

	new_syscall_enter (300, NULL);

	rc = sys_fstatat64 (dfd, filename, statbuf, flag);
	DPRINT ("Pid %d records fstatat64 returning %ld\n", current->pid, rc);

	if (rc == 0) {
		pretval = ARGSKMALLOC(sizeof(struct stat64), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_stat64: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, statbuf, sizeof(struct stat64))) {
			ARGSKFREE (pretval, sizeof(struct stat64));
			return -EFAULT;
		}
	}
		
	new_syscall_exit (300, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_fstatat64 (int dfd, char __user *filename, struct stat64 __user *statbuf, int flag)
{
	struct stat* retparams = NULL;
	long rc = get_next_syscall (300, (char **) &retparams, NULL);
	if (retparams) {
		if (copy_to_user (statbuf, retparams, sizeof(struct stat64))) printk ("Pid %d cannot copy statbuf to user\n", current->pid);
	}
	return rc;
}

asmlinkage long 
shim_fstatat64 (int dfd, char __user *filename, struct stat64 __user *statbuf, int flag)
SHIM_CALL(fstatat64, 300, dfd, filename, statbuf, flag)

asmlinkage long 
shim_unlinkat (int dfd, const char __user *pathname, int flag)
SHIM_NOOP(unlinkat, dfd, pathname, flag)

asmlinkage long 
shim_renameat (int olddfd, const char __user *oldname, int newdfd, const char __user *newname)
SHIM_NOOP(renameat, olddfd, oldname, newdfd, newname)

asmlinkage long 
shim_linkat (int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags)
SHIM_NOOP(linkat, olddfd, oldname, newdfd, newname, flags)

asmlinkage long 
shim_symlinkat (const char __user *oldname, int newdfd, const char __user *newname)
SHIM_NOOP(symlinkat, oldname, newdfd, newname)

asmlinkage long 
shim_readlinkat (int dfd, const char __user *path, char __user *buf, int bufsiz)
SHIM_NOOP(readlinkat, dfd, path, buf, bufsiz)

asmlinkage long 
shim_fchmodat (int dfd, const char __user *filename, mode_t mode)
SHIM_NOOP(fchmodat, dfd, filename, mode)

asmlinkage long 
shim_faccessat (int dfd, const char __user *filename, int mode)
SHIM_NOOP(faccessat, dfd, filename, mode)

/* No prototype available */
asmlinkage long sys_pselect6(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig);

asmlinkage long 
shim_pselect6 (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig)
SHIM_NOOP(pselect6, n, inp, outp, exp, tsp, sig)

/* No prototype available */
asmlinkage long sys_ppoll(struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize);

asmlinkage long 
shim_ppoll (struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize)
SHIM_NOOP(ppoll, ufds, nfds, tsp, sigmask, sigsetsize)

asmlinkage long 
shim_unshare (unsigned long unshare_flags) SHIM_NOOP(unshare, unshare_flags)

static asmlinkage long 
record_set_robust_list (struct robust_list_head __user *head, size_t len)
{
	long rc;

	new_syscall_enter (311, NULL);

	DPRINT ("Pid %d records set_robust_list\n", current->pid);
	rc = sys_set_robust_list (head, len);

	new_syscall_exit (311, rc, NULL);

	return rc;
}

static asmlinkage long 
replay_set_robust_list (struct robust_list_head __user *head, size_t len)
{
	return get_next_syscall (311, NULL, NULL);
}

asmlinkage long
shim_set_robust_list (struct robust_list_head __user *head, size_t len)
SHIM_CALL(set_robust_list, 311, head, len)

asmlinkage long
shim_get_robust_list (int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr)
SHIM_NOOP(get_robust_list, pid, head_ptr, len_ptr)

asmlinkage long 
shim_splice (int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags)
SHIM_NOOP(splice, fd_in, off_in, fd_out, off_out, len, flags)

asmlinkage long 
shim_sync_file_range (int fd, loff_t offset, loff_t nbytes, unsigned int flags)
SHIM_NOOP(sync_file_range, fd, offset, nbytes, flags)

asmlinkage long 
shim_tee (int fdin, int fdout, size_t len, unsigned int flags)
SHIM_NOOP(tee, fdin, fdout, len, flags)

asmlinkage long 
shim_vmsplice (int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags)
SHIM_NOOP(vmsplice, fd, iov, nr_segs, flags)

asmlinkage long 
shim_move_pages (pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags)
SHIM_NOOP(move_pages, pid, nr_pages, pages, nodes, status, flags)

asmlinkage long 
shim_getcpu (unsigned __user *cpup, unsigned __user *nodep, struct getcpu_cache __user *unused)
SHIM_NOOP(getcpu, cpup, nodep, unused)

asmlinkage long 
shim_epoll_pwait (int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize)
SHIM_NOOP(epoll_pwait, epfd, events, maxevents, timeout, sigmask, sigsetsize)

asmlinkage long 
shim_utimensat (int dfd, char __user *filename, struct timespec __user *utimes, int flags)
SHIM_NOOP(utimensat, dfd, filename, utimes, flags)

asmlinkage long 
shim_signalfd (int ufd, sigset_t __user *user_mask, size_t sizemask)
SHIM_NOOP(signalfd, ufd, user_mask, sizemask)

asmlinkage long 
shim_timerfd_create (int clockid, int flags)
SHIM_NOOP(timerfd_create, clockid, flags)

static asmlinkage long 
record_eventfd (unsigned int count)
{
	long rc;

	new_syscall_enter (323, NULL);
	rc = sys_eventfd (count);
	new_syscall_exit (323, rc, NULL);
	DPRINT ("Pid %d records eventfd returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_eventfd (unsigned int count)
{
	return get_next_syscall (323, NULL, NULL);
}

asmlinkage long shim_eventfd (unsigned int count) SHIM_CALL (eventfd, 323, count)

asmlinkage long 
shim_fallocate (int fd, int mode, loff_t offset, loff_t len)
SHIM_NOOP(fallocate, fd, mode, offset, len)

asmlinkage long 
shim_timerfd_settime (int ufd, int flags, const struct itimerspec __user *utmr, struct itimerspec __user *otmr)
SHIM_NOOP(timerfd_settime, ufd, flags, utmr, otmr)

asmlinkage long 
shim_timerfd_gettime (int ufd, struct itimerspec __user *otmr)
SHIM_NOOP(timerfd_gettime, ufd, otmr)

asmlinkage long 
shim_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags)
SHIM_NOOP(signalfd4, ufd, user_mask, sizemask, flags)

static asmlinkage long 
record_eventfd2 (unsigned int count, int flags)
{
	long rc;

	new_syscall_enter (328, NULL);
	rc = sys_eventfd2 (count, flags);
	new_syscall_exit (328, rc, NULL);
	DPRINT ("Pid %d records eventfd2 returning %ld\n", current->pid, rc);

	return rc;
}

static asmlinkage long 
replay_eventfd2 (unsigned int count, int flags)
{
	return get_next_syscall (328, NULL, NULL);
}

asmlinkage long shim_eventfd2(unsigned int count, int flags) SHIM_CALL(eventfd2, 328, count, flags)

asmlinkage long 
shim_epoll_create1(int flags)
SHIM_NOOP(epoll_create, flags)

asmlinkage long 
shim_dup3(unsigned int oldfd, unsigned int newfd, int flags)
SHIM_NOOP(dup3, oldfd, newfd, flags)

asmlinkage long 
shim_pipe2(int __user *fildes, int flags)
SHIM_NOOP(pipe2, fildes, flags)

asmlinkage long 
shim_inotify_init1(int flags)
SHIM_NOOP(inotify_init1, flags)

asmlinkage long 
shim_preadv(unsigned long fd, const struct iovec __user *vec,
	   unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
SHIM_NOOP(preadv, fd, vec, vlen, pos_l, pos_h)

asmlinkage long 
shim_pwritev(unsigned long fd, const struct iovec __user *vec,
	    unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
SHIM_NOOP(pwritev, fd, vec, vlen, pos_l, pos_h)

asmlinkage long 
shim_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig, siginfo_t __user *uinfo)
SHIM_NOOP(rt_tgsigqueueinfo, tgid, pid, sig, uinfo)

asmlinkage long 
shim_perf_event_open(struct perf_event_attr __user *attr_uptr,
		    pid_t pid, int cpu, int group_fd, unsigned long flags)
SHIM_NOOP(perf_event_open, attr_uptr, pid, cpu, group_fd, flags)

asmlinkage long 
shim_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags,
	     struct timespec __user *timeout)
SHIM_NOOP(recvmmsg, fd, msg, vlen, flags, timeout)

asmlinkage long 
shim_fanotify_init(unsigned int flags, unsigned int event_f_flags)
SHIM_NOOP(fanotify_init, flags, event_f_flags)

asmlinkage long 
shim_fanotify_mark(int fanotify_fd, unsigned int flags, u64 mask, int fd,
		  const char  __user *pathname)
SHIM_NOOP(fanotify_mark, fanotify_fd, flags, mask, fd, pathname)

static asmlinkage long 
record_prlimit64 (pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim)
{
	long rc;
	struct rlimit64 *pretval = NULL;

	new_syscall_enter (340, NULL);

	rc = sys_prlimit64 (pid, resource, new_rlim, old_rlim);
	DPRINT ("Pid %d records prlimit64 pid %d resource %u new_rlim %p old_rlim %p returning %ld\n", current->pid, pid, resource, new_rlim, old_rlim, rc);
	if (rc == 0 && old_rlim) {
		pretval = ARGSKMALLOC(sizeof(struct rlimit64), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_prlimit: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, old_rlim, sizeof(struct rlimit64))) { 
			printk("record_prlimit: can't copy old value from user\n");
			ARGSKFREE (pretval, sizeof(struct rlimit64));
			pretval = NULL;
			rc = -EFAULT;
		}
	}
		
	new_syscall_exit (340, rc, pretval);

	return rc;
}

static asmlinkage long 
replay_prlimit64 (pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim)
{
	struct rlimit64 *retparams = NULL;
	long rc_orig, rc;

	rc_orig = get_next_syscall (340, (char **) &retparams, NULL);
	if (new_rlim) {
		rc = sys_prlimit64 (pid, resource, new_rlim, old_rlim);
		if (rc != rc_orig) printk ("Pid %d: prlimit64 pid %d resource %u changed its return in replay, rec %ld rep %ld\n", current->pid, pid, resource, rc_orig, rc);
	}
	if (retparams) {
		if (copy_to_user (old_rlim, retparams, sizeof(struct rlimit64))) printk ("Pid %d replay_prlimit cannot copy to user\n", current->pid);
	}
	DPRINT ("replay_prlimit64 pid %d resource %u returns %ld\n", pid, resource, rc_orig);

	return rc_orig;
}

asmlinkage long shim_prlimit64 (pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim) SHIM_CALL(prlimit64, 340, pid, resource, new_rlim, old_rlim)

asmlinkage long 
shim_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle,
		       int __user *mnt_id, int flag)
SHIM_NOOP(name_to_handle_at, dfd, name, handle, mnt_id, flag)

asmlinkage long 
shim_open_by_handle_at(int mountdirfd, struct file_handle __user *handle, int flags)
SHIM_NOOP(open_by_handle_at, mountdirfd, handle, flags)

asmlinkage long 
shim_clock_adjtime(clockid_t which_clock, struct timex __user *tx)
SHIM_NOOP(clock_adjtime, which_clock, tx)

asmlinkage long 
shim_syncfs(int fd)
SHIM_NOOP(syncfs, fd)

asmlinkage long 
shim_sendmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags)
SHIM_NOOP(sendmmsg, fd, msg, vlen, flags)

asmlinkage long 
shim_setns(int fd, int nstype)
SHIM_NOOP(setns, fd, nstype)

asmlinkage long 
shim_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt,
		      const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
SHIM_NOOP(process_vm_readv, pid, lvec, liovcnt, rvec, riovcnt, flags)

asmlinkage long 
shim_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt,
		       const struct iovec __user *rvec, unsigned long riovcnt, 
		       unsigned long flags)
SHIM_NOOP(process_vm_writev, pid, lvec, liovcnt, rvec, riovcnt, flags)

asmlinkage long 
shim_kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2)
SHIM_NOOP(kcmp, pid1, pid2, type, idx1, idx2)

struct file* init_log_write (struct record_thread* prect, int logid, loff_t* ppos, int* pfd)
{
	char filename[MAX_LOGDIR_STRLEN+20];
	struct stat64 st;
	mm_segment_t old_fs;
	int rc;

	sprintf (filename, "%s/klog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	if (prect->rp_group->rg_log_opened[logid]) {
		rc = sys_stat64(filename, &st);
		if (rc < 0) {
			printk ("Stat of file %s failed\n", filename);
			return NULL;
		}
		*ppos = st.st_size;
		*pfd = sys_open(filename, O_WRONLY|O_APPEND, 0644);
		MPRINT ("Reopened log file %s, pos = %ld\n", filename, (long) *ppos);
	} else {
		*pfd = sys_open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		MPRINT ("Opened log file %s\n", filename);
		*ppos = 0;
		prect->rp_group->rg_log_opened[logid] = 1;
	}
	set_fs(old_fs);
	if (*pfd < 0) {
		printk ("Cannot open log file %s, rc = %d\n", filename, *pfd);
		return NULL;
	}

	return (fget(*pfd));
}

void term_log_write (struct file* file, int fd)
{
	int rc;

	fput(file);

	rc = sys_close (fd);
	if (rc < 0) printk ("term_log_write: file close failed with rc %d\n", rc);
}

void write_begin_log (struct file* file, loff_t* ppos, struct record_thread* prect)
{
	int copyed;
	unsigned long long hpc1 = 0;	
	unsigned long long hpc2 = 0;	
	struct timeval tv1;
	struct timeval tv2;

#ifdef USE_HPC
	hpc1 = rdtsc(); 
	do_gettimeofday(&tv1);
	hpc2 = rdtsc();
	do_gettimeofday(&tv2);
#endif

	copyed = vfs_write(file, (char *) &hpc1, sizeof(unsigned long long), ppos);
	if (copyed != sizeof(unsigned long long)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (1)\n",
				current->pid, sizeof(unsigned long long), copyed);
	}

	copyed = vfs_write(file, (char *) &tv1, sizeof(struct timeval), ppos);
	if (copyed != sizeof(struct timeval)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (2)\n",
				current->pid, sizeof(struct timeval), copyed);
	}

	copyed = vfs_write(file, (char *) &hpc2, sizeof(unsigned long long), ppos);
	if (copyed != sizeof(unsigned long long)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (3)\n",
				current->pid, sizeof(unsigned long long), copyed);
	}

	copyed = vfs_write(file, (char *) &tv2, sizeof(struct timeval), ppos);
	if (copyed != sizeof(struct timeval)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (4)\n",
				current->pid, sizeof(struct timeval), copyed);
	}
}

static struct iovec vec[UIO_MAXIOV];
static inline ssize_t
write_buffer (struct file* file, char* buf, ssize_t len, loff_t* ppos, int* pcnt) 
{
	ssize_t copyed;

	vec[*pcnt].iov_base = buf;
	vec[*pcnt].iov_len = len;
	(*pcnt)++;
	if (*pcnt == UIO_MAXIOV) {
		copyed = vfs_writev (file, vec, *pcnt, ppos);
		*pcnt = 0;
	}
	return copyed;
}

static inline ssize_t
write_buffer_finish (struct file* file, loff_t* ppos, int* pcnt) 
{
	return vfs_writev (file, vec, *pcnt, ppos);
}

static ssize_t write_log_data (struct file* file, loff_t* ppos, struct record_thread* prect, struct syscall_result* psr, int count, int log)
{
	int kcnt = 0;
	ssize_t copyed = 0;

#ifdef USE_ARGSALLOC
	struct argsalloc_node* node;
#else
	int i = 0;
	int size = 0;
#endif

#ifdef USE_HPC
	unsigned long long hpc1;	
	unsigned long long hpc2;	
	struct timeval tv1;
	struct timeval tv2;
#endif

	if (count <= 0) return 0;

	MPRINT ("Pid %d, start write log data\n", current->pid);

	rg_lock(prect->rp_group);

#ifdef USE_HPC
	hpc1 = rdtsc(); 
	do_gettimeofday(&tv1);
	msleep(1);
	hpc2 = rdtsc();
	do_gettimeofday(&tv2);

	copyed = vfs_write(file, (char *) &hpc1, sizeof(unsigned long long), ppos);
	if (copyed != sizeof(unsigned long long)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (1)\n",
				current->pid, sizeof(unsigned long long), copyed);
	}

	copyed = vfs_write(file, (char *) &tv1, sizeof(struct timeval), ppos);
	if (copyed != sizeof(struct timeval)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (2)\n",
				current->pid, sizeof(struct timeval), copyed);
	}

	copyed = vfs_write(file, (char *) &hpc2, sizeof(unsigned long long), ppos);
	if (copyed != sizeof(unsigned long long)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (3)\n",
				current->pid, sizeof(unsigned long long), copyed);
	}

	copyed = vfs_write(file, (char *) &tv2, sizeof(struct timeval), ppos);
	if (copyed != sizeof(struct timeval)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (4)\n",
				current->pid, sizeof(struct timeval), copyed);
	}
#endif

	/* First write out syscall records in a bunch */
	copyed = vfs_write(file, (char *) &count, sizeof(count), ppos);
	if (copyed != sizeof(count)) {
		printk ("write_log_data: tried to write record count, got rc %d\n", copyed);
	}

	MPRINT ("Pid %d write_log_data logid %d count %d, size %d\n", current->pid, log, count, sizeof(struct syscall_result)*count);

	copyed = vfs_write(file, (char *) psr, sizeof(struct syscall_result)*count, ppos);
	if (copyed != sizeof(struct syscall_result)*count) {
		printk ("write_log_data: tried to write %d, got rc %d\n",
			sizeof(struct syscall_result), copyed);
	}

#ifdef USE_ARGSALLOC
	list_for_each_entry_reverse (node, &prect->rp_argsalloc_list, list) {
		int argsalloced_size = node->pos - node->head;
		MPRINT ("Pid %d logid %d argssize write buffer slab size %d\n", current->pid, log, argsalloced_size);
		write_buffer (file, node->head, argsalloced_size, ppos, &kcnt);
	}
#else
	for (i = 0; i < count; i++) {
		if (psr->args) {
			switch(psr->sysnum) {
				case 174: size = sizeof(struct sigaction); break;
				case 175: size = sizeof(struct rt_sigprocmask_args); break;
				case 192: size = sizeof(struct mmap_pgoff_args); break;
				default:
					  size = 0;
					  printk("write_log_data: unrecognized syscall with non-NULL args\n");
			}
			write_buffer (file, psr->args, size, ppos, &kcnt);
		}
		if (psr->retparams) {
			switch (psr->sysnum) {
			case 3: size = psr->retval; break;
			case 7: size = sizeof(struct waitpid_retvals); break;
			case 11: size = sizeof(struct rvalues); break;
			case 18: size = sizeof(struct __old_kernel_stat); break;
			case 28: size = sizeof(struct __old_kernel_stat); break;
			case 42: size = 2*sizeof(int); break;
			case 43: size = sizeof(struct tms); break;
			case 54: size = *((int *)psr->retparams)+sizeof(int); break;	
			case 55: size = sizeof(struct flock);
			case 59: size = sizeof(struct oldold_utsname); break;
			case 62: size = sizeof(struct ustat); break;
			case 73: size = sizeof(old_sigset_t); break;
			case 76: size = sizeof(struct rlimit); break;
			case 77: size = sizeof(struct rusage); break;
			case 78: size = sizeof(struct gettimeofday_retvals); break;
			case 85: size = psr->retval; break;
			case 99: size = sizeof(struct statfs); break;
			case 100: size = sizeof(struct statfs); break;
			case 102: {
				int call = *(int *)((char*) psr->retparams + sizeof(atomic_t));

				switch (call) {
				case SYS_ACCEPT: 
				case SYS_GETSOCKNAME:
				case SYS_GETPEERNAME:
				{
					struct accept_retvals* pretvals = psr->retparams;
					size = sizeof(struct accept_retvals) + pretvals->addrlen;
					break;
				}
				case SYS_SOCKETPAIR:
				{
					size = sizeof(struct socketpair_retvals);
					break;
				}
				case SYS_RECV:
					size = sizeof(struct recvfrom_retvals) + psr->retval;
					break;
				case SYS_RECVFROM:
					size = sizeof(struct recvfrom_retvals) + psr->retval-1; 
					break;
				case SYS_RECVMSG:
					size = sizeof(struct recvmsg_retvals) + psr->retval-1; 
					break;
				case SYS_GETSOCKOPT:
				{
					struct getsockopt_retvals* pretvals = (struct getsockopt_retvals *) psr->retparams;
					size = sizeof(struct getsockopt_retvals) + pretvals->optlen;
					break;
				}
				default:
					size = sizeof(struct generic_socket_retvals);
				}
				break;
			}
			case 104: size = sizeof(struct itimerval); break;
			case 114: size = sizeof(struct wait4_retvals); break;
			case 116: size = sizeof(struct sysinfo); break;
			case 117: 
			{
				int call;
				call = ((struct ipc_retvals *) psr->retparams)->call;
				switch (call) {
					case SHMAT: size = sizeof(struct shmat_retvals); break;
					case SEMOP:
					case SEMTIMEDOP:
					case SEMCTL: size = sizeof(struct sem_retvals); break;
					default:
						size = sizeof(struct ipc_retvals);
				}
				break;
			}
			case 122: size = sizeof(struct new_utsname); break;
			case 126: size = sizeof(old_sigset_t); break;
			case 140: size = sizeof(loff_t); break;
			case 141: size = psr->retval; break;
			case 142: size = sizeof(struct select_retvals); break;
			case 145: size = psr->retval; break;
			case 155: size = sizeof(struct sched_param); break;
			case 162: size = sizeof(struct timespec); break;
			case 168: size = *((int *)psr->retparams)+sizeof(int); break;
			case 174: size = sizeof(struct sigaction); break;
			case 175: size = *((size_t *)psr->retparams)+sizeof(size_t); break;
			case 177: size = sizeof(siginfo_t); break;
			case 180: size = psr->retval; break;
			case 183: size = psr->retval; break;
			case 187: size = sizeof(off_t); break;
			case 191: size = sizeof(struct rlimit); break;
			case 192: size = sizeof(struct mmap_pgoff_retvals); break;
			case 195: size = sizeof(struct stat64); break;
			case 196: size = sizeof(struct stat64); break;
			case 197: size = sizeof(struct stat64); break;
			case 205: size = (psr->retval > 0) ? sizeof(gid_t)*psr->retval : 0; break;
			case 209: size = (psr->retval >= 0) ? sizeof(uid_t)*3 : 0; break;
			case 211: size = (psr->retval >= 0) ? sizeof(gid_t)*3 : 0; break;
			case 220: size = psr->retval; break;
			case 221: size = sizeof(struct flock64); break;
			case 229: size = (psr->retval >= 0) ? psr->retval : 0; break;
			case 230: size = (psr->retval >= 0) ? psr->retval : 0; break;
			case 239: size = sizeof(struct sendfile64_retvals); break;
			case 242: size = sizeof(cpumask_t); break;
			case 243: size = sizeof(struct set_thread_area_retvals); break;
			case 256: size = sizeof(struct epoll_wait_retvals) + ((psr->retval)-1)*sizeof(struct epoll_event); break;
			case 265: size = sizeof(struct timespec); break;
			case 266: size = sizeof(struct timespec); break;
			case 268: size = sizeof(struct statfs64); break;
			case 300: size = sizeof(struct stat64); break;
			case 340: size = sizeof(struct rlimit64); break;
			default: 
				size = 0;
				printk ("write_log_data: unrecognized syscall %d\n", psr->sysnum);
			}
			write_buffer (file, psr->retparams, size, ppos, &kcnt);
		}
		if (psr->signal) {
			struct repsignal *r = psr->signal;
			while (r) {
				write_buffer(file, (char *)r, sizeof(*r), ppos, &kcnt);
				r = r->next;
			}
		}
		psr++;
	}
#endif

	write_buffer_finish (file, ppos, &kcnt);

	DPRINT ("Wrote %d bytes to the file for sysnum %d\n", copyed, psr->sysnum);

	rg_unlock(prect->rp_group);
	return copyed;
}

static void
free_kernel_log_internal (struct syscall_result* psr, int syscall_count)
{
	int i;

	DPRINT("Pid %d free_kernel_log_internal\n", current->pid);

	for (i=0; i < syscall_count; i++) {
		DPRINT ("    freeing sysnum: log_ptr: %d, sysnum: %d, signal %p, ret %p, arg %p\n",
				i, psr[i].sysnum, psr[i].signal, psr[i].retparams, psr[i].args);

		//if (psr->signal) check_KFREE (psr->signal);
		while (psr[i].signal) {
			struct repsignal *r = psr[i].signal;
			psr[i].signal = psr[i].signal->next;
			r->signr = 0x6b6b6b6b;
			check_KFREE(r);
		}
		if (psr[i].retparams) {
			//if (psr[i].sysnum == 102 || psr[i].sysnum == 239) { // Socketcall, Sendfile64
			DPRINT ("    freeing sysnum: log_ptr: %d, sysnum: %d, ret %p\n",
					i, psr[i].sysnum, psr[i].retparams);
			if (retval_uses_ref(psr[i].sysnum)) {
				atomic_t* pa = (atomic_t *)psr[i].retparams;
				if (atomic_dec_and_test(pa)) {
					check_KFREE (psr[i].retparams);
				}
			} else if (psr[i].sysnum == 3) {
				if (psr[i].retval > KMALLOC_THRESHOLD) {
					VFREE(psr[i].retparams);
				}
				else {
					check_KFREE (psr[i].retparams);
				}
			} else {
				check_KFREE (psr[i].retparams);
			}
		}
	}
}


int read_log_data (struct record_thread* prect)
{
 	int rc;
 	int count = 0; // num syscalls returned by read
 	rc = read_log_data_internal (prect, prect->rp_log, prect->rp_record_pid, &count, &prect->rp_read_log_pos);
	MPRINT("Pid %d read_log_data_internal returned %d syscalls\n", current->pid, count);
	prect->rp_in_ptr = count;
 	return rc;
}

int read_log_data_internal (struct record_thread* prect, struct syscall_result* psr, int logid, int* syscall_count, loff_t* pos)
{
	char filename[MAX_LOGDIR_STRLEN+20];
	int fd;
	struct file* file;
	int rc, size, cnt = 0;
	mm_segment_t old_fs;
	int count, i;

#ifdef USE_HPC
	// for those calibration constants
	char dummy_buffer[2*sizeof(unsigned long long) + 2*sizeof(struct timeval)];
#endif
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	
	MPRINT ("Reading logid %d starting at pos %lld\n", logid, (long long) *pos);
	sprintf (filename, "%s/klog.id.%d", prect->rp_group->rg_logdir, logid);
	MPRINT ("Opening %s\n", filename);
	fd = sys_open(filename, O_RDONLY, 0644);
	MPRINT ("Open returns %d\n", fd);
	if (fd < 0) {
		printk ("read_log_data: cannot open log file %s\n", filename);
		return -EINVAL;
	}

	file = fget(fd);

#ifdef USE_HPC
	rc = vfs_read (file, (char *) dummy_buffer, 2*sizeof(unsigned long long) + 2*sizeof(struct timeval), pos);
	if (rc == 0) {
		MPRINT ("no more records in the log\n");
		*syscall_count = 0;
		goto error;
	}
	if (rc != 2*sizeof(unsigned long long) + 2*sizeof(struct timeval)) {
		printk ("vfs_read returns %d, sizeof calibration constants %d\n", rc, 2*sizeof(unsigned long long) + 2*sizeof(struct timeval));
		BUG();
		goto error;
	}
#endif

	// read one section of the log (array of syscall results and then the args/retvals/signals)
	rc = vfs_read (file, (char *) &count, sizeof(count), pos);
	if (rc != sizeof(count)) {
		MPRINT ("vfs_read returns %d, sizeof(count) %d\n", rc, sizeof(count));
		*syscall_count = 0;
		goto error;
	}

	MPRINT ("read_log_data syscall count is %d\n", count);

	rc = vfs_read (file, (char *) &psr[cnt], sizeof(struct syscall_result)*count, pos);
	if (rc != sizeof(struct syscall_result)*count) {
		printk ("vfs_read returns %d when %d of records expected\n", rc, sizeof(struct syscall_result)*count);
		goto error;
	}

	for (i = 0; i < count; i++) {
		DPRINT ("syscall sysnum %3d retval %ld\n", 
				psr[cnt].sysnum, psr[cnt].retval);
		if (psr[cnt].args) {
			psr[cnt].args = NULL;
			switch (psr[cnt].sysnum) {
				case 174: size = sizeof(struct sigaction); break;
				case 175: size = sizeof(struct rt_sigprocmask_args); break;
				case 192: size = sizeof(struct mmap_pgoff_args); break;
				default: 
					  size = 0;
					  printk ("read_log_data: unrecognized syscall %d\n", psr[cnt].sysnum);
			}
			if (size > 0) {
				char *buf = KMALLOC(size, GFP_KERNEL);
				if (buf == NULL) {
					printk ("Cannot allocate log memory, args size = %d\n", size);
					rc = sys_close (fd);
					if (rc < 0) printk ("read_log_data: file close failed with rc %d\n", rc);
					set_fs (old_fs);
					return -ENOMEM;
				}
				rc = vfs_read (file, buf, size, pos);
				if (rc != size) {
					printk ("vfs_read of data returns %d\n", rc);
					KFREE(buf);
					goto error;
				}

				if (retval_uses_ref(psr[cnt].sysnum))
					atomic_set((atomic_t *)buf, 1);

				psr[cnt].args = buf;
				DPRINT ("\t%d bytes of args included\n", size);
			}
		}
		if (psr[cnt].retparams) {
			int do_vmalloc = 0;
			loff_t peekpos;
			psr[cnt].retparams = NULL;
			switch (psr[cnt].sysnum) {
				case 3: size = psr[cnt].retval;	
					if (size > KMALLOC_THRESHOLD) {
						do_vmalloc = 1;	
					} 
					break;
			        case 7: size = sizeof(struct waitpid_retvals); break;
			        case 11: size = sizeof(struct rvalues); break;
				case 18: size = sizeof(struct __old_kernel_stat); break;
				case 28: size = sizeof(struct __old_kernel_stat); break;
				case 42: size = 2*sizeof(int); break;
				case 43: size = sizeof(struct tms); break;
				case 54: {
						 peekpos = *pos;
						 rc = vfs_read(file, (char *)&size,
								 sizeof(int), &peekpos);
						 if (rc != sizeof(int)) {
							 printk ("vfs_read cannot read ioctl value\n");
							 goto error;
						 }
						 size += sizeof(int);
						 break;
					 }
			        case 55: size = sizeof(struct flock); break;
				case 59: size = sizeof(struct oldold_utsname); break;
				case 62: size = sizeof(struct ustat); break;
				case 73: size = sizeof(old_sigset_t); break;
				case 76: size = sizeof(struct rlimit); break;
				case 77: size = sizeof(struct rusage); break;
				case 78: size = sizeof(struct gettimeofday_retvals); break;
				case 85: size = psr[cnt].retval; break;
				case 99: size = sizeof(struct statfs); break;
				case 100: size = sizeof(struct statfs); break;
				case 102: {
						  atomic_t atom;
						  int call, addrlen;
						  peekpos = *pos;
						  rc = vfs_read(file, (char *)&atom,
								  sizeof(atomic_t), &peekpos);
						  if (rc != sizeof(atomic_t)) {
							  printk ("vfs_read cannot read socketcall refcnt\n");
							  goto error;
						  }
						  rc = vfs_read(file, (char *)&call,
								  sizeof(int), &peekpos);
						  if (rc != sizeof(int)) {
							  printk ("vfs_read cannot read socketcall value\n");
							  goto error;
						  }
						  DPRINT ("\tsocketcall %d\n", call);
						  switch (call) {
#ifdef MULTI_COMPUTER
							 case SYS_CONNECT:
#endif
							  case SYS_ACCEPT:
							  case SYS_GETSOCKNAME:
							  case SYS_GETPEERNAME:
								  {	
									  rc = vfs_read(file, (char *)&addrlen,
											  sizeof(int), &peekpos);
									  if (rc != sizeof(int)) {
										  printk ("vfs_read cannot read accept value\n");
										  goto error;
									  }
									  size = sizeof(struct accept_retvals) + addrlen;
									  break;
								  }
							  case SYS_SOCKETPAIR:
								  size = sizeof(struct socketpair_retvals);
								  break;
							  case SYS_RECV:
								  size = sizeof(struct recvfrom_retvals) + psr[cnt].retval; 
								  break;
							  case SYS_RECVFROM:
								  size = sizeof(struct recvfrom_retvals) + psr[cnt].retval-1; 
								  break;
							  case SYS_RECVMSG:
								  size = sizeof(struct recvmsg_retvals) + psr[cnt].retval-1; 
								  break;
							  case SYS_GETSOCKOPT:
								  {
									  int optlen;
									  rc = vfs_read(file, (char *)&optlen,
											  sizeof(int), &peekpos);
									  if (rc != sizeof(int)) {
										  printk ("vfs_read cannot read accept value\n");
										  goto error;
									  }
									  size = sizeof(struct getsockopt_retvals) + optlen;
									  break;
								  }
							  default:
								  size = sizeof(struct generic_socket_retvals);
						  }
						  break;
					  }
				case 104: size = sizeof(struct itimerval); break;
			        case 114: size = sizeof(struct wait4_retvals); break;
			        case 116: size = sizeof(struct sysinfo); break;
				case 117: 
					  {
						  struct ipc_retvals ipc_rv;
						  peekpos = *pos;
						  rc = vfs_read(file, (char *)&ipc_rv, sizeof(struct ipc_retvals), &peekpos);
						  if (rc != sizeof(struct ipc_retvals)) {
							  printk ("vfs_read cannot read ipc retvals\n");
							  goto error;
						  }
						  switch (ipc_rv.call) {
							  case SHMAT: size = sizeof(struct shmat_retvals); break;
							  case SEMOP:
							  case SEMTIMEDOP:
							  case SEMCTL: size = sizeof(struct sem_retvals); break;
							  default: size = sizeof(struct ipc_retvals); 
						  }
						  break;
					  }
				case 122: size = sizeof(struct new_utsname); break;
			        case 126: size = sizeof(old_sigset_t); break;
				case 140: size = sizeof(loff_t); break;
				case 141: size = psr[cnt].retval; break;
				case 142: size = sizeof(struct select_retvals); break;
				case 145: size = psr[cnt].retval;	
				        if (size > KMALLOC_THRESHOLD) {
						do_vmalloc = 1;	
					} 
					break;
				case 155: size = sizeof(struct sched_param); break;
				case 162: size = sizeof(struct timespec); break;
				case 168: {
						  peekpos = *pos;
						  rc = vfs_read(file, (char *)&size,
								  sizeof(int), &peekpos);
						  if (rc != sizeof(int)) {
							  printk ("cannot read 168 value\n");
							  goto error;
						  }
						  size += sizeof(int);
						  break;
					  }
				case 174: size = sizeof(struct sigaction); break;
				case 175: {
						  size_t val;
						  peekpos = *pos;
						  rc = vfs_read(file, (char *)&val,
								  sizeof(size_t), &peekpos);
						  if (rc != sizeof(size_t)) {
							  printk("cannot read 175 value\n");
							  goto error;
						  }
						  size = val + sizeof(size_t);
						  break;
					  }
				case 177: size = sizeof(siginfo_t); break;
				case 180: size = psr[cnt].retval; break;
				case 183: size = psr[cnt].retval; break;
				case 187: size = sizeof(off_t); break;
				case 191: size = sizeof(struct rlimit); break;
			        case 192: size = sizeof(struct mmap_pgoff_retvals); break;
				case 195: size = sizeof(struct stat64); break;
				case 196: size = sizeof(struct stat64); break;
			        case 197: size = sizeof(struct stat64); break;
			        case 205: size = (psr[cnt].retval > 0) ? sizeof(gid_t)*psr[cnt].retval : 0; break;
			        case 209: size = (psr[cnt].retval >= 0) ? sizeof(uid_t)*3 : 0; break;
			        case 211: size = (psr[cnt].retval >= 0) ? sizeof(gid_t)*3 : 0; break;
				case 220: size = psr[cnt].retval; break;
 			        case 221: size = sizeof(struct flock64); break;
			        case 229: size = (psr[cnt].retval >= 0) ? psr[cnt].retval : 0; break;
			        case 230: size = (psr[cnt].retval >= 0) ? psr[cnt].retval : 0; break;
				case 239: size = sizeof(struct sendfile64_retvals); break;
			        case 242: size = sizeof(cpumask_t); break;
				case 243: size = sizeof(struct set_thread_area_retvals); break;
				case 256: size = sizeof(struct epoll_wait_retvals) + ((psr[cnt].retval)-1)*sizeof(struct epoll_event); break;
				case 265: size = sizeof(struct timespec); break;
				case 266: size = sizeof(struct timespec); break;
				case 268: size = sizeof(struct statfs64); break;
				case 300: size = sizeof(struct stat64); break;
			        case 340: size = sizeof(struct rlimit64); break;
				default: 
					  size = 0;
					  printk ("read_log_data: unrecognized syscall %d\n", psr[cnt].sysnum);
			}
			if (size > 0) {
				char *buf;
				if (do_vmalloc) {
					buf = VMALLOC(size);
				} else {
					buf = KMALLOC(size, GFP_KERNEL);

				}
				if (buf == NULL) {
					printk ("Cannot allocate log memory, size=%d, sysnum=%d\n", size, psr[cnt].sysnum);
					return -ENOMEM;
				}
				rc = vfs_read (file, buf, size, pos);
				if (rc != size) {
					printk ("vfs_read of data returns %d\n", rc);
					if (do_vmalloc) {
						VFREE(buf);
					} else {
						KFREE(buf);
					}
					goto error;
				}

				if (retval_uses_ref(psr[cnt].sysnum))
					atomic_set((atomic_t *)buf, 1);

				psr[cnt].retparams = buf;
				DPRINT ("\t%d bytes of return parameters included\n", size);
			}
		}
		if (psr[cnt].signal) {
			//psr[cnt].signal = KMALLOC(sizeof(struct repsignal), GFP_KERNEL);
			//rc = vfs_read (file, (char *) psr[cnt].signal, sizeof(struct repsignal), &pos);
			//if (rc != sizeof(struct repsignal)) {
			//	printk ("vfs_read returns %d\n", rc);
			//	return rc;
			struct repsignal **next = &psr[cnt].signal;
			struct repsignal *r;
			while (*next) {
				r = KMALLOC(sizeof(struct repsignal), GFP_KERNEL);
				rc = vfs_read(file, (char *)r, sizeof(*r), pos);
				if (rc != sizeof(struct repsignal)) {
					printk("vfs_read returns %d\n", rc);
					*next = NULL;
					goto error;
				}
				*next = r;
				next = &r->next;
			}
			DPRINT ("\tsignal info included\n");
		}
		cnt++;
	}
	*syscall_count = cnt;  
	fput(file);

	rc = sys_close (fd);
	if (rc < 0) printk ("read_log_data: file close failed with rc %d\n", rc);
	set_fs (old_fs);

	return 0;

error:
	fput(file);
	rc = sys_close (fd);
	if (rc < 0) printk ("read_log_data: file close failed with rc %d\n", rc);
	set_fs (old_fs);
	return rc;
}

#ifdef CONFIG_SYSCTL
static struct ctl_table replay_ctl[] = {
	{
		.procname	= "syslog_recs",
		.data		= &syslog_recs,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "replay_debug",
		.data		= &replay_debug,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "replay_min_debug",
		.data		= &replay_min_debug,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "argsalloc_size",
		.data		= &argsalloc_size,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{0, },
};

static struct ctl_table replay_ctl_root[] = {
	{
		.procname	= "kernel",
		.mode		= 0555,
		.child		= replay_ctl,
	},
	{0, },
};
#endif

static int __init replay_init(void)
{
#ifdef CONFIG_SYSCTL
	register_sysctl_table(replay_ctl_root);
#endif
	return 0;
}

module_init(replay_init)
