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
#include <linux/socket.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <asm/atomic.h>
#include <asm/ldt.h>
#include <asm/syscall.h>
#include <linux/statfs.h>
#include <linux/workqueue.h>
#include <linux/ipc_namespace.h>
#include <linux/delay.h>
#include <linux/prctl.h>
#include <linux/shm.h>
#include <linux/mqueue.h>
#include <linux/keyctl.h>
#include <linux/serial.h>
#include <linux/msg.h>
#include "../ipc/util.h" // For shm utility functions
#include <asm/user_32.h>

/* FIXME: I should move this to include... */
#include "../kernel/replay_graph/replayfs_btree128.h"
#include "../kernel/replay_graph/replayfs_filemap.h"
#include "../kernel/replay_graph/replayfs_syscall_cache.h"

// mcc: fix this later
//#define MULTI_COMPUTER

//#define REPLAY_PARANOID

// If defined, use file cache for reads of read-only files
#define CACHE_READS

/*
 * Enables read compression, sourcing reads of a file from another uncompressed file.
 * This will have potential data size and performance implications on both recorded/replayed files
 * AND non-record/replay reads from files whose creations were recorded.
 *
 * It may (however) drastically reduce the size of recorded reads by recording the origin of data, instead of its contents.
 *
 * This automatically disables TRACE_*
 */
#define REPLAY_COMPRESS_READS

//#define TRACE_READ_WRITE
//#define TRACE_PIPE_READ_WRITE
//#define TRACE_SOCKET_READ_WRITE

#ifdef REPLAY_COMPRESS_READS
#  undef TRACE_READ_WRITE
#  undef TRACE_PIPE_READ_WRITE
#  undef TRACE_SOCKET_READ_WRITE
#endif

#if defined(TRACE_READ_WRITE) && !defined(CACHE_READS)
# error "TRACE_READ_WRITE without CACHE_READS unimplemented!"
#endif

#if defined(TRACE_PIPE_READ_WRITE) && !defined(TRACE_READ_WRITE)
# error "TRACE_PIPE_READ_WRITE without TRACE_READ_WRITE unimplemented!"
#endif

#if defined(TRACE_SOCKET_READ_WRITE) && !defined(TRACE_PIPE_READ_WRITE)
# error "TRACE_SOCKET_READ_WRITE without TRACE_PIPE_READ_WRITE unimplemented!"
#endif

// how long we wait on the wait_queue before timing out
#define SCHED_TO 1000000

#define DPRINT if(replay_debug) printk
//#define DPRINT(x,...)
#define MPRINT if(replay_debug || replay_min_debug) printk
//#define MPRINT(x,...)
#define MCPRINT

//#define KFREE(x) my_kfree(x, __LINE__)
//#define KMALLOC(size, flags) my_kmalloc(size, flags, __LINE__)

#define ARGSKMALLOC(size, flags) argsalloc(size)
#define ARGSKFREE(ptr, size) argsfree(ptr, size)

#ifdef REPLAY_COMPRESS_READS
/* Okay, time for fun! */
/* We have a syscall cache */
extern struct replayfs_syscall_cache syscache;
static struct btree_head32 meta_tree;
DEFINE_MUTEX(meta_tree_lock);

static int is_recorded_filename(const char *filename) {
	int ret = 0;
	struct file *filp = filp_open(filename, O_RDWR, 0);

	if (!IS_ERR(filp) && filp != NULL) {
		struct inode *inode = filp->f_dentry->d_inode;

		/* If the inode has not been written */
		if (inode->i_rdev == 0 && MAJOR(inode->i_sb->s_dev) != 0) {
			if (i_size_read(filp->f_dentry->d_inode) == 0) {
				//printk("%s %d: Empty file is record file! %lu\n", __func__, __LINE__, inode->i_ino);
				ret = 1;
			} else {
				/* Do btree lookup */
				ret = replayfs_filemap_exists(filp);
				//printk("%s %d: Filemap exists for %lu returns %d\n", __func__, __LINE__, inode->i_ino, ret);
			}
		} else {
			//printk("%s %d: filp is for an untracked file.\n", __func__, __LINE__);
		}

		filp_close(filp, NULL);
	} else {
		//printk("filp is NULL??\n");
	}

	return ret;
}

static int is_recorded_file(int fd) {
	int ret = 0;
	struct file *filp = fget(fd);

	if (filp) {
		struct inode *inode = filp->f_dentry->d_inode;

		/* If the inode has not been written */
		if (inode->i_rdev == 0 && MAJOR(inode->i_sb->s_dev) != 0) {
			if (i_size_read(filp->f_dentry->d_inode) == 0) {
				//printk("%s %d: Empty file is record file! %p\n", __func__, __LINE__, filp);
				ret = 1;
			} else {
				/* Do btree lookup */
				ret = replayfs_filemap_exists(filp);
				//if (ret) {
					//printk("%s %d: Filemap exists for %p returns %d\n", __func__, __LINE__, filp, ret);
				//}
			}
		} else {
			//printk("%s %d: filp is for an untracked file.\n", __func__, __LINE__);
		}

		fput(filp);
	} else {
		//printk("filp is NULL??\n");
	}

	return ret;
}


struct replay_recorded_file_meta {
	struct replayfs_filemap map;
	struct replayfs_diskalloc alloc;
	loff_t meta_pos;
};

loff_t meta_get_size(struct replay_recorded_file_meta *meta) {
	struct page *page;
	struct replayfs_btree_meta *bmeta;
	loff_t ret;

	page = replayfs_diskalloc_get_page(&meta->alloc, meta->meta_pos);

	bmeta = kmap(page);

	ret = bmeta->i_size;

	kunmap(page);
	replayfs_diskalloc_put_page(&replayfs_alloc, page);

	return ret;
}

void update_size(struct file *filp, struct replay_recorded_file_meta *met) {
	struct page *page;
	struct replayfs_btree_meta *meta;

	page = replayfs_diskalloc_get_page(&met->alloc, met->meta_pos);

	meta = kmap(page);

	/* FIXME: Update saved isize! */
	if (filp->f_pos > meta->i_size) {

		meta->i_size = filp->f_pos;

		SetPageDirty(page);
	}

	kunmap(page);
	replayfs_diskalloc_put_page(&met->alloc, page);
}

static struct replay_recorded_file_meta *get_meta(struct file *filp) {
	struct replay_recorded_file_meta *meta;

	mutex_lock(&meta_tree_lock);
	meta = btree_lookup32(&meta_tree, (u32)filp->f_dentry->d_inode);

	if (meta == NULL) {
		meta = kmalloc(sizeof(struct replay_recorded_file_meta), GFP_KERNEL);

		if (replayfs_filemap_exists(filp)) {
			//printk("%s %d: Doing load on filp %lu\n", __func__, __LINE__, filp->f_dentry->d_inode->i_ino);
			replayfs_diskalloc_init(&meta->alloc, filp);
		} else {
			//printk("%s %d: Doing create on filp %lu\n", __func__, __LINE__, filp->f_dentry->d_inode->i_ino);
			replayfs_diskalloc_create(&meta->alloc, filp);
		}

		replayfs_filemap_init_with_pos(&meta->map, &meta->alloc, filp, &meta->meta_pos);
		//printk("%s %d: Created filemap with metapos %lld\n", __func__, __LINE__, meta->meta_pos);

		if (btree_insert32(&meta_tree, (u32)filp->f_dentry->d_inode, meta, GFP_KERNEL)) {
			BUG();
		}
	}

	mutex_unlock(&meta_tree_lock);

	return meta;
}

static struct replay_recorded_file_meta *replay_get_filename_meta(const char *filename) {
	struct replay_recorded_file_meta *meta;
	struct file *filp;

	filp = filp_open(filename, O_RDWR, 0);

	BUG_ON(!filp);

	meta = get_meta(filp);

	filp_close(filp, NULL);

	return meta;
}

static struct replay_recorded_file_meta *replay_get_file_meta(int fd) {
	struct replay_recorded_file_meta *meta;
	struct file *filp;

	filp = fget(fd);

	BUG_ON(!filp);

	meta = get_meta(filp);

	fput(filp);

	return meta;
}

struct file_work_struct {
	struct work_struct work;
	struct list_head list;
	u32 entry;
};

#define NUM_WORK_ENTRIES 0x100
DEFINE_SPINLOCK(work_lock);
struct list_head file_work_entries;
struct file_work_struct file_work_entries_alloc[NUM_WORK_ENTRIES];

void replay_filp_close_work(struct work_struct *ws);

void put_work_struct(struct file_work_struct *fws) {

	spin_lock(&work_lock);
	list_add(&fws->list, &file_work_entries);
	spin_unlock(&work_lock);
}

struct file_work_struct *get_work_struct(void) {
	struct file_work_struct *entry;
	spin_lock(&work_lock);
	BUG_ON(list_empty(&file_work_entries));
	if (list_empty(&file_work_entries)) {
		entry = NULL; 
	} else {
		entry = list_first_entry(&file_work_entries, struct file_work_struct, list);
		list_del(&entry->list);
		INIT_WORK(&entry->work, replay_filp_close_work);
	}
	spin_unlock(&work_lock);

	return entry;
}

static void replay_filp_close_internal(u32 key) {
	struct replay_recorded_file_meta *meta;
	/* The filp is closed, free its meta */
	mutex_lock(&meta_tree_lock);

	meta = btree_remove32(&meta_tree, key);

	if (meta != NULL) {
		//printk("%s %d: Destroying filemap for %lld with key %u\n", __func__, __LINE__, meta->meta_pos, key);
		replayfs_filemap_destroy(&meta->map);
		replayfs_diskalloc_destroy(&meta->alloc);
		kfree(meta);
	}

	mutex_unlock(&meta_tree_lock);
}

void replay_filp_close_work(struct work_struct *ws) {
	struct file_work_struct *fws = container_of(ws, struct file_work_struct, work);

	replay_filp_close_internal(fws->entry);

	put_work_struct(fws);
}

void replay_filp_close(struct file *filp) {
	/*
	if (current->record_thrd != NULL || current->replay_thrd != NULL) {
		struct file_work_struct *work = get_work_struct();

		work->entry = (u32)filp->f_dentry->d_inode;

		//printk("%s %d: Scheduling destruction of filemap key %u\n", __func__, __LINE__, work->entry);
		schedule_work(&work->work);
	}
	*/
}
#else
void replay_filp_close(struct file *filp) {
}
#endif

#define IS_RECORDED_FILE 1<<3

#ifdef TRACE_PIPE_READ_WRITE
extern const struct file_operations read_pipefifo_fops;
extern const struct file_operations write_pipefifo_fops;
extern const struct file_operations rdwr_pipefifo_fops;
#define is_pipe(X) ((X)->f_op == &read_pipefifo_fops || (X)->f_op == &write_pipefifo_fops || (X)->f_op == &rdwr_pipefifo_fops)

static atomic_t glbl_pipe_id = {1};

struct pipe_track {
	struct mutex lock;
	int id;
	u64 owner_read_id;
	u64 owner_write_id;

	loff_t owner_read_pos;
	loff_t owner_write_pos;

	int shared;

	struct replayfs_btree128_key key;
};

#define READ_PIPE_WITH_DATA 1<<2
#define READ_IS_PIPE 1<<1

DEFINE_MUTEX(pipe_tree_mutex);
static struct btree_head32 pipe_tree;

void replay_free_pipe(void *pipe) {
	struct pipe_track *info;

	mutex_lock(&pipe_tree_mutex);
	info = btree_lookup32(&pipe_tree, (u32)pipe);

	if (info != NULL) {
		struct replayfs_btree128_key key;
		struct replayfs_filemap map;
		int ret;


		memcpy(&key, &info->key, sizeof(key));

		kfree(info);
		btree_remove32(&pipe_tree, (u32)pipe);
		mutex_unlock(&pipe_tree_mutex);

		/* Get the map that needs to be freed */
		ret = replayfs_filemap_init_key(&map, &replayfs_alloc, &key);
		if (!ret) {
			/* Free it */
			replayfs_filemap_delete(&map, &key);
		}
	} else {
		mutex_unlock(&pipe_tree_mutex);
	}
}
#else 
void replay_free_pipe(void *pipe) {
}
#endif

#ifdef TRACE_SOCKET_READ_WRITE
extern const struct proto_ops unix_stream_ops;
extern const struct proto_ops unix_dgram_ops;
extern const struct proto_ops unix_seqpacket_ops;

extern struct socket *sock_from_file(struct file *, int *);

void replay_sock_put(struct sock *sk) {
	struct pipe_track *info;

	mutex_lock(&pipe_tree_mutex);
	info = btree_lookup32(&pipe_tree, (u32)sk);

	if (info != NULL) {
		struct replayfs_btree128_key key;
		struct replayfs_filemap map;
		int ret;

		memcpy(&key, &info->key, sizeof(key));

		kfree(info);
		btree_remove32(&pipe_tree, (u32)sk);
		mutex_unlock(&pipe_tree_mutex);

		/* Get the map that needs to be freed */
		ret = replayfs_filemap_init_key(&map, &replayfs_alloc, &key);
		if (!ret) {
			/* Free it */
			replayfs_filemap_delete(&map, &key);
		}
	} else {
		mutex_unlock(&pipe_tree_mutex);
	}
}
#else
void replay_sock_put(struct sock *sk) {} // Noop
#endif

#define IS_CACHED_MASK 1

// write out the kernel logs asynchronously
//#define WRITE_ASYNC

#ifdef REPLAY_STATS
struct replay_stats rstats;
#endif

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

#define SIGNAL_WHILE_SYSCALL_IGNORED 53

/* Variables configurable via /proc file system */
unsigned int syslog_recs = 20000;
unsigned int replay_debug = 0;
unsigned int replay_min_debug = 0;
unsigned long argsalloc_size = (512*1024);
// If the replay clock is greater than this value, MPRINT out the syscalls made by pin
unsigned long pin_debug_clock = LONG_MAX;

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

#define SR_HAS_RETPARAMS        0x1 
#define SR_HAS_SIGNAL           0x2
#define SR_HAS_START_CLOCK_SKIP 0x4
#define SR_HAS_STOP_CLOCK_SKIP  0x8
#define SR_HAS_NONZERO_RETVAL   0x10

// This structure records the result of a system call
struct syscall_result {
#ifdef USE_HPC
	unsigned long long	hpc_begin;	// Time-stamp counter value when system call started
	unsigned long long	hpc_end;	// Time-stamp counter value when system call finished
#endif
	short			sysnum;		// system call number executed
	u_char                  flags;          // See defs above
};

// This holds a memory range that should be preallocated
struct reserved_mapping {
	u_long m_begin;
	u_long m_end;
};

#ifdef CACHE_READS
struct record_cache_data {
	char is_cache_file; // True if this is a cache file descriptor
	struct mutex mutex;  // Only one thread at a time gets to access the descriptor
};

struct record_cache_chunk {
	int                        count; // Number of files in this chunk
	struct record_cache_data*  data;  // Dynamically allocated array of data
	struct record_cache_chunk* next;  // Next chunk
};

struct record_cache_files {
	atomic_t                   refcnt; // Refs to this structure
	struct rw_semaphore        sem; // Protects this structure
	int                        count; // Maximum number of files in this struct 
	struct record_cache_chunk* list;  // Array of flags per file descriptor
};

struct replay_cache_files {
	atomic_t refcnt; // Refs to this structure
	int      count; // Maximum number of files in this struct 
	int*     data;  // Array of cache fds per file descriptor
};
#else
struct record_cache_files;
struct replay_cache_files;
#endif

struct record_group {
	__u64 rg_id;                         // Unique identifier for all time for this recording

#ifdef REPLAY_LOCK_DEBUG
	pid_t rg_locker;
	struct semaphore rg_sem; 
#else
	struct mutex rg_mutex;      // Protect all structures for group
#endif
	atomic_t rg_refcnt;         // Refs to this structure

	char rg_logdir[MAX_LOGDIR_STRLEN+1]; // contains the directory to which we will write the log

	struct page* rg_shared_page;          // Used for shared clock below
	atomic_t* rg_pkrecord_clock;          // Where clock is mapped into kernel address space for this record/replay 
	char rg_shmpath[MAX_LOGDIR_STRLEN+1]; // contains the path of the shared-memory file that we will used for user-level mapping of clock

	char rg_linker[MAX_LOGDIR_STRLEN+1]; // contains the name of a special linker to use - for user level pthread library

	atomic_t rg_record_threads; // Number of active record threads
	int rg_save_mmap_flag;		// If on, records list of mmap regions during record
	ds_list_t* rg_reserved_mem_list; // List of addresses that are mmaped, kept on the fly as they occur
	char rg_mismatch_flag;      // Set when an error has occurred and we want to abandon ship
	char* rg_libpath;           // For glibc hack
};

// This structure has task-specific replay data
struct replay_group {
	struct record_group* rg_rec_group; // Pointer to record group
	ds_list_t* rg_replay_threads; // List of replay threads for this group
	atomic_t rg_refcnt;         // Refs to this structure
	ds_list_t* rg_reserved_mem_list; // List of addresses we should preallocate to keep pin from using them
	u_long rg_max_brk;          // Maximum value of brk address
	ds_list_t* rg_used_address_list; // List of addresses that will be used by the application (and hence, not by pin)
	int rg_follow_splits;       // Ture if we should replay any split-off replay groups
};

struct argsalloc_node {
	void*            head;
	void*            pos;
	size_t           size;
	struct list_head list;
};

struct sysv_mapping {
	int record_id;
	int replay_id;
	struct list_head list;
};

struct sysv_shm {
	u_long addr;
	u_long len;
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
#define REPLAY_MAX_RANDOM_VALUES 10
struct rvalues {
	int    cnt;
	u_long val[REPLAY_MAX_RANDOM_VALUES];
};

// This structure records/replays other values passed to an executable during exec
struct exec_values {
	int uid;
	int euid;
	int gid;
	int egid; 
	int secureexec;
};

//This has record thread specific data
struct record_thread {
	struct record_group* rp_group; // Points to record group
	struct record_thread* rp_next_thread; // Circular record thread list

	atomic_t rp_refcnt;            // Reference count for this object
	pid_t rp_record_pid;           // Pid of recording task (0 if not set)
	short rp_clone_status;         // Prevent rec task from exiting
	                               // before rep task is created 
	                               // (0:init,1:cloning,2:completed)
	long rp_sysrc;                 // Return code for replay_prefork

	/* Recording log */
	struct syscall_result* rp_log;  // Logs system calls per thread
	u_long rp_in_ptr;               // Next record to insert
	u64 rp_count;                   // Number of syscalls run by this thread

	loff_t rp_read_log_pos;		// The current position in the log file that is being read
	struct list_head rp_argsalloc_list;	// kernel linked list head pointing to linked list of argsalloc_nodes

	u_long rp_user_log_addr;        // Where the user log info is stored 
#ifdef USE_EXTRA_DEBUG_LOG
	u_long rp_user_extra_log_addr;  // For extra debugging log
	char rp_elog_opened;		// Flag that says whether or not the extra log has been opened 
	loff_t rp_read_elog_pos;	// The current position in the extra log file that is being read
#endif
	int __user * rp_ignore_flag_addr;     // Where the ignore flag is stored

	struct rvalues random_values;   // Tracks kernel randomness during syscalls (currently execve only) 
	struct exec_values exec_values; // Track other exec-specifc values

	atomic_t* rp_precord_clock;     // Points to the recording clock in use
	u_long  rp_expected_clock;      // Used for delta clock

	char rp_ulog_opened;		// Flag that says whether or not the user log has been opened 
	char rp_klog_opened;		// Flag that says whether or not the kernel log has been opened 
	loff_t rp_read_ulog_pos;	// The current position in the ulog file that is being read
	struct repsignal_context* rp_repsignal_context_stack;  // Saves replay context on signal delivery
	u_long rp_record_hook;          // Used for dumbass linking in glibc
	struct repsignal *rp_signals;   // Stores delayed signals
	struct repsignal* rp_last_signal; // Points to last signal recorded for this process
#ifdef CACHE_READS
	struct record_cache_files* rp_cache_files; // Info about open cache files
#endif
};

#define REPLAY_STATUS_RUNNING         0 // I am the running thread - should only be one of these per group
#define REPLAY_STATUS_ELIGIBLE        1 // I could run now
#define REPLAY_STATUS_WAIT_CLOCK      2 // Cannot run because waiting for an event
#define REPLAY_STATUS_DONE            3 // Exiting

#define REPLAY_PIN_TRAP_STATUS_NONE	0  // Not handling any sort of extra Pin SIGTRIP
#define REPLAY_PIN_TRAP_STATUS_EXIT	1  // I was waiting for a syscall exit, but was interrupted by a Pin SIGTRAP
#define REPLAY_PIN_TRAP_STATUS_ENTER	2  // I was waiting for a syscall enter, but was interrupted by a Pin SIGTRAP

// This has replay thread specific data
struct replay_thread {
	struct replay_group* rp_group; // Points to replay group
	struct replay_thread* rp_next_thread; // Circular replay thread list
	struct record_thread* rp_record_thread; // Points to record thread

	atomic_t rp_refcnt;            // Reference count for this object
	pid_t rp_replay_pid;           // Pid of replaying task (0 if not set)
	u_long rp_out_ptr;             // Next record to read
	short rp_replay_exit;          // Set after a rollback
	u_char rp_signals;             // Set if sig should be delivered
	u_long app_syscall_addr;       // Address in user-land that is set when the syscall should be replayed

	int rp_status;                  // One of the replay statuses above
	u_long rp_wait_clock;           // Valid if waiting for kernel or user-level clock according to rp_status
	u_long rp_stop_clock_skip;      // Temporary storage while processing syscall
	wait_queue_head_t rp_waitq;     // Waiting on this queue if in one of the waiting states

	long rp_saved_rc;               // Stores syscall result when blocking in syscall conflicts with a pin lock
	char* rp_saved_retparams;       // Stores syscall results when blocking in syscall conflicts with a pin lock
	struct syscall_result* rp_saved_psr; // Stores syscall info when blocking in syscall conflicts with a pin lock
	struct rvalues random_values;   // Tracks kernel randomness during syscalls (currently execve only) 
	struct exec_values exec_values; // Track other exec-specifc values

	u_long* rp_preplay_clock;       // Points to the replay clock in use
	u_long  rp_expected_clock;      // Used for delta clock
	struct list_head rp_sysv_list;	// List of mappings from replay SYSV IDs to reocrd SYSV IDs
	struct list_head rp_sysv_shms;	// List of SYSV shared memory segments for this process/thread
	u_long rp_replay_hook;          // Used for dumbass linking in glibc

	const char* rp_exec_filename;   // Used during execve to pass same arguments as recording (despite use of cache file)
	int rp_pin_restart_syscall;	// Used to see if we should restart a syscall because of Pin
	u_long rp_start_clock_save;	// Save the value of the start clock to resume after Pin returns back
	u_long rp_stop_clock_save;	// Save the value of the stop clock to resume after Pin returns back
	u_long argv;			// Save the location of the program args
	int argc;			// Save the number of program args
	u_long envp;			// Save the location of the env. vars
	int envc;			// Save the number of environment vars
#ifdef CACHE_READS
	struct replay_cache_files* rp_cache_files; // Info about open cache files
#endif
};

/* Prototypes */
struct file* init_log_write (struct record_thread* prect, loff_t* ppos, int* pfd);
void term_log_write (struct file* file, int fd);
int read_log_data (struct record_thread* prt);
int read_log_data_internal (struct record_thread* prect, struct syscall_result* psr, int logid, int* syscall_count, loff_t* pos);
static ssize_t write_log_data(struct file* file, loff_t* ppos, struct record_thread* prect, struct syscall_result* psr, int count);
static void destroy_record_group (struct record_group *prg);
static void destroy_replay_group (struct replay_group *prepg);
static void __destroy_replay_thread (struct replay_thread* prp);
static void argsfreeall (struct record_thread* prect);
void write_begin_log (struct file* file, loff_t* ppos, struct record_thread* prect);
static void write_and_free_kernel_log(struct record_thread *prect);
void write_mmap_log (struct record_group* prg);
int read_mmap_log (struct record_group* prg);
//static int add_sysv_mapping (struct replay_thread* prt, int record_id, int replay_id);
//static int find_sysv_mapping (struct replay_thread* prt, int record_id);
static void delete_sysv_mappings (struct replay_thread* prt);
#ifdef WRITE_ASYNC
static void write_and_free_kernel_log_async(struct record_thread *prect);
static void write_and_free_handler (struct work_struct *work);
#endif
static int record_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs);
static int replay_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs);
static asmlinkage long replay_poll (struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs);

/* Return values for complex system calls */
struct gettimeofday_retvals {
	short           has_tv;
	short           has_tz;
	struct timeval  tv;
	struct timezone tz;
};

struct pselect6_retvals {
	char            has_inp;
	char            has_outp;
	char            has_exp;
	char            has_tsp;
	fd_set          inp;
	fd_set          outp;
	fd_set          exp;
	struct timespec tsp;
};

struct generic_socket_retvals {
	int call;
};

// mcc: This should probably be fixed since it allocated an extra 4 bytes
struct accept_retvals {
	int call;
	int addrlen;
	char addr; // Variable length buffer follows
};

struct socketpair_retvals {
	int call;
	int sv0;
	int sv1;
};

struct recvfrom_retvals {
	int call;
	struct sockaddr addr;
	int addrlen;
	char buf;  // Variable length buffer follows 
};

struct recvmsg_retvals {
	int          call;
	int          msg_namelen;
	long         msg_controllen;
	unsigned int msg_flags;
};
// Followed by msg_namelen bytes of msg_name, msg_controllen bytes of msg_control and rc of data

struct getsockopt_retvals {
	int call;
	int optlen;
	char optval; // Variable length buffer follows
};

// retvals for shmat, since we need to save additional information
struct shmat_retvals {
	u_long len; // For generic length field
	int    call; // Currently needed for PIN memory allocation - would like to eliminate
	u_long size;
	u_long raddr;
};

// retvals for mmap_pgoff - needed to find cached files for non-COW filesystems
struct mmap_pgoff_retvals {
	dev_t           dev;
	u_long          ino;
	struct timespec mtime; 
};

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

// Cannot unlink shared path page when a replay group is deallocated, so we queue the work up for later
struct replay_paths_to_free {
  char path[MAX_LOGDIR_STRLEN+1]; // path to deallocate
  struct replay_paths_to_free* next;
};
static struct replay_paths_to_free* paths_to_free = NULL;
DEFINE_MUTEX(paths_to_free_mutex);

/* Creates a new clock for a record group */
static int
create_shared_clock (struct record_group* prg)
{
	u_long uaddr;
	int fd, rc;
	mm_segment_t old_fs = get_fs();
	struct replay_paths_to_free* ptmp;

	set_fs(KERNEL_DS);
	mutex_lock(&paths_to_free_mutex);
	while (paths_to_free) {
		ptmp = paths_to_free;
		paths_to_free = ptmp->next;
		fd = sys_unlink (ptmp->path);
		KFREE (ptmp);
	}
	mutex_unlock(&paths_to_free_mutex);

	snprintf (prg->rg_shmpath, MAX_LOGDIR_STRLEN+1, "/dev/shm/uclock%d", current->pid);
	fd = sys_open (prg->rg_shmpath, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0644);
	if (fd < 0) {
		printk ("create_shared_clock: pid %d cannot open shared file %s, rc=%d\n", current->pid, prg->rg_shmpath, fd);
		goto out_oldfs;
	}

	rc = sys_ftruncate (fd, 4096);
	if (rc < 0) {
		printk ("create_shared_clock: pid %d cannot create new shm page, rc=%d\n", current->pid, rc);
		goto out_close;
	}	

	uaddr = sys_mmap_pgoff (0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (IS_ERR((void *) uaddr)) {
		printk ("create_shared_clock: pid %d cannot map shm page, rc=%ld\n", current->pid, PTR_ERR((void *) uaddr));
		goto out_close;
	}

	rc = get_user_pages (current, current->mm, uaddr, 1, 1, 0, &prg->rg_shared_page, NULL);
	if (rc != 1) {
		printk ("creare_shared_clock: pid %d cannot get shm page, rc=%d\n", current->pid, rc);
		goto out_unmap;
	}

	prg->rg_pkrecord_clock = (atomic_t *) kmap (prg->rg_shared_page);
	DPRINT ("record/replay clock is at %p\n", prg->rg_pkrecord_clock);

	rc = sys_munmap (uaddr, 4096);
	if (rc < 0) printk ("create_shared_clock: pid %d cannot munmap shared page, rc=%d\n", current->pid, rc);

	rc = sys_close(fd);
	if (rc < 0) printk ("create_shared_clock: pid %d cannot close shared file %s, rc=%d\n", current->pid, prg->rg_shmpath, rc);

	return 0;

out_unmap:
	sys_munmap (uaddr, 4096);
out_close:
	sys_close (fd);
	sys_unlink (prg->rg_shmpath);
out_oldfs:
	set_fs(old_fs);

	return -1;
}

static void
recycle_shared_clock (char* path)
{
	struct replay_paths_to_free* pnew;

	mutex_lock(&paths_to_free_mutex);
	pnew = KMALLOC(sizeof(struct replay_paths_to_free), GFP_KERNEL);
	if (pnew == NULL) {
		printk ("Cannot alloc memory to queue freed path\n");
	} else {
		strcpy (pnew->path, path);
		pnew->next = paths_to_free;
		paths_to_free = pnew;
	}
	mutex_unlock(&paths_to_free_mutex);
}

#ifdef CACHE_READS
#define INIT_RECPLAY_CACHE_SIZE 32

static struct record_cache_files*
init_record_cache_files (void)
{
	struct record_cache_files* pfiles;
	int i;

	pfiles = KMALLOC(sizeof(struct record_cache_files), GFP_KERNEL);
	if (pfiles == NULL) {
		printk ("init_record_cache_files: cannot allocate struct\n");
		return NULL;
	}

	atomic_set(&pfiles->refcnt, 1);
	init_rwsem(&pfiles->sem);
	pfiles->count = INIT_RECPLAY_CACHE_SIZE;
	pfiles->list = KMALLOC(sizeof(struct record_cache_chunk), GFP_KERNEL);
	if (pfiles->list == NULL) {
		printk ("init_record_cache_files: cannot allocate list\n");
		KFREE (pfiles);
		return NULL;
	}
	pfiles->list->count = INIT_RECPLAY_CACHE_SIZE;
	pfiles->list->next = NULL;
	pfiles->list->data = KMALLOC(INIT_RECPLAY_CACHE_SIZE*sizeof(struct record_cache_data), GFP_KERNEL);
	if (pfiles->list->data == NULL) {
		printk ("init_record_cache_files: cannot allocate data\n");
		KFREE (pfiles);
		return NULL;
	}
	for (i = 0; i < INIT_RECPLAY_CACHE_SIZE; i++) {
		mutex_init (&pfiles->list->data[i].mutex);
		pfiles->list->data[i].is_cache_file = 0;
	}

	return pfiles;
}

static void
get_record_cache_files (struct record_cache_files* pfiles)
{
	atomic_inc(&pfiles->refcnt);
}

static void 
put_record_cache_files (struct record_cache_files* pfiles)
{
	struct record_cache_chunk* pchunk;

	if (atomic_dec_and_test(&pfiles->refcnt)) {
		pfiles->count = 0;
		while (pfiles->list) {
			pchunk = pfiles->list;
			pfiles->list = pchunk->next;
			KFREE (pchunk->data);
			KFREE (pchunk);
		}
		KFREE (pfiles);
	}
}

static int
is_record_cache_file_lock (struct record_cache_files* pfiles, int fd)
{
	struct record_cache_chunk* pchunk;
	int rc = 0;

	down_read(&pfiles->sem);
	if (fd < pfiles->count) {
		pchunk = pfiles->list;
		while (fd >= pchunk->count) {
			fd -= pchunk->count;
			pchunk = pchunk->next;
		}
		if (pchunk->data[fd].is_cache_file) {
			mutex_lock (&pchunk->data[fd].mutex); /* return locked */
			rc = 1;
		}
	}
	up_read(&pfiles->sem);

	return rc;
}

static int
is_record_cache_file (struct record_cache_files* pfiles, int fd)
{
	struct record_cache_chunk* pchunk;
	int rc = 0;

	down_read(&pfiles->sem);
	if (fd < pfiles->count) {
		pchunk = pfiles->list;
		while (fd >= pchunk->count) {
			fd -= pchunk->count;
			pchunk = pchunk->next;
		}
		if (pchunk->data[fd].is_cache_file) rc = 1;
	}
	up_read(&pfiles->sem);

	return rc;
}

static void
record_cache_file_unlock (struct record_cache_files* pfiles, int fd)
{
	struct record_cache_chunk* pchunk;

	down_read(&pfiles->sem);
	pchunk = pfiles->list;
	while (fd >= pchunk->count) {
		fd -= pchunk->count;
		pchunk = pchunk->next;
	}
	mutex_unlock(&pchunk->data[fd].mutex);	
	up_read(&pfiles->sem);
}

static int
set_record_cache_file (struct record_cache_files* pfiles, int fd)
{
	struct record_cache_chunk* tmp, *pchunk;
	int newcount, chunkcount;
	int i;

	down_write(&pfiles->sem);
	if (fd >= pfiles->count) {
		newcount = pfiles->count;
		while (fd >= newcount) newcount *= 2;
		chunkcount = newcount - pfiles->count;
		tmp = KMALLOC(sizeof(struct record_cache_chunk), GFP_KERNEL);
		if (tmp == NULL) {
			printk ("set_record_cache_files: cannot allocate list\n");
			up_write(&pfiles->sem);
			return -ENOMEM;
		}		 
		tmp->data = KMALLOC(chunkcount*sizeof(struct record_cache_data), GFP_KERNEL);
		if (tmp->data == NULL) {
			printk ("set_cache_file: cannot allocate new data buffer of size %d\n", chunkcount*sizeof(struct record_cache_data));
			KFREE (tmp);
			up_write(&pfiles->sem);
			return -ENOMEM;
		}
		for (i = 0; i < chunkcount; i++) {
			mutex_init (&tmp->data[i].mutex);
			tmp->data[i].is_cache_file = 0;
		}
		pchunk = pfiles->list;
		while (pchunk->next != NULL) pchunk = pchunk->next;
		pchunk->next = tmp;
		tmp->count = chunkcount;
		tmp->next = NULL;
		pfiles->count = newcount;
	}
	pchunk = pfiles->list;
	while (fd >= pchunk->count) {
		fd -= pchunk->count;
		pchunk = pchunk->next;
	}
	pchunk->data[fd].is_cache_file = 1;
	up_write(&pfiles->sem);

	return 0;
}

static void
copy_record_cache_files (struct record_cache_files* pfrom, struct record_cache_files* pto)
{
	struct record_cache_chunk* pchunk;
	int i, fd = 0;
	
	down_read(&pfrom->sem);
	pchunk = pfrom->list;
	while (pchunk) {
		for (i = 0; i < pchunk->count; i++) {
			if (pchunk->data[i].is_cache_file) {
				set_record_cache_file(pto, fd);
			}
			fd++;
		}
		pchunk = pchunk->next;
	}
        up_read(&pfrom->sem);
}

static void
clear_record_cache_file (struct record_cache_files* pfiles, int fd)
{
	struct record_cache_chunk* pchunk;

	down_read(&pfiles->sem);
	if (fd < pfiles->count) {
		pchunk = pfiles->list;
		while (fd >= pchunk->count) {
			fd -= pchunk->count;
			pchunk = pchunk->next;
		}
		pchunk->data[fd].is_cache_file = 0;
	}
	up_read(&pfiles->sem);
}

static void
close_record_cache_files (struct record_cache_files* pfiles)
{
	struct record_cache_chunk* pchunk;
	int i;

	down_read(&pfiles->sem);
	pchunk = pfiles->list;
	while (pchunk) {
		for (i = 0; i < pchunk->count; i++) {
			pchunk->data[i].is_cache_file = 0;
		}
		pchunk = pchunk->next;
	}
	up_read(&pfiles->sem);
}

static struct replay_cache_files*
init_replay_cache_files (void)
{
	struct replay_cache_files* pfiles;
	int i;

	pfiles = KMALLOC(sizeof(struct replay_cache_files), GFP_KERNEL);
	if (pfiles == NULL) {
		printk ("init_replay_cache_files: cannot allocate struct\n");
		return NULL;
	}
	atomic_set(&pfiles->refcnt, 1);
	pfiles->count = INIT_RECPLAY_CACHE_SIZE;
	pfiles->data = KMALLOC(INIT_RECPLAY_CACHE_SIZE*sizeof(int), GFP_KERNEL);
	if (pfiles->data == NULL) {
		printk ("init_replay_cache_files: cannot allocate data\n");
		return NULL;
	}
	for (i = 0; i < INIT_RECPLAY_CACHE_SIZE; i++) pfiles->data[i] = -1;

	return pfiles;
}

static void
get_replay_cache_files (struct replay_cache_files* pfiles)
{
	atomic_inc(&pfiles->refcnt);
}

static void 
put_replay_cache_files (struct replay_cache_files* pfiles)
{
	if (atomic_dec_and_test(&pfiles->refcnt)) {
		pfiles->count = 0;
		KFREE (pfiles->data);
	}
}

static int
is_replay_cache_file (struct replay_cache_files* pfiles, int fd, int* cache_fd)
{
	if (fd < 0 || fd >= pfiles->count) return 0;
	*cache_fd = pfiles->data[fd];
	return (pfiles->data[fd] >= 0); 
}

static int
set_replay_cache_file (struct replay_cache_files* pfiles, int fd, int cache_fd)
{
	int newcount;
	int* tmp;
	int i;

	if (fd >= pfiles->count) {
		newcount = pfiles->count;
		while (fd >= newcount) newcount *= 2;
		tmp = KMALLOC(newcount*sizeof(int), GFP_KERNEL);
		if (tmp == NULL) {
			printk ("set_cache_file: cannot allocate new data buffer of size %d\n", newcount);
			return -ENOMEM;
		}
		for (i = 0; i < pfiles->count; i++) tmp[i] = pfiles->data[i];
		for (i = pfiles->count; i < newcount; i++) tmp[i] = -1;
		KFREE (pfiles->data);
		pfiles->data = tmp;
		pfiles->count = newcount;
	}
	pfiles->data[fd] = cache_fd;
	return 0;
}

static void
copy_replay_cache_files (struct replay_cache_files* pfrom, struct replay_cache_files* pto)
{
	int i;
	
	for (i = pfrom->count-1; i >= 0; i--) { // Backward makes allocation in set efficient
		if (pfrom->data[i] != -1) {
			set_replay_cache_file(pto, i, pfrom->data[i]);
		}
	}
}

static void
clear_replay_cache_file (struct replay_cache_files* pfiles, int fd)
{
	if (fd < pfiles->count) pfiles->data[fd] = -1;
}

static void
close_replay_cache_files (struct replay_cache_files* pfiles)
{
	int i;

	for (i = 0; i < pfiles->count; i++) {
		pfiles->data[i] = -1;
	}
}

#endif

/* Creates a new replay group for the replaying process info */
static struct replay_group*
new_replay_group (struct record_group* prec_group, int follow_splits)
{
	struct replay_group* prg;

	prg = KMALLOC (sizeof(struct replay_group), GFP_KERNEL);
	if (prg == NULL) {
		printk ("Cannot allocate replay_group\n");
		goto err;
	}
	DPRINT ("new_replay_group: %p\n", prg);

	prg->rg_rec_group = prec_group;

	prg->rg_follow_splits = follow_splits;
	prg->rg_replay_threads = ds_list_create(NULL, 0, 1);
	if (prg->rg_replay_threads == NULL) {
		printk ("Cannot create replay_group rg_replay_threads\n");
		goto err_replaythreads;
	}

	atomic_set (&prg->rg_refcnt, 0);

	prg->rg_reserved_mem_list = ds_list_create (rm_cmp, 0, 1);
	prg->rg_used_address_list = NULL;

	// Record group should not be destroyed before replay group
	get_record_group (prec_group);

#ifdef REPLAY_STATS
	atomic_inc(&rstats.started);
#endif

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

	MPRINT ("Pid %d new_record_group: entered\n", current->pid);

	prg = KMALLOC (sizeof(struct record_group), GFP_KERNEL);
	if (prg == NULL) {
		printk ("Cannot allocate record_group\n");
		goto err;
	}

	if (logdir == NULL) {
		prg->rg_id = get_replay_id();
		if (prg->rg_id == 0) {
			printk ("Cannot get replay id\n");
			goto err_free;
		}
	}

#ifdef REPLAY_LOCK_DEBUG
	sema_init(&prg->rg_sem, 1);
#else
	mutex_init (&prg->rg_mutex);
#endif	
	atomic_set(&prg->rg_refcnt, 0);

	if (create_shared_clock (prg) < 0) goto err_free;

	if (logdir) {
		strncpy (prg->rg_logdir, logdir, MAX_LOGDIR_STRLEN+1);
	} else {
		make_logdir_for_replay_id (prg->rg_id, prg->rg_logdir);
	}
	memset (prg->rg_linker, 0, MAX_LOGDIR_STRLEN+1);

	prg->rg_mismatch_flag = 0;
	prg->rg_libpath = NULL;

	atomic_set(&prg->rg_record_threads, 0);
	prg->rg_save_mmap_flag = 0;
	prg->rg_reserved_mem_list = ds_list_create (rm_cmp, 0, 1);

	MPRINT ("Pid %d new_record_group %lld: exited\n", current->pid, prg->rg_id);
	return prg;

err_free:
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
#ifdef REPLAY_STATS
	atomic_inc(&rstats.finished);
#endif
	printk ("Goodbye, cruel lamp!  This replay is over\n");
	MPRINT ("Pid %d destroy replay group %p: exit\n", current->pid, prepg);
}

// PARSPEC: eventually: want to make sure that all replay groups are destroyed
static void
destroy_record_group (struct record_group *prg)
{
	struct reserved_mapping* pmapping;

	MPRINT ("Pid %d destroying record group %p\n", current->pid, prg);

	kunmap (prg->rg_shared_page);
	put_page (prg->rg_shared_page);
	if (prg->rg_libpath) KFREE (prg->rg_libpath);

	// Free all of the mappings
	while ((pmapping = ds_list_get_first (prg->rg_reserved_mem_list)) != NULL) {
		KFREE (pmapping);
	}
	recycle_shared_clock (prg->rg_shmpath);
	ds_list_destroy (prg->rg_reserved_mem_list);

	KFREE (prg);
#ifdef REPLAY_PARANOID
	printk ("vmalloc cnt: %d\n", atomic_read(&vmalloc_cnt));
#endif
}

/* Creates a new record thread */
static struct record_thread* 
new_record_thread (struct record_group* prg, u_long recpid, struct record_cache_files* pfiles)
{
	struct record_thread* prp;

	prp = KMALLOC (sizeof(struct record_thread), GFP_KERNEL);
	if (prp == NULL) {
		printk ("Cannot allocate record_thread\n");
		return NULL;
	}

	prp->rp_group = prg;
	prp->rp_next_thread = prp;

	atomic_set(&prp->rp_refcnt, 1);

	MPRINT ("Pid %d creates new record thread: %p, recpid %lu\n", current->pid, prp, recpid);

	prp->rp_record_pid = recpid;
	prp->rp_clone_status = 0;
	prp->rp_sysrc = 0;

	// Recording log inits
	// mcc: current in-memory log segment; the log can be bigger than what we hold in memory,
	// so we just flush it out to disk when this log segment is full and reset the rp_in_ptr
	prp->rp_log = VMALLOC(sizeof(struct syscall_result)*syslog_recs);
	if (prp->rp_log == NULL) {
		KFREE (prp);
		return NULL;
	}

	prp->rp_in_ptr = 0;
	prp->rp_count = 0;
	prp->rp_read_log_pos = 0;

	INIT_LIST_HEAD(&prp->rp_argsalloc_list);

	prp->rp_user_log_addr = 0;
#ifdef USE_EXTRA_DEBUG_LOG
	prp->rp_user_extra_log_addr = 0;
	prp->rp_elog_opened = 0;			
	prp->rp_read_elog_pos = 0;	
#endif
	prp->rp_ignore_flag_addr = 0;

	prp->rp_precord_clock = prp->rp_group->rg_pkrecord_clock;
	prp->rp_expected_clock = 0;
	prp->rp_ulog_opened = 0;			
	prp->rp_klog_opened = 0;			
	prp->rp_read_ulog_pos = 0;	
	prp->rp_repsignal_context_stack = NULL;
	prp->rp_record_hook = 0;
	prp->rp_signals = NULL;
	prp->rp_last_signal = NULL;

	atomic_inc(&prg->rg_record_threads);
#ifdef CACHE_READS
	if (pfiles) {
		prp->rp_cache_files = pfiles;
		get_record_cache_files (pfiles);
	} else {
		prp->rp_cache_files = init_record_cache_files ();
		if (prp->rp_cache_files == NULL) {
			KFREE (prp->rp_log);
			KFREE (prp);
			return NULL;
		}
	}
#endif
	get_record_group(prg);
	return prp;
}

/* Creates a new replay thread */
static struct replay_thread* 
new_replay_thread (struct replay_group* prg, struct record_thread* prec_thrd, u_long reppid, u_long out_ptr, struct replay_cache_files* pfiles)
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
	prp->rp_signals = 0;
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

	ds_list_append(prg->rg_replay_threads, prp);
	
        prp->rp_preplay_clock = (u_long *) prp->rp_group->rg_rec_group->rg_pkrecord_clock;
	prp->rp_expected_clock = 0;
	INIT_LIST_HEAD(&prp->rp_sysv_list);
	INIT_LIST_HEAD(&prp->rp_sysv_shms);

	prp->rp_pin_restart_syscall = 0;
	prp->rp_start_clock_save = 0;
	prp->rp_replay_hook = 0;

#ifdef CACHE_READS
	if (pfiles) {
		prp->rp_cache_files = pfiles;
		get_replay_cache_files (pfiles);
	} else {
		prp->rp_cache_files = init_replay_cache_files();
		if (prp->rp_cache_files == NULL) {
			KFREE (prp);
			return NULL;
		}
	}
#endif

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
	argsfreeall (prp);
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

	put_record_cache_files (prp->rp_cache_files);

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

	for (prev = prp; prev->rp_next_thread != prp; prev = prev->rp_next_thread);
	prev->rp_next_thread = prp->rp_next_thread;

	// remove sys mappings
	delete_sysv_mappings (prp);

	BUG_ON (ds_list_remove(prp->rp_group->rg_replay_threads, prp) == NULL);

#ifdef CACHE_READS
	put_replay_cache_files (prp->rp_cache_files);
#endif

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
	printk ("SYSCALL MISMATCH\n");
#ifdef REPLAY_STATS
	atomic_inc(&rstats.mismatched);
#endif
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
	char buf[256];

	printk ("vmas for task %d mm %p\n", tsk->pid, tsk->mm);
	down_read (&tsk->mm->mmap_sem);
	for (mpnt = tsk->mm->mmap; mpnt; mpnt = mpnt->vm_next) {
		printk ("VMA start %lx end %lx", mpnt->vm_start, mpnt->vm_end);
		if (mpnt->vm_file) {
			printk (" file %s ", dentry_path (mpnt->vm_file->f_dentry, buf, sizeof(buf)));
			if (mpnt->vm_flags & VM_READ) {
				printk ("r");
			} else {
				printk ("-");
			}
			if (mpnt->vm_flags & VM_WRITE) {
				printk ("w");
			} else {
				printk ("-");
			}
			if (mpnt->vm_flags & VM_EXEC) {
				printk ("x");
			} else {
				printk ("-");
			}
		}
		printk ("\n");
	}
	up_read (&tsk->mm->mmap_sem);
}

void
print_replay_threads (void)
{
	struct replay_thread* tmp;
	// See if we can find another eligible thread
	tmp = current->replay_thrd->rp_next_thread;

	MPRINT ("Pid %d current thread is %d (recpid %d) status %d clock %ld - clock is %ld\n", 
			current->pid, current->replay_thrd->rp_replay_pid, current->replay_thrd->rp_record_thread->rp_record_pid, 
			current->replay_thrd->rp_status, current->replay_thrd->rp_wait_clock, *(current->replay_thrd->rp_preplay_clock));
	while (tmp != current->replay_thrd) {
		MPRINT ("\tthread %d (recpid %d) status %d clock %ld - clock is %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock, *(current->replay_thrd->rp_preplay_clock));
		tmp = tmp->rp_next_thread;
	}
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
	MPRINT ("Pid %d ret_from_fork_replay\n", current->pid);
	ret = wait_event_interruptible_timeout (prept->rp_waitq, prept->rp_status == REPLAY_STATUS_RUNNING, SCHED_TO);
	if (ret == 0) printk ("Replay pid %d timed out waiting for cloned thread to go\n", current->pid);
	if (ret == -ERESTARTSYS) printk ("Pid %d: ret_from_fork_replay cannot wait due to signal - try again\n", current->pid);
	if (prept->rp_status != REPLAY_STATUS_RUNNING) {
		MPRINT ("Replay pid %d woken up during clone but not running.  We must want it to die\n", current->pid);
		sys_exit (0);
	}
	MPRINT ("Pid %d done with ret_from_fork_replay\n", current->pid);
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

void
reserve_memory (u_long addr, u_long len)
{
	struct reserved_mapping* pmapping, *nmapping;
	ds_list_iter_t* iter;
	ds_list_t* reserved_mem_list = NULL;

	if (current->record_thrd) {
		reserved_mem_list = current->record_thrd->rp_group->rg_reserved_mem_list;
	} else if (current->replay_thrd) {
		reserved_mem_list = current->replay_thrd->rp_record_thread->rp_group->rg_reserved_mem_list;
	} else {
		printk("Pid %d not a record/replay thread, can't reserve memory\n", current->pid);
		return;
	}

	BUG_ON(!reserved_mem_list);

	len = (len % PAGE_SIZE == 0) ? len : len - (len % PAGE_SIZE) + PAGE_SIZE; // pad to nearest page size
	MPRINT ("Inserting reserved memory from %lx to %lx\n", addr, addr+len);

	iter = ds_list_iter_create (reserved_mem_list);
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
					ds_list_remove (reserved_mem_list, nmapping);
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
	ds_list_insert (reserved_mem_list, pmapping);
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
preallocate_memory (struct record_group* prg)
{
	struct vm_area_struct* vma;
	ds_list_iter_t* iter;
	struct reserved_mapping* pmapping;
	u_long begin_at;

	iter = ds_list_iter_create (prg->rg_reserved_mem_list);
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

// Need to re-establish preallcoations (if needed) after a deallocation such as a munmap,
// in case that memory area is used again in the future
static void 
preallocate_after_munmap (u_long addr, u_long len)
{
	ds_list_iter_t* iter;
	struct reserved_mapping* pmapping;
	u_long begin, end;

	len = (len % PAGE_SIZE == 0) ? len : len - (len % PAGE_SIZE) + PAGE_SIZE; // pad to nearest page size
	MPRINT ("Re-allocating reserved memory as needed from %lx to %lx\n", addr, addr+len);

	iter = ds_list_iter_create (current->replay_thrd->rp_record_thread->rp_group->rg_reserved_mem_list);
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

static struct argsalloc_node* new_argsalloc_node (void* slab, size_t size)
{
	struct argsalloc_node* new_node;
	new_node = KMALLOC (sizeof(struct argsalloc_node), GFP_KERNEL);
	if (new_node == NULL) {
		printk ("new_argalloc_node: Cannot allocate struct argsalloc_node\n");
		return NULL;
	}

	new_node->head = slab;
	new_node->pos = slab;
	new_node->size = size;
	//new_node->list should be init'ed in the calling function

	return new_node;
}

/*
 * Adds another slab for args/retparams/signals allocation,
 * if no slab exists, then we create one */ 
static int add_argsalloc_node (struct record_thread* prect, void* slab, size_t size) { 
	struct argsalloc_node* new_node;
	new_node = new_argsalloc_node(slab, size);
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
	struct record_thread* prect = current->record_thrd;
	struct argsalloc_node* node;
	size_t asize;
	void* ptr;

	node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);

	// check to see if we've allocated a slab and if we have enough space left in the slab
	if (unlikely(list_empty(&prect->rp_argsalloc_list) || ((node->head + node->size - node->pos) < size))) {
		int rc;
		void* slab;

		MPRINT ("Pid %d argsalloc: not enough space left in slab, allocating new slab\n", current->pid);
		
		asize = (size > argsalloc_size) ? size : argsalloc_size;
		slab = VMALLOC(asize);
		if (slab == NULL) {
			printk ("Pid %d argsalloc: couldn't alloc slab with size %u\n", current->pid, asize);
			return NULL;
		}
		rc = add_argsalloc_node(current->record_thrd, slab, asize);
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

	return ptr;
}

/* Simplified method to return pointer to next data to consume on replay */
static char* 
argshead (struct record_thread* prect)
{
	struct argsalloc_node* node;
	node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
	if (unlikely(list_empty(&prect->rp_argsalloc_list))) {
		printk ("argshead: pid %d sanity check failed - no anc. data\n", current->pid);
		BUG();
	}
	return node->pos;
}

/* Simplified method to advance pointer on replay */
static void 
argsconsume (struct record_thread* prect, u_long size)
{
	struct argsalloc_node* node;
	node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
	if (unlikely(list_empty(&prect->rp_argsalloc_list))) {
		printk ("argsconsume: pid %d sanity check failed - no anc. data\n", current->pid);
		BUG();
	}
	if (unlikely (node->head + node->size - node->pos < size)) {
		printk ("argsconsume: pid %d sanity check failed - head %p size %lu pos %p size %lu\n", current->pid, node->head, (u_long) node->size, node->pos, size);
		BUG();
	}
	node->pos += size;
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

// Free all allocated data values at once
static void argsfreeall (struct record_thread* prect)
{
	struct argsalloc_node* node;
	struct argsalloc_node* next_node;

	list_for_each_entry_safe (node, next_node, &prect->rp_argsalloc_list, list) {
		VFREE(node->head);
		list_del(&node->list);
		KFREE(node);	
	}
}

// function to keep track of the sysv identifiers, since we always want to return the record identifier
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

unsigned long get_clock_value (void)
{
	if (current->replay_thrd) {
		struct replay_thread* prt = current->replay_thrd;
		if (prt->rp_preplay_clock) {
			return *(prt->rp_preplay_clock);
		} else {
			return -EINVAL;
		}
	} else if (current->record_thrd) {
		struct record_thread* prt = current->record_thrd;
		if (prt->rp_precord_clock) {
			return atomic_read(prt->rp_precord_clock);
		} else {
			return -EINVAL;
		}
	} else {
		printk ("get_clock_value called by a non-replay process\n");
		return -EINVAL;
	}
}
EXPORT_SYMBOL(get_clock_value);

long get_record_group_id (__u64* prg_id)
{
	if (current->record_thrd) {
		if (copy_to_user (prg_id, &current->record_thrd->rp_group->rg_id, sizeof(__u64))) {
			return -EINVAL;
		}
		return 0;
	} else if (current->replay_thrd) {
		if (copy_to_user (prg_id, &current->replay_thrd->rp_record_thread->rp_group->rg_id, sizeof(__u64))) {
			return -EINVAL;
		}
		return 0;
	}
	printk ("get_record_group_id called by a non-replay process\n");
	return -EINVAL;
}
EXPORT_SYMBOL(get_record_group_id);

long get_num_filemap_entries(int fd, loff_t offset, int size) {
	int num_entries = 0;
	struct file *filp;
	struct replayfs_filemap map;
	struct replayfs_filemap_entry* entry;

	filp = fget(fd);
	if (!filp) {
		return -EBADF;
	}
	replayfs_filemap_init(&map, &replayfs_alloc, filp);

	//printk("get filemap entries for fd %d offset %lld, size %d\n", fd, offset, size);
	entry = replayfs_filemap_read(&map, offset, size);
	if (IS_ERR(entry) || entry == NULL) {
		printk("get filemap can't find entry %p\n", entry);
		replayfs_filemap_destroy(&map);
		fput(filp);
		if (entry != NULL) {
			return PTR_ERR(entry);
		} 
		return -ENOMEM;
	}

	replayfs_filemap_destroy(&map);
	fput(filp);
	num_entries = entry->num_elms;
	//printk("get_num_filemap_entries is %d\n", num_entries);
	kfree(entry);

	return num_entries;
}
EXPORT_SYMBOL(get_num_filemap_entries);

long get_filemap(int fd, loff_t offset, int size, void __user* entries, int num_entries)
{
	int rc = 0;
	int i = 0;
	struct file *filp;
	struct replayfs_filemap map;
	struct replayfs_filemap_entry* entry;

	filp = fget(fd);
	if (!filp) {
		return -EBADF;
	}
	replayfs_filemap_init(&map, &replayfs_alloc, filp);

	entry = replayfs_filemap_read(&map, offset, size);
	if (IS_ERR(entry) || entry == NULL) {
		replayfs_filemap_destroy(&map);
		fput(filp);
		if (entry != NULL) {
			return PTR_ERR(entry);
		}
		return -ENOMEM;
	}

	replayfs_filemap_destroy(&map);
	fput(filp);

	// okay cool, walk the file map now
	for (i = 0; i < num_entries; i++) {
		struct replayfs_filemap_value* value;
		value = (entry->elms) + i;
		if (copy_to_user(entries + (i * sizeof(struct replayfs_filemap_value)), value, sizeof(struct replayfs_filemap_value))) {
			rc = -EFAULT;
			break;
		}
	}

	kfree(entry);
	return rc;
}
EXPORT_SYMBOL(get_filemap);

// For glibc hack - allocate and return the LD_LIBRARY_PATH env variable
static char* 
get_libpath (const char __user* const __user* env)
{
	const char __user *const __user *up;
	const char __user * pc;
	char tokbuf[16];
	char* retbuf;
	u_long len;

	up = env;
	do {
		if (get_user (pc, up)) {
			printk ("copy_args: invalid env value\n");
			return NULL;
		}
		if (pc == 0) break; // No more args
		if (strncpy_from_user (tokbuf, pc, sizeof(tokbuf)) != sizeof(tokbuf)) {
			up++;
			continue;
		}
		if (memcmp(tokbuf,"LD_LIBRARY_PATH=", sizeof(tokbuf))) {
			up++;
			continue;
		}
		len = strnlen_user(pc, 4096);
		if (len > 4096) {
			printk ("get_libpath: path too long\n");
			return NULL;
		}
		retbuf = KMALLOC (len, GFP_KERNEL);
		if (retbuf == NULL) {
			printk ("get_libpath cannot allocate buffer\n");
			return NULL;
		}
		if (copy_from_user (retbuf, pc, len)) {
			printk ("get_libpath cannot copy path from user\n");
			return NULL;
		}
		return retbuf;
	} while (1);

	return NULL;
}

// Checks to see if matching libpath is present in arg/env buffer - returns 0 if true, index if no match, -1 if not present
static int
is_libpath_present (struct record_group* prg, char* p)
{
	int cnt, i, len;

	// Skip args
	cnt = *((int *) p);
	p += sizeof(int);
	for (i = 0; i < cnt; i++) {
		len = *((int *) p);
		p += sizeof(int) + len;
	}

	cnt = *((int *) p);
	p += sizeof(int);
	for (i = 0; i < cnt; i++) {
		len = *((int *) p);
		if (strncmp(p+sizeof(int), "LD_LIBRARY_PATH=", 16) == 0) {
			DPRINT ("pid %d: libpath is %s\n", current->pid, (char *)(p+sizeof(int)));
			if (strcmp(p+sizeof(int), prg->rg_libpath) == 0) {
				DPRINT ("pid %d: libpath matches\n", current->pid);
				return 0; // match found
			}
			DPRINT ("pid %d: libpath does not match %d %d, return %d\n", current->pid, strlen(prg->rg_libpath)+1, len, i);
			return i; // libarary path there at this index but does not match
		}
		p += sizeof(int) + len;
	}
	DPRINT ("pid %d: libpath not found\n", current->pid);
	return -1; // library path not there at all
}

static char**
patch_for_libpath (struct record_group* prg, char* p, int present)
{
	int cnt, env_cnt, i, len;
	char** env;

	// Skip args
	cnt = *((int *) p);
	p += sizeof(int);
	for (i = 0; i < cnt; i++) {
		len = *((int *) p);
		p += sizeof(int) + len;
	}

	cnt = *((int *) p);
	p += sizeof(int);
	if (present < 0) {
		env_cnt = cnt+2;
	} else {
		env_cnt = cnt+1;
	}
	env = KMALLOC((env_cnt+1) * sizeof(char *), GFP_KERNEL);
	if (env == NULL) {
		printk ("patch_for_libpath: unable to allocate env struct\n");
		return NULL;
	}

	for (i = 0; i < cnt; i++) {
		len = *((int *) p);
		if (present == i) {
			env[i] = KMALLOC(strlen(prg->rg_libpath)+1, GFP_KERNEL);
			if (env[i] == NULL) {
				printk ("patch_for_libpath: unable to allocate new env\n");
				return NULL;
			}			
			strcpy(env[i], prg->rg_libpath);
			DPRINT ("pid %d: put libpath at index %d\n", current->pid, i);
		} else {
			env[i] = KMALLOC(len, GFP_KERNEL);
			if (env[i] == NULL) {
				printk ("patch_for_libpath: unable to allocate env. %d of length %d\n", i, len);
				return NULL;
			}
			strcpy(env[i], p+sizeof(int));
		}
		p += sizeof(int) + len;
	}
	if (present < 0) {
		DPRINT ("pid %d: put libpath at end\n", current->pid);
		env[i] = KMALLOC(strlen(prg->rg_libpath)+1, GFP_KERNEL);
		if (env[i] == NULL) {
			printk ("patch_for_libpath: unable to allocate new env\n");
			return NULL;
		}			
		strcpy(env[i], prg->rg_libpath);
		env[i+1] = NULL;
	} else {
		env[i] = NULL;
	}
	return env;
}

static char*
patch_buf_for_libpath (struct record_group* prg, char* buf, int* pbuflen, int present)
{
	int cnt, i, len, env_len = 0, skip_len = 0;
	char* p = buf, *newbuf;
	u_long buflen, newbuflen;

	// Figure out length
	cnt = *((int *) p);
	p += sizeof(int);
	for (i = 0; i < cnt; i++) {
		len = *((int *) p);
		p += sizeof(int) + len;
	}
	cnt = *((int *) p);
	if (present < 0) *((int *) p) = cnt+1; // adding one entry to end
	p += sizeof(int);
	for (i = 0; i < cnt; i++) {
		len = *((int *) p);
		if (present == i) {
			env_len = len;
			skip_len = (u_long) p - (u_long) buf;
		}
		p += sizeof(int) + len;
	}
	buflen = (u_long) p - (u_long) buf;
	if (present < 0) {
		newbuflen = buflen + sizeof(int) + strlen (prg->rg_libpath)+1;
	} else {
		newbuflen = buflen + strlen (prg->rg_libpath)+1 - env_len;
	}
	newbuf = KMALLOC(newbuflen, GFP_KERNEL);
	if (newbuf == NULL) {
		printk ("patch_buf_for_libpath: cannot allocate buffer of size %lu\n", newbuflen);
		return NULL;
	}
	if (present < 0) {
		memcpy (newbuf, buf, buflen);
		p = newbuf+buflen;
		*((int *) p) = strlen(prg->rg_libpath)+1;
		p += sizeof(int);
		strcpy (p, prg->rg_libpath);
	} else {
		memcpy (newbuf, buf, skip_len);
		p = newbuf+skip_len;
		*((int *) p) = strlen(prg->rg_libpath)+1;
		p += sizeof(int);
		strcpy (p, prg->rg_libpath);
		p += strlen(prg->rg_libpath)+1;
		memcpy (p, buf+skip_len+sizeof(int)+env_len, buflen-skip_len-sizeof(int)-env_len);
	}

	*pbuflen = newbuflen;
	return newbuf;
}

static void
libpath_env_free (char** env)
{
	int i = 0;

	while (env[i] != NULL) {
		KFREE(env[i]);
		i++;
	}
	KFREE(env);
}

/* This function forks off a separate process which replays the foreground task.*/
int fork_replay (char __user* logdir, const char __user *const __user *args, const char __user *const __user *env, char* linker, int save_mmap, int fd)
{
	struct record_group* prg;
	long retval;
	char ckpt[MAX_LOGDIR_STRLEN+10];
	const char __user * pc;
	char* filename;
	char* argbuf;
	int argbuflen;
	void* slab;

	MPRINT ("in fork_replay for pid %d\n", current->pid);
	if (current->record_thrd || current->replay_thrd) {
		printk ("fork_replay: pid %d cannot start a new recording while already recording or replaying\n", current->pid);
		return -EINVAL;
	}

	if (atomic_read (&current->mm->mm_users) > 1) {
		printk ("fork with multiple threads is not currently supported\n");
		return -EINVAL;
	}

	// Create a record_group structure for this task
	prg = new_record_group (NULL);
	if (prg == NULL) return -ENOMEM;

	current->record_thrd = new_record_thread(prg, current->pid, NULL);
	if (current->record_thrd == NULL) {
		destroy_record_group(prg);
		return -ENOMEM;
	}
	prg->rg_save_mmap_flag = save_mmap;

	// allocate a slab for retparams
	slab = VMALLOC (argsalloc_size);
	if (slab == NULL) return -ENOMEM;
	if (add_argsalloc_node(current->record_thrd, slab, argsalloc_size)) {
		VFREE (slab);
		destroy_record_group(prg);
		current->record_thrd = NULL;
		printk ("Pid %d fork_replay: error adding argsalloc_node\n", current->pid);
		return -ENOMEM;
	}
	MPRINT ("fork_replay added new slab %p to record_thread %p\n", slab, current->record_thrd);

	current->replay_thrd = NULL;
	MPRINT ("Record-Pid %d, tsk %p, prp %p\n", current->pid, current, current->record_thrd);

	if (linker) {
		strncpy (current->record_thrd->rp_group->rg_linker, linker, MAX_LOGDIR_STRLEN);
		MPRINT ("Set linker for record process to %s\n", linker);
	}

	if (fd >= 0) {
		retval = sys_close (fd);
		if (retval < 0) printk ("fork_replay: unable to close fd %d, rc=%ld\n", fd, retval);
	}

	sprintf (ckpt, "%s/ckpt", prg->rg_logdir);
	argbuf = copy_args (args, env, &argbuflen);
	if (argbuf == NULL) {
		printk ("replay_checkpoint_to_disk: copy_args failed\n");
		return -EFAULT;
	}

	// Finally do exec from which we should not return
	get_user (pc, args);
	filename = getname(pc);
	if (IS_ERR(filename)) {
		printk ("fork_replay: unable to copy exec filname\n");
		return -EINVAL;
	}

	// Save reduced-size checkpoint with info needed for exec
	retval = replay_checkpoint_to_disk (ckpt, filename, argbuf, argbuflen);
	if (retval) {
		printk ("replay_checkpoint_to_disk returns %ld\n", retval);
		return retval;
	}

	// Hack to support multiple glibcs - record and LD_LIBRARY_PATH info
	prg->rg_libpath = get_libpath (env);
	if (prg->rg_libpath == NULL) return -EINVAL;

	retval = record_execve (filename, args, env, get_pt_regs (NULL));
	if (retval) printk ("fork_replay: execve returns %ld\n", retval);
	return retval;
}

EXPORT_SYMBOL(fork_replay);

char*
get_linker (void)
{
	if (current->record_thrd) {
		MPRINT ("Get linker in record process: %s\n", current->record_thrd->rp_group->rg_linker);
		return current->record_thrd->rp_group->rg_linker;
	} else if (current->replay_thrd) {
		MPRINT ("Get linker from record process: %s\n", 
			current->replay_thrd->rp_group->rg_rec_group->rg_linker);
		return current->replay_thrd->rp_group->rg_rec_group->rg_linker;
	} else {
		printk ("Cannot get linker for non record/replay process\n");
		return NULL;
	}
}

long
replay_ckpt_wakeup (int attach_pin, char* logdir, char* linker, int fd, int follow_splits, int save_mmap)
{
	struct record_group* precg; 
	struct record_thread* prect;
	struct replay_group* prepg;
	struct replay_thread* prept;
	long record_pid, rc;
	char ckpt[MAX_LOGDIR_STRLEN+10];
	char** args;
	char** env;
	char* execname;
	__u64 rg_id;
	mm_segment_t old_fs = get_fs();
	
	MPRINT ("In replay_ckpt_wakeup\n");
	if (current->record_thrd || current->replay_thrd) {
		printk ("fork_replay: pid %d cannot start a new replay while already recording or replaying\n", current->pid);
		return -EINVAL;
	}

	// First create a record group and thread for this replay
	precg = new_record_group (logdir);
	if (precg == NULL) return -ENOMEM;
	precg->rg_save_mmap_flag = save_mmap;

	prect = new_record_thread(precg, 0, NULL);
	if (prect == NULL) {
		destroy_record_group(precg);
		return -ENOMEM;
	}

	prepg = new_replay_group (precg, follow_splits);
	if (prepg == NULL) {
		destroy_record_group(precg);
		return -ENOMEM;
	}

	prept = new_replay_thread (prepg, prect, current->pid, 0, NULL);
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

	record_pid = replay_resume_from_disk(ckpt, &execname, &args, &env, &rg_id);
	if (record_pid < 0) return record_pid;

	// Read in the log records 
	prect->rp_record_pid = record_pid;
	rc = read_log_data (prect);
	if (rc < 0) return rc;

	// Create a replay group and thread for this process
	current->replay_thrd = prept;
	current->record_thrd = NULL;

	MPRINT ("Pid %d set_record_group_id to %llu\n", current->pid, rg_id);
	current->replay_thrd->rp_record_thread->rp_group->rg_id = rg_id;

	if (linker) {
		strncpy (current->replay_thrd->rp_group->rg_rec_group->rg_linker, linker, MAX_LOGDIR_STRLEN);
		MPRINT ("Set linker for replay process to %s\n", linker);
	}

	// If pin, set the process to sleep, so that we can manually attach pin
	// We would then have to wake up the process after pin has been attached.
	if (attach_pin) {
		prept->app_syscall_addr = 1;  // Will be set to actual value later
		
		rc = read_mmap_log(precg);
		if (rc) {
			printk("replay_ckpt_wakeup: could not read memory log for Pin support\n");
			return rc;
		}
		preallocate_memory (precg); // Actually do the prealloaction for this process

		printk ("Pid %d sleeping in order to let you attach pin\n", current->pid);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}

	if (fd >= 0) {
		rc = sys_close (fd);
		if (rc < 0) printk ("replay_ckpt_wakeup: unable to close fd %d, rc=%ld\n", fd, rc);
	}

	set_fs(KERNEL_DS);
	rc = replay_execve (execname, (const char* const *) args, (const char* const *) env, get_pt_regs (NULL));
	set_fs(old_fs);
	if (rc < 0) printk ("replay_ckpt_wakeup: replay_execve of <%s> returns %ld\n", args[0], rc);
	return rc;
}
EXPORT_SYMBOL(replay_ckpt_wakeup);

static inline long
new_syscall_enter (long sysnum)
{
	struct syscall_result* psr;
	struct record_thread* prt = current->record_thrd;
	u_long new_clock, start_clock;
	u_long* p;

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
		write_and_free_kernel_log (prt);
		prt->rp_in_ptr = 0;
	}

	psr = &prt->rp_log[prt->rp_in_ptr]; 
	psr->sysnum = sysnum;
	new_clock = atomic_add_return (1, prt->rp_precord_clock);
	start_clock = new_clock - prt->rp_expected_clock - 1;
	if (start_clock == 0) {
		psr->flags = 0;
	} else {
		psr->flags = SR_HAS_START_CLOCK_SKIP;
		p = ARGSKMALLOC(sizeof(u_long), GFP_KERNEL);
		if (unlikely (p == NULL)) return -ENOMEM;
		*p = start_clock;
	}
	prt->rp_expected_clock = new_clock;
	MPRINT ("pid %d incremented clock to %d on syscall %ld enter\n", current->pid, atomic_read(prt->rp_precord_clock), sysnum);

#ifdef USE_HPC
	psr->hpc_begin = rdtsc(); // minus cc_calibration
#endif

	return 0;
}

long new_syscall_enter_external (long sysnum)
{
	return new_syscall_enter (sysnum);
}

static inline long
new_syscall_done (long sysnum, long retval) 
{
	struct syscall_result* psr;
	struct record_thread* prt = current->record_thrd;
	u_long new_clock, stop_clock;
	u_long* ulp;
	long *p;

	psr = &prt->rp_log[prt->rp_in_ptr];

	if (retval) {
		psr->flags |= SR_HAS_NONZERO_RETVAL;
		p = ARGSKMALLOC(sizeof(long), GFP_KERNEL);
		if (unlikely (p == NULL)) return -ENOMEM;
		*p = retval;
	} 

	new_clock = atomic_add_return (1, prt->rp_precord_clock);
	stop_clock = new_clock - prt->rp_expected_clock - 1;
	if (stop_clock) {
		psr->flags |= SR_HAS_STOP_CLOCK_SKIP;
		ulp = ARGSKMALLOC(sizeof(u_long), GFP_KERNEL);
		if (unlikely (ulp == NULL)) return -ENOMEM;
		*ulp = stop_clock;
	}
	prt->rp_expected_clock = new_clock;

	return 0;
}

static inline long
new_syscall_exit (long sysnum, void* retparams)
{
	struct syscall_result* psr;
	struct record_thread* prt = current->record_thrd;

	psr = &prt->rp_log[prt->rp_in_ptr];
	psr->flags = retparams ? (psr->flags | SR_HAS_RETPARAMS) : psr->flags;
#ifdef USE_HPC
	psr->hpc_end = rdtsc();
#endif
	if (unlikely(prt->rp_signals)) signal_wake_up (current, 0); // we want to deliver signals when this syscall exits

#ifdef MCPRINT
	if (replay_min_debug || replay_debug) {
		MPRINT ("Pid %d add syscall %d exit\n", current->pid, psr->sysnum);
	}
#endif
	prt->rp_in_ptr += 1;
	prt->rp_count += 1;
	return 0;
}

const char* replay_get_exec_filename (void) 
{
	MPRINT ("Got exec filename: %s\n", current->replay_thrd->rp_exec_filename);
	return current->replay_thrd->rp_exec_filename;
}

long new_syscall_exit_external (long sysnum, long retval, void* retparams)
{
	new_syscall_done (sysnum, retval);
	return new_syscall_exit (sysnum, retparams);
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
	MPRINT ("Delivering deferred signal now at %d\n", atomic_read(prt->rp_precord_clock));
	psignal = prt->rp_signals;
	prt->rp_signals = psignal->next;
	memcpy (info, &psignal->info, sizeof (siginfo_t));
	signr = psignal->signr;
	KFREE(psignal);

	return signr;
}

// Don't use standard debugging by default here because a printk could deadlock kernel
#define SIGPRINT(x,...)
//#define SIGPRINT printk

static int defer_signal (struct record_thread* prt, int signr, siginfo_t* info)
{
	struct repsignal* psignal = KMALLOC(sizeof(struct repsignal), GFP_ATOMIC); 
	if (psignal == NULL) {
		SIGPRINT ("Cannot allocate replay signal\n");
		return 0;  // Replay broken - but might as well let recording proceed
	}
	psignal->signr = signr;
	memcpy (&psignal->info, info, sizeof(siginfo_t));
	psignal->next = prt->rp_signals;
	prt->rp_signals = psignal;
	return -1;
}

// This is called with interrupts disabled so there is little we can do
// If signal is to be deferred, we do that since we can use atomic allocation.
// mcc: Called with current->sighand->siglock held and local interrupts disabled
long
check_signal_delivery (int signr, siginfo_t* info, struct k_sigaction* ka)
{
	struct record_thread* prt = current->record_thrd;
	int ignore_flag;
	int sysnum = syscall_get_nr(current, get_pt_regs(NULL));
	struct syscall_result* psr;

	if (prt->rp_in_ptr == 0) {
		SIGPRINT ("Pid %d - no syscall records yet - signal %d\n", current->pid, signr);
		if (sig_fatal(current, signr)) {
			SIGPRINT ("Fatal signal sent w/o recording - replay broken?\n");
			return 0; 
		}
		return defer_signal (prt, signr, info);
	}
	psr = &prt->rp_log[(prt->rp_in_ptr-1)]; 

	if (prt->rp_ignore_flag_addr) {
		get_user (ignore_flag, prt->rp_ignore_flag_addr);
	} else {
		ignore_flag = 0;
	}

        SIGPRINT ("Pid %d check signal delivery signr %d fatal %d - clock is currently %d ignore flag %d sysnum %d psr->sysnum %d handler %p\n", 
		  current->pid, signr, sig_fatal(current, signr), atomic_read(prt->rp_precord_clock), ignore_flag, sysnum, psr->sysnum, ka->sa.sa_handler);

	if (ignore_flag && sysnum >= 0) {
		return 0;
	} else if (!sig_fatal(current,signr) && sysnum != psr->sysnum && sysnum != 0 /* restarted syscall */) {
		// This is an unrecorded system call or a trap.  Since we cannot guarantee that the signal will not delivered
		// at this same place on replay, delay the delivery until we reach such a safe place.  Signals that immediately
		// terminate the program should not be delayed, however.
		SIGPRINT ("Pid %d: not a safe place to record a signal - syscall is %d but last recorded syscall is %d ignore flag %d\n", current->pid, sysnum, psr->sysnum, ignore_flag);
		return defer_signal (prt, signr, info);
	}
	return 0; // Will handle this signal later
}

// This is a signal that will actually be handled, we need to record it
long
record_signal_delivery (int signr, siginfo_t* info, struct k_sigaction* ka)
{
	struct record_thread* prt = current->record_thrd;
	struct repsignal* psignal;
	struct syscall_result* psr = &prt->rp_log[(prt->rp_in_ptr-1)]; 
	struct repsignal_context* pcontext;
	struct pthread_log_head* phead = (struct pthread_log_head __user *) prt->rp_user_log_addr;
	int ignore_flag, need_fake_calls = 1;
	int sysnum = syscall_get_nr(current, get_pt_regs(NULL));

	if (prt->rp_ignore_flag_addr) {
		get_user (ignore_flag, prt->rp_ignore_flag_addr);
	} else {
		ignore_flag = 0;
	}

        MPRINT ("Pid %d recording signal delivery signr %d fatal %d - clock is currently %d ignore flag %d sysnum %d psr->sysnum %d handler %p\n", 
		current->pid, signr, sig_fatal(current, signr), atomic_read(prt->rp_precord_clock), ignore_flag, sysnum, psr->sysnum, ka->sa.sa_handler);

	// Note that a negative sysnum means we entered kernel via trap, interrupt, etc.  It is not safe to deliver a signal here, even in the ignore region because
	// We might be in a user-level critical section where we are adding to the log.  Instead, defer and deliver later if possible.
	if (ignore_flag && sysnum >= 0) {
	  
		// Signal delivered after an ignored syscall.  We need to add a "fake" syscall for sequencing.  
		new_syscall_enter (SIGNAL_WHILE_SYSCALL_IGNORED); 
		new_syscall_done (SIGNAL_WHILE_SYSCALL_IGNORED, 0);
		new_syscall_exit (SIGNAL_WHILE_SYSCALL_IGNORED, NULL);
		psr = &prt->rp_log[(prt->rp_in_ptr-1)]; 

                // Also, let the user-level know to make syscall on replay by incrementing count in ignore_flag
		get_user (need_fake_calls, &phead->need_fake_calls);
		need_fake_calls++;
		put_user (need_fake_calls, &phead->need_fake_calls);
		MPRINT ("Pid %d record_signal inserts fake syscall - ignore_flag now %d, need_fake_calls now %d\n", current->pid, ignore_flag, need_fake_calls); 
	} else if (!sig_fatal(current,signr) && sysnum != psr->sysnum && sysnum != 0 /* restarted syscall */) {
		printk ("record_signal_delivery: this should have been handled!!!\n");
		return -1;
	}
	if (sig_fatal(current,signr) && sysnum != psr->sysnum && sysnum != 0 /* restarted syscall */) {
		struct pthread_log_head __user* phead = (struct pthread_log_head __user *) prt->rp_user_log_addr;
		// Sweet! There is always guaranteed to be allocated space for a record - also, we do not need to write out a full log since we are always the last record
#ifdef USE_DEBUG_LOG
		struct pthread_log_data __user* pdata;
		MPRINT ("Pid %d: after signal, user code will not run again, so the kernel needs to insert a fake call for replay\n", current->pid);
		get_user (pdata, &phead->next);
		if (pdata) {
			put_user (need_fake_calls, &pdata->retval); // Add the record - akin to what pthread_log.c in eglibc does
			put_user (FAKE_SYSCALLS, &pdata->type);
			pdata++;
			put_user (pdata, &phead->next);
			put_user (0, &phead->need_fake_calls);
		} else {
			printk ("record_signal_delivery: pid %d could not get head pointer\n", current->pid);
		}
#else
		char __user* pnext;
		unsigned long entry;

		MPRINT ("Pid %d: after signal, user code will not run again, so the kernel needs to insert a fake call for replay\n", current->pid);
		get_user (pnext, &phead->next);
		if (pnext) {
			get_user (entry, &phead->num_expected_records); 
			entry |= FAKE_CALLS_FLAG;
			put_user (entry, (u_long __user *) pnext);  
			pnext += sizeof(u_long);
			put_user (need_fake_calls, (int __user *) pnext);
			pnext += sizeof(int);
			put_user (pnext, &phead->next);
			put_user (0, &phead->num_expected_records);
			put_user (0, &phead->need_fake_calls);
		} else {
			printk ("record_signal_delivery: pid %d could not get head pointer\n", current->pid);
		}
#endif

		if (!ignore_flag) {
			// Also need the fake syscall
			new_syscall_enter (SIGNAL_WHILE_SYSCALL_IGNORED); 
			new_syscall_done (SIGNAL_WHILE_SYSCALL_IGNORED, 0);
			new_syscall_exit (SIGNAL_WHILE_SYSCALL_IGNORED, NULL);
			psr = &prt->rp_log[(prt->rp_in_ptr-1)]; 
		}
	}

	MPRINT ("Pid %d: recording and delivering signal\n", current->pid);

	psignal = ARGSKMALLOC(sizeof(struct repsignal), GFP_KERNEL); 
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
	if ((psr->flags&SR_HAS_SIGNAL) == 0) {
		psr->flags |= SR_HAS_SIGNAL;
	} else {
		prt->rp_last_signal->next = psignal;
	}
	prt->rp_last_signal = psignal;

	if (ka->sa.sa_handler > SIG_IGN) {
		// Also save context from before signal
		pcontext = KMALLOC (sizeof(struct repsignal_context), GFP_ATOMIC);
		pcontext->ignore_flag = ignore_flag;
		pcontext->next = prt->rp_repsignal_context_stack;
		prt->rp_repsignal_context_stack = pcontext;
		// If we were in an ignore region, that is no longer the case
		if (prt->rp_ignore_flag_addr) put_user (0, prt->rp_ignore_flag_addr); 
	}

	return 0;
}

void
replay_signal_delivery (int* signr, siginfo_t* info)
{
	struct replay_thread* prt = current->replay_thrd;
	struct repsignal* psignal;
	
	if (!prt->rp_signals) {
		MPRINT ("pid %d replay_signal called but no signals, signr is %d\n", current->pid, *signr);
		*signr = 0;
		return;
	}
	psignal = (struct repsignal *) argshead (prt->rp_record_thread);
	argsconsume (prt->rp_record_thread, sizeof(struct repsignal));

	MPRINT ("Pid %d replaying signal delivery signo %d, clock %lu\n", current->pid, psignal->signr, *(prt->rp_preplay_clock));
	prt->rp_signals = psignal->next ? 1 : 0;

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
			DPRINT ("safe to return pending signal\n");
			return 1;
		}
	}
	return 0;
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
	file = init_log_write (prect, &pos, &fd);
	if (file) {
		write_psr = &prect->rp_log[0];
		write_log_data (file, &pos, prect, write_psr, prect->rp_in_ptr);
		term_log_write (file, fd);
	}
	set_fs(old_fs);

	argsfreeall (prect);
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
	file = init_log_write (prect, &pos, &fd);
	if (file) {
		MPRINT ("Writing %lu records for pid %d\n", prect->rp_in_ptr, current->pid);
		write_psr = &prect->rp_log[0];
		write_log_data (file, &pos, prect, write_psr, prect->rp_in_ptr);
		term_log_write (file, fd);
	}
	set_fs(old_fs);

	argsfreeall (prect);
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
	u_long next;
	char __user *start;
	struct stat64 st;
	char filename[MAX_LOGDIR_STRLEN+20];
	struct file* file;
	int fd;
	mm_segment_t old_fs;
	long to_write, written;
	long rc = 0;

	DPRINT ("Pid %d: write_user_log %p\n", current->pid, phead);
	if (phead == 0) return 0; // Nothing to do

	if (copy_from_user (&next, &phead->next, sizeof(u_long))) {
		printk ("Pid %d: unable to get log head next ptr\n", current->pid);
		return -EINVAL;
	}
	DPRINT ("Pid %d: log current address is at %lx\n", current->pid, next); 
	start = (char __user *) phead + sizeof (struct pthread_log_head);
	to_write = (char *) next - start;
	MPRINT ("Pid %d - need to write %ld bytes of user log\n", current->pid, to_write);
	if (to_write == 0) {
		MPRINT ("Pid %d - no entries to write in ulog\n", current->pid);
		return 0;
	}

	sprintf (filename, "%s/ulog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	// see if we're appending to the user log data before
	if (prect->rp_ulog_opened) {
		DPRINT ("Pid %d, ulog %s has been opened before, so we'll append\n", current->pid, filename);
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

	// Before each user log segment, we write the number of bytes in the segment
	written = vfs_write(file, (char *) &to_write, sizeof(int), &prect->rp_read_ulog_pos);
	set_fs(old_fs);

	if (written != sizeof(int)) {
		printk ("write_user_log: tried to write %d, got rc %ld\n", sizeof(int), written);
		rc = -EINVAL;
	}

	written = vfs_write(file, start, to_write, &prect->rp_read_ulog_pos);
	if (written != to_write) {
		printk ("write_user_log1: tried to write %ld, got rc %ld\n", to_write, written);
		rc = -EINVAL;
	}

	fput(file);
	DPRINT("Pid %d closing %s\n", current->pid, filename);
	sys_close (fd);

	// We reset the next pointer to reflect the records that were written
	// In some circumstances such as failed execs, this will prevent dup. writes
#ifdef USE_DEBUG_LOG
	next = (u_long) ((char __user *) phead + sizeof (struct pthread_log_head));
#else
	next = (u_long) phead + sizeof (struct pthread_log_head);
#endif
	if (copy_to_user (&phead->next, &next, sizeof (u_long))) {
		printk ("Unable to put log head next\n");
		return -EINVAL;
	}

	DPRINT ("Pid %d: log current address is at %lx\n", current->pid, next); 

	return rc;
}

/* Reads in a user log - currently does not handle wraparound - so read in one big chunk */
long
read_user_log (struct record_thread* prect)
{
	struct pthread_log_head __user * phead = (struct pthread_log_head __user *) prect->rp_user_log_addr;
	char __user *start;
	struct stat64 st;
	char filename[MAX_LOGDIR_STRLEN+20];
	struct file* file;
	int fd;
	mm_segment_t old_fs;
	long copyed, rc = 0;

	// the number of entries in this segment
	int num_bytes;

	DPRINT ("Pid %d: read_user_log %p\n", current->pid, phead);
	if (phead == 0) return -EINVAL; // Nothing to do

	start = (char __user *) phead + sizeof (struct pthread_log_head);
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
	copyed = vfs_read (file, (char *) &num_bytes, sizeof(int), &prect->rp_read_ulog_pos);
	set_fs(old_fs);
	if (copyed != sizeof(int)) {
		printk ("read_user_log: tried to read num entries %d, got rc %ld\n", sizeof(int), copyed);
		rc = -EINVAL;
		goto close_out;
	}

	// read the entire segment after we've read how many entries are in it
	copyed = vfs_read (file, (char __user *) start, num_bytes, &prect->rp_read_ulog_pos);
	if (copyed != num_bytes) {
		printk ("read_user_log: tried to read %d, got rc %ld\n", num_bytes, copyed);
		rc = -EINVAL;
	} else {
		DPRINT ("Pid %d read %ld bytes from user log\n", current->pid, copyed);
		put_user (start+copyed, (char **) &phead->end);
	}
		

close_out:
	fput(file);
	sys_close (fd);

	return rc;
}

#ifdef USE_EXTRA_DEBUG_LOG
/* Writes out the user log - currently does not handle wraparound - so write in one big chunk */
long
write_user_extra_log (struct record_thread* prect)
{
	struct pthread_extra_log_head __user * phead = (struct pthread_extra_log_head __user *) prect->rp_user_extra_log_addr;
	struct pthread_extra_log_head head;
	char __user *start;
	struct stat64 st;
	char filename[MAX_LOGDIR_STRLEN+20];
	struct file* file;
	int fd;
	mm_segment_t old_fs;
	long to_write, written;
	long rc = 0;

	DPRINT ("Pid %d: write_user_extra_log %p\n", current->pid, phead);
	if (phead == 0) return 0; // Nothing to do

	if (copy_from_user (&head, phead, sizeof (struct pthread_extra_log_head))) {
		printk ("Pid %d: unable to get extra log head\n", current->pid);
		return -EINVAL;
	}
	DPRINT ("Pid %d: extra log current address is at %p\n", current->pid, head.next); 
	start = (char __user *) phead + sizeof (struct pthread_extra_log_head);
	to_write = (char *) head.next - start;
	MPRINT ("Pid %d - need to write %ld bytes of user extra log\n", current->pid, to_write);
	if (to_write == 0) {
		MPRINT ("Pid %d - no entries to write in extra user log\n", current->pid);
		return 0;
	}

	sprintf (filename, "%s/elog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	// see if we're appending to the user log data before
	if (prect->rp_elog_opened) {
		DPRINT ("Pid %d, extra log %s has been opened before, so we'll append\n", current->pid, filename);
		rc = sys_stat64(filename, &st);
		if (rc < 0) {
			printk ("Pid %d - write_extra_log_data, can't append stat of file %s failed\n", current->pid, filename);
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
		prect->rp_elog_opened = 1;
		rc = sys_stat64(filename, &st);
	}

	if (fd < 0) {
		printk ("Cannot open exta log file %s, rc =%d\n", filename, fd);
		return -EINVAL;
	}

	file = fget(fd);
	if (file == NULL) {
		printk ("write_extra_user_log: invalid file\n");
		return -EINVAL;
	}

	// Before each user log segment, we write the number of bytes in the segment
	written = vfs_write(file, (char *) &to_write, sizeof(int), &prect->rp_read_elog_pos);
	set_fs(old_fs);

	if (written != sizeof(int)) {
		printk ("write_user_log: tried to write %d, got rc %ld\n", sizeof(int), written);
		rc = -EINVAL;
	}

	written = vfs_write(file, start, to_write, &prect->rp_read_elog_pos);
	if (written != to_write) {
		printk ("write_extra_user_log1: tried to write %ld, got rc %ld\n", to_write, written);
		rc = -EINVAL;
	}

	fput(file);
	DPRINT("Pid %d closing %s\n", current->pid, filename);
	sys_close (fd);

	// We reset the next pointer to reflect the records that were written
	// In some circumstances such as failed execs, this will prevent dup. writes
	head.next = (char __user *) phead + sizeof (struct pthread_extra_log_head);

	if (copy_to_user (phead, &head, sizeof (struct pthread_extra_log_head))) {
		printk ("Unable to put extra log head\n");
		return -EINVAL;
	}

	DPRINT ("Pid %d: log extra current address is at %p\n", current->pid, head.next); 

	return rc;
}

/* Reads in a user log - currently does not handle wraparound - so read in one big chunk */
long
read_user_extra_log (struct record_thread* prect)
{
	struct pthread_extra_log_head* phead = (struct pthread_extra_log_head __user *) prect->rp_user_extra_log_addr;
	char __user *start;
	struct stat64 st;
	char filename[MAX_LOGDIR_STRLEN+20];
	struct file* file;
	int fd;
	mm_segment_t old_fs;
	long copyed, rc = 0;

	// the number of entries in this segment
	int num_bytes;

	printk ("Pid %d: read_user_extra_log %p\n", current->pid, phead);
	if (phead == 0) return -EINVAL; // Nothing to do

	start = (char __user *) phead + sizeof (struct pthread_extra_log_head);
	DPRINT ("Extra log start is at %p\n", start);
	
	sprintf (filename, "%s/elog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);
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
		printk ("Cannot open extra log file %s, rc =%d\n", filename, fd);
		return fd;
	}

	file = fget(fd);
	if (file == NULL) {
		printk ("read_user_extra_log: invalid file\n");
		return -EINVAL;
	}

	// read how many entries that are in this segment
	set_fs(KERNEL_DS);	
	copyed = vfs_read (file, (char *) &num_bytes, sizeof(int), &prect->rp_read_elog_pos);
	set_fs(old_fs);
	if (copyed != sizeof(int)) {
		printk ("read_extra_user_log: tried to read num entries %d, got rc %ld\n", sizeof(int), copyed);
		rc = -EINVAL;
		goto close_out;
	}

	// read the entire segment after we've read how many entries are in it
	copyed = vfs_read (file, (char __user *) start, num_bytes, &prect->rp_read_elog_pos);
	if (copyed != num_bytes) {
		printk ("read_user_extra_log: tried to read %d, got rc %ld\n", num_bytes, copyed);
		rc = -EINVAL;
	} else {	
		DPRINT ("Pid %d read %ld bytes from extra log\n", current->pid, copyed);
		put_user (start+copyed, &phead->end);
	}

close_out:
	fput(file);
	sys_close (fd);

	return rc;
}
#endif

/* Used for Pin support. 
 * We need to consume syscall log entries in a specific order
 * on exit after a SIGTRAP */
static inline long
get_next_clock (struct replay_thread* prt, struct replay_group* prg, long wait_clock_value)
{
	struct replay_thread* tmp;
	long retval = 0;
	int ret;

	while (*(prt->rp_preplay_clock) < wait_clock_value) {
		MPRINT ("Replay pid %d is waiting for clock value %ld, current clock value is %ld\n", current->pid, wait_clock_value, *(prt->rp_preplay_clock));
		prt->rp_status = REPLAY_STATUS_WAIT_CLOCK;
		prt->rp_wait_clock = wait_clock_value;

		tmp = prt->rp_next_thread;
		do {
			MPRINT ("Consider thread %d status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock);
			if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= *(prt->rp_preplay_clock))) {
				tmp->rp_status = REPLAY_STATUS_RUNNING;
				wake_up (&tmp->rp_waitq);
				DPRINT ("Wake it up\n");
				break;
			}
			tmp = tmp->rp_next_thread;
			if (tmp == prt) {
				if (prt->rp_pin_restart_syscall) {
					printk("Pid %d: This was a restarted syscall entry, let's sleep and try again\n", current->pid);
					msleep(1000);
					break;
				}
				printk ("Pid %d (recpid %d): Crud! no elgible thread to run\n", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid);
				printk ("current clock value is %ld waiting for %lu\n", *(prt->rp_preplay_clock), wait_clock_value);
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
			MPRINT ("Replay pid %d waiting for clock value %ld but current clock value is %ld\n", current->pid, wait_clock_value, *(prt->rp_preplay_clock));
			rg_unlock (prg->rg_rec_group);
			ret = wait_event_interruptible_timeout (prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prt->rp_record_thread->rp_in_ptr == prt->rp_out_ptr+1), SCHED_TO);
			rg_lock (prg->rg_rec_group);
			if (ret == 0) printk ("Replay pid %d timed out waiting for clock value %ld but current clock value is %ld\n", current->pid, wait_clock_value, *(prt->rp_preplay_clock));
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
        MPRINT ("Pid %d incremented replay clock to %ld\n", current->pid, *(prt->rp_preplay_clock));
	return retval;
}

static inline long
get_next_syscall_enter (struct replay_thread* prt, struct replay_group* prg, int syscall, char** ppretparams, struct syscall_result** ppsr)
{
	struct syscall_result* psr;
	struct replay_thread* tmp;
	struct record_thread* prect = prt->rp_record_thread;
	u_long start_clock;
	u_long* pclock;
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
		MPRINT ("Pid %d We are just trying to exit after a replay foul-up - just die\n", current->pid);
		*ppsr = NULL; // Lets caller know to skip the exit call.
		rg_unlock (prg->rg_rec_group);
		return 0;
	}

	while (prect->rp_in_ptr == prt->rp_out_ptr) {
		if (syscall == TID_WAKE_CALL) {
			// We did not record an exit so there is no record to consume - just ignore this and let the thread exit
			MPRINT ("pid %d recpid %d syscall mismatch during exit is OK - no more syscalls found\n", current->pid, prect->rp_record_pid);
			*ppsr = NULL; // Lets caller know to skip the exit call.
			rg_unlock (prg->rg_rec_group);
			return 0;
		}
		// log overflowed and we need to read in next batch of records
		MPRINT ("Pid %d recpid %d syscall %d reached end of in-memory log -- free previous syscall records and rad in new ones\n", current->pid, prect->rp_record_pid, syscall);
		argsfreeall (prect);
		prect->rp_in_ptr = 0;
		read_log_data (prect);
		if (prect->rp_in_ptr == 0) {
			// There should be one record there at least
			printk ("Pid %d waiting for non-existant syscall record %d - recording not synced yet??? \n", current->pid, syscall);
			__syscall_mismatch(prg->rg_rec_group);
		}
		prt->rp_out_ptr = 0;
	}

	psr = &prect->rp_log[prt->rp_out_ptr];

	MPRINT ("Replay Pid %d, index %ld sys %d\n", current->pid, prt->rp_out_ptr, psr->sysnum);

	start_clock = prt->rp_expected_clock;
	if (psr->flags & SR_HAS_START_CLOCK_SKIP) {
		pclock = (u_long *) argshead(prect);
		argsconsume(prect, sizeof(u_long));
		start_clock += *pclock;
	}
	prt->rp_expected_clock = start_clock + 1;
	// Pin can interrupt, so we need to save the start clock in case we need to resume
	prt->rp_start_clock_save = start_clock;

	if (unlikely(psr->sysnum != syscall)) {
		if (psr->sysnum == SIGNAL_WHILE_SYSCALL_IGNORED && prect->rp_in_ptr == prt->rp_out_ptr+1) {
			printk ("last record is apparently for a terminal signal - we'll just proceed anyway\n");
		} else {
			printk ("[ERROR]Pid  %d record pid %d expected syscall %d in log, got %d, start clock %ld\n", 
				current->pid, prect->rp_record_pid, syscall, psr->sysnum, start_clock);
			dump_stack();
			__syscall_mismatch (prg->rg_rec_group);
		}
	}

	if ((psr->flags & SR_HAS_NONZERO_RETVAL) == 0) {
		retval = 0;
	} else {
		retval = *((long *) argshead(prect));
		argsconsume(prect, sizeof(long));
	}
	MPRINT ("Replay Pid %d, index %ld sys %d retval %ld\n", current->pid, prt->rp_out_ptr, psr->sysnum, retval);

	// Pin can interrupt, so we need to save the stop clock in case we need to resume
	prt->rp_stop_clock_save = prt->rp_expected_clock;
	if (psr->flags & SR_HAS_STOP_CLOCK_SKIP) { // Nead to read this in exactly this order but use it later
		prt->rp_stop_clock_skip = *((u_long *) argshead(prect));
		MPRINT ("Stop clock skip is %lu\n", prt->rp_stop_clock_skip);
		argsconsume(prect, sizeof(u_long));
		prt->rp_stop_clock_save += prt->rp_stop_clock_skip;
	}

	if (ppretparams) {
		if (psr->flags & SR_HAS_RETPARAMS) {
			*ppretparams = argshead(prect);
		} else {
			*ppretparams = NULL;
		}
	} else if (unlikely((psr->flags & SR_HAS_RETPARAMS) != 0)) {
		printk ("[ERROR]Pid %d record pid %d not expecting return parameters, syscall %d start clock %ld\n", 
			current->pid, prect->rp_record_pid, syscall, start_clock);
		__syscall_mismatch (prg->rg_rec_group);
	}

	// Done with syscall record 
	prt->rp_out_ptr += 1;

	// Do this twice - once for syscall entry and once for exit
	while (*(prt->rp_preplay_clock) < start_clock) {
		MPRINT ("Replay pid %d is waiting for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, start_clock, *(prt->rp_preplay_clock));
		prt->rp_status = REPLAY_STATUS_WAIT_CLOCK;
		prt->rp_wait_clock = start_clock;
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
				printk ("Pid %d (recpid %d): Crud! no elgible thread to run on syscall entry\n", current->pid, prect->rp_record_pid);
				printk ("current clock value is %ld waiting for %lu\n", *(prt->rp_preplay_clock), start_clock);
				dump_stack(); // how did we get here?
				// cycle around again and print
				tmp = tmp->rp_next_thread;
				while (tmp != current->replay_thrd) {
					printk("\t thread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
					tmp = tmp->rp_next_thread;
				}
				__syscall_mismatch (prg->rg_rec_group);
			}
		} while (tmp != prt);

		while (!(prt->rp_status == REPLAY_STATUS_RUNNING || (prt->rp_replay_exit && prect->rp_in_ptr == prt->rp_out_ptr+1))) {	
			MPRINT ("Replay pid %d waiting for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, start_clock, *(prt->rp_preplay_clock));
			rg_unlock (prg->rg_rec_group);
			ret = wait_event_interruptible_timeout (prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prect->rp_in_ptr == prt->rp_out_ptr+1), SCHED_TO);
			rg_lock (prg->rg_rec_group);
			if (ret == 0) printk ("Replay pid %d timed out waiting for clock value %ld on syscall entry but current clock value is %ld\n", current->pid, start_clock, *(prt->rp_preplay_clock));
			if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prect->rp_in_ptr == prt->rp_out_ptr+1))) {
				MPRINT ("Replay pid %d woken up to die on entrance in_ptr %lu out_ptr %lu\n", current->pid, prect->rp_in_ptr, prt->rp_out_ptr);
				rg_unlock (prg->rg_rec_group);
				sys_exit (0);
			}
			if (ret == -ERESTARTSYS) {
				/*
				 * We need to make sure we exit threads in the right order if Pin is attached.
				 * If Pin is attached, interupt the system call and return back to Pin. 
				 * Pin will proceed and handle the SIGTRAP. 
				 * Pin will then trap back into the kernel, where we then increment the clock 
				 * and end the syscall.
				 *
				 * Certain system calls, we need to be more lax with though and 
				 * simply wait for Pin to finish, such as exec and clone.
				 */
				if (is_pin_attached() && (syscall != 11 || syscall != 120)) {
					MPRINT ("Pid %d -- Pin attached -- enterting syscall cannot wait due to signal, would try again but Pin is attaached. exiting with ERESTART\n", current->pid);
					prt->rp_saved_psr = psr;
					prt->rp_pin_restart_syscall = REPLAY_PIN_TRAP_STATUS_ENTER;
					rg_unlock (prg->rg_rec_group);
					return -ERESTART_RESTARTBLOCK;
				}

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

static inline long
get_next_syscall_exit (struct replay_thread* prt, struct replay_group* prg, struct syscall_result* psr)
{
	struct record_thread* prect = prt->rp_record_thread;
	struct replay_thread* tmp;
	int ret;
	u_long stop_clock;

	BUG_ON (!psr);

	stop_clock = prt->rp_expected_clock;
	if (psr->flags & SR_HAS_STOP_CLOCK_SKIP) stop_clock += prt->rp_stop_clock_skip;
	prt->rp_expected_clock = stop_clock + 1;

	rg_lock (prg->rg_rec_group);
	while (*(prt->rp_preplay_clock) < stop_clock) {
		MPRINT ("Replay pid %d is waiting for clock value %ld on syscall exit but current clock value is %ld\n", current->pid, stop_clock, *(prt->rp_preplay_clock));
		prt->rp_status = REPLAY_STATUS_WAIT_CLOCK;
		prt->rp_wait_clock = stop_clock;
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
				printk ("replay pid %d waiting for clock value on syscall exit - current clock value is %ld\n", current->pid, *(prt->rp_preplay_clock));
				if (prt->rp_pin_restart_syscall) {
					printk("Pid %d: This was a restarted syscall exit, let's sleep and try again\n", current->pid);
					msleep(1000);
					break;
				}
				printk ("replay pid %d waiting for clock value %ld on syscall exit - current clock value is %ld\n", current->pid, stop_clock, *(prt->rp_preplay_clock));
				sys_exit_group (0);
			}
		} while (tmp != prt);

		while (!(prt->rp_status == REPLAY_STATUS_RUNNING || (prt->rp_replay_exit && prect->rp_in_ptr == prt->rp_out_ptr+1))) {   
			MPRINT ("Replay pid %d waiting for clock value %ld on syscall exit but current clock value is %ld\n", current->pid, stop_clock, *(prt->rp_preplay_clock));
			rg_unlock (prg->rg_rec_group);
			ret = wait_event_interruptible_timeout (prt->rp_waitq, prt->rp_status == REPLAY_STATUS_RUNNING || prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && prect->rp_in_ptr == prt->rp_out_ptr+1), SCHED_TO);
			rg_lock (prg->rg_rec_group);
			if (ret == 0) printk ("Replay pid %d timed out waiting for clock value %ld on syscall exit but current clock value is %ld\n", current->pid, stop_clock, *(prt->rp_preplay_clock));
			if (prg->rg_rec_group->rg_mismatch_flag || (prt->rp_replay_exit && (prect->rp_in_ptr == prt->rp_out_ptr+1))) {
				rg_unlock (prg->rg_rec_group);
				MPRINT ("Replay pid %d woken up to die on exit\n", current->pid);
				sys_exit (0);
			}
			if (ret == -ERESTARTSYS) {
				/* Pin SIGTRAP interrupted a syscall exit, SIGTRAP is also used by
				 *  Pin to reattach after exec, so we need to ignore exec and just wait */
				if (is_pin_attached() && (psr->sysnum != 11 || psr->sysnum != 120)) {
					MPRINT ("Pid %d: exiting syscall cannot wait due to signal - try again, but pin is attached, exiting with ERESTART\n", current->pid);
					prt->rp_saved_psr = psr;
					if (prt->rp_pin_restart_syscall != REPLAY_PIN_TRAP_STATUS_ENTER) {
						prt->rp_pin_restart_syscall = REPLAY_PIN_TRAP_STATUS_EXIT;
					}
					rg_unlock (prg->rg_rec_group);
					return -ERESTART_RESTARTBLOCK;
				}

				printk ("Pid %d: exiting syscall cannot wait due to signal w/clock %lu - try again\n", current->pid, *(prt->rp_preplay_clock));
				print_replay_threads();
				rg_unlock (prg->rg_rec_group);
				msleep (1000);
				rg_lock (prg->rg_rec_group);
			}
		}
	}

	if (unlikely((psr->flags & SR_HAS_SIGNAL) != 0)) {
		MPRINT ("Pid %d set deliver signal flag before clock %ld increment\n", current->pid, *(prt->rp_preplay_clock));
		prt->rp_signals = 1;
		signal_wake_up (current, 0);
	}

	(*prt->rp_preplay_clock)++;
	MPRINT ("Pid %d incremented replay clock on syscall %d exit to %ld\n", current->pid, psr->sysnum, *(prt->rp_preplay_clock));
	prect->rp_count += 1;

	rg_unlock (prg->rg_rec_group);
	return 0;
}

long
get_next_syscall_enter_external (int syscall, char** ppretparams, struct syscall_result** ppsr)
{
	return get_next_syscall_enter (current->replay_thrd, current->replay_thrd->rp_group, syscall, ppretparams, ppsr);
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
get_next_syscall (int syscall, char** ppretparams)
{
	struct replay_thread* prt = current->replay_thrd;
	struct replay_group* prg = prt->rp_group;
	struct syscall_result* psr;
	long retval;
	long exit_retval;

	retval = get_next_syscall_enter (prt, prg, syscall, ppretparams, &psr);

	// Needed to exit the threads in the correct order with Pin attached.
	// Essentially, return to Pin after Pin interrupts the syscall with a SIGTRAP.
	// The thread will then begin to exit. recplay_exit_start will exit the threads
	// in the correct order
	if (is_pin_attached() && prt->rp_pin_restart_syscall == REPLAY_PIN_TRAP_STATUS_ENTER) {
		prt->rp_saved_rc = retval;
		return retval;
	}

	exit_retval = get_next_syscall_exit (prt, prg, psr);

	// Reset Pin syscall address value to 0 at the end of the system call
	// This is required to differentiate between syscalls when
	// Pin issues the same syscall immediately after the app
	if (is_pin_attached()) {
		if ((*(int*)(prt->app_syscall_addr)) != 999) {
			(*(int*)(prt->app_syscall_addr)) = 0;
		}
	}

	// Need to return restart back to Pin so it knows to continue
	if ((exit_retval == -ERESTART_RESTARTBLOCK) && is_pin_attached()) {
		prt->rp_saved_rc = retval;
		return exit_retval;
	}

	return retval;
}

void consume_remaining_records (void)
{
	struct syscall_result* psr;
	struct replay_thread* prt = current->replay_thrd;
	char* tmp;

	while (prt->rp_record_thread->rp_in_ptr != prt->rp_out_ptr) {
		psr = &prt->rp_record_thread->rp_log[prt->rp_out_ptr];
		MPRINT ("Pid %d recpid %d consuming unused record: sysnum %d\n", current->pid, prt->rp_record_thread->rp_record_pid, psr->sysnum);
		get_next_syscall (psr->sysnum, &tmp);
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

// only one for now - likely more though
void record_execval (int uid, int euid, int gid, int egid, int secureexec)
{
	current->record_thrd->exec_values.uid = uid;
	current->record_thrd->exec_values.euid = euid;
	current->record_thrd->exec_values.gid = gid;
	current->record_thrd->exec_values.egid = egid;
	current->record_thrd->exec_values.secureexec = secureexec;
}

void replay_execval (int* uid, int* euid, int* gid, int* egid, int* secureexec)
{
	*uid = current->replay_thrd->exec_values.uid;
	*euid = current->replay_thrd->exec_values.euid;
	*gid = current->replay_thrd->exec_values.gid;
	*egid = current->replay_thrd->exec_values.egid;
	*secureexec = current->replay_thrd->exec_values.secureexec;
	MPRINT ("In %s\n", __func__);
}

unsigned long get_replay_args(void)
{       
	if (current->replay_thrd) {
		return current->replay_thrd->argv;
	} else {
		printk("Pid %d, no args start on non-replay\n", current->pid);
		return 0;
	}
}
EXPORT_SYMBOL(get_replay_args);

unsigned long get_env_vars(void)
{
	if (current->replay_thrd) {
		return current->replay_thrd->envp;
	} else {
		printk("Pid %d, no env vars on non-replay\n", current->pid);
		return 0;
	}
}
EXPORT_SYMBOL(get_env_vars);

void save_exec_args (unsigned long argv, int argc, unsigned long envp, int envc)
{
	if (current->replay_thrd) {
		struct replay_thread* prt = current->replay_thrd;
		prt->argv = argv;
		prt->argc = argc;
		prt->envp = envp;
		prt->envc = envc;
		MPRINT ("In %s\n", __func__);
	}
	return;
}

/* These functions check the clock condition before and after a syscall, respectively.  We have to do this for syscalls for which
   Pin holds a lock throughout to avoid a deadlock. */
long check_clock_before_syscall (int syscall)
{
	struct replay_thread* prt = current->replay_thrd;
	int ignore_flag;

	// This should block until it is time to execute the syscall.  We must save the returned values for use in the actual system call
	DPRINT ("Pid %d pre-wait for syscall %d\n", current->pid, syscall);

	if (prt->rp_record_thread->rp_ignore_flag_addr) {
		get_user (ignore_flag, prt->rp_record_thread->rp_ignore_flag_addr);
	} else {
		ignore_flag = 0;
	}
	if (!ignore_flag) {						
		prt->rp_saved_rc = get_next_syscall_enter (prt, prt->rp_group, syscall, &prt->rp_saved_retparams, &prt->rp_saved_psr);
	}

	return 0;
}
EXPORT_SYMBOL(check_clock_before_syscall);

#ifdef REPLAY_STATS
long
get_replay_stats (struct replay_stats __user * ustats)
{
	if (copy_to_user (ustats, &rstats, sizeof(struct replay_stats))) {
		return -EFAULT;
	} 
	return 0;
}
EXPORT_SYMBOL(get_replay_stats);
#endif

long check_clock_after_syscall (int syscall)
{
	struct replay_thread* prt = current->replay_thrd;
	int ignore_flag;

	if (prt->rp_record_thread->rp_ignore_flag_addr) {
		get_user (ignore_flag, prt->rp_record_thread->rp_ignore_flag_addr);
	} else {
		ignore_flag = 0;
	}
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
	DPRINT ("Pid %d post-wait for syscall for syscall %d\n", current->pid, prt->rp_saved_psr->sysnum);
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
		if (current->record_thrd->rp_ignore_flag_addr) {
			get_user (ignore_flag, current->record_thrd->rp_ignore_flag_addr);
		} else {
			ignore_flag = 0;
		}
		printk("Pid %d recpid ----- PTHREAD:%ld:%ld.%06ld:%d:%s", current->pid, clock, tv.tv_sec, tv.tv_usec, ignore_flag, buf);
	} else {
		printk ("sys_pthread_print: pid %d is not a record/replay proces: %s\n", current->pid, buf);
		return -EINVAL;
	}

	return 0;
}

asmlinkage long
sys_pthread_init (int __user * status, u_long record_hook, u_long replay_hook)
{
	if (current->record_thrd) {
		struct record_thread* prt = current->record_thrd;
		put_user (1, status);
		prt->rp_record_hook = record_hook;
		DPRINT ("pid %d sets record hook %lx\n", current->pid, record_hook);
	} else if (current->replay_thrd) {
		struct replay_thread* prt = current->replay_thrd;
		put_user (2, status);
		prt->rp_replay_hook = replay_hook;
		DPRINT ("pid %d sets replay hook %lx\n", current->pid, replay_hook);
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
			DPRINT ("pid %d record hook %lx returned\n", current->pid, prt->rp_record_hook);
		}
	} else if (current->replay_thrd) {
		struct replay_thread* prt = current->replay_thrd;
		if (prt->rp_replay_hook) {
			put_user (2, status);
			put_user (prt->rp_replay_hook, replay_hook);
			DPRINT ("pid %d replay hook %lx returned\n", current->pid, prt->rp_replay_hook);
		}
	} else {
			put_user (3, status);		
	}
	return 0;
}

asmlinkage long
sys_pthread_log (u_long log_addr, int __user * ignore_addr)
{
	struct rlimit* rlim;
	long rc;

	if (current->record_thrd) {
		current->record_thrd->rp_user_log_addr = log_addr;
		current->record_thrd->rp_ignore_flag_addr = ignore_addr;

		// Up the resource limit by one if it is set so as not to interfere with user-level mlocks
		read_lock(&tasklist_lock);
		rlim = current->signal->rlim + RLIMIT_MEMLOCK;
		task_lock(current->group_leader);
		DPRINT ("rlimit before %ld %ld\n", rlim->rlim_cur, rlim->rlim_max);
		if (rlim->rlim_max) rlim->rlim_max += PAGE_SIZE;
		if (rlim->rlim_cur) rlim->rlim_cur += PAGE_SIZE;
		DPRINT ("rlimit after %ld %ld\n", rlim->rlim_cur, rlim->rlim_max);
		task_unlock(current->group_leader);
		read_unlock(&tasklist_lock);
		
		rc = sys_mlock ((u_long) ignore_addr, sizeof(int)); // lock this in memory because we need to check when recording signals with interrupts disabled 
		if (rc < 0) DPRINT ("pid %d: mlock of ignore address %p failed, rc=%ld\n", current->pid, ignore_addr, rc); 
		DPRINT ("User log info address for thread %d is %lx, ignore addr is %p\n", current->pid, log_addr, ignore_addr);
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
sys_pthread_elog (int type, u_long addr)
{
#ifdef USE_EXTRA_DEBUG_LOG
	if (type == 0) { // allocate/register log
		if (current->record_thrd) {
			current->record_thrd->rp_user_extra_log_addr = addr;
			MPRINT ("User extra log info address for thread %d is %lx\n", current->pid, addr);
		} else if (current->replay_thrd) {
			current->replay_thrd->rp_record_thread->rp_user_extra_log_addr = addr;
			read_user_extra_log (current->replay_thrd->rp_record_thread);
			MPRINT ("Read extra user log into address %lx for thread %d\n", addr, current->pid);
		} else {
			printk ("sys_pthread_elog called by pid %d which is neither recording nor replaying\n", current->pid);
			return -EINVAL;
		}
	} else { // Log is full
		if (current->record_thrd) {
			DPRINT ("Pid %d: extra log full\n", current->pid);
			if (write_user_extra_log (current->record_thrd) < 0) printk ("Extra debug log write failed\n");
		} else if (current->replay_thrd) {
			DPRINT ("Pid %d: Resetting user log\n", current->pid);
			read_user_extra_log (current->replay_thrd->rp_record_thread);	
		} else {
			printk ("sys_pthread_elog called by pid %d which is neither recording nor replaying\n", current->pid);
			return -EINVAL;
		}
	}

	return 0;
#else
	return -EINVAL; // Support not compiled intot this kernel
#endif
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
				syscall_mismatch ();
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
				printk ("Pid %d: blocking syscall cannot wait due to signal - try again (%d)\n", current->pid, prg->rg_rec_group->rg_mismatch_flag);
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
		DPRINT ("Pid %d: log full\n", current->pid);
		if (write_user_log (current->record_thrd) < 0) sys_exit_group(0); // Logging failed
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
	} else {
		put_user (3, status);
	}
	return 0;
}

/* Returns a fd for the shared memory page back to the user */
asmlinkage long sys_pthread_shm_path (void)
{
	int fd;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);

	if (current->record_thrd) {
		struct record_group* prg = current->record_thrd->rp_group;
		MPRINT ("Pid %d (record) returning existing shmpath %s\n", current->pid, prg->rg_shmpath);
		fd = sys_open(prg->rg_shmpath, O_RDWR | O_NOFOLLOW, 0644);
	} else if (current->replay_thrd) {
		struct record_group* prg = current->replay_thrd->rp_group->rg_rec_group;
		MPRINT ("Pid %d (replay) returning existing shmpath %s\n", current->pid, prg->rg_shmpath);
		fd = sys_open(prg->rg_shmpath, O_RDWR | O_NOFOLLOW, 0644);
	} else {
		printk("[WARN]Pid %d, neither record/replay is asking for the shm_path???\n", current->pid);
		fd = -EINVAL;
	}

	set_fs(old_fs);

	return fd;
}

asmlinkage long sys_pthread_sysign (void)
{
	// This replays an ignored syscall which delivers a signal
	DPRINT ("In sys_pthread_sysign\n");
	return get_next_syscall (SIGNAL_WHILE_SYSCALL_IGNORED, NULL); 
}

#define SHIM_CALL_MAIN(number, F_RECORD, F_REPLAY, F_SYS)	\
{ \
	int ignore_flag;						\
	if (current->record_thrd) {					\
		if (current->record_thrd->rp_ignore_flag_addr) {	\
			get_user (ignore_flag, current->record_thrd->rp_ignore_flag_addr); \
			if (ignore_flag) return F_SYS;			\
		}							\
		return F_RECORD;					\
	}								\
	if (current->replay_thrd && test_app_syscall(number)) {		\
		if (current->replay_thrd->rp_record_thread->rp_ignore_flag_addr) { \
			get_user (ignore_flag, current->replay_thrd->rp_record_thread->rp_ignore_flag_addr); \
			if (ignore_flag) { \
				printk ("syscall %d ignored\n", number); \
				return F_SYS;				\
			}						\
		}							\
		DPRINT("Pid %d, regular replay syscall %d\n", current->pid, number); \
		return F_REPLAY;					\
	}								\
	else if (current->replay_thrd) {				\
		if (*(current->replay_thrd->rp_preplay_clock) > pin_debug_clock) {	\
			DPRINT("Pid %d, pin syscall %d\n", current->pid, number);	\
		}							\
	}								\
	return F_SYS;							\
}

#define SHIM_CALL(name, number, args...)					\
{ \
	SHIM_CALL_MAIN(number, record_##name(args), replay_##name(args),	\
		       sys_##name(args))    \
}

#define SIMPLE_RECORD0(name, sysnum)		                        \
	static asmlinkage long						\
	record_##name (void)						\
	{								\
		long rc;						\
		new_syscall_enter (sysnum);				\
		rc = sys_##name();					\
		new_syscall_done (sysnum, rc);				\
		new_syscall_exit (sysnum, NULL);			\
		return rc;						\
	}								

#define SIMPLE_RECORD1(name, sysnum, arg0type, arg0name)		\
	static asmlinkage long						\
	record_##name (arg0type arg0name)				\
	{								\
		long rc;						\
		new_syscall_enter (sysnum);				\
		rc = sys_##name(arg0name);				\
		new_syscall_done (sysnum, rc);				\
		new_syscall_exit (sysnum, NULL);			\
		return rc;						\
	}								

#define SIMPLE_RECORD2(name, sysnum, arg0type, arg0name, arg1type, arg1name)	\
	static asmlinkage long						\
	record_##name (arg0type arg0name, arg1type arg1name)		\
	{								\
		long rc;						\
		new_syscall_enter (sysnum);				\
		rc = sys_##name(arg0name, arg1name);			\
		new_syscall_done (sysnum, rc);				\
		new_syscall_exit (sysnum, NULL);			\
		return rc;						\
	}								

#define SIMPLE_RECORD3(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
	static asmlinkage long						\
	record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name)	\
	{								\
		long rc;						\
		new_syscall_enter (sysnum);				\
		rc = sys_##name(arg0name, arg1name, arg2name);		\
		new_syscall_done (sysnum, rc);				\
		new_syscall_exit (sysnum, NULL);			\
		return rc;						\
	}								

#define SIMPLE_RECORD4(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
	static asmlinkage long						\
	record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) \
	{								\
		long rc;						\
		new_syscall_enter (sysnum);				\
		rc = sys_##name(arg0name, arg1name, arg2name, arg3name); \
		new_syscall_done (sysnum, rc);				\
		new_syscall_exit (sysnum, NULL);			\
		return rc;						\
	}								

#define SIMPLE_RECORD5(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
	static asmlinkage long						\
	record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) \
	{								\
		long rc;						\
		new_syscall_enter (sysnum);				\
		rc = sys_##name(arg0name, arg1name, arg2name, arg3name, arg4name); \
		new_syscall_done (sysnum, rc);				\
		new_syscall_exit (sysnum, NULL);			\
		return rc;						\
	}								

#define SIMPLE_RECORD6(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name, arg5type, arg5name) \
	static asmlinkage long						\
	record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name, arg5type arg5name) \
	{								\
		long rc;						\
		new_syscall_enter (sysnum);				\
		rc = sys_##name(arg0name, arg1name, arg2name, arg3name, arg4name, arg5name); \
		new_syscall_done (sysnum, rc);				\
		new_syscall_exit (sysnum, NULL);			\
		return rc;						\
	}								

#define SIMPLE_REPLAY(name, sysnum, args...)		\
  static asmlinkage long				\
  replay_##name (args)					\
  {							\
	  return get_next_syscall (sysnum, NULL);	\
  }

#define SIMPLE_SHIM0(name, sysnum)					\
	SIMPLE_RECORD0(name, sysnum);					\
	SIMPLE_REPLAY (name, sysnum, void);				\
	asmlinkage long shim_##name (void) SHIM_CALL(name, sysnum);	

#define SIMPLE_SHIM1(name, sysnum, arg0type, arg0name)			\
	SIMPLE_RECORD1(name, sysnum, arg0type, arg0name);		\
	SIMPLE_REPLAY (name, sysnum, arg0type arg0name);		\
	asmlinkage long shim_##name (arg0type arg0name) SHIM_CALL(name, sysnum, arg0name);	

#define SIMPLE_SHIM2(name, sysnum, arg0type, arg0name, arg1type, arg1name) \
	SIMPLE_RECORD2(name, sysnum, arg0type, arg0name, arg1type, arg1name); \
	SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name) SHIM_CALL(name, sysnum, arg0name, arg1name);	

#define SIMPLE_SHIM3(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
	SIMPLE_RECORD3(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name); \
	SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name);	

#define SIMPLE_SHIM4(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
	SIMPLE_RECORD4(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name); \
	SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name);	
#define SIMPLE_SHIM5(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
	SIMPLE_RECORD5(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name); \
	SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name, arg4name);	

#define SIMPLE_SHIM6(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name, arg5type, arg5name) \
	SIMPLE_RECORD6(name, sysnum, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name, arg5type, arg5name); \
	SIMPLE_REPLAY (name, sysnum, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name, arg5type arg5name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name, arg5type arg5name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name, arg4name, arg5name);

#define RET1_RECORD1(name, sysnum, type, dest, arg0type, arg0name)	\
static asmlinkage long record_##name (arg0type arg0name)	\
{									\
	long rc;							\
	type *pretval = NULL;						\
									\
	new_syscall_enter (sysnum);					\
	rc = sys_##name (arg0name);					\
	new_syscall_done (sysnum, rc);					\
	if (rc >= 0 && dest) {						\
	        pretval = ARGSKMALLOC (sizeof(type), GFP_KERNEL);	\
		if (pretval == NULL) {					\
			printk ("record_##name: can't allocate buffer\n"); \
			return -ENOMEM;					\
		}							\
		if (copy_from_user (pretval, dest, sizeof (type))) {	\
			printk ("record_##name: can't copy to buffer\n"); \
			ARGSKFREE(pretval, sizeof(type));		\
			pretval = NULL;					\
			rc = -EFAULT;					\
		}							\
	}								\
									\
	new_syscall_exit (sysnum, pretval);				\
	return rc;							\
}

#define RET1_RECORD2(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name) \
{									\
	long rc;							\
	type *pretval = NULL;						\
									\
	new_syscall_enter (sysnum);					\
	rc = sys_##name (arg0name, arg1name);				\
	new_syscall_done (sysnum, rc);					\
	if (rc >= 0 && dest) {						\
	        pretval = ARGSKMALLOC (sizeof(type), GFP_KERNEL);	\
		if (pretval == NULL) {					\
			printk ("record_##name: can't allocate buffer\n"); \
			return -ENOMEM;					\
		}							\
		if (copy_from_user (pretval, dest, sizeof (type))) {	\
			printk ("record_##name: can't copy to buffer\n"); \
			ARGSKFREE(pretval, sizeof(type));		\
			pretval = NULL;					\
			rc = -EFAULT;					\
		}							\
	}								\
									\
	new_syscall_exit (sysnum, pretval);				\
	return rc;							\
}

#define RET1_RECORD3(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) \
{									\
	long rc;							\
	type *pretval = NULL;						\
									\
	new_syscall_enter (sysnum);					\
	rc = sys_##name (arg0name, arg1name, arg2name);			\
	new_syscall_done (sysnum, rc);					\
	if (rc >= 0 && dest) {						\
	        pretval = ARGSKMALLOC (sizeof(type), GFP_KERNEL);	\
		if (pretval == NULL) {					\
			printk ("record_##name: can't allocate buffer\n"); \
			return -ENOMEM;					\
		}							\
		if (copy_from_user (pretval, dest, sizeof (type))) {	\
			printk ("record_##name: can't copy to buffer\n"); \
			ARGSKFREE(pretval, sizeof(type));		\
			pretval = NULL;					\
			rc = -EFAULT;					\
		}							\
	}								\
									\
	new_syscall_exit (sysnum, pretval);				\
	return rc;							\
}

#define RET1_RECORD4(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) \
{									\
	long rc;							\
	type *pretval = NULL;						\
									\
	new_syscall_enter (sysnum);					\
	rc = sys_##name (arg0name, arg1name, arg2name, arg3name);	\
	new_syscall_done (sysnum, rc);					\
	if (rc >= 0 && dest) {						\
	        pretval = ARGSKMALLOC (sizeof(type), GFP_KERNEL);	\
		if (pretval == NULL) {					\
			printk ("record_##name: can't allocate buffer\n"); \
			return -ENOMEM;					\
		}							\
		if (copy_from_user (pretval, dest, sizeof (type))) {	\
			printk ("record_##name: can't copy to buffer\n"); \
			ARGSKFREE(pretval, sizeof(type));		\
			pretval = NULL;					\
			rc = -EFAULT;					\
		}							\
	}								\
									\
	new_syscall_exit (sysnum, pretval);				\
	return rc;							\
}

#define RET1_RECORD5(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) \
{									\
	long rc;							\
	type *pretval = NULL;						\
									\
	new_syscall_enter (sysnum);					\
	rc = sys_##name (arg0name, arg1name, arg2name, arg3name, arg4name);	\
	new_syscall_done (sysnum, rc);					\
	if (rc >= 0 && dest) {						\
	        pretval = ARGSKMALLOC (sizeof(type), GFP_KERNEL);	\
		if (pretval == NULL) {					\
			printk ("record_##name: can't allocate buffer\n"); \
			return -ENOMEM;					\
		}							\
		if (copy_from_user (pretval, dest, sizeof (type))) {	\
			printk ("record_##name: can't copy to buffer\n"); \
			ARGSKFREE(pretval, sizeof(type));		\
			pretval = NULL;					\
			rc = -EFAULT;					\
		}							\
	}								\
									\
	new_syscall_exit (sysnum, pretval);				\
	return rc;							\
}

#define RET1_REPLAYG(name, sysnum, dest, size, args...)			\
static asmlinkage long replay_##name (args)				\
{									\
	char *retparams = NULL;						\
	long rc = get_next_syscall (sysnum, (char **) &retparams);	\
									\
	if (retparams) {						\
		if (copy_to_user (dest, retparams, size)) printk ("replay_##name: pid %d cannot copy to user\n", current->pid); \
		argsconsume (current->replay_thrd->rp_record_thread, size); \
	}								\
									\
	return rc;							\
}									\

#define RET1_REPLAY(name, sysnum, type, dest, args...) RET1_REPLAYG(name, sysnum, dest, sizeof(type), args)

#define RET1_SHIM1(name, sysnum, type, dest, arg0type, arg0name)	\
	RET1_RECORD1(name, sysnum, type, dest, arg0type, arg0name);	\
	RET1_REPLAY (name, sysnum, type, dest, arg0type arg0name);	\
	asmlinkage long shim_##name (arg0type arg0name) SHIM_CALL(name, sysnum, arg0name);	

#define RET1_SHIM2(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name) \
	RET1_RECORD2(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name); \
	RET1_REPLAY (name, sysnum, type, dest, arg0type arg0name, arg1type arg1name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name) SHIM_CALL(name, sysnum, arg0name, arg1name);	

#define RET1_SHIM3(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
	RET1_RECORD3(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name); \
	RET1_REPLAY (name, sysnum, type, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name);	

#define RET1_SHIM4(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
	RET1_RECORD4(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name); \
	RET1_REPLAY (name, sysnum, type, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name);	

#define RET1_SHIM5(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
	RET1_RECORD5(name, sysnum, type, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name); \
	RET1_REPLAY (name, sysnum, type, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name, arg4name);	

#define RET1_COUNT_RECORD3(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) \
{									\
	long rc;							\
	char *pretval = NULL;						\
									\
	new_syscall_enter (sysnum);					\
	rc = sys_##name (arg0name, arg1name, arg2name);			\
	new_syscall_done (sysnum, rc);					\
	if (rc >= 0 && dest) {						\
		pretval = ARGSKMALLOC (rc, GFP_KERNEL);			\
		if (pretval == NULL) {					\
			printk ("record_##name: can't allocate buffer\n"); \
			return -ENOMEM;					\
		}							\
		if (copy_from_user (pretval, dest, rc)) {		\
			printk ("record_##name: can't copy to buffer\n"); \
			ARGSKFREE(pretval, rc);				\
			pretval = NULL;					\
			rc = -EFAULT;					\
		}							\
	}								\
									\
	new_syscall_exit (sysnum, pretval);				\
	return rc;							\
}

#define RET1_COUNT_RECORD4(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) \
{									\
	long rc;							\
	char *pretval = NULL;						\
									\
	new_syscall_enter (sysnum);					\
	rc = sys_##name (arg0name, arg1name, arg2name, arg3name);	\
	new_syscall_done (sysnum, rc);					\
	if (rc >= 0 && dest) {						\
		pretval = ARGSKMALLOC (rc, GFP_KERNEL);			\
		if (pretval == NULL) {					\
			printk ("record_##name: can't allocate buffer\n"); \
			return -ENOMEM;					\
		}							\
		if (copy_from_user (pretval, dest, rc)) {		\
			printk ("record_##name: can't copy to buffer\n"); \
			ARGSKFREE(pretval, rc);				\
			pretval = NULL;					\
			rc = -EFAULT;					\
		}							\
	}								\
									\
	new_syscall_exit (sysnum, pretval);				\
	return rc;							\
}

#define RET1_COUNT_RECORD5(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
static asmlinkage long record_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) \
{									\
	long rc;							\
	char *pretval = NULL;						\
									\
	new_syscall_enter (sysnum);					\
	rc = sys_##name (arg0name, arg1name, arg2name, arg3name, arg4name); \
	new_syscall_done (sysnum, rc);					\
	if (rc >= 0 && dest) {						\
		pretval = ARGSKMALLOC (rc, GFP_KERNEL);			\
		if (pretval == NULL) {					\
			printk ("record_##name: can't allocate buffer\n"); \
			return -ENOMEM;					\
		}							\
		if (copy_from_user (pretval, dest, rc)) {		\
			printk ("record_##name: can't copy to buffer\n"); \
			ARGSKFREE(pretval, rc);				\
			pretval = NULL;					\
			rc = -EFAULT;					\
		}							\
	}								\
									\
	new_syscall_exit (sysnum, pretval);				\
	return rc;							\
}

#define RET1_COUNT_REPLAY(name, sysnum, dest, args...)			\
static asmlinkage long replay_##name (args)				\
{									\
	char *retparams = NULL;						\
	long rc = get_next_syscall (sysnum, &retparams);		\
									\
	if (retparams) {						\
		if (copy_to_user (dest, retparams, rc)) printk ("replay_##name: pid %d cannot copy to user\n", current->pid); \
		argsconsume (current->replay_thrd->rp_record_thread, rc); \
	}								\
									\
	return rc;							\
}									\

#define RET1_COUNT_SHIM3(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name) \
	RET1_COUNT_RECORD3(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name); \
	RET1_COUNT_REPLAY (name, sysnum, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name);	

#define RET1_COUNT_SHIM4(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name) \
	RET1_COUNT_RECORD4(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name); \
	RET1_COUNT_REPLAY (name, sysnum, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name);	

#define RET1_COUNT_SHIM5(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name) \
	RET1_COUNT_RECORD5(name, sysnum, dest, arg0type, arg0name, arg1type, arg1name, arg2type, arg2name, arg3type, arg3name, arg4type, arg4name); \
	RET1_COUNT_REPLAY (name, sysnum, dest, arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name); \
	asmlinkage long shim_##name (arg0type arg0name, arg1type arg1name, arg2type arg2name, arg3type arg3name, arg4type arg4name) SHIM_CALL(name, sysnum, arg0name, arg1name, arg2name, arg3name, arg4name);	

#ifndef USE_DEBUG_LOG
static void
flush_user_log (struct record_thread* prt)
{
	struct pthread_log_head* phead = (struct pthread_log_head __user *) prt->rp_user_log_addr;
	char* pnext;
	u_long entry;
	int fake_calls;

	if (phead == NULL) return;

	get_user (pnext, &phead->next);
	if (pnext) {
		get_user (entry, &phead->num_expected_records); 
		get_user (fake_calls, &phead->need_fake_calls);
		if (entry == 0 && fake_calls == 0) return;
		if (fake_calls) entry |= FAKE_CALLS_FLAG;
		put_user (entry, (u_long __user *) pnext);  
		pnext += sizeof(unsigned long);
		if (fake_calls) {
			put_user (fake_calls, (int __user *) pnext);  
			pnext += sizeof(int);
		}
		put_user (pnext, &phead->next);
		put_user (0, &phead->need_fake_calls);
		put_user (0, &phead->num_expected_records);
	} else {
		printk ("flush_user_log: next pointer invalid: phead is %p\n", phead);
	}
}
#endif

static void
deallocate_user_log (struct record_thread* prt)
{
	long rc;

	struct pthread_log_head* phead = (struct pthread_log_head __user *) prt->rp_user_log_addr;
	MPRINT ("Pid %d -- deallocate user log phead %p\n", current->pid, phead);
	rc = sys_munmap ((u_long) phead, PTHREAD_LOG_SIZE+4096);
	if (rc < 0) printk ("pid %d: deallocate_user_log failed, rc=%ld\n", current->pid, rc);
}

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
	struct record_thread* prt = current->record_thrd;
	struct rlimit* rlim;
	long rc;

	if (prt) {
		MPRINT ("Record thread %d starting to exit\n", current->pid);
#ifndef USE_DEBUG_LOG
		flush_user_log (prt);
#endif
		write_user_log (prt); // Write this out before we destroy the mm
#ifdef USE_EXTRA_DEBUG_LOG
		write_user_extra_log (prt);
#endif
		MPRINT ("Pid %d -- Deallocate the user log", current->pid);
		deallocate_user_log (prt); // For multi-threaded programs, we need to reuse the memory

		if (prt->rp_ignore_flag_addr) {
			rc = sys_munlock ((u_long) prt->rp_ignore_flag_addr, sizeof(int)); // lock this in memory because we need to check when recording signals with interrupts disabled 
			if (rc >= 0) {
				read_lock(&tasklist_lock);
				rlim = current->signal->rlim + RLIMIT_MEMLOCK;
				task_lock(current->group_leader);
				DPRINT ("rlimit before %ld %ld\n", rlim->rlim_cur, rlim->rlim_max);
				if (rlim->rlim_max) rlim->rlim_max += PAGE_SIZE;
				if (rlim->rlim_cur) rlim->rlim_cur += PAGE_SIZE;
				DPRINT ("rlimit after %ld %ld\n", rlim->rlim_cur, rlim->rlim_max);
				task_unlock(current->group_leader);
				read_unlock(&tasklist_lock);
			} else {
				DPRINT("pid %d: munlock of ignore address %p failed, rc=%ld\n", current->pid, prt->rp_ignore_flag_addr, rc); 
			}
		} else {
			printk ("No ignore address for pid %d\n", current->pid);
		}

	} else if (current->replay_thrd) {
		MPRINT ("Replay thread %d starting to exit, recpid %d\n", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid);
		
		// When exiting threads with Pin attached, we need to make sure we exit the threads
		// in the correct order, while making sure Pin doesn't deadlock
		if (is_pin_attached() && current->replay_thrd->rp_pin_restart_syscall) {
			MPRINT ("Pid %d, since this was a restart syscall, need to wait for exit, %d\n", current->pid, current->replay_thrd->rp_pin_restart_syscall);
			BUG_ON (!current->replay_thrd->rp_saved_psr);
			if (current->replay_thrd->rp_pin_restart_syscall == REPLAY_PIN_TRAP_STATUS_ENTER) {
				u_long wait_clock;
				struct replay_thread* prept = current->replay_thrd;
				BUG_ON(!prept->rp_saved_psr);
				BUG_ON(!prept->rp_start_clock_save);
				
				MPRINT ("Pid %d -- need to consume start clock first", current->pid);

				// since Pin is forcing an exit, we need to consume the last clock value in
				// this thread
				wait_clock = prept->rp_start_clock_save;

				MPRINT ("Pid %d, recplay start, wait for clock value %lu from saved syscall entry\n", current->pid, wait_clock);
				get_next_clock(prept, prept->rp_group, wait_clock);
				prept->rp_pin_restart_syscall = REPLAY_PIN_TRAP_STATUS_EXIT;
			}
			MPRINT ("Pid %d, recplay start, wait for clock value %lu from saved syscall exit\n", current->pid, current->replay_thrd->rp_stop_clock_save);
			get_next_clock(current->replay_thrd, current->replay_thrd->rp_group, current->replay_thrd->rp_stop_clock_save);
			current->replay_thrd->rp_pin_restart_syscall = REPLAY_PIN_TRAP_STATUS_NONE;
			// So we don't have abnormal termination, since Pin told us to exit
			MPRINT ("Pid %d - thread exiting because of Pin\n", current->pid);
			current->replay_thrd->rp_replay_exit = 1;
		}
	}
}

void 
recplay_exit_middle(void)
{
	struct replay_thread* tmp;
	u_long clock;
	int num_blocked;

	if (current->record_thrd) {
		struct record_thread* prt = current->record_thrd;
		MPRINT ("Record thread %d in middle of exit\n", current->pid);
	
		// Write kernel log after we have updated the tid ptr
#ifdef WRITE_ASYNC
		write_and_free_kernel_log_async(prt);
#else
		write_and_free_kernel_log(prt); // Write out remaining records
#endif
		// write out mmaps if the last record thread to exit the record group
		if (atomic_dec_and_test(&prt->rp_group->rg_record_threads)) {
			if (prt->rp_group->rg_save_mmap_flag) {
				rg_lock (prt->rp_group);
				MPRINT ("Pid %d last record thread to exit, write out mmap log\n", current->pid);
				write_mmap_log(prt->rp_group);
				prt->rp_group->rg_save_mmap_flag = 0;
				rg_unlock (prt->rp_group);
			}
		}
	} else if (current->replay_thrd) {
		if (atomic_dec_and_test(&current->replay_thrd->rp_group->rg_rec_group->rg_record_threads)) {
			if (current->replay_thrd->rp_group->rg_rec_group->rg_save_mmap_flag) {
				rg_lock (current->replay_thrd->rp_group->rg_rec_group);
				MPRINT ("Pid %d last record thread to exit, write out mmap log\n", current->pid);
				write_mmap_log(current->replay_thrd->rp_group->rg_rec_group);
				current->replay_thrd->rp_group->rg_rec_group->rg_save_mmap_flag = 0;
				rg_unlock (current->replay_thrd->rp_group->rg_rec_group);
			}
		}
		MPRINT ("Replay thread %d recpid %d in middle of exit\n", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid);	
		rg_lock (current->replay_thrd->rp_group->rg_rec_group);
		if (current->replay_thrd->rp_status != REPLAY_STATUS_RUNNING || current->replay_thrd->rp_group->rg_rec_group->rg_mismatch_flag) {
			if (!current->replay_thrd->rp_replay_exit && !current->replay_thrd->rp_group->rg_rec_group->rg_mismatch_flag) { 
				// Usually get here by terminating when we see the exit flag and all records have been consumed
				printk ("Non-running pid %d is exiting with status %d - abnormal termination?\n", current->pid, current->replay_thrd->rp_status);
				dump_stack();
			}
			current->replay_thrd->rp_status = REPLAY_STATUS_DONE;  // Will run no more 
			rg_unlock (current->replay_thrd->rp_group->rg_rec_group);
			return;
		}

		clock = *current->replay_thrd->rp_preplay_clock;
		current->replay_thrd->rp_status = REPLAY_STATUS_DONE;  // Will run no more 	
		tmp = current->replay_thrd->rp_next_thread;
		num_blocked = 0;
		while (tmp != current->replay_thrd) {
			DPRINT ("Pid %d considers thread %d (recpid %d) status %d clock %ld - clock is %ld\n", current->pid, tmp->rp_replay_pid, current->replay_thrd->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock, clock);
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

extern long do_restart_poll(struct restart_block *restart_block); /* In select.c */

static long 
record_restart_syscall(struct restart_block* restart)
{
	printk ("Pid %d calls record_restart_syscall\n", current->pid);
	if (restart->fn == do_restart_poll) {
		long rc;
		char* pretvals = NULL;
		short* p;
		int i;
		
		new_syscall_enter (168);

		rc = restart->fn (restart); 
		new_syscall_done (168, rc);			       
		if (rc > 0) {
			pretvals = ARGSKMALLOC(sizeof(int)+restart->poll.nfds*sizeof(short), GFP_KERNEL);
			if (pretvals == NULL) {
				printk("restart_record_poll: can't allocate buffer\n");
				return -ENOMEM;
			}
			*((u_long *)pretvals) = restart->poll.nfds*sizeof(short);
			p = (short *) (pretvals+sizeof(u_long));
			for (i = 0; i < restart->poll.nfds; i++) {
				if (copy_from_user (p, &restart->poll.ufds[i].revents, sizeof(short))) {
					printk ("record_poll: can't copy retval %d\n", i);
					ARGSKFREE (pretvals,sizeof(u_long)+restart->poll.nfds*sizeof(short));
					return -EFAULT;
				}
				p++;
			}
		}

		new_syscall_exit (168, pretvals);
		
		return rc;
	} else {
		printk ("Record pid %d clock %d unhandled restart function %p do_restart_poll %p\n", current->pid, atomic_read(current->record_thrd->rp_precord_clock), restart->fn, do_restart_poll);
		return restart->fn (restart); 
	}
}

static long 
replay_restart_syscall(struct restart_block* restart)
{
	printk ("Replay pid %d RESTARTING syscall\n", current->pid);
	if (restart->fn == do_restart_poll) {
		return replay_poll (restart->poll.ufds, restart->poll.nfds, 0 /* unused */);
	} else {
		printk ("Replay pid %d unhandled restart function\n", current->pid);
		return restart->fn (restart); 
	}
}

asmlinkage long 
shim_restart_syscall(void)
{
	struct restart_block *restart = &current_thread_info()->restart_block;

	if (current->record_thrd) return record_restart_syscall (restart);
	if (current->replay_thrd) return replay_restart_syscall (restart);
	return restart->fn(restart); // Skip sys_restart_syscall because this is all it does
}

asmlinkage long 
shim_exit(int error_code)
{
	if (current->record_thrd) MPRINT ("Recording Pid %d naturally exiting\n", current->pid);
	if (current->replay_thrd && test_app_syscall(1)) MPRINT ("Replaying Pid %d naturally exiting\n", current->pid);
	return sys_exit (error_code);
}


#ifdef TRACE_SOCKET_READ_WRITE
int track_usually_pt2pt_read(void *key, int size, struct file *filp) {
	u_int *is_cached;
	u64 rg_id = current->record_thrd->rp_group->rg_id;
	struct pipe_track *info;
	struct replayfs_filemap map;

	is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);

	*is_cached = READ_IS_PIPE;

	/* We have to lock our pipe tree externally */
	mutex_lock(&pipe_tree_mutex);

	info = btree_lookup32(&pipe_tree, (u32)key);

	/* The pipe is not in the tree, this is its first write (by a recorded process) */
	if (info == NULL) {
		/* Create a new pipe_track */
		info = kmalloc(sizeof(struct pipe_track), GFP_KERNEL);
		/* Crap... no memory */
		if (info == NULL) {
			/* FIXME: fail cleanly */
			BUG();
		}

		mutex_init(&info->lock);

		/* Now initialize the structure */
		info->owner_read_id = rg_id;
		info->owner_write_id = 0;
		info->id = atomic_inc_return(&glbl_pipe_id);

		info->owner_write_pos = 0;
		info->owner_read_pos = size;

		info->key.id1 = filp->f_dentry->d_inode->i_ino;
		info->key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

		info->shared = 0;
		if (btree_insert32(&pipe_tree, (u32)key, info, GFP_KERNEL)) {
			/* FIXME: fail cleanly */
			BUG();
		}

		mutex_unlock(&pipe_tree_mutex);
	/* The pipe is in the tree, update it */
	} else {
		/* We lock the pipe before we unlock the tree, to ensure that the pipe updates are orded with respect to lookup in the tree */
		mutex_lock(&info->lock);
		mutex_unlock(&pipe_tree_mutex);

		/* If the pipe is exclusive, don't keep any data about it */
		if (info->shared == 0) {
			/* It hasn't been read yet */
			if (unlikely(info->owner_read_id == 0)) {
				info->owner_read_id = rg_id;
				BUG_ON(info->owner_read_pos != 0);
				info->owner_read_pos = size;
			/* If it continues to be exclusive */
			} else if (likely(info->owner_read_id == rg_id)) {
				info->owner_read_pos += size;
			/* This is the un-sharing read */
			} else {
				info->shared = 1;

				/* Okay, we need to allocate a filemap for this file */
				replayfs_filemap_init(&map, &replayfs_alloc, filp);

				/* Write a record of the old data, special case of 0 means held linearly in pipe */
				replayfs_filemap_write(&map, info->owner_write_id, 0, info->id, 0, 0, info->owner_write_pos);

				/* Now append a read record indicating the data we have */
				*is_cached |= READ_PIPE_WITH_DATA;

				info->owner_read_pos += size;
			}
		} else {
			/* Okay, we need to allocate a filemap for this file */
			replayfs_filemap_init(&map, &replayfs_alloc, filp);

			*is_cached |= READ_PIPE_WITH_DATA;

			info->owner_read_pos += size;
		}

		mutex_unlock(&info->lock);
	}

	/* If this is a shared pipe, we will mark multiple writers, and save all the writer data */
	if (*is_cached & READ_PIPE_WITH_DATA) {
		struct replayfs_filemap_entry *args;
		struct replayfs_filemap_entry *entry;
		int cpy_size;

		/* Append the data */
		entry = replayfs_filemap_read(&map, info->owner_read_pos - size, size);
	
		if (IS_ERR(entry) || entry == NULL) {
			entry = kmalloc(sizeof(struct replayfs_filemap_entry), GFP_KERNEL);
			entry->num_elms = 0;
		}

		cpy_size = sizeof(struct replayfs_filemap_entry) +
				(entry->num_elms * sizeof(struct replayfs_filemap_value));

		args = ARGSKMALLOC(cpy_size, GFP_KERNEL);

		memcpy(args, entry, cpy_size);

		kfree(entry);

		replayfs_filemap_destroy(&map);

	/* Otherwise, we just need to know the source id of this pipe */
	} else {
		struct pipe_track *info;
		char *buf = ARGSKMALLOC(sizeof(u64) + sizeof(int), GFP_KERNEL);
		u64 *writer = (void *)buf;
		int *id = (int *)(writer +1);
		mutex_lock(&pipe_tree_mutex);
		info = btree_lookup32(&pipe_tree, (u32)key);
		BUG_ON(info == NULL);
		mutex_lock(&info->lock);
		mutex_unlock(&pipe_tree_mutex);
		*writer = info->owner_write_id;
		*id = info->id;
		mutex_unlock(&info->lock);
	}

	return 0;
}

int track_usually_pt2pt_write_begin(void *key, struct file *filp) {
	u64 rg_id = current->record_thrd->rp_group->rg_id;
	struct pipe_track *info;

	/* Wohoo, we have a pipe.  Lets track its writer */

	/* We have to lock our pipe tree externally */
	mutex_lock(&pipe_tree_mutex);

	info = btree_lookup32(&pipe_tree, (u32)key);

	/* The pipe is not in the tree, this is its first write (by a recorded process) */
	if (info == NULL) {
		/* Create a new pipe_track */
		info = kmalloc(sizeof(struct pipe_track), GFP_KERNEL);
		/* Crap... */
		if (info == NULL) {
			/* FIXME: fail cleanly */
			BUG();
		}

		mutex_init(&info->lock);

		/* Now initialize the structure */
		info->owner_read_id = 0;
		info->owner_write_id = rg_id;
		info->id = atomic_inc_return(&glbl_pipe_id);

		info->owner_write_pos = 0;
		info->owner_read_pos = 0;

		info->key.id1 = filp->f_dentry->d_inode->i_ino;
		info->key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

		info->shared = 0;
		if (btree_insert32(&pipe_tree, (u32)key, info, GFP_KERNEL)) {
			/* FIXME: fail cleanly */
			BUG();
		}

		mutex_unlock(&pipe_tree_mutex);
	} else {
		mutex_unlock(&pipe_tree_mutex);
	}
	return 0;
}

int track_usually_pt2pt_write(void *key, int size, struct file *filp, int do_shared) {
	u64 rg_id = current->record_thrd->rp_group->rg_id;
	struct pipe_track *info;
	char *pretparams;
	/* Wohoo, we have a pipe.  Lets track its writer */
	u_int *shared;


	if (do_shared) {
		shared = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);
		*shared = READ_IS_PIPE;
	}

	/* We have to lock our pipe tree externally */
	mutex_lock(&pipe_tree_mutex);

	info = btree_lookup32(&pipe_tree, (u32)key);

	/* The pipe is not in the tree, this is its first write (by a recorded process) */
	if (info == NULL) {
		/* Create a new pipe_track */
		info = kmalloc(sizeof(struct pipe_track), GFP_KERNEL);
		/* Crap... */
		if (info == NULL) {
			/* FIXME: fail cleanly */
			BUG();
		}

		mutex_init(&info->lock);

		/* Now initialize the structure */
		info->owner_read_id = 0;
		info->owner_write_id = rg_id;
		info->id = atomic_inc_return(&glbl_pipe_id);

		info->owner_write_pos = size;
		info->owner_read_pos = 0;

		info->key.id1 = filp->f_dentry->d_inode->i_ino;
		info->key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

		info->shared = 0;
		if (btree_insert32(&pipe_tree, (u32)key, info, GFP_KERNEL)) {
			/* FIXME: fail cleanly */
			BUG();
		}

		pretparams = ARGSKMALLOC(sizeof(int), GFP_KERNEL);
		BUG_ON(pretparams == NULL);
		*((int *)pretparams) = info->id;

		mutex_unlock(&pipe_tree_mutex);
	} else {
		mutex_lock(&info->lock);
		mutex_unlock(&pipe_tree_mutex);

		if (info->shared == 0) {
			if (unlikely(info->owner_write_id == 0)) {
				info->owner_write_id = rg_id;
				BUG_ON(info->owner_write_pos != 0);
				info->owner_write_pos = size;
				pretparams = ARGSKMALLOC(sizeof(int), GFP_KERNEL);
				if (pretparams == NULL) {
					mutex_unlock(&info->lock);
					return -ENOMEM;
				}
				*((int *)pretparams) = info->id;
			} else if (likely(info->owner_write_id == rg_id)) {
				info->owner_write_pos += size;
				pretparams = ARGSKMALLOC(sizeof(int), GFP_KERNEL);
				if (pretparams == NULL) {
					mutex_unlock(&info->lock);
					return -ENOMEM;
				}
				*((int *)pretparams) = info->id;
			/* This is the un-sharing write */
			} else {
				struct replayfs_filemap map;
				info->shared = 1;
				if (do_shared) {
					*shared |= READ_PIPE_WITH_DATA;
				}

				/* Okay, we need to allocate a filemap for this file */
				replayfs_filemap_init(&map, &replayfs_alloc, filp);

				/* Write a record of the old data, special case of 0 means held linearly in pipe */
				replayfs_filemap_write(&map, info->owner_write_id, 0, info->id, 0, 0, info->owner_write_pos);

				/* Write a record of our data */
				replayfs_filemap_write(&map, rg_id, current->record_thrd->rp_record_pid, current->record_thrd->rp_count, 0, info->owner_write_pos, size);

				replayfs_filemap_destroy(&map);

				info->owner_write_pos += size;
			}
		} else {
			struct replayfs_filemap map;
			if (do_shared) {
				*shared |= READ_PIPE_WITH_DATA;
			}

			/* Okay, we need to allocate a filemap for this file */
			replayfs_filemap_init(&map, &replayfs_alloc, filp);

			/* Write a record of our data */
			replayfs_filemap_write(&map, rg_id, current->record_thrd->rp_record_pid, current->record_thrd->rp_count, 0, info->owner_write_pos, size);

			replayfs_filemap_destroy(&map);

			info->owner_write_pos += size;
		}

		mutex_unlock(&info->lock);
	}
	return 0;
}

void consume_socket_args_read(void *retparams) {
	int consume_size = 0;
	u_int is_cache_file = *((u_int *)retparams);
	if (is_cache_file & READ_PIPE_WITH_DATA) {
		struct replayfs_filemap_entry *entry;

		consume_size = sizeof(u_int);
		entry = (void *)(retparams + consume_size);

		consume_size += sizeof(struct replayfs_filemap_entry) +
				(entry->num_elms * sizeof(struct replayfs_filemap_value));

		argsconsume (current->replay_thrd->rp_record_thread, consume_size);
	} else if (is_cache_file & READ_IS_PIPE) {
		consume_size = sizeof(u_int) + sizeof(u64) + sizeof(int);

		argsconsume (current->replay_thrd->rp_record_thread, consume_size);
	}
}

void consume_socket_args_write(void *retparams) {
	u_int shared = *((u_int *)retparams);
	if (shared) {
		argsconsume (current->replay_thrd->rp_record_thread, sizeof(u_int) + sizeof(int));
	}
}
#endif


/* fork system call is handled by shim_clone */

#ifdef CACHE_READS
static asmlinkage long
record_read (unsigned int fd, char __user * buf, size_t count)
{
	long rc;
	char *pretval = NULL;
	struct files_struct* files;
	struct fdtable *fdt;
	struct file* filp;
	int is_cache_file;
#ifdef TRACE_SOCKET_READ_WRITE
	int err;
#endif
	new_syscall_enter (3);					
	DPRINT ("pid %d, record read off of fd %d\n", current->pid, fd);
#ifdef REPLAY_COMPRESS_READS
	//printk("%s %d: Doing check on fd of %d\n", __func__, __LINE__, fd);
	if (is_recorded_file(fd)) {
		struct replay_recorded_file_meta *meta;
		struct replayfs_filemap_entry *entry;
		char *args;

		size_t cpy_size;

		//printk("%s %d: Yes, is_recorded file\n", __func__, __LINE__);

		is_cache_file = IS_RECORDED_FILE;

		filp = fget(fd);

		//printk("%s %d: Have recorded file! (%p)\n", __func__, __LINE__, filp);

		/* Okay, we need to save the btree recording from this file */
		if (buf) {
			struct replayfs_syscache_id id;
			int i;
			int buff_offs = 0;
			loff_t size;
			int num_available;
			/* First step, get meta data from fd */
			meta = replay_get_file_meta(fd);
			BUG_ON(meta == NULL);

			//printk("%s %d: Initial count is %u\n", __func__, __LINE__, count);
			size = meta_get_size(meta);
			num_available = filp->f_pos + count;
			if (num_available > size) {
				count -= num_available - size;
			}
			//printk("%s %d: Count adjusted to %u\n", __func__, __LINE__, count);
			rc = count;
			/* Now do a lookup */

			//printk("%s %d: Doing filemap lookup for pos, size {%lld, %ld}\n", __func__, __LINE__, filp->f_pos, rc);
			entry = replayfs_filemap_read(&meta->map, filp->f_pos, rc);

			//printk("%s %d: Got entry %p\n", __func__, __LINE__, entry);
			if (IS_ERR(entry) || entry == NULL) {
				entry = kmalloc(sizeof(struct replayfs_filemap_entry), GFP_KERNEL);
				/* FIXME: Handle this properly */
				BUG_ON(entry == NULL);
				entry->num_elms = 0;
				rc = 0;
				count = 0;
			} else {
				filp->f_pos += rc;
			}

			//printk("%s %d: entry->num_elms is %d\n", __func__, __LINE__, entry->num_elms);
			for (i = 0; i < entry->num_elms; i++) {
				struct replayfs_disk_alloc *alloc;
				struct replayfs_filemap_value *val = &entry->elms[i];
				loff_t entry_pos;

				int copy_offs;

				/* Get alloc pos ref'd by entry */
				id.unique_id = val->bval.id.unique_id;
				id.pid = val->bval.id.pid;
				id.sysnum = val->bval.id.sysnum;

				entry_pos = replayfs_syscache_get(&syscache, &id);
				/* Entry should be > 0, otherwise there is a problem */
				BUG_ON(entry_pos < 0);

				/* Get the disk_alloc referenced by entry */
				alloc = replayfs_disk_alloc_get(&replayfs_alloc, entry_pos);

				copy_offs = val->read_offset + val->bval.buff_offs;

				/* Copy the data into user space */
				/* I've already checked access_ok, so I'm just doing a normal copy now */
				replayfs_disk_alloc_read(alloc, buf + buff_offs, val->size, copy_offs + sizeof(struct replayfs_syscache_entry));

				buff_offs += val->size;

				replayfs_disk_alloc_put(alloc);
			}

			new_syscall_done (3, rc);

			cpy_size = sizeof(u_int) + sizeof(struct replayfs_filemap_entry) +
					(entry->num_elms * sizeof(struct replayfs_filemap_value));

			/* Save results into args */
			args = ARGSKMALLOC(cpy_size, GFP_KERNEL);
			pretval = args;

			*((u_int*)args) = is_cache_file;

			memcpy(args+sizeof(u_int), entry, cpy_size);

			/* Free memory */
			kfree(entry);
			/* dun */

			/* FIXME: see below */
			/* Yeah, this is hacky... I'll clean it up later */
			buf = 0;
			is_cache_file = 0;
		} else {
			/* FIXME: is this really the correct return code? */
			printk("%s %d: BUG?\n", __func__, __LINE__);
			rc = 0;
		}

		/* HACK, to fail the "if (rc>0&&buf)"... */
		buf = NULL;

		fput(filp);
	} else {
		is_cache_file = is_record_cache_file_lock(current->record_thrd->rp_cache_files, fd);
		rc = sys_read (fd, buf, count);
		new_syscall_done (3, rc);
	}
#else
	//printk("%s %d: In else? of macro?\n", __func__, __LINE__);
	is_cache_file = is_record_cache_file_lock(current->record_thrd->rp_cache_files, fd);
	rc = sys_read (fd, buf, count);
	new_syscall_done (3, rc);
#endif
	if (rc > 0 && buf) {
		// For now, include a flag that indicates whether this is a cached read or not - this is only
		// needed for parseklog and so we may take it out later

		files = current->files;
		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		if (fd >= fdt->max_fds) {
			printk ("record_read: invalid fd but read succeeded?\n");
			record_cache_file_unlock (current->record_thrd->rp_cache_files, fd);
			return -EINVAL;
		}

		filp = fdt->fd[fd];
		spin_unlock(&files->file_lock);
		if (is_cache_file) {
			// Since not all syscalls handled for cached reads, record the position
			DPRINT ("Cached read of fd %u - record by reference\n", fd);
			pretval = ARGSKMALLOC (sizeof(u_int) + sizeof(loff_t), GFP_KERNEL);
			if (pretval == NULL) {
				printk ("record_read: can't allocate pos buffer\n"); 
				record_cache_file_unlock (current->record_thrd->rp_cache_files, fd);
				return -ENOMEM;
			}
			*((u_int *) pretval) = 1;
			record_cache_file_unlock (current->record_thrd->rp_cache_files, fd);
			*((loff_t *) (pretval+sizeof(u_int))) = filp->f_pos - rc;

#ifdef TRACE_READ_WRITE
			do {
				struct replayfs_filemap_entry *entry;
				struct replayfs_filemap map;

				size_t cpy_size;

				struct replayfs_filemap_entry *args;
				replayfs_filemap_init(&map, &replayfs_alloc, filp);
				
				entry = replayfs_filemap_read(&map, filp->f_pos - rc, rc);

				if (IS_ERR(entry) || entry == NULL) {
					entry = kmalloc(sizeof(struct replayfs_filemap_entry), GFP_KERNEL);
					/* FIXME: Handle this properly */
					BUG_ON(entry == NULL);
					entry->num_elms = 0;
				}

				cpy_size = sizeof(struct replayfs_filemap_entry) +
						(entry->num_elms * sizeof(struct replayfs_filemap_value));

				args = ARGSKMALLOC(cpy_size, GFP_KERNEL);

				memcpy(args, entry, cpy_size);

				kfree(entry);

				replayfs_filemap_destroy(&map);
			} while (0);
#endif
#ifdef TRACE_PIPE_READ_WRITE
		/* If this is is a pipe */
		} else if (is_pipe(filp)) {
			struct replayfs_filemap map;
			u_int *is_cached;
			u64 rg_id = current->record_thrd->rp_group->rg_id;
			struct pipe_track *info;
			/* Wohoo, we have a pipe.  Lets track its writer */

			is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);

			pretval = (char *)is_cached;

			*is_cached = READ_IS_PIPE;

			/* We have to lock our pipe tree externally */
			mutex_lock(&pipe_tree_mutex);

			info = btree_lookup32(&pipe_tree, (u32)filp->f_dentry->d_inode->i_pipe);

			/* The pipe is not in the tree, this is its first write (by a recorded process) */
			if (info == NULL) {
				/* Create a new pipe_track */
				info = kmalloc(sizeof(struct pipe_track), GFP_KERNEL);
				/* Crap... no memory */
				if (info == NULL) {
					/* FIXME: fail cleanly */
					BUG();
				}

				mutex_init(&info->lock);

				/* Now initialize the structure */
				info->owner_read_id = rg_id;
				info->owner_write_id = 0;
				info->id = atomic_inc_return(&glbl_pipe_id);

				info->owner_write_pos = 0;
				info->owner_read_pos = rc;

				info->key.id1 = filp->f_dentry->d_inode->i_ino;
				info->key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

				info->shared = 0;
				if (btree_insert32(&pipe_tree, (u32)filp->f_dentry->d_inode->i_pipe, info, GFP_KERNEL)) {
					/* FIXME: fail cleanly */
					BUG();
				}

				mutex_unlock(&pipe_tree_mutex);
			/* The pipe is in the tree, update it */
			} else {
				/* We lock the pipe before we unlock the tree, to ensure that the pipe updates are orded with respect to lookup in the tree */
				mutex_lock(&info->lock);
				mutex_unlock(&pipe_tree_mutex);

				/* If the pipe is exclusive, don't keep any data about it */
				if (info->shared == 0) {
					/* It hasn't been read yet */
					if (unlikely(info->owner_read_id == 0)) {
						info->owner_read_id = rg_id;
						BUG_ON(info->owner_read_pos != 0);
						info->owner_read_pos = rc;
					/* If it continues to be exclusive */
					} else if (likely(info->owner_read_id == rg_id)) {
						info->owner_read_pos += rc;
					/* This is the un-sharing read */
					} else {
						info->shared = 1;

						/* Okay, we need to allocate a filemap for this file */
						replayfs_filemap_init(&map, &replayfs_alloc, filp);

						/* Write a record of the old data, special case of 0 means held linearly in pipe */
						replayfs_filemap_write(&map, info->owner_write_id, 0, info->id, 0, 0, info->owner_write_pos);

						/* Now append a read record indicating the data we have */
						*is_cached |= READ_PIPE_WITH_DATA;

						info->owner_read_pos += rc;
					}
				} else {

					/* Okay, we need to allocate a filemap for this file */
					replayfs_filemap_init(&map, &replayfs_alloc, filp);

					*is_cached |= READ_PIPE_WITH_DATA;

					info->owner_read_pos += rc;
				}

				mutex_unlock(&info->lock);
			}

			/* If this is a shared pipe, we will mark multiple writers, and save all the writer data */
			if (*is_cached & READ_PIPE_WITH_DATA) {
				struct replayfs_filemap_entry *args;
				struct replayfs_filemap_entry *entry;
				int cpy_size;

				/* Append the data */
				entry = replayfs_filemap_read(&map, info->owner_read_pos - rc, rc);
			
				if (IS_ERR(entry) || entry == NULL) {
					entry = kmalloc(sizeof(struct replayfs_filemap_entry), GFP_KERNEL);
					entry->num_elms = 0;
				}

				cpy_size = sizeof(struct replayfs_filemap_entry) +
						(entry->num_elms * sizeof(struct replayfs_filemap_value));

				args = ARGSKMALLOC(cpy_size + rc, GFP_KERNEL);

				memcpy(args, entry, cpy_size);

				kfree(entry);

				replayfs_filemap_destroy(&map);

				memcpy(((char *)args) + cpy_size, buf, rc);
			/* Otherwise, we just need to know the source id of this pipe */
			} else {
				struct pipe_track *info;
				char *buff = ARGSKMALLOC(sizeof(u64) + sizeof(int) + rc, GFP_KERNEL);
				u64 *writer = (void *)buff;
				int *id = (int *)(writer +1);
				mutex_lock(&pipe_tree_mutex);
				info = btree_lookup32(&pipe_tree, (u32)filp->f_dentry->d_inode->i_pipe);
				mutex_lock(&info->lock);
				mutex_unlock(&pipe_tree_mutex);
				BUG_ON(info == NULL);
				*writer = info->owner_write_id;
				*id = info->id;
				mutex_unlock(&info->lock);

				memcpy(buff+sizeof(u64)+sizeof(int), buf, rc);
			}
#endif
#ifdef TRACE_SOCKET_READ_WRITE
		} else if (sock_from_file(filp, &err)) {
			struct socket *socket = sock_from_file(filp, &err);

			if (socket->ops == &unix_stream_ops || socket->ops == &unix_seqpacket_ops) {
				int ret;
				ret = track_usually_pt2pt_read(socket->sk, rc, filp);
				if (ret) {
					return ret;
				}
			} else {
				u_int *is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);
				if (is_cached == NULL) {
					return -ENOMEM;
				}
				*is_cached = 0;
			}

			/* FIXME: This is... hacky */
			pretval = ARGSKMALLOC (rc, GFP_KERNEL);
			if (copy_from_user (pretval, buf, rc)) { 
				printk ("record_read: can't copy to buffer\n"); 
				ARGSKFREE(pretval, rc);	
				return -EFAULT;
			}
#endif 
		} else {
			pretval = ARGSKMALLOC (rc+sizeof(u_int), GFP_KERNEL);
			if (pretval == NULL) {
				printk ("record_read: can't allocate buffer\n"); 
				return -ENOMEM;
			}
			*((u_int *) pretval) = 0;
			if (copy_from_user (pretval+sizeof(u_int), buf, rc)) { 
				printk ("record_read: can't copy to buffer\n"); 
				ARGSKFREE(pretval, rc+sizeof(u_int));	
				return -EFAULT;
			}
		}
	} else if (is_cache_file) {
		record_cache_file_unlock (current->record_thrd->rp_cache_files, fd);
	}

	new_syscall_exit (3, pretval);				
	return rc;							
}

static asmlinkage long 
replay_read (unsigned int fd, char __user * buf, size_t count)
{
	char *retparams = NULL;
	long retval, rc = get_next_syscall (3, &retparams);
	int cache_fd;

	if (retparams) {
#if defined(TRACE_PIPE_READ_WRITE) || defined(REPLAY_COMPRESS_READS)
		u_int is_cache_file = *((u_int *)retparams);
#endif
		int consume_size;

#ifdef REPLAY_COMPRESS_READS
		if (is_cache_file & IS_RECORDED_FILE) {
			struct replayfs_filemap_entry *entry = (void *)(retparams + sizeof(u_int));
			struct replayfs_syscache_id id;
			int buff_offs = 0;
			int i;

			BUG_ON(!access_ok(VERIFY_WRITE, buf, rc));

			/* We've recorded the origin tracking info, so we'll just copy the data from the right chunks */
			/* Here comes the syscache */
			/* Foreach elm in entry */
			for (i = 0; i < entry->num_elms; i++) {
				struct replayfs_disk_alloc *alloc;
				struct replayfs_filemap_value *val = &entry->elms[i];
				loff_t entry_pos;

				int copy_offs;

				/* Get alloc pos ref'd by entry */
				id.unique_id = val->bval.id.unique_id;
				id.pid = val->bval.id.pid;
				id.sysnum = val->bval.id.sysnum;

				entry_pos = replayfs_syscache_get(&syscache, &id);
				/* Entry should be > 0, otherwise there is a problem */
				BUG_ON(entry_pos < 0);

				/* Get the disk_alloc referenced by entry */
				alloc = replayfs_disk_alloc_get(&replayfs_alloc, entry_pos);

				copy_offs = val->read_offset + val->bval.buff_offs;

				/* Copy the data into user space */
				/* I've already checked access_ok, so I'm just doing a normal copy now */
				replayfs_disk_alloc_read(alloc, buf + buff_offs, val->size, copy_offs + sizeof(struct replayfs_syscache_entry));

				buff_offs += val->size;

				replayfs_disk_alloc_put(alloc);
			}

			/* Consume args */
			consume_size = sizeof(u_int) + sizeof(struct replayfs_filemap_entry) +
					(entry->num_elms * sizeof(struct replayfs_filemap_value));

			argsconsume (current->replay_thrd->rp_record_thread, consume_size); 

			/* Return data */
		} else
#endif
		if (is_replay_cache_file(current->replay_thrd->rp_cache_files, fd, &cache_fd)) {
			// read from the open cache file
			loff_t off = *((loff_t *) (retparams+sizeof(u_int)));
			DPRINT ("read from cache file %d files %p bytes %ld off %ld\n", cache_fd, current->replay_thrd->rp_cache_files, rc, (u_long) off);
			retval = sys_pread64 (cache_fd, buf, rc, off);
			if (retval != rc) {
				printk ("pid %d read from cache file %d files %p orig fd %u off %ld returns %ld not expected %ld\n", current->pid, cache_fd, current->replay_thrd->rp_cache_files, fd, (long) off, retval, rc);
				return syscall_mismatch();
			}
			consume_size = sizeof(u_int) + sizeof(loff_t);
			argsconsume (current->replay_thrd->rp_record_thread, consume_size);

#ifdef TRACE_READ_WRITE
			do {
				struct replayfs_filemap_entry *entry = (void *)(retparams + consume_size);

				consume_size = sizeof(struct replayfs_filemap_entry) +
						(entry->num_elms * sizeof(struct replayfs_filemap_value));

				argsconsume (current->replay_thrd->rp_record_thread, consume_size); 
			} while (0);
#endif
#ifdef TRACE_PIPE_READ_WRITE
		} else if (is_cache_file & READ_PIPE_WITH_DATA) {
			struct replayfs_filemap_entry *entry;

			consume_size = sizeof(u_int);
			entry = (void *)(retparams + consume_size);

			consume_size += sizeof(struct replayfs_filemap_entry) +
					(entry->num_elms * sizeof(struct replayfs_filemap_value));

			if (copy_to_user (buf, retparams+consume_size, rc)) printk ("replay_read: pid %d cannot copy to user\n", current->pid); 

			argsconsume (current->replay_thrd->rp_record_thread, consume_size + rc);
		} else if (is_cache_file & READ_IS_PIPE) {
			consume_size = sizeof(u_int) + sizeof(u64) + sizeof(int);

			if (copy_to_user (buf, retparams+consume_size, rc)) printk ("replay_read: pid %d cannot copy to user\n", current->pid); 

			argsconsume (current->replay_thrd->rp_record_thread, consume_size + rc);
#endif
		} else {
			// uncached read
			DPRINT ("uncached read of fd %u\n", fd);
			if (copy_to_user (buf, retparams+sizeof(u_int), rc)) printk ("replay_read: pid %d cannot copy to user\n", current->pid);
			consume_size = sizeof(u_int)+rc;
			argsconsume (current->replay_thrd->rp_record_thread, consume_size); 
		}
	}

	return rc;							
}									

asmlinkage ssize_t shim_read (unsigned int fd, char __user * buf, size_t count) SHIM_CALL (read, 3, fd, buf, count);
#else
RET1_COUNT_SHIM3(read, 3, buf, unsigned int, fd, char __user *, buf, size_t, count);
#endif

static asmlinkage ssize_t 
record_write (unsigned int fd, const char __user * buf, size_t count)
{
	char *pretparams = NULL;
	ssize_t size;
	char kbuf[80];
#ifdef TRACE_SOCKET_READ_WRITE
	int err;
#endif

	if (fd == 99999) {  // Hack that assists in debugging user-level code
		new_syscall_enter (4);
		new_syscall_done (4, count);			       
		memset (kbuf, 0, sizeof(kbuf));
		if (copy_from_user (kbuf, buf, count < 79 ? count : 80)) printk ("record_write: cannot copy kstring\n");
		printk ("Pid %d clock %d logged clock %ld records: %s", current->pid, atomic_read(current->record_thrd->rp_precord_clock)-1, current->record_thrd->rp_expected_clock-1, kbuf);
		new_syscall_exit (4, NULL);
		return count;
	}


#ifdef TRACE_PIPE_READ_WRITE
	do {
		struct file *filp;
		filp = fget(fd);

		if (filp && is_pipe(filp)) {
			int ret;
			ret = track_usually_pt2pt_write_begin(filp->f_dentry->d_inode, filp);

			fput(filp);
		}
	} while (0);
#endif
#ifdef TRACE_SOCKET_READ_WRITE
	do {
		int err = 0;
		struct socket *sock = sockfd_lookup(fd, &err);

		if (sock != NULL && (sock->ops == &unix_stream_ops || sock->ops == &unix_seqpacket_ops)) {
			int ret;
			struct sock *peer;
			struct sock *sk = sock->sk;
			peer = unix_peer_get(sk);
			ret = track_usually_pt2pt_write_begin(peer, sock->file);
			sock_put(peer);

			fput(sock->file);
		}
	} while (0);
#endif
	/* Okay... this is tricky... */
#ifdef REPLAY_COMPRESS_READS
	/* We tweak the write of this file into the modification of its btree, oh yeah */
	/* NOTE: iff (its a "replay" file) */
	if (is_recorded_file(fd)) {
		loff_t fpos;
		struct replay_recorded_file_meta *meta;
		struct replayfs_syscache_id id;
		struct replayfs_filemap *map;
		struct file *filp;

		meta = replay_get_file_meta(fd);

		map = &meta->map;
		new_syscall_enter (4);

		filp = fget(fd);
		BUG_ON(filp == NULL);
		/* 
		 * We hack to use a bit in the pretparams to tell the replay that this write 
		 * should be saved in the syscache on replay...
		 */
		if (!pretparams) {
			pretparams = (void *)1;
		}

		/* 
		 * All right, our btree is recording straight into this file, so
		 * all we have to do is tweak our btree (and for performand update the syscache)
		 */

		fpos = filp->f_pos;

		//printk("%s %d: Doing filemap write for data\n", __func__, __LINE__);
		size = count;
		replayfs_filemap_write(map, current->record_thrd->rp_group->rg_id,
				current->record_thrd->rp_record_pid, current->record_thrd->rp_count, 0, fpos, size);

		filp->f_pos += count;

		/* SYSCACHE!!! */
		id.sysnum = current->record_thrd->rp_count;
		id.unique_id = current->record_thrd->rp_group->rg_id;
		id.pid = current->record_thrd->rp_record_pid;

		replayfs_syscache_add(&syscache, &id, size, buf);

		update_size(filp, meta);

		fput(filp);

		new_syscall_done (4, size);			       
	} else {
		new_syscall_enter (4);
		size = sys_write (fd, buf, count);
		new_syscall_done (4, size);			       
	}
#else
	new_syscall_enter (4);
	size = sys_write (fd, buf, count);
	new_syscall_done (4, size);			       
#endif

#ifdef TRACE_READ_WRITE
	if (size > 0) {
		struct file *filp;
		struct inode *inode;

		filp = fget (fd);
		inode = filp->f_dentry->d_inode;

		if (inode->i_rdev == 0 && MAJOR(inode->i_sb->s_dev) != 0) {
			loff_t fpos;
			struct replayfs_filemap map;
			replayfs_filemap_init(&map, &replayfs_alloc, filp);

			fpos = filp->f_pos - size;
			if (fpos >= 0) {
				replayfs_filemap_write(&map, current->record_thrd->rp_group->rg_id, current->record_thrd->rp_record_pid, 
						current->record_thrd->rp_count, 0, fpos, size);
			}
			replayfs_filemap_destroy(&map);
#  ifdef TRACE_PIPE_READ_WRITE
		/* If this is is a pipe */
		} else if (is_pipe(filp)) {
			u64 rg_id = current->record_thrd->rp_group->rg_id;
			struct pipe_track *info;
			/* Wohoo, we have a pipe.  Lets track its writer */

			/* We have to lock our pipe tree externally */
			mutex_lock(&pipe_tree_mutex);

			info = btree_lookup32(&pipe_tree, (u32)filp->f_dentry->d_inode->i_pipe);

			/* The pipe is not in the tree, this is its first write (by a recorded process) */
			if (info == NULL) {
				/* Create a new pipe_track */
				info = kmalloc(sizeof(struct pipe_track), GFP_KERNEL);
				/* Crap... */
				if (info == NULL) {
					/* FIXME: fail cleanly */
					BUG();
				}

				mutex_init(&info->lock);

				/* Now initialize the structure */
				info->owner_read_id = 0;
				info->owner_write_id = rg_id;
				info->id = atomic_inc_return(&glbl_pipe_id);

				info->owner_write_pos = size;
				info->owner_read_pos = 0;

				info->key.id1 = filp->f_dentry->d_inode->i_ino;
				info->key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

				info->shared = 0;
				if (btree_insert32(&pipe_tree, (u32)filp->f_dentry->d_inode->i_pipe, info, GFP_KERNEL)) {
					/* FIXME: fail cleanly */
					BUG();
				}

				pretparams = ARGSKMALLOC(sizeof(int), GFP_KERNEL);
				BUG_ON(pretparams == NULL);
				*((int *)pretparams) = info->id;

				mutex_unlock(&pipe_tree_mutex);
			} else {
				mutex_lock(&info->lock);
				mutex_unlock(&pipe_tree_mutex);

				if (info->shared == 0) {
					if (info->owner_write_id == 0) {
						info->owner_write_id = rg_id;
						BUG_ON(info->owner_write_pos != 0);
						info->owner_write_pos = size;
						pretparams = ARGSKMALLOC(sizeof(int), GFP_KERNEL);
						BUG_ON(pretparams == NULL);
						*((int *)pretparams) = info->id;
					} else if (likely(info->owner_write_id == rg_id)) {
						info->owner_write_pos += size;
						pretparams = ARGSKMALLOC(sizeof(int), GFP_KERNEL);
						BUG_ON(pretparams == NULL);
						*((int *)pretparams) = info->id;
					/* This is the un-sharing write */
					} else {
						struct replayfs_filemap map;
						info->shared = 1;

						/* Okay, we need to allocate a filemap for this file */
						replayfs_filemap_init(&map, &replayfs_alloc, filp);

						/* Write a record of the old data, special case of 0 means held linearly in pipe */
						replayfs_filemap_write(&map, info->owner_write_id, 0, info->id, 0, 0, info->owner_write_pos);

						/* Write a record of our data */
						replayfs_filemap_write(&map, rg_id, current->record_thrd->rp_record_pid, current->record_thrd->rp_count, 0, info->owner_write_pos, size);

						replayfs_filemap_destroy(&map);

						info->owner_write_pos += size;
					}
				} else {
					struct replayfs_filemap map;

					/* Okay, we need to allocate a filemap for this file */
					replayfs_filemap_init(&map, &replayfs_alloc, filp);

					/* Write a record of our data */
					replayfs_filemap_write(&map, rg_id, current->record_thrd->rp_record_pid, current->record_thrd->rp_count, 0, info->owner_write_pos, size);

					replayfs_filemap_destroy(&map);

					info->owner_write_pos += size;
				}

				mutex_unlock(&info->lock);
			}
#  endif
#ifdef TRACE_SOCKET_READ_WRITE
		} else if (sock_from_file(filp, &err)) {
			struct socket *sock = sock_from_file(filp, &err);


			if (sock->ops == &unix_stream_ops || sock->ops == &unix_seqpacket_ops) {
				int ret;
				struct sock *peer;
				struct sock *sk = sock->sk;
				peer = unix_peer_get(sk);
				ret = track_usually_pt2pt_write(peer, size, filp, 0);
				sock_put(peer);
				if (ret) {
					//ARGSKFREE(pretvals, sizeof(struct generic_socket_retvals));
					return ret;
				}
				/* FIXME: in all honesty, new_syscall_exit is just looking for NULL/non-NULL, but this is hacky */
				pretparams = (void *)1;
			}
#endif
		}

		fput(filp);
	}
#endif
	new_syscall_exit (4, pretparams);

	return size;
}

static asmlinkage ssize_t 
replay_write (unsigned int fd, const char __user * buf, size_t count)
{
	ssize_t rc;
	char *pretparams = NULL;
	char kbuf[80];

	rc = get_next_syscall (4, &pretparams);
	if (fd == 99999) { // Hack that assists in debugging user-level code
		memset (kbuf, 0, sizeof(kbuf));
		if (copy_from_user (kbuf, buf, count < 80 ? count : 79)) printk ("replay_write: cannot copy kstring\n");
		printk ("Pid %d (recpid %d) clock %ld log_clock %ld replays: %s", current->pid, current->replay_thrd->rp_record_thread->rp_record_pid, *(current->replay_thrd->rp_preplay_clock), current->replay_thrd->rp_expected_clock - 1, kbuf);
	}
	DPRINT ("Pid %d replays write returning %d\n", current->pid,rc);
#ifdef REPLAY_COMPRESS_READS
	if (pretparams != NULL) {
		struct replayfs_syscache_id id;
		id.sysnum = current->replay_thrd->rp_out_ptr - 1;
		id.unique_id = current->replay_thrd->rp_record_thread->rp_group->rg_id;
		id.pid = current->replay_thrd->rp_record_thread->rp_record_pid;

		replayfs_syscache_add(&syscache, &id, rc, buf);

		/* We don't actually allocate any space! <insert evil laugh here> */
		//argsconsume (current->replay_thrd->rp_record_thread, sizeof(int));
	}
#elif defined(TRACE_PIPE_READ_WRITE)
	if (pretparams != NULL) {
		argsconsume (current->replay_thrd->rp_record_thread, sizeof(int));
	}
#endif

	return rc;
}

asmlinkage ssize_t shim_write (unsigned int fd, const char __user * buf, size_t count) SHIM_CALL (write, 4, fd, buf, count);

struct open_retvals {
	dev_t           dev;
	u_long          ino;
	struct timespec mtime;
};

#ifdef CACHE_READS
static asmlinkage long							
record_open (const char __user * filename, int flags, int mode)
{								
	struct file* file;
	struct inode* inode;
	struct open_retvals* recbuf = NULL;
	long rc;	

	new_syscall_enter (5);	      
	rc = sys_open (filename, flags, mode);
	new_syscall_done (5, rc);

	// If opened read-only and a regular file, then use replay cache
	if (rc >= 0) {
		/*
		file = fget(rc);
		inode = file->f_dentry->d_inode;
		fput(file);
		printk("%s %d: Opened %s to fd %ld with ino %lu\n", __func__, __LINE__, filename, rc, inode->i_ino);
		*/
		MPRINT ("record_open of name %s with flags %x\n", filename, flags);
		if ((flags&O_ACCMODE) == O_RDONLY && !(flags&(O_CREAT|O_DIRECTORY))) {
			file = fget (rc);
			inode = file->f_dentry->d_inode;
			DPRINT ("i_rdev is %x\n", inode->i_rdev);
			DPRINT ("i_sb->s_dev is %x\n", inode->i_sb->s_dev);
			if (inode->i_rdev == 0 && MAJOR(inode->i_sb->s_dev) != 0) {
				MPRINT ("This is an open that we can cache\n");
				recbuf = ARGSKMALLOC(sizeof(struct open_retvals), GFP_KERNEL);
				rg_lock (current->record_thrd->rp_group);
				/* Add entry to filemap cache */
				add_file_to_cache (file, &recbuf->dev, &recbuf->ino, &recbuf->mtime);
				if (set_record_cache_file (current->record_thrd->rp_cache_files, rc) < 0) fput(file);
				rg_unlock (current->record_thrd->rp_group);
			}
			fput (file);
		}
	}

	new_syscall_exit (5, recbuf);			
	return rc;
}								

static asmlinkage long				       
replay_open (const char __user * filename, int flags, int mode)
{	
	struct open_retvals* pretvals;
	long rc, fd;

	rc = get_next_syscall (5, (char **) &pretvals);	
	DPRINT ("replay_open: trying to open %s\n", filename);
	if (pretvals) {
		fd = open_cache_file (pretvals->dev, pretvals->ino, pretvals->mtime, flags);
		DPRINT ("replay_open: opened cache file %s flags %x fd is %ld rc is %ld\n", filename, flags, fd, rc);
		if (set_replay_cache_file (current->replay_thrd->rp_cache_files, rc, fd) < 0) sys_close (fd);
		argsconsume (current->replay_thrd->rp_record_thread, sizeof(struct open_retvals)); 
	}

	return rc;
}

asmlinkage long shim_open (const char __user * filename, int flags, int mode) SHIM_CALL (open, 5, filename, flags, mode);
#else
SIMPLE_SHIM3(open, 5, const char __user *, filename, int, flags, int, mode);
#endif

#ifdef CACHE_READS
static asmlinkage long							
record_close (int fd)
{									
	long rc;							
#ifdef REPLAY_COMPRESS_READS
	do {
		struct file *filp = fget(fd);
		if (filp != NULL) {
			replay_filp_close_internal((u32)filp->f_dentry->d_inode);
			fput(filp);
		}
	} while (0);
#endif
	new_syscall_enter (6);
	rc = sys_close (fd);
	new_syscall_done (6, rc);
	if (rc >= 0) clear_record_cache_file (current->record_thrd->rp_cache_files, fd);
	new_syscall_exit (6, NULL);				
	return rc;							
}								

static asmlinkage long				       
replay_close (int fd)
{	
	long rc;
	int cache_fd; 

	rc = get_next_syscall (6, NULL);
	if (rc >= 0 && is_replay_cache_file (current->replay_thrd->rp_cache_files, fd, &cache_fd)) {
		clear_replay_cache_file (current->replay_thrd->rp_cache_files, fd);
		DPRINT ("pid %d about to close cache fd %d fd %d\n", current->pid, cache_fd, fd);
		sys_close (cache_fd);
	}

	return rc;
}

asmlinkage long shim_close (int fd) SHIM_CALL (close, 6, fd);
#else
SIMPLE_SHIM1(close, 6, int, fd);
#endif

RET1_SHIM3(waitpid, 7, int, stat_addr, pid_t, pid, int __user *, stat_addr, int, options);
SIMPLE_SHIM2(creat, 8, const char __user *, pathname, int, mode);
SIMPLE_SHIM2(link, 9, const char __user *, oldname, const char __user *, newname);
SIMPLE_SHIM1(unlink, 10, const char __user *, pathname);

// This should be called with the record group lock
static int
add_file_to_cache_by_name (const char __user * filename, dev_t* pdev, u_long* pino, struct timespec* pmtime)
{
	mm_segment_t old_fs;
	struct file* file;
	int fd;

	old_fs = get_fs();
	set_fs (KERNEL_DS);
	fd = sys_open (filename, O_RDONLY, 0); // note that there is a race here if library is changed after syscall
	if (fd < 0) {
		printk ("add_file_to_cache_by_name: pid %d cannot open file %s\n", current->pid, filename);
		set_fs(old_fs);
		return -EINVAL;
	}
	file = fget (fd);
	if (file == NULL) {
		printk ("add_file_to_cache_by_name: pid %d cannot get file\n", current->pid);
		set_fs(old_fs);
		return -EINVAL;
	}
	add_file_to_cache (file, pdev, pino, pmtime);
	fput (file);
	sys_close (fd);
	set_fs (old_fs);

	return 0;
}

struct execve_retvals {
	u_char is_new_group;
	union {
		struct {
			struct rvalues     rvalues;
			struct exec_values evalues;
			dev_t              dev;
			u_long             ino;
			struct timespec    mtime;
		} same_group;
		struct {
			__u64           log_id;
		} new_group;
	} data;
};

// Simply recording the fact that an execve takes place, we won't replay it
static int 
record_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs) 
{
	struct execve_retvals* pretval = NULL;
	struct record_thread* prt = current->record_thrd;
	struct record_group* precg;
	struct record_thread* prect;
	void* slab;
	char ckpt[MAX_LOGDIR_STRLEN+10];
	long rc, retval;
	char* argbuf, *newbuf;
	int argbuflen, present;
	char** env;
	mm_segment_t old_fs;

	MPRINT ("Record pid %d performing execve of %s\n", current->pid, filename);
	new_syscall_enter (11);

	current->record_thrd->random_values.cnt = 0;

	// (flush) and write out the user log before exec-ing (otherwise it disappears)
#ifndef USE_DEBUG_LOG
	flush_user_log (prt);
#endif
	write_user_log (prt);
#ifdef USE_EXTRA_DEBUG_LOG
	write_user_extra_log (prt);
#endif
	// Have to copy arguments out before address space goes away - we will likely need them later
	argbuf = copy_args (__argv, __envp, &argbuflen);

	// Hack to support multiple glibcs - make sure that LD_LIBRARY_PATH is in there
	present = is_libpath_present (current->record_thrd->rp_group, argbuf);
	if (present) {
		// Need to copy environments to kernel and modify
		env = patch_for_libpath (current->record_thrd->rp_group, argbuf, present);
		newbuf = patch_buf_for_libpath (current->record_thrd->rp_group, argbuf, &argbuflen, present);
		if (env == NULL || newbuf == NULL) {
			printk ("libpath patch failed\n");
			return -ENOMEM;
		}
		KFREE (argbuf);
		argbuf = newbuf;
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		rc = do_execve(filename, __argv, (const char __user *const __user *) env, regs);
		set_fs(old_fs);
		libpath_env_free (env);
	} else {
		rc = do_execve(filename, __argv, __envp, regs);
	}

	new_syscall_done (11, rc);
	if (rc >= 0) {
		prt->rp_user_log_addr = 0; // User log address no longer valid since new address space entirely
#ifdef USE_EXTRA_DEBUG_LOG
		prt->rp_user_extra_log_addr = 0;
#endif
		// Our rule is that we record a split if there is an exec with more than one thread in the group.   Not sure this is best
		// but I don't know what is better
		if (prt->rp_next_thread != prt) {

			DPRINT ("New record group\n");

			// First setup new record group
			precg = new_record_group (NULL);
			if (precg == NULL) {
				current->record_thrd = NULL;
				return -ENOMEM;
			}
			strcpy (precg->rg_linker, prt->rp_group->rg_linker);
			precg->rg_save_mmap_flag = prt->rp_group->rg_save_mmap_flag;

			MPRINT ("Pid %d - splits a new record group with logdir %s, save_mmap_flag %d\n", current->pid, precg->rg_logdir, precg->rg_save_mmap_flag);

			if (prt->rp_group->rg_libpath) {
				precg->rg_libpath = KMALLOC(strlen(prt->rp_group->rg_libpath)+1, GFP_KERNEL);
				if (precg->rg_libpath == NULL) {
					printk ("Unable to allocate libpath on execve\n");
					current->record_thrd = NULL;
					return -ENOMEM;
				}
				strcpy (precg->rg_libpath, prt->rp_group->rg_libpath);
			}

			prect = new_record_thread (precg, current->pid, NULL);
			if (prect == NULL) {
				destroy_record_group (precg);
				current->record_thrd = NULL;
				return -ENOMEM;
			}
			memcpy (&prect->random_values, &prt->random_values, sizeof(prt->random_values));
			memcpy (&prect->exec_values, &prt->exec_values, sizeof(prt->exec_values));

			slab = VMALLOC (argsalloc_size);
			if (slab == NULL) {
				destroy_record_group (precg);
				current->record_thrd = NULL;
				return -ENOMEM;
			}

			if (add_argsalloc_node(current->record_thrd, slab, argsalloc_size)) {
				VFREE (slab);
				destroy_record_group (precg);
				current->record_thrd = NULL;
				return -ENOMEM;
			}
			// Now write last record to log and flush it to disk
			pretval = ARGSKMALLOC(sizeof(struct execve_retvals), GFP_KERNEL);
			if (pretval == NULL) {
				printk ("Unable to allocate space for execve retvals\n");
				return -ENOMEM;
			}
			pretval->is_new_group = 1;
			pretval->data.new_group.log_id = precg->rg_id;
			new_syscall_exit (11, pretval); 
			write_and_free_kernel_log (prt);

			if (atomic_dec_and_test(&prt->rp_group->rg_record_threads)) {
				rg_lock (prt->rp_group);
				MPRINT ("Pid %d last record thread to exit, write out mmap log\n", current->pid);
				write_mmap_log(prt->rp_group);
				prt->rp_group->rg_save_mmap_flag = 0;
				rg_unlock (prt->rp_group);
			}

			__destroy_record_thread (prt);  // The old group may no longer be valid after this

			// Switch thread to new record group
			current->record_thrd = prt = prect;

			// Write out checkpoint for the new group
			sprintf (ckpt, "%s/ckpt", precg->rg_logdir);
			retval = replay_checkpoint_to_disk (ckpt, (char *) filename, argbuf, argbuflen);
			if (retval) {
				printk ("record_execve: replay_checkpoint_to_disk returns %ld\n", retval);
				VFREE (slab);
				destroy_record_group (precg);
				current->record_thrd = NULL;
				return retval;
			}
			argbuf = NULL;

			// Write out first log record (exec) for the new group - the code below will finish the job
			new_syscall_enter (11);
			new_syscall_done (11, 0);
		} else {
#ifdef CACHE_READS
			close_record_cache_files(prt->rp_cache_files); // This is conservative - some files may not have been closed on exec - but it is correct
#endif
			prt->rp_ignore_flag_addr = NULL; // No longer valid since address space destroyed
		}

		pretval = ARGSKMALLOC(sizeof(struct execve_retvals), GFP_KERNEL);
		if (pretval == NULL) {
			printk ("Unable to allocate space for execve retvals\n");
			return -ENOMEM;
		}

		pretval->is_new_group = 0;
		memcpy (&pretval->data.same_group.rvalues, &prt->random_values, sizeof (struct rvalues));
		memcpy (&pretval->data.same_group.evalues, &prt->exec_values, sizeof (struct exec_values));
		rg_lock(prt->rp_group);
		add_file_to_cache_by_name (filename, &pretval->data.same_group.dev, &pretval->data.same_group.ino, &pretval->data.same_group.mtime);
		rg_unlock(prt->rp_group);
	}
	if (argbuf) KFREE (argbuf);
	new_syscall_exit (11, pretval);
	return rc;
}

void complete_vfork_done(struct task_struct *tsk); // In fork.c

// need to advance the record log past the execve, but we don't replay it
// We need to record that an exec happened in the log for knowing when to clear
// preallocated memory in a forked process
static int
replay_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs) 
{
	struct replay_thread* prt = current->replay_thrd;
	struct replay_thread* tmp;
	struct replay_group* prg = prt->rp_group;
	struct syscall_result* psr;
	struct execve_retvals* retparams = NULL;
	mm_segment_t old_fs;
	long rc, retval;
	char name[CACHE_FILENAME_SIZE], logdir[MAX_LOGDIR_STRLEN+1], linker[MAX_LOGDIR_STRLEN+1]; 
	int num_blocked, follow_splits;
	u_long clock, app_syscall_addr;
	__u64 logid;

	retval = get_next_syscall_enter (prt, prg, 11, (char **) &retparams, &psr);  // Need to split enter/exit because of vfork/exec wait
	if (retval >= 0) {

#ifdef CACHE_READS
		close_replay_cache_files (prt->rp_cache_files); // Simpler to just close whether group survives or not
#endif
		if (retparams->is_new_group) {
			if (current->vfork_done) complete_vfork_done (current);

			get_next_syscall_exit (prt, prg, psr);

			if (prg->rg_follow_splits) {

				DPRINT ("Following split\n");
				// Let some other thread in this group run because we are done
				get_record_group(prg->rg_rec_group);
				rg_lock (prg->rg_rec_group);
				clock = *prt->rp_preplay_clock;
				prt->rp_status = REPLAY_STATUS_DONE;  
				tmp = prt->rp_next_thread;
				num_blocked = 0;
				while (tmp != prt) {
					DPRINT ("Pid %d considers thread %d status %d clock %ld - clock is %ld\n", current->pid, tmp->rp_replay_pid, tmp->rp_status, tmp->rp_wait_clock, clock);
					if (tmp->rp_status == REPLAY_STATUS_ELIGIBLE || (tmp->rp_status == REPLAY_STATUS_WAIT_CLOCK && tmp->rp_wait_clock <= clock)) {
						tmp->rp_status = REPLAY_STATUS_RUNNING;
						wake_up (&tmp->rp_waitq);
						break;
					} else if (tmp->rp_status != REPLAY_STATUS_DONE) {
						num_blocked++;
					}
					tmp = tmp->rp_next_thread;
					if (tmp == prt && num_blocked) {
						printk ("Pid %d (recpid %d): Crud! no elgible thread to run on exit, clock is %ld\n", current->pid, prt->rp_record_thread->rp_record_pid, clock);
						dump_stack(); // how did we get here?
						// cycle around again and print
						tmp = tmp->rp_next_thread;
						while (tmp != current->replay_thrd) {
							printk("\t thread %d (recpid %d) status %d clock %ld\n", tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock);
							tmp = tmp->rp_next_thread;
						}
					}
				}
				
				// Save id because group may be deleted
				logid = retparams->data.new_group.log_id;
				app_syscall_addr = prt->app_syscall_addr;
				strcpy (linker, prg->rg_rec_group->rg_linker);
				follow_splits = prg->rg_follow_splits;

				// Now remove reference to the replay group
				put_replay_group (prg);
				current->replay_thrd = NULL;
				rg_unlock(prg->rg_rec_group);
				put_record_group(prg->rg_rec_group);
				
				// Now start a new group if needed
				get_logdir_for_replay_id (logid, logdir);
				return replay_ckpt_wakeup (app_syscall_addr, logdir, linker, -1, follow_splits, prg->rg_rec_group->rg_save_mmap_flag);
			} else {
				DPRINT ("Don't follow splits - so just exit\n");
				sys_exit_group (0);
			}
		} else {
			MPRINT ("Replay pid %d performing execve of %s\n", current->pid, filename);
			memcpy (&current->replay_thrd->random_values, &retparams->data.same_group.rvalues, sizeof(struct rvalues));
			memcpy (&current->replay_thrd->exec_values, &retparams->data.same_group.evalues, sizeof(struct exec_values));
			argsconsume(prt->rp_record_thread, sizeof(struct execve_retvals));      
			current->replay_thrd->random_values.cnt = 0;

			rg_lock(prt->rp_record_thread->rp_group);
			get_cache_file_name (name, retparams->data.same_group.dev, retparams->data.same_group.ino, retparams->data.same_group.mtime);
			rg_unlock(prt->rp_record_thread->rp_group);

			old_fs = get_fs();
			set_fs(KERNEL_DS);
			prt->rp_exec_filename = filename;
			MPRINT ("%s %d: do_execve(%s, %p, %p, %p)\n", __func__, __LINE__, name, __argv, __envp, regs);
			rc = do_execve (name, __argv, __envp, regs);
			set_fs(old_fs);

			prt->rp_record_thread->rp_ignore_flag_addr = NULL;

			if (rc != retval) {
				printk ("[ERROR] Replay pid %d sees execve return %ld, recorded rc was %ld\n", current->pid, rc, retval);
				syscall_mismatch();
			}
		}

		/* Irregardless of splitting, if pin is attached we'll try to attach */
		if (is_pin_attached()) {
			prt->app_syscall_addr = 1; /* We need to reattach the pin tool after exec */
			preallocate_memory (prt->rp_record_thread->rp_group); /* And preallocate memory again - our previous preallocs were just destroyed */
			create_used_address_list ();
		}
	}
	get_next_syscall_exit (prt, prg, psr);

	MPRINT ("replay_execve: sp is %lx, ip is %lx\n", regs->sp, regs->ip);

	return retval;
}

int shim_execve(const char *filename, const char __user *const __user *__argv, const char __user *const __user *__envp, struct pt_regs *regs) 
SHIM_CALL_MAIN(11, record_execve(filename, __argv, __envp, regs), replay_execve(filename, __argv, __envp, regs), do_execve(filename, __argv, __envp, regs))

SIMPLE_SHIM1(chdir, 12, const char __user *, filename);

static asmlinkage long 
record_time(time_t __user * tloc)
{
	long rc;
	time_t* pretval = NULL;

	new_syscall_enter (13);
	rc = sys_time (tloc);
	new_syscall_done (13, rc);
	DPRINT ("Pid %d records time returning %ld\n", current->pid, rc);
	if (tloc) {
		pretval = ARGSKMALLOC(sizeof(time_t), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_time: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, tloc, sizeof(time_t))) {
			printk("record_time: can't copy from user\n");
			ARGSKFREE (pretval, sizeof(time_t));
			return -EFAULT;
		}
	}
	new_syscall_exit (13, pretval); 

	return rc;
}

RET1_REPLAY(time, 13, time_t, tloc, time_t __user * tloc);

asmlinkage long shim_time(time_t __user * tloc) SHIM_CALL (time, 13, tloc);

SIMPLE_SHIM3 (mknod, 14, const char __user *, filename, int, mode, unsigned, dev);
SIMPLE_SHIM2(chmod, 15, const char __user *, filename, mode_t,  mode);
SIMPLE_SHIM3(lchown16, 16, const char __user *, filename, old_uid_t, user, old_gid_t, group);
RET1_SHIM2(stat, 18, struct __old_kernel_stat, statbuf, char __user *, filename, struct __old_kernel_stat __user *, statbuf);
SIMPLE_SHIM3(lseek, 19, unsigned int, fd, off_t, offset, unsigned int, origin);
SIMPLE_SHIM0(getpid, 20);
SIMPLE_SHIM5(mount, 21, char __user *, dev_name, char __user *, dir_name, char __user *, type, unsigned long, flags, void __user *, data);
SIMPLE_SHIM1(oldumount, 22, char __user *, name);
SIMPLE_SHIM1(setuid16, 23, uid_t, uid);
SIMPLE_SHIM0(getuid16, 24);
SIMPLE_SHIM1(stime, 25, time_t __user*, tptr);

static asmlinkage long 
record_ptrace(long request, long pid, long addr, long data)
{
	struct task_struct* tsk = pid_task (find_vpid(pid), PIDTYPE_PID);
	long rc;						

	if (tsk) { // Invalid pid should fail, so replay is easy
		if (!tsk->record_thrd) {
			printk ("[ERROR] pid %d records ptrace of non-recordig pid %ld\n", current->pid, pid);
			return sys_ptrace(request, pid, addr, data);
		} else if (tsk->record_thrd->rp_group != current->record_thrd->rp_group) {
			printk ("[ERROR] pid %d records ptrace of pid %ld in different record group - must merge\n", current->pid, pid);
			return sys_ptrace(request, pid, addr, data);
		} // Now we know two tasks are in same record group, so memory ops should be deterministic (unless they incorrectly involve replay-specific structures) */
	}

	new_syscall_enter (26);
	rc = sys_ptrace(request, pid, addr, data);
	new_syscall_done (26, rc);
	new_syscall_exit (26, NULL);				
	return rc;						
}

static asmlinkage long 
replay_ptrace(long request, long pid, long addr, long data)
{
	struct replay_thread* tmp;
	long rc, retval;

	rc = get_next_syscall (26, NULL);	

	// Need to adjust pid to reflect the replay process, not the record process
	tmp = current->replay_thrd->rp_next_thread;
	while (tmp != current->replay_thrd) {
		if (tmp->rp_record_thread->rp_record_pid == pid) {
			retval = sys_ptrace (request, tmp->rp_record_thread->rp_record_pid, addr, data);
			if (rc != retval) {
				printk ("ptrace returns %ld on replay but returned %ld on record\n", retval, rc);
				syscall_mismatch();
			}
			return rc;
		}
	}
	printk ("ptrace: pid %d cannot find record pid %ld in replay group\n", current->pid, pid);
	return syscall_mismatch();
}

asmlinkage long shim_ptrace(long request, long pid, long addr, long data)
{
	// Paranoid check
	if (!(current->record_thrd  || current->replay_thrd)) {
		struct task_struct* tsk = pid_task (find_vpid(pid), PIDTYPE_PID);
		if (tsk && tsk->record_thrd) {
			printk ("[ERROR]: non-recorded process %d ptracing the address space of recorded thread %ld\n", current->pid, pid);
		}
	}
	SHIM_CALL(ptrace, 26, request, pid, addr, data)
}

SIMPLE_SHIM1(alarm, 27, unsigned int, seconds);
RET1_SHIM2(fstat, 28, struct __old_kernel_stat, statbuf, unsigned int, fd, struct __old_kernel_stat __user *, statbuf);
SIMPLE_SHIM0(pause, 29);
SIMPLE_SHIM2(utime, 30, char __user *, filename, struct utimbuf __user *, times);

SIMPLE_SHIM2(access, 33, const char __user *, filename, int, mode);
SIMPLE_SHIM1 (nice, 34, int, increment);
SIMPLE_SHIM0(sync, 36);
SIMPLE_SHIM2(kill, 37, int, pid, int, sig);
SIMPLE_SHIM2(rename, 38, const char __user *, oldname, const char __user *, newname);
SIMPLE_SHIM2(mkdir, 39, const char __user *, pathname, int, mode);
SIMPLE_SHIM1(rmdir, 40, const char __user *, pathname);
SIMPLE_SHIM1(dup, 41, unsigned int, fildes);

asmlinkage long 
record_pipe (int __user *fildes)
{
	long rc;
	int* pretval = NULL;

	new_syscall_enter (42);
	rc = sys_pipe (fildes);
	new_syscall_done (42, rc);
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
	new_syscall_exit (42, pretval);

	return rc;
}

RET1_REPLAYG(pipe, 42, fildes, 2*sizeof(int), int __user* fildes);

asmlinkage long shim_pipe (int __user *fildes) SHIM_CALL(pipe, 42, fildes);

RET1_SHIM1(times, 43, struct tms, tbuf, struct tms __user *, tbuf);

static asmlinkage unsigned long 
record_brk (unsigned long brk)
{
	unsigned long rc;

	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (45);
	rc = sys_brk (brk);
	new_syscall_done (45, rc);
	new_syscall_exit (45, NULL);
	rg_unlock(current->record_thrd->rp_group);

	return rc;
}	

static asmlinkage unsigned long 
replay_brk (unsigned long brk)
{
	u_long retval, rc = get_next_syscall (45, NULL);
	retval = sys_brk(brk);
	if (rc != retval) {
		printk ("Replay brk returns different value %lx than %lx\n", retval, rc);
		syscall_mismatch();
	}
	return rc;
}

asmlinkage unsigned long shim_brk (unsigned long abrk) SHIM_CALL(brk, 45, abrk);
SIMPLE_SHIM1 (setgid16, 46, old_gid_t, gid);
SIMPLE_SHIM0(getgid16, 47);
SIMPLE_SHIM2(signal, 48, int, sig, __sighandler_t, handler);
SIMPLE_SHIM0(geteuid16, 49);
SIMPLE_SHIM0(getegid16, 50);
SIMPLE_SHIM1(acct, 51, char __user *, name)
SIMPLE_SHIM2(umount, 52, char __user *, name, int, flags);

static asmlinkage long 
record_ioctl (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	char* recbuf = NULL;
	long rc = 0;
	int dir;
	int size;

	switch (cmd) {
	case TCSBRK:
	case TCSBRKP:
	case TIOCSBRK:
	case TIOCCBRK:
	case TCFLSH:
	case TIOCEXCL:
	case TIOCNXCL:
	case TIOCSCTTY:
 	case FIOCLEX:
	case FIONCLEX:
	case TIOCCONS:
	case TIOCNOTTY:
	case TIOCVHANGUP:
	case TIOCSERCONFIG:
	case TIOCSERGWILD:
	case TIOCSERSWILD:
	case TIOCMIWAIT:
		dir = _IOC_NONE;
		size = 0;
 		break;
	case TIOCSTI:
		dir = _IOC_READ;
		size = sizeof(char);
		break;
	case TIOCLINUX:
		dir = _IOC_READ | _IOC_WRITE;
		size = sizeof(char);
		break;
	case FIONBIO:
	case FIOASYNC:
	case FIBMAP:
	case TCXONC:
	case TIOCMBIS:
	case TIOCMBIC:
	case TIOCMSET:
	case TIOCSSOFTCAR:
	case TIOCPKT:
	case TIOCSETD:
		dir = _IOC_READ;
		size = sizeof(int);
		break;
	case TIOCOUTQ:
	case FIGETBSZ:
	case FIONREAD:
	case TIOCMGET:
	case TIOCGSOFTCAR:
	case TIOCGETD:
	case TIOCSERGETLSR:
		dir = _IOC_WRITE;
		size = sizeof(int);
		break;
	case FIOQSIZE:
		dir = _IOC_WRITE;
		size = sizeof(loff_t);
		break;
	case TCGETA:
	case TCGETS:
		dir = _IOC_WRITE;
		size = sizeof(struct termios);
		break;
	case TCSETA:
	case TCSETS:
	case TCSETAW:
	case TCSETAF:
	case TCSETSW:
	case TCSETSF:
		dir = _IOC_READ;
		size = sizeof(struct termios);
		break;
	case TIOCGSID:
		dir = _IOC_WRITE;
		size = sizeof(pid_t);
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
	case TIOCGSERIAL:
		dir = _IOC_WRITE;
		size = sizeof(struct serial_struct);
		break;
	case TIOCSSERIAL:
		dir = _IOC_READ;
		size = sizeof(struct serial_struct);
		break;
	case TIOCGRS485:
		dir = _IOC_WRITE;
		size = sizeof(struct serial_rs485);
		break;
	case TIOCSRS485:
		dir = _IOC_READ;
		size = sizeof(struct serial_rs485);
		break;
	case TCGETX:
		dir = _IOC_WRITE;
		size = sizeof(struct termiox);
		break;
	case TCSETX:
	case TCSETXW:
	case TCSETXF:
		dir = _IOC_READ;
		size = sizeof(struct termiox);
		break;
	case TIOCGLCKTRMIOS:
		dir = _IOC_WRITE;
		size = sizeof(struct termios);
		break;
	case TIOCSLCKTRMIOS:
		dir = _IOC_READ;
		size = sizeof(struct termios);
		break;
	case TIOCGICOUNT:
		dir = _IOC_WRITE;
		size = sizeof(struct serial_icounter_struct);
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

	new_syscall_enter (54);
	if (rc == 0) rc = sys_ioctl (fd, cmd, arg);
	new_syscall_done (54, rc);

	DPRINT ("Pid %d records ioctl fd %d cmd 0x%x arg 0x%lx returning %ld\n", current->pid, fd, cmd, arg, rc);

	if (rc >= 0 && (dir & _IOC_WRITE)) {
		recbuf = ARGSKMALLOC(sizeof(u_long)+size, GFP_KERNEL);
		if (!recbuf) {
			printk ("record_ioctl: can't allocate return\n");
			rc = -ENOMEM;
		} else {
			if (copy_from_user(recbuf+sizeof(u_long), (void __user *)arg, size)) {
				printk("record_ioctl: faulted on readback\n");
				ARGSKFREE(recbuf, sizeof(u_long)+size);
				recbuf = NULL;
				rc = -EFAULT;
			}
			*((u_long *)recbuf) = size;
		}
	}

	new_syscall_exit (54, recbuf);

	return rc;
}

static asmlinkage long 
replay_ioctl (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	char* retparams = NULL;
	u_long my_size;
	long rc = get_next_syscall (54, &retparams);
	if (retparams) {
		my_size = *((u_long *)retparams);
		if (copy_to_user((void __user *)arg, retparams+sizeof(u_long), my_size)) {
			printk("replay_ioctl: pid %d faulted\n", current->pid);
			return -EFAULT;
		}
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + my_size);
	}
	return rc;
}

asmlinkage long shim_ioctl (unsigned int fd, unsigned int cmd, unsigned long arg) SHIM_CALL(ioctl, 54, fd, cmd, arg);

static asmlinkage long 
record_fcntl (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	char* recbuf = NULL;
	long rc;

	new_syscall_enter (55);
	rc = sys_fcntl (fd, cmd, arg);
	new_syscall_done (55, rc);
	if (rc >= 0) {
		if (cmd == F_GETLK) {
			recbuf = ARGSKMALLOC(sizeof(int) + sizeof(struct flock), GFP_KERNEL);
			if (!recbuf) {
				printk ("record_fcntl: can't allocate return buffer\n");
				return -ENOMEM;
			}
			*(u_long *) recbuf = sizeof(struct flock);
			if (copy_from_user(recbuf + sizeof(u_long), (struct flock __user *)arg, sizeof(struct flock))) {
				printk("record_fcntl: faulted on readback\n");
				KFREE(recbuf);
				return -EFAULT;
			}
		} else if (cmd == F_GETOWN_EX) {
			recbuf = ARGSKMALLOC(sizeof(int) + sizeof(struct f_owner_ex), GFP_KERNEL);
			if (!recbuf) {
				printk ("record_fcntl: can't allocate return buffer\n");
				return -ENOMEM;
			}
			*(u_long *) recbuf = sizeof(struct f_owner_ex);
			if (copy_from_user(recbuf + sizeof(int), (struct f_owner_ex __user *)arg, sizeof(struct f_owner_ex))) {
				printk("record_fcntl: faulted on readback\n");
				KFREE(recbuf);
				return -EFAULT;
			}
		}
	}
	new_syscall_exit (55, recbuf);

	return rc;
}

static asmlinkage long 
replay_fcntl (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	char* retparams = NULL;
	long rc = get_next_syscall (55, &retparams);
	if (retparams) {
		u_long bytes = *((u_long *) retparams);
		if (copy_to_user((void __user *)arg, retparams + sizeof(u_long), bytes)) return syscall_mismatch();
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + bytes);
	}
	return rc;
}

asmlinkage long shim_fcntl (unsigned int fd, unsigned int cmd, unsigned long arg) SHIM_CALL(fcntl, 55, fd, cmd, arg);

SIMPLE_SHIM2(setpgid, 57, pid_t, pid, pid_t, pgid);
RET1_SHIM1(olduname, 59, struct oldold_utsname, name, struct oldold_utsname __user *, name);
SIMPLE_SHIM1(umask, 60, int, mask);
SIMPLE_SHIM1(chroot, 61, const char __user *, filename);
RET1_SHIM2(ustat, 62, struct ustat, ubuf, unsigned, dev, struct ustat __user *, ubuf);
SIMPLE_SHIM2(dup2, 63, unsigned int, oldfd, unsigned int, newfd);
SIMPLE_SHIM0(getppid, 64);
SIMPLE_SHIM0(getpgrp, 65);
SIMPLE_SHIM0(setsid, 66);

asmlinkage int sys_sigaction(int sig, const struct old_sigaction __user *act, struct old_sigaction __user *oact); /* No prototype for sys_sigaction */

RET1_RECORD3(sigaction, 67, struct old_sigaction, oact, int, sig, const struct old_sigaction __user *, act, struct old_sigaction __user *, oact);

static asmlinkage long replay_sigaction (int sig, const struct old_sigaction __user *act, struct old_sigaction __user *oact)
{									
	char *retparams = NULL;						
	long rc;
									
	if (current->replay_thrd->app_syscall_addr) {
		return sys_sigaction (sig, act, oact); // do actual syscall when PIN is attached
	}

	rc = get_next_syscall (67, (char **) &retparams); 
	if (retparams) {						
		if (copy_to_user (oact, retparams, sizeof(struct old_sigaction))) printk ("replay_sigaction: pid %d cannot copy to user\n", current->pid); 
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct old_sigaction));
	}								
	return rc;							
}									

asmlinkage int shim_sigaction (int sig, const struct old_sigaction __user *act, struct old_sigaction __user *oact) SHIM_CALL(sigaction, 67, sig, act, oact);

SIMPLE_SHIM0(sgetmask, 68);
SIMPLE_SHIM1(ssetmask, 69, int, newmask);
SIMPLE_SHIM2(setreuid16, 70, old_uid_t, ruid, old_uid_t, euid);
SIMPLE_SHIM2(setregid16, 71, old_gid_t, rgid, old_gid_t, egid);
asmlinkage int sys_sigsuspend(int history0, int history1, old_sigset_t mask); /* No prototype for sys_sigsuspend */
SIMPLE_SHIM3(sigsuspend, 72, int, history0, int, history1, old_sigset_t, mask);
RET1_SHIM1(sigpending, 73, old_sigset_t, set, old_sigset_t __user *, set);
SIMPLE_SHIM2(sethostname, 74, char __user *, name, int, len);
SIMPLE_RECORD2(setrlimit, 75, unsigned int, resource, struct rlimit __user *, rlim);

static asmlinkage long 
replay_setrlimit (unsigned int resource, struct rlimit __user *rlim)
{
	long rc;
	long rc_orig = get_next_syscall (75, NULL);
	rc = sys_setrlimit (resource, rlim);
	if (rc != rc_orig) printk ("setrlim changed its return in replay\n");
	return rc_orig;
}

asmlinkage long shim_setrlimit (unsigned int resource, struct rlimit __user *rlim) SHIM_CALL(setrlimit, 75, resource, rlim);

RET1_SHIM2(old_getrlimit, 76, struct rlimit, rlim, unsigned int, resource, struct rlimit __user *, rlim);
RET1_SHIM2(getrusage, 77, struct rusage, ru, int, who, struct rusage __user *, ru);

static asmlinkage long 
record_gettimeofday (struct timeval __user *tv, struct timezone __user *tz)
{
	long rc;
	struct gettimeofday_retvals* pretvals = NULL;

	new_syscall_enter (78);
	rc = sys_gettimeofday (tv, tz);
	new_syscall_done (78, rc);
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

	new_syscall_exit (78, pretvals);

	return rc;
}

static asmlinkage long 
replay_gettimeofday (struct timeval __user *tv, struct timezone __user *tz)
{
	struct gettimeofday_retvals* retparams = NULL;
	long rc = get_next_syscall (78, (char **) &retparams);

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
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct gettimeofday_retvals));
	}
	return rc;
}

asmlinkage long shim_gettimeofday (struct timeval __user *tv, struct timezone __user *tz) SHIM_CALL(gettimeofday, 78, tv, tz);

SIMPLE_SHIM2(settimeofday, 79, struct timeval __user *, tv, struct timezone __user *, tz);

static asmlinkage long 
record_getgroups16 (int gidsetsize, old_gid_t __user *grouplist)
{
	long rc;
	old_gid_t* pretval = NULL;

	new_syscall_enter (80);
	rc = sys_getgroups16 (gidsetsize, grouplist);
	new_syscall_done (80, rc);
	if (gidsetsize > 0 && rc > 0) {
		pretval = ARGSKMALLOC(sizeof(old_gid_t)*rc, GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_getgroups16: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, grouplist, sizeof(old_gid_t)*rc)) {
			printk ("record_getgroups16: can't copy from user %p into %p\n", grouplist, pretval);
			ARGSKFREE (pretval, sizeof(old_gid_t)*rc);
			return -EFAULT;
		}
	}
	new_syscall_exit (80, pretval);

	return rc;
}

static asmlinkage long 
replay_getgroups16 (int gidsetsize, old_gid_t __user *grouplist)
{
	old_gid_t* retparams = NULL;
	long rc = get_next_syscall (80, (char **) &retparams);
	if (retparams) {
		if (copy_to_user (grouplist, retparams, sizeof(old_gid_t)*rc)) printk ("Pid %d cannot copy groups to user\n", current->pid);
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(old_gid_t)*rc);
	}
	return rc;
}

asmlinkage long shim_getgroups16 (int gidsetsize, old_gid_t __user *grouplist) SHIM_CALL(getgroups16, 80, gidsetsize, grouplist);

SIMPLE_SHIM2(setgroups16, 81, int, gidsetsize, old_gid_t __user *, grouplist);
/* old_select is redirected to shim_select */
SIMPLE_SHIM2(symlink, 83, const char __user *, oldname, const char __user *, newname);
RET1_SHIM2(lstat, 84, struct __old_kernel_stat, statbuf, char __user *, filename, struct __old_kernel_stat __user *, statbuf);
RET1_COUNT_SHIM3(readlink, 85, buf, const char __user *, path, char __user *, buf, int, bufsiz);

static asmlinkage long
record_uselib (const char __user * library)
{
	long rc;
	struct mmap_pgoff_retvals* recbuf = NULL; // Shouldn't be called - new code uses mmap

	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (86);
	rc = sys_uselib (library);
	new_syscall_done (86, rc);
	if (rc == 0) {
		recbuf = ARGSKMALLOC(sizeof(struct mmap_pgoff_retvals), GFP_KERNEL);
		if (recbuf == NULL) {
			printk ("record_uselib: pid %d cannot allocate return buffer\n", current->pid);
			return -EINVAL;
		}
		if (add_file_to_cache_by_name (library, &recbuf->dev, &recbuf->ino, &recbuf->mtime) < 0) return -EINVAL;
	}
	new_syscall_exit (86, recbuf);
	rg_unlock(current->record_thrd->rp_group);

	return rc;
}

static asmlinkage long 
replay_uselib (const char __user * library)
{
	u_long retval, rc;
	struct mmap_pgoff_retvals* recbuf = NULL;
	struct replay_thread* prt = current->replay_thrd;
	mm_segment_t old_fs;
	char name[CACHE_FILENAME_SIZE];

	rc = get_next_syscall (86, (char **) &recbuf);

	if (recbuf) {
		rg_lock(prt->rp_record_thread->rp_group);
		get_cache_file_name (name, recbuf->dev, recbuf->ino, recbuf->mtime);
		rg_unlock(prt->rp_record_thread->rp_group);
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		retval = sys_uselib (name);
		set_fs(old_fs);
		if (rc != retval) {
			printk ("Replay mmap_pgoff returns different value %lx than %lx\n", retval, rc);
			syscall_mismatch ();
		}
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct mmap_pgoff_retvals));
	}
	return rc;
}

asmlinkage long shim_uselib (const char __user * library) SHIM_CALL(uselib, 86, library);

SIMPLE_SHIM2(swapon, 87, const char __user *, specialfile, int, swap_flags);
SIMPLE_SHIM4(reboot, 88, int, magic1, int, magic2, unsigned int, cmd, void __user *, arg);

struct old_linux_dirent { // From readdir.c - define this for completeness but system call should never be called
	unsigned long	d_ino;
	unsigned long	d_offset;
	unsigned short	d_namlen;
	char		d_name[1];
};

RET1_SHIM3(old_readdir, 89, struct old_linux_dirent, dirent, unsigned int, fd, struct old_linux_dirent __user *, dirent, unsigned int, count)

// old_mmap is a shim that calls sys_mmap_pgoff - we handle record/replay there instead

static asmlinkage long 
record_munmap (unsigned long addr, size_t len)
{
	long rc;
	
	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (91);
	rc = sys_munmap (addr, len);
	new_syscall_done (91, rc);
	new_syscall_exit (91, NULL);
	DPRINT ("Pid %d records munmap of addr %lx returning %ld\n", current->pid, addr, rc);
	rg_unlock(current->record_thrd->rp_group);

	return rc;
}

static asmlinkage long 
replay_munmap (unsigned long addr, size_t len)
{
	u_long retval, rc;

	if (is_pin_attached()) {
		rc = current->replay_thrd->rp_saved_rc;
		(*(int*)(current->replay_thrd->app_syscall_addr)) = 999;
	} else {
		rc = get_next_syscall (91, NULL);
	}

	retval = sys_munmap (addr, len);
	DPRINT ("Pid %d replays munmap of addr %lx len %d returning %ld\n", current->pid, addr, len, retval);
	if (rc != retval) {
		printk ("Replay munmap returns different value %lu than %lu\n",	retval, rc);
		return syscall_mismatch();
	}
	if (retval == 0 && is_pin_attached()) preallocate_after_munmap (addr, len);
	
	return rc;
}

asmlinkage long shim_munmap (unsigned long addr, size_t len) SHIM_CALL(munmap, 91, addr, len);

SIMPLE_SHIM2(truncate, 92, const char __user *, path, unsigned long, length);
SIMPLE_SHIM2(ftruncate, 93, unsigned int, fd, unsigned long, length);
SIMPLE_SHIM2(fchmod, 94, unsigned int, fd, mode_t, mode);
SIMPLE_SHIM3(fchown16, 95, unsigned int, fd, old_uid_t, user, old_gid_t, group);
SIMPLE_SHIM2(getpriority, 96, int, which, int, who);
SIMPLE_SHIM3(setpriority, 97, int, which, int, who, int, niceval);
RET1_SHIM2(statfs, 99, struct statfs, buf, const char __user *, path, struct statfs __user *, buf);
RET1_SHIM2(fstatfs, 100, struct statfs, buf, unsigned int, fd, struct statfs __user *, buf)
SIMPLE_SHIM3(ioperm,101, unsigned long, from, unsigned long, num, int, turn_on);

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

static char *
copy_iovec_to_args(long size, const struct iovec __user *vec, unsigned long vlen)
{
	char* recbuf = NULL, *copyp;
	struct iovec* kvec;
	long rem_size, to_copy;
	int i;

	if (size > 0) {
		recbuf = ARGSKMALLOC(size, GFP_KERNEL);
		if (recbuf == NULL) {
			printk ("Unable to allocate readv buffer\n");
			return NULL;
		}
		
		kvec = KMALLOC(vlen*sizeof(struct iovec), GFP_KERNEL);
		if (kvec == NULL) {
			printk ("Pid %d copy_iovec_to_args allocation of vector failed\n", current->pid);
			KFREE(kvec);
			ARGSKFREE(recbuf, size);
			return NULL;
		}

		if (copy_from_user (kvec, vec, vlen*sizeof(struct iovec))) {
			printk ("Pid %d copy_iovec_to_args copy_from_user of vector failed\n", current->pid);
			KFREE(kvec);
			ARGSKFREE(recbuf, size);
			return NULL;
		}
		rem_size = size;
		copyp = recbuf;
		for (i = 0; i < vlen; i++) {
			to_copy = kvec[i].iov_len;
			if (rem_size < to_copy) to_copy = rem_size;

			if (copy_from_user (copyp, kvec[i].iov_base, to_copy)) {
				printk ("Pid %d copy_iovec_to_args copy_from_user of data failed\n", current->pid);
				KFREE(kvec);
				ARGSKFREE(recbuf, size);
				return NULL;
			}
			copyp += to_copy;
			rem_size -= to_copy;
			if (rem_size == 0) break;
		}
		KFREE (kvec);
	}

	return recbuf;
}

static long
log_mmsghdr (struct mmsghdr __user *msg, long rc, long* plogsize)
{
	long len, i;
	struct mmsghdr* phdr;
	char* pdata;

	plogsize = ARGSKMALLOC(sizeof(u_long), GFP_KERNEL);
	len = sizeof(u_long);
	if (plogsize == NULL) {
		printk("record_recvmmsg: can't allocate msg size\n");
		return -ENOMEM;
	}
	for (i = 0; i < rc; i++) {
		phdr = ARGSKMALLOC(sizeof(struct mmsghdr), GFP_KERNEL);
		if (phdr == NULL) {
			printk("record_recvmmsg: can't allocate msg hdr %ld\n", i);
			ARGSKFREE(plogsize, len);
			return -ENOMEM;
		}
		len += sizeof(struct mmsghdr);
		if (copy_from_user (phdr, msg+i, sizeof(struct mmsghdr))) {
			printk("record_recvmmsg: can't allocate msg header %ld\n", i);
			ARGSKFREE (plogsize, len);
			return -EFAULT;
		}
		
		if (phdr->msg_hdr.msg_namelen) {
			pdata = ARGSKMALLOC(phdr->msg_hdr.msg_namelen, GFP_KERNEL);
			if (pdata == NULL) {
				printk("record_recvmmsg: can't allocate msg name %ld\n", i);
				ARGSKFREE(plogsize, len);
				return -ENOMEM;
			}
			len += phdr->msg_hdr.msg_namelen;
			if (copy_from_user (pdata, phdr->msg_hdr.msg_name, phdr->msg_hdr.msg_namelen)) {
				printk("record_recvmmsg: can't copy msg_name %ld of size %d\n", i, phdr->msg_hdr.msg_namelen);
				ARGSKFREE (plogsize, len);
				return -EFAULT;
			}
		}
		if (phdr->msg_hdr.msg_controllen) {
			pdata = ARGSKMALLOC(phdr->msg_hdr.msg_controllen, GFP_KERNEL);
			if (pdata == NULL) {
				printk("record_recvmmsg: can't allocate msg control %ld\n", i);
				ARGSKFREE(plogsize, len);
				return -ENOMEM;
			}
			len += phdr->msg_hdr.msg_controllen;
			if (copy_from_user (pdata, phdr->msg_hdr.msg_control, phdr->msg_hdr.msg_controllen)) {
				printk("record_recvmmsg: can't copy msg_control %ld of size %d\n", i, phdr->msg_hdr.msg_controllen);
				ARGSKFREE (plogsize, len);
				return -EFAULT;
			}
		}
		if (copy_iovec_to_args(phdr->msg_len, phdr->msg_hdr.msg_iov, phdr->msg_hdr.msg_iovlen) == NULL) {
			printk ("record_recvmmsg: can't allocate or copy msg data %ld\n", i);
			ARGSKFREE (plogsize, len);
			return -ENOMEM;
		}
		len += phdr->msg_len;
	}
	*plogsize = len;
	return 0;
}

static asmlinkage long 
record_socketcall(int call, unsigned long __user *args)
{
	long rc = 0;
	unsigned long a[6];
	unsigned int len;

	DPRINT ("Pid %d in record_socketcall(%d)\n", current->pid, call);

	new_syscall_enter (102);

	if (call < 1 || call > SYS_SENDMMSG) {
		printk ("record_socketcall: out of range call %d\n", call);
		new_syscall_done (102, -EINVAL);
		new_syscall_exit (102, NULL);
		return -EINVAL;
	}

	len = nargs[call];
	if (len > sizeof(a)) {
		printk ("record_socketcall: invalid length\n");
		new_syscall_done (102, -EINVAL);
		new_syscall_exit (102, NULL);
		return -EINVAL;
	}

	if (copy_from_user (a, args, len)) {
		printk ("record_socketcall: cannot copy arguments\n");
		new_syscall_done (102, -EFAULT);
		new_syscall_exit (102, NULL);
		return -EFAULT;
	}

#ifdef TRACE_SOCKET_READ_WRITE
	if (call == SYS_SENDTO || call == SYS_SEND) {
		int err = 0;
		struct socket *sock = sockfd_lookup(a[0], &err);

		if (sock != NULL && (sock->ops == &unix_stream_ops || sock->ops == &unix_seqpacket_ops)) {
			int ret;
			struct sock *peer;
			struct sock *sk = sock->sk;
			peer = unix_peer_get(sk);
			ret = track_usually_pt2pt_write_begin(peer, sock->file);
			sock_put(peer);

			fput(sock->file);
		}
	}
#endif

	rc = sys_socketcall (call, args);
	new_syscall_done (102, rc);

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
				new_syscall_exit(102, pretvals);
				return rc;
			}

			tmp = (struct sockaddr_in*)(&pretvals->addr);

			pretvals->call = call;
			new_syscall_exit (102, pretvals);
			return rc;
		} else {
			struct accept_retvals* pretvals = NULL;
			pretvals = ARGSKMALLOC(sizeof(struct accept_retvals), GFP_KERNEL);
			if (pretvals == NULL) {
				printk("record_socketcall(socket): can't allocate buffer\n");
				return -ENOMEM;
			}
			pretvals->call = call;
			pretvals->addrlen = 0;
			new_syscall_exit (102, pretvals);
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
		new_syscall_exit (102, pretvals);
		return rc;
#endif
	}
#ifdef TRACE_SOCKET_READ_WRITE
	case SYS_SEND:
	case SYS_SENDTO:
	{
		struct generic_socket_retvals* pretvals = NULL;
		pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_socketcall(socket): can't allocate buffer\n");
			return -ENOMEM;
		}
		pretvals->call = call;

		/* Need to track write info for send and sendto */
		if (rc >= 0) {
			struct file *filp = fget(a[0]);
			struct socket *sock = filp->private_data;


			if (sock->ops == &unix_stream_ops || sock->ops == &unix_seqpacket_ops) {
				int ret;
				struct sock *peer;
				struct sock *sk = sock->sk;
				peer = unix_peer_get(sk);
				ret = track_usually_pt2pt_write(peer, rc, filp, 1);
				sock_put(peer);
				if (ret) {
					ARGSKFREE(pretvals, sizeof(struct generic_socket_retvals));
					return ret;
				}
			} else {
				int *is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);
				if (is_cached == NULL) {
					return -ENOMEM;
				}
				*is_cached = 0;
			}

			fput(filp);
		}

		new_syscall_exit (102, pretvals);
		return rc;
	}
#else
	case SYS_SEND:
	case SYS_SENDTO:
#endif
	case SYS_SENDMSG:
	case SYS_SENDMMSG:
	case SYS_SOCKET:
	case SYS_BIND:
	case SYS_LISTEN:
	case SYS_SHUTDOWN:
	case SYS_SETSOCKOPT:
	{
		struct generic_socket_retvals* pretvals = NULL;
		pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_socketcall(socket): can't allocate buffer\n");
			return -ENOMEM;
		}
		pretvals->call = call;
		new_syscall_exit (102, pretvals);
		return rc;
	}
	case SYS_ACCEPT:
	case SYS_ACCEPT4:
#ifdef MULTI_COMPUTER
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

				new_syscall_exit (102, pretvals);
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
					new_syscall_exit(102, peer_retvals);
					return rc;
				}

				peer_retvals->call = call;
				new_syscall_exit (102, peer_retvals);
				return rc;
			}
		}
		printk("Pid %d - record_socketcall(accept) returned %d\n", current->pid, rc);
		new_syscall_exit (102, NULL);
		return rc;
	}
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
		}
		new_syscall_exit (102, pretvals);
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
			DPRINT ("pid %d records socketpair retuning %ld, sockets %d and %d\n", current->pid, rc, pretvals->sv0, pretvals->sv1);
		}
		new_syscall_exit (102, pretvals);
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
#ifdef TRACE_SOCKET_READ_WRITE
			do /* magic */ {
				struct file *filp = fget(a[0]);
				struct socket *socket = filp->private_data;

				if (socket->ops == &unix_stream_ops || socket->ops == &unix_seqpacket_ops) {
					int ret;
					ret = track_usually_pt2pt_read(socket->sk, rc, filp);
					if (ret) {
						ARGSKFREE(pretvals, sizeof(struct recvfrom_retvals) + rc);
						return ret;
					}
				} else {
					u_int *is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);
					if (is_cached == NULL) {
						return -ENOMEM;
					}
					*is_cached = 0;
				}

				fput(filp);
			} while (0);
#endif
		}

		new_syscall_exit (102, pretvals);
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
					ARGSKFREE (pretvals, sizeof(struct recvfrom_retvals)+rc-1);
					return -EFAULT;
				}
				if (copy_from_user(&pretvals->addr, (char *) args[4], pretvals->addrlen)) {
					printk("record_socketcall(recvfrom): can't copy addr\n");
					ARGSKFREE (pretvals, sizeof(struct recvfrom_retvals)+rc-1);
					return -EFAULT;
				}
			}
			pretvals->call = call;

#ifdef TRACE_SOCKET_READ_WRITE
			do /* magic */ {
				struct file *filp = fget(a[0]);
				struct socket *socket = filp->private_data;

				if (socket->ops == &unix_stream_ops || socket->ops == &unix_seqpacket_ops) {
					int ret;
					ret = track_usually_pt2pt_read(socket->sk, rc, filp);
					if (ret) {
						ARGSKFREE(pretvals, sizeof(struct recvfrom_retvals)+rc-1);
						return ret;
					}
				} else {
					u_int *is_cached = ARGSKMALLOC(sizeof(u_int), GFP_KERNEL);
					if (is_cached == NULL) {
						return -ENOMEM;
					}
					*is_cached = 0;
				}

				fput(filp);
			} while (0);
#endif
		}

		new_syscall_exit (102, pretvals);
		return rc;
	}
	case SYS_RECVMSG:
	{
		struct recvmsg_retvals* pretvals = NULL;
		struct msghdr __user *pmsghdr = (struct msghdr __user *) a[1];
		char* pdata;
		long iovlen, rem_size, to_copy, i;

		if (rc >= 0) {

			DPRINT ("record_socketcall(recvmsg): namelen: %d, controllen %ld iov_len %d rc %ld\n", pmsghdr->msg_namelen, (long) pmsghdr->msg_controllen, pmsghdr->msg_iovlen, rc);

			pretvals = ARGSKMALLOC(sizeof(struct recvmsg_retvals) + pmsghdr->msg_namelen + pmsghdr->msg_controllen + rc, GFP_KERNEL);
			if (pretvals == NULL) {
				printk("record_socketcall(recvmsg): can't allocate buffer\n");
				return -ENOMEM;
			}
			pretvals->call = call;
			get_user (pretvals->msg_namelen, &pmsghdr->msg_namelen);
			get_user (pretvals->msg_controllen, &pmsghdr->msg_controllen);
			get_user (pretvals->msg_flags, &pmsghdr->msg_flags);

			pdata = ((char *) pretvals) + sizeof (struct recvmsg_retvals);

			if (pretvals->msg_namelen) {
				if (copy_from_user (pdata, pmsghdr->msg_name, pretvals->msg_namelen)) {
					printk("record_socketcall(recvmsg): can't copy msg_name of size %d\n", pretvals->msg_namelen);
					ARGSKFREE (pretvals, sizeof(struct recvmsg_retvals) + pmsghdr->msg_namelen + pmsghdr->msg_controllen + rc);
					return -EFAULT;
				}
				pdata += pmsghdr->msg_namelen;
			}
			if (pmsghdr->msg_controllen) {
				if (copy_from_user (pdata, pmsghdr->msg_control, pretvals->msg_controllen)) {
					printk("record_socketcall(recvmsg): can't copy msg_control of size %ld\n", pretvals->msg_controllen);
					ARGSKFREE (pretvals, sizeof(struct recvmsg_retvals) + pmsghdr->msg_namelen + pmsghdr->msg_controllen + rc);
					return -EFAULT;
				}
				pdata += pmsghdr->msg_controllen;
			}
			
			get_user (iovlen, &pmsghdr->msg_iovlen);
			rem_size = rc;
			for (i = 0; i < iovlen; i++) {
				get_user(to_copy, &pmsghdr->msg_iov[i].iov_len);
				if (rem_size < to_copy) to_copy = rem_size;

				if (copy_from_user (pdata, pmsghdr->msg_iov[i].iov_base, to_copy)) {
					printk ("Pid %d record_readv copy_from_user of data failed\n", current->pid);
					ARGSKFREE (pretvals, sizeof(struct recvmsg_retvals) + pmsghdr->msg_namelen + pmsghdr->msg_controllen + rc);
					return -EFAULT;
				}
				pdata += to_copy;
				rem_size -= to_copy;
				if (rem_size == 0) break;
			}
			if (rem_size != 0) printk ("record_socketcall(recvmsg): %ld bytes of data remain???\n", rem_size);
		}

		new_syscall_exit (102, pretvals);
		return rc;

	}
	case SYS_RECVMMSG:
	{
		struct mmsghdr __user *pmsghdr = (struct mmsghdr __user *) a[1];
		struct getsockopt_retvals* pretvals = NULL;
		long logsize, retval;

		pretvals = ARGSKMALLOC(sizeof(struct generic_socket_retvals), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_socketcall(socket): can't allocate buffer\n");
			return -ENOMEM;
		}
		pretvals->call = call;

		if (rc > 0) {
			retval = log_mmsghdr(pmsghdr, rc, &logsize);
			if (retval < 0) return retval;
		}
		new_syscall_exit (102, pretvals);
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
		}
		new_syscall_exit (102, pretvals);
		return rc;
	}
	default:
		printk ("record_socketcall: type %d not handled\n", call);
		return -EINVAL;
	}
}

static int
copy_args_to_iovec (char* retparams, long size, const struct iovec __user * vec, unsigned long vlen)
{
	char* copyp;
	struct iovec* kvec;
	long rem_size, to_copy;
	int i;

	kvec = KMALLOC(vlen*sizeof(struct iovec), GFP_KERNEL);
	if (kvec == NULL) {
		printk ("Pid %d replay_readv allocation of vector failed\n", current->pid);
		return -ENOMEM;
	}
		
	if (copy_from_user (kvec, vec, vlen*sizeof(struct iovec))) {
		printk ("Pid %d replay_readv copy_from_user of vector failed\n", current->pid);
		KFREE (kvec);
		return -EFAULT;
	}
	rem_size = size;
	copyp = retparams;
	for (i = 0; i < vlen; i++) {
		to_copy = kvec[i].iov_len;
		if (rem_size < to_copy) to_copy = rem_size;
		
		if (copy_to_user (kvec[i].iov_base, copyp, to_copy)) {
			printk ("Pid %d replay_readv copy_to_user of data failed\n", current->pid);
			KFREE (kvec);
			return -EFAULT;
		}
		copyp += to_copy;
		rem_size -= to_copy;
		if (rem_size == 0) break;
	}
	KFREE (kvec);
	return 0;
}

static asmlinkage long
extract_mmsghdr (char* retparams, struct mmsghdr __user *msg, long rc)
{
	struct mmsghdr* phdr;
	long retval, i;
	struct iovec __user *iovec;
	unsigned long iovlen;

	argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + *((u_long *) retparams));
	retparams += sizeof(u_long);
	for (i = 0; i < rc; i++) {
		phdr = (struct mmsghdr *) retparams;
		retparams += sizeof (struct mmsghdr);
		put_user (phdr->msg_len, &msg[i].msg_len);
		put_user (phdr->msg_hdr.msg_controllen, &msg[i].msg_hdr.msg_controllen); // This is a in-out parameter
		put_user (phdr->msg_hdr.msg_flags, &msg[i].msg_hdr.msg_flags);           // Out parameter
		
		if (phdr->msg_hdr.msg_namelen) {
			if (copy_to_user (&msg[i].msg_hdr.msg_name, retparams, phdr->msg_hdr.msg_namelen)) {
				printk ("extract_mmsghdr: pid %d cannot copy msg_name to user\n", current->pid);
				syscall_mismatch();
			}
			retparams += phdr->msg_hdr.msg_namelen;
		}
		
		if (phdr->msg_hdr.msg_controllen) {
			if (copy_to_user (&msg[i].msg_hdr.msg_control, retparams, phdr->msg_hdr.msg_controllen)) {
				printk ("extract_mmsghdr: pid %d cannot copy msg_control to user\n", current->pid);
				syscall_mismatch();
			}
			retparams += phdr->msg_hdr.msg_controllen;
		}
		get_user (iovec, &msg[i].msg_hdr.msg_iov);
		get_user (iovlen, &msg[i].msg_hdr.msg_iovlen);
		retval = copy_args_to_iovec (retparams, phdr->msg_len, iovec, iovlen);
		if (retval < 0) return retval;
		retparams += retval;
	}
	return 0;
}

static asmlinkage long 
replay_socketcall (int call, unsigned long __user *args)
{
	char* retparams = NULL;
	long rc, retval = 0;
	unsigned long kargs[6];
	unsigned int len;

	DPRINT ("Pid %d in replay_socketcall(%d)\n", current->pid, call);

	if (call < 1 || call > SYS_SENDMMSG) {
		retval = -EINVAL;
	} else {
		len = nargs[call];
		if (len > sizeof(kargs)) {
			retval = -EINVAL;
		} else {
			if (copy_from_user (kargs, args, len)) retval = -EFAULT;
		}
	}

	rc = get_next_syscall (102, &retparams);
	
	if (retval < 0) {
		if (rc == retval) return rc;
		printk ("replay_socketcall: call %d record had rc %ld but replay has rc %ld\n", call, rc, retval);
		syscall_mismatch();
	}

	DPRINT ("Pid %d, replay_socketcall %d, rc is %ld\n", current->pid, call, rc);

	switch (call) {
#ifdef TRACE_SOCKET_READ_WRITE
	case SYS_SEND:
	case SYS_SENDTO:
		if (retparams) {
			argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
			retparams += sizeof(struct generic_socket_retvals);
			/* We need to allocate something on write regardless, then use it to determine how much to free... ugh */
			consume_socket_args_write(retparams);
		}
		return rc;
#else
	case SYS_SEND:
	case SYS_SENDTO:
#endif
	case SYS_SOCKET:
	case SYS_CONNECT:
	case SYS_BIND:
	case SYS_LISTEN:
	case SYS_SHUTDOWN:
	case SYS_SETSOCKOPT:
	case SYS_SENDMSG:
	case SYS_SENDMMSG:
		if (retparams) argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
		return rc;
	case SYS_ACCEPT:
	case SYS_ACCEPT4: 
		if (retparams) {
			struct accept_retvals* retvals = (struct accept_retvals *) retparams;
			if (kargs[1]) {
				*((int *) kargs[2]) = retvals->addrlen;
				if (copy_to_user ((char *) args[1], &retvals->addr, retvals->addrlen)) {
					printk ("Pid %d replay_socketcall_accept cannot copy to user\n", current->pid);
				}
			}
			argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct accept_retvals)+retvals->addrlen);
		}
		return rc;
	case SYS_GETSOCKNAME:
	case SYS_GETPEERNAME:
		if (retparams) {
			struct accept_retvals* retvals = (struct accept_retvals *) retparams;
			*((int *) kargs[2]) = retvals->addrlen;
			if (copy_to_user ((char *) args[1], &retvals->addr, retvals->addrlen)) {
				printk ("Pid %d replay_socketcall_getpeername cannot copy to user\n", current->pid);
			}
			argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct accept_retvals)+retvals->addrlen);
		}
		return rc;
	case SYS_SOCKETPAIR:
		if (retparams) {
			int* sv;
			struct socketpair_retvals* retvals = (struct socketpair_retvals *) retparams;

			sv = (int *) KMALLOC(2 * sizeof(int), GFP_KERNEL);
			*sv = retvals->sv0;
			*(sv+1) = retvals->sv1;

			if (copy_to_user ((int *) args[3], sv, 2 * sizeof(int))) {
			       printk ("Pid %d replay_socketcall_socketpair cannot copy to user\n", current->pid);
			}	       

			KFREE(sv);
			argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct socketpair_retvals));
		}
		return rc;
	case SYS_RECV:
		if (retparams) {
			struct recvfrom_retvals* retvals = (struct recvfrom_retvals *) retparams;
			if (copy_to_user ((char *) kargs[1], &retvals->buf, rc)) {
				printk ("Pid %d replay_socketcall_recv cannot copy to user\n", current->pid);
			}
			argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct recvfrom_retvals)+rc);
#ifdef TRACE_SOCKET_READ_WRITE
			consume_socket_args_read(retparams + sizeof(struct recvfrom_retvals) + rc);
#endif
		}
		return rc;
	case SYS_RECVFROM:
		if (retparams) {
			struct recvfrom_retvals* retvals = (struct recvfrom_retvals *) retparams;
			if (copy_to_user ((char *) kargs[1], &retvals->buf, rc)) {
				printk ("Pid %d replay_socketcall_recvfrom cannot copy to user\n", current->pid);
			}
			if (kargs[4]) {
				*((int *) kargs[5]) = retvals->addrlen;
				if (copy_to_user ((char *) kargs[4], &retvals->addr, retvals->addrlen)) {
					printk ("Pid %d cannot copy sockaddr from to user\n", current->pid);
				}

			}
			argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct recvfrom_retvals)+rc-1);
#ifdef TRACE_SOCKET_READ_WRITE
			consume_socket_args_read(retparams + sizeof(struct recvfrom_retvals) + rc - 1);
#endif
		}
		return rc;
	case SYS_RECVMSG: 
		if (retparams) {
			struct recvmsg_retvals* retvals = (struct recvmsg_retvals *) retparams;
			char* pdata = ((char *) retvals) + sizeof (struct recvmsg_retvals);
			struct msghdr *msg = (struct msghdr __user *) args[1];
			long rem_size, to_copy, i, iovlen;

			put_user (retvals->msg_controllen, &msg->msg_controllen); // This is a in-out parameter
			put_user (retvals->msg_flags, &msg->msg_flags);           // Out parameter

			if (retvals->msg_namelen) {
				if (copy_to_user ((char *) msg->msg_name, pdata, retvals->msg_namelen)) {
					printk ("Pid %d cannot copy msg_name to user\n", current->pid);
					syscall_mismatch();
				}
				pdata += retvals->msg_namelen;
			}

			if (retvals->msg_controllen) {
				if (copy_to_user ((char *) msg->msg_control, pdata, retvals->msg_controllen)) {
					printk ("Pid %d cannot copy msg_name to user\n", current->pid);
					syscall_mismatch();
				}
				pdata += retvals->msg_controllen;
			}

			get_user (iovlen, &msg->msg_iovlen);
			rem_size = rc;
			for (i = 0; i < iovlen; i++) {
				get_user (to_copy, &msg->msg_iov[i].iov_len);
				if (rem_size < to_copy) to_copy = rem_size;

				if (copy_to_user (msg->msg_iov[i].iov_base, pdata, to_copy)) {
					printk ("Pid %d replay_readv copy_to_user of data failed\n", current->pid);
					syscall_mismatch();
				}
				pdata += to_copy;
				rem_size -= to_copy;
				if (rem_size == 0) break;
			}

			if (rem_size != 0) {
				printk ("replay_socketcall(recvmsg): %ld bytes remaining\n", rem_size);
				syscall_mismatch();
			}
			argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct recvmsg_retvals)+retvals->msg_namelen+retvals->msg_controllen+rc);
		}
		return rc;
	case SYS_RECVMMSG:
		if (retparams) {
			struct mmsghdr __user *pmsghdr = (struct mmsghdr __user *) kargs[1];
			argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct generic_socket_retvals));
			retval = extract_mmsghdr (retparams, pmsghdr, rc);
			if (retval < 0) syscall_mismatch();
		}
		return rc;
	case SYS_GETSOCKOPT:
		if (retparams) {
			struct getsockopt_retvals* retvals = (struct getsockopt_retvals *) retparams;

			if (copy_to_user ((char*) args[3], &retvals->optval, retvals->optlen)) {
				printk ("Pid %d cannot copy optval to user\n", current->pid);
			}

			if (copy_to_user ((char *) args[4], &retvals->optlen, sizeof(int))) {
				printk ("Pid %d cannot copy optlen to user\n", current->pid);
			}
			argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct getsockopt_retvals)+retvals->optlen);
		}
		return rc;
	}
	return syscall_mismatch();
}

asmlinkage long shim_socketcall (int call, unsigned long __user *args) SHIM_CALL(socketcall, 102, call, args);

static asmlinkage long 
record_syslog (int type, char __user *buf, int len)
{
	char* recbuf = NULL;
	long rc;

	new_syscall_enter (103);
	rc = sys_syslog (type, buf, len);
	new_syscall_done (103, rc);
	if (rc > 0 && (type >= 2 && type <= 4)) {
		recbuf = ARGSKMALLOC(rc, GFP_KERNEL);
		if (recbuf == NULL) {
			printk ("record_syslog: can't allocate return buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user(recbuf, buf, rc)) {
			printk("record_syslog: faulted on readback\n");
			ARGSKFREE(recbuf, rc);
			return -EFAULT;
		}
	}
	new_syscall_exit (103, recbuf);

	return rc;
}

RET1_COUNT_REPLAY(syslog, 103, buf, int type, char __user * buf, int len);

asmlinkage long shim_syslog (int type, char __user *buf, int len) SHIM_CALL(syslog, 103, type, buf, len);

RET1_SHIM3(setitimer, 104, struct itimerval, ovalue, int, which, struct itimerval __user *, value, struct itimerval __user *, ovalue);
RET1_SHIM2(getitimer, 105, struct itimerval, value, int, which, struct itimerval __user *, value);
RET1_SHIM2(newstat, 106, struct stat, statbuf, char __user *, filename, struct stat __user *, statbuf);
RET1_SHIM2(newlstat, 107, struct stat, statbuf, char __user *, filename, struct stat __user *, statbuf);
RET1_SHIM2(newfstat, 108, struct stat, statbuf, unsigned int, fd, struct stat __user *, statbuf);
RET1_SHIM1(uname, 109, struct old_utsname, name, struct old_utsname __user *, name);
// I believe ptregs_iopl is deterministic, so don't intercept it
SIMPLE_SHIM0(vhangup, 111);
// I believe vm86old is deterministic, so don't intercept it

struct wait4_retvals {
	int           stat_addr;
	struct rusage ru;
};

static asmlinkage long 
record_wait4 (pid_t upid, int __user *stat_addr, int options, struct rusage __user *ru) 
{
	long rc;
	struct wait4_retvals* retvals = NULL;

	new_syscall_enter (114);
	rc = sys_wait4 (upid, stat_addr, options, ru);
	new_syscall_done (114, rc);
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
	new_syscall_exit (114, retvals);

	return rc;
}

static asmlinkage long 
replay_wait4 (pid_t upid, int __user *stat_addr, int options, struct rusage __user *ru) 
{
	struct wait4_retvals* pretvals;
	long rc = get_next_syscall (114, (char **) &pretvals);
	if (pretvals) {
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
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct wait4_retvals));
	}
	return rc;
}

asmlinkage long shim_wait4 (pid_t upid, int __user *stat_addr, int options, struct rusage __user *ru) SHIM_CALL(wait4, 114, upid, stat_addr, options, ru);

SIMPLE_SHIM1(swapoff, 115, const char __user *, specialfile);
RET1_SHIM1(sysinfo, 116, struct sysinfo, info, struct sysinfo __user *, info);

static asmlinkage long 
record_ipc (uint call, int first, u_long second, u_long third, void __user *ptr, long fifth)
{
	mm_segment_t old_fs;
	char* pretval = NULL;
	u_long len = 0;
	long rc;

	new_syscall_enter (117);
	rc = sys_ipc (call, first, second, third, ptr, fifth);
	new_syscall_done (117, rc);
	if (rc >= 0) {
		switch (call) {
		case MSGCTL: 
			switch (second) {
			case IPC_STAT:
			case MSG_STAT:
				len = sizeof(struct msqid64_ds);
				break;
			case IPC_INFO:
			case MSG_INFO:
				len = sizeof(struct msginfo);
				break;

			}
			if (len > 0) {
				pretval = ARGSKMALLOC(sizeof(u_long) + sizeof(int) + len, GFP_KERNEL);
				if (pretval == NULL) {
					printk("record_ipc (msgctl): can't allocate return value\n");
					return -ENOMEM;
				}
				*((u_long *) pretval) = sizeof(int) + len;
				*((int *) pretval + sizeof(u_long)) = call;
				if (copy_from_user (pretval + sizeof(u_long) + sizeof(int), ptr, len)) {
					ARGSKFREE (pretval, sizeof(u_long)+sizeof(int)+len);
					return -EFAULT;
				}
			}
			break;
		case MSGRCV: 
			pretval = ARGSKMALLOC(sizeof(u_long) + sizeof(long) + rc, GFP_KERNEL);
			if (pretval == NULL) {
				printk("record_ipc (msgrcv): can't allocate return value\n");
				return -ENOMEM;
			}
			*((u_long *) pretval) = sizeof(int) + sizeof(long) + rc;
			*((int *) pretval + sizeof(u_long)) = call;
			if (copy_from_user (pretval + sizeof(u_long) + sizeof(int), ptr, sizeof(long)+rc)) {
				ARGSKFREE (pretval, sizeof(u_long)+sizeof(int)+sizeof(long)+rc);
				return -EFAULT;
			}
			break;
		case SEMCTL:
			switch (second) {
			case IPC_STAT:
			case MSG_STAT:
				len = sizeof(struct semid_ds);
				break;
			case IPC_INFO:
			case MSG_INFO:
				len = sizeof(struct seminfo);
				break;
			case GETALL: {
				union semun fourth;
				struct semid_ds info;
				fourth.buf = &info;
				old_fs = get_fs();
				set_fs(KERNEL_DS);
				sys_semctl (first, second, IPC_STAT, fourth);
				set_fs(old_fs);
				len = info.sem_nsems*sizeof(u_short);
				break;
			}
			}
			if (len > 0) {
				pretval = ARGSKMALLOC(sizeof(u_long) + sizeof(int)+len, GFP_KERNEL);
				if (pretval == NULL) {
					printk("record_ipc (semctl): can't allocate return value\n");
					return -ENOMEM;
				}
				*((u_long *) pretval) = sizeof(int) + len;
				*((int *) pretval + sizeof(u_long)) = call;
				if (copy_from_user (pretval + sizeof(u_long) + sizeof(int), ptr, len)) {
					ARGSKFREE (pretval, sizeof(u_long)+sizeof(int)+len);
					return -EFAULT;
				}
			}
			break;
		case SHMAT: {
			struct shmat_retvals* patretval;
			unsigned long raddr;
			struct shmid_kernel* shp;
			u_long size;
			struct ipc_namespace* ns = current->nsproxy->ipc_ns;
			struct kern_ipc_perm *ipcp;
			
			get_user(raddr, (unsigned long __user *) third);
			
			// Need to get size in case we need to attach PIN on replay
			ipcp = ipc_lock(&ns->ids[IPC_SHM_IDS], first);
			if (IS_ERR(ipcp)) {
				printk ("record_ipc: cannot lock ipc for shmat\n");
				return -EINVAL;
			}
			shp = container_of(ipcp, struct shmid_kernel, shm_perm);
			size = shp->shm_segsz;
			ipc_unlock(&shp->shm_perm);
			
			pretval = ARGSKMALLOC (sizeof(struct shmat_retvals), GFP_KERNEL);
			patretval = (struct shmat_retvals *) pretval;
			if (patretval == NULL) {
				printk ("record_ipc(shmat) can't allocate buffer\n"); 
				return -ENOMEM;
			}
			patretval->len = sizeof(struct shmat_retvals) - sizeof(u_long);
			patretval->call = call; 
			patretval->size = size;
			patretval->raddr = raddr;

			if (current->record_thrd->rp_group->rg_save_mmap_flag) {
				MPRINT("Pid %d, shmat reserve memory %lx len %lx\n",
						current->pid,
						patretval->raddr, patretval->size);
				reserve_memory(patretval->raddr, patretval->size);
			}

			break;
		}
		case SHMCTL: {
			int cmd = second;
			ipc_parse_version(&cmd);
			switch (cmd) {
			case IPC_STAT:
			case SHM_STAT:
				len = sizeof(struct shmid_ds);
				break;
			case IPC_INFO:
			case SHM_INFO:
				len = sizeof(struct shminfo);
				break;
			}
			if (len > 0) {
				pretval = ARGSKMALLOC(sizeof(u_long) + sizeof(int) + len, GFP_KERNEL);
				if (pretval == NULL) {
					printk("record_ipc (shmctl): can't allocate return value\n");
					return -ENOMEM;
				}
				*((u_long *) pretval) = sizeof(int) + len;
				*((int *) pretval + sizeof(u_long)) = call;
				if (copy_from_user (pretval + sizeof(u_long) + sizeof(int), ptr, len)) {
					printk("record_ipc (shmctl): can't copy data from user\n");
					ARGSKFREE (pretval, sizeof(u_long)+sizeof(int)+len);
					return -EFAULT;
				}
			}
			break;
		}
		}
	}
	new_syscall_exit (117, pretval);
	return rc;
}

static asmlinkage long 
replay_ipc (uint call, int first, u_long second, u_long third, void __user *ptr, long fifth)
{
	char* retparams;
	long retval;
	long rc = get_next_syscall (117, (char **) &retparams);
	int repid, cmd;

	switch (call) {
	case MSGCTL:
	case MSGRCV:
	case SEMCTL:
		if (retparams && ptr) {
			u_long len = *((u_long *) retparams);
			if (copy_to_user (ptr, retparams+sizeof(u_long)+sizeof(int), len-sizeof(int))) {
				printk ("replay_ipc (call %d): pid %d cannot copy to user\n", call, current->pid);
				return syscall_mismatch();
			}
			argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
		}
		return rc;
	case SHMAT: 
		if (rc == 0) {
			struct shmat_retvals* atretparams = (struct shmat_retvals *) retparams;

			if (current->replay_thrd->rp_record_thread->rp_group->rg_save_mmap_flag) {
				MPRINT ("Pid %d, replay shmat reserve memory %lx len %lx\n",
						current->pid,
						atretparams->raddr, atretparams->size);
				reserve_memory(atretparams->raddr, atretparams->size);
			}

			// do_shmat checks to see if there are any existing mmaps in the region to be shmat'ed. So we'll have to munmap our preallocations for this region
			// before proceding.
			if (is_pin_attached()) {
				struct sysv_shm* tmp;
				tmp = KMALLOC(sizeof(struct sysv_shm), GFP_KERNEL);
				if (tmp == NULL) {
					printk ("Pid %d: could not alllocate for sysv_shm\n", current->pid);
					return -ENOMEM;
				}
				tmp->addr = atretparams->raddr;
				tmp->len = atretparams->size;
				list_add(&tmp->list, &current->replay_thrd->rp_sysv_shms);

				MPRINT ("  Pin is attached to pid %d - munmap preallocation before shmat at addr %lx size %lu\n", current->pid, atretparams->raddr, atretparams->size);
				retval = sys_munmap (atretparams->raddr, atretparams->size);
				if (retval) printk ("[WARN]Pid %d shmat failed to munmap the preallocation at addr %lx size %lu\n", current->pid, rc, atretparams->size);
			}

			// redo the mapping with at the same address returned during recording
			repid = find_sysv_mapping (current->replay_thrd, first);
			retval = sys_ipc (call, repid, rc, third, (void __user *) atretparams->raddr, fifth);
			if (retval != rc) {
				printk ("replay_ipc(shmat) returns different value %ld than %ld\n", retval, rc);
				return syscall_mismatch();
			}
			if (retval == 0) {
				u_long raddr;
				get_user(raddr, (unsigned long __user *) third);
				printk ("Pid %d replays SHMAT success address %lx\n", current->pid, raddr);
				if (raddr != atretparams->raddr) {
					printk ("replay_ipc(shmat) returns different address %lx than %lx\n", raddr, atretparams->raddr);
				}
			}
			argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct shmat_retvals));
		}
		return rc;
	case SHMDT: 
		retval = sys_ipc (call, first, second, third, ptr, fifth);
		if (retval != rc) {
			printk ("replay_ipc(shmdt) returns different value %ld than %ld\n", retval, rc);
			return syscall_mismatch();
		}
		/*
		 * For Pin support, we need to preallocate this again if this memory area that was just munmap'ed
		 */
		if (!retval && is_pin_attached()) {
			u_long size = 0;
			struct sysv_shm* tmp;
			struct sysv_shm* tmp_safe;
			list_for_each_entry_safe (tmp, tmp_safe, &current->replay_thrd->rp_sysv_shms, list) {
				if (tmp->addr == (u_long)ptr) {
					size = tmp->len;
					list_del(&tmp->list);
					KFREE(tmp);
				}
			}
			if (size == 0) {
				MPRINT("Pid %d replay shmdt: could not find shm %lx ???\n", current->pid, (u_long) ptr);
				syscall_mismatch();
			}

			MPRINT("Pid %d Remove shm at addr %lx, len %lx\n", current->pid, (u_long) ptr, size);
			preallocate_after_munmap((u_long) ptr, size);
		}

		return rc;
	case SHMGET: 
		retval = sys_ipc (call, first, second, third, ptr, fifth);
		if ((rc < 0 && retval >= 0) || (rc >= 0 && retval < 0)) {
			printk ("Pid %d replay_ipc SHMGET, on record we got %ld, but replay we got %ld\n", current->pid, rc, retval);
			return syscall_mismatch();
		}
		
		// put a mapping from the re-run replay identifier (pseudo), to the record one
		if (add_sysv_mapping (current->replay_thrd, rc, retval)) {
			printk ("Pid %d replay_ipc SHMGET, could not add replay identifier mapping, replay: %ld, record %ld\n", current->pid, retval, rc);
			return syscall_mismatch();
		}
		return rc;
	case SHMCTL: 
		cmd = second;
		ipc_parse_version(&cmd);
		switch (cmd) {
		case IPC_STAT:
		case IPC_INFO:
		case SHM_STAT:
		case SHM_INFO:
			if (retparams && ptr) {
				u_long len = *((u_long *) retparams);
				if (copy_to_user (ptr, retparams+sizeof(u_long)+sizeof(int), len-sizeof(int))) {
					printk ("replay_ipc (call %d): pid %d cannot copy to user\n", call, current->pid);
					return syscall_mismatch();
				}
				argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
			}
			break;
		case IPC_RMID:
			repid = find_sysv_mapping (current->replay_thrd, first);
			return sys_ipc (call, repid, second, third, ptr, fifth);
		}
		return rc;
	}
	return rc;
}

asmlinkage long shim_ipc (uint call, int first, u_long second, u_long third, void __user *ptr, long fifth) SHIM_CALL (ipc, 117, call, first, second, third, ptr, fifth);

SIMPLE_SHIM1(fsync, 118, unsigned int, fd);

unsigned long dummy_sigreturn(struct pt_regs *regs); /* In arch/x86/kernel/signal.c */

long shim_sigreturn(struct pt_regs* regs)
{
	if (current->record_thrd) {
		struct repsignal_context* pcontext = current->record_thrd->rp_repsignal_context_stack;
		if (pcontext) {
			if (current->record_thrd->rp_ignore_flag_addr) put_user (pcontext->ignore_flag, current->record_thrd->rp_ignore_flag_addr);
			current->record_thrd->rp_repsignal_context_stack = pcontext->next;
			KFREE (pcontext);
		} else {
			printk ("Pid %d does sigreturn but no context???\n", current->pid);
		}
	}

	return dummy_sigreturn(regs);
}

static long 
record_clone(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
	struct pthread_log_head __user * phead = NULL;
#ifdef USE_DEBUG_LOG
	struct pthread_log_data __user * start, *old_start = NULL;
#else
	char __user * start, *old_start = NULL;
	u_long old_expected_clock, old_num_expected_records;
#endif
#ifdef USE_EXTRA_DEBUG_LOG
	struct pthread_extra_log_head __user * pehead = NULL;
	char __user * estart, *old_estart = NULL;
#endif
	struct record_group* prg;
	struct task_struct* tsk;
	long rc;
	void* slab;

	prg = current->record_thrd->rp_group;

	new_syscall_enter (120);

	if (!(clone_flags&CLONE_VM)) {
		/* The intent here is to change the next pointer for the child - the easiest way to do this is to change
		   the parent, fork, and then revert the parent */
		phead = (struct pthread_log_head __user *) current->record_thrd->rp_user_log_addr;
#ifdef USE_DEBUG_LOG
		start = (struct pthread_log_data __user *) ((char __user *) phead + sizeof (struct pthread_log_head));
#else
		start = (char __user *) phead + sizeof (struct pthread_log_head);
#endif
		get_user (old_start, &phead->next);
		put_user (start, &phead->next);
#ifdef USE_EXTRA_DEBUG_LOG
		pehead = (struct pthread_extra_log_head __user *) current->record_thrd->rp_user_extra_log_addr;
		estart = (char __user *) pehead + sizeof (struct pthread_extra_log_head);
		get_user (old_estart, &pehead->next);
		put_user (estart, &pehead->next);
#endif

#ifndef USE_DEBUG_LOG
		get_user (old_expected_clock, &phead->expected_clock);
		put_user (0, &phead->expected_clock);
		get_user (old_num_expected_records, &phead->num_expected_records);
		put_user (0, &phead->num_expected_records);
#endif
	}

	rc = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
	MPRINT ("Pid %d records clone with flags %lx fork %d returning %ld\n", current->pid, clone_flags, (clone_flags&CLONE_VM) ? 0 : 1, rc);

	rg_lock(prg);
	new_syscall_done (120, rc);
	new_syscall_exit (120, NULL);

	if (rc > 0) {
		// Create a record thread struct for the child
		tsk = pid_task(find_vpid(rc), PIDTYPE_PID);
		if (tsk == NULL) {
			printk ("record_clone: cannot find child\n");
			rg_unlock(prg);
			return -ECHILD;
		}

#ifdef CACHE_READS
		if (clone_flags&CLONE_FILES) {
			// file descriptor table is shared so share handles to clone files
			tsk->record_thrd = new_record_thread (prg, tsk->pid, current->record_thrd->rp_cache_files);
		} else {
#endif
			tsk->record_thrd = new_record_thread (prg, tsk->pid, NULL); 
#ifdef CACHE_READS
			copy_record_cache_files (current->record_thrd->rp_cache_files, tsk->record_thrd->rp_cache_files);
		}
#endif
		if (tsk->record_thrd == NULL) {
			rg_unlock(prg);
			return -ENOMEM; 
		}
		tsk->replay_thrd = NULL;

		tsk->record_thrd->rp_next_thread = current->record_thrd->rp_next_thread;
		current->record_thrd->rp_next_thread = tsk->record_thrd;
		
		if (!(clone_flags&CLONE_VM)) {
			tsk->record_thrd->rp_user_log_addr = current->record_thrd->rp_user_log_addr;
			tsk->record_thrd->rp_ignore_flag_addr = current->record_thrd->rp_ignore_flag_addr;
			put_user (old_start, &phead->next);
#ifdef USE_EXTRA_DEBUG_LOG
			tsk->record_thrd->rp_user_extra_log_addr = current->record_thrd->rp_user_extra_log_addr;
			put_user (old_estart, &pehead->next);
#endif
#ifndef USE_DEBUG_LOG
			put_user (old_expected_clock, &phead->expected_clock);
			put_user (old_num_expected_records, &phead->num_expected_records);
#endif			
		}

		// allocate a slab for retparams
		slab = VMALLOC (argsalloc_size);
		if (slab == NULL) return -ENOMEM;
		if (add_argsalloc_node(tsk->record_thrd, slab, argsalloc_size)) {
			VFREE (slab);
			printk ("Pid %d fork_replay: error adding argsalloc_node\n", current->pid);
			return -ENOMEM;
		}

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
	struct task_struct* tsk = NULL;
	struct replay_group* prg;
	struct replay_thread* prept;
	long rc;
	pid_t pid;
	ds_list_iter_t* iter;
	struct record_thread* prt;
	struct syscall_result* psr;

	prg = current->replay_thrd->rp_group;

	MPRINT ("Pid %d replay_clone with flags %lx\n", current->pid, clone_flags);
	if (is_pin_attached()) {
		rc = current->replay_thrd->rp_saved_rc;
		(*(int*)(current->replay_thrd->app_syscall_addr)) = 999;
	} else {
		rc = get_next_syscall_enter (current->replay_thrd, prg, 120, NULL, &psr);
	}

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
			prt = new_record_thread (prg->rg_rec_group, rc, NULL);
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
#ifdef CACHE_READS
		if (clone_flags&CLONE_FILES) {
			// file descriptor table is shared so share handles to clone files
			tsk->replay_thrd = new_replay_thread(prg, prt, pid, 0, current->replay_thrd->rp_cache_files);
		} else {
#endif
			tsk->replay_thrd = new_replay_thread(prg, prt, pid, 0, NULL);
#ifdef CACHE_READS
			copy_replay_cache_files (current->replay_thrd->rp_cache_files, tsk->replay_thrd->rp_cache_files);
		}
#endif
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
			DPRINT ("This is a fork-style clone - reset the user log appropriately\n");
			tsk->replay_thrd->rp_record_thread->rp_user_log_addr = current->replay_thrd->rp_record_thread->rp_user_log_addr;
#ifdef USE_EXTRA_DEBUG_LOG
			tsk->replay_thrd->rp_record_thread->rp_user_extra_log_addr = current->replay_thrd->rp_record_thread->rp_user_extra_log_addr;
#endif
			tsk->replay_thrd->rp_record_thread->rp_ignore_flag_addr = current->replay_thrd->rp_record_thread->rp_ignore_flag_addr;
		}
		
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
		
	if (current->replay_thrd->app_syscall_addr == 0) {
		get_next_syscall_exit (current->replay_thrd, prg, psr);
	}

	if (rc > 0 && (clone_flags&CLONE_VM) && is_pin_attached()) {
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
		// This is a Pin fork
		child_pid = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
		tsk = pid_task (find_vpid(child_pid), PIDTYPE_PID);
		if (!tsk) {
			printk ("[DIFF]shim_clone: cannot find replaying Pid %d\n", child_pid);
			return -EINVAL;
		}
		tsk->replay_thrd = NULL;
		// Special case for Pin: Pin threads run along side the application's, but without the
		// replay flag set. Becuase of this, we need to wake up the thread after sys_clone.
		// See copy_process in kernel/fork.c
		wake_up_new_task(tsk);
		MPRINT("Pid %d - Pin fork child %d\n", current->pid, child_pid);
		return child_pid;
	}
	return do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);
}

SIMPLE_SHIM2(setdomainname, 121, char __user *, name, int, len);
RET1_SHIM1(newuname, 122, struct new_utsname, name, struct new_utsname __user *, name);
/* modify_ldt appears to only affect the process and is deterministic, so do not record/replay */
RET1_SHIM1(adjtimex, 124, struct timex, txc_p, struct timex __user *, txc_p);

static asmlinkage long 
record_mprotect (unsigned long start, size_t len, unsigned long prot)
{
	long rc;

	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (125);
	rc = sys_mprotect (start, len, prot);
	new_syscall_done (125, rc);
	DPRINT ("Pid %d records mprotect %lx for %lx-%lx returning %ld\n", current->pid, prot, start, start+len, rc);
	new_syscall_exit (125, NULL);
	rg_unlock(current->record_thrd->rp_group);

	return rc;
}

static asmlinkage long 
replay_mprotect (unsigned long start, size_t len, unsigned long prot)
{
	u_long retval, rc;

	if (is_pin_attached()) {
		rc = current->replay_thrd->rp_saved_rc;
		(*(int*)(current->replay_thrd->app_syscall_addr)) = 999;
	} else {
		rc = get_next_syscall (125, NULL);
	}

	retval = sys_mprotect (start, len, prot);
	DPRINT ("Pid %d replays mprotect %lx for %lx-%lx returning %ld\n", current->pid, prot, start, start+len, retval);

	if (rc != retval) {
		printk ("Replay: mprotect returns diff. value %lu than %lu\n", retval, rc);
		return syscall_mismatch();
	}
	return rc;
}

asmlinkage long shim_mprotect (unsigned long start, size_t len, unsigned long prot) SHIM_CALL(mprotect, 125, start, len, prot);

RET1_SHIM3(sigprocmask, 126, old_sigset_t, oset, int, how, old_sigset_t __user *, set, old_sigset_t __user *, oset);
SIMPLE_SHIM3(init_module, 128, void __user *, umod, unsigned long,  len, const char __user *, uargs);
SIMPLE_SHIM2(delete_module, 129, const char __user *, name_user, unsigned int, flags);

asmlinkage long 
record_quotactl (unsigned int cmd, const char __user *special, qid_t id, void __user *addr)
{
	char* pretval = NULL;
	u_int cmds = cmd >> SUBCMDSHIFT;
	long rc;
	u_long len = 0;

	new_syscall_enter (131);
	rc = sys_quotactl (cmd, special, id, addr);
	new_syscall_done (131, rc);
	if (rc >= 0) {
		
		switch (cmds) {
		case Q_GETQUOTA: 
			len = sizeof(struct if_dqblk);
			break;
		case Q_GETINFO:
			len = sizeof(struct if_dqinfo);
			break;
		case Q_GETFMT:
			len = sizeof(__u32);
			break;
		case Q_XGETQUOTA:
			len = sizeof(struct fs_disk_quota);
			break;
		case Q_XGETQSTAT:
			len = sizeof(struct fs_quota_stat);
			break;
		}
		if (len > 0) {
			pretval = ARGSKMALLOC(sizeof(u_long) + len, GFP_KERNEL);
			if (pretval == NULL) {
				printk("record_quotactl: can't allocate return value\n");
				return -ENOMEM;
			}
			*((u_long *) pretval) = len;
			if (copy_from_user (pretval + sizeof(u_long), addr, len)) {
				ARGSKFREE (pretval, sizeof(u_long)+len);
				return -EFAULT;
			}
		}
	}
	new_syscall_exit (131, pretval);
	return rc;
}

asmlinkage long 
replay_quotactl (unsigned int cmd, const char __user *special, qid_t id, void __user *addr)
{
	char* retparams = NULL;
	u_long len;
	long rc;

	rc = get_next_syscall (131, &retparams);
	if (retparams && addr) {
		len = *((u_long *) retparams);
		if (copy_to_user (addr, retparams+sizeof(u_long), len)) {
			printk ("replay_quotactl: pid %d cannot copy to user\n", current->pid);
			return syscall_mismatch();
		}
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
	}
	return rc;
}

asmlinkage long shim_quotactl (unsigned int cmd, const char __user *special, qid_t id, void __user *addr) SHIM_CALL(quotactl, 131, cmd, special, id, addr);

SIMPLE_SHIM1(getpgid, 132, pid_t, pid);
SIMPLE_SHIM1(fchdir, 133, unsigned int, fd);

static asmlinkage long 
record_bdflush (int func, long data)
{									
	long rc;							
	long *pretval = NULL;						
									
	new_syscall_enter (134);				
	rc = sys_bdflush (func, data);
	new_syscall_done (134, rc);
	if (rc >= 0 && func > 2 && func%2 == 0) {
	        pretval = ARGSKMALLOC (sizeof(long), GFP_KERNEL);
		if (pretval == NULL) {				
			printk ("record_bdflush: can't allocate buffer\n"); 
			return -ENOMEM;					
		}							
		if (copy_from_user (pretval, (long __user *) data, sizeof (long))) {	
			printk ("record_bdflush: can't copy to buffer\n"); 
			ARGSKFREE(pretval, sizeof(long));		
			pretval = NULL;					
			rc = -EFAULT;					
		}							
	}								
									
	new_syscall_exit (134, pretval);				
	return rc;							
}

static asmlinkage long replay_bdflush (int func, long data)
{									
	char *retparams = NULL;						
	long rc = get_next_syscall (134, &retparams); 
	if (retparams) {						
		if (copy_to_user ((long __user *) data, retparams, sizeof(long))) printk ("replay_bdflush: pid %d cannot copy to user\n", current->pid); 
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(long));
	}								
									
	return rc;							
}									

asmlinkage long shim_bdflush (int func, long data) SHIM_CALL (bdflush, 134, func, data);

static asmlinkage long 
record_sysfs (int option, unsigned long arg1, unsigned long arg2)
{									
	long rc, len;							
	char *pretval = NULL;						
									
	new_syscall_enter (135);				
	rc = sys_sysfs (option, arg1, arg2);
	new_syscall_done (135, rc);
	if (rc >= 0 && option == 2) {
		len = strlen_user ((char __user *) arg2)+1;
		if (len <= 0) {
			printk ("record_sysfs: pid %d unable to determine buffer length\n", current->pid);
			return -EINVAL;
		}
	        pretval = ARGSKMALLOC (len+sizeof(long), GFP_KERNEL);
		if (pretval == NULL) {				
			printk ("record_sysfs: can't allocate buffer\n"); 
			return -ENOMEM;					
		}					
		*((u_long *) pretval) = len;
		if (copy_from_user (pretval+sizeof(u_long), (long __user *) arg2, len)) {	
			printk ("record_sysfs: can't copy to buffer\n"); 
			ARGSKFREE(pretval, len);		
			return -EFAULT;
		}							
	}								
									
	new_syscall_exit (135, pretval);				
	return rc;							
}

static asmlinkage long 
replay_sysfs (int option, unsigned long arg1, unsigned long arg2)
{									
	char *retparams = NULL;						
	long rc = get_next_syscall (135, &retparams); 
	if (retparams) {						
		u_long len = *((u_long *) retparams);
		if (copy_to_user ((char __user *) arg2, retparams+sizeof(u_long), len)) printk ("replay_sysfs: pid %d cannot copy to user\n", current->pid); 
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
	}								
									
	return rc;							
}									

asmlinkage long shim_sysfs (int option, unsigned long arg1, unsigned long arg2) SHIM_CALL(sysfs, 135, option, arg1, arg2);

SIMPLE_SHIM1(personality, 136, u_long, parm);
SIMPLE_SHIM1(setfsuid16, 138, old_uid_t, uid);
SIMPLE_SHIM1(setfsgid16, 139, old_gid_t, gid);
RET1_SHIM5(llseek, 140, loff_t, result, unsigned int, fd, unsigned long, offset_high, unsigned long, offset_low, loff_t __user *, result, unsigned int, origin);
RET1_COUNT_SHIM3(getdents, 141, dirent, unsigned int, fd, struct linux_dirent __user *, dirent, unsigned int, count);

static asmlinkage long 
record_select (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
{
	long rc;
	char* pretvals, *p;
	u_long sets = 0, size;
	
	new_syscall_enter (142);
	rc = sys_select (n, inp, outp, exp, tvp);
	new_syscall_done (142, rc);

	/* Record user's memory regardless of return value in order to capture partial output. */
	if (inp) sets++;
	if (outp) sets++;
	if (exp) sets++;
	size = FDS_BYTES(n)*sets;
	if (tvp) size += sizeof(struct timeval);
	
	pretvals = ARGSKMALLOC(sizeof(u_long)+size, GFP_KERNEL);
	if (pretvals == NULL) {
		printk("record_select: can't allocate buffer\n");
		return -ENOMEM;
	}
	*((u_long *) pretvals) = size; // Needed for parseklog currently
	p = pretvals + sizeof(u_long);
	if (inp) {
		if (copy_from_user (p, inp, FDS_BYTES(n))) {
			printk ("record_select: copy of inp failed\n");
			ARGSKFREE(pretvals, sizeof(u_long)+size);
			return -EFAULT;
		}
		p += FDS_BYTES(n);
	}
	if (outp) {
		if (copy_from_user (p, outp, FDS_BYTES(n))) {
			printk ("record_select: copy of outp failed\n");
			ARGSKFREE(pretvals, sizeof(u_long)+size);
			return -EFAULT;
		}
		p += FDS_BYTES(n);
	}
	if (exp) {
		if (copy_from_user (p, exp, FDS_BYTES(n))) {
			printk ("record_select: copy of exp failed\n");
			ARGSKFREE(pretvals, sizeof(u_long)+size);
			return -EFAULT;
		}
		p += FDS_BYTES(n);
	}
	if (tvp) {
		if (copy_from_user (p, tvp, sizeof(struct timeval))) {
			printk ("record_select: copy of exp failed\n");
			ARGSKFREE(pretvals, sizeof(u_long)+size);
			return -EFAULT;
		}
	}

	new_syscall_exit (142, pretvals);
	return rc;
}

asmlinkage long 
replay_select (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
{
	char* retparams;
	u_long size;
	long rc = get_next_syscall (142, (char **) &retparams);

	size = *((u_long *) retparams);
	retparams += sizeof(u_long);
	if (inp) {
		if (copy_to_user (inp, retparams, FDS_BYTES(n))) {
			printk ("Pid %d cannot copy inp to user\n", current->pid);
			syscall_mismatch();
		}
		retparams += FDS_BYTES(n);
	}
	if (outp) {
		if (copy_to_user (outp, retparams, FDS_BYTES(n))) {
			printk ("Pid %d cannot copy outp to user\n", current->pid);
			syscall_mismatch();
		}
		retparams += FDS_BYTES(n);
	}
	if (exp) {
		if (copy_to_user (exp, retparams, FDS_BYTES(n))) {
			printk ("Pid %d cannot copy exp to user\n", current->pid);
			syscall_mismatch();
		}
		retparams += FDS_BYTES(n);
	}
	if (tvp) {
		if (copy_to_user (tvp, retparams, sizeof(struct timeval))) {
			printk ("Pid %d cannot copy tvp to user\n", current->pid);
			syscall_mismatch();
		}
	}
	argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long)+size);
	
	return rc;
}

asmlinkage long shim_select (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp) SHIM_CALL(select, 142, n, inp, outp, exp, tvp);

SIMPLE_SHIM2 (flock, 143, unsigned int, fd, unsigned int, cmd);
SIMPLE_SHIM3 (msync, 144, unsigned long, start, size_t, len, int, flags);

static asmlinkage long 
record_readv (unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
	long size;

	new_syscall_enter (145);
	size = sys_readv (fd, vec, vlen);
	new_syscall_done (145, size);
	new_syscall_exit (145, copy_iovec_to_args(size, vec, vlen));
	return size;
}

static asmlinkage long 
replay_readv (unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
	char* retparams;
	long retval, rc;

	rc = get_next_syscall (145, &retparams);
	if (retparams) {
		retval = copy_args_to_iovec (retparams, rc, vec, vlen);
		if (retval < 0) return retval;
		argsconsume(current->replay_thrd->rp_record_thread, rc);
	}

	return rc;
}

asmlinkage long shim_readv (unsigned long fd, const struct iovec __user *vec, unsigned long vlen) SHIM_CALL(readv, 145, fd, vec, vlen);

SIMPLE_SHIM3(writev, 146, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen);
SIMPLE_SHIM1(getsid, 147, pid_t, pid);
SIMPLE_SHIM1(fdatasync, 148, int, fd);

static asmlinkage long 
record_sysctl (struct __sysctl_args __user *args)
{									
	long rc;							
	char *pretval = NULL;						
	struct __sysctl_args kargs;
	size_t oldlen = 0;

	new_syscall_enter (149);				
	rc = sys_sysctl (args);
	new_syscall_done (149, rc);
	if (rc >= 0) {
		if (copy_from_user (&kargs, args, sizeof(struct __sysctl_args))) {
			printk ("record_sysctl: pid %d cannot copy args struct from user\n", current->pid);
			return -EFAULT;
		}
		if (kargs.oldval && kargs.oldlenp) {
			if (copy_from_user (&oldlen, &kargs.oldlenp, sizeof(size_t))) {
				printk ("record_sysctl: pid %d cannot copy size from user\n", current->pid);
				return -EFAULT;
			}
			pretval = ARGSKMALLOC (sizeof(oldlen), GFP_KERNEL);
			if (pretval == NULL) {				
				printk ("record_sysctl: pid %d can't allocate buffer of size %ld\n", current->pid, (long) oldlen); 
				return -ENOMEM;					
			}
			*((u_long *) pretval) = oldlen;
			if (copy_from_user (pretval+sizeof(u_long), kargs.oldval, oldlen)) {	
				printk ("record_sysctl: pid %d cannot copy buffer from user\n", current->pid); 
				ARGSKFREE(pretval, oldlen);		
				return -EFAULT;
			}			
		}				
	}																	
	new_syscall_exit (149, pretval);				
	return rc;							
}

static asmlinkage long 
replay_sysctl (struct __sysctl_args __user *args)
{									
	char *retparams = NULL;						
	struct __sysctl_args kargs;
	u_long oldlen;

	long rc = get_next_syscall (149, &retparams); 
	if (retparams) {						
		if (copy_from_user (&kargs, args, sizeof(struct __sysctl_args))) {
			printk ("replay_sysctl: pid %d cannot copy args struct from user\n", current->pid);
			return syscall_mismatch();
		}
		oldlen = *((u_long *) retparams);
		if (copy_to_user (kargs.oldval, retparams+sizeof(u_long), oldlen)) printk ("replay_sysctl: pid %d cannot copy to user\n", current->pid); 
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + oldlen);
	}								
									
	return rc;							
}									

asmlinkage long shim_sysctl (struct __sysctl_args __user *args) SHIM_CALL(sysctl, 149, args); 

SIMPLE_SHIM2(mlock, 150, unsigned long, start, size_t, len);
SIMPLE_SHIM2(munlock, 151, unsigned long, start, size_t, len);
SIMPLE_SHIM1(mlockall, 152, int, flags);
SIMPLE_SHIM0(munlockall, 153);
SIMPLE_SHIM2(sched_setparam, 154, pid_t, pid, struct sched_param __user *, param);
RET1_SHIM2(sched_getparam, 155, struct sched_param, param, pid_t, pid, struct sched_param __user *, param);
SIMPLE_SHIM3(sched_setscheduler, 156, pid_t, pid, int, policy, struct sched_param __user *, param);
SIMPLE_SHIM1(sched_getscheduler, 157, pid_t, pid);

SIMPLE_RECORD0(sched_yield, 158);
SIMPLE_REPLAY(sched_yield, 158, void);
asmlinkage long shim_sched_yield (void) 
{
	struct replay_thread* tmp;
	int ret;

	if (current->replay_thrd && !test_app_syscall(158)) {
		MPRINT ("Pid %d: pin appears to be calling sched yield\n", current->pid);

		// See if we can find another eligible thread
		tmp = current->replay_thrd->rp_next_thread;

		while (tmp != current->replay_thrd) {
			MPRINT ("Pid %d considers thread %d (recpid %d) status %d clock %ld - clock is %ld\n", current->pid, tmp->rp_replay_pid, tmp->rp_record_thread->rp_record_pid, tmp->rp_status, tmp->rp_wait_clock, *(current->replay_thrd->rp_preplay_clock));
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

SIMPLE_SHIM1(sched_get_priority_max, 159, int, policy);
SIMPLE_SHIM1(sched_get_priority_min, 160, int, policy);
RET1_SHIM2(sched_rr_get_interval, 161, struct timespec, interval, pid_t, pid, struct timespec __user *,interval);
RET1_SHIM2(nanosleep, 162, struct timespec, rmtp, struct timespec __user *, rqtp, struct timespec __user *, rmtp);

static asmlinkage unsigned long 
record_mremap (unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
	unsigned long rc;

	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (163);
	rc = sys_mremap (addr, old_len, new_len, flags, new_addr);
	new_syscall_done (163, rc);
	new_syscall_exit (163, NULL);
	rg_unlock(current->record_thrd->rp_group);
	
	return rc;
}

static asmlinkage unsigned long 
replay_mremap (unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
	u_long retval, rc = get_next_syscall (163, NULL);
	retval = sys_mremap (addr, old_len, new_len, flags, new_addr);
	DPRINT ("Pid %d replays mremap with address %lx returning %lx\n", current->pid, addr, retval);

	if (rc != retval) {
		printk ("Replay mremap returns different value %lu than %lu\n", retval, rc);
		return syscall_mismatch();
	}
	return rc;
}

asmlinkage unsigned long shim_mremap (unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr) SHIM_CALL(mremap, 163, addr, old_len, new_len, flags, new_addr);

SIMPLE_SHIM3(setresuid16, 164, old_uid_t, ruid, old_uid_t, euid, old_uid_t, suid);

static asmlinkage long
record_getresuid16 (old_uid_t __user *ruid, old_uid_t __user *euid, old_uid_t __user *suid) 
{
	long rc;
	old_uid_t* pretval = NULL;

	new_syscall_enter (165);
	rc = sys_getresuid16 (ruid, euid, suid);
	new_syscall_done (165, rc);
	if (rc >= 0) {
		pretval = ARGSKMALLOC(sizeof(old_uid_t)*3, GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_getresuid16: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, ruid, sizeof(old_uid_t)) ||
		    copy_from_user (pretval+1, euid, sizeof(old_uid_t)) ||
		    copy_from_user (pretval+2, suid, sizeof(old_uid_t))) {
			ARGSKFREE (pretval, sizeof(old_uid_t)*3);
			return -EFAULT;
		}
	}
	new_syscall_exit (165, pretval);

	return rc;
}

static asmlinkage long
replay_getresuid16 (old_uid_t __user *ruid, old_uid_t __user *euid, old_uid_t __user *suid) 
{
	old_uid_t* retparams = NULL;
	long rc = get_next_syscall (165, (char **) &retparams);
	if (rc >= 0) {
		if (retparams) {
			if (copy_to_user (ruid, retparams, sizeof(old_uid_t)) ||
			    copy_to_user (euid, retparams+1, sizeof(old_uid_t)) ||
			    copy_to_user (suid, retparams+2, sizeof(old_uid_t))) {
				printk ("replay_getresuid16: pid %d cannot copy uids to user\n", current->pid);
			}
			argsconsume(current->replay_thrd->rp_record_thread, 3*sizeof(old_uid_t));
		} else {
			printk ("getresuid16 has return values but non-negative rc?\n");
		}
	}
	return rc;
}

asmlinkage long shim_getresuid16 (old_uid_t __user *ruid, old_uid_t __user *euid, old_uid_t __user *suid) SHIM_CALL(getresuid16, 165, ruid, euid, suid);

// I believe vm86 is deterministic, so don't intercept it

static asmlinkage long 
record_poll (struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs)
{
	long rc;
	char* pretvals = NULL;
	short* p;
	int i;

	new_syscall_enter (168);
	rc = sys_poll (ufds, nfds, timeout_msecs);
	new_syscall_done (168, rc);
	if (rc > 0) {
		pretvals = ARGSKMALLOC(sizeof(int)+nfds*sizeof(short), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_poll: can't allocate buffer\n");
			return -ENOMEM;
		}
		*((u_long *)pretvals) = nfds*sizeof(short);
		p = (short *) (pretvals+sizeof(u_long));
		for (i = 0; i < nfds; i++) {
			if (copy_from_user (p, &ufds[i].revents, sizeof(short))) {
				printk ("record_poll: can't copy retval %d\n", i);
				ARGSKFREE (pretvals,sizeof(u_long)+nfds*sizeof(short));
				return -EFAULT;
			}
			p++;
		}
	}		
	new_syscall_exit (168, pretvals);

	return rc;
}

static asmlinkage long 
replay_poll (struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs)
{
	char* retparams = NULL;
	long rc;
	int i;
	short* p;

	rc = get_next_syscall (168, (char **) &retparams);
	if (rc == -ERESTART_RESTARTBLOCK) { // Save info for restart of syscall
		struct restart_block *restart_block;
		
		printk ("pid %d restarting poll system call\n", current->pid);
		restart_block = &current_thread_info()->restart_block;
		restart_block->fn = do_restart_poll;
		restart_block->poll.ufds = ufds;
		restart_block->poll.nfds = nfds;
		set_thread_flag(TIF_SIGPENDING); // Apparently necessary to actually restart 
	}
	if (retparams) {
		p = (short *) (retparams+sizeof(u_long));
		for (i = 0; i < nfds; i++) {
			if (copy_to_user (&ufds[i].revents, p, sizeof(short))) {
				printk ("Pid %d cannot copy revent %d to user\n", current->pid, i);
				syscall_mismatch();
			}
			p++;
		}
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + *((u_long *) retparams));
	} else {
		for (i = 0; i < nfds; i++) {
			put_user ((short) 0, &ufds[i].revents);
		}
	}
	
	return rc;
}

asmlinkage long shim_poll (struct pollfd __user *ufds, unsigned int nfds, long timeout_msecs) SHIM_CALL(poll, 168, ufds, nfds, timeout_msecs);

SIMPLE_SHIM3(setresgid16, 170, old_gid_t, rgid, old_gid_t, egid, old_gid_t, sgid);

static asmlinkage long
record_getresgid16 (old_gid_t __user *rgid, old_gid_t __user *egid, old_gid_t __user *sgid) 
{
	long rc;
	old_gid_t* pretval = NULL;

	new_syscall_enter (171);
	rc = sys_getresgid16 (rgid, egid, sgid);
	new_syscall_done (171, rc);
	if (rc >= 0) {
		pretval = ARGSKMALLOC(sizeof(old_gid_t)*3, GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_getresgid16: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, rgid, sizeof(old_gid_t)) ||
		    copy_from_user (pretval+1, egid, sizeof(old_gid_t)) ||
		    copy_from_user (pretval+2, sgid, sizeof(old_gid_t))) {
			ARGSKFREE (pretval, sizeof(old_gid_t)*3);
			return -EFAULT;
		}
	}
	new_syscall_exit (171, pretval);

	return rc;
}

static asmlinkage long
replay_getresgid16 (old_gid_t __user *rgid, old_gid_t __user *egid, old_gid_t __user *sgid) 
{
	old_gid_t* retparams = NULL;
	long rc = get_next_syscall (171, (char **) &retparams);
	if (rc >= 0) {
		if (retparams) {
			if (copy_to_user (rgid, retparams, sizeof(old_gid_t)) ||
			    copy_to_user (egid, retparams+1, sizeof(old_gid_t)) ||
			    copy_to_user (sgid, retparams+2, sizeof(old_gid_t))) {
				printk ("replay_getresgid16: pid %d cannot copy gids to user\n", current->pid);
			}
			argsconsume(current->replay_thrd->rp_record_thread, 3*sizeof(old_gid_t));
		} else {
			printk ("getresgid16 has return values but non-negative rc?\n");
		}
	}
	return rc;
}

asmlinkage long shim_getresgid16 (old_gid_t __user *rgid, old_gid_t __user *egid, old_gid_t __user *sgid) SHIM_CALL(getresgid16, 171, rgid, egid, sgid);

asmlinkage long 
record_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	char* pretval = NULL;
	u_long len = 0;
	long rc;

	new_syscall_enter (172);
	rc = sys_prctl (option, arg2, arg3, arg4, arg5);
	new_syscall_done (172, rc);
	if (rc >= 0) {
		switch (option) {
		case PR_GET_CHILD_SUBREAPER:
		case PR_GET_PDEATHSIG:
		case PR_GET_TSC:
		case PR_GET_UNALIGN:
			len = sizeof(int);
			break;
		case PR_GET_NAME:
			len = 16; /* per man page */
			break;
		case PR_GET_TID_ADDRESS:
			len = sizeof(int *);
			break;
		}
		if (len > 0) {
			pretval = ARGSKMALLOC(sizeof(u_long) + len, GFP_KERNEL);
			if (pretval == NULL) {
				printk("record_quotactl: can't allocate return value\n");
				return -ENOMEM;
			}
			*((u_long *) pretval) = len;
			if (copy_from_user (pretval + sizeof(u_long), (char __user *) arg2, len)) {
				ARGSKFREE (pretval, sizeof(u_long)+len);
				return -EFAULT;
			}
		}
	}
	new_syscall_exit (172, NULL);

	return rc;
}

asmlinkage long 
replay_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	char* retparams = NULL;
	long retval;
	long rc = get_next_syscall (172, &retparams);

	DPRINT("Pid %d calls replay_prctl with option %d\n", current->pid, option);
	if (option == PR_SET_NAME || option == PR_SET_MM) { // Do this also during recording
		retval = sys_prctl(option, arg2, arg3, arg4, arg5);
		if (retval != rc) {
			printk ("pid %d mismatch: prctl option %d returns %ld on replay and %ld during recording\n", current->pid, option, retval, rc);
			return syscall_mismatch();
		}
	}
	if (retparams && arg2) {
		u_long len = *((u_long *) retparams);
		if (copy_to_user ((char __user *) arg2, retparams+sizeof(u_long), len)) {
			printk ("replay_quotactl: pid %d cannot copy to user\n", current->pid);
			return syscall_mismatch();
		}
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
	}
	return rc;
}

asmlinkage long shim_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) SHIM_CALL(prctl, 172, option, arg2, arg3, arg4, arg5);

long dummy_rt_sigreturn(struct pt_regs *regs); /* In arch/x86/kernel/signal.c */

long shim_rt_sigreturn(struct pt_regs* regs)
{
	if (current->record_thrd) {
		struct repsignal_context* pcontext = current->record_thrd->rp_repsignal_context_stack;
		if (pcontext) {
			if (current->record_thrd->rp_ignore_flag_addr) put_user (pcontext->ignore_flag, current->record_thrd->rp_ignore_flag_addr);
			current->record_thrd->rp_repsignal_context_stack = pcontext->next;
			KFREE (pcontext);
		} else {
			printk ("Pid %d does rt_sigreturn but no context???\n", current->pid);
		}
	}

	return dummy_rt_sigreturn(regs);
}

/* Can't find a definition of this in header files */
asmlinkage long sys_rt_sigaction (int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize);

static asmlinkage long
record_rt_sigaction (int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize)
{
	long rc;
	struct sigaction* pretval = NULL;
	
	new_syscall_enter (174);
	rc = sys_rt_sigaction (sig, act, oact, sigsetsize);
	new_syscall_done (174, rc);

	if (rc == 0 && oact) {
		pretval = ARGSKMALLOC(sizeof(struct sigaction), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_rt_sigaction: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, oact, sizeof(struct sigaction))) {
			ARGSKFREE (pretval, sizeof(struct sigaction));
			pretval = NULL;
			rc = -EFAULT;
		}
	}
	new_syscall_exit (174, pretval);
	
	return rc;
}

static asmlinkage long
replay_rt_sigaction (int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize)
{
	long rc, retval;
	char* retparams = NULL;
	struct replay_thread* prt = current->replay_thrd;
	
	if (is_pin_attached()) {
		rc = prt->rp_saved_rc;
		retparams = prt->rp_saved_retparams;
		// this is an application syscall (with Pin)
		(*(int*)(prt->app_syscall_addr)) = 999;
		// actually perform rt_sigaction
		retval = sys_rt_sigaction (sig, act, oact, sigsetsize);
		if (rc != retval) {
			printk("ERROR: sigaction mismatch, got %ld, expected %ld", retval, rc);
			syscall_mismatch();
		}
	} else {
		rc = get_next_syscall (174, &retparams);
	}

	if (retparams) {
		if (oact) {
			if (copy_to_user (oact, retparams, sizeof(struct sigaction))) {
				printk ("Pid %d replay_rt_sigaction cannot copy oact %p to user\n", current->pid, oact);
			}
		}
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct sigaction));
	}

	return rc;
}

asmlinkage long
shim_rt_sigaction (int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize)
SHIM_CALL(rt_sigaction, 174, sig, act, oact, sigsetsize);

static asmlinkage long
record_rt_sigprocmask (int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
	long rc;
	char* buf = NULL;

	new_syscall_enter (175);
	rc = sys_rt_sigprocmask (how, set, oset, sigsetsize);
	new_syscall_done (175, rc);
	DPRINT ("Pid %d records rt_sigprocmask returning %ld\n", current->pid, rc);

	if (rc == 0 && oset) {
		/* Buffer describes its own size */
		buf = ARGSKMALLOC(sizeof(u_long) + sigsetsize, GFP_KERNEL);
		if (buf == NULL) {
			printk("record_rt_sigprocmask: can't alloc buffer\n");
			return -ENOMEM;
		}
		*((u_long *) buf) = sigsetsize;
		if (copy_from_user (buf+sizeof(u_long), oset, sigsetsize)) {
			ARGSKFREE (buf, sizeof(u_long) + sigsetsize);
			buf = NULL;
			rc = -EFAULT;
		}
	}
	new_syscall_exit (175, buf);
	
	return rc;

}

static asmlinkage long
replay_rt_sigprocmask (int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
	char* retparams = NULL;
	size_t size;
	struct replay_thread* prt = current->replay_thrd;
	long rc, retval;
	
	if (is_pin_attached()) {
		retval = sys_rt_sigprocmask (how, set, oset, sigsetsize);
		rc = prt->rp_saved_rc;
		retparams = prt->rp_saved_retparams;
		
		if (rc != retval) {
			printk("ERROR: sigprocmask expected %ld, got %ld\n", rc, retval);
			syscall_mismatch();
		}

		if (prt->rp_saved_psr) {
			if (prt->rp_saved_psr->sysnum == 175) {
				(*(int*)(prt->app_syscall_addr)) = 999;
			}
		}
	} else {
		rc = get_next_syscall (175, &retparams);
	}

	if (retparams) {
		size = *((size_t *) retparams);
		if (size != sigsetsize) printk ("Pid %d has diff sigsetsize %d than %d\n", current->pid, sigsetsize, size);
		if (copy_to_user (oset, retparams+sizeof(size_t), size)) printk ("Pid %d cannot copy to user\n", current->pid);
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + size);
	}
	return rc;
}

asmlinkage long
shim_rt_sigprocmask (int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize) SHIM_CALL(rt_sigprocmask, 175, how, set, oset, sigsetsize);

static asmlinkage long 
record_rt_sigpending (sigset_t __user *set, size_t sigsetsize)
{									
	long rc;							
	char *pretval = NULL;						
									
	new_syscall_enter (176);				
	rc = sys_rt_sigpending (set, sigsetsize);
	new_syscall_done (176, rc);
	if (rc >= 0 && set) {						
		pretval = ARGSKMALLOC (sizeof(long) + sigsetsize, GFP_KERNEL);	
		if (pretval == NULL) {					
			printk ("record_rt_sigpending: can't allocate buffer\n"); 
			return -ENOMEM;					
		}							
		*((u_long *) pretval) = sigsetsize;
		if (copy_from_user (pretval+sizeof(u_long), set, sigsetsize)) { 
			printk ("record_rt_sigpending: can't copy to buffer\n"); 
			ARGSKFREE(pretval, sizeof(u_long) + sigsetsize);		
			rc = -EFAULT;					
		}							
	}																	
	new_syscall_exit (176, pretval);				

	return rc;							
}

static asmlinkage long 
replay_rt_sigpending (sigset_t __user *set, size_t sigsetsize)
{									
	u_long len;
	char *retparams = NULL;						
	long rc = get_next_syscall (176, &retparams);		

	if (retparams) {						
		len = *((u_long *) retparams);
		if (copy_to_user (set, retparams + sizeof(u_long), len)) printk ("replay_rt_sigpending: pid %d cannot copy to user\n", current->pid); 
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + len);
	}								
									
	return rc;							
}									

asmlinkage long shim_rt_sigpending (sigset_t __user *set, size_t sigsetsize) SHIM_CALL(rt_sigpending, 176, set, sigsetsize);

/* Note that sigsetsize must by a constant size in the kernel code or rt_sigtimedwait will fail, so special handling not needed */
RET1_SHIM4(rt_sigtimedwait, 177, siginfo_t, uinfo, const sigset_t __user *, uthese, siginfo_t __user *, uinfo, const struct timespec __user *, uts, size_t, sigsetsize);
SIMPLE_SHIM3(rt_sigqueueinfo, 178, int, pid, int, sig, siginfo_t __user *, uinfo);
SIMPLE_SHIM2(rt_sigsuspend, 179, sigset_t __user *, unewset, size_t, sigsetsize);
RET1_COUNT_SHIM4(pread64, 180, buf, unsigned int, fd, char __user *, buf, size_t, count, loff_t, pos);
SIMPLE_SHIM4(pwrite64, 181, unsigned int, fd, const char __user *, buf, size_t, count, loff_t, pos);
SIMPLE_SHIM3(chown16, 182, const char __user *, filename, old_uid_t, user, old_gid_t, group);

static asmlinkage long 
record_getcwd (char __user *buf, unsigned long size) 
{
	long rc;
	char *recbuf = NULL;

	new_syscall_enter (183);
	rc = sys_getcwd (buf, size);
	new_syscall_done (183, rc);
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
	new_syscall_exit (183, recbuf);

	return rc;
}

RET1_COUNT_REPLAY(getcwd, 183, buf, char __user *buf, unsigned long size);

asmlinkage long shim_getcwd (char __user *buf, unsigned long size) SHIM_CALL(getcwd, 183, buf, size);

extern int cap_validate_magic(cap_user_header_t header, unsigned *tocopy); // In kernel/capability.h

static asmlinkage long 
record_capget (cap_user_header_t header, cap_user_data_t dataptr)
{
	long rc;
	char* retvals = NULL;
	unsigned tocopy;
	u_long size;

	new_syscall_enter (184);
	cap_validate_magic(header, &tocopy);
	rc = sys_capget (header, dataptr);
	new_syscall_done (184, rc);
	if (rc >= 0) {
		size = sizeof(struct __user_cap_header_struct);
		if (dataptr) size += tocopy*sizeof(struct __user_cap_data_struct);

		retvals = ARGSKMALLOC(sizeof(u_long)+size, GFP_KERNEL);
		if (retvals == NULL) {
			printk("record_capget: can't allocate buffer\n");
			return -ENOMEM;
		}
		*((u_long *) retvals) = size;

		if (copy_from_user (retvals+sizeof(u_long), header, sizeof(struct __user_cap_header_struct))) {
			printk ("record_capget: unable to copy header from user\n");
			ARGSKFREE (retvals, sizeof(u_long) + size);
			return -EFAULT;
		}
		if (dataptr) {
			if (copy_from_user (retvals+sizeof(u_long)+sizeof(struct __user_cap_header_struct), dataptr, tocopy*sizeof(struct __user_cap_data_struct))) {
				printk ("record_capget: pid %d unable to copy dataptr from user address %p\n", current->pid, dataptr);
				ARGSKFREE (retvals, sizeof(u_long) + size);
				return -EFAULT;
			}
		}
	}
	new_syscall_exit (184, retvals);

	return rc;
}

static asmlinkage long 
replay_capget (cap_user_header_t header, cap_user_data_t dataptr)
{
	char* pretvals = NULL;
	unsigned tocopy;
	u_long size;
	long rc;

	cap_validate_magic(header, &tocopy);
	rc = get_next_syscall (184, &pretvals);
	if (pretvals) {
		size = *((u_long *) pretvals);
		if (copy_to_user (header, pretvals + sizeof(u_long), sizeof(struct __user_cap_header_struct))) {
			printk ("Pid %d replay_capget cannot copy header to user\n", current->pid);
			return syscall_mismatch();
		}
		if (dataptr) {
			if (copy_to_user (dataptr, pretvals + sizeof(u_long) + sizeof (struct __user_cap_header_struct), tocopy*sizeof(struct __user_cap_data_struct))) {
				printk ("Pid %d replay_capget cannot copy dataptr to user\n", current->pid);
				return syscall_mismatch();
			}
		}
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + size);
	}
	return rc;
}

asmlinkage long shim_capget (cap_user_header_t header, cap_user_data_t dataptr) SHIM_CALL(capget, 184, header, dataptr)

RET1_SHIM2(capset, 185, struct __user_cap_header_struct, header, cap_user_header_t, header, const cap_user_data_t, data);
/* sigaltstack should be deterministic, so do not intercept */
RET1_SHIM4(sendfile, 187, off_t, offset, int, out_fd, int, in_fd, off_t __user *, offset, size_t, count);

void 
record_vfork_handler (struct task_struct* tsk)
{
	struct record_group* prg = current->record_thrd->rp_group;
	void* slab;

	DPRINT ("In record_vfork_handler\n");
	rg_lock(prg);
	tsk->record_thrd = new_record_thread (prg, tsk->pid, NULL);
	if (tsk->record_thrd == NULL) {
		printk ("record_vfork_handler: cannot allocate record thread\n");
		rg_unlock(prg);
		return;
	}
	tsk->replay_thrd = NULL;

#ifdef CACHE_READS
	copy_record_cache_files (current->record_thrd->rp_cache_files, tsk->record_thrd->rp_cache_files);
#endif

	tsk->record_thrd->rp_next_thread = current->record_thrd->rp_next_thread;
	current->record_thrd->rp_next_thread = tsk->record_thrd;
	
	tsk->record_thrd->rp_user_log_addr = 0; // Should not write to user log before exec - otherwise violates vfork principles
#ifdef USE_EXTRA_DEBUG_LOG
	tsk->record_thrd->rp_user_extra_log_addr = 0;
#endif
	tsk->record_thrd->rp_ignore_flag_addr = current->record_thrd->rp_ignore_flag_addr;
	
	// allocate a slab for retparams
	slab = VMALLOC (argsalloc_size);
	if (slab == NULL) {
		rg_unlock(prg);
		printk ("record_vfork_handler: no memory for slab\n");
		return;
	}
	if (add_argsalloc_node(tsk->record_thrd, slab, argsalloc_size)) {
		rg_unlock(prg);
		VFREE (slab);
		printk ("Pid %d record_vfork: error adding argsalloc_node\n", current->pid);
		return;
	}

	rg_unlock(prg);
	DPRINT ("Done with record_vfork_handler\n");
}

static long
record_vfork (unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr)
{
	long rc;

	new_syscall_enter (190);

	/* On clone, we reset the user log.  On, vfork we do not do this because the parent and child share one
           address space.  This sharing will get fixed on exec. */

	rc = do_fork (clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr);		
	MPRINT ("Pid %d records vfork returning %ld\n", current->pid, rc);
	new_syscall_done (190, rc);
	new_syscall_exit (190, NULL);
	
	return rc;
}

void 
replay_vfork_handler (struct task_struct* tsk)
{
	struct replay_group* prg = current->replay_thrd->rp_group;
	struct record_thread* prt;
	struct replay_thread* prept;
	ds_list_iter_t* iter;
	long rc = current->replay_thrd->rp_saved_rc;

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
		prt = new_record_thread (prg->rg_rec_group, rc, NULL);
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
	tsk->replay_thrd = new_replay_thread(prg, prt, tsk->pid, 0, NULL);
	BUG_ON (!tsk->replay_thrd);
	
#ifdef CACHE_READS
	copy_replay_cache_files (current->replay_thrd->rp_cache_files, tsk->replay_thrd->rp_cache_files);
#endif

	// inherit the parent's app_syscall_addr
	tsk->replay_thrd->app_syscall_addr = current->replay_thrd->app_syscall_addr;
	
	MPRINT ("Pid %d, tsk->pid %d refcnt for replay thread %p now %d\n", current->pid, tsk->pid, tsk->replay_thrd,
		atomic_read(&tsk->replay_thrd->rp_refcnt));
	MPRINT ("Pid %d, tsk->pid %d refcnt for record thread pid %d now %d\n", current->pid, tsk->pid, prt->rp_record_pid,
		atomic_read(&prt->rp_refcnt));
	
	// Fix up the circular thread list
	tsk->replay_thrd->rp_next_thread = current->replay_thrd->rp_next_thread;
	current->replay_thrd->rp_next_thread = tsk->replay_thrd;
	
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
	if (is_pin_attached()) {
		rc = prt->rp_saved_rc;
		(*(int*)(prt->app_syscall_addr)) = 999;
	} else {
		rc = get_next_syscall_enter (prt, prg, 190, NULL, &psr);
		prt->rp_saved_rc = rc;
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

RET1_SHIM2(getrlimit, 191, struct rlimit, rlim, unsigned int, resource, struct rlimit __user *, rlim);

static asmlinkage long 
record_mmap_pgoff (unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
	long rc;
	struct mmap_pgoff_retvals* recbuf = NULL;
	
	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (192);
	rc = sys_mmap_pgoff (addr, len, prot, flags, fd, pgoff);
	new_syscall_done (192, rc);

	/* Good thing we have the extra synchronization and rg_lock
	 * held, since we need to store some return values of mmap
	 * with the argument list: the mapped file, and the memory
	 * region allocated (different from that requested).
	 */
	if ((rc > 0 || rc < -1024) && ((long) fd) >= 0 && !is_record_cache_file(current->record_thrd->rp_cache_files, fd)) {
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

	DPRINT ("Pid %d records mmap_pgoff with addr %lx len %lx prot %lx flags %lx fd %ld ret %lx\n", current->pid, addr, len, prot, flags, fd, rc);

	/* Save the regions to pre-allocate later for replay,
	 * Needed for Pin support	
	 */
	if (current->record_thrd->rp_group->rg_save_mmap_flag) {
		if (rc != -1) {
			MPRINT("Pid %d record mmap_pgoff reserve memory addr %lx len %lx\n", current->pid, addr, len);
			reserve_memory(rc, len);
		}
	}

	new_syscall_exit (192, recbuf);
	rg_unlock(current->record_thrd->rp_group);

	return rc;
}

static asmlinkage long 
replay_mmap_pgoff (unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
	u_long retval, rc, is_cache_file;
	int given_fd = fd;
	struct mmap_pgoff_retvals* recbuf = NULL;
	struct replay_thread* prt = current->replay_thrd;
	struct syscall_result* psr;

	if (is_pin_attached()) {
		rc = prt->rp_saved_rc;
		recbuf = (struct mmap_pgoff_retvals *) prt->rp_saved_retparams;
		psr = prt->rp_saved_psr;
		(*(int*)(prt->app_syscall_addr)) = 999;
	} else {
		rc = get_next_syscall (192, (char **) &recbuf);
	}

	if (recbuf) {
		rg_lock(prt->rp_record_thread->rp_group);
		given_fd = open_mmap_cache_file (recbuf->dev, recbuf->ino, recbuf->mtime, (prot&PROT_WRITE) && (flags&MAP_SHARED));
		rg_unlock(prt->rp_record_thread->rp_group);
		DPRINT ("replay_mmap_pgoff opens cache file %x %lx %lx.%lx, fd = %d\n", recbuf->dev, recbuf->ino, recbuf->mtime.tv_sec, recbuf->mtime.tv_nsec, given_fd);
		if (given_fd < 0) {
			printk ("replay_mmap_pgoff: can't open cache file, rc=%d\n", given_fd);
			syscall_mismatch();
		}
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct mmap_pgoff_retvals));
	} else if (is_replay_cache_file (prt->rp_cache_files, fd, &given_fd)) {
		DPRINT ("replay_mmap_pgoff uses open cache file %d for %lu\n", given_fd, fd);
		is_cache_file = 1;
	} else if (given_fd >= 0) {
		printk ("replay_mmap_pgoff: fd is %d but there are no return values recorded\n", given_fd);
	}

	retval = sys_mmap_pgoff (rc, len, prot, (flags | MAP_FIXED), given_fd, pgoff);
	DPRINT ("Pid %d replays mmap_pgoff with address %lx len %lx input address %lx fd %d flags %lx prot %lx pgoff %lx returning %lx, flags & MAP_FIXED %lu\n", current->pid, addr, len, rc, given_fd, flags, prot, pgoff, retval, flags & MAP_FIXED);
	
	if (rc != retval) {
		printk ("Replay mmap_pgoff returns different value %lx than %lx\n", retval, rc);
		syscall_mismatch ();
	}

	if (recbuf && given_fd > 0 && !is_cache_file) sys_close(given_fd);

	// Save the regions for preallocation for replay+pin
	if (prt->rp_record_thread->rp_group->rg_save_mmap_flag) {
		if (rc != -1) {
			MPRINT ("Pid %d replay mmap_pgoff reserve memory addr %lx len %lx\n", current->pid, rc, len);
			reserve_memory(rc, len);
		}
	}

	return rc;
}

asmlinkage long shim_mmap_pgoff (unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff) SHIM_CALL(mmap_pgoff, 192, addr, len, prot, flags, fd, pgoff);

SIMPLE_SHIM2(truncate64, 193, const char __user *, path, loff_t, length);
SIMPLE_SHIM2(ftruncate64, 194, unsigned int, fd, loff_t, length);

static asmlinkage long
record_stat64(char __user *filename, struct stat64 __user *statbuf) {
	long rc;
	struct stat64 *pretval = NULL;

	new_syscall_enter (195);
	rc = sys_stat64 (filename, statbuf);
	new_syscall_done (195, rc);
	if (rc >= 0 && statbuf) {

#ifdef REPLAY_COMPRESS_READS
		//printk("Stat64 on %s\n", filename);
		if (is_recorded_filename(filename)) {
			struct replay_recorded_file_meta *meta;
			meta = replay_get_filename_meta(filename);

			statbuf->st_size = meta_get_size(meta);
			//printk("%s is recorded file, adjustin size to %lld\n", filename, (loff_t)statbuf->st_size);
		}
#endif

		pretval = ARGSKMALLOC (sizeof(struct stat64), GFP_KERNEL);

		if (pretval == NULL) {
			printk ("record_stat64: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, statbuf, sizeof (struct stat64))) {
			printk ("record_stat64: can't copy to buffer\n");
			ARGSKFREE(pretval, sizeof(struct stat64));
			pretval = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (195, pretval);
	return rc;
}

RET1_REPLAY (stat64, 195, struct stat64, statbuf, char __user *filename, struct stat64 __user *statbuf);

asmlinkage long shim_stat64(char __user *filename, struct stat64 __user *statbuf) SHIM_CALL(stat64, 195, filename, statbuf);

//RET1_SHIM2(stat64, 195, struct stat64, statbuf, char __user *, filename, struct stat64 __user *, statbuf);
//RET1_SHIM2(lstat64, 196, struct stat64, statbuf, char __user *, filename, struct stat64 __user *, statbuf);
//RET1_SHIM2(fstat64, 197, struct stat64, statbuf, unsigned long, fd, struct stat64 __user *, statbuf);

static asmlinkage long
record_lstat64(char __user *filename, struct stat64 __user *statbuf) {
	long rc;
	struct stat64 *pretval = NULL;

	new_syscall_enter (196);
	rc = sys_lstat64 (filename, statbuf);
	new_syscall_done (196, rc);
	if (rc >= 0 && statbuf) {

#ifdef REPLAY_COMPRESS_READS
		//printk("Stat64 on %s\n", filename);
		if (is_recorded_filename(filename)) {
			struct replay_recorded_file_meta *meta;
			meta = replay_get_filename_meta(filename);

			statbuf->st_size = meta_get_size(meta);
			printk("%s is recorded file, adjustin size to %lld\n", filename, (loff_t)statbuf->st_size);
		}
#endif

		pretval = ARGSKMALLOC (sizeof(struct stat64), GFP_KERNEL);

		if (pretval == NULL) {
			printk ("record_stat64: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, statbuf, sizeof (struct stat64))) {
			printk ("record_stat64: can't copy to buffer\n");
			ARGSKFREE(pretval, sizeof(struct stat64));
			pretval = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (196, pretval);
	return rc;
}

RET1_REPLAY (lstat64, 196, struct stat64, statbuf, char __user *filename, struct stat64 __user *statbuf);

asmlinkage long shim_lstat64(char __user *filename, struct stat64 __user *statbuf) SHIM_CALL(lstat64, 196, filename, statbuf);


static asmlinkage long
record_fstat64(int fd, struct stat64 __user *statbuf) {
	long rc;
	struct stat64 *pretval = NULL;

	new_syscall_enter (197);
	rc = sys_fstat64 (fd, statbuf);
	new_syscall_done (197, rc);
	if (rc >= 0 && statbuf) {

#ifdef REPLAY_COMPRESS_READS
		//printk("fstat64 on %d\n", fd);
		if (is_recorded_file(fd)) {
			struct replay_recorded_file_meta *meta;

			//printk("stating recorded file, getting meta for %d\n", fd);
			meta = replay_get_file_meta(fd);

			statbuf->st_size = meta_get_size(meta);
			//printk("%d is recorded file, adjustin size to %lld\n", fd, (loff_t)statbuf->st_size);
		}
#endif

		pretval = ARGSKMALLOC (sizeof(struct stat64), GFP_KERNEL);

		if (pretval == NULL) {
			printk ("record_fstat64: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, statbuf, sizeof (struct stat64))) {
			printk ("record_fstat64: can't copy to buffer\n");
			ARGSKFREE(pretval, sizeof(struct stat64));
			pretval = NULL;
			rc = -EFAULT;
		}
	}

	new_syscall_exit (197, pretval);
	return rc;
}

RET1_REPLAY (fstat64, 197, struct stat64, statbuf, int fd, struct stat64 __user *statbuf);

asmlinkage long shim_fstat64(int fd, struct stat64 __user *statbuf) SHIM_CALL(fstat64, 197, fd, statbuf);

SIMPLE_SHIM3(lchown, 198, const char __user *, filename, uid_t, user, gid_t, group);
SIMPLE_SHIM0(getuid, 199);
SIMPLE_SHIM0(getgid, 200);
SIMPLE_SHIM0(geteuid, 201);
SIMPLE_SHIM0(getegid, 202);
SIMPLE_SHIM2(setreuid, 203, uid_t, ruid, uid_t, euid);
SIMPLE_SHIM2(setregid, 204, gid_t, rgid, gid_t, egid);

static asmlinkage long 
record_getgroups (int gidsetsize, gid_t __user *grouplist)
{
	long rc;
	gid_t* pretval = NULL;

	new_syscall_enter (205);
	rc = sys_getgroups (gidsetsize, grouplist);
	new_syscall_done (205, rc);
	if (gidsetsize > 0 && rc > 0) {
		pretval = ARGSKMALLOC(sizeof(gid_t)*rc, GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_getgroups: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, grouplist, sizeof(gid_t)*rc)) {
			printk ("record_getgroups: can't copy from user %p into %p\n", grouplist, pretval);
			ARGSKFREE (pretval, sizeof(gid_t)*rc);
			return -EFAULT;
		}
	}
	new_syscall_exit (205, pretval);

	return rc;
}

static asmlinkage long 
replay_getgroups (int gidsetsize, gid_t __user *grouplist)
{
	gid_t* retparams = NULL;
	long rc = get_next_syscall (205, (char **) &retparams);
	if (retparams) {
		if (copy_to_user (grouplist, retparams, sizeof(gid_t)*rc)) printk ("Pid %d cannot copy groups to user\n", current->pid);
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(gid_t)*rc);
	}
	return rc;
}

asmlinkage long shim_getgroups (int gidsetsize, gid_t __user *grouplist) SHIM_CALL(getgroups, 205, gidsetsize, grouplist);

SIMPLE_SHIM2(setgroups, 206, int, gidsetsize, gid_t __user *, grouplist);
SIMPLE_SHIM3(fchown, 207, unsigned int, fd, uid_t, user, gid_t, group);
SIMPLE_SHIM3(setresuid, 208, uid_t, ruid, uid_t, euid, uid_t, suid);

static asmlinkage long
record_getresuid (uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) 
{
	long rc;
	uid_t* pretval = NULL;

	new_syscall_enter (209);
	rc = sys_getresuid (ruid, euid, suid);
	new_syscall_done (209, rc);
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
	new_syscall_exit (209, pretval);

	return rc;
}

static asmlinkage long
replay_getresuid (uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) 
{
	uid_t* retparams = NULL;
	long rc = get_next_syscall (209, (char **) &retparams);
	if (rc >= 0) {
		if (retparams) {
			if (copy_to_user (ruid, retparams, sizeof(uid_t)) ||
			    copy_to_user (euid, retparams+1, sizeof(uid_t)) ||
			    copy_to_user (suid, retparams+2, sizeof(uid_t))) {
				printk ("replay_getresuid: pid %d cannot copy uids to user\n", current->pid);
			}
			argsconsume(current->replay_thrd->rp_record_thread, 3*sizeof(uid_t));
		} else {
			printk ("getresuid has return values but non-negative rc?\n");
		}
	}
	return rc;
}

asmlinkage long shim_getresuid (uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) SHIM_CALL(getresuid, 209, ruid, euid, suid);

SIMPLE_SHIM3(setresgid, 210, gid_t, rgid, gid_t, egid, gid_t, sgid);

static asmlinkage long
record_getresgid (gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) 
{
	long rc;
	gid_t* pretval = NULL;

	new_syscall_enter (211);
	rc = sys_getresgid (rgid, egid, sgid);
	new_syscall_done (211, rc);
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
	new_syscall_exit (211, pretval);

	return rc;
}

static asmlinkage long
replay_getresgid (gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) 
{
	gid_t* retparams = NULL;
	long rc = get_next_syscall (211, (char **) &retparams);
	if (rc >= 0) {
		if (retparams) {
			if (copy_to_user (rgid, retparams, sizeof(gid_t)) ||
			    copy_to_user (egid, retparams+1, sizeof(gid_t)) ||
			    copy_to_user (sgid, retparams+2, sizeof(gid_t))) {
				printk ("replay_getresgid: pid %d cannot copy gids to user\n", current->pid);
			}
			argsconsume(current->replay_thrd->rp_record_thread, 3*sizeof(gid_t));
		} else {
			printk ("getresgid has return values but non-negative rc?\n");
		}
	}
	return rc;
}

asmlinkage long shim_getresgid (gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) SHIM_CALL(getresgid, 211, rgid, egid, sgid);

SIMPLE_SHIM3(chown, 212, const char __user *, filename, uid_t, user, gid_t, group);
SIMPLE_SHIM1(setuid, 213, uid_t, uid);
SIMPLE_SHIM1(setgid, 214, gid_t, gid);
SIMPLE_SHIM1(setfsuid, 215, uid_t, uid);
SIMPLE_SHIM1(setfsgid, 216, gid_t, gid);
SIMPLE_SHIM2(pivot_root, 217, const char __user *, new_root, const char __user *, put_old);

static asmlinkage long 
record_mincore (unsigned long start, size_t len, unsigned char __user * vec) 
{
	char* pretvals = NULL;
	unsigned long pages;
	long rc;

	new_syscall_enter (218);
	rc = sys_mincore (start, len, vec);
	new_syscall_done (218, rc);
	if (rc >= 0) {
		pages = len >> PAGE_SHIFT;
		pages += (len & ~PAGE_MASK) != 0;
	  
		pretvals = ARGSKMALLOC(sizeof(u_long) + pages, GFP_KERNEL);
		if (!pretvals) {
			printk ("record_mincore: can't allocate return buffer\n");
			return -ENOMEM;
		}
		*((u_long *) pretvals) = pages;
		if (copy_from_user(pretvals + sizeof(u_long), vec, pages)) {
			printk("record_mincore: faulted on readback\n");
			ARGSKFREE(pretvals, sizeof(u_long) + pages);
			return -EFAULT;
		}
	}
	new_syscall_exit (218, pretvals);

	return rc;
}

static asmlinkage long 
replay_mincore (unsigned long start, size_t len, unsigned char __user * vec) 
{
	char* retparams = NULL;
	long rc = get_next_syscall (218, &retparams);
	if (retparams) {
		u_long pages = *((u_long *) retparams);
		if (copy_to_user(vec, retparams + sizeof(u_long), pages)) return syscall_mismatch();
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + pages);
	}
	return rc;
}

asmlinkage long shim_mincore (unsigned long start, size_t len, unsigned char __user * vec) SHIM_CALL(mincore, 218, start, len, vec);

static asmlinkage long 
record_madvise (unsigned long start, size_t len_in, int behavior)
{
	long rc;

	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (219);
	rc = sys_madvise (start, len_in, behavior);
	new_syscall_done (219, rc);
	new_syscall_exit (219, NULL);
	rg_unlock(current->record_thrd->rp_group);

	return rc;
}

static asmlinkage long 
replay_madvise (unsigned long start, size_t len_in, int behavior)
{
	long retval, rc = get_next_syscall (219, NULL);
	retval = sys_madvise (start, len_in, behavior);

	if (rc != retval) {
		printk ("Replay madvise returns different val %lu than %lu\n", retval, rc);
		syscall_mismatch();
	}

	return rc;
}

asmlinkage long shim_madvise (unsigned long start, size_t len_in, int behavior) SHIM_CALL(madvise, 219, start, len_in, behavior);

RET1_COUNT_SHIM3(getdents64, 220, dirent, unsigned int, fd, struct linux_dirent64 __user *, dirent, unsigned int, count);

static asmlinkage long 
record_fcntl64 (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	char* recbuf = NULL;
	long rc;

	new_syscall_enter (221);
	rc = sys_fcntl64 (fd, cmd, arg);
	new_syscall_done (221, rc);
	if (rc >= 0) {
		if (cmd == F_GETLK) {
			recbuf = ARGSKMALLOC(sizeof(u_long) + sizeof(struct flock64), GFP_KERNEL);
			if (!recbuf) {
				printk ("record_fcntl64: can't allocate return buffer\n");
				return -ENOMEM;
			}
			*((u_long *) recbuf) = sizeof(struct flock64);
			if (copy_from_user(recbuf + sizeof(u_long), (struct flock64 __user *)arg, sizeof(struct flock64))) {
				printk("record_fcntl64: faulted on readback\n");
				KFREE(recbuf);
				return -EFAULT;
			}
		} else if (cmd == F_GETOWN_EX) {
			recbuf = ARGSKMALLOC(sizeof(u_long) + sizeof(struct f_owner_ex), GFP_KERNEL);
			if (!recbuf) {
				printk ("record_fcntl64: can't allocate return buffer\n");
				return -ENOMEM;
			}
			*((u_long *) recbuf) = sizeof(struct f_owner_ex);
			if (copy_from_user(recbuf + sizeof(u_long), (struct f_owner_ex __user *)arg, sizeof(struct f_owner_ex))) {
				printk("record_fcntl64: faulted on readback\n");
				KFREE(recbuf);
				return -EFAULT;
			}
		}
	}
	new_syscall_exit (221, recbuf);

	return rc;
}

static asmlinkage long 
replay_fcntl64 (unsigned int fd, unsigned int cmd, unsigned long arg)
{
	char* retparams = NULL;
	long rc = get_next_syscall (221, &retparams);
	if (retparams) {
		u_long bytes = *((u_long *) retparams);
		if (copy_to_user((void __user *)arg, retparams + sizeof(u_long), bytes)) return syscall_mismatch();
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + bytes);
	}
	return rc;
}

asmlinkage long shim_fcntl64 (unsigned int fd, unsigned int cmd, unsigned long arg) SHIM_CALL(fcntl64, 221, fd, cmd, arg);

SIMPLE_SHIM0(gettid, 224);
SIMPLE_SHIM3(readahead, 225, int, fd, loff_t, offset, size_t, count);
SIMPLE_SHIM5(setxattr, 226, const char __user *, path, const char __user *, name, const void __user *, value, size_t, size, int, flags);
SIMPLE_SHIM5(lsetxattr, 227, const char __user *, path, const char __user *, name, const void __user *, value, size_t, size, int, flags);
SIMPLE_SHIM5(fsetxattr, 228, int, fd, const char __user *, name, const void __user *, value, size_t, size, int, flags);
RET1_COUNT_SHIM4(getxattr, 229, value, const char __user *, path, const char __user *, name, void __user *, value, size_t, size);
RET1_COUNT_SHIM4(lgetxattr, 230, value, const char __user *, path, const char __user *, name, void __user *, value, size_t, size);
RET1_COUNT_SHIM4(fgetxattr, 231, value, int, fd, const char __user *, name, void __user *, value, size_t, size);
RET1_COUNT_SHIM3(listxattr, 232, list, const char __user *, path, char __user *, list, size_t, size);
RET1_COUNT_SHIM3(llistxattr, 233, list, const char __user *, path, char __user *, list, size_t, size);
RET1_COUNT_SHIM3(flistxattr, 234, list, int, fd, char __user *, list, size_t, size);
SIMPLE_SHIM2(removexattr, 235, const char __user *, path, const char __user *, name);
SIMPLE_SHIM2(lremovexattr, 236, const char __user *, path, const char __user *, name);
SIMPLE_SHIM2(fremovexattr, 237, int, fd, const char __user *, name);
SIMPLE_SHIM2(tkill, 238, int, pid, int, sig);

RET1_SHIM4(sendfile64, 239, loff_t, offset, int, out_fd, int, in_fd, loff_t __user *, offset, size_t, count);

static asmlinkage long 
record_futex (u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
	struct pt_regs* pregs;
	long rc;

	new_syscall_enter (240);
	rc = sys_futex (uaddr, op, val, utime, uaddr2, val3);
	new_syscall_done (240, rc);
	pregs = get_pt_regs (NULL);
	// Really should not get here because it means we are missing synchronizations at user level
	printk ("Pid %d in replay futex uaddr=%p, op=%d, val=%d, ip=%lx, sp=%lx, bp=%lx\n", current->pid, uaddr, op, val, pregs->ip, pregs->sp, pregs->bp);
	new_syscall_exit (240, NULL);

	return rc;
}

static asmlinkage long 
replay_futex (u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
	struct pt_regs* pregs;
	long rc = get_next_syscall (240, NULL);
	pregs = get_pt_regs (NULL);
	// Really should not get here because it means we are missing synchronizations at user level
	printk ("Pid %d in replay futex uaddr=%p, op=%d, val=%d, ip=%lx, sp=%lx, bp=%lx\n", current->pid, uaddr, op, val, pregs->ip, pregs->sp, pregs->bp);
	return rc;
}

asmlinkage long shim_futex (u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3) SHIM_CALL (futex, 240, uaddr, op, val, utime, uaddr2, val3);

SIMPLE_SHIM3(sched_setaffinity, 241, pid_t, pid, unsigned int, len, unsigned long __user *, user_mask_ptr);

static asmlinkage long 
record_sched_getaffinity (pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	long rc;
	char* pretval = NULL;

	new_syscall_enter (242);
	rc = sys_sched_getaffinity (pid, len, user_mask_ptr);
	new_syscall_done (242, rc);
	if (rc >= 0) {
		pretval = ARGSKMALLOC(sizeof(u_long) + len, GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_sched_getaffinity: can't allocate buffer\n");
			return -ENOMEM;
		}
		*((u_long *) pretval) = len;
		if (copy_from_user (pretval+sizeof(u_long), user_mask_ptr, len)) { 
			ARGSKFREE (pretval, sizeof(u_long) + len);
			rc = -EFAULT;
		}
	}
	new_syscall_exit (242, pretval);

	return rc;
}

static asmlinkage long 
replay_sched_getaffinity (pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	char* retparams = NULL;
	long rc = get_next_syscall (242, &retparams);
	if (retparams) {
		u_long bytes = *((u_long *) retparams);
		if (copy_to_user(user_mask_ptr, retparams + sizeof(u_long), bytes)) return syscall_mismatch();
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + bytes);
	}
	return rc;
}

asmlinkage long shim_sched_getaffinity (pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr) SHIM_CALL(sched_getaffinity, 242, pid, len, user_mask_ptr)

// Pin virtualizes this system call but we need to replay the prior behavior.  So, we bypass Pin by using a different syscall number
asmlinkage long sys_fake_getaffinity (pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
	return replay_sched_getaffinity (pid, len, user_mask_ptr);
}
/* set_thread_area appears to be thread-specific and deterministic, so do not record/replay  */
/* get_thread_area appears to be thread-specific and deterministic, so do not record/replay  */
RET1_SHIM2(io_setup, 245, aio_context_t, ctxp, unsigned, nr_events, aio_context_t __user *, ctxp);
SIMPLE_SHIM1(io_destroy, 246, aio_context_t, ctx);

static asmlinkage long 
record_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout)
{
	long rc;
	char* pretvals = NULL;

	new_syscall_enter (247);
	rc = sys_io_getevents (ctx_id, min_nr, nr, events, timeout);
	new_syscall_done (247, rc);	
	if (rc > 0) {
		pretvals = ARGSKMALLOC (rc * sizeof(struct io_event), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_io_getevents: can't allocate buffer with %ld record\n", rc);
			return -ENOMEM;
		}
		if (copy_from_user (pretvals, events, rc * sizeof(struct io_event))) {
			printk("record_io_getevents: can't copy buffer with %ld record\n", rc);
			ARGSKFREE (pretvals, rc * sizeof(struct io_event));
			return -EFAULT;
		}
	}
	new_syscall_exit (247, pretvals);

	return rc;
}

static asmlinkage long 
replay_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout)
{
	long rc;
	char* retparams = NULL;
	rc = get_next_syscall (247, &retparams);
	if (rc > 0) {
		if (copy_to_user (events, retparams, rc * sizeof(struct io_event))) {
			printk ("Pid %d cannot copy io_getevents retvals to user\n", current->pid);
		}
		argsconsume(current->replay_thrd->rp_record_thread, rc * sizeof(struct io_event));
	}

	return rc;
}

asmlinkage long shim_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout) SHIM_CALL(io_getevents, 247, ctx_id, min_nr, nr, events, timeout);

SIMPLE_SHIM3(io_submit, 248, aio_context_t, ctx_id, long, nr, struct iocb __user * __user *, iocbpp);
RET1_SHIM3(io_cancel, 249, struct io_event, result, aio_context_t, ctx_id, struct iocb __user *, iocb, struct io_event __user *, result);
SIMPLE_SHIM4(fadvise64, 250, int, fd, loff_t, offset, size_t, len, int, advice);

static asmlinkage void 
record_exit_group (int error_code)
{
	new_syscall_enter (252);
	new_syscall_done (252, 0);
	new_syscall_exit (252, NULL);
	MPRINT ("Pid %d recording exit group with code %d\n", current->pid, error_code);
	sys_exit_group (error_code);
}

static asmlinkage void
replay_exit_group (int error_code)
{
	struct replay_group* prg;
	struct task_struct* t;

	get_next_syscall (252, NULL);
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
}

asmlinkage void
shim_exit_group (int error_code) 
{ 
	if (current->record_thrd) record_exit_group (error_code);
	if (current->replay_thrd && test_app_syscall(252)) replay_exit_group(error_code);
	sys_exit_group (error_code);					
}

RET1_COUNT_SHIM3(lookup_dcookie, 253, buf, u64, cookie64, char __user *, buf, size_t, len);
SIMPLE_SHIM1(epoll_create, 254, int, size);
SIMPLE_SHIM4(epoll_ctl, 255, int, epfd, int, op, int, fd, struct epoll_event __user *, event);

static asmlinkage long 
record_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout)
{
	long rc;
	char* pretvals = NULL;

	new_syscall_enter (256);
	rc = sys_epoll_wait (epfd, events, maxevents, timeout);
	new_syscall_done (256, rc);
	if (rc > 0) {
		pretvals = ARGSKMALLOC (rc * sizeof(struct epoll_event), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_epoll_wait: can't allocate buffer with %ld record\n", rc);
			return -ENOMEM;
		}
		if (copy_from_user (pretvals, events, rc * sizeof(struct epoll_event))) {
			printk("record_epoll_wait: can't copy buffer with %ld record\n", rc);
			ARGSKFREE (pretvals, rc * sizeof(struct epoll_event));
			return -EFAULT;
		}
	}
	new_syscall_exit (256, pretvals);

	return rc;
}

static asmlinkage long 
replay_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout)
{
	long rc;
	char* retparams = NULL;
	rc = get_next_syscall (256, &retparams);
	if (rc > 0) {
		if (copy_to_user (events, retparams, rc * sizeof(struct epoll_event))) {
			printk ("Pid %d cannot copy epoll_wait retvals to user\n", current->pid);
		}
		argsconsume(current->replay_thrd->rp_record_thread, rc * sizeof(struct epoll_event));
	}

	return rc;
}

asmlinkage long shim_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout) SHIM_CALL (epoll_wait, 256, epfd, events, maxevents, timeout);

static asmlinkage unsigned long 
record_remap_file_pages (unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)
{
	unsigned long rc;

	rg_lock(current->record_thrd->rp_group);
	new_syscall_enter (257);
	rc = sys_remap_file_pages (start, size, prot, pgoff, flags);
	new_syscall_done (257, rc);
	new_syscall_exit (257, NULL);
	rg_unlock(current->record_thrd->rp_group);
	
	return rc;
}

static asmlinkage unsigned long 
replay_remap_file_pages (unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)
{
	u_long retval, rc = get_next_syscall (257, NULL);
	retval = sys_remap_file_pages (start, size, prot, pgoff, flags);
	if (rc != retval) {
		printk ("replay_remap_file_pages for pid %d returns different value %lu than %lu\n", current->pid, retval, rc);
		return syscall_mismatch();
	}
	return rc;
}

asmlinkage long shim_remap_file_pages (unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags) SHIM_CALL(remap_file_pages, 257, start, size, prot, pgoff, flags);

SIMPLE_RECORD1(set_tid_address, 258, int __user*, tidptr);

static asmlinkage long 
replay_set_tid_address (int __user* tidptr)
{
	sys_set_tid_address(tidptr);
	return get_next_syscall (258, NULL);
}

asmlinkage long shim_set_tid_address (int __user* tidptr) SHIM_CALL(set_tid_address, 258, tidptr);

RET1_SHIM3(timer_create, 259, timer_t, created_timer_id, const clockid_t, which_clock, struct sigevent __user *, timer_event_spec, timer_t __user *, created_timer_id);
RET1_SHIM4(timer_settime, 260, struct itimerspec, old_setting, timer_t, timer_id, int, flags, const struct itimerspec __user *, new_setting, struct itimerspec __user *, old_setting);
RET1_SHIM2(timer_gettime, 261, struct itimerspec, setting, timer_t, timer_id, struct itimerspec __user *, setting);
SIMPLE_SHIM1(timer_getoverrun, 262, timer_t, timer_id);
SIMPLE_SHIM1(timer_delete, 263, timer_t, timer_id);
SIMPLE_SHIM2(clock_settime, 264, const clockid_t, which_clock, const struct timespec __user *, tp);
RET1_SHIM2(clock_gettime, 265, struct timespec, tp, const clockid_t, which_clock, struct timespec __user *, tp);
RET1_SHIM2(clock_getres, 266, struct timespec, tp, const clockid_t, which_clock, struct timespec __user *, tp);
RET1_SHIM4(clock_nanosleep, 267, struct timespec, rmtp, const clockid_t, which_clock, int, flags, const struct timespec __user *, rqtp, struct timespec __user *, rmtp);
RET1_SHIM3(statfs64, 268, struct statfs64, buf, const char __user *, path, size_t, sz, struct statfs64 __user *, buf);
RET1_SHIM3(fstatfs64, 269, struct statfs64, buf, unsigned int, fd, size_t, sz, struct statfs64 __user *, buf);
SIMPLE_SHIM3(tgkill, 270, int, tgid, int, pid, int, sig);
SIMPLE_SHIM2(utimes, 271, char __user *, filename, struct timeval __user *, utimes);
SIMPLE_SHIM4(fadvise64_64, 272, int, fd, loff_t, offset, loff_t, len, int, advice);
SIMPLE_SHIM6(mbind, 274, unsigned long, start, unsigned long, len, unsigned long, mode, unsigned long __user *, nmask, unsigned long, maxnode, unsigned, flags);

static asmlinkage long 
record_get_mempolicy (int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags) 
{
	char* pretvals = NULL;
	long rc;

	new_syscall_enter (275);
	rc = sys_get_mempolicy (policy, nmask, maxnode, addr, flags);
	new_syscall_done (275, rc);
	if (rc >= 0) {
		unsigned long copy = ALIGN(maxnode-1, 64) / 8;
		pretvals = ARGSKMALLOC(sizeof(u_long) + sizeof(int) + copy, GFP_KERNEL);
		if (!pretvals) {
			printk ("record_get_mempolicy: can't allocate return buffer\n");
			return -ENOMEM;
		}
		*((u_long *) pretvals) = sizeof(int) + copy;
		if (policy) {
			int kpolicy;
			if (get_user (kpolicy, policy) == 0) *((int *) (pretvals + sizeof(u_long))) = kpolicy;
		}
		if (copy_from_user(pretvals + sizeof(u_long) + sizeof(int), nmask, copy)) {
			printk("record_get_mempolicy: faulted on readback\n");
			ARGSKFREE(pretvals, sizeof(u_long) + sizeof(int) + copy);
			return -EFAULT;
		}
	}
	new_syscall_exit (275, pretvals);

	return rc;
}

static asmlinkage long 
replay_get_mempolicy (int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags) 
{
	char* retparams = NULL;
	long rc = get_next_syscall (275, &retparams);
	if (retparams) {
		u_long bytes = *((u_long *) retparams);
		if (policy) put_user (*((int *) (retparams + sizeof(u_long))), policy);
		if (copy_to_user(nmask, retparams + sizeof(u_long) + sizeof(int), bytes - sizeof(int))) return syscall_mismatch();
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + bytes);
	}
	return rc;
}

asmlinkage long shim_get_mempolicy (int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags) SHIM_CALL(get_mempolicy, 275, policy, nmask, maxnode, addr, flags);

SIMPLE_SHIM3(set_mempolicy, 276, int, mode, unsigned long __user *, nmask, unsigned long, maxnode);
SIMPLE_SHIM4(mq_open, 277, const char __user *, u_name, int, oflag, mode_t, mode, struct mq_attr __user *, u_attr);
SIMPLE_SHIM1(mq_unlink, 278, const char __user *, u_name);
SIMPLE_SHIM5(mq_timedsend, 279, mqd_t, mqdes, const char __user *, u_msg_ptr, size_t, msg_len, unsigned int, msg_prio, const struct timespec __user *, u_abs_timeout);
RET1_COUNT_SHIM5(mq_timedreceive, 280, u_msg_ptr, mqd_t, mqdes, char __user *, u_msg_ptr, size_t, msg_len, unsigned int __user *, u_msg_prio, const struct timespec __user *, u_abs_timeout);
SIMPLE_SHIM2(mq_notify, 281, mqd_t, mqdes, const struct sigevent __user *, u_notification);
RET1_SHIM3(mq_getsetattr, 282, struct mq_attr, u_omqstat, mqd_t, mqdes, const struct mq_attr __user *, u_mqstat, struct mq_attr __user *, u_omqstat);
SIMPLE_SHIM4(kexec_load, 283, unsigned long, entry, unsigned long, nr_segments, struct kexec_segment __user *, segments, unsigned long, flags);

struct waitid_retvals {
	struct siginfo info;
	struct rusage  ru;
};

static asmlinkage long 
record_waitid (int which, pid_t upid, struct siginfo __user *infop, int options, struct rusage __user *ru)
{
	long rc;
	struct waitid_retvals* retvals = NULL;

	new_syscall_enter (284);
	rc = sys_waitid (which, upid, infop, options, ru);
	new_syscall_done (284, rc);
	if (rc >= 0) {
		retvals = ARGSKMALLOC(sizeof(struct waitid_retvals), GFP_KERNEL);
		if (retvals == NULL) {
			printk("record_waitid: can't allocate buffer\n");
			return -ENOMEM;
		}

		if (infop) {
			if (copy_from_user (&retvals->info, infop, sizeof(struct siginfo))) {
				printk ("record_waitid: unable to copy siginfo from user\n");
				ARGSKFREE (retvals, sizeof(struct waitid_retvals));
				return -EFAULT;
			}
		}
		if (ru) {
			if (copy_from_user (&retvals->ru, ru, sizeof(struct rusage))) {
				printk ("record_waitid: unable to copy rusage from user\n");
				ARGSKFREE (retvals, sizeof(struct waitid_retvals));
				return -EFAULT;
			}
		}
	}
	new_syscall_exit (284, retvals);

	return rc;
}

static asmlinkage long 
replay_waitid (int which, pid_t upid, struct siginfo __user *infop, int options, struct rusage __user *ru)
{
	struct waitid_retvals* pretvals;
	long rc = get_next_syscall (284, (char **) &pretvals);
	if (rc >= 0) {
		if (infop) {
			if (copy_to_user (infop, &pretvals->info, sizeof(struct siginfo))) {
				printk ("Pid %d replay_waitid cannot copy status to user\n", current->pid);
				return syscall_mismatch();
			}
		}
		if (ru) {
			if (copy_to_user (ru, &pretvals->ru, sizeof(struct rusage))) {
				printk ("Pid %d replay_waitid cannot copy status to user\n", current->pid);
				return syscall_mismatch();
			}
		}
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct waitid_retvals));
	}
	return rc;
}

asmlinkage long shim_waitid (int which, pid_t upid, struct siginfo __user *infop, int options, struct rusage __user *ru) SHIM_CALL(waitid, 284, which, upid, infop, options, ru);

SIMPLE_SHIM5(add_key, 286, const char __user *, _type, const char __user *, _description, const void __user *, _payload, size_t, plen, key_serial_t, ringid);
SIMPLE_SHIM4(request_key, 287, const char __user *, _type, const char __user *, _description, const char __user *, _callout_info, key_serial_t, destringid);

static asmlinkage long 
record_keyctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	char* recbuf = NULL;
	long rc;

	new_syscall_enter (288);
	rc = sys_keyctl (option, arg2, arg3, arg4, arg5);
	new_syscall_done (288, rc);
	if (rc >= 0) {
		if (option == KEYCTL_DESCRIBE || option == KEYCTL_READ || option == KEYCTL_GET_SECURITY) {
			recbuf = ARGSKMALLOC(arg4 + sizeof(u_long), GFP_KERNEL);
			if (!recbuf) {
				printk ("record_keyctl: can't allocate return buffer\n");
				return -ENOMEM;
			}
			*(u_long *) recbuf = arg4;
			if (copy_from_user(recbuf + sizeof(u_long), (char __user *) arg3, arg4)) {
				printk("record_keyctl: faulted on readback\n");
				return -EFAULT;
			}
		}
	}
	new_syscall_exit (288, recbuf);

	return rc;
}

static asmlinkage long 
replay_keyctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	char* retparams = NULL;
	long rc = get_next_syscall (288, &retparams);
	if (retparams) {
		u_long bytes = *((u_long *) retparams);
		if (copy_to_user((char __user *)arg3, retparams + sizeof(u_long), bytes)) return syscall_mismatch();
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + bytes);
	}
	return rc;
}

asmlinkage long shim_keyctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) SHIM_CALL(keyctl, 288, option, arg2, arg3, arg4, arg5);

SIMPLE_SHIM3(ioprio_set, 289, int, which, int, who, int, ioprio);
SIMPLE_SHIM2(ioprio_get, 290, int, which, int, who);
SIMPLE_SHIM0(inotify_init, 291);
SIMPLE_SHIM3(inotify_add_watch, 292, int, fd, const char __user *, path, u32, mask);
SIMPLE_SHIM2(inotify_rm_watch, 293, int, fd, u32, wd);
SIMPLE_SHIM4(migrate_pages, 294, pid_t, pid, unsigned long, maxnode, const unsigned long __user *, old_nodes, const unsigned long __user *, new_nodes);
SIMPLE_SHIM4(openat, 295, int, dfd, const char __user *, filename, int, flags, int, mode);
SIMPLE_SHIM3(mkdirat, 296, int, dfd, const char __user *, pathname, int, mode);
SIMPLE_SHIM4(mknodat, 297, int, dfd, const char __user *, filename, int, mode, unsigned, dev);
SIMPLE_SHIM5(fchownat, 298, int, dfd, const char __user *, filename, uid_t, user, gid_t, group, int, flag);
SIMPLE_SHIM3(futimesat, 299, int, dfd, char __user *, filename, struct timeval __user *,utimes);
RET1_SHIM4(fstatat64, 300, struct stat64, statbuf, int, dfd, char __user *, filename, struct stat64 __user *, statbuf, int, flag);
SIMPLE_SHIM3(unlinkat, 301, int, dfd, const char __user *, pathname, int, flag);
SIMPLE_SHIM4(renameat, 302, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname);
SIMPLE_SHIM5(linkat, 303, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname, int, flags);
SIMPLE_SHIM3(symlinkat, 304, const char __user *, oldname, int, newdfd, const char __user *, newname);
RET1_COUNT_SHIM4(readlinkat, 305, buf, int, dfd, const char __user *, path, char __user *, buf, int, bufsiz)
SIMPLE_SHIM3(fchmodat, 306, int, dfd, const char __user *, filename, mode_t, mode);
SIMPLE_SHIM3(faccessat, 307, int, dfd, const char __user *, filename, int, mode);

static asmlinkage long 
record_pselect6 (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig) 
{
	long rc;
	struct pselect6_retvals* pretvals;

	new_syscall_enter (308);
	rc = sys_pselect6 (n, inp, outp, exp, tsp, sig);
	new_syscall_done (308, rc);

	/* Record user's memory regardless of return value in order to capture partial output. */
	pretvals = ARGSKMALLOC(sizeof(struct pselect6_retvals), GFP_KERNEL);
	if (pretvals == NULL) {
		printk("record_pselect6: can't allocate buffer\n");
		return -ENOMEM;
	}
	memset(pretvals, 0, sizeof(struct pselect6_retvals));
	if (inp && copy_from_user (&pretvals->inp, inp, sizeof(fd_set)) == 0)
		pretvals->has_inp = 1;
	if (outp && copy_from_user (&pretvals->outp, outp, sizeof(fd_set)) == 0)
		pretvals->has_outp = 1;
	if (exp && copy_from_user (&pretvals->exp, exp, sizeof(fd_set)) == 0)
		pretvals->has_exp = 1;
	if (tsp && copy_from_user (&pretvals->tsp, tsp, sizeof(struct timespec)) == 0)
		pretvals->has_tsp = 1;

	new_syscall_exit (308, pretvals);

	return rc;
}

asmlinkage long 
replay_pselect6 (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig) 
{
	struct pselect6_retvals* retparams = NULL;
	long rc = get_next_syscall (308, (char **) &retparams);
	if (retparams->has_inp && copy_to_user (inp, &retparams->inp, sizeof(fd_set))) {
		printk ("Pid %d cannot copy inp to user\n", current->pid);
	}
	if (retparams->has_outp && copy_to_user (outp, &retparams->outp, sizeof(fd_set))) {
		printk ("Pid %d cannot copy outp to user\n", current->pid);
	}
	if (retparams->has_exp && copy_to_user (exp, &retparams->exp, sizeof(fd_set))) {
		printk ("Pid %d cannot copy exp to user\n", current->pid);
	}
	if (retparams->has_tsp && copy_to_user (tsp, &retparams->tsp, sizeof(struct timespec))) {
		printk ("Pid %d cannot copy tvp to user\n", current->pid);
	}
	argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct pselect6_retvals));
	
	return rc;
}

asmlinkage long shim_pselect6 (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig) SHIM_CALL(pselect6, 308, n, inp, outp, exp, tsp, sig);

static asmlinkage long 
record_ppoll (struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize)
{
	long rc;
	char* pretvals;

	new_syscall_enter (309);
	rc = sys_ppoll (ufds, nfds, tsp, sigmask, sigsetsize);
	new_syscall_done (309, rc);

	/* Record user's memory regardless of return value in order to capture partial output. */
	pretvals = ARGSKMALLOC(sizeof(u_long)+nfds*sizeof(struct pollfd), GFP_KERNEL);
	if (pretvals == NULL) {
		printk("record_ppoll: can't allocate buffer\n");
		return -ENOMEM;
	}
	*((u_long *)pretvals) = nfds*sizeof(struct pollfd);
	if (copy_from_user (pretvals+sizeof(u_long), ufds, nfds*sizeof(struct pollfd))) {
		printk ("record_ppoll: can't copy retvals\n");
		ARGSKFREE (pretvals,sizeof(u_long)+nfds*sizeof(struct pollfd));
		return -EFAULT;
	}
		
	new_syscall_exit (309, pretvals);

	return rc;
}

static asmlinkage long 
replay_ppoll (struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize)
{
	char* retparams = NULL;
	long rc;

	rc = get_next_syscall (309, (char **) &retparams);
	if (copy_to_user (ufds, retparams+sizeof(u_long), nfds*sizeof(struct pollfd))) {
		printk ("Pid %d cannot copy inp to user\n", current->pid);
	}
	argsconsume(current->replay_thrd->rp_record_thread, nfds*sizeof(struct pollfd));
	
	return rc;
}

asmlinkage long shim_ppoll (struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize) SHIM_CALL(ppoll, 309, ufds, nfds, tsp, sigmask, sigsetsize);

SIMPLE_SHIM1(unshare, 310, unsigned long, unshare_flags);
SIMPLE_SHIM2(set_robust_list, 311, struct robust_list_head __user *, head, size_t, len);

struct get_robust_list_retvals {
	struct robust_list_head __user * head_ptr;
	size_t                           len;
};

static asmlinkage long 
record_get_robust_list (int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr)
{
	long rc;
	struct get_robust_list_retvals* retvals = NULL;

	new_syscall_enter (312);
	rc = sys_get_robust_list (pid, head_ptr, len_ptr);
	new_syscall_done (312, rc);
	if (rc >= 0) {
		retvals = ARGSKMALLOC(sizeof(struct get_robust_list_retvals), GFP_KERNEL);
		if (retvals == NULL) {
			printk("record_get_robust_list: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (&retvals->head_ptr, head_ptr, sizeof(struct robust_list_head __user *))) {
			printk ("record_get_robust_list: unable to copy head_ptr from user\n");
			ARGSKFREE (retvals, sizeof(struct get_robust_list_retvals));
			return -EFAULT;
		}
		if (copy_from_user (&retvals->len, len_ptr, sizeof(size_t))) {
			printk ("record_get_robust_list: unable to copy len from user\n");
			ARGSKFREE (retvals, sizeof(struct get_robust_list_retvals));
			return -EFAULT;
		}
	}
	new_syscall_exit (312, retvals);

	return rc;
}

static asmlinkage long 
replay_get_robust_list (int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr)
{
	struct get_robust_list_retvals* pretvals;
	long rc = get_next_syscall (312, (char **) &pretvals);
	if (rc >= 0) {
		if (copy_to_user (head_ptr, &pretvals->head_ptr, sizeof(struct robust_list_head __user *))) {
			printk ("Pid %d replay_get_robust_list cannot copy head_ptr to user\n", current->pid);
			return syscall_mismatch();
		}
		if (copy_to_user (len_ptr, &pretvals->len, sizeof(size_t))) {
			printk ("Pid %d replay_get_robust_list cannot copy len to user\n", current->pid);
			return syscall_mismatch();
		}
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct get_robust_list_retvals));
	}
	return rc;
}

asmlinkage long shim_get_robust_list (int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr) SHIM_CALL(get_robust_list, 312, pid, head_ptr, len_ptr);

struct splice_retvals {
	loff_t off_in;
	loff_t off_out;
};

static asmlinkage long 
record_splice (int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags) 
{
	long rc;
	struct splice_retvals* pretvals = NULL;

	new_syscall_enter (313);
	rc = sys_splice (fd_in, off_in, fd_out, off_out, len, flags); 
	new_syscall_done (313, rc);
	if (rc == 0) {
		pretvals = ARGSKMALLOC(sizeof(struct splice_retvals), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_splice: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (off_in) {
			if (copy_from_user (&pretvals->off_in, off_in, sizeof(loff_t))) {
				printk ("record_splic: pid %d cannot copy off_in from user\n", current->pid);
				ARGSKFREE (pretvals, sizeof(struct splice_retvals));
				return -EFAULT;
			}
		}
		if (off_out) {
			if (copy_from_user (&pretvals->off_out, off_out, sizeof(loff_t))) {
				printk ("record_splice: pid %d cannot copy off_out from user\n", current->pid);
				ARGSKFREE (pretvals, sizeof(struct splice_retvals));
				return -EFAULT;
			}
		}

	}
	new_syscall_exit (313, pretvals);

	return rc;
}

static asmlinkage long 
replay_splice (int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags) 
{
	struct splice_retvals* retparams = NULL;
	long rc = get_next_syscall (313, (char **) &retparams);

	if (retparams) {
		if (off_in) {
			if (copy_to_user (off_in, &retparams->off_in, sizeof(loff_t))) {
				printk ("replay_splice: pid %d cannot copy off_in to user\n", current->pid);
				return syscall_mismatch();
			}
		}
		if (off_out) {
			if (copy_to_user (off_out, &retparams->off_out, sizeof(loff_t))) {
				printk ("replay_splice: pid %d cannot copy tz to user\n", current->pid);
				return syscall_mismatch();
			}
		}	
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct splice_retvals));
	}
	return rc;
}

asmlinkage long shim_splice (int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags) SHIM_CALL(splice, 313, fd_in, off_in, fd_out, off_out, len, flags);

SIMPLE_SHIM4(sync_file_range, 314, int, fd, loff_t, offset, loff_t, nbytes, unsigned int, flags);
SIMPLE_SHIM4(tee, 315, int, fdin, int, fdout, size_t, len, unsigned int, flags);
SIMPLE_SHIM4(vmsplice, 316, int, fd, const struct iovec __user *, iov, unsigned long, nr_segs, unsigned int, flags);

static asmlinkage long 
record_move_pages (pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags) 
{
	char* pretvals = NULL;
	long rc;

	new_syscall_enter (317);
	rc = sys_move_pages (pid, nr_pages, pages, nodes, status, flags);
	new_syscall_done (317, rc);
	if (rc >= 0) {
		pretvals = ARGSKMALLOC(sizeof(u_long) + nr_pages*sizeof(int), GFP_KERNEL);
		if (!pretvals) {
			printk ("record_move_pages: can't allocate return buffer\n");
			return -ENOMEM;
		}
		*((u_long *) pretvals) = nr_pages;
		if (copy_from_user(pretvals + sizeof(u_long), status, nr_pages*sizeof(int))) {
			printk("record_move_pages: faulted on readback\n");
			ARGSKFREE(pretvals, sizeof(u_long) + nr_pages*sizeof(int));
			return -EFAULT;
		}
	}
	new_syscall_exit (317, pretvals);

	return rc;
}

static asmlinkage long 
replay_move_pages (pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags) 
{
	char* retparams = NULL;
	long rc = get_next_syscall (317, &retparams);
	if (retparams) {
		u_long bytes = *((u_long *) retparams);
		if (copy_to_user(status, retparams + sizeof(u_long), bytes)) return syscall_mismatch();
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(u_long) + bytes);
	}
	return rc;
}

asmlinkage long shim_move_pages (pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags) SHIM_CALL(move_pages, 317, pid, nr_pages, pages, nodes, status, flags);

static asmlinkage long
record_getcpu (unsigned __user *cpup, unsigned __user *nodep, struct getcpu_cache __user *unused)
{
	long rc;
	old_uid_t* pretval = NULL;

	new_syscall_enter (318);
	rc = sys_getcpu (cpup, nodep, unused);
	new_syscall_done (318, rc);
	if (rc >= 0) {
		pretval = ARGSKMALLOC(sizeof(unsigned)*2, GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_getcpu: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (cpup) {
			if (copy_from_user (pretval, cpup, sizeof(unsigned))) {
				printk ("record_getcpu: can't copy cpup\n");
				ARGSKFREE (pretval, sizeof(unsigned)*2);
				return -EFAULT;
			}
		}
		if (nodep) {
			if (copy_from_user (pretval+1, nodep, sizeof(unsigned))) {
				printk ("record_getcpu: can't copy cpup\n");
				ARGSKFREE (pretval, sizeof(unsigned)*2);
				return -EFAULT;
			}
		}
	}
	new_syscall_exit (318, pretval);

	return rc;
}

static asmlinkage long
replay_getcpu (unsigned __user *cpup, unsigned __user *nodep, struct getcpu_cache __user *unused)
{
	unsigned* retparams = NULL;
	long rc = get_next_syscall (318, (char **) &retparams);
	if (rc >= 0) {
		if (retparams) {
			if (cpup) {
				if (copy_to_user (cpup, retparams, sizeof(unsigned))) {
					printk ("replay_getcpu: pid %d cannot copy cpup to user\n", current->pid);
				}
			}
			if (nodep) {
				if (copy_to_user (nodep, retparams+1, sizeof(unsigned))) {
					printk ("replay_getcpu: pid %d cannot copy nodep to user\n", current->pid);
				}
			}
			argsconsume(current->replay_thrd->rp_record_thread, 2*sizeof(unsigned));
		}
	}
	return rc;
}

asmlinkage long shim_getcpu (unsigned __user *cpup, unsigned __user *nodep, struct getcpu_cache __user *unused) SHIM_CALL(getcpu, 318, cpup, nodep, unused);

static asmlinkage long 
record_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize)
{
	long rc;
	char* pretvals = NULL;

	new_syscall_enter (319);
	rc = sys_epoll_pwait (epfd, events, maxevents, timeout, sigmask, sigsetsize);
	new_syscall_done (319, rc);
	if (rc > 0) {
		pretvals = ARGSKMALLOC (rc * sizeof(struct epoll_event), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_epoll_pwait: can't allocate buffer with %ld record\n", rc);
			return -ENOMEM;
		}
		if (copy_from_user (pretvals, events, rc * sizeof(struct epoll_event))) {
			printk("record_epoll_pwait: can't copy buffer with %ld record\n", rc);
			ARGSKFREE (pretvals, rc * sizeof(struct epoll_event));
			return -EFAULT;
		}
	}
	new_syscall_exit (319, pretvals);

	return rc;
}

static asmlinkage long 
replay_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize)
{
	long rc;
	char* retparams = NULL;
	rc = get_next_syscall (319, &retparams);
	if (rc > 0) {
		if (copy_to_user (events, retparams, rc * sizeof(struct epoll_event))) {
			printk ("Pid %d cannot copy epoll_pwait retvals to user\n", current->pid);
		}
		argsconsume(current->replay_thrd->rp_record_thread, rc * sizeof(struct epoll_event));
	}

	return rc;
}

asmlinkage long shim_epoll_pwait (int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize) SHIM_CALL (epoll_pwait, 319, epfd, events, maxevents, timeout, sigmask, sigsetsize);

SIMPLE_SHIM4(utimensat, 320, int, dfd, char __user *, filename, struct timespec __user *, utimes, int, flags);
SIMPLE_SHIM3(signalfd, 321, int, ufd, sigset_t __user *, user_mask, size_t, sizemask);
SIMPLE_SHIM2(timerfd_create, 322, int, clockid, int, flags);
SIMPLE_SHIM1(eventfd, 323, unsigned int, count);
SIMPLE_SHIM4(fallocate, 324, int, fd, int, mode, loff_t, offset, loff_t, len);
RET1_SHIM4(timerfd_settime, 325, struct itimerspec, otmr, int, ufd, int, flags, const struct itimerspec __user *, utmr, struct itimerspec __user *,otmr);
RET1_SHIM2(timerfd_gettime, 326, struct itimerspec, otmr, int, ufd, struct itimerspec __user *, otmr);
SIMPLE_SHIM4(signalfd4, 327, int, ufd, sigset_t __user *, user_mask, size_t, sizemask, int, flags);
SIMPLE_SHIM2(eventfd2, 328, unsigned int, count, int, flags);
SIMPLE_SHIM1(epoll_create1, 329, int, flags);
SIMPLE_SHIM3(dup3, 330, unsigned int, oldfd, unsigned int, newfd, int, flags);

asmlinkage long 
record_pipe2 (int __user *fildes, int flags)
{
	long rc;
	int* pretval = NULL;

	new_syscall_enter (331);
	rc = sys_pipe2 (fildes, flags);
	new_syscall_done (331, rc);
	if (rc == 0) {
		pretval = ARGSKMALLOC(2*sizeof(int), GFP_KERNEL);
		if (pretval == NULL) {
			printk("record_pipe2: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (copy_from_user (pretval, fildes, 2*sizeof(int))) {
			ARGSKFREE (pretval, 2*sizeof(int));
			return -EFAULT;
		}
	}
	new_syscall_exit (331, pretval);

	return rc;
}

RET1_REPLAYG(pipe2, 331, fildes, 2*sizeof(int), int __user* fildes, int flags);

asmlinkage long shim_pipe2 (int __user *fildes, int flags) SHIM_CALL(pipe2, 331, fildes, flags);

SIMPLE_SHIM1(inotify_init1, 332, int, flags);

static asmlinkage long 
record_preadv (unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h) 
{
	long size;

	new_syscall_enter (333);
	size = sys_preadv (fd, vec, vlen, pos_l, pos_h);
	new_syscall_done (333, size);
	new_syscall_exit (333, copy_iovec_to_args(size, vec, vlen));
	return size;
}

static asmlinkage long 
replay_preadv (unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h) 
{
	char* retparams;
	long retval, rc;

	rc = get_next_syscall (333, &retparams);
	if (retparams) {
		retval = copy_args_to_iovec (retparams, rc, vec, vlen);
		if (retval < 0) return retval;
		argsconsume(current->replay_thrd->rp_record_thread, rc);
	}

	return rc;
}

asmlinkage long shim_preadv(unsigned long fd, const struct iovec __user *vec,  unsigned long vlen, unsigned long pos_l, unsigned long pos_h) SHIM_CALL(preadv, 333, fd, vec, vlen, pos_l, pos_h);

SIMPLE_SHIM5(pwritev, 334, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h);
SIMPLE_SHIM4(rt_tgsigqueueinfo, 335, pid_t, tgid, pid_t, pid, int, sig, siginfo_t __user *, uinfo);
SIMPLE_SHIM5(perf_event_open, 336, struct perf_event_attr __user *, attr_uptr, pid_t, pid, int, cpu, int, group_fd, unsigned long, flags);

static asmlinkage long 
record_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout) 
{
	long rc, retval;
	long* plogsize = NULL;

	new_syscall_enter (337);
	rc = sys_recvmmsg (fd, msg, vlen, flags, timeout);
	new_syscall_done (337, rc);
	if (rc > 0) {
		retval = log_mmsghdr(msg, rc, plogsize);
		if (retval < 0) return retval;
	}
	new_syscall_exit (337, plogsize);

	return rc;
}

static asmlinkage long 
replay_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout) 
{
	char* retparams;
	long rc, retval;

	rc = get_next_syscall (337, &retparams);
	if (retparams) {
		retval = extract_mmsghdr (retparams, msg, rc);
		if (retval < 0) syscall_mismatch();
	}

	return rc;
}

asmlinkage long shim_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout) SHIM_CALL(recvmmsg, 337, fd, msg, vlen, flags, timeout);

SIMPLE_SHIM2(fanotify_init, 338, unsigned int, flags, unsigned int, event_f_flags);
SIMPLE_SHIM5(fanotify_mark, 339, int, fanotify_fd, unsigned int, flags, u64, mask, int, fd, const char  __user *, pathname);

RET1_RECORD4(prlimit64, 340, struct rlimit64, old_rlim, pid_t, pid, unsigned int, resource, const struct rlimit64 __user *, new_rlim, struct rlimit64 __user *, old_rlim);

static asmlinkage long 
replay_prlimit64 (pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim)
{
	struct rlimit64 *retparams = NULL;
	long rc_orig, rc;

	rc_orig = get_next_syscall (340, (char **) &retparams);
	if (new_rlim) {
		rc = sys_prlimit64 (pid, resource, new_rlim, old_rlim);
		if (rc != rc_orig) printk ("Pid %d: prlimit64 pid %d resource %u changed its return in replay, rec %ld rep %ld\n", current->pid, pid, resource, rc_orig, rc);
	}
	if (retparams) {
		if (copy_to_user (old_rlim, retparams, sizeof(struct rlimit64))) printk ("Pid %d replay_prlimit cannot copy to user\n", current->pid);
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct rlimit64));
	}
	DPRINT ("replay_prlimit64 pid %d resource %u returns %ld\n", pid, resource, rc_orig);

	return rc_orig;
}

asmlinkage long shim_prlimit64 (pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim) SHIM_CALL(prlimit64, 340, pid, resource, new_rlim, old_rlim);

struct name_to_handle_at_retvals {
	struct file_handle handle;
	int                mnt_id;
};

static asmlinkage long 
record_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag)
{
	long rc;
	struct name_to_handle_at_retvals* pretvals = NULL;

	new_syscall_enter (341);
	rc = sys_name_to_handle_at (dfd, name, handle, mnt_id, flag);
	new_syscall_done (341, rc);
	if (rc == 0) {
		pretvals = ARGSKMALLOC(sizeof(struct name_to_handle_at_retvals), GFP_KERNEL);
		if (pretvals == NULL) {
			printk("record_name_to_handle_at: can't allocate buffer\n");
			return -ENOMEM;
		}
		if (handle) {
			if (copy_from_user (&pretvals->handle, handle, sizeof(struct file_handle))) {
				printk ("record_name_to_handle_at: pid %d cannot copy handle from user\n", current->pid);
				ARGSKFREE (pretvals, sizeof(struct name_to_handle_at_retvals));
				return -EFAULT;
			}
		}
		if (mnt_id) {
			if (copy_from_user (&pretvals->mnt_id, mnt_id, sizeof(int))) {
				printk ("record_name_to_handle_at: pid %d cannot copy mnt_id from user\n", current->pid);
				ARGSKFREE (pretvals, sizeof(struct name_to_handle_at_retvals));
				return -EFAULT;
			}
		}
	}
	new_syscall_exit (341, pretvals);

	return rc;
}

static asmlinkage long 
replay_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag)
{
	struct name_to_handle_at_retvals* retparams = NULL;
	long rc = get_next_syscall (341, (char **) &retparams);

	if (retparams) {
		if (handle) {
			if (copy_to_user (handle, &retparams->handle, sizeof(struct file_handle))) {
				printk ("replay_name_to_handle_at: pid %d cannot copy handle to user\n", current->pid);
				return syscall_mismatch();
			}
		}
		if (mnt_id) {
			if (copy_to_user (mnt_id, &retparams->mnt_id, sizeof(int))) {
				printk ("replay_name_to_handle_at: pid %d cannot copy tz to user\n", current->pid);
				return syscall_mismatch();
			}
		}
		argsconsume(current->replay_thrd->rp_record_thread, sizeof(struct name_to_handle_at_retvals));
	}
	return rc;
}

asmlinkage long shim_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag) SHIM_CALL(name_to_handle_at, 341, dfd, name, handle, mnt_id, flag);

SIMPLE_SHIM3(open_by_handle_at, 342, int, mountdirfd, struct file_handle __user *, handle, int, flags);
RET1_SHIM2(clock_adjtime, 343, struct timex, tx, clockid_t, which_clock, struct timex __user *,tx);
SIMPLE_SHIM1(syncfs, 344, int, fd);
SIMPLE_SHIM4(sendmmsg, 345, int, fd, struct mmsghdr __user *, msg, unsigned int, vlen, unsigned, flags);
SIMPLE_SHIM2(setns, 346, int, fd, int, nstype);

static asmlinkage long 
record_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
{
	struct task_struct* tsk = pid_task (find_vpid(pid), PIDTYPE_PID);
	long rc;						

	if (tsk) { // Invalid pid should fail, so replay is easy
		if (!tsk->record_thrd) {
			printk ("[ERROR] pid %d records process_vm_read of non-recordig pid %d\n", current->pid, pid);
			return sys_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags);
		} else if (tsk->record_thrd->rp_group != current->record_thrd->rp_group) {
			printk ("[ERROR] pid %d records process_vm_read of pid %d in different record group - must merge\n", current->pid, pid);
			return sys_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags);
		} // Now we know two tasks are in same record group, so memory ops should be deterministic (unless they incorrectly involve replay-specific structures) */
	}

	new_syscall_enter (347);
	rc =  sys_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags);
	new_syscall_done (347, rc);
	new_syscall_exit (347, NULL);				
	return rc;						
}

static asmlinkage long 
replay_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
{
	struct replay_thread* tmp;
	long rc, retval;

	rc = get_next_syscall (347, NULL);	

	// Need to adjust pid to reflect the replay process, not the record process
	tmp = current->replay_thrd->rp_next_thread;
	while (tmp != current->replay_thrd) {
		if (tmp->rp_record_thread->rp_record_pid == pid) {
			retval = sys_process_vm_readv (tmp->rp_record_thread->rp_record_pid, lvec, liovcnt, rvec, riovcnt, flags);
			if (rc != retval) {
				printk ("process_vm_readv returns %ld on replay but returned %ld on record\n", retval, rc);
				syscall_mismatch();
			}
			return rc;
		}
	}
	printk ("process_vm_readv: pid %d cannot find record pid %d in replay group\n", current->pid, pid);
	return syscall_mismatch();
}

asmlinkage long shim_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags) SHIM_CALL(process_vm_readv, 347, pid, lvec, liovcnt, rvec, riovcnt, flags);

static asmlinkage long 
record_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
{
	struct task_struct* tsk = pid_task (find_vpid(pid), PIDTYPE_PID);
	long rc;						

	if (tsk) { // Invalid pid should fail, so replay is easy
		if (!tsk->record_thrd) {
			printk ("[ERROR] pid %d records process_vm_writev of non-recordig pid %d\n", current->pid, pid);
			return sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);
		} else if (tsk->record_thrd->rp_group != current->record_thrd->rp_group) {
			printk ("[ERROR] pid %d records process_vm_writev of pid %d in different record group - must merge\n", current->pid, pid);
			return sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);
		} // Now we know two tasks are in same record group, so memory ops should be deterministic (unless they incorrectly involve replay-specific structures) */
	}

	new_syscall_enter (348);
	rc =  sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);
	new_syscall_done (348, rc);
	new_syscall_exit (348, NULL);				
	return rc;						
}

static asmlinkage long 
replay_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
{
	struct replay_thread* tmp;
	long rc, retval;

	rc = get_next_syscall (348, NULL);	

	// Need to adjust pid to reflect the replay process, not the record process
	tmp = current->replay_thrd->rp_next_thread;
	while (tmp != current->replay_thrd) {
		if (tmp->rp_record_thread->rp_record_pid == pid) {
			retval = sys_process_vm_writev (tmp->rp_record_thread->rp_record_pid, lvec, liovcnt, rvec, riovcnt, flags);
			if (rc != retval) {
				printk ("process_vm_writev returns %ld on replay but returned %ld on record\n", retval, rc);
				syscall_mismatch();
			}
			return rc;
		}
	}
	printk ("process_vm_writev: pid %d cannot find record pid %d in replay group\n", current->pid, pid);
	return syscall_mismatch();
}

asmlinkage long shim_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags) 
{
	// Paranoid check
	if (!(current->record_thrd  || current->replay_thrd)) {
		struct task_struct* tsk = pid_task (find_vpid(pid), PIDTYPE_PID);
		if (tsk && tsk->record_thrd) {
			printk ("[ERROR]: non-recorded process %d modifying the address space of recorded thread %d\n", current->pid, pid);
		}
	}
	SHIM_CALL(process_vm_writev, 348, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

SIMPLE_SHIM5(kcmp, 349, pid_t, pid1, pid_t, pid2, int, type, unsigned long, idx1, unsigned long, idx2);

struct file* init_log_write (struct record_thread* prect, loff_t* ppos, int* pfd)
{
	char filename[MAX_LOGDIR_STRLEN+20];
	struct stat64 st;
	mm_segment_t old_fs;
	int rc;

	sprintf (filename, "%s/klog.id.%d", prect->rp_group->rg_logdir, prect->rp_record_pid);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	if (prect->rp_klog_opened) {
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
		prect->rp_klog_opened = 1;
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

static ssize_t write_log_data (struct file* file, loff_t* ppos, struct record_thread* prect, struct syscall_result* psr, int count)
{
	struct argsalloc_node* node;
	ssize_t copyed = 0;
	struct iovec* pvec; // Concurrent writes need their own vector
	int kcnt = 0;
	u_long data_len;
#ifdef USE_HPC
	unsigned long long hpc1;	
	unsigned long long hpc2;	
	struct timeval tv1;
	struct timeval tv2;
#endif

	if (count <= 0) return 0;

	MPRINT ("Pid %d, start write log data\n", current->pid);

	pvec = KMALLOC (sizeof(struct iovec) * UIO_MAXIOV, GFP_KERNEL);
	if (pvec == NULL) {
		printk ("Cannot allocate iovec for write_log_data\n");
		return 0;
	}

#ifdef USE_HPC
	hpc1 = rdtsc(); 
	do_gettimeofday(&tv1);
	msleep(1);
	hpc2 = rdtsc();
	do_gettimeofday(&tv2);

	copyed = vfs_write(file, (char *) &hpc1, sizeof(unsigned long long), ppos);
	if (copyed != sizeof(unsigned long long)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (1)\n", current->pid, sizeof(unsigned long long), copyed);
	}

	copyed = vfs_write(file, (char *) &tv1, sizeof(struct timeval), ppos);
	if (copyed != sizeof(struct timeval)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (2)\n", current->pid, sizeof(struct timeval), copyed);
	}

	copyed = vfs_write(file, (char *) &hpc2, sizeof(unsigned long long), ppos);
	if (copyed != sizeof(unsigned long long)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (3)\n", current->pid, sizeof(unsigned long long), copyed);
	}

	copyed = vfs_write(file, (char *) &tv2, sizeof(struct timeval), ppos);
	if (copyed != sizeof(struct timeval)) {
		printk("[WARN] Pid %d write_hpc_calibration, expected to write %d got %d (4)\n", current->pid, sizeof(struct timeval), copyed);
	}
#endif

	/* First write out syscall records in a bunch */
	copyed = vfs_write(file, (char *) &count, sizeof(count), ppos);
	if (copyed != sizeof(count)) {
		printk ("write_log_data: tried to write record count, got rc %d\n", copyed);
		KFREE (pvec);
		return -EINVAL;
	}

	MPRINT ("Pid %d write_log_data count %d, size %d\n", current->pid, count, sizeof(struct syscall_result)*count);

	copyed = vfs_write(file, (char *) psr, sizeof(struct syscall_result)*count, ppos);
	if (copyed != sizeof(struct syscall_result)*count) {
		printk ("write_log_data: tried to write %d, got rc %d\n", sizeof(struct syscall_result)*count, copyed);
		KFREE (pvec);
		return -EINVAL;
	}

	/* Now write ancillary data - count of bytes goes first */
	data_len = 0;
	list_for_each_entry_reverse (node, &prect->rp_argsalloc_list, list) {
		data_len += node->pos - node->head;
	}
	MPRINT ("Ancillary data written is %lu\n", data_len);
	copyed = vfs_write(file, (char *) &data_len, sizeof(data_len), ppos);
	if (copyed != sizeof(count)) {
		printk ("write_log_data: tried to write ancillary data length, got rc %d\n", copyed);
		KFREE (pvec);
		return -EINVAL;
	}

	list_for_each_entry_reverse (node, &prect->rp_argsalloc_list, list) {
		MPRINT ("Pid %d argssize write buffer slab size %d\n", current->pid, node->pos - node->head);
		pvec[kcnt].iov_base = node->head;
		pvec[kcnt].iov_len = node->pos - node->head;
		if (++kcnt == UIO_MAXIOV) {
			copyed = vfs_writev (file, pvec, kcnt, ppos);
			kcnt = 0;
		}
	}

	vfs_writev (file, pvec, kcnt, ppos); // Write any remaining data before exit
	
	DPRINT ("Wrote %d bytes to the file for sysnum %d\n", copyed, psr->sysnum);
	KFREE (pvec);

	return copyed;
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
	struct file* file;
	int fd, rc, count;
	mm_segment_t old_fs;
	u_long data_len;
	struct argsalloc_node* node;
	char* slab;

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

	rc = vfs_read (file, (char *) &psr[0], sizeof(struct syscall_result)*count, pos);
	if (rc != sizeof(struct syscall_result)*count) {
		printk ("vfs_read returns %d when %d of records expected\n", rc, sizeof(struct syscall_result)*count);
		goto error;
	}

	rc = vfs_read (file, (char *) &data_len, sizeof(data_len), pos);
	if (rc != sizeof(data_len)) {
		printk ("vfs_read returns %d, sizeof(data_len) %d\n", rc, sizeof(data_len));
		*syscall_count = 0;
		goto error;
	}

	/* Read in length of ancillary data, and add it to the argsalloc list */
	MPRINT ("read_log_data data length is %lu\n", data_len);
	if (data_len > 0) {
		slab = VMALLOC(data_len);
		rc = add_argsalloc_node(prect, slab, data_len);
		if (rc) {
			printk("read_log_data_internal: pid %d argalloc: problem adding argsalloc_node\n", current->pid);
			VFREE(slab);
			*syscall_count = 0;
			goto error;
		}

		node = list_first_entry(&prect->rp_argsalloc_list, struct argsalloc_node, list);
		rc = vfs_read (file, node->pos, data_len, pos);
		if (rc != data_len) {
			printk ("read_log_data_internal: vfs_read of ancillary data returns %d, epected %lu\n", rc, data_len);
			*syscall_count = 0;
			goto error;
		}
	}

	*syscall_count = count;  
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

/* Write out the list of memory regions used in this record group */
void write_mmap_log (struct record_group* prg)
{
	char filename[MAX_LOGDIR_STRLEN+20];
	int fd = 0;
	loff_t pos = 0;
	struct file* file = NULL;
	mm_segment_t old_fs;

	int copyed;
	ds_list_t* memory_list;
	ds_list_iter_t* iter;
	struct reserved_mapping* pmapping;

	MPRINT ("Pid %d write_mmap_log start\n", current->pid);

	if (!prg->rg_save_mmap_flag) return;

	// one mlog per record group
	sprintf (filename, "%s/mlog", prg->rg_logdir);
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	fd = sys_open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd < 0) {
		printk("Pid %d write_mmap_log: could not open file %s, %d\n", current->pid, filename, fd);
		return;
	}
	file = fget(fd);

	if (!file) {
		printk("Pid %d write_mmap_log, could not open file %s\n", current->pid, filename);
		return;
	}

	memory_list = prg->rg_reserved_mem_list;

	iter = ds_list_iter_create (memory_list);
	while ((pmapping = ds_list_iter_next (iter)) != NULL) {
		DPRINT ("Pid %d writing allocation [%lx, %lx)\n",
				current->pid, pmapping->m_begin, pmapping->m_end);
		copyed = vfs_write(file, (char *) pmapping, sizeof(struct reserved_mapping), &pos);
		if (copyed != sizeof(struct reserved_mapping)) {
			printk("[WARN] Pid %d write reserved_mapping, expected to write %d got %d\n", current->pid, sizeof(struct reserved_mapping), copyed);
		}
	}
	ds_list_iter_destroy (iter);

	term_log_write(file, fd);
	set_fs(old_fs);

	MPRINT ("Pid %d write mmap log done\n", current->pid);
}

/* Reads in a list of memory regions that will be used in a replay */
int read_mmap_log (struct record_group* precg)
{
	int fd;
	int rc = 0;
	char filename[MAX_LOGDIR_STRLEN+20];
	struct file* file;
	mm_segment_t old_fs;
	loff_t pos = 0;

	struct stat64 st;
	int num_entries = 0;
	int i = 0;
	struct reserved_mapping* pmapping;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	sprintf (filename, "%s/mlog", precg->rg_logdir);
	MPRINT ("Pid %d Opening mlog %s\n", current->pid, filename);
	fd = sys_open(filename, O_RDONLY, 0644);
	if (fd < 0) {
		printk("read_mmap_log: cannot open log file %s\n", filename);
		return -EINVAL;
	}
	file = fget(fd);

	// stat the file, see how many pmaps we expect
	rc = sys_stat64(filename, &st);
	if (rc < 0) {
		printk("read_mmap_log: cannot stat file %s, %d\n", filename, rc);
		return -EINVAL;
	}
	num_entries = st.st_size / (sizeof(struct reserved_mapping));

	// Read the mappings from file and put them in the record thread structure
	for (i = 0; i < num_entries; i++) {
		pmapping = KMALLOC (sizeof(struct reserved_mapping), GFP_KERNEL);
		if (pmapping == NULL) {
			printk ("read_mmap_log: Cannot allocate new reserve mapping\n");
			return -ENOMEM;
		}
		rc = vfs_read(file, (char *) pmapping, sizeof(struct reserved_mapping), &pos);
		if (rc < 0) {
			printk("Pid %d problem reading in a reserved mapping, rc %d\n", current->pid, rc);
			KFREE (pmapping);
			return rc;
		}
		if (rc != sizeof(struct reserved_mapping)) {
			printk("Pid %d read reserved_mapping expected %d, got %d\n", current->pid, sizeof(struct reserved_mapping), rc);
			KFREE(pmapping);
			return rc;	
		}

		ds_list_insert (precg->rg_reserved_mem_list, pmapping);
	}

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
	{
		.procname	= "pin_debug_clock",
		.data		= &pin_debug_clock,
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

#ifdef REPLAY_COMPRESS_READS
	btree_init32(&meta_tree);
	INIT_LIST_HEAD(&file_work_entries);

	do {
		int i;
		for (i = 0; i < NUM_WORK_ENTRIES; i++) {
			list_add(&file_work_entries_alloc[i].list, &file_work_entries);
		}
	} while (0);
#endif

#ifdef TRACE_PIPE_READ_WRITE
	btree_init32(&pipe_tree);
#endif


	return 0;
}

module_init(replay_init)
