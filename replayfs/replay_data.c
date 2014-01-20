#include "replay_data.h"
#include "replayfs_file_log.h"
#include "replayfs_fs.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/signal.h>

#include <linux/replay.h>

/* #define REPLAY_DATA_DEBUG */
/* #define REPLAY_DATA_ALLOC_DEBUG */
/* #define REPLAY_DATA_LOCK_DEBUG */

#ifdef REPLAY_DATA_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

#ifdef REPLAY_DATA_ALLOC_DEBUG
#define alloc_debugk(...) printk(__VA_ARGS__)
#define alloc_dump_stack() dump_stack()
#else
#define alloc_debugk(...)
#define alloc_dump_stack()
#endif

#ifdef REPLAY_DATA_LOCK_DEBUG
#define lock_debugk(...) printk(__VA_ARGS__)
#define lock_dump_stack() dump_stack()
#else
#define lock_debugk(...)
#define lock_dump_stack()
#endif



#define REPLAY_RESUME_PROG "/home/ddevec/replayfs/module/resume"
#define REPLAYFS_LOG_DIR "/home/replayfs_data_dir/logs/"

/* strlen + _ + "8digithex" + _ + "16digithex" */
#define REPLAYFS_LOG_DIRLEN strlen(REPLAYFS_LOG_DIR)+8+16+2

struct replay_desc_cache replay_cache;

static int replay_desc_set_state(struct replay_desc *replay, int state);
static void replay_desc_state_update(struct replay_desc *replay);
static unsigned int hash(unsigned int a);
static unsigned int hash64(loff_t val);

int replay_cache_init(void) {
	int i;
	mutex_init(&replay_cache.lock);

	for (i = 0; i < REPLAY_DESC_CACHE_SIZE; i++) {
		replay_cache.cache[i] = NULL;
	}

	return 0;
}

void replay_cache_destroy(void) {
	int i;
	/* Unref each entry */
	for (i = 0; i < REPLAY_DESC_CACHE_SIZE; i++) {
		if (replay_cache.cache[i] != NULL) {
			replay_cache_put(replay_cache.cache[i]);
		}
	}
}

/* XXX NOTE: replay_cache.lock must be held! */
static struct replay_desc *replay_desc_init(loff_t replay_unique_id) {
	struct replay_desc *ret;
	unsigned int index;

	ret = kmalloc(sizeof(struct replay_desc), GFP_NOIO);
	if (ret == NULL) {
		goto out;
	}

	index = hash64(replay_unique_id) % REPLAY_DESC_CACHE_SIZE;

	/* Initialize the descriptor */
	ret->unique_id = replay_unique_id;

	/* Ref this entry, as its currently held in the cache */
	atomic_set(&ret->ref_cnt, 1);

	/* Initialize our mutexes */
	mutex_init(&ret->state_lock);
	mutex_init(&ret->cache_lock);

	/* Initialize our data stores */
	if (ram_replayfs_page_alloc_init(&ret->meta_cache, NULL)) {
		kfree(ret);
		goto out;
	}
	if (ram_replayfs_page_alloc_init(&ret->data_cache, NULL)) {
		ram_replayfs_page_alloc_destroy(&ret->meta_cache);
		kfree(ret);
		goto out;
	}

	/* Initialize our wait queues */
	init_waitqueue_head(&ret->waitq);
	init_waitqueue_head(&ret->writer_waitq);

	/* Set the state to done */
	ret->state = REPLAY_STATE_DONE;

	/* 
	 * If I were to forget to initialize this, it may cause the page_alloc to try
	 * to grab a page in very high space, and that may in turn cause the
	 * page_alloc to allocate a ton of memory, and that may run my system out of
	 * memory and freak the kernel out.  I wouldn't want that...
	 */
	ret->num_syscalls = 0;
	ret->data_cache_pos = 0;

	/* Say we have never read a syscall */
	ret->last_syscall = -1;
	ret->max_sysnum = -1;

	/* Add the entry to the cache for use */
	if (replay_cache.cache[index] != NULL) {
		/* Evict the previous entry */
		replay_cache_put(replay_cache.cache[index]);
	}

	replay_cache.cache[index] = ret;

out:
	return ret;
}

/* XXX NOTE: Assumes the replay is already removed from the cache!!! */
void replay_desc_destroy(struct replay_desc *replay) {

	/* First, kill the replay process */
	replay_desc_kill(replay);
	replay_desc_state_update(replay);

	/* Deallocate our memory */
	lock_debugk("%s %d: Write Locking %p\n", __func__, __LINE__, &replay->cache_lock);
	mutex_lock(&replay->cache_lock);
	/*lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&replay->state_lock);*/
	mutex_lock(&replay->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);

	ram_replayfs_page_alloc_destroy(&replay->data_cache);
	ram_replayfs_page_alloc_destroy(&replay->meta_cache);

	/*lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
	 * &replay->state_lock);*/
	mutex_unlock(&replay->state_lock);
	lock_debugk("%s %d: Write Unlocking %p\n", __func__, __LINE__, &replay->cache_lock);
	mutex_unlock(&replay->cache_lock);

	/* Free the strucutre, and be done with it */
	kfree(replay);
}

struct replay_desc *replay_cache_get(loff_t replay_unique_id) {
	struct replay_desc *replay;

	unsigned int index;

	/* Look up this unique ID */
	index = hash64(replay_unique_id) % REPLAY_DESC_CACHE_SIZE;

	/* Must lock through the entire function to make the insertion atomic */
	mutex_lock(&replay_cache.lock);

	/* See if we already have this entry cached */
	if (replay_cache.cache[index] != NULL &&
			replay_cache.cache[index]->unique_id == replay_unique_id) {
		replay = replay_cache.cache[index];
		atomic_inc(&replay->ref_cnt);
		goto out;
	}

	/* If the replay didn't exist, lets make one */
	/* 
	 * NOTE: replay_desc_init() will insert into the cache, and handle
	 * ref_counting (and clocking and evictions...)
	 */
	replay = replay_desc_init(replay_unique_id);
	if (replay == NULL) {
		goto out;
	}

	/* We still need to increment the ref count once more
	 *   (because we are returning it to the user...
	 *     Once for being in the cache, and once for the user's reference)
	 */
	atomic_inc(&replay->ref_cnt);

out:
	alloc_debugk("%s %d: Get called on replay_desc %p, count is %d\n", __func__,
			__LINE__, replay, atomic_read(&replay->ref_cnt));
	alloc_dump_stack();

	mutex_unlock(&replay_cache.lock);
	return replay;
}

void replay_cache_put(struct replay_desc *replay) {
	/* Decrement the refcount */
	alloc_debugk("%s %d: Put called on replay_desc %p, count is %d\n", __func__,
			__LINE__, replay, atomic_read(&replay->ref_cnt)-1);
	alloc_dump_stack();

	if (atomic_dec_and_test(&replay->ref_cnt)) {
		/* We are no longer in use! */
		replay_desc_destroy(replay);
	}
}


int replay_desc_prefetch(struct replay_desc *replay, loff_t prefetch_sysnum) {
	int ret = 0;

	/*lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&replay->state_lock);*/
	mutex_lock(&replay->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);

	if (replay->max_sysnum < prefetch_sysnum) {
		replay->max_sysnum = prefetch_sysnum;
	}

	/* 
	 * If we're not running, and we're not paused for some reason, we should be
	 */
	if (replay->state != REPLAY_STATE_RUNNING &&
			replay->state != REPLAY_STATE_PAUSED) {
		if (replay_desc_set_state(replay, REPLAY_STATE_RUNNING)) {
			ret = 1;
			goto out;
		}
	}

out:
	/*lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
	 * &replay->state_lock);*/
	mutex_unlock(&replay->state_lock);
	return ret;
}

/* Force the pid pointed to by replay onto a wait list */
int replay_desc_pause(struct replay_desc *replay) {
	int ret;

	ret = 0;
	/*lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&replay->state_lock);*/
	mutex_lock(&replay->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);

	if (replay->state == REPLAY_STATE_PAUSED) {
		goto out;
	}

	/* Actually manage setting the state */
	replay_desc_set_state(replay, REPLAY_STATE_PAUSED);

out:
	/*lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
	 * &replay->state_lock);*/
	mutex_unlock(&replay->state_lock);
	return ret;
}

/* Remove the pid pointed to by replay from our wait list */
int replay_desc_resume(struct replay_desc *replay) {
	int ret;

	ret = 0;
	/*lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&replay->state_lock);*/
	mutex_lock(&replay->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);

	if (replay->state == REPLAY_STATE_RUNNING) {
		goto out;
	}

	/* Actually manage setting the state */
	replay_desc_set_state(replay, REPLAY_STATE_RUNNING);

out:
	/*lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
	 * &replay->state_lock);*/
	mutex_unlock(&replay->state_lock);
	return ret;
}

/* Kills the replaying process, does not delete the desc */
int replay_desc_kill(struct replay_desc *replay) {
	int ret;

	ret = 0;

	/*lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&replay->state_lock);*/
	mutex_lock(&replay->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);
	if (replay->state == REPLAY_STATE_DEAD) {
		goto out;
	}

	if (replay_desc_set_state(replay, REPLAY_STATE_DEAD)) {
		ret = -1;
		goto out;
	}

out:
	/*lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
	 * &replay->state_lock);*/
	mutex_unlock(&replay->state_lock);
	return ret;
}

static unsigned int hash64(loff_t val) {
	int ret;

	ret = hash(val >> 32);
	ret ^= hash(val & 0xFFFFFFFF);

	return ret;
}

static unsigned int hash(unsigned int a) {
	a = (a+0x7ed55d16) + (a<<12);
	a = (a^0xc761c23c) ^ (a>>19);
	a = (a+0x165667b1) + (a<<5);
	a = (a+0xd3a2646c) ^ (a<<9);
	a = (a+0xfd7046c5) + (a<<3);
	a = (a^0xb55a4f09) ^ (a>>16);
	return a;
}

/* This actually spawns off the process which the replay_desc represents */
/* NOTE XXX: Assumes replay->state_lock is held!!! */
static int replay_desc_start(struct replay_desc *replay) {
	int ret;
	char *argv[] = {REPLAY_RESUME_PROG, NULL, NULL};
	char arg1[REPLAYFS_LOG_DIRLEN + 1];
	unsigned int dir_hash;
	char *envp[] = {"HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL};

	ret = 0;

	/* Prepare our argument string */
	argv[1] = arg1;

	dir_hash = hash64(replay->unique_id);
	sprintf(argv[1], REPLAYFS_LOG_DIR "%016llX",
			(unsigned long long)replay->unique_id);

	/* Now launch the child's thread */
	debugk("%s %d: Launching a new replay process (id): %016llX\n", __func__,
			__LINE__, (unsigned long long)replay->unique_id);
	ret = call_usermodehelper(REPLAY_RESUME_PROG, argv, envp, UMH_WAIT_EXEC);

	debugk("%s %d: call_usermodehelper(%s, {%s, %s, %s}) returens %d\n", __func__, __LINE__,
			REPLAY_RESUME_PROG, argv[0], argv[1], argv[2], ret);

	BUG_ON(ret != 0);

	return ret;
}

/* 
 * This does the actual heavy lifting of the state switching, adjusts the state
 * and prepares the user-level thread to be suspended
 *
 * NOTE XXX: Assumes replay->state_lock is held!!!
 */
static int replay_desc_set_state(struct replay_desc *replay, int state) {
	/* First thing is first, see what state we are trying to set */
	int ret;
	ret = 0;
	switch (state) {
		case REPLAY_STATE_RUNNING:
			/* See if our replay process exists */
			if (replay->state == REPLAY_STATE_DEAD ||
					replay->state == REPLAY_STATE_DONE) {
				/* If so, we need to restart the process */
				ret = replay_desc_start(replay);
			/* Okay, we're not dead, lets just kick start the wait queue */
			} else {
				/* Make sure our state is updated */
				replay->state = REPLAY_STATE_RUNNING;
				/* Kick start the writer's waitq */
				wake_up_interruptible(&replay->writer_waitq);
			}
			break;
		case REPLAY_STATE_PAUSED:
			/* Make sure we're not dead... that would be bad */
			if (replay->state == REPLAY_STATE_DEAD) {
				ret = -1;
				goto out;
			}

			/* 
			 * Okay, we're still alive, our pause method is lazy, we tell it to stop
			 * at the next synchronization point (intercepted syscall)
			 */
			replay->state = REPLAY_STATE_PAUSED;

			break;
		case REPLAY_STATE_DONE:
			/* 
			 * All right, we don't want to waste cpu cycles fetching something we
			 * dont think we need.  Lets tell this thread its done
			 */
			replay->state = REPLAY_STATE_DONE;
			break;
		case REPLAY_STATE_DEAD:
			/* 
			 * The process must be killed externally, we're just updating the state
			 * here
			 */
			replay->state = REPLAY_STATE_DEAD;
			break;
	}

out:
	return ret;
}

static void replay_desc_state_update(struct replay_desc *replay) {
	int waited;
	/* Grab the state lock */

	lock_debugk("%s %d: %p: Read Locking %p\n", __func__, __LINE__, current, &replay->cache_lock);
	alloc_dump_stack();
	mutex_lock(&replay->cache_lock);
	/*lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&replay->state_lock);*/
	mutex_lock(&replay->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);

	waited = 1;
	while (waited) {
		waited = 0;

		if (replay->state == REPLAY_STATE_DEAD) {
			struct siginfo sinfo;
			memset(&sinfo, 0, sizeof(struct siginfo));
			sinfo.si_signo = SIGKILL;
			sinfo.si_code = SI_USER;

			send_sig_info(SIGKILL, &sinfo, current);
		}

		if (replay->state == REPLAY_STATE_RUNNING) {
			/* Check to see if we have hit our prefetch point */
			while (replay->max_sysnum >= replay->last_syscall) {
				/* Sleep until this is not true */
				/* 
				 * NOTE: I don't need to release the cache_lock because no one else can
				 * write to the data during this time
				 */
				waited = 1;
				debugk("%s %d: User level process sent last syscall (%lld) sleeping\n",
						__func__, __LINE__, replay->last_syscall);
				lock_debugk("%s %d: Read Unlocking %p\n", __func__, __LINE__, &replay->cache_lock);
				mutex_unlock(&replay->cache_lock);
				/*lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__,
						current, &replay->state_lock);*/
				mutex_unlock(&replay->state_lock);
				wait_event_interruptible(replay->writer_waitq,
						replay->max_sysnum < replay->last_syscall);
				lock_debugk("%s %d: Read Locking %p\n", __func__, __LINE__, &replay->cache_lock);
				mutex_lock(&replay->cache_lock);
				/*lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
						&replay->state_lock);*/
				mutex_lock(&replay->state_lock);
				lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);
				debugk("%s %d: User level woken to fetchwlast syscall (%lld)\n",
						__func__, __LINE__, replay->last_syscall);
			}
		}

		if (replay->state == REPLAY_STATE_PAUSED) {
				waited = 1;
				debugk("%s %d: User level process paused?\n", __func__, __LINE__);
				lock_debugk("%s %d: Read Unlocking %p\n", __func__, __LINE__, &replay->cache_lock);
				mutex_unlock(&replay->cache_lock);
				/*lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__,
						current, &replay->state_lock);*/
				mutex_unlock(&replay->state_lock);
				wait_event_interruptible(replay->writer_waitq,
						replay->state != REPLAY_STATE_PAUSED);
				lock_debugk("%s %d: Read Locking %p\n", __func__, __LINE__, &replay->cache_lock);
				mutex_lock(&replay->cache_lock);
				/*lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
						&replay->state_lock);*/
				mutex_lock(&replay->state_lock);
				lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);
		}
	}

	lock_debugk("%s %d: Read Unlocking %p\n", __func__, __LINE__, &replay->cache_lock);
	mutex_unlock(&replay->cache_lock);
	/*lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
			&replay->state_lock);*/
	mutex_unlock(&replay->state_lock);
}

/* Okay, a replay process had begun a new syscall, time to keep track of this */
/* 
 * Just like with the syscall_mods in the replayfs component, we will have a
 * fixed size data "entry" with a variable number of "mods" which will be
 * scanned in reverse order, to find the data written by this syscall
 */
int count2 = 0;
struct replay_desc_entry *replay_desc_add_next_entry(struct replay_desc *replay,
		loff_t sysnum) {
	struct replay_desc_entry *ret;
	loff_t entry_pos;
	loff_t page_of_entry;
	int offset_in_page;

	char *cbuf;

	debugk("%s %d: Replay is %p\n", __func__, __LINE__, replay);


	/* 
	 * First, lets check to make sure we haven't just overshot our desired
	 * distance 
	 */
	replay_desc_state_update(replay);
	debugk("%s %d: Replay is %p\n", __func__, __LINE__, replay);

	/* First, grab the lock */
	/* 
	 * NOTE: This is held through the entire writing process, it will be released
	 * in replay_desc_add_next_entry_done
	 */
	debugk("%s %d: Replay is %p\n", __func__, __LINE__, replay);
	count2++;
	lock_debugk("%s %d: Write Locking %p (count %d)\n", __func__, __LINE__,
			&replay->cache_lock, count2);

	mutex_lock(&replay->cache_lock);
	debugk("%s %d: Replay is %p\n", __func__, __LINE__, replay);

	/* 
	 * If this process respawned for some reason, we should ignore anything before
	 * our last syscall
	 */
	if (sysnum < replay->last_syscall) {
		lock_debugk("%s %d: Write Unlocking %p\n", __func__, __LINE__, &replay->cache_lock);
		mutex_unlock(&replay->cache_lock);
		return NULL;
	}

	/* Update our last syscall information */
	debugk("%s %d: desc (%p) got sysnum %lld\n", __func__, __LINE__, replay,
			sysnum);
	replay->last_syscall = sysnum;

	/* Now, check to see what our position is */
	entry_pos = replay->num_syscalls * sizeof(struct replay_desc_entry);

	/* Update our num_syscalls information */
	replay->num_syscalls++;

	page_of_entry = entry_pos / PAGE_SIZE;
	offset_in_page = entry_pos % PAGE_SIZE;

	/* Get the actual entry data */
	cbuf = ram_page_alloc_get_page(&replay->meta_cache, page_of_entry);

	ret = (struct replay_desc_entry *)(cbuf + offset_in_page);

	/* Initialize the replay_desc_entry from the replay_desc */

	ret->num_inodes = 0;
	ret->syscall_num = sysnum;
	ret->pos = entry_pos;

	return ret;
}

void replay_desc_add_next_entry_done(struct replay_desc *replay,
		struct replay_desc_entry *entry) {
	int offset_in_page;
	loff_t page_of_entry;

	char *page;

	offset_in_page = entry->pos % PAGE_SIZE;
	page_of_entry = entry->pos / PAGE_SIZE;

	page = (char *)entry;

	page -= offset_in_page;

	/* Return the page_alloc page */
	ram_page_alloc_put_page(&replay->meta_cache, page, page_of_entry);

	/* Finally, unlock the cache lock, we're done updating the cache */
	lock_debugk("%s %d: Write Unlocking %p\n", __func__, __LINE__, &replay->cache_lock);
	mutex_unlock(&replay->cache_lock);

	/* Wake up any waiting process */
	debugk("%s %d: Waking up the waiter of waitq (%p) last_syscall is %lld\n", __func__, __LINE__,
			&replay->waitq, replay->last_syscall);
	wake_up_interruptible(&replay->waitq);

	/* 
	 * Lets now make sure that we should keep running
	 */
	replay_desc_state_update(replay);
}


int replay_desc_add_mod(struct replay_desc *replay,
		struct replay_desc_inode_entry *inode, const void *data, loff_t offset,
		size_t size) {
	loff_t start_pos;
	loff_t mod_pos;
	loff_t page_of_mod;
	int offset_in_page;

	int nwritten;

	char *page;

	struct replay_desc_mod *mod;

	/* Allocate space for this mod */
	start_pos = replay->data_cache_pos;

	/* Figure out where our mod should go */
	/* NOTE: We align so we guarantee the mod is on one page */
	mod_pos = start_pos + size + sizeof(struct replay_desc_mod) - 1;
	mod_pos -= mod_pos % sizeof(struct replay_desc_mod);

	/* Get our mod */

	page_of_mod = mod_pos / PAGE_SIZE;
	offset_in_page = mod_pos % PAGE_SIZE;

	page = ram_page_alloc_get_page(&replay->data_cache, page_of_mod);

	mod = (struct replay_desc_mod *)(page + offset_in_page);

	debugk("%s %d: Adding mod with offset %lld size %d\n", __func__, __LINE__,
			offset, size);
	mod->size = size;
	mod->offset = offset;
	mod->prev_mod_pos = inode->last_mod_offs;

	/* Put the page */
	ram_page_alloc_put_page(&replay->data_cache, page, page_of_mod);

	/* Now, update the position pointers */
	inode->last_mod_offs = mod_pos;
	replay->data_cache_pos = mod_pos + sizeof(struct replay_desc_mod);

	/* Now fill in the data */
	mod_pos -= size;


	debugk("%s %d: Attempting to write data from %p into %p at offset %lld\n",
			__func__, __LINE__, &replay->data_cache, (void *)data, mod_pos);
	nwritten = ram_page_alloc_write(&replay->data_cache, (void *)data, mod_pos, size);
	BUG_ON(nwritten != size);

	inode->nmods++;

	return nwritten;
};

struct replay_desc_inode_entry *replay_desc_entry_add_inode(
		struct replay_desc *replay, struct replay_desc_entry *entry,
		struct replayfs_unique_id *id) {
	struct replay_desc_inode_entry *ret;

	BUG_ON(entry->num_inodes >= REPLAY_SYSCALL_MAX_INODES);

	ret = &entry->inodes[entry->num_inodes];

	entry->num_inodes++;

	memcpy(&ret->id, id, sizeof(struct replayfs_unique_id));
	ret->nmods = 0;

	ret->last_mod_offs = 0;

	return ret;
}

void replay_desc_state_init(struct replay_desc *desc,
		struct replay_desc_state *state) {
	/* First, find the syscall */
	state->entry_pos = desc->num_syscalls-1;
	state->entry = NULL;
	state->mod = NULL;
}

/*
 * NOTE: This function always returns with the read lock held... even in
 * failure..
 */
int replay_desc_state_set_info(struct replay_desc *desc, loff_t syscall,
		struct replayfs_unique_id *id, struct replay_desc_state *state) {
	loff_t page_of_entry;
	loff_t prev_page_of_entry;
	int offset_in_page;
	int i;

	char *page;
	struct replay_desc_entry *entry;
	int debug_cnt;

	lock_debugk("%s %d: Read Locking %p\n", __func__, __LINE__, &desc->cache_lock);
	mutex_lock(&desc->cache_lock);

	/* Make sure we have the data, if not, wait for it */
	debug_cnt = 0;
	while (desc->last_syscall < syscall) {
		/* Make sure we're going to fetch this syscall */
		if (desc->max_sysnum < syscall) {
			replay_desc_prefetch(desc, syscall);
		}
		if (debug_cnt < 10) {
			debugk("%s %d: Detected that we haven't read this syscall yet, sleeping (on %p).  last_syscall: %lld, desired syscall: %lld\n",
					__func__, __LINE__, &desc->waitq, desc->last_syscall, syscall);

			lock_debugk("%s %d: Read Unlocking %p\n", __func__, __LINE__, &desc->cache_lock);
		}
		mutex_unlock(&desc->cache_lock);
		wait_event_interruptible(desc->waitq,
				desc->last_syscall >= syscall);
		if (debug_cnt < 10) {
			lock_debugk("%s %d: Read Locking %p\n", __func__, __LINE__, &desc->cache_lock);
		}
		mutex_lock(&desc->cache_lock);

		if (debug_cnt < 10) {
			debugk("%s %d: Woken after receiving syscall %lld (expected %lld)\n",
					__func__, __LINE__, desc->last_syscall, syscall);
		}
		state->entry_pos = desc->num_syscalls-1;
		if (debug_cnt < 10) {
			debugk("%s %d: Setting state->entry_pos to %lld\n", __func__, __LINE__,
					state->entry_pos);
		}

		/* This prevents the kernel from deadlocking when I have a bug... */
		debug_cnt++;
		/*
		 * NOTE: This function always returns with the read lock held... even in
		 * failure..
		 */
		if (debug_cnt > 1000) {
			printk("%s %d: File {%lld} interrupted waiting on syscall %lld, from unique_id {%lld, %lld}, desc->lat_syscall is %lld\n",
					__func__, __LINE__, desc->unique_id, syscall, id->log_num,
					id->sys_num, desc->last_syscall);
			return -1;
		}
	}

	debugk("%s %d: w00t, finally made it past the desc->last_syscall < syscall wait loop!\n",
			__func__, __LINE__);


	if (state->entry != NULL) {
		prev_page_of_entry =
			(state->entry_pos * sizeof(struct replay_desc_entry)) / PAGE_SIZE;
		offset_in_page =
			(state->entry_pos * sizeof(struct replay_desc_entry)) % PAGE_SIZE;

		page = ((char *)state->entry) - offset_in_page;
	} else {
		prev_page_of_entry = -1;
		page = NULL;
	}

	state->entry = NULL;
	entry = NULL;


	debugk("%s %d: Scanning for entry, state->entry_pos is %lld\n",
			__func__, __LINE__, state->entry_pos);
	for (; state->entry_pos >= 0;
			state->entry_pos--) {
		int offset_in_page;

		/* Get the entry at this point */
		page_of_entry =
			(state->entry_pos * sizeof(struct replay_desc_entry)) / PAGE_SIZE;
		offset_in_page =
			(state->entry_pos * sizeof(struct replay_desc_entry)) % PAGE_SIZE;

		/* If we need a new page, get it */
		if (prev_page_of_entry != page_of_entry) {
			if (page != NULL) {
				ram_page_alloc_put_page(&desc->meta_cache, page, page_of_entry);
			}
			prev_page_of_entry = page_of_entry;
			page = ram_page_alloc_get_page(&desc->meta_cache, page_of_entry);
		}

		entry = (struct replay_desc_entry *)(page + offset_in_page);

		debugk("%s %d: Scanning for entry, entry->syscall_num is %lld, syscall is %lld\n",
				__func__, __LINE__, entry->syscall_num, syscall);

		if (entry->syscall_num == syscall) {
			state->entry = entry;
			break;
		}
	}

	BUG_ON(state->entry == NULL);

	for (i = 0; i < REPLAY_SYSCALL_MAX_INODES; i++) {
		if (replayfs_id_matches(&entry->inodes[i].id, id)) {
			state->inode = &entry->inodes[i];
			break;
		}
	}

	BUG_ON(i == REPLAY_SYSCALL_MAX_INODES);

	/* Set up our mod position */
	state->mod_num = state->inode->nmods-1;
	state->mod_offs = state->inode->last_mod_offs;

	page_of_entry = state->mod_offs / PAGE_SIZE;
	offset_in_page = state->mod_offs % PAGE_SIZE;

	page = ram_page_alloc_get_page(&desc->data_cache, page_of_entry);

	state->mod = (struct replay_desc_mod *)(page + offset_in_page);

	return 0;
}

/* Our state is no longer maintaining state... free up our state */
void replay_desc_state_destroy(struct replay_desc *replay,
		struct replay_desc_state *state) {
	char *page;
	loff_t page_of_entry;
	int offset_in_page;

	/* Free up the currently used entry */
	if (state->entry != NULL) {

		page_of_entry =
			(state->entry_pos * sizeof(struct replay_desc_entry)) / PAGE_SIZE;
		offset_in_page =
			(state->entry_pos * sizeof(struct replay_desc_entry)) % PAGE_SIZE;

		page = ((char *)state->entry) - offset_in_page;

		ram_page_alloc_put_page(&replay->meta_cache, page, page_of_entry);
	}

	if (state->mod) {
		page_of_entry = state->mod_offs / PAGE_SIZE;
		offset_in_page = state->mod_offs % PAGE_SIZE;

		page = ((char *)state->mod) - offset_in_page;

		ram_page_alloc_put_page(&replay->data_cache, page, page_of_entry);
	}

	lock_debugk("%s %d: Read Unlocking %p\n", __func__, __LINE__, &replay->cache_lock);
	mutex_unlock(&replay->cache_lock);
}

int replay_desc_state_next_mod(struct replay_desc *desc,
		struct replay_desc_state *state) {
	loff_t prev_page_of_mod;
	loff_t page_of_mod;
	int prev_offset_in_page;
	int offset_in_page;
	char *page;


	BUG_ON(state->mod_num < 0);

	prev_page_of_mod = state->mod_offs / PAGE_SIZE;
	prev_offset_in_page = state->mod_offs % PAGE_SIZE;

	state->mod_num--;
	state->mod_offs = state->mod->prev_mod_pos;

	page_of_mod = state->mod_offs / PAGE_SIZE;
	offset_in_page = state->mod_offs % PAGE_SIZE;


	page = ((char *)state->mod) - offset_in_page;

	if (page_of_mod != prev_page_of_mod) {
		ram_page_alloc_put_page(&desc->data_cache, page, prev_page_of_mod);

		page = ram_page_alloc_get_page(&desc->data_cache, page_of_mod);
	} else {
		page = ((char *)state->mod) - prev_offset_in_page;
	}

	state->mod = (struct replay_desc_mod *)(page +offset_in_page);

	return state->mod_num + 1;
}

int replay_desc_state_read_mod(struct replay_desc *desc,
		struct replay_desc_state *state, void *buff,
		loff_t offset, size_t size) {
	loff_t data_pos;
	int nread;

	BUG_ON(size > state->mod->size);

	/* Oh boy, this is the fun one, lets read our data out */
	/* NOTE: The state already has us reader-locked */
	data_pos = state->mod_offs - state->mod->size;

	/* Now figure out where to read in the data part... */
	BUG_ON(offset < state->mod->offset);
	debugk("%s %d: state->mod->offset is %lld\n", __func__, __LINE__, state->mod->offset);
	offset -= state->mod->offset;

	debugk("%s %d: Attempting to read data from %p into %p at offset %lld (%lld + %lld)\n",
			__func__, __LINE__, &desc->data_cache, buff, data_pos + offset, data_pos,
			offset);

	nread = ram_page_alloc_read(&desc->data_cache, buff, data_pos + offset, size);

	return nread;
}

