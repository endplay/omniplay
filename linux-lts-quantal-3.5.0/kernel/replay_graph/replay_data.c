#include "replay_data.h"
#include "replayfs_filemap.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/signal.h>
#include <linux/slab.h>

#include <linux/replay.h>

//#define REPLAY_DATA_DEBUG
/* #define REPLAY_DATA_ALLOC_DEBUG */
/*#define REPLAY_DATA_LOCK_DEBUG*/

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

/* FIXME: Ugh... figure this out... */
/*
 * TODO: From Mike, learn how to start a replay pragmatically inside the kernel
 */
#define REPLAY_RESUME_PROG "/home/ddevec/omniplay/test/resume"
#define REPLAYFS_LOG_DIR "/replay_logdb/"

/* strlen + _ + "8digithex" + _ + "16digithex" */
#define REPLAYFS_LOG_DIRLEN strlen(REPLAYFS_LOG_DIR)+8+16+2

static struct replay_desc_cache cache;

static int replay_desc_set_state(struct replay_desc *replay, int state);
static void replay_desc_state_update(struct replay_desc *replay);
static unsigned int hash(unsigned int a);
static unsigned int hash64(loff_t val);

int replay_desc_kill(struct replay_desc *replay);

int replay_cache_init(void) {
	int rc;

	rc = btree_init(&cache.descs);
		
	if (rc) {
		return rc;
	}

	mutex_init(&cache.lock);

	INIT_LIST_HEAD(&cache.lru);

	return 0;
}

void replay_cache_destroy(void) {
	btree_destroy(&cache.descs);

	mutex_destroy(&cache.lock);

}

/* XXX NOTE: cache.lock must be held! */
void replay_desc_destroy(struct replay_desc *replay);
static struct replay_desc *replay_desc_init(loff_t replay_unique_id) {
	struct replay_desc *ret;
	int rc;

	ret = kmalloc(sizeof(struct replay_desc), GFP_NOFS);
	if (ret == NULL) {
		ret = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* Initialize the descriptor */
	debugk("%s %d: Creating process with unique_id of %lld\n", __func__, __LINE__, replay_unique_id);
	ret->unique_id = replay_unique_id;

	ret->this = NULL;

	/* Ref this entry, as its currently held in the cache */
	atomic_set(&ret->ref_cnt, 2);

	/* Initialize our mutexes */
	mutex_init(&ret->state_lock);

	/* Initialize our wait queues */
	init_waitqueue_head(&ret->waitq);
	init_waitqueue_head(&ret->writer_waitq);

	INIT_LIST_HEAD(&ret->waiting_syscalls);

	/* Set the state to done */
	ret->state = REPLAY_STATE_DONE;

	/* Say we have never read a syscall */
	ret->last_syscall = -1;
	ret->max_sysnum = -1;

	/* Add the entry to the cache for use */
	rc = btree_insert(&cache.descs, &btree_geo64, (unsigned long *)&replay_unique_id, ret, GFP_NOFS);

	if (rc) {
		replay_desc_destroy(ret);
		ret = ERR_PTR(rc);
	}

out:
	return ret;
}

/* XXX NOTE: Assumes the replay is already removed from the cache!!! */
void replay_desc_destroy(struct replay_desc *replay) {

	/* First, kill the replay process */
	replay_desc_kill(replay);
	replay_desc_state_update(replay);

	/* Free the strucutre, and be done with it */
	kfree(replay);
}

struct replay_desc *replay_cache_get(loff_t replay_unique_id) {
	struct replay_desc *replay;

	/* Must lock through the entire function to make the insertion atomic */
	mutex_lock(&cache.lock);

	/* See if we already have this entry cached */
	replay = btree_lookup(&cache.descs, &btree_geo64, (unsigned long *)&replay_unique_id);

	if (replay != NULL) {
		/* We still need to increment the ref count */
		atomic_inc(&replay->ref_cnt);

		goto out;
	}

	/* If the replay didn't exist, lets make one */
	/* 
	 * NOTE: replay_desc_init() will insert into the cache, and handle
	 * ref_counting (and clocking and evictions...)
	 */
	replay = replay_desc_init(replay_unique_id);

out:
	alloc_debugk("%s %d: Get called on replay_desc %p, count is %d\n", __func__,
			__LINE__, replay, atomic_read(&replay->ref_cnt));
	alloc_dump_stack();

	mutex_unlock(&cache.lock);
	return replay;
}

void replay_cache_put(struct replay_desc *replay) {
	/* Decrement the refcount */
	alloc_debugk("%s %d: Put called on replay_desc %p, count (after dec) is %d\n", __func__,
			__LINE__, replay, atomic_read(&replay->ref_cnt)-1);
	alloc_dump_stack();

	if (atomic_dec_and_test(&replay->ref_cnt)) {
		/* We are no longer in use! */
		replay_desc_destroy(replay);
	}
}


int replay_desc_prefetch(struct replay_desc *replay, loff_t prefetch_sysnum) {
	int ret = 0;

	lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&replay->state_lock);
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
	lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
	 &replay->state_lock);
	mutex_unlock(&replay->state_lock);
	return ret;
}

/* Force the pid pointed to by replay onto a wait list */
int replay_desc_pause(struct replay_desc *replay) {
	int ret;

	ret = 0;
	lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&replay->state_lock);
	mutex_lock(&replay->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);

	if (replay->state == REPLAY_STATE_PAUSED) {
		goto out;
	}

	/* Actually manage setting the state */
	replay_desc_set_state(replay, REPLAY_STATE_PAUSED);

out:
	lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
	 &replay->state_lock);
	mutex_unlock(&replay->state_lock);
	return ret;
}

/* Remove the pid pointed to by replay from our wait list */
int replay_desc_resume(struct replay_desc *replay) {
	int ret;

	ret = 0;
	lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&replay->state_lock);
	mutex_lock(&replay->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);

	if (replay->state == REPLAY_STATE_RUNNING) {
		goto out;
	}

	/* Actually manage setting the state */
	replay_desc_set_state(replay, REPLAY_STATE_RUNNING);

out:
	lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
	  &replay->state_lock);
	mutex_unlock(&replay->state_lock);
	return ret;
}

/* Kills the replaying process, does not delete the desc */
int replay_desc_kill_nolock(struct replay_desc *replay) {
	int ret;

	ret = 0;

	if (replay->state == REPLAY_STATE_DEAD) {
		goto out;
	}

	if (replay_desc_set_state(replay, REPLAY_STATE_DEAD)) {
		ret = -1;
		goto out;
	}

out:
	return ret;
}

/* Kills the replaying process, does not delete the desc */
int replay_desc_kill(struct replay_desc *replay) {
	int ret;


	lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&replay->state_lock);
	mutex_lock(&replay->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);
	ret = replay_desc_kill_nolock(replay);
	lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
		&replay->state_lock);
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
	sprintf(argv[1], REPLAYFS_LOG_DIR "rec_%lld",
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

static void replay_desc_state_update_nolock(struct replay_desc *replay) {
	int waited;

	waited = 1;
	while (waited) {
		waited = 0;

		if (replay->state == REPLAY_STATE_DEAD) {
			int rc;
			struct siginfo sinfo;
			memset(&sinfo, 0, sizeof(struct siginfo));
			if (replay->this != NULL) {
				DECLARE_WAIT_QUEUE_HEAD(q);
				sinfo.si_signo = SIGKILL;
				sinfo.si_code = SI_USER;

				debugk("%s %d: Sening SIGKILL to %p\n", __func__, __LINE__,
						replay->this);
				send_sig_info(SIGKILL, &sinfo, replay->this);

				/* Hacky wait queue which doesn't really work */
				do {
					if (task_is_dead(replay->this)) {
						break;
					}

					lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__,
							current, &replay->state_lock);
					mutex_unlock(&replay->state_lock);
					rc = wait_event_interruptible_timeout(q, task_is_dead(replay->this),
							msecs_to_jiffies(100));
					lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
							&replay->state_lock);
					mutex_lock(&replay->state_lock);
					lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);
				} while (rc == 0);

				put_task_struct(replay->this);
				replay->this = NULL;
			}
		}

		if (replay->state == REPLAY_STATE_RUNNING) {
			/* Check to see if we have hit our prefetch point */
			while (replay->max_sysnum >= replay->last_syscall) {
				/* Sleep until this is not true */
				waited = 1;
				debugk("%s %d: User level process sent last syscall (%lld) sleeping\n",
						__func__, __LINE__, replay->last_syscall);
				lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__,
						current, &replay->state_lock);
				mutex_unlock(&replay->state_lock);
				wait_event_interruptible(replay->writer_waitq,
						replay->max_sysnum < replay->last_syscall);
				lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
						&replay->state_lock);
				mutex_lock(&replay->state_lock);
				lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);
				debugk("%s %d: User level woken to fetchwlast syscall (%lld)\n",
						__func__, __LINE__, replay->last_syscall);
			}
		}

		if (replay->state == REPLAY_STATE_PAUSED) {
				waited = 1;
				debugk("%s %d: User level process paused?\n", __func__, __LINE__);
				lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__,
						current, &replay->state_lock);
				mutex_unlock(&replay->state_lock);
				wait_event_interruptible(replay->writer_waitq,
						replay->state != REPLAY_STATE_PAUSED);
				lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
						&replay->state_lock);
				mutex_lock(&replay->state_lock);
				lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);
		}
	}
}

static void replay_desc_state_update(struct replay_desc *replay) {

	/* Grab the state lock */

	lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&replay->state_lock);
	mutex_lock(&replay->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);

	replay_desc_state_update_nolock(replay);

	lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
			&replay->state_lock);
	mutex_unlock(&replay->state_lock);
}

static int check_desc_for_data_atomic(struct replay_desc *desc, loff_t unique_id, char mod) {
	int ret;
	mutex_lock(&desc->state_lock);
	debugk("%s %d: desc->last_syscall is %lld, unique_id is %lld\n", __func__,
			__LINE__, desc->last_syscall, unique_id);
	debugk("%s %d: desc->last_mod is %d, mod is %d\n", __func__, __LINE__,
			desc->last_mod, mod);
	ret = (desc->last_syscall > unique_id || 
				(desc->last_syscall == unique_id && desc->last_mod >= mod)
			);
	mutex_unlock(&desc->state_lock);
	debugk("%s %d: Ret is %d\n", __func__, __LINE__, ret);
	return ret;
}

loff_t replay_data_get(
		struct replayfs_syscall_cache *cache, loff_t unique_id, loff_t sysnum,
		char mod) {
	loff_t ret;
	struct waiting_syscall this_syscall;
	struct replay_desc *desc;

	int rc;

	debugk("%s %d: In %s!\n", __func__, __LINE__, __func__);
	/* First thing, get the desc of this id */
	desc = replay_cache_get(unique_id);
	if (IS_ERR(desc)) {
		return PTR_ERR(desc);
	}

	lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&desc->state_lock);
	mutex_lock(&desc->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);

	debugk("%s %d: Updating sysnum\n", __func__, __LINE__);
	if (desc->max_sysnum < sysnum) {
		desc->max_sysnum = sysnum;
	}

	this_syscall.sysnum = sysnum;
	this_syscall.mod = mod;
	this_syscall.entry_pos = 0;

	debugk("%s %d: Adding syscall to list %p {%p, %p}\n", __func__, __LINE__,
			desc, desc->waiting_syscalls.prev, desc->waiting_syscalls.next);
	if (list_empty(&desc->waiting_syscalls)) {
		debugk("%s %d: Desc->waiting_syscalls is empty\n", __func__, __LINE__);
		list_add(&this_syscall.list, &desc->waiting_syscalls);
	} else {
		struct waiting_syscall *wait;
		debugk("%s %d: Desc->waiting_syscalls not empty\n", __func__, __LINE__);
		list_for_each_entry(wait, &desc->waiting_syscalls, list) {
			debugk("%s %d: wait is %p\n", __func__, __LINE__, wait);
			if (wait->sysnum > sysnum) {
				list_add_tail(&wait->list, &this_syscall.list);
				break;
			} else if (wait->sysnum == sysnum) {
				if (wait->mod > mod) {
					list_add_tail(&wait->list, &this_syscall.list);
					break;
				}
			}
		}
	}

	/* Now, if the desc is past our sysnum (or not running), reset it */
	if (desc->state != REPLAY_STATE_RUNNING || desc->last_syscall == -1 || desc->last_syscall >= sysnum) {
		debugk("%s %d: Resetting desc!\n", __func__, __LINE__);
		replay_desc_kill_nolock(desc);
		replay_desc_state_update_nolock(desc);

		desc->last_syscall = 0;

		replay_desc_start(desc);
	}

	lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
	 &desc->state_lock);
	mutex_unlock(&desc->state_lock);

	/* Wait for desc */
	debugk("%s %d: Waiting for syscall\n", __func__, __LINE__);
	rc = 1;
	do {
		debugk("%s %d: Waiting on %p\n", __func__, __LINE__, desc);
		rc = wait_event_interruptible(desc->waitq, check_desc_for_data_atomic(desc, sysnum, mod));
		/*
		rc = wait_event_timeout(desc->waitq, check_desc_for_data_atomic(desc,
					sysnum, mod), msecs_to_jiffies(10000));
					*/

		if (rc == -ERESTARTSYS) {
			printk("%s %d: INTERRUPT waiting for syscall %lld.  Desc is at %lld\n", __func__,
					__LINE__, sysnum, desc->last_syscall);
			mutex_lock(&desc->state_lock);
			if (this_syscall.entry_pos != 0) {
				lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
				 &desc->state_lock);
				mutex_unlock(&desc->state_lock);
			} else {
				list_del(&this_syscall.list);
				lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
				 &desc->state_lock);
				mutex_unlock(&desc->state_lock);
			}
			ret = rc;
			goto out;
		}
	} while (rc);
	debugk("%s %d: Woot!! got syscall\n", __func__, __LINE__);


	lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&desc->state_lock);
	mutex_lock(&desc->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);
	/* 
	 * The replaying thread populated the entry field when it filled the cache
	 * with the data.  Woot. (This is refcnt'd and needs to be dec'd later, but it
	 * was inc'd by the filling process.)
	 */
	ret = this_syscall.entry_pos;

	lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
	 &desc->state_lock);
	mutex_unlock(&desc->state_lock);

out:
	replay_cache_put(desc);
	debugk("%s %d: Return %lld\n", __func__, __LINE__, ret);
	return ret;
}

void replay_put_data(loff_t unique_id, loff_t sysnum, int mod,
		loff_t entry_pos) {
	struct replay_desc *desc;
	struct waiting_syscall *waiting;

	debugk("%s %d: In %s!\n", __func__, __LINE__, __func__);

	desc = replay_cache_get(unique_id);

	if (desc->this == NULL) {
		get_task_struct(current);
		desc->this = current;
	}

	lock_debugk("%s %d: %p: Mutex Locking %p\n", __func__, __LINE__, current,
			&desc->state_lock);
	mutex_lock(&desc->state_lock);
	lock_debugk("%s %d: %p: Locked\n", __func__, __LINE__, current);

	if (desc->last_syscall != sysnum) {
		desc->last_mod = 0;
	} else {
		BUG_ON(desc->last_mod == 255);
		desc->last_mod++;
	}

	desc->last_syscall = sysnum;

	/* Remove all satisfied waiting entries */
	do {
		if (list_empty(&desc->waiting_syscalls)) {
			break;
		}

		debugk("%s %d: Wait Loop itr!!\n", __func__, __LINE__);

		waiting =
			list_first_entry(&desc->waiting_syscalls, struct waiting_syscall, list);
		debugk("%s %d: --------------- Have syscall {%lld, %d}, waiting is {%lld, %d}\n",
				__func__, __LINE__, sysnum, mod, (long long int)waiting->sysnum, waiting->mod);

		BUG_ON(desc->state != REPLAY_STATE_DEAD && (waiting->sysnum < sysnum || 
				(waiting->sysnum == sysnum && waiting->mod < mod)));

		/* Update the waiting entry, and remove it from the waiting list */
		if (waiting->sysnum == sysnum && waiting->mod == mod) {
			debugk("%s %d: Removing waiting from the list\n", __func__, __LINE__);
			list_del(&waiting->list);

			/* Update entry's refcnt */
			//syscache_entry_ref(entry);

			debugk("%s %d: Updating waiting (%p) to have entry %lld\n", __func__,
					__LINE__, waiting, entry_pos);
			waiting->entry_pos = entry_pos;
		}
	} while (waiting->sysnum == sysnum && waiting->mod == mod);

	//wake_up_interruptible_all(&desc->waitq);
	debugk("%s %d: Waking up %p\n", __func__, __LINE__, desc);
	wake_up_all(&desc->waitq);

	lock_debugk("%s %d: %p: Mutex Unlocking %p\n", __func__, __LINE__, current,
	 &desc->state_lock);
	mutex_unlock(&desc->state_lock);

	debugk("%s %d: cache_put!!\n", __func__, __LINE__);
	replay_cache_put(desc);
}

