#ifndef __REPLAY_DATA_H
#define __REPLAY_DATA_H

#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/btree.h>
#include <asm/atomic.h>

#include "replayfs_filemap.h"
#include "replayfs_syscall_cache.h"

#define REPLAY_STATE_PAUSED 0
#define REPLAY_STATE_RUNNING 1
#define REPLAY_STATE_DONE 2
#define REPLAY_STATE_DEAD 3

struct replay_desc_cache {
	struct mutex lock;

	struct btree_head descs;

	struct list_head lru;
};

struct waiting_syscall {
	struct list_head list;
	loff_t sysnum : 56;
	loff_t mod : 8;
	loff_t entry_pos;
};

struct replay_desc {
	/* Managed by the replay_data struct, lru list */
	struct list_head lru;

	/* Only assigned on creation (no lock needed) */
	loff_t unique_id;

	struct task_struct *this;

	atomic_t ref_cnt;

	/* Protects all state (fields below this point) */
	struct mutex state_lock;

	struct list_head waiting_syscalls;

	/* Last recorded syscall (non-recorded syscalls not counted) */
	/* Protected by cache_lock */
	loff_t last_syscall;
	int last_mod;

	/* Waitq for the reading therad */
	wait_queue_head_t waitq;
	/* Waitq for the writing thread */
	wait_queue_head_t writer_waitq;
	int state;

	/* Will run to max_sysnum, then pause */
	loff_t max_sysnum;
};

/* 
 * Idea: Organize desc's into b-tree (refcnt'd)
 *
 * Have a function to fetch data from a single syscall
 *   By default on replay, syscalls put data into cache
 *   The function's job is to check cache, then request data from syscall
 */

/* Global init/destructors */
int replay_cache_init(void);
void replay_cache_destroy(void);

/* 
 * NOTE: The syscache lock must be held for this. (it should only be called from
 * the syscache, when filling an empty request, to remove the race where the
 * syscall is evicted from the cache before it is read by the requester). 
 *
 * NOTE: It is the responsibility of the caller to put the reference when done!
 */
loff_t replay_data_get(
		struct replayfs_syscall_cache *cache, loff_t unique_id,
		loff_t sysnum, char mod);

void replay_put_data(loff_t unique_id, loff_t sysnum, int mod,
		loff_t entry_pos);

#if 0
/* Functions used by both kernel FS and replaying process */
struct replay_desc *replay_cache_get(loff_t replay_unique_id);
void replay_cache_put(struct replay_desc *replay);

/* Interface from kernal FS into replay_desc */
int replay_desc_prefetch(struct replay_desc *replay, loff_t prefetch_sysnum);
int replay_desc_pause(struct replay_desc *replay);
int replay_desc_resume(struct replay_desc *replay);

void replay_desc_state_init(struct replay_desc *desc,
		struct replay_desc_state *state);

int replay_desc_state_set_info(struct replay_desc *desc, loff_t syscall,
		struct replayfs_unique_id *id, struct replay_desc_state *state);

void replay_desc_state_destroy(struct replay_desc *desc,
		struct replay_desc_state *state);

int replay_desc_state_next_mod(struct replay_desc *desc,
		struct replay_desc_state *state);
int replay_desc_state_read_mod(struct replay_desc *desc,
		struct replay_desc_state *state, void *buff,
		loff_t offset, size_t size);

/* Kills the replaying process, does not delete (or dereference) the desc */
int replay_desc_kill(struct replay_desc *replay);

/* Interface from replaying process into replay_desc */
struct replay_desc_entry *replay_desc_add_next_entry(struct replay_desc *replay,
		loff_t sysnum);
void replay_desc_add_next_entry_done(struct replay_desc *replay, struct
		replay_desc_entry *);

struct replay_desc_inode_entry *replay_desc_entry_add_inode(struct replay_desc *,
		struct replay_desc_entry *, struct replayfs_unique_id *id);

int replay_desc_add_mod(struct replay_desc *replay,
		struct replay_desc_inode_entry *inode, const void *data, loff_t offset,
		size_t size);
#endif

#endif

