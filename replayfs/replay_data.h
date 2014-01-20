#ifndef __REPLAY_DATA_H
#define __REPLAY_DATA_H

#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <asm/atomic.h>

#include "replayfs_file_log.h"
#include "replayfs_pagealloc.h"

#define REPLAY_STATE_PAUSED 0
#define REPLAY_STATE_RUNNING 1
#define REPLAY_STATE_DONE 2
#define REPLAY_STATE_DEAD 3

struct replay_desc {
	/* Only assigned on creation (no lock needed) */
	loff_t unique_id;

	atomic_t ref_cnt;

	/* To allow maximum concurrency to cache accesses */
	struct mutex cache_lock;

	/* Tells how many syscalls have been recorded */
	/* Protected by cache_lock */
	loff_t num_syscalls;

	/* Last recorded syscall (non-recorded syscalls not counted) */
	/* Protected by cache_lock */
	loff_t last_syscall;

	/* Current index within the data_cache, all data below that point is in use */
	loff_t data_cache_pos;

	struct ram_page_alloc meta_cache;
	struct ram_page_alloc data_cache;

	/* Protects all state (fields below this point) */
	struct mutex state_lock;
	/* Waitq for the reading therad */
	wait_queue_head_t waitq;
	/* Waitq for the writing thread */
	wait_queue_head_t writer_waitq;
	int state;

	/* Will run to max_sysnum, then pause */
	loff_t max_sysnum;
};

/* The most inodes a syscall can modify */
#define REPLAY_SYSCALL_MAX_INODES 4

struct replay_desc_mod {
	loff_t offset;
	size_t size;

	loff_t prev_mod_pos;
/* Aligned for easy access */
} __attribute__(( aligned(32) ));

struct replay_desc_inode_entry {
	/* Unique identifier of the inode modified */
	struct replayfs_unique_id id;

	/* Number of modifiers on the syscall */
	int nmods;

	/* Pointer to the last modifier (within the data section) */
	loff_t last_mod_offs;
};

/* Represents the (meta) data written by one syscall */
struct replay_desc_entry {
	int num_inodes;

	loff_t syscall_num;
	loff_t pos;

	/* An entry per inode potentially modified by this syscall */
	struct replay_desc_inode_entry inodes[REPLAY_SYSCALL_MAX_INODES];
/*
 * NOTE: This is aligned for ease fitting into a page, and allocating within a
 * page 
 */
} __attribute__(( aligned(128) ));

struct replay_desc_state {
	struct replay_desc_entry *entry;
	loff_t entry_pos;

	struct replay_desc_inode_entry *inode;

	struct replay_desc_mod *mod;
	loff_t mod_offs;
	int mod_num;
};

#define REPLAY_DESC_CACHE_SIZE 0x1000

struct replay_desc_cache {
	struct mutex lock;
	struct replay_desc *cache[REPLAY_DESC_CACHE_SIZE];
};

/* Global init/destructors */
int replay_cache_init(void);
void replay_cache_destroy(void);

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

