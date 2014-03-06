#ifndef __REPLAYFS_SYSCALL_CACHE_H
#define __REPLAYFS_SYSCALL_CACHE_H

#include <linux/btree.h>

#include <linux/replay.h>
#include <linux/fs.h>
//#include "replayfs_filemap.h"
#include "replayfs_btree128.h"
#include "replayfs_diskalloc.h"

/* 
 * Cache of replay mods, indexed by <log_id (64), sysnum(56), modnum(8)> (128 bits)
 *
 * Cache consists of btree, mapping index to data chunk.
 */

#define is_replay() (current->replay_thrd)
# define is_record() (current->record_thrd)

#define SYSCACHE_MEMLEAK_CHECK

struct replayfs_syscache_id {
	loff_t unique_id : 48;
	loff_t pid : 16;
	loff_t sysnum : 64;
} __attribute__((aligned(16)));

static inline struct replayfs_btree128_key *k(struct replayfs_syscache_id *id) {
	return ((struct replayfs_btree128_key *)id);
}

static inline u64 k1(struct replayfs_syscache_id *id) {
	u64 ret;
	//printk("K1, 1: id->unique_id is %lld\n", (long long int)id->unique_id);
	ret = id->unique_id;
	//printk("K1, 2: ret pre shift is %llu\n", ret);
	/*
	ret <<= 16;
	printk("K1, 2: ret post shift is %llu\n", ret);
	ret |= id->pid;
	*/
	//printk("K1, 2: ret post or is %llu\n", ret);
	return ret;
}

static inline u64 k2(struct replayfs_syscache_id *id) {
	u64 ret;
	ret = id->sysnum;
	return ret;
}

struct replayfs_syscall_cache {
	struct mutex lock;

	struct replayfs_syscache_id lru_start;

	struct replayfs_diskalloc *allocator;
	struct replayfs_btree128_head entries;

#ifdef SYSCACHE_MEMLEAK_CHECK
	atomic_t nallocs;
	atomic_t nfrees;
#endif
};

struct replayfs_syscache_entry {
	struct replayfs_syscache_id lru_prev;
	struct replayfs_syscache_id lru_next;
	int clock;

	char data[0];
};

int replayfs_syscache_init(struct replayfs_syscall_cache *cache, struct
		replayfs_diskalloc *allocator, loff_t meta_pos, int needs_init);
void replayfs_syscache_destroy(struct replayfs_syscall_cache *cache);

int replayfs_syscache_add(struct replayfs_syscall_cache *cache,
		struct replayfs_syscache_id *id, size_t size, const void *data);

loff_t replayfs_syscache_get(
		struct replayfs_syscall_cache *cache, struct replayfs_syscache_id *id);

void replayfs_syscache_put(struct replayfs_syscall_cache *cache,
		loff_t pos);

#endif

