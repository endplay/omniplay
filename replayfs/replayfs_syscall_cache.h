#ifndef __REPLAYFS_SYSCALL_CACHE_H
#define __REPLAYFS_SYSCALL_CACHE_H

#include "replayfs_file_log.h"
#include "replayfs_pagealloc.h"
#include "replayfs_perftimer.h"

/* 
 * Caches partially read/written information from syscalls
 *    Each entry tagged with:
 *       <Channel ID, Version, Range>
 *
 * This cache stores information persistently to disk.
 *   On-disk storage scheme?
 *     Could use page_alloc (disk version)
 *
 * How to determine if entry is there?
 *   Bloom filter (written to disk)
 *     Tells if any data from {unique_id, version} is cached
 *     Can get index file, which tells where data is stored
 *
 * efficiently look up mostly read data?
 *   LRU -- Put before actual data, since it is mostly read, it may be read with
 *   data
 */

/* 4K entries of each... */
#define SYSCACHE_ENTRY_CACHE_SIZE (1<<12)
#define SYSCACHE_INDEX_CACHE_SIZE (1<<12)

#define SYSCACHE_MEMLEAK_CHECK

struct syscache_index_meta {
	struct replayfs_unique_id id;
	loff_t version;
};

struct syscache_index {
	struct mutex lock;

	atomic_t refcnt;

	int catalog_end_page;

	struct syscache_index_meta meta;

	struct replayfs_syscall_cache *cache;
	page_alloc_t meta_alloc;

	/* FIXME: This only works for one supported page */
	void *data_page;
	int data_page_dirty;
};

/* NOTE: Each file position entry may exist in exactly 1 cache entry */
struct replayfs_syscache_id {
	struct replayfs_unique_id id;
	loff_t version;
	loff_t pos;
};

struct replayfs_syscache_lru {
	struct replayfs_syscache_id next;
	struct replayfs_syscache_id prev;
};

struct replayfs_syscache_header {
	int valid;
	struct replayfs_syscache_id id;
	int lru_clock;
	/* lru_next is marked to invalid on eviction! */
	struct replayfs_syscache_lru lru;
	size_t size;
};

struct replayfs_syscache_entry {
	struct replayfs_syscache_header *header;
	int header_page_idx;

	int valid;

	atomic_t refcnt;

	/* location of the index pointing to this entry */
	struct syscache_index *index;

	page_alloc_t data;
};

struct replayfs_syscall_cache_meta {
	loff_t size;
	loff_t max_size;

	struct replayfs_syscache_id lru_next;
};

struct replayfs_syscall_cache {
	struct mutex lock;

	struct perftimer *iget_hash_timer;
	struct perftimer *iget_pagealloc_timer;
	struct perftimer *iget_read_timer;
	struct perftimer *iget_rest_timer;

	struct perftimer *get_iget_timer;
	struct perftimer *get_ifind_timer;

	struct replayfs_syscache_entry *entry_cache[SYSCACHE_ENTRY_CACHE_SIZE];
	struct syscache_index *index_cache[SYSCACHE_INDEX_CACHE_SIZE];

#ifdef SYSCACHE_MEMLEAK_CHECK
	struct kmem_cache *entry_alloc;
	struct kmem_cache *index_alloc;
#endif

	/* Data held persistently on disk */
	struct replayfs_syscall_cache_meta meta;
	/* Holds the info persistently */
	page_alloc_t meta_disk;
};

int replayfs_syscache_init(struct replayfs_syscall_cache *cache);
void replayfs_syscache_destroy(struct replayfs_syscall_cache *cache);

#define replayfs_syscache_id_copy(dest, src) \
	memcpy(dest, src, sizeof(struct replayfs_syscache_id))

static inline void replayfs_syscache_id_invalidate(
		struct replayfs_syscache_id *id) {
	id->pos = -1;
}

static inline int replayfs_syscache_id_is_valid(
		struct replayfs_syscache_id *id) {
	return id->pos != -1;
}

static inline void replayfs_syscache_lru_invalidate(
		struct replayfs_syscache_lru *lru) {
	replayfs_syscache_id_invalidate(&lru->next);
}

static inline int replayfs_syscache_lru_is_valid(
		struct replayfs_syscache_lru *lru) {
	return replayfs_syscache_id_is_valid(&lru->next);
}


/* 
 * Ensures the added data is within the cache (possibly merging entries) and
 * updates the LRU for that set of data
 */
int replayfs_syscache_add(struct replayfs_syscall_cache *cache,
		struct replayfs_syscache_id *id,
		size_t size, void *data);

/* offset is based on global start, not start of entry */
void replayfs_syscache_entry_read(struct replayfs_syscache_entry *entry,
		void *buff, loff_t offset, size_t size);

struct replayfs_syscache_entry *replayfs_syscache_get(
		struct replayfs_syscall_cache *cache, struct replayfs_syscache_id *id,
		size_t size);

struct replayfs_syscache_entry *replayfs_syscache_check(
		struct replayfs_syscall_cache *cache, struct replayfs_syscache_id *id,
		size_t size);

void replayfs_syscache_put(struct replayfs_syscall_cache *cache,
		struct replayfs_syscache_entry *entry);

static inline loff_t replayfs_syscache_entry_offset(
		struct replayfs_syscache_entry *entry) {
	loff_t pos;

	mutex_lock(&entry->index->cache->lock);
	pos = entry->header->id.pos;
	mutex_unlock(&entry->index->cache->lock);

	return pos;
}

static inline size_t replayfs_syscache_entry_size(
		struct replayfs_syscache_entry *entry) {
	size_t size;

	mutex_lock(&entry->index->cache->lock);
	size = entry->header->size;
	mutex_unlock(&entry->index->cache->lock);

	return size;
}

#endif
