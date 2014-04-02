#include "replayfs_syscall_cache.h"
#include "replay_data.h"

#include "replayfs_btree.h"

#include <linux/slab.h>

//#define REPLAYFS_SYSCACHE_DEBUG
/*#define REPLAYFS_SYSCACHE_LOCK_DEBUG*/
/*#define REPLAYFS_SYSCACHE_ALLOC_DEBUG*/
/*#define REPLAYFS_SYSCACHE_ALLOC_REFCNT_DEBUG*/

#ifdef REPLAYFS_SYSCACHE_DEBUG
#  define debugk(...) printk(__VA_ARGS__)
#else
#  define debugk(...)
#endif

#ifdef REPLAYFS_SYSCACHE_LOCK_DEBUG
#  define lock_debugk(...) printk(__VA_ARGS__)
#else
#  define lock_debugk(...)
#endif

#ifdef REPLAYFS_SYSCACHE_ALLOC_DEBUG
#  define alloc_debugk(...) printk(__VA_ARGS__)
#  ifdef REPLAYFS_SYSCACHE_ALLOC_REFCNT_DEBUG
#    define alloc_refcnt_debugk(...) printk(__VA_ARGS__)
#  else
#    define alloc_refcnt_debugk(...)
#  endif
#else
#  define alloc_debugk(...)
#  define alloc_refcnt_debugk(...)
#endif

#ifdef REPLAYFS_SYSCACHE_ALLOC_REFCNT_DEBUG
void print_entry_cache(struct replayfs_syscall_cache *cache) {
}
#else
#  define print_entry_cache(...) 
#endif

#ifdef SYSCACHE_MEMLEAK_CHECK
#define CACHE_ALLOC(X) atomic_inc(&X->nallocs)
#define CACHE_FREE(X) atomic_inc(&X->nfrees)
#else
#define CACHE_ALLOC(X)
#define CACHE_FREE(X)
#endif

static void replayfs_syscache_entry_destroy(struct replayfs_syscache_entry *entry) {
	kfree(entry);
}

void replayfs_syscache_entry_put(struct replayfs_syscache_entry *entry) {
	alloc_refcnt_debugk("%s %d: entry is %p, refcnt is %d\n", __func__, __LINE__, entry,
			atomic_read(&entry->refcnt)-1);
	print_entry_cache(entry->index->cache);
	//if (atomic_dec_and_test(&entry->refcnt)) {
		replayfs_syscache_entry_destroy(entry);
	//}
}

int replayfs_syscache_init(struct replayfs_syscall_cache *cache,
		struct replayfs_diskalloc *allocator,
		loff_t meta_pos, int needs_init) {
	int rc;

	BUILD_BUG_ON(sizeof(struct replayfs_syscache_id) != 16);

	mutex_init(&cache->lock);

	debugk("%s %d: Initializing cache %p\n", __func__, __LINE__, cache);

	cache->allocator = allocator;
	debugk("%s %d: set allocator to %p\n", __func__, __LINE__, cache->allocator);

	if (needs_init) {
		debugk("%s %d: REPLAYFS_BTREE128 CREATE BEING CALLED!!!\n", __func__,
				__LINE__);
		printk("%s %d: Doing btree128 create on %p, %lld\n", __func__, __LINE__,
				&cache->entries, meta_pos);
		rc = replayfs_btree128_create(&cache->entries, allocator, meta_pos);
	} else {
		debugk("%s %d: Doing btree128 init\n", __func__, __LINE__);
		rc = replayfs_btree128_init(&cache->entries, allocator, meta_pos);
	}

	if (rc) {
		return rc;
	}

	lock_debugk("%s %d: Process %p: Cache is %p\n", __func__, __LINE__, current,
			cache);

#ifdef SYSCACHE_MEMLEAK_CHECK
	atomic_set(&cache->nallocs, 0);
	atomic_set(&cache->nfrees, 0);
#endif

	return 0;
}

void replayfs_syscache_destroy(struct replayfs_syscall_cache *cache) {

	debugk("%s %d: Freeing cache %p\n", __func__, __LINE__, cache);

	replayfs_btree128_destroy(&cache->entries);

#ifdef SYSCACHE_MEMLEAK_CHECK
	alloc_debugk("%s %d: Comparing nallocs (%d) to nfrees (%d)\n", __func__, __LINE__,
			atomic_read(&cache->nallocs), atomic_read(&cache->nfrees));
	BUG_ON(atomic_read(&cache->nallocs) != atomic_read(&cache->nfrees));
#endif
}

int replayfs_syscache_add(struct replayfs_syscall_cache *cache,
		struct replayfs_syscache_id *id, size_t size, const void *data) {
	int ret;
	struct replayfs_syscache_entry entry;
	struct replayfs_btree128_value *value;
	struct replayfs_btree128_value val;
	struct page *ret_page;
	ret = 0;

	btree_check();
	debugk("%s %d: In %s\n", __func__, __LINE__, __func__);
	mutex_lock(&cache->lock);
	/* Try to lookup first... to make sure the entry doesn't exist */
	debugk("%s %d: Looking up id {%lld, %d, %lld}\n", __func__, __LINE__,
			(loff_t)id->unique_id, id->pid, (loff_t)id->sysnum);
	btree_check();
	value = replayfs_btree128_lookup(&cache->entries, k(id), &ret_page);
	debugk("%s %d: got valid entry %p\n", __func__, __LINE__, value);
	if (value == NULL) {
		struct replayfs_disk_alloc *alloc;
	btree_check();

		debugk("%s %d: diskalloc, alloc\n", __func__, __LINE__);
		alloc = replayfs_diskalloc_alloc(cache->allocator,
				sizeof(struct replayfs_syscache_entry) + size);
		debugk("%s %d: diskalloc, alloc return\n", __func__, __LINE__);
		//entry = kmalloc(sizeof(struct replayfs_syscache_entry) + size, GFP_NOFS);
	btree_check();

		if (alloc == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		entry.clock = 0;
	btree_check();

		/* Record the entry state */
		debugk("%s %d: diskalloc, write\n", __func__, __LINE__);
		if (replayfs_disk_alloc_write(alloc, &entry,
				sizeof(struct replayfs_syscache_entry), 0, 0)) {
			BUG();
		}
		debugk("%s %d: diskalloc, write2\n", __func__, __LINE__);
	btree_check();
		/* Record the entry data */
		if (replayfs_disk_alloc_write(alloc, (void *)data, size,
				sizeof(struct replayfs_syscache_entry), 0)) {
			BUG();
		}
		debugk("%s %d: diskalloc, write2 return\n", __func__, __LINE__);
		val.id = replayfs_disk_alloc_pos(alloc);
	btree_check();

		debugk("%s %d: !!!!!!!!!!!!!!!!!!!!!!!Inserting new entry to syscall_cache {%lld, %d, %lld}\n", __func__,
				__LINE__, (long long int)id->unique_id, id->pid, (long long int)id->sysnum);
		ret = replayfs_btree128_insert(&cache->entries, k(id), &val, GFP_NOFS);

	btree_check();
		value = &val;

		replayfs_disk_alloc_put(alloc);

		/* Make sure the data is passed while we're at it */
	btree_check();
		if (is_replay()) {
			replay_put_data(id->unique_id, id->sysnum, 0, value->id);
		}
	btree_check();
	} else {
		/* Make sure the data is passed while we're at it */
	btree_check();
		if (is_replay()) {
			replay_put_data(id->unique_id, id->sysnum, 0, value->id);
		}

	btree_check();
		replayfs_btree128_put_page(&cache->entries, ret_page);
	btree_check();
	}

	debugk("%s %d: Checking if we need to update the record log for this data\n", __func__,
			__LINE__);

	btree_check();

out:
	mutex_unlock(&cache->lock);

	return ret;
}

loff_t replayfs_syscache_get(
		struct replayfs_syscall_cache *cache, struct replayfs_syscache_id *id) {
	struct page *page;
	struct replayfs_btree128_value *val;
	loff_t pos;

	debugk("%s %d: Looking up syscall cache entry {%lld, %d, %lld}\n", __func__,
			__LINE__, (long long int)id->unique_id, id->pid, (long long int)id->sysnum);
	val = replayfs_btree128_lookup(&cache->entries, k(id), &page);
	if (val != NULL) {
		pos = val->id;
		replayfs_btree128_put_page(&cache->entries, page);
	} else {
		debugk("%s %d: Calling data_get with id of %p\n", __func__,
				__LINE__, id);
		debugk("%s %d: Calling data_get with unique_id of %lld\n", __func__,
				__LINE__, (long long int)id->unique_id);
		pos = replay_data_get(cache, id->unique_id, id->sysnum, 0);
		debugk("%s %d: Got data: %lld\n", __func__, __LINE__, pos);
	}

	return pos;
}

