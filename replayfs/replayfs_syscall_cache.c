#include "replayfs_syscall_cache.h"
#include "replayfs_fs.h"

/*#define REPLAYFS_SYSCACHE_DEBUG*/
/*#define REPLAYFS_SYSCACHE_LOCK_DEBUG*/
/*#define REPLAYFS_SYSCACHE_ALLOC_DEBUG*/
/*#define REPLAYFS_SYSCACHE_ALLOC_REFCNT_DEBUG*/

extern struct kmem_cache *replayfs_page_cache;

#ifdef REPLAYFS_SYSCACHE_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

#ifdef REPLAYFS_SYSCACHE_LOCK_DEBUG
#define lock_debugk(...) printk(__VA_ARGS__)
#else
#define lock_debugk(...)
#endif

#ifdef REPLAYFS_SYSCACHE_ALLOC_DEBUG
#define alloc_debugk(...) printk(__VA_ARGS__)

#ifdef REPLAYFS_SYSCACHE_ALLOC_REFCNT_DEBUG
#define alloc_refcnt_debugk(...) printk(__VA_ARGS__)
#else
#define alloc_refcnt_debugk(...)
#endif

#else
#define alloc_debugk(...)
#define alloc_refcnt_debugk(...)
#endif

/* 512 MB syscache default size... will need to tweak later */
#define REPLAYFS_SYSCACHE_MAX_SIZE (512<<20)
#define REPLAYFS_SYSCACHE_META_FILE "syscache_meta"

#define syscache_id_copy(X, Y) replayfs_syscache_id_copy(X, Y)

static struct replayfs_syscache_entry *replayfs_syscache_entry_get(
		struct replayfs_syscall_cache *cache, struct replayfs_syscache_id *id);
static void replayfs_syscache_entry_put(struct replayfs_syscache_entry *entry);
static void syscache_index_destroy(struct syscache_index *index);
static struct syscache_index *syscache_index_get(struct replayfs_syscall_cache *cache,
		struct replayfs_unique_id *id, loff_t version);
static struct syscache_index *syscache_index_check(struct replayfs_syscall_cache *cache,
		struct replayfs_unique_id *id, loff_t version);
static int syscache_index_find_id(struct syscache_index *index,
		loff_t pos, size_t size, struct replayfs_syscache_header **header);
static int syscache_index_alloc_header(struct syscache_index *index,
		struct replayfs_syscache_header **header);
static void syscache_index_put(struct syscache_index *index);

#ifdef REPLAYFS_SYSCACHE_ALLOC_REFCNT_DEBUG
void print_entry_cache(struct replayfs_syscall_cache *cache) {
	int i;
	printk("%s %d: Dumping all valid entries of entry cache:\n", __func__,
			__LINE__);
	for (i = 0; i < SYSCACHE_ENTRY_CACHE_SIZE; i++) {
		if (cache->entry_cache[i] != NULL) {
			printk("\t%p\n", cache->entry_cache[i]);
		}
	}

	printk("%s %d: Dumping all valid entries of index cache:\n", __func__,
			__LINE__);
	for (i = 0; i < SYSCACHE_INDEX_CACHE_SIZE; i++) {
		if (cache->index_cache[i] != NULL) {
			printk("\t%p\n", cache->index_cache[i]);
		}
	}
}
#else
#define print_entry_cache(...) 
#endif

static void *syscache_index_get_page(struct syscache_index *index, int idx) {
	BUG_ON(idx != 0);
	if (index->data_page == NULL) {
		index->data_page = page_alloc_get_page(&index->meta_alloc, 0);
	}
	return index->data_page;
}

static void syscache_index_put_page(struct syscache_index *index, void *page, int idx) {
	if (index->data_page != NULL) {
		if (index->data_page_dirty) {
			page_alloc_put_page(&index->meta_alloc, index->data_page, 0);
			index->data_page = NULL;
		} else {
			page_alloc_put_page_clean(&index->meta_alloc, index->data_page, 0);
			index->data_page = NULL;
		}
	}
}

static unsigned int syscache_id_hash(struct replayfs_syscache_id *id) {
	unsigned int hash;
	hash = replayfs_id_hash(&id->id);
	hash ^= hash_int64(id->version);
	hash ^= hash_int64(id->pos);

	return hash;
}

static unsigned int syscache_index_hash(struct replayfs_unique_id *id, loff_t version) {
	unsigned int hash;

	hash = replayfs_id_hash(id);
	hash ^= hash_int64(version);

	return hash;
}

static inline void syscache_entry_invalidate(
		struct replayfs_syscache_entry *entry) {
	entry->header->valid = 0;
	entry->valid = 0;
	entry->index->data_page_dirty = 1;
}

static inline void syscache_entry_validate(
		struct replayfs_syscache_entry *entry) {
	entry->header->valid = 1;
	entry->valid = 1;
	entry->index->data_page_dirty = 1;
}

/* This is tricky... */
void replayfs_syscache_lru_add(
		struct replayfs_syscall_cache *cache,
		struct replayfs_syscache_entry *prev, struct replayfs_syscache_entry *add) {
	struct replayfs_syscache_entry *next_entry;
	/* Okay, lets take care of this now... */

	next_entry = replayfs_syscache_entry_get(cache, &prev->header->lru.next);

	syscache_id_copy(&next_entry->header->lru.prev, &add->header->id);
	syscache_id_copy(&prev->header->lru.next, &add->header->id);
	syscache_id_copy(&add->header->lru.next, &next_entry->header->id);
	syscache_id_copy(&add->header->lru.prev, &prev->header->id);

	replayfs_syscache_entry_put(next_entry);
}

void replayfs_syscache_lru_init(
		struct replayfs_syscall_cache *cache,
		struct replayfs_syscache_entry *entry) {
	/* Okay, lets take care of this now... */

	syscache_id_copy(&entry->header->lru.prev, &entry->header->id);
	syscache_id_copy(&entry->header->lru.next, &entry->header->id);
}

void replayfs_syscache_lru_add_prev(
		struct replayfs_syscall_cache *cache,
		struct replayfs_syscache_entry *next, struct replayfs_syscache_entry *add) {
	struct replayfs_syscache_entry *prev_entry;
	/* Okay, lets take care of this now... */

	prev_entry = replayfs_syscache_entry_get(cache, &next->header->lru.prev);

	syscache_id_copy(&prev_entry->header->lru.next, &add->header->id);
	syscache_id_copy(&next->header->lru.prev, &add->header->id);
	syscache_id_copy(&add->header->lru.prev, &prev_entry->header->id);
	syscache_id_copy(&add->header->lru.next, &next->header->id);

	replayfs_syscache_entry_put(prev_entry);
}

void replayfs_syscache_lru_remove(
		struct replayfs_syscall_cache *cache,
		struct replayfs_syscache_lru *lru) {
	struct replayfs_syscache_entry *next_entry;
	struct replayfs_syscache_entry *prev_entry;

	next_entry = replayfs_syscache_entry_get(cache, &lru->next);
	prev_entry = replayfs_syscache_entry_get(cache, &lru->prev);

	syscache_id_copy(&next_entry->header->lru.prev, &prev_entry->header->id);
	syscache_id_copy(&prev_entry->header->lru.next, &next_entry->header->id);

	replayfs_syscache_entry_put(next_entry);
	replayfs_syscache_entry_put(prev_entry);
}

void syscache_index_dirty(struct syscache_index *index, int idx) {
	BUG_ON(idx != 0);
	index->data_page_dirty = 1;
}

static inline void syscache_index_put(struct syscache_index *index) {
	alloc_refcnt_debugk("%s %d: index is %p, refcnt is %d\n", __func__, __LINE__, index,
			atomic_read(&index->refcnt)-1);
	if (atomic_dec_and_test(&index->refcnt)) {
		syscache_index_destroy(index);
	}
}

/* 
 * Okay, we need to cache our replayfs_syscache_entries, this may be a bit of a
 * pain.
 */

static struct replayfs_syscache_entry *replayfs_syscache_entry_get(
		struct replayfs_syscall_cache *cache, struct replayfs_syscache_id *id) {
	struct replayfs_syscache_entry *entry;
	struct syscache_index *index;
	int idx;
	int hash;

	char index_str[0x180];

	/* If it isn't cached, find it in the index */
	index = syscache_index_get(cache, &id->id, id->version);

	/* Scan the cache for the entry with id */
	hash = syscache_id_hash(id) % SYSCACHE_ENTRY_CACHE_SIZE;

	if (cache->entry_cache[hash] != NULL) {
		entry = cache->entry_cache[hash];
		atomic_inc(&entry->refcnt);
		debugk("%s %d: Found entry in cache, entry is %p\n", __func__, __LINE__,
				entry);
		goto out_put;
	}

	/* Search the index for the entry */
#ifdef SYSCACHE_MEMLEAK_CHECK
	entry = kmem_cache_alloc(cache->entry_alloc, GFP_NOIO);
#else
	entry = kmalloc(sizeof(struct replayfs_syscache_entry), GFP_NOIO);
#endif
	debugk("%s %d: entry is %p\n", __func__, __LINE__, entry);
	if (entry == NULL) {
		entry = ERR_PTR(-ENOMEM);
		/* XXX FIXME: for now, report bug */
		BUG();
		goto out_put;
	}

	idx = syscache_index_find_id(index, id->pos, 1, &entry->header);

	debugk("%s %d: idx is %d\n", __func__, __LINE__, idx);

	/* Initialize the entrie's data */
	sprintf(index_str, "%016llX_%016llX_%016llX_%016llX.syscache_data",
			id->id.log_num,
			id->id.sys_num,
			id->version,
			id->pos);

	debugk("%s %d: index_str is %s\n", __func__, __LINE__, index_str);

	/* Initialize the data section */
	replayfs_page_alloc_init(&entry->data, index_str);

	debugk("%s %d: Returned from replayfs_page_alloc_init!\n", __func__, __LINE__);

	/* Set up the refcnt */
	atomic_set(&entry->refcnt, 1);

	debugk("%s %d: Setting entry %p's index to %p\n", __func__, __LINE__, entry, index);
	entry->index = index;

	/* Okay, this entry wasn't in the index... we need to allocate it */
	if (idx < 0) {
		idx = syscache_index_alloc_header(index, &entry->header);

		entry->header->valid = 1;
		replayfs_syscache_id_copy(&entry->header->id, id);
		entry->header->lru_clock = 1;
		entry->header->size = 0;

		entry->index->data_page_dirty = 1;

		/*
		if (replayfs_syscache_id_is_valid(&cache->meta.lru_next)) {
			struct replayfs_syscache_entry *lru_next;

			lru_next = replayfs_syscache_entry_get(cache, &cache->meta.lru_next);

			replayfs_syscache_lru_add_prev(cache, lru_next, entry);

			replayfs_syscache_entry_put(lru_next);
		} else {
			replayfs_syscache_id_copy(&cache->meta.lru_next, id);
			replayfs_syscache_lru_init(cache, entry);
		}
		*/
	}

	debugk("%s %d: Entry's size is %d\n", __func__, __LINE__, entry->header->size);

	entry->valid = entry->header->valid;

	/* Add the entry to the cache */
	if (cache->entry_cache[hash] != NULL) {
		debugk("%s %d: !!! Detected conflict in the entry_cache inserting %p, freeing %p\n",
				__func__, __LINE__, entry, cache->entry_cache[hash]);
		replayfs_syscache_entry_put(cache->entry_cache[hash]);
	}
	cache->entry_cache[hash] = entry;

	atomic_inc(&entry->refcnt);

	alloc_debugk("%s %d: Creating entry %p\n", __func__, __LINE__, entry);

out:
	debugk("%s %d: entry is %p entry->header is %p\n",
			__func__, __LINE__, entry, entry->header);
	alloc_refcnt_debugk("%s %d: entry is %p, refcnt is %d\n", __func__, __LINE__, entry,
			atomic_read(&entry->refcnt));
	return entry;

out_put:
	syscache_index_put(index);
	goto out;
}

static void replayfs_syscache_entry_destroy(struct replayfs_syscache_entry *entry) {
	struct replayfs_syscall_cache *cache;

	alloc_debugk("%s %d: Freeing entry %p\n", __func__, __LINE__, entry);

	if (!entry->valid) {
		/* Delete our page data */
		replayfs_page_alloc_delete(&entry->data);
	} else {
		replayfs_page_alloc_destroy(&entry->data);
	}

	cache = entry->index->cache;

	syscache_index_put(entry->index);
#ifdef SYSCACHE_MEMLEAK_CHECK
	kmem_cache_free(cache->entry_alloc, entry);
#else
	kfree(entry);
#endif
}

void replayfs_syscache_entry_put(struct replayfs_syscache_entry *entry) {
	alloc_refcnt_debugk("%s %d: entry is %p, refcnt is %d\n", __func__, __LINE__, entry,
			atomic_read(&entry->refcnt)-1);
	print_entry_cache(entry->index->cache);
	if (atomic_dec_and_test(&entry->refcnt)) {
		replayfs_syscache_entry_destroy(entry);
	}
}

/* Gets syscall_cache_meta from disk */
static int replayfs_syscall_cache_meta_read(
		struct replayfs_syscall_cache *cache) {
	page_alloc_read(&cache->meta_disk, &cache->meta, 0, sizeof(cache->meta));
	return 0;
}

/* Saves syscall_cache_meta to disk */
void replayfs_syscall_cache_meta_write(
		struct replayfs_syscall_cache *cache) {
	page_alloc_write(&cache->meta_disk, &cache->meta, 0, sizeof(cache->meta));
}

static int syscache_index_alloc_header(struct syscache_index *index,
		struct replayfs_syscache_header **header) {
	void *page;
	void *page_pos;
	struct replayfs_syscache_header *i;
	int idx = -1;

	/* 
	 * Okay, we need to find the entry covering pos in index, we start by scanning
	 * the new entries, then we scan the sorted entries
	 */

	page = syscache_index_get_page(index, 0);
	page_pos = page + sizeof(struct syscache_index_meta);

	/* Skip over the syscache_index_meta */
	for (i = (struct replayfs_syscache_header *)page_pos;
			(void *)i+sizeof(struct replayfs_syscache_header) < page+PAGE_SIZE; i++) {
		if (i->valid == 0) {
			*header = i;
			idx = 0;
			goto out;
		}
	}

out:
	return idx;
}

static int syscache_index_find_id(struct syscache_index *index,
		loff_t pos, size_t size, struct replayfs_syscache_header **header) {
	void *page;
	void *page_pos;
	char *cpage;
	struct replayfs_syscache_header *i;
	int idx = -1;

	loff_t top_pos;

	/* 
	 * Okay, we need to find the entry covering pos in index, we start by scanning
	 * the new entries, then we scan the sorted entries
	 */
	top_pos = pos+size-1;

	page = syscache_index_get_page(index, 0);
	cpage = page;
	page_pos = cpage + sizeof(struct syscache_index_meta);
	debugk("%s %d: Page_pos is %p, page is %p\n", __func__, __LINE__, page_pos, page);

	/* Skip over the syscache_index_meta */
	for (i = (struct replayfs_syscache_header *)page_pos;
			((char *)i)+sizeof(struct replayfs_syscache_header) < cpage+PAGE_SIZE; i++) {
		if (i->id.pos >= pos && i->id.pos <= top_pos && i->valid) {
			*header = i;
			idx = 0;
			debugk("%s %d: Found header %p at index %d\n", __func__, __LINE__, *header, idx);
			goto out;
		}
	}

out:
	return idx;
}

struct replayfs_syscache_entry *syscache_index_find(
		struct syscache_index *index, loff_t pos, size_t size) {
	int idx;
	struct replayfs_syscache_header *header;
	struct replayfs_syscache_entry *entry;

	/* Okay... find if the index has any files in this range. */
	idx = syscache_index_find_id(index, pos, size, &header);

	if (idx == -1) {
		return NULL;
	}

	debugk("%s %d: idx is %d\n", __func__, __LINE__, idx);
	/* Okay, lets get this entry and return it */
	entry = replayfs_syscache_entry_get(index->cache, &header->id);

	return entry;
}

static struct replayfs_syscache_entry *syscache_entry_merge(
		struct replayfs_syscall_cache *cache, struct syscache_index *index,
		struct replayfs_syscache_entry *e1, struct replayfs_syscache_entry *e2) {

	struct replayfs_syscache_entry *bottom;
	struct replayfs_syscache_entry *top;

	/* Determine which entry is the lower */
	if (e1->header->id.pos < e2->header->id.pos) {
		bottom = e1;
		top = e2;
	} else {
		bottom = e2;
		top = e1;
	}

	/* If the top of the top is above the top of the bottom... */
	if (bottom->header->id.pos + bottom->header->size <
			bottom->header->id.pos + bottom->header->size) {
		/* (bottom->header.id.pos+bottom->size) - top->header.id.pos; */
		/* Merge the portion of top not contained in bottom */
		void *data;
		int ntoread;
		int nread;
		int nwritten;

		/* How much higher does top go then bottom? */
		ntoread = top->header->id.pos + top->header->size -
			(bottom->header->id.pos + bottom->header->size);

		data = kmalloc(ntoread, GFP_NOIO);
		if (data == NULL) {
			return ERR_PTR(-ENOMEM);
		}

		nread = page_alloc_read(&top->data, data,
				top->header->id.pos - (bottom->header->id.pos+bottom->header->size), ntoread);
		BUG_ON(nread != ntoread);

		nwritten = page_alloc_write(&bottom->data, data,
				bottom->header->id.pos + bottom->header->size, nread);
		BUG_ON(nwritten != nread);

		kfree(data);
	}

	atomic_inc(&bottom->refcnt);
	alloc_refcnt_debugk("%s %d: entry is %p, refcnt is %d\n", __func__, __LINE__, bottom,
			atomic_read(&bottom->refcnt));
	return bottom;
}

static int syscache_entry_overlap(
		struct replayfs_syscache_entry *e1,
		struct replayfs_syscache_entry *e2
		) {
	if (e1->header->id.pos < e2->header->id.pos) {
		return (e1->header->id.pos + e1->header->size >
				e2->header->id.pos+e2->header->size) ?
			e2->header->size : (e1->header->id.pos+e1->header->size) - e2->header->id.pos;
	} else {
		return (e2->header->id.pos + e2->header->size > e2->header->id.pos +
				e2->header->size) ?
			e1->header->size : (e2->header->id.pos+e2->header->size) - e1->header->id.pos;
	}
}

static void syscache_index_meta_init(struct syscache_index *index,
		struct replayfs_unique_id *id, loff_t version) {

	memcpy(&index->meta.id, id, sizeof(struct replayfs_unique_id));
	index->meta.version = version;
}

static void syscache_index_destroy(struct syscache_index *index) {
	alloc_debugk("%s %d: Destroying index %p\n", __func__, __LINE__, index);
	syscache_index_put_page(index, index->data_page, 0);

	debugk("%s %d: Saving metadata for {%lld, %lld, %lld}\n", __func__, __LINE__,
			index->meta.id.log_num, index->meta.id.sys_num, index->meta.version);
	page_alloc_write(&index->meta_alloc, &index->meta, 0,
			sizeof(struct syscache_index_meta));

	replayfs_page_alloc_destroy(&index->meta_alloc);

#ifdef SYSCACHE_MEMLEAK_CHECK
	kmem_cache_free(index->cache->index_alloc, index);
#else
	kfree(index);
#endif
}

static struct syscache_index *syscache_index_check(struct replayfs_syscall_cache *cache,
		struct replayfs_unique_id *id, loff_t version) {
	struct syscache_index *index;
	unsigned int hash;

	/* Check to see if the index is in the index cache */

	/* 
	 * Note, this has to be an atomic check and add, otherwise locking has to be
	 * force externally... ugh
	 *
	 * Could do a double-check locking type approach -- read lock check, write
	 * lock re-check and add
	 */

	index = NULL;

	hash = syscache_index_hash(id, version) % SYSCACHE_INDEX_CACHE_SIZE;
	debugk("%s %d: %p: Scanning for entry with hash 0x%X {%lld, %lld, %lld}\n",
			__func__, __LINE__, current, hash, id->log_num, id->sys_num, version);
	if (cache->index_cache[hash] != NULL) {
		index = cache->index_cache[hash];
		if (!memcmp(&index->meta.id, id, sizeof(struct replayfs_unique_id)) &&
				version == index->meta.version) {
			atomic_inc(&index->refcnt);
			debugk("%s %d: Found entry %p\n", __func__, __LINE__, index);
			goto out;
		}
	}

	debugk("%s %d: %p: Did not find entry\n", __func__, __LINE__, current);

out:
	alloc_refcnt_debugk("%s %d: index is %p, refcnt is %d\n", __func__, __LINE__, index,
			atomic_read(&index->refcnt));

	return index;
}

static struct syscache_index *syscache_index_get(struct replayfs_syscall_cache *cache,
		struct replayfs_unique_id *id, loff_t version) {
	struct syscache_index *index;
	unsigned int hash;
	int nread;
	char index_str[0x180];

	/* Check to see if the index is in the index cache */

	/* 
	 * Note, this has to be an atomic check and add, otherwise locking has to be
	 * force externally... ugh
	 *
	 * Could do a double-check locking type approach -- read lock check, write
	 * lock re-check and add
	 */

	perftimer_start(cache->iget_hash_timer);
	hash = syscache_index_hash(id, version) % SYSCACHE_INDEX_CACHE_SIZE;
	debugk("%s %d: %p: Scanning for entry with hash 0x%X {%lld, %lld, %lld}\n",
			__func__, __LINE__, current, hash, id->log_num, id->sys_num, version);
	if (cache->index_cache[hash] != NULL) {
		index = cache->index_cache[hash];
		if (!memcmp(&index->meta.id, id, sizeof(struct replayfs_unique_id)) &&
				version == index->meta.version) {
			atomic_inc(&index->refcnt);
			debugk("%s %d: Found entry %p\n", __func__, __LINE__, index);
			perftimer_stop(cache->iget_hash_timer);
			goto out;
		}
	}
	perftimer_stop(cache->iget_hash_timer);

	debugk("%s %d: %p: Did not find entry\n", __func__, __LINE__, current);

#ifdef SYSCACHE_MEMLEAK_CHECK
	index = kmem_cache_alloc(cache->index_alloc, GFP_NOIO);
#else
	index = kmalloc(sizeof(struct syscache_index), GFP_NOIO);
#endif

	if (index == NULL) {
		index = ERR_PTR(-ENOMEM);
		goto out;
	}

	index->cache = cache;

	/* XXX: Do I really want the files allocated like this? */
	sprintf(index_str, "%016llX_%016llX_%016llX.syscache_index", id->log_num, id->sys_num, version);

	debugk("%s %d: %p: Calling replayfs_page_alloc_init\n", __func__, __LINE__,
			current);
	perftimer_start(cache->iget_pagealloc_timer);
	/* Lookup file index */
	if (replayfs_page_alloc_init(&index->meta_alloc, index_str)) {
#ifdef SYSCACHE_MEMLEAK_CHECK
		kmem_cache_free(cache->index_alloc, index);
#else
		kfree(index);
#endif
		debugk("%s %d: pagealloc_init failure!\n", __func__, __LINE__);
		index = ERR_PTR(-ENOMEM);
		perftimer_stop(cache->iget_pagealloc_timer);
		goto out;
	}
	perftimer_stop(cache->iget_pagealloc_timer);
	debugk("%s %d: %p: Done calling replayfs_page_alloc_init\n", __func__,
			__LINE__, current);

	perftimer_start(cache->iget_read_timer);
	nread = page_alloc_read(&index->meta_alloc, &index->meta, 0,
			sizeof(struct syscache_index_meta));
	BUG_ON(nread != sizeof(struct syscache_index_meta));
	perftimer_stop(cache->iget_read_timer);

	perftimer_start(cache->iget_rest_timer);
	debugk("%s %d: %p: Done calling page_alloc_read\n", __func__, __LINE__,
			current);
	/* 
	 * If we read an invalid log_num (0) then we know that the index hasn't been
	 * initalized, initialize it 
	 */
	if (index->meta.id.log_num == 0) {
		debugk("%s %d: Meta->id.log_num == 0, initializing empty index\n", __func__,
				__LINE__);
		syscache_index_meta_init(index, id, version);
	}

	/* Initialize the remainder of the data */
	/* Refcnt is 2, one for the cache, one for the returned instance */
	atomic_set(&index->refcnt, 2);
	mutex_init(&index->lock);

	index->data_page_dirty = 0;
	index->data_page = NULL;

	alloc_debugk("%s %d: %p: Before putting index %p in index cache\n", __func__,
			__LINE__, current, index);
	print_entry_cache(index->cache);

	alloc_debugk("%s %d: %p: hash is 0x%X index_cache size is 0x%X\n", __func__,
			__LINE__, current, hash, SYSCACHE_INDEX_CACHE_SIZE);
	alloc_debugk("%s %d: %p Index cache base is %p max is %p\n", __func__,
			__LINE__, current, &cache->index_cache[0],
			&cache->index_cache[SYSCACHE_INDEX_CACHE_SIZE]-1);

	if (cache->index_cache[hash] != NULL) {
		alloc_debugk("%s %d: !!! Detected conflict in the entry_cache inserting %p, freeing %p\n",
				__func__, __LINE__, index, cache->index_cache[hash]);
		syscache_index_put(cache->index_cache[hash]);
	}

	cache->index_cache[hash] = index;
	alloc_debugk("%s %d: %p: Inserting at %p\n", __func__, __LINE__, current,
			&cache->index_cache[hash]);

	alloc_debugk("%s %d: %p: Allocating index %p\n", __func__, __LINE__, current, index);
	print_entry_cache(index->cache);
	perftimer_stop(cache->iget_rest_timer);

out:
	alloc_refcnt_debugk("%s %d: index is %p, refcnt is %d\n", __func__, __LINE__, index,
			atomic_read(&index->refcnt));
	return index;
}

int replayfs_syscache_init(struct replayfs_syscall_cache *cache) {
	int i;

	mutex_init(&cache->lock);

	debugk("%s %d: Initializing cache %p\n", __func__, __LINE__, cache);

	cache->iget_hash_timer = perftimer_create("index get hash compare",
			"syscache");
	cache->iget_pagealloc_timer = perftimer_create("index get page alloc init",
			"syscache");
	cache->iget_read_timer = perftimer_create("index get pagealloc read",
			"syscache");
	cache->iget_rest_timer = perftimer_create("index get other",
			"syscache");

	cache->get_iget_timer = perftimer_create("iget",
			"syscache");
	cache->get_ifind_timer = perftimer_create("ifind",
			"syscache");


	for (i = 0; i < SYSCACHE_INDEX_CACHE_SIZE; i++) {
		cache->index_cache[i] = NULL;
	}

	for (i = 0; i < SYSCACHE_ENTRY_CACHE_SIZE; i++) {
		cache->entry_cache[i] = NULL;
	}

	if (replayfs_page_alloc_init(&cache->meta_disk, REPLAYFS_SYSCACHE_META_FILE)) {
		debugk("%s %d: FAILURE: failed to initialize disk image of cache header\n",
				__func__, __LINE__);
		return -1;
	}

	if (replayfs_syscall_cache_meta_read(cache)) {
		debugk("%s %d: FAILURE: failed to initialize cache's metadata from disk image\n",
				__func__, __LINE__);
		return -1;
	}

	if (cache->meta.size == 0) {
		replayfs_syscache_id_invalidate(&cache->meta.lru_next);
		cache->meta.max_size = REPLAYFS_SYSCACHE_MAX_SIZE;
	}

	lock_debugk("%s %d: Process %p: Cache is %p\n", __func__, __LINE__, current,
			cache);

#ifdef SYSCACHE_MEMLEAK_CHECK
	cache->entry_alloc = kmem_cache_create("syscall_cache_entry_cache",
			sizeof(struct replayfs_syscache_entry), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);

	cache->index_alloc = kmem_cache_create("syscall_cache_index_cache",
			sizeof(struct syscache_index), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD, NULL);

	BUG_ON(cache->entry_alloc == NULL);
	BUG_ON(cache->index_alloc == NULL);
#endif

	return 0;
}

void replayfs_syscache_destroy(struct replayfs_syscall_cache *cache) {
	int i;

	debugk("%s %d: Freeing cache %p\n", __func__, __LINE__, cache);

	for (i = 0; i < SYSCACHE_ENTRY_CACHE_SIZE; i++) {
		if (cache->entry_cache[i] != NULL) {
			if (atomic_read(&cache->entry_cache[i]->refcnt) != 1) {
				printk("%s %d: WARNING: entry_cache entry %p is still referenced externally(%d)\n",
						__func__, __LINE__, cache->entry_cache[i],
						atomic_read(&cache->entry_cache[i]->refcnt));
			}
			replayfs_syscache_entry_put(cache->entry_cache[i]);
		}
	}

	for (i = 0; i < SYSCACHE_INDEX_CACHE_SIZE; i++) {
		if (cache->index_cache[i] != NULL) {
			if (atomic_read(&cache->index_cache[i]->refcnt) != 1) {
				printk("%s %d: WARNING: index_cache entry %p is still referenced externally(%d)\n",
						__func__, __LINE__, cache->index_cache[i],
						atomic_read(&cache->index_cache[i]->refcnt));
			}
			syscache_index_put(cache->index_cache[i]);
		}
	}

#ifdef SYSCACHE_MEMLEAK_CHECK
	printk("%s %d: Deleting caches\n", __func__, __LINE__);
	kmem_cache_destroy(cache->entry_alloc);
	kmem_cache_destroy(cache->index_alloc);
#endif

	replayfs_page_alloc_destroy(&cache->meta_disk);
}

/* 
 * Ensures the added data is within the cache (possibly merging entries) and
 * updates the LRU for that set of data
 */
int count = 0;
int replayfs_syscache_add(struct replayfs_syscall_cache *cache,
		struct replayfs_syscache_id *id,
		size_t size, void *data) {

	int ret;
	size_t delta;

	/* Get file data index for this data */
	struct syscache_index *index;
	struct replayfs_syscache_entry *entry;
	struct replayfs_syscache_entry *cur_entry;

	count++;
	lock_debugk("%s %d: Process %p: Cache is %p\n", __func__, __LINE__, current,
			cache);
	lock_debugk("%s %d: Process %p mutex_locking %p (count %d)\n", __func__, __LINE__,
			current, &cache->lock, count);


	mutex_lock(&cache->lock);

	index = syscache_index_get(cache, &id->id, id->version);
	if (IS_ERR(index)) {
		debugk("%s %d: index is invalid?  %p\n", __func__, __LINE__, index);
		ret = PTR_ERR(index);
		goto out_index;
	}

	ret = 0;

	/* See if there is already an entry containing this data */
	entry = syscache_index_find(index, id->pos, 1);
	if (IS_ERR(entry)) {
		ret = PTR_ERR(entry);
		debugk("%s %d: Entry is null\n", __func__, __LINE__);
		goto out;
	}

	if (entry == NULL) {
		/* If not, make one */
		debugk("%s %d: Here!\n", __func__, __LINE__);
		entry = replayfs_syscache_entry_get(cache, id);
		debugk("%s %d: Entry is %p\n", __func__, __LINE__, entry);
		/* Initialize it */
		entry->header->size = size;
		entry->index->data_page_dirty = 1;

		debugk("%s %d: Here!\n", __func__, __LINE__);
		page_alloc_write(&entry->data, data, 0, size);
		debugk("%s %d: Here!\n", __func__, __LINE__);

		BUG_ON(entry == NULL);
	}

	delta = size;

	debugk("%s %d: Here!\n", __func__, __LINE__);
	/* Delete this entry, so it doesn't return in future searches */
	syscache_entry_invalidate(entry);

	debugk("%s %d: Here!\n", __func__, __LINE__);
	/* While prior versions of this data range exist in index */
	cur_entry = syscache_index_find(index, id->pos, size);
	debugk("%s %d: Here!\n", __func__, __LINE__);
	while (cur_entry != NULL) {
		struct replayfs_syscache_entry *new_entry;

		/* Find the overlap size between the two entries */
		delta -= syscache_entry_overlap(cur_entry, entry);

		debugk("%s %d: Here!\n", __func__, __LINE__);
		new_entry = syscache_entry_merge(cache, index, cur_entry, entry);
		if (IS_ERR(new_entry)) {
			ret = PTR_ERR(new_entry);
			goto out;
		}

		debugk("%s %d: Here!\n", __func__, __LINE__);
		/* Invalidate our entries, so they are deleted when their refcounts hit 0 */
		syscache_entry_invalidate(cur_entry);
		syscache_entry_invalidate(entry);

		/* 
		 * We're done with these entries (the refcnt has been indexed in merge for
		 * the reused one)
		 */
		replayfs_syscache_put(cache, cur_entry);
		replayfs_syscache_put(cache, entry);

		debugk("%s %d: Here!\n", __func__, __LINE__);
		entry = new_entry;

		debugk("%s %d: syscache_index_find(%p, %lld, %u)\n", __func__, __LINE__, index, id->pos, size);
		cur_entry = syscache_index_find(index, id->pos, size);
		debugk("%s %d: Here!\n", __func__, __LINE__);
	}

	debugk("%s %d: Here!\n", __func__, __LINE__);
	/* Update the entry in the index (or add it if its missing) */
	syscache_entry_validate(entry);

	/* Update the syscache size info by the delta */
	BUG_ON(delta < 0);
	cache->meta.size += delta;

	replayfs_syscache_put(cache, entry);

out:
	syscache_index_put(index);

out_index:
	mutex_unlock(&cache->lock);
	lock_debugk("%s %d: Process %p mutex_unlocking %p\n", __func__, __LINE__,
			current, &cache->lock);

	return ret;
}

/* FIXME: Need to make this check //much// faster */
struct replayfs_syscache_entry *replayfs_syscache_get(
		struct replayfs_syscall_cache *cache, struct replayfs_syscache_id *id,
		size_t size) {
	struct syscache_index *index;
	struct replayfs_syscache_entry *entry = NULL;

	lock_debugk("%s %d: %p: mutex_locking %p\n", __func__, __LINE__,
			current, &cache->lock);
	mutex_lock(&cache->lock);

	perftimer_start(cache->get_iget_timer);
	/* Get the file data index for this data */
	index = syscache_index_get(cache, &id->id, id->version);
	perftimer_stop(cache->get_iget_timer);

	perftimer_start(cache->get_ifind_timer);
	/* return first element in this range */
	entry = syscache_index_find(index, id->pos, size);
	perftimer_stop(cache->get_ifind_timer);

	syscache_index_put(index);

	lock_debugk("%s %d: %p: mutex_unlocking %p\n", __func__, __LINE__,
			current, &cache->lock);
	mutex_unlock(&cache->lock);

	return entry;
}

struct replayfs_syscache_entry *replayfs_syscache_check(
		struct replayfs_syscall_cache *cache, struct replayfs_syscache_id *id,
		size_t size) {
	struct syscache_index *index;
	struct replayfs_syscache_entry *entry = NULL;

	lock_debugk("%s %d: %p: mutex_locking %p\n", __func__, __LINE__,
			current, &cache->lock);
	mutex_lock(&cache->lock);

	perftimer_start(cache->get_iget_timer);
	/* Get the file data index for this data */
	index = syscache_index_check(cache, &id->id, id->version);
	perftimer_stop(cache->get_iget_timer);

	if (index == NULL) {
		goto out;
	}

	perftimer_start(cache->get_ifind_timer);
	/* return first element in this range */
	entry = syscache_index_find(index, id->pos, size);
	perftimer_stop(cache->get_ifind_timer);

	syscache_index_put(index);

out:
	lock_debugk("%s %d: %p: mutex_unlocking %p\n", __func__, __LINE__,
			current, &cache->lock);
	mutex_unlock(&cache->lock);

	return entry;
}

/* offset is based on global start, not start of entry */
void replayfs_syscache_entry_read(struct replayfs_syscache_entry *entry,
		void *buff, loff_t offset, size_t size) {
	loff_t local_start;
	size_t nread;

	lock_debugk("%s %d: Process %p mutex_locking %p\n", __func__, __LINE__,
			current, &entry->index->cache->lock);
	mutex_lock(&entry->index->cache->lock);

	BUG_ON(offset < entry->header->id.pos);

	BUG_ON(offset+size > entry->header->id.pos + entry->header->size);

	local_start = offset-entry->header->id.pos;

	nread = page_alloc_read(&entry->data, buff, local_start, size);
	BUG_ON(nread != size);

	mutex_unlock(&entry->index->cache->lock);
	lock_debugk("%s %d: Process %p mutex_unlocking %p\n", __func__, __LINE__,
			current, &entry->index->cache->lock);

	debugk("%s %d: requested %d bytes of data from %lld, data read is %.*s\n",
			__func__, __LINE__, size, offset, size, (char *)buff);
}

void replayfs_syscache_put(struct replayfs_syscall_cache *cache,
		struct replayfs_syscache_entry *entry) {
	replayfs_syscache_entry_put(entry);
}

