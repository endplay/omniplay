#include "replayfs_file_log.h"
#include "replayfs_fs.h"
#include "replayfs_dir.h"
#include "replayfs_syscall_cache.h"

#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/thread_info.h>
#include <linux/unistd.h>

#include <linux/replay.h>

/*#define REPLAYFS_FILE_LOG_DEBUG*/
/*#define REPLAYFS_FILE_LOG_ALLOC_DEBUG*/

#ifdef REPLAYFS_FILE_LOG_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

#ifdef REPLAYFS_FILE_LOG_ALLOC_DEBUG
#define alloc_debugk(...) printk(__VA_ARGS__)
#else
#define alloc_debugk(...)
#endif

extern struct kmem_cache *replayfs_page_cache;

static void replayfs_file_log_destroy(struct replayfs_file_log *log);

struct range_set {
	struct list_head list;
	loff_t start;
	loff_t size;
};

#define MOD_OFFS_INIT 0xFFFFFFFFFFFFFFFFULL

int replayfs_file_log_cache_init(struct replayfs_file_log_cache *cache,
		struct replayfs_syscall_cache *syscall_cache) {
	int i;
	/* Initialize the lock */
	mutex_init(&cache->lock);

	INIT_LIST_HEAD(&cache->free_list);

	cache->syscall_cache = syscall_cache;
	cache->read_cache_timer = perftimer_create("read_cache", "file_log");
	cache->log_get_entry_timer = perftimer_create("log_get_entry times", "file_log");

	/* Initialize each entry of the cache */
	for (i = 0; i < REPLAYFS_FILE_LOG_CACHE_SIZE; i++) {
		INIT_HLIST_HEAD(&cache->cache[i]);
	}

#ifdef FILE_LOG_MEMCHK
	cache->file_log_cache = kmem_cache_create("file_log_cache",
			sizeof(struct replayfs_file_log_cache), 0,
			0, NULL);
	cache->range_set_cache = kmem_cache_create("range_set_cache",
			sizeof(struct range_set), 0,
			SLAB_RECLAIM_ACCOUNT, NULL);
	BUG_ON(cache->file_log_cache == NULL);
	BUG_ON(cache->range_set_cache == NULL);
#endif

	return 0;
}

void replayfs_file_log_cache_destroy(struct replayfs_file_log_cache *cache) {
	struct replayfs_file_log *entry;
	struct replayfs_file_log *_e;

	mutex_lock(&cache->lock);
	
	list_for_each_entry_safe(entry, _e, &cache->free_list, free_list) {
		list_del(&entry->free_list);
		hlist_del(&entry->list);
		replayfs_file_log_destroy(entry);
	}

#ifdef FILE_LOG_MEMCHK
	kmem_cache_destroy(cache->file_log_cache);
	kmem_cache_destroy(cache->range_set_cache);
#endif

	mutex_unlock(&cache->lock);
}

struct replayfs_file_log *replayfs_file_log_init(
		struct replayfs_unique_id *id, struct replayfs_file_log_cache *log_cache,
		struct replayfs_syscall_cache *cache) {
	struct replayfs_file_log_meta meta;
	struct replayfs_file_log *ret;
	char *name;

	/* FIXME TODO */
	/* Check to see if this entry exists on disk??? */

#ifdef FILE_LOG_MEMCHK
	ret = kmem_cache_alloc(log_cache->file_log_cache, GFP_NOIO);
#else
	ret = kmalloc(sizeof(struct replayfs_file_log), GFP_NOIO);
#endif
	if (ret == NULL) {
		/* FIXME: for debugging, remove later */
		BUG();
		return ret;
	}

	ret->log_cache = log_cache;

	/*name = kmalloc(PAGE_SIZE, GFP_NOIO);*/
	name = kmem_cache_alloc(replayfs_page_cache, GFP_NOIO);
	if (name == NULL) {
		printk("%s %d: GAH, Out of memory!\n", __func__, __LINE__);
#ifdef FILE_LOG_MEMCHK
		kmem_cache_free(log_cache->file_log_cache, ret);
#else
		kfree(ret);
#endif
		return NULL;
	}

	/* Initialize the log's lock */
	mutex_init(&ret->lock);

	atomic_set(&ret->refs, 1);

	memcpy(&ret->id, id, sizeof(struct replayfs_unique_id));

	name[0] = '\0';
	sprintf(name, "%08X_%016llX.entry", (unsigned int)id->log_num,
			(unsigned long long)id->sys_num);
	replayfs_page_alloc_init(&ret->entry_alloc, name);

	sprintf(name, "%08X_%016llX.data", (unsigned int)id->log_num,
			(unsigned long long)id->sys_num);
	replayfs_page_alloc_init(&ret->data_alloc, name);

	page_alloc_read(&ret->entry_alloc, &meta, PAGE_SIZE/2, sizeof(meta));
	debugk("%s %d: loading file_log metadata, cur_data_offs is %lld num_entries is %lld\n",
			__func__, __LINE__, meta.cur_data_offs, meta.num_entries);

	ret->cur_data_offs = meta.cur_data_offs;
	ret->num_entries = meta.num_entries;

	debugk("%s %d: Allocating log %p\n", __func__, __LINE__, ret);

	ret->cache = cache;

	/*kfree(name);*/
	kmem_cache_free(replayfs_page_cache, name);
	return ret;
}

static void replayfs_file_log_destroy(struct replayfs_file_log *log) {
	struct replayfs_file_log_meta meta;

	/* Save off our metadata in the beginning of the entry alloc */
	meta.cur_data_offs = log->cur_data_offs;
	meta.num_entries = log->num_entries;

	debugk("%s %d: Saving file_log metadata, cur_data_offs is %lld num_entries is %lld\n",
			__func__, __LINE__, meta.cur_data_offs, meta.num_entries);
	page_alloc_write(&log->entry_alloc, &meta, PAGE_SIZE/2, sizeof(meta));

	replayfs_page_alloc_destroy(&log->entry_alloc);
	replayfs_page_alloc_destroy(&log->data_alloc);

	debugk("%s %d: Freeing log %p\n", __func__, __LINE__, log);
#ifdef FILE_LOG_MEMCHK
	kmem_cache_free(log->log_cache->file_log_cache, log);
#else
	kfree(log);
#endif
}

struct replayfs_file_log *replayfs_file_log_cache_get(
		struct replayfs_file_log_cache *cache,
		struct replayfs_unique_id *id) {
	struct hlist_head *list;
	struct hlist_node *pos;
	struct replayfs_file_log *entry;
	/* Look for this entry in our cache */
	unsigned int index;

	/* cache size is a multiple of 2, the mod converts to an and operation */
	index = replayfs_id_hash(id) % REPLAYFS_FILE_LOG_CACHE_SIZE;

	debugk("%s %d: Getting file_log to match {%u, %lld} [%d]\n", __func__, __LINE__,
			(unsigned int)id->log_num, id->sys_num, index);

	/* Now, scan the hlist at index and search for inode */
	debugk("%s %d: Write locking cache->lock\n", __func__, __LINE__);
	mutex_lock(&cache->lock);
	debugk("%s %d: Done write locking cache->lock\n", __func__, __LINE__);
	list = &cache->cache[index];

	hlist_for_each_entry(entry, pos, list, list) {
		debugk("%s %d: checking for match against {%u, %lld}\n", __func__, __LINE__,
				(unsigned int)entry->id.log_num, entry->id.sys_num);
		if (replayfs_id_matches(&entry->id, id)) {
			debugk("%s %d: Match found!\n", __func__, __LINE__);
			atomic_inc(&entry->refs);
			mutex_unlock(&cache->lock);
			return entry;
		}
	}

	entry = replayfs_file_log_init(id, cache, cache->syscall_cache);
	hlist_add_head(&entry->list, list);
	list_add(&entry->free_list, &cache->free_list);

	mutex_unlock(&cache->lock);

	return entry;
}

void replayfs_file_log_cache_put(struct replayfs_file_log_cache *cache,
		struct replayfs_file_log *log) {
}

struct replayfs_file_log_entry *replayfs_file_log_get_entry(
		struct replayfs_file_log *log, loff_t entry_num) {
	int page_of_entry;
	int offset_in_page;
	char *page;

	if (entry_num == REPLAYFS_CURRENT_VERSION) {
		entry_num = log->num_entries-1;
	}

	if (entry_num > log->num_entries) {
		return NULL;
	}

	/* Calculate the page of the entry */
	page_of_entry = (unsigned int)entry_num / ENTRIES_PER_PAGE;

	/* Figure out where in the page the entry is */
	offset_in_page =
		((unsigned int)entry_num % ENTRIES_PER_PAGE) * sizeof(struct replayfs_file_log_entry);

	debugk("%s %d: Reading entry from %llu to page %llu, offset %d\n", __func__, __LINE__,
			(unsigned long long)entry_num, (unsigned long long)page_of_entry, offset_in_page);

	/* Read that page */
	page = page_alloc_get_page(&log->entry_alloc, page_of_entry);

	/* Now, read out the entry */
	page += offset_in_page;

	return (struct replayfs_file_log_entry *)page;
}

void replayfs_file_log_put_entry(struct replayfs_file_log *log,
		struct replayfs_file_log_entry *entry, loff_t entry_num) {
	int page_of_entry;
	int offset_in_page;
	char *centry;

	centry = (char *)entry;

	/* Calculate the page of the entry */
	page_of_entry = (unsigned int)entry_num / ENTRIES_PER_PAGE;
	offset_in_page = (entry_num * sizeof(struct replayfs_file_log_entry)) %
		PAGE_SIZE;

	centry -= offset_in_page;

	page_alloc_put_page(&log->entry_alloc, centry, page_of_entry);
}

void replayfs_file_log_add_next(
		struct replayfs_file_log *log) {
	int page_of_entry;
	int offset_in_page;
	char *page;
	loff_t entry_num;
	struct replayfs_file_log_entry *entry;

	mutex_lock(&log->lock);

	entry_num = log->num_entries;

	/* Calculate the page of the entry */
	page_of_entry = (unsigned int)entry_num / ENTRIES_PER_PAGE;

	/* Figure out where in the page the entry is */
	offset_in_page = (unsigned int)entry_num % ENTRIES_PER_PAGE;
	offset_in_page *= sizeof(struct replayfs_file_log_entry);

	debugk("%s %d: Adding entry at %llu to page %llu, offset %d\n", __func__, __LINE__,
			(unsigned long long)entry_num, (unsigned long long)page_of_entry, offset_in_page);

	/* Read that page */
	page = page_alloc_get_page(&log->entry_alloc, page_of_entry);

	/* Now, read out the entry */

	entry = (struct replayfs_file_log_entry *)(page + offset_in_page);

	/* If this is a replay process we shouldn't be adding log entries... */
	BUG_ON(test_thread_flag(TIF_REPLAY));

	/* Initialize entry */
	if (test_thread_flag(TIF_RECORD)) {
		entry->type = current->record_thrd->unique_id;
		entry->sysnum = syscall_log_size(&current->record_thrd->syscall_log);
		debugk("%s %d: TIF_RECORD set, unique id is %lld, sysnum is %lld\n", __func__,
				__LINE__, entry->type, entry->sysnum);
		/* XXX NOTE: This is really useful to debug unsupported syscalls */
		/* dump_stack(); */
	} else {
		entry->type = REPLAYFS_ENTRY_LOG_DATA;
	}

	/* This entry has no modifications */
	debugk("%s %d: Zeroing nmods: %p\n", __func__, __LINE__, &entry->nmods);
	entry->nmods = 0;

	page_alloc_put_page(&log->entry_alloc, page, page_of_entry);
}

void replayfs_file_log_next_done(struct replayfs_file_log *log, loff_t i_size) {
	struct replayfs_file_log_entry *entry;

	/* Update the entry's size */
	entry = replayfs_file_log_get_current(log);

	entry->file_size = i_size;

	entry->mtime = CURRENT_TIME_SEC;

	/* Mark the log that this entry is done */

	entry->offset = log->cur_data_offs;
	debugk("%s %d: Set entry->offset to %lld\n", __func__, __LINE__, entry->offset);

	replayfs_file_log_put_current(entry, log);

	log->num_entries++;

	mutex_unlock(&log->lock);
}

size_t replayfs_file_log_entry_add(struct replayfs_file_log_entry *entry,
		struct replayfs_file_log *log, const void *data, size_t size, loff_t pos) {
	loff_t offset;
	loff_t page_num;
	int offset_in_page;
	const char *cdata;

	size_t size_left;


	struct replayfs_file_mod *mod;

	if (entry->type == REPLAYFS_ENTRY_LOG_DATA) {
		debugk("%s %d: DETECTED NON-RECORD WRITE\n", __func__, __LINE__);
		debugk("%s %d: Called with argument (size) as (lld) %llu\n", __func__, __LINE__,
				(unsigned long long)size);

		/* Allocate space for the mod */

		/* Update the logs cur_data_offset entry */
		log->cur_data_offs += size + sizeof(struct replayfs_file_mod);

		/* 
		 * Ensure cur_data_offset is aligned to a struct replayfs_file_mod size 
		 *
		 * This alignment ensures we don't have to worry about fragmenting a
		 * replayfs_file_mod across pages! (NOTE: that is as long as struct
		 * replayfs_file_mod is less than a page size and a power of two)
		 */
		log->cur_data_offs += sizeof(struct replayfs_file_mod) - 1;
		log->cur_data_offs -= (unsigned int)log->cur_data_offs % sizeof(struct replayfs_file_mod);
		debugk("%s %d: aligned log->cur_data_offs to %llu\n", __func__,
				__LINE__, (unsigned long long)log->cur_data_offs);
		
		/* Find the initial offset of this modification */
		/* 
		 * Note: the modification information goes after the data (in logical space)
		 * so that modification entrys may be scanned in reverse 
		 */
		offset = log->cur_data_offs - sizeof(struct replayfs_file_mod);
		page_num = (unsigned int)offset / PAGE_SIZE;
		offset_in_page = (unsigned int)offset % PAGE_SIZE;

		/* Now that we know our offset, allocate a new offset header */
		cdata = page_alloc_get_page(&log->data_alloc, page_num);

		debugk("%s %d: Writing mod %d to %lld\n", __func__, __LINE__, entry->nmods, offset);
		mod = (struct replayfs_file_mod *)(cdata + offset_in_page);

		mod->offset = pos;
		mod->size = size;

		page_alloc_put_page(&log->data_alloc, (void *)cdata, page_num);

		cdata = data;

		/* Now begin filling in the data */
		offset -= size;
		size_left = size;
		/* Now fill the data in */
		while (size_left) {
			size_t nwritten;
			char *page;

			/* Find the initial offset of this modification */
			page_num = (unsigned int)offset / PAGE_SIZE;
			offset_in_page = (unsigned int)offset % PAGE_SIZE;

			/* How much space is left in the page? */
			nwritten = PAGE_SIZE - offset_in_page;

			/* Make sure we don't write too many bytes */
			if (nwritten > size_left) {
				nwritten = size_left;
			}

			/* Get our page */
			debugk("%s %d: Writing entry data to {%lld, %d}\n", __func__, __LINE__,
					page_num, offset_in_page);
			page = page_alloc_get_page(&log->data_alloc, page_num);

			memcpy(page + offset_in_page, cdata, nwritten);

			page_alloc_put_page(&log->data_alloc, page, page_num);

			cdata += nwritten;
			offset += nwritten;
			size_left -= nwritten;
		}
	} else {
		debugk("%s %d: DETECTED RECORD WRITE, not saving data\n", __func__, __LINE__);
		debugk("%s %d: Called with argument (size) as (lld) %llu\n", __func__, __LINE__,
				(unsigned long long)size);

		/* Allocate space for the mod */

		/* Update the logs cur_data_offset entry */
		log->cur_data_offs += sizeof(struct replayfs_file_mod);

		debugk("%s %d: updated log->cur_data_offs to %llu\n", __func__,
				__LINE__, (unsigned long long)log->cur_data_offs);
		
		/* Find the initial offset of this modification */
		/* 
		 * Note: the modification information goes after the data (in logical space)
		 * so that modification entrys may be scanned in reverse 
		 */
		offset = log->cur_data_offs - sizeof(struct replayfs_file_mod);
		page_num = (unsigned int)offset / PAGE_SIZE;
		offset_in_page = (unsigned int)offset % PAGE_SIZE;

		/* Now that we know our offset, allocate a new offset header */
		cdata = page_alloc_get_page(&log->data_alloc, page_num);

		debugk("%s %d: Writing mod %d to %lld\n", __func__, __LINE__, entry->nmods, offset);
		mod = (struct replayfs_file_mod *)(cdata + offset_in_page);

		mod->offset = pos;
		mod->size = size;

		page_alloc_put_page(&log->data_alloc, (void *)cdata, page_num);
	}

	entry->nmods++;

	return size;
}

size_t replayfs_file_log_entry_add_user(struct replayfs_file_log_entry *entry,
		struct replayfs_file_log *log, const void __user *data, size_t size, loff_t pos) {
	if (!access_ok(VERIFY_READ, data, size)) {
		return -EACCES;
	}

	return replayfs_file_log_entry_add(entry, log, (const void *)data, size, pos);
}

struct replayfs_file_log_entry *replayfs_file_log_get_current(
		struct replayfs_file_log *log) {

	struct replayfs_file_log_entry *entry;

	loff_t log_entry;
	loff_t page_of_entry;
	int offset_in_page;
	char *page;

	/* Which entry are we after? */
	log_entry = log->num_entries * sizeof(struct replayfs_file_log_entry);

	page_of_entry = log_entry / PAGE_SIZE;
	offset_in_page = log_entry % PAGE_SIZE;

	/* Lets load up the page */
	page = page_alloc_get_page(&log->entry_alloc, page_of_entry);

	entry = (struct replayfs_file_log_entry *)(page + offset_in_page);
	debugk("%s %d: {%lld, %d} entry->nmods (%p) is %d\n", __func__, __LINE__,
			page_of_entry, offset_in_page, &entry->nmods, entry->nmods);

	return entry;
}

void replayfs_file_log_put_current(struct replayfs_file_log_entry *entry,
		struct replayfs_file_log *log) {
	loff_t log_entry;
	loff_t page_of_entry;
	int offset_in_page;
	char *page;

	page = (char *)entry;


	/* Which entry are we after? */
	log_entry = log->num_entries * sizeof(struct replayfs_file_log_entry);

	page_of_entry = log_entry / PAGE_SIZE;
	offset_in_page = log_entry % PAGE_SIZE;

	page -= offset_in_page;

	debugk("%s %d: {%lld, %d} entry->nmods (%p) is %d\n", __func__, __LINE__,
			page_of_entry, offset_in_page, &entry->nmods, entry->nmods);
	page_alloc_put_page(&log->entry_alloc, page, page_of_entry);
}

int replayfs_file_log_entry_next_mod(struct replayfs_file_log_entry *entry,
		struct replayfs_file_log *log, struct replayfs_file_mod *mod,
		int j, loff_t *mod_offs) {

	if (entry->nmods < j) {
		BUG();
		return -1;
	}

	debugk("In %s\n", __func__);

	if (*mod_offs == MOD_OFFS_INIT) {
		char *cdata;
		struct replayfs_file_mod *tmp_mod;

		loff_t page_num;
		loff_t page_offs;

		*mod_offs = entry->offset - sizeof(struct replayfs_file_mod);
		/*
		debugk("%s %d: mod_offs 0, mod_offs reassigned to %llu\n", __func__, __LINE__,
				(unsigned long long)*mod_offs);

		debugk("%s %d: mod offset %lld\n", __func__, __LINE__, *mod_offs);
		*/

		page_num = (unsigned int)*mod_offs / PAGE_SIZE;
		page_offs = (unsigned int)*mod_offs % PAGE_SIZE;

		/*
		debugk("%s %d: page_num %llu page_offs %llu\n", __func__, __LINE__,
				(unsigned long long)page_num, (unsigned long long) page_offs);

		debugk("%s %d: calling page_alloc_get_page with log %p\n", __func__,
				__LINE__, log);
		*/
		cdata = page_alloc_get_page(&log->data_alloc, page_num);
		/*
		debugk("%s %d: out of page_alloc_get_page %p\n", __func__,
				__LINE__, log);
		*/

		tmp_mod = (struct replayfs_file_mod *)(cdata + page_offs);

		memcpy(mod, tmp_mod, sizeof(struct replayfs_file_mod));

		/* Rewind to point to the mod's data */
		if (entry->type == REPLAYFS_ENTRY_LOG_DATA) {
			*mod_offs -= mod->size;
		}

		page_alloc_put_page(&log->data_alloc, cdata, page_num);
	} else {
		char *cdata;
		struct replayfs_file_mod *tmp_mod;

		loff_t page_num;
		loff_t page_offs;

		/*
		debugk("%s %d: mod_offs non-zero branch, with mod_offs of %lld!\n", __func__,
				__LINE__, *mod_offs);
		*/

		/* Backtrack to before the prior mod */
		/* First reverse align the data */
		*mod_offs -= *mod_offs % sizeof(struct replayfs_file_mod);

		/* rewind to read the previous mod instead of its data */
		*mod_offs -= sizeof(struct replayfs_file_mod);

		/*debugk("%s %d: mod offset %lld\n", __func__, __LINE__, *mod_offs);*/

		/* Remap our page */
		page_num = (unsigned int)*mod_offs / PAGE_SIZE;
		page_offs = (unsigned int)*mod_offs % PAGE_SIZE;

		/* Get the new file mod */
		cdata = page_alloc_get_page(&log->data_alloc, page_num);

		tmp_mod = (struct replayfs_file_mod *)(cdata + page_offs);

		memcpy(mod, tmp_mod, sizeof(struct replayfs_file_mod));

		page_alloc_put_page(&log->data_alloc, cdata, page_num);

		/*
		debugk("%s %d: Mod at %lld has size %d\n", __func__, __LINE__, *mod_offs, mod->size);
		*/

		/* Rewind to point to the mod's data */
		if (entry->type == REPLAYFS_ENTRY_LOG_DATA) {
			*mod_offs -= mod->size;
		}
	}

	return 0;
}

/* How do we allocate arbitrary address ranges for this algorithm? */
ssize_t replayfs_file_log_read_user(struct replayfs_file_log *log, loff_t version,
		char __user *buf, size_t len, loff_t *ppos) {
	if (!access_ok(VERIFY_WRITE, buf, len)) {
		return -EACCES;
	}

	return replayfs_file_log_read(log, version, (void *)buf, len, ppos);
}

ssize_t replayfs_file_log_read(struct replayfs_file_log *log, loff_t version,
		char *buf, size_t len, loff_t *ppos) {
	int num_to_read;
	loff_t i;
	char *cbuf;

	struct replayfs_file_log_cache *cache;

	struct replay_desc *desc;
	struct replay_desc_state desc_state;

	struct range_set *range_set;

	struct range_set *n;

	/* 
	 * They are reading from a recorded file, reconstruct the file with the file's
	 * log 
	 */

	struct list_head range_list;

	desc = NULL;
	cbuf = buf;

	num_to_read = len;

	cache = log->log_cache;

	debugk("%s %d: In replayfs_file_log_read\n", __func__, __LINE__);
	if (version == REPLAYFS_CURRENT_VERSION) {
		version = replayfs_file_log_size(log) - 1;
	}

	/* Step 1, determine which log entries satisfy the read operation */
	INIT_LIST_HEAD(&range_list);

	/* Set up the range of addresses we need checked */
#ifdef FILE_LOG_MEMCHK
	range_set = kmem_cache_alloc(cache->range_set_cache, GFP_NOIO);
	alloc_debugk("%s %d: range_set_alloc %p\n", __func__, __LINE__, range_set);
#else
	range_set = kmalloc(sizeof(struct range_set), GFP_NOIO);
#endif
	BUG_ON(range_set == NULL);
	range_set->start = *ppos;
	range_set->size = num_to_read;

	list_add(&range_set->list, &range_list);

	debugk("%s %d: Searching for range (%lld, %lld)\n", __func__, __LINE__,
			range_set->start, range_set->size);

	/* 
	 * To do this we iterate backwards over the file's log and see which
	 * operations are relavent to our addresses
	 */
	/* Iterate in reverse */
	debugk("%s %d: version is %llu\n", __func__, __LINE__,
			(unsigned long long)version);

	for (i = version; i >= 0; i--) {
		int j;
		struct replayfs_file_log_entry *entry;

		struct replayfs_syscache_id id;

		loff_t mod_offs;

		loff_t entry_start;
		loff_t entry_end;

		/* 
		 * First check to see if any part of this version is satisfied by the
		 * syscall cache
		 */
		id.version = i;
		memcpy(&id.id, &log->id, sizeof(struct replayfs_unique_id));

#if 1
		perftimer_start(log->log_cache->read_cache_timer);
		/* For each range in the range set */
		list_for_each_entry_safe(range_set, n, &range_list, list) {
			struct replayfs_syscache_entry *entry;

			id.pos = range_set->start;

			/* Check if an entry exists in the entry cache */
			/*entry = replayfs_syscache_get(log->cache, &id, range_set->size);*/
			entry = replayfs_syscache_check(log->cache, &id, range_set->size);

			/* 
			 * If so, get the data from the entry, and remove the range from the range
			 * list 
			 */
			debugk("%s %d: entry is %p\n", __func__, __LINE__, entry);
			if (entry != NULL) {
				loff_t pos;
				size_t size;
				loff_t end;
				loff_t range_end;

				loff_t entry_pos;
				size_t entry_size;
				loff_t entry_end;

				int buf_offs;

				size = range_set->size;
				pos = range_set->start;

				entry_size = replayfs_syscache_entry_size(entry);
				debugk("%s %d: !!! entry_size is %d\n", __func__, __LINE__,
						entry_size);
				entry_pos = replayfs_syscache_entry_offset(entry);

				pos = (entry_pos < pos) ? pos : entry_pos;

				/* The number of bytes from pos to the end of entry */
				entry_end = entry_size+pos;
				range_end = size+pos;

				end = (range_end < entry_end) ? range_end : entry_end;

				size = end - pos;

				buf_offs = pos - *ppos;

				replayfs_syscache_entry_read(entry, cbuf+buf_offs, pos, size);

				replayfs_syscache_put(log->cache, entry);

				/* Now split/remove our range set after the modification... */

				/* 
				 * If we didn't hit the end of our range, put a new range_set into our
				 * range_list
				 */
				if (end != entry_end) {
					struct range_set *tmp;
#  ifdef FILE_LOG_MEMCHK
					tmp = kmem_cache_alloc(cache->range_set_cache, GFP_NOIO);
					alloc_debugk("%s %d: range_set_alloc %p\n", __func__, __LINE__, tmp);
#  else
					tmp = kmalloc(sizeof(struct range_set), GFP_NOIO);
#  endif
					/* ...crap */
					if (tmp == NULL) {
						BUG();
						return -ENOMEM;
					}

					tmp->start = end;
					tmp->size = range_end - entry_end;
					debugk("%s %d: setting tmp->size to %lld, range_end is %lld, entry_end is %lld\n",
							__func__, __LINE__, tmp->size, range_end, entry_end);

					list_add(&tmp->list, &range_set->list);

					/* 
					 * We need to evalute on this new range_set next iteration, just in case
					 * multiple entries map to the same range set 
					 */
					n = tmp;
				}

				/* If we hit the start, then remove this entry from our range list */
				if (pos != range_set->start) {
					range_set->size = pos-range_set->start;
					debugk("%s %d: setting range_set->size to %lld, pos is %lld, range_set->start is %lld\n",
							__func__, __LINE__, range_set->size, pos, range_set->start);
				} else {
					list_del(&range_set->list);
#  ifdef FILE_LOG_MEMCHK
					kmem_cache_free(cache->range_set_cache, range_set);
					alloc_debugk("%s %d: range_set_free %p\n", __func__, __LINE__,
							range_set);
#  else
					kfree(range_set);
#  endif
				}
			}
		}
		perftimer_stop(log->log_cache->read_cache_timer);
#endif

		perftimer_start(log->log_cache->log_get_entry_timer);
		entry = replayfs_file_log_get_entry(log, i);
		perftimer_stop(log->log_cache->log_get_entry_timer);

		/* Initialize, for odd interface... */
		debugk("%s %d: Version %lld, nmods: %d (%p)\n", __func__, __LINE__, i,
				entry->nmods, &entry->nmods);
		mod_offs = MOD_OFFS_INIT;

		/* 
		 * If this is a replay entry, then we need to index into the replay data
		 * structure
		 */

		if (entry->type != REPLAYFS_ENTRY_LOG_DATA) {
			/*debugk("%s %d: Getting cache desc\n", __func__, __LINE__);*/
			desc = replay_cache_get(entry->type);
			/*debugk("%s %d: Got desc (%p), Initializing read state\n", __func__,
					__LINE__, desc);*/
			replay_desc_state_init(desc, &desc_state);
			/*debugk("%s %d: Setting state info\n", __func__, __LINE__);*/

			/* Try to get the state info */
			if (replay_desc_state_set_info(desc, entry->sysnum, &log->id,
						&desc_state)) {
				printk("%s %d: desc_state_set_info FAILURE DETECTED!\n", __func__,
						__LINE__);
				/* Woah, we failed getting the state info... destroy everything */
				replay_desc_state_destroy(desc, &desc_state);
				replay_cache_put(desc);
				replayfs_file_log_put_entry(log, entry, i);
				list_for_each_entry_safe(range_set, n, &range_list, list) {
#ifdef FILE_LOG_MEMCHK
					kmem_cache_free(cache->range_set_cache, range_set);
					alloc_debugk("%s %d: range_set_free %p\n", __func__, __LINE__,
							range_set);
#else
					kfree(range_set);
#endif
				}
				num_to_read = -EINTR;
				goto out_fail;
			}
		}

		for (j = 0; j < entry->nmods; j++) {
			struct replayfs_file_mod mod;

			/*
			debugk("%s %d: Version %lld, mod: %d\n", __func__, __LINE__, i,
					entry->nmods - j);
					*/

			/* Find this mod */
			replayfs_file_log_entry_next_mod(entry, log, &mod, j, &mod_offs);

			/*
			debugk("%s %d: version %lld mod %d, offs %llu, size %u\n", __func__,
					__LINE__, i, j, (unsigned long long)mod.offset,
					(unsigned int)mod.size);
					*/

			entry_start = mod.offset;
			entry_end = mod.offset + mod.size -1;

			/* If this entry satisfies some of our needed addresses, reduce our range */
			list_for_each_entry_safe(range_set, n, &range_list, list) {
				loff_t range_start;
				loff_t range_end;
				loff_t nread;
				struct range_set *unsatisfied_bottom;
				struct range_set *unsatisfied_top;
				/* 
				 * To reduce our range, we need to split it, into the part before this
				 * entry satisfies, and after, this may also be part of a split range
				 * already... gah!
				 */
				/* Compare this range to the range provided by the entry */

				range_start = range_set->start;
				range_end = range_set->start + range_set->size - 1;

				/*
				debugk("%s %d: Checking range set {%lld, %lld}\n", __func__, __LINE__,
						range_start, range_end);
						*/
				/* Check for overlap */
				if (entry_start < range_end && entry_end > range_start) {
					loff_t bottom;
					loff_t top;
					loff_t data_offs;
					loff_t buf_offs;

					/* Cool, this overlaps.  Lets figure out which ranges overlap */
					/* Find the bottom range */
					bottom = entry_start;
					if (entry_start < range_start) {
						bottom = range_start;
					}

					top = entry_end;
					if (entry_end > range_end) {
						top = range_end;
					}

					buf_offs = (bottom - *ppos);

					/*
					debugk("%s %d: Found addr %llu - %llu in (ver,mod) (%lld,%d), reading the data\n",
							__func__, __LINE__, (unsigned long long)bottom,
							(unsigned long long)top, i, j);
							*/

					if (entry->type == REPLAYFS_ENTRY_LOG_DATA) {
						/* How far am I from the start of this data range? */
						data_offs = mod_offs + (bottom - entry_start);

						/*
						debugk("%s %d: Data_off (%llu) derrived from mod_offs (%llu), entry_start (%llu), and bottom (%llu)\n",
								__func__, __LINE__, (unsigned long long)data_offs,
								(unsigned long long)mod_offs, (unsigned long long)entry_start,
								(unsigned long long)bottom);
								*/

						/* Now, copy the required data over */
						/*
						debugk("%s %d: Reading %lld bytes of data at mod_offs %lld\n",
								__func__, __LINE__, top - bottom + 1, mod_offs);
						debugk("%s %d: Reading with buf_offs of %lld, ppos is %lld (%p), bottom is %lld\n",
								__func__, __LINE__, buf_offs, *ppos, ppos, bottom);
						*/
						nread = page_alloc_read(&log->data_alloc, cbuf + buf_offs,
								data_offs, top - bottom + 1);
					} else {
						/*
						debugk("%s %d: Reading addr %llu - %llu in (ver,mod) (%lld,%d), Into buffer at %p\n",
								__func__, __LINE__, (unsigned long long)bottom,
								(unsigned long long)top, i, j, cbuf+buf_offs);
						debugk("%s %d: Reading replay mod %d from replay cache\n", __func__,
								__LINE__, j);
						*/

						nread = replay_desc_state_read_mod(desc, &desc_state, cbuf + buf_offs, bottom,
								top-bottom+1);

						/* Also, add this data to the syscall cache */
						id.pos = bottom;
						id.version = version;

						/*
						debugk("%s %d: Adding to syscall cache %lld bytes at %lld, version %lld\n",
								__func__, __LINE__, top-bottom+1, bottom, version);
								*/

						/* Add the data to the syscall cache */
						replayfs_syscache_add(log->cache, &id, top-bottom+1, cbuf+buf_offs);

						id.version = i;
					}

					/*
					debugk("%s %d: Nread is now %llu top-bottom+1 is %llu\n", __func__, __LINE__,
							(unsigned long long)nread, (unsigned long long)(top-bottom+1));
					*/
					BUG_ON(nread != top - bottom + 1);

					/* Now that we've gotten this data take it out of our range */
					unsatisfied_bottom = NULL;
					unsatisfied_top = NULL;

					/*debugk("%s %d: Splitting any unread addresses\n", __func__, __LINE__);*/

					/* Lets populate any subset of this set we missed */
					/* If we didn't fill the entire bottom */
					/*
					debugk("%s %d: range_start %lld, bottom %lld\n", __func__, __LINE__, range_start, bottom);
					*/
					if (range_start != bottom) {
						/*
						debugk("%s %d: We did not allocate from the beginning of our range, updating our range set\n", __func__, __LINE__);
						*/
						/* Don't reallocate a range set, reuse the current memory space */
						unsatisfied_bottom = range_set;
						/* 
						 * The list is initialized already, so we don't need to deal with that
						 */

						unsatisfied_bottom->start = range_start;
						unsatisfied_bottom->size = entry_start - range_start;
					} 

					/*
					debugk("%s %d: range_end %lld, top %lld\n", __func__, __LINE__,
							range_end, top);
					*/
					if (range_end != top) {
						/*
						debugk("%s %d: We did not allocate from the end of our range, updating range set\n", __func__, __LINE__);
						*/
						if (unsatisfied_bottom == NULL) {
							/*debugk("%s %d: Recycling range_set\n", __func__, __LINE__);*/
							unsatisfied_top = range_set;
						} else {
							/*debugk("%s %d: Reallocating range_set\n", __func__, __LINE__);*/
#ifdef FILE_LOG_MEMCHK
							unsatisfied_top = kmem_cache_alloc(cache->range_set_cache,
									GFP_NOIO);
							alloc_debugk("%s %d: range_set_alloc %p\n", __func__, __LINE__,
									unsatisfied_top);
#else
							unsatisfied_top = kmalloc(sizeof(struct range_set), GFP_NOIO);
#endif
							/* 
							 * Put the top half after the bottom half on the order 
							 *     (keep it sorted)
							 */
							list_add(&unsatisfied_top->list, &unsatisfied_bottom->list);
							/* 
							 * The next entry we scan should be the top half (yes, this is
							 * hackish
							 */
							n = unsatisfied_top;
						}

						/* End is inclusive... */
						unsatisfied_top->start = entry_end + 1;
						unsatisfied_top->size = range_end - entry_end;
					} 

					if (unsatisfied_bottom == NULL && unsatisfied_top == NULL) {
						/*
						debugk("%s %d: This range set was complete, deleting and freeing\n",
								__func__, __LINE__);
						*/
						/* Clean up the current range_set */
						list_del(&range_set->list);
#ifdef FILE_LOG_CACHE
						kmem_cache_free(cache->range_set_cache, range_set);
						alloc_debugk("%s %d: range_set_free %p\n", __func__, __LINE__,
								range_set);
#else
						kfree(range_set);
#endif
					}

					/* If the range of unsatisfied addresses is empty we're done */
					/* See if we're done */
					if (list_empty(&range_list)) {
						debugk("%s %d: Got my last range, exiting\n",
								__func__, __LINE__);

						if (entry->type != REPLAYFS_ENTRY_LOG_DATA) {
							debugk("%s %d: Destroying state, freeing desc\n", __func__, __LINE__);
							replay_desc_state_destroy(desc, &desc_state);
							replay_cache_put(desc);
							debugk("%s %d: Done destroying state, freeing desc\n", __func__, __LINE__);
						}

						replayfs_file_log_put_entry(log, entry, i);

						goto out;
					}
				}
				debugk("%s %d: Done checking range set\n", __func__, __LINE__);
			}

			if (entry->type != REPLAYFS_ENTRY_LOG_DATA) {
				/*
				debugk("%s %d: Calling replay_desc_state_next_mod\n", __func__,
						__LINE__);
						*/
				replay_desc_state_next_mod(desc, &desc_state);
				/*
				debugk("%s %d: Done calling replay_desc_state_next_mod\n", __func__,
						__LINE__);
						*/
			}
		}

		debugk("%s %d: Finished checking version, freeing data and getting next version\n",
				__func__, __LINE__);

		if (entry->type != REPLAYFS_ENTRY_LOG_DATA) {
			debugk("%s %d: Destroying state, freeing desc\n", __func__, __LINE__);
			replay_desc_state_destroy(desc, &desc_state);
			replay_cache_put(desc);
			debugk("%s %d: Done destroying state, freeing desc\n", __func__, __LINE__);
		}

		replayfs_file_log_put_entry(log, entry, i);
	}


	/* 
	 * We may not have satisfied all ranges, for example we may read a page of a
	 * file that does not have the end of the file allocated...
	 *
	 * In that instance, we will zero fill the remainder of our ranges
	 */
	list_for_each_entry_safe(range_set, n, &range_list, list) {
		loff_t buf_offs;

		buf_offs = range_set->start - *ppos;
		/* Convert that range set into a buffer position */
		debugk("%s %d: Unsatisfied range at {%lld-%lld}, zeroing memory\n",
				__func__, __LINE__, range_set->start,
				range_set->start+range_set->size-1);
		memset(cbuf + buf_offs, 0, range_set->size);
#ifdef FILE_LOG_CACHE
		kmem_cache_free(cache->range_set_cache, range_set);
		alloc_debugk("%s %d: range_set_free %p\n", __func__, __LINE__,
				range_set);
#else
		kfree(range_set);
#endif
	}

	/* FIXME: Hacky printing */
	if (len == PAGE_SIZE) {
		debugk("%s %d: Reading a page, assuming its a directory\n", __func__,
				__LINE__);
#ifdef REPLAYFS_FILE_LOG_DEBUG
		dump_stack();
#endif

		for (i = 0; i < REPLAYFS_DIRS_PER_PAGE; i++) {
			debugk("%s %d: Dir[%lld] has size %d (%.*s)\n", __func__, __LINE__, i, 
					((struct replayfs_dir_page *)buf)->dirs[i].header.name_len,
					((struct replayfs_dir_page *)buf)->dirs[i].header.name_len,
					((struct replayfs_dir_page *)buf)->dirs[i].name);
		}
		
	}

out:
	/* return the number of bytes we read */
	*ppos += num_to_read;
out_fail:
	return num_to_read;
}

