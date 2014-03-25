#include "replayfs_filemap.h"
#include "replayfs_btree.h"
#include "replayfs_btree128.h"

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mm.h>

//#define REPLAYFS_FILEMAP_DEBUG

//#define REPLAYFS_FILEMAP_DEBUG_LOCK

#ifdef  REPLAYFS_FILEMAP_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

#ifdef  REPLAYFS_FILEMAP_DEBUG_LOCK_META
#define meta_lock_debugk(...) printk(__VA_ARGS__)
#else
#define meta_lock_debugk(...)
#endif

#ifdef  REPLAYFS_FILEMAP_DEBUG_LOCK
#define lock_debugk(...) printk(__VA_ARGS__)
#else
#define lock_debugk(...)
#endif

static DEFINE_MUTEX(meta_lock);
extern struct replayfs_btree128_head filemap_meta_tree;

static int replayfs_filemap_create(struct replayfs_filemap *map,
		struct replayfs_diskalloc *alloc, struct replayfs_btree128_key *key, loff_t *pos) {
	int ret;
	struct page *page;
	struct replayfs_btree128_value val;

	/* Populate val */
	page = replayfs_diskalloc_alloc_page(alloc);

	if (pos) {
		*pos = PAGE_SIZE * (loff_t)page->index;
	}

	replayfs_diskalloc_put_page(alloc, page);

	ret = replayfs_btree_create(&map->entries, alloc,
			PAGE_SIZE * (loff_t)page->index);
	if (ret) {
		//replayfs_diskalloc_free_page(alloc, page);
		goto out;
	}

	val.id = PAGE_SIZE * (loff_t)page->index;

	/*
	printk("%s %d - %p: Inserting tree with key {%llu, %llu} to {%lld}\n",
			__func__, __LINE__, current, key->id1, key->id2, val.id);
			*/
	BUG_ON(!mutex_is_locked(&meta_lock));
	ret = replayfs_btree128_insert(&filemap_meta_tree, key, &val,
			GFP_KERNEL);

	if (ret) {
		/* error is -EEXIST or -ENOMEM... thats bad */
		replayfs_btree_destroy(&map->entries);
		//replayfs_diskalloc_free_page(alloc, page);
		BUG();
		goto out;
	}

out:
	return ret;
}

int replayfs_filemap_init_key (struct replayfs_filemap *map,
		struct replayfs_diskalloc *alloc, struct replayfs_btree128_key *key) {
	int ret;
	struct replayfs_btree128_value *disk_pos;
	struct page *page;

	meta_lock_debugk("%s %d - %p: Locking %p\n", __func__, __LINE__, current,
			&meta_lock);
	mutex_lock(&meta_lock);
	meta_lock_debugk("%s %d - %p: Locked %p\n", __func__, __LINE__, current,
			meta_lock);
	/* Check for this file in the meta btree */
	/*
	printk("%s %d - %p: Looking for key {%llu, %llu}  -- ",
			__func__, __LINE__, current, key->id1, key->id2);
			*/
	disk_pos = replayfs_btree128_lookup(&filemap_meta_tree, key, &page);
	/*
	if (disk_pos != NULL) {
		printk("Found!\n");
	} else {
		printk("Not Found\n");
	}
	*/

	/* If exists */
	if (disk_pos != NULL) {
		loff_t id;
		/*
		debugk("%s %d: Opening filemap for file {%llu} with disk_pos of %lld\n",
				__func__, __LINE__, inode->i_ino, disk_pos->id);
				*/

		id = disk_pos->id;
		replayfs_btree128_put_page(&filemap_meta_tree, page);
		meta_lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
				&meta_lock);
		mutex_unlock(&meta_lock);

		debugk("%s %d: ----LOADING btree from %lld\n", __func__, __LINE__,
				disk_pos->id);
		lock_debugk("%s %d - %p: Mutex init: %p\n", __func__, __LINE__, current, &map->lock);
		mutex_init(&map->lock);
		ret = replayfs_btree_init(&map->entries, alloc, id);
	} else {
		meta_lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
				&meta_lock);
		mutex_unlock(&meta_lock);
		ret = -ENOENT;
	}

	if (ret) {
		goto out;
	}

out:
	return ret;
}

int replayfs_filemap_exists(struct file *filp) {
	int ret;
	struct replayfs_btree128_value *disk_pos;
	struct page *page;
	struct replayfs_btree128_key key;

	glbl_diskalloc_init();

	//printk("%s %d: Checking for the existance of %p\n", __func__, __LINE__, filp);
	/* Give the file a unique id, filp->dentry->ino->sb->s_dev concat ino->i_no */
	key.id1 = filp->f_dentry->d_inode->i_ino;
	key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;
	//printk("%s %d: Checking for the existance of {%lld, %lld}\n", __func__,
			//__LINE__, key.id1, key.id2);

	meta_lock_debugk("%s %d - %p: Locking %p\n", __func__, __LINE__, current,
			&meta_lock);
	mutex_lock(&meta_lock);
	meta_lock_debugk("%s %d - %p: Locked %p\n", __func__, __LINE__, current,
			&meta_lock);
	/* Check for this file in the meta btree */
	/*
	printk("%s %d - %p: Looking for key {%llu, %llu}  -- ",
			__func__, __LINE__, current, key.id1, key.id2);
			*/
	disk_pos = replayfs_btree128_lookup(&filemap_meta_tree, &key, &page);
	/*
	if (disk_pos != NULL) {
		printk("Found!\n");
	} else {
		printk("Not Found\n");
	}
	*/

	/* If exists */
	if (disk_pos != NULL) {
		ret = 1;
		replayfs_btree128_put_page(&filemap_meta_tree, page);
	} else {
		ret = 0;
	}

	//printk("%s %d: Ret for %p is %d\n", __func__, __LINE__, filp, ret);
	meta_lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
			&meta_lock);
	mutex_unlock(&meta_lock);

	return ret;
}

/* Reinitialize with the location of the root node */
int replayfs_filemap_init_with_pos(struct replayfs_filemap *map,
		struct replayfs_diskalloc *alloc, struct file *filp, loff_t *meta_pos) {
	int ret;
	struct replayfs_btree128_value *disk_pos;
	struct page *page;
	struct replayfs_btree128_key key;

	glbl_diskalloc_init();

	/* Give the file a unique id, filp->dentry->ino->sb->s_dev concat ino->i_no */
	key.id1 = filp->f_dentry->d_inode->i_ino;
	key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

	lock_debugk("%s %d - %p: Mutex init: %p\n", __func__, __LINE__, current, &map->lock);
	mutex_init(&map->lock);

	meta_lock_debugk("%s %d - %p: Locking %p\n", __func__, __LINE__, current,
			&meta_lock);
	mutex_lock(&meta_lock);
	meta_lock_debugk("%s %d - %p: Locked %p\n", __func__, __LINE__, current,
			&meta_lock);
	/* Check for this file in the meta btree */
	debugk("%s %d: Checking btree for key {%lld, %lld}\n", __func__, __LINE__,
			key.id1, key.id2);
	/*
	printk("%s %d - %p: Looking for key {%llu, %llu}  -- ",
			__func__, __LINE__, current, key.id1, key.id2);
			*/
	disk_pos = replayfs_btree128_lookup(&filemap_meta_tree, &key, &page);
	/*
	if (disk_pos != NULL) {
		printk("Found!\n");
	} else {
		printk("Not Found\n");
	}
	*/

	/* If exists */
	if (disk_pos != NULL) {
		loff_t id;
		/*
		debugk("%s %d: Opening filemap for file {%llu} with disk_pos of %lld\n",
				__func__, __LINE__, inode->i_ino, disk_pos->id);
				*/

		id = disk_pos->id;
		*meta_pos = id;
		replayfs_btree128_put_page(&filemap_meta_tree, page);
		meta_lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
				&meta_lock);
		mutex_unlock(&meta_lock);

		debugk("%s %d: ----LOADING btree from %lld\n", __func__, __LINE__,
				disk_pos->id);
		ret = replayfs_btree_init(&map->entries, alloc, id);
	} else {
		debugk("%s %d: ----Creating btree\n", __func__, __LINE__);
		/* Save the location of the btree entry metadata in the meta btree */
		ret = replayfs_filemap_create(map, alloc, &key, meta_pos);
		debugk("%s %d: ----Btree created at %lld\n", __func__, __LINE__,
				map->entries.meta_loc);

		meta_lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
				&meta_lock);
		mutex_unlock(&meta_lock);
	}

	if (ret) {
		goto out;
	}

out:
	return ret;
}

int replayfs_filemap_init(struct replayfs_filemap *map,
		struct replayfs_diskalloc *alloc, struct file *filp) {
	int ret;
	struct replayfs_btree128_value *disk_pos;
	struct page *page;
	struct replayfs_btree128_key key;

	glbl_diskalloc_init();

	/* Give the file a unique id, filp->dentry->ino->sb->s_dev concat ino->i_no */
	key.id1 = filp->f_dentry->d_inode->i_ino;
	key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

	lock_debugk("%s %d - %p: Mutex init: %p\n", __func__, __LINE__, current, &map->lock);
	mutex_init(&map->lock);

	meta_lock_debugk("%s %d - %p: Locking %p\n", __func__, __LINE__, current,
			&meta_lock);
	mutex_lock(&meta_lock);
	meta_lock_debugk("%s %d - %p: Locked %p\n", __func__, __LINE__, current,
			&meta_lock);
	/* Check for this file in the meta btree */
	/*
	printk("%s %d - %p: Looking for key {%llu, %llu}  -- ",
			__func__, __LINE__, current, key.id1, key.id2);
			*/
	disk_pos = replayfs_btree128_lookup(&filemap_meta_tree, &key, &page);
	/*
	if (disk_pos != NULL) {
		printk("Found!\n");
	} else {
		printk("Not Found\n");
	}
	*/

	/* If exists */
	if (disk_pos != NULL) {
		loff_t id;
		/*
		debugk("%s %d: Opening filemap for file {%llu} with disk_pos of %lld\n",
				__func__, __LINE__, inode->i_ino, disk_pos->id);
				*/

		id = disk_pos->id;
		replayfs_btree128_put_page(&filemap_meta_tree, page);
		meta_lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
				&meta_lock);
		mutex_unlock(&meta_lock);

		debugk("%s %d: ----LOADING btree from %lld\n", __func__, __LINE__,
				disk_pos->id);
		ret = replayfs_btree_init(&map->entries, alloc, id);
	} else {
		debugk("%s %d: ----Creating btree for file %.*s\n", __func__, __LINE__,
				filp->f_dentry->d_name.len, filp->f_dentry->d_name.name);
		/* Save the location of the btree entry metadata in the meta btree */
		ret = replayfs_filemap_create(map, alloc, &key, NULL);
		debugk("%s %d: ----Btree created at %lld\n", __func__, __LINE__,
				map->entries.meta_loc);
		meta_lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
				&meta_lock);
		mutex_unlock(&meta_lock);
	}

	if (ret) {
		goto out;
	}

out:
	return ret;
}

void replayfs_filemap_destroy(struct replayfs_filemap *map) {
	mutex_destroy(&map->lock);
	replayfs_btree_destroy(&map->entries);
}

void replayfs_filemap_delete(struct replayfs_filemap *map, struct file *filp) {
	struct replayfs_btree128_key key;

	mutex_destroy(&map->lock);

	key.id1 = filp->f_dentry->d_inode->i_ino;
	key.id2 = filp->f_dentry->d_inode->i_sb->s_dev;

	debugk("%s %d: Deleting btree\n", __func__, __LINE__);
	replayfs_btree_delete(&map->entries);
	debugk("%s %d: Done deleting btree\n", __func__, __LINE__);

	meta_lock_debugk("%s %d - %p: Locking %p\n", __func__, __LINE__, current,
			&meta_lock);
	mutex_lock(&meta_lock);
	/*
	printk("%s %d - %p: Removing key {%llu, %llu}\n", __func__, __LINE__, current,
			key.id1, key.id2);
			*/
	replayfs_btree128_remove(&filemap_meta_tree, &key);
	meta_lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
			&meta_lock);
	mutex_unlock(&meta_lock);
	debugk("%s %d: Done\n", __func__, __LINE__);
}

int replayfs_filemap_write(struct replayfs_filemap *map, loff_t unique_id,
		pid_t pid, loff_t syscall_num, char mod, loff_t offset, int size) {
	int ret = 0;

	struct replayfs_btree_key key;
	struct replayfs_btree_value value;

	value.id.unique_id = unique_id;
	value.id.pid = pid;
	value.id.sysnum = syscall_num;
	value.buff_offs = 0;

	key.offset = offset;
	key.size = size;

	debugk("%s %d: Inserting into filemap btree (%lld) key {%lld, %lld}\n", __func__,
			__LINE__, map->entries.meta_loc, key.offset, key.size);
	lock_debugk("%s %d - %p: Locking %p\n", __func__, __LINE__, current,
			&map->lock);
	mutex_lock(&map->lock);
	lock_debugk("%s %d - %p: Locked %p\n", __func__, __LINE__, current,
			&map->lock);
	debugk("%s %d: Filemap writing to %lld, %p\n", __func__, __LINE__,
			map->entries.meta_loc, map->entries.node_page);
	ret = replayfs_btree_insert_update(&map->entries, &key, &value, GFP_NOFS);
	lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
			&map->lock);
	mutex_unlock(&map->lock);
	debugk("%s %d: Btree insert update\n", __func__, __LINE__);

	/*
	debugk("%s %d: Wrote to filemap for inode %lu with disk_pos of %lld\n",
			__func__, __LINE__, map->owner->i_ino,
			replayfs_filemap_disk_pos(map));
			*/

	return ret;
}

struct replayfs_filemap_entry *replayfs_filemap_read(struct replayfs_filemap *map,
		loff_t offset, int size) {
	loff_t ret;
	int vals_index;
	int vals_size = 1<<4;
	struct replayfs_filemap_value *vals;
	struct replayfs_filemap_entry *entry;

	loff_t end_addr = offset+size;
	loff_t cur_addr = offset;

	debugk("%s %d: In %s!\n", __func__, __LINE__, __func__);
	vals = kmalloc(sizeof(struct replayfs_filemap_value) * vals_size, GFP_KERNEL);
	debugk("%s %d: vals is %p\n", __func__, __LINE__, vals);
	if (vals == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	vals_index = 0;

	debugk("%s %d: Doing read with offset %lld, size %d, cur_addr %lld end_addr %lld\n",
			__func__, __LINE__, offset, size, cur_addr, end_addr);

	lock_debugk("%s %d - %p: Locking %p\n", __func__, __LINE__, current,
			&map->lock);
	mutex_lock(&map->lock);
	lock_debugk("%s %d - %p: Locked %p\n", __func__, __LINE__, current,
			&map->lock);

	ret = 0;

	/* Okay, here is the fun part.  First find all of the ranges */
	while (cur_addr < end_addr) {
		loff_t val_end;
		loff_t entry_end;
		loff_t size;
		loff_t offset;
		struct replayfs_btree_key key;
		struct replayfs_btree_value *val;
		struct page *btree_page;

		debugk("%s %d: Filemap reading from %lld, %p\n", __func__, __LINE__,
				map->entries.meta_loc, map->entries.node_page);
		val = replayfs_btree_lookup(&map->entries,
				cur_addr, &key, &btree_page);

		if (val == NULL) {
			lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
					&map->lock);
			mutex_unlock(&map->lock);
			return ERR_PTR(-ENOENT);
		}

		if (IS_ERR(val)) {
			lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
					&map->lock);
			mutex_unlock(&map->lock);
			return (void *)val;
		}

		debugk("%s %d: Got val!\n", __func__, __LINE__);
		/* Now I have a set of ranges, figure out what ranges */
		val_end = key.offset + key.size;

		entry_end = val_end;
		if (val_end > end_addr) {
			entry_end = end_addr;
		}

		size = key.offset + key.size - cur_addr;
		if (key.offset + key.size > end_addr) {
			size = end_addr - cur_addr;
		}

		offset = cur_addr - key.offset;

		/* The range from cur_addr to entry_end is from this entry */
		/* Okay, I need to do some fancy magik stuffs here... */
		/* I don't know the size of this list before I build it, but I need a list... */
		/* I eventually want to put it in one large malloced chunk */
		/* Run this twice?  thats double the tree searches... ugh */
		/* Maybe instead I can do some malloc list magic... it'll be ugly though */
		/* I can over-allocate, then keep a pointer... */
		/* I can allocate a separate list structure... */
		/* 
		 * Lets just allocate a few pointers, and if they overflow, we'll get some
		 * more... One allocation, shouldn't take much memory
		 */
		/* Need to grow vals... */
		if (vals_index == vals_size) {
			struct replayfs_filemap_value *old_vals;
			vals_size <<=1;
			old_vals = vals;
			lock_debugk("%s %d: Trying to allocate %lld bytes\n", __func__, __LINE__,
					sizeof(struct replayfs_filemap_value) * (loff_t)vals_size);
			vals = kmalloc(sizeof(struct replayfs_filemap_value) * vals_size,
					GFP_KERNEL);
			if (vals == NULL) {
				printk("%s %d: vals allocation failed???\n", __func__, __LINE__);
				vals = old_vals;
				ret = -ENOMEM;
				goto out_unlock;
			}
			memcpy(vals, old_vals,
					sizeof(struct replayfs_filemap_value) * (vals_size>>1));
			debugk("%s %d: here!\n", __func__, __LINE__);
			kfree(old_vals);
		}
		/*
		printk("%s %d: Adding val with buff_offs %u!\n", __func__, __LINE__,
				val->buff_offs);
				*/
		memcpy(&vals[vals_index].bval, val, sizeof(struct replayfs_btree_value));
		vals[vals_index].offset = key.offset;
		vals[vals_index].size = size;
		vals[vals_index].read_offset = offset;
		vals_index++;

		debugk("%s %d: Updating cur_addr (%lld) to val_end (%lld)\n", __func__, __LINE__,
				cur_addr, val_end);
		cur_addr = val_end;

		replayfs_btree_put_page(&map->entries, btree_page);
	}
	lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
			&map->lock);
	mutex_unlock(&map->lock);

	/* Now copy the vals into a dedup struct */
	/* First allocate it */
	entry = kmalloc(
			sizeof(struct replayfs_filemap_entry) + 
			(sizeof(struct replayfs_filemap_value) * vals_index), GFP_KERNEL);
	if (entry == NULL) {
		ret = -ENOMEM;
		goto out;
	}


	debugk("%s %d: about to alloc/copy with vals_index of %d!\n", __func__, __LINE__, vals_index);
	memcpy(entry->elms, vals, vals_index * sizeof(struct replayfs_filemap_value));
	entry->num_elms = vals_index;

	debugk("%s %d: here, entry->num_elms is %d!\n", __func__, __LINE__,
			entry->num_elms);

out:
	kfree(vals);
	if (ret) {
		debugk("%s %d: Erroring out with ret %lld!\n", __func__, __LINE__, ret);
		entry = ERR_PTR(ret);
	}
	return entry;

out_unlock:
	lock_debugk("%s %d - %p: Unlocking %p\n", __func__, __LINE__, current,
			&map->lock);
	mutex_unlock(&map->lock);
	goto out;
}

