/* 
 * Methods just for inode manipulation, and creation
 */

#include <linux/replay_syscall_result.h>
#include <linux/replay.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/thread_info.h>
#include <linux/sched.h>

#include "replayfs_fs.h"
#include "replayfs_inode.h"
#include "replayfs_dir.h"

/* #define REPLAYFS_INODE_DEBUG */

#ifdef REPLAYFS_INODE_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

unsigned int hash_int(unsigned int a) {
	a = (a+0x7ed55d16) + (a<<12);
	a = (a^0xc761c23c) ^ (a>>19);
	a = (a+0x165667b1) + (a<<5);
	a = (a+0xd3a2646c) ^ (a<<9);
	a = (a+0xfd7046c5) + (a<<3);
	a = (a^0xb55a4f09) ^ (a>>16);
	return a;
}

unsigned int hash_int64(loff_t a) {
	unsigned int hash = 0;

	hash ^= hash_int(a & 0xFFFFFFFF);
	hash ^= hash_int(a >> 32);

	return hash;
}

unsigned int replayfs_id_hash(struct replayfs_unique_id *id) {
	unsigned int hash = 0;

	hash ^= hash_int64(id->log_num);
	hash ^= hash_int64(id->sys_num);

	return hash;
}

void replayfs_get_unique(struct inode *inode, struct replayfs_unique_id *id) {
	/* Figure out what our unique ID should be from the replay log */
	/* If this is a record thread pull it from there */
	if (test_thread_flag(TIF_RECORD)) {
		struct syscall_log *log;

		/* Pull thread data from record thread structure */
		log = &current->record_thrd->syscall_log;

		/* syscall_num from the syscall_log structure */
		id->sys_num = syscall_log_size(log);

		/* File unique id -- inode -- name from the syscall_log's file_name */
		id->log_num = current->record_thrd->unique_id;

	/* If this is a replay thread, we shouldn't be here! */
	} else if (test_thread_flag(TIF_REPLAY)) {
		BUG();

	/* 
	 * If this is neither we need to make up a unique id... we'll take the inode
	 * number...
	 */
	} else {
		id->sys_num = REPLAYFS_SYS_NUM_RECORDED;
		id->log_num = inode->i_ino;
	}
}

void inode_detach(struct inode *inode) {
	struct replayfs_inode_info *info;
	struct super_block *sb;
	struct replayfs_sb_info *sbi;

	sb = inode->i_sb;
	sbi = REPLAYFS_SB(sb);

	info = REPLAYFS_I(inode);

	debugk("%s %d: Removing inode: {%u, %lld, %lld} (%p)\n", __func__, __LINE__,
			(unsigned int)info->id.log_num, info->id.sys_num, info->version, info);

	spin_lock(&sbi->i_get_lock);
	hlist_del(&info->i_get_hash);
	spin_unlock(&sbi->i_get_lock);
}

void inode_attach(struct inode *inode) {
	struct replayfs_inode_info *info;
	struct super_block *sb;
	struct replayfs_sb_info *sbi;

	sb = inode->i_sb;
	sbi = REPLAYFS_SB(sb);

	info = REPLAYFS_I(inode);

	debugk("%s %d: Inserting inode: {%u, %lld, %lld} (%p)\n", __func__, __LINE__,
			(unsigned int)info->id.log_num, info->id.sys_num, info->version, info);

	spin_lock(&sbi->i_get_lock);
	hlist_add_head(&info->i_get_hash, &sbi->i_get_head);
	spin_unlock(&sbi->i_get_lock);
}

struct inode *replayfs_iget(struct super_block *sb,
		struct replayfs_unique_id *id, loff_t version) {
	struct inode *ret;
	struct raw_inode *raw;
	struct replayfs_sb_info *sbi;
	struct hlist_head *head;
	struct hlist_node *node;
	struct replayfs_inode_info *i;

	struct replayfs_file_log_entry *entry;

	loff_t pos = 0;

	ret = NULL;

	sbi = REPLAYFS_SB(sb);
	head = &sbi->i_get_head;

	debugk("%s %d: Searching for: {%u, %lld, %lld}\n", __func__, __LINE__,
			(unsigned int)id->log_num, id->sys_num, version);

	spin_lock(&sbi->i_get_lock);

	hlist_for_each_entry(i, node, head, i_get_hash) {
		debugk("%s %d: List gave an inode %p\n", __func__, __LINE__, i);

		debugk("%s %d: checking against: {%u, %lld, %lld}\n", __func__, __LINE__,
				(unsigned int)i->id.log_num, i->id.sys_num, i->version);

		debugk("%s %d: SB DEBUG: i->vfs_inode.i_sb: %p,  sb: %p\n", __func__,
				__LINE__, i->vfs_inode.i_sb, sb);
		BUG_ON(i->vfs_inode.i_sb != sb);

		if (!replayfs_id_matches(id, &i->id) || i->version != version) {
			continue;
		}

		ret = igrab(&i->vfs_inode);
		if (ret) {
			spin_unlock(&sbi->i_get_lock);

			debugk("%s %d: Returning inode %p with count %d\n", __func__, __LINE__, ret,
					atomic_read(&ret->i_count));

			return ret;
		}
	}

	debugk("%s %d: Spin locking sbi->i_get_lock\n", __func__, __LINE__);
	spin_unlock(&sbi->i_get_lock);
	debugk("%s %d: Spin locked sbi->i_get_lock\n", __func__, __LINE__);

	raw = kmalloc(sizeof(*raw), GFP_NOFS);
	if (raw == NULL) {
		return ERR_PTR(-ENOMEM);
	}

	/* We don't have the inode cached... see if we have the backing store held */
	ret = new_inode(sb);

	/* Make sure the inode's super block is set up... */
	ret->i_sb = sb;

	if (ret == NULL) {
		kfree(raw);
		return ERR_PTR(-ENOMEM);
	}

	BUG_ON(sizeof(struct raw_inode) > PAGE_SIZE);

	ret->i_ino = iunique(sb, REPLAYFS_ROOT_INO);

	debugk("%s %d: At replayfs_file_log_cache_get\n", __func__, __LINE__);
	REPLAYFS_I(ret)->file_log = replayfs_file_log_cache_get(&sbi->cache, id);
	debugk("%s %d: Past replayfs_file_log_cache_get\n", __func__, __LINE__);
	
	REPLAYFS_I(ret)->version = version;

	memcpy(&REPLAYFS_I(ret)->id, id, sizeof(struct replayfs_unique_id));

	/* Initialize the inode from its data */
	debugk("%s %d: At replayfs_file_log_read\n", __func__, __LINE__);
	replayfs_file_log_read(REPLAYFS_I(ret)->file_log, version, (void*)raw,
			sizeof(*raw), &pos);
	debugk("%s %d: past replayfs_file_log_read\n", __func__, __LINE__);

	ret->i_mode = raw->mode;
	ret->i_uid = raw->uid;
	ret->i_gid = raw->gid;

	debugk("%s %d: Inode loaded, mode is %04o, uid is %d, gid is %d\n", __func__,
			__LINE__, ret->i_mode, ret->i_uid, ret->i_gid);

	ret->i_version = 1;

	/* Setup timestuffs */
	ret->i_ctime = raw->ctime;
	ret->i_atime = CURRENT_TIME_SEC;

	/* For the purpose of getting data, user the actual current version */
	if (version == REPLAYFS_CURRENT_VERSION) {
		version = replayfs_file_log_size((REPLAYFS_I(ret))->file_log)-1;
		debugk("%s %d: Reassigned version to %lld\n", __func__, __LINE__, version);
	}

	/* Get the mtime of this version */
	entry = replayfs_file_log_get_entry(REPLAYFS_I(ret)->file_log, version);
	ret->i_mtime = replayfs_file_log_entry_mtime(entry);
	i_size_write(ret, entry->file_size);

	debugk("%s %d: Loaded new i_size of %lld\n", __func__, __LINE__,
			entry->file_size);
	replayfs_file_log_put_entry(REPLAYFS_I(ret)->file_log, entry, version);

	/* 
	 * We don't really count link counts.... this will not be unlinked ever
	 * though, because we never forget anything!
	 */

	inode_attach(ret);
	insert_inode_hash(ret);

	/* Set up the address and file operations... this is based on the mode */
	if (S_ISDIR(ret->i_mode)) {
		ret->i_op = &replayfs_dir_iops;
		ret->i_fop = &replayfs_dir_fops;
		ret->i_mapping->a_ops = &replayfs_aops;
	} else {
		ret->i_op = &replayfs_file_iops;
		ret->i_fop = &replayfs_fops;
		ret->i_mapping->a_ops = &replayfs_aops;
	}

	kfree(raw);

	debugk("%s %d: Returning inode %p with count %d\n", __func__, __LINE__, ret,
			atomic_read(&ret->i_count));

	return ret;
}

struct inode *replayfs_inode_init(struct inode *inode, struct super_block *sb,
		loff_t version, int mode) {
	struct inode *ret;
	int err;
	struct replayfs_file_log_entry *entry;

	ret = inode;

	inode->i_ino = iunique(sb, REPLAYFS_ROOT_INO);

	/* Look up our log based on this identifier */
	REPLAYFS_I(inode)->file_log = replayfs_file_log_cache_get(&REPLAYFS_SB(sb)->cache,
			&REPLAYFS_I(inode)->id);
	debugk("%s %d: Allocated inode file log: %p\n", __func__, __LINE__,
			REPLAYFS_I(inode)->file_log);

	/* inodes default to the current version... */
	REPLAYFS_I(inode)->version = version;

	inode->i_uid = current->fsuid;
	inode->i_gid = current->fsgid;

	inode->i_mode = mode;
	inode->i_version = 1;
	err = 0;
	if (err) {
		iput(inode);
		ret = ERR_PTR(err);
		goto out;
	}

	/* Get the file's current size */
	if (version == REPLAYFS_CURRENT_VERSION) {
		version = replayfs_file_log_size(REPLAYFS_I(inode)->file_log) - 1;
	}

	if (version >= 0) {
		entry = replayfs_file_log_get_entry(REPLAYFS_I(inode)->file_log,
				REPLAYFS_I(inode)->version);

		debugk("%s %d: Reading size from version %lld, entry is %p, file size is %lld\n",
				__func__, __LINE__, version, entry, entry->file_size);
		i_size_write(inode, entry->file_size);

		replayfs_file_log_put_entry(REPLAYFS_I(inode)->file_log, entry,
				REPLAYFS_I(inode)->version);
	} else {
		i_size_write(inode, 0);
	}

	inode->i_mtime = inode->i_ctime = inode->i_atime = CURRENT_TIME_SEC;

	inode->i_sb = sb;

	inode_attach(inode);
	insert_inode_hash(inode);

out:
	return ret;
}

struct inode *replayfs_new_inode(struct super_block *sb, int mode) {
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode) {
		inode = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* Get our (deterministic) unique identifier */
	replayfs_get_unique(inode, &REPLAYFS_I(inode)->id);

	inode = replayfs_inode_init(inode, sb, REPLAYFS_CURRENT_VERSION, mode);

out:
	return inode;
}

struct dentry *replayfs_inode_lookup(struct inode *dir,
		struct dentry *dentry, struct nameidata *nameidata) {
	struct inode *file_inode;
	struct super_block *sb;
	struct dentry *ret;
	struct replayfs_unique_id id;

	int ino;

	sb = dir->i_sb;

	debugk("%s looking up inode %s\n", __func__, dentry->d_name.name);

	file_inode = NULL;
	ino = replayfs_inode_by_name(dir, dentry, &id);
	if (ino) {
		debugk("%s %s IS  found!\n", __func__, dentry->d_name.name);
		file_inode = replayfs_iget(sb, &id, REPLAYFS_CURRENT_VERSION);
		if (IS_ERR(file_inode)) {
			return ERR_CAST(file_inode);
		}
	} else {
		debugk("%s %s NOT found!\n", __func__, dentry->d_name.name);
	}

	ret = d_splice_alias(file_inode, dentry);

	return ret;
}

loff_t replayfs_inode_version(struct inode *inode) {
	loff_t version;

	version = REPLAYFS_I(inode)->version;

	/* Get the file's current size */
	if (version == REPLAYFS_CURRENT_VERSION) {
		version = replayfs_file_log_size(REPLAYFS_I(inode)->file_log) - 1;
	}

	return version;
}

/* 
 * Must be called after replayfs_file_log_add_next, but before
 * replayfs_file_log_next_done if the metadata (ctime, nlinks, uid, gid, mode)
 * of the inode have been changed
 */
void replayfs_inode_modified_metadata(struct inode *inode, replayfs_log_t *log,
		replayfs_log_inode_t *log_inode) {
	struct raw_inode raw;

	loff_t pos = 0;

	raw.ctime = inode->i_ctime;
	raw.uid = inode->i_uid;
	raw.gid = inode->i_gid;
	raw.mode = inode->i_mode;
	/*raw.nlink = inode->i_nlink;*/

	replayfs_log_add_mod(log, log_inode, &raw, sizeof(raw),
			pos);
}

