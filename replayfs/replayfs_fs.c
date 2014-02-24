#include "replayfs_fs.h"
#include "replayfs_inode.h"
#include "replayfs_dir.h"
#include "replayfs_acl.h"
#include "replayfs_file_log.h"
#include "replayfs_log.h"
#include "replayfs_syscall_cache.h"
#include "replayfs_perftimer.h"

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/statfs.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <asm/errno.h>
#include <linux/buffer_head.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/mount.h>

#define replayfs_assert(X) BUG_ON((X) == 0)

/* #define REPLAYFS_FS_DEBUG */
/* #define REPLAYFS_ALLOC_DEBUG */

#ifdef REPLAYFS_FS_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

#ifdef REPLAYFS_ALLOC_DEBUG
#define alloc_debugk(...) printk(__VA_ARGS__)
#define alloc_dump_stack() dump_stack()
#else
#define alloc_debugk(...)
#define alloc_dump_stack()
#endif

/* Initialized at module insertion */
spinlock_t id_lock;
loff_t unique_id;

extern struct vfsmount *vfs_loc;

static struct kmem_cache *replayfs_inode_cache;
extern struct kmem_cache *replayfs_page_cache;

/* Static declarations for operation structures */
static int replayfs_file_open(struct inode *inode, struct file *file);
static int replayfs_file_release(struct inode *inode, struct file *file);
static int replayfs_super_write_inode(struct inode *inode, int wait);
static struct inode *replayfs_inode_alloc(struct super_block *sb);
static void replayfs_inode_destroy(struct inode *node);
static int replayfs_super_write_inode(struct inode *inode, int wait);
int replayfs_readpage(struct file *file, struct page *page);
int replayfs_writepage(struct page *page,
		struct writeback_control *wbc);
static int replayfs_prepare_write(struct file *file, struct page *page,
		unsigned from, unsigned to);
static int replayfs_commit_write(struct file *file, struct page *page,
		unsigned from, unsigned to);
static int replayfs_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry);

/* iops */
static int replayfs_mkdir(struct inode *dir, struct dentry *dentry, int mode);
	
static int replayfs_rmdir(struct inode *dir, struct dentry *dentry);
static int replayfs_create(struct inode *dir, struct dentry *dentry, int mode,
		struct nameidata *nd);
static int replayfs_unlink(struct inode *idir, struct dentry *dentry);
static int replayfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry);

static int replayfs_setattr(struct dentry *dentry, struct iattr *ia);

static void replayfs_inode_delete(struct inode *inode);

static void replay_put_sb(struct super_block *sb);

/* FIXME: These should be in a header (exported from replayfs_file.c */
ssize_t replayfs_file_read(struct file *filp, char __user *buf, size_t len,
		loff_t *ppos);
ssize_t replayfs_file_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *ppos);

/* Structs Defining operations */

struct inode_operations replayfs_dir_iops = {
	mkdir: replayfs_mkdir,
	rmdir: replayfs_rmdir,
	create: replayfs_create,
	link: replayfs_link,
	unlink: replayfs_unlink,
	setattr: replayfs_setattr,
	rename: replayfs_rename,
	lookup: replayfs_inode_lookup,
	permission: replayfs_permission
};

struct inode_operations replayfs_file_iops = {
	setattr: replayfs_setattr,
	permission: replayfs_permission
};

struct file_operations replayfs_fops = {
	llseek: generic_file_llseek,
	open: replayfs_file_open,
	read: replayfs_file_read,
	write: replayfs_file_write,
	/*
	aio_read: generic_file_aio_read,
	aio_write: generic_file_aio_write,
	splice_read: generic_file_splice_read,
	splice_write: generic_file_splice_write,
	*/
	release: replayfs_file_release,
	unlocked_ioctl: replayfs_ioctl,
	/*
	mmap: generic_file_mmap,
	*/
	fsync: simple_sync_file
};

struct file_operations replayfs_dir_fops = {
	llseek: generic_file_llseek,
	read: do_sync_read,
	readdir: replayfs_dir_readdir,
	unlocked_ioctl: replayfs_ioctl,
	fsync: simple_sync_file
};

struct super_operations replayfs_sops = {
	write_inode: replayfs_super_write_inode,
	put_super: replay_put_sb,
	statfs: simple_statfs,
	alloc_inode: replayfs_inode_alloc,
	delete_inode: replayfs_inode_delete,
	destroy_inode: replayfs_inode_destroy
};

struct address_space_operations replayfs_aops = {
	readpage: replayfs_readpage,
	writepage: replayfs_writepage,
	prepare_write: replayfs_prepare_write,
	commit_write: replayfs_commit_write
};

static void _replayfs_inode_init(struct kmem_cache *cachep, void *foo) {
	struct replayfs_inode_info *replay_inode = (struct replayfs_inode_info *)foo;

	inode_init_once(&replay_inode->vfs_inode);
}

static int replayfs_init_allocators(void) {
	replayfs_inode_cache = kmem_cache_create("replayfs_inode_cache",
			sizeof(struct replayfs_inode_info), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD,
			_replayfs_inode_init);

	if (replayfs_inode_cache == NULL) {
		return -1;
	}

	return glbl_page_alloc_init();
}

static void replayfs_destroy_allocators(void) {
	if (replayfs_inode_cache) {
		kmem_cache_destroy(replayfs_inode_cache);
	}

	glbl_page_alloc_destroy();
}

static struct inode *replayfs_inode_alloc(struct super_block *sb) {
	struct replayfs_inode_info *ret;

	ret = kmem_cache_alloc(replayfs_inode_cache, GFP_NOFS);
	if (ret == NULL) {
		return NULL;
	}


	alloc_debugk("%s %d: Allocing inode %p\n", __func__, __LINE__, ret);
	alloc_dump_stack();

	return &ret->vfs_inode;
}

static void replayfs_inode_delete(struct inode *inode) {
	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);
	inode_detach(inode);
}

static void replayfs_inode_destroy(struct inode *inode) {
	replayfs_file_log_cache_put(&REPLAYFS_SB(inode->i_sb)->cache,
			REPLAYFS_I(inode)->file_log);

	alloc_debugk("%s %d: Destroy inode %p\n", __func__, __LINE__, REPLAYFS_I(inode));
	alloc_dump_stack();

	kmem_cache_free(replayfs_inode_cache, REPLAYFS_I(inode));
}

/*
static void replayfs_super_read_inode(struct inode *inode) {
	printk("super_read setting times\n");
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;

	printk("super_read updaitng mapping %p aops\n", inode->i_mapping);
	inode->i_mapping->a_ops = &replayfs_aops;
}
*/

static int replayfs_setattr(struct dentry *dentry, struct iattr *ia) {
	int error;
	struct inode *inode;

	replayfs_log_t log;
	replayfs_log_inode_t log_inode;

	inode = dentry->d_inode;

	error = replayfs_begin_log_operation(&log);
	if (error) {
		goto out;
	}

	replayfs_log_add_inode(&log, &log_inode, inode);

	error = inode_change_ok(inode, ia);
	if (!error) {
		error = inode_setattr(inode, ia);
	}


	replayfs_inode_modified_metadata(inode, &log, &log_inode);

	replayfs_log_inode_done(&log, &log_inode, inode->i_size);
	replayfs_end_log_operation(&log);

out:
	return error;
}

static int replayfs_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry) {
	struct inode *inode;
	int ret;

	replayfs_log_t log;
	replayfs_log_inode_t log_inode;

	inode = old_dentry->d_inode;

	inode->i_ctime = CURRENT_TIME_SEC;
	inode_inc_link_count(inode);
	atomic_inc(&inode->i_count);

	ret = replayfs_begin_log_operation(&log);
	if (ret) {
		goto out;
	}

	replayfs_log_add_inode(&log, &log_inode, inode);

	ret = replayfs_dir_add_nondir(new_dentry, inode, &log, &log_inode);

	replayfs_log_inode_done(&log, &log_inode, inode->i_size);

	replayfs_end_log_operation(&log);

out:
	return ret;
}


static int replayfs_file_open(struct inode *inode, struct file *file) {
	int ret;
	/* Disable read ahead */
	file->f_ra.ra_pages = 0;
	ret = generic_file_open(inode, file);

	return ret;
}

static int replayfs_file_release(struct inode *inode, struct file *file) {
	struct dentry *dentry;
	dentry = file->f_dentry;
	debugk("REPLAYFS: In file_release!\n");
	return 0;
}

static int replayfs_mkdir(struct inode *dir, struct dentry *dentry, int mode) {
	struct inode *new_dir;
	int err;

	replayfs_log_t log;
	replayfs_log_inode_t log_inode_dir;
	replayfs_log_inode_t log_inode_new_dir;


	/* Increment the parent directorie's link counter */
	inode_inc_link_count(dir);

	/* Allocate a new inode */
	new_dir = replayfs_new_inode(dir->i_sb, S_IFDIR | mode);
	err = PTR_ERR(new_dir);
	if (IS_ERR(new_dir)) {
		goto out_dir;
	}

	/* Begin log operation on the new dir */
	err = replayfs_begin_log_operation(&log);
	if (err) {
		goto out_dir;
	}

	replayfs_log_add_inode(&log, &log_inode_new_dir, new_dir);

	/* Begin log operation on the new dir */
	replayfs_log_add_inode(&log, &log_inode_dir, dir);

	new_dir->i_op = &replayfs_dir_iops;
	new_dir->i_fop = &replayfs_dir_fops;
	new_dir->i_mapping->a_ops = &replayfs_aops;

	/* Increment the new inode's link count */
	inode_inc_link_count(new_dir);

	/* Initialize the new inode to an empty dir */
	err = replayfs_dir_make_empty(new_dir, dir, &log, &log_inode_new_dir);
	if (err) {
		goto out_fail;
	}

	/* Link the new inode to the dentry */
	err = replayfs_dir_add_link(dentry, new_dir, &log, &log_inode_dir);
	if (err) {
		goto out_fail;
	}

	/* Setup the dentry cache */
	d_instantiate(dentry, new_dir);

	/* Finish! */
	/* Finish those log operations */

	/* 
	 * This operation doesn't modify metadata for the dir... we shouldn't give a
	 * metadata update!
	 */
	/*replayfs_inode_modified_metadata(dir, &log, &log_inode_dir);*/
	replayfs_inode_modified_metadata(new_dir, &log, &log_inode_new_dir);
	replayfs_log_inode_done(&log, &log_inode_new_dir, new_dir->i_size);
	replayfs_log_inode_done(&log, &log_inode_dir, dir->i_size);
	replayfs_end_log_operation(&log);
out:
	return err;

out_fail:
	replayfs_log_inode_done(&log, &log_inode_new_dir, new_dir->i_size);
	replayfs_log_inode_done(&log, &log_inode_dir, dir->i_size);
	replayfs_end_log_operation(&log);
	inode_dec_link_count(new_dir);
	inode_dec_link_count(new_dir);
	iput(new_dir);
out_dir:
	inode_dec_link_count(dir);
	goto out;
}

static int replayfs_unlink(struct inode *idir, struct dentry *dentry) {
	struct inode *inode;
	struct replayfs_dir *dir;
	struct page *page;
	loff_t dir_pos;
	int err;

	replayfs_log_t log;
	replayfs_log_inode_t log_inode;

	err = -ENOENT;

	inode = dentry->d_inode;

	/* Begin log operation on the dir */
	replayfs_begin_log_operation(&log);

	replayfs_log_add_inode(&log, &log_inode, idir);

	dir = replayfs_dir_find_entry(idir, dentry, &page, &dir_pos);
	if (!dir) {
		goto out;
	}

	err = replayfs_dir_delete_entry(dir, page, dir_pos, &log, &log_inode);
	if (err) {
		goto out;
	}

	/* Update the ctime */
	inode->i_ctime = idir->i_ctime;
	/* Unlink from the inode */
	/* If we are about to remove the inode, drop it from our cache */
	inode_dec_link_count(inode);

	/* All done! No error */
	err = 0;
out:
	replayfs_log_inode_done(&log, &log_inode, idir->i_size);
	replayfs_end_log_operation(&log);
	return err;
}

static int replayfs_rmdir(struct inode *dir, struct dentry *dentry) {
	struct inode *inode;
	int err;

	inode = dentry->d_inode;
	err = -ENOTEMPTY;
	
	/* NOTE: Don't need to start log operation here, that is handled in unlink */

	if (replayfs_dir_is_empty(inode)) {
		err = replayfs_unlink(dir, dentry);
		/* If we were successful */
		if (!err) {
			/* Clear this inode, and decrement our link counts */
			inode->i_size = 0;
			inode_dec_link_count(inode);
			inode_dec_link_count(dir);
		}
	}

	return err;
}


static int replayfs_create(struct inode *dir, struct dentry *dentry, int mode,
		struct nameidata *nd) {
	struct inode *inode;

	int err;

	inode = replayfs_new_inode(dir->i_sb, mode);
	err = PTR_ERR(inode);

	debugk("%s %d: Creating a new inode, parent has mode %o\n", __func__,
			__LINE__, dir->i_mode);

	if (!IS_ERR(inode)) {
		replayfs_log_t log;
		replayfs_log_inode_t log_inode;

		inode->i_op = &replayfs_file_iops;
		inode->i_mapping->a_ops = &replayfs_aops;
		inode->i_fop = &replayfs_fops;

		replayfs_begin_log_operation(&log);

		replayfs_log_add_inode(&log, &log_inode, dentry->d_parent->d_inode);

		mark_inode_dirty(inode);

		err = replayfs_dir_add_nondir(dentry, inode, &log, &log_inode);

		replayfs_log_inode_done(&log, &log_inode,
					dentry->d_parent->d_inode->i_size);

		/* Save the metadata modification to the new inode */
		replayfs_log_add_inode(&log, &log_inode, inode);

		replayfs_inode_modified_metadata(inode, &log, &log_inode);

		replayfs_log_inode_done(&log, &log_inode, inode->i_size);
		replayfs_end_log_operation(&log);
	}

	debugk("%s %d: Done creating a new inode\n", __func__, __LINE__);

	return err;
}

static int replayfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry) {
	/* Should I move this to dir? it deals w/ dir representations... */
	struct inode *old_inode;
	struct inode *new_inode;
	struct replayfs_dir *old_rep;
	struct replayfs_dir *dir_parent_rep;
	struct page *old_page;
	struct page *dir_parent_page;
	loff_t old_dir_pos;
	loff_t new_dir_pos;

	int err;

	replayfs_log_t log;
	replayfs_log_inode_t log_inode_new;
	replayfs_log_inode_t log_inode_old;

	old_inode = old_dentry->d_inode;
	new_inode = new_dentry->d_inode;

	dir_parent_rep = NULL;
	dir_parent_page = NULL;

	err = -ENOENT;

	err = replayfs_begin_log_operation(&log);
	if (err) {
		goto out_early;
	}

	replayfs_log_add_inode(&log, &log_inode_new, new_inode);
	replayfs_log_add_inode(&log, &log_inode_old, old_inode);

	/* Get the replayfs_dir for the dentry in the old_dir */
	old_rep = replayfs_dir_find_entry(old_dir, old_dentry, &old_page, &old_dir_pos);
	if (!old_rep) {
		/* There was no old_dentry in old_dir... return the error */
		goto out;
	}

	/* See if we need to update the parent */
	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		dir_parent_rep = replayfs_dir_dotdot(old_inode, &dir_parent_page);
		if (!dir_parent_rep) {
			goto out_old_dir;
		}
	}

	/* If there is a new inode to update */
	if (new_inode) {
		struct page *new_page;
		struct replayfs_dir *new_rep;

		/* See if the new entry exists in the new directory */
		new_rep = replayfs_dir_find_entry(new_dir, new_dentry, &new_page,
				&new_dir_pos);
		if (new_rep != NULL) {
			err = -ENOENT;
			goto out_dir;
		}
		inode_inc_link_count(old_inode);
		/* Link the old inode into the new directory */
		replayfs_dir_set_link(new_dir, new_rep, new_page, old_inode);
		new_inode->i_ctime = CURRENT_TIME_SEC;

		if (dir_parent_rep) {
			drop_nlink(new_inode);
		}

		inode_dec_link_count(new_inode);
	/* ??? */
	} else {
		inode_inc_link_count(old_inode);
		err = replayfs_dir_add_link(new_dentry, old_inode, &log, &log_inode_old);
		if (err) {
			inode_dec_link_count(old_inode);
			goto out_dir;
		}

		if (dir_parent_rep) {
			inode_inc_link_count(new_dir);
		}
	}

	old_inode->i_ctime = CURRENT_TIME_SEC;

	replayfs_dir_delete_entry(old_rep, old_page, old_dir_pos, &log, &log_inode_old);
	inode_dec_link_count(old_inode);

	if (dir_parent_rep) {
		replayfs_dir_set_link(old_inode, dir_parent_rep, dir_parent_page, new_dir);
		inode_dec_link_count(old_dir);
	}

out_dir:
	if (dir_parent_rep) {
		replayfs_put_page(dir_parent_page);
	}
out_old_dir:
	if (old_rep) {
		replayfs_put_page(old_page);
	}
out:
	replayfs_log_inode_done(&log, &log_inode_new, new_inode->i_size);
	replayfs_log_inode_done(&log, &log_inode_old, old_inode->i_size);
	replayfs_end_log_operation(&log);
out_early:
	return err;
}

static int replayfs_commit_write(struct file *file, struct page *page,
		unsigned from, unsigned to) {
	struct inode *inode;
	loff_t pos;

	pos = ((loff_t)page->index << PAGE_CACHE_SHIFT) + to;

	inode = page->mapping->host;

	ClearPageDirty(page);

	SetPageUptodate(page);
	kunmap(page);

	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		mark_inode_dirty(inode);
	}

	return 0;
}

struct file *replayfs_open_filp_by_id(struct vfsmount *vfs,
		struct replayfs_unique_id *id, loff_t version) {
	struct inode *req_inode;
	mm_segment_t old_fs;
	struct inode *inode;
	struct dentry *dentry;

	struct file *new_filp;
	struct dentry *new_dentry;
	struct qstr new_str;
	char *name;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	debugk("%s %d: arguments ({%lld, %lld}, %lld)\n", __func__, __LINE__,
			id->log_num, id->sys_num, version);

	set_fs(old_fs);

	/* Get the root's inode */
	inode = vfs->mnt_sb->s_root->d_inode;
	dentry = vfs->mnt_sb->s_root;

	/* Open the new file */

	/* Instantiate a dentry for this file */
	/* 
	 * NOTE: This dentry will only be used for this file, all other
	 * accesses will point to the current version...
	 */
	/* Need to fudge the dentry creation... give it a fake name */
	/* Make a new qstr to hold the fudged name */

	/* Put name on the heap, so it doesn't overflow the stack... */
	debugk("%s %d: About to call kmalloc\n", __func__, __LINE__);
	/*name = kmalloc(PAGE_SIZE, GFP_NOFS);*/
	name = kmem_cache_alloc(replayfs_page_cache, GFP_NOFS);
	debugk("%s %d: kmalloc done\n", __func__, __LINE__);

	/* Now, append our prefix to the current name */
	name[0] = '\0';
	sprintf(name, "__%016llX_%016llX_%016llX", (unsigned long long)version,
			(unsigned long long)id->log_num, (unsigned long long)id->sys_num);

	new_str.len = strlen(name);
	new_str.name = name;
	new_str.hash = full_name_hash(new_str.name, new_str.len);

	debugk("%s %d: new name is %s\n", __func__, __LINE__, new_str.name);

	/* Give that name to the dentry */
	/* See if the entry exists in the dentry cache */
	new_dentry = d_lookup(dentry, &new_str);
	debugk("%s %d: new dentry is %p\n", __func__, __LINE__, new_dentry);
	if (new_dentry == NULL) {
		debugk("%s %d: about to call d_alloc\n", __func__, __LINE__);
		new_dentry = d_alloc(dentry, &new_str);
		debugk("%s %d: dalloc'd new dentry %p\n", __func__, __LINE__, new_dentry);
		if (new_dentry == NULL) {
			/*kfree(name);*/
			kmem_cache_free(replayfs_page_cache, name);
			return ERR_PTR(-ENOMEM);
		}

		/* Now get the inode of this file */
		debugk("%s %d: about to call replayfs_iget\n", __func__, __LINE__);
		req_inode = replayfs_iget(inode->i_sb, id, version);
		debugk("%s %d: done calling replayfs_iget\n", __func__, __LINE__);
		if (req_inode == NULL) {
			d_delete(new_dentry);
			new_filp = ERR_PTR(-ENOMEM);
			goto out;
		}

		inode_inc_link_count(req_inode);
		inode_inc_link_count(inode);

		debugk("%s %d: about to call d_add\n", __func__, __LINE__);
		d_add(new_dentry, req_inode);
		debugk("%s %d: added new dentry %p\n", __func__, __LINE__, new_dentry);
	} else {
		req_inode = new_dentry->d_inode;
	}

	/* We can free the memory used for naming now */
	/*kfree(name);*/
	kmem_cache_free(replayfs_page_cache, name);

	/* Get our new file pointer */
	debugk("%s %d: calling dentry_open\n", __func__, __LINE__);
	new_filp = dentry_open(new_dentry, mntget(vfs), O_RDONLY);
	debugk("%s %d: called dentry_open, new_filp is %p\n", __func__, __LINE__,
			new_filp);
	if (IS_ERR(new_filp)) {
		d_delete(new_dentry);
		goto out;
	} else {
	}

	/* Call the actual fs open operation */
	replayfs_file_open(req_inode, new_filp);

out:
	/* Return our file descriptor */
	return new_filp;
}

long replayfs_ioctl(struct file *filp, unsigned int cmd,
		unsigned long arg) {
	struct inode *inode;
	struct dentry *dentry;

	dentry = filp->f_dentry;
	inode = filp->f_dentry->d_inode;

	debugk("In %s!\n", __func__);

	debugk("%s %d: Cmd is %u, REPLAYFS_IOCTL_SET_VERSION is %u REPLAYFS_IOCTL_GET_VERSION is %u\n", __func__,
			__LINE__, cmd, REPLAYFS_IOCTL_SET_VERSION, REPLAYFS_IOCTL_GET_VERSION);

	switch (cmd) {
		/* Opens a new fd to point to the requested version of the file */
		case REPLAYFS_IOCTL_SET_VERSION:
			do {
				unsigned long long req_version;
				long new_fd;
				struct inode *req_inode;

				debugk("%s %d: cmd is SET_VERSION\n", __func__, __LINE__);

				if (copy_from_user(&req_version, (unsigned long long __user *)arg,
						sizeof(unsigned long long))) {
					return -EFAULT;
				}

				/* They requested a version > current... we can't do that! */
				if (req_version >= replayfs_file_log_size(REPLAYFS_I(inode)->file_log)) {
					return -EINVAL;
				}


				/* Open the new file */
				new_fd = get_unused_fd();
				if (new_fd >= 0) {
					struct file *new_filp;
					struct dentry *new_dentry;
					struct qstr new_str;
					char *name;
					int oldname_len;
					const char *oldname;

					oldname = dentry->d_name.name;
					oldname_len = dentry->d_name.len;

					/* Instantiate a dentry for this file */
					/* 
					 * NOTE: This dentry will only be used for this file, all other
					 * accesses will point to the current version...
					 */
					/* Need to fudge the dentry creation... give it a fake name */
					/* Make a new qstr to hold the fudged name */

					/* Put name on the heap, so it doesn't overflow the stack... */
					name = kmalloc(PAGE_SIZE, GFP_NOFS);
					/* See if the current dentry is already a replayfs versioned file */
					if (dentry->d_name.len > 17) {
						if (!memcmp(dentry->d_name.name, "__replayfsvers", 14)) {
							/* 
							 * The name is already replayfs versioned... remove the version
							 * info 
							 */
							int uscore_cnt;
							int offs;

							for (uscore_cnt = 0, offs=14; uscore_cnt < 2; offs++) {
								BUG_ON(offs == dentry->d_name.len);

								if (oldname[14] == '_') {
									uscore_cnt++;
								}
							}

							oldname_len -= offs;
							oldname += offs;
						}
					}

					/* Now, append our prefix to the current name */
					name[0] = '\0';
					sprintf(name, "__replayfsvers%llu__%*.s", req_version, oldname_len, oldname);

					new_str.len = strlen(name);
					new_str.name = name;
					new_str.hash = full_name_hash(new_str.name, new_str.len);

					debugk("%s %d: new name is %s", __func__, __LINE__, new_str.name);

					/* Name formua is: __replayfsvers%version%__%filename% */

					/* Give that name to the dentry */
					/* See if the entry exists in the dentry cache */
					new_dentry = d_lookup(dentry->d_parent, &new_str);
					if (new_dentry == NULL) {
						new_dentry = d_alloc(dentry->d_parent, &new_str);
						if (new_dentry == NULL) {
							put_unused_fd(new_fd);
							kfree(name);
							return -ENOMEM;
						}
						/* Get the inode of this file at that version */
						
						/* Now get the inode of this file */
						req_inode = replayfs_iget(inode->i_sb, &REPLAYFS_I(inode)->id,
								req_version);
						if (req_inode == NULL) {
							new_fd = -ENOMEM;
						}

						req_inode->i_fop = inode->i_fop;
						req_inode->i_op = inode->i_op;
						req_inode->i_mapping->a_ops = inode->i_mapping->a_ops;

						inode_inc_link_count(req_inode);
						inode_inc_link_count(inode);

						debugk("%s %d: req_inode is %p\n", __func__, __LINE__, req_inode);

						d_add(new_dentry, req_inode);
					} else {
						req_inode = new_dentry->d_inode;
					}

					/* We can free the memory used for naming now */
					kfree(name);

					/* Get our new file pointer */
					new_filp = dentry_open(new_dentry, mntget(filp->f_vfsmnt), O_RDONLY);
					if (IS_ERR(new_filp)) {
						put_unused_fd(new_fd);
						new_fd = PTR_ERR(new_filp);
					} else {
						/* Install that file pointer to a fd, and return */
						fd_install(new_fd, new_filp);

						/* Call the actual fs open operation */
						replayfs_file_open(req_inode, new_filp);
					}
				}

				/* Return our file descriptor */
				return new_fd;
			} while (0);
		case REPLAYFS_IOCTL_GET_SUBDIR:
			do {
				char fname[0x80];
				struct page *dir_page;
				loff_t dir_pos;
				struct replayfs_dir *dir;
				struct dentry entry;
				int new_fd;

				/* Figure out if the file exists */

				/* Get file name within directory */
				/* Scan backwards for '/' or begin of path */
				entry.d_name.len = strncpy_from_user(fname, (const char *)arg, 0x80);
				entry.d_name.name = fname;

				if (entry.d_name.len < 0) {
					/* Shouldn't happen, we should catch error cases and break early */
					return -EFAULT;
				}

				/* 
				 * If the file doesn't exist, and the return is successful, we created the
				 * file...
				 */
				dir = replayfs_dir_find_entry(filp->f_dentry->d_inode,
						&entry, &dir_page, &dir_pos);

					/* Okay, find the subdir */
				if (dir == NULL) {
					return -ENOENT;
				}

				new_fd = get_unused_fd();
				if (new_fd >= 0) {
					struct file *filp;

					filp = replayfs_open_filp_by_id(vfs_loc,
							&dir->header.id,
							0);
					if (filp == NULL) {
						put_unused_fd(new_fd);
						return -EINVAL;
					}

					fd_install(new_fd, filp);

					replayfs_file_open(filp->f_dentry->d_inode, filp);
				}

				/* Return our file descriptor */
				return new_fd;
			} while (0);
			break;
		case REPLAYFS_IOCTL_GET_VERSION:
			if (REPLAYFS_I(inode)->version == REPLAYFS_CURRENT_VERSION) {
				return replayfs_file_log_size(REPLAYFS_I(inode)->file_log)-1;
			} else {
				return REPLAYFS_I(inode)->version;
			}
		case REPLAYFS_IOCTL_MAX_VERSION:
			do {
				loff_t max_version;

				max_version = replayfs_file_log_size(REPLAYFS_I(inode)->file_log)-1;
				if (copy_to_user((unsigned long long __user *)arg, &max_version,
							sizeof(unsigned long long))) {
					return -EFAULT;
				}
			} while (0);
			return 0;
		default:
			return -ENOTTY;
	}
}

static int replayfs_prepare_write(struct file *file, struct page *page,
		unsigned from, unsigned to) {
	return 0;
}

static int replayfs_super_write_inode(struct inode *inode, int wait) {

	return 0;
}

int replayfs_init_unique(void) {
	int err;
	loff_t pos;
	mm_segment_t old_fs;
	struct file *meta_file;

	err = 0;
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	meta_file = filp_open(PREFIX_STRING "/meta_file.data", O_RDWR | O_CREAT, 0777);
	if (meta_file == NULL) {
		goto err_fail_no_open;
	}
	
	pos = 0;
	err = vfs_read(meta_file, (char __user *)&unique_id, sizeof(unique_id), &pos);

	if (err < 0) {
		goto err_fail;
	}

	if (err < sizeof(unique_id)) {
		unique_id = 0;
	}

	err = 0;
	
	filp_close(meta_file, NULL);
	set_fs(old_fs);

	spin_lock_init(&id_lock);

out:
	return err;

err_fail:
	filp_close(meta_file, NULL);
err_fail_no_open:
	set_fs(old_fs);
	goto out;
}

loff_t replayfs_next_unique(void) {
	loff_t ret;

	spin_lock(&id_lock);
	ret = unique_id++;
	spin_unlock(&id_lock);

	return ret;
}

void replayfs_destroy_unique(void) {
	loff_t pos;
	int err;
	mm_segment_t old_fs;

	struct file *meta_file;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	meta_file = filp_open(PREFIX_STRING "/meta_file.data", O_RDWR, 0777);
	BUG_ON(meta_file == NULL);

	pos = 0;
	err = vfs_write(meta_file, (const __user char *)&unique_id,
			sizeof(unique_id), &pos);

	BUG_ON(err != sizeof(unique_id));

	filp_close(meta_file, NULL);

	set_fs(old_fs);
}

static int replayfs_super_info_init(struct replayfs_sb_info *sbi) {
	int err;

	err = 0;

	spin_lock_init(&sbi->i_get_lock);
	INIT_HLIST_HEAD(&sbi->i_get_head);


	err = replayfs_syscache_init(&sbi->syscall_cache);
	if (err) {
		goto out;
	}

	err = replayfs_file_log_cache_init(&sbi->cache, &sbi->syscall_cache);

	if (err) {
		goto out;
	}


out:
	return err;
}


static int replayfs_fill_super(struct super_block *sb, void *data, int silent) {
	struct inode *root_inode;
	struct replayfs_sb_info *sbi;
	int error;

	sbi = NULL;
	root_inode = NULL;

	error = 0;

	sb->s_blocksize = REPLAYFS_BLOCKSIZE;
	sb->s_blocksize_bits = REPLAYFS_BLOCKSIZE_BITS;
	sb->s_magic = REPLAYFS_MAGIC;
	sb->s_op = &replayfs_sops;

	sbi = kmalloc(sizeof(struct replayfs_sb_info), GFP_NOFS);
	if (sbi == NULL) {
		error = -ENOMEM;
		goto out_fail;
	}

	error = replayfs_super_info_init(sbi);
	if (error) {
		goto out_fail;
	}

	sb->s_fs_info = sbi;

	/* Fill the root inode */
	root_inode = new_inode(sb);
	if (root_inode == NULL) {
		error = -ENOMEM;
		goto out_fail;
	}


	debugk("%s %d: root inode sb was %p\n", __func__, __LINE__, root_inode->i_sb);
	root_inode->i_sb = sb;

	REPLAYFS_I(root_inode)->id.log_num = REPLAYFS_ROOT_INO;
	REPLAYFS_I(root_inode)->id.sys_num = -1;

	REPLAYFS_I(root_inode)->file_log =
		replayfs_file_log_cache_get(&REPLAYFS_SB(sb)->cache,
				&REPLAYFS_I(root_inode)->id);
	debugk("%s %d: Called replayfs_file_log_cache_get, returend pointer is %p\n",
			__func__, __LINE__, REPLAYFS_I(root_inode)->file_log);

	if (replayfs_file_log_size(REPLAYFS_I(root_inode)->file_log) == 0) {
		replayfs_log_t log;
		replayfs_log_inode_t log_inode;

		debugk("%s %d: Root inode is uninitialized, initializing root inode\n",
				__func__, __LINE__);

		replayfs_begin_log_operation(&log);

		replayfs_log_add_inode(&log, &log_inode, root_inode);

		REPLAYFS_I(root_inode)->version = REPLAYFS_CURRENT_VERSION;
		root_inode->i_ino = REPLAYFS_ROOT_INO;
		root_inode->i_version = 1;

		i_size_write(root_inode, 0);

		root_inode->i_op = &replayfs_dir_iops;
		root_inode->i_fop = &replayfs_dir_fops;
		root_inode->i_mapping->a_ops = &replayfs_aops;
		root_inode->i_mode = S_IFDIR | S_IRWXUGO;

		debugk("%s %d: Calling Replayfs_dir_make_empty on root_inode\n", __func__,
				__LINE__);
		replayfs_dir_make_empty(root_inode, root_inode, &log, &log_inode);

		root_inode->i_mode = S_IFDIR | S_IRWXUGO;

		replayfs_inode_modified_metadata(root_inode, &log, &log_inode);

		debugk("%s %d: Calling replayfs_file_log_next_done on root_inode\n", __func__,
				__LINE__);
		replayfs_log_inode_done(&log, &log_inode, root_inode->i_size);
		replayfs_end_log_operation(&log);
	} else {
		struct replayfs_file_log_entry *entry;
		loff_t version;

		version = replayfs_file_log_size(REPLAYFS_I(root_inode)->file_log)-1;

		entry = replayfs_file_log_get_entry(REPLAYFS_I(root_inode)->file_log, version);

		root_inode->i_mtime = replayfs_file_log_entry_mtime(entry);
		i_size_write(root_inode, entry->file_size);

		debugk("%s %d: Loaded new i_size of %lld\n", __func__, __LINE__,
				entry->file_size);
		replayfs_file_log_put_entry(REPLAYFS_I(root_inode)->file_log, entry, version);
	}

	inode_attach(root_inode);

	REPLAYFS_I(root_inode)->version = REPLAYFS_CURRENT_VERSION;
	root_inode->i_ino = REPLAYFS_ROOT_INO;
	root_inode->i_version = 1;

	root_inode->i_op = &replayfs_dir_iops;
	root_inode->i_fop = &replayfs_dir_fops;
	root_inode->i_mapping->a_ops = &replayfs_aops;
	root_inode->i_mode = S_IFDIR | S_IRWXUGO;

	insert_inode_hash(root_inode);
	sb->s_root = d_alloc_root(root_inode);
	if (sb->s_root == NULL) {
		error = -ENOMEM;
		goto out_fail;
	}

	return 0;

out_fail:
	if (sbi) {
		replay_put_sb(sb);
	}
	if (root_inode) {
		iput(root_inode);
	}
	return error;
}

static int replay_get_sb(struct file_system_type *fs_type,
		int flags, const char *dev_name, void *data, struct vfsmount *mnt) {

	vfs_loc = mnt;

	return get_sb_single(fs_type, flags, data, replayfs_fill_super, mnt);
}

static void replay_put_sb(struct super_block *sb) {
	struct replayfs_sb_info *sbi;

	sbi = REPLAYFS_SB(sb);

	printk("%s %d: Putting SB\n", __func__, __LINE__);

	replayfs_file_log_cache_destroy(&sbi->cache);
	replayfs_syscache_destroy(&sbi->syscall_cache);
	
	kfree(sbi);
}

static struct file_system_type replayfs_type = {
	owner: THIS_MODULE,
	name: "replayfs",
	get_sb: replay_get_sb,
	kill_sb: kill_anon_super
};

/*
static struct ctl_table_header *____header;

static struct ctl_table replay_ctl[] = {
	{
		.ctl_name = CTL_UNNUMBERED,
		.procname = "syslog_recs",
		.data   = &syslog_recs,
		.maxlen   = sizeof(unsigned int),
		.mode   = 0666,
		.proc_handler = &proc_dointvec,
	},
	{
		.ctl_name = CTL_UNNUMBERED,
		.procname =
		"replay_mismatch_coredump",
		.maxlen   = sizeof(unsigned long),
		.data = &replay_mismatch_coredump,
		.mode = 0666,
		.proc_handler = &proc_dointvec,
	},
	{0, },
};

static struct ctl_table replay_ctl_root[] = {
	{
		.ctl_name = CTL_KERN,
		.procname = "replayfs",
		.mode   = 0555,
		.child    = replay_ctl,
	},
	{0, },
};
*/

int replayfs_fs_init(void) {
	int err;

	perftimer_init();

	debugk("Sizeof pgoff_t is %u, loff_t %u\n", sizeof(pgoff_t),
			sizeof(loff_t));

	if (PAGE_SIZE != sizeof(struct replayfs_dir_page)) {
		printk("REPLAYFS ERROR: PAGE_SIZE == %lu, replayfs_dir_page size == %d\n",
				PAGE_SIZE, sizeof(struct replayfs_dir_page));
		return 1;
	}

	/* Init memory management */
	if (replayfs_init_allocators()) {
		return 1;
	}

	/* All is going well so far, setup our super block */
	err = register_filesystem(&replayfs_type);
	if (err) {
		replayfs_destroy_allocators();
		return 1;
	}

	return 0;
}

void exit_replay_fs(void) {
	unregister_filesystem(&replayfs_type);
	replayfs_destroy_allocators();
}

