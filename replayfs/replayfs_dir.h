#ifndef __REPLAYFS_DIR_H__
#define __REPLAYFS_DIR_H__

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

#include "replayfs_file_log.h"
#include "replayfs_fs.h"
#include "replayfs_log.h"

/* Operations to manipulate the internal directory structure of the FS */

#define REPLAYFS_DIRS_PER_PAGE (PAGE_SIZE/sizeof(struct replayfs_dir))
/* The number of dirs we want per page... */
#define DIRS_PER_PAGE 8
#define DIR_SIZE (PAGE_SIZE/DIRS_PER_PAGE)

struct replayfs_dir_header {
	struct replayfs_unique_id id;
	int name_len;
	int type;
};

struct replayfs_dir {
	struct replayfs_dir_header header;
	char name[(DIR_SIZE - sizeof(struct replayfs_dir_header))];
};

struct replayfs_dir_page {
	struct replayfs_dir dirs[REPLAYFS_DIRS_PER_PAGE];
};

/* Find the directory entry for dentry (entry) in the inode (inode) */
struct replayfs_dir *replayfs_dir_find_entry(struct inode *inode,
		struct dentry *entry, struct page **page, loff_t *dir_pos);

int replayfs_dir_delete_entry(struct replayfs_dir *dir, struct page *page,
		loff_t dir_pos, replayfs_log_t *dir_log,
		replayfs_log_inode_t *dir_log_inode);

int replayfs_dir_new_entry_external(struct inode *idir,
		const char *name, struct replayfs_unique_id *new_id, mode_t new_mode,
		replayfs_log_t *dir_log, replayfs_log_inode_t *dir_log_inode);

void replayfs_dir_set_link(struct inode *dir, struct replayfs_dir *rep,
		struct page *page, struct inode *inode);

/* Check to see if the directory represented by the inode is empty */
int replayfs_dir_is_empty(struct inode *);

/* Get the directory entry for ".." */
struct replayfs_dir *replayfs_dir_dotdot(struct inode *, struct page **);

/* Add a non directory (ex. file) (inode) to the directory (dentry->parent) */
int replayfs_dir_add_nondir(struct dentry *dentry, struct inode *inode,
		replayfs_log_t *dir_log, replayfs_log_inode_t *dir_log_inode);

/* Add a link to a directory (inode) to the directory (dentry->parent) */
int replayfs_dir_add_link(struct dentry *dentry, struct inode *inode,
		replayfs_log_t *dir_log, replayfs_log_inode_t *dir_log_inode);

int replayfs_dir_make_empty(struct inode *dir, struct inode *parent,
		replayfs_log_t *dir_log, replayfs_log_inode_t *dir_log_inode);

int replayfs_dir_readdir(struct file *filp, void *dirent, filldir_t filldir);

int replayfs_inode_by_name(struct inode *idir, struct dentry *entry,
		struct replayfs_unique_id *id);

#endif

