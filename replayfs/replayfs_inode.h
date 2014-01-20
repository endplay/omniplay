#ifndef __REPLAYFS_INODE_H__
#define __REPLAYFS_INODE_H__

#include <linux/kernel.h>
#include <linux/fs.h>

#include "replayfs_fs.h"
#include "replayfs_log.h"

/* The "on-disk" representation of our inodes... used to maintain metadata */
struct raw_inode {
	struct timespec ctime;
	uid_t uid;
	gid_t gid;
	umode_t mode;
};

struct inode *replayfs_new_inode(struct super_block *sb, int mode);

struct inode *replayfs_iget(struct super_block *sb,
		struct replayfs_unique_id *id, loff_t version);

loff_t replayfs_inode_version(struct inode *inode);

struct dentry *replayfs_inode_lookup(struct inode *dir, struct dentry *dentry,
		struct nameidata *nameidata);

struct inode *replayfs_inode_init(struct inode *inode, struct super_block *sb,
		loff_t version, int mode);

void replayfs_get_unique(struct inode *inode, struct replayfs_unique_id *id);

void replayfs_inode_modified_metadata(struct inode *inode, replayfs_log_t *log,
		replayfs_log_inode_t *log_inode);

void inode_attach(struct inode *inode);
void inode_detach(struct inode *inode);

#endif
