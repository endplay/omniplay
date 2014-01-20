#ifndef __REPLAYFS_FS_H__
#define __REPLAYFS_FS_H__

/* Needed by user-land */
#include <linux/ioctl.h>
#define REPLAYFS_IOCTL_SET_VERSION _IOR('f', 135, unsigned long long *)
#define REPLAYFS_IOCTL_GET_VERSION _IOR('f', 136, unsigned long long *)
#define REPLAYFS_IOCTL_GET_SUBDIR _IOR('f', 137, const char *)
#define REPLAYFS_IOCTL_MAX_VERSION _IOR('f', 138, unsigned long long *)

#ifdef __KERNEL__
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>

#include "replayfs_file_log.h"
#include "replayfs_syscall_cache.h"

#define REPLAYFS_MAGIC 0xedde
#define REPLAYFS_ROOT_INO 1

#define REPLAYFS_BLOCKSIZE_BITS 11
#define REPLAYFS_BLOCKSIZE (1 << REPLAYFS_BLOCKSIZE_BITS)

#define REPLAYFS_I(X) container_of(X, struct replayfs_inode_info, vfs_inode)
#define REPLAYFS_SB(X) ((struct replayfs_sb_info *)((X)->s_fs_info))

#define REPLAYFS_SYS_NUM_RECORDED 0xFFFFFFFFFFFFFFFFULL

#define VERSION_CURRENT ((unsigned int)-1)

extern struct address_space_operations replayfs_aops;
extern struct file_operations replayfs_dir_fops;
extern struct file_operations replayfs_fops;
extern struct inode_operations replayfs_file_iops;
extern struct inode_operations replayfs_dir_iops;

struct replayfs_inode_info {
	struct hlist_node i_get_hash;

	struct replayfs_unique_id id;

	struct inode vfs_inode;

	/* The log of the inode's history */
	/* This is shared between multiple inodes (read-only), except by current, then
	 * append only
	 */
	struct replayfs_file_log *file_log;

	/* The index within the log this file represents */
	loff_t version;
};

struct replayfs_sb_info {
	spinlock_t i_get_lock;
	struct hlist_head i_get_head;

	struct replayfs_syscall_cache syscall_cache;
	struct replayfs_file_log_cache cache;

	struct file *meta_file;
};

loff_t replayfs_super_next_unique(struct super_block *sb);

int replayfs_fs_init(void);
void exit_replay_fs(void);

long replayfs_ioctl(struct file *filp, unsigned int cmd,
		unsigned long arg);

void replayfs_destroy_unique(void);
int replayfs_init_unique(void);
loff_t replayfs_next_unique(void);

struct page *replayfs_get_page(struct inode *dir, int n);
void replayfs_put_page(struct page *page);

struct file *replayfs_open_filp_by_id(struct vfsmount *vfs_loc,
		struct replayfs_unique_id *id, loff_t version);

unsigned int replayfs_id_hash(struct replayfs_unique_id *id);
unsigned int hash_int(unsigned int a);
unsigned int hash_int64(loff_t a);

static inline int replayfs_id_matches(struct replayfs_unique_id *id1,
		struct replayfs_unique_id *id2) {
	return (id1->log_num == id2->log_num) && (id1->sys_num == id2->sys_num);
}
#endif /* __KERNEL__ */

#endif

