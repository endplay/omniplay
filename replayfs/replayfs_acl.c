#include "replayfs_fs.h"
#include "replayfs_inode.h"
#include "replayfs_dir.h"
#include "replayfs_acl.h"

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

/* TODO: Acl support? */

/*
static inline struct posix_acl *replayfs_get_acl(struct inode *inode) {
	return REPLAYFS_I(inode)->acl;
}

int replayfs_init_acl(struct inode *inode, struct inode *parent) {
	struct posix_acl *acl;
	int error;

	acl = NULL;
	error = 0;

	if (!S_ISLNK(inode->i_mode)) {
		acl = replayfs_get_acl(dir);
	}

	if (acl) {
		struct posix_acl *clone;
		mode_t mode;

	}

	return error;
}

static int replayfs_check_acl(struct inode *inode, int mask) {
	struct posix_acl *acl;

	acl = replayfs_get_acl(inode);

	if (IS_ERR(acl)) {
		return PTR_ERR(acl);
	}
	if (acl) {
		int err = posix_acl_permission(inode, acl, mask);
		return err;
	}
	return -EAGAIN;
}
*/

int replayfs_permission(struct inode *inode, int mask, struct nameidata *nd) {
	/* generic_permission(inode, mask, replayfs_check_acl); */
	/*printk("In %s\n", __func__);*/
	return generic_permission(inode, mask, NULL);
}

