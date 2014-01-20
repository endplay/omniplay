#ifndef __REPLAYFS_ACL_H__
#define __REPLAYFS_ACL_H__

#include <linux/fs.h>

int replayfs_permission(struct inode *inode, int mask, struct nameidata *nd);

#endif
