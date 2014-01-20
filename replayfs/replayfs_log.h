#ifndef __REPLAYFS_LOG_H__
#define __REPLAYFS_LOG_H__

/* 
 * This is a shim to coordinate between recording and replaying processes
 *
 * NOTE: If a non-replay process is running, the log decides to save the data,
 * this component does not concern itself with that
 */

#include "replay_data.h"
#include "replayfs_file_log.h"

#include <linux/fs.h>

struct replayfs_replay_log {
	struct replay_desc *replay;
	struct replay_desc_entry *entry;
};

typedef union {
	struct replayfs_replay_log replay;
} replayfs_log_t;

struct replayfs_record_log {
	struct replayfs_file_log *file;
	struct replayfs_file_log_entry *entry;
};

typedef union {
	struct replay_desc_inode_entry *inode;
	struct replayfs_record_log record;
} replayfs_log_inode_t;

int replayfs_begin_log_operation(replayfs_log_t *log);
void replayfs_end_log_operation(replayfs_log_t *log);

/* 
 * For use from replaying process only, makes it so open() does not need to
 * instantiate a file, if replaying metadata write.
 *   (doing so would lead to a deadlock)
 */
int replayfs_log_add_inode_by_id(replayfs_log_t *log,
		replayfs_log_inode_t *inode_t, struct replayfs_unique_id *id);

int replayfs_log_add_inode(replayfs_log_t *log, replayfs_log_inode_t *inode_t,
		struct inode *inode);
void replayfs_log_inode_done(replayfs_log_t *log, replayfs_log_inode_t *inode,
		loff_t i_size);

int replayfs_log_add_mod(replayfs_log_t *log, replayfs_log_inode_t *inode,
		void *data, loff_t offset, size_t size);

#endif

