#include "replayfs_log.h"
#include "replayfs_fs.h"
#include "replayfs_file_log.h"
#include "replayfs_inode.h"

#include <linux/replay.h>
#include <linux/replay_syscall_result.h>

/* #define REPLAY_DATA_DEBUG */

#ifdef REPLAY_DATA_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif


int replayfs_begin_log_operation(replayfs_log_t *log) {

	int ret;

	ret = 0;
	/* If we are replaying, we should run our replay record operation */
	if (test_thread_flag(TIF_REPLAY)) {
		loff_t sysnum;
		loff_t unique_id;
		debugk("%s %d: Replay start log operation start\n", __func__, __LINE__);

		/* Get our sysnum from the replay log */
		sysnum = current->replay_thrd->rp_record_thread->syscall_log.read_pos;

		/* Now, get our unique ID from the replay log */
		unique_id = current->replay_thrd->rp_record_thread->unique_id;
		debugk("%s %d: unique_id is %lld\n", __func__, __LINE__, unique_id);

		/* Now, fetch our replay descriptor */
		log->replay.replay = replay_cache_get(unique_id);
		if (log->replay.replay == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		debugk("%s %d: replay is %p, sysnum is %lld\n", __func__, __LINE__,
				log->replay.replay, sysnum);

		log->replay.entry = replay_desc_add_next_entry(log->replay.replay, sysnum);
		/* This shouldn't happen... */
		if (log->replay.entry == NULL) {
			/* 
			 * We should do some memory freeing, and return ENOMEM.... but this
			 * /really/ shouldn't happen
			 */
			ret = -1;
			goto out;
		}
		debugk("%s %d: Replay start log operation done\n", __func__, __LINE__);
	}

out:
	return ret;
}

void replayfs_end_log_operation(replayfs_log_t *log) {
	if (test_thread_flag(TIF_REPLAY)) {
		debugk("%s %d: Replay end log operation start\n", __func__, __LINE__);
		replay_desc_add_next_entry_done(log->replay.replay, log->replay.entry);
		replay_cache_put(log->replay.replay);
		debugk("%s %d: Replay end log operation done\n", __func__, __LINE__);
	}
}

int replayfs_log_add_inode(replayfs_log_t *log, replayfs_log_inode_t *inode_t,
		struct inode *inode) {
	if (test_thread_flag(TIF_REPLAY)) {
		debugk("%s %d: Replay inode add start\n", __func__, __LINE__);
		inode_t->inode = replay_desc_entry_add_inode(log->replay.replay,
				log->replay.entry, &REPLAYFS_I(inode)->id);
		debugk("%s %d: Replay inode add done\n", __func__, __LINE__);
	} else {
		inode_t->record.file = REPLAYFS_I(inode)->file_log;
		replayfs_file_log_add_next(inode_t->record.file);
		inode_t->record.entry = replayfs_file_log_get_current(inode_t->record.file);
	}

	return 0;
}

int replayfs_log_add_inode_by_id(replayfs_log_t *log, replayfs_log_inode_t *inode_t,
		struct replayfs_unique_id *id) {
	if (test_thread_flag(TIF_REPLAY)) {
		debugk("%s %d: Replay inode add start\n", __func__, __LINE__);
		inode_t->inode = replay_desc_entry_add_inode(log->replay.replay,
				log->replay.entry, id);
		debugk("%s %d: Replay inode add done\n", __func__, __LINE__);
	} else {
		BUG();
	}

	return 0;
}

void replayfs_log_inode_done(replayfs_log_t *log, replayfs_log_inode_t *inode,
		loff_t i_size) {
	if (test_thread_flag(TIF_REPLAY)) {
		/* 
		 * Do we really do nothing on replay here?  
		 * ...I guess no operation is needed because of the end_log_operation...
		 */
	} else {

		replayfs_file_log_put_current(inode->record.entry, inode->record.file);
		replayfs_file_log_next_done(inode->record.file, i_size);
	}
}

int replayfs_log_add_mod(replayfs_log_t *log, replayfs_log_inode_t *inode,
		void *data, loff_t offset, size_t size) {
	int ret;

	if (test_thread_flag(TIF_REPLAY)) {
		debugk("%s %d: Replay add mod start\n", __func__, __LINE__);
		/* 
		 * FIXME: Offset and size are backwards somewhere in this call chain... I'm
		 * reversing them here... its /really/ hacky
		 */
		ret = replay_desc_add_mod(log->replay.replay, inode->inode, data, size,
				offset);
		debugk("%s %d: Replay add mod done\n", __func__, __LINE__);
	} else {
		debugk("%s %d: Recording mod at %lld size %d to file log {%lld, %lld} (%p)\n",
				__func__, __LINE__, offset, size, inode->record.file->id.log_num,
				inode->record.file->id.sys_num, inode->record.file);
		ret = replayfs_file_log_entry_add(inode->record.entry, inode->record.file,
				data, offset, size);
	}

	return ret;
}

