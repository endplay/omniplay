#include <linux/kernel.h>
#include <linux/fs.h>

#include "replayfs_fs.h"
#include "replayfs_file_log.h"
#include "replayfs_log.h"
#include "replayfs_inode.h"
#include "replayfs_perftimer.h"

/*#define REPLAYFS_FILE_DEBUG*/

#ifdef REPLAYFS_FILE_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

/* 
 * Instead of doing generic file operations we're programming our own, so that
 * we can save a log of the data instead of the data itself.
 */

struct perftimer *read_total = NULL;
struct perftimer *between_reads = NULL;
struct perftimer *write_total = NULL;
struct perftimer *between_writes = NULL;

ssize_t replayfs_file_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *ppos) {

	struct replayfs_inode_info *info;
	replayfs_log_t log;
	replayfs_log_inode_t log_inode;

	if (between_writes == NULL || write_total == NULL) {
		between_writes = perftimer_create("between writes", "Writes");
		write_total = perftimer_create("write total", "Writes");
	}

	perftimer_tick(between_writes);
	perftimer_start(write_total);

	debugk("%s %d: In write\n", __func__, __LINE__);
	debugk("%s %d: Write args: (%p, %p, %u, %p (%llu))\n", __func__, __LINE__,
			filp, buf, (unsigned int)len, ppos, (unsigned long long)*ppos);

	info = REPLAYFS_I(filp->f_dentry->d_inode);

	/* Record everything, including the data */
	debugk("%s %d: calling file_log_add_next with argument %p\n", __func__,
			__LINE__, info->file_log);

	if (!replayfs_begin_log_operation(&log)) {

		replayfs_log_add_inode(&log, &log_inode, &info->vfs_inode);

		/* Report to the underlying storage the write has happened */
		replayfs_log_add_mod(&log, &log_inode, (void *)buf, len, (*ppos)+PAGE_SIZE);

		/* Update the size before reporting it to the file_log */
		if (!test_thread_flag(TIF_REPLAY)) {
			i_size_write(&info->vfs_inode, info->vfs_inode.i_size + len);
		}

		replayfs_log_inode_done(&log, &log_inode, info->vfs_inode.i_size);
		replayfs_end_log_operation(&log);
	}

	*ppos += len;

	perftimer_stop(write_total);

	return len;
}

/* How do we allocate arbitrary address ranges for this algorithm? */
ssize_t replayfs_file_read(struct file *filp, char __user *buf, size_t len,
		loff_t *ppos) {
	int num_to_read;
	loff_t version;
	struct inode *inode;
	loff_t pppos;

	if (between_reads == NULL || read_total == NULL) {
		between_reads = perftimer_create("between reads", "Reads");
		read_total = perftimer_create("read total", "Reads");
	}

	perftimer_tick(between_reads);
	perftimer_start(read_total);

	pppos = *ppos + PAGE_SIZE;

	/* 
	 * They are reading from a recorded file, reconstruct the file with the file's
	 * log 
	 */

	inode = filp->f_dentry->d_inode;

	debugk("%s %d: len %d, *ppos %llu, size %d\n", __func__, __LINE__,
			(unsigned int)len, (unsigned long long)*ppos,
			(unsigned int)inode->i_size);

	/* Step 0, standard error checking (permission, size, bla bla blah) */
	/* If they want more data then we have, adjust */
	if (*ppos + len > inode->i_size) {
		num_to_read = inode->i_size - *ppos;
	} else {
		num_to_read = len;
	}

	version = replayfs_inode_version(inode);

	/* Extract the data from the log */
	debugk("%s %d: Attempting to read version %lld\n", __func__, __LINE__, version);
	num_to_read = replayfs_file_log_read_user(REPLAYFS_I(inode)->file_log,
			version, buf, num_to_read, &pppos);
	*ppos = pppos - PAGE_SIZE;

	debugk("Data read is %.*s\n", num_to_read, buf);

	debugk("%s %d: num_to_read (num read) is %d\n", __func__, __LINE__,
			num_to_read);

	perftimer_stop(read_total);

	/* return the number of bytes we read */
	return num_to_read;
}

