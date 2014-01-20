#include "replayfs_fs.h"
#include "replay_data.h"
#include "replayfs_inode.h"
#include "replayfs_dir.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/unistd.h>
#include <linux/mount.h>

#include <linux/replay.h>

/* #define REPLAYFS_SHIM_DEBUG */

#ifdef REPLAYFS_SHIM_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

/*
 * Causes the replayfs to keep and check the read data to ensure files and
 * replays do not diverge
 */
#define REPLAYFS_CHECK_READ_DATA

#define OPEN_TABLE_SIZE 64

struct replayfs_open_retparams {
	struct replayfs_unique_id unique_id;
	loff_t version;
	loff_t pos;
};

struct replayfs_fch_retparams {
	loff_t version;
};

struct replayfs_read_retparams {
	loff_t version;
#ifdef REPLAYFS_CHECK_READ_DATA
	char data[0];
#endif
};

struct replayfs_parent_retparams {
	struct replayfs_unique_id parent_id;
	loff_t parent_version;
};

struct replayfs_self_retparams {
	struct replayfs_unique_id id;
	loff_t version;
};

struct vfsmount *vfs_loc;

/* Replayfs process local storage */
struct replayfs_proc_local {
	struct replayfs_open_retparams open_table[OPEN_TABLE_SIZE];
};

static void __get_file_info(const char __user *user_path, struct replayfs_unique_id *id,
		loff_t *version) {
	mm_segment_t old_fs;

	struct file *filp;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	debugk("%s %d: Attempting to open %s\n", __func__, __LINE__, user_path);
	filp = filp_open(user_path, O_RDONLY, 0777);

	if (!IS_ERR(filp)) {
		debugk("%s %d: %s's size is %lld\n", __func__, __LINE__, user_path,
				filp->f_dentry->d_inode->i_size);
		if (filp->f_op->unlocked_ioctl == replayfs_ioctl) {
			/* Get the directories info (id, version) */
			*version = replayfs_inode_version(filp->f_dentry->d_inode);
			memcpy(id,
					&REPLAYFS_I(filp->f_dentry->d_inode)->file_log->id,
					sizeof(struct replayfs_unique_id));
		} else {
			*version = REPLAYFS_CURRENT_VERSION;
		}
		filp_close(filp, NULL);
	} else {
		/* Signal failure to open the file with an invalid version... */
		*version = REPLAYFS_CURRENT_VERSION;
	}

	set_fs(old_fs);
}

static void get_parent_info(const char __user *user_path, struct replayfs_unique_id *id,
		loff_t *version) {
	int pos;
	char dirname[0x100];

	/* Parse the path to find the directory */
	pos = strlen_user(user_path)-1;
	BUG_ON(pos >= 0x80 || pos < 0);
	if (strncpy_from_user(dirname, user_path, 0x80) < 0) {
		BUG();
	}

	/* Find the last / */
	while(dirname[pos] != '/' && pos != 0) {
		pos--;
	}

	if (pos != 0) {
		dirname[pos] = '\0';
	} else {
		dirname[0] = '.';
		dirname[1] = '/';
		dirname[2] = '\0';
	}

	__get_file_info(dirname, id, version);
}

static void get_self_info(const char __user *user_path, struct replayfs_unique_id *id,
		loff_t *version) {
	int len;

	len = strlen_user(user_path);
	if (!access_ok(user_path, len, MAY_READ)) {
		BUG();
	}

	__get_file_info(user_path, id, version);
}

static void *replayfs_new_pls(void) {
	void *ret;
	int i;

	ret = kmalloc(sizeof(struct replayfs_proc_local), GFP_NOFS);
	/* I should support this... somehow... I think */
	BUG_ON(ret == NULL);

	for (i = 0; i < OPEN_TABLE_SIZE; i++) {
		struct replayfs_proc_local *pls;

		pls = ret;

		/* Initialize the open table to all closed */
		pls->open_table[i].unique_id.log_num = REPLAYFS_CURRENT_VERSION;
		pls->open_table[i].version = REPLAYFS_CURRENT_VERSION;
	}

	return ret;
}

static void replayfs_free_pls(void *pls) {
	kfree(pls);
}

void replayfs_pls_init(void) {
	replay_attach_pls(replayfs_new_pls, replayfs_free_pls);
}

void replayfs_pls_destroy(void) {
	replay_clear_pls();
}

/* Retrieve the (p)rocess (l)ocal (s)torage for the replayfs unit */
static inline void *replayfs_get_pls(void) {
	return current->replay_thrd->rp_pls;
}

void *replayfs_open_get_retparams(struct syscall_result *syscall, const char __user *filename, char *kfilename, int flags, int mode) {
	struct replayfs_open_retparams *rets;
	struct replayfs_proc_local *pls;
	int fd;

	struct file *filp;

	rets = syscall->retparams;
	fd = syscall->retval;

	/*
	 * We need to open the file based on its unique id, and store its return
	 * mapping in some process-local storage
	 */
	debugk("%s %d: Open called with string %s\n", __func__, __LINE__, filename);
	debugk("%s %d: Checking log_num (%llX) and fd (%d)\n", __func__, __LINE__,
			rets->unique_id.log_num, fd);
	if (fd >= 0) {
		pls = replayfs_get_pls();
		if (pls == NULL) {
			goto out;
		}

		if (rets->version != REPLAYFS_CURRENT_VERSION) {
			memcpy(&pls->open_table[fd], rets, sizeof(struct replayfs_open_retparams));
			pls->open_table[fd].pos = 0;
		} else {
			pls->open_table[fd].version = REPLAYFS_CURRENT_VERSION;
		}

		/* Add this to the processes local storage */
		BUG_ON(fd > OPEN_TABLE_SIZE);

		if (pls->open_table[fd].version != REPLAYFS_CURRENT_VERSION) {

			/* Call open on the dir containing our file */
			filp = replayfs_open_filp_by_id(vfs_loc,
					&pls->open_table[fd].unique_id,
					pls->open_table[fd].version);

			debugk("%s %d: Tried to open file {%lld, %lld, %lld}, got %p\n",
					__func__, __LINE__,
					pls->open_table[fd].unique_id.log_num,
					pls->open_table[fd].unique_id.sys_num, pls->open_table[fd].version,
					filp);

			/*
			 * Update unique id to represent the file, not the directory
			 *   (for future writes/reads)
			 */
			pls->open_table[fd].unique_id.sys_num =
						current->replay_thrd->rp_record_thread->syscall_log.read_pos;
			pls->open_table[fd].unique_id.log_num =
					current->replay_thrd->rp_record_thread->unique_id;

			debugk("%s %d: filp->i_size is %lld\n", __func__, __LINE__,
					filp->f_dentry->d_inode->i_size);

			debugk("%s %d: OPEN Setting pls->open_table[%d].unique_id to {%lld, %lld}\n",
					__func__, __LINE__, fd, pls->open_table[fd].unique_id.log_num,
					pls->open_table[fd].unique_id.sys_num);
		} else {
			filp = NULL;
		}

		/* Simulate the operations the directory would undergo */
		if (filp) {
			int pos;
			struct dentry entry;
			struct page *dir_page;
			struct replayfs_dir *dir;
			struct raw_inode raw;
			loff_t dir_pos;
			char fname[0x80];

			replayfs_log_t log;
			replayfs_log_inode_t log_inode;

			/* Figure out if the file exists */

			/* Get file name within directory */
			/* Scan backwards for '/' or begin of path */
			pos = strlen(filename);
			entry.d_name.len = pos;
			if (strncpy_from_user(fname, filename, 0x80) < 0) {
				/* Shouldn't happen, we should catch error cases and break early */
				BUG();
			}

			while (pos != 0 && fname[pos] != '/') {
				pos--;
			}

			entry.d_name.len -= pos;
			entry.d_name.name = &fname[pos];

			/*
			 * If the file doesn't exist, and the return is successful, we created the
			 * file...
			 */
			dir = replayfs_dir_find_entry(filp->f_dentry->d_inode,
					&entry, &dir_page, &dir_pos);

			/*
			 * If the file doesn't exist, simulate the file creation process, passing
			 * needed data
			 */
			if (dir == NULL) {
				struct replayfs_unique_id id;

				/* Okay, the file doesn't exist... we need to fake crating it. */

				/* Fill out the identifier of the inode created by this syscall */
				id.sys_num =
					current->replay_thrd->rp_record_thread->syscall_log.read_pos;
				id.log_num = current->replay_thrd->rp_record_thread->unique_id;

				/* Get the log and log_inode for this file */
				if (!replayfs_begin_log_operation(&log)) {

					debugk("%s %d: OPEN: Adding entry for id {%lld, %lld}\n", __func__,
							__LINE__, id.log_num, id.sys_num);
					replayfs_log_add_inode_by_id(&log, &log_inode, &id);

					/* Set up the initial metadata (owner, mode) */
					raw.uid = current->fsuid;
					raw.gid = current->fsgid;
					raw.mode = mode;

					/*
					 * FIXME
					 * Gah... this is an issue, ctime is non-deterministic input, but I don't
					 * have a way to save it... I'll have to make one...
					 */
					raw.ctime = CURRENT_TIME_SEC;

					replayfs_log_add_mod(&log, &log_inode, &raw, sizeof(raw), 0);
					/* NOTE: size doesn't matter for record */
					replayfs_log_inode_done(&log, &log_inode, 0);

					/* Now add the directory operation */
					replayfs_log_add_inode(&log, &log_inode, filp->f_dentry->d_inode);

					replayfs_dir_new_entry_external(filp->f_dentry->d_inode,
							entry.d_name.name, &id, mode, &log, &log_inode);

					/* NOTE: size doesn't matter for record */
					replayfs_log_inode_done(&log, &log_inode, 0);

					replayfs_end_log_operation(&log);
				}
			} else {

				pls->open_table[fd].unique_id.sys_num =
						dir->header.id.sys_num;
				pls->open_table[fd].unique_id.log_num =
						dir->header.id.log_num;

				debugk("%s %d: OPEN FIXING pls->open_table[%d].unique_id to {%lld, %lld}\n",
						__func__, __LINE__, fd, pls->open_table[fd].unique_id.log_num,
						pls->open_table[fd].unique_id.sys_num);

				replayfs_put_page(dir_page);
			}

			filp_close(filp, NULL);

		/* If the file exists at version, don't modify the directory or file */
		} else {
		}
	}

out:
	return NULL;
}

/* Called before the syscall from replay.c on record */
void replayfs_open_init_retparams(struct syscall_result *syscall, const char __user *filename, int flags, int mode) {
	struct replayfs_open_retparams *rets;

	debugk("%s %d: Recording call to open beginning\n", __func__, __LINE__);

	rets = RETPARAMSKMALLOC(syscall->log, sizeof(struct replayfs_open_retparams), GFP_NOFS);


	get_parent_info(filename, &rets->unique_id, &rets->version);

	rets->pos = 0;

	debugk("%s %d: Recording call to open ending\n", __func__, __LINE__);

	/* Done */
	syscall->retparams = rets;
}

void replayfs_generic_set_retparams(struct syscall_result *syscall, void *raw) {
	/* NOTE: I don't need to free the old ret, it was never alloced */
	debugk("%s %d: Hooked main on record\n", __func__, __LINE__);
}

void *replayfs_write_get_retparams(struct syscall_result *syscall, int fd, const char __user *buf, size_t count) {
	struct replayfs_proc_local *pls;
	struct file *filp;

	debugk("%s %d: Intercepted a write syscall on replay!\n", __func__, __LINE__);
	debugk("%s %d: The write's entry number is %lld\n", __func__, __LINE__,
			current->replay_thrd->rp_record_thread->syscall_log.read_pos);

	/*
	 * Okay, look up this process's file based on the fd...
	 */
	pls = replayfs_get_pls();

	if (
				pls->open_table[fd].version == REPLAYFS_CURRENT_VERSION
			) {
		return syscall->retparams;
	}

	/*
	 * The version we open doesn't matter, this is handled internally.  So we're
	 * arbitrarily opening version 0, that way we don't have any dependencies
	 */
	debugk("%s %d: about to call replayfs_open_filp_by_id\n", __func__, __LINE__);
	filp = replayfs_open_filp_by_id(vfs_loc,
			&pls->open_table[fd].unique_id,
			0);
	debugk("%s %d: filp is %p\n", __func__, __LINE__, filp);
	/* Now that we have the file structure, see if its in the replayfs FS */
	if (filp != NULL) {
		if (filp->f_op->unlocked_ioctl == replayfs_ioctl) {
			/*
			 * If this is a replayfs file, we need to write it, to gain the data from
			 * this replay
			 */

			/* If this isn't a replay process... we're in trouble */
			BUG_ON(!test_thread_flag(TIF_REPLAY));

			/* Actually do the write operation */
			debugk("%s %d: Calling vfs write!\n", __func__, __LINE__);
			/*vfs_write(filp, buf, count, &pos);*/
			filp->f_op->write(filp, buf, count, &pls->open_table[fd].pos);
		}

		filp_close(filp, NULL);
	}

	/* Return the retparams */
	return syscall->retparams;
}

void replayfs_write_set_retparams(struct syscall_result *syscall, int fd, const char __user *buf, size_t count) {
	/*
	 * Record -- do nothing special
	 */
	debugk("%s %d: Intercepted a write on record!\n", __func__, __LINE__);
	debugk("%s %d: The write's entry number is %d retval is %ld\n", __func__, __LINE__,
			syscall_log_size(&current->record_thrd->syscall_log)-1, syscall->retval);
	if (raw) {
		RETPARAMSKFREE(syscall->log, raw, syscall->retval);
	}
	syscall->retparams = NULL;
}

void *replayfs_read_get_retparams(struct syscall_result *syscall, int fd, char __user *buf, size_t count) {
	/*
	 * So, we're replaying the file.  We should re-read the file's result that we
	 * we don't have to store it in the log
	 */

	/* We read data... lets get that data */
	if (syscall->retval > 0) {
		struct replayfs_read_retparams *rets;

		struct replayfs_proc_local *pls;
		struct file *filp;

		void *new_retparam;

		mm_segment_t old_fs;

		size_t nread;

		debugk("%s %d: syscall->retval > 0 (%ld)\n", __func__, __LINE__,  syscall->retval);

		pls = replayfs_get_pls();

		rets = syscall->retparams;

		if (
					pls->open_table[fd].version == REPLAYFS_CURRENT_VERSION
				) {
			debugk("%s %d: File is not a replayfs file, returning unmodified retparams\n",
					__func__, __LINE__);

			return syscall->retparams;
		}

		filp = replayfs_open_filp_by_id(vfs_loc,
				&pls->open_table[fd].unique_id,
				rets->version);

		new_retparam = syslog_argsalloc(syscall->log, syscall->retval);

		old_fs = get_fs();
		set_fs(KERNEL_DS);

		debugk("%s %d: Reading from filp, syscall->retval (%ld), pls->open_table[fd].pos (%lld)\n",
				__func__, __LINE__, syscall->retval, pls->open_table[fd].pos);
		/*
		nread = vfs_read(filp, new_retparam, syscall->retval,
				&pls->open_table[fd].pos);
				*/
		nread = filp->f_op->read(filp, new_retparam, syscall->retval,
				&pls->open_table[fd].pos);

		set_fs(old_fs);

		/* XXX XXX XXX XXX XXX XXX XXX XXX XXX
		 * NOTE
		 *   Leftoff here -- syscall->retval is 20, the file contents are
		 *   "testtest2\n", expected syscall->retval is 10.  nread is 10.  Need to
		 *   trace where syscall->retval is coming from... (in the replay kernel,
		 *   replay.c/replay_shims.c
		 */

		if (nread != syscall->retval) {
			printk("%s %d: ERROR Did not read as much data as expected, printing diagnostic stack dump\n",
					__func__, __LINE__);
			printk("%s %d: nread (%d) != syscall->retval (%ld)\n", __func__, __LINE__, nread, syscall->retval);
			dump_stack();
			printk("!!!!!!????!?!?!?!!!?!!!!******************!!!?!?!!!!?!???!!!\n");
			BUG();
		}

		filp_close(filp, NULL);

#ifdef REPLAYFS_CHECK_READ_DATA
		if (memcmp(new_retparam, rets->data, syscall->retval)) {
			printk("%s %d: ERROR Data diverges from expected!!!!\n",
					__func__, __LINE__);
			dump_stack();
			printk("!!!!!!????!?!?!?!!!?!!!!******************!!!?!?!!!!?!???!!!\n");
			BUG();
		}
#endif

		debugk("%s %d: Got new retparams for syscall, returning those\n", __func__,
				__LINE__);
		return new_retparam;
	}

	return syscall->retparams;
}

void replayfs_read_set_retparams(struct syscall_result *syscall, int fd, char __user *buf, size_t count) {
	/*
	 * Record - Reading a file, we actually don't need to save any retparams...
	 */

	if (syscall->retval > 0) {
		struct replayfs_read_retparams *rets;

		struct file *filp;

		debugk("%s %d: READ CALLED, syscall->retval > 0 (%ld)\n", __func__,
				__LINE__, syscall->retval);

		/* Get version from file */
		filp = fget(fd);

		if (filp->f_op->unlocked_ioctl == replayfs_ioctl) {

			debugk("%s %d: File is a replayfs file!\n", __func__,
					__LINE__);

#ifdef REPLAYFS_CHECK_READ_DATA
			rets = RETPARAMSKMALLOC(syscall->log,
					sizeof(struct replayfs_read_retparams) + syscall->retval + 4,
					GFP_NOFS);

			BUG_ON(rets == NULL);

			memcpy(rets->data, raw, syscall->retval);
#else
			rets = RETPARAMSKMALLOC(syscall->log,
					sizeof(struct replayfs_read_retparams), GFP_NOFS);

			BUG_ON(rets == NULL);
#endif

			/* XXX FIXME RACE!!!! */
			/*
			 * Should fix by locking a RW lock before the read (retparam init) and
			 * unlocking after this
			 */
			rets->version = replayfs_inode_version(filp->f_dentry->d_inode);

			RETPARAMSKFREE(syscall->log, raw, syscall->retval);

			/* Free the read's retparams */
			syscall->retparams = rets;
		} else {
			debugk("%s %d: File is NOT a replayfs file!\n", __func__,
					__LINE__);
			syscall->retparams = raw;
		}
		fput(filp);
	}
}

void replayfs_mkdir_init_retparams(struct syscall_result *syscall, const char __user *pathname, int mode) {
	struct replayfs_parent_retparams *rets;

	rets = RETPARAMSKMALLOC(syscall->log, sizeof(struct replayfs_parent_retparams), GFP_NOFS);

	get_parent_info(pathname, &rets->parent_id, &rets->parent_version);

	/* Parse the path to find the directory */

	syscall->retparams = rets;
}

void *replayfs_mkdir_get_retparams(struct syscall_result *syscall, const char __user *pathname, int mode) {
	struct replayfs_parent_retparams *rets;

	rets = syscall->retparams;

	/* See if the directory was successfully opened before */
	if (rets->parent_version != REPLAYFS_CURRENT_VERSION) {
		struct file *filp;

		/* Open the directory at the previous version */
		filp = replayfs_open_filp_by_id(vfs_loc,
				&rets->parent_id,
				rets->parent_version);

		if (filp) {
			int pos;
			struct dentry entry;
			struct page *dir_page;
			struct replayfs_dir *dir;
			struct raw_inode raw;
			loff_t dir_pos;
			char fname[0x80];

			replayfs_log_t log;
			replayfs_log_inode_t log_inode;

			/* Figure out if the file exists */

			/* Get file name within directory */
			/* Scan backwards for '/' or begin of path */
			pos = strlen(pathname);
			entry.d_name.len = pos;
			if (strncpy_from_user(fname, pathname, 0x80) < 0) {
				/* Shouldn't happen, we should catch error cases and break early */
				BUG();
			}

			while (pos != 0 && fname[pos] != '/') {
				pos--;
			}

			entry.d_name.len -= pos;
			entry.d_name.name = &fname[pos];

			/*
			 * If the file doesn't exist, and the return is successful, we created the
			 * file...
			 */
			dir = replayfs_dir_find_entry(filp->f_dentry->d_inode,
					&entry, &dir_page, &dir_pos);

			/*
			 * If the file doesn't exist, simulate the file creation process, passing
			 * needed data
			 */
			if (dir == NULL) {
				struct replayfs_unique_id id;

				/* Okay, the file doesn't exist... we need to fake crating it. */

				/* Get the log and log_inode for this file */
				if (!replayfs_begin_log_operation(&log)) {

					/* Fill out the identifier of the inode created by this syscall */
					id.sys_num =
						current->replay_thrd->rp_record_thread->syscall_log.read_pos;
					id.log_num = current->replay_thrd->rp_record_thread->unique_id;

					replayfs_log_add_inode_by_id(&log, &log_inode, &id);

					/* Set up the initial metadata (owner, mode) */
					raw.uid = current->fsuid;
					raw.gid = current->fsgid;
					raw.mode = mode | S_IFDIR;

					/*
					 * FIXME
					 * Gah... this is an issue, ctime is non-deterministic input, but I don't
					 * have a way to save it... I'll have to make one...
					 */
					raw.ctime = CURRENT_TIME_SEC;

					replayfs_log_add_mod(&log, &log_inode, &raw, sizeof(raw), 0);

					/* NOTE: size doesn't matter for record */
					replayfs_log_inode_done(&log, &log_inode, 0);

					/* Now add the directory operation */
					replayfs_log_add_inode(&log, &log_inode, filp->f_dentry->d_inode);

					replayfs_dir_new_entry_external(filp->f_dentry->d_inode,
							entry.d_name.name, &id, mode | S_IFDIR, &log, &log_inode);

					/* NOTE: size doesn't matter for record */
					replayfs_log_inode_done(&log, &log_inode, 0);

					replayfs_end_log_operation(&log);
				}
			} else {
				replayfs_put_page(dir_page);
			}

			filp_close(filp, NULL);

		/* If we could open it before, but not now... we've got a problem */
		} else {
			BUG();
		}
	}

	return NULL;
}

void replayfs_rmdir_init_retparams(struct syscall_result *syscall, const char __user *pathname) {
	struct replayfs_parent_retparams *rets;

	rets = RETPARAMSKMALLOC(syscall->log, sizeof(struct replayfs_parent_retparams), GFP_NOFS);

	get_parent_info(pathname, &rets->parent_id, &rets->parent_version);

	syscall->retparams = rets;
}

void *replayfs_rmdir_get_retparams(struct syscall_result *syscall, const char __user *pathname) {
	struct replayfs_parent_retparams *rets;

	rets = syscall->retparams;

	/* See if the directory was successfully opened before */
	if (rets->parent_version != REPLAYFS_CURRENT_VERSION) {
		struct file *filp;

		/* Open the directory at the previous version */
		filp = replayfs_open_filp_by_id(vfs_loc,
				&rets->parent_id,
				rets->parent_version);

		if (filp) {
			int pos;
			struct dentry entry;
			struct page *dir_page;
			struct replayfs_dir *dir;
			loff_t dir_pos;
			char fname[0x80];

			replayfs_log_t log;
			replayfs_log_inode_t log_inode;

			/* Figure out if the file exists */

			/* Get file name within directory */
			/* Scan backwards for '/' or begin of path */
			pos = strlen(pathname);
			entry.d_name.len = pos;
			if (strncpy_from_user(fname, pathname, 0x80) < 0) {
				/* Shouldn't happen, we should catch error cases and break early */
				BUG();
			}

			while (pos != 0 && fname[pos] != '/') {
				pos--;
			}

			entry.d_name.len -= pos;
			entry.d_name.name = &fname[pos];

			/*
			 * If the file doesn't exist, and the return is successful, we created the
			 * file...
			 */
			dir = replayfs_dir_find_entry(filp->f_dentry->d_inode,
					&entry, &dir_page, &dir_pos);

			/*
			 * If the file doesn't exist, simulate the file creation process, passing
			 * needed data
			 */
			if (dir != NULL) {
				/* Get the log and log_inode for this file */
				if (!replayfs_begin_log_operation(&log)) {

					/* Now add the directory operation */
					replayfs_log_add_inode(&log, &log_inode, filp->f_dentry->d_inode);

					replayfs_dir_delete_entry(dir, dir_page, dir_pos, &log, &log_inode);

					/* NOTE: size doesn't matter for record */
					replayfs_log_inode_done(&log, &log_inode, 0);

					replayfs_end_log_operation(&log);
				}
			} else {
				/* The dir didn't exist... don't do anything */
			}

			filp_close(filp, NULL);

		/* If we could open it before, but not now... we've got a problem */
		} else {
			BUG();
		}
	}

	return NULL;
}

void replayfs_unlink_init_retparams(struct syscall_result *syscall, const char __user *pathname) {
	struct replayfs_parent_retparams *rets;

	rets = RETPARAMSKMALLOC(syscall->log, sizeof(struct replayfs_parent_retparams), GFP_NOFS);

	get_parent_info(pathname, &rets->parent_id, &rets->parent_version);

	syscall->retparams = rets;
}

void *replayfs_unlink_get_retparams(struct syscall_result *syscall, const char __user *pathname) {
	struct replayfs_parent_retparams *rets;

	rets = syscall->retparams;

	debugk("%s %d: syscall_log.read_pos is %lld\n", __func__, __LINE__,
			current->replay_thrd->rp_record_thread->syscall_log.read_pos);

	/* See if the directory was successfully opened before */
	if (rets->parent_version != REPLAYFS_CURRENT_VERSION) {
		struct file *filp;

		/* Open the directory at the previous version */
		filp = replayfs_open_filp_by_id(vfs_loc,
				&rets->parent_id,
				rets->parent_version);

		if (filp) {
			int pos;
			struct dentry entry;
			struct page *dir_page;
			struct replayfs_dir *dir;
			loff_t dir_pos;
			char fname[0x80];

			replayfs_log_t log;
			replayfs_log_inode_t log_inode;

			/* Get file name within directory */
			/* Scan backwards for '/' or begin of path */
			pos = strlen(pathname);
			entry.d_name.len = pos;
			if (strncpy_from_user(fname, pathname, 0x80) < 0) {
				/* Shouldn't happen, we should catch error cases and break early */
				BUG();
			}

			while (pos != 0 && fname[pos] != '/') {
				pos--;
			}

			entry.d_name.len -= pos;
			entry.d_name.name = &fname[pos];

			/*
			 * If the file doesn't exist, and the return is successful, we created the
			 * file...
			 */
			dir = replayfs_dir_find_entry(filp->f_dentry->d_inode,
					&entry, &dir_page, &dir_pos);

			/*
			 * If the file doesn't exist, simulate the file creation process, passing
			 * needed data
			 */
			if (dir != NULL) {
				/* Get the log and log_inode for this file */
				if (!replayfs_begin_log_operation(&log)) {

					/* Now add the directory operation */
					replayfs_log_add_inode(&log, &log_inode, filp->f_dentry->d_inode);

					replayfs_dir_delete_entry(dir, dir_page, dir_pos, &log, &log_inode);

					/* NOTE: size doesn't matter for record */
					replayfs_log_inode_done(&log, &log_inode, 0);

					replayfs_end_log_operation(&log);
				}
			} else {
				/* The dir didn't exist... don't do anything */
				printk("%s %d: Here :(\n", __func__, __LINE__);
			}

			filp_close(filp, NULL);

		/* If we could open it before, but not now... we've got a problem */
		} else {
			BUG();
		}
	}

	return NULL;
}

void replayfs_chmod_init_retparams(struct syscall_result *syscall, const char __user *filename, int mode) {
	struct replayfs_self_retparams *rets;

	rets = RETPARAMSKMALLOC(syscall->log, sizeof(struct replayfs_self_retparams), GFP_NOFS);

	get_self_info(filename, &rets->id, &rets->version);

	syscall->retparams = rets;
}

void *replayfs_chmod_get_retparams(struct syscall_result *syscall, const char __user *filename, int mode) {
	struct replayfs_self_retparams *rets;

	rets = syscall->retparams;

	/* See if the directory was successfully opened before */
	if (rets->version != REPLAYFS_CURRENT_VERSION) {
		struct file *filp;

		/* Open the directory at the previous version */
		filp = replayfs_open_filp_by_id(vfs_loc,
				&rets->id,
				rets->version);

		if (filp) {
			struct raw_inode raw;
			replayfs_log_t log;
			replayfs_log_inode_t log_inode;

			struct inode *inode;

			loff_t pos = 0;

			inode = filp->f_dentry->d_inode;

			raw.ctime = inode->i_ctime;
			raw.uid = inode->i_uid;
			raw.gid = inode->i_gid;
			raw.mode = (inode->i_mode & S_IFDIR) | mode;

			/* Now simulate the ch action on the file */
			/* Get the log and log_inode for this file */
			if (!replayfs_begin_log_operation(&log)) {

				/* Now add the directory operation */
				replayfs_log_add_inode(&log, &log_inode, filp->f_dentry->d_inode);

				/* Modify the metadata */
				replayfs_log_add_mod(&log, &log_inode, &raw, sizeof(raw),
						pos);

				/* NOTE: size doesn't matter for record */
				replayfs_log_inode_done(&log, &log_inode, 0);

				replayfs_end_log_operation(&log);
			}

			filp_close(filp, NULL);
		} else {
			BUG();
		}
	}

	return NULL;
}

void replayfs_chown_init_retparams(struct syscall_result *syscall, const char __user *filename, uid_t user, gid_t group) {
	struct replayfs_self_retparams *rets;

	rets = RETPARAMSKMALLOC(syscall->log, sizeof(struct replayfs_self_retparams), GFP_NOFS);

	get_self_info(filename, &rets->id, &rets->version);

	syscall->retparams = rets;
}

void *replayfs_chown_get_retparams(struct syscall_result *syscall, const char __user *filename, uid_t user, gid_t group) {
	struct replayfs_self_retparams *rets;

	rets = syscall->retparams;

	/* See if the directory was successfully opened before */
	if (rets->version != REPLAYFS_CURRENT_VERSION) {
		struct file *filp;

		/* Open the directory at the previous version */
		filp = replayfs_open_filp_by_id(vfs_loc,
				&rets->id,
				rets->version);

		if (filp) {
			struct raw_inode raw;
			replayfs_log_t log;
			replayfs_log_inode_t log_inode;

			struct inode *inode;

			loff_t pos = 0;

			inode = filp->f_dentry->d_inode;

			raw.ctime = inode->i_ctime;
			raw.uid = user;
			raw.gid = group;
			raw.mode = inode->i_mode;

			/* Now simulate the ch action on the file */
			/* Get the log and log_inode for this file */
			if (!replayfs_begin_log_operation(&log)) {

				/* Now add the directory operation */
				replayfs_log_add_inode(&log, &log_inode, filp->f_dentry->d_inode);

				/* Modify the metadata */
				replayfs_log_add_mod(&log, &log_inode, &raw, sizeof(raw),
						pos);

				/* NOTE: size doesn't matter for record */
				replayfs_log_inode_done(&log, &log_inode, 0);

				replayfs_end_log_operation(&log);
			}

			filp_close(filp, NULL);
		} else {
			BUG();
		}
	}

	return NULL;
}

void replayfs_fchmod_init_retparams(struct syscall_result *syscall, int fd, mode_t mode) {
	/* If this call was a success */
	if (syscall->retval == 0) {
		struct replayfs_fch_retparams *rets;

		struct file *filp;

		/* Get version from file */
		filp = fget(fd);

		if (filp->f_op->unlocked_ioctl == replayfs_ioctl) {

			debugk("%s %d: File is a replayfs file!\n", __func__,
					__LINE__);

			rets = RETPARAMSKMALLOC(syscall->log,
					sizeof(struct replayfs_fch_retparams), GFP_NOFS);

			BUG_ON(rets == NULL);

			/* XXX FIXME RACE!!!! */
			/*
			 * Should fix by locking lock before the read (retparam init) and
			 * unlocking after this
			 */
			rets->version = replayfs_inode_version(filp->f_dentry->d_inode);

			/*
			if (raw) {
				RETPARAMSKFREE(syscall->log, raw, syscall->retval);
			}
			*/

			/* Free the read's retparams */
			syscall->retparams = rets;
		} else {
			debugk("%s %d: File is NOT a replayfs file!\n", __func__,
					__LINE__);
			syscall->retparams = raw;
		}
		fput(filp);
	}
}

void *replayfs_fchmod_get_retparams(struct syscall_result *syscall, int fd, mode_t mode) {
	struct replayfs_fch_retparams *rets;

	struct replayfs_proc_local *pls;
	struct file *filp;

	rets = syscall->retparams;

	/*
	 * Okay, look up this process's file based on the fd...
	 */
	pls = replayfs_get_pls();

	if (
				pls->open_table[fd].version == REPLAYFS_CURRENT_VERSION
			) {
		return syscall->retparams;
	}

	/*
	 * The version we open doesn't matter, this is handled internally.  So we're
	 * arbitrarily opening version 0, that way we don't have any dependencies
	 */
	filp = replayfs_open_filp_by_id(vfs_loc,
			&pls->open_table[fd].unique_id,
			rets->version);

	if (filp) {
		struct raw_inode raw;
		replayfs_log_t log;
		replayfs_log_inode_t log_inode;

		struct inode *inode;

		loff_t pos = 0;


		inode = filp->f_dentry->d_inode;

		raw.ctime = inode->i_ctime;
		raw.uid = inode->i_uid;
		raw.gid = inode->i_gid;
		raw.mode = mode;

		/* Now simulate the ch action on the file */
		/* Get the log and log_inode for this file */
		if (!replayfs_begin_log_operation(&log)) {

			/* Now add the directory operation */
			replayfs_log_add_inode(&log, &log_inode, filp->f_dentry->d_inode);

			/* Modify the metadata */
			replayfs_log_add_mod(&log, &log_inode, &raw, sizeof(raw),
					pos);

			/* NOTE: size doesn't matter for record */
			replayfs_log_inode_done(&log, &log_inode, 0);

			replayfs_end_log_operation(&log);
		}

		filp_close(filp, NULL);
	} else {
		BUG();
	}

	return NULL;
}

void replayfs_fchown32_init_retparams(struct syscall_result *syscall, int fd, uid_t user, gid_t group) {
	/* If this call was a success */
	if (syscall->retval == 0) {
		struct replayfs_fch_retparams *rets;

		struct file *filp;

		/* Get version from file */
		filp = fget(fd);

		if (filp->f_op->unlocked_ioctl == replayfs_ioctl) {

			debugk("%s %d: File is a replayfs file!\n", __func__,
					__LINE__);

			rets = RETPARAMSKMALLOC(syscall->log,
					sizeof(struct replayfs_fch_retparams), GFP_NOFS);

			BUG_ON(rets == NULL);

			/* XXX FIXME RACE!!!! */
			/*
			 * Should fix by locking lock before the read (retparam init) and
			 * unlocking after this
			 */
			rets->version = replayfs_inode_version(filp->f_dentry->d_inode);

			/*
			if (raw) {
				RETPARAMSKFREE(syscall->log, raw, syscall->retval);
			}
			*/

			/* Free the read's retparams */
			syscall->retparams = rets;
		} else {
			debugk("%s %d: File is NOT a replayfs file!\n", __func__,
					__LINE__);
			syscall->retparams = raw;
		}
		fput(filp);
	}
}

void *replayfs_fchown32_get_retparams(struct syscall_result *syscall, int fd, uid_t user, gid_t group) {
	struct replayfs_fch_retparams *rets;

	struct replayfs_proc_local *pls;
	struct file *filp;

	rets = syscall->retparams;


	/*
	 * Okay, look up this process's file based on the fd...
	 */
	pls = replayfs_get_pls();

	if (
				pls->open_table[fd].version == REPLAYFS_CURRENT_VERSION
			) {
		return syscall->retparams;
	}

	/*
	 * The version we open doesn't matter, this is handled internally.  So we're
	 * arbitrarily opening version 0, that way we don't have any dependencies
	 */
	filp = replayfs_open_filp_by_id(vfs_loc,
			&pls->open_table[fd].unique_id,
			rets->version);

	if (filp) {
		struct raw_inode raw;
		replayfs_log_t log;
		replayfs_log_inode_t log_inode;

		struct inode *inode;

		loff_t pos = 0;


		inode = filp->f_dentry->d_inode;

		raw.ctime = inode->i_ctime;
		raw.uid = user;
		raw.gid = group;
		raw.mode = inode->i_mode;

		/* Now simulate the ch action on the file */
		/* Get the log and log_inode for this file */
		if (!replayfs_begin_log_operation(&log)) {

			/* Now add the directory operation */
			replayfs_log_add_inode(&log, &log_inode, filp->f_dentry->d_inode);

			/* Modify the metadata */
			replayfs_log_add_mod(&log, &log_inode, &raw, sizeof(raw),
					pos);

			/* NOTE: size doesn't matter for record */
			replayfs_log_inode_done(&log, &log_inode, 0);

			replayfs_end_log_operation(&log);
		}

		filp_close(filp, NULL);
	} else {
		BUG();
	}

	return NULL;
}

void replayfs_utimes_init_retparams(struct syscall_result *syscall, const char __user *filename, const struct timeval *times) {
	struct replayfs_self_retparams *rets;

	rets = RETPARAMSKMALLOC(syscall->log, sizeof(struct replayfs_self_retparams), GFP_NOFS);

	get_self_info(filename, &rets->id, &rets->version);

	syscall->retparams = rets;
}

void *replayfs_utimes_get_retparams(struct syscall_result *syscall, const char __user *filename, const struct timeval *times) {
	struct replayfs_self_retparams *rets;

	rets = syscall->retparams;

	/* See if the directory was successfully opened before */
	if (rets->version != REPLAYFS_CURRENT_VERSION) {
		struct file *filp;

		/* Open the directory at the previous version */
		filp = replayfs_open_filp_by_id(vfs_loc,
				&rets->id,
				rets->version);

		if (filp) {
			struct raw_inode raw;
			replayfs_log_t log;
			replayfs_log_inode_t log_inode;

			struct inode *inode;

			loff_t pos = 0;

			inode = filp->f_dentry->d_inode;

			raw.ctime = inode->i_ctime;
			raw.uid = inode->i_uid;
			raw.gid = inode->i_gid;
			raw.mode = inode->i_mode;

			/* Now simulate the ch action on the file */
			/* Get the log and log_inode for this file */
			if (!replayfs_begin_log_operation(&log)) {

				/* Now add the directory operation */
				replayfs_log_add_inode(&log, &log_inode, filp->f_dentry->d_inode);

				/* Modify the metadata */
				replayfs_log_add_mod(&log, &log_inode, &raw, sizeof(raw),
						pos);

				/* NOTE: size doesn't matter for record */
				replayfs_log_inode_done(&log, &log_inode, 0);

				replayfs_end_log_operation(&log);
			}

			filp_close(filp, NULL);
		} else {
			BUG();
		}
	}

	return NULL;
}

void replayfs_utime_init_retparams(struct syscall_result *syscall, const char __user *filename, const struct timeval *times) {
	struct replayfs_self_retparams *rets;

	rets = RETPARAMSKMALLOC(syscall->log, sizeof(struct replayfs_self_retparams), GFP_NOFS);

	get_self_info(filename, &rets->id, &rets->version);

	syscall->retparams = rets;
}

void *replayfs_utime_get_retparams(struct syscall_result *syscall, const char __user *filename, const struct timeval *times) {
	struct replayfs_self_retparams *rets;

	rets = syscall->retparams;

	/* See if the directory was successfully opened before */
	if (rets->version != REPLAYFS_CURRENT_VERSION) {
		struct file *filp;

		/* Open the directory at the previous version */
		filp = replayfs_open_filp_by_id(vfs_loc,
				&rets->id,
				rets->version);

		if (filp) {
			struct raw_inode raw;
			replayfs_log_t log;
			replayfs_log_inode_t log_inode;

			struct inode *inode;

			loff_t pos = 0;

			inode = filp->f_dentry->d_inode;

			raw.ctime = inode->i_ctime;
			raw.uid = inode->i_uid;
			raw.gid = inode->i_gid;
			raw.mode = inode->i_mode;

			/* Now simulate the ch action on the file */
			/* Get the log and log_inode for this file */
			if (!replayfs_begin_log_operation(&log)) {

				/* Now add the directory operation */
				replayfs_log_add_inode(&log, &log_inode, filp->f_dentry->d_inode);

				/* Modify the metadata */
				replayfs_log_add_mod(&log, &log_inode, &raw, sizeof(raw),
						pos);

				/* NOTE: size doesn't matter for record */
				replayfs_log_inode_done(&log, &log_inode, 0);

				replayfs_end_log_operation(&log);
			}

			filp_close(filp, NULL);
		} else {
			BUG();
		}
	}

	return NULL;
}

void replayfs_shim_init(void) {
	syscall_log_set_retparams(__NR_write,
				NULL,
				replayfs_write_set_retparams,
				replayfs_write_get_retparams
			);

	syscall_log_set_retparams(__NR_read,
				NULL,
				replayfs_read_set_retparams,
				replayfs_read_get_retparams
			);

	syscall_log_set_retparams(__NR_open,
				replayfs_open_init_retparams,
				replayfs_generic_set_retparams,
				replayfs_open_get_retparams
			);

	syscall_log_set_retparams(__NR_mkdir,
				replayfs_mkdir_init_retparams,
				replayfs_generic_set_retparams,
				replayfs_mkdir_get_retparams
			);

	syscall_log_set_retparams(__NR_rmdir,
				replayfs_rmdir_init_retparams,
				replayfs_generic_set_retparams,
				replayfs_rmdir_get_retparams
			);

	syscall_log_set_retparams(__NR_unlink,
				replayfs_unlink_init_retparams,
				replayfs_generic_set_retparams,
				replayfs_unlink_get_retparams
			);
	syscall_log_set_retparams(__NR_chmod,
				replayfs_chmod_init_retparams,
				replayfs_generic_set_retparams,
				replayfs_chmod_get_retparams
			);
	syscall_log_set_retparams(__NR_fchmod,
				replayfs_fchmod_init_retparams,
				replayfs_generic_set_retparams,
				replayfs_fchmod_get_retparams
			);
	syscall_log_set_retparams(__NR_chown32,
				replayfs_chown_init_retparams,
				replayfs_generic_set_retparams,
				replayfs_chown_get_retparams
			);
	syscall_log_set_retparams(__NR_fchown32,
				replayfs_fchown32_init_retparams,
				replayfs_generic_set_retparams,
				replayfs_fchown32_get_retparams
			);
	syscall_log_set_retparams(__NR_utimes,
			  replayfs_utimes_init_retparams,
				replayfs_generic_set_retparams,
				replayfs_utimes_get_retparams
			);
	syscall_log_set_retparams(__NR_utime,
			  replayfs_utime_init_retparams,
				replayfs_generic_set_retparams,
				replayfs_utime_get_retparams
			);
}

void replayfs_shim_destroy(void) {
	syscall_log_clear_retparams(__NR_write);
	syscall_log_clear_retparams(__NR_read);
	syscall_log_clear_retparams(__NR_open);
	syscall_log_clear_retparams(__NR_mkdir);
	syscall_log_clear_retparams(__NR_rmdir);
	syscall_log_clear_retparams(__NR_unlink);
	syscall_log_clear_retparams(__NR_chmod);
	syscall_log_clear_retparams(__NR_chown32);
	syscall_log_clear_retparams(__NR_fchown32);
	syscall_log_clear_retparams(__NR_utimes);
	syscall_log_clear_retparams(__NR_utime);
}

