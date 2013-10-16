// replay_logdb.c: manages the organization of replay logs on disk
#include <linux/mutex.h>
#include <linux/syscalls.h>
#include <linux/replay.h>
#include <asm/uaccess.h>

#define LOGDB_DIR "/replay_logdb/"
#define LOGDB_INDEX LOGDB_DIR "ndx"
#define LOGID_INCREMENT 4096

// Global variables
DEFINE_MUTEX(replay_id_mutex);
__u64 last_logid = 0;
__u64 max_logid = 0;

#define RID_LOCK mutex_lock(&replay_id_mutex); 
#define RID_UNLOCK mutex_unlock(&replay_id_mutex);

// Returns the next logid - may need to get a range allocated first
__u64 
get_replay_id (void)
{
	mm_segment_t old_fs = get_fs();
	__u64 ret_id;
	int fd, rc;

	RID_LOCK;
	set_fs(KERNEL_DS);

	if (max_logid == 0) {
		// First, get maximum log id that was saved persitently to disk
		fd = sys_open (LOGDB_INDEX, O_RDWR, 0);
		if (fd >= 0) {

			rc = sys_read (fd, (char *) &max_logid, sizeof(max_logid));
			if (rc != sizeof(max_logid)) {
				printk ("get_replay_id: cannot get max allocated id, rc=%d\n", rc);
				sys_close (fd);
				set_fs(old_fs);
				RID_UNLOCK;
				return 0;
			}

			rc = sys_lseek (fd, 0, SEEK_SET);
			if (rc < 0) {
				printk ("get_replay_id: cannot seek back to beginning of file, rc=%d\n", rc);
				sys_close (fd);
				set_fs(old_fs);
				RID_UNLOCK;
				return 0;
			}
				
		} else if (fd == -ENOENT) {

			fd = sys_open (LOGDB_INDEX, O_RDWR | O_CREAT | O_EXCL, 0666);
			if (fd <= 0) {
				printk ("get_replay_id: cannot create new index file, rc=%d\n", fd);
				sys_close (fd);
				set_fs(old_fs);
				RID_UNLOCK;
				return 0;
			}

		} else {
			printk ("get_replay_id: cannot open %s,rc=%d\n", LOGDB_INDEX, fd);
			set_fs(old_fs);
			RID_UNLOCK;
			return 0;
		}

		// Need to allocate some more ids
		max_logid += LOGID_INCREMENT;

		rc = sys_write (fd, (char *) &max_logid, sizeof(max_logid));
		if (rc != sizeof(max_logid)) {
			printk ("get_replay_id: cannot write max allocated id, rc=%d\n", rc);
			sys_close (fd);
			set_fs(old_fs);
			RID_UNLOCK;
			return 0;
		}
		if (sys_fsync (fd) < 0) printk ("get_replay_id: cannot sync index file\n");
		if (sys_close (fd) < 0) printk ("get_replay_id: cannot close index file\n");
	}
		
	ret_id = ++last_logid;
	set_fs(old_fs);
	RID_UNLOCK;

	return ret_id;
}

int
get_logdir_for_replay_id (__u64 id, char* buf)
{
	mm_segment_t old_fs = get_fs();
	int rc;

	if (id == 0) return -1;

	sprintf (buf, "%srec_%lld", LOGDB_DIR, id);
	set_fs(KERNEL_DS);
	rc = sys_mkdir (buf, 0777);
	if (rc < 0) printk ("get_logdir_for_replayid: cannot create directory %s, rc=%d\n", buf, rc);
	set_fs(old_fs);

	return rc;
}

