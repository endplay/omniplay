#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/replay.h>
#include <linux/mount.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include <asm/fcntl.h>
#include <asm/ldt.h>
#include <asm/desc.h>
#include <linux/proc_fs.h>
#include <linux/replay.h>
#include <linux/file_list.h>

int init_file_list (struct file_list_struct* file_list, char* file_list_path) {
	mm_segment_t old_fs = get_fs ();
	int fd, rc = -1, copyed;
	int count;
	struct file* file = NULL;
	loff_t pos = 0;
	//change it later

	mutex_init (&file_list->file_list_mutex);
	
	file_list_path = "/replay_logdb/file_list";

	printk ("Pid %d begins init_file_list, filename %s\n", current->pid, file_list_path);
	set_fs (KERNEL_DS);

	fd = sys_open (file_list_path, O_RDONLY, 0);
	if (fd < 0) {
		printk ("init_file_list , cannot open file %s, return %d\n", file_list_path, fd);
		goto exit;
	}
	file = fget (fd);

	//read the count for ignored files
	copyed = vfs_read (file, (char*) &count, sizeof(int), &pos);
	if (copyed != sizeof (int)) {
		printk ("init_file_list: ftried to read count for ignored_file_list, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	if (count > 0) {
		file_list->ignored_count = count;
		file_list->ignored_list = (struct file_list_name_struct*) kmalloc (count * sizeof(struct file_list_name_struct), GFP_KERNEL);
		if (file_list->ignored_list == NULL) {
			printk ("init_file_list: unable to allocate ignored_list with size %d\n", count*sizeof(struct file_list_name_struct));
			rc = -ENOMEM;
			goto exit;
		}
		copyed = vfs_read (file, (char*)file_list->ignored_list, count*sizeof(struct file_list_name_struct), &pos);
		if (copyed != count*sizeof(struct file_list_name_struct)) {
			printk ("init_file_list: ftried to read ignored_list for ignored_file_list, got rc %d, expected:%d\n", copyed, count*sizeof(struct file_list_name_struct));
			rc = copyed;
			goto exit;
		}
	} else {
		file_list->ignored_count = 0;
		file_list->ignored_list = NULL;
	}

	//read the count for modify files
	copyed = vfs_read (file, (char*) &count, sizeof(int), &pos);
	if (copyed != sizeof (int)) {
		printk ("init_file_list: ftried to read count for modify_file_list, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	if (count > 0) {
		file_list->modify_count = count;
		file_list->modify_list = (struct file_list_name_struct*) kmalloc (count * sizeof(struct file_list_name_struct), GFP_KERNEL);
		if (file_list->modify_list == NULL) {
			printk ("init_file_list: unable to allocate modify_list with size %d\n", count*sizeof(struct file_list_name_struct));
			rc = -ENOMEM;
			goto exit;
		}
		copyed = vfs_read (file, (char*)file_list->modify_list, count*sizeof(struct file_list_name_struct), &pos);
		if (copyed != count*sizeof(struct file_list_name_struct)) {
			printk ("init_file_list: ftried to read modify_list for modify_file_list, got rc %d, expected:%d\n", copyed, count*sizeof(struct file_list_name_struct));
			rc = copyed;
			goto exit;
		}
	} else {
		file_list->modify_count = 0;
		file_list->modify_list = NULL;
	}



	printk ("Pid %d init_file_list done.\n", current->pid);

exit:
	if (fd >= 0) {
		rc = sys_close (fd);
		if (rc < 0) printk ("init_file_list: close returns %d\n", rc);
	}
	if (file) fput(file);
	set_fs(old_fs);
	if (rc < 0) return rc;
	return 0;
}

void free_file_list (struct file_list_struct *file_list) {
	if (file_list->ignored_count) kfree (file_list->ignored_list);
	if (file_list->modify_count) kfree (file_list->modify_list);
}

inline int is_ignored_file (struct file_list_struct *file_list, const char* filename) {
	int i = 0;
	for (; i<file_list->ignored_count; ++i) {
		if (!strncmp (filename, file_list->ignored_list[i].filename, file_list->ignored_list[i].length)) {
			//printk ("Pid %d open a file from ignored_list %s, can be ignored\n", current->pid, filename);
			return 1;
		}
	}
	printk ("Pid %d open a file that cannot be ignored %s\n", current->pid, filename);
	return 0;
}


inline int is_modify_file (struct file_list_struct *file_list, const char* filename) {
	int i = 0;
	for (; i<file_list->modify_count; ++i) {
		if (!strncmp (filename, file_list->modify_list[i].filename, file_list->modify_list[i].length)) {
			printk ("Pid %d open a file from modify_list %s\n", current->pid, filename);
			return 1;
		}
	}
	return 0;
}
