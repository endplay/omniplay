#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/timer.h>
#include <linux/ioctl.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <linux/replay.h>

#include <linux/ds_list.h>
#include "devspec.h"

MODULE_AUTHOR("Jason Flinn");
MODULE_LICENSE("GPL");

/* Debugging stuff */
//#define DPRINT printk
#define DPRINT(x,...)

/* Called by apps to open the device. */ 
static int 
spec_psdev_open(struct inode* inode, struct file* filp)
{
	DPRINT ("process %d has opened device\n", current->pid);
	return 0;
}

/* Called by apps to release the device */
static int
spec_psdev_release(struct inode * inode, struct file * file)
{
	DPRINT ("process %d has closed device\n", current->pid);
	return 0;
}

static long
spec_psdev_ioctl (struct file* file, u_int cmd, u_long data)
{
  	int len = _IOC_SIZE(cmd), retval;
	struct ckpt_proc *pckpt_proc, *new_ckpt_proc;
	struct record_data rdata;
	struct wakeup_data wdata;
	struct wakeup_ckpt_data wcdata;
	struct get_used_addr_data udata;
	struct filemap_num_data fndata;
	struct filemap_entry_data fedata;
	struct get_record_pid_data recordpid_data;
	struct set_pin_address_data pin_data;
	struct get_replay_pid_data replay_pid_data;
	int syscall;
	char logdir[MAX_LOGDIR_STRLEN+1];
	char filename[MAX_LOGDIR_STRLEN+1];
	char* tmp = NULL;
	long rc;
	int device;
	pid_t pid;

	pckpt_proc = new_ckpt_proc = NULL;
	DPRINT ("pid %d cmd number 0x%08x\n", current->pid, cmd);

	switch (cmd) {
	case SPECI_REPLAY_FORK:
		if (len != sizeof(rdata)) {
			printk ("ioctl SPECI_FORK_REPLAY fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&rdata, (void *) data, sizeof(rdata))) {
			printk ("ioctl SPECI_FORK_REPLAY fails, inavlid data\n");
			return -EFAULT;
		}
		if (rdata.linkpath) {
			tmp = getname(rdata.linkpath);
			if (tmp == NULL) {
				printk ("SPECI_REPLAY_FORK: cannot get linker name\n");
				return -EFAULT;
			} 
		} else {
			tmp = NULL;
		}
		if (rdata.logdir) {
			retval = strncpy_from_user(logdir, rdata.logdir, MAX_LOGDIR_STRLEN);
			if (retval < 0 || retval >= MAX_LOGDIR_STRLEN) {
				printk ("ioctl SPECI_FOR_REPLAY fails, strcpy returns %d\n", retval);
				return -EINVAL;
			}
			return fork_replay (logdir, rdata.args, rdata.env, tmp, rdata.save_mmap,
					rdata.fd, rdata.pipe_fd);
		} else {
			return fork_replay (NULL, rdata.args, rdata.env, tmp, rdata.save_mmap,
					rdata.fd, rdata.pipe_fd);
		}
	case SPECI_RESUME:
		if (len != sizeof(wdata)) {
			printk ("ioctl SPECI_RESUME fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&wdata, (void *) data, sizeof(wdata)))
			return -EFAULT;
		retval = strncpy_from_user(logdir, wdata.logdir, MAX_LOGDIR_STRLEN);
		if (retval < 0 || retval >= MAX_LOGDIR_STRLEN) {
			printk ("ioctl SPECI_RESUME fails, strcpy returns %d\n", retval);
			return -EINVAL;
		}
		
		if (wdata.linker) {
			tmp = getname(wdata.linker);
			if (tmp == NULL) {
				printk ("SPECI_RESUME: cannot get linker name\n");
				return -EFAULT;
			} 
		} else {
			tmp = NULL;
		}

		if (wdata.pin) {
			device = ATTACH_PIN;
		} else if (wdata.gdb) {
			device = ATTACH_GDB;
		} else {
			device = 0; //NONE
		}

		rc = replay_ckpt_wakeup(device, logdir, tmp, wdata.fd,
					wdata.follow_splits, wdata.save_mmap, wdata.attach_index,
					wdata.attach_pid, wdata.ckpt_at, wdata.record_timing);

		if (tmp) putname (tmp);
		return rc;

	case SPECI_CKPT_RESUME:
		if (len != sizeof(wcdata)) {
			printk ("ioctl SPECI_CKPT_RESUME fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&wcdata, (void *) data, sizeof(wcdata)))
			return -EFAULT;
		retval = strncpy_from_user(logdir, wcdata.logdir, MAX_LOGDIR_STRLEN);
		if (retval < 0 || retval >= MAX_LOGDIR_STRLEN) {
			printk ("ioctl SPECI_CKPT_RESUME fails, strcpy returns %d\n", retval);
			return -EINVAL;
		}

		retval = strncpy_from_user(filename, wcdata.filename, MAX_LOGDIR_STRLEN);
		if (retval < 0 || retval >= MAX_LOGDIR_STRLEN) {
			printk ("ioctl SPECI_FOR_REPLAY fails, strcpy returns %d\n", retval);
			return -EINVAL;
		}
		if (wcdata.linker) {
			tmp = getname(wcdata.linker);
			if (tmp == NULL) {
				printk ("SPECI_CKPT_RESUME: cannot get linker name\n");
				return -EFAULT;
			} 
		} else {
			tmp = NULL;
		}

		if (wcdata.pin) {
			device = ATTACH_PIN;
		} else if (wcdata.gdb) {
			device = ATTACH_GDB;
		} else {
			device = 0; //NONE
		}

		rc = replay_full_ckpt_wakeup(device, logdir, filename, tmp, wcdata.fd,
					     wcdata.follow_splits, wcdata.save_mmap, wcdata.attach_index,
					     wcdata.attach_pid);

		if (tmp) putname (tmp);
		return rc;

	case SPECI_CKPT_PROC_RESUME:
		if (len != sizeof(wcdata)) {
			printk ("ioctl SPECI_CKPT_RESUME fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&wcdata, (void *) data, sizeof(wcdata)))
			return -EFAULT;
		retval = strncpy_from_user(logdir, wcdata.logdir, MAX_LOGDIR_STRLEN);
		if (retval < 0 || retval >= MAX_LOGDIR_STRLEN) {
			printk ("ioctl SPECI_CKPT_RESUME fails, strcpy returns %d\n", retval);
			return -EINVAL;
		}
		retval = strncpy_from_user(filename, wcdata.filename, MAX_LOGDIR_STRLEN);
		if (retval < 0 || retval >= MAX_LOGDIR_STRLEN) {
			printk ("ioctl SPECI_FOR_REPLAY fails, strcpy returns %d\n", retval);
			return -EINVAL;
		}

		rc = replay_full_ckpt_proc_wakeup(logdir, filename, wcdata.fd);

		if (tmp) putname (tmp);
		return rc;

	case SPECI_SET_PIN_ADDR: 
		if (len != sizeof(struct set_pin_address_data)) {
			printk ("ioctl SPECI_SET_PIN_ADDR fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&pin_data, (void *) data, sizeof(pin_data)))
			return -EFAULT;
		rc = set_pin_address (pin_data.pin_address, pin_data.pthread_data, pin_data.pcurthread, 
				      &pin_data.attach_ndx);
		if (copy_to_user ((void *) data, &pin_data, sizeof(pin_data)))
			return -EFAULT;
		return rc;
	case SPECI_CHECK_BEFORE:
		if (len != sizeof(int)) {
			printk ("ioctl SPECI_CHECK_BEFORE fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&syscall, (void *) data, sizeof(syscall)))
			return -EFAULT;
		return check_clock_before_syscall (syscall);
	case SPECI_CHECK_AFTER:
		return check_clock_after_syscall (0);
	case SPECI_GET_LOG_ID:
		return get_log_id ();
	case SPECI_GET_CLOCK_VALUE:
		return get_clock_value ();
	case SPECI_GET_USED_ADDR:
		if (len != sizeof(udata)) {
			printk ("ioctl SPECI_GET_USED_ADDR fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&udata, (void *) data, sizeof(udata)))
			return -EFAULT;
		
		return get_used_addresses (udata.plist, udata.nlist);
	case SPECI_GET_REPLAY_STATS:
		return get_replay_stats ((struct replay_stats *) data);
	case SPECI_GET_REPLAY_ARGS:
		return get_replay_args();
	case SPECI_GET_ENV_VARS:
		return get_env_vars();
	case SPECI_GET_RECORD_GROUP_ID:
		return get_record_group_id((__u64 *) data);
	case SPECI_GET_NUM_FILEMAP_ENTRIES:
		if (len != sizeof(fndata)) {
			printk ("ioctl SPECI_GET_NUM_FILEMAP_ENTRIES fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&fndata, (void *) data, sizeof(fndata))) {
			return -EFAULT;
		}
		return get_num_filemap_entries(fndata.fd, fndata.offset, fndata.size);
	case SPECI_GET_FILEMAP:
		if (len != sizeof(fedata)) {
			printk ("ioctl SPECI_GET_FILEMAP fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&fedata, (void *) data, sizeof(fedata))) {
			return -EFAULT;
		}
		return get_filemap(fedata.fd, fedata.offset, fedata.size, fedata.entries, fedata.num_entries);
	case SPECI_RESET_REPLAY_NDX:
		return reset_replay_ndx();
	case SPECI_GET_CURRENT_RECORD_PID:
		if (len != sizeof(struct get_record_pid_data))
		{
			printk("ioctl SPECI_GET_CURRENT_RECORD_PID fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user(&recordpid_data, (void *)data, sizeof(recordpid_data)))
		{
			return -EFAULT;
		}
		return get_current_record_pid(recordpid_data.nonrecordPid);
	case SPECI_GET_ATTACH_STATUS:
		if (len != sizeof(pid_t))
		{
			printk("ioctl SPECI_GET_ATTACH_STATUS fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user(&pid, (void *)data, sizeof(pid_t)))
		{
			return -EFAULT;
		}
		return get_attach_status (pid);
		
	case SPECI_WAIT_FOR_REPLAY_GROUP:
		if (len != sizeof(pid_t))
		{
			printk("ioctl SPECI_WAIT_REPLAY_GROUP fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user(&pid, (void *)data, sizeof(pid_t)))
		{
			return -EFAULT;
		}
		return wait_for_replay_group(pid);


	case SPECI_TRY_TO_EXIT:
		if (len != sizeof(pid_t))
		{
			printk("ioctl SPECI_TRY_TO_EXIT fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user(&pid, (void *)data, sizeof(pid_t)))
		{
			return -EFAULT;
		}
		return try_to_exit (pid);

	case SPECI_GET_REPLAY_PID:
		if (len != sizeof(replay_pid_data)) {
			printk ("ioctl SPECI_GET_REPLAY_PID fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&replay_pid_data, (void *) data, sizeof(replay_pid_data))) {
			return -EFAULT;
		}

		return get_replay_pid (replay_pid_data.parent_pid, replay_pid_data.record_pid);

	case SPECI_MAP_CLOCK: {
		return pthread_shm_path ();
	}
	default:
		return -EINVAL;
	}
}


static struct file_operations spec_psdev_fops = {
	owner:		THIS_MODULE,
	unlocked_ioctl:	spec_psdev_ioctl,
	open:		spec_psdev_open,
	release:	spec_psdev_release,
};



#ifdef MODULE

int init_module(void)
{
	printk(KERN_INFO "User-level speculation module version 1.0\n");

	if(register_chrdev(SPEC_PSDEV_MAJOR, "spec_psdev", 
			   &spec_psdev_fops)) {
		printk(KERN_ERR "spec_psdev: unable to get major %d\n", 
		SPEC_PSDEV_MAJOR);
		return -EIO;
	}
	
	return 0;
}

void cleanup_module(void)
{
	unregister_chrdev(SPEC_PSDEV_MAJOR,"spec_psdev");
	printk(KERN_INFO "User-Level speculation module 1.0 exiting.\n");
}

#endif
