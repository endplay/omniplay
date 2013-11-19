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
	struct get_used_addr_data udata;
	int syscall;
	u_long app_syscall_addr;
	char logdir[MAX_LOGDIR_STRLEN+1];
	char* tmp = NULL;
	long rc;

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
			return fork_replay (logdir, rdata.args, rdata.env, tmp, rdata.save_mmap, rdata.fd);
		} else {
			return fork_replay (NULL, rdata.args, rdata.env, tmp, rdata.save_mmap, rdata.fd);
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
			printk ("ioctl SPECI_FOR_REPLAY fails, strcpy returns %d\n", retval);
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
		rc = replay_ckpt_wakeup (wdata.pin, logdir, tmp, wdata.fd, wdata.follow_splits);
		if (tmp) putname (tmp);
		return rc;

	case SPECI_SET_PIN_ADDR:
		if (len != sizeof(u_long)) {
			printk ("ioctl SPECI_SET_PIN_ADDR fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&app_syscall_addr, (void *) data, sizeof(app_syscall_addr)))
			return -EFAULT;
		return set_pin_address (app_syscall_addr);
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
	case SPECI_GET_USED_ADDR:
		if (len != sizeof(udata)) {
			printk ("ioctl SPECI_GET_USED_ADDR fails, len %d\n", len);
			return -EINVAL;
		}
		if (copy_from_user (&udata, (void *) data, sizeof(udata)))
			return -EFAULT;
		
		return get_used_addresses (udata.plist, udata.nlist);
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
	printk (KERN_INFO "User-Level speculation module 1.0 exiting.\n");
}

#endif
