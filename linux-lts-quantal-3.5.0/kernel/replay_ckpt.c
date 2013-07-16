/* Kernel support for multithreaded replay - checkpoint and resume
   Jason Flinn */
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

// No clean way to handle this that I know of...
extern int replay_debug, replay_min_debug;
#define DPRINT if(replay_debug) printk
//#define DPRINT(x,...)
#define MPRINT if(replay_debug || replay_min_debug) printk
//#define MPRINT(x,...)

#define KMALLOC kmalloc
#define KFREE kfree

// File format:
// pid
// arguments (#, followed by len/data for each
// env. values (#, followed by len/data for each

// This function writes the process state to a disk file
long replay_checkpoint_to_disk (char* filename, const char __user *const __user *args, const char __user *const __user *env) 
{
	mm_segment_t old_fs = get_fs();
	int fd, rc, copyed, i, args_cnt, env_cnt, len;
	struct file* file = NULL;
	pid_t pid;
	loff_t pos = 0;
	const char __user *const __user *p;
	const char __user * pc;

	MPRINT ("pid %d enters replay_checkpoint_to_disk: filename %s\n", current->pid, filename);

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd < 0) {
		printk ("replay_checkpoint_to_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);

	// First - write out process identifier
	pid = current->pid;
	copyed = vfs_write (file, (char *) &pid, sizeof(pid), &pos);
	if (copyed != sizeof(pid)) {
		printk ("replay_checkpoint_to_disk: tried to write pid, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	// Next, write out arguments to exec
	args_cnt = 0;
	p = args;
	do {
		if (get_user (pc, p)) {
			printk ("replay_checkpoint_to_disk: invalid args value\n");
		        rc = -EFAULT;
			goto exit;
		}
		if (pc == 0) break; // No more args
		args_cnt++;
		p++;
	} while (1);
	MPRINT ("args count is %d\n", args_cnt);
	copyed = vfs_write (file, (char *) &args_cnt, sizeof(args_cnt), &pos);
	if (copyed != sizeof(args_cnt)) {
		printk ("replay_checkpoint_to_disk: tried to write argument count, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}
	p = args;
	for (i = 0; i < args_cnt; i++) {
		if (get_user (pc, p)) {
			printk ("replay_checkpoint_to_disk: invalid args value\n");
		        rc = -EFAULT;
			goto exit;
		}
		len = strnlen_user(pc, 4096);		
		copyed = vfs_write (file, (char *) &len, sizeof(len), &pos);
		if (copyed != sizeof(len)) {
			printk ("replay_checkpoint_to_disk: tried to write argument length, got rc %d\n", copyed);
			rc = copyed;
			goto exit;
		}
		copyed = vfs_write (file, pc, len, &pos);
		if (copyed != len) {
			printk ("replay_checkpoint_to_disk: tried to write argument, got rc %d\n", copyed);
			rc = copyed;
			goto exit;
		}
		p++;
	}
	
	// Next, write out env passed to exec
	env_cnt = 0;
	p = env;
	do {
		if (get_user (pc, p)) {
			printk ("replay_checkpoint_to_disk: invalid env value\n");
		        rc = -EFAULT;
			goto exit;
		}
		if (pc == 0) break; // No more env
		env_cnt++;
		p++;
	} while (1);
	MPRINT ("env count is %d\n", env_cnt);
	copyed = vfs_write (file, (char *) &env_cnt, sizeof(env_cnt), &pos);
	if (copyed != sizeof(env_cnt)) {
		printk ("replay_checkpoint_to_disk: tried to write environment count, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}
	p = env;
	for (i = 0; i < env_cnt; i++) {
		if (get_user (pc, p)) {
			printk ("replay_checkpoint_to_disk: invalid env value\n");
		        rc = -EFAULT;
			goto exit;
		}
		len = strnlen_user(pc, 4096);		
		copyed = vfs_write (file, (char *) &len, sizeof(len), &pos);
		if (copyed != sizeof(len)) {
			printk ("replay_checkpoint_to_disk: tried to write environment length, got rc %d\n", copyed);
			rc = copyed;
			goto exit;
		}
		copyed = vfs_write (file, pc, len, &pos);
		if (copyed != len) {
			printk ("replay_checkpoint_to_disk: tried to write environment, got rc %d\n", copyed);
			rc = copyed;
			goto exit;
		}
		p++;
	}

exit:
	if (file) fput(file);
	if (fd >= 0)  {
		rc = sys_close (fd);
		if (rc < 0) printk ("replay_checkpoint_to_disk: close returns %d\n", rc);
	}
	set_fs(old_fs);
	return rc;
}

long replay_resume_from_disk (char* filename, char*** argsp, char*** envp) 
{
	mm_segment_t old_fs = get_fs();
	int rc, fd, args_cnt, env_cnt, copyed, i, len;
	struct file* file = NULL;
	loff_t pos = 0;
	pid_t record_pid;
	char** args;
	char** env;

	MPRINT ("pid %d enters replay_resume_from_disk: filename %s\n", current->pid, filename);

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_RDONLY, 0);
	if (fd < 0) {
		printk ("replay_checkpoint_from_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);

	// Read the record pid
	copyed = vfs_read(file, (char *) &record_pid, sizeof(record_pid), &pos);
	if (copyed != sizeof(record_pid)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	// Next, read the number of arguments
	copyed = vfs_read(file, (char *) &args_cnt, sizeof(args_cnt), &pos);
	if (copyed != sizeof(args_cnt)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}
	MPRINT ("%d arguments in checkpoint\n", args_cnt);
	
	args = kmalloc((args_cnt+1) * sizeof(char *), GFP_KERNEL);
	if (args == NULL) {
		printk ("replay_resume_froma_disk: unable to allocate arguments\n");
		rc = -ENOMEM;
		goto exit;
	}

	// Now read in each argument
	for (i = 0; i < args_cnt; i++) {
		copyed = vfs_read(file, (char *) &len, sizeof(len), &pos);
		if (copyed != sizeof(len)) {
			printk ("replay_resume_from_disk: tried to read argument %d len, got rc %d\n", i, copyed);
			rc = copyed;
			goto exit;
		}
		args[i] = kmalloc(len+1, GFP_KERNEL);
		if (args[i] == NULL) {
			printk ("replay_resume_froma_disk: unable to allocate argument %d\n", i);
			rc = -ENOMEM;
			goto exit;
		}
		copyed = vfs_read(file, args[i], len, &pos);
		MPRINT ("copyed %d bytes\n", copyed);
		if (copyed != len) {
			printk ("replay_resume_from_disk: tried to read argument %d, got rc %d\n", i, copyed);
			rc = copyed;
			goto exit;
		}
		args[i][len] = '\0'; // NULL terminator not in file format
		MPRINT ("Argument %d is %s\n", i, args[i]);
	}
	args[i] = NULL;

	// Next, read the number of env. objects
	copyed = vfs_read(file, (char *) &env_cnt, sizeof(env_cnt), &pos);
	if (copyed != sizeof(env_cnt)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}
	MPRINT ("%d env. objects in checkpoint\n", env_cnt);
	
	env = kmalloc((env_cnt+1) * sizeof(char *), GFP_KERNEL);
	if (env == NULL) {
		printk ("replay_resume_froma_disk: unable to allocate env struct\n");
		rc = -ENOMEM;
		goto exit;
	}

	// Now read in each env. object
	for (i = 0; i < env_cnt; i++) {
		copyed = vfs_read(file, (char *) &len, sizeof(len), &pos);
		if (copyed != sizeof(len)) {
			printk ("replay_resume_from_disk: tried to read env. %d len, got rc %d\n", i, copyed);
			rc = copyed;
			goto exit;
		}
		env[i] = kmalloc(len+1, GFP_KERNEL);
		if (env[i] == NULL) {
			printk ("replay_resume_froma_disk: unable to allocate env. %d\n", i);
			rc = -ENOMEM;
			goto exit;
		}
		copyed = vfs_read(file, env[i], len, &pos);
		if (copyed != len) {
			printk ("replay_resume_from_disk: tried to read env. %d, got rc %d\n", i, copyed);
			rc = copyed;
			goto exit;
		}
		env[i][len] = '\0'; // NULL terminator not in file format
		MPRINT ("Env. %d is %s\n", i, env[i]);
	}
	env[i] = NULL;

	*argsp = args;
	*envp = env;

	MPRINT ("replay_resume_from_disk done\n");

exit:
	if (fd >= 0) {
		rc = sys_close (fd);
		if (rc < 0) printk ("replay_resume_from_disk: close returns %d\n", rc);
	}
	if (file) fput(file);
	set_fs(old_fs);
	if (rc < 0) return rc;
	return record_pid;
}

