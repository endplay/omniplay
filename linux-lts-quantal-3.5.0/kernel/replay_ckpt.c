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

/* Prototypes not in header files */
void set_tls_desc(struct task_struct *p, int idx, const struct user_desc *info, int n); /* In tls.c */
void fill_user_desc(struct user_desc *info, int idx, const struct desc_struct *desc); /* In tls.c */

struct vma_stats {
	u_long vmas_start;
	u_long vmas_end;
	int    vmas_flags;
	u_long vmas_pgoff;
	char   vmas_file[PATH_MAX];
};

struct mm_info {
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long arg_start, arg_end, env_start, env_end;
	//exe file
#ifdef CONFIG_PROC_FS
	char exe_file[PATH_MAX];
#endif
};

#define KMALLOC kmalloc
#define KFREE kfree

char*
get_exe_path (struct mm_struct* mm, char* path)
{
	char* p;

	down_read(&mm->mmap_sem);
	p = d_path (&mm->exe_file->f_path, path, PATH_MAX);
	up_read(&mm->mmap_sem);
	return p;
}

// File format:
// Resisters (only one set = single-threaded process
// # of VM areas
// for each VM area:
//    VMA structure
//    VMA contents
// mm info
// thread-level storage
// replay_thrd->app_syscall_addr

// This function writes the process state to a disk file
//long replay_checkpoint_to_disk (char* filename) 
long replay_checkpoint_to_disk (char* filename, u_long app_syscall_addr) 
{
	int fd, rc, copyed, i;
	mm_segment_t old_fs = get_fs();
	struct file* file = NULL;
	loff_t pos = 0;
	struct vm_area_struct* vma;
	struct vma_stats* pvmas = NULL;
	char* buffer = NULL;
	struct mm_info* pmminfo = NULL;
	struct inode* inode;
	char* p;
	pid_t pid;
        u_long syscall_addr;       // Address in user-land that is set when the syscall should be replayed

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

	// Next - write out the registers, assuming a single-threaded app here
	copyed = vfs_write(file, (char *) get_pt_regs(NULL), sizeof(struct pt_regs), &pos);
	if (copyed != sizeof(struct pt_regs)) {
		printk ("replay_checkpoint_to_disk: tried to write regs, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	down_read (&current->mm->mmap_sem);

	// Next - number of VM area
	copyed = vfs_write(file, (char *) &current->mm->map_count, sizeof(int), &pos);
	if (copyed != sizeof(int)) {
		printk ("replay_checkpoint_to_disk: tried to write map_count, got rc %d\n", copyed);
		rc = copyed;
		goto unlock;
	}

	/* These are too big to put on the kernel stack */
	pvmas = KMALLOC (sizeof(struct vma_stats), GFP_KERNEL);
	buffer = KMALLOC (PATH_MAX, GFP_KERNEL);
	if (!pvmas || !buffer) {
		printk ("replay_checkpoint_to_disk: cannot allocate memory\n");
		rc = -ENOMEM;
		goto unlock;
	}

	// Next - info and data for each vma
	for (vma = current->mm->mmap; vma; vma = vma->vm_next) {
		pvmas->vmas_start = vma->vm_start;
		pvmas->vmas_end = vma->vm_end;
		pvmas->vmas_flags = vma->vm_flags;
		pvmas->vmas_pgoff = vma->vm_pgoff;
		if(vma->vm_file) {
			inode = vma->vm_file->f_path.dentry->d_inode;
			p = d_path (&vma->vm_file->f_path, buffer, PATH_MAX);
			strcpy (pvmas->vmas_file, p);
		} else {
			pvmas->vmas_file[0] = '\0';
		}
		copyed = vfs_write(file, (char *) pvmas, sizeof(struct vma_stats), &pos);
		if (copyed != sizeof(struct vma_stats)) {
			printk ("replay_checkpoint_to_disk: tried to write vma info, got rc %d\n", copyed);
			rc = copyed;
			goto freemem;
		}
		
		if(!strcmp(pvmas->vmas_file, "/dev/zero//deleted")) continue; /* Skip writing this one */

		set_fs(old_fs);
		copyed = vfs_write(file, (char *) pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, &pos);
		set_fs(KERNEL_DS);
		if (copyed != pvmas->vmas_end - pvmas->vmas_start) {
			printk ("replay_checkpoint_to_disk: tried to write vma data, got rc %d\n", copyed);
			rc = copyed;
			goto freemem;
		}
	}

	// Process-specific info in the mm struct
	pmminfo = KMALLOC (sizeof(struct mm_info), GFP_KERNEL);
	if (pmminfo == NULL) {
		printk ("replay_checkpoint_to_disk: unable to allocate mm_info structure\n");
		rc = -ENOMEM;
		goto freemem;
	}
	pmminfo->start_code = current->mm->start_code;
	pmminfo->end_code = current->mm->end_code;
	pmminfo->start_data = current->mm->start_data;
	pmminfo->end_data = current->mm->end_data;
	pmminfo->start_brk = current->mm->start_brk;
	pmminfo->brk = current->mm->brk;
	pmminfo->start_stack = current->mm->start_stack;
	pmminfo->arg_start = current->mm->arg_start;
	pmminfo->arg_end = current->mm->arg_end;
	pmminfo->env_start = current->mm->env_start;
	pmminfo->env_end = current->mm->env_end;

#ifdef CONFIG_PROC_FS
	p = get_exe_path (current->mm, buffer);
	strcpy (pmminfo->exe_file, p);
#endif

	copyed = vfs_write(file, (char *) pmminfo, sizeof(struct mm_info), &pos);
	if (copyed != sizeof(struct mm_info)) {
		printk ("replay_checkpoint_to_disk: tried to write mm info, got rc %d\n", copyed);
		rc = copyed;
		goto freemem;
	}
	
	// Write out TLS info
	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
		struct user_desc desc;
		fill_user_desc(&desc, GDT_ENTRY_TLS_MIN+i, &current->thread.tls_array[i]);
		copyed = vfs_write(file, (char *) &desc, sizeof(desc), &pos);
		if (copyed != sizeof(desc)) {
			printk ("replay_checkpoint_to_disk: tried to write TLS entry #%d, got rc %d\n", i, copyed);
			rc = copyed;
			goto freemem;
		}
		MPRINT ("Pid %d replay_checkpoint_to_disk filling user_desc base_addr %x limit %x\n", current->pid, desc.base_addr, desc.limit);
	}
	
	// Write out the app_syscall_addr for the replay thread
	syscall_addr = app_syscall_addr;
	copyed = vfs_write(file, (char *) &syscall_addr, sizeof(u_long), &pos);
	if (copyed != sizeof(u_long)) {
		printk ("replay_checkpoint_to_disk: tried to write app_syscall_addr %lu, got rc %d", syscall_addr, copyed);
		rc = copyed;
		goto freemem;
	}

freemem:
	KFREE(buffer);
	KFREE(pvmas);
	KFREE(pmminfo);
unlock:
	up_read (&current->mm->mmap_sem);
exit:
	if (file) fput(file);
	rc = sys_close (fd);
	if (rc < 0) printk ("replay_checkpoint_to_disk: close returns %d\n", rc);
	set_fs(old_fs);
	return rc;
}

//long replay_resume_from_disk (char* filename) 
long replay_resume_from_disk (char* filename, u_long* app_syscall_addr) 
{
	int fd, exe_fd, rc, copyed, i, map_count;
	mm_segment_t old_fs = get_fs();
	struct file* file = NULL, *map_file;
	loff_t pos = 0;
	struct vm_area_struct* vma, *vma_next;
	struct vma_stats* pvmas = NULL;
	struct mm_info* pmminfo = NULL;
	u_long addr;
	pid_t record_pid;
	u_long syscall_addr;

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

	// Restore the user-level registers
	copyed = vfs_read(file, (char *) get_pt_regs(NULL), sizeof(struct pt_regs), &pos);
	if (copyed != sizeof(struct pt_regs)) {
		printk ("replay_resume_from_disk: tried to read regs, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	// Delete all the vm areas of current process 
	down_write (&current->mm->mmap_sem);
	vma = current->mm->mmap;
	while(vma) {
		vma_next = vma->vm_next;
		do_munmap(current->mm, vma->vm_start, vma->vm_end - vma->vm_start);
		vma = vma_next;
	} 
	up_write (&current->mm->mmap_sem);

	// Next - read the number of VM area
	copyed = vfs_read(file, (char *) &map_count, sizeof(int), &pos);
	if (copyed != sizeof(int)) {
		printk ("replay_resume_from_disk: tried to read map_count, got rc %d\n", copyed);
		rc = copyed;
		goto exit;
	}

	/* This is too big to put on the kernel stack */
	pvmas = KMALLOC (sizeof(struct vma_stats), GFP_KERNEL);
	if (!pvmas) {
		printk ("replay_resume_from_disk: cannot allocate memory\n");
		rc = -ENOMEM;
		goto exit;
	}
	
	// Map each VMA and copy data from the file
	for (i = 0; i < map_count; i++) {
		copyed = vfs_read (file, (char *) pvmas, sizeof(struct vma_stats), &pos);
		if (copyed != sizeof(struct vma_stats)) {
			printk ("replay_resume_from_disk: tried to read vma info, got rc %d\n", copyed);
			rc = copyed;
			goto freemem;
		}	
	
		if (pvmas->vmas_file[0]) { // does file mapping exists here?
			if (!strcmp(pvmas->vmas_file, "/dev/zero//deleted")) {
				printk ("special vma for /dev/zero!\n");
				pvmas->vmas_file[9] = '\0';
			}
			map_file = filp_open (pvmas->vmas_file, O_RDONLY, 0);
			if (IS_ERR(map_file)) {
				printk ("replay_resume_from_disk: filp_open error\n");
				rc = PTR_ERR(map_file);
				goto freemem;
			}
		} else { 
			map_file = NULL;
		}
		DPRINT ("About to do mmap: map_file %p start %lx len %lx flags %x shar %x pgoff %lx\n", 
			map_file, pvmas->vmas_start, pvmas->vmas_end-pvmas->vmas_start, 
			(pvmas->vmas_flags&(VM_READ|VM_WRITE|VM_EXEC)), 
			((pvmas->vmas_flags&VM_MAYSHARE) ? MAP_SHARED : MAP_PRIVATE)|MAP_FIXED, pvmas->vmas_pgoff);
		addr = do_mmap_pgoff(map_file, pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, 
				     (pvmas->vmas_flags&(VM_READ|VM_WRITE|VM_EXEC)), 
				     ((pvmas->vmas_flags&VM_MAYSHARE) ? MAP_SHARED : MAP_PRIVATE)|MAP_FIXED, pvmas->vmas_pgoff);
		if (map_file) filp_close (map_file, NULL);
		if (IS_ERR((char *) addr)) {
			printk ("replay_resume_from_disk: mmap error %ld\n", PTR_ERR((char *) addr));
			rc = addr;
			goto freemem;
		}

		if(!strcmp(pvmas->vmas_file, "/dev/zero//deleted")) continue; /* Skip writing this one */

		if (!(pvmas->vmas_flags&VM_WRITE)) rc = sys_mprotect (pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, PROT_WRITE); // force it to writable temproarilly

		set_fs(old_fs);
		DPRINT ("Reading from file position %lu\n", (u_long) pos);
		copyed = vfs_read (file, (char *) pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, &pos);
		set_fs(KERNEL_DS);
		if (copyed != pvmas->vmas_end - pvmas->vmas_start) {
			printk ("replay_resume_from_disk: tried to read vma data, got rc %d\n", copyed);
			rc = copyed;
			goto freemem;
		}

		if (!(pvmas->vmas_flags&VM_WRITE)) rc = sys_mprotect (pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, pvmas->vmas_flags&(VM_READ|VM_WRITE|VM_EXEC)); // restore old protections
		
	}

	{
	  u_long foo;
	  get_user(foo, (char *) 0xbfab44c8);
	  DPRINT ("Value at address 0xbfab44c8 is %lx\n", foo);
	}


	// Process-specific info in the mm struct
	pmminfo = KMALLOC (sizeof(struct mm_info), GFP_KERNEL);
	if (pmminfo == NULL) {
		printk ("replay_resume_from_disk: unable to allocate mm_info structure\n");
		rc = -ENOMEM;
		goto freemem;
	}
	copyed = vfs_read (file, (char *) pmminfo, sizeof(struct mm_info), &pos);
	if (copyed != sizeof(struct mm_info)) {
		printk ("replay_resume_from_disk: tried to read mm info, got rc %d\n", copyed);
		rc = copyed;
		goto freemem;
	}
	current->mm->start_code =  pmminfo->start_code;
	current->mm->end_code =	pmminfo->end_code;
	current->mm->start_data = pmminfo->start_data;
	current->mm->end_data =	pmminfo->end_data;
	current->mm->start_brk = pmminfo->start_brk;
	current->mm->brk = pmminfo->brk;
	current->mm->start_stack = pmminfo->start_stack;
	current->mm->arg_start = pmminfo->arg_start;
	current->mm->arg_end =	pmminfo->arg_end;
	current->mm->env_start = pmminfo->env_start;
	current->mm->env_end =	pmminfo->env_end;
	
#ifdef CONFIG_PROC_FS
	exe_fd = sys_open (pmminfo->exe_file, O_RDONLY, 0);
	set_mm_exe_file (current->mm, fget(exe_fd));
	sys_close (exe_fd);
#endif

	// Read in TLS info
	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
		struct user_desc desc;
		copyed = vfs_read (file, (char *) &desc, sizeof(desc), &pos);
		if (copyed != sizeof(desc)) {
			printk ("replay_resume_from_disk: tried to read TLS entry #%d, got rc %d\n", i, copyed);
			rc = copyed;
			goto freemem;
		}
		set_tls_desc(current, GDT_ENTRY_TLS_MIN+i, &desc, 1);
		MPRINT ("Pid %d resume ckpt set user_desc base_addr %x limit %x\n", current->pid, desc.base_addr, desc.limit);

		// I'm not sure why, but we need to force a context switch to make sure that the TLS info is 
		// loaded correctly for the CPU.  It would be worth understanding why this is.
		msleep (1); 
	}

	// Read in app syscall addr
	copyed = vfs_read (file, (char *) &syscall_addr, sizeof(u_long), &pos);
	if (copyed != sizeof(u_long)) {
		printk ("replay_resume_from_disk: tried to read app_syscall_addr %lu, got rc %d\n", syscall_addr, copyed);
		rc = copyed;
		goto freemem;
	}
	if (app_syscall_addr)
		*app_syscall_addr = syscall_addr;

	rc = sys_close (fd);
	if (rc < 0) printk ("replay_resume_from_disk: close returns %d\n", rc);

	MPRINT ("replay_resume_from_disk done\n");

freemem:
	KFREE (pmminfo);
	KFREE (pvmas);
exit:
	if (file) fput(file);
	set_fs(old_fs);
	if (rc < 0) return rc;
	return record_pid;
}

