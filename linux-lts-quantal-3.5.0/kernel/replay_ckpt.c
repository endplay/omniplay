/* Kernel support for multithreaded replay - checkpoint and resume
   Jason Flinn */
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/replay.h>
#include <linux/mount.h>
#include <linux/delay.h>
#include <linux/shm.h>
#include <linux/btree.h>
#include <asm/uaccess.h>
#include <asm/fcntl.h>
#include <asm/ldt.h>
#include <asm/desc.h>
#include <asm/ptrace.h>
#include <asm/elf.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/fpu-internal.h>
#include <linux/proc_fs.h>
#include <linux/replay.h>
#include <linux/replay_maps.h>

// No clean way to handle this that I know of...
extern int replay_debug, replay_min_debug;
#define DPRINT if(replay_debug) printk
#define MPRINT if(replay_debug || replay_min_debug) printk

#define KMALLOC kmalloc
#define KFREE kfree

#define WRITABLE_MMAPS "/run/shm/replay_mmap_%d"
#define WRITABLE_MMAPS_LEN 21
//#define WRITABLE_MMAPS_LEN 17
//#define WRITABLE_MMAPS "/tmp/replay_mmap_%d"


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
	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */
	void* vdso;
	//exe file
#ifdef CONFIG_PROC_FS
	char exe_file[PATH_MAX];
#endif
};
//defined in replay.c
struct ckpt_tsk; 

struct ckpt_data {
	u_long proc_count;
	__u64  rg_id;
	int    clock;	
};

struct ckpt_proc_data {
	pid_t  record_pid;
	long   retval;
	loff_t logpos;
	u_long outptr;
	u_long consumed;
	u_long expclock;
	u_long pthreadclock;
	u_long p_ignore_flag; //this is really just a memory address w/in the vma
	u_long p_user_log_addr;
	u_long user_log_pos;
	u_long p_clear_child_tid;
	u_long p_replay_hook;
//	u_long rss_stat_counts[NR_MM_COUNTERS]; //the counters from the checkpointed task
};

static void
print_vmas (struct task_struct* tsk)
{
	struct vm_area_struct* mpnt;
	char buf[256];

	printk ("vmas for task %d mm %p\n", tsk->pid, tsk->mm);
	down_read (&tsk->mm->mmap_sem);
	for (mpnt = tsk->mm->mmap; mpnt; mpnt = mpnt->vm_next) {
		printk ("VMA start %lx end %lx", mpnt->vm_start, mpnt->vm_end);
		if (mpnt->vm_flags & VM_MAYSHARE) {
			printk (" s");
		} else {
			printk (" p");
		}
		if (mpnt->vm_file) {
			printk (" file %s ", dentry_path (mpnt->vm_file->f_dentry, buf, sizeof(buf)));
			if (mpnt->vm_flags & VM_READ) {
				printk ("r");
			} else {
				printk ("-");
			}
			if (mpnt->vm_flags & VM_WRITE) {
				printk ("w");
			} else {
				printk ("-");
			}
			if (mpnt->vm_flags & VM_EXEC) {
				printk ("x");
			} else {
				printk ("-");
			}
		}
		printk ("\n");
	}
	up_read (&tsk->mm->mmap_sem);
}

void print_fpu_state(struct fpu *f, pid_t record_pid) 
{
	//first byte and last byte of the thread_xstate in the struct fpu
	unsigned char *c = (unsigned char *)f->state;
	unsigned char *last = c + sizeof(union thread_xstate);

	printk("%d fpu state:\n", record_pid);
	printk("\tlast_cpu %u\n",f->last_cpu);
	printk("\thas_fpu %u\n",f->has_fpu);
	while (c < last) { 
		printk("%02x ",*c);
		c++;
	} 
	printk("\n");
}


// File format:
// pid
// arguments (#, followed by len/data for each
// env. values (#, followed by len/data for each

// Allocate buffer and populate it with arguments and environment data from user level
char*
copy_args (const char __user* const __user* args, const char __user* const __user* env, int* buflen)
{
	int args_cnt, args_len, env_cnt, env_len, len, i;
	const char __user *const __user *up;
	const char __user * pc;
	char* buf, *p;

	// First determine buffer size
	args_cnt = 0;
	args_len = 0;
	up = args;
	do {
		if (get_user (pc, up)) {
			printk ("replay_checkpoint_to_disk: invalid args value\n");
			return NULL;
		}
		if (pc == 0) break; // No more args
		args_cnt++;
		args_len += strnlen_user(pc, 4096) + sizeof(int);
		up++;
	} while (1);

	env_cnt = 0;
	env_len = 0;
	up = env;
	do {
		if (get_user (pc, up)) {
			printk ("copy_args: invalid env value\n");
			return NULL;
		}
		if (pc == 0) break; // No more env
		env_cnt++;
		env_len += strnlen_user(pc, 4096) + sizeof(int);
		up++;
	} while (1);
	
	// Now allocate buffer
	*buflen = 2*sizeof(int) + args_len + env_len;
	buf = KMALLOC(*buflen, GFP_KERNEL);
	if (buf == NULL) {
		printk ("copy_args: unable to allocate buffer\n");
		return NULL;
	}

	// Now populate the buffer
	p = buf;
	*((int *) p) = args_cnt;
	p += sizeof(int);

	up = args;
	for (i = 0; i < args_cnt; i++) {
		if (get_user (pc, up) || pc == 0) {
			printk ("copy_args: invalid args value\n");
			KFREE (buf);
			return NULL;
		}		
		len = strnlen_user(pc, 4096);
		*((int *) p) = len;
		p += sizeof(int);
		if (copy_from_user (p, pc, len)) {
			printk ("copy_args: can't copy argument %d\n", i);
			KFREE (buf);
			return NULL;
		}
		p += len;
		up++;
	}

	*((int *) p) = env_cnt;
	p += sizeof(int);

	up = env;
	for (i = 0; i < env_cnt; i++) {
		if (get_user (pc, up) || pc == 0) {
			printk ("copy_args: invalid env value\n");
			KFREE (buf);
			return NULL;
		}		
		len = strnlen_user(pc, 4096);
		*((int *) p) = len;
		p += sizeof(int);
		if (copy_from_user (p, pc, len)) {
			printk ("copy_args: can't copy argument %d\n", i);
			KFREE (buf);
			return NULL;
		}
		p += len;
		up++;
	}

	return buf;
}

// This function writes the process state to a disk file
long 
replay_checkpoint_to_disk (char* filename, char* execname, char* buf, int buflen, __u64 parent_rg_id)
{
	mm_segment_t old_fs = get_fs();
	int fd, rc, copied, len;
	struct file* file = NULL;
	pid_t pid;
	loff_t pos = 0;
	__u64 rg_id;
	struct timespec time;

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
	copied = vfs_write (file, (char *) &pid, sizeof(pid), &pos);
	if (copied != sizeof(pid)) {
		printk ("replay_checkpoint_to_disk: tried to write pid, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next, write out the record group identifier
	get_record_group_id(&rg_id);
	MPRINT ("Pid %d get record group id %llu\n", current->pid, rg_id);
	copied = vfs_write (file, (char *) &rg_id, sizeof(rg_id), &pos);
	if (copied != sizeof(rg_id)) {
		printk ("replay_checkpoint_to_disk: tried to write rg_id, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next, record the parent group identifier
	MPRINT ("Pid %d parent record group id %llu\n", current->pid, parent_rg_id);
	copied = vfs_write (file, (char *) &parent_rg_id, sizeof(rg_id), &pos);
	if (copied != sizeof(parent_rg_id)) {
		printk ("replay_checkpoint_to_disk: tried to write parent_rg_id, got %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next, write out exec name
	len = strlen_user(execname);
	copied = vfs_write (file, (char *) &len, sizeof(len), &pos);
	if (copied != sizeof(len)) {
		printk ("replay_checkpoint_to_disk: tried to write exec name len, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	copied = vfs_write (file, execname, len, &pos);
	if (copied != len) {
		printk ("replay_checkpoint_to_disk: tried to write exec name, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next, write out rlimit information
	copied = vfs_write (file, (char *) &current->signal->rlim, sizeof(struct rlimit)*RLIM_NLIMITS, &pos);
	if (copied != sizeof(struct rlimit)*RLIM_NLIMITS) {
		printk ("replay_checkpoint_to_disk: tried to write rlimits, got rc %d\n", copied);
		rc = -EFAULT;
		goto exit;
	}

	// Next, copy the signal handlers
	copied = vfs_write (file, (char *) &current->sighand->action, sizeof(struct k_sigaction) * _NSIG, &pos);
	if (copied != sizeof(struct k_sigaction)*_NSIG) {
		printk ("replay_checkpoint_to_disk: tried to write sighands, got rc %d\n", copied);
		rc = -EFAULT;
		goto exit;
	}

	// Next, write out arguments to exec
	copied = vfs_write (file, buf, buflen, &pos);
	if (copied != buflen) {
		printk ("replay_checkpoint_to_disk: tried to write arguments, got rc %d\n", copied);
		rc = -EFAULT;
		goto exit;
	}
	KFREE (buf);

	// Next, the time the recording started.
	time = CURRENT_TIME;
	copied = vfs_write (file, (char *) &time, sizeof(time), &pos);
	if (copied != sizeof(time)) {
		printk ("replay_checkpoint_to_disk: tried to write time, got %d\n", copied);
		rc = copied;
		goto exit;
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

long replay_resume_from_disk (char* filename, char** execname, char*** argsp, char*** envp, __u64* prg_id) 
{
	mm_segment_t old_fs = get_fs();
	int rc, fd, args_cnt, env_cnt, copied, i, len;
	struct file* file = NULL;
	loff_t pos = 0;
	pid_t record_pid;
	__u64 rg_id;
	__u64 parent_rg_id;
	char** args;
	char** env;
	struct timespec time;

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
	copied = vfs_read(file, (char *) &record_pid, sizeof(record_pid), &pos);
	if (copied != sizeof(record_pid)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next read the record group id
	copied = vfs_read(file, (char *) &rg_id, sizeof(rg_id), &pos);
	MPRINT ("Pid %d replay_resume_from_disk: rg_id %llu\n", current->pid, rg_id);
	if (copied != sizeof(rg_id)) {
		printk ("replay_resume_from_disk: tried to read rg_id, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	*prg_id = rg_id;

	// Next read the parent record group id
	copied = vfs_read(file, (char *) &parent_rg_id, sizeof(parent_rg_id), &pos);
	MPRINT ("Pid %d replay_resume_from_disk: parent_rg_id %llu", current->pid, parent_rg_id);
	if (copied != sizeof(parent_rg_id)) {
		printk ("replay_resume_from_disk: tried to read parent_rg_id got %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next read the exec name
	copied = vfs_read(file, (char *) &len, sizeof(len), &pos);
	if (copied != sizeof(len)) {
		printk ("replay_resume_from_disk: tried to read execname len, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	*execname = KMALLOC (len, GFP_KERNEL);
	if (*execname == NULL) {
		printk ("replay_resume_from_disk: unable to allocate exev name of len %d\n", len);
		rc = -ENOMEM;
		goto exit;
	}
	copied = vfs_read(file, *execname, len, &pos);
	if (copied != len) {
		printk ("replay_resume_from_disk: tried to read execname, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	
	// Next, read the rlimit info
	copied = vfs_read(file, (char *) &current->signal->rlim, sizeof(struct rlimit)*RLIM_NLIMITS, &pos);
	if (copied != sizeof(struct rlimit)*RLIM_NLIMITS) {
		printk ("replay_resume_from_disk: tried to read rlimits, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	copied = vfs_read(file, (char *) &current->sighand->action, sizeof(struct k_sigaction) * _NSIG, &pos);
	if (copied != sizeof(struct k_sigaction)*_NSIG) {
		printk ("replay_resume_from_disk: tried to read sighands, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next, read the number of arguments
	copied = vfs_read(file, (char *) &args_cnt, sizeof(args_cnt), &pos);
	if (copied != sizeof(args_cnt)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	MPRINT ("%d arguments in checkpoint\n", args_cnt);
	
	args = KMALLOC((args_cnt+1) * sizeof(char *), GFP_KERNEL);
	if (args == NULL) {
		printk ("replay_resume_from_disk: unable to allocate arguments\n");
		rc = -ENOMEM;
		goto exit;
	}

	// Now read in each argument
	for (i = 0; i < args_cnt; i++) {
		copied = vfs_read(file, (char *) &len, sizeof(len), &pos);
		if (copied != sizeof(len)) {
			printk ("replay_resume_from_disk: tried to read argument %d len, got rc %d\n", i, copied);
			rc = copied;
			goto exit;
		}
		args[i] = KMALLOC(len+1, GFP_KERNEL);
		if (args[i] == NULL) {
			printk ("replay_resume_froma_disk: unable to allocate argument %d\n", i);
			rc = -ENOMEM;
			goto exit;
		}
		copied = vfs_read(file, args[i], len, &pos);
		MPRINT ("copied %d bytes\n", copied);
		if (copied != len) {
			printk ("replay_resume_from_disk: tried to read argument %d, got rc %d\n", i, copied);
			rc = copied;
			goto exit;
		}
		args[i][len] = '\0'; // NULL terminator not in file format
		MPRINT ("Argument %d is %s\n", i, args[i]);
	}
	args[i] = NULL;

	// Next, read the number of env. objects
	copied = vfs_read(file, (char *) &env_cnt, sizeof(env_cnt), &pos);
	if (copied != sizeof(env_cnt)) {
		printk ("replay_resume_from_disk: tried to read record pid, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	MPRINT ("%d env. objects in checkpoint\n", env_cnt);
	
	env = KMALLOC((env_cnt+1) * sizeof(char *), GFP_KERNEL);
	if (env == NULL) {
		printk ("replay_resume_froma_disk: unable to allocate env struct\n");
		rc = -ENOMEM;
		goto exit;
	}

	// Now read in each env. object
	for (i = 0; i < env_cnt; i++) {
		copied = vfs_read(file, (char *) &len, sizeof(len), &pos);
		if (copied != sizeof(len)) {
			printk ("replay_resume_from_disk: tried to read env. %d len, got rc %d\n", i, copied);
			rc = copied;
			goto exit;
		}
		env[i] = KMALLOC(len+1, GFP_KERNEL);
		if (env[i] == NULL) {
			printk ("replay_resume_froma_disk: unable to allocate env. %d\n", i);
			rc = -ENOMEM;
			goto exit;
		}
		copied = vfs_read(file, env[i], len, &pos);
		if (copied != len) {
			printk ("replay_resume_from_disk: tried to read env. %d, got rc %d\n", i, copied);
			rc = copied;
			goto exit;
		}
		env[i][len] = '\0'; // NULL terminator not in file format
		MPRINT ("Env. %d is %s\n", i, env[i]);
	}
	env[i] = NULL;

	*argsp = args;
	*envp = env;
	
	// Next read the time
	copied = vfs_read(file, (char *) &time, sizeof(time), &pos);
	if (copied != sizeof(time)) {
		printk ("replay_resume_from_disk: tried to read time, got %d\n", copied);
		rc = copied;
		goto exit;
	}

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

#ifdef CONFIG_PROC_FS
static char*
get_exe_path (struct mm_struct* mm, char* path)
{
	char* p;

	down_read(&mm->mmap_sem);
	p = d_path (&mm->exe_file->f_path, path, PATH_MAX);
	up_read(&mm->mmap_sem);
	return p;
}
#endif

static int 
get_replay_mmap (struct btree_head32 *replay_mmap_btree, char *filename) 
{ 
	int key, newkey, inserted = 0; 

	sscanf(filename, WRITABLE_MMAPS ,&key); // get the key	
	newkey = (int)btree_lookup32(replay_mmap_btree, key);
	if (newkey == 0) { 
		//we need to create a new key! 
		newkey = get_next_mmap_file();
		btree_insert32(replay_mmap_btree, (u32)key,(void*)newkey,GFP_KERNEL);
		inserted = 1;
	}
	sprintf(filename, WRITABLE_MMAPS,newkey);
	return inserted;
}


// This function writes the global checkpoint state to disk
long 
replay_full_checkpoint_hdr_to_disk (char* filename, __u64 rg_id, int clock, u_long proc_count, struct ckpt_tsk *ct, struct task_struct *tsk,loff_t* ppos)
{
	mm_segment_t old_fs = get_fs();
	struct file* file = NULL;
	struct ckpt_data cdata;
	int fd = -1, rc, copied;

	MPRINT ("pid %d enters replay_full_checkpoint_hdr_to_disk: filename %s\n", current->pid, filename);

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd < 0) {
		printk ("replay_full_checkpoint_hdr_to_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);
	*ppos = 0;

	// Write out checkpoint data
	cdata.rg_id = rg_id;
	cdata.clock = clock;
	cdata.proc_count = proc_count;
	copied = vfs_write (file, (char *) &cdata, sizeof(cdata), ppos);
	if (copied != sizeof(cdata)) {
		printk ("replay_full_checkpoint_hdr_to_disk: tried to write ckpt data, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	rc = checkpoint_ckpt_tsks_header(ct, -1, 0, file, ppos); 	

	//this is part of the replay_group, so do it here instead of for each proc: 
	rc = checkpoint_task_xray_monitor (tsk, file, ppos);
	
exit:
	if (file) fput(file);
	if (fd >= 0)  {
		rc = sys_close (fd);
		if (rc < 0) printk ("replay_checkpoint_proc_to_disk: close returns %d\n", rc);
	}
	set_fs(old_fs);
	return rc;
}

// This function writes the process state to a disk file
long 
replay_full_checkpoint_proc_to_disk (char* filename, struct task_struct* tsk, pid_t record_pid, 
				     int is_thread, long retval, loff_t logpos, u_long outptr, 
				     u_long consumed, u_long expclock, u_long pthread_block_clock, 
				     u_long ignore_flag, u_long user_log_addr, u_long user_log_pos,
				     u_long replay_hook, loff_t* ppos)
{
	mm_segment_t old_fs = get_fs();
	int fd = -1, rc, copied, i;
	struct file* file = NULL;
	struct vm_area_struct* vma;
	struct vma_stats* pvmas = NULL;
	char* buffer = NULL;
	struct mm_info* pmminfo = NULL;
	struct inode* inode;
	char* p;
	struct user_desc desc;
	struct ckpt_proc_data cpdata;
	long nr_pages = 0;
	struct page** ppages = NULL;  
	struct fpu *fpu = &(tsk->thread.fpu); 

	char fpu_is_allocated;

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_WRONLY|O_APPEND, 0);
	if (fd < 0) {
		printk ("replay_full_checkpoint_proc_to_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);

	// First - write out checkpoint data
	cpdata.record_pid = record_pid;
	cpdata.retval = retval;
	cpdata.logpos = logpos;
	cpdata.outptr = outptr;
	cpdata.consumed = consumed;
	cpdata.expclock = expclock;
	cpdata.pthreadclock = pthread_block_clock;
	cpdata.p_ignore_flag  = ignore_flag;
	cpdata.p_user_log_addr = user_log_addr;
	cpdata.user_log_pos = user_log_pos; 
	cpdata.p_clear_child_tid = (u_long)tsk->clear_child_tid; //ah, not having this messes up our replay on exit
	cpdata.p_replay_hook = replay_hook;

	copied = vfs_write (file, (char *) &cpdata, sizeof(cpdata), ppos);
	if (copied != sizeof(cpdata)) {
		printk ("replay_full_checkpoint_proc_to_disk: tried to write process data, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	// Next - write out the registers
	copied = vfs_write(file, (char *) get_pt_regs(tsk), sizeof(struct pt_regs), ppos);
	if (copied != sizeof(struct pt_regs)) {
		printk ("replay_full_checkpoint_proc_to_disk: tried to write regs, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	//this is a part of the replay_thrd, so we do it regardless of thread / process
	checkpoint_sysv_mappings (tsk, file, ppos);

	// Write out the floating point registers: 
	if (current == tsk) { 
		//force the fpu to flush to the task_struct's data structures
		unlazy_fpu(tsk);
	}
	fpu = &(tsk->thread.fpu);

	fpu_is_allocated = fpu_allocated(fpu);
	copied = vfs_write(file, &(fpu_is_allocated), sizeof(char), ppos);
	if (copied != sizeof(char)) {
		printk ("replay_full_checkpoint_proc_to_disk: tried to write last_cpu, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}	

	if (fpu_is_allocated){
		copied = vfs_write(file, (char *) &(fpu->last_cpu), sizeof(unsigned int), ppos);
		if (copied != sizeof(unsigned int)) {
			printk ("replay_full_checkpoint_proc_to_disk: tried to write last_cpu, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}
		copied = vfs_write(file, (char *) &(fpu->has_fpu), sizeof(unsigned int), ppos);
		if (copied != sizeof(unsigned int)) {
			printk ("replay_full_checkpoint_proc_to_disk: tried to write has_fpu, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}

		//thread_xstate's actual size is stored by this variable

		copied = vfs_write(file, (char *) fpu->state, xstate_size, ppos);
		if (copied != sizeof(union thread_xstate)) {
			printk ("replay_full_checkpoint_proc_to_disk: tried to write thread_xstate, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}
	}

	

	//this is part of the replay_thrd, so we do it regardless of thread / process
	checkpoint_sysv_mappings (tsk, file, ppos);
	if (!is_thread) { 
		// Write out the replay cache state
		checkpoint_replay_cache_files (tsk, file, ppos);		
		down_read (&tsk->mm->mmap_sem);

		// Next - number of VM area
		copied = vfs_write(file, (char *) &tsk->mm->map_count, sizeof(int), ppos);
		if (copied != sizeof(int)) {
			printk ("replay_full_checkpoint_proc_to_disk: tried to write map_count, got rc %d\n", copied);
			rc = copied;
			goto unlock;
		}
		
		/* These are too big to put on the kernel stack */
		pvmas = KMALLOC (sizeof(struct vma_stats), GFP_KERNEL);
		buffer = KMALLOC (PATH_MAX, GFP_KERNEL);
		if (!pvmas || !buffer) {
			printk ("replay_full_checkpoint_proc_to_disk: cannot allocate memory\n");
			rc = -ENOMEM;
			goto unlock;
		}

		// Next - info and data for each vma
		for (vma = tsk->mm->mmap; vma; vma = vma->vm_next) {
			
			if (vma->vm_start == (u_long) tsk->mm->context.vdso) {
				continue; // Don't save VDSO - will regenerate it on restore
			}
			
			pvmas->vmas_start = vma->vm_start;
			pvmas->vmas_end = vma->vm_end;
			pvmas->vmas_flags = vma->vm_flags;
			pvmas->vmas_pgoff = vma->vm_pgoff;
			
			if(vma->vm_file) {
				inode = vma->vm_file->f_path.dentry->d_inode;
				p = d_path (&vma->vm_file->f_path, buffer, PATH_MAX);
				strcpy (pvmas->vmas_file, p);
			}
			else {
				pvmas->vmas_file[0] = '\0';
			}
 
			copied = vfs_write(file, (char *) pvmas, sizeof(struct vma_stats), ppos);
			if (copied != sizeof(struct vma_stats)) {
				printk ("replay_full_checkpoint_proc_to_disk: tried to write vma info, got rc %d\n", copied);
				rc = copied;
				goto freemem;
			}
			
			if(!strncmp(pvmas->vmas_file, "/dev/zero", 9)) continue; /* Skip writing this one */

			if (!(pvmas->vmas_flags & VM_READ) || 
			    ((pvmas->vmas_flags&VM_MAYSHARE) && 
			     strncmp(pvmas->vmas_file, WRITABLE_MMAPS,WRITABLE_MMAPS_LEN))) { //why is this in here...? 
				continue;
			}
			
			if (current->pid != tsk->pid) {
				// Need to map these pages to kernel space
				nr_pages = (pvmas->vmas_end-pvmas->vmas_start)/PAGE_SIZE;
				DPRINT ("Region: %lx to %lx: number of pages is %ld\n", pvmas->vmas_start, pvmas->vmas_end, nr_pages);
				ppages = KMALLOC(sizeof(struct page *) * nr_pages, GFP_KERNEL);
				if (ppages == NULL) {
					printk ("replay_full_checkpoint_proc_to_disk: cannot allocate page array\n");
					rc = -ENOMEM;
					goto freemem;
				}

				rc = get_user_pages (tsk, tsk->mm, pvmas->vmas_start, nr_pages, 0, 0, ppages, NULL);
				if (rc != nr_pages) {
					printk ("replay_full_checkpoint_proc_to_disk: cannot get user pages,rc=%d\n", rc);
					KFREE (ppages);
					ppages = NULL;
					goto freemem;
				}
				for (i = 0; i < nr_pages; i++) {
					char* p = kmap (ppages[i]);
					copied = vfs_write(file, p, PAGE_SIZE, ppos);
					kunmap (ppages[i]);
					if (copied != PAGE_SIZE) {
						printk ("replay_full_checkpoint_proc_to_disk: tried to write vma page, got rc %d\n", copied);
						rc = copied;
						goto freemem;
					}
				}
				for (i = 0; i < nr_pages; i++) {
					put_page (ppages[i]);
				}
				KFREE(ppages);
				ppages = NULL;
			} else {
				set_fs(old_fs);
				copied = vfs_write(file, (char *) pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, ppos);
				set_fs(KERNEL_DS);
				if (copied != pvmas->vmas_end - pvmas->vmas_start) {
					printk ("replay_full_checkpoint_proc_to_disk: tried to write vma data, got rc %d\n", copied);
					rc = copied;
					goto freemem;
				}
			}
		}

		// Process-specific info in the mm struct
		pmminfo = KMALLOC (sizeof(struct mm_info), GFP_KERNEL);
		if (pmminfo == NULL) {
			printk ("replay_full_checkpoint_proc_to_disk: unable to allocate mm_info structure\n");
			rc = -ENOMEM;
			goto freemem;
		}
		pmminfo->start_code = tsk->mm->start_code;
		pmminfo->end_code = tsk->mm->end_code;
		pmminfo->start_data = tsk->mm->start_data;
		pmminfo->end_data = tsk->mm->end_data;
		pmminfo->start_brk = tsk->mm->start_brk;
		pmminfo->brk = tsk->mm->brk;
		pmminfo->start_stack = tsk->mm->start_stack;
		pmminfo->arg_start = tsk->mm->arg_start;
		pmminfo->arg_end = tsk->mm->arg_end;
		pmminfo->env_start = tsk->mm->env_start;
		pmminfo->env_end = tsk->mm->env_end;
		memcpy (pmminfo->saved_auxv, tsk->mm->saved_auxv, sizeof(pmminfo->saved_auxv));
		pmminfo->vdso = tsk->mm->context.vdso;		

#ifdef CONFIG_PROC_FS
		p = get_exe_path (tsk->mm, buffer);
		strcpy (pmminfo->exe_file, p);
#endif

		copied = vfs_write(file, (char *) pmminfo, sizeof(struct mm_info), ppos);
		if (copied != sizeof(struct mm_info)) {
			printk ("replay_full_checkpoint_proc_to_disk: tried to write mm info, got rc %d\n", copied);
			rc = copied;
			goto freemem;
		}
	}
	else { 
		//we didn't do this in the if above ^^ 
		down_read (&tsk->mm->mmap_sem);
	}


	// Write out TLS info
	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
		fill_user_desc(&desc, GDT_ENTRY_TLS_MIN+i, &tsk->thread.tls_array[i]);
		copied = vfs_write(file, (char *) &desc, sizeof(desc), ppos);
		if (copied != sizeof(desc)) {
			printk ("replay_full_checkpoint_proc_to_disk: tried to write TLS entry #%d, got rc %d\n", i, copied);
			rc = copied;
			goto freemem;
		}
		MPRINT ("Pid %d replay_full_checkpoint_proc_to_disk filling user_desc base_addr %x limit %x\n", tsk->pid, desc.base_addr, desc.limit);
	}

	// Next, write out rlimit information
	copied = vfs_write (file, (char *) &tsk->signal->rlim, sizeof(struct rlimit)*RLIM_NLIMITS, ppos);
	if (copied != sizeof(struct rlimit)*RLIM_NLIMITS) {
		printk ("replay_checkpoint_proc_to_disk: tried to write rlimits, got rc %d\n", copied);
		rc = -EFAULT;
		goto exit;
	}

	// Next, copy the signal handlers
	copied = vfs_write (file, (char *) &tsk->sighand->action, sizeof(struct k_sigaction) * _NSIG, ppos);
	if (copied != sizeof(struct k_sigaction)*_NSIG) {
		printk ("replay_checkpoint_proc_to_disk: tried to write sighands, got rc %d\n", copied);
		rc = -EFAULT;
		goto exit;
	}

freemem:
	if (ppages) {
		for (i = 0; i < nr_pages; i++) {
			put_page (ppages[i]);
		}
		KFREE(ppages);
	}
	KFREE(buffer);
	KFREE(pvmas);
	KFREE(pmminfo);
unlock:
	up_read (&tsk->mm->mmap_sem);
exit:
	if (file) fput(file);
	if (fd >= 0)  {
		rc = sys_close (fd);
		if (rc < 0) printk ("replay_checkpoint_proc_to_disk: close returns %d\n", rc);
	}
	set_fs(old_fs);
	return rc;
}

long replay_full_resume_hdr_from_disk (char* filename, __u64* prg_id, int* pclock, u_long* pproc_count, loff_t* ppos) 
{
	mm_segment_t old_fs = get_fs();
	int rc = 0, fd, copied;
	struct file* file = NULL;
	struct ckpt_data cdata;

	MPRINT ("pid %d enters replay_full_resume_hdr_from_disk: filename %s\n", current->pid, filename);

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_RDONLY, 0);
	if (fd < 0) {
		printk ("replay_full_reusme_hdr_from_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);
	*ppos = 0;

	// Read the checkpoint header data
	copied = vfs_read(file, (char *) &cdata, sizeof(cdata), ppos);
	MPRINT ("Pid %d replay_full_resume_hdr_from_disk: rg_id %llu\n", current->pid, cdata.rg_id);
	if (copied != sizeof(cdata)) {
		printk ("replay_full_resume_hdr_from_disk: tried to read ckpt data, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}
	*prg_id = cdata.rg_id;
	*pclock = cdata.clock;
	*pproc_count = cdata.proc_count;

	rc = restore_ckpt_tsks_header(*pproc_count, file, ppos); 	
	rc = restore_task_xray_monitor (current, file, ppos);

	MPRINT ("replay_full_resume_hdr_from_disk done\n");

exit:
	if (fd >= 0) {
		if (sys_close (fd) < 0) printk ("replay_full_resume_hdr_from_disk: close returns %d\n", rc);
	}
	if (file) fput(file);
	set_fs(old_fs);
	return rc;
}

long replay_full_resume_proc_from_disk (char* filename, pid_t clock_pid, int is_thread, 
					long* pretval, loff_t* plogpos, u_long* poutptr, 
					u_long* pconsumed, u_long* pexpclock, 
					u_long* pthreadclock, u_long *ignore_flag, 
					u_long *user_log_addr, ulong *user_log_pos,
					u_long *child_tid,u_long *replay_hook, loff_t* ppos)
{
	mm_segment_t old_fs = get_fs();
	int rc = 0, fd, exe_fd, copied, i, map_count, key, shmflg=0, id, premapped = 0, new_file = 0;
	struct file* file = NULL, *map_file;
	pid_t record_pid = -1;
	struct vm_area_struct* vma, *vma_next;
	struct vma_stats* pvmas = NULL;
	struct mm_info* pmminfo = NULL;
	u_long addr;
	struct ckpt_proc_data cpdata;
	struct user_desc desc;
	int flags;
	struct btree_head32 replay_mmap_btree;
	struct fpu *fpu = NULL;

	char fpu_is_allocated;
	MPRINT ("pid %d enters replay_full_resume_proc_from_disk: filename %s\n", current->pid, filename);

	set_fs(KERNEL_DS);
	fd = sys_open (filename, O_RDONLY, 0);
	if (fd < 0) {
		printk ("replay_checkpoint_from_disk: open of %s returns %d\n", filename, fd);
		rc = fd;
		goto exit;
	}
	file = fget(fd);

	// Read the process checkpoint data
	copied = vfs_read(file, (char *) &cpdata, sizeof(cpdata), ppos);
	if (copied != sizeof(cpdata)) {
		printk ("replay_full_resume_proc_from_disk: tried to read checkpoint process data, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	record_pid = cpdata.record_pid;
	*pretval = cpdata.retval;
	*plogpos = cpdata.logpos;
	*poutptr = cpdata.outptr;
	*pconsumed = cpdata.consumed;
	*pexpclock = cpdata.expclock;
	*pthreadclock = cpdata.pthreadclock;
	*ignore_flag = cpdata.p_ignore_flag;
	*user_log_addr = cpdata.p_user_log_addr;
	*user_log_pos  = cpdata.user_log_pos;
	*child_tid = cpdata.p_clear_child_tid; 
	*replay_hook = cpdata.p_replay_hook;

	// Restore the user-level registers
	copied = vfs_read(file, (char *) get_pt_regs(NULL), sizeof(struct pt_regs), ppos);
	if (copied != sizeof(struct pt_regs)) {
		printk ("replay_full_resume_proc_from_disk: tried to read regs, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	//this is a part of the replay_thrd, so we do it regardless of thread / process
	restore_sysv_mappings (file, ppos);

	// Restore the floating point registers: 
	fpu = &(current->thread.fpu);

	copied = vfs_read(file, &(fpu_is_allocated), sizeof(char), ppos);
	if (copied != sizeof(char)) {
		printk ("replay_full_checkpoint_proc_to_disk: tried to read fpu_is_allocated, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}	

	if (fpu_is_allocated) { 

		//allocate the new fpu if we need it and it isn't setup
		if (!fpu_allocated(fpu)) {
			printk("allocating fpu\n");
			fpu_alloc(fpu);
		}

		copied = vfs_read(file, (char *) &(fpu->last_cpu), sizeof(unsigned int), ppos);
		if (copied != sizeof(unsigned int)) {
			printk ("replay_full_resume_proc_from_disk: tried to read last cpu, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}
		copied = vfs_read(file, (char *) &(fpu->has_fpu), sizeof(unsigned int), ppos);
		if (copied != sizeof(unsigned int)) {
			printk ("replay_full_resume_proc_from_disk: tried to read has_fpu, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}
		copied = vfs_read(file, (char *) fpu->state, xstate_size, ppos);
		if (copied != sizeof(union thread_xstate)) {
			printk ("replay_full_resume_proc_from_disk: tried to read thread_xstate, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}
	}

	//this is a part of the replay_thrd, so we do it regardless of thread / process
	restore_sysv_mappings (file, ppos);

	if (!is_thread) { 
		
		// restore the replay cache state (this is going to be done on per process)
		restore_replay_cache_files (file, ppos);

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
		copied = vfs_read(file, (char *) &map_count, sizeof(int), ppos);
		if (copied != sizeof(int)) {
			printk ("replay_full_resume_proc_from_disk: tried to read map_count, got rc %d\n", copied);
			rc = copied;
			goto exit;
		}
		
		/* This is too big to put on the kernel stack */
		pvmas = KMALLOC (sizeof(struct vma_stats), GFP_KERNEL);
		if (!pvmas) {
			printk ("replay_full_resume_proc_from_disk: cannot allocate memory\n");
			rc = -ENOMEM;
			goto exit;
		}
		
		// Map each VMA and copy data from the file - assume VDSO handled separately - so use map_count-1
		btree_init32(&replay_mmap_btree);
		for (i = 0; i < map_count-1; i++) {
			premapped = 0;
			copied = vfs_read (file, (char *) pvmas, sizeof(struct vma_stats), ppos);
			if (copied != sizeof(struct vma_stats)) {
				printk ("replay_full_resume_proc_from_disk: tried to read vma info, got rc %d\n", copied);
				rc = copied;
				goto freemem;
			}				
			if (pvmas->vmas_file[0]) { 
				flags = O_RDONLY;
				if (!strncmp(pvmas->vmas_file, "/dev/zero", 9)) {
					MPRINT ("special vma for /dev/zero!\n");
					map_file = NULL;
				} else {
					if (!strncmp(pvmas->vmas_file, "/run/shm/uclock", 15)) {
						flags = O_RDWR;
						MPRINT ("special uclock vma\n");
						sprintf (pvmas->vmas_file, "/run/shm/uclock%d", clock_pid);
					}
					if (!strncmp(pvmas->vmas_file,WRITABLE_MMAPS,WRITABLE_MMAPS_LEN)) { 
						new_file = get_replay_mmap(&replay_mmap_btree, pvmas->vmas_file);
						if (new_file) { 
							flags = O_CREAT|O_RDWR;					
							map_file = filp_open (pvmas->vmas_file, flags, 0777);
							if (IS_ERR(map_file)) {
								rc = PTR_ERR(map_file);
								printk ("replay_full_resume_proc_from_disk: filp_open error %s rc %d\n", pvmas->vmas_file, rc);
								goto freemem;
							}				
							rc = do_truncate (map_file->f_path.dentry,
									  pvmas->vmas_end - pvmas->vmas_start, 
									  ATTR_MTIME | ATTR_CTIME, map_file);

							if (rc) { 
								printk("%d problem with do_truncate, rc %d \n",
								       current->pid, rc);
								goto freemem;
							}
						}
						else { 
							flags = O_RDWR;
							map_file = filp_open (pvmas->vmas_file, flags, 0);
							if (IS_ERR(map_file)) {
								rc = PTR_ERR(map_file);
								printk ("replay_full_resume_proc_from_disk: filp_open error %s rc %d\n", pvmas->vmas_file, rc);
								goto freemem;
							}
						}
					}
					else if (!strncmp(pvmas->vmas_file, "/SYSV",5)) { 
						sscanf(pvmas->vmas_file, "/SYSV%08x",&key);						
						id = find_sysv_mapping_by_key(key); 
						if (id < 0) { 
							printk("whoops.. what happened, key isn't in sysvmappings\n");
							goto freemem; 
						}

						//get the correct shmflags
						if (pvmas->vmas_flags&VM_EXEC) { 
							shmflg |= SHM_EXEC;
						}
						else if (pvmas->vmas_flags&VM_READ && 
							 !(pvmas->vmas_flags&VM_WRITE)) { 
							shmflg |= SHM_RDONLY; 
						}

						addr = sys_shmat(id, (char __user *)pvmas->vmas_start, shmflg); 
						
						rc = add_sysv_shm((u_long)pvmas->vmas_start, 
							     (u_long)(pvmas->vmas_end - pvmas->vmas_start));
						if (rc < 0) { 
							printk("whoops... add_sysv_shm returns negative?\n");
							goto freemem;
						}


						premapped = 1;
						map_file = NULL; //just to be sure something weird doesn't happen
					}

					else { 
						MPRINT ("Opening file %s\n", pvmas->vmas_file);
						map_file = filp_open (pvmas->vmas_file, flags, 0);
						if (IS_ERR(map_file)) {
							rc = PTR_ERR(map_file);
							printk ("replay_full_resume_proc_from_disk: filp_open error %s rc %d\n", pvmas->vmas_file, rc);
							goto freemem;
						}
					}
				}
			} else { 
				map_file = NULL;
			}

			if (!premapped) { 
				MPRINT ("About to do mmap: map_file %p start %lx len %lx flags %x writable? %d shar %x pgoff %lx\n", 
					map_file, pvmas->vmas_start, pvmas->vmas_end-pvmas->vmas_start, 
					(pvmas->vmas_flags&(VM_READ|VM_WRITE|VM_EXEC)), 
					(pvmas->vmas_flags & VM_WRITE),
					((pvmas->vmas_flags&VM_MAYSHARE) ? MAP_SHARED : MAP_PRIVATE) | 
					MAP_FIXED | (pvmas->vmas_flags & VM_GROWSDOWN), 
					pvmas->vmas_pgoff);


				addr = do_mmap_pgoff(map_file, pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, 
					     (pvmas->vmas_flags&(VM_READ|VM_WRITE|VM_EXEC)), 
					     ((pvmas->vmas_flags&VM_MAYSHARE) ? MAP_SHARED : MAP_PRIVATE) | 
						     MAP_FIXED | 
						     (pvmas->vmas_flags&VM_GROWSDOWN), 
					     pvmas->vmas_pgoff);
			}						
			if (map_file) filp_close (map_file, NULL);
			if (IS_ERR((char *) addr)) {
				printk ("replay_full_resume_proc_from_disk: mmap error %ld\n", PTR_ERR((char *) addr));
				if (map_file) filp_close (map_file, NULL);
				rc = addr;
				goto freemem;
			}
			
			if (!strncmp(pvmas->vmas_file, "/dev/zero", 9)) continue; /* Skip writing this one */
			if (!(pvmas->vmas_flags&VM_READ) || 
			    ((pvmas->vmas_flags&VM_MAYSHARE) && 
			     strncmp(pvmas->vmas_file,WRITABLE_MMAPS,WRITABLE_MMAPS_LEN))) {
				continue;  // Not in checkpoint - so skip writing this one
			}				
			if (!(pvmas->vmas_flags&VM_WRITE)){
                                // force it to writable temproarilly
				rc = sys_mprotect (pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, PROT_WRITE); 
			}
		     
			set_fs(old_fs);			
			copied = vfs_read (file, (char *) pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, ppos);
			set_fs(KERNEL_DS);
			if (copied != pvmas->vmas_end - pvmas->vmas_start) {
				printk ("%d reading from ckpt file into (0x%x,0x%x)\n", current->pid, pvmas->vmas_start, pvmas->vmas_start + (pvmas->vmas_end - pvmas->vmas_start));
				print_vmas(current);
				rc = copied;
				goto freemem;
			}
			if (!(pvmas->vmas_flags&VM_WRITE)) rc = sys_mprotect (pvmas->vmas_start, pvmas->vmas_end - pvmas->vmas_start, pvmas->vmas_flags&(VM_READ|VM_WRITE|VM_EXEC)); // restore old protections		
		}
		btree_destroy32(&replay_mmap_btree);
		// Process-specific info in the mm struct
		pmminfo = KMALLOC (sizeof(struct mm_info), GFP_KERNEL);
		if (pmminfo == NULL) {
			printk ("replay_full_resume_proc_from_disk: unable to allocate mm_info structure\n");
			rc = -ENOMEM;
			goto freemem;
		}
		copied = vfs_read (file, (char *) pmminfo, sizeof(struct mm_info), ppos);
		if (copied != sizeof(struct mm_info)) {
			printk ("replay_full_resume_proc_from_disk: tried to read mm info, got rc %d\n", copied);
			rc = copied;
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
		memcpy (current->mm->saved_auxv, pmminfo->saved_auxv, sizeof(pmminfo->saved_auxv));
		current->mm->context.vdso = pmminfo->vdso;
		arch_restore_additional_pages (current->mm->context.vdso);
#ifdef CONFIG_PROC_FS
		exe_fd = sys_open (pmminfo->exe_file, O_RDONLY, 0);
		set_mm_exe_file (current->mm, fget(exe_fd));
		sys_close (exe_fd);
#endif

	}
	else { 
		arch_restore_sysenter_return(current->mm->context.vdso);
	}


	// Read in TLS info
	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
		copied = vfs_read (file, (char *) &desc, sizeof(desc), ppos);
		if (copied != sizeof(desc)) {
			printk ("replay_full_resume_proc_from_disk: tried to read TLS entry #%d, got rc %d\n", i, copied);
			rc = copied;
			goto freemem;
		}
		set_tls_desc(current, GDT_ENTRY_TLS_MIN+i, &desc, 1);
		MPRINT ("Pid %d resume ckpt set GDT entry %d base_addr %x limit %x\n", current->pid, GDT_ENTRY_TLS_MIN+i, desc.base_addr, desc.limit);
	}

	// Next, read the rlimit info
	copied = vfs_read(file, (char *) &current->signal->rlim, sizeof(struct rlimit)*RLIM_NLIMITS, ppos);
	if (copied != sizeof(struct rlimit)*RLIM_NLIMITS) {
		printk ("replay_full_resume_proc_from_disk: tried to read rlimits, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	copied = vfs_read(file, (char *) &current->sighand->action, sizeof(struct k_sigaction) * _NSIG, ppos);
	if (copied != sizeof(struct k_sigaction)*_NSIG) {
		printk ("replay_full_resume_proc_from_disk: tried to read sighands, got rc %d\n", copied);
		rc = copied;
		goto exit;
	}

	MPRINT ("replay_full_resume_proc_from_disk done\n");
freemem:
	KFREE (pmminfo);
	KFREE (pvmas);
exit:
	if (fd >= 0) {
		if (sys_close (fd) < 0) printk ("replay_full_resume_proc_from_disk: close returns %d\n", rc);
	}
	if (file) fput(file);
	set_fs(old_fs);
	if (rc < 0) return rc;
	return record_pid;
}
