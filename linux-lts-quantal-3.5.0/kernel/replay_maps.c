// Jason Flinn
// created: 5/8/13
//
// This file contains the code to manage a cache of mmapped regions.  Rather than record the individual read/writes, 
// we need to store a copy of each region on mapping so that it can be faithfully replayed.  This strategy assumes
// that write-shared regions are not accessed in a racy manner (but we make the same asumption for address spaces).
// 
// We expect a lot of reuse across recordings, so we try to store one entry per unique mapped region.  We can reliably
// identify such regions by secure hash of the content, but then each mmap requires a full scan of the region to calculate
// the hash.   A better way is therefore to use the file modification time.  If the mapped file mod time is before the cache
// time, then the file is unchanged, and we do not need to check for a hash map.
//
// Maybe this should be expanded to all file data?

#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/replay_maps.h>
#include <linux/slab.h>
#include <asm/stat.h>
#include <asm/uaccess.h>

#define DPRINT(x,...)

char cache_dir[] = "/replay_cache";
#define COPY_CHUNK 4096

// We hold the record lock when this function is called
int add_file_to_cache (struct file* vm_file, dev_t* pdev, unsigned long* pino, struct timespec* pmtime) 
{
	char cname[CACHE_FILENAME_SIZE], nname[CACHE_FILENAME_SIZE];
	struct stat64 st;
	int fd, rc, copyed;
	mm_segment_t old_fs;
	loff_t ipos = 0, opos = 0;
	char* buffer;
	struct file* ofile;
	struct inode* inode = vm_file->f_dentry->d_inode;

	*pino = inode->i_ino;
	*pdev = inode->i_sb->s_dev;
	sprintf (cname, "%s/%x_%lx", cache_dir, inode->i_sb->s_dev, inode->i_ino);
	DPRINT ("looking for cache file %s\n", cname);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	
	// See if file is already in cache
	rc = sys_stat64 (cname, &st);
	if (rc >= 0) {
		
		DPRINT ("cache time: %lu.%u\n", st.st_mtime, st.st_mtime_nsec);
		DPRINT ("file mod time: %ld.%ld\n", inode->i_mtime.tv_sec, inode->i_mtime.tv_nsec);
		
		// is mod time < cache time? - if so, done!
		if (inode->i_mtime.tv_sec < st.st_mtime ||
		    (inode->i_mtime.tv_sec == st.st_mtime && inode->i_mtime.tv_nsec < st.st_mtime_nsec)) {
			DPRINT ("File is already in the cache and up to date - so done\n");
			pmtime->tv_sec = st.st_mtime;
			pmtime->tv_nsec = st.st_mtime_nsec;
			set_fs(old_fs);
			return 0;
		} else {
			// file not up to date, so we need a new version - save this old version
			sprintf (nname, "%s/%x_%lx_%lu_%u", cache_dir, inode->i_sb->s_dev, inode->i_ino, st.st_mtime, st.st_mtime_nsec);
			rc = sys_rename (cname, nname);
		}
	}

	// xxx - would a by-hash content index also be useful???  
 	
	// else add to cache 
	fd = sys_open (cname, O_CREAT|O_TRUNC|O_WRONLY, 0755);
	if (fd < 0) {
		DPRINT ("add_file_to_cache: cannot create cache file %s, rc=%d\n", cname, fd);
		set_fs(old_fs);
		return -1;
	}
	ofile = fget(fd);
	buffer = kmalloc (COPY_CHUNK, GFP_KERNEL);
	if (buffer == NULL) {
		printk ("add_file_to_cache: cannot allocate copy buffer\n");
		sys_close (fd);
		fput (ofile);
		set_fs(old_fs);
		return -ENOMEM;
	}
 
	do {
		copyed = vfs_read(vm_file, buffer, COPY_CHUNK, &ipos);
		if (copyed > 0) {
			rc = vfs_write(ofile, buffer, copyed, &opos);
			if (rc != copyed) {
				printk ("add_file_to_cache: read %d bytes but wrote %d bytes\n", copyed, rc);
				kfree (buffer);
				fput (ofile);
				sys_close (fd);
				rc = sys_unlink (cname);
				if (rc < 0) printk ("add_file_to_cache: cannot delete cache file on error\n");
				set_fs(old_fs);
				return -EIO;
			}
		}
	} while (copyed > 0);

	rc = sys_stat64 (cname, &st);
	if (rc < 0) printk ("add_file_to_cache: stat on newly created cache file failed, rc = %d\n", rc);
	pmtime->tv_sec = st.st_mtime;
	pmtime->tv_nsec = st.st_mtime_nsec;

	kfree(buffer);
	fput(ofile);
	if (sys_close (fd) < 0) printk ("add_file_to_cache: sys_close failed?\n");
	set_fs(old_fs);

	return 0;
}

int get_cache_file_name (char* cname, dev_t dev, u_long ino, struct timespec mtime)
{
	mm_segment_t old_fs;
	struct stat64 st;
	int rc;

	// check if most recent cache file is still valid
	sprintf (cname, "%s/%x_%lx", cache_dir, dev, ino);
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	
	rc = sys_stat64 (cname, &st);
	if (rc < 0) {
		printk ("get_cache_file_name: cannot stat cache file, rc=%d\n", rc);
		set_fs(old_fs);
		return -ENOENT;
	}

	DPRINT ("cache time: %lu.%u\n", st.st_mtime, st.st_mtime_nsec);
	DPRINT ("replay mod time: %ld.%ld\n", mtime.tv_sec, mtime.tv_nsec);
	
	if (st.st_mtime != mtime.tv_sec || st.st_mtime_nsec != mtime.tv_nsec) {
		sprintf (cname, "%s/%x_%lx_%lu_%lu", cache_dir, dev, ino, mtime.tv_sec, mtime.tv_nsec);
	}
	set_fs(old_fs);

	return 0;
}

int open_cache_file (dev_t dev, u_long ino, struct timespec mtime, int flags)
{
	char cname[CACHE_FILENAME_SIZE];
	mm_segment_t old_fs;
	struct stat64 st;
	int fd, rc;

        // check if most recent cache file is still valid
	sprintf (cname, "%s/%x_%lx", cache_dir, dev, ino);
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	
	rc = sys_stat64 (cname, &st);
	if (rc < 0) {
		printk ("open_cache_file: cannot stat cache file, rc=%d\n", rc);
		set_fs(old_fs);
		return -ENOENT;
	}

	DPRINT ("cache time: %lu.%u\n", st.st_mtime, st.st_mtime_nsec);
	DPRINT ("replay mod time: %ld.%ld\n", mtime.tv_sec, mtime.tv_nsec);
	
	if (st.st_mtime == mtime.tv_sec && st.st_mtime_nsec == mtime.tv_nsec) {
		// if so, open it and return
		DPRINT ("opening cache file %s\n", cname);
		fd = sys_open (cname, flags, 0);
	} else {
		// otherwise, open a past versio
		sprintf (cname, "%s/%x_%lx_%lu_%lu", cache_dir, dev, ino, mtime.tv_sec, mtime.tv_nsec);
		DPRINT ("opening cache file %s\n", cname);
		fd = sys_open (cname, flags, 0);
	}
	if (fd < 0) printk ("open_cache_file: cannot open cache file %s, rc=%d\n", cname, fd);

	return fd;
}

int open_mmap_cache_file (dev_t dev, u_long ino, struct timespec mtime, int is_write)
{
	char cname[CACHE_FILENAME_SIZE], tname[CACHE_FILENAME_SIZE];
	mm_segment_t old_fs;
	struct stat64 st;
	int fd, tfd, rc, copyed;
	struct file* tfile, *cfile;
	loff_t ipos = 0, opos = 0;
	static u_long counter = 0;
	char* buffer;

        // check if most recent cache file is still valid
	sprintf (cname, "%s/%x_%lx", cache_dir, dev, ino);
	
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	
	rc = sys_stat64 (cname, &st);
	if (rc < 0) {
		printk ("open_cache_file: cannot stat cache file, rc=%d\n", rc);
		set_fs(old_fs);
		return -ENOENT;
	}

	DPRINT ("cache time: %lu.%u\n", st.st_mtime, st.st_mtime_nsec);
	DPRINT ("replay mod time: %ld.%ld\n", mtime.tv_sec, mtime.tv_nsec);
	
	if (st.st_mtime == mtime.tv_sec && st.st_mtime_nsec == mtime.tv_nsec) {
		// if so, open it and return
		fd = sys_open (cname, O_RDONLY, 0);
	} else {
		// otherwise, open a past versio
		sprintf (cname, "%s/%x_%lx_%lu_%lu", cache_dir, dev, ino, mtime.tv_sec, mtime.tv_nsec);
		fd = sys_open (cname, O_RDONLY, 0);
	}
	if (fd < 0) printk ("open_cache_file: cannot open cache file %s, rc=%d\n", cname, fd);

	if (is_write) {
		// For writeable mmaps, we need to create a copy just for this replay
		sprintf (tname, "/tmp/replay_mmap_%lu", counter++);
		tfd = sys_open (tname, O_CREAT|O_TRUNC|O_RDWR, 0600);
		if (tfd < 0) {
			printk ("open_cache_file: cannot create temp file %s, rc=%d\n", tname, tfd);
			sys_close (fd);
			set_fs(old_fs);
			return tfd;
		}
		buffer = kmalloc (COPY_CHUNK, GFP_KERNEL);
		if (buffer == NULL) {
			printk ("add_file_to_cache: cannot allocate copy buffer\n");	
		return -ENOMEM;
		}
		cfile = fget(fd);
		tfile = fget(tfd);
		do {
			copyed = vfs_read (cfile, buffer, COPY_CHUNK, &ipos);
			if (copyed > 0) {
				rc = vfs_write (tfile, buffer, copyed, &opos);
				if (rc != copyed) {
					printk ("open_cache_file: read %d bytes but wrote %d bytes\n", copyed, rc);
					fput (tfile);
					fput (cfile);
					kfree (buffer);
					sys_close (tfd);
					sys_close (fd);
					set_fs(old_fs);
					return -EIO;
				}
			}
		} while (copyed > 0);

		fput (tfile);
		fput (cfile);
		kfree (buffer);
		sys_close (fd); // Will use temp file instead
		fd = tfd;
	}
	 
	set_fs(old_fs);

	return fd;
}
