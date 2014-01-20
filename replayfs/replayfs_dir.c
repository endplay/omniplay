#include "replayfs_dir.h"
#include "replayfs_fs.h"
#include "replayfs_inode.h"
#include "replayfs_log.h"

/*#define REPLAYFS_DIR_DEBUG*/

#ifdef REPLAYFS_DIR_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

#define S_SHIFT 12

static inline void dir_create(struct page *page, struct replayfs_dir *odir,
		replayfs_log_t *log, replayfs_log_inode_t *log_inode, loff_t pos,
		const char *name, int name_len, char type,
		struct replayfs_unique_id *id) {
	struct replayfs_dir *dir;

	if (test_thread_flag(TIF_REPLAY)) {
		dir = kmalloc(sizeof(struct replayfs_dir), GFP_NOFS);

		/* FIXME: should handle this */
		BUG_ON(dir == NULL);

		memcpy(dir, odir, sizeof(struct replayfs_dir));
	} else {
		dir = odir;
	}

	/* If this is a replay thread... mark the page as out of date... */

	strncpy(dir->name, name, name_len);
	dir->header.name_len = name_len;
	dir->header.type = type;
	memcpy(&dir->header.id, id,
			sizeof(struct replayfs_unique_id));

	debugk("%s %d: Dir header (%p) is {%u, %lld}\n", __func__, __LINE__,
			&dir->header.id, (unsigned int)dir->header.id.log_num,
			dir->header.id.sys_num);

	replayfs_log_add_mod(log, log_inode, dir, sizeof(struct replayfs_dir),
			pos+PAGE_SIZE);

	if (test_thread_flag(TIF_REPLAY)) {
		kfree(dir);
	}
}

static inline void dir_end(struct page *page, struct replayfs_dir *odir,
		replayfs_log_t *log, replayfs_log_inode_t *log_inode, loff_t pos) {
	size_t size;
	struct replayfs_dir *dir;

	if (test_thread_flag(TIF_REPLAY)) {
		dir = kmalloc(sizeof(struct replayfs_dir), GFP_NOFS);

		/* FIXME: should handle this */
		BUG_ON(dir == NULL);

		memcpy(dir, odir, sizeof(struct replayfs_dir));
	} else {
		dir = odir;
	}

	dir->header.name_len = -1;

	size = sizeof(struct replayfs_dir);
	debugk("%s %d: Size passed to replayfs_file_log_entry_add is %llu\n",
			__func__, __LINE__, (unsigned long long)size);
	replayfs_log_add_mod(log, log_inode, dir, size, pos+PAGE_SIZE);

	if (test_thread_flag(TIF_REPLAY)) {
		kfree(dir);
	}
}

static inline void dir_free(struct page *page, struct replayfs_dir *odir,
		replayfs_log_t *log, replayfs_log_inode_t *log_inode, loff_t pos) {
	struct replayfs_dir *dir;

	if (test_thread_flag(TIF_REPLAY)) {
		dir = kmalloc(sizeof(struct replayfs_dir), GFP_NOFS);

		/* FIXME: should handle this */
		BUG_ON(dir == NULL);

		memcpy(dir, odir, sizeof(struct replayfs_dir));
	} else {
		dir = odir;
	}


	dir->header.name_len = 0;

	replayfs_log_add_mod(log, log_inode, dir, sizeof(struct replayfs_dir),
			pos+PAGE_SIZE);

	if (test_thread_flag(TIF_REPLAY)) {
		kfree(dir);
	}
}

static inline int dir_is_free(struct replayfs_dir *dir) {
	return dir->header.name_len == 0;
}

static inline int dir_is_end(struct replayfs_dir *dir) {
	return dir->header.name_len < 0;
}

static inline int dir_pages(struct inode *dir) {
	return (dir->i_size+PAGE_CACHE_SIZE-1)>>PAGE_CACHE_SHIFT;
}

static inline int dir_matches(struct replayfs_dir *dir, const char *name,
		int name_len) {
	return (
				dir->header.name_len == name_len &&
				!strncmp(name, dir->name, name_len)
			);
}

struct replayfs_dir *replayfs_dir_find_entry(struct inode *idir,
		struct dentry *entry, struct page **entry_page, loff_t *dir_pos) {
	const char *name;
	struct replayfs_dir *ret;
	int offs;
	int npages;
	int start;
	int name_len;

	name = entry->d_name.name;
	name_len = entry->d_name.len;
	start = 0;
	offs = start;
	npages = dir_pages(idir);

	ret = NULL;

	/* Iterate through each entry on each page */
	while (offs < npages) {
		struct page *cur_page;
		struct replayfs_dir_page *dir_page;
		int i;

		cur_page = replayfs_get_page(idir, offs);
		BUG_ON(IS_ERR(cur_page));

		dir_page = (void *)page_address(cur_page);

		for (i = 0; i < REPLAYFS_DIRS_PER_PAGE; i++) {
			struct replayfs_dir *dir;
			dir = &dir_page->dirs[i];

			if (dir_is_end(dir)) {
				BUG_ON(offs+1 < npages);
				debugk("%s %d: Found end_dir at {%d, %d}\n", __func__, __LINE__,
						offs, i);
				goto out;
			}

			if (dir_is_free(dir)) {
				BUG_ON(offs+1 < npages);
				debugk("%s %d: Found free_dir at {%d, %d}\n", __func__, __LINE__,
						offs, i);
				continue;
			}

			if (dir_matches(dir, name, name_len)) {
				*entry_page = cur_page;
				*dir_pos = offs * PAGE_SIZE + i * sizeof(struct replayfs_dir);
				ret = dir;
				goto out;
			}
		}


		replayfs_put_page(cur_page);

		offs++;
	}

out:
	return ret;
}

static inline void replayfs_mark_inode_dirty(struct inode *inode) {
	if (!test_thread_flag(TIF_REPLAY)) {
		mark_inode_dirty(inode);
	}
}

int replayfs_dir_delete_entry(struct replayfs_dir *dir, struct page *page,
		loff_t dir_pos, replayfs_log_t *dir_log, replayfs_log_inode_t *dir_log_inode) {
	struct inode *inode;
	int err;

	err = 0;

	inode = page->mapping->host;

	dir_free(page, dir, dir_log, dir_log_inode, dir_pos);

	if (!test_thread_flag(TIF_REPLAY)) {
		inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	}

	replayfs_mark_inode_dirty(inode);

	replayfs_put_page(page);
	return err;
}

int replayfs_dir_is_empty(struct inode *inode) {
	return inode->i_size = 3*sizeof(struct replayfs_dir);
}

int replayfs_dir_readdir(struct file *filp, void *dirent, filldir_t filldir) {
	loff_t pos;
	struct replayfs_dir *ret;
	int offs;
	int npages;
	int start;

	struct inode *idir;

	idir = filp->f_path.dentry->d_inode;

	pos = filp->f_pos;

	start = 0;
	offs = start;
	npages = dir_pages(idir);

	ret = NULL;

	debugk("In %s: pos %d, npages: %d (idir->i_size %lld)\n", __func__, (int)pos,
			npages, idir->i_size);
	/* If we're already past the end of the directory return */
	if (pos >= idir->i_size - sizeof(struct replayfs_dir)) {
		return 0;
	}

	/* Iterate through each entry on each page */
	while (offs < npages) {
		struct page *cur_page;
		struct replayfs_dir_page *dir_page;
		int i;

		debugk("%s scanning page %d\n", __func__, offs);
		cur_page = replayfs_get_page(idir, offs);
		BUG_ON(IS_ERR(cur_page));

		dir_page = page_address(cur_page);

		for (i = 0; i < REPLAYFS_DIRS_PER_PAGE; i++) {
			struct replayfs_dir *dir;
			struct inode *entry_inode;

			dir = &dir_page->dirs[i];

			if (dir_is_end(dir)) {
				debugk("%s enddir found at %d:%d\n", __func__, offs, i);

				filp->f_pos = 
					((offs<<PAGE_CACHE_SHIFT) + (sizeof(struct replayfs_dir) * i));

				BUG_ON(offs+1 < npages);
				goto out;
			}

			if (dir_is_free(dir)) {
				debugk("%s free dir found at %d:%d\n", __func__, offs, i);
				continue;
			} 

			/* Find the ino of this directory */
			entry_inode = replayfs_iget(idir->i_sb, &dir->header.id,
					REPLAYFS_CURRENT_VERSION);

			/* Found a valid entry! */
			debugk("%s adding %.*s to dirent\n", __func__, dir->header.name_len, dir->name);
			filldir(dirent, dir->name, dir->header.name_len, 
					((offs<<PAGE_CACHE_SHIFT) + (sizeof(struct replayfs_dir) * i)),
					entry_inode->i_ino, dir->header.type);

			iput(entry_inode);
		}

		replayfs_put_page(cur_page);

		offs++;
	}

out:
	return 0;
}

static inline void replayfs_SetPageDirty(struct page *cur_page) {
	if (!test_thread_flag(TIF_REPLAY)) {
		SetPageDirty(cur_page);
	}
}

static inline void replayfs_i_size_write(struct inode *idir, loff_t new_size) {
	if (!test_thread_flag(TIF_REPLAY)) {
		i_size_write(idir, new_size);
	}
}

static int __always_inline __replayfs_dir_new_entry(struct inode *idir,
		const char *name, struct replayfs_unique_id *new_id, mode_t new_mode,
		replayfs_log_t *dir_log, replayfs_log_inode_t *dir_log_inode) {
	int ret;
	int offs;
	int npages;
	int start;

	start = 0;
	offs = start;
	npages = dir_pages(idir);

	ret = 0;

	debugk("%s starting, npages is %d i_size is %d\n", __func__, (int)npages, (int)idir->i_size);

	/* Iterate through each existing dir entry, find an unused entry */
	while (offs < npages) {
		struct page *cur_page;
		struct replayfs_dir_page *dir_page;
		int i;

		cur_page = replayfs_get_page(idir, offs);
		BUG_ON(IS_ERR(cur_page));

		dir_page = page_address(cur_page);

		for (i = 0; i < REPLAYFS_DIRS_PER_PAGE; i++) {
			struct replayfs_dir *dir;
			loff_t dir_pos;

			dir_pos = offs * PAGE_SIZE + offsetof(struct replayfs_dir_page, dirs[i]);

			dir = &dir_page->dirs[i];

			debugk("%s checking entry %d:%d len %d\n", __func__,
					offs, i, dir->header.name_len);

			/* The directory is unallocated, fill it */
			if (dir_is_free(dir)) {
				debugk("%s Creating new directroy entry %s->{%u, %lld}\n", __func__,
						name, (unsigned int)new_id->log_num,
						new_id->sys_num);
				dir_create(cur_page, dir, dir_log, dir_log_inode,
						dir_pos,
						name, strlen(name),
						new_mode >> S_SHIFT, new_id);
				replayfs_SetPageDirty(cur_page);
				goto out;
			}

			if (dir_is_end(dir)) {
				/* We hit the end of the indexing, add a new entry here */
				debugk("%s Creating new directroy entry %s->{%u, %lld}\n", __func__,
						name, (unsigned int)new_id->log_num,
						new_id->sys_num);
				dir_create(cur_page, dir, dir_log, dir_log_inode,
						dir_pos,
						name, strlen(name),
						new_mode >> S_SHIFT, new_id);
				replayfs_SetPageDirty(cur_page);

				debugk("%s Growing dir size to %d\n", __func__,
						(int)(idir->i_size + sizeof(struct replayfs_dir)));

				/* Grow the directory size */
				replayfs_i_size_write(idir, idir->i_size + sizeof(struct replayfs_dir));

				/* If this page has space, put our enddir entry here */
				if (i < REPLAYFS_DIRS_PER_PAGE-1) {
					dir = &dir_page->dirs[i+1];
					dir_end(cur_page, dir, dir_log, dir_log_inode,
							offs * PAGE_SIZE + offsetof(struct replayfs_dir_page, dirs[i+1]));
				/* Otherwise, get the next page, and put it there */
				} else {
					replayfs_put_page(cur_page);
					cur_page = replayfs_get_page(idir, offs+1);
					replayfs_SetPageDirty(cur_page);
					dir_page = page_address(cur_page);

					dir = &dir_page->dirs[0];
					dir_end(cur_page, dir, dir_log, dir_log_inode,
							offs * PAGE_SIZE + offsetof(struct replayfs_dir_page, dirs[i+1]));
				}

				goto out;
			}
		}

		replayfs_put_page(cur_page);

		offs++;
	}

	/* We should always allocate the page... I hope */
	BUG();

out:
	return ret;
}

int replayfs_dir_new_entry_external(struct inode *idir,
		const char *name, struct replayfs_unique_id *new_id, mode_t new_mode,
		replayfs_log_t *dir_log, replayfs_log_inode_t *dir_log_inode) {
	return __replayfs_dir_new_entry(idir, name, new_id,
			new_mode, dir_log, dir_log_inode);
}

/* Insert the new inode into info with name */
int replayfs_dir_new_entry(struct inode *idir,
		const char *name, struct inode *new_inode, replayfs_log_t *dir_log,
		replayfs_log_inode_t *dir_log_inode) {
	return __replayfs_dir_new_entry(idir, name, &REPLAYFS_I(new_inode)->id,
			new_inode->i_mode, dir_log, dir_log_inode);
}

struct replayfs_dir *replayfs_dir_dotdot(struct inode *node, struct page **pagep) {
	struct replayfs_dir *ret;
	struct dentry tmp;
	loff_t dir_pos;

	tmp.d_name.name = "..";
	tmp.d_name.len = 2;
	
	ret = replayfs_dir_find_entry(node, &tmp, pagep, &dir_pos);

	return ret;
}

void replayfs_dir_set_link(struct inode *dir, struct replayfs_dir *rep,
		struct page *page, struct inode *file) {
	lock_page(page);
	memcpy(&rep->header.id, &REPLAYFS_I(file)->id,
			sizeof(struct replayfs_unique_id));
	rep->header.type = file->i_mode >> S_SHIFT;
	unlock_page(page);

	replayfs_put_page(page);
}

int replayfs_dir_add_link(struct dentry *dentry, struct inode *new_inode,
		replayfs_log_t *dir_log, replayfs_log_inode_t *dir_log_inode) {
	struct inode *parent;
	struct replayfs_dir *found;

	int name_len;
	const char *name;
	struct page *dir_page;

	loff_t dir_pos;

	int err;

	parent = dentry->d_parent->d_inode;
	name = dentry->d_name.name;

	name_len = dentry->d_name.len;

	/* Check to see if this file exists in the parent */
	found = replayfs_dir_find_entry(parent, dentry, &dir_page, &dir_pos);
	if (found) {
		replayfs_put_page(dir_page);
		err = -EEXIST;
		goto out;
	}

	/* Add this directory to the parents information */
	err = replayfs_dir_new_entry(parent, dentry->d_name.name, new_inode, dir_log,
			dir_log_inode);

out:
	return err;
}

int replayfs_dir_add_nondir(struct dentry *dentry, struct inode *inode,
		replayfs_log_t *dir_log, replayfs_log_inode_t *dir_log_inode) {
	int err;

	err = replayfs_dir_add_link(dentry, inode, dir_log, dir_log_inode);
	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}

	inode_dec_link_count(inode);
	iput(inode);

	return err;
}

int replayfs_inode_by_name(struct inode *idir, struct dentry *entry,
		struct replayfs_unique_id *id) {
	struct replayfs_dir *dir;
	struct page *page;
	ino_t res;

	loff_t dir_pos;

	res = 0;

	dir = replayfs_dir_find_entry(idir, entry, &page, &dir_pos);
	if (dir) {
		replayfs_put_page(page);
		memcpy(id, &dir->header.id, sizeof(struct replayfs_unique_id));
		res = 1;
	}

	return res;
}

int replayfs_init_dir(struct inode *dir, replayfs_log_t *dir_log,
		replayfs_log_inode_t *dir_log_inode) {
	struct page *cur_page;
	struct replayfs_dir_page *dir_page;
	struct replayfs_dir *entry;

	debugk("In %s\n", __func__);

	i_size_write(dir, sizeof(struct replayfs_dir));

	cur_page = replayfs_get_page(dir, 0);
	dir_page = page_address(cur_page);
	entry = &dir_page->dirs[0];

	dir_end(cur_page, entry, dir_log, dir_log_inode, 0);

	return 0;
}

/* Allocate a new empty directory, it will only hold the . and .. entries */
int replayfs_dir_make_empty(struct inode *dir, struct inode *parent,
		replayfs_log_t *dir_log, replayfs_log_inode_t *dir_log_inode) {
	int err;

	debugk("%s calling replayfs_init_dir with dir of %p\n", __func__, dir);
	err = replayfs_init_dir(dir, dir_log, dir_log_inode);
	if (err) {
		return err;
	}

	debugk("%s calling dir_new_entry with dir of %p, . %p\n", __func__, dir, dir);
	/* Add the . and .. entries */
	if (replayfs_dir_new_entry(dir, ".", dir, dir_log, dir_log_inode)) {
		return 1;
	}

	debugk("%s calling dir_new_entry with dir of %p, .. %p\n", __func__, dir,
			parent);
	if (replayfs_dir_new_entry(dir, "..", parent, dir_log, dir_log_inode)) {
		return 1;
	}

	return 0;
}

