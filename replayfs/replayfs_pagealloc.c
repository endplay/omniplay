#include "replayfs_fs.h"
#include "replayfs_dir.h"
#include "replayfs_file_log.h"
#include "replayfs_dev.h"

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/statfs.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <asm/errno.h>
#include <linux/buffer_head.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#define ALLOC_PAGE_CACHE_ASSOC 0x1000

struct kmem_cache *replayfs_page_cache;

struct kmem_cache *replayfs_pagealloc_cache;

atomic_t alloc_num;

struct replayfs_pagealloc_header {
	atomic_t refcnt;

	struct list_head cache_list;
	struct list_head alloc_list;

	int dirty;

	page_alloc_t *alloc;
	/* Unique identifier */
	int page_num;
	int alloc_num;
};

struct mutex alloc_cache_lock;
static struct list_head alloc_page_cache[ALLOC_PAGE_CACHE_ASSOC];

static unsigned int hash_page(int page_num, int alloc_num) {
	unsigned int hash;
	hash = hash_int(page_num);
	hash = hash_int(hash);
	hash ^= hash_int(alloc_num);

	return hash;
}

#define replayfs_free_page(X) free_page(((unsigned long)X))
#define replayfs_alloc_page(X) ((void *)__get_free_page(X))

/*#define REPLAYFS_PAGE_ALLOC_DEBUG*/

/*#define DEBUG_ALLOC_INIT*/

/*#define REPLAYFS_PAGE_ALLOC_ALLOC_DEBUG*/

#ifdef REPLAYFS_PAGE_ALLOC_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

#ifdef REPLAYFS_PAGE_ALLOC_ALLOC_DEBUG
#define alloc_debugk(...) printk(__VA_ARGS__)
#else
#define alloc_debugk(...)
#endif

#ifndef RAM_ONLY
#define DECL_NAME(X) ram_##X
#else
#define DECL_NAME(X) X
#endif

void page_alloc_put_page_clean(page_alloc_t *alloc, void *page, int n);

/* Used in ram version only */
struct page_alloc_block {
	int num_blocks;
	char *blocks[ALLOC_BLOCK_SIZE];
	struct page_alloc_block *next_block;
};

struct page_alloc_block *page_alloc_block_create(void) {
	struct page_alloc_block *block;

	block = replayfs_alloc_page(GFP_NOIO);

	if (block == NULL) {
		return NULL;
	}
	alloc_debugk("%s %d: Allocated page (block): %p\n", __func__, __LINE__, block);

	block->num_blocks = 0;

	/* Null out the block pointer table */
	memset(block->blocks, 0, ALLOC_BLOCK_SIZE*sizeof(char *));

	block->next_block = NULL;

	return block;
}

int DECL_NAME(replayfs_page_alloc_init)(struct ram_page_alloc *alloc, const char *name) {
	alloc->block = page_alloc_block_create();
	debugk("%s %d: Initialized ram_page_alloc at %p\n", __func__, __LINE__, alloc);
#ifdef DEBUG_ALLOC_INIT
	dump_stack();
#endif
	return (alloc->block == NULL);
}

void DECL_NAME(replayfs_page_alloc_destroy)(struct ram_page_alloc *alloc) {
	struct page_alloc_block *next;
	struct page_alloc_block *cur;
	/* Free the blocks for each allocated block */

	debugk("%s %d: Destroying ram_page_alloc %p\n", __func__, __LINE__, alloc);

	cur = alloc->block;

	while (cur != NULL) {
		int i;
		for (i = 0; i < ALLOC_BLOCK_SIZE; i++) {
			if (cur->blocks[i] != NULL) {
				replayfs_free_page(cur->blocks[i]);
				alloc_debugk("%s %d: Freed page (block): %p\n", __func__, __LINE__,
						cur->blocks[i]);
			}
		}
		next = cur->next_block;
		replayfs_free_page(cur);
		alloc_debugk("%s %d: Freed page: %p\n", __func__, __LINE__,
				cur);

		cur = next;
	}
}

struct page_alloc_block *page_alloc_get_block(struct ram_page_alloc *alloc,
		int num) {
	int i;
	struct page_alloc_block *cur;

	cur = alloc->block;
	i = 0;

	while (i < num) {
		if (cur->next_block == NULL) {
			cur->next_block = page_alloc_block_create();
			BUG_ON(cur->next_block == NULL);
		}
		cur = cur->next_block;
		i++;
	}

	return cur;
}

void *DECL_NAME(page_alloc_get_page)(struct ram_page_alloc *alloc, int n) {
	struct page_alloc_block *block;

	int block_num;
	int block_offs;

	/* Get the page at n */

	/* Figure out what block that is on */
	block_num = n / ALLOC_BLOCK_SIZE;
	block_offs = n % ALLOC_BLOCK_SIZE;

	/* Get that block (allocate it if needed) */
	/*debugk("%s calling page_alloc_get_block with %p %d\n", __func__, alloc,
	 * block_num);*/
	block = page_alloc_get_block(alloc, block_num);
	/*debugk("%s page_alloc_get_block returned %p\n", __func__, block);*/
	BUG_ON(block == NULL);

	/* If the page is not resident, allocate it */
	if (!block->blocks[block_offs]) {
		block->blocks[block_offs] =
			replayfs_alloc_page(GFP_NOIO);
		alloc_debugk("%s %d: Allocated page: %p\n", __func__, __LINE__,
				block->blocks[block_offs]);

		BUG_ON(block->blocks[block_offs] == NULL);
	}

	/*debugk("%s returning %p\n", __func__, block->blocks[block_offs]);*/
	return block->blocks[block_offs];
}

int DECL_NAME(page_alloc_read_user)(struct ram_page_alloc *alloc, void __user *buff,
		loff_t offset, loff_t size) {
	char *cbuff;
	int i;

	loff_t first_page;
	loff_t last_page;
	loff_t num_pages;
	loff_t offset_addr;
	loff_t last_addr;

	int page_offs;

	first_page = offset / PAGE_SIZE;
	page_offs = offset % PAGE_SIZE;

	last_page = offset + size + PAGE_SIZE-1;
	last_page /= PAGE_SIZE;

	last_addr = offset+size;

	num_pages = last_page - first_page;

	cbuff = buff;
	offset_addr = 0;

	for (i = 0; i < num_pages; i++) {
		void *data;
		int num_to_read;

		num_to_read = last_addr - (offset+offset_addr);

		if (num_to_read > PAGE_SIZE - page_offs) {
			num_to_read = PAGE_SIZE - page_offs;
		}

		data = DECL_NAME(page_alloc_get_page)(alloc, first_page+i);

		if (copy_to_user(cbuff + offset_addr, data + page_offs, num_to_read)) {
			return -EACCES;
		}

		page_offs = 0;
		offset_addr += num_to_read;

		DECL_NAME(page_alloc_put_page)(alloc, data, first_page+i);
	}

	return offset_addr;
}

/* Memcpy, must happen once per read, we'll have it happen here... */
int DECL_NAME(page_alloc_read)(struct ram_page_alloc *alloc, void *buff, loff_t offset,
		loff_t size) {
	char *cbuff;
	int i;

	loff_t first_page;
	loff_t last_page;
	loff_t num_pages;
	loff_t offset_addr;
	loff_t last_addr;

	int page_offs;

	first_page = offset / PAGE_SIZE;
	page_offs = offset % PAGE_SIZE;

	last_page = offset + size + PAGE_SIZE-1;
	last_page /= PAGE_SIZE;

	last_addr = offset+size;

	num_pages = last_page - first_page;

	cbuff = buff;
	offset_addr = 0;

	for (i = 0; i < num_pages; i++) {
		void *data;
		int num_to_read;

		num_to_read = last_addr - (offset+offset_addr);

		if (num_to_read > PAGE_SIZE - page_offs) {
			num_to_read = PAGE_SIZE - page_offs;
		}

		data = DECL_NAME(page_alloc_get_page)(alloc, first_page+i);

		memcpy(cbuff + offset_addr, data + page_offs, num_to_read);

		page_offs = 0;
		offset_addr += num_to_read;

		DECL_NAME(page_alloc_put_page)(alloc, data, first_page+i);
	}

	return offset_addr;
}

int DECL_NAME(page_alloc_write_user)(struct ram_page_alloc *alloc, void *buff, loff_t offset,
		loff_t size) {
	char *cbuff;
	int i;

	loff_t first_page;
	loff_t last_page;
	loff_t num_pages;
	loff_t offset_addr;
	loff_t last_addr;

	int page_offs;

	first_page = offset / PAGE_SIZE;
	page_offs = offset % PAGE_SIZE;

	last_page = offset + size + PAGE_SIZE-1;
	last_page /= PAGE_SIZE;

	last_addr = offset+size;

	num_pages = last_page - first_page;

	cbuff = buff;
	offset_addr = 0;

	for (i = 0; i < num_pages; i++) {
		void *data;
		int num_to_read;

		num_to_read = offset+offset_addr - last_addr;
		if (num_to_read > PAGE_SIZE - page_offs) {
			num_to_read = PAGE_SIZE - page_offs;
		}

		data = DECL_NAME(page_alloc_get_page)(alloc, first_page+i);
		if (copy_to_user(data+page_offs, cbuff + offset_addr, num_to_read)) {
			return -EACCES;
		}

		page_offs = 0;
		offset_addr += num_to_read;

		DECL_NAME(page_alloc_put_page)(alloc, data, first_page+i);
	}

	return offset_addr;
}

int DECL_NAME(page_alloc_write)(struct ram_page_alloc *alloc, void *buff, loff_t offset,
		loff_t size) {
	char *cbuff;
	int i;

	loff_t first_page;
	loff_t last_page;
	loff_t num_pages;
	loff_t offset_addr;
	loff_t last_addr;

	int page_offs;

	first_page = offset / PAGE_SIZE;
	page_offs = offset % PAGE_SIZE;

	last_page = offset + size + PAGE_SIZE-1;
	last_page /= PAGE_SIZE;

	last_addr = offset+size;

	num_pages = last_page - first_page;

	cbuff = buff;
	offset_addr = 0;

	for (i = 0; i < num_pages; i++) {
		void *data;
		int num_to_read;

		debugk("%s %d: offset: %lld, offset_addr: %lld, last_addr: %lld\n",
				__func__, __LINE__, offset, offset_addr, last_addr);
		num_to_read = last_addr - (offset+offset_addr);
		if (num_to_read > PAGE_SIZE - page_offs) {
			num_to_read = PAGE_SIZE - page_offs;
		}

		debugk("%s %d: num to write: %d\n", __func__, __LINE__, num_to_read);

		data = DECL_NAME(page_alloc_get_page)(alloc, first_page+i);
		memcpy(data+page_offs, cbuff + offset_addr, num_to_read);

		page_offs = 0;
		debugk("%s %d: offset_addr: %lld\n", __func__, __LINE__, offset_addr);
		offset_addr += num_to_read;
		debugk("%s %d: offset_addr after update: %lld\n", __func__, __LINE__, offset_addr);

		DECL_NAME(page_alloc_put_page)(alloc, data, first_page+i);
	}

	debugk("%s %d: offset_addr before return: %lld\n", __func__, __LINE__, offset_addr);
	return offset_addr;
}

/* For our current implementation, do nothin */
void DECL_NAME(page_alloc_put_page)(struct ram_page_alloc *alloc, void *data, int n) {
}

#ifndef RAM_ONLY
int glbl_page_alloc_init(void) {
	int i;

	atomic_set(&alloc_num, 0);

	mutex_init(&alloc_cache_lock);

	for (i = 0; i < ALLOC_PAGE_CACHE_ASSOC; i++) {
		INIT_LIST_HEAD(&alloc_page_cache[i]);
	}

	replayfs_page_cache = kmem_cache_create("replayfs_page_cache",
				PAGE_SIZE, 0, 0, NULL);

	if (replayfs_page_cache == NULL) {
		return -1;
	}

	replayfs_pagealloc_cache = kmem_cache_create("replayfs_pagealloc_cache",
				PAGE_SIZE + sizeof(struct replayfs_pagealloc_header), 0, 0, NULL);

	if (replayfs_pagealloc_cache == NULL) {
		kmem_cache_destroy(replayfs_page_cache);
		return -1;
	}

	return 0;
}

void glbl_page_alloc_destroy(void) {
	/* ??? */
	/* Profit */

	if (replayfs_page_cache) {
		kmem_cache_destroy(replayfs_page_cache);
	}

	if (replayfs_pagealloc_cache) {
		kmem_cache_destroy(replayfs_pagealloc_cache);
	}
}

static void *pagealloc_cache_page_get(page_alloc_t *alloc, int page_num) {
	unsigned int hash;
	struct replayfs_pagealloc_header *header;
	char *data;


	hash = hash_page(page_num, alloc->alloc_num) % ALLOC_PAGE_CACHE_ASSOC;

	debugk("%s %d: Searching for page {%d %d} (hash 0x%X) \n",
			__func__, __LINE__, alloc->alloc_num, page_num, hash);

	mutex_lock(&alloc_cache_lock);
	list_for_each_entry(header, &alloc_page_cache[hash], cache_list) {
		debugk("%s %d: Found a header with {%d, %d} (address %p)\n",
				__func__, __LINE__, header->page_num, header->alloc_num, header);
		if (header->page_num == page_num && header->alloc_num == alloc->alloc_num) {
			atomic_inc(&header->refcnt);
			mutex_unlock(&alloc_cache_lock);

			debugk("%s %d: Found page in cache, returning page with header %p\n",
					__func__, __LINE__, header);

			data = (char *)(header);
			data += sizeof(struct replayfs_pagealloc_header);

			alloc_debugk("%s %d: Got page: %p (refcnt %d)\n", __func__, __LINE__,
					header, atomic_read(&header->refcnt));

			return data;
		}
	}

	debugk("%s %d: Page not found :(\n", __func__, __LINE__);
	return NULL;
}

static void *pagealloc_cache_page_create(page_alloc_t *alloc, int page_num) {
	unsigned int hash;
	struct replayfs_pagealloc_header *header;
	char *data;

	hash = hash_page(page_num, alloc->alloc_num) % ALLOC_PAGE_CACHE_ASSOC;
	/* allocation not found... make a new one */
	data = kmem_cache_alloc(replayfs_pagealloc_cache, GFP_NOIO);
	if (data == NULL) {
		return NULL;
	}

	header = (void *)data;

	debugk("%s %d: Creating page {%d, %d} with header %p\n",
			__func__, __LINE__, alloc->alloc_num, page_num, header);

	data += sizeof(struct replayfs_pagealloc_header);

	list_add(&header->alloc_list, &alloc->page_list);
	debugk("%s %d: inserting page into cache at 0x%X\n", __func__, __LINE__, hash);
	list_add(&header->cache_list, &alloc_page_cache[hash]);

	/* 2, 1 for the returned value, 2 for the one in cache_list */
	atomic_set(&header->refcnt, 2);
	mutex_unlock(&alloc_cache_lock);

	header->dirty = 0;

	header->alloc_num = alloc->alloc_num;
	header->page_num = page_num;

	header->alloc = alloc;


	alloc_debugk("%s %d: Alloc'd page: %p (refcnt %d)\n", __func__, __LINE__,
			header, atomic_read(&header->refcnt));

	return data;
}

static void pagealloc_page_put(struct replayfs_pagealloc_header *header) {
	alloc_debugk("%s %d: Put page called on header %p (refcnt before dec %d)\n",
			__func__, __LINE__, header, atomic_read(&header->refcnt));
	if (atomic_dec_and_test(&header->refcnt)) {

		if (header->dirty) {
			mm_segment_t old_fs;
			loff_t offs;
			void *data;
			int nwritten;

			debugk("%s %d: Page dirty, writing\n", __func__, __LINE__);

			offs = header->page_num * PAGE_SIZE;

			data = header+1;

			old_fs = get_fs();
			set_fs(KERNEL_DS);

			nwritten = vfs_write(header->alloc->backend_file, data, PAGE_SIZE, &offs);

			set_fs(old_fs);

			/* We should write it all... I hope */
			BUG_ON(nwritten != PAGE_SIZE);
		}

		alloc_debugk("%s %d: Freeing page %p\n", __func__, __LINE__, header);
		kmem_cache_free(replayfs_pagealloc_cache, header);
	}
}

int page_alloc_read_user(page_alloc_t *alloc, void __user *buff,
		loff_t offset, loff_t size) {
	int ret;

	if (!access_ok(VERIFY_WRITE, buff, size)) {
		return -EACCES;
	}

	ret = page_alloc_read(alloc, (void *)buff, offset, size);

	return ret;
}

/* Need to break it into page operations... ugh */
int page_alloc_read(page_alloc_t *alloc, void *buff,
		loff_t offset, loff_t size) {
	/* Use kernel_read, so we don't check the memory buffer */
	int page_of_data;
	int offset_in_page;
	int ntowrite;
	int nwritten;

	nwritten = 0;
	while (size) {
		void *page;
		page_of_data = offset / PAGE_SIZE;
		offset_in_page = offset % PAGE_SIZE;

		ntowrite = PAGE_SIZE - offset_in_page;
		if (ntowrite > size) {
			ntowrite = size;
		}

		page = page_alloc_get_page(alloc, page_of_data);

		if (page == NULL) {
			break;
		}

		memcpy(buff + nwritten, page + offset_in_page, ntowrite);

		page_alloc_put_page_clean(alloc, page, page_of_data);

		size -= ntowrite;
		nwritten += ntowrite;
	}

	return nwritten;
}

int page_alloc_write_user(page_alloc_t *alloc, void __user *buff, loff_t offset,
		loff_t size) {
	int ret;
	if (!access_ok(VERIFY_READ, buff, size)) {
		return -EACCES;
	}

	ret = page_alloc_write(alloc, (void *)buff, offset, size);

	return ret;
}

int page_alloc_write(page_alloc_t *alloc, void *buff, loff_t offset,
		loff_t size) {
	/* Use kernel_read, so we don't check the memory buffer */
	int page_of_data;
	int offset_in_page;
	int ntowrite;
	int nwritten;

	nwritten = 0;
	while (size) {
		void *page;
		page_of_data = offset / PAGE_SIZE;
		offset_in_page = offset % PAGE_SIZE;

		ntowrite = PAGE_SIZE - offset_in_page;
		if (ntowrite > size) {
			ntowrite = size;
		}

		page = page_alloc_get_page(alloc, page_of_data);

		if (page == NULL) {
			break;
		}

		memcpy(page + offset_in_page, buff + nwritten, ntowrite);

		page_alloc_put_page(alloc, page, page_of_data);

		size -= ntowrite;
		nwritten += ntowrite;
	}

	return nwritten;
}

void *page_alloc_get_page(page_alloc_t *alloc, int n) {
	void *page;

	page = pagealloc_cache_page_get(alloc, n);
	if (page == NULL) {
		page = pagealloc_cache_page_create(alloc, n);

		if (page != NULL) {
			int nread;
			loff_t offs;
			mm_segment_t old_fs;

			offs = PAGE_SIZE*n;

			old_fs = get_fs();
			set_fs(KERNEL_DS);

			nread = vfs_read(alloc->backend_file, page, PAGE_SIZE, &offs);

			set_fs(old_fs);

			if (nread < PAGE_SIZE) {
				char *cpage;

				cpage = page;

				memset(cpage+nread, 0, PAGE_SIZE-nread);
			}
		}
	}

	return page;
}

void page_alloc_put_page(page_alloc_t *alloc, void *page, int n) {
	char *cbuf;

	struct replayfs_pagealloc_header *header;

	cbuf = page;

	header = (struct replayfs_pagealloc_header *)
			(cbuf - sizeof(struct replayfs_pagealloc_header));

	header->dirty = 1;
	pagealloc_page_put(header);

	/*
	alloc_debugk("%s %d: Put page: %p (refcnt %d)\n", __func__, __LINE__, page,
			atomic_read(&header->refcnt));
			*/
}

void page_alloc_put_page_clean(page_alloc_t *alloc, void *page, int n) {
	char *cbuf;

	struct replayfs_pagealloc_header *header;

	cbuf = page;

	header = (struct replayfs_pagealloc_header *)
			(cbuf - sizeof(struct replayfs_pagealloc_header));

	pagealloc_page_put(header);
	/*
	alloc_debugk("%s %d: Put page: %p (refcnt %d)\n", __func__, __LINE__, page,
			atomic_read(&header->refcnt));
			*/
}

int replayfs_page_alloc_init(page_alloc_t *alloc, const char *name) {
	char *fixed_name;
	uint32_t name_hash;
	mm_segment_t old_fs;

	alloc->alloc_num = atomic_inc_return(&alloc_num);
	INIT_LIST_HEAD(&alloc->page_list);

	name_hash = full_name_hash(name, strlen(name));

	/* Ugh! */
	fixed_name = replayfs_alloc_page(GFP_NOIO);

	fixed_name[0] = '\0';

	/* Append the correct prefix to name */
	/* PREFIX_STR is constant, so we can concat in compiler, name is not */
	/* 
	 * Hash is to ease where we store the data, we can easily make subdirs if one
	 * dir is too slow... /hash%0xFF/(hash>>8)&0xFF/name
	 */
	sprintf(fixed_name, PREFIX_STRING "/%01X/%02X/%s", name_hash&0xF,
			(name_hash>>4)&0xFF, name);

	/* Open a file with the name name */
	debugk("%s %d: Attempting to open file: %s\n", __func__, __LINE__, fixed_name);

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	alloc->backend_file = filp_open(fixed_name, O_RDWR | O_CREAT, 0777);

	/*printk("%s %d: Have backend file of %p\n", __func__, __LINE__,
			alloc->backend_file);*/
#if 0
	/* If we couldn't open it because the directory didn't exist */
	if (PTR_ERR(alloc->backend_file) == -ENOENT) {
		char *dir_name = replayfs_alloc_page(GFP_NOIO);
		int error;
		struct nameidata nd;
		struct dentry *dentry;

		sprintf(dir_name, PREFIX_STRING "/%01X", name_hash&0xF);

		error = path_lookup(dir_name, LOOKUP_PARENT, &nd);
		dentry = lookup_create(&nd, 1);
		error = PTR_ERR(dentry);
		if (IS_ERR(dentry)) {
			BUG();
		}

		error = mnt_want_write(nd.path.mnt);
		if (error) {
			BUG();
		}

	 error = vfs_mkdir(nd.path.dentry->d_inode, dentry, 0777);
	 mnt_drop_write(nd.path.mnt);

	 dput(dentry);
	 mutex_unlock(&nd.path.dentry->d_inode->i_mutex);

		/*
		rc = -EBUSY;
		while (rc) {
			rc = sys_mkdir(dir_name, 0777);
			printk("Got unexpected error of 0x%08X\n", rc);
			if (rc && rc != -EEXIST && rc != -EBUSY) {
				BUG();
			}
		}
		*/

		sprintf(dir_name, PREFIX_STRING "/%01X/%02X", name_hash&0xF, (name_hash>>4)&0xFF);

		error = path_lookup(dir_name, LOOKUP_PARENT, &nd);
		dentry = lookup_create(&nd, 1);
		error = PTR_ERR(dentry);
		if (IS_ERR(dentry)) {
			BUG();
		}

		error = mnt_want_write(nd.path.mnt);
		if (error) {
			BUG();
		}

	 error = vfs_mkdir(nd.path.dentry->d_inode, dentry, 0777);
	 mnt_drop_write(nd.path.mnt);

	 dput(dentry);
	 mutex_unlock(&nd.path.dentry->d_inode->i_mutex);

		/*
		rc = -EBUSY;
		while (rc) {
			rc = sys_mkdir(dir_name, 0777);
			printk("Got unexpected error of 0x%08X\n", rc);
			if (rc && rc != -EEXIST && rc != -EBUSY) {
				BUG();
			}
		}
		*/

		replayfs_free_page(dir_name);

		sprintf(fixed_name, PREFIX_STRING "/%01X/%02X/%s", name_hash&0xF,
				(name_hash>>4)&0xFF, name);

		alloc->backend_file = filp_open(fixed_name, O_RDWR | O_CREAT, 0777);

		printk("%s %d: New backend file of %p\n", __func__, __LINE__,
				alloc->backend_file);
	} 
#endif
	
	/*alloc->fd = replayfs_dev_open(fixed_name);*/

	set_fs(old_fs);

	if (IS_ERR(alloc->backend_file)) {
	/*if (alloc->fd < 0) {*/
		printk("%s %d: filp_open returned: %lX\n", __func__, __LINE__,
				-PTR_ERR(alloc->backend_file));
		BUG();
	}

	replayfs_free_page(fixed_name);

	/*BUG_ON(alloc->fd < 0);*/

	return 0;
}

void replayfs_page_alloc_delete(page_alloc_t *alloc) {
	/* Delete the file */
	/*
	int error;
	mutex_lock_nested(&alloc->backend_file->f_dentry->d_inode->i_mutex,
			I_MUTEX_PARENT);
	error = mnt_want_write(alloc->backend_file->f_vfsmnt);
	BUG_ON(error);
			*/
	if (vfs_unlink(alloc->backend_file->f_dentry->d_parent->d_inode,
			alloc->backend_file->f_dentry)) {
		printk("%s %d: ERROR: Unlink failure! dentry->name is %.*s\n",
				__func__, __LINE__,
				alloc->backend_file->f_dentry->d_name.len,
				alloc->backend_file->f_dentry->d_name.name);
	}
	/*
	mnt_drop_write(alloc->backend_file->f_vfsmnt);
	mutex_unlock(&alloc->backend_file->f_dentry->d_inode->i_mutex);
	*/

	replayfs_page_alloc_destroy(alloc);
}

void replayfs_page_alloc_destroy(page_alloc_t *alloc) {
	struct replayfs_pagealloc_header *header;
	struct replayfs_pagealloc_header *_tmp;
	/* Remove the entry from the cache list, and put it */
	mutex_lock(&alloc_cache_lock);
	list_for_each_entry_safe(header, _tmp, &alloc->page_list, alloc_list) {
		list_del(&header->cache_list);
		pagealloc_page_put(header);
	}
	mutex_unlock(&alloc_cache_lock);


	filp_close(alloc->backend_file, NULL);
	/*replayfs_dev_close(alloc->fd);*/
	/*replayfs_free_page(alloc->name);*/
}

#endif

