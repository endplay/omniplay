#include "replayfs_diskalloc.h"

#include "replayfs_btree128.h"

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/swap.h>
#include <linux/gfp.h>

//#define REPLAYFS_DISKALLOC_DEBUG

//#define REPLAYFS_DISKALLOC_ALLOC_DEBUG

#ifdef REPLAYFS_DISKALLOC_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

#ifdef REPLAYFS_DISKALLOC_ALLOC_DEBUG
#define alloc_debugk(...) printk(__VA_ARGS__)
#else
#define alloc_debugk(...)
#endif

#define WORDS_PER_PAGE (PAGE_SIZE/sizeof(unsigned int))
#define MAPPINGS_PER_PAGE (PAGE_SIZE * 8)
#define PAGE_MASK_SIZE_IN_PAGES (PAGE_ALLOC_PAGES / MAPPINGS_PER_PAGE)

atomic_t initd = {0};
struct replayfs_diskalloc replayfs_alloc;
struct replayfs_btree128_head filemap_meta_tree;

void replayfs_diskalloc_read_page_location(struct replayfs_diskalloc *alloc,
		void *buffer, loff_t page);
void replayfs_diskalloc_write_page_location(struct replayfs_diskalloc *alloc,
		void *buffer, loff_t page);

int glbl_diskalloc_init(void) {
	int ret = 0;
	int val;
	/* Run the initialization once */
	val = atomic_add_unless(&initd, 1, 1);
	if (val) {
		ret = replayfs_diskalloc_init(&replayfs_alloc);
	}

	return ret;
}

static int alloc_readpage(struct file *file, struct page *page) {
	struct inode *inode;

	void *page_addr;

	loff_t page_num;

	inode = page->mapping->host;

	/* Which page should we read from? */
	page_num = page->index * PAGE_SIZE;

	/* If the page is part of the root inode... */
	/* Copy that memory to the page */
	//SetPageUptodate(page);
	page_addr = kmap(page);
	if (page_addr) {
		/*
		printk("%s %d: Filling Page %lld\n", __func__, __LINE__,
				(loff_t)page->index*PAGE_SIZE);
		*/
		replayfs_diskalloc_read_page_location(&replayfs_alloc,
			page_addr, page_num);
	} else {
		BUG();
	}

	SetPageMappedToDisk(page);

	if (PageLocked(page)) {
		unlock_page(page);
	}

	/* deallocate the page */
	kunmap(page);

	SetPageUptodate(page);
	SetPageChecked(page);

	//debugk("%s %d: Returning success!\n", __func__, __LINE__);
	return 0;
}

int alloc_writepage(struct page *page,
		struct writeback_control *wbc) {
	struct inode *inode;
	void *page_addr = kmap(page);

	inode = page->mapping->host;

	/*
	printk("%s %d: Writing back page %lld\n", __func__, __LINE__, (loff_t)page->index *
			PAGE_SIZE);
	*/
	replayfs_diskalloc_write_page_location(&replayfs_alloc,
			page_addr, page->index * PAGE_SIZE);

	kunmap(page);

	ClearPageDirty(page);

	return 0;
}

static atomic_t gets = {0};
static atomic_t puts = {0};
static struct page *alloc_get_page(loff_t offset) {
	struct page *page;

	//pgoff_t pg_offset = offset & ~(PAGE_SIZE-1);
	pgoff_t pg_offset = offset >> PAGE_CACHE_SHIFT;

	page = alloc_page(GFP_KERNEL);
	BUG_ON(IS_ERR(page));
	BUG_ON(page == NULL);
	/* Make sure we read in the data... */
	ClearPageUptodate(page);
	//page = read_mapping_page(buf_inode->i_mapping, pg_offset, NULL);

	page->index = pg_offset;

	/*
	printk("%s %d: Allocating page %lld\n", __func__, __LINE__, PAGE_SIZE *
			(loff_t)page->index);
	*/

	if (!PageChecked(page) || !PageUptodate(page)) {
		alloc_readpage(NULL, page);
	}

	atomic_inc(&gets);

	return page;
}

void replayfs_diskalloc_sync_page(struct replayfs_diskalloc *alloc,
		struct page *page) {
	if (PageDirty(page)) {
		/*
		printk("%s %d: Writing back page %lld\n", __func__, __LINE__,
				(loff_t)page->index * PAGE_SIZE);
		*/
		alloc_writepage(page, NULL);
	}
}

static void alloc_put_page(struct page *page) {
	if (PageDirty(page)) {
		/*
		printk("%s %d: Writing back page %lld\n", __func__, __LINE__,
				(loff_t)page->index * PAGE_SIZE);
		*/
		alloc_writepage(page, NULL);
	}

	if (PageLocked(page)) {
		unlock_page(page);
	}

	//debugk("%s %d: Page dirty status of %lu is %d\n", __func__, __LINE__, page->index, PageDirty(page));

	/* FIXME: Free page */
	/*
	printk("%s %d: Freeing page %lld\n", __func__, __LINE__,
			(loff_t)page->index * PAGE_SIZE);
	*/
	atomic_inc(&puts);
	__free_page(page);

	//BUG_ON(atomic_read(&gets) > atomic_read(&puts)+10);
	//page_cache_release(page);
}

static int create_diskalloc(struct replayfs_diskalloc *alloc) {
	struct page *page;

	loff_t index;

	int ret = 0;
	int i;
	mm_segment_t old_fs;

	/* ensure the file is truncated */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	sys_truncate(REPLAYFS_DISK_FILE, 0);

	alloc->filp = filp_open(REPLAYFS_DISK_FILE, O_RDWR | O_CREAT, 0777);
	if (IS_ERR(alloc->filp)) {
		ret =  PTR_ERR(alloc->filp);
		debugk("%s %d: Error, couldn't open the allocation file (%d)!\n", __func__,
				__LINE__, ret);
		goto out;
	}

	/* Initialize the free page map */
	for (i = 0; i < PAGE_MASK_SIZE_IN_PAGES; i++) {
		char *page_addr;

		page = alloc_get_page(i/8);
		page_addr = kmap(page);

		page_addr[i/8] |= 1<<(i%8);

		//mark_page_accessed(page);
		SetPageDirty(page);

		kunmap(page);
		alloc_put_page(page);
	}

	page = replayfs_diskalloc_alloc_page(alloc);

	debugk("%s %d: page->index is %lu, PAGE_ALLOC_PAGES is %d\n", __func__,
			__LINE__, page->index, PAGE_ALLOC_PAGES/(PAGE_SIZE*8));
	BUG_ON(page->index != PAGE_ALLOC_PAGES/(PAGE_SIZE*8));

	index = (loff_t)page->index * PAGE_SIZE;

	replayfs_diskalloc_put_page(alloc, page);

	//printk("%s %d: Creating diskalloc tree at %lld\n", __func__, __LINE__, index);
	replayfs_btree128_create(&filemap_meta_tree, alloc, index);

out:
	set_fs(old_fs);
	return ret;
}

static int init_diskalloc(struct replayfs_diskalloc *alloc) {
	int ret = 0;

	ret = create_diskalloc(alloc);
	if (ret) {
		goto out;
	}

	alloc->last_free_page_word = 0;

out:
	return ret;
}

static int read_diskalloc(struct replayfs_diskalloc *alloc) {
	int ret = 0;

	/* 
	 * Not sure if I need to do anything here... probably initialize the 
	 *     lru lists n stuff
	 */

	alloc->last_free_page_word = 0;

	/*
	printk("%s %d: Reading the diskalloc tree from %lld\n", __func__, __LINE__,
			(loff_t)PAGE_ALLOC_PAGES/8);
			*/
	replayfs_btree128_init(&filemap_meta_tree, alloc, (loff_t)PAGE_ALLOC_PAGES/8);

	return ret;
}

int replayfs_diskalloc_init(struct replayfs_diskalloc *alloc) {
	int ret;

	debugk("%s %d: Initing %p\n", __func__, __LINE__, &alloc->lock);
	mutex_init(&alloc->lock);

	alloc->filp = filp_open(REPLAYFS_DISK_FILE, O_RDWR, 0777);

	debugk("%s %d: Diskalloc init opened the disk file with return of %p\n",
			__func__, __LINE__, alloc->filp);
	if (IS_ERR(alloc->filp)) {
		ret = init_diskalloc(alloc);
	} else {
		ret = read_diskalloc(alloc);
	}

	return ret;
}

void replayfs_diskalloc_destroy(struct replayfs_diskalloc *alloc) {
	filp_close(alloc->filp, NULL);

	mutex_destroy(&alloc->lock);
}

static loff_t first_free_page(struct replayfs_diskalloc *alloc) {
	loff_t ret = -1;
	struct page *page;
	int *used_page_map;
	int offset;

	/* Scan for the first free page */
	/* Get the page of our value */
	ret = (loff_t)alloc->last_free_page_word * 32;
	page = alloc_get_page((loff_t)alloc->last_free_page_word * sizeof(unsigned int));
	debugk("%s %d: Checking page %lu\n", __func__, __LINE__, page->index);

	offset = alloc->last_free_page_word % (PAGE_SIZE / sizeof(unsigned int));
	debugk("%s %d: Offset %d\n", __func__, __LINE__, offset);

	used_page_map = kmap(page);

	while ((loff_t)page->index < PAGE_ALLOC_SIZE / PAGE_SIZE) {
		if (offset * sizeof(unsigned int) == PAGE_SIZE) {
			struct page *old_page = page;
			offset = 0;
			page = alloc_get_page((old_page->index + 1) * PAGE_SIZE);
			kunmap(old_page);
			alloc_put_page(old_page);
			used_page_map = kmap(page);
		}

		debugk("%s %d: offset is %d\n", __func__, __LINE__, offset);
		debugk("%s %d: checking %u for zeros\n", __func__, __LINE__,
				used_page_map[offset]);

		if (~used_page_map[offset] != 0) {

			/* __builtin_clz == find the offset of the msb(it) != 0 */
			ret = ((page->index * PAGE_SIZE) + offset) * 32 +
				(__builtin_ctz(~used_page_map[offset]));

			/*
			alloc->last_free_page_word = offset + 
				(page->index * PAGE_SIZE / sizeof(unsigned int));
				*/
			alloc->last_free_page_word = ret / (8 * sizeof(unsigned int));

			used_page_map[offset] |= 1 << (__builtin_ctz(~used_page_map[offset]));
			mark_page_accessed(page);
			SetPageDirty(page);
			//__set_page_dirty_nobuffers(page);
			//TestSetPageWriteback(page);

			break;
		}

		offset++;
	}

	kunmap(page);
	alloc_put_page(page);

	debugk("%s %d: returning %lld\n", __func__, __LINE__, ret);
	return ret;
}

void mark_free(struct replayfs_diskalloc *alloc, loff_t index) {
	/* The word offset of this bit */
	loff_t word = (index / 32) % WORDS_PER_PAGE;
	struct page *page = alloc_get_page(index/MAPPINGS_PER_PAGE);
	unsigned int *used_page_map = kmap(page);

	/* K, now that we have the page, mark the offset as read */
	used_page_map[word] &= ~(1 << (index & 0x1F));

	mark_page_accessed(page);
	SetPageDirty(page);
	//__set_page_dirty_nobuffers(page);
	//TestSetPageWriteback(page);

	kunmap(page);
	alloc_put_page(page);
}

/*static*/ void diskalloc_free_page(struct replayfs_diskalloc *alloc,
		struct page *page) {
	debugk("%s %d: UNIMPLMENTED!!!\n", __func__, __LINE__);
}

loff_t replayfs_diskalloc_alloc_page_idx(struct replayfs_diskalloc *alloc) {
	loff_t page_idx;

	page_idx = first_free_page(alloc);

	return page_idx;
}

unsigned long max_page = 0;

struct page *replayfs_diskalloc_alloc_page(struct replayfs_diskalloc *alloc) {
	struct page *page;
	loff_t page_idx;
	/* Magic here */
	/* Okay, allocation policy, get the next page from the first extent */
	glbl_diskalloc_init();

	page = ERR_PTR(-ENOMEM);
	
	debugk("%s %d: Locking %p\n", __func__, __LINE__, &alloc->lock);
	/* Lock the diskalloc */
	mutex_lock(&alloc->lock);

	/* Find the first free page */
	page_idx = first_free_page(alloc);
	debugk("%s %d: Got page_idx of %lld\n", __func__, __LINE__, page_idx);
	if (page_idx > 0) {
		/* ask the extent for a  page */
		debugk("%s %d: Alloc/Getting page: %lld\n", __func__, __LINE__, page_idx);
		page = alloc_get_page(page_idx * PAGE_SIZE);
		debugk("%s %d: Alloc/Got page: %lu\n", __func__, __LINE__, page->index);

		SetPageUptodate(page);
	}

	BUG_ON(page_idx < max_page);
	max_page = page_idx;

	mutex_unlock(&alloc->lock);

	return page;
}

void replayfs_diskalloc_free_page(struct replayfs_diskalloc *alloc,
		struct page *page) {
	glbl_diskalloc_init();

	mutex_lock(&alloc->lock);

	/* Undo the magic */
	mark_free(alloc, page->index * PAGE_SIZE);

	alloc_put_page(page);

	mutex_unlock(&alloc->lock);
}

struct page *replayfs_diskalloc_get_page(struct replayfs_diskalloc *alloc,
		loff_t page) {
	struct page *ret;
	/* Just return the page at the spot */

	glbl_diskalloc_init();

	ret = alloc_get_page(page);

	return ret;
}

void replayfs_diskalloc_read_page_location(struct replayfs_diskalloc *alloc,
		void *buffer, loff_t page) {
	struct file *filp;
	loff_t pos;
	int nread;
	mm_segment_t old_fs;

	pos = page;

	glbl_diskalloc_init();
	filp = alloc->filp;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	debugk("%s %d: Args to vfs_read are %p, %p, PAGE_SIZE and pos of %p (%lld)\n", 
			__func__, __LINE__, filp, buffer, &pos, pos);
	nread = vfs_read(filp, buffer, PAGE_SIZE, &pos);

	set_fs(old_fs);

	debugk("%s %d: nread is %d\n", __func__, __LINE__, nread);
	BUG_ON(nread < 0);

	if (nread < PAGE_SIZE) {
		memset(buffer + nread, 0, PAGE_SIZE - nread);
		nread = PAGE_SIZE - nread;
	}

	BUG_ON(nread != PAGE_SIZE);
}

void replayfs_diskalloc_write_page_location(struct replayfs_diskalloc *alloc,
		void *buffer, loff_t page) {
	struct file *filp;
	int nwritten;
	mm_segment_t old_fs;
	loff_t pos;

	glbl_diskalloc_init();

	filp = alloc->filp;

	/* Which page should we read from */
	pos = page;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	nwritten = vfs_write(filp, buffer, PAGE_SIZE, &pos);

	set_fs(old_fs);
}

void replayfs_diskalloc_put_page(struct replayfs_diskalloc *alloc,
		struct page *page) {
	alloc_put_page(page);
}

