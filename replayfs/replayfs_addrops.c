#include "replayfs_fs.h"
#include "replayfs_dir.h"
#include "replayfs_file_log.h"
#include "replayfs_inode.h"

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
#include <linux/slab.h>

/*
#define REPLAYFS_ADDROPS_DEBUG
*/

#ifdef REPLAYFS_ADDROPS_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

/* 
 * Reads a logical page from the file 
 *     (decompresses the page from the log)
 */
int replayfs_readpage(struct file *file, struct page *page) {
	struct inode *inode;

	void *page_addr;

	int page_num;

	debugk("In %s! file: %p, page %p\n", __func__, file, page);

	inode = page->mapping->host;

	/* Which page should we read from? */
	page_num = page->index;

	/* Copy that memory to the page */
	SetPageUptodate(page);
	page_addr = kmap(page);
	if (page_addr) {
		loff_t pos;
		int nread;

		pos = page_num * PAGE_SIZE;

		debugk("%s %d: Calling replayfs_file_log_read: id {%lld, %lld} version %lld into page %p\n",
				__func__, __LINE__, REPLAYFS_I(inode)->file_log->id.log_num,
				REPLAYFS_I(inode)->file_log->id.sys_num, REPLAYFS_I(inode)->version,
				page);
		nread = replayfs_file_log_read(REPLAYFS_I(inode)->file_log,
				REPLAYFS_I(inode)->version, page_addr, PAGE_SIZE, &pos);

		BUG_ON(nread != PAGE_SIZE);
	}

	if (PageLocked(page)) {
		unlock_page(page);
	}

	/* deallocate the page */
	kunmap(page);

	return 0;
}

int replayfs_writepage(struct page *page,
		struct writeback_control *wbc) {

	/* 
	 * This is handled externally, the cache must be write-through for this system
	 * to work... the write-back cache provided by the page cache isn't sufficient
	 * by itself
	 */
#if 0
	struct inode *inode;
	struct page_alloc *alloc;

	void *page_addr;

	int page_num;

	inode = page->mapping->host;

	/* Which page should we read from */
	page_num = page->index;

	/* Get my buffer */
	file_buff = page_alloc_get_page(alloc, page_num);
	BUG_ON(file_buff == NULL);

	page_addr = kmap(page);

	/* Ugh, now need to add an entry about accessing data */

	/* overwrite my buffer with the page cache's */
	memcpy(file_buff, page_addr, PAGE_SIZE);
#endif

	ClearPageDirty(page);
	if (PageLocked(page)) {
		unlock_page(page);
	}
	kunmap(page);

	return 0;
}

void replayfs_put_page(struct page *page) {
	kunmap(page);
	page_cache_release(page);
}

struct page *replayfs_get_page(struct inode *dir, int n) {
	struct page *page;
	struct address_space *mapping;
	int i;

	/* The first page is actually a metadata page.... we ignore that */
	n++;

	mapping = dir->i_mapping;

	debugk("%s %d: Reading page from maping\n", __func__, __LINE__);
	page = read_mapping_page(mapping, n, NULL);
	debugk("%s %d: read_mapping_page returned page %p\n", __func__, __LINE__, page);

	if (!IS_ERR(page)) {
		kmap(page);
		if (!PageChecked(page)) {
			printk("%s %d: WARNING PAGE NOT CHECKED!!!\n", __func__, __LINE__);
			SetPageChecked(page);
		}
		if (PageError(page)) {
			goto fail;
		}
		debugk("%s %d: Page is %p page_addr is %p\n", __func__, __LINE__, page,
				page_address(page));
		for (i = 0; i < REPLAYFS_DIRS_PER_PAGE; i++) {
			debugk("%s %d: Dir[%d] has size %d (%.*s)\n", __func__, __LINE__, i,
					((struct replayfs_dir_page *)page_address(page))->dirs[i].header.name_len,
					((struct replayfs_dir_page *)page_address(page))->dirs[i].header.name_len,
					((struct replayfs_dir_page *)page_address(page))->dirs[i].name);
		}
	}


	return page;

fail:
	replayfs_put_page(page);
	return ERR_PTR(-EIO);
}

