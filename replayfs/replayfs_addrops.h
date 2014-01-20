#ifndef __REPLAYFS_ADDROPS_H__
#define __REPLAYFS_ADDROPS_H__

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>

#define ALLOC_BLOCK_SIZE ((PAGE_SIZE-8)/sizeof(char *))

struct page_alloc_block {
	int num_blocks;
	char *blocks[ALLOC_BLOCK_SIZE];
	struct page_alloc_block *next_block;
};

struct page_alloc {
	int num_pages;
	struct page_alloc_block *block;
};

int glbl_page_alloc_init(void);
void glbl_page_alloc_destroy(void);

int page_alloc_read_user(struct page_alloc *alloc, void __user *buff,
		loff_t offset, loff_t size);
int page_alloc_read(struct page_alloc *alloc, void *buff,
		loff_t offset, loff_t size);

void *page_alloc_get_page(struct page_alloc *alloc, int n);
void page_alloc_put_page(struct page_alloc *alloc, int n);
int page_alloc_read(struct page_alloc *alloc, void *buff, loff_t offset,
		loff_t size);

#endif
