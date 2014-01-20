#ifndef __REPLAYFS_ADDROPS_H__
#define __REPLAYFS_ADDROPS_H__

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>

/* 
 * Causes the FS contents to only be stored in ram, allowing for easy debugging
 * and no permanent disk image
 */
/* #define RAM_ONLY */

/* FIXME: This is hacky! */
/* #define PREFIX_STRING "/home/ddevec/replayfs/replayfs/data_dir" */
#define PREFIX_STRING "/home/replayfs_data_dir"

#define ALLOC_BLOCK_SIZE ((PAGE_SIZE-8)/sizeof(char *))

struct ram_page_alloc {
	int num_pages;
	struct page_alloc_block *block;
};

struct disk_page_alloc {
	int alloc_num;
	struct list_head page_list;
	struct file *backend_file;
	/*
	int fd;
	char *name;
	*/
};

#ifdef RAM_ONLY
typedef struct ram_page_alloc page_alloc_t;
#else
typedef struct disk_page_alloc page_alloc_t;
#endif

int glbl_page_alloc_init(void);
void glbl_page_alloc_destroy(void);

int page_alloc_read_user(page_alloc_t *alloc, void __user *buff,
		loff_t offset, loff_t size);
int page_alloc_read(page_alloc_t *alloc, void *buff,
		loff_t offset, loff_t size);

int page_alloc_write(page_alloc_t *alloc, void *buff, loff_t offset,
		loff_t size);

void *page_alloc_get_page(page_alloc_t *alloc, int n);
void page_alloc_put_page(page_alloc_t *alloc, void *page, int n);
void page_alloc_put_page_clean(page_alloc_t *alloc, void *page, int n);

void page_alloc_sync(page_alloc_t *alloc, void *page, int n);

int replayfs_page_alloc_init(page_alloc_t *alloc, const char *name);
void replayfs_page_alloc_destroy(page_alloc_t *alloc);
void replayfs_page_alloc_delete(page_alloc_t *alloc);

#ifndef RAM_ONLY
int ram_page_alloc_read_user(struct ram_page_alloc *alloc, void __user *buff,
		loff_t offset, loff_t size);
int ram_page_alloc_read(struct ram_page_alloc *alloc, void *buff,
		loff_t offset, loff_t size);

int ram_page_alloc_write(struct ram_page_alloc *alloc, void *buff, loff_t offset,
		loff_t size);

void *ram_page_alloc_get_page(struct ram_page_alloc *alloc, int n);
void ram_page_alloc_put_page(struct ram_page_alloc *alloc, void *page, int n);

int ram_replayfs_page_alloc_init(struct ram_page_alloc *alloc, const char *name);
void ram_replayfs_page_alloc_destroy(struct ram_page_alloc *alloc);

/* Used on initialization to initialize a replayfs_file_log read from disk */
loff_t ram_page_alloc_size(page_alloc_t *alloc);
#else
#define ram_page_alloc_read_user(...) page_alloc_read_user(__VA_ARGS__)
#define ram_page_alloc_read(...) page_alloc_read(__VA_ARGS__)
#define ram_page_alloc_write(...) page_alloc_write(__VA_ARGS__)
#define ram_page_alloc_get_page(...) page_alloc_get_page(__VA_ARGS__)
#define ram_page_alloc_put_page(...) page_alloc_put_page(__VA_ARGS__)

#define ram_replayfs_page_alloc_alloc_init(...) \
	replayfs_page_alloc_init(__VA_ARGS__)
#define ram_replayfs_page_alloc_alloc_destroy(...) \
	replayfs_page_alloc_destroy(__VA_ARGS__)
#endif

#endif
