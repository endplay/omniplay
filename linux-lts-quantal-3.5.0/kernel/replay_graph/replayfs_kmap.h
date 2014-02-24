#ifndef __REPLAYFS_KMAP_H
#define __REPLAYFS_KMAP_H

#include <linux/mm_types.h>

//#define REPLAYFS_DEBUG_MAPPINGS

#ifdef  REPLAYFS_DEBUG_MAPPINGS
void replayfs_kmap_init(void);
void replayfs_kmap_destroy(void);
#define replayfs_kmap(X) __replayfs_kmap(X, __func__, __LINE__)
#define replayfs_kunmap(X) __replayfs_kunmap(X, __func__, __LINE__)
void *__replayfs_kmap(struct page *page, const char *func, int line);
void __replayfs_kunmap(struct page *page, const char *func, int line);
#else
#define replayfs_kmap_init(...)
#define replayfs_kmap_destroy(...)
#define replayfs_kmap(X) kmap(X)
#define replayfs_kunmap(X) kunmap(X)
#endif

#endif

