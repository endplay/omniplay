#ifndef __REPLAYFS_KMAP_H
#define __REPLAYFS_KMAP_H

#include <linux/mm_types.h>

//#define REPLAYFS_DEBUG_MAPPINGS
#define REPLAYFS_DEBUG_PAGEALLOC

#ifdef REPLAYFS_DEBUG_PAGEALLOC
void pagealloc_print_status(struct page *page);

void __pagealloc_put(struct page *page, const char *function, int line);
void __pagealloc_get(struct page *page, const char *function, int line);

#define replayfs_pagealloc_get(X) __pagealloc_get(X, __func__, __LINE__)
#define replayfs_pagealloc_put(X) __pagealloc_put(X, __func__, __LINE__)
#else
#define pagealloc_print_status(X) 
#define replayfs_pagealloc_get(X)
#define replayfs_pagealloc_put(X)
#endif


#ifdef  REPLAYFS_DEBUG_MAPPINGS
#define replayfs_kmap(X) __replayfs_kmap(X, __func__, __LINE__)
#define replayfs_kunmap(X) __replayfs_kunmap(X, __func__, __LINE__)
void *__replayfs_kmap(struct page *page, const char *func, int line);
void __replayfs_kunmap(struct page *page, const char *func, int line);
#else
#define replayfs_kmap(X) kmap(X)
#define replayfs_kunmap(X) kunmap(X)
#endif

#if defined(REPLAYFS_DEBUG_PAGEALLOC) || defined(REPLAYFS_DEBUG_MAPPINGS)
void replayfs_kmap_init(void);
void replayfs_kmap_destroy(void);
#else
#define replayfs_kmap_init(...)
#define replayfs_kmap_destroy(...)
#endif

#endif

