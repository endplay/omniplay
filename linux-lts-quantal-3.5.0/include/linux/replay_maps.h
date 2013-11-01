#ifndef __REPLAY_MAPS_H__
#define __REPLAY_MAPS_H__

#define CACHE_FILENAME_SIZE 64

// Makes a copy of the specified file in the cache (if not already present) 
// The recgroup lock must be held when calling this function
int add_file_to_cache (struct file* vm_file, dev_t* pdev, unsigned long* pino, struct timespec* pmtime);

// Returns the path of a cache file corresponding to the given parameters.  The caller must allocate cname
// to be a buffer of size CACHE_FILENAME_SIZE
// The recgroup lock must be held when calling this function
int get_cache_file_name (char* cname, dev_t dev, u_long ino, struct timespec mtime);

// Opens a cache file corresponding to the given parameters.  The caller must close the file. 
// The recgroup lock must be held when calling this function
int open_cache_file (dev_t dev, u_long ino, struct timespec mtime, int flags);

// Opens a cache file corresponding to the given parameters for an mmap.  The caller must close the file. 
// The recgroup lock must be held when calling this function
int open_mmap_cache_file (dev_t dev, u_long ino, struct timespec mtime, int is_write);

#endif
