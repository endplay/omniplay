#ifndef __REPLAY_MAPS_H__
#define __REPLAY_MAPS_H__

// Makes a copy of the specified file in the cache (if not already present) 
// The recgroup lock must be held when calling this function
int add_file_to_cache (struct file* vm_file, dev_t* pdev, unsigned long* pino, struct timespec* pmtime);

// Opens a cache file corresponding to the given parameters.  The caller must close the file. 
// The recgroup lock must be held when calling this function
int open_cache_file (dev_t dev, u_long ino, struct timespec mtime, int is_write);

#endif
