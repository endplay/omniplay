#ifndef __REPLAYFS_FILEMAP_H
#define __REPLAYFS_FILEMAP_H

#include <linux/btree.h>
#include <linux/fs.h>

#include "replayfs_btree.h"
#include "replayfs_btree128.h"

struct replayfs_unique_id {
	loff_t log_num;
	loff_t sys_num;
	pid_t pid;
};

struct replayfs_filemap_value {
	struct replayfs_btree_value bval;

	loff_t offset;
	size_t size;
	size_t read_offset;
};

struct replayfs_filemap_entry {
	int num_elms;
	struct replayfs_filemap_value elms[0];
};

struct replayfs_filemap {
	struct mutex lock;

	/* Holds the mapping of addresses to the source of that data */
	struct replayfs_btree_head entries;
};

extern struct replayfs_diskalloc *replayfs_alloc;

int replayfs_filemap_glbl_init(void);

int replayfs_filemap_init_key (struct replayfs_filemap *map,
		struct replayfs_diskalloc *alloc, struct replayfs_btree128_key *key);

int replayfs_filemap_exists(struct file *filp);
/* Reinitialize with the location of the root node */
int replayfs_filemap_init(struct replayfs_filemap *map,
		struct replayfs_diskalloc *alloc, struct file *filp);

/* Reinitialize with the location of the root node */
int replayfs_filemap_init_with_pos(struct replayfs_filemap *map,
		struct replayfs_diskalloc *alloc, struct file *filp, loff_t *meta_pos);
/* Can't explicitly create a new one externally! */
/*
int replayfs_filemap_create(struct replayfs_filemap *map,
		struct replayfs_diskalloc *alloc, struct file *filp, loff_t *pos);
		*/
/* Get rid of the filemap */
void replayfs_filemap_destroy(struct replayfs_filemap *map);

void replayfs_filemap_delete(struct replayfs_filemap *map,
		struct file *filp);

/* Add a write to the filemap... */
int replayfs_filemap_write(struct replayfs_filemap *map, loff_t unique_id,
		pid_t pid, loff_t syscall_num, char mod, loff_t offset, int size);

/* 
 * How does this interact with other layers?
 *   The data layer calls the filemap layer, to adjust the current filemap.
 *   Reads from the data layer may access the filemap layer to figure out where
 *       data comes from
 *     In accessing the filemap layer they are requesting the origin of the data
 *     Does it make sense to return a dedup reference, or a full deduped chunk?
 *       I'm voting chunk, this way the map can manage the entire dedup process
 *           itself, rather than stringing that all over the place
 *
 * Should the Data layer manage the Dedup?
 *   No, see previous
 */

/* 
 * Returns source of read entries
 */
struct replayfs_filemap_entry *replayfs_filemap_read(struct replayfs_filemap *map, loff_t offset, int size);

#endif
