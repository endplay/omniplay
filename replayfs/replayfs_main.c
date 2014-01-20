
#include "replayfs_fs.h"
#include "replay_data.h"
#include "replayfs_inode.h"
#include "replayfs_dir.h"
#include "replayfs_dev.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/unistd.h>
#include <linux/mount.h>

#include <linux/replay.h>

#define REPLAYFS_MAIN_DEBUG

#ifdef REPLAYFS_MAIN_DEBUG
#define debugk(...) printk(__VA_ARGS__)
#else
#define debugk(...)
#endif

extern int replay_write(unsigned int fd, const char __user *buf, size_t count);
extern int record_write(unsigned int fd, const char __user *buf, size_t count);

extern int replay_read(unsigned int fd, char __user *buf, size_t count);
extern int record_read(unsigned int fd, char __user *buf, size_t count);

extern void replayfs_pls_init(void);
extern void replayfs_pls_destroy(void);

extern void replayfs_shim_init(void);
extern void replayfs_shim_destroy(void);

int replayfs_init(void) {
	int err;
	debugk("REPLAYFS: Inserting module into the kernel\n");

	replay_cache_init();

	debugk("REPLAYFS: Hooking replay system\n");
	/* Set up syscall interception */

	replayfs_pls_init();

	replayfs_shim_init();

	replayfs_fs_init();

	replay_set_next_unique_id(replayfs_next_unique);

	debugk("REPLAYFS: Inserted\n");
	err = 0;
	return err;
}

void replayfs_exit(void) {
	replay_cache_destroy();

	debugk("REPLAYFS: Unhooking replay system\n");

	replayfs_pls_destroy();

	replayfs_shim_destroy();

	exit_replay_fs();

	replay_set_next_unique_id(NULL);

	debugk("REPLAYFS: Module removed from the kernel\n");
}

module_init(replayfs_init);
module_exit(replayfs_exit);

MODULE_LICENSE("GPL");

