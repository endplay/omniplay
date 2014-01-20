obj-m += replayfs.o

replayfs-objs := entry_table.o replayfs_main.o replayfs_fs.o \
		replayfs_dir.o replayfs_inode.o replayfs_addrops.o replayfs_acl.o \
		replayfs_file_log.o replayfs_file.o replayfs_pagealloc.o replay_data.o \
		replayfs_log.o replayfs_shims.o replayfs_syscall_cache.o \
		replayfs_perftimer.o

unifdef-y += replayfs_fs.h

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	make -C ./test/
	make -C ./user_daemon/

clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	make -C ./test/ clean
	make -C ./user_daemon/ clean

clean-files := Module.symvers
