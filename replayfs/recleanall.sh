#!/bin/sh

if [ -d /sys/module/replayfs ]; then
	sudo umount mnt
	sudo rmmod replayfs.ko
fi

./clean_fs.sh

sudo insmod replayfs.ko || {
	echo "Failed to insert replayfs module!";
	exit 1;
}

echo "Module inserted, .text section loction:"
cat /sys/module/replayfs/sections/.text

sudo mount -t replayfs none mnt || {
	echo "Failed to mount replayfs filesystem to mnt";
	exit 1;
}

