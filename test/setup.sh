#/bin/sh

if [ ! -e /replay_cache ]
then
    mkdir /replay_cache
fi

/sbin/insmod dev/spec.ko

if [ ! -e /dev/spec0 ]
then
    mknod /dev/spec0 c 149 0
fi