#/bin/sh

if [ ! -e /replay_cache ]
then
    mkdir /replay_cache
    chmod a+rwx /replay_cache
fi

if [ ! -e /replay_logdb ]
then
    mkdir /replay_logdb
    chmod a+rwx /replay_logdb
fi

/sbin/insmod dev/spec.ko

if [ ! -e /dev/spec0 ]
then
    mknod /dev/spec0 c 149 0
		chmod 777 /dev/spec0
fi

# To allow PIN to attach
echo 0 > /proc/sys/kernel/yama/ptrace_scope
