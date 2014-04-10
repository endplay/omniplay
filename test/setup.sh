#!/bin/bash

if [[ -z $OMNIPLAY_DIR ]]; then
	echo "OMNIPLAY_DIR not set, please run <omniplay_dir>/scripts/setup.sh"
	exit 0
fi

source $OMNIPLAY_DIR/scripts/common.sh

setup_spec

##/bin/sh
#
#if [ ! -e /replay_cache ]
#then
#    mkdir /replay_cache
#    chmod a+rwx /replay_cache
#fi
#
#if [ ! -e /replay_logdb ]
#then
#    mkdir /replay_logdb
#    chmod a+rwx /replay_logdb
#fi
#
#/sbin/insmod dev/spec.ko || {
#	echo "Unable to insert spec!"
#	exit 1
#}
##
#if [ ! -e /dev/spec0 ]
#then
#    mknod /dev/spec0 c 149 0
#		chmod 777 /dev/spec0
#fi
#
## To allow PIN to attach
#echo 0 > /proc/sys/kernel/yama/ptrace_scope
