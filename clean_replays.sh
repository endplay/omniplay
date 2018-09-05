#!/bin/bash

if [[ -z $OMNIPLAY_DIR ]]; then
	echo "OMNIPLAY_DIR not set, please run <omniplay_dir>/scripts/setup.sh"
	exit 0
fi

source $OMNIPLAY_DIR/scripts/common.sh

# Make sure spec is inserted
setup_spec

sudo rm -rf /replay_logdb/
sudo mkdir /replay_logdb
sudo chmod 777 /replay_logdb

sudo rm -rf /replay_cache/
sudo mkdir /replay_cache
sudo chmod 777 /replay_cache

$OMNIPLAY_DIR/test/reset_ndx

$OMNIPLAY_DIR/test/reset_ndx

#if [[ "$do_logrotate" -ne "0" ]]; then
	#$OMNIPLAY_DIR/rotate_logs.sh
#fi

