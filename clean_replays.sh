#!/bin/bash

if [[ -z $OMNIPLAY_DIR ]]; then
	echo "OMNIPLAY_DIR not set, please run <omniplay_dir>/scripts/setup.sh"
	exit 0
fi

source $OMNIPLAY_DIR/scripts/common.sh

# Make sure spec is inserted
setup_spec

pushd /replay_logdb/ &> /dev/null || {
	exit 0
}
ls | xargs sudo rm -rf
popd  &> /dev/null

find /replay_cache/ -type f | xargs sudo rm -f 
sudo rm -rf /replay_cache/
sudo mkdir /replay_cache/
sudo chmod 777 /replay_cache

cache_size=$(ls /replay_cache/ | wc -l)

if [[ "$cache_size" -ne "0" ]]; then
	echo "Failed to clean replay_cache!";
	exit 1
fi

$OMNIPLAY_DIR/test/reset_ndx

#if [[ "$do_logrotate" -ne "0" ]]; then
	#$OMNIPLAY_DIR/rotate_logs.sh
#fi

