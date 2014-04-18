#!/bin/bash

#do_logrotate=1

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

sudo rm -rf /replay_graph/*
#sudo mkdir -p /replay_graph
#sudo chmod 777 /replay_graph

if [[ "$cache_size" -ne "0" ]]; then
	echo "Failed to clean replay_cache!";
	exit 1
fi

if [[ "$logdb_size" -ne "0" ]]; then
	echo "Failed to clean replay_cache!";
	exit 1
fi

#if [[ "$do_logrotate" -ne "0" ]]; then
	#$OMNIPLAY_DIR/rotate_logs.sh
#fi

