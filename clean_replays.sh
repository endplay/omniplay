#!/bin/bash

# Make sure spec is inserted
/sbin/lsmod | grep spec &> /dev/null || {
	  echo "Spec not detected, starting up devspec"
		pushd ~/omniplay/test/ &> /dev/null
		sudo ./setup.sh
		popd &> /dev/null
}

pushd /replay_logdb/ &> /dev/null || {
	exit 0
}
sudo rm -rf *
popd  &> /dev/null

pushd /replay_cache/ &> /dev/null || {
	exit 0
}
sudo rm -rf *
popd  &> /dev/null

sudo rm -rf /replay_logdb/* /replay_cache/* /replay_cache/replaymap.disk

ls /replay_cache/ | grep replaymap.disk && {
	echo "Failed to remove replaymap.disk!";
	exit 1
}
