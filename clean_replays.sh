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
ls | xargs sudo rm -rf
popd  &> /dev/null

find /replay_cache/ -type f | xargs sudo rm -f 

cache_size=$(ls /replay_cache/ | wc -l)

if [[ "$cache_size" -ne "0" ]]; then
	echo "Failed to clean replay_cache!";
	exit 1
fi

