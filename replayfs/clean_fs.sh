#!/bin/bash

pushd /home/replayfs_data_dir

sudo rm -rf *.data *.entry *.syscache_index *_syscache_meta logs/*

for i in {0..15};
do
	x=$( printf "%X" $i )
	sudo rm -rf $x
	mkdir $x
	pushd $x &> /dev/null
	for j in {0..255};
	do
		y=$( printf "%02X" $j )
		mkdir $y
	done
	popd &> /dev/null
done

mkdir -p logs

popd

