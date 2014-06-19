#!/bin/bash

if [[ -z $OMNIPLAY_DIR ]]; then
	echo "OMNIPLAY_DIR not set, please run <omniplay_dir>/scripts/setup.sh"
	exit 0
fi

source $OMNIPLAY_DIR/scripts/common.sh

python $OMNIPLAY_DIR/logdb/run_tool.py $@
