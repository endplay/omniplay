#!/bin/bash

source ../.omniplay_setup

if [[ -z $OMNIPLAY_DIR ]]; then
	echo "OMNIPLAY_DIR not set, please run <omniplay_dir>/scripts/setup.sh"
	exit 0
fi

source $OMNIPLAY_DIR/scripts/common.sh

setup_spec

