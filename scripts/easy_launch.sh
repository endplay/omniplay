#!/bin/bash

# Make sure we're configured
if [[ -z $OMNIPLAY_DIR ]]; then
	echo "OMNIPLAY_DIR not set, please run <omniplay_dir>/scripts/setup.sh"
	exit 0
fi

# Pull our common functions library
source $OMNIPLAY_DIR/scripts/common.sh

if [[ "$#" -lt "1" ]]; then
	echo "Usage $0 <program to launch> <args>"
fi

# Make sure spec is setup
setup_spec

# If we're recording... exit
is_record_proc || {
	echo "Already recording!"
	exit 1
}

# Make sure launcher exists
ensure_can_launch "launcher"

# Run launcher... calling which first, for good measure
bin=`which $1`

args=()
whitespace="[[:space:]]"
idx=0
for i in "$@"; do

	# Skip the first argument
	if [[ "$idx" -eq "0" ]]; then
		idx=1
		continue
	fi

	if [[ $i =~ $whitespace ]]; then
		i=\"$i\"
	fi

	args+=("$i")
done

launch_recording "$bin" "${args[@]}"

