#!/bin/bash

# Proper way to Include:
##!/bin/bash
#
#if [[ -z $OMNIPLAY_DIR ]]; then
#	echo "OMNIPLAY_DIR not set, please run <omniplay_dir>/scripts/setup.sh"
#	exit 0
#fi
#
#source $OMNIPLAY_DIR/scripts/common.sh

function setup_spec() {
	/sbin/lsmod | grep spec &> /dev/null || {
			echo "Spec not detected, starting up devspec"
			pushd $OMNIPLAY_DIR/test &> /dev/null
			sudo ./setup.sh || {
				pushd dev &> /dev/null
				echo "Spec module couldn't be inserted... rebuilding"

				make || {
					echo "Make failure!"
					exit 1
				}

				popd &> /dev/null

				sudo ./setup.sh || {
					echo "Setup still failed... aborting"
					exit 1
				}
			}
			popd &> /dev/null
	}
}

function build_test() {
	pushd $OMNIPLAY_DIR/test &> /dev/null
	makemsg=$(make)

	if [[ "$?" -ne "0" ]]; then
		echo "Failed to build test!"
		echo "Test output:"
		echo $makemsg
		return 1
	fi

	popd &> /dev/null
}

function check_for_prog() {
	progname="$1"

	if [[ ! -x "$OMNIPLAY_DIR/test/$progname" ]]; then
		return 0
	fi

	return 1
}

