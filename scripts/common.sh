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



