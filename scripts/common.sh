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

function do_spec_setup() {
	if [[ ! -e /replay_cache ]]; then
			sudo mkdir /replay_cache
			sudo chmod a+rwx /replay_cache
	fi

	if [[ ! -e /replay_logdb ]]; then
			sudo mkdir /replay_logdb
			sudo chmod a+rwx /replay_logdb
	fi

	sudo /sbin/insmod $OMNIPLAY_DIR/test/dev/spec.ko || {
		echo "Unable to insert spec!"
		return 1
	}

	if [[ ! -e /dev/spec0 ]]; then
			sudo mknod /dev/spec0 c 149 0
			sudo chmod 777 /dev/spec0
	fi

	echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope &> /dev/null

	return 0
}

function setup_spec() {
	/sbin/lsmod | grep spec &> /dev/null || {
			echo "Spec not detected, starting up devspec"
			pushd $OMNIPLAY_DIR/test &> /dev/null
			do_spec_setup || {
				pushd dev &> /dev/null
				echo "Spec module couldn't be inserted... rebuilding"

				make || {
					echo "Make failure!"
					exit 1
				}

				popd &> /dev/null

				do_spec_setup || {
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

function is_record_proc() {
	rc=$(cat /proc/sys/kernel/proc_is_record)

	if [[ "$rc" == "1" ]]; then
		return 1
	else
		return 0
	fi
}

#Returns 1 when the program doesn't exist!
#Arg 1 is the program you want to check for (in test)
function check_for_prog() {
	progname="$1"

	if [[ ! -x "$OMNIPLAY_DIR/test/$progname" ]]; then
		return 1
	fi

	return 0
}

#Assumes spec is inserted!
#arg1 is absolute path to binary
function launch_recording() {
	local my_pthread=$OMNIPLAY_DIR/eglibc-2.15/prefix/lib:/lib:/lib/i386-linux-gnu:/usr/lib:/usr/lib/i386-linux-gnu

	local record="$OMNIPLAY_DIR/test/launcher -m --pthread $my_pthread "

	local bin=$1
	shift
	local args=(${@})
	local str="${args[*]}"

	/bin/bash -c "$record $bin $str"
}

#Arg 1 is the program you want to check for (in test)
#Ex ensure_can_launch "launcher" -- Will exit if launcher cannot be found
function ensure_can_launch() {
	check_for_prog "$1" || {
		echo "Cant find $1, trying to build test"

		build_test || { 
			exit 1
		}

		check_for_prog "$1" || {
			echo "Still cant find $1, exiting"
			exit 1
		}
	}
}

