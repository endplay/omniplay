#!/bin/bash

#RECORD="/home/ddevec/omniplay/test/launcher -m --pthread $MY_PTHREAD"
RECORD=""

PAYLOAD="/tmp/client_payload"

PWD=`pwd`
TESTDIR="$PWD/test"
SERVER="$TESTDIR/socket_server"
CLIENT="$TESTDIR/socket_client"

if [ ! -e $SERVER ]; then
	echo "Server file: $SERVER does not exist, trying to build"
	pushd $TESTDIR &> /dev/null
	make
	popd &> /dev/null
fi

if [ ! -e $SERVER ]; then
	echo "Couldn't build server file ($SERVER) aborting"
	exit 1
fi

# Make sure spec is inserted
/sbin/lsmod | grep spec &> /dev/null || {
	  echo "Spec not detected, starting up devspec"
		pushd ~/omniplay/test/ &> /dev/null
		sudo ./setup.sh
		popd &> /dev/null
}


# Spawn server
MY_JOB_NAME=$SERVER
$RECORD $MY_JOB_NAME &
PID=$!

sleep 1

# Now spawn clients
echo "test123 test123 test456" > $PAYLOAD
echo "Running socket_client!"
$RECORD $CLIENT < $PAYLOAD

echo "testabc testabc testefg" > $PAYLOAD
echo "Running 2nd socket_client!"
$RECORD $CLIENT < $PAYLOAD

sleep 1

echo "Killing pid $PID"
kill -9 $PID

rm $PAYLOAD

echo "Success"
exit 0
