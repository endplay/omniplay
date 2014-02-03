#!/bin/bash

CVSCHECKOUT=~/.gitcvsimport/
MODULE=omniplay
BRANCH=$(git branch | sed -n -e 's/^\* \(.*\)/\1/p')


git checkout cvs
git merge --no-ff master || {
	echo "Could not merge master"
	git checkout $BRANCH
	exit 1
}

if [ ! -d "$CVSCHECKOUT" ]; then
	echo "omniplay cvs module not checked out, checking out"
	mkdir -p $CVSCHECKOUT
	pushd $CVSCHECKOUT
	cvs co $MODULE || {
		echo "cvs co failure!"
		exit 1
	}
	popd
fi

git cvsexportcommit -w $CVSCHECKOUT/$MODULE -u -p -k -c ORIG_HEAD HEAD

git checkout $BRANCH

