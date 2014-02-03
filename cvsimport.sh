#!/bin/bash

CVSCHECKOUT=~/.gitcvsimport/
MODULE=omniplay
BRANCH=$(git branch | sed -n -e 's/^\* \(.*\)/\1/p')


git cvsimport -k
git merge cvs || {
	echo "Could not merge cvs"
	git checkout $BRANCH
	exit 1
}

