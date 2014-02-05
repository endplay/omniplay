#!/bin/bash

CVSCHECKOUT=~/.gitcvsimport/
MODULE=omniplay
BRANCH=$(git branch | sed -n -e 's/^\* \(.*\)/\1/p')

git stash

git checkout cvs

git cvsimport -k

git checkout $BRANCH
git merge cvs || {
	echo "Could not merge cvs"
	git checkout $BRANCH
	exit 1
}
git stash pop

