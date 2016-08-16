#!/bin/bash

command=$1

stdout=$command.out
stderr=$command.err


nohup $command 1>$stdout 2>$stderr&


