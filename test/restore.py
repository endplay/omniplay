#!/usr/bin/python
#
# This script implements the kludge of sending a checkpoint resume a SIGSTOP/SIGCONT pair.
# This appears to be necessary to get the register restoration correct, but I don't know why.
#

import os
import sys
import subprocess
import signal
import time

if len(sys.argv) != 3:
    sys.exit()

replay_id = sys.argv[1]
ckpt_id = sys.argv[2]

process = subprocess.Popen(["./resume", "/replay_logdb/rec_" + replay_id, "--pthread", 
                            "../eglibc-2.15/prefix/lib", "--from_ckpt", ckpt_id])

#print "replay from ckpt started"
