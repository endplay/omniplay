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
    print "restore replay_id ckpt_id"
    sys.exit()

replay_id = sys.argv[1]
ckpt_id = sys.argv[2]

process = subprocess.Popen(["./resume", "/replay_logdb/rec_" + replay_id, "--pthread", 
                            "../eglibc-2.15/prefix/lib", "--from_ckpt", ckpt_id])

print "ckpt process is", process.pid

rc = 255
while rc != 0:
    rc = subprocess.call(["./kick_ckpt", str(process.pid)])

process.send_signal(signal.SIGSTOP)
process.send_signal(signal.SIGCONT)

print "replay from ckpt started"
