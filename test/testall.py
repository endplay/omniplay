#!/usr/bin/python
#
# format: testall.py [start] [finish]
#
# Try to replay all recordings with ids in the range (start,finish)

import sys
import glob
import re
import os
import subprocess
import time

if "OMNIPLAY_DIR" not in os.environ:
    print "OMNIPLAY_DIR is not yet set, please run <omniplay>/scripts/setup.sh"
    sys.exit(1)

omniplay_dir=os.environ["OMNIPLAY_DIR"]

def get_stats():
    p = subprocess.Popen (["./getstats"], stdout=subprocess.PIPE)
    lines = p.stdout.read().split("\n")
    m = re.search(" ([0-9]+)$", lines[0])
    if m:
        started = int(m.groups()[0])
    else:
        print "bad output from stats:", lines[0]
        exit (0)
    m = re.search(" ([0-9]+)$", lines[1])
    finished = int(m.groups()[0])
    m = re.search(" ([0-9]+)$", lines[2])
    mismatched = int(m.groups()[0])
    return (started, finished, mismatched)

# Parse arguments
start = 0
finish = sys.maxint

if (len(sys.argv) > 1):
    start = int(sys.argv[1])

if (len(sys.argv) > 2):
    finish = int(sys.argv[2])

# Now get list of recordings that fall within the specified range
recordings = {}
for recdir in glob.glob ("/replay_logdb/rec_*"):
    m = re.search("_([0-9]+)$", recdir)
    if m:
        ndx = int(m.groups()[0])
        if ndx >= start and ndx <= finish:
            recordings[ndx] = recdir

reclist = sorted(recordings.keys())

(last_started, last_finished, last_mismatched) = get_stats()

# Replay them one by one
for rec in reclist:
    print "Replaying", rec
    os.system("./parseckpt " + recordings[rec] + " | egrep Argument");
    print "Running: " + "./resume " + recordings[rec] + " --pthread " + omniplay_dir + "/eglibc-2.15/prefix/lib/"
    os.system("./resume " + recordings[rec] + " --pthread " + omniplay_dir + "/eglibc-2.15/prefix/lib/")
    done = 0
    while (not done):
        (started, finished, mismatched) = get_stats()
        if started == last_started+1:
            if mismatched == last_mismatched:
                if finished == last_finished+1:
                    print "replayed OK\n"
                    last_started = started
                    last_finished = finished
                    last_mismatched = mismatched
                    done = 1
                else:
                    print "still running"
                    time.sleep(1)
            else:
                print "mismatch!!!\n"
                sys.exit(1)
        else:
            print "error: never started?\n"
            sys.exit(0)
