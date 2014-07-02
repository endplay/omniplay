#!/usr/bin/python
"""
intended to use for regression testing
"""

import omniplay

import collections
import tempfile
import time
import sys
import os
import re

TestData = collections.namedtuple("t", ["ckpt", "child_ids"])

def main():
    """
    main function
    """
    test_num = 0
    group_num = 0
    env = omniplay.OmniplayEnvironment()

    recordings = []

    with open("./tests", "r") as f:
        tests = f.readlines()

    # Record all tests
    print "Doing recordings"
    for line in tests:
        test_num += 1
        group_num += 1
        print "\trecording: " + line[0:-1]
        rec = env.record(''.join(['bash -c "', line, '"']))

        td = TestData(ckpt = rec, child_ids = [rec.group_id])
        recordings.append(td)



    # Klog parsing time
    print "\nNow testing klog parsing:"
    for rec in recordings:
        ckpt = rec.ckpt
        print ("\tParsing klog for: " + str(ckpt.group_id) +
                ": " + str(ckpt.args))

        # Now find all children groups of this recording
        to_scan = collections.deque([ckpt.group_id])
        
        while to_scan:
            n = to_scan.popleft()

            directory = env.get_record_dir(n)

            for f in os.listdir(directory):
                if re.match("klog.id", f) is not None:
                    fullname = '/'.join([directory, f])
                    if os.path.isfile(fullname):
                        (fd, tmpdir) = tempfile.mkstemp()
                        print "\t\tRunning parseklog on " + fullname
                        env.parseklog(fullname, tmpdir)

                        with os.fdopen(fd, "r") as f:
                            for line in f.readlines():
                                match = re.match("\tnew group id: ([0-9]+)", line)
                                if match is not None:
                                    group_num += 1
                                    #print "\t\talso scanning child with id: " + match.group(1)
                                    to_scan.append(match.group(1))
                                    rec.child_ids.append(match.group(1))
                        os.remove(tmpdir)

    (last_started, last_finished, last_mismatched) = env.get_stats()

    # Now check to see that each of the recordings replays
    print "\nNow replaying the processes:"
    for rec in recordings:
        ckpt = rec.ckpt
        print "\treplaying: " + str(ckpt.group_id) + ": " + str(ckpt.args)
        for rg in rec.child_ids:
            print "\t\t Testing child id: " + str(rg)
            directory = env.get_record_dir(rg)


            proc = env.replay(directory)

            done = 0
            printwait = 0
            while (not done):
                (started, finished, mismatched) = env.get_stats()
                if started == last_started+1:
                    if mismatched == last_mismatched:
                        if finished == last_finished+1:
                            print "\t\treplayed OK\n"
                            last_started = started
                            last_finished = finished
                            last_mismatched = mismatched
                            done = 1
                        else:
                            if printwait == 20:
                                print "\t\tstill running"
                                printwait = 0
                            else:
                                printwait += 1
                            time.sleep(.05)
                    else:
                        print "\t\tmismatch!!!\n"
                        sys.exit(1)
                else:
                    print "\t\terror: never started?\n"
                    sys.exit(1)


    print "Successfully ran " + str(test_num) + " tests with " + str(group_num) + " total record groups"

if __name__ == "__main__":
    main()

