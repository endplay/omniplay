#!/usr/bin/python
"""
intended to use for regression testing
"""

import omniplay

import collections
import argparse
import tempfile
import time
import sys
import os
import re

ChildData = collections.namedtuple("t2", ["rgid", "replay_dmesg"])
TestData = collections.namedtuple("t", ["ckpt", "child_ids", "record_dmesg"])

TIMEOUT_SECS = 300

class Logger(object):
    """
    Utility class for logging output
    """
    def __init__(self, silent = False, outfile = sys.stdout):
        self._logstr = ""
        self._silent = silent
        self._outfile = outfile

    def printf(self, string):
        """
        Prints to outfile/adds to logstr
        """
        savestr = ''.join([string, "\n"])
        if (not self._silent):
            self._outfile.write(savestr)
        self._logstr += savestr

    def get_logstr(self):
        """
        Access logstr
        """
        return self._logstr

    def is_silent(self):
        """
        If it actually prints to outfile
        """
        return self._silent

def _do_dump_internal(env, group_id, record_log, logger, replay_log):
    """
    I really didn't want to separate this, but its easier to command-line test
    with just the group_id as an argument
    """
    if (not os.path.isdir("./test_dump")):
        os.mkdir("./test_dump")

    outdir = ''.join(["./test_dump/", str(group_id)])

    # If the output is already there delete it (eases testing)
    if (os.path.exists(outdir)):
        omniplay.run_shell(''.join(["rm -rf ", outdir]))

    os.mkdir(outdir)

    with open(''.join([outdir, "/fail.log"]), "w") as f:
        f.write(logger.get_logstr())

    with open(''.join([outdir, "/record.dmesg"]), "w") as f:
        f.write(record_log)

    with open(''.join([outdir, "/replay.dmesg"]), "w") as f:
        f.write(replay_log)

    env.parsegroup(group_id, outdir)

def do_dump(env, rec, logger, replay_log):
    """
    Dumps the replay information for a given recording
    """
    print "Dumping recording info for " + str(rec.ckpt.group_id) + ": " + str(rec.ckpt.args)
    print "All info dumped to ./test_dump"

    _do_dump_internal(env, rec.ckpt.group_id, rec.record_dmesg,
            logger, replay_log)
    

def main(args):
    """
    main function
    """

    logger = Logger(args.silent)
    dmesg = omniplay.dmesg.OmniplayDmesg()

    test_num = 0
    group_num = 0
    env = omniplay.OmniplayEnvironment()

    recordings = []

    with open(args.testfile, "r") as f:
        tests = []
        for line in f.readlines():
            if (not line.startswith('#')):
                tests.append(line)

    # Record all tests
    logger.printf("Doing recordings")
    for line in tests:
        test_num += 1
        group_num += 1
        logger.printf("\trecording: " + line[0:-1])
        
        dmesg.start_recording()
        rec = env.record(''.join(['bash -c "', line, '"']))
        dmesg_data = dmesg.stop_recording()

        td = TestData(ckpt = rec,
                child_ids = [ChildData(rgid=rec.group_id, replay_dmesg=None)],
                record_dmesg=dmesg_data)
        recordings.append(td)



    # Klog parsing time
    # FIXME: Use new env functions to parse all klogs easily
    logger.printf("\nNow testing klog parsing:")
    for rec in recordings:
        ckpt = rec.ckpt
        logger.printf("\tParsing klog for: " + str(ckpt.group_id) +
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
                        logger.printf("\t\tRunning parseklog on " + fullname)
                        env.parseklog(fullname, tmpdir)

                        with os.fdopen(fd, "r") as f:
                            for line in f.readlines():
                                match = re.match("\tnew group id: ([0-9]+)", line)
                                if match is not None:
                                    group_num += 1
                                    #print "\t\talso scanning child with id: " + match.group(1)
                                    to_scan.append(match.group(1))

                                    rec.child_ids.append(ChildData(rgid=match.group(1),
                                        replay_dmesg=None))
                        os.remove(tmpdir)

    (last_started, last_finished, last_mismatched) = env.get_stats()

    # Now check to see that each of the recordings replays
    logger.printf("\nNow replaying the processes:")
    for rec in recordings:
        ckpt = rec.ckpt
        logger.printf("\treplaying: " + str(ckpt.group_id) + ": " +
                str(ckpt.args))
        for rg in rec.child_ids:
            logger.printf("\t\t Testing child id: " + str(rg))
            directory = env.get_record_dir(rg.rgid)

            dmesg.start_recording()
            env.replay(directory)

            done = 0
            timepassed = 0
            printwait = 0
            while (not done):
                (started, finished, mismatched) = env.get_stats()
                if started == last_started+1:
                    if mismatched == last_mismatched:
                        if finished == last_finished+1:
                            logger.printf("\t\treplayed OK\n")
                            last_started = started
                            last_finished = finished
                            last_mismatched = mismatched
                            done = 1
                        else:
                            if printwait == 20:
                                logger.printf("\t\tstill running")
                                printwait = 0
                            else:
                                printwait += 1

                            if timepassed > 20*TIMEOUT_SECS:
                                logger.printf("\t\tTest Timed out!")
                                replay_dmesg = dmesg.stop_recording()
                                do_dump(env, rec, logger, replay_dmesg)
                                sys.exit(1)
                                
                            timepassed += 1
                            time.sleep(.05)
                    else:
                        logger.printf("\t\tmismatch!!!\n")
                        replay_dmesg = dmesg.stop_recording()
                        do_dump(env, rec, logger, replay_dmesg)
                        sys.exit(1)
                else:
                    logger.printf("\t\terror: never started?\n")
                    sys.exit(1)


    logger.printf("Successfully ran " + str(test_num) + " tests with " +
            str(group_num) + " total record groups")

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Run regression testsuite of record/replays")
    parser.add_argument("-t", "--testfile", dest="testfile", default="tests",
        help='Specify testfile which contains tests to run.  Default is "tests"')
    parser.add_argument("-q", "--quiet", dest="silent", action="store_true",
        help="Don't print to console")
    main_args = parser.parse_args()
    main(main_args)

