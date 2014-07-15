#!/usr/bin/python
"""
intended to use for regression testing
"""

import omniplay

import collections
import traceback
import argparse
import tempfile
import time
import sys
import os
import re

TIMEOUT_SECS = 300
TIMEOUT_PER_SEC = 20

class PythonTest(object):
    """
    Encapsulates a python test
    """
    def __init__(self, mod, env, logger, dmesg):
        self._mod_name = mod
        fromlist = ["record", "replay", "parse", "dump"]
        self._mod = __import__(mod, fromlist=fromlist)
        self._env = env
        self._logger = logger
        self._dmesg = dmesg
        self._state = None
        self._record_log = ""

    def __str__(self):
        return self._mod_name

    def record(self):
        """
        Does the recording portion of the python test
        """
        self._dmesg.start_recording()
        self._state = self._mod.record(self._env)
        self._record_log = self._dmesg.stop_recording()

    def parse(self):
        """
        Does any needed log parsing or static recording verification
        """
        return self._mod.parse(self._state)

    def replay(self):
        """
        Does the replaying portion of the python test
        (dynamic recording verification)
        """
        self._dmesg.start_recording()
        self._mod.replay(self._state)
        self._dmesg.stop_recording()

    def dump(self, replay_log=None):
        """
        Dumps the tests contents, on failure
        """
        self._logger.printf("Dumping recording info for " + str(self))
        self._logger.printf("All info dumped to ./test_dump")

        if (not os.path.isdir("./test_dump")):
            os.mkdir("./test_dump")

        outdir = ''.join(["./test_dump/", str(self)])

        # If the output is already there delete it (eases testing)
        if (os.path.exists(outdir)):
            omniplay.run_shell(''.join(["rm -rf ", outdir]))

        os.mkdir(outdir)

        with open(''.join([outdir, "/fail.log"]), "w") as f:
            f.write(self._logger.get_logstr())

        with open(''.join([outdir, "/record.dmesg"]), "w") as f:
            f.write(self._record_log)

        if replay_log is not None:
            with open(''.join([outdir, "/replay.dmesg"]), "w") as f:
                f.write(replay_log)

        self._mod.dump(self._state, outdir)


class BashTest(object):
    """
    Encapsulates a bash test
    """
    def __init__(self, cmd, env, logger, dmesg):
        self._env = env
        self._cmd = cmd
        self._rec = None
        self._logger = logger
        self._dmesg = dmesg
        self._children = []
        self._record_log = ""

    def __str__(self):
        if self._rec is None:
            return self._cmd
        else:
            return str(self._rec.group_id) + ": " + self._cmd

    def record(self):
        """
        Records the bash test
        """
        
        self._dmesg.start_recording()
        self._rec = self._env.record(''.join(['bash -c "', self._cmd, '"']))
        self._record_log = self._dmesg.stop_recording()

    def parse(self):
        """
        Does any log parsing of the bash test to make sure it functions
        """
        num_parsed = 0
        ckpt = self._rec

        # Now find all children groups of this recording
        self._children.append(ckpt.group_id)
        to_scan = collections.deque([ckpt.group_id])
        
        while to_scan:
            n = to_scan.popleft()

            directory = self._env.get_record_dir(n)

            for f in os.listdir(directory):
                if re.match("klog.id", f) is not None:
                    fullname = '/'.join([directory, f])
                    if os.path.isfile(fullname):
                        (fd, tmpdir) = tempfile.mkstemp()
                        self._logger.printf("\t\tRunning parseklog on " +
                                fullname)
                        self._env.parseklog(fullname, tmpdir)
                        num_parsed += 1

                        with os.fdopen(fd, "r") as f:
                            for line in f.readlines():
                                match = re.match("\tnew group id: ([0-9]+)",
                                        line)
                                if match is not None:
                                    to_scan.append(match.group(1))

                                    self._children.append(match.group(1))
                        os.remove(tmpdir)

        return num_parsed
        

    def replay(self):
        """
        Replays the bash test
        """
        (last_started, last_finished, last_mismatched) = self._env.get_stats()

        # Now check to see that each of the recordings replays
        for rg in self._children:
            self._logger.printf("\t\t Testing child id: " + str(rg))
            directory = self._env.get_record_dir(rg)

            self._dmesg.start_recording()
            self._env.replay(directory)

            done = 0
            timepassed = 0
            printwait = 0
            wait_sec = 1
            while (not done):
                (started, finished, mismatched) = self._env.get_stats()
                if started == last_started+1:
                    if mismatched == last_mismatched:
                        if finished == last_finished+1:
                            self._logger.printf("\t\treplayed OK\n")
                            last_started = started
                            last_finished = finished
                            last_mismatched = mismatched
                            done = 1
                        else:

                            if printwait == TIMEOUT_PER_SEC * wait_sec:
                                wait_sec *= 2
                                self._logger.printf(
                                    "\t\tstill running (waiting for {} seconds)".format
                                        (timepassed/TIMEOUT_PER_SEC))
                                printwait = 0
                            else:
                                printwait += 1

                            if timepassed > 20*TIMEOUT_SECS:
                                self._logger.printf("\t\terorr: Test Timed out!")
                                raise RuntimeError("Replay timed out")
                                
                            timepassed += 1
                            time.sleep(1.0 / TIMEOUT_PER_SEC)
                    else:
                        self._logger.printf("\t\terror: mismatch!!!\n")
                        raise RuntimeError("Syscall Mismatch")
                else:
                    self._logger.printf("\t\terror: never started?\n")
                    raise RuntimeError("?Replay did not start?")

    def dump(self, replay_log=None):
        """
        Dumps all of test's available contents.
        """

        self._logger.printf("Dumping recording info for " + str(self))
        self._logger.printf("All info dumped to ./test_dump")

        if (not os.path.isdir("./test_dump")):
            os.mkdir("./test_dump")

        outdir = ''.join(["./test_dump/", str(self._rec.group_id)])

        # If the output is already there delete it (eases testing)
        if (os.path.exists(outdir)):
            omniplay.run_shell(''.join(["rm -rf ", outdir]))

        os.mkdir(outdir)

        with open(''.join([outdir, "/fail.log"]), "w") as f:
            f.write(self._logger.get_logstr())

        with open(''.join([outdir, "/record.dmesg"]), "w") as f:
            f.write(self._record_log)

        if replay_log is not None:
            with open(''.join([outdir, "/replay.dmesg"]), "w") as f:
                f.write(replay_log)

        self._env.parsegroup(self._rec.group_id, outdir)

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


def parse_input(lines, env, logger, dmesg):
    """
    Responsible for parsing the testfile, and returning a list of tests
    """
    tests = []
    for line in lines:
        line = line.strip()

        if not line:
            continue

        if line.startswith('#'):
            continue

        if line.startswith("%"):
            match = re.match("%import (.+)", line)
            if match is not None:
                test = match.group(1).strip()
                logger.printf("have module " + test)

                tests.append(PythonTest(test, env, logger, dmesg))
                continue

            logger.printf("Invalid % directive: " + line)

        else:
            tests.append(BashTest(line, env, logger, dmesg))

    return tests

def main(args):
    """
    main function
    """
    try:
        cur_test = None

        logger = Logger(args.silent)
        dmesg = omniplay.dmesg.OmniplayDmesg()

        test_num = 0
        group_num = 0
        env = omniplay.OmniplayEnvironment()
        tests = []

        if not args.no_testfile:
            with open(args.testfile, "r") as f:
                lines = f.readlines()
                tests.extend(parse_input(lines, env, logger, dmesg))

        if args.tests is not None:
            tests.extent(parse_input(args.tests, env, logger, dmesg))

        # Record all tests
        logger.printf("Doing recordings")
        for test in tests:
            test_num += 1
            logger.printf("\trecording: " + str(test))
            test.record()



        # Klog parsing time
        # FIXME: Use new env functions to parse all klogs easily
        logger.printf("\nNow testing klog parsing:")
        for test in tests:
            logger.printf("\tParsing klog for: " + str(test))
            group_num += test.parse()
            

        logger.printf("\nNow replaying the processes:")
        for test in tests:
            cur_test = test
            logger.printf("\treplaying: " + str(test))
            test.replay()

        cur_test = None

        logger.printf("Successfully ran " + str(test_num) + " tests with " +
                str(group_num) + " total record groups")
    except:
        traceback.print_exc(file=sys.stderr)
    finally:
        dmesg_out = dmesg.stop_recording()
        if cur_test is not None:
            logger.printf("Killed while running a test, doing a dump of that test")
            cur_test.dump(dmesg_out)
        sys.exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Run regression testsuite of record/replays")
    parser.add_argument("-t", "--testfile", dest="testfile", default="tests",
        help='Specify testfile which contains tests to run.  Default is "tests"')
    parser.add_argument("-q", "--quiet", dest="silent", action="store_true",
        help="Don't print to console")
    parser.add_argument("-N", "--no-testfile", dest="no_testfile",
        action="store_true",
        help="Don't use a testfile, just use --with-test arguments")
    parser.add_argument("--with-test", dest="tests", action="append",
        help="Specifies an additional test line to run")
    main_args = parser.parse_args()
    main(main_args)

