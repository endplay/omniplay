#!/usr/bin/python

import argparse
import os
import sys
import time
import json
import difflib

import runtime

class InvalidTest(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        print(repr(self.msg))

class TestInfo(object):
    def __init__(self, json_data):
        if 'replay_directory' in json_data:
            self.replay_directory = json_data['replay_directory']
        else:
            raise InvalidTest("Missing replay directory in test")

        if 'golden_file' in json_data:
            self.golden_file = json_data['golden_file']
        else:
            raise InvalidTest("Missing golden file in test")

        if 'linkage_tool' in json_data:
            self.linkage_tool = json_data['linkage_tool']
        else:
            raise InvalidTest("Missing linkage tool")

    def validate_test(self):
        if not os.path.exists(self.golden_file):
            raise InvalidTest("Golden file does not exist")

    def __str__(self):
        return ("Test %s (tool %s)" % (self.replay_directory, self.linkage_tool))

def load_test_file(test_file):
    all_tests = []
    with open(test_file) as test_json_file:
        json_data = json.load(test_json_file)
        assert "tests" in json_data
        for test in json_data['tests']:
            test_info = TestInfo(test)
            all_tests.append(test_info)
    return all_tests

def main(args):
    tests = "/".join([args.omniplay_directory, "logdb", "tests"])
    test_file = args.test_file

    if not os.path.exists(test_file):
        print("Test file: %s does not exist" % test_file)
        sys.exit(0)

    # the runtime info provides us with functions to replay the test
    runtime_info = runtime.RunTimeInfo(omniplay_location=args.omniplay_directory)

    all_tests = load_test_file(test_file)
    for test in all_tests:
        test.validate_test()
        log_f = open("/tmp/stderr_log", "w")
        tool_f = open("/tmp/tool_log", "w")

        replay_process = runtime_info.replay(test.replay_directory, log_f, pin=True)
        attach_process = runtime_info.attach_tool(replay_process.pid, test.linkage_tool, "/tmp/tool_output", tool_f)

        attach_process.wait()
        replay_process.wait()
        
        if not os.path.exists("/tmp/tool_output"):
            print("%s FAILED" % str(test))
            continue

        # diff tool_output and golden_file 
        tool_out = open("/tmp/tool_output")
        golden_file = open(test.golden_file)

        tool_lines = tool_out.readlines()
        golden_lines = golden_file.readlines()

        diff = difflib.ndiff(tool_lines, golden_lines)
        diff_string = ''.join(x[2:] for x in diff if (x.startswith('- ') or x.startswith('+ ')))
        if diff_string:
            print("%s FAILED" % str(test))
            print("diff string is: %s" % diff_string)
            continue

        # cleanup for the next test
        os.remove("/tmp/tool_output")
        print("%s passed" % str(test))

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Regression test framework for the linkage tool")
    parser.add_argument("omniplay_directory", help="Location of your omniplay directory")
    parser.add_argument("test_file", help="test file to run")
    args = parser.parse_args()
    main(args)
