#!/usr/bin/python

import argparse
import os
import sys
import subprocess
import shlex
import shutil
import time

import runtime

OMNIPLAY = "/home/mcchow/omniplay"
pthread_lib = "/home/mcchow/omniplay/eglibc-2.15/prefix/lib"
PIN = "/home/mcchow/pin-2.13"

def main(args):
    rec_dir = args.replay_directory

    log_f = open("/tmp/stderr_log", "w")
    tool_f = open("/tmp/tool_log", "w")

    runtime_info = runtime.RunTimeInfo(omniplay_location=OMNIPLAY)
    replay_process = runtime_info.replay(rec_dir, log_f, pin=True)

    time.sleep(1)

    attach_process = runtime_info.attach_tool(replay_process.pid, "linkage_copy.so", "/tmp/tool_output", tool_f)

    attach_process.wait()
    replay_process.wait()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Run replay with tool script")
    parser.add_argument("replay_directory", help="Directory of the replay to start the query on")
    args = parser.parse_args()
    main(args)
