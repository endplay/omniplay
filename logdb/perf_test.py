#!/usr/bin/python

import argparse
import os
import sys
import subprocess
import shlex
import time

OMNIPLAY = "/home/mcchow/omniplay"
pthread_lib = "/home/mcchow/omniplay/eglibc-2.15/prefix/lib"
PIN = "/home/mcchow/pin-2.13"

def main(args):
    rec_dir = args.replay_directory
    num_runs = 1
    if args.runs:
        num_runs = args.runs

    # baseline
    times = []
    for i in range(0, num_runs):
        start = time.time()
        process = replay(rec_dir)
        process.wait()
        end = time.time()
        times.append(end - start)
    print(times)
    print("base line is: %f" % (sum(times) / float(len(times))))

    tool = OMNIPLAY + "/pin_tools/obj-ia32/print_instructions.so"
    t = time_tool(rec_dir, tool, num_runs)
    print("print instructions is: %f" % t)

    tool = OMNIPLAY + "/pin_tools/obj-ia32/linkage_copy.so"
    t = time_tool(rec_dir, tool, num_runs)
    print("linkage_copy is: %f" % t)

def replay(rec_dir, pin=False):
    resume = OMNIPLAY + "/test/resume"
    cmd = resume + " " + rec_dir + " --pthread " + pthread_lib
    if pin:
        cmd += " -p"

    devnull = open(os.devnull, 'wb')
    process = subprocess.Popen(shlex.split(cmd), shell=False, stderr=devnull, stdout=devnull)
    return process

def attach_tool(pid, tool):
    pin = PIN + "/pin"
    cmd = ''.join([pin, " -pid ", str(pid), " -t ", tool])

    devnull = open(os.devnull, 'wb')
    process = subprocess.Popen(shlex.split(cmd), shell=False, stderr=devnull, stdout=devnull)
    return process

def time_tool(rec_dir, tool, num_runs):
    times = []
    for i in range(0, num_runs):
        replay_process = replay(rec_dir, pin=True)
        time.sleep(1)
        start = time.time()
        attach_process = attach_tool(replay_process.pid, tool)
        attach_process.wait()
        replay_process.wait()
        end = time.time()
        times.append(end - start)
    print(times)
    return sum(times) / float(len(times))

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Query script")
    parser.add_argument("replay_directory", help="Directory of the replay to start the query on")
    parser.add_argument("-n", "--runs", help="The number of runs of each test to run", type=int, dest='runs')
    args = parser.parse_args()
    main(args)
