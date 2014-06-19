#!/usr/bin/python

import argparse
import os
import sys
import subprocess
import shlex
import shutil
import time

import runtime

class parseStack():
    def __init__(self):
        self.outputs = dict()
        self.hash2file = dict()
        self.tuple2file = dict()
        self.stack_count = dict()

    def print_dictionary(self, out_f):
        for out_channel, in_channel in self.outputs.items():
            out_f.write(str(out_channel) + ": " + str(list(in_channel)) + "\n")
            for out_file in self.tuple2file[out_channel]:
                out_f.write(out_file + ":\n")
            for in_files in in_channel:
                # in_channel is a set of tuples, in_files are tuples
                out_f.write(str(list(self.tuple2file[in_files])) + "\n")
            out_f.write("===============================\n\n")

    def parse(self, out_file, pid):
       for line in out_file:
            line = line.split(' ');
            out_syscall = line[0]
            out_syschannel = line[1]
            out_hash_val = line[2]
            out_stack_count = line[3]
            out_syscall = line[4]
            in_syscall = line[5]
            in_file = line[6]
            in_stack_hash = line[7]
            in_stack_count = line[8]
            in_sysnum = line[9]

            in_stack_info = in_stack_hash, in_stack_count
            out_stack_info = out_hash_val, out_stack_count
            if out_stack_info not in self.outputs:
                self.outputs[out_stack_info] = set()
            if out_hash_val not in self.hash2file:
                self.hash2file[out_hash_val] = set()
            if in_stack_info not in self.tuple2file:
                self.tuple2file[in_stack_info] = set()
            if out_stack_info not in self.tuple2file:
                self.tuple2file[out_stack_info] = set()
                
            #self.outputs[out_hash_val].add(in_stack_hash)
            #self.outputs[out_hash_val].add(in_stack_info)
            self.outputs[out_stack_info].add(in_stack_info)
            self.hash2file[out_hash_val].add(out_syschannel)
            self.tuple2file[in_stack_info].add(in_file)
            self.tuple2file[out_stack_info].add(out_syschannel)
            #self.hash2file[out_stack_info] = out_syschannel

def back_query(args):
    rec_dir = args.replay_dir
    flags = ""
    if args.flags:
        flags = args.flags
        print(flags)

    omniplay_path = os.environ['OMNIPLAY_DIR']
    if not 'OMNIPLAY_DIR' in os.environ:
        print("Your OMNIPLAY_DIR environment variable is not setup")
        sys.exit(0)
    runtime_info = runtime.RunTimeInfo(omniplay_location=omniplay_path)

    '''
    if not os.path.exists(args.pin_tool):
        print("Pin tool %s does not exist, make sure this is the absolute path" %
                args.pin_tool)
    '''
    # assert os.path.exists(args.pin_tool)
    # assert os.path.exists(runtime_info.tools_location + "/" + args.pin_tool)

    print("Running replay: %s with tool %s" % (args.replay_dir, args.pin_tool))

    stderr_log = "/tmp/stderr_log"
    if args.stderr_log:
        stderr_log = args.stderr_log
    log_f = open(stderr_log, "w")
    tool_f = open("/tmp/tool_log", "w")

    replay_process = runtime_info.replay(rec_dir, log_f, pin=True)

    time.sleep(1)
    start_time = time.time()

    attach_process = runtime_info.attach_tool_extended(replay_process.pid, args.pin_tool,
                                                        tool_f, flags=flags)

    attach_process.wait()
    replay_process.wait()
    end_time = time.time()
    
    #print("pid = %d" % (os.getpid()))
    print("done, took %f secs" % (end_time - start_time))


def build_flags(s):
    flag = " -i 1 "
    s = list(s)
    for item in s:
        flag = flag + "-c " + item[0] + "," + item[1] + " "

    return flag


if __name__ == "__main__":
    parser = argparse.ArgumentParser("parse set of callstacks to taint")
    parser = argparse.ArgumentParser(prefix_chars='=')
    parser.add_argument("pid", help="pid instance we're interested in")
    parser.add_argument("=p", "==print_stack", help="to parse and print callstack dependencies")
    parser.add_argument("=b", "==back_query", nargs=2, action='append')
    parser.add_argument("=f", "==flags", dest="flags")
    parser.add_argument("=r", "==replay_dir")
    parser.add_argument("=pin", "==pin_tool")
    parser.add_argument("=a", "==all_input_channels")
    parser.add_argument("=l", "==log", dest="stderr_log")


    args = parser.parse_args()

    pid = args.pid
    
    input_f = open('/home/andrew/out/%s' %pid, 'r')
    a = parseStack()
    a.parse(input_f, pid)

    if args.print_stack:
        output_f = open('/tmp/out_log_%s' %pid, 'w')
        a.print_dictionary(output_f)

    if args.a:
        args.back_query = a.outputs.keys()

    if args.back_query:
        s = set()
        for bq in range(len(args.back_query)):
            key = tuple(args.back_query[bq])
            s = s | a.outputs[key]
        print 'Number of Files Opened: %d' % len(s)
        args.flags = build_flags(s)

        back_query(args)

