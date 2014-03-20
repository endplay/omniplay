#!/usr/bin/python

import re
import os
import argparse

import opinfo
import runtime

def get_filemap(runtime_info, filename):
    filemap_process = runtime_info.filemap(filename)
    filemap_process.wait()
    filemap_output = filemap_process.communicate()[0]

    if not filemap_output:
        print("Could not get filemap info for %s" % filename)
        return None

    writes = []
    for line in filemap_output.split("\n"):
        if not line:
            continue
        fields = line.split(" ")
        file_offset = int(fields[0])
        size = int(fields[1])
        group_id = int(fields[2])
        pid = int(fields[3])
        sysnum = int(fields[4])
        offset = int(fields[5])
        wi = opinfo.WriteInfo(group_id, pid, sysnum, offset, size, channel=filename)
        print("Starting Write info [%d, %d, %d, %d, %d]" % (group_id, pid, sysnum, offset, size))
        writes.append(wi)

    return writes

def run_io_tool(runtime_info, replay_group_id):
    # run the replay
    replay_dir = "/replay_logdb/rec_" + str(replay_group_id)
    stderr_log = open("/tmp/stderr_log", "w")
    replay_process = runtime_info.replay(replay_dir, stderr_log, pin=True)

    attach_process = runtime_info.attach_tool_extended(replay_process.pid, "io.so", stderr_log)

    replay_process.wait()
    attach_process.wait()

def search_output(replay_group_id, string):
    # okay, the output should be in /tmp/io_<replay group id>
    io_dir = "/tmp/io_" + str(replay_group_id)
    assert os.path.isdir(io_dir)
    assert os.path.isdir(io_dir + "/reads")
    assert os.path.isdir(io_dir + "/writes")

    # list every file in the directory
    found_writes = []
    write_files = os.listdir(io_dir + "/writes")
    for write_file in write_files:
        result = search_file(io_dir + "/writes/" + write_file, string)
        if result:
            found_writes.extend(result)
        

    for wi in found_writes:
        print(wi)
    return found_writes

def search_file(filename, string):
    # list of byte ranges where the string was found
    found_writes = []
    f = open(filename, "r")
    header_line = f.readline()
    fields = header_line.strip().split(" ")

    assert len(fields) == 6

    group_id = int(fields[0])
    pid = int(fields[1])
    syscall_cnt = int(fields[2])
    offset = int(fields[3])
    size = int(fields[4])
    channel = fields[5]

    count = 0
    for line in f.readlines():
        idx = line.find(string)
        if idx != -1:
            found_offset = offset + count + idx
            wi = opinfo.WriteInfo(group_id,
                                    pid,
                                    syscall_cnt,
                                    found_offset,
                                    size=len(string),
                                    channel=channel)
            found_writes.append(wi)
        count += len(line)

    return found_writes

def main(args):
    # form the right query to run
    runtime_info = runtime.RunTimeInfo(verbose=args.verbose)
    # make sure everything is in order
    runtime_info.check_system()

    # run_io_tool(runtime_info, args.replay_group_id)
    search_output(args.replay_group_id, args.error_string)

if __name__ == "__main__":
    parser = argparse.ArgumentParser("searches for a regex in the output \
            of a program and returns the corresponding bytes")
    parser.add_argument("-v", "--verbose", help="Verbose output", dest="verbose", action="store_true")
    parser.add_argument("error_string", help="Error string to look for")
    parser.add_argument("replay_group_id",
            help="Replay group id to look for it in")
    args = parser.parse_args()
    main(args)
