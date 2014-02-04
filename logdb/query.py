#!/usr/bin/python

import argparse
import sys
import os
import time
import subprocess
import sqlite3
import collections

# our modules
import ipc
import logdb
import opinfo
import runtime

class Query(object):
    def __init__(self, runtime_info, write_info, linkages=[]):
        self.runtime_info = runtime_info
        self.linkages = linkages
        self.query_log_filename = "/tmp/query_log"
        self.query_log = open(self.query_log_filename, "w")
        self.query_output = "/tmp/query_output"

        # IPC graph to walk up as the query is done
        self.graph = ipc.IPCGraph()

        # list of lists of write infos
        # Invariant: All the write infos in an element must have the same group id
        #  represents a node/group id to replay
        self.run_queue = []

        # timings
        self.tool_start = 0
        self.tool_end = 0

        self.query_start_time = 0
        self.query_end_time = 0

        self.run_queue.append([write_info])
        
        # for querying meta information
        self.rldb = logdb.ReplayLogDB(self.runtime_info.omniplay_location, logdb_name="replay.db", logdb_dir="/replay_logdb", replay_table_name="replays")

    def lookup_sourcing_read(self, read_info):
        rldb = logdb.ReplayLogDB(self.runtime_info.omniplay_location)
        rldb.init_cursor()

        links = rldb.lookup_writes(read_info)
        rldb.close_cursor()

        return links

    def verify_replay(self):
        return os.path.isfile(self.query_output)

    def parse_query_output(self):
        prev_write_info = None
        prev_read_info = None
        links = {}

        q = open(self.query_output, "r")
        for line in q:
            print(line.strip())
            fields = line.split(" ")
            assert len(fields) == 14
            (write_rec_group, write_pid, write_syscall, write_idx) = \
                    (int(fields[2]), int(fields[3]), int(fields[4]), int(fields[5]))
            (read_rec_group, read_pid, read_syscall, read_idx) = \
                    (int(fields[9]), int(fields[10]), int(fields[11]), int(fields[12]))

            if prev_write_info is None:
                prev_write_info = opinfo.WriteInfo(write_rec_group, write_pid, write_syscall, write_idx)
            elif prev_write_info.group_id == write_rec_group and \
                        prev_write_info.pid == write_pid and \
                        prev_write_info.syscall == write_syscall:
                    prev_write_info.size += 1
            else:
                prev_write_info = opinfo.WriteInfo(write_rec_group, write_pid, write_syscall, write_idx)

            if prev_read_info is None:
                prev_read_info = opinfo.ReadInfo(read_rec_group, read_pid, read_syscall, read_idx)
            elif prev_read_info.group_id == read_rec_group and \
                    prev_read_info.pid == read_pid and \
                    prev_read_info.syscall == read_syscall:
                 prev_read_info.size += 1
            else:
                prev_read_info = opinfo.ReadInfo(read_rec_group, read_pid, read_syscall, read_idx)

            # now link the current write info to the current read info, if not exists
            if prev_write_info and prev_read_info:
                if prev_write_info not in links:
                    links[prev_write_info] = prev_read_info
        q.close()

        # return mappings of writes to reads within this process
        return links

    def run(self):
        self.query_start_time = time.time()
        while len(self.run_queue) > 0:
            wis = self.run_queue.pop()
            assert(wis)
            group_id = wis[0].group_id
            for wi in wis:
                assert wi.group_id == group_id
            print("Run replay for group_id %d" % (group_id))

            # reset from previous run
            # os.remove(self.query_output)

            replay_dir = "/replay_logdb/rec_" + str(group_id)
            replay_process = self.runtime_info.replay(replay_dir, self.query_log, pin=True)

            # wake for a little interval
            time.sleep(1)

            self.tool_start = int(time.time())
            attach_process = self.runtime_info.attach_tool(replay_process.pid, "linkage_copy.so", self.query_output, self.query_log)
            attach_process.wait()
            replay_process.wait()
            self.tool_end = int(time.time())
            print("Copy tool took %d secs" % (self.tool_end - self.tool_start))

            # make sure that the replay suceed
            if not self.verify_replay():
                print("ERROR: query failed to replay, group id %d, linkage copy" % (group_id))
                print("You might want to look for errors in %s" % self.query_log_filename)
                return False

            new_writes = []
            # find intraprocess links
            links = self.parse_query_output()
            # For every write that we are interested in, look up the write to the sourcing read
            for wi in wis: 
                if wi not in links:
                    continue
                ri = links[wi]
                writes = self.lookup_sourcing_read(ri)

                if not self.graph.has_node(ri.group_id, ri.pid):
                    program_cmd = self.rldb.get_program_args(ri.group_id, ri.pid)
                    self.graph.add_node(ri.group_id, ri.pid, cmd=program_cmd)
                    if self.runtime_info.verbose:
                        print("Add read node (%d, %d)" % (ri.group_id, ri.pid))

                read_node = self.graph.get_node(ri.group_id, ri.pid)
                assert (read_node)
                read_node.add_read(ri)

                for (r, write) in writes.iteritems():
                    if not self.graph.has_node(write.group_id, write.pid):
                        program_cmd = self.rldb.get_program_args(write.group_id, write.pid)
                        self.graph.add_node(write.group_id, write.pid, cmd=program_cmd)
                        new_writes.append(write)
                    write_node = self.graph.get_node(write.group_id, write.pid)
                    assert(write_node)
                    write_node.add_write(write)
                    if self.runtime_info.verbose:
                        print("Add write node (%d, %d)" % (write.group_id, write.pid))
                    # add an edge from this write to the read
                    write_node.add_edge(read_node, write, r)

            # combine writes with the same group id
            combined_writes = collections.defaultdict(list)
            for nw in new_writes:
                combined_writes[nw.group_id].append(nw)
            combined_new_writes = list(combined_writes.values())
            for cbw in combined_new_writes:
                self.run_queue.append(cbw)
                if self.runtime_info.verbose:
                    # print them out for debugging
                    print("Appended list writes: [")
                    for cb in cbw:
                        print(cb)
                    print("]")
            
        self.query_end_time = time.time()
        print("Query took %f sec" % (self.query_end_time - self.query_start_time))
        return True

    def draw_graph(self, output_file="/tmp/output.dot"):
        self.graph.visualize_graph(output_file)

def main(args):
    # Usage: python query.py <replay dir> <replay group> <pid> <syscall cnt>

    print("Replay directory is " + args.replay_directory)

    linkages = []
    if args.linkages:
        linkages = map(lambda x: x.upper(), args.linkages)

    tools_location = ''
    if args.omniplay:
        tools_location = ''.join([os.path.abspath(args.omniplay), "/pin_tools/obj-ia32"])
    query = Query(args.replay_directory, tools_location, linkages)
    query.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Query script")
    parser.add_argument("replay_directory", help="Directory of the replay to start the query on")
    parser.add_argument("-l", "--linkages", help="The linkages to use to run the query",
            nargs='+', dest='linkages')
    parser.add_argument("-m", "--omniplay", 
                        help="Your omniplay path, otherwise it assumes \
                                it is in your home directory",
                        dest='omniplay')
    args = parser.parse_args()
    main(args)
