#!/usr/bin/python

import argparse
import sys
import os
import time
import subprocess
import sqlite3
import collections
import re

# our modules
import ipc
import logdb
import opinfo
import runtime

class Query(object):
    def __init__(self, runtime_info, write_infos, linkages=[]):
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

        self.run_queue.append(write_infos)
        
        # for querying meta information
        self.rldb = logdb.ReplayLogDB(self.runtime_info.omniplay_location, logdb_name="replay.db", logdb_dir="/replay_logdb", replay_table_name="replays")

        self.linkage_tool = self.find_linkage_tool()
        if not self.linkage_tool:
            print("Could not find appropriate linkage")
            sys.exit(0)

    def find_linkage_tool(self):
        '''
        Given the linkages asked for in the query, pick out the correct tool
        '''
        linkages = map(lambda x: x.upper(), self.linkages)
        linkage_tool_name = ''

        if "COPY" in linkages:
            if "DATA" in linkages:
                linkage_tool_name = "linkage_data.so"
            else:
                linkage_tool_name = "linkage_copy.so"
        else:
            print("No supported linkages of that type, defaulting to copy")
            linkage_tool_name = "linkage_copy.so"

        return linkage_tool_name

    def lookup_sourcing_read(self, read_info):
        rldb = logdb.ReplayLogDB(self.runtime_info.omniplay_location)
        rldb.init_cursor()

        links = rldb.lookup_writes(read_info)
        rldb.close_cursor()

        return links

    def verify_replay(self):
        return os.path.isfile(self.query_output)

    def find_matching_exec(self, group_id, pid):
        klog = self.rldb.get_replay_directory(group_id) + "/klog.id." + str(pid)
        if self.runtime_info.verbose:
            print("Find matching exec in klog %s" % klog)
        assert os.path.exists(klog)

        if self.runtime_info.verbose:
            print("Trying to find matching exec for group id %d, pid %d" %
                    (group_id, pid))

        cmd = ''.join([self.runtime_info.omniplay_location, "/test/parseklog ", klog])
        if self.runtime_info.verbose:
            print(cmd)
        logproc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        logout = logproc.communicate()[0]

        # parse parseklog output
        idx = -1
        lines = logout.split('\n')
        for line in lines:
            line = line.strip()
            m = re.match("^([0-9]*): sysnum *([0-9]*) flags [0-9]* retval.*begin", line)
            if not m:
                continue
            try:
                syscall_idx = int(m.group(1))
                syscall_num = int(m.group(2))

                if syscall_num == 11:
                    idx = syscall_idx
                    # keep going though because we want the last successful exec
            except ValueError:
                continue

        if idx == -1:
            if self.runtime_info.verbose:
                print("No matching exec found in parent")
            return None

        if self.runtime_info.verbose:
            print("Found matching exec for group id %d, pid %d at syscall index %d" %
                    (group_id, pid, idx))

        exec_info = opinfo.ExecInfo(group_id, pid, idx, 0)
        return exec_info

    def parse_query_output(self):

        def __instance_check(obj, op_type):
            return (op_type == "WRITE" and isinstance(obj, opinfo.WriteInfo)) or \
                    (op_type == "READ" and isinstance(obj, opinfo.ReadInfo)) or \
                    (op_type == "EXEC" and isinstance(obj, opinfo.ExecInfo))

        prev_write_info = None
        prev_read_info = None
        links = {}

        q = open(self.query_output, "r")
        for line in q:
            # ignore comments
            if line.startswith("#"):
                continue
            # print(line.strip())
            # format: TYPE CHANNEL GROUPID RECORDPID SYSCALLCNT OFFSET
            fields = line.split(" ")
            assert len(fields) == 12
            (write_type, write_channel, write_rec_group, write_pid, write_syscall, write_idx) = \
                    (fields[0], fields[1], int(fields[2]), int(fields[3]), int(fields[4]), int(fields[5]))
            (read_type, read_channel, read_rec_group, read_pid, read_syscall, read_idx) = \
                    (fields[6], fields[7], int(fields[8]), int(fields[9]), int(fields[10]), int(fields[11]))

            if prev_write_info is None:
                if write_type == "WRITE":
                    prev_write_info = opinfo.WriteInfo(write_rec_group, write_pid, write_syscall, write_idx, channel=write_channel)
                elif write_type == "EXEC":
                    prev_write_info = opinfo.ExecInfo(write_rec_group, write_pid, write_syscall, write_idx, channel=write_channel)
            elif prev_write_info.group_id == write_rec_group and \
                        prev_write_info.pid == write_pid and \
                        prev_write_info.syscall == write_syscall and \
                        prev_write_info.channel == write_channel and \
                        __instance_check(prev_write_info, write_type):
                prev_write_info.size += 1
            else:
                if write_type == "WRITE":
                    prev_write_info = opinfo.WriteInfo(write_rec_group, write_pid, write_syscall, write_idx, channel=write_channel)
                elif write_type == "EXEC":
                    prev_write_info = opinfo.ExecInfo(write_rec_group, write_pid, write_syscall, write_idx, channel=write_channel)

            if prev_read_info is None:
                if read_type == "READ":
                    prev_read_info = opinfo.ReadInfo(read_rec_group, read_pid, read_syscall, read_idx, channel=read_type)
                elif read_type == "EXEC":
                    prev_read_info = opinfo.ExecInfo(read_rec_group, read_pid, read_syscall, read_idx, channel=read_type)
            elif prev_read_info.group_id == read_rec_group and \
                    prev_read_info.pid == read_pid and \
                    prev_read_info.syscall == read_syscall and \
                    prev_read_info.channel == read_channel and \
                    __instance_check(prev_read_info, read_type):
                 prev_read_info.size += 1
            else:
                if read_type == "READ":
                    prev_read_info = opinfo.ReadInfo(read_rec_group, read_pid, read_syscall, read_idx, channel=read_type)
                elif read_type == "EXEC":
                    prev_read_info = opinfo.ExecInfo(read_rec_group, read_pid, read_syscall, read_idx, channel=read_type)

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
            attach_process = self.runtime_info.attach_tool(replay_process.pid, self.linkage_tool, self.query_output, self.query_log)
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
                # internal process links
                ri = links[wi]
                # now find the IPC links for this read
                if (isinstance(ri, opinfo.ReadInfo)):
                    writes = self.lookup_sourcing_read(ri)
                    if self.runtime_info.verbose:
                        print("Found %d writes for read %s" % (len(writes), str(ri)))

                    if not self.graph.has_node(ri.group_id, ri.pid):
                        program_cmd = self.rldb.get_program_args(ri.group_id)
                        self.graph.add_node(ri.group_id, ri.pid, cmd=program_cmd)
                        if self.runtime_info.verbose:
                            print("Add read node (%d, %d)" % (ri.group_id, ri.pid))

                    read_node = self.graph.get_node(ri.group_id, ri.pid)
                    assert (read_node)
                    read_node.add_read(ri)

                    for (r, write) in writes.iteritems():
                        if not self.graph.has_node(write.group_id, write.pid):
                            program_cmd = self.rldb.get_program_args(write.group_id)
                            self.graph.add_node(write.group_id, write.pid, cmd=program_cmd)
                            new_writes.append(write)
                        write_node = self.graph.get_node(write.group_id, write.pid)
                        assert(write_node)
                        write_node.add_write(write)
                        if self.runtime_info.verbose:
                            print("Add write node (%d, %d)" % (write.group_id, write.pid))
                        # add an edge from this write to the read
                        write_node.add_edge(read_node, write, r)
                elif (isinstance(ri, opinfo.ExecInfo)):
                    parent_id = self.rldb.get_parent_id(ri.group_id)
                    if parent_id == 0:
                        continue
                    assert parent_id != wi.group_id
                    if self.runtime_info.verbose:
                        print("Match exec in group %d, pid %d from parent %d" % (ri.group_id, ri.pid, parent_id))
                    exec_info = self.find_matching_exec(parent_id, ri.pid)
                    if not exec_info:
                        if self.runtime_info.verbose:
                            print("No matching exec found for parent id %d" % parent_id)
                        continue
                    if not self.graph.has_node(exec_info.group_id, exec_info.pid):
                        program_cmd = self.rldb.get_program_args(exec_info.group_id)
                        if not program_cmd:
                            if self.runtime_info.verbose:
                                print("Could not find cmd for group %d, pid %d" % (exec_info.group_id, exec_info.pid))
                            program_cmd = ''
                        self.graph.add_node(exec_info.group_id, exec_info.pid, cmd=program_cmd)
                        new_writes.append(exec_info)
                    exec_node = self.graph.get_node(exec_info.group_id, exec_info.pid)
                    assert(exec_node)

                    # add edge between exec's
                    read_node = self.graph.get_node(ri.group_id, ri.pid)
                    exec_node.add_edge(read_node, exec_info, ri)

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
