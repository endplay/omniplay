#!/usr/bin/python

import re
import os
import sys
import time
import shlex
import sqlite3
import argparse
import subprocess
import collections
from operator import attrgetter

import pydot

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
	# relative to the process's log directory
        self.query_output = "query_output"

        # IPC graph to walk up as the query is done
        self.graph = ipc.IPCGraph()

        # list of lists of write infos
        # Invariant: All the write infos in an element must have 
        #   the same group id
        #   represents a node/group id to replay
        self.run_queue = []

        # timings
        self.tool_start = 0
        self.tool_end = 0

        self.query_start_time = 0
        self.query_end_time = 0

        self.run_queue.append(write_infos)
        
        # for querying meta information
        self.rldb = logdb.ReplayLogDB(self.runtime_info.omniplay_location,
                                        logdb_name="replay.db",
                                        logdb_dir="/replay_logdb",
                                        replay_table_name="replays")

        self.linkage_tool = self.find_linkage_tool()
        if not self.linkage_tool:
            print("Could not find appropriate linkage")
            sys.exit(0)

        # the current pid and group id of the 
        # replay process the query is currently running
        self.current_pid = 0
        self.current_gid = 0

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
        elif "DATA" in linkages:
            linkage_tool_name = "linkage_data.so"
        else:
            print("No supported linkages of that type, defaulting to copy")
            linkage_tool_name = "linkage_copy.so"

        return linkage_tool_name

    def lookup_sourcing_read(self, group_id, pid, syscall):
        rldb = logdb.ReplayLogDB(self.runtime_info.omniplay_location)
        rldb.init_cursor()

        links = rldb.lookup_sourcing_writes(group_id, pid, syscall)
        rldb.close_cursor()

        return links

    def verify_replay(self):
        path = "/tmp/" + str(self.current_pid) + "/" + self.query_output
        print("verify replay path: %s" % path)
        return os.path.exists("/tmp/" + str(self.current_pid) + self.query_output)

    def find_matching_exec(self, group_id, pid):
        klog = self.rldb.get_replay_directory(group_id) + "/klog.id." + str(pid)
        if self.runtime_info.verbose:
            print("Find matching exec in klog %s" % klog)
        assert os.path.exists(klog)

        if self.runtime_info.verbose:
            print("Trying to find matching exec for group id %d, pid %d" %
                    (group_id, pid))

        cmd = ''.join([self.runtime_info.omniplay_location,
                            "/test/parseklog ", klog])
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

    def interpret_query_output(self):
        '''
        We need a post-processing step after the linkage tool is run.
        The output is in a binary format that needs to be interpreted
        and the mapping from the tokens also needs to be interpreted.
        '''
        interpret_tokens = self.runtime_info.tools_location + "/interpret_tokens"
        assert os.path.exists(interpret_tokens)

        assert (self.current_pid)
        assert (self.current_gid)
        tokens_file = ''.join(["/tmp/", str(self.current_pid), "/tokens_", str(self.current_gid)])
        filenames_file = ''.join(["/tmp/", str(self.current_pid), "/filenames_", str(self.current_gid)])
        interpret_file = "/tmp/interpret_result"
        assert os.path.exists(interpret_tokens)
        query_output = ''.join(["/tmp/", str(self.current_pid), "/", self.query_output])
        cmd = ' '.join([interpret_tokens, tokens_file, filenames_file, query_output, interpret_file])
        print(cmd)

        process = subprocess.Popen(shlex.split(cmd), shell=False, stderr=subprocess.PIPE)
        process.wait()
        stderr_output = process.communicate()[1]
        if stderr_output:
            print("There was an error interpretting the tokens")
            print(stderr_output)
            sys.exit(1)

        # update the output file
        self.query_output = interpret_file

    def parse_query_output(self):

        def __instance_check(obj, op_type):
            return (op_type == "WRITE" and isinstance(obj, opinfo.WriteInfo)) or \
                    (op_type == "READ" and isinstance(obj, opinfo.ReadInfo)) or \
                    (op_type == "EXEC" and isinstance(obj, opinfo.ExecInfo))

        prev_write_info = None
        prev_read_info = None
        links = collections.defaultdict(list)

        q = open(self.query_output, "r")
        for line in q:
            # ignore comments
            if line.startswith("#"):
                continue
            # print(line.strip())
            # format: TYPE CHANNEL GROUPID RECORDPID SYSCALLCNT OFFSET
            fields = line.split(" ")
            assert len(fields) == 12

            write_type = fields[0]
            write_channel = fields[1]
            write_rec_group = int(fields[2])
            write_pid = int(fields[3])
            write_syscall = int(fields[4])
            write_idx = int(fields[5])

            # sourcing read
            read_type = fields[6]
            read_channel = fields[7]
            read_rec_group = int(fields[8])
            read_pid = int(fields[9])
            read_syscall = int(fields[10])
            read_idx = int(fields[11])

            # group together writes, group together reads that point to the same write
            if write_type == "WRITE":
                write_info = opinfo.WriteInfo(write_rec_group,
                                                write_pid,
                                                write_syscall,
                                                write_idx,
                                                channel=write_channel)
            elif write_type == "EXEC":
                write_info = opinfo.ExecInfo(write_rec_group,
                                                write_pid,
                                                write_syscall,
                                                write_idx,
                                                channel=write_channel)
            else:
                print("Unknown write type %s" % write_type)
                continue

            if read_type == "READ":
                read_info = opinfo.ReadInfo(read_rec_group,
                                                read_pid,
                                                read_syscall,
                                                read_idx,
                                                channel=read_channel)
            elif read_type == "EXEC":
                read_info = opinfo.ExecInfo(read_rec_group,
                                                read_pid,
                                                read_syscall,
                                                read_idx,
                                                channel=read_channel)
            else:
                print("Unknown read type %s" % read_type)
                continue

            links[write_info].append(read_info)

        return links

    def visualize_query_output(self, links, writes, output_file):
        '''
        Create a dot graph of an intraprocess links, for a given input set of writes
        '''
        graph = pydot.Dot(graph_type='digraph', rankdir='LR')

        write2reads = {}
        # mapping from ReadInfo to pydot Node
        read_nodes = {}

        # sort the writes
        writes = sorted(writes, key=attrgetter('group_id', 'pid', 'syscall', 'offset'))

        # go through the links and create the nodes
        for write in writes:
            reads = []
            for i in range(0, write.size):
                tmp_write = opinfo.WriteInfo(write.group_id, write.pid,
                                            write.syscall, write.offset + i,
                                            channel=write.channel,
                                            size=1)
                if tmp_write not in links:
                    continue
                for r in links[tmp_write]:
                    reads.append(r)

            reads = opinfo.remove_dups(reads)
            reads = opinfo.group_infos(reads)
            write2reads[write] = reads

        # now repartition the writes into ranges that only have the same reads
        repart_writes = []
        prev_write = None
        for write in writes:
            for i in range(0, write.size):
                if prev_write is None:
                    prev_write = opinfo.WriteInfo(write.group_id, write.pid, write.syscall, write.offset,
                                                    channel=write.channel, size=1)
                    repart_writes.append(prev_write)
                else:
                    # check to see if the write is next continuously and if they have the same sourcing reads
                    if (write.offset == (prev_write.offset + prev_write.size)) and \
                            opinfo.compare_lists(write2reads[write], write2reads[prev_write]):
                        prev_write.size += 1 
                    else:
                        prev_write = opinfo.WriteInfo(write.group_id, write.pid, write.syscall, write.offset,
                                                    channel=write.channel, size=1)
                        repart_writes.append(prev_write)

        if self.runtime_info.verbose:
            for write in repart_writes:
                print("%s" % write)

        for write in repart_writes:
            write_name = 'WRITE \n'
            write_name += ('Group %d, Pid %d, Syscall %d, Offset %d, size %d' % (
                    write.group_id, write.pid, write.syscall, write.offset, write.size))
            write_name += ('\n%s' % write.channel)
            write_node = pydot.Node(write_name, shape="box")
            graph.add_node(write_node)

            for r in reads:
                if (r, r.size) not in read_nodes:
                    read_name = 'READ\n'
                    read_name += ('Group %d, Pid %d, Syscall %d, Offset %d, size %d' % (
                        r.group_id, r.pid, r.syscall, r.offset, r.size))
                    read_name += ('\n%s' % r.channel)
                    read_node = pydot.Node(read_name, shape="box")
                    read_nodes[(r, r.size)] = read_node
                read_node = read_nodes[(r, r.size)]
                graph.add_node(read_node)
                edge = pydot.Edge(read_node, write_node)
                graph.add_edge(edge)

        graph.write(output_file)

        print("Done writing intraprocess graph!")

    def run(self):
        '''
        Actually run the query. Here are the steps that happen when running a query:
        1) Get the replay group id to replay from the write info
        2) Start the replay
        3) Attach the correct Pin tool and wait until it's done executing
        4) Do post-processing on the output, in order to interpret the binary output
        and do token interpretation.
        5) Parse the output from the linkage tool, producing intraprocess
        read to write links
        6) Query the IPC graph database for the writes that produced the the reads.
        7) Repeat starting from step 1 for each of the writes
        '''
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
            replay_process = self.runtime_info.replay(replay_dir,
                                                        self.query_log,
                                                        pin=True)
            self.current_pid = replay_process.pid
            self.current_gid = group_id

            # wake for a little interval
            time.sleep(1)

            self.tool_start = int(time.time())
            attach_process = self.runtime_info.attach_tool(replay_process.pid,
                                                            self.linkage_tool,
                                                            self.query_output,
                                                            self.query_log)
            attach_process.wait()
            replay_process.wait()
            self.tool_end = int(time.time())
            print("Copy tool took %d secs" % (self.tool_end - self.tool_start))

            # make sure that the replay suceed
            # if not self.verify_replay():
            #     print("ERROR: query failed to replay, group id %d, linkage copy" % (group_id))
            #     print("You might want to look for errors in %s" % self.query_log_filename)
            #     return False

            # TODO: might want to make a copy of the output somewhere for debugging purposes

            new_writes = []
            # Extra post-processing step for interpreting tokens
            self.interpret_query_output()
            # find intraprocess links
            links = self.parse_query_output()
            # For every write that we are interested in, 
            #   look up the write to the sourcing read
            for wi in wis: 

                # reads associated with sourcing this write range
                sourcing_reads = []
                for i in range(0, wi.size):
                    tmp_write = opinfo.WriteInfo(wi.group_id, wi.pid,
                                                    wi.syscall,
                                                    wi.offset + i,
                                                    channel=wi.channel,
                                                    size=1)
                    if tmp_write not in links:
                        continue
                    # add reads from intraprocess links
                    for r in links[tmp_write]:
                        sourcing_reads.append(r)

                if not sourcing_reads:
                    if self.runtime_info.verbose:
                        print("No info found for: %s" % str(wi))
                    continue

                sourcing_reads = opinfo.remove_dups(sourcing_reads)
                sourcing_reads = opinfo.group_infos(sourcing_reads)
                # now find the IPC links for each read group
                for ri in sourcing_reads:
                    if (isinstance(ri, opinfo.ReadInfo)):
                        # query the DB
                        ipc_links = self.lookup_sourcing_read(ri.group_id, ri.pid, ri.syscall)
                        if self.runtime_info.verbose:
                            print("Found %d IPC writes for read %s" % 
                                    (len(ipc_links), str(ri)))

                        # create a node in the IPC graph for the process that
                        #  produced the read if we haven't created it yet
                        if not self.graph.has_node(ri.group_id, ri.pid):
                            program_cmd = self.rldb.get_program_args(ri.group_id)
                            self.graph.add_node(ri.group_id, ri.pid, cmd=program_cmd)
                            if self.runtime_info.verbose:
                                print("Add read node (%d, %d)" % (ri.group_id, ri.pid))

                        read_node = self.graph.get_node(ri.group_id, ri.pid)
                        assert (read_node)
                        read_node.add_read(ri)

                        for (r, write) in ipc_links.iteritems():
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



                if (isinstance(ri, opinfo.ReadInfo)):
                    # query the DB
                    writes = self.lookup_sourcing_read(ri.group_id, ri.pid, ri.syscall)
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
                        print("Match exec in group %d, pid %d from parent %d" % 
                                (ri.group_id, ri.pid, parent_id))
                    exec_info = self.find_matching_exec(parent_id, ri.pid)
                    if not exec_info:
                        if self.runtime_info.verbose:
                            print("No matching exec found for parent id %d" % parent_id)
                        continue
                    if not self.graph.has_node(exec_info.group_id, exec_info.pid):
                        program_cmd = self.rldb.get_program_args(exec_info.group_id)
                        if not program_cmd:
                            if self.runtime_info.verbose:
                                print("Could not find cmd for group %d, pid %d" % 
                                        (exec_info.group_id, exec_info.pid))
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
