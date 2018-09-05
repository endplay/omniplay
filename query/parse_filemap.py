import os
import re
import collections
import subprocess

class GraphEdge(object):
    def __init__(self, read_log, read_pid, read_sysnum, read_offset, read_size,
		    write_log, write_pid, write_sysnum, write_offset, write_size, 
		    exhausts_reader=0, exhausts_writer=0):
        self.read_log = read_log
        self.read_pid = read_pid
        self.read_sysnum = read_sysnum
        self.read_offset = read_offset
        self.read_size = read_size
        self.write_log = write_log
        self.write_pid = write_pid
        self.write_sysnum = write_sysnum
        self.write_offset = write_offset
        self.write_size = write_size
        self.exhausts_reader = exhausts_reader
        self.exhausts_writer = exhausts_writer

    def __str__(self):
        return str(self.__dict__)

class OrderedPipe(object):
    def __init__(self, log_id, pid, sysnum, size, pipe_offset, writer_id=0):
        self.log_id = log_id
        self.sysnum = sysnum
        self.size = size
        self.write_id = writer_id
        self.pipe_offset = pipe_offset
        self.pid = pid

    def __str__(self):
        return ''.join(["OrderedPipe(logid=", str(self.log_id),
            ", pid=", str(self.pid), 
            ", sysnum=", str(self.sysnum),
            ", size=", str(self.size),
            ", pipe_offset=", str(self.pipe_offset),
            ", write_id=", str(self.write_id), ")"])
   
    def get_graph_edge(self, writer_pipe):
        # Figure out which bytes this writer supplys by matching the pipe_size
        # Make sure this writer satisfies something from this reader
        if writer_pipe.pipe_offset > self.pipe_offset + self.size or \
                writer_pipe.pipe_offset + writer_pipe.size < self.pipe_offset:
            return None

        # Now, find the overlapping range
        min_offset = max(writer_pipe.pipe_offset, self.pipe_offset)
        max_offset = min(writer_pipe.pipe_offset + writer_pipe.size,
                self.pipe_offset + self.size)
        exhausts_reader = False
        exhausts_writer = False
        if max_offset == self.pipe_offset + self.size:
            exhausts_reader = True
        if max_offset == writer_pipe.pipe_offset + writer_pipe.size:
            exhausts_writer = True

        size = max_offset - min_offset

        read_offset = min_offset - self.pipe_offset
        write_offset = max(min_offset - writer_pipe.pipe_offset, 0)

        # Now we create a graph edge from self to writer with offset min_offset and size size
        edge = GraphEdge(self.log_id, self.pid,
                self.sysnum, read_offset, size, 
                writer_pipe.log_id, writer_pipe.pid,
                writer_pipe.sysnum, 
                write_offset, size, exhausts_reader, exhausts_writer)
        return edge

class UnorderedPipe(object):
    def __init__(self, log_id, pid, sysnum, writer_id, size, start_clock):
        self.log_id = log_id
        self.size = size
        self.start_clock = start_clock
        self.writer_id = writer_id
        self.pid = pid
        self.sysnum = sysnum

    def __str__(self):
        return ''.join(["UnorderedPipe(logid=", str(self.log_id),
            ", pid=", str(self.pid),
            ", sysnum=", str(self.sysnum),
            ", writer_id=", str(self.writer_id),
            ", size=", str(self.size),
            ", start_clock=", str(self.start_clock), ")"])

    def get_offset(self, prevPipe):
        assert(prevPipe is None or self.log_id == prevPipe.log_id)
        if (prevPipe is None):
            return OrderedPipe(self.log_id, self.pid, self.sysnum, self.size, 0)
        else:
            return OrderedPipe(self.log_id, self.pid, self.sysnum, self.size,
                                prevPipe.pipe_offset + prevPipe.size)

class PipeInfo(object):
    def __init__(self, logdb):
        self.db = logdb
        # Dictionary, [id] = pipe(reader) array 
        self.pipes = collections.defaultdict(list)
        self.ordered_pipes = collections.defaultdict(list)

    def add_pipe(self, log_id, pipe_id, pid, sysnum, writer_id, size,
            start_clock):
        pipe = UnorderedPipe(log_id, pid, sysnum, writer_id, size, start_clock)
        self.pipes[pipe_id].append(pipe)
        
    def add_ordered_pipe(self, log_id, pid, read_sysnum, read_offset,
            read_size, write_id, write_pipe, write_offset, write_size): 
        pipe = OrderedPipe(log_id, pid, read_sysnum,
                read_size, write_offset, write_id)
        self.ordered_pipes[write_pipe].append(pipe)

    def get_writes(self, log_id, pipe_id):
        '''
        Find the rec directory for log_id
        foreach klog in directory
            parseklog with -p
            regex parse
            Add the data to a write_array
        '''
        write_array = []
        logdb_dir = self.db.logdb_dir

        # get a list of replay directories
        klog_directory = ''.join([logdb_dir, "/rec_", str(log_id)])
        # filter out everything that is not a directory
        klog_files = os.listdir(klog_directory)
        klog_files = filter(lambda x: x.startswith("klog"), klog_files)
        # Gets the full path
        klog_files = map(lambda x: ''.join([klog_directory, "/", x]),
                klog_files)

        for klog in klog_files:
            # First, figure out the record pid
            fields = klog.split(".")
            pid = int(fields[-1])

            # Now, parse the output of the parseklog file
            cmd = ''.join([self.db.omniplay_path,
                "/test/parseklog ", klog, " -p"])
            logproc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            graphoutput = logproc.communicate()[0]

            lines = graphoutput.split('\n')
            for line in lines:
                line = line.strip()
                match = re.match("^([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)",
                        line)
                if match is not None:
                    if int(match.group(1)) == pipe_id:
                        sysnum = int(match.group(4))
                        size = int(match.group(2))
                        start_clock = int(match.group(3))
                        write_array.append(UnorderedPipe(log_id, pid, sysnum, 
                                            log_id, size, start_clock))
        return write_array

    def compute_pipes(self, graph_edges):
        '''
        For each pipe_id 
            Sort the pipe_reader array by start_time
            Now, calculate the offsets
            Now, get the writer info (based on log_id)
            Sort that by start_time
            Calculate those offsets
            Now, match, then insert those into the graph edges
        '''
        for (pipe_id, pipe_readers) in self.pipes.iteritems():
            sorted_readers = sorted(pipe_readers,
                    key=lambda pipe_reader: pipe_reader.start_clock)
            prev_pipe = None
            ordered_readers = []
            for pipe in sorted_readers:
                ret_pipe = pipe.get_offset(prev_pipe)
                ordered_readers.append(ret_pipe)
                prev_pipe = ret_pipe

            log_id = pipe_readers[0].writer_id
            if log_id == 0:
                print("skipping writer id 0")
                continue

            # Now, get all writes from this log_id
            write_array = self.get_writes(log_id, pipe_id)

            sorted_writers = sorted(write_array,
                    key=lambda pipe_writer: pipe_writer.start_clock)
            ordered_writes = []
            prev_pipe = None
            for pipe in sorted_writers:
                ret_pipe = pipe.get_offset(prev_pipe)
                ordered_writes.append(ret_pipe)
                prev_pipe = ret_pipe

            if pipe_id in self.ordered_pipes:
                ordered_readers = ordered_readers + self.ordered_pipes[pipe_id]
                del self.ordered_pipes[pipe_id]

            write_itr = iter(ordered_writes)

            writer = None
            try:
                writer = next(write_itr)
            except StopIteration:
                writer = None
            read_itr = iter(ordered_readers)

            try:
                reader = next(read_itr)
            except StopIteration:
                writer = None

            have_edge = False
            if writer is not None and reader is not None:
                have_edge = True

            while have_edge:
                edge = reader.get_graph_edge(writer)
                have_edge = edge is not None

                if have_edge:
                    graph_edges.append(edge)

                if edge.exhausts_writer:
                    try:
                        writer = next(write_itr)
                    except StopIteration:
                        break

                if edge.exhausts_reader:
                    try:
                        reader = next(read_itr)
                    except StopIteration:
                        break

        for (pipe_id, ordered_readers) in self.ordered_pipes.iteritems():

            log_id = ordered_readers[0].write_id

            write_array = []
            self.get_writes(log_id, write_array, pipe_id)

            sorted_writers = sorted(write_array,
                    key=lambda pipe_writer: pipe_writer.start_clock)
            ordered_writes = []
            prev_pipe = None
            for pipe in sorted_writers:
                ret_pipe = pipe.get_offset(prev_pipe)
                ordered_writes.append(ret_pipe)
                prev_pipe = ret_pipe

            write_itr = iter(ordered_writes)

            writer = None
            try:
                writer = next(write_itr)
            except StopIteration:
                writer = None
            read_itr = iter(ordered_readers)

            try:
                reader = next(read_itr)
            except StopIteration:
                writer = None

            have_edge = False
            if writer is not None and reader is not None:
                have_edge = True

            while have_edge:
                edge = reader.get_graph_edge(writer)
                have_edge = edge is not None

                if have_edge:
                    graph_edges.append(edge)

                if edge.exhausts_writer:
                    try:
                        writer = next(write_itr)
                    except StopIteration:
                        break

                if edge.exhausts_reader:
                    try:
                        reader = next(read_itr)
                    except StopIteration:
                        break
