import os
import sys
import sqlite3
import subprocess
import collections
import re

class GraphEdge(object):
    def __init__(self, read_log, read_pid, read_sysnum, read_offset, read_size, write_log, write_pid, write_sysnum, write_offset, write_size, exhausts_reader=0, exhausts_writer=0):
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
        #return ''.join(["OrderedPipe(read_log=", str(self.read_log), ", read_pid=", str(self.pid), ", sysnum=", str(self.sysnum), ", size=", str(self.size), ", pipe_offset=", str(self.pipe_offset), ", write_id=", str(self.write_id), ")"])
        return str(self.__dict__)
   


class ParseInfo(object):
    def __init__(self, ctime=0, program_name="", log_id=0, record_pid=0, program_args="", replay_graph=None):
        self.ctime = ctime
        self.program_name = program_name
        self.logid = log_id
        self.record_pid = record_pid
        self.program_args = program_args
        self.replay_graph = replay_graph



class OrderedPipe(object):
    def __init__(self, log_id, pid, sysnum, size, pipe_offset, writer_id=0):
        self.log_id = log_id
        self.sysnum = sysnum
        self.size = size
        self.write_id = writer_id
        self.pipe_offset = pipe_offset
        self.pid = pid

    def __str__(self):
        return ''.join(["OrderedPipe(logid=", str(self.log_id), ", pid=", str(self.pid), ", sysnum=", str(self.sysnum), ", size=", str(self.size), ", pipe_offset=", str(self.pipe_offset), ", write_id=", str(self.write_id), ")"])
   
    def get_graph_edge(self, writer_pipe):
        # Figure out which bytes this writer supplys by matching the pipe_size
        # Make sure this writer satisfies something from this reader
        if writer_pipe.pipe_offset > self.pipe_offset + self.size or writer_pipe.pipe_offset + writer_pipe.size < self.pipe_offset:
            return None

        # Now, find the overlapping range

        min_offset = max(writer_pipe.pipe_offset, self.pipe_offset)
        max_offset = min(writer_pipe.pipe_offset + writer_pipe.size, self.pipe_offset + self.size)
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
        edge = GraphEdge(self.log_id, self.pid, self.sysnum, read_offset, size, writer_pipe.log_id, writer_pipe.pid, writer_pipe.sysnum, write_offset, size, exhausts_reader, exhausts_writer)
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
        return ''.join(["UnorderedPipe(logid=", str(self.log_id), ", pid=", str(self.pid), ", sysnum=", str(self.sysnum), ", writer_id=", str(self.writer_id),  ", size=", str(self.size), ", start_clock=", str(self.start_clock), ")"])

    def get_offset(self, prevPipe):
        assert(prevPipe is None or self.log_id == prevPipe.log_id)
        if (prevPipe is None):
            return OrderedPipe(self.log_id, self.pid, self.sysnum, self.size, 0)
        else:
            return OrderedPipe(self.log_id, self.pid, self.sysnum, self.size, prevPipe.pipe_offset+prevPipe.size)

class PipeInfo(object):
    def __init__(self, logdb):
        self.db = logdb
        # Dictionary, [id] = pipe(reader) array 
        self.pipes = collections.defaultdict(list)
        self.ordered_pipes = collections.defaultdict(list)

    def add_pipe(self, log_id, pipe_id, pid, sysnum, writer_id, size, start_clock):
        pipe = UnorderedPipe(log_id, pid, sysnum, writer_id, size, start_clock)
        self.pipes[pipe_id].append(pipe)
        
    def add_ordered_pipe(self, log_id, pid, read_sysnum, read_offset, read_size, write_id, write_pipe, write_offset, write_size): 
        pipe = OrderedPipe(log_id, pid, read_sysnum, read_size, write_offset, write_id)
        self.ordered_pipes[write_pipe].append(pipe)

    def get_writes(self, log_id, write_array, pipe_id):
        '''
        Find the rec directory for log_id
        foreach klog in directory
            parseklog with -p
            regex parse
            Add the data to a write_array
        '''

        logdb_dir = self.db.logdb_dir

        # get a list of replay directories
        klog_directory = ''.join([logdb_dir, "/rec_", str(log_id)])
        # filter out everything that is not a directory
        klog_files = os.listdir(klog_directory)
        klog_files = filter(lambda x: x.startswith("klog"), klog_files)
        # Gets the full path
        klog_files = map(lambda x: ''.join([klog_directory, "/", x]), klog_files)

        for klog in klog_files:
            # First, figure out the record pid
            fields = klog.split(".")
            pid = int(fields[-1])

            # Now, parse the output of the parseklog file
            cmd = ''.join([self.db.omniplay_path, "/test/parseklog ", klog, " -p"])
            logproc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            graphoutput = logproc.communicate()[0]

            lines = graphoutput.split('\n')
            for line in lines:
                line = line.strip()
                match = re.match("^([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)", line)
                if match is not None:
                    if int(match.group(1)) == pipe_id:
                        write_array.append(UnorderedPipe(log_id, pid, int(match.group(4)), log_id, int(match.group(2)), int(match.group(3))));


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
            sorted_readers = sorted(pipe_readers, key=lambda pipe_reader: pipe_reader.start_clock)
            prev_pipe = None
            ordered_readers = []
            for pipe in sorted_readers:
                ret_pipe = pipe.get_offset(prev_pipe)
                ordered_readers.append(ret_pipe)
                prev_pipe = ret_pipe

            log_id = pipe_readers[0].writer_id

            '''
            Now, get all writes from this log_id
            '''
            write_array = []
            self.get_writes(log_id, write_array, pipe_id)

            sorted_writers = sorted(write_array, key=lambda pipe_writer: pipe_writer.start_clock)
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

            sorted_writers = sorted(write_array, key=lambda pipe_writer: pipe_writer.start_clock)
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

class ReplayLogDB(object):
    '''
    Class holding the operations for creating, insert, querying the replay db.

    Using sqlite3 for now...we might want to change the backing db store later.
    Need to change create_table, replay_id_exists, and insert_replay then.
    '''
    def __init__(self, omniplay_path, logdb_name="replay.db", logdb_dir="/replay_logdb", replay_table_name="replays", graph_table_name="graph_edges"):
        # Path of the omniplay root directory
        self.omniplay_path = omniplay_path

        # name of the logdb
        self.logdb_name = logdb_name

        # logdb directory (absolute path)
        self.logdb_dir = os.path.abspath(logdb_dir)

        # name of the table in the DB
        self.replay_table_name = replay_table_name
        
        self.graph_table_name = graph_table_name

    def get_logdb_path(self):
        return ''.join([self.logdb_dir, "/", self.logdb_name])

    def get_ndx_path(self):
        return ''.join([self.logdb_dir, "/", "ndx"])

    def create_table(self):
        '''
        Create a new table in the db for replays
        '''
        logdb = self.get_logdb_path() 
        conn = sqlite3.connect(logdb)

        c = conn.cursor()

        # create a table indexing the replays
        # date: time replay started in seconds since epoch (bleh, no good way to store dates in sqlite)
        # id: log id
        # record_pid: record pid
        # program: short program name, e.g. ls
        # args: arguments to the program, e.g. -l
        sql = '''CREATE TABLE IF NOT EXISTS {table_name} 
        (date INT, id INT, record_pid INT, program TEXT, args TEXT)'''.format(table_name=self.replay_table_name)
        c.execute(sql)

        sql = '''CREATE TABLE IF NOT EXISTS {table_name} 
        (write_id INT, write_pid INT, write_sysnum INT, write_offset INT, write_size INT, read_id INT, read_pid INT, read_sysnum INT, read_offset INT, read_size INT)'''.format(table_name=self.graph_table_name)
        c.execute(sql)

        conn.commit()

        conn.close()

        print("Created db %s" % self.logdb_name)

    def replay_id_exists(self, replay_id):
        '''
        Returns True if replay_id exists in the db, False otherwise
        '''
        conn = sqlite3.connect(self.get_logdb_path())
        c = conn.cursor()

        c.execute("SELECT * from {table_name} WHERE id=?".format(table_name=self.replay_table_name),
                (replay_id, ))
        fetched = c.fetchone()
        if fetched is None:
            return False
        return True

    def insert_replay(self, ctime, program_name, log_id, record_pid, args):
        '''
        Insert a replay into the DB
        '''
        conn = sqlite3.connect(self.get_logdb_path())
        c = conn.cursor()
        values = (ctime, log_id, record_pid, program_name, args)
        c.execute('''INSERT INTO {table_name} VALUES (?,?,?,?,?)'''.format(table_name=self.replay_table_name),
                values)
        conn.commit()
        conn.close()

    def insert_graph(self, graph_edges):
        '''
        Insert a replay into the DB
        '''
        conn = sqlite3.connect(self.get_logdb_path())
        c = conn.cursor()
        for edge in graph_edges:
            (read_id, read_pid, read_sysnum, read_offset, read_size, write_id, write_pid, write_sysnum, write_offset, write_size) = (edge.read_log, edge.read_pid, edge.read_sysnum, edge.read_offset, edge.read_size, edge.write_log, edge.write_pid, edge.write_sysnum, edge.write_offset, edge.write_size)
            values = (write_id, write_pid, write_sysnum, write_offset, write_size, read_id, read_pid, read_sysnum, read_offset, read_size)
            c.execute('''INSERT INTO {table_name} VALUES (?,?,?,?,?,?,?,?,?,?)'''.format(table_name=self.graph_table_name),
                    values)
        conn.commit()
        conn.close()

    def populate(self):
        '''
        Goes through the replay_logdb directory and inserts a record for replays that
        it already hasn't inserted.
        '''
        # get a list of replay directories
        replay_directories = os.listdir(self.logdb_dir)
        # filter out everything that is not a directory
        replay_directories = filter(lambda x: not os.path.isdir(x), replay_directories)
        # Gets the full path
        replay_directories = map(lambda x: ''.join([self.logdb_dir, "/", x]), replay_directories)

        for directory in replay_directories:
            # parse ckpt
            info = self.parse_directory(directory)
            if info is None:
                if directory != self.get_logdb_path() and directory != self.get_ndx_path():
                    print("could not parse %s" % directory)
                continue
            (ctime, program_name, log_id, record_pid, args, graph_edges) = (info.ctime, info.program_name, info.logid, info.record_pid, info.program_args, info.replay_graph)

            # see if id in db
            if self.replay_id_exists(log_id):
                print("Skipping %s because it's already in the db" % directory)
                continue

            assert(graph_edges is not None)
            self.insert_replay(ctime, program_name, log_id, record_pid, args)
            self.insert_graph(graph_edges)
            print("Inserted replay id %d" % log_id)

    def parse_directory(self, logdb_dir):
        '''
        Calls the parseckpt program and parses its output.

        Returns a tuple (program_name, log_id, record_pid, args)
        Returns None if it can't parse the log directory
        '''
        if not os.path.isdir(logdb_dir):
            #print("%s is not a directory" % logdb_dir)
            return None
        ckpt = logdb_dir + "/ckpt"
        if not os.path.isfile(ckpt):
            print("No ckpt in directory %s" % logdb_dir)
            return None

        # get a list of replay directories
        klog_directories = os.listdir(logdb_dir)
        # filter out everything that is not a directory
        klog_directories = filter(lambda x: x.startswith("klog"), klog_directories)
        # Gets the full path
        klog_directories = map(lambda x: ''.join([logdb_dir, "/", x]), klog_directories)
        
        # information to extract from the replay directory
        program_name = ""
        logid = 0
        record_pid = 0
        program_args = ""

        # get the time the ckpt was last modified
        # (ideally we would want the creation time, but it doesn't seem like
        #  it's easy to do in Python)
        ctime = int(os.stat(ckpt).st_ctime)

        # execute parseckpt
        parse_ckpt = self.omniplay_path + "/test/parseckpt"
        cmd = ''.join([parse_ckpt, " ", logdb_dir])
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        output = process.communicate()[0]

        # get ID from logdb
        try:
            fields = logdb_dir.split("_")
            logid = int(fields[-1])
        except:
            # 0 for default
            logid = 0

        graph_edges = []
        pipeInfo = PipeInfo(self)
        for directory in klog_directories:
            # First, figure out the record pid
            fields = directory.split(".")
            pid = int(fields[-1])

            # Now, parse the output of the parseklog file
            cmd = ''.join([self.omniplay_path, "/test/parseklog ", directory, " -g"])
            logproc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            graphoutput = logproc.communicate()[0]

            lines = graphoutput.split('\n')
            for line in lines:
                line = line.strip()
                match = re.match("^([0-9]+) ([0-9]+) ([0-9]+) {([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)}", line)
                if match is not None:
                    graph_edges.append(GraphEdge(logid, pid, int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4)), int(match.group(5)), int(match.group(6)), int(match.group(7)), int(match.group(8))));
                else:
                    match = re.match("^pipe: ([0-9]+) ([0-9]+) ([0-9]+) {([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)}", line)
                    if match is not None:
                        if (int(match.group(5)) == 0):
                            pipeInfo.add_ordered_pipe(logid, pid, int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4)), int(match.group(6)), int(match.group(7)), int(match.group(8)));
                        else:
                            graph_edges.append(GraphEdge(logid, pid, int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4)), int(match.group(5)), int(match.group(6)), int(match.group(7)), int(match.group(8))));
                    else:
                        match = re.match("^pipe: ([0-9]+), ([0-9]+), ([0-9]+) {([0-9]+)} {([0-9]+)}", line)
                        if match is not None:
                            #pipe: writer_id, pipe_id, sysnum {size} {start_clock}
                            pipeInfo.add_pipe(logid, int(match.group(2)), pid,  int(match.group(3)), int(match.group(1)), int(match.group(4)), int(match.group(5)));

        pipeInfo.compute_pipes(graph_edges)

        # split by newline, parse for information
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith("record pid:"):
                fields = line.split(" ")
                if len(fields) != 3:
                    print("ERROR: parseckpt format must have changed!")
                    print("See line: %s (directory %s)" % (line, logdb_dir))
                    return None
                try:
                    record_pid = int(fields[2])
                except ValueError:
                    print("ERROR: parseckpt format must have changed!")
                    print("See line: %s (directory %s)" % (line, logdb_dir))
                    return None
            elif line.startswith("Argument"):
                fields = line.split(" ")
                if len(fields) < 4:
                    print("ERROR: parseckpt format must have changed!")
                    print("See line: %s (directory %s)" % (line, logdb_dir))
                    return None

                arg_num = fields[1]
                try:
                    arg_num = int(arg_num)
                except ValueError:
                    print("ERROR: parseckpt format must have changed!")
                    print("See line: %s (directory %s)" % (line, logdb_dir))
                    return None

                if arg_num == 0:
                    program_name = fields[3]
                else:
                    program_args = ''.join([program_args, " ", fields[3]])

        return ParseInfo(ctime, program_name, logid, record_pid, program_args, graph_edges)

