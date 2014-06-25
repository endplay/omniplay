import os
import sqlite3
import subprocess
import collections
import re

## our modules
import opinfo

_GraphEdge = collections.namedtuple('GraphEdge', 
        ['read_log', 'read_pid', 'read_sysnum', 'read_offset', 'read_size', 'write_log',
        'write_pid', 'write_sysnum', 'write_offset', 'write_size', 'exhausts_reader', 'exhausts_writer'])

_ParseInfo = collections.namedtuple('ParseInfo',
        ['ctime', 'program_name', 'logid', 'record_pid', 'parent_groupid', 'program_args', 'replay_graph'])

class ReplayLogDB(object):
    '''
    Class holding the operations for creating, insert, querying the replay db.

    Using sqlite3 for now...we might want to change the backing db store later.
    Need to change create_table, replay_id_exists, and insert_replay then.
    '''
    # XXX Bleh, probably need to have a file lock on the replay directory whenever I'm doing
    #  any sort of operation. But right now, assuming there's not enough concurrent access to the logdb directory as
    #  this is just a convenience DB anyways
    def __init__(self, omniplay_env, logdb_name="replay.db",
            replay_table_name="replays", graph_table_name="graph_edges"):

        # Path of the omniplay root directory
        self.omniplay_path = omniplay_env.omniplay_location

        # name of the logdb
        self.logdb_name = logdb_name

        # logdb directory (absolute path)
        self.logdb_dir = os.path.abspath(omniplay_env.logdb_dir)

        # name of the table in the DB
        self.replay_table_name = replay_table_name
        
        self.graph_table_name = graph_table_name

        # stateful state
        self.cursor = None
        self.conn = None

    def _init_cursor(self):
        self.conn = sqlite3.connect(self._get_logdb_path())
        self.cursor = self.conn.cursor()

    def _close_cursor(self):
        self.conn.commit()
        self.conn.close()

        self.conn = None
        self.cursor = None

    def _commit_transaction(self):
        self.conn.commit()

    def _get_logdb_path(self):
        return ''.join([self.logdb_dir, "/", self.logdb_name])

    def _get_ndx_path(self):
        return ''.join([self.logdb_dir, "/", "ndx"])

    def _get_replay_directory(self, group_id):
        return ''.join([self.logdb_dir, "/rec_", str(group_id)])

    def get_most_recent_replay(self, program_name):
        self._init_cursor()
        cursor = self.cursor
        assert cursor
        if program_name != "":
            sql = """SELECT MAX(id) FROM replays WHERE program LIKE '%{program_name}'""".format(
                    program_name=program_name)
        else:
            sql = '''SELECT MAX(id) FROM replays'''
        cursor.execute(sql)
        fetched = cursor.fetchone()

        self._close_cursor()

        if fetched is None:
            return None
        try:
            return int(fetched[0])
        except ValueError:
            return None
        return None

    def get_all_replays_program(self, program_name):
        self._init_cursor()
        cursor = self.cursor
        assert cursor

        if program_name != "":
            sql = """SELECT id FROM replays WHERE program LIKE '%{program_name}'""".format(program_name=program_name)
        else:
            sql = '''SELECT id FROM replays'''
        cursor.execute(sql)
        fetched = cursor.fetchall()
        self._close_cursor()
        if fetched is None:
            return None
        replay_ids = []
        for row in fetched:
            (replay_id,) = row
            try:
                return replay_ids.append(int(replay_id))
            except ValueError:
                continue
        return replay_ids

    def _create_table(self):
        '''
        Create a new table in the db for replays
        '''
        c = self.cursor

        # create a table indexing the replays
        # date: time replay started in seconds since epoch (bleh, no good way to store dates in sqlite)
        # id: log id
        # record_pid: record pid
        # program: short program name, e.g. ls
        # args: arguments to the program, e.g. -l
        sql = '''CREATE TABLE IF NOT EXISTS {table_name} 
        (date INT, id INT, record_pid INT, parent_id INT, program TEXT, args TEXT)'''
        sql = sql.format(table_name=self.replay_table_name)
        c.execute(sql)

        sql = ("CREATE TABLE IF NOT EXISTS {table_name} (write_id INT, write_pid INT, write_sysnum INT, " + 
            "write_offset INT, write_size INT, read_id INT, read_pid INT, read_sysnum INT, " + 
            "read_offset INT, read_size INT)")
        sql = sql.format(table_name=self.graph_table_name)
        c.execute(sql)

        sql = '''CREATE INDEX IF NOT EXISTS read_index on {table_name} (read_id, read_pid, read_sysnum)'''
        sql = sql.format(table_name=self.graph_table_name)
        c.execute(sql)
        
        sql = '''CREATE INDEX IF NOT EXISTS write_index on {table_name} (write_id, write_pid, write_sysnum)'''
        sql = sql.format(table_name=self.graph_table_name)
        c.execute(sql)

        self._commit_transaction()
        #print("Created db %s, with tables %s, %s" % (self.logdb_name, self.replay_table_name, self.graph_table_name))

    def _get_ids(self):
        '''
        Returns a list of IDs in the db
        '''
        ids = []
        conn = sqlite3.connect(self._get_logdb_path())
        c = conn.cursor()
        for row in c.execute("SELECT id from {table_name}".format(table_name=self.replay_table_name)):
            ids.append(row[0])

        conn.close()
        return sorted(ids)

    def _max_id(self):
        '''
        Returns a list of IDs in the db
        '''
        conn = sqlite3.connect(self._get_logdb_path())
        c = conn.cursor()
        for row in c.execute("SELECT MAX(id) from {table_name}".format(table_name=self.replay_table_name)):
            ret = row[0]

        conn.close()

        return ret

    def _replay_id_exists(self, replay_id):
        '''
        Returns True if replay_id exists in the db, False otherwise
        '''
        conn = sqlite3.connect(self._get_logdb_path())
        c = conn.cursor()

        c.execute("SELECT * from {table_name} WHERE id=?".format(table_name=self.replay_table_name),
                (replay_id, ))
        fetched = c.fetchone()

        conn.close()

        if fetched is None:
            return False
        return True

    def get_parent_id(self, replay_id):
        conn = sqlite3.connect(self._get_logdb_path())
        c = conn.cursor()

        c.execute("SELECT parent_id from {table_name} WHERE id=?".format(table_name=self.replay_table_name),
            (replay_id, ))
        fetched = c.fetchone()

        conn.close()

        if fetched is None:
            return 0
        return int(fetched[0])

    def _insert_replay(self, cursor, ctime, program_name, log_id, record_pid, parent_id, args):
        '''
        Insert a replay into the DB
        '''
        values = (ctime, log_id, record_pid, parent_id, program_name, args)
        cursor.execute('''INSERT INTO {table_name} VALUES (?,?,?,?,?,?)'''.format(table_name=self.replay_table_name),
                values)

    def _remove_replay(self, replay_id):
        conn = sqlite3.connect(self._get_logdb_path())
        c = conn.cursor()
        c.execute('''DELETE FROM {table_name} WHERE id?'''.format(table_name=self.replay_table_name),
                (replay_id, ))
        conn.commit()
        conn.close()

    def _insert_graph(self, cursor, graph_edges):
        '''
        Insert a replay into the DB
        '''
        for edge in graph_edges:
            (read_id, read_pid, read_sysnum, read_offset, read_size, write_id, 
                    write_pid, write_sysnum, write_offset, write_size) = \
                (edge.read_log, edge.read_pid, edge.read_sysnum, edge.read_offset, edge.read_size, edge.write_log, 
                    edge.write_pid, edge.write_sysnum, edge.write_offset, edge.write_size)
            values = (write_id, write_pid, write_sysnum, write_offset, write_size,
                read_id, read_pid, read_sysnum, read_offset, read_size)
            cursor.execute(
                    'INSERT INTO {table_name} VALUES (?,?,?,?,?,?,?,?,?,?)'.format(table_name=self.graph_table_name),
                    values)

    def _populate(self):
        '''
        Goes through the replay_logdb directory and inserts a record for replays that
        it already hasn't inserted.
        '''
        # get a list of replay directories
        replay_directories = os.listdir(self.logdb_dir)
        # only get the replay directories
        replay_directories = filter(lambda x: x.startswith("rec_"), replay_directories)

        # Gets the full path
        replay_directories = map(lambda x: ''.join([self.logdb_dir, "/", x]), replay_directories)
        # filter out everything that is not a directory
        replay_directories = filter(lambda x: os.path.isdir(x), replay_directories)

        if self.cursor is None:
            print("Error: cursor is not inited, could not populate db")
            return

        max_id = self._max_id()
        for directory in replay_directories:
            log_id = int(re.match(''.join([self.logdb_dir, "/rec_([0-9]+)"]), directory).group(1))
            # see if id in db
            if max_id >= log_id:
                continue

            # parse ckpt
            info = self._parse_directory(directory)
            if info is None:
                if directory != self._get_logdb_path() and directory != self._get_ndx_path():
                    print("could not parse %s" % directory)
                continue

            (ctime, program_name, log_id, record_pid, args, graph_edges) = (info.ctime, info.program_name,
                    info.logid, info.record_pid, info.program_args, info.replay_graph)


            assert(graph_edges is not None)
            self._insert_replay(self.cursor, ctime, program_name, log_id, record_pid, info.parent_groupid, args)
            self._insert_graph(self.cursor, graph_edges)
            #print("Inserted replay id %d, parent %d" % (log_id, info.parent_groupid))

    def lookup_writes(self, read_info):
        return self.lookup_sourcing_writes(read_info.group_id, read_info.pid, read_info.syscall)

    def lookup_sourcing_writes(self, group_id, pid, syscall):
        graph_table_name = "graph_edges"
        c = self.cursor
        c.execute(("SELECT write_id, write_pid, write_sysnum, write_offset, write_size, read_id, read_pid, " + 
                "read_sysnum, read_offset, read_size from {table_name} WHERE read_id=? AND read_pid=? " + 
                "AND read_sysnum=?").format(table_name=graph_table_name), (group_id, pid, syscall))
        fetched = c.fetchall()

        links = {}
        for row in fetched:
            (write_id, write_pid, write_sysnum, write_offset, write_size,
                    read_id, read_pid, read_sysnum, read_offset, read_size) = row
            wi = opinfo.WriteInfo(write_id, write_pid, write_sysnum, write_offset, size=write_size)
            ri = opinfo.ReadInfo(read_id, read_pid, read_sysnum, read_offset, size=read_size)
            links[ri] = wi
        return links

    def _parse_directory(self, logdb_dir):
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
        except ValueError:
            # 0 for default
            logid = 0

        graph_edges = []
        pipeInfo = _PipeInfo(self)
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
                    edge = _GraphEdge(logid, pid, int(match.group(1)), int(match.group(2)),
                            int(match.group(3)), int(match.group(4)), int(match.group(5)), int(match.group(6)),
                            int(match.group(7)), int(match.group(8)), 0, 0)
                    graph_edges.append(edge)
                else:
                    match = re.match(
                        "^pipe: ([0-9]+) ([0-9]+) ([0-9]+) {([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)}", line)

                    if match is not None:
                        if (int(match.group(5)) == 0):
                            pipeInfo.add_ordered_pipe(logid, pid, int(match.group(1)),
                                    int(match.group(3)), int(match.group(4)), int(match.group(6)),
                                    int(match.group(7)))
                        else:
                            edge = _GraphEdge(logid, pid, int(match.group(1)), int(match.group(2)),
                                    int(match.group(3)), int(match.group(4)), int(match.group(5)),
                                    int(match.group(6)), int(match.group(7)), int(match.group(8)), 0, 0)
                            graph_edges.append(edge)
                    else:
                        match = re.match("^pipe: ([0-9]+), ([0-9]+), ([0-9]+) {([0-9]+)} {([0-9]+)}", line)
                        if match is not None:
                            #pipe: writer_id, pipe_id, sysnum {size} {start_clock}
                            pipeInfo.add_pipe(logid, int(match.group(2)), pid,  int(match.group(3)),
                                    int(match.group(1)), int(match.group(4)), int(match.group(5)))

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
            elif line.startswith("parent record group id:"):
                fields = line.split(" ")
                if len(fields) != 5:
                    print("ERROR: parseckpt format must have changed!")
                    print("See line: %s (directory %s)" % (line, logdb_dir))
                    return None
                try:
                    parent_id = int(fields[4])
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

        return _ParseInfo(ctime, program_name, logid, record_pid, parent_id, program_args, graph_edges)

    def get_program_args(self, group_id):
        conn = sqlite3.connect(self._get_logdb_path())
        c = conn.cursor()
        c.execute("SELECT program from {table_name} WHERE id=?".format(table_name=self.replay_table_name), (group_id,))
        fetched = c.fetchone()
        if fetched is None:
            program = None
        else:
            program = fetched[0]

        c.execute("SELECT args from {table_name} WHERE id=?".format(table_name=self.replay_table_name), (group_id,))
        fetched = c.fetchone()
        if fetched is None:
            args = None
        else:
            args = fetched[0]

        conn.close()

        if program is None:
            return None
        elif args is None:
            return program
        else:
            return program + args

    def updatedb(self):
        self._init_cursor()
        self._create_table()
        self._populate()
        self._close_cursor()

class _OrderedPipe(object):
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
        if (writer_pipe.pipe_offset > self.pipe_offset + self.size or
                writer_pipe.pipe_offset + writer_pipe.size < self.pipe_offset):
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
        edge = _GraphEdge(self.log_id, self.pid, self.sysnum, read_offset, size,
                writer_pipe.log_id, writer_pipe.pid, writer_pipe.sysnum, write_offset,
                size, exhausts_reader, exhausts_writer)
        return edge

class _UnorderedPipe(object):
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

    def get_offset(self, prev_pipe):
        assert(prev_pipe is None or self.log_id == prev_pipe.log_id)
        if (prev_pipe is None):
            return _OrderedPipe(self.log_id, self.pid, self.sysnum, self.size, 0)
        else:
            return _OrderedPipe(self.log_id, self.pid, self.sysnum,
                    self.size, prev_pipe.pipe_offset+prev_pipe.size)

class _PipeInfo(object):
    def __init__(self, logdb):
        self.db = logdb
        # Dictionary, [id] = pipe(reader) array 
        self.pipes = collections.defaultdict(list)
        self.ordered_pipes = collections.defaultdict(list)

    def add_pipe(self, log_id, pipe_id, pid, sysnum, writer_id, size, start_clock):
        # If we don't know the writer (aka id 0) then we can't find the source of the data, ignore it
        if writer_id != 0:
            pipe = _UnorderedPipe(log_id, pid, sysnum, writer_id, size, start_clock)
            self.pipes[pipe_id].append(pipe)

        #else:
        #    print "Warning, log {id} has an unknown writer at syscall {sysn}".format(
        #            id=str(log_id), sysn=str(sysnum))
        
    def add_ordered_pipe(self, log_id, pid, read_sysnum, read_size, write_id, 
            write_pipe, write_offset): 
        pipe = _OrderedPipe(log_id, pid, read_sysnum, read_size, write_offset, write_id)
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
                        write_array.append(_UnorderedPipe(log_id, pid, int(match.group(4)), 
                                log_id, int(match.group(2)), int(match.group(3))))

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

            # Now, get all writes from this log_id
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
