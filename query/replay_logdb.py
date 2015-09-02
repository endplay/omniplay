import re
import os
import sys
import sqlite3
import subprocess
import operator
import time

# our modules
import byterange
import parse_filemap

class ParsedDirectoryInfo(object):
    def __init__(self, ctime=0, program_name="", log_id=0, record_pid=0, 
                        parent_id=0, replay_start_time=0,
                        replay_end_time = 0,
                        program_args="", replay_graph=None):
        self.ctime = ctime
        self.program_name = program_name
        self.logid = log_id
        self.record_pid = record_pid
        self.parent_id = parent_id
        self.replay_start_time = 0
        self.replay_end_time = 0
        self.program_args = program_args
        self.replay_graph = replay_graph

class ReplayLogDB(object):
    '''
    Class holding the operations for creating, insert, querying the replay db.

    Using sqlite3 for now...we might want to change the backing db store later.
    Need to change create_table, replay_id_exists, and insert_replay then.
    '''
    def __init__(self, omniplay_path, logdb_name="replay.db", 
                                        logdb_dir="/replay_logdb",
                                        replay_table_name="replays",
                                        graph_table_name="graph_edges",
                                        start=0,
                                        finish=sys.maxint):

        # Path of the omniplay root directory
        self.omniplay_path = omniplay_path

        # name of the logdb
        self.logdb_name = logdb_name

        # logdb directory (absolute path)
        self.logdb_dir = os.path.abspath(logdb_dir)

        # name of the table in the DB
        self.replay_table_name = replay_table_name
        
        self.graph_table_name = graph_table_name

        # stateful state
        self.cursor = None
        self.conn = None

        self.start_id = start
        self.end_id = finish
        assert self.end_id >= self.start_id

    def init_cursor(self):
        self.conn = sqlite3.connect(self.get_logdb_path())
        self.cursor = self.conn.cursor()

    def close_cursor(self):
        self.conn.commit()
        self.conn.close()

        self.conn = None
        self.cursor = None

    def commit_transaction(self):
        self.conn.commit()

    def get_logdb_path(self):
        return ''.join([self.logdb_dir, "/", self.logdb_name])

    def get_ndx_path(self):
        return ''.join([self.logdb_dir, "/", "ndx"])

    def get_replay_directory(self, group_id):
        return ''.join([self.logdb_dir, "/rec_", str(group_id)])

    def create_tables(self):
        '''
        Create a new table in the db for replays
        '''
        c = self.cursor

        # create a table indexing the replays
        # date: time replay started in seconds since epoch
        # id: log id
        # record_pid: record pid
        # program: short program name, e.g. ls
        # args: arguments to the program, e.g. -l
        sql = '''CREATE TABLE IF NOT EXISTS {table_name} '''.format(
                table_name=self.replay_table_name)
        sql += '''(date INT, id INT, record_pid INT, parent_id INT, '''
        sql += '''replay_start_time INT, replay_end_time INT, '''
        sql += '''program TEXT, args TEXT)'''
        c.execute(sql)

        sql = '''CREATE TABLE IF NOT EXISTS {table_name} '''.format(
                table_name=self.graph_table_name)
        sql += '''(write_id INT, write_pid INT, '''
        sql += '''write_sysnum INT, write_offset INT, '''
        sql += '''write_size INT, read_id INT, '''
        sql += '''read_pid INT, read_sysnum INT, '''
        sql += '''read_offset INT, read_size INT)'''
        c.execute(sql)

        sql = '''CREATE INDEX IF NOT EXISTS read_index '''
        sql += '''on {table_name} '''.format(
                table_name=self.graph_table_name)
        sql += '''(read_id, read_pid, read_sysnum)'''
        c.execute(sql)
        
        sql = '''CREATE INDEX IF NOT EXISTS write_index '''
        sql += '''on {table_name} '''.format(
                table_name=self.graph_table_name)
        sql += '''(write_id, write_pid, write_sysnum)'''
        c.execute(sql)

        self.commit_transaction()
        print("Created db %s, with tables %s, %s" % 
                (self.logdb_name,
                self.replay_table_name,
                self.graph_table_name))

    def get_ids(self):
        '''
        Returns a list of IDs in the db
        '''
        ids = []
        c = self.cursor
        for row in c.execute("SELECT id from {table_name}".format(
            table_name=self.replay_table_name)):
            ids.append(row[0])
        return sorted(ids)

    def replay_id_exists(self, replay_id):
        '''
        Returns True if replay_id exists in the db, False otherwise
        '''
        c = self.cursor
        c.execute("SELECT * from {table_name} WHERE id=?".format(
            table_name=self.replay_table_name),
            (replay_id, ))
        fetched = c.fetchone()

        if fetched is None:
            return False
        return True

    def get_parent_id(self, replay_id):
        c = self.cursor
        c.execute("SELECT parent_id from {table_name} WHERE id=?".format(
            table_name=self.replay_table_name), (replay_id, ))
        fetched = c.fetchone()

        if fetched is None:
            return 0
        return int(fetched[0])

    def get_last_id(self):
        c = self.cursor
        c.execute('''SELECT MAX(id) from {table_name}'''.format(
            table_name=self.replay_table_name))
        fetched = c.fetchone()
        if fetched is None or fetched[0] is None:
            return 0
        return int(fetched[0])

    def insert_replay(self, parsed_directory_info):
        '''
        Insert a replay into the DB
        '''
        values = (parsed_directory_info.ctime, 
                    parsed_directory_info.logid,
                    parsed_directory_info.record_pid,
                    parsed_directory_info.parent_id,
                    parsed_directory_info.replay_start_time,
                    parsed_directory_info.replay_end_time,
                    parsed_directory_info.program_name,
                    parsed_directory_info.program_args)
        self.cursor.execute(
                '''INSERT INTO {table_name} VALUES (?,?,?,?,?,?,?,?)'''.format(
                table_name=self.replay_table_name), values)
        self.commit_transaction()

    def get_all_replays(self):
        c = self.cursor
        c.execute('''SELECT * FROM {table_name}'''.format(
            table_name=self.replay_table_name))

        replays = []
        fetched = c.fetchall()

        for row in fetched:
            (date, group_id, record_pid, parent_id, program, args) = row
            replays.append(row)

        return replays

    def insert_graph(self, graph_edges):
        '''
        Insert a replay into the DB
        '''
        cursor = self.cursor
        for edge in graph_edges:
            (read_id, read_pid, read_sysnum, read_offset, read_size,
                write_id, write_pid, write_sysnum, write_offset, write_size) = \
                    (edge.read_log, edge.read_pid, edge.read_sysnum,
                            edge.read_offset, edge.read_size,
                            edge.write_log, edge.write_pid, edge.write_sysnum,
                            edge.write_offset, edge.write_size)
            values = (write_id, write_pid,
                        write_sysnum, write_offset, write_size,
                        read_id, read_pid, read_sysnum,
                        read_offset, read_size)
            cursor.execute(
                '''INSERT INTO ''' +
                '''{table_name} VALUES (?,?,?,?,?,?,?,?,?,?)'''.format(
                table_name=self.graph_table_name), values)

    def parse_ckpt(self, rec_dir):
        program_name = None
        record_pid = None
        program_args = ""
        replay_time = None
        parent_id = 0

        parse_ckpt = self.omniplay_path + "/test/parseckpt"
        cmd = ''.join([parse_ckpt, " ", rec_dir])
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        output = process.communicate()[0]

        # split by newline, parse for the checkpoint information
        lines = output.split('\n')
        for (line_count, line) in enumerate(lines):
            line = line.strip()
            if line.startswith("record pid:"):
                fields = line.split(" ")
                if len(fields) != 3:
                    print("ERROR: parseckpt format must have changed!" +
                            "Can't get record pid")
                    print("See line %d: %s (directory %s)" %
                            (line_count, line, rec_dir))
                    return None
                try:
                    record_pid = int(fields[2])
                except ValueError:
                    print("ERROR: parseckpt format must have changed!" +
                            "Can't parse record pid")
                    print("See line %d: %s (directory %s)" %
                            (line_count, line, rec_dir))
                    return None
            elif line.startswith("parent record group id:"):
                fields = line.split(" ")
                if len(fields) != 5:
                    print("ERROR: parseckpt format must have changed! " +
                            "Can't get parent id")
                    print("See line %d: %s (directory %s)"
                            % (line_count, line, rec_dir))
                    return None
                try:
                    parent_id = int(fields[4])
                except ValueError:
                    print("ERROR: parseckpt format must have changed! " +
                            "Can't parse parent id")
                    print("See line %d: %s (directory %s)" %
                            (line_count, line, rec_dir))
                    return None
            elif line.startswith("time of replay is:"):
                fields = line.split(" ")
                if len(fields) != 8:
                    print("ERROR: parseckpt format must have changed!" +
                            "Can't read replay time!")
                    print("See line %d: %s (directory %s)" %
                            (line_count, line, rec_dir))
                try:
                    replay_time = int(fields[4])
                except ValueError:
                    print("ERROR: parseckpt format must have changed!" +
                            "Can't parse replay time")
                    print("See line %d: %s (directory %s)" %
                            (line_count, line, rec_dir))
                    return None
            elif line.startswith("Argument"):
                fields = line.split(" ")
                if len(fields) < 4:
                    print("ERROR: parseckpt format must have changed!" +
                            "Can't parse arguments!")
                    print("See line %d: %s (directory %s)" %
                            (line_count, line, rec_dir))
                    return None

                arg_num = fields[1]
                try:
                    arg_num = int(arg_num)
                except ValueError:
                    print("ERROR: parseckpt format must have changed!")
                    print("See line: %s (directory %s)" % (line, rec_dir))
                    return None

                if arg_num == 0:
                    program_name = fields[3]
                else:
                    program_args = ''.join([program_args, " ", fields[3]])

        if not program_name:
            print("ERROR: (%s) parseckpt did not have a program name. " +
                "Treating this as invalid replay" % rec_dir)
            return None
        if not record_pid:
            print("ERROR: (%s) parseckpt did not have a record pid. " +
                "Treating this as invalid replay" % rec_dir)
            return None
        if not replay_time:
            print("ERROR: (%s) parseckpt did not have a replay time. Using 0"
                    % rec_dir)
            replay_time = 0
        
        return (program_name, record_pid, parent_id, program_args, replay_time)

    def get_last_modified_klog_time(self, directory):
        klogs = filter(lambda x: x.startswith("klog"), os.listdir(directory))
        # make absolute path
        klogs = map(lambda x: directory + "/" + x, klogs)

        last_modified_time = 0
        for klog in klogs:
            mtime = os.stat(klog).st_mtime
            if (mtime > last_modified_time):
                last_modified_time = mtime
        return last_modified_time

    def populate(self):
        '''
        Goes through the replay_logdb directory
        and inserts a record for replays that
        it already hasn't inserted.
        '''
        time_start = time.time()
        # get a list of replay directories
        replay_directories = os.listdir(self.logdb_dir)

        group_ids = [int(x.split("_")[1]) for x in replay_directories
                if x.startswith("rec_")]
        last_group_id = self.get_last_id()
        # only get the directories that we havne't already inserted
        group_ids = sorted(filter(lambda x: x > last_group_id, group_ids))
        # Only populate between a certain range
        group_ids = sorted(filter(lambda x: x >= self.start_id, group_ids))
        group_ids = sorted(filter(lambda x: x < self.end_id, group_ids))
        replay_directories = []
        for group_id in group_ids:
            replay_directories.append(''.join([self.logdb_dir,
                "/rec_", str(group_id)]))
        # filter out everything that is not a directory
        replay_directories = filter(lambda x: os.path.isdir(x),
                replay_directories)

        if self.cursor is None:
            print("Error: cursor is not inited, could not populate db.")
            print("Error: Please init the cursor before callling this method")
            return

        print(replay_directories)
        for directory in replay_directories:
            ## parse ckpt
            # get ID from logdb
            logid = 0
            try:
                fields = directory.split("_")
                logid = int(fields[-1])
            except:
                # 0 for default
                logid = 0
                print("Could not get group id from directory " +
                        "%s, treating as invalid replay directory" % directory)
                continue

            # see if id in db
            if self.replay_id_exists(logid):
                print("Skipping %s because it's already in the db" % directory)
                continue

            parsed_directory_info = self.parse_directory(logid, directory)
            if parsed_directory_info is None:
                if directory != self.get_logdb_path() and \
                        directory != self.get_ndx_path():
                    print("Could not parse %s, treating as invalid replay"
                            % directory)
                continue

            assert(parsed_directory_info is not None)
            assert(parsed_directory_info.replay_graph is not None)

            self.insert_replay(parsed_directory_info)
            self.insert_graph(parsed_directory_info.replay_graph)

            # commit the insert
            self.commit_transaction()
            print("Inserted replay id %d, parent %d" %
                (parsed_directory_info.logid,
                parsed_directory_info.parent_id))

        time_end = time.time()
        print("Time it took to populate the db: %f seconds" %
                (time_end - time_start))

    def lookup_writers(self, read_byterange, copy_meta=False):
        self.cursor.execute("SELECT write_id, write_pid, write_sysnum, " +
                "write_offset, write_size, " +
                "read_id, read_pid, read_sysnum, read_offset, " +
                "read_size from {table_name} " +
                "WHERE read_id=? AND read_pid=? AND read_sysnum=?".format(
                        table_name=self.graph_table_name),
                        (read_byterange.group_id,
                            read_byterange.pid,
                            read_byterange.syscall))
        fetched = self.cursor.fetchall()

        byteranges = []
        rows = []
        for row in fetched:
            rows.append(row)
        # sort by group_id, pid, sysnum, offset
        # XXX there's probably some way to do this in SQL
        #  but not going to right now
        rows = sorted(rows, key=operator.itemgetter(5, 6, 7, 8))
        offset = read_byterange.offset
        size = read_byterange.size
        if copy_meta:
            meta = read_byterange.meta.copy()
        else:
            meta = {}
        for row in rows:
            (write_id, write_pid, write_sysnum, write_offset, write_size,
                    read_id, read_pid, read_sysnum, read_offset, read_size) = \
                row
            # the returned range from the DB may be larger than what we care for
            if offset >= read_offset and offset < read_offset + read_size:
                diff = offset - read_offset
                if offset + size <= read_offset + read_size:
                    byteranges.append(byterange.ByteRange(write_id, 
                                                            write_pid,
                                                            write_sysnum,
                                                            write_offset + diff,
                                                            size,
                                                            meta=meta))
                    # XXX this looks wrong
                    break
                else:
                    # if the range falls between what the DB returns us
                    diff_size = read_offset + read_size - offset
                    offset = read_offset + read_size
                    size = size - diff_size
                    byteranges.append(byterange.ByteRange(write_id, 
                                                            write_pid,
                                                            write_sysnum,
                                                            write_offset + diff,
                                                            diff_size,
                                                            meta=meta))
        return byteranges

    def lookup_readers(self, write_byterange, copy_meta=False):
        self.cursor.execute("SELECT write_id, write_pid, write_sysnum, " + 
                "write_offset, write_size, " +
                "read_id, read_pid, read_sysnum, " +
                "read_offset, read_size from {table_name} " +
                "WHERE write_id=? AND write_pid=? AND write_sysnum=?".format(
                    table_name=self.graph_table_name),
                (write_byterange.group_id, write_byterange.pid, write_byterange.syscall))
        fetched = self.cursor.fetchall()

        byteranges = []
        rows = []
        for row in fetched:
            rows.append(row)
        # sort by group_id, pid, sysnum, offset
        # XXX there's probably some way to do this in SQL but not going to right now
        rows = sorted(rows, key=operator.itemgetter(0, 1, 2, 3))
        offset = write_byterange.offset
        size = write_byterange.size
        if copy_meta:
            meta = write_byterange.meta.copy()
        else:
            meta = {}
        for row in rows:
            (write_id, write_pid, write_sysnum, write_offset, write_size,
                    read_id, read_pid, read_sysnum, read_offset, read_size) = row
            # the returned range from the DB may be larger than what we care for
            if offset >= write_offset and offset < write_offset + write_size:
                diff = offset - write_offset
                if offset + size <= write_offset + write_size:
                    byteranges.append(byterange.ByteRange(read_id, 
                                                            read_pid,
                                                            read_sysnum,
                                                            read_offset + diff,
                                                            size,
                                                            meta=meta))
                else:
                    # if the range falls between what the DB returns us
                    diff_size = write_offset + write_size - offset
                    offset = write_offset + write_size
                    size = size - diff_size
                    byteranges.append(byterange.ByteRange(read_id, 
                                                            read_pid,
                                                            read_sysnum,
                                                            read_offset + diff,
                                                            diff_size,
                                                            meta=meta))
        return byteranges

    def parse_directory(self, logid, logdb_dir):
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
            print("No ckpt in directory %s, skipping" % logdb_dir)
            return None

        # get a list of replay directories
        klog_directories = os.listdir(logdb_dir)
        # filter out everything that is not a directory
        klog_directories = filter(lambda x: x.startswith("klog"), klog_directories)
        # Gets the full path
        klog_directories = map(lambda x: ''.join([logdb_dir, "/", x]), klog_directories)
        
        # get the time the ckpt was last modified
        # (ideally we would want the creation time, but it doesn't seem like
        #  it's easy to do in Python)
        ctime = int(os.stat(ckpt).st_ctime)

        # execute parseckpt
        ckpt_info = self.parse_ckpt(logdb_dir)
        if not ckpt_info:
            # can't parse the ckpt, just skip this replay
            return None
        (program_name, record_pid, parent_id, program_args, replay_time) = ckpt_info

        replay_endtime = self.get_last_modified_klog_time(logdb_dir)

        graph_edges = []
        pipeInfo = parse_filemap.PipeInfo(self)

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
                    graph_edges.append(parse_filemap.GraphEdge(logid, pid,
                                        int(match.group(1)), int(match.group(2)), 
                                        int(match.group(3)), int(match.group(4)), 
                                        int(match.group(5)), int(match.group(6)), 
                                        int(match.group(7)), int(match.group(8))))
                else:
                    match = re.match("^pipe: ([0-9]+) ([0-9]+) ([0-9]+) {([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)}", line)
                    if match is not None:
                        if (int(match.group(5)) == 0):
                            pipeInfo.add_ordered_pipe(logid, pid,
                                    int(match.group(1)), int(match.group(2)),
                                    int(match.group(3)), int(match.group(4)),
                                    int(match.group(6)), int(match.group(7)),
                                    int(match.group(8)))
                        else:
                            graph_edges.append(parse_filemap.GraphEdge(logid, pid, 
                                            int(match.group(1)), int(match.group(2)),
                                            int(match.group(3)), int(match.group(4)),
                                            int(match.group(5)), int(match.group(6)),
                                            int(match.group(7)), int(match.group(8))))
                    else:
                        match = re.match("^pipe: ([0-9]+), ([0-9]+), ([0-9]+) {([0-9]+)} {([0-9]+)}", line)
                        if match is not None:
                            #pipe: writer_id, pipe_id, sysnum {size} {start_clock}
                            pipeInfo.add_pipe(logid, int(match.group(2)), pid,  
                                                int(match.group(3)), int(match.group(1)),
                                                int(match.group(4)), int(match.group(5)))

            if logproc.returncode < 0:
                print("parseklog for %s failed with %d" %
                                (directory, logproc.returncode))
                return None

        # add pipe information to graph edges
        pipeInfo.compute_pipes(graph_edges)

        return ParsedDirectoryInfo(ctime, program_name, logid,
                record_pid, parent_id, 
                replay_time, replay_endtime,
                program_args, graph_edges)

    def get_program_args(self, group_id):
        self.cursor.execute(
                "SELECT program from {table_name} WHERE id=?".format(
                table_name=self.replay_table_name
                ), (group_id,)
        )
        fetched = self.cursor.fetchone()
        if fetched is None or fetched[0] is None:
            program = None
        else:
            program = fetched[0]

        self.cursor.execute(
                "SELECT args from {table_name} WHERE id=?".format(
                table_name=self.replay_table_name
                ), (group_id,)
        )
        fetched = self.cursor.fetchone()
        if fetched is None or fetched[0] is None:
            args = None
        else:
            args = fetched[0]

        if program is None:
            return None
        elif args is None:
            return program
        else:
            return program + args
