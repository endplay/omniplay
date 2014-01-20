import os
import sys
import sqlite3
import subprocess
import re

class ParseInfo(object):
    def __init__(self, ctime=0, program_name="", log_id=0, record_pid=0, program_args="", replay_graph=None):
        self.ctime = ctime
        self.program_name = program_name
        self.logid = log_id
        self.record_pid = record_pid
        self.program_args = program_args
        self.replay_graph = replay_graph
        

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

    def insert_graph(self, log_id, recorded_pid, graph_edges):
        '''
        Insert a replay into the DB
        '''
        conn = sqlite3.connect(self.get_logdb_path())
        c = conn.cursor()
        for edge in graph_edges:
            (read_sysnum, read_offset, read_size, write_id, write_pid, write_sysnum, write_offset, write_size) = edge
            values = (write_id, write_pid, write_sysnum, write_offset, write_size, log_id, recorded_pid, read_sysnum, read_offset, read_size)
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
                if directory != self.get_logdb_path():
                    print("could not parse %s" % directory)
                continue
            (ctime, program_name, log_id, record_pid, args, graph_edges) = (info.ctime, info.program_name, info.logid, info.record_pid, info.program_args, info.replay_graph)

            # see if id in db
            if self.replay_id_exists(log_id):
                print("Skipping %s because it's already in the db" % directory)
                continue

            assert(graph_edges is not None)
            self.insert_replay(ctime, program_name, log_id, record_pid, args)
            self.insert_graph(log_id, record_pid, graph_edges)
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
                match = re.match("([0-9]+) ([0-9]+) ([0-9]+) {([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)}", line)
                if match is not None:
                    graph_edges.append((int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4)), int(match.group(5)), int(match.group(6)), int(match.group(7)), int(match.group(8))));

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

