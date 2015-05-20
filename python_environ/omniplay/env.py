"""@package env
Omniplay Environment support.  Supports standard operations like recording 
a process, replaying a process, and attaching a pin tool to a replay.
"""
import os
import re
import time
import shlex
import tempfile
import subprocess
import collections

import gdbscripts
import logdb

LogCkpt = collections.namedtuple('LogCheckpoint',
        ['pid', 'group_id', 'parent_group_id', 'exe', 'args', 'env'])

def run_shell(cmd, stin=None, outp=None, err=None, do_wait=True):
    """ Utility tool for launching a bash command and waiting for it to finish, optional input/output redirection

    @param cmd The command to be launched
    @param stin File to redirect standard in from
    @param outp File to redirect standard out from
    @param err File to redirect stderr from
    @return The subprocess of the bash shell
    """
    outp_needs_close = False
    err_needs_close = False
    stin_needs_close = False
    if outp is None:
        outp_needs_close = True
        outp = open(os.devnull, 'w')

    if err is None:
        err_needs_close = True
        err = open(os.devnull, 'w')

    if stin is None:
        stin_needs_close = True
        stin = open(os.devnull, 'r')

    cmd = ''.join(['bash -c "', cmd, '"'])

    proc = subprocess.Popen(shlex.split(cmd), shell=False, stdin=stin, stdout=outp, stderr=err)
    if do_wait:
        if proc.wait() != 0:
            raise RuntimeError("Child exited with unexpected return code")

    if outp_needs_close:
        outp.close()

    if err_needs_close:
        err.close()

    if stin_needs_close:
        stin.close()

    return proc


def _find_children(klog_filp):
    """
    Finds all record groups spawned from a klog

    @klog_filp the file of the klog (python file object, not string)
    @returns a list of integers, containing group_ids
    """
    ret = []
    for line in klog_filp.readlines():
        match = re.match("\tnew group id: ([0-9]+)", line)
        if match is not None:
            #print "\t\talso scanning child with id: " + match.group(1)
            ret.append(int(match.group(1)))

    return ret

class OmniplayEnvironment(object):
    """
    Encapsulates complete omniplay environment.  Used for recording/replaying/log parsing/running pin tools
    """
    
    def __init__(self, omniplay_location=None, pthread_lib=None, pin_root=None,
                    verbose=False):
        self.record_dir = "/replay_logdb"
        self.recording_suffix = "rec_"

        self.verbose = verbose

        # compute the home
        if omniplay_location:
            self.omniplay_location = omniplay_location
        else:
            if 'OMNIPLAY_DIR' not in os.environ:
                raise EnvironmentError("OMNIPLAY_DIR not defined, please run the setup script")

            self.omniplay_location = os.environ['OMNIPLAY_DIR']

        if pthread_lib:
            self.pthread = pthread_lib
            self.pthread_resume = pthread_lib
        else:
            self.pthread = ''.join([self.omniplay_location,
                "/eglibc-2.15/prefix/lib:/lib:/lib/i386-linux-gnu:/usr/lib:/usr/lib/i386-linux-gnu"])
            self.pthread_resume = ''.join([self.omniplay_location, "/eglibc-2.15/prefix/lib"])

        if pin_root:
            self.pin_root = pin_root
        else:
            home = os.path.expanduser("~")
            # default is $(HOME)/pin-2.13
            self.pin_root = '/'.join([home, "pin-2.13"])

        #FIXME: Should I just build the pin tools if they don't exist?
        self.tools_location = '/'.join([self.omniplay_location, "pin_tools/obj-ia32"])

        self.logdb_dir = "/replay_logdb/"

        binaries = collections.namedtuple('Binary', ["record", "parseklog",
                "filemap", "replay", "parseckpt", "getstats", "pin", "currentpid"])
        scripts = collections.namedtuple('Scripts', ["setup", "record", "insert", "run_pin"])

        self.scripts_dir = ''.join([self.omniplay_location, "/scripts"])
        self.scripts = scripts(
                setup = '/'.join([self.scripts_dir, "setup.sh"]),
                record = '/'.join([self.scripts_dir, "easy_launch.sh"]),
                insert = '/'.join([self.scripts_dir, "insert_spec.sh"]),
                run_pin = '/'.join([self.scripts_dir, "run_pin.sh"])
            )


        self.test_dir = ''.join([self.omniplay_location, "/test"])

        self.bins = binaries(
                replay = '/'.join([self.test_dir, "resume"]),
                record = '/'.join([self.test_dir, "launcher"]),
                parseklog = '/'.join([self.test_dir, "parseklog"]),
                filemap = '/'.join([self.test_dir, "filemap"]),
                parseckpt = '/'.join([self.test_dir, "parseckpt"]),
                getstats = '/'.join([self.test_dir, "getstats"]),
                pin = '/'.join([self.pin_root, "pin"]),
                currentpid = '/'.join([self.test_dir, "currentpid"])
            )

        self.gdbscripts_dir = ''.join([self.omniplay_location, "/pygdb_tools"])
        self.gdblaunchpad = '/'.join([self.gdbscripts_dir, "gdblaunchpad.py"])

        self.setup_system()

    def setup_system(self):
        '''
        Check the system to see if all of the required binaries are there
        '''
        assert os.path.exists(self.omniplay_location)
        assert os.path.isdir(self.omniplay_location)

        assert os.path.exists(self.scripts_dir)
        assert os.path.isdir(self.scripts_dir)

        self.insert_spec()

        for pthread in self.pthread.split(':'):
            assert os.path.exists(pthread)
            assert os.path.isdir(pthread)
        assert os.path.exists(self.pin_root)
        assert os.path.isdir(self.tools_location)

        for binary in self.bins:
            assert os.path.exists(binary)

        for script in self.scripts:
            assert os.path.exists(script)

    def insert_spec(self):
        """
        Inserts the spec module into the system, may require a password

        No args
        returns None
        """
        run_shell(self.scripts.insert)

    def record(self, cmd, stin=None, stout=None, sterr=None):
        """
        Spawns a new process and records it

        @param cmd  The full command to run with options. 
              Does not need to be an absolute path
        @param stin File to be used for stdin redirection
        @param stout File to be used for stdout redirection
        @param sterr File to be used for stderr redirection

        @returns the LogCkpt of the recorded process
        """
        # Get the binary
        args = shlex.split(cmd)
        args.reverse()
        command = args.pop()
        args.reverse()

        # Need to convert the binary into a full path
        whichcmd = ' '.join(["which", command])
        #print "whichcmd is " + whichcmd
        proc = subprocess.Popen(shlex.split(whichcmd), stdout=subprocess.PIPE)
        proc.wait()
        command = proc.stdout.read()
        # If which gives a relative command, append our cwd to it
        if command.startswith('./'):
            # -1 to trim \n
            command = '/'.join([os.getcwd(), command[2:]])

        while command[-1] == '\n':
            command = command[0:-1]

        #print "adjusted command to " + command

        # Get highest recorded process number
        if stout is None:
            stout = open(os.devnull, 'w')

        if sterr is None:
            sterr = open(os.devnull, 'w')

        if stin is None:
            stin = open(os.devnull, 'r')

        (fd, tmpname) = tempfile.mkstemp()
        os.close(fd)

        launcher = ' '.join([self.bins.record, "-o", tmpname, "-m", "--pthread", self.pthread])

        args = shlex.split(launcher) + [command] + args
        #print "about to run" + str(args)
        proc = subprocess.Popen(args, shell=False, stdin=stin, stdout=stout, stderr=sterr)
        proc.wait()
        #print "here?"
        
        with open(tmpname) as tmpfile:
            line = tmpfile.readlines()[0]
            match = re.match("Record log saved to: ([-0-9a-zA-Z._/]+)", line)
            logdir = match.group(1)

        os.remove(tmpname)

        ckptinfo = self.parseckpt(logdir)

        return ckptinfo

    def replay(self, replay_dir, pipe_log=None, pin=False, gdb=False, follow=False):
        '''
        Replays a recording, returning the replaying subprocess - Does NOT wait for the process to finish

        @param replay_dir Directory of recording
        @param pipe_log Output redirection for stdout/stderr
        @param pin will pin be attached?
        @param follow Follow the execution?

        @returns the subprocess of the replaying process
        '''
        cmd = ' '.join([self.bins.replay, "--pthread", self.pthread_resume, replay_dir])

        if pipe_log is None:
            pipe_log = open(os.devnull, 'w')

        if pin:
            cmd += " -p"
        if gdb:
            cmd += " -g"
        if follow:
            cmd += " -f"

        if self.verbose:
            print(cmd)

        process = subprocess.Popen(shlex.split(cmd), shell=False, stdout=pipe_log, stderr=pipe_log)
        return process

    def attach_tool(self, pid, tool_name, pipe_output, flags=''):
        """
        Attaches a pin tool to a replaying process.  NOTE: you probably want to use the run_tool wrapper instead
        Does not wait for the process to finish

        @param pid The pid of the process to be attached to
        @param tool_name The name of the tool to be attached.  Either an 
            absolute path, or the toolname if it exists in the standard tool directory
        @param pipe_output File to be used for standard out redirection
        @param flags Flags to be passed to the pin tool

        @returns the pin subprocess
        """
        tool = tool_name
        # Check if tool_name exists...
        if not os.path.exists(tool):
            tool = '/'.join([self.tools_location, tool])

        assert(os.path.exists(tool))

        cmd = ' '.join([self.bins.pin, "-follow_execv", "-pid", str(pid), "-t", tool, flags])

        process = subprocess.Popen(shlex.split(cmd), shell=False, stdout=pipe_output)
        return process

    def _get_program_name(self, groupId, logdbInst=None):
        """
        Gets just the executable name for the replay group
        """
        if logdbInst == None:
            logdbInst = logdb.ReplayLogDB(self)
            logdbInst.updatedb()

        programArgs = logdbInst.get_program_args(groupId)
        programName = shlex.split(programArgs)[0]
        return programName

    def attach_gdb(self, group_id, pid, script_path=None, pipe_output=None, script_args=None):
        """
        Attaches gdb to a replaying process.

        If script_path is None, gdb will be started in interactive mode, otherwise it will run the
            specified python script.

        NOTE: Usually you want to use 'run_gdb_interactive' or 'run_gdb_script'
        This does not wait for the process to finish.

        @param group_id The replay group id of the replaying process.
        @param pid The pid of the replaying process to attach to
        @param script_path Specifies the path of the script that gdb should run. If this is None, gdb will be interactive.
        @param pipe_output Where to pipe the output of gdb to. This is ignored if no script is specified.
        @returns The subprocess of the gdb process
        """
        progName = self._get_program_name(group_id)

        cmd = "gdb %s %i" % (progName, pid)

        if script_path != None:
            #TODO: change the -batch to a -batch-silent
            cmd += " -batch -x %s" % self.gdblaunchpad

        if self.verbose:
            print(cmd)

        #if script_path == None or pipe_output == None:
        #    stdout_arg = None
        #    stderr_arg = None
        #else:
        #    outhandle = open(pipe_output, 'w')
        #    stdout_arg = outhandle
        #    stderr_arg = outhandle

        prep = gdbscripts.ScriptPreparer(group_id)

        if script_path != None:
            if pipe_output != None:
                prep.set_redirect_file(pipe_output)

            if script_args != None:
                script_args["SCRIPT"] = script_path
            else:
                script_args = { "SCRIPT" : script_path }
            prep.set_script_args(script_args)

        gdb_proc = subprocess.Popen(shlex.split(cmd), shell=False)

        return gdb_proc

    def run_tool(self, binary, tool, flags="", output="/tmp/stderr_log", toolout="/tmp/tool_log"):
        '''
        Starts a replay, then attaches a pin tool with flags

        @param binary The recording to run (ex "/replay_logdb/rec_1")
        @param tool The pin tool to run, accepts absolute path, relative path,
            or name of tool if its in the standard tool directory
        @param flags Flags to be passed to the pin tool
        @param output Path to use for output redirection for the attached process
        @param toolout Path to use as otuput redirection for the pin tool

        @returns None
        '''

        log_f = open(output, "w")
        tool_f = open(toolout, "w")

        replay_process = self.replay(binary, log_f, pin=True)

        # FIXME: Parse output for sleep info?
        time.sleep(1)

        attach_process = self.attach_tool(replay_process.pid, tool, tool_f, flags=flags)

        attach_process.wait()
        replay_process.wait()

    def run_gdb_interactive(self, group_id):
        """
        Starts a replay and then attaches gdb to it in interactive mode.
        """

        replay_dir = self.get_record_dir(group_id)

        replay_proc = self.replay(replay_dir, gdb=True)
        gdb_proc = self.attach_gdb(group_id, replay_proc.pid)

        gdb_proc.wait()
        replay_proc.wait()

    def run_gdb_script(self, group_id, script_path, pipe_output=None, script_args=None):
        """
        Starts a replay and then attaches gdb to it, which runs the given script
        """
        replay_dir = self.get_record_dir(group_id)

        replay_proc = self.replay(replay_dir, gdb=True)
        gdb_proc = self.attach_gdb(group_id, replay_proc.pid, script_path=script_path, pipe_output=pipe_output)

        gdb_proc.wait()
        replay_proc.wait()

    def filemap(self, filename, filemap_output="/tmp/filemap_output"):
        """
        Reports filemap (file dependency) information about a given file.

        @warning This spawns a subprocess to generate the info, and does not wait for it to finish

        @param filename The file to get filemap information for
        @param filemap_output The file where the information will be saved

        @returns The subprocess generating he output
        """
        cmd = ' '.join([self.bins.filemap, filename, filemap_output])

        process = subprocess.Popen(shlex.split(cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process


    def parseckpt(self, filename, outfile=None):
        """
        Parses a given record log, and returns a LogCkpt structure representing it

        @param filename The recording checkpoint to be parsed (ex. /replay_logdb/rec_1)
        @param outfile Optionally a file to save the ckpt to

        @returns LogCkpt representing the parsed checkpoint
        """
        cmd = ' '.join([self.bins.parseckpt, filename])

        proc = run_shell(cmd, outp=subprocess.PIPE)

        args = []
        env = {}

        with os.fdopen(os.dup(proc.stdout.fileno())) as f:
            for line in f:

                if outfile is not None:
                    outfile.write(line)

                match = re.match("record pid: ([0-9]+)", line)
                if match is not None:
                    pid = int(match.group(1))
                    continue

                match = re.match("record group id: ([0-9]+)", line)
                if match is not None:
                    group_id = int(match.group(1))
                    continue

                match = re.match("parent record group id: ([0-9]+)", line)
                if match is not None:
                    parent_group_id = int(match.group(1))
                    continue

                match = re.match("record filename: (.+)", line)
                if match is not None:
                    exe = match.group(1)
                    continue

                match = re.match("Argument [0-9]+ is (.+)", line)
                if match is not None:
                    args.append(match.group(1))
                    continue

                match = re.match("Env\. var\. [0-9]+ is (.+)", line)
                if match is not None:
                    match = re.match("([-_a-zA-Z0-9]+)=(.*)", match.group(1))
                    env[match.group(1)] = match.group(2)
                    continue

        return LogCkpt(
                pid = pid,
                group_id = group_id,
                parent_group_id = parent_group_id,
                exe = exe,
                args = args,
                env = env
            )

    def parseklog(self, klog, output):
        """
        Does a simple parsing of a kernel log using the parseklog tool (in OMNIPLAY_DIR/test)
        More complex klog parsing may be done with the parseklog module

        @param klog The path to the klog to be parsed
        @param output The path where the klog output should be saved

        @returns None
        """
        with open(output, 'w+') as f:
            run_shell(' '.join([self.bins.parseklog, klog]), outp=f)

    def _klogs_for_id(self, group_id):
        """
        Returns a list of tuples (path, pid) to klogs for a given record group

        @param group_id The group to get the klogs for
        @returns A list of (string, int) tuples
        """
        ret = []

        directory = self.get_record_dir(group_id)

        for f in os.listdir(directory):
            match = re.match("klog.id.([0-9]+)", f)
            if match is not None:
                ret.append(('/'.join([directory, f]), int(match.group(1))))

        return ret

    def get_all_children(self, group_id, parsedir=None):
        """
        Finds all of the children for a specific record group.  This requires
        parsing the klogs, so it may take a little while

        @param group_id the group to find children for
        @param parsedir The location to put the klog parsings.  They will be stored
            temporarily (and deleted) if not specified

        @returns A list of group_ids
        """
        # Now find all children groups of this recording
        to_scan = collections.deque([group_id])

        ret = []
        
        while to_scan:
            n = to_scan.popleft()

            klogs = self._klogs_for_id(n)
            for (fullname, pid) in klogs:

                print "\t\tRunning parseklog on " + fullname

                if parsedir is None:
                    (fd, tmpdir) = tempfile.mkstemp()
                    self.parseklog(fullname, tmpdir)

                    with os.fdopen(fd, "r") as f:
                        chillins = _find_children(f)
                        to_scan.extend(chillins)
                        ret.extend(chillins)
                    os.remove(tmpdir)
                else:
                    klogdir = ''.join([parsedir, "/", str(n)])
                    if (not os.path.isdir(klogdir)):
                        os.mkdir(klogdir)
                    klogloc = ''.join([klogdir, "/klog.id.", str(pid)])
                    self.parseklog(fullname, klogloc)

                    with open(klogloc, "r") as f:
                        chillins = _find_children(f)
                        to_scan.extend(chillins)
                        ret.extend(chillins)

        return ret


    def parsegroup(self, group_id, outdir):
        """
        Parses all klogs for all children of a record group.  Specify a record
        group ID and the directory to put all of the outputs

        @group_id The group_id to be parsed
        @outdir The output directory for all of the parsed info
        @returns A list of all children
        """
        count = 0

        # First parse the ckpt for the group (in group/ckpt)
        ckpt_output = ''.join([outdir, "/ckpt"])
        ckpt_file = self.get_record_dir(group_id)
        with open(ckpt_output, "w") as f:
            self.parseckpt(ckpt_file, outfile=f)

        # Now parse the klogs in the checkpoint
        klogdir = '/'.join([outdir, "klogs"])
        if (not os.path.isdir(klogdir)):
            os.mkdir(klogdir)

        # Gets and parses all childrens klogs into the specified directory
        return self.get_all_children(group_id, klogdir)


    def get_record_dir(self, record_group):
        """
        Given a record group id, translates it into the record group's directory

        @param record_group the group id of a record group

        @returns A string representing the directory where the recording is stored
        """
        subdir = ''.join([self.recording_suffix, str(record_group)])
        return '/'.join([self.record_dir, subdir])

    def get_stats(self):
        """
        Returns the record/replay/mismatch stats for this boot
        """
        p = subprocess.Popen (self.bins.getstats, stdout=subprocess.PIPE)
        lines = p.stdout.read().split("\n")
        m = re.search(" ([0-9]+)$", lines[0])
        if m:
            started = int(m.groups()[0])
        else:
            print "bad output from stats:", lines[0]
            exit (0)
        m = re.search(" ([0-9]+)$", lines[1])
        finished = int(m.groups()[0])
        m = re.search(" ([0-9]+)$", lines[2])
        mismatched = int(m.groups()[0])
        return (started, finished, mismatched)

    def pid_to_current_record_pid(self, pid):
        """
        Given the pid of a replaying process, return the currently running
        record pid.
        Uses the currentpid utility.
        On error returns None.
        """
        cmd = ' '.join([self.bins.currentpid, str(pid)])
        process = subprocess.Popen(shlex.split(cmd), shell=False, stdout=subprocess.PIPE, stderr=None)
        output, errors = process.communicate()

        lines = output.split("\n")
        for line in lines:
            if re.search("ERROR", line):
                return None

        return int(lines[0])

