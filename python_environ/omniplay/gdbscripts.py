"""@package gdbscripts
Utilities to be used inside of gdb scripts and for launching them.
"""
import os
import pickle
import shlex
import subprocess
import re

_env_group_str = "GDB_SCRIPT_GROUP"
_env_args_str = "GDB_SCRIPT_ARGS"
_env_pipe_str = "GDB_SCRIPT_PIPE"

class ScriptPreparer():
    """
    This class is used to setup the environment for launching
    a gdb script.
    """
    def __init__(self, group_id):
        global _env_group_str
        os.environ[_env_group_str] = str(group_id)

    def set_script_args(self, args):
        """
        Set arguments for the script. These arguments can be retreived
        through the ScriptUtilities class.
        Usually you don't want to use this class, it is mainly used
        internally inside the OmniplayEnvironment class.

        @param args A dictionary of named options or arguments
            to pass to the script.
        """
        global _env_args_str
        argstr = pickle.dumps(args)
        os.environ[_env_args_str] = argstr

    def set_redirect_file(self, outfile):
        """
        Set the file that the script outputs to. This only works if
        using the launchpad.
        """
        global _env_pipe_str
        os.environ[_env_pipe_str] = str(outfile)

class ScriptUtilities():
    """
    Gives utilities for gdb scripts, such as retreiving arguments and other
    information. Will not work outside of a gdb script.
    """

    def __init__(self):
        global _env_args_str
        if _env_args_str in os.environ:
            argstr = os.environ[_env_args_str]
            self.arg_dict = pickle.loads(argstr)
        else:
            self.arg_dict = {}

        self.omniplay_location = os.environ["OMNIPLAY_DIR"]
        self.currentpid = self.omniplay_location + "/test/currentpid"

    def get_arg(self, arg_key):
        """
        Retreives an argument that was part of the dictionary given to
        ScriptPreparer.set_script_args
        """
        return self.arg_dict[arg_key]

    def get_replay_group(self):
        """
        Gets the replay group of the replay that gdb is attached to.
        """
        global _env_group_str
        group = os.environ[_env_group_str]
        return int(group)

    def get_current_record_pid(self, nonrecordPid):
        """
        Given the pid of a replaying process, return the currently running
        record pid.
        Uses the currentpid utility.
        On error returns None.
        """
        cmd = ' '.join([self.currentpid, str(nonrecordPid)])
        process = subprocess.Popen(shlex.split(cmd), shell=False, stdout=subprocess.PIPE, stderr=None)
        output, errors = process.communicate()

        lines = output.split("\n")
        for line in lines:
            if re.search("ERROR", line):
                return None

        return int(lines[0])

    def get_redirect_file(self):
        """
        Gets the file that this script is redirected to.
        """
        global _env_pipe_str
        if _env_pipe_str not in os.environ:
            return None
        return os.environ[_env_pipe_str]

