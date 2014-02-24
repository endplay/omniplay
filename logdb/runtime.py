import os
import shlex
import subprocess

class RunTimeInfo(object):
    def __init__(self, omniplay_location=None, pthread_lib=None, pin_root=None,
                    verbose=False):
        self.verbose = verbose
        # compute the home
        if omniplay_location:
            self.omniplay_location = omniplay_location
        else:
            home = os.path.expanduser("~")
            self.omniplay_location = ''.join([home, "/omniplay"])

        if pthread_lib:
            self.pthread = pthread_lib
        else:
            self.pthread = ''.join([self.omniplay_location, "/eglibc-2.15/prefix/lib"])

        if pin_root:
            self.pin_root = pin_root
        else:
            home = os.path.expanduser("~")
            # default is $(HOME)/pin-2.13
            self.pin_root = ''.join([home, "/pin-2.13"])

        self.pinbin = ''.join([self.pin_root, "/pin"])

        self.tools_location = ''.join([self.omniplay_location, "/pin_tools/obj-ia32"])
        self.resume = ''.join([self.omniplay_location, "/test/resume"])

    def replay(self, replay_dir, pipe_log, pin=False, follow=False):
        cmd = ' '.join([self.resume, replay_dir, "--pthread", self.pthread])

        if pin:
            cmd += " -p"
        if follow:
            cmd += " -f"

        if self.verbose:
            print(cmd)

        process = subprocess.Popen(shlex.split(cmd), shell=False, stdout=pipe_log, stderr=pipe_log)
        return process

    def attach_tool(self, pid, tool_name, tool_output, pipe_output):
        # look up the right tool according to the linkages specified
        # tool = "linkage_copy.so"
        tool = tool_name
        cmd = ''.join([self.pinbin, " -pid ", str(pid), " -t ", self.tools_location, "/", tool,
            " -o ", tool_output])

        if self.verbose:
            print(cmd)

        process = subprocess.Popen(shlex.split(cmd), shell=False, stdout=pipe_output, stderr=pipe_output)
        return process

    def filemap(self, filename):
        filemap_output = "/tmp/filemap_output"
        cmd = ''.join([self.omniplay_location, "/test/filemap", " ", filename, " ", filemap_output])
        process = subprocess.Popen(shlex.split(cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process
