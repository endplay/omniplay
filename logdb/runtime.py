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

    def check_system(self):
        '''
        Check the system to see if all of the required binaries are there
        '''
        assert os.path.exists(self.omniplay_location)
        assert os.path.isdir(self.omniplay_location)
        assert os.path.exists(self.pthread)
        assert os.path.isdir(self.pthread)
        assert os.path.exists(self.pin_root)
        assert os.path.exists(self.pinbin)
        assert os.path.isdir(self.tools_location)

        assert os.path.exists(self.omniplay_location + "/test/resume")
        assert os.path.exists(self.resume)
        assert os.path.exists(self.omniplay_location + "/test/parseklog")
        assert os.path.exists(self.omniplay_location + "/test/filemap")

        # check for pin tools
        assert os.path.exists(self.tools_location + "/linkage_copy.so")
        assert os.path.exists(self.tools_location + "/linkage_data.so")

    def replay(self, replay_dir, pipe_log, pin=False, follow=False):
        '''
        @param replay_dir - replay directory
        @param pipe_log - open file handle
        '''
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
        '''
        @param pid - Pid to attach to
        @param tool_name - tool name in the omniplay directory to run
        @param tool_output - (string) filename to save output to
        @param pipe_output - open file handle to redirect output to
        '''
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
