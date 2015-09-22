import os
import shlex
import subprocess

def get_linkages():
    return ["COPY", "DATA", "INDEX"]

class RunTimeInfo(object):
    '''
    Class that holds a handle for running replay processes and 
    attaching pin to them
    '''
    def __init__(self, omniplay_location=None,
                        pthread_lib=None,
                        pin_root=None,
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
            self.pthread = ''.join([self.omniplay_location,
                "/eglibc-2.15/prefix/lib"])

        if pin_root:
            self.pin_root = pin_root
        else:
            home = os.path.expanduser("~")
            # default is $(HOME)/pin-2.13
            self.pin_root = ''.join([home, "/pin-2.13"])

        self.pinbin = ''.join([self.pin_root, "/pin"])

        self.tools_location = ''.join([self.omniplay_location,
            "/dift/obj-ia32"])
        self.resume = ''.join([self.omniplay_location,
            "/test/resume"])

    def check_system(self):
        '''
        Check the system to see if all of the required
         binaries are there
        '''
        assert os.path.exists(self.omniplay_location)
        assert os.path.isdir(self.omniplay_location)
        assert os.path.exists(self.pthread)
        assert os.path.isdir(self.pthread)
        assert os.path.exists(self.pin_root)
        assert os.path.exists(self.pinbin)
        assert os.path.isdir(self.tools_location)

        assert os.path.exists(self.omniplay_location +
                "/test/resume")
        assert os.path.exists(self.resume)
        assert os.path.exists(self.omniplay_location +
                "/test/parseklog")
        assert os.path.exists(self.omniplay_location +
                "/test/filemap")

        # check for pin tools
        #assert os.path.exists(self.tools_location +
        # "/linkage_copy.so")
        #assert os.path.exists(self.tools_location +
        # "/linkage_data.so")

    def replay(self, replay_dir, pipe_log, pin=False,
            follow=False):
        '''
        @param replay_dir - replay directory
        @param pipe_log - open file handle
        '''
        cmd = ' '.join([self.resume,
            replay_dir,
            "--pthread",
            self.pthread])

        if pin:
            cmd += " -p"
        if follow:
            cmd += " -f"

        if self.verbose:
            print(cmd)

        process = subprocess.Popen(shlex.split(cmd),
            shell=False,
            stdout=pipe_log,
            stderr=pipe_log)
        return process

    def replay_process(self, replay_group_id, pin=False,
            follow=False):
        replay_dir = "/replay_logdb/rec_" + str(replay_group_id)
        pipe_log = open("/tmp/replay_stderr_log_%s" %
            str(replay_group_id), "w")
        return self.replay(replay_dir, pipe_log,
                pin=pin, follow=follow)

    def attach_tool_extended(self, pid, tool_name, pipe_output,
                                            absolute_path=False,
                                            pin_follow=False,
                                            flags=''):
        '''
        Same as attach tool, but provides more options,
          like specifying the flags or a tool that is not 
          in the the tools location
        '''
        tool = tool_name
        if not absolute_path:
            tool = ''.join([self.tools_location, "/", tool])
            assert(os.path.exists(tool))
        if pin_follow:
            cmd = ''.join([self.pinbin,
                    " -follow_execv -pid ", str(pid),
                    " -t ", tool, " ", flags])
        else:
            cmd = ''.join([self.pinbin,
                    " -pid ", str(pid),
                    " -t ", tool, " ", flags])
        print(cmd)
        process = subprocess.Popen(shlex.split(cmd),
            shell=False, stdout=pipe_output)
        return process

    def filemap(self, filename):
        filemap_output = "/tmp/filemap_output"
        cmd = ''.join([self.omniplay_location,
                            "/test/filemap", " ",
                            filename, " ", filemap_output])
        process = subprocess.Popen(shlex.split(cmd), shell=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process

    def get_toolname(self, linkage_name, forward=False):
        if not forward:
            if linkage_name == "DATA":
                return "linkage_data.so"
            elif linkage_name == "COPY":
                return "linkage_copy.so"
            elif linkage_name == "INDEX":
                return "linkage_offset.so"
            else:
                assert(False)
        else:
            if linkage_name == "DATA":
                return "linkage_forward_data.so"
            elif linkage_name == "COPY":
                return "linkage_forward_copy.so"
            elif linkage_name == "INDEX":
                return "linkage_forward_offset.so"
            else:
                assert(False)

    def run_linkage(self, replay_group_id, linkage_name,
            flags="", forward=False, pin_follow=True):
        '''
        Runs the linkage on a replay group

        @param replay_group_id - int - replay group to run
        @param linkage_name - string - 
            name of the tool to run (e.g. COPY, DATA, INDEX)
        @returns (replay process, pin attached process)
        '''
        replay_process = self.replay_process(
                replay_group_id, pin=True)
        toolname = self.get_toolname(
                linkage_name, forward=forward)
        pipe_log = open("/tmp/tool_output_" +
                str(replay_group_id), "w")
        attach_process = self.attach_tool_extended(
                replay_process.pid,
                toolname, pipe_log,
                flags=flags,
                pin_follow=pin_follow)
        return (replay_process, attach_process)
