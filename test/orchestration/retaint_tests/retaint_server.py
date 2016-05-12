import sys

sys.path.append("..")

import experiment_utilities
import spur
import os
import shlex
import subprocess

CLOUDLAB_PREFIX_DIR = "/local/src/omniplay/eglibc-2.15/prefix"
CLOUDLAB_STREAMSERVER_DIR = "/local/src/omniplay/dift/proc64"
CLOUDLAB_STREAMCTL_DIR = "/local/src/omniplay/test/"
LOCAL_PREFIX_DIR = "/home/arquinn/Documents/omniplay/eglibc-2.15/prefix"
STREAMCTL_DIR = "/home/arquinn/Documents/omniplay/test/"
 

class Server:
    def __init__(self, host,rp_dir, parts_file):
        self.host = host
        self.replay_dir = rp_dir
        self.parts_file = parts_file

    def one_time_setup(self, user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        shell.run(["./insert_spec_emulab.sh"], cwd = "/local/src/omniplay/scripts")
        try:
            shell.run(["sudo","/bin/mkdir","-p", LOCAL_PREFIX_DIR + "/lib/"], cwd="/");
        except spur.results.RunProcessError:
            print>>sys.stderr, "already made the home ld-2.15 directory"

        try:
            shell.run(["sudo","/bin/ln","-s",CLOUDLAB_PREFIX_DIR + "/lib/ld-2.15.so",LOCAL_PREFIX_DIR + "/lib/ld-2.15.so"], cwd="/");

        except spur.results.RunProcessError:
            print>>sys.stderr, "already linked in ld-2.15.so... move on"

    def replace_prefix(self, user, password, prefix_name):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:            
            try:
                results = shell.run(["sudo","/bin/rm",CLOUDLAB_PREFIX_DIR + "/lib/ld-2.15.so"], cwd="/")
            except spur.results.RunProcessError:
                print>>sys.stderr, "whoops, ld-2.15.so didn't exist yet" 

            results = shell.run(["sudo","/bin/ln","-s","/local/src/omniplay/eglibc-2.15/loaders/"+prefix_name, CLOUDLAB_PREFIX_DIR + "/lib/ld-2.15.so"],cwd="/")


    def clear_replay_dirs(self,user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            try:
                results = shell.run(["sudo","/bin/rm","-rf","/replay_logdb"],cwd = "/")
                cmd = shlex.split("/bin/bash -c \"for i in $(ls /tmp); do sudo rm -r /tmp/$i; done\"")
                results = shell.run(cmd,cwd = "/")


            except spur.results.RunProcessError:
                print "replay_logdb didn't exist... oh well"

            cmd = shlex.split("/bin/bash -c \"for i in $(ls /replay_cache); do sudo rm -rf /replay_cache/$i; done\"")

            results = shell.run(cmd,cwd = "/")
            results = shell.run(["sudo","/bin/mkdir","/replay_logdb"],cwd = "/")
            results = shell.run(["sudo","/bin/chmod","777","/replay_logdb"],cwd = "/")
            results = shell.run(["sudo","/bin/chmod","777","/replay_cache"],cwd = "/")

    def prep_test(self,user,password, partitions_file): 
        experiment_utilities.put_file(self.host, user, password, partitions_file, CLOUDLAB_STREAMCTL_DIR + "partitions.test")

                

    def start_recv_files(self, user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            result = shell.run(["./run_background_task.sh","./recv_replay_files"],cwd=CLOUDLAB_STREAMSERVER_DIR)

    def get_retaint_stats_file(self,user,password, output_dir):
        shell = experiment_utilities.open_ssh_session(self.host,user,password)
        cmd = shlex.split("/bin/bash -c \"/bin/tar -czf /tmp/retaint.tgz /tmp/*\"")

        rt_file = "/tmp/retaint.tgz"
        out_file = output_dir + "retaint.tgz"

        with shell:
            shell.run(cmd,cwd="/")
        experiment_utilities.get_file(self.host, user, password,out_file, rt_file)

    def run_retaint_experiment(self,user,password, a):
        
        args = ["./retaint",self.replay_dir,"partitions.test"]

        #append any special per-test arguemnts to this test
        for arg in a:
            args.append(arg)

        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            result = shell.run(args,cwd=CLOUDLAB_STREAMCTL_DIR)
            print>>sys.stderr, result.output



    def sync_files(self,user, password):
    
        #sync replay files
        self.start_recv_files(user, password)
        args = ["./sync_files", self.replay_dir, self.host]
        
        try:
            p = subprocess.check_output(args, cwd=STREAMCTL_DIR)
            print>>sys.stderr, p
        except subprocess.CalledProcessError as e:
            print>>sys.stderr, "streamctl returned non-zero rc"
            print>>sys.stderr, e.cmd
            print>>sys.stderr, e.returncode
            print>>sys.stderr, e.output
            print>>sys.stderr, e.error

        #sync parts file
        self.prep_test(user,password, self.parts_file)
        sys.stderr.write("finished sync\n")
    
    def start_pound_cpu(self, user,password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            result = shell.run(["./run_background_task.sh","./pound_cpu"],cwd=CLOUDLAB_STREAMSERVER_DIR)


    def kill_pound_cpu(self, user,password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            shell.spawn(["pkill","-9","pound_cpu"])

