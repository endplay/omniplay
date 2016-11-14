
import experiment_utilities
import sys
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
    def __init__(self, host, num_epochs):
        self.host = host
        self.num_epochs = num_epochs

    def __eq__(self,other):
        return (self.host == other.host)

    def __ne__(self,other):
        return (self.host != other.host)

    def one_time_setup(self, user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        shell.run(["./insert_spec_emulab.sh"], cwd = "/local/src/omniplay/scripts")
        try:
            shell.run(["sudo","/bin/mkdir","-p", LOCAL_PREFIX_DIR + "/lib/"], cwd="/");
        except spur.results.RunProcessError:
            print>>sys.gstderr, "already made the home ld-2.15 directory"

        try:
            shell.run(["sudo","/bin/ln","-s",CLOUDLAB_PREFIX_DIR + "/lib/ld-2.15.so",LOCAL_PREFIX_DIR + "/lib/ld-2.15.so"], cwd="/");

        except spur.results.RunProcessError:
            print>>sys.stderr, "already linked in ld-2.15.so... move on"
        
        cmd = shlex.split("/bin/bash -c \"for i in $(ls /replay_cache); do sudo rm -rf /replay_cache/$i; done\"")

        results = shell.run(cmd,cwd = "/")
        try:
            results = shell.run(["sudo","/bin/mkdir","/replay_logdb"],cwd = "/")
        except spur.results.RunProcessError:
            print>>sys.stderr, "alread made replay_logdb"

        
        results = shell.run(["sudo","/bin/chmod","777","/replay_logdb"],cwd = "/")
        results = shell.run(["sudo","/bin/chmod","777","/replay_cache"],cwd = "/")
        

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
            except spur.results.RunProcessError:
                print "replay_logdb didn't exist... oh well"

            cmd = shlex.split("/bin/bash -c \"for i in $(ls /replay_cache); do sudo rm -rf /replay_cache/$i; done\"")

            results = shell.run(cmd,cwd = "/")
            results = shell.run(["sudo","/bin/mkdir","/replay_logdb"],cwd = "/")
            results = shell.run(["sudo","/bin/chmod","777","/replay_logdb"],cwd = "/")
            results = shell.run(["sudo","/bin/chmod","777","/replay_cache"],cwd = "/")
                
    def start_streamserver(self, user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            result = shell.run(["./run_background_task.sh","./streamserver"],cwd=CLOUDLAB_STREAMSERVER_DIR)
            result = shell.run(["./run_background_task.sh","./pound_cpu"],cwd=CLOUDLAB_STREAMSERVER_DIR)

    def recv_files(self, user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            result = shell.run(["./run_background_task.sh","./recv_replay_files"],cwd=CLOUDLAB_STREAMSERVER_DIR)

    def start_recv_files(self, user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            result = shell.run(["./run_background_task.sh","./recv_replay_files"],cwd=CLOUDLAB_STREAMSERVER_DIR)

    def prep_for_ctrl(self,user,password, partitions_file, server_config_file,seqtt_results_folder): 
        if partitions_file != None:
            experiment_utilities.put_file(self.host, user, password, partitions_file, CLOUDLAB_STREAMCTL_DIR + "partitions.test")

        if server_config_file != None:
            experiment_utilities.put_file(self.host, user, password, server_config_file, CLOUDLAB_STREAMCTL_DIR + "server.config")

        if seqtt_results_folder != None:
            experiment_utilities.put_files(self.host, user, password,seqtt_results_folder, CLOUDLAB_STREAMCTL_DIR + "seqtt.results")

    
    def start_ctrl(self, user, password, flags):

        args = ["time","./streamctl","partitions.test","server.config","-w"]
        for item in flags:
            args.append(item)                

        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            try:
                shell.run(["/bin/rm","-r",CLOUDLAB_STREAMCTL_DIR + "/tmp_results"], cwd="/")
            except spur.results.RunProcessError:
                print>>sys.stderr, "whoops, tmp_results didn't exist yet" 

            result = shell.run(args,cwd=CLOUDLAB_STREAMCTL_DIR)
            print>>sys.stderr, result.output


    def kill_server(self, user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            shell.spawn(["pkill","-9","streamserver"])
            shell.spawn(["pkill","-9","pound_cpu"])


class Test_Configuration: 
    def __init__(self, pfilename, correct_dir, server_file, hosts):

        self.num_partitions = sum(1 for line in open(pfilename, "r")) -1 #off by one b/c line with directory
        self.pfilename = pfilename
        self.cdir = correct_dir
        self.sfile = server_file
        self.hosts = hosts
        self.ctrl_host = self.hosts[0]#choose the first host as ctrl


    def ship_replay_files(self,user,password): 
        self.ctrl_host.start_recv_files(user, password)

        replay_dir = open(self.pfilename, "r").readline().strip()
        args = ["./sync_files", replay_dir, self.ctrl_host.host]
                
        try:
            p = subprocess.check_output(args, cwd=STREAMCTL_DIR)
            print>>sys.stderr, p
        except subprocess.CalledProcessError as e:
            print>>sys.stderr, "streamctl returned non-zero rc"
            print>>sys.stderr, e.cmd
            print>>sys.stderr, e.returncode
            print>>sys.stderr, e.output


    def prep_ctrl(self, user, password):
        self.ctrl_host.prep_for_ctrl(user, password, self.pfilename, None, None)

    def prep_sync_ctrl(self, user, password):
        self.ctrl_host.prep_for_ctrl(user, password, self.pfilename, self.sfile, self.cdir)

    def start_ctrl(self, user, password, flags): 
        self.ctrl_host.start_ctrl(user, password, flags)

        print>>sys.stderr, "<finished with stream_ctl for "+str(self.num_partitions) + " host test>"

    def get_stats_files(self, user, password, out_files):         

        output_file_prefix = out_files + str(self.num_partitions)
        
        taint_files = ["tar","-zcf","/tmp/taint-stats.tgz"]
        stream_files = ["tar","-zcf","/tmp/stream-stats.tgz"]
        for i in range(self.num_partitions):
            taint_files.append("/tmp/taint-stats-" + str(i))
            stream_files.append("/tmp/stream-stats-" + str(i))

        shell = experiment_utilities.open_ssh_session(self.ctrl_host.host, user, password)
        with shell:
            shell.run(taint_files,cwd = "/")
            shell.run(stream_files,cwd = "/")    


        local_taint = output_file_prefix + ".taint-stats.tgz"
        local_stream = output_file_prefix + ".stream-stats.tgz"
        remote_taint = "/tmp/taint-stats.tgz"
        remote_stream = "/tmp/stream-stats.tgz"

        experiment_utilities.get_file(self.ctrl_host.host, user, password,local_taint, remote_taint)
        experiment_utilities.get_file(self.ctrl_host.host, user, password,local_stream, remote_stream)
