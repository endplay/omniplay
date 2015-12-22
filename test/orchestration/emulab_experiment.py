import optparse
import getpass
import os
import sys
import subprocess
import math
import experiment_utilities
#not positive that I need these! 
import paramiko
import spur

STREAMSERVER_PORT = 19764 #Streamserver port as defined by the 
ERRORS_DIR = "stream_outputs/"
CLOUDLAB_PREFIX_DIR = "/local/src/omniplay/eglibc-2.15/"
CLOUDLAB_STREAMSERVER_DIR = "/local/src/omniplay/dift/proc64"
CLOUDLAB_SCRIPTS_DIR = "/local/src/omniplay/scripts"
STREAMCTL_DIR = "/home/arquinn/Documents/omniplay/test/"

class Server:
    def __init__(self, host, num_epochs):
        self.host = host
        self.num_epochs = num_epochs

    #servers are equal if they share a host
    def __eq__(self,other):
        return (self.host == other.host)

    #servers are not equal if they differ in host
    def __ne__(self,other):
        return (self.host != other.host)

    def get_output_name(self):
        return self.host + "." + str(self.num_epochs)

    def replace_prefix(self, user, password, prefix_name):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            experiment_utilities.put_file(self.host, user, password, prefix_name, CLOUDLAB_PREFIX_DIR +"/prefix.tar.gz")
            results = shell.run(["/bin/tar","-xf","prefix.tar.gz"],cwd = CLOUDLAB_PREFIX_DIR)

    def create_new_replay_dirs(self,user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            try:
                results = shell.run(["sudo","/bin/rm","-rf","/replay_logdb"],cwd = "/")
            except spur.results.RunProcessError:
                print "replay_logdb didn't exist... oh well"

            results = shell.run(["sudo","/bin/mkdir","/replay_logdb"],cwd = "/")
            results = shell.run(["sudo","/bin/chmod","777","/replay_logdb"],cwd = "/")
            results = shell.run(["sudo","/bin/rm","-rf","/replay_cache/*"],cwd = "/")
            results = shell.run(["sudo","/bin/chmod","777","/replay_cache"],cwd = "/")
            results = shell.run(["./insert_spec_emulab.sh"], cwd = "/local/src/omniplay/scripts")

    def prepare_for_replay(self, user, password, prefix_name): 
        self.replace_prefix(user, password, prefix_name)
        self.create_new_replay_dirs(user,password)

    def start_server(self, user, password, output_path):
        out = open(output_path + self.get_output_name() + ".stdout","wr")
        err = open(output_path + self.get_output_name() + ".stderr","wr")

        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        spawn = shell.spawn(["./streamserver"],cwd=CLOUDLAB_STREAMSERVER_DIR, stdout=out, stderr=err, store_pid=True)
        return shell, spawn

class Test_Configuration: 
    #not sure that I need both the server_list and the server_config file....? 
    def __init__(self, partition_filename, server_config_file, prefix, debug_dir, results_dir): 
        self.partition_filename = partition_filename
        self.server_config_file = "orchestration/" + server_config_file
        self.prefix = prefix
        self.num_partitions = sum(1 for this_line in open("../" + partition_filename, "r")) -1 #off by one b/c line with directory
        self.hosts = []
        self.debug_dir = debug_dir
        self.results_dir = results_dir

        self.results = []
        self.shells = []

        with open(server_config_file, "r") as server_list:
            curr_num = 0
            while curr_num < self.num_partitions: 
                line = server_list.readline() 
                words = line.split()
                s = Server(words[1], int(words[0]))
            
                if self.hosts.count(s) <= 0:
                    self.hosts.append(s)
                else:
                    s2_index = self.hosts.index(s)
                    self.hosts[s2_index].num_epochs += s.num_epochs
            
                curr_num += int(words[0])
            
    def prepare_for_replay(self, user, password): 
        if self.prefix:
            for h in self.hosts: 
                h.prepare_for_replay(user, password, self.prefix)
        else:
            print "no prefix specified, skipping the prepare_for_replay"

    def start_ctl(self, user, password, flags): 
        try:
            p = subprocess.check_output(["./streamctl", self.partition_filename, self.server_config_file, "-w", flags], cwd=STREAMCTL_DIR)
        except subprocess.CalledProcessError as e:
            print "streamctl returned non-zero rc"
            print e.cmd
            print e.returncode
            print e.output
            

    def start_servers(self, user, password):
        output_filename = self.debug_dir + "/" + str(self.num_partitions) + "."
        for h in self.hosts:
            shell, result = h.start_server(user, password, output_filename)
            self.shells.append(shell)
            self.results.append(result)

    def kill_procs(self):
        for i in range(len(self.shells)):
            with self.shells[i]:
                self.results[i].send_signal(9)

    def get_stats_files(self, user, password): 
        
        output_file_prefix = results_dir + "/" + str(test.num_parititions) + "."
        server_index = 0
        offset = 0
        results = []
    
        for i in range(self.num_partitions):

            if i >= offset + self.hosts[server_index].num_epochs:
                offset += self.hosts[server_index].num_epochs
                server_index += 1
                            
            server = self.hosts[server_index]

            local_stream_file = output_file_prefix + "." + server.get_output_name() + ".dift-stats" + str(i)
            local_agg_file = output_file_prefix + "." + server.get_output_name() + ".stream-stats" + str(i)
            remote_stream_file =  "/tmp/dift-stats" + str(i - offset)
            remote_agg_file =  "/tmp/" + str(i - offset)+ "/stream-stats" 

            experiment_utilities.get_file(server.host, username, password,local_stream_file, remote_stream_file)
            experiment_utilities.get_file(server.host, username, password, local_agg_file, remote_agg_file)
    
def get_tests(filename, server_desc_filename, prefix_filename, debug_dir, results_dir):

    config_file = open(filename, "r")
    tests = []
    for line in config_file:        
        next_test = Test_Configuration(line.strip(), server_desc_filename, prefix_filename, debug_dir, results_dir)
        tests.append(next_test)

    config_file.close()
    return tests


def make_server_description(num_parts, cores_per_server, server_name_ending):

    num_rows = int(math.ceil((num_parts + 0.0) / (cores_per_server + 0.0)))
    with open("server_config.tmp","w+") as wfile:
        for i in range(num_rows):
            server_name = "node-" + str(i) + server_name_ending
            wfile.write(str(cores_per_server) + " " + server_name + " " + server_name + "\n")    

def main(): 
    if (len(sys.argv) < 2):
        sys.stderr.write("you must supply a configuration file on command line\n")
        sys.stderr.write("config files have a separete line of the following:\n")
        sys.stderr.write("<epoch_description_file>")
        sys.stderr.write("for each test.\n")
        return -1

    config_file = sys.argv[1]
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output-dir", dest="output_dir",
                      help="where to save all the output files", metavar="OUTPUT-DIR")

    parser.add_option("-p", "--eglib-prefix-tar.gz", dest="prefix",
                      help="where the eglibc prefix.tar.gz is currently stored on this machine", metavar="PREFIX.TAR.GZ")

    parser.add_option("-s", "--sync", action="store_true",dest="sync",
                      help="whether to sync the prefix and replay files", metavar="SYNC")


    (options, args) = parser.parse_args()
    output_dir = options.output_dir

    if output_dir == None:
        output_dir = ""
    else:
        output_dir += "/"
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)        
        
    debug_dir = output_dir + "debug"
    results_dir = output_dir + "results"

    if not os.path.isdir(debug_dir):
        os.makedirs(debug_dir)
    if not os.path.isdir(results_dir):
        os.makedirs(results_dir)

    if options.sync and not options.prefix:
        print "if you want to sync files, you must specify a prefix path!"
        return -2 
        

    #stuff to manage cloudlab --> we need to ship additional data that we didn't need to send! 
    #1. We need to make sure to run the streamctl with -s in order to ship the logs 
    #2. We need to make sure to ship the seqtt answer (Also we need to check this stuff!!!) *** Punting on this issue ***
    #3. We need to make sure to ship the prefix lib that is needed for this experiment. 
    #4. We need to clear out the replay logdb and replay_cache
        
    #I assume for now that we won't go over 64 parts! 
    make_server_description(64, 4, ".arquinn-QV12107.Dift.emulab.net")
    test_configurations = get_tests(config_file, "server_config.tmp", options.prefix, debug_dir, results_dir)
    password = getpass.getpass()         

    
    #Need to add a sync parameter to the parser
    if options.sync: 
        last_test = test_configurations[-1]
        last_test.prepare_for_replay("arquinn", password)
        last_test.start_servers("arquinn", password)
        last_test.start_ctl("arquinn",password, "-s")
        sys.stderr.write("finished syncing the files\n");    
        last_test.kill_procs()

    return -2
            
    for test in test_configurations:    
        #startup all aggregators in this test configuration:
        test.start_servers("arquinn", password)
        test.start_ctl("arquinn",password, "")
        test.get_stats_files("arquinn", password)
        test.kill_procs()
        sys.stderr.write("finished with " + test.partition_filename+ "\n")

main()
