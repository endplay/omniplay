import optparse
import getpass
import os
import sys
import shutil
import paramiko
import spur
import subprocess
import test_results
import math

STREAMSERVER_PORT = 19764 #Streamserver port as defined by the 
ERRORS_DIR = "stream_outputs/"
CLOUDLAB_PREFIX_DIR = "/local/src/omniplay/eglibc-2.15/"

class Server:
    def __init__(self, host, port, num_epochs):
        self.host = host
        self.port = port
        self.num_epochs = num_epochs

    #servers are equal if they share a host and a port
    def __eq__(self,other):
        return (self.host == other.host) and (self.port == other.port)

    #servers are not equal if they differ in host or port
    def __ne__(self,other):
        return (self.host != other.host) or (self.port != other.port)

    def get_output_name(self):
        return self.host + "." + str(self.num_epochs)

class Test_Configuration: 
    def __init__(self, partition_filename, server_list): 
        self.partition_filename = partition_filename
        self.num_partitions = sum(1 for this_line in open(partition_filename, "r")) -1 #off by one error for the line with directories
        self.dift_hosts = []
        self.agg_hosts = []

        for line in server_list: 
            words = line.split()
            dift = Server(words[1], STREAMSERVER_PORT, int(words[0]))
            agg = Server(words[2],STREAMSERVER_PORT, int(words[0]))

            if self.dift_hosts.count(dift) <= 0:
                self.dift_hosts.append(dift)
            else:
                dift2_index = self.dift.index(dift)
                self.dift_hosts[dift2index].num_epochs += dift.num_epochs
            if self.agg_hosts.count(agg) <= 0:
                self.agg_hosts.append(agg)
            else:
                agg2_index = self.agg_hosts.index(agg)
                self.agg_hosts[agg2_index].num_epochs += agg.num_epochs


def open_ssh_session(host, user, password):
    return spur.SshShell(hostname=host, username=user, password=password, missing_host_key=spur.ssh.MissingHostKey.warn)


def open_paramiko_ssh_session(host, user, password): 
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username = user, password = password)
    return ssh

def put_file(host, user, password, local_file, remote_file):
    ssh = open_paramiko_ssh_session(host, user, password)
    sftp = ssh.open_sftp()
    sftp.put(local_file, remote_file)
    sftp.close()

def get_file(host, user, password, local_file, remote_file):
    ssh = open_paramiko_ssh_session(host, user, password)
    sftp = ssh.open_sftp()
    sftp.get(local_file, remote_file)
    sftp.close()


def start_server(host, port, user, password, path): 

    stdout_file = open(path + ".stdout","wr")
    stderr_file = open(path + ".stderr","wr")

    shell = open_ssh_session(host, user, password)
    if port != STREAMSERVER_PORT:
        spawn = shell.spawn(["./streamserver"],cwd="/home/arquinn/Documents/omniplay/dift/proc64", stdout = stdout_file, stderr = stderr_file, store_pid = True)
    else:
        spawn = shell.spawn(["./streamserver"],cwd="/home/arquinn/Documents/omniplay/dift/proc64", stdout = stdout_file, stderr = stderr_file, store_pid = True)
    return shell, spawn


def replace_prefix(host, user, password, local_prefix_dir, remote_prefix_dir, prefix_name):

    shell = open_ssh_session(host, user, password)
    with shell:
        sftp.put(local_prefix_dir +"/"+ prefix_name, remote_prefix_dir +"/"+ prefix_name)
        results = shell.run(["/bin/tar","-xf",prefix_name],cwd = remote_prefix_dir)


def start_ctl(partitions_file, config_file): 
    p = subprocess.Popen(["./streamctl",partitions_file,config_file, "-w"], cwd="/home/arquinn/Documents/omniplay/test/", stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    return p.communicate()

    
def get_tests(filename, server_description):

    config_file = open(filename, "r")
    tests = []
    for line in config_file:        
        next_test = Test_Configuration(line.strip(), server_description)
        tests.append(next_test)

    config_file.close()
    return tests


def make_server_description(num_parts, cores_per_server, server_name_ending):
    server_descs = []
    num_rows = int(math.ceil((num_parts + 0.0) / (cores_per_server + 0.0)))
    for i in range(num_rows):
        server_name = "node-" + str(i) + server_name_ending
        server_descs.append(str(cores_per_server) + " " + server_name + " " + server_name)

    return server_descs

def get_stats_files(test, username, stream_stats_dir): 
    #now get and write the results! 
    stream_server_index = 0
    stream_offset = 0
    agg_offset = 0
    agg_server_index = 0
    results = []
    
    output_file_prefix = stream_stats_dir + "/" + str(test.num_partitions)

    for i in range(test.num_partitions):
                        
        if i >= stream_offset + test.dift_hosts[stream_server_index].num_epochs:
            stream_offset += test.dift_hosts[stream_server_index].num_epochs
            stream_server_index += 1

        if i >= agg_offset + test.agg_hosts[agg_server_index].num_epochs:
            agg_offset += test.agg_hosts[agg_server_index].num_epochs
            agg_server_index += 1
                            
        stream_server = test.dift_hosts[stream_server_index]
        agg_server = test.agg_hosts[agg_server_index]

        local_stream_file = output_file_prefix + "." stream_server.get_output_name() + ".dift-stats" + str(i)
        local_agg_file = output_file_prefix + "." + agg_server.get_output_name() + ".stream-stats" + str(i)

        remote_stream_file =  "/tmp/dift-stats" + str(i - stream_offset)
        remote_agg_file =  "/tmp/" + str(i - agg_offset)+ "/stream-stats" 

        get_file(stream_server.host, username, password,local_stream_file, remote_stream_file)
        get_file(agg_server.host, username, password, local_agg_file, remote_agg_file)
    
        



def main(): 
    if (len(sys.argv) < 2):
        sys.stderr.write("you must supply a configuration file on command line\n")
        sys.stderr.write("config files have a separete line of the following:\n")
        sys.stderr.write("<epoch_description_file> <server_description_file>")
        sys.stderr.write("for each test.\n")
        return -1

    config_file = sys.argv[1]
    parser = optparse.OptionParser()
    parser.add_option("-s", "--stream-stats-dir", dest="stream_stats",
                      help="where to save the stream-stats", metavar="STREAM-STATS-DIR")
    parser.add_option("-p", "--eglib-prefix-tar.gz", dest="prefix_tar",
                      help="where the eglibc prefix.tar.gz is currently stored on this machine", metavar="PREFIX.TAR.GZ")

    (options, args) = parser.parse_args()
    stream_stats_dir = options.stream_stats

    if stream_stats_dir == None:
        stream_stats_dir = ""
    else:
        stream_stats_dir += "/"
        if not os.path.isdir(stream_stats_dir):
            os.makedirs(stream_stats_dir)        

    if not os.path.isdir(stream_stats_dir + "pin_output"):
        os.makedirs(stream_stats_dir +"pin_output")

    #stuff to manage cloudlab --> we need to ship additional data that we didn't need to send! 
    #1. We need to make sure to run the streamctl with -s in order to ship the logs 
    #2. We need to make sure to ship the seqtt answer (Also we need to check this stuff!!!) 
    #3. We need to make sure to ship the prefix lib that is needed for this experiment. 
        
    #I assume for now that we won't go over 64 parts! 
    server_description = make_server_description(64, 4, ".replay_cluster_exp.Dift.apt.emulab.net")
    test_configurations = get_tests(config_file, server_description)

    password = getpass.getpass()         
    if options.prefix_tar != None:    
        split_path = options.prefix_tar.split("/")
        local_prefix_dir = "/".join([split_path[i] for i in range(len(split_path) - 1)]) + "/" #include everything BUT the last word
        prefix_name = split_path[-1]

        #weird ordering here...? 
        #TODO: fix that `arquinn' right there
        for line in server_description: 
            server_name = server_description.split()[-1] #the last name will suffice...
            replace_prefix(server_name, "arquinn", password, local_prefix_dir, CLOUDLAB_PREFIX_DIR, prefix_name)


    return -2


#this doesn't really make sense anymore... I no longer have the notion of separate stream and dift servers... 
#b/c we're moving to the shared memory land    

    for test in test_configurations:    
        #startup all aggregators in this test configuration:
        agg_shells = []
        agg_results = []
        for agg_server in test.agg_hosts:
            agg_output_path = stream_stats_dir + "/pin_output/" + str(test.num_partitions) + "." + agg_server.output_name()
            agg_shell, agg_result = start_server(agg_server.host, agg_server.port, None, password, agg_output_path)
            agg_shells.append(agg_shell)
            agg_results.append(agg_result)

            sys.stderr.write(str(agg_result.pid) + " started on aggregator\n")

        #startup all dift servers in this test configuration
        dift_shells = []
        dift_results = []
        for dift_server in test.dift_hosts:
            dift_output_path = stream_stats_dir + "/pin_output/" + str(test.num_partitions) + "." + dift_server.output_name()
            dift_shell, dift_result = start_server(dift_server.host, dift_server.port, None, password, dift_output_path)
            dift_shells.append(dift_shell)
            dift_results.append(dift_result)
            sys.stderr.write(str(dift_result.pid) + " started on dift\n")

        sys.stderr.write(start_ctl(test.partition_filename, test.server_filename)[1])
        
        #kill the processes: 
        for i in range(len(agg_shells)):
            with agg_shells[i]:
                agg_results[i].send_signal(9)
        for i in range(len(dift_shells)):
            with dift_shells[i]:
                dift_results[i].send_signal(9)


        get_stats_files(test)
        sys.stderr.write("finished with " + test.partition_filename+ "\n")
            
    

main()
