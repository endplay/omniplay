import optparse
import getpass
import os
import sys
import shutil
import paramiko
import spur
import subprocess
import test_results

STREAMSERVER_PORT = 19764 #Streamserver port as defined by the 
ERRORS_DIR = "stream_outputs/"

class Agg_Server:
    def __init__(self, host, port, num_epochs):
        self.host = host
        self.port = port
        self.num_epochs = num_epochs

    #agg_servers are equal if they share a host and a port
    def __eq__(self,other):
        return (self.host == other.host) and (self.port == other.port)

    #agg_servers are not equal if they differ in host or port
    def __ne__(self,other):
        return (self.host != other.host) or (self.port != other.port)


class Dift_Server:
    def __init__(self, host, port, num_epochs):
        self.host = host
        self.port = port
        self.num_epochs = num_epochs

class Test_Configuration: 
    def __init__(self): 
        self.partition_filename = ""
        self.server_fileneame = ""
        self.num_partitions = -1
        self.dift_hosts = []
        self.agg_hosts = []
        
    def add_dift(self, dift):
        self.dift_hosts.append(dift)
    def add_agg(self, agg):
        self.agg_hosts.append(agg)

    def set_partition_filename(self, filename):
        self.partition_filename = filename
    def set_server_filename(self, filename):
        self.server_filename = filename
    def set_num_partitions(self, parts):
        self.num_partitions = parts


def open_ssh_session(host, user, password):
    return spur.SshShell(hostname=host, username=user, password=password, missing_host_key=spur.ssh.MissingHostKey.warn)

def open_sftp_session(host, user, password): 
    sess = paramiko.SSHClient()
    sess.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
    sess.connect(host, username=user, password=password)
    return sess

def read_sftp_file(host, user, password, filename):

    sess = open_sftp_session(host,user,password)
    ftp = sess.open_sftp()
    f =  ftp.file(filename, mode="r")
    rtn_string = f.readlines()
    sess.close()
    return rtn_string

def start_aggregator(host, port, user, password):
    agg_stdout = open(ERRORS_DIR + "agg_stdout_" + host + ":" + str(port),"wr")
    agg_stderr = open(ERRORS_DIR + "agg_stderr_" + host + ":" + str(port),"wr")

    shell = open_ssh_session(host, user, password)
    if port != STREAMSERVER_PORT:
        spawn = shell.spawn(["./streamserver"], cwd="/home/arquinn/Documents/omniplay/dift/proc64", stdout = agg_stdout, stderr = agg_stderr, store_pid = True)
    else:
        spawn = shell.spawn(["./streamserver"], cwd="/home/arquinn/Documents/omniplay/dift/proc64", stdout = agg_stdout, stderr = agg_stderr, store_pid = True)
    return shell, spawn

def start_dift(host, port, user, password): 
    stdout_file = open(ERRORS_DIR + "dift_stdout_" + host, "wr")
    stderr_file = open(ERRORS_DIR + "dift_stderr_" + host, "wr")

    shell = open_ssh_session(host, user, password)
    if port != STREAMSERVER_PORT:
        spawn = shell.spawn(["./streamserver"],cwd="/home/arquinn/Documents/omniplay/dift/proc64", stdout = stdout_file, stderr = stderr_file, store_pid = True)
    else:
        spawn = shell.spawn(["./streamserver"],cwd="/home/arquinn/Documents/omniplay/dift/proc64", stdout = stdout_file, stderr = stderr_file, store_pid = True)

    return shell, spawn


def start_ctl(partitions_file, config_file): 
    p = subprocess.Popen(["./streamctl",partitions_file,config_file, "-w"], cwd="/home/arquinn/Documents/omniplay/test/", stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    return p.communicate()
    
def get_servers(test, filename):
    server_file = open(filename,"r")
    for line in server_file: 
        words = line.split()
        dift = Dift_Server(words[1], STREAMSERVER_PORT, int(words[0]))
        agg = Agg_Server(words[2],STREAMSERVER_PORT, int(words[0]))
        if len(words) > 3:
            agg = Agg_Server(words[2],words[3],words[0])

        if test.dift_hosts.count(dift) <= 0:
            test.add_dift(dift)
        else:
            dift2 = test.dift.index(dift)
            dift2.num_epochs += dift.num_epochs

        if test.agg_hosts.count(agg) <= 0:
            test.add_agg(agg)
        else:
            agg2_index = test.agg_hosts.index(agg)
            test.agg_hosts[agg2_index].num_epochs += agg.num_epochs

    server_file.close()

def get_tests(filename):

    config_file = open(filename, "r")
    tests = []
    for line in config_file:        
        next_test = Test_Configuration()
        
        words = line.split() 
        if len(words) < 2:
            sys.stderr.write("problem with config file line: ")
            sys.stderr.write(line)
            sys.stderr.write("\n")
            raise Exception("Problem parsing configuraiton file")

        next_test.set_partition_filename(words[0])
        next_test.set_server_filename(words[1])
        get_servers(next_test, words[1])
        next_test.set_num_partitions(sum(1 for line in open(words[0], "r")) -1) #off by one error for the line with directories

        tests.append(next_test)

    config_file.close()
    return tests


def main(): 
    if (len(sys.argv) < 2):
        sys.stderr.write("you must supply a configuration file on command line\n")
        sys.stderr.write("config files have a separete line of the following:\n")
        sys.stderr.write("<epoch_description_file> <server_description_file>")
        sys.stderr.write("for each test.\n")
        return -1

    config_file = sys.argv[1]
    test_configurations = get_tests(config_file)
    password = getpass.getpass()

    file_time = open("time_outputs.csv", "w")
    file_data = open("data_outputs.csv", "w")



    file_time.write(",".join(test_results.Test_Results.get_titles()))
    file_data.write(",".join(test_results.Test_Results.get_data_titles()))
    file_time.write("\n")
    file_data.write("\n")
    for test in test_configurations:    

        #startup all aggregators in this test configuration:
        agg_shells = []
        agg_results = []
        for agg_server in test.agg_hosts:
            agg_shell, agg_result = start_aggregator(agg_server.host, agg_server.port, None, password)
            agg_shells.append(agg_shell)
            agg_results.append(agg_result)

            sys.stderr.write(str(agg_result.pid) + " started on aggregator\n")

        #startup all dift servers in this test configuration
        dift_shells = []
        dift_results = []
        for dift_server in test.dift_hosts:
            dift_shell, dift_result = start_dift(dift_server.host, dift_server.port, None, password)
            dift_shells.append(dift_shell)
            dift_results.append(dift_result)
            sys.stderr.write(str(dift_result.pid) + " started on dift\n")

        sys.stderr.write(start_ctl(test.partition_filename, test.server_filename)[1])
        stream_server_index = 0
        stream_epoch_offset = 0
        results = []
        
        sys.stderr.write("finished with control for" + test.partition_filename+ "\n")

        #kill the existing processes: 
        for i in range(len(agg_shells)):
            with agg_shells[i]:
                agg_results[i].send_signal(9)
        for i in range(len(dift_shells)):
            with dift_shells[i]:
                dift_results[i].send_signal(9)


        for i in range(test.num_partitions):
                        
            if i >= stream_epoch_offset + test.dift_hosts[stream_server_index].num_epochs:
                stream_epoch_offset += test.dift_hosts[stream_server_index].num_epochs
                stream_server_index += 1
            
            stream_server_host = test.dift_hosts[stream_server_index].host
            agg_server = test.agg_hosts[0] #only supporting a single aggregator here... 
            
            dift_file = read_sftp_file(stream_server_host, None, password, "/tmp/dift-stats" + str(i - stream_epoch_offset))
            stream_file = read_sftp_file(agg_server.host, None, password, "/tmp/" + str(i)+ "/stream-stats")
            results = test_results.Test_Results()

            results.epoch_number = i
            results.number_of_epochs = test.num_partitions
            results.parse_lines(dift_file)
            results.parse_lines(stream_file)
            results.compute_other_values() ##we need to do this to account for some odd values from our streamserver
            results.compute_other_data_values()

            file_time.write(",".join([str(s) for s in results.get_values()]))
            file_data.write(",".join([str(s) for s in results.get_data_values()]))
            
            file_time.write("\n")
            file_data.write("\n")
        file_time.write("\n")
        file_data.write("\n")

        sys.stderr.write("finished with " + test.partition_filename+ "\n")
            
    

main()
