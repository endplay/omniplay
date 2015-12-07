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

class Server:
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


def start_server(host, port, user, password, path): 

    stdout_file = open(path + ".stdout","wr")
    stderr_file = open(path + ".stderr","wr")

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
        dift = Server(words[1], STREAMSERVER_PORT, int(words[0]))
        agg = Server(words[2],STREAMSERVER_PORT, int(words[0]))
        if len(words) > 3:
            agg = Server(words[2],words[3],words[0])

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

def output_file(list_to_output, filename): 
    with open(filename, "w") as ofile:
        for line in list_to_output:
            ofile.write(line)

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
    parser.add_option("-t", "--time-outputs", dest="time_outputs",
                      help="where to save the parsed time info", metavar="TIME-OUTPUTS")
    parser.add_option("-d", "--data-outputs", dest="data_outputs",
                      help="where to save the parsed data outputs", metavar="DATA-OUTPUTS")

    (options, args) = parser.parse_args()
    if options.time_outputs == None: 
        sys.stderr.write("You must supply a time-outputs file path!\n")
        return -1
    if options.data_outputs == None: 
        sys.stderr.write("You must supply a data-outputs file path!\n")
        return -1

    stream_stats_dir = options.stream_stats

    if stream_stats_dir == None:
        stream_stats_dir = ""
    
    elif not os.path.isdir(stream_stats_dir):
        os.makedirs(stream_stats_dir)
        
    if not os.path.isdir(stream_stats_dir + "/pin_output"):
        os.makedirs(stream_stats_dir +"/pin_output")

    test_configurations = get_tests(config_file)
    password = getpass.getpass()        

    file_time = open(options.time_outputs, "w")
    file_data = open(options.data_outputs, "w")

    file_time.write(",".join(test_results.Test_Results.get_titles()))
    file_data.write(",".join(test_results.Test_Results.get_data_titles()))
    file_time.write("\n")
    file_data.write("\n")

    for test in test_configurations:    
        #startup all aggregators in this test configuration:
        agg_shells = []
        agg_results = []
        for agg_server in test.agg_hosts:
            agg_output_path = stream_stats_dir + "/pin_output/" + str(test.num_partitions) + "." + agg_server.host + "." + str(agg_server.num_epochs)
            agg_shell, agg_result = start_server(agg_server.host, agg_server.port, None, password, agg_output_path)
            agg_shells.append(agg_shell)
            agg_results.append(agg_result)

            sys.stderr.write(str(agg_result.pid) + " started on aggregator\n")

        #startup all dift servers in this test configuration
        dift_shells = []
        dift_results = []
        for dift_server in test.dift_hosts:
            dift_output_path = stream_stats_dir + "/pin_output/" + str(test.num_partitions) + "." + dift_server.host + "." + str(dift_server.num_epochs)
            dift_shell, dift_result = start_server(dift_server.host, dift_server.port, None, password, dift_output_path)
            dift_shells.append(dift_shell)
            dift_results.append(dift_result)
            sys.stderr.write(str(dift_result.pid) + " started on dift\n")

        sys.stderr.write(start_ctl(test.partition_filename, test.server_filename)[1])
        stream_server_index = 0
        stream_offset = 0
        agg_offset = 0
        agg_server_index = 0
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
                        
            if i >= stream_offset + test.dift_hosts[stream_server_index].num_epochs:
                stream_offset += test.dift_hosts[stream_server_index].num_epochs
                stream_server_index += 1

            if i >= agg_offset + test.agg_hosts[agg_server_index].num_epochs:
                agg_offset += test.agg_hosts[agg_server_index].num_epochs
                agg_server_index += 1
                
            
            stream_server_host = test.dift_hosts[stream_server_index].host
            agg_server_host = test.agg_hosts[agg_server_index].host
            
            dift_file = read_sftp_file(stream_server_host, None, password, "/tmp/dift-stats" + str(i - stream_offset))
            agg_file = read_sftp_file(agg_server_host, None, password, "/tmp/" + str(i)+ "/stream-stats")
            #dump the files to local file system
            dift_filename = stream_stats_dir + "/" + str(test.num_partitions) + "." + stream_server_host +".dift-stats" + str(i-stream_offset)
            agg_filename = stream_stats_dir + "/" + str(test.num_partitions) + "." + agg_server_host + ".stream-stats" + str(i-agg_offset)
            output_file(dift_file, dift_filename)
            output_file(agg_file, agg_filename)


            results = test_results.Test_Results()
            results.epoch_number = i
            results.number_of_epochs = test.num_partitions
            results.parse_lines(dift_file)
            results.parse_lines(agg_file)
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
