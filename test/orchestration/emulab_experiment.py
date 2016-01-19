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
CLOUDLAB_STREAMCTL_DIR = "/local/src/omniplay/test/"
CLOUDLAB_SCRIPTS_DIR = "/local/src/omniplay/scripts"
STREAMCTL_DIR = "/home/arquinn/Documents/omniplay/test/"
OUT2MERGE_DIR = "/home/arquinn/Documents/omniplay/dift/proc64"
HOME_DIR = "/home/arquinn"

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
        return self.host

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
            

    def ship_script(self, user, password):
        experiment_utilities.put_file(self.host, user, password, "run_background_task.sh", CLOUDLAB_STREAMSERVER_DIR + "/run_background_task.sh")
        experiment_utilities.put_file(self.host, user, password, "recv_replay_files", CLOUDLAB_STREAMSERVER_DIR + "/recv_replay_files")
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            results = shell.run(["sudo","/bin/chmod","777","run_background_task.sh"],cwd = CLOUDLAB_STREAMSERVER_DIR)
            results = shell.run(["sudo","/bin/chmod","777","recv_replay_files"],cwd = CLOUDLAB_STREAMSERVER_DIR)

    def prepare_for_replay(self, user, password, prefix_name): 
        self.replace_prefix(user, password, prefix_name)
        self.create_new_replay_dirs(user,password)
        self.ship_script(user,password)

    def start_server(self, user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            result = shell.run(["./run_background_task.sh","./streamserver"],cwd=CLOUDLAB_STREAMSERVER_DIR)

    def start_recv_files(self, user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            result = shell.run(["./run_background_task.sh","./recv_replay_files"],cwd=CLOUDLAB_STREAMSERVER_DIR)

    def prep_for_ctrl(self,user,password, partitions_file, server_config_file): 
        experiment_utilities.put_file(self.host, user, password, STREAMCTL_DIR + partitions_file, CLOUDLAB_STREAMCTL_DIR + "partitions.test")
        experiment_utilities.put_file(self.host, user, password, STREAMCTL_DIR + server_config_file, CLOUDLAB_STREAMCTL_DIR + "server.config")
    
    def start_ctrl(self, user,password, flags):
        args = ["./streamctl","partitions.test","server.config","-w"]
        for item in flags:
            args.append(item)                

        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            result = shell.run(args,cwd=CLOUDLAB_STREAMCTL_DIR)
            print result.output


    def kill_server(self, user, password):
        shell = experiment_utilities.open_ssh_session(self.host, user, password)
        with shell:
            shell.spawn(["pkill","-9","streamserver"])

class Test_Configuration: 
    #not sure that I need both the server_list and the server_config file....? 
    def __init__(self, partition_filename, server_config_files, prefix, stats_dir, results_dir, correct_dir): 
        self.partition_filename = partition_filename
        self.prefix = prefix
        self.num_partitions = sum(1 for this_line in open("../" + partition_filename, "r")) -1 #off by one b/c line with directory
        self.hosts = []
        self.stats_dir = stats_dir
        self.results_dir = results_dir
        self.correct_dir = correct_dir

        self.server_config_file = ""
        self.results = []
        self.shells = []

        for server_config in server_config_files:
            lines = sum(1 for line in open(server_config, "r"))
            num_cores = int(open(server_config, "r").readline().split()[0])
            total = lines * num_cores
            if total >= self.num_partitions:
                self.server_config_file = "orchestration/" + server_config
                break

        if len(self.server_config_file) == 0:
            print "oh no!, we don't have a server config big enough for",self.num_partitions

        with open("../" + self.server_config_file, "r") as server_list:
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
                print "<prepared",h.host,"for replay>"
        else:
            print "no prefix specified, skipping the prepare_for_replay"

        #clear out the existing results directories:
        server_index = 0
        offset = 0

        for i in range(self.num_partitions):
            if i >= offset + self.hosts[server_index].num_epochs:
                offset += self.hosts[server_index].num_epochs
                server_index += 1
                            
            server = self.hosts[server_index]
            remote_results_dir =  "/tmp/" + str(i - offset)
            shell = experiment_utilities.open_ssh_session(server.host, user, password)
            with shell:
                shell.run(["rm","-rf",remote_results_dir],cwd="/")
        print "<finished preparing for reaplay>"


    def ship_replay_files(self,user,password): 
        ctrl_host = self.hosts[0]
        ctrl_host.start_recv_files(user, password)

        replay_dir = open("../" +self.partition_filename, "r").readline().strip()
        args = ["./sync_files", replay_dir, ctrl_host.host]
                
        try:
            p = subprocess.check_output(args, cwd=STREAMCTL_DIR)
            print p
        except subprocess.CalledProcessError as e:
            print "streamctl returned non-zero rc"
            print e.cmd
            print e.returncode
            print e.output


    def start_ctrl(self, user, password, flags): 
        ctrl_host = self.hosts[0]
        ctrl_host.prep_for_ctrl(user,password, self.partition_filename, self.server_config_file)
        ctrl_host.start_ctrl(user, password, flags)
        print "<finished with stream_ctl for "+str(self.num_partitions) + " host test>"

    #needs to be rewritten
    def get_stats_files(self, user, password):         
        ctrl_host = self.hosts[0]
        output_file_prefix = self.stats_dir + "/" + str(self.num_partitions)

        for i in range(self.num_partitions):
            taint_file = "/tmp/taint-stats-" + str(i)
            stream_file = "/tmp/stream-stats-" + str(i)

            results_taint_file = STREAMCTL_DIR + "orchestration/" + output_file_prefix + ".taint-stats-" + str(i)
            results_stream_file = STREAMCTL_DIR + "orchestration/"+ output_file_prefix  +".stream-stats-" + str(i)

            experiment_utilities.get_file(ctrl_host.host, user, password, results_taint_file, taint_file)
            experiment_utilities.get_file(ctrl_host.host, user, password, results_stream_file, stream_file)


    def out2mergecmp(self):
        output_dir = self.results_dir + "/" + str(self.num_partitions) + "/"
        p = subprocess.check_output(["rm","-rf","tmp"],cwd=STREAMCTL_DIR+"/orchestration/"+output_dir)

        files = os.listdir(output_dir)
        sorted_files = sorted(files, key=lambda x: int(x.split('.')[0]), reverse=True)

        for i in sorted_files:
            p = subprocess.check_output(["tar","-xzf",i],cwd=STREAMCTL_DIR+"/orchestration/"+output_dir)
            os.chdir(output_dir + "/tmp/")
            newest_dir = max(os.listdir("."), key = os.path.getctime)
            os.chdir(STREAMCTL_DIR+"/orchestration")

            dest = i.split(".")[0]
            if newest_dir != dest:
                p = subprocess.check_output(["mv",newest_dir,dest],cwd=STREAMCTL_DIR+"/orchestration/"+output_dir +"/tmp/")

            
        ctrl_host = self.hosts[0]
        
        args = ["./out2mergecmp",str(ctrl_host.num_epochs), self.correct_dir,"-d",STREAMCTL_DIR+"/orchestration/"+output_dir+"/tmp"]
        for i in range(self.num_partitions):
            args.append(str(i))

        p = subprocess.check_output(args,cwd=OUT2MERGE_DIR)    
        print p


    def get_results_files(self, user, password):        
        output_dir = self.results_dir + "/" + str(self.num_partitions) + "/"
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
        
        server_index = 0
        offset = 0
    
        for i in range(self.num_partitions):

            if i >= offset + self.hosts[server_index].num_epochs:
                offset += self.hosts[server_index].num_epochs
                server_index += 1
                            
            server = self.hosts[server_index]
            remote_results_dir =  "/tmp/" + str(i - offset)
            remote_merge_output =  "/dev/shm/tmp." + str(i - offset) + ".merge-outputs-resolved"
            shell = experiment_utilities.open_ssh_session(server.host, user, password)
            with shell:
                for j in range(server.num_epochs):
                    remote_merge = remote_merge_output + "-" + str(j)
                    remote_results = remote_results_dir + "/merge-outputs-resolved-" + str(j)
                    shell.run(["mv",remote_merge, remote_results],cwd="/")

                shell.run(["tar","-zcf",remote_results_dir+".tgz",remote_results_dir],cwd = "/")                    

            local_results = output_dir + str(i) + ".tgz"
            remote_results = remote_results_dir + ".tgz"


            experiment_utilities.get_file(server.host, user, password,local_results, remote_results)
        print "<finished transfering results files>"

def get_hosts(server_config_file):
    hosts = []
    with open("../" + server_config_file, "r") as server_list:
        for line in server_list:
            words = line.split()
            s = Server(words[1], int(words[0]))    
            hosts.append(s)

    return hosts

    
def get_tests(filename, server_descs, prefix_filename, stats_dir, results_dir, correct_dir):

    config_file = open(filename, "r")
    tests = []
    for line in config_file:        

        next_test = Test_Configuration(line.strip(), server_descs, prefix_filename, stats_dir, results_dir, correct_dir)
        tests.append(next_test)

    config_file.close()
    return tests, get_hosts("orchestration/" +server_descs[0])


def make_server_description(num_hosts, cores_list, server_name_ending):

    server_config_names = []
    j = -1

    for num_cores in cores_list:
        j += 1
        server_config_names.append("server_config."+str(j))
        with open("server_config."+ str(j),"w+") as wfile:
            for i in range(num_hosts):
                server_name = "node-" + str(i) + server_name_ending
                wfile.write(str(num_cores) + " " + server_name + " " + server_name + "\n")    

    return server_config_names

# start_servers... needs to all be overhauled.. 
#
#
def start_servers(hosts, user, password):
    for h in hosts:
        h.start_server(user, password)
        print "<started streamserver on "+str(h.host)+">"
        
# kill_procs with shells and results
#
#
def kill_procs(hosts, user, password):
    for h in hosts:
        h.kill_server(user, password)
        print "<killed streamserver on "+str(h.host)+">"



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
    parser.add_option("--hs", "--host-suffix",dest="host_suffix",
                      help="the end of the hostname", metavar="HOST_SUFFIX")
    parser.add_option("-n", "--num_hosts",dest="num_hosts",
                      help="the number of hosts", metavar="NUM_HOSTS")
    parser.add_option("-c", "--correct_results_dir",dest="correct_dir",
                      help="the dir containing the seqtt results", metavar="CORRECCT_DIR")
    parser.add_option("--password", dest="password",
                      help="the password for username", metavar="PASSWORD")


    (options, args) = parser.parse_args()
    if options.host_suffix == None or len(options.host_suffix) == 0: 
        print "You must specify a host_suffix!"
        return -3

    if options.num_hosts == None or len(options.num_hosts) == 0: 
        print "You must specify the number of hosts"
        return -4

    if options.correct_dir == None or not os.path.isdir(options.correct_dir):
        print "You must specify the directory with the seqtt answer!"
        print options.correct_dir
        return -5


    output_dir = options.output_dir

    if output_dir == None:
        output_dir = ""
    else:
        output_dir += "/"
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)        
        
    stats_dir = output_dir + "stats"
    results_dir = output_dir + "results"

    if not os.path.isdir(stats_dir):
        os.makedirs(stats_dir)
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
        
    server_config_files = make_server_description(int(options.num_hosts), [4,8], options.host_suffix)  
    test_configurations, hosts = get_tests(config_file, server_config_files, options.prefix, stats_dir, results_dir, options.correct_dir)
    password = options.password


    last_test = test_configurations[-1]
    if options.sync: 
        last_test.prepare_for_replay("arquinn", password)
        last_test.ship_replay_files("arquinn",password)

    hosts_used = hosts[:last_test.num_partitions / 4] #this oughta be the number of hosts that we're using no? 
    start_servers(hosts_used, "arquinn", password) #why can't I just use last_test's hosts? 
        
    if options.sync:
        last_test.start_ctrl("arquinn", password,["-seq","-s","-stats"])
        last_test.get_results_files("arquinn",password)
        last_test.out2mergecmp()
        last_test.get_stats_files("arquinn",password)
        sys.stderr.write("finished syncing the files\n")

        kill_procs(hosts,"arquinn", password)
        return 0 #if we do sync, we don't do experiment
            
    for test in test_configurations:    
        #startup all aggregators in this test configuration:
        test.start_ctrl("arquinn", password,["-seq", "-stats"])
        test.get_stats_files("arquinn", password)
        sys.stderr.write("finished with " + test.partition_filename+ "\n")

        #test.get_results_files("arquinn",password)
        #test.out2mergecmp() #run the comparison! (for now at least)

    kill_procs(hosts_used,"arquinn",password)
main()
