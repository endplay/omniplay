#!/usr/bin/python

import server
import time
import datetime
import sys
import argparse
import getpass
import copy
import os


TESTS_DIR = "/home/arquinn/Documents/omniplay/test/experiment_config_files/"
SEQ_RES="/seqtt.results"

ARGS_MAP = {"gzip":["-stats","-c", "-w"],
            "gzip2":["-stats","-c", "-w", "-lowmem"],
            "nginx":["-stats","-c", "-w", "-p","4788"], 
            "mongo":["-stats","-w", "-c","-lowmem"],
            "mongolonger":["-stats","-w", "-c","-lowmem"],
            "evince":["-stats","-c", "-w","-lowmem"],
            "firefox":["-stats","-c","-w","-lowmem","-filter_inet"], 
            "firefoxlonger":["-stats","-c","-w","-lowmem","-filter_part","ookie","-filter_output_after","90000000"], 
            "openoffice":["-stats","-c","-w","-lowmem","-filter_part","jflinn"],
            "gs":["-stats","-w","-c"]
            }
LD_MAP = {"gzip":"my.ld-2.15.so",
          "gzip2":"my.ld-2.15.so",
          "nginx":"my.ld-2.15.so",
          "mongo":"my.ld-2.15.so",
          "mongolonger":"my.ld-2.15.so",
          "evince":"jason.ld-2.15.so",
          "firefox":"jason.ld-2.15.so",
          "firefoxlonger":"jason.ld-2.15.so",
          "openoffice":"jason.ld-2.15.so",
          "gs":"jason.ld-2.15.so"
          }

VERF_ARGS = ["-v","tmp_results","seqtt.results"]#, "-record_trace"]
SYNC_ARGS = ["-s","-v","tmp_results","seqtt.results"]
OPTS = [["-seq"],["-seq","-streamls"], ["-seqppl","-streamls"], []]

def sync_files(user, password, tconfigs, args,do_full_sync):
    
    last_test = tconfigs[-1]
    last_test.ship_replay_files(user,password)
    last_test.prep_sync_ctrl(user,password)

    if do_full_sync:
        last_test.start_ctrl(user, password, args)
    sys.stderr.write("finished full sync\n")
    

def run_tests(user, password, stats_dir, tconfigs, args,num_rounds, offset): 
    for t in tconfigs:
        for r in range(num_rounds):   
            d = r + int(offset)
            t.prep_ctrl(user,password)                                     
            t.start_ctrl(user, password, args)
            t.get_stats_files(user, password, stats_dir + str(d) + "/")
            sys.stderr.write("<finished "+str(r)+" round (written to"+str(d)+">")
                
def get_test_configs(filename, correct_dir, hosts, start_offset, server_filename):

    config_file = open(filename, "r")
    num_lines = sum(1 for line in open(filename))
    count = 0
    tests = []
    prefix = ""
    for line in config_file:
        count += 1
        if count < num_lines and\
                (start_offset < 0 or (TESTS_DIR + line.strip()).split(".")[-1] >= start_offset):

            next_test = server.Test_Configuration(TESTS_DIR + line.strip(), \
                                                  None,\
                                                  server_filename,\
                                                  hosts)
        else:
            next_test = server.Test_Configuration(TESTS_DIR + line.strip(), correct_dir, server_filename, hosts)

        tests.append(next_test)

    config_file.close()
    return tests



def gen_hosts(num_cores, server_name_ending, server_filename):

    hosts = []
    with open(server_filename,"r") as rfile:
        for line in rfile:
            server_name = line.split()[1]
            if ".net" not in server_name:
                server_name += "." + server_name_ending
            s = server.Server(server_name,str(num_cores))
            hosts.append(s)

    return hosts


def main(): 

    parser = argparse.ArgumentParser()
    parser.add_argument("--hs", "--host-suffix",dest="host_suffix", required=True)
    parser.add_argument("-p","--password",dest="password", required=True)
    parser.add_argument("-t","--test",dest="test", required=True)
    parser.add_argument("--sf","--server_filename",dest="server_filename", required=True)
    parser.add_argument("--nr","--num_rounds",dest="num_rounds", required=True)
    parser.add_argument("--ec","--experiment_conf",dest="exp_conf", required=True)
    parser.add_argument("-o","--offset",dest="offset", required=True)
    parser.add_argument("--sot", "--skip_one_time",action="store_true",dest="skip_otime", default=False)
    parser.add_argument("--sld", "--skip_loader", action="store_true",dest="skip_ld",default=False)
    parser.add_argument("--sc", "--skip_clear", action="store_true",dest="skip_clear",default=False)
    parser.add_argument("--ss", "--skip_sync", action="store_true",dest="skip_sync",default=False)
    parser.add_argument("--sa", "--skip_all", action="store_true",dest="skip_all",default=False)
    parser.add_argument("--sop", "--skip_one_pass", action="store_true",dest="skip_one_pass",default=False)
    parser.add_argument("--only_preprue", action="store_true",dest="only_preprune",default=False)
    parser.add_argument("--only_stream", action="store_true",dest="only_stream",default=False)
    parser.add_argument("--only_one_pass", action="store_true",dest="only_one_pass",default=False)
    parser.add_argument("--only_seq", action="store_true",dest="only_seq",default=False)

    parser.add_argument("--so", "--start_offset", dest="start_offset")
    parser.add_argument("--selective_skip", dest="selective_skip")


    cmd_args = parser.parse_args()

    ## setup the stats_dir
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S.%m.%d.%Y")
    base_stats_dir = st + "." + cmd_args.test + ".stats." + cmd_args.exp_conf.strip("/")
    while os.path.isdir(base_stats_dir+"/"):
        print>>sys.stderr,"whoops, someone already made",base_stats_dir,"try again!"
        st = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S.%m.%d.%Y")
        base_stats_dir = st + "." + cmd_args.test + ".stats"

    print>>sys.stderr,"stats dir is",base_stats_dir


    ## get the hosts
    hosts = gen_hosts(4, cmd_args.host_suffix,cmd_args.server_filename)
    
    ## pull the values out of the map
    loader = LD_MAP[cmd_args.test]
    args = ARGS_MAP[cmd_args.test]
    
    ## get the tests_configs
    if cmd_args.start_offset != None and cmd_args.start_offset > 0:

        tconfs = get_test_configs(TESTS_DIR + cmd_args.test + cmd_args.exp_conf, \
                                      TESTS_DIR + cmd_args.test + SEQ_RES, \
                                      hosts,\
                                      cmd_args.start_offset,\
                                      cmd_args.server_filename)
    else: 
        tconfs = get_test_configs(TESTS_DIR + cmd_args.test + cmd_args.exp_conf, \
                                      TESTS_DIR + cmd_args.test + SEQ_RES, \
                                      hosts,\
                                      -1,\
                                      cmd_args.server_filename)

        


    ## a better library would allow you to do all these things w/ one session. oh well
    for h in hosts:
        if not cmd_args.selective_skip or (cmd_args.selective_skip and cmd_args.selective_skip in h.host):

            if not cmd_args.skip_ld and not cmd_args.skip_all:
                h.replace_prefix("arquinn",cmd_args.password, loader)

            if not cmd_args.skip_clear and not cmd_args.skip_all:
                h.clear_replay_dirs("arquinn",cmd_args.password)
        
        #weirdly needs to happen last. (the loader won't be in place o/w)
            if not cmd_args.skip_otime and not cmd_args.skip_all:
                h.one_time_setup("arquinn", cmd_args.password)


        h.start_streamserver("arquinn", cmd_args.password)        
        print >> sys.stderr, "<started streamserver on "+str(h.host)+">"        



    if not cmd_args.skip_sync and not cmd_args.skip_all:
        sync_cmd_args = copy.deepcopy(args)
        sync_cmd_args.extend(SYNC_ARGS)
        sync_cmd_args.extend(["-hs","."+cmd_args.host_suffix])
        sync_cmd_args.append("-seqppl") #can't do one_pass
        sync_cmd_args.append("-streamls")

        print>>sys.stderr, sync_cmd_args
        if len(hosts) > 1:
            sync_files("arquinn",cmd_args.password,tconfs,sync_cmd_args, True)
        else:
            sync_files("arquinn",cmd_args.password,tconfs,sync_cmd_args, False)
            print>>sys.stderr, "skipping sync, we only have on host!"

    for c in OPTS:
        if cmd_args.skip_one_pass and len(c) == 0:
            continue
        if cmd_args.only_preprune and "-seqppl" not in c: #only do ppl
            continue

        if cmd_args.only_stream and "-streamls" not in c: #only do stream
            continue
        if cmd_args.only_stream and "-seqppl" in c: #only do stream
            continue

        if cmd_args.only_seq and "-seq" not in c:
            continue
        if cmd_args.only_seq and "-streamls" in c: #only do stream
            continue

        if cmd_args.only_one_pass and len(c) > 0:
            continue

        if len(c) != 0:
            name = c[-1].strip("-")
            name = ".".join([t.strip("-") for t in c])

        else:
            name = "one_pass"

        stats_dir = base_stats_dir + "/" + name + "/"
        for r in range(int(cmd_args.num_rounds)):
            d = r + int(cmd_args.offset)
            if not os.path.isdir(stats_dir + str(d) + "/"):
                os.makedirs(stats_dir + str(d) + "/")

        
        a = copy.deepcopy(args)
        a.extend(VERF_ARGS)
        a.extend(c)       
        a.extend(["-hs","." + cmd_args.host_suffix])
        print>>sys.stderr, name, a
        

        run_tests("arquinn", cmd_args.password, stats_dir, tconfs,a, int(cmd_args.num_rounds),int(cmd_args.offset))
        
    for h in hosts:
        h.kill_server("arquinn", cmd_args.password)
        print >> sys.stderr, "<killing streamserver on "+str(h.host)+">"        

main()
