#!/usr/bin/python

import retaint_server
import time
import datetime
import sys
import argparse
import getpass
import copy
import os

LD_MAP = {"gzip":"my.ld-2.15.so",
          "nginx":"my.ld-2.15.so",
          "mongo":"my.ld-2.15.so",
          "evince":"jason.ld-2.15.so",
          "firefox":"jason.ld-2.15.so",
          "openoffice":"jason.ld-2.15.so",
          "gs":"jason.ld-2.15.so" }

ARGS_MAP = {"firefox":["-filter_inet","-following","0"], 
            "openoffice":["-filter_partfile","jflinn","-following","0"] }


def run_tests(h,user, password, stats_dir, offset, args): 
    h.run_retaint_experiment(user,password, args)
    h.get_retaint_stats_file(user, password, stats_dir + str(offset))

def main(): 

    parser = argparse.ArgumentParser()
    parser.add_argument("--host",dest="host", required=True)
    parser.add_argument("-t","--test",dest="test",required=True)
    parser.add_argument("-p","--password",dest="password", required=True)
    parser.add_argument("--pf","--parts_file",dest="pfile", required=True)
    parser.add_argument("-o","--offset",dest="offset", required=True)

    cmd_args = parser.parse_args()

    ## setup the stats_dir

    partsfile = cmd_args.pfile.split("/")[-1]
    base_stats_dir = cmd_args.test + ".stats.retaint/" + partsfile +"/"
    if not os.path.isdir(base_stats_dir):
        os.makedirs(base_stats_dir)
    print>>sys.stderr,"stats dir is",base_stats_dir

    
    ## pull the values out of the map
    loader = LD_MAP[cmd_args.test]

    args = []
    if cmd_args.test in ARGS_MAP:
        args = ARGS_MAP[cmd_args.test]

    



    replay_dir = open(cmd_args.pfile, "r").readline().strip()
    h = retaint_server.Server(cmd_args.host,replay_dir, cmd_args.pfile)

    print >> sys.stderr, "<and here we go...>"
    ## a better library would allow you to do all these things w/ one session. oh well    
    h.replace_prefix("arquinn",cmd_args.password, loader)                            
    h.clear_replay_dirs("arquinn",cmd_args.password)
    h.one_time_setup("arquinn", cmd_args.password)

    h.sync_files("arquinn", cmd_args.password)

    h.start_pound_cpu("arquinn",cmd_args.password)
    run_tests(h,"arquinn", cmd_args.password, base_stats_dir,int(cmd_args.offset),args)
    h.kill_pound_cpu("arquinn",cmd_args.password)

    print >> sys.stderr, "<and we're done>"

main()
