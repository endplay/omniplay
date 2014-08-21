#!/usr/bin/python

import argparse
import os
import sys
import time

import runtime

def main(args):
    rec_dir = args.replay_directory
    flags = ""
    if args.flags:
        flags = args.flags
        print(flags)
    replay_follow = False
    if args.replay_follow:
        replay_follow = True

    if args.args_pass:
        argstr = args.args_pass

        # Split the line at the ,'s
        opts = argstr.split(',')

        # Add the ,'s to the flags
        for itm in opts:
            flags += " -"
            itm = itm.replace('=', ' ')
            flags += itm

    omniplay_path = os.environ['OMNIPLAY_DIR']
    if not 'OMNIPLAY_DIR' in os.environ:
        print("Your OMNIPLAY_DIR environment variable is not setup")
        sys.exit(0)
    runtime_info = runtime.RunTimeInfo(omniplay_location=omniplay_path)

    if args.pin_tool[0] == "/" and not os.path.exists(args.pin_tool):
        if not os.path.exists(runtime_info.tools_location + "/" + args.pin_tool):
            print("Pin tool %s does not exist")
            sys.exit(0)

    # assert os.path.exists(args.pin_tool)
    # assert os.path.exists(runtime_info.tools_location + "/" + args.pin_tool)

    print("Running replay: %s with tool %s" % (args.replay_directory, args.pin_tool))

    stderr_log = "/tmp/stderr_log"
    if args.stderr_log:
        stderr_log = args.stderr_log
    log_f = open(stderr_log, "w")
    tool_f = open("/tmp/tool_log", "w")

    replay_process = runtime_info.replay(rec_dir, log_f, pin=True,
                                                follow=replay_follow)
    replay_pid = replay_process.pid

    time.sleep(1)
    start_time = time.time()

    attach_process = runtime_info.attach_tool_extended(replay_process.pid, args.pin_tool,
                                                        tool_f, flags=flags)

    attach_process.wait()
    replay_process.wait()
    end_time = time.time()
    
    print("done, took %f secs" % (end_time - start_time))
    print("replay pid was %d" % replay_pid)

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Run replay with tool script")
    parser.add_argument("replay_directory", help="Directory of the replay to start the query on")
    parser.add_argument("pin_tool", help="Pin tool to run")
    parser.add_argument("-f", "--flags", dest="flags")
    parser.add_argument("-x", "--extended", dest="extended", action="store_true")
    parser.add_argument("-l", "--log", dest="stderr_log")
    parser.add_argument("-o", dest="stderr_log")
    parser.add_argument("-a", "--arg-pass", dest="args_pass")
    parser.add_argument("-w", "--follow", dest="replay_follow", action="store_true")
    main_args = parser.parse_args()
    main(main_args)

