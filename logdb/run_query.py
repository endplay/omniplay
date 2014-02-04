#!/usr/bin/python

import argparse

# our modules
import opinfo
import query
import runtime

def main(args):
    if args.verbose:
        print("Verbose output turned on")
    runtime_info = runtime.RunTimeInfo(verbose=args.verbose)
    write_info = opinfo.WriteInfo(4143, 3468, 42, 0, 5)
    q = query.Query(runtime_info, write_info)
    q.run()
    q.draw_graph()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Runs a provenance query")
    parser.add_argument("-v", "--verbose", help="Verbose output", dest="verbose", action="store_true")
    args = parser.parse_args()
    main(args)
