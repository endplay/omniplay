#!/usr/bin/python

import argparse
import os
import sys

# our modules
import opinfo
import query
import runtime

def main(args):
    if args.verbose:
        print("Verbose output turned on")
    if not os.path.exists(args.filename):
        print("File %s does not exist" % args.filename)
        sys.exit(0)

    # form the right query to run
    runtime_info = runtime.RunTimeInfo(verbose=args.verbose)
    filemap_process = runtime_info.filemap(args.filename)
    filemap_process.wait()
    
    if not os.path.exists("/tmp/filemap_output"):
        print("Could not get filemap?")
        sys.exit(0)

    writes = []
    # now process the filemap results
    f = open("/tmp/filemap_output", "r")
    for line in f.readlines():
        fields = line.split(" ")
        offset = int(fields[0])
        size = int(fields[1])
        group_id = int(fields[2])
        pid = int(fields[3])
        sysnum = int(fields[4])
        wi = opinfo.WriteInfo(group_id, pid, sysnum, offset, size)
        print("Starting Write info [%d, %d, %d, %d, %d]" % (group_id, pid, sysnum, offset, size))
        writes.append(wi)

    if not writes:
        print("File %s has no write information!")
        sys.exit(0)

    # write_info = opinfo.WriteInfo(4143, 3468, 42, 0, 5)
    q = query.Query(runtime_info, writes)
    q.run()
    q.draw_graph()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Runs a provenance query")
    parser.add_argument("filename", help="File to run query on")
    parser.add_argument("-v", "--verbose", help="Verbose output", dest="verbose", action="store_true")
    parser.add_argument("-l", "--linkages", help="The linkages to use to run the query",
            nargs='+', dest='linkages')
    args = parser.parse_args()
    main(args)
