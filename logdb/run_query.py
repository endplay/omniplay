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
    # make sure everything is in order
    runtime_info.check_system()

    filemap_process = runtime_info.filemap(args.filename)
    # filemap output is to stdout
    filemap_process.wait()
    filemap_output = filemap_process.communicate()[0]
    
    if not filemap_output:
        print("Could not get filemap info for %s" % args.filename)
        sys.exit(0)

    writes = []
    print(filemap_output.split("\n"))
    # now process the filemap results
    for line in filemap_output.split("\n"):
        if not line:
            continue
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

    # set linkages from command-line args
    linkages = []
    if args.linkages:
        linkages = args.linkages

    q = query.Query(runtime_info, writes, linkages)
    q.run()
    q.draw_graph()
    q.graph.output_graph()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Runs a provenance query")
    parser.add_argument("-v", "--verbose", help="Verbose output", dest="verbose", action="store_true")
    parser.add_argument("filename", help="File to run query on")
    parser.add_argument("-l", "--linkages", help="The linkages to use to run the query",
            nargs='+', dest='linkages')
    args = parser.parse_args()
    main(args)
