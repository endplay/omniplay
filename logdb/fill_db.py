#!/usr/bin/python

import omniplay
import argparse

def main():
    start_id = 0
    if args.start:
        try:
            start_id = int(args.start)
        except ValueError:
            print("could not parse start group id, %s, needs to be an int" % 
                    args.start)
            sys.exit(0)

    end_id = sys.maxint
    if args.end:
        try:
            end_id = int(args.end)
        except ValueError:
            print("could not parse end group id, %s, needs to be an int" %
                    args.end)
            sys.exit(0)

    if args.verbose:
        print("Starting from group id %d, going to %d" % 
                (start_id, end_id))

    # bounds check
    if end_id < start_id:
        print("Invalid ID bounds, end_id < start_id")
        sys.exit(-1)

    env = omniplay.OmniplayEnvironment()
    rldb = omniplay.logdb.ReplayLogDB(env, start_id=start_id, end_id=end_id)
    rldb.updatedb()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Runs a single linkage on a replay group")
    parser.add_argument("-s", "--start", help="Group ID to start at")
    parser.add_argument("-e", "--end", help="Group ID to end at")
    parser.add_argument("-v", "--verbose", help="verbose output")
    args = parser.parse_args()
    main(args)
