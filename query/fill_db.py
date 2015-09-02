#!/usr/bin/python

import os
import sys
import argparse

# our modules
import replay_logdb

def main(args):
    if args.omniplay:
        omniplay_path = args.omniplay
    elif os.environ['OMNIPLAY_DIR']:
        omniplay_path = os.environ['OMNIPLAY_DIR']
    else:
        print("Your OMNIPLAY_DIR environment variable is not setup")
        print("and you haven't provided an omniplay path")
        print("usage: python fill_db.py -o [omniplay path]")
        sys.exit(1)

    print("Your provided omniplay path is %s" % omniplay_path)

    start_id = 0
    if args.start:
        try:
            start_id = int(args.start)
        except ValueError:
            print("could not parse start group id, %s, needs to be an int"
                    % args.start)
            sys.exit(0)

    end_id = sys.maxint
    if args.end:
        try:
            end_id = int(args.end)
        except ValueError:
            print("could not parse end group id, %s, needs to be an int"
                    % args.end)
            sys.exit(0)

    print("Starting from group id %d, going to %d" % (start_id, end_id))

    # See logdb.py, but the default location for the db is 
    #  /replay_logdb/replay.db
    #  and creates the table 'replays'
    rldb = replay_logdb.ReplayLogDB(omniplay_path, 
                                logdb_name="replay.db",
                                logdb_dir="/replay_logdb",
                                replay_table_name="replays",
                                start=start_id,
                                finish=end_id)
    rldb.init_cursor()
    rldb.create_tables()

    # looks in logdb_dir and populates the DB from this directory.
    # Ignores replays already in the DB
    rldb.populate()
    rldb.close_cursor()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Runs a single linkage on a replay group")
    parser.add_argument("-o", "--omniplay",
            help="Omniplay director, overrides the env. variable")
    parser.add_argument("-s", "--start", help="Group ID to start at")
    parser.add_argument("-e", "--end", help="Group ID to end at")
    args = parser.parse_args()
    main(args)
