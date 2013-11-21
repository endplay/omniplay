#!/usr/bin/python

import sys
import logdb

def main():

    if len(sys.argv) != 2:
        print("Please provide your omniplay path")
        sys.exit(-1)

    # pass in path for omniplay
    omniplay_path = sys.argv[1]

    # See logdb.py, but the defaul location for the db is /replay_logdb/replay.db
    #  and creates the table 'replays'
    rldb = logdb.ReplayLogDB(omniplay_path, logdb_name="replay.db", logdb_dir="/replay_logdb", replay_table_name="replays")
    rldb.create_table()

    # looks in logdb_dir and populates the DB from this directory.
    # Ignores replays already in the DB
    rldb.populate()

if __name__ == "__main__":
    main()
