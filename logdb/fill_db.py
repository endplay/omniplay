#!/usr/bin/python

import os
import sys
import logdb

def main():

    omniplay_path = None

    if len(sys.argv) != 2:
        omniplay_path = os.environ['OMNIPLAY_DIR']
        if not 'OMNIPLAY_DIR' in os.environ:
            print("Please provide your omniplay path, or run setup to set your OMNIPLAY_DIR env variable")
            sys.exit(-1)
    else:
        # pass in path for omniplay
        omniplay_path = sys.argv[1]

    # See logdb.py, but the defaul location for the db is /replay_logdb/replay.db
    #  and creates the table 'replays'
    rldb = logdb.ReplayLogDB(omniplay_path, logdb_name="replay.db",
            logdb_dir="/replay_logdb", replay_table_name="replays")
    rldb.init_cursor()
    rldb.create_table()

    # looks in logdb_dir and populates the DB from this directory.
    # Ignores replays already in the DB
    rldb.populate()
    rldb.close_cursor()

if __name__ == "__main__":
    main()

