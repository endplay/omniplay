#!/usr/bin/python

import omniplay

def main():

    env = omniplay.OmniplayEnvironment()

    # See logdb.py, but the defaul location for the db is /replay_logdb/replay.db
    #  and creates the table 'replays'
    rldb = omniplay.logdb.ReplayLogDB(env)
    rldb.updatedb()

if __name__ == "__main__":
    main()

