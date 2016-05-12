#!/usr/bin/python

SERVER_FILENAME= "server_config"
REVERSE = "server_config_reversed"

with open(REVERSE,"w+") as ofile:
    for line in reversed(open(SERVER_FILENAME).readlines()):
        ofile.write(line)
