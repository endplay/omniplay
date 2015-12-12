#!/usr/bin/python

import sys
import os

newlog = "/replay_logdb." + sys.argv[1] 
newcache = "/replay_cache." + sys.argv[1] 
oldlog = "/replay_logdb." + sys.argv[2] 
oldcache = "/replay_cache." + sys.argv[2] 

if not os.path.isdir(newlog):
    print newlog, "does not exist"
    sys.exit(0)

if not os.path.isdir(newcache):
    print newcache, "does not exist"
    sys.exit(0)

if os.path.isdir(oldlog):
    print oldlog, "exists"
    sys.exit(0)

if os.path.isdir(oldcache):
    print oldcache, "exists"
    sys.exit(0)

os.rename("/replay_logdb", oldlog)
os.rename("/replay_cache", oldcache)
os.rename(newlog,"/replay_logdb")
os.rename(newcache,"/replay_cache")
