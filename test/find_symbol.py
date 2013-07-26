#!/usr/bin/python

import sys
import os
import subprocess
import popen2
import commands
import re

if (len(sys.argv) != 4):
    print "format: find_symbol.py <address> <dir> <pid>"
    sys.exit(0)

symbol = int(sys.argv[1], 16)
print "dir is: ", sys.argv[2]
print "pid is: ", sys.argv[3]

klog = sys.argv[2] + "/klog.id." + sys.argv[3]
p = subprocess.Popen (["./parseklog", klog], stdout=subprocess.PIPE)
lines = p.stdout.read().split("\n")
last_address = 0
need_dev = 0
for line in lines:
    if ("sysnum 192" in line):
        m = re.search("\([0-9a-f]*\)", line)
        if m:
            hex_address = m.group(0)
            hex_address = hex_address[1:len(hex_address)-1]
            address = int(hex_address,16)
            if (address < symbol and address > last_address):
                last_address = address
                last_hex_address = hex_address
                need_dev = 1
    elif ("dev is" in line and need_dev):
        last_dev = line[8:]
    elif ("ino is" in line and need_dev):
        last_ino = line[8:]
    elif ("mtime is" in line and need_dev):
        last_mtime = line[10:]
        need_dev = 0

p.stdout.close()

offset = symbol - last_address

last_path = "/replay_cache/" + last_dev + "_" + last_ino;
print last_path, last_hex_address,
print "0x%x"%offset

p = subprocess.Popen (["nm", last_path], stdout=subprocess.PIPE)
lines = p.stdout.read().split("\n")
last_address = 0
for line in lines:
    info = line.split()
    if (len(info) == 3):
        [address, type, symbol] = info
        address = int(address,16)
        if (address < offset and address > last_address and not symbol[0:2] == ".L"):
            last_address = address
            last_symbol = symbol

print "%s 0x%x"%(last_symbol, last_address)

p.stdout.close()


