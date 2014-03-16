#!/usr/bin/python

import sys
import glob
import re
import os

if (len(sys.argv) != 2):
    print "format: parselogs.py <dir>"
    sys.exit(0)

dir = sys.argv[1]

for klog in glob.glob(dir + "/klog.id.*"):
    m = re.search("id.(\d+)", klog)
    os.system("./parseklog " + klog + "> /tmp/klog." + m.group(1));

for ulog in glob.glob(dir + "/ulog.id.*"):
    m = re.search("id.(\d+)", ulog)
    os.system("./parseulog " + ulog + "> /tmp/ulog." + m.group(1));
