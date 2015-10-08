#!/usr/bin/python

import sys
import glob
import re
import os

if (len(sys.argv) < 2):
    print "format: parselogs.py <dir> [-k]"
    sys.exit(0)

if (len(sys.argv) == 3 and sys.argv[2] == "-k"):
    no_user = 1
else:
    no_user = 0
dir = sys.argv[1]

for klog in glob.glob(dir + "/klog.id.*"):
    m = re.search("id.(\d+)", klog)
    os.system("./parseklog " + klog + "> /tmp/klog." + m.group(1));

if not no_user:
    for ulog in glob.glob(dir + "/ulog.id.*"):
        m = re.search("id.(\d+)", ulog)
        os.system("./parseulog " + ulog + "> /tmp/ulog." + m.group(1));
