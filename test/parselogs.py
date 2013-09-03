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
    print klog
    m = re.search("\d+", klog)
    print m.group(0)
    os.system("./parseklog " + klog + "> /tmp/klog." + m.group(0));
