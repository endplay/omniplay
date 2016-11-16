#!/usr/bin/python

import sys

def main(): 
    ckpt_file = sys.argv[1]
    attach_points = []
    curr_time = 0.00

    with open(ckpt_file, "r") as cfile:
        num_entries = cfile.readline().strip()
        for line in cfile:
            words = line.strip().split()
            if (2.5 * float(words[2])) >= curr_time + 500: 
                print words[1].strip(",")
                curr_time += 500

main()
