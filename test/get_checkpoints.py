#!/usr/bin/python

import sys

def main(): 
    ckpt_file = sys.argv[1]
    pid = sys.argv[2]

    attach_points = []
    curr_time = 0.00

    with open(ckpt_file, "r") as cfile:
        for line in cfile:
#            print line
            words = line.strip().split(",")
            if (2.5 * float(words[2])) >= curr_time + 500 and words[0] == pid: 
                print words[1],
                curr_time += 500


                      
    


main()
