#!/usr/bin/python

import sys
import os


def parse_stats(directory): 
    l = []

    print directory
    for v in os.listdir(directory + "/tmp/"):
        with open(directory + "/tmp/"+v+"/taint_stats") as ofile:
            retaint_time = 0.0
            for line in ofile:
                if "Retaint execution time:" in line:
                    retaint_time = line.split()[3]

            l.append(retaint_time)

                                       
    return l



def main(): 
    d = sys.argv[1]

    bm_name = d.split(".")[0]
    print bm_name
    with open(bm_name +".retaint","w+") as ofile:
        dirs = sorted(os.listdir(d), key=lambda x: (int(x.split('.')[1])))

        for val in dirs:
            size = val.split(".")[1]
            ofile.write(size)
            ofile.write(",")
            l = parse_stats(d + "/" + val)
            outstr = ",".join(l)
            ofile.write(outstr)
            ofile.write("\n")


main()
