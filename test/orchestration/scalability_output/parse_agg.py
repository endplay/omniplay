#!/usr/bin/python
import sys


def get_stats(filename): 
    rd = {}
    with open(filename, "r") as dfile:
        for line in dfile:
            words = line.split(",")
            rd[words[0]] = (words[2], words[3].strip())

    return rd

def main():
    print sys.argv
    bmlistfile = sys.argv[1]

    bm_data = {}
    with open(bmlistfile, "r") as bmfile:
        for line in bmfile:
            bm = line.strip().split("/")[1].split(".")[0]
            bm_data[bm] = get_stats(line.strip())



    with open("opt_files/opt.stats", "w+") as ofile:
        print>>ofile, "benchmark, Backwards Pass, Both Passes, Preprune"
        
        for l in bm_data:

            print>>ofile, l,",",
            if "one_pass" in bm_data[l]:
                print>>ofile, bm_data[l]["one_pass"][0],",",bm_data[l]["one_pass"][1],",",
            else:
                print>>ofile, "0,0,",

            if "seq.streamls" in bm_data[l]:
                print>>ofile, bm_data[l]["seq.streamls"][0],",",bm_data[l]["seq.streamls"][1],",",
            else:
                print>>ofile, "0,0,",

            if "seqppl.streamls" in bm_data[l]:
                print>>ofile, bm_data[l]["seqppl.streamls"][0],",",bm_data[l]["seqppl.streamls"][1],","
            else:
                print>>ofile, "0,0,"
            
                
        
    



main()
