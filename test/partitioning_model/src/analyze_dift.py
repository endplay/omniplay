#!/usr/bin/python

import matplotlib.pyplot as plt
import math
import numpy as np
import sys
import optparse
import os
import copy
from scipy import stats
import graph_utilities
import epoch

def get_stats(input_dir, data_file):
    dift = []
    utime = []
    ctime = []
    taint_in = []
    taint_out = []
    uinsts = []
    ainsts = []
    imisses = []
    instructions = []
    traces = []
    pin_insts = []
    pin_traces = []
    pin_nmerges = []
    pin_nsaved = []
    num_merges = []
    num_saved = []
    fftime = []
    

    epochs = []
    with open(data_file, "r") as df:         
        for line in df: 
            words = line.split()
            utime.append(float(words[2]))
            ctime.append(float(words[3]))
            uinsts.append(float(words[4]))
            imisses.append(float(words[5]))
            pin_insts.append(float(words[6]))
            pin_traces.append(float(words[7]))
            pin_nmerges.append(float(words[8]))

    num_epochs = int(data_file.split("/")[-1].split(".")[0])
    for i in range(num_epochs): 
        taint_file = input_dir + str(num_epochs) + ".taint-stats-" + str(i)
        with open(taint_file, "r") as fh:
            for line in fh:
                if line[:10] == "DIFT began":
                    began = float(line.split()[3])
                if line[:10] == "DIFT ended":
                    ended = float(line.split()[3])
                    dift.append(float((ended-began)*1000.0))
                if line[:len("Instructions instrumented")] == "Instructions instrumented":
                    instructions.append(float(line.split()[2]))
                if line[:len("Traces instrumented")] == "Traces instrumented":
                    traces.append(float(line.split()[2]))
                if line[:len("Num merges")] == "Num merges" and "saved" not in line:
                    num_merges.append(float(line.split()[2]))
                elif line[:len("Num merges")] == "Num merges":
                    num_saved.append(float(line.split()[3]))
                    
        stream_file = input_dir + str(num_epochs) + ".stream-stats-" + str(i)
        with open(stream_file, "r") as fh:
            for line in fh:
              if line[:13] == "Receive time:":
                  fftime.append(int(line.split()[2]))
        
    ftime = []
    for f,d in zip(fftime, dift):
        ftime.append(f - d) 

#    mean_dift = np.mean(dift)
    mean_fftime = np.mean(fftime)
    for i in range(num_epochs):
        e = epoch.Epoch(i,data_file,utime[i], ctime[i],utime[i],imisses[i],pin_insts[i],\
                        pin_traces[i],pin_nmerges[i],mean_fftime, dift[i],instructions[i],\
                        traces[i],num_merges[i],ftime[i], "k")
        
        epochs.append(e)

    return epochs

def main(): 

    filename = sys.argv[1]
    epochs = []

    #code to get arguments from the command line
    args = []
    for i in range(2,len(sys.argv)):
        print sys.argv[i]
        args.append(float(sys.argv[i]))


    with open(filename, "r") as in_file:
        for line in in_file:
            print line.strip()
            out_dir = line.split()[0]
            data_file = line.split()[1]

            es = get_stats(out_dir, data_file)

            epochs.extend(es)


    for e in epochs: 
        e.estimate_dift(211,.08,.000058)
        e.estimate_ff(2.5)

    epochs.sort(key = lambda x: x.recv_mean_diff)
    miss = []
    dift = []
    edift = []

    expected = []
    actual = []

    for e in epochs:

#        miss.append(math.fabs(e.mdift))
        miss.append(e.mdift + e.mftime)
        dift.append(e.dift)
        edift.append(e.edift)


        expected.append(e.eftime + e.edift)
        actual.append(e.recv)
        

        enoninst_term = (e.utime * 211) + (e.pin_nmerges * .000058)
        einst_term = e.pin_insts * .08

        inst_term = e.instructions * .08
        noninst_term = e.recv - inst_term

        inst_str = "i: " + str(einst_term - inst_term)
        noninst_str = "ni: " + str(enoninst_term - noninst_term)
        

        print e, e.recv_mean_diff,"\t", e.dift, "\t", (e.mdift + e.mftime), "\t",inst_str, "\t",noninst_str,"\t"


    print
    print "mispredict mean:",np.mean(miss),"std:",np.std(miss)
    print "expected",np.mean(expected), "std:",np.std(expected)
    print "actual",np.mean(actual),"std:",np.std(actual)



    

main()

 
