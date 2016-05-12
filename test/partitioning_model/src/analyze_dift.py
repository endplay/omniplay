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

#HEADINGS = ["utime","Inst_Instrumented"]
#HEADINGS = ["pin_nmerges"]
#HEADINGS = ["utime","uinsts"]
#HEADINGS = ["utime","pin_insts", "nm_all"]
HEADINGS = ["uinsts","pin_insts"]
#HEADINGS = ["ctime"]

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

    with open(data_file, "r") as df:         
        for line in df: 
            words = line.split()
            utime.append(float(words[2]))
            ctime.append(float(words[3]))
            taint_in.append(float(words[4]))
            taint_out.append(float(words[5]))
            uinsts.append(float(words[6]))
            imisses.append(float(words[7]))
            pin_insts.append(float(words[8]))
            if len(words) > 9:
                pin_traces.append(float(words[-3]))
            if len(words) > 10:
                pin_nmerges.append(float(words[-2]))
#                pin_nsaved.append(float(words[-1]))

    num_epochs = int(data_file.split(".")[-2])
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


#    for m,s in zip(num_merges,num_saved):
#        nm_all.append(m+s)
    
 


#    return [ctime], ftime
#    return [pin_nmerges], num_merges
#    return [pin_traces], traces
#    return [utime, uinsts], dift
    return [utime,pin_insts], dift
#    return [pin_insts], instructions

def linear_regression(cx, cy): 

    np_y = np.array(cy)            
    mean_y = sum(np_y) / len(np_y)
    SS_tot = sum([(i - float(mean_y))**2 for i in np_y]) + 0.0

    
    np_x = np.vstack([cx, np.ones(len(cx[0]))]).T
    output = np.linalg.lstsq(np_x,np_y)
    return (1 - output[1][0] / SS_tot), output


def user_input_lr(args, xdata, ydata):
    


    np_y = np.array(ydata)
    np_x = np.array(xdata).T
    mean_y = np.mean(np_y)
    SS_tot = sum([(i - float(mean_y))**2 for i in ydata]) + 0.0

    print np_x

    yguess = []
    for xpoint in np_x:
        cy = 0
        for a,xv in zip(args,xpoint):
            cy += a * xv
            print xv,

        print cy
        yguess.append(cy)

        
    SS_res = sum([(y - yg)**2 for y,yg in zip(ydata,yguess)])
    
    print "user_input_lr",1 - (SS_res / SS_tot)

def main(): 


    filename = sys.argv[1]
    x = []
    for i in HEADINGS:
        x.append([])
    y = []

    args = []
    for i in range(2,len(sys.argv)):
        print sys.argv[i]
        args.append(float(sys.argv[i]))


    with open(filename, "r") as in_file:
        for line in in_file:
            print line
            out_dir = line.split()[0]
            data_file = line.split()[1]

            xx,yy = get_stats(out_dir, data_file)

            for i in range(len(xx)):
                x[i].extend(xx[i])
            y.extend(yy)     


    user_input_lr(args, x, y)        
    val, output = linear_regression(x,y)

    print "R^2 =",val
    print "model =",output[0][0],HEADINGS[0],
    
    for i in range(1,len(HEADINGS)):
        print  "+",output[0][i],HEADINGS[i],
    print ""



main()

