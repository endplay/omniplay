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

HEADINGS = ["utime","uinsts"]


def get_stats(input_dir, data_file):
    dift = []
    utime = []
    taint_in = []
    taint_out = []
    uinsts = []
    ainsts = []
    imisses = []
    instructions = []
    traces = []
    instrument = []
    num_merges = []
    num_saved = []

    with open(data_file, "r") as df:         
        for line in df: 
            words = line.split()
            utime.append(float(words[2]))
            taint_in.append(float(words[3]))
            taint_out.append(float(words[4]))
            uinsts.append(float(words[5]))
            ainsts.append(float(words[6]))
            imisses.append(float(words[7]))


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

                if line[:len("Instrument time")] == "Instrument time":
                    instrument.append(float(line.split()[2]))

                if line[:len("Num merges")] == "Num merges" and "saved" not in line:
                    num_merges.append(float(line.split()[2]))
                if line[:len("Num merges")] == "Num merges" and "saved" in line:
                    num_saved.append(float(line.split()[3]))

    ratio = []
    for i in range(len(uinsts)): 
        if ainsts[i] >0:
            ratio.append((uinsts[i] / ainsts[i]))
        else:
            ratio.append(0)

    imrat = [(imisses[i] * ratio[i]) for i in range(len(ratio))]


    return [utime, uinsts], dift
#    return [uinsts], instructions

def linear_regression(cx, cy): 

    np_y = np.array(cy)            
    mean_y = sum(np_y) / len(np_y)
    SS_tot = sum([(i - float(mean_y))**2 for i in np_y]) + 0.0

    
    np_x = np.vstack([cx, np.ones(len(cx[0]))]).T
    output = np.linalg.lstsq(np_x,np_y)
    return (1 - output[1][0] / SS_tot), output

def calc_r2(cx,cy,model):

    np_y = np.array(cy)
    np_x = np.array(cx).T

    aprx = []
    print len(np_x), len(cy)
    for xvals in np_x:
        val = 0
        for x,m in zip(xvals,model):
            val += (x * m)
        aprx.append(val)

    for y,fy in zip(cy,aprx):
        print y,fy

    SS_res = sum([(y - fy)**2 for y,fy in zip(cy,aprx)])

    mean_y = sum(np_y) / len(np_y)
    SS_tot = sum([(i - float(mean_y))**2 for i in np_y]) + 0.0

    print 1 - (SS_res / SS_tot)

def main(): 

    filename = sys.argv[1]
    model = []
    for i in range(2,len(sys.argv)):
        model.append(float(sys.argv[i]))
    
    x = []
    for i in HEADINGS:
        x.append([])
    y = []

    with open(filename, "r") as in_file:
        for line in in_file:
            print line
            out_dir = line.split()[0]
            data_file = line.split()[1]

            xx,yy = get_stats(out_dir, data_file)

            for i in range(len(xx)):
                x[i].extend(xx[i])
            y.extend(yy) 
                    
    
    for i in range(0,len(HEADINGS)):
        print  "+",model[i],HEADINGS[i],


    calc_r2(x,y,model)
#    val, output = linear_regression(x,y)




main()

