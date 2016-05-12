#!/usr/bin/python

import sys
sys.path.append("..")

import test_results
import matplotlib.pyplot as plt
import numpy as np

def make_line_chart(xdata, ydata, yerror,labels,filename, fig_number, title = "", xaxis = "", yaxis = ""):
    
    fig = plt.figure(fig_number)

    for xd,yd,ye,l  in zip(xdata,ydata,yerror,labels):
        plt.errorbars(xd,yd,yerr=ye, label = l)



    legend=plt.legend(bbox_to_anchor=(1.0,1.0), loc=0)
    plt.xlabel(xaxis)
    plt.ylabel(yaxis)
    plt.title(title)


    plt.savefig(filename +".pdf", bbox_extra_artists=[legend],bbox_inches='tight',dpi=500)
    plt.close()


def get_sample(vals):
    times = []
    for v in vals[1:]:
        times.append(float(v))
    
    nptimes = np.array(times)
    return test_results.Sample(len(times),np.mean(nptimes), np.std(nptimes))
    
    

def parse_input(benchmark): 
    
    ns = None
    samples = []
    epochs = []
    with open(benchmark, "r") as ofile:

        #start by getting the first epoch retaint time
        line = ofile.readline()
        vals = line.split(",")
        epochs.append(int(vals[0]))
        ns = get_sample(vals[1:])
        samples.append(ns)

        #now do the rest
        for line in ofile:
            vals = line.split(",")
            epochs.append(int(vals[0]))
            samples.append(get_sample(vals[1:]))
                         
        
    assert(ns)
    for s in samples:
        print s
    for i,s in enumerate(samples):
        samples[i] /= ns
    for s in samples:
        print s

    yd = []
    ye = []
    for s in samples:
        yd.append(s.mean)
        ye.append(s.ci)
    return epochs, yd, ye


def main():
    
    benchmarks = sys.argv[1]
    x = []
    y = []
    yerr = []
    labels = []
    with open(benchmarks, "r") as bfile:
        for b in bfile:
            xd,yd,ye = parse_input(b.strip())
            labels.append(b.strip())
            x.append(xd)
            y.append(yd)
            yerr.append(ye)

    make_line_chart(x,y,yerr, labels,"retaint",1, title="Overhead of Re-tainting", xaxis="Number of Epochs", yaxis="Normalized Runtime")

        
        


main()
