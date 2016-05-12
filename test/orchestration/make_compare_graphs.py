#!/usr/bin/python

import sys
import os
import copy
import test_results
import graph_utilities

class epoch_data:
    def __init__(self, epochs = 0, mean = 0, ci = 0):
        self.nume = epochs
        self.sample = test_results.Sample()
        self.sample.mean = mean
        self.sample.ci   = ci

    def __str__(self):
        return "nume " + str(self.nume) + " sample " + str(self.sample)

def get_times(filename):
    edata = []
    with open(filename) as ofile:
        for line in ofile:
            words = line.split(",")
            edata.append(epoch_data(int(words[0]), float(words[1]), float(words[2])))
        
    return edata


def get_opt_data(ed): 
    print "opt data"
    opt_data = []
    for e in ed:
        print e
        if e.nume == 128: 
            opt_data.append(e)

    return opt_data
            

def convert_data(d_samples): 

    labels = []
    ticks = []
    data = []
    err  = []

    s =  sorted(d_samples.items())

    for l,d in s:
        labels.append(l)
        cdata = []    
        cerr = []
        cticks = []
        for ed in d:
            cdata.append(ed.sample.mean)
            cerr.append(ed.sample.ci)
            if ed.nume > 0:
                cticks.append(ed.nume)
            
        if len(cticks) > len(ticks):
            ticks = copy.deepcopy(cticks)
        data.append(cdata)
        err.append(cerr)

        
    return labels,ticks,data,err


def normalize(data, norm_against): 

    norm_data = {}
    for k in data:
        edata = []
        for ed in data[k]:
            e = epoch_data(ed.nume)
            e.sample = ed.sample
            e.sample /= norm_against
            edata.append(e)
        norm_data[k] = edata
            

    return norm_data

def main(): 

    comp_samples = {}
    opt_latency = {}

    d = sys.argv[1]
    
    files = os.listdir(d)
    for f in files:
        name = f
        if os.path.isdir(d + "/" + f):
            edata = get_times(d + "/" + f + "/compute.stats")
            comp_samples[name] = copy.deepcopy(edata)            

            edata = get_times(d + "/" + f + "/aggregate.stats")
            big_querry = get_opt_data(edata)
            if big_querry != []:
                opt_latency[name] = get_opt_data(edata)

    print "compute stats"
    for c in comp_samples:
        print c
        for i in comp_samples[c]:
            print i
        print
    
    print "optimizations stats"
    for t in opt_latency:
        print t
        for i in opt_latency[t]:
            print i
        print



    one_epoch = comp_samples["one_epoch"]

    del comp_samples["one_epoch"]
    norm_comp_samples = normalize(comp_samples, one_epoch[0].sample)

    max_comp_size = 0
    for k in norm_comp_samples:
        if len(norm_comp_samples[k]) > max_comp_size:
            max_comp_size = len(norm_comp_samples[k])

    for k in norm_comp_samples:
        while len(norm_comp_samples[k]) < max_comp_size:
            norm_comp_samples[k].insert(0,epoch_data())  


    
    labels, ticks,data, err= convert_data(opt_latency)
#    for l,x,e in zip(labels,data,err):
#        print l,x,e
    print ticks
            
    graph_utilities.make_bar_chart(data, err, labels, ticks,d +"/optimization_comparisons",17,xaxis="Number of Epochs",yaxis="Query Time (ms)")

    labels, ticks,data, err= convert_data(norm_comp_samples)
#    for l,d,e in zip(labels,data,err):
#        print l,d,e
            
    print ticks
    graph_utilities.make_bar_chart(data, err, labels, ticks,d+"/compute_time",18)



main()
