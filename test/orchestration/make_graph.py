#!/usr/bin/python

import matplotlib.pyplot as plt
import numpy as np
import sys
import optparse
import os
import subprocess

import test_results
import stats
import graph_utilities

def calc_sums(epochs):
    sum_list = []
    sum_list.append(epochs[0][1]) #num_epochs
    sum_list.append(epochs[0][1]) #epoch_number

    #each of the values
    for i in range(2, len(epochs[0])): 
        sum = 0
        #each of the items
        for index in range(len(epochs)):
            sum += epochs[index][i]
        sum_list.append(sum)
        
    return sum_list

def get_stats_type(data, index):


    means = []
    stddevs = []
    curr_epochs_values = []

    curr_num_epochs = -1

    for epoch in data:
        if epoch[1] != curr_num_epochs:
            curr_num_epochs = epoch[1]

            if curr_num_epochs != 1:
                means.append(np.mean(np.array(curr_epochs_values)))
                stddevs.append(np.std(np.array(curr_epochs_values)))

                del curr_epochs_values[:]

        curr_epochs_values.append(float(epoch[index]))
            
 
    means.append(np.mean(np.array(curr_epochs_values)))
    stddevs.append(np.std(np.array(curr_epochs_values)))
   
    return means, stddevs

    

def get_results_list(input_dir):
    files = os.listdir(input_dir)
    sorted_files = sorted(files, key=lambda x: (int(x.split('.')[0]), int(x.split('stats-')[-1]), x.split('.')[-1]))

    time_list = []
    curr_list = []

    curr_total = []
    curr_compute = []
    curr_aggregation = []

    total_list = []    
    compute_list = []    
    aggregation_list = []


    max_list = []
    epochs_list = []
    curr_num_epochs = -1

    headings = []


    for f in sorted_files:
        if "stream-stats" in f:
            continue
        num_epochs = int(f.split('.')[0])
        if num_epochs != curr_num_epochs:
            if len(curr_list) > 0:
                time_list.append(curr_list)
                max_list.append(curr_list[0])
                epochs_list.append(curr_num_epochs)
                total_list.append(curr_total) #add in a new empty list
                compute_list.append(curr_compute)
                aggregation_list.append(curr_aggregation)
                curr_list = []
                curr_total = []
                curr_compute = []
                curr_aggregation = []

            curr_num_epochs = num_epochs

        test = test_results.Test_Results()
        string = open(input_dir + "/" + f).readlines()            
        test.parse_lines(string)
        
        num = f.split(".")[-1][len("taint-stats-"):]
        stream_name = f.split(".")[:-1] 
        stream_name.append("stream-stats-" + str(num))
        stream_filename = ".".join(stream_name)        
        string = open(input_dir + "/" + stream_filename).readlines()            
        test.parse_lines(string)


        test.fix_dift_stats()
        test.combine_stats() 
        curr_list.append(test.get_values())
        curr_total.append(test.get_total_time())
        curr_compute.append(test.get_compute_time())
        curr_aggregation.append(test.get_aggregation_time())
#        test.print_compute_times()
        if test.get_compute_time() < 0:
            print "whoops 1, negative compute time!?!",f
            test.print_compute_times()

        headings = test.get_titles()
    

    time_list.append(curr_list)
    max_list.append(curr_list[0])
    epochs_list.append(curr_num_epochs)
    total_list.append(curr_total)
    compute_list.append(curr_compute)
    aggregation_list.append(curr_aggregation)
    if test.get_compute_time() < 0:
        print "whoops, negative compute time!?!",f
        print test.print_compute_times()
        

    return headings, epochs_list,time_list, max_list, total_list, compute_list, aggregation_list


def parse_stats(input_dir,output_dir): 
    
    currd = os.getcwd()

    for t in os.listdir(input_dir): 
        d = output_dir + "/" + t
        subprocess.call(["/bin/cp", "-r",input_dir + "/" + t, d])
    
    for d in os.listdir(output_dir):
        os.chdir(output_dir + "/" + d)

        #untar all of the tars, move them all to their final resting place
        for tar in os.listdir("."):
            print tar

            num_epochs = tar.split(".")[0] #the num_epochs is the first value            
            subprocess.call(["/bin/tar","-xf", tar])
            subprocess.call(["/bin/rm",tar])

            for stats_file in os.listdir("tmp"):                
                subprocess.call(["/bin/mv", "tmp/" + stats_file, str(num_epochs) + "." + stats_file])

            subprocess.call(["/bin/rm","-r","tmp"])
        os.chdir(currd)
    os.chdir(currd)

def create_stats_files(input_dir, nepochs, output_dir): 
    
    in_base = input_dir + "/" + str(nepochs) + "."

    with open(output_dir + str(nepochs) + ".stats.txt", "w+") as outf:
        stats.get_stats(nepochs, in_base, outf) 


def get_aves(at):

    averages = [] #array index by num_epochs -> array of aves
    for n in at:
        count = len(n) #number of epochs
        averages.append([])
        for i in range(len(n[0])):
            averages[-1].append(0.0)
#        print "num_epochs",count,"num_stats",len(averages[-1])

        for example in n:
            for i in range(len(example)):
                averages[-1][i] += example[i]
        for i in range(len(averages[-1])):
            averages[-1][i] /= count;


    return averages


def get_tots(at):
    tots = [] #array index by num_epochs -> array of aves
    for n in at:
        count = len(n) #number of epochs
        tots.append([])
        for i in range(len(n[0])):
            tots[-1].append(0.0)
        print "num_epochs",count,"num_stats",len(tots[-1])

        for example in n:
            for i in range(len(example)):
                tots[-1][i] += example[i]


    return tots


def get_maxes(t):

    tots = [] #array index by num_epochs -> array of tots
    for n in t:
        tots.append(n[0]) #the first epoch is always the max

    return tots


def get_sum(t):
    sums = []
    for n in t: #array indexed by num_epochs -> array of sums of compute time
        sum = 0
        for example in n:
            sum += example

        sums.append([sum])
    return sums


def print_aves(aves):
    for r in aves:
        print "next round!"
        for n in r:
            for i in n:
                print i,
            print ""
    

def build_samples(aves, es): 
    
    samples = [] #array from num_epochs -> sample
    print "in build_samples"
    epochs = {}
    print len(aves), len(es)

    for a,e in zip(aves,es): #for each epoch size
        print "epoch",e,a,"\t"

        for epoch,epoch_size in zip(a,e):
            if epoch_size in epochs:
                epochs[epoch_size].append(epoch)
            else:
                epochs[epoch_size] = [epoch]
        print 

    
    for eps in sorted(epochs.keys()):
        print "found",eps,"epochs",epochs[eps]
        npl = np.array(epochs[eps])
        s = test_results.Sample(len(epochs[eps]), np.mean(npl), np.std(npl))
        samples.append(s)

    for s in samples:
        print s

    return samples

def normalize_speedup_and_flip(samples, epochs):
    
    if epochs[0] != 1 or len(epochs) == 1:
        normal = samples[0] #we always normalize against the first size
    else: 
        normal = samples[1]
    ydata = []
    yerr = []

    for i in range(len(normal)):
        cdata = []
        cerr = []

        for s in samples:            
            d = normal[i] / s[i] #normalize this value
            #our measurements can't handle 0 time averages.. not sure what to do:
            if d.mean == 0.0:
                print "oh no.. what do I do when it takes 0 seconds?"
                cdata.append(1.0)
                cerr.append(0.0)
            else:                
                cdata.append(d.mean)
                cerr.append(d.ci)

        ydata.append(cdata)
        yerr.append(cerr)

    return ydata, yerr


def normalize(samples, nsample):
    
    rsamples = []
    for s in samples:            
        d = nsample / s #normalize this value
        rsamples.append(d)

    return rsamples



def normalize_time_and_flip(samples, epochs):

    if epochs[0] != 1 or len(epochs) == 1:
        normal = samples[0] #we always normalize against the first size
    else: 
        normal = samples[1]

    ydata = []
    yerr = []

    for i in range(len(normal)):
        cdata = []
        cerr = []

        for s in samples:            
            d = s[i] / normal[i] #normalize this value

            #our measurements can't handle 0 time averages.. not sure what to do:
            if d.mean == 0.0:
                print "oh no.. what do I do when it takes 0 seconds?"
                cdata.append(1.0)
                cerr.append(0.0)
            else:                
                cdata.append(d.mean)
                cerr.append(d.ci)

        ydata.append(cdata)
        yerr.append(cerr)


    return ydata, yerr

def parse_replay_time(f, odir):
    subprocess.call(["/bin/cp",f,odir+"/replay_time"])

def build_replay_time(d):
    rp_times = []
    with open(d + "/replay_time") as ifile:
        for w in ifile:
            print w
            rp_times.append(float(w.strip()))


    nprt = np.array(rp_times)
    return test_results.Sample(len(rp_times), np.mean(nprt),np.std(nprt))



def main(): 
    parser = optparse.OptionParser()
    parser.add_option("-i", "--input-dir", dest="input_dir",
                      help="where the stats files are saved currently", metavar="INPUT-DIR")
    parser.add_option("-o", "--output-dir", dest="output_dir",
                      help="the dir where we want to save the output files", metavar="OUTPUT-Dir")
    parser.add_option("-r", "--replay_time", dest="replay_time_file")
    parser.add_option("-n", "--bm_name", dest="bm_name")

    (options, args) = parser.parse_args()
    if options.output_dir == None or options.output_dir == "":
        print "must provide me with an output dir"
        return -1
    

    if not os.path.isdir(options.output_dir):
        os.makedirs(options.output_dir)
    if not os.path.isdir(options.output_dir + "/graphs_and_stats"):
        os.makedirs(options.output_dir + "/graphs_and_stats")


    #untar all of the stuff from the input_dir
    if options.input_dir != None and options.input_dir != "":
        parse_stats(options.input_dir,options.output_dir)
        print "parsing input stats...?"

    if options.replay_time_file:
        parse_replay_time(options.replay_time_file, options.output_dir)


    ave_times = []
    max_times = []
    tot_times = []
    comp_times = []
    agg_times = []
    max_e = []
    dift_times = []
    epoch_times = []
    files = os.listdir(options.output_dir)
    for j in files:
        if not os.path.isdir(options.output_dir + "/" + str(j)) or "graph" in j:
            continue
        print j
        

        headings,epochs,times,max_list, total_list,compute_list,agg_list = get_results_list(options.output_dir + "/" + str(j))
        if len(epochs) > len(max_e):
            max_e = epochs



        for i in range(len(times)):
            curr_times = times[i]
            num_epochs = epochs[i]
            curr_arange = np.arange(len(curr_times))
            graph_utilities.make_stacked_chart(curr_times,headings,curr_arange,options.output_dir +"/graphs_and_stats/"+ str(j) + "." + str(num_epochs), i * (int(j)+1))
            create_stats_files(options.output_dir + "/" + str(j), num_epochs, options.output_dir + "/graphs_and_stats/" + str(j) + ".")        



        ttimes = get_tots(times)
        dt = []
        for t in ttimes:
            dt.append(t[1] + t[2])



        dift_times.append(dt)            
        epoch_times.append(epochs)
        ave_times.append(get_aves(times))
        tot_times.append(get_tots(times))
        max_times.append(get_maxes(total_list)) 
        comp_times.append(get_sum(compute_list))
        agg_times.append(get_maxes(agg_list))  #do I want the max? I'm acutally not sure..


    print "dift_stats"
    samples = build_samples(dift_times, epoch_times)
    with open(options.output_dir + "/dift.stats","w+") as stat_file:
        for num,s in zip(max_e,samples):
            print >> stat_file, num,",",s.mean,",",s.ci
#            print num,",",s.mean,",",s.ci


    print "latency_stats"
    samples = build_samples(max_times, epoch_times)
    #we'll normalize the samples if we can
    if max_e[0] == 1:
        samples = normalize(samples,samples[0])
        

    data = []
    errs = []
    es = []
    cur_val = 1
    with open(options.output_dir + "/latency.stats","w+") as stat_file:
        for num,s in zip(max_e,samples):
            print >> stat_file, num,",",s.mean,",",s.ci
            print num,",",s.mean,",",s.ci
            while cur_val != num:
                data.append(0)
                errs.append(0)
                es.append(cur_val)
                cur_val *=2


#    replay_time = build_replay_time(options.output_dir)    
#    print data
#    print errs
#    print es
#    graph_utilities.make_scale_chart(data, errs,replay_time.mean,replay_time.ci,es,options.output_dir + "/scalability_graph", 19, title=options.bm_name + " Querry Latency", xaxis="Number of Cores",yaxis="Total Time (ms)") #hmm


    print "latency_stats...raw!"
    #output raw latency stats for further processing
    samples = build_samples(max_times, epoch_times)
    with open(options.output_dir + "/latency.raw.stats","w+") as stat_file:
        for num,s in zip(max_e,samples):
            print >> stat_file, num,",",s.mean,",",s.ci
            print num,",",s.mean,",",s.ci



    samples = build_samples(agg_times, epoch_times)
    #we'll normalize the samples if we can
    if max_e[0] == 1:
        samples = normalize(samples,samples[0])

    data = []
    errs = []
    es = []
    cur_val = 1
    with open(options.output_dir + "/aggregation.stats","w+") as stat_file:
        for num,s in zip(max_e,samples):
            print >> stat_file, num,",",s.mean,",",s.ci
            print num,",",s.mean,",",s.ci


    samples = build_samples(agg_times, epoch_times)
    data = []
    errs = []
    es = []
    cur_val = 1
    with open(options.output_dir + "/aggregation.raw.stats","w+") as stat_file:
        for num,s in zip(max_e,samples):
            print >> stat_file, num,",",s.mean,",",s.ci
#            print num,",",s.mean,",",s.ci



#    ydata, yerr = normalize_speedup_and_flip(samples, epochs)
#    for i in range(len(ydata)):
#        print ydata[i],yerr[i]

#    graph_utilities.make_line_chart(epochs,ydata,yerr,["total_time"], options.output_dir + "/max",39, title="Total Time",xaxis="Number of Epochs",yaxis="Normalized Speedup")

#    for i in comp_times:
#        print i

    print "compute_stats...raw!"
    samples = build_samples(comp_times, epoch_times)
    with open(options.output_dir + "/compute.stats","w+") as stat_file:
        for num,s in zip(epochs,samples):
            print >> stat_file, num,",",s.mean,",",s.ci
            print num, ",",s.mean,",",s.ci


#    for s in samples:
#        for a in s:
#            print a

#    ydata, yerr = normalize_time_and_flip(samples, epochs)
#    for i in range(len(ydata)):
#        print ydata[i],yerr[i]

#    graph_utilities.make_line_chart(epochs,ydata,yerr,["compute_time"], options.output_dir + "/compute_time",39, title="Compute Time",xaxis="Number of Epochs",yaxis="Compute Time")





main()
