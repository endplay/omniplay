#!/usr/bin/python

import sys
import glob
import os

epoch_start_time = {}
epoch_dift_time = {}
epoch_dump_pid = {}
epoch_dump_time = {}
epoch_map_time = {}
epoch_end_time = {}
epoch_merge_time = {}
epoch_pid = {}
max_epochno = 0

fd = open(sys.argv[1], "r")
for line in fd:
    tokens = line.strip().split()
    if line[:12] == "\tStart time:":
        (sec, usec) = tokens[2].split(".")
        start_time = float(sec) + float(usec)/1000000.0
    if line[:16] == "\tTool done time:":
        (sec, usec) = tokens[3].split(".")
        tool_done_time = float(sec) + float(usec)/1000000.0
    if line[:10] == "\tEnd time:":
        (sec, usec) = tokens[2].split(".")
        end_time = float(sec) + float(usec)/1000000.0
    if line[:5] == "Epoch":
        epochno = int(line.split(" ")[1].split(":")[0])
        if epochno+1 > max_epochno:
            max_epochno = epochno+1
    if line[:18] == "\tEpoch start time:":
        (sec, usec) = tokens[3].split(".")
        epoch_start_time[epochno] = float(sec) + float(usec)/1000000.0
    if line[:17] == "\tDIFT start time:":
        (sec, usec) = tokens[3].split(".")
        epoch_dift_time[epochno] = float(sec) + float(usec)/1000000.0
    if line[:16] == "\tMap start time:":
        (sec, usec) = tokens[3].split(".")
        epoch_map_time[epochno] = float(sec) + float(usec)/1000000.0
    if line[:16] == "\tEpoch end time:":
        (sec, usec) = tokens[3].split(".")
        epoch_end_time[epochno] = float(sec) + float(usec)/1000000.0
    if line[:5] == "\tPid:":
        pid = int(tokens[1])
        epoch_pid[epochno] = pid
        if pid in epoch_dump_pid:
            epoch_dump_time[epochno] = epoch_dump_pid[pid]
    if line[:10] == "dump start":
        dirno = int(tokens[3].split("/")[2])
        sec = int(tokens[4])
        usec = int(tokens[6]) 
        epoch_dump_pid[dirno] = float(sec) + float(usec)/1000000.0
    if line[:6] == "Merge ":
        epoch1 = int(tokens[1])
        epoch2 = int(tokens[2])
        (sec, usec) = tokens[4].split(".")
        if (epoch1,epoch2) in epoch_merge_time:
            epoch_merge_time[(epoch1,epoch2)] += (float(sec) + float(usec)/1000000.0)
        else:
            epoch_merge_time[(epoch1,epoch2)] = 0.0-(float(sec) + float(usec)/1000000.0)

            
total_ff_time = 0.0
total_dift_time = 0.0
total_dump_time = 0.0
total_map_time = 0.0

ff_time = {}
dift_time = {}
dump_time = {}
map_time = {}
total_level = {}
epoch_time = {}
max_epoch_time = 0.0
max_epoch = 0

print "Run time: %6.2f"%(end_time - start_time)       
merge_time = end_time - tool_done_time
print
print "Epoch Launch     FF   DIFT   Dump    Map  Merge   Total"
for i in range(max_epochno):
    ff_time[i] = epoch_dift_time[i]-epoch_start_time[i]
    total_ff_time += ff_time[i]
    if i in epoch_dump_time:
        dift_time[i] = epoch_dump_time[i]-epoch_dift_time[i]
        total_dift_time += dift_time[i]
        dump_time[i] = epoch_map_time[i]-epoch_dump_time[i]
        total_dump_time += dump_time[i]
    else:
        dift_time[i] = epoch_map_time[i]-epoch_dift_time[i]
        dump_time[i] = 0
    map_time[i] = epoch_end_time[i]-epoch_map_time[i]
    total_map_time += map_time[i]
    epoch_time[i] = ff_time[i] + dift_time[i] + dump_time[i] + map_time[i]
    if epoch_time[i] > max_epoch_time:
        max_epoch_time = epoch_time[i]
        max_epoch = i
    print "%5d %6.2f %6.2f %6.2f %6.2f %6.2f"%(i, epoch_start_time[i]-start_time, ff_time[i], dift_time[i], dump_time[i], map_time[i]),
    mlevel = 2
    while mlevel <= max_epochno:
        if (i,i+mlevel-1) in epoch_merge_time:
            print "%6.2f"%(epoch_merge_time[(i,i+mlevel-1)]),
            if mlevel in total_level:
                total_level[mlevel] = total_level[mlevel] + epoch_merge_time[(i,i+mlevel-1)]
            else:
                total_level[mlevel] = epoch_merge_time[(i,i+mlevel-1)]
        else:            
            print "      ",
        mlevel = mlevel * 2
    print


print "             %6.2f %6.2f %6.2f %6.2f"%(total_ff_time, total_dift_time, total_dump_time, total_map_time),
total_time = total_ff_time + total_dift_time + total_dump_time + total_map_time 
mlevel = 2
while mlevel <= max_epochno:
    print "%6.2f"%(total_level[mlevel]),
    total_time += total_level[mlevel]
    mlevel = mlevel * 2
print "%7.2f"%(total_time)

bottleneck = {}
for i in range(max_epochno):
    bottleneck[i] = i

mlevel = 2
while mlevel <= max_epochno:
    for i in range(max_epochno):
        if (i,i+mlevel-1) in epoch_merge_time:
            if epoch_time[i] > epoch_time[i+mlevel/2]:
                epoch_time[i] = epoch_time[i] + epoch_merge_time[(i,i+mlevel-1)]
            else:
                epoch_time[i] = epoch_time[i+mlevel/2] + epoch_merge_time[(i,i+mlevel-1)] 
                bottleneck[i] = bottleneck[i+mlevel/2];
            #print "finish time for %d level %d is %6.2f"%(i, mlevel, epoch_time[i])
    mlevel *= 2

print
print
print "Longest epoch %6.2f (%d)"%(max_epoch_time, max_epoch)
print "Total time    %6.2f (%d)"%(epoch_time[0], bottleneck[0])

print
print

total_time = 0
read_addr_time = 0
do_outputs_time = 0
write_addr_time = 0
write_output_time = 0
passthru_time = 0
first_addr_size = 0
second_output_size = 0
second_addr_size = 0
for i in range(max_epochno):
    for name in glob.glob("/tmp/" + str(epoch_pid[i]) + "/*-stats"):
        fh = open(name)
        for line in fh:
            if line[:11] == "Total time:":
                total_time += int(line.split()[2])
            if line[:15] == "Read addr time:":
                read_addr_time += int(line.split()[3])
            if line[:16] == "Do outputs time:":
                do_outputs_time += int(line.split()[3])
            if line[:19] == "\tWrite output time:":
                write_output_time += int(line.split()[3])
            if line[:16] == "Write addr time:":
                write_addr_time += int(line.split()[3])
            if line[:19] == "\tPass through time:":
                passthru_time += int(line.split()[3])
            if line[:16] == "First addr size:":
                tokens = line.split(",")
                first_addr_size += int(tokens[0].split()[3])
                second_output_size += int(tokens[1].split()[3])
                second_addr_size += int(tokens[2].split()[3])
        fh.close()

print "Total time:      %7d"%(total_time)
print "Read addr time:  %7d"%(read_addr_time)
print "Do outputs time: %7d"%(do_outputs_time)
print "\tWrite output time:%7d"%(write_output_time)
print "Write addr time: %7d"%(write_addr_time)
print "\tPassthru time:%7d"%(passthru_time)
print "First addr size: %7dM"%(first_addr_size/1000000)
print "Second outp size:%7dM"%(second_output_size/1000000)
print "Second addr size:%7dM"%(second_addr_size/1000000)

if (len(sys.argv) == 3):
    #cmd = "../dift/obj-ia32/outcmp " + sys.argv[2] + " 0" 
    #for i in range(max_epochno):
    #    cmd += " " + str(epoch_pid[i])
    #os.system(cmd)

    cmd = "../dift/obj-ia32/out2mergecmp " + sys.argv[2]
    for i in range(max_epochno):
        cmd += " " + str(epoch_pid[i])
    os.system(cmd)

