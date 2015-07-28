#!/usr/bin/python

import sys

epoch_start_time = {}
epoch_dift_time = {}
epoch_dump_pid = {}
epoch_dump_time = {}
epoch_map_time = {}
epoch_end_time = {}
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
        if pid in epoch_dump_pid:
            epoch_dump_time[epochno] = epoch_dump_pid[pid]
    if line[:10] == "dump start":
        dirno = int(tokens[3].split("/")[2])
        sec = int(tokens[4])
        usec = int(tokens[6]) 
        epoch_dump_pid[dirno] = float(sec) + float(usec)/1000000.0
            
total_ff_time = 0.0
total_dift_time = 0.0
total_dump_time = 0.0
total_map_time = 0.0

ff_time = {}
dift_time = {}
dump_time = {}
map_time = {}
max_epoch_time = 0

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
    epoch_time = ff_time[i] + dift_time[i] + dump_time[i] + map_time[i]
    if epoch_time > max_epoch_time:
        max_epoch_time = epoch_time
    print "%5d %6.2f %6.2f %6.2f %6.2f %6.2f"%(i, epoch_start_time[i]-start_time, ff_time[i], dift_time[i], dump_time[i], map_time[i])

print "             %6.2f %6.2f %6.2f %6.2f %6.2f %7.2f"%(total_ff_time, total_dift_time, total_dump_time, total_map_time, merge_time, 
                                                          total_ff_time + total_dift_time + total_dump_time + total_map_time + merge_time)

print
print
print "Longest epoch %6.2f"%(max_epoch_time)
print "Total time    %6.2f"%(max_epoch_time+merge_time)

