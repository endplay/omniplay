#!/usr/bin/python

import sys

epoch_start_time = {}
epoch_dift_time = {}
epoch_done_waiting_time = {}
epoch_waiting_time = {}
epoch_splice_time = {}
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
    if line[:19] == "\tSplice start time:":
        (sec, usec) = tokens[3].split(".")
        epoch_splice_time[epochno] = float(sec) + float(usec)/1000000.0
    if line[:16] == "\tMap start time:":
        (sec, usec) = tokens[3].split(".")
        epoch_map_time[epochno] = float(sec) + float(usec)/1000000.0
    if line[:16] == "\tEpoch end time:":
        (sec, usec) = tokens[3].split(".")
        epoch_end_time[epochno] = float(sec) + float(usec)/1000000.0
    if line[:10] == "Waiting on":
        epoch = int(tokens[3].split(".")[1])
        (sec, usec) = tokens[5].split(".")
        epoch_waiting_time[epoch-1] = float(sec) + float(usec)/1000000.0
    if line[:12] == "Done waiting":
        epoch = int(tokens[4].split(".")[1])
        (sec, usec) = tokens[6].split(".")
        epoch_done_waiting_time[epoch-1] = float(sec) + float(usec)/1000000.0

total_ff_time = 0.0
total_dift_time = 0.0
total_write_time = 0.0
total_splice_time = 0.0
total_map_time = 0.0

ff_time = {}
dift_time = {}
write_time = {}
splice_time = {}
map_time = {}

print "Run time: %6.2f"%(end_time - start_time)       
merge_time = end_time - tool_done_time
print
print "Epoch Launch     FF   DIFT   Wait Write Splice   Map  Merge   Total"
for i in range(max_epochno):
    if i == max_epochno-1:
        ff_time[i] = epoch_dift_time[i]-epoch_start_time[i]
        total_ff_time += ff_time[i]
        dift_time[i] = epoch_splice_time[i]-epoch_dift_time[i]
        total_dift_time += dift_time[i]
        splice_time[i] = epoch_map_time[i]-epoch_splice_time[i]
        total_splice_time += splice_time[i]
        map_time[i] = epoch_end_time[i]-epoch_map_time[i]
        total_map_time += map_time[i]
        print "%5d %6.2f %6.2f %6.2f ------ ------ %6.2f %6.2f"%(i, epoch_start_time[i]-start_time, ff_time[i], dift_time[i],
                                                                 splice_time[i], map_time[i])
    elif i == 0:
        ff_time[i] = epoch_dift_time[i]-epoch_start_time[i]
        total_ff_time += ff_time[i]
        dift_time[i] = epoch_waiting_time[i]-epoch_dift_time[i]
        total_dift_time += dift_time[i]
        write_time[i] = epoch_map_time[i]-epoch_done_waiting_time[i] 
        total_write_time += write_time[i]
        map_time[i] = epoch_end_time[i]-epoch_map_time[i]
        total_map_time += map_time[i]
        print "%5d %6.2f %6.2f %6.2f %6.2f %6.2f ------ %6.2f"%(i, epoch_start_time[i]-start_time, ff_time[i],
                                                                dift_time[i], epoch_done_waiting_time[i]-epoch_waiting_time[i],
                                                                write_time[i], map_time[i])
    else:
        ff_time[i] = epoch_dift_time[i]-epoch_start_time[i]
        total_ff_time += ff_time[i]
        dift_time[i] = epoch_waiting_time[i]-epoch_dift_time[i]
        total_dift_time += dift_time[i]
        write_time[i] = epoch_splice_time[i]-epoch_done_waiting_time[i] 
        total_write_time += write_time[i]
        splice_time[i] = epoch_map_time[i]-epoch_splice_time[i]
        total_splice_time += splice_time[i]
        map_time[i] = epoch_end_time[i]-epoch_map_time[i]
        total_map_time += map_time[i]
        print "%5d %6.2f %6.2f %6.2f %6.2f %6.2f %6.2f %6.2f"%(i, epoch_start_time[i]-start_time, ff_time[i],
                                                               dift_time[i], epoch_done_waiting_time[i]-epoch_waiting_time[i],
                                                               write_time[i], splice_time[i], map_time[i])

print "             %6.2f %6.2f        %6.2f %6.2f %6.2f %6.2f %6.2f %7.2f"%(total_ff_time, total_dift_time, total_write_time, total_splice_time, 
                                                                       total_map_time, merge_time, 
                                                                       total_ff_time + total_dift_time + total_write_time, total_splice_time + total_map_time + merge_time)

print
print
print

dift_end = {}
splice_end = {}
map_end = {}
max_map_end = 0
for i in range(max_epochno):
    dift_end[i] = ff_time[i] + dift_time[i]

splice_end[max_epochno-1] = dift_end[max_epochno-1] + splice_time[max_epochno-1]
splice_time[0] = 0
for i in reversed(range(max_epochno-1)):
    if dift_end[i] > splice_end[i+1]:
        splice_end[i] = dift_end[i] + write_time[i] + splice_time[i] 
    else:
        splice_end[i] = splice_end[i+1] + write_time[i] + splice_time[i]

for i in range(max_epochno):
    map_end[i] = splice_end[i] + map_time[i]
    if map_end[i] > max_map_end:
        max_map_end = map_end[i]

merge_end = max_map_end + merge_time

for i in range(max_epochno):
    print "%5d %6.2f %6.2f %6.2f"%(i, dift_end[i], splice_end[i], map_end[i])
print "Merge                      %6.2f"%(merge_end);                       
