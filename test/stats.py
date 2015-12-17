#!/usr/bin/python

import sys

seq = 1

# For timings
dift = []
recv = []
receive = []
output = []
index = []
address = []
idle = []
finish = []
prune = []
make = []
send = []

# For address processing
values = []
passthrus = []
unmodifieds = []
resolveds = []
indirects = []
others = []
merges = []

epochs = int(sys.argv[1])

# Not done in the first epoch
prune.append(0)
receive.append(0)

for i in range(epochs):
    fh = open ("/tmp/taint-stats-" + str(i))
    for line in fh:
        if line[:10] == "DIFT began":
            began = float(line.split()[3])
        if line[:10] == "DIFT ended":
            ended = float(line.split()[3])
            dift.append(int((ended-began)*1000.0))
    fh.close()

for i in range(epochs):
    fh = open ("/tmp/stream-stats-" + str(i))
    for line in fh:
        if line[:13] == "Receive time:":
            recv.append(int(line.split()[2]))
        if line[:23] == "Output processing time:":
            output.append(int(line.split()[3]))
        if line[:22] == "Index generation time:":
            index.append(int(line.split()[3]))
        if line[:24] == "Address processing time:":
            address.append(int(line.split()[3]))
        if line[:12] == "Finish time:":
            finish.append(int(line.split()[2]))
        if line[:24] == "Address processing idle:":
            idle.append(int(line.split()[3]))
            if i != epochs-1:
                address[i] -= idle[i]
        if line[:15] == "Address tokens ":
            values.append(int(line.split()[10]))
            passthrus.append(int(line.split()[4]))
            unmodifieds.append(int(line.split()[12][0:-1]))
            resolveds.append(int(line.split()[6][0:-1]))
            indirects.append(int(line.split()[8]))
            others.append(values[i]-(passthrus[i]+unmodifieds[i]+resolveds[i]+indirects[i]))
            merges.append(int(line.split()[14]))
        if line[:21] == "Receive live set time":
            receive.append(int(line.split()[4]))
        if line[:19] == "Prune live set time":
            prune.append(int(line.split()[4]))
        if line[:18] == "Make live set time":
            make.append(int(line.split()[4]))
        if line[:18] == "Send live set time":
            send.append(int(line.split()[4]))

# Not done in the last epoch
index.append(0)
address.append(0)
idle.append(0)
make.append(0)
send.append(0)

values.append(0)
passthrus.append(0)
unmodifieds.append(0)
resolveds.append(0)
indirects.append(0)
others.append(0)
merges.append(0)

for i in range(epochs):
    recv[i] -= dift[i]

while len(prune) < epochs:
    receive.append(0)
    prune.append(0)
    send.append(0)

if (seq):
    print "Epoch    DIFT     FF   Recv.  Prune   Make   Send Output  Index Address   Idle Finish"
    for i in range(epochs):
        print "%5s %7s %6s %7s %6s %6s %6s %6s %6d %7d %6d %6d"%(i,dift[i],recv[i],receive[i],prune[i],make[i],send[i],output[i],index[i], address[i], idle[i], finish[i])
    print "  Max %7d %6d %7d %6d %6d %6d %6d %6d %7d %6d %6d"%(max(dift),max(recv),max(receive),max(prune),max(make),max(send),max(output),max(index),max(address), max(idle), max(finish))
    print "Total %7d %6d %7d %6d %6d %6d %6d %6d %7d %6d %6d"%(sum(dift),sum(recv),sum(receive),sum(prune),sum(make),sum(send),sum(output),sum(index),sum(address), sum(idle), sum(finish))
    print " Core %7d %6d %7d %6d %6d %6d %6d %6d %7d %6d %6d"%(sum(dift)/epochs,sum(recv)/epochs,sum(receive)/epochs,sum(prune)/epochs,sum(make)/epochs,sum(send)/epochs,sum(output)/epochs,sum(index)/epochs,sum(address)/epochs, sum(idle)/epochs,sum(finish)/epochs)
else:
    print "Epoch   DIFT Output  Index Address   Idle Finish"
    for i in range(epochs):
        print "%5s %6s %6s %6d %7d %6d %6d"%(i,recv[i],output[i],index[i], address[i], idle[i], finish[i])
    print "  Max %6d %6d %6d %7d %6d %6d"%(max(recv),max(output),max(index),max(address), max(idle), max(finish))
    print "Total %6d %6d %6d %7d %6d %6d"%(sum(recv),sum(output),sum(index),sum(address), sum(idle), sum(finish))
    print " Core %6d %6d %6d %7d %6d %6d"%(sum(recv)/epochs,sum(output)/epochs,sum(index)/epochs,sum(address)/epochs, sum(idle)/epochs,sum(finish)/epochs)

print
print
print "Epoch     Values  Passthrus Unmodified  Resolveds  Indirects      Other   (Merges)"
for i in range(epochs):
    print "%5d %10d %10d %10d %10d %10d %10d %10d"%(i,values[i],passthrus[i],unmodifieds[i],resolveds[i],indirects[i],others[i], merges[i])
print "  Max %10d %10d %10d %10d %10d %10d %10d"%(max(values),max(passthrus),max(unmodifieds),max(resolveds),max(indirects),max(others),max(merges))
print "Total %10d %10d %10d %10d %10d %10d %10d"%(sum(values),sum(passthrus),sum(unmodifieds),sum(resolveds),sum(indirects),sum(others),sum(merges))
print " Core %10d %10d %10d %10d %10d %10d %10d"%(sum(values)/epochs,sum(passthrus)/epochs,sum(unmodifieds)/epochs,sum(resolveds)/epochs,sum(indirects)/epochs,sum(others)/epochs,sum(merges)/epochs)
