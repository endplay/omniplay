#!/usr/bin/python

import sys


def get_stats(num_epochs, input_base_dir, output_f):

    seq = 1

    # For timings
    dift = []
    recv = []
    total = []
    receive = []
    output = []
    index = []
    address = []
    finish = []
    prune = []
    make = []
    send = []
    other = []

    # For address processing
    tokens = []
    passthrus = []
    unmodifieds = []
    resolveds = []
    indirects = []
    others = []
    merges = []

    epochs = num_epochs

    for i in range(epochs):
        fh = open (input_base_dir + "taint-stats-" + str(i))
        for line in fh:
            if line[:10] == "DIFT began":
                began = float(line.split()[3])
            if line[:10] == "DIFT ended":
                ended = float(line.split()[3])
                dift.append(int((ended-began)*1000.0))
        fh.close()

    for i in range(epochs):
        fh = open (input_base_dir + "stream-stats-" + str(i))
        for line in fh:
            if line[:11] == "Total time:":
                total.append(int(line.split()[2]))
            if line[:13] == "Receive time:":
                recv.append(int(line.split()[2]))
            if line[:21] == "Receive live set time":
                receive.append(int(line.split()[4]))
            if line[:19] == "Prune live set time":
                prune.append(int(line.split()[4]))
            if line[:18] == "Make live set time":
                make.append(int(line.split()[4]))
            if line[:23] == "Send live set wait time":
                send.append(int(line.split()[5]))
            if line[:23] == "Output processing time:":
                output.append(int(line.split()[3]))
            if line[:16] == "Index wait time:":
                index.append(int(line.split()[3]))
            if line[:24] == "Address processing time:":
                address.append(int(line.split()[3]))
            if line[:12] == "Finish time:":
                finish.append(int(line.split()[2]))

            if line[:15] == "Address tokens ":
                tokens.append(int(line.split()[2]))
                passthrus.append(int(line.split()[4]))
                unmodifieds.append(int(line.split()[10][0:-1]))
                resolveds.append(int(line.split()[6][0:-1]))
                indirects.append(int(line.split()[8]))
                others.append(tokens[i]-(passthrus[i]+unmodifieds[i]+resolveds[i]+indirects[i]))
                merges.append(int(line.split()[12]))

    for i in range(epochs):
        other.append(total[i]-recv[i]-receive[i]-prune[i]-make[i]-send[i]-output[i]-index[i]-address[i]-finish[i])
        if num_epochs == 128 and i == 0:
            print "dift", dift[i]
            print "recv", recv[i]
            print "diff", recv[i] - dift[i]


        recv[i] -= dift[i]

    print >> output_f, "Epoch    DIFT     FF   Recv.  Prune   Make   Send Output  Index Address Finish  Other"
    for i in range(epochs):
        print >> output_f, "%5s %7s %6s %7s %6s %6s %6d %6d %6d %7d %6d %6d"%(i,dift[i],recv[i],receive[i],prune[i],make[i],send[i],output[i],index[i],address[i],finish[i],other[i])
    print >> output_f, "  Max %7d %6d %7d %6d %6d %6d %6d %6d %7d %6d %6d"%(max(dift),max(recv),max(receive),max(prune),max(make),max(send),max(output),max(index),max(address),max(finish),max(other))
    print >> output_f, "Total %7d %6d %7d %6d %6d %6d %6d %6d %7d %6d %6d"%(sum(dift),sum(recv),sum(receive),sum(prune),sum(make),sum(send),sum(output),sum(index),sum(address),sum(finish),sum(other))
    print >> output_f, " Core %7d %6d %7d %6d %6d %6d %6d %6d %7d %6d %6d"%(sum(dift)/epochs,sum(recv)/epochs,sum(receive)/epochs,sum(prune)/epochs,sum(make)/epochs,sum(send)/epochs,sum(output)/epochs,sum(index)/epochs,sum(address)/epochs,sum(finish)/epochs,sum(other)/epochs)

    print >> output_f,""
    print >> output_f,""
    print >> output_f, "Epoch     Tokens  Passthrus Unmodified  Resolveds  Indirects      Other   (Merges)"
    for i in range(epochs):
        print >> output_f, "%5d %10d %10d %10d %10d %10d %10d %10d"%(i,tokens[i],passthrus[i],unmodifieds[i],resolveds[i],indirects[i],others[i], merges[i])
    print >> output_f, "  Max %10d %10d %10d %10d %10d %10d %10d"%(max(tokens),max(passthrus),max(unmodifieds),max(resolveds),max(indirects),max(others),max(merges))
    print >> output_f, "Total %10d %10d %10d %10d %10d %10d %10d"%(sum(tokens),sum(passthrus),sum(unmodifieds),sum(resolveds),sum(indirects),sum(others),sum(merges))
    print >> output_f, " Core %10d %10d %10d %10d %10d %10d %10d"%(sum(tokens)/epochs,sum(passthrus)/epochs,sum(unmodifieds)/epochs,sum(resolveds)/epochs,sum(indirects)/epochs,sum(others)/epochs,sum(merges)/epochs)
