2#!/usr/bin/python

import sys


def get_stats(num_epochs, input_base_dir, output_f):

    seq = 1

    instrumented = []

    # For timings
    dift = []
    recv = []
    total = []
    preprune = []
    prepruneg = []
    pwait = []
    receive = []
    insert = []
    output = []
    index = []
    address = []
    finish = []
    prune = []
    make = []
    send = []
    other = []
    rindexmerge = []
    rindexaddr = []
    rindexstream = []


    #for data sizes
    live_set = []
    merge_log = []
    output_log = []
    input_log = []
    addr_log = []


    # For address processing
    tokens = []
    passthrus = []
    unmodifieds = []
    resolveds = []
    indirects = []
    others = []
    merges = []

    #prune stats
    pruned = []
    simplified = []
    unchanged = []
    total_merges = []
    prune_pass_one = []
    prune_pass_one_max = []
    prune_pass_two = []
    live_set = []

    #make_new_live_set stats (mostly for curiosity)
    no_changes = []
    zeros = []
    inputs = []
    meges = []
    merge_zeros = []
    not_live = []
    


    epochs = num_epochs
    for i in range(epochs):
        fh = open (input_base_dir + "taint-stats-" + str(i))
        for line in fh:
            if line[:10] == "DIFT began":
                began = float(line.split()[3])
            if line[:10] == "DIFT ended":
                ended = float(line.split()[3])
                dift.append(int((ended-began)*1000.0))
            if line[:26] == "Instructions instrumented:":
                instrumented.append(int(line.split()[2]))

        fh.close()

    for i in range(epochs):

          fh = open (input_base_dir + "stream-stats-" + str(i))

          for line in fh:
              if line[:11] == "Total time:":
                  total.append(int(line.split()[2]))
              if line[:13] == "Receive time:":
                  recv.append(int(line.split()[2]))
              if line[:19] == "Preprune local time":
                  preprune.append(int(line.split()[3]))
              if line[:20] == "Preprune global time":
                  prepruneg.append(int(line.split()[3]))
              if line[:19] == "Receive fb set time":
                  pwait.append(int(line.split()[4]))
              if line[:21] == "Receive live set time":
                  receive.append(int(line.split()[4]))
              if line[:20] == "Insert live set time":
                  insert.append(int(line.split()[4]))
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
              if line[:23] == "Make rindex merge time:":
                  rindexmerge.append(int(line.split()[4]))
              if line[:22] == "Make rindex addr time:":
                  rindexaddr.append(int(line.split()[4]))
              if line[:24] == "Make rindex stream time:":
                  rindexstream.append(int(line.split()[4]))

              if line[:15] == "Address tokens ":
                  tokens.append(int(line.split()[2]))
                  passthrus.append(int(line.split()[4]))
                  unmodifieds.append(int(line.split()[10][0:-1]))
                  resolveds.append(int(line.split()[6][0:-1]))
                  indirects.append(int(line.split()[8]))
                  others.append(tokens[i]-(passthrus[i]+unmodifieds[i]+resolveds[i]+indirects[i]))
                  merges.append(int(line.split()[12]))


              if line[:10] == "no changes":
                  no_changes.append(int(line.split()[2][:-1]))
                  zeros.append(int(line.split()[4][:-1]))
                  inputs.append(int(line.split()[6][:-1]))
                  meges.append(int(line.split()[8][:-1]))
                  merge_zeros.append(int(line.split()[10][:-1]))
                  not_live.append(int(line.split()[13]))

              if line[:9] == "Received ":
                  words = line.split()
                  if words[-1] == "set" and words[-2] == "live":
                      live_set.append(int(words[1]))                  
                  if words[-1] == "data" and words[-2] == "merge":
                      merge_log.append(int(words[1]))
                  if words[-1] == "data" and words[-2] == "output":
                      output_log.append(int(words[1]))
                  if words[-1] == "data" and words[-2] == "input":
                      input_log.append(int(words[1]))
                  if words[-1] == "data" and words[-2] == "addr":
                      addr_log.append(int(words[1]))


              if line[:24] == "Total prune pass 1 time:":
                  prune_pass_one.append(int(line.split()[5]))
                  prune_pass_one_max.append(int(line.split()[9]))
                      
              if line[:24] == "Total prune pass 2 time:":
                  prune_pass_two.append(int(line.split()[5]))                              

              if line[:7] == "Pruned ":
                  pruned.append(int(line.split()[1]))
                  simplified.append(int(line.split()[3]))
                  unchanged.append(int(line.split()[5]))
                  total_merges.append(int(line.split()[7]))



                  

    for i in range(epochs):
        preprune[i] += prepruneg[i]
        other.append(total[i]-recv[i]-preprune[i]-pwait[i]-receive[i]-insert[i]-prune[i]-make[i]-send[i]-output[i]-index[i]-address[i]-finish[i]-rindexmerge[i]-rindexaddr[i]-rindexstream[i])
        recv[i] -= dift[i]


#    print "%7s %6s %6s %7s %6s %6s %6s %6s %6d %6d %6d %7d %6d %6d %7d"%(len(dift),len(recv),len(preprune),len(pwait),len(receive),len(insert),len(prune),len(make),len(send),len(output),len(index),len(address),len(finish),len(other),len(total))


    if (sum(rindexstream)+sum(rindexaddr)+sum(rindexmerge) > 0):
        print>>output_f, "Epoch    DIFT     FF     PP  RMerge  RAddr Stream  Prune   Make   Send Output  Index Address Finish  Other   Total"
        for i in range(epochs):
            print>>output_f, "%5s %7s %6s %6s %7s %6s %6s %6s %6s %6d %6d %6d %7d %6d %6d %7d"%(i,dift[i],recv[i],preprune[i],rindexmerge[i],rindexaddr[i],rindexstream[i],prune[i],make[i],send[i],output[i],index[i],address[i],finish[i],other[i], total[i])
        print>>output_f, "  Max %7d %6d %6d %7d %6d %6d %6d %6d %6d %6d %6d %7d %6d %6d %7d"%(max(dift),max(recv),max(preprune),max(rindexmerge),max(rindexaddr),max(rindexstream),max(prune),max(make),max(send),max(output),max(index),max(address),max(finish),max(other),max(total))
        print>>output_f, "Total %7d %6d %6d %7d %6d %6d %6d %6d %6d %6d %6d %7d %6d %6d %7d"%(sum(dift),sum(recv),sum(preprune),sum(rindexmerge),sum(rindexaddr),sum(rindexstream),sum(prune),sum(make),sum(send),sum(output),sum(index),sum(address),sum(finish),sum(other), sum(total))
        print>>output_f, " Core %7d %6d %6d %7d %6d %6d %6d %6d %6d %6d %6d %7d %6d %6d %7d"%(sum(dift)/epochs,sum(recv)/epochs,sum(preprune)/epochs,sum(rindexmerge)/epochs,sum(rindexaddr)/epochs,sum(insert)/epochs,sum(prune)/epochs,sum(make)/epochs,sum(send)/epochs,sum(output)/epochs,sum(index)/epochs,sum(rindexstream)/epochs,sum(finish)/epochs,sum(other)/epochs,sum(total)/epochs)
    else:
        print>>output_f, "Epoch    DIFT     FF     PP    Wait  Recv. Insert  Prune   Make   Send Output  Index Address Finish  Other   Total"
        for i in range(epochs):
            print>>output_f, "%5s %7s %6s %6s %7s %6s %6s %6s %6s %6d %6d %6d %7d %6d %6d %7d"%(i,dift[i],recv[i],preprune[i],pwait[i],receive[i],insert[i],prune[i],make[i],send[i],output[i],index[i],address[i],finish[i],other[i], total[i])
        print>>output_f, "  Max %7d %6d %6d %7d %6d %6d %6d %6d %6d %6d %6d %7d %6d %6d %7d"%(max(dift),max(recv),max(preprune),max(pwait),max(receive),max(insert),max(prune),max(make),max(send),max(output),max(index),max(address),max(finish),max(other),max(total))
        print>>output_f, "Total %7d %6d %6d %7d %6d %6d %6d %6d %6d %6d %6d %7d %6d %6d %7d"%(sum(dift),sum(recv),sum(preprune),sum(pwait),sum(receive),sum(insert),sum(prune),sum(make),sum(send),sum(output),sum(index),sum(address),sum(finish),sum(other), sum(total))
        print>>output_f, " Core %7d %6d %6d %7d %6d %6d %6d %6d %6d %6d %6d %7d %6d %6d %7d"%(sum(dift)/epochs,sum(recv)/epochs,sum(preprune)/epochs,sum(pwait)/epochs,sum(receive)/epochs,sum(insert)/epochs,sum(prune)/epochs,sum(make)/epochs,sum(send)/epochs,sum(output)/epochs,sum(index)/epochs,sum(address)/epochs,sum(finish)/epochs,sum(other)/epochs,sum(total)/epochs)




    print >> output_f,""
    print >> output_f,""
    print >> output_f, "Epoch     Tokens  Passthrus Unmodified  Resolveds  Indirects      Other   (Merges)"
    for i in range(epochs):
        print >> output_f, "%5d %10d %10d %10d %10d %10d %10d %10d"%(i,tokens[i],passthrus[i],unmodifieds[i],resolveds[i],indirects[i],others[i], merges[i])
    print >> output_f, "  Max %10d %10d %10d %10d %10d %10d %10d"%(max(tokens),max(passthrus),max(unmodifieds),max(resolveds),max(indirects),max(others),max(merges))
    print >> output_f, "Total %10d %10d %10d %10d %10d %10d %10d"%(sum(tokens),sum(passthrus),sum(unmodifieds),sum(resolveds),sum(indirects),sum(others),sum(merges))
    print >> output_f, " Core %10d %10d %10d %10d %10d %10d %10d"%(sum(tokens)/epochs,sum(passthrus)/epochs,sum(unmodifieds)/epochs,sum(resolveds)/epochs,sum(indirects)/epochs,sum(others)/epochs,sum(merges)/epochs)


    print >> output_f,""
    print >> output_f,""
    print >> output_f, "Epoch      Merge     Output      Input       Addr       Live"
    for i in range(epochs):
        print >> output_f, "%5d %10d %10d %10d %10d %10d"%(i,merge_log[i],output_log[i],input_log[i],addr_log[i],live_set[i])
    print >> output_f, "  Max %10d %10d %10d %10d %10d"%(max(merge_log),max(output_log),max(input_log),max(addr_log),max(live_set))
    print >> output_f, "Total %10d %10d %10d %10d %10d"%(sum(merge_log),sum(output_log),sum(input_log),sum(addr_log),sum(live_set))
    print >> output_f, " Core %10d %10d %10d %10d %10d"%(sum(merge_log)/epochs,sum(output_log)/epochs,sum(input_log)/epochs,sum(addr_log)/epochs,sum(live_set)/epochs)

    print >> output_f, ""
    print >> output_f, ""
    print >> output_f, "Epoch Instrumented"
    for i in range(epochs):
        print >> output_f,"%5d %12d"%(i, instrumented[i])
    print >> output_f, "  Max %12d"%(max(instrumented))
    print >> output_f,"Total %12d"%(sum(instrumented))
    print >> output_f," Core %12d"%(sum(instrumented)/epochs)
