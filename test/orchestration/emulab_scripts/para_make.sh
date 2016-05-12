#!/bin/bash

host="$1"

for i in {1..34}; do 
    echo node-$i.$host


#    scp -o StrictHostKeyChecking=no  grub node-$i.$host:~/grub
#    echo 'sudo mv ~/grub /etc/default/grub; sudo update-grub;' | ssh node-$i.$host&
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/pound_cpu.cpp node-$i.$host:/local/src/omniplay/dift/proc64/pound_cpu.cpp

#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/streamserver.withwait.cpp node-$i.$host:/local/src/omniplay/dift/proc64/streamserver.cpp
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/test/retaint_test.cpp node-$i.$host:/local/src/omniplay/test/retaint_test.cpp
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/test/streamctl.cpp node-$i.$host:/local/src/omniplay/test/streamctl.cpp
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/test/Makefile node-$i.$host:/local/src/omniplay/test/Makefile
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/linkage_new2.cpp node-$i.$host:/local/src/omniplay/dift/linkage_new2.cpp
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/taint_interface/taint.h node-$i.$host:/local/src/omniplay/dift/taint_interface/taint.h
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/taint_interface/taint_full_interface.c node-$i.$host:/local/src/omniplay/dift/taint_interface/taint_full_interface.c
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/taint_interface/taint_interface.h node-$i.$host:/local/src/omniplay/dift/taint_interface/taint_interface.h

#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/stream.cpp node-$i.$host:/local/src/omniplay/dift/proc64/stream.cpp

    echo 'cd /local/src/omniplay/linux-lts-quantal-3.5.0; source ../.omniplay_setup;./compile' | ssh node-$i.$host&  #make the kernel
#    echo 'cd /local/src/omniplay/test;source ../.omniplay_setup;make clean; make -j 5' | ssh node-$i.$host&                                           #make the test directory
#    echo 'cd /local/src/omniplay/dift/;source ../.omniplay_setup;make clean;make -j 5' | ssh node-$i.$host&     #make the dift directory
#    echo 'cd /local/src/omniplay/dift/proc64; make -j 5' | ssh node-$i.$host&                                   #make the streamserver directory

 #   scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/Makefile node-$i.$host:/local/src/omniplay/dift/proc64/Makefile
#    echo 'cd /local/src/omniplay/test/dev;sudo rmmod spec;sudo insmod spec.ko' | ssh node-$i.$host&                                   #make the streamserver directory

done

#echo node-40.$host

#scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/stream.cpp node-33.$host:/local/src/omniplay/dift/proc64/stream.cpp
#scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/streamserver.cpp node-33.$host:/local/src/omniplay/dift/proc64/streamserver.cpp
#scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/streamnw.cpp node-33.$host:/local/src/omniplay/dift/proc64/streamnw.cpp
#scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/Makefile node-33.$host:/local/src/omniplay/dift/proc64/Makefile
#scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/linkage_new2.cpp node-33.$host:/local/src/omniplay/dift/linkage_new2.cpp
#echo 'cd /local/src/omniplay/dift/proc64;make -j 5' | ssh node-33.$host
