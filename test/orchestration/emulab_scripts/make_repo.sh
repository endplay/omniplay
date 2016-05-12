#!/bin/bash

host="$1"

for i in {0..34}; do 
    echo node-$i.$host

#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/stream.cpp node-$i.$host:/local/src/omniplay/dift/proc64/stream.cpp



    echo 'echo -e "y\n"| sudo ssh-keygen -f ~/.ssh/id_rsa -N "" ' | ssh node-$i.$host
    echo 'sudo chmod 740 /users/arquinn/.ssh/id_rsa' | ssh node-$i.$host
    scp -o StrictHostKeyChecking=no node-$i.$host:/users/arquinn/.ssh/id_rsa.pub ~/.ssh/id_rsa_node-$i.pub
    scp -o StrictHostKeyChecking=no ~/.ssh/known_hosts.cloudlab node-$i.$host:/users/arquinn/.ssh/known_hosts
    cat ~/.ssh/id_rsa_node-$i.pub >> ~/.ssh/authorized_keys

    echo 'cd /local/src/omniplay; git pull' | ssh node-$i.$host&


#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/pound_cpu.cpp node-$i.$host:/local/src/omniplay/dift/proc64/pound_cpu.cpp
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/Makefile node-$i.$host:/local/src/omniplay/dift/proc64/Makefile
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/streamserver.withwait.cpp node-$i.$host:/local/src/omniplay/dift/proc64/streamserver.cpp
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/test/retaint_test.cpp node-$i.$host:/local/src/omniplay/test/retaint_test.cpp
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/test/streamserver.h node-$i.$host:/local/src/omniplay/test/streamserver.h
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/test/Makefile node-$i.$host:/local/src/omniplay/test/Makefile
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/linkage_new2.cpp node-$i.$host:/local/src/omniplay/dift/linkage_new2.cpp
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/taint_interface/taint.h node-$i.$host:/local/src/omniplay/dift/taint_interface/taint.h
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/taint_interface/taint_full_interface.c node-$i.$host:/local/src/omniplay/dift/taint_interface/taint_full_interface.c
#    scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/taint_interface/taint_interface.h node-$i.$host:/local/src/omniplay/dift/taint_interface/taint_interface.h
#    echo 'cd /local/src/omniplay/test;make clean;make -j 5' | ssh node-$i.$host&
#    echo 'cd /local/src/omniplay/dift/;source ../.omniplay_setup;make clean;make -j 5' | ssh node-$i.$host&
#    echo 'cd /local/src/omniplay/dift/proc64; make -j 5' | ssh node-$i.$host&

done

#echo node-40.$host

#scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/stream.cpp node-33.$host:/local/src/omniplay/dift/proc64/stream.cpp
#scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/streamserver.cpp node-33.$host:/local/src/omniplay/dift/proc64/streamserver.cpp
#scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/streamnw.cpp node-33.$host:/local/src/omniplay/dift/proc64/streamnw.cpp
#scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/proc64/Makefile node-33.$host:/local/src/omniplay/dift/proc64/Makefile
#scp -o StrictHostKeyChecking=no  ~/Documents/omniplay/dift/linkage_new2.cpp node-33.$host:/local/src/omniplay/dift/linkage_new2.cpp
#echo 'cd /local/src/omniplay/dift/proc64;make -j 5' | ssh node-33.$host
