#!/bin/bash

host="$1"

for i in {0..34}; do 
    echo node-$i.$host

    echo 'pkill -9 retaint; pkill -9 recv_replay_files;pkill -9 streamctl; pkill -9 stream; pkill -9 streamserver; pkill -9 pound_cpu;pkill -9 800001_640037; pkill -9 800001_5810aa; pkill -9 800001_c40b0a;' | ssh -o StrictHostKeyChecking=no node-$i.$host
    echo 'rm -r /tmp/*' | ssh -o StrictHostKeyChecking=no node-$i.$host
   echo 'rm -r /dev/shm/*' | ssh -o StrictHostKeyChecking=no node-$i.$host   


done