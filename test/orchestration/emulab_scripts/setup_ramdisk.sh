#!/bin/bash

host="$1"

for i in {0..2}; do 
    echo node-$i.$host


    echo "mkdir /replay_logdb/rec_61441/7" | ssh -o StrictHostKeyChecking=no node-$i.$host
    echo "sudo mount -t ramfs -o 500M ramfs /replay_logdb/rec_61441/7" | ssh -o StrictHostKeyChecking=no node-$i.$host
    echo "sudo chmod 777 /replay_logdb/rec_61441/7" | ssh -o StrictHostKeyChecking=no node-$i.$host
#    echo "cp /replay_logdb/rec_61441/ckpt.* /replay_logdb/rec_61441/7/ckpt.*" | ssh -o StrictHostKeyChecking=no node-$i.$host


### actually, don't want to do this!! ###
#    echo "echo 7 | sudo tee /proc/sys/kernel/replay_ckpt_dir" | ssh -o StrictHostKeyChecking=no node-$i.$host



#    echo 'cat /local/src/omniplay/dift/proc64/streamserver.err' | ssh -o StrictHostKeyChecking=no node-$i.$host
#    echo 'echo 1 | sudo tee /proc/sys/kernel/replay_min_debug' | ssh -o StrictHostKeyChecking=no node-$i.$host   
#    echo 'ps -Tu arquinn -o pid,uname,comm,pcpu' | ssh -o StrictHostKeyChecking=no node-$i.$host
#    echo 'rm -r /tmp/*' | ssh -o StrictHostKeyChecking=no node-$i.$host
#    echo 'rm -r /dev/shm/*' | ssh -o StrictHostKeyChecking=no node-$i.$host
done