#!/bin/bash

host="$1"

for i in {0..66}; do 
    echo node-$i.$host

#    echo 'cat /local/src/omniplay/dift/proc64/streamserver.err' | ssh -o StrictHostKeyChecking=no node-$i.$host
#    echo 'echo 1 | sudo tee /proc/sys/kernel/replay_min_debug' | ssh -o StrictHostKeyChecking=no node-$i.$host   
    echo "ping node-$((i + 1)) -c 4" | ssh -o StrictHostKeyChecking=no node-$i.$host
    echo "ping node-$((i + 2)) -c 4" | ssh -o StrictHostKeyChecking=no node-$i.$host
done