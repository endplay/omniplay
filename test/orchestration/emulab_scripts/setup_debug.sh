#!/bin/bash

host="$1"

for i in {0..66}; do 
    echo node-$i.$host

    echo 'echo /tmp/core.%p | sudo tee /proc/sys/kernel/core_pattern' | ssh -o StrictHostKeyChecking=no node-$i.$host
    echo 'echo 9411455 | sudo tee /proc/sys/kernel/replay_min_debug_low' | ssh -o StrictHostKeyChecking=no node-$i.$host   
    echo 'echo 9411478 | sudo tee /proc/sys/kernel/replay_min_debug_high' | ssh -o StrictHostKeyChecking=no node-$i.$host   
done