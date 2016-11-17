#!/bin/bash

host="$1"

for i in {0..66}; do 
    echo node-$i.$host

    echo 'cd /local/src/omniplay/dift/proc64; ./run_background_task.sh ./streamserver' | ssh -o StrictHostKeyChecking=no node-$i.$host

done