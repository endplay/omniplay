ping #!/bin/bash

host="$1"

for i in {0..66}; do 
    echo node-$i.$host

#    echo 'cat /local/src/omniplay/dift/proc64/streamserver.err' | ssh -o StrictHostKeyChecking=no node-$i.$host
#    echo 'echo 1 | sudo tee /proc/sys/kernel/replay_min_debug' | ssh -o StrictHostKeyChecking=no node-$i.$host   
#    echo 'ps -Tu arquinn -o pid,uname,comm,pcpu' | ssh -o StrictHostKeyChecking=no node-$i.$host
    ping -qc 4 node-$i.$host
#    echo 'rm -r /tmp/*' | ssh -o StrictHostKeyChecking=no node-$i.$host
#    echo 'rm -r /dev/shm/*' | ssh -o StrictHostKeyChecking=no node-$i.$host
done