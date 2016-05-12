#!/bin/bash

host="$1"

for i in {0..66}; do 
    echo node-$i.$host

    echo 'df -h' | ssh -o StrictHostKeyChecking=no node-$i.$host

done