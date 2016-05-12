#!/bin/bash

test="$1"
host="$2"
password="$3"


PFILES[1]="../../experiment_config_files/$test/$test.1"
PFILES[2]="../../experiment_config_files/$test/$test.2.sq"
PFILES[3]="../../experiment_config_files/$test/$test.4.sq"
PFILES[4]="../../experiment_config_files/$test/$test.8.sq"
PFILES[5]="../../experiment_config_files/$test/$test.16.sq"
PFILES[6]="../../experiment_config_files/$test/$test.32.sq"
PFILES[7]="../../experiment_config_files/$test/$test.64.sq"
PFILES[8]="../../experiment_config_files/$test/$test.128.sq"


for i in {1..5}; do
    pfile=${PFILES[$i]}
    offset=$(($(($(($i-1))*5))+10))
    
    for j in {1..5}; do 
	./retaint_experiment.py -t $test --host node-$(($offset+$j)).$host --pf $pfile -p $password -o $j&
    done
done
wait

for i in {6..8}; do
    pfile=${PFILES[$i]}
    offset=$(($(($i-5))*5))
    
    for j in {1..5}; do 
	./retaint_experiment.py -t $test --host node-$(($offset+$j)).$host --pf $pfile -p $password -o $j&
    done
done
wait


