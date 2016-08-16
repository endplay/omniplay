#!/bin/bash

BASE="../experiment_config_files"

HOST=".$1"
NUM_HOSTS="35"
ROUND="no_seq"

NAMES[1]="gzip"
#NAMES[1]="mongo"
#NAMES[1]="firefox"
#NAMES[1]="openoffice"
#NAMES[1]="evince"
#NAMES[1]="gs"


echo -n "Password:"
read -s password

for i in {1..1}; do 
    NAME=${NAMES[$i]}
    TEST=$BASE"/"$NAME;
    OUTPUT_COMPRESS=emulab_output/"$NAME"_compress_"$ROUND";
    OUTPUT_PREPRUNE=emulab_output/"$NAME"_partitions_"$ROUND";
    
    echo "$TEST"
    if [ "$NAME" == "nginx" ]
    then
	python emulab_experiment.py $TEST/experiment.config -o $OUTPUT_PREPRUNE --hs=$HOST -n $NUM_HOSTS -c $TEST/seqtt.results -s --password $password;
    else
	python emulab_experiment.py $TEST/experiment.config -o $OUTPUT_PREPRUNE --hs=$HOST -n $NUM_HOSTS -c $TEST/seqtt.results -s --password $password; 
    fi	
  
    python emulab_experiment.py $TEST/experiment.config -o $OUTPUT_COMPRESS --hs=$HOST -c $TEST/seqtt.results -n $NUM_HOSTS --password $password -r 2 --compress;

    pushd ../;
   ./switch.py ${NAMES[$((i+1))]} ${NAMES[$i]};
    popd;
done;
