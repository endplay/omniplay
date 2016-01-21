#!/bin/bash
BASE="$OMNIPLAY_DIR/test/experiment_config_files"
HOST=".$1"
NUM_HOSTS="32"

GS=$BASE"/gzip.rec.2"
GS_NAME="ghostscript"

GZIP=$BASE"/gzip.rec.52"
GZIP_NAME="gzip"

EVINCE=$BASE"/evince.rec.61441"
EVINCE_NAME="evince"

NGINX=$BASE"/mine.rec.73731"
NGINX_NAME="nginx"

TEST=$EVINCE
NAME=$EVINCE_NAME



echo -n "Password:"
read -s password

OUTPUT="emulab_output_$NAME"

python emulab_experiment.py $TEST/experiment.config -o $OUTPUT -p $TEST/prefix.tar.gz --hs=$HOST -n $NUM_HOSTS -c $TEST/seqtt.results -s --password $password
python emulab_experiment.py $TEST/experiment.config -o $OUTPUT --hs=$HOST -c $TEST/seqtt.results -n $NUM_HOSTS --password $password -r 5

