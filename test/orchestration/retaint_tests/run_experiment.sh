#!/bin/bash

HOST="arquinn-QV15174.dift-pg0.apt.emulab.net"
password="Br@nf0rd123"

#NAMES[1]="gzip"
#NAMES[2]="mongo"
NAMES[3]="firefox"
NAMES[4]="openoffice"
NAMES[5]="evince"
#NAMES[6]="gs"
#NAMES[7]="nginx"



for i in {3..5}; do 
 
    NAME=${NAMES[$i]}
    
    echo starting "$NAME"
    echo "./retaint_bm.sh $NAME $HOST $password"

    ./retaint_bm.sh $NAME $HOST $password

    pushd ../../;
    sudo ./switch.py ${NAMES[$((i+1))]} ${NAMES[$i]};
    popd;
done;
