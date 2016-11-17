#!/bin/bash

source ~/.omniplay_setup

rec=$1
ckpts=$(cat $2)

echo $rec

for ckpt in $ckpts; do
    $OMNIPLAY_DIR/test/resume --pthread $MY_RESUME_PTHREAD $rec --ckpt_at=$ckpt -p --attach_offset=6789,67781845&
    echo "finished taking $ckpt"
done


#replay_ckpts=`ls $rec/ckpt.* | awk '{split($0,a,"/"); split(a[4],b,"."); print b[2]}'`
#echo $replay_ckpts

#for ckpt in $replay_ckpts; do
#    $OMNIPLAY_DIR/test/resume --pthread $MY_RESUME_PTHREAD $rec --from_ckpt=$ckpt
#    echo "finished with $ckpt"
#done
