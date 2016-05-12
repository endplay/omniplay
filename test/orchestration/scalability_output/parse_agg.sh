#!/bin/bash

results_file="agg_norm_files/optimization.stats"
rm $results_file
touch $results_file
echo "benchmark streamppl stream seq backwards_pass" > $results_file

for i in agg_norm_files/*128.stats; do
    echo $i
    size=`wc -c <$i`
    if [ $size -ge 1 ];then
	echo $i | awk '{split($0,parts,"/"); split(parts[2],bm,".");printf bm[1]}' >> $results_file
	cat $i | awk '{split($0,words,","); printf words[3]}' >> $results_file
	echo "" >> $results_file
    fi
done
