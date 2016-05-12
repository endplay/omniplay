#!/bin/bash


for i in {4,8,16,32,64,128};do 
    ./get_partition_data /replay_logdb.mongo/rec_12289/ ../../experiment_config_files/mongo/mongo.$i -r ../../experiment_config_files/mongo/traces.all/ 8  > timing_data/mongo.$i.partition
done;

for i in {8,16,32,64,128};do 
    ./get_partition_data /replay_logdb.firefox/rec_77825/ ../../experiment_config_files/firefox/firefox.$i -r ../../experiment_config_files/firefox/traces.all/ 8  -fork 0 1531 1529 > timing_data/firefox.$i.partition
done;

for i in {1,2,4,8,16,32,64,128};do 
    ./get_partition_data  /replay_logdb/rec_52/ ../../experiment_config_files/gzip/gzip.$i -r ../../experiment_config_files/gzip/traces.all 8 > timing_data/gzip.$i.partition
done;

for i in {1,2,4,8,16,32,64,128};do 
    ./get_partition_data /replay_logdb.gs/rec_28695 ../../experiment_config_files/gs/gs.$i -r ../../experiment_config_files/gs/traces.all 8 > timing_data/gs.$i.partition
done;

for i in {8,16,32,64,128};do 
    ./get_partition_data /replay_logdb.openoffice/rec_35/ ../../experiment_config_files/openoffice/openoffice.$i -r ../../experiment_config_files/openoffice/traces.all 16 -fork 0 2767 2758  > timing_data/openoffice.$i.partition
done;


for i in {16,32,64,128};do 
    ./get_partition_data /replay_logdb.evince/rec_61441/ ../../experiment_config_files/evince/evince.$i -r ../../experiment_config_files/evince/traces.all 16 > timing_data/evince.$i.partition
done;

echo "starting nginx"
for i in {8,16,32,64,128};do 
    ./get_partition_data /replay_logdb.nginx/rec_73731  ../../experiment_config_files/nginx/nginx.$i -nosort -fork 11 4786 4787 4788 > timing_data/nginx.$i.partition
done;
