

for i in {4,8,16,32,64,128};do 
    ./mkpartition_iter /replay_logdb.mongo/rec_12289/ $i -ut_arg 150 -ui_arg 1.4 > experiment_config_files/mongo/mongo.$i.fq.2
done;

for i in {8,16,32,64,128};do 
    ./mkpartition_iter /replay_logdb.firefox/rec_77825/ $i -ut_arg 180 -ui_arg 1.4 -fork 0 1529 1531 > experiment_config_files/firefox/firefox.$i.fq.2
done

#already finished
#for i in {1,2,4,8,16,32,64,128};do 
#    ./mkpartition_iter /replay_logdb/rec_52/ $i -ut_arg 122 -ui_arg 1.4 > experiment_config_files/gzip/gzip.$i.fq
#done;

#for i in {2,4,8,16,32,64,128};do 
#    ./mkpartition_iter /replay_logdb.gs/rec_28695/ $i -ut_arg 140 -ui_arg 1.4 -s  > experiment_config_files/gs/gs.$i.fq.2
#done;

for i in {8,16,32,64,128};do 
    ./mkpartition_iter /replay_logdb.openoffice/rec_35/ $i -ut_arg 180 + -ui_arg 1.4 -fork 0 2767 2758 > experiment_config_files/openoffice/openoffice.$i.fq.2
done;

for i in {16,32,64,128};do 
    ./mkpartition_iter /replay_logdb.evince/rec_61441/ $i -ut_arg 150 -ui_arg 1.4 > experiment_config_files/evince/evince.$i.fq.2
done;


for i in {2,4,8,16,32,64,128};do 
    ./mkpartition_iter /replay_logdb.nginx/rec_73731/ $i -ut_arg 136 -ui_arg 1.4 -fork 11 4786 4787 4788 > experiment_config_files/nginx/nginx.$i.fq
done;

