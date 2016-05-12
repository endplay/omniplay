DIR="$1"
pushd $DIR;

mkdir stats1;
mkdir stats0;
mv stats/*.tgz1 stats1;
mv stats/*.tgz0 stats0;
cd stats1;



mkdir tarballs;
mv *.tgz* tarballs;

for i in {1,2,4,8,16,32,64,128,256}; do 
    tar -xvf tarballs/$i.taint-stats.tgz*; 
    tar -xvf tarballs/$i.stream-stats.tgz*;
    for j in $(seq 0 $(($i-1))); do 
	mv tmp/taint-stats-$j tmp/$i.taint-stats-$j; 
	mv tmp/stream-stats-$j tmp/$i.stream-stats-$j; 
    done;
done; 

mkdir stats; mv tmp/* stats/;
rm -r tmp;

cd ../stats0;

mkdir tarballs;
mv *.tgz* tarballs;

for i in {1,2,4,8,16,32,64,128,256}; do 
    tar -xvf tarballs/$i.taint-stats.tgz*; 
    tar -xvf tarballs/$i.stream-stats.tgz*;
    for j in $(seq 0 $(($i-1))); do 
	mv tmp/taint-stats-$j tmp/$i.taint-stats-$j; 
	mv tmp/stream-stats-$j tmp/$i.stream-stats-$j; 
    done;
done; 

mkdir stats;
mv tmp/* stats/;
rm -r tmp;




popd



