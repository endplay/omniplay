#!/bin/bash

./run_test_sop.sh "mongolonger" "ckpt"
#pushd ../; ./kill_all.sh arquinn-QV15174.dift-pg0.apt.emulab.net; popd;



#pushd ../;
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf  server_config --sc --offset 0 --nr 5 --only_stream --ec /experiment.config.$PASS.128
#popd
#pushd ../; ./kill_all.sh arquinn-QV15174.dift-pg0.apt.emulab.net; popd;

#pushd ../;
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf  server_config --sa --offset 0 --nr 5 --only_preprue --ec /experiment.config.$PASS.128
#popd

#./run_test_one_epoch.sh "mongolonger"