#!/bin/bash
BM="$1"

pushd ../

./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.first.1 --nr 1 --offset 0 --sc --ec  /experiment.config.1 --only_seq &>run.test.$BM.0.1&
sleep 2
./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.second.1 --nr 1 --offset 1 --sc --ec /experiment.config.1 --only_seq &>run.test.$BM.1.1&
sleep 2
./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.third.1 --nr 1 --offset 2 --sc  --ec /experiment.config.1 --only_seq &>run.test.$BM.2.1&
sleep 2
./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.fourth.1 --nr 1 --offset 3 --sc --ec /experiment.config.1 --only_seq &>run.tes.$BM.3.1&
sleep 2
./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.fifth.1 --nr 1 --offset 4  --sc --ec /experiment.config.1 --only_seq


popd