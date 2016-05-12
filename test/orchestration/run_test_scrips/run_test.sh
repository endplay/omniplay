#!/bin/bash
BM="$1"
PASS="$2"

pushd ../
#all machines for 128
./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config --nr 5 --offset 0 --only_preprue --ec /experiment.config.$PASS.128

#half for 64
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.first.half --nr 2 --offset 0 --sc --only_preprue --ec /experiment.config.$PASS.64 &>run.test.$BM.$PASS.1.2&
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM  --sf server_config.second.half --nr 3 --offset 2 --sc --only_preprue --ec /experiment.config.$PASS.64


#half for 64
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM  --sc  --sf server_config.first.quarter --nr 1  --offset 0 --only_preprue --ec /experiment.config.$PASS.small &>run.test.$BM.$PASS.1.4&
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM  --sc  --sf server_config.second.quarter --nr 1  --offset 1 --only_preprue --ec /experiment.config.$PASS.small &>run.test.$BM.$PASS.2.4&
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM  --sc  --sf server_config.third.quarter --nr 1 --offset 2 --only_preprue --ec /experiment.config.$PASS.small  &>run.test.$BM.$PASS.3.4&
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM  --sc  --sf server_config.fourth.quarter --nr 2  --offset 3 --only_preprue --ec /experiment.config.$PASS.small


popd