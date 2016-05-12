#!/bin/bash
BM="$1"
PASS="$2"

pushd ../
#all machines for 128
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config --offset 0 --sa --nr 3 --only_preprue --ec /experiment.config.$PASS.128


#half for 64
./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.first.half --nr 5 --offset 0  --sop --sc --sld  --only_preprue --ec /experiment.config.$PASS.64
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.second.half --nr 3 --offset 2 --sop --sc  --sot --sld --only_preprue --ec /experiment.config.$PASS.64

#half for 64
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.first.half --nr 5  --offset 0  --sc --sld --only_seq --ec /experiment.config.$PASS.small
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.second.quarter --nr 3  --offset 1  --sop --sc --only_preprue  --ec /experiment.config.$PASS.small &>run.test.$BM.$PASS.2.4&
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.third.quarter --nr 3  --offset 2 --sop --sc --only_preprue --ec /experiment.config.$PASS.small  &>run.test.$BM.$PASS.3.4&
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.fourth.quarter --nr 2  --offset 0  --sop  --sc  --only_preprue --ec /experiment.config.$PASS.small

popd