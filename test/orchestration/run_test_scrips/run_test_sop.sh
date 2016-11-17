#!/bin/bash
BM="$1"
PASS="$2"

pushd ../;
#all machines for 128
./emulab_scripts/kill_all.sh arquinn-QV18549.dift-pg0.apt.emulab.net;
./streamlined_experiment.py --hs arquinn-QV18549.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config --offset 4 --nr 1 --only_preprue --sot --sa  --sop --ec /experiment.config.$PASS.128

#half for 64
./emulab_scripts/kill_all.sh arquinn-QV18549.dift-pg0.apt.emulab.net;
./streamlined_experiment.py --hs arquinn-QV18549.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config --nr 5 --offset 0 --sop --sot --sld --sc --only_preprue --ec /experiment.config.$PASS.64
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.second.half --nr 3 --offset 2 --sop --sc  --sot --sld --only_preprue --ec /experiment.config.$PASS.64

#half for 64
#sleep 2

./emulab_scripts/kill_all.sh arquinn-QV18549.dift-pg0.apt.emulab.net;
./streamlined_experiment.py --hs arquinn-QV18549.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config --nr 5 --offset 0 --sop --sot --sc --sld --only_preprue --ec /experiment.config.$PASS.small

#./emulab_scripts/kill_all.sh arquinn-QV18324.dift-pg0.apt.emulab.net;
#./streamlined_experiment.py --hs arquinn-QV18324.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.small --nr 5  --offset 0 --sop --sc --only_preprue --ec /experiment.config.$PASS.small
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV1517-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.second.quarter --nr 3  --offset 1  --sop --sc --only_preprue  --ec /experiment.config.$PASS.small &>run.test.$BM.$PASS.2.4&
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV15174.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.third.quarter --nr 3  --offset 2 --sop --sc --only_preprue --ec /experiment.config.$PASS.small  &>run.test.$BM.$PASS.3.4&
#sleep 2
#./streamlined_experiment.py --hs arquinn-QV17614.dift-pg0.apt.emulab.net -p Br@nf0rd123 -t $BM --sf server_config.fourth.quarter --nr 5  --offset 0  --sop  --sc  --only_preprue --ec /experiment.config.$PASS.small

popd