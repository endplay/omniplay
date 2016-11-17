#!/bin/bash

./run_test_sop.sh "mongo" "fq"
pushd ../; ./kill_all.sh arquinn-QV15174.dift-pg0.apt.emulab.net; popd;
#./run_test_one_epoch.sh "mongo"
#pushd ../; ./kill_all.sh arquinn-QV15174.dift-pg0.apt.emulab.net; popd;
#./run_test_sop.sh "mongo" "sq"