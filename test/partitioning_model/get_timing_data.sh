#!/bin/bash


./get_timing_data /replay_logdb.mongolonger/rec_102403/ --stop 67781845 > timing_data/mongolonger.timing_data
./get_timing_data /replay_logdb.firefoxlonger/rec_4098/ --fork 0 3540 3542 > timing_data/firefoxlonger.timing_data
./get_timing_data /replay_logdb.gzip/rec_52/ > timing_data/gzip.timing_data
./get_timing_data /replay_logdb.gs/rec_28695 > timing_data/gs.timing_data
./get_timing_data /replay_logdb.openoffice/rec_35/  --fork 0 2767 2758  > timing_data/openoffice.timing_data
./get_timing_data /replay_logdb/rec_61441/ > timing_data/evince.timing_data
./get_timing_data /replay_logdb.nginx/rec_73731  --fork 11 4786 4787 4788 > timing_data/nginx.timing_data
