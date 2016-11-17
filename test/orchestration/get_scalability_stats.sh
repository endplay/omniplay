#!/bin/bash

#tests="gzip.final.results nginx.final.results evince.final.results openoffice.final.results mongolonger.final.results firefoxlonger.final.results gs.final.results"
tests="evince.final.results"
#tests="gs.final.results"
#tests="gs.final.results"
#types="fq sq ckpt"
types="ckpt"
mkdir "scalability_output"
mkdir "scalability_output/norm_files"
mkdir "scalability_output/opt_files"
mkdir "scalability_output/stacked_files"

for test_name in $tests; do
    for type in $types; do
	echo $test_name

	rm -r "$test_name/$type/results/seqppl.streamls"
	rm -r "$test_name/$type/results/seq"
	rm -r "$test_name/$type/results/seq.streamls"
	rm -r "$test_name/$type/results/one_pass"


	./make_graph.py -i "$test_name/$type/tarballs/seqppl.streamls" -o "$test_name/$type/results/seqppl.streamls" -r "$test_name/replay_time" -n "$test_name $type"
	./make_graph.py -i "$test_name/$type/tarballs/seq.streamls" -o "$test_name/$type/results/seq.streamls" -r "$test_name/replay_time" -n "$test_name $type"
	./make_graph.py -i "$test_name/$type/tarballs/seq" -o "$test_name/$type/results/seq" -r "$test_name/replay_time" -n "$test_name $type"
	./make_graph.py -i "$test_name/$type/tarballs/one_pass" -o "$test_name/$type/results/one_pass" -r "$test_name/replay_time" -n "$test_name $type"


	#we copy out the latency stats and the stacked bar charts for non aggs, and copy out the agg stats for the.. well aggs
	cp "$test_name/$type/results/seqppl.streamls/latency.stats" "scalability_output/norm_files/$test_name.$type.norm.stats"

	for size in {1,2,4,8,16,32,64,128}; do
	    cp "$test_name/$type/results/seqppl.streamls/graphs_and_stats/0.$size.csv" "scalability_output/stacked_files/$test_name.$type.0.$size.csv"
	    cp "$test_name/$type/results/seqppl.streamls/graphs_and_stats/1.$size.csv" "scalability_output/stacked_files/$test_name.$type.1.$size.csv"
	    cp "$test_name/$type/results/seqppl.streamls/graphs_and_stats/2.$size.csv" "scalability_output/stacked_files/$test_name.$type.2.$size.csv"
	    cp "$test_name/$type/results/seqppl.streamls/graphs_and_stats/3.$size.csv" "scalability_output/stacked_files/$test_name.$type.3.$size.csv"
	    cp "$test_name/$type/results/seqppl.streamls/graphs_and_stats/4.$size.csv" "scalability_output/stacked_files/$test_name.$type.4.$size.csv"
	done;

	test $type == "agg" && (cp "$test_name/$type/results/seqppl.streamls/aggregation.stats" "scalability_output/agg_norm_files/$test_name.seqppl.streamls.norm.stats")

	rm "scalability_output/opt_files/$test_name.$type.128.stats"
	touch "scalability_output/opt_files/$test_name.$type.128.stats"
	awk '/./{line=$0} END{printf "seqppl.streamls, "; print line}' "$test_name/$type/results/seqppl.streamls/latency.raw.stats" >> "scalability_output/opt_files/$test_name.$type.128.stats"
	awk '/./{line=$0} END{printf "seq.streamls, "; print line}' "$test_name/$type/results/seq.streamls/latency.raw.stats" >> "scalability_output/opt_files/$test_name.$type.128.stats"
	awk '/./{line=$0} END{printf "seq, "; print line}' "$test_name/$type/results/seq/latency.raw.stats" >> "scalability_output/opt_files/$test_name.$type.128.stats"
	awk '/./{line=$0} END{printf "one_pass, "; print line}' "$test_name/$type/results/one_pass/latency.raw.stats" >> "scalability_output/opt_files/$test_name.$type.128.stats"

	
	test $type == "agg" && (rm "scalability_output/opt_files/$test_name.$type.128.stats")
	test $type == "agg" && (touch "scalability_output/opt_files/$test_name.$type.128.stats")
	test $type == "agg" && (awk '/./{line=$0} END{printf "seqppl.streamls, "; print line}' "$test_name/$type/results/seqppl.streamls/aggregation.raw.stats" >> "scalability_output/opt_files/$test_name.$type.128.stats")
	test $type == "agg" && (awk '/./{line=$0} END{printf "seq.streamls, "; print line}' "$test_name/$type/results/seq.streamls/aggregation.raw.stats" >> "scalability_output/opt_files/$test_name.$type.128.stats")
	test $type == "agg" && (awk '/./{line=$0} END{printf "seq, "; print line}' "$test_name/$type/results/seq/aggregation.raw.stats" >> "scalability_output/opt_files/$test_name.$type.128.stats")
	test $type == "agg" && (awk '/./{line=$0} END{printf "one_pass, "; print line}' "$test_name/$type/results/one_pass/aggregation.raw.stats" >> "scalability_output/opt_files/$test_name.$type.128.stats")



     
    done
done
	

