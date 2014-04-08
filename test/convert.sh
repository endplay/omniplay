RECS=/replay_logdb/rec_*
for rec in $RECS
do
	FILES=$(ls $rec | grep "klog.id.[0-9]\{4,\}$")
	for f in $FILES
	do
	echo "parsing $rec/$f"
	./parseklog $rec/$f -c /dev/null > m
	original=$(ls -l $rec/$f | awk '{print $5}')
	new=$(ls -l $rec/$f.convert | awk '{print $5}')
	echo "x message size: $((save=$original-$new))  , orignal size:$original, new: $new"
	done
done
