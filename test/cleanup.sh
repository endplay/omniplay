RECS=/replay_logdb/rec_*
for rec in $RECS
do
	FILES=$(ls $rec | grep "klog.id.[0-9]\{4,\}$")
	for f in $FILES
	do
	echo "cleaning $rec/$f" >&2
	rm $rec/$f
	done
done
