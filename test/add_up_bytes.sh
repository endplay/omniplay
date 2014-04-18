#!/bin/bash

extra=0
count=0
for replay_dir in /replay_logdb/*; do
	if [[ -d $replay_dir ]]; then
		echo "Parsing replay dir $replay_dir"
		for replay_file in $replay_dir/*; do
			if echo "$replay_file" | grep "klog.id." &> /dev/null; then
				output=$(./parseklog $replay_file -s)
				rc=$?

				if [[ "$rc" -ne "0" ]]; then
					echo "Failed to parse $replay_file"
				fi

				line=$(echo "$output" | tail -n1) 
				stats=$(echo "$line" | sed -e "s|Extra bytes added by replay_graph:||")

				extra=$(($extra+$stats))

				size=$(stat -c %s $replay_file)
				count=$(($count+$size))
			fi
		done
	fi
done

echo "Total log bytes $count"
echo "Bytes from file graph $extra"

