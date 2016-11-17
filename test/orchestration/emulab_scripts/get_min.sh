#!/bin/bash

FILE="$1"

awk 'BEGIN {FS=","} ; {m=$2; for (i=2; i<=NF; i++) if ($i < m) m=$i; print "Min value: ", m}' $FILE