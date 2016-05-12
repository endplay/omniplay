set multiplot layout 1,3 title "Same plot with a multi-line title\nshowing adjustment of plot area\n to accommodate it" font ",14"
set xtics rotate
set bmargin 5
#
set title "Plot 1"
unset key
plot sin(x)/x
#
set title "Plot 2"
unset key
#plot 'silver.dat' using 1:2 ti 'silver.dat'
#

set title "Plot 3"
set style data histogram
set style histogram rowstacked
set style fill solid
set key autotitle column
set boxwidth 0.8
set format y "    "
set tics scale 0

plot    "../norm_files/gzip.final.results.sq.128.csv" using 2 t "Start Delay" ls 1, \
	 '' using 3 t "Pin Time" ls 2,\
	 '' using 4 t "Dift Time" ls 3,\
	 '' using 5 t "Preprune Time" ls 4, \
	 '' using 6 t "Forward Pass Time" ls 5,\
	 '' using 7 t "Backward Pass Time" ls 6


#plot 'immigration.dat' using 2 with histograms , \
#     '' using  7 with histograms , \
#     '' using  8 with histograms , \
#     '' using 11 with histograms 
#
unset multiplot