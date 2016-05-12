reset
fontsize = 20
set term postscript enhanced eps fontsize color
set output "../output_graphs/evince.fq.128.eps"

set style line 1 linecolor rgb "#d73027" lt 1
set style line 2 linecolor rgb "#fc8d59" lt 1
set style line 3 linecolor rgb "#fee090" lt 1
set style line 4 linecolor rgb "#e0f3f8" lt 1
set style line 5 linecolor rgb "#91bfdb" lt 1
set style line 6 linecolor rgb "#4575b4" lt 1
set style line 7 linecolor rgb "#e6f598" lt 1
set style fill solid 1.0
set style data histogram
set style histogram rowstacked

#set xtics 0,40,128
set xtic 128
set ytic 1000

set title "Evince First Query"
set xlabel "Epoch" 
set ylabel "Time (ms)"offset 2
set xrange [1:128]
#set key outside center bottom
set key outside center bottom vertical maxrows 3

set datafile separator "," 

plot    "../norm_files/evince.final.results.fq.128.csv" using 2 t "Start Delay" ls 1, \
	 '' using 3 t "Pin Time" ls 2,\
	 '' using 4 t "Dift Time" ls 3,\
	 '' using 5 t "Preprune Time" ls 4, \
	 '' using 6 t "Forward Pass Time" ls 5,\
	 '' using 7 t "Backward Pass Time" ls 6
