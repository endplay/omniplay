reset
fontsize = 20
set term postscript enhanced eps fontsize
set output "dyn_pts.eps"
set style fill solid 1.00 border 0
set style histogram errorbars gap 1 lw 1
#set style histogram gap 1
set style data histogram
set xtics rotate by -45
#set xtics font "Times-Roman, 20"
#set ytics font "Times-Roman, 18"
set grid ytics
set xtics nomirror
set xlabel "Benchmarks" 
set ylabel "Normalized Runtime"offset 2
#set yrange [0:*]
#set yrange [0:45]
set boxwidth 1
set key Left

set offset -.5, -.5, 0, 0

set datafile separator ","

# Gray-happy colors
#set style line 1 lt 1 lc rgb "#44aa99"
#set style line 2 lt 1 lc rgb "#228844"
#set style line 3 lt 1 lc rgb "#332288"
#set style line 4 lt 1 lc rgb "#aa4499"
#set style line 5 lt 1 lc rgb "#777777"
#set style line 6 lt 1 lc rgb "#992288"
#set style line 7 lt 1 lc rgb "#ee3333"
#set style line 8 lt 1 lc rgb "#ee7722"

#plot 'data' using 2:5:xtic(1) ti "Baseline" ls 1, \
#      '' using 3:6 ti "Replay system" ls 2, \
#     '' using 4:7 ti "    + Process Graph" ls 3
#     #'' using 5:8 ti "    + 2nd Hard Drive" lt 1 lc "#e69f00"

#plot './plotgen/dyn_pts/dyn_pts.data' using 2:6:xtic(1) ti "Dynamic Only" lt 1 fill solid .65, \
#      '' using 3:7 ti "Static + Dynamic" lt 1 fill pattern 5, \
#      '' using 5:9 ti "Optimistic Dynamic" lt 1 fill solid .3
##     '' using 5 ti "Optimistic Dynamic Without Rollbacks" lt 1 fill pattern 4


plot '../opt_files/opt.stats' using 2:3:xtic(1) title "Backwards Pass" lt 1 fill solid .65, \
     '' using 4:5 ti "Both Passes" lt 1 fill pattern 5,\
     '' using 6:7 ti "Preprune" lt 1 fill solid .3

