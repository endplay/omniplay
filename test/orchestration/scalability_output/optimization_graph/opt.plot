# solution2.gnuplot
reset
set terminal postscript eps enhanced 14


set output "../output_graphs/output_opt.eps"
set title "Comparison of Optimizations"
set ylabel "Time (ms)"

set style data histogram
set style histogram cluster errorbars gap 1 lw 1
set xtics rotate by -45
set xtics nomirror

set style fill solid border 0
set offset -.5, -.5,0,0
set boxwidth 1.0



set style line 1 linecolor rgb "#d73027" lt 1
set style line 2 linecolor rgb "#fc8d59" lt 1
set style line 3 linecolor rgb "#fee090" lt 1
set style line 4 linecolor rgb "#e0f3f8" lt 1

set datafile separator ","

plot '../opt_files/opt.stats' using 2:3:xtic(1) title "Backwards Pass" ls 1,\
     '' using 4:5 ti "Both Passes" ls 2,\
     '' using 6:7 ti "Preprune" ls 3
     