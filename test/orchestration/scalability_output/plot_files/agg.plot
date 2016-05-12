reset
fontsize = 20
set term postscript enhanced eps fontsize
set output "../output_graphs/output_agg.eps"
set style fill solid 1.00 border 0
#set style histogram errorbars gap 1 lw 1
#set style histogram gap 1
#set style data histogram
#set xtics rotate by -45 
#set xtics font "Times-Roman, 20" 
#set ytics font "Times-Roman, 18" 
set grid ytics
set xtics
set xlabel "Number of Cores" 
set ylabel "Normalized Speedup"offset 2
set xrange [1:128]
#set yrange [0:*]
#set yrange [0:45]
#set boxwidth 1
set key Left
set log

#set offset -.5, -.5, 0, 0

set datafile separator "," 
set style line 1 linecolor rgb "#1b9e77" lt 1
set style line 2 linecolor rgb "#d95f02" lt 1
set style line 3 linecolor rgb "#7570b3" lt 1
set style line 4 linecolor rgb "#e7298a" lt 1
set style line 5 linecolor rgb "#66a61e" lt 1
set style line 6 linecolor rgb "#66a61e" lt 1
set style line 7 linecolor rgb "#a6761d" lt 1


plot    "../agg_norm_files/firefox.final.results.seqppl.streamls.norm.stats" title 'firefox' with linespoints ls 1, \
	"../agg_norm_files/firefoxlonger.final.results.seqppl.streamls.norm.stats" title 'firefox' with linespoints ls 2, \
        "../agg_norm_files/gzip.final.results.seqppl.streamls.norm.stats" title 'gzip' with linespoints ls 3, \
	"../agg_norm_files/openoffice.final.results.seqppl.streamls.norm.stats" title 'openoffice' with linespoints ls 4, \
        "../agg_norm_files/gs.final.results.seqppl.streamls.norm.stats" title 'gs' with linespoints ls 5, \
        "../agg_norm_files/nginx.final.results.seqppl.streamls.norm.stats" title 'nginxp' with linespoints ls 6, \
        "../agg_norm_files/evince.final.results.seqppl.streamls.norm.stats" title 'evince' with linespoints ls 7, \
        "../agg_norm_files/evince.final.results.seqppl.streamls.norm.stats" using 1:1 title "linear scaling" with lines


#        "../agg_norm_files/mongo.final.results.seqppl.streamls.norm.stats" title 'mongo' with linespoints , \
#        "../agg_norm_files/mongolonger.final.results.seqppl.streamls.norm.stats" title 'mongo' with linespoints , \
