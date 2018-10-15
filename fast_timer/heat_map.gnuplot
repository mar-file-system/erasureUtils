# see fast_timer/README.txt
#
# NOTE: '<cat' reads data from stdin


set title "`cat foo.fname`\ncost (in sec) of `cat foo.op` for 10+2 write-threads, across `cat foo.count` runs, moving 1 GB/run"
set ylabel "run"
set xlabel "block-number (thread)"

set key off
set xtics 1
set ytics 2

# plot [-0.5:11.5] [-0.5:30.5] '<cat' using 4:2:6 with image

set term jpeg size 1024,768
set output "`cat foo.fname`.heat.`cat foo.op`.jpg"
plot [-0.5:11.5] [-0.5:30.5] '<cat' using 4:2:6 with image
