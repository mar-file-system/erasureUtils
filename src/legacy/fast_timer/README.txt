When configured to do so, we gather some statistics during storage
accesses, in a low-impact way.  We currently gather statistics only within
each opened file-handle.  Some stats (handle, erasure) apply to the handle
as a whole, and others (open, close, read, write) may be gathered for each
thread in the handle.  In the case of

(1) configure for collection (and printing) of statistics.  This is crude:

    $ ./configure --enable-stats=0xff ...
    $ make clean
    $ make
    $ make install


(2) Gather stats over multiple runs of libneTest, something like this:

    $ for i in `seq 0 31`; do
         libneTest write foo.rand.1G /nfs/pod0/block%d/cap0/testing/foo.rand.1G.nfs 10 2 0 > foo.stats.write.1G.nfs.$i
      done


(3) You can get a detailed overview of those runs, something like so:

    $ fast_timer/extract_stats.overview 32 foo.stats.write.1G.nfs



(4) for per-thread collected stats (currently: thread, open, close, read,
    write, rename), you can generate a "heat-map" like this:

    $ for op in open read write close; do
         fast_timer/heat_map 32 foo.stats.write.1G.nfs $op | gnuplot fast_timer/heat_map.gnuplot
      done


    This will generate the following visualized results:

       foo.stats.write.1G.nfs.OPEN.jpg
       foo.stats.write.1G.nfs.READ.jpg
       foo.stats.write.1G.nfs.WRITE.jpg
       foo.stats.write.1G.nfs.CLOSE.jpg

    NOTE: even writes to object-storage have a "read" component, where they
    are reading the data to be written to storage.  Similarly, reads from
    object storage have a "write" component.

