
#ifndef __TIMING_H__
#define __TIMING_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
Copyright (c) 2015, Los Alamos National Security, LLC
All rights reserved.

Copyright 2015.  Los Alamos National Security, LLC. This software was produced
under U.S. Government contract DE-AC52-06NA25396 for Los Alamos National
Laboratory (LANL), which is operated by Los Alamos National Security, LLC for
the U.S. Department of Energy. The U.S. Government has rights to use, reproduce,
and distribute this software.  NEITHER THE GOVERNMENT NOR LOS ALAMOS NATIONAL
SECURITY, LLC MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY
FOR THE USE OF THIS SOFTWARE.  If software is modified to produce derivative
works, such modified software should be clearly marked, so as not to confuse it
with the version available from LANL.
 
Additionally, redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.
3. Neither the name of Los Alamos National Security, LLC, Los Alamos National
Laboratory, LANL, the U.S. Government, nor the names of its contributors may be
used to endorse or promote products derived from this software without specific
prior written permission.

THIS SOFTWARE IS PROVIDED BY LOS ALAMOS NATIONAL SECURITY, LLC AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL LOS ALAMOS NATIONAL SECURITY, LLC OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-----
NOTE:
-----
Although these files reside in a seperate repository, they fall under the MarFS copyright and license.

MarFS is released under the BSD license.

MarFS was reviewed and released by LANL under Los Alamos Computer Code identifier:
LA-CC-15-039.

These erasure utilites make use of the Intel Intelligent Storage
Acceleration Library (Intel ISA-L), which can be found at
https://github.com/01org/isa-l and is under its own license.

MarFS uses libaws4c for Amazon S3 object communication. The original version
is at https://aws.amazon.com/code/Amazon-S3/2601 and under the LGPL license.
LANL added functionality to the original work. The original work plus
LANL contributions is found at https://github.com/jti-lanl/aws4c.

GNU licenses can be found at http://www.gnu.org/licenses/.
*/


// (co-maintain help message in libneTest)
// (co-maintain timing_flag_name() in erasure.c)
typedef enum {
   TF_OPEN    =  0x0001,
   TF_RW      =  0x0002,    /* each individual read/write, in given stream */
   TF_CLOSE   =  0x0004,    /* cost of close */
   TF_RENAME  =  0x0008,
   TF_STAT    =  0x0010,
   TF_XATTR   =  0x0020,
   TF_CRC     =  0x0040,
   TF_THREAD  =  0x0080,    /* from beginning to end  */

   TF_ERASURE =  0x0100,    /* single-thread */
   TF_HANDLE  =  0x0200,    /* from start to stop, all threads, in 1 handle */
   TF_SIMPLE  =  0x0400,    /* diagnostic output uses terse numeric formats */

   // TF_GLOBAL  =  0x0800,    /* cost across all handles */
} TimingFlags;

typedef  uint16_t  TimingFlagsValue;

const char* timing_flag_name(TimingFlags flags);


// One struct for each channel.  Each stat corresponds with a TimingFlag.
// A channel that is opened O_WRONLY still does "reads" to fill its buffers.
#include "fast_timer/fast_timer.h"
typedef struct {
   FastTimer   thread;
   FastTimer   open;
   LogHisto    open_h;

   FastTimer   read;
   LogHisto    read_h;

   FastTimer   write;
   LogHisto    write_h;

   FastTimer   close;
   LogHisto    close_h;

   FastTimer   rename;
   FastTimer   stat;
   FastTimer   xattr;

   FastTimer   crc;
   LogHisto    crc_h;
} BenchStats;



// The TimingData in ne_handle can be superseded by an alternative, for
// use by pftool, to accumulate data across multiple handles, over time.

typedef struct {
   TimingFlags    flags;
   int            pod_id;            /* pod-number for this set of stats */
   int            blk_count;         /* (fka "total_blk") */
   int            event_count;       /* number of accum events, so we can compute average */

   FastTimer      handle_timer;      /* from pre-open to post-close, all threads complete */
   FastTimer      erasure;           /* single-threaded, across all blocks */
   LogHisto       erasure_h;
   LogHisto       misc_h;            /* handle-less ops (e.g. unlink) */

   BenchStats     agg_stats;         /* aggregated across "threads", O_RDONLY */
   BenchStats     stats[ MAXPARTS ]; /* ops w/in each thread */
} TimingData;


// insert/extract the useful portion of TimingStats to/from buffer
// (e.g. for transport via MPI)
ssize_t export_timing_data(TimingData* const timing_data, char*       buffer, size_t buf_size);
int     import_timing_data(TimingData*       timing_data, char* const buffer, size_t buf_size);
int     accumulate_timing_data(TimingData* dest, TimingData* src);
int     print_timing_data(TimingData* timing_data, const char* header, int avg, int use_syslog);


#ifdef __cplusplus
}
#endif


#endif

