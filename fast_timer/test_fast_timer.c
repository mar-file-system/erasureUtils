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
MarFS is released under the BSD license.

MarFS was reviewed and released by LANL under Los Alamos Computer Code identifier:
LA-CC-15-039.

MarFS uses libaws4c for Amazon S3 object communication. The original version
is at https://aws.amazon.com/code/Amazon-S3/2601 and under the LGPL license.
LANL added functionality to the original work. The original work plus
LANL contributions is found at https://github.com/jti-lanl/aws4c.

GNU licenses can be found at http://www.gnu.org/licenses/.
*/


// During the sleep phase, run a short build (with e.g. '-j 8'), to
// increase the likelihood of a thread migration.

// see: https://www.ccsl.carleton.ca/~jamuir/rdtscpm1.pdf
// see: https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>             // sleep()
#include <string.h>
#include <errno.h>

#include "fast_timer.h"


int main(int argc, char* argv[]) {

   // show cpuid info, if there was a command-line arg
   if (argc > 1) {
      printf("\n");
      show_cpuid();
      printf("\n");
   }


   // timers, etc
   const int sleep_sec = 5;
   const int no_op_ct  = 1000000;

   LogHisto  hist;

   log_histo_reset(&hist);


   FastTimer overall;
   FastTimer timer;
   FastTimer no_ops;

   fast_timer_inits();

   fast_timer_reset(&overall);
   fast_timer_reset(&timer);
   fast_timer_reset(&no_ops);


   // perform various timings
   fast_timer_start(&overall);
   printf("\n");





   // time each of five 1-second sleeps
   printf("performing %d 1-second sleeps\n", sleep_sec);
   int i;
   for (i=0; i<sleep_sec; ++i) {
      fast_timer_start(&timer);
      sleep(1);
      fast_timer_stop(&timer);

      // record duration of this interval.
      log_histo_add_interval(&hist, &timer);
   }

   // show stats
   fast_timer_show(&timer, "-- loop with sleeps");
   printf("\n");

   fast_timer_show_details(&timer, NULL);
   printf("\n");

   // show log-histogram bins
   // (run test_histogram, to show details of bin-values, etc)
   printf("histogram bins (most-significant first):\n");
   log_histo_show_bins(&hist, NULL);
   printf("\n");




   // measure the cost of timer start/stop operations
   printf("performing %d empty timer start/stops\n", no_op_ct);
   for (i=0; i<no_op_ct; ++i) {
      fast_timer_start(&no_ops);
      fast_timer_stop(&no_ops);
   }

   // show stats
   fast_timer_show(&no_ops, "-- loop with empty start/stops");
   printf("\n");

   fast_timer_show_details(&timer, NULL);
   printf("  * avg cost of timer start + stop: %5.3f nsec\n",
          fast_timer_nsec(&no_ops) / (double)no_op_ct);
   printf("\n");
   printf("\n");




   // Q: is it any faster to fuse stop and start?
   // A: No.
   printf("performing %d empty timer fused-start/stops\n", no_op_ct);
   fast_timer_reset(&no_ops);
   fast_timer_start(&no_ops);
   for (i=0; i<no_op_ct; ++i) {
      fast_timer_stop_start(&no_ops);
   }
   fast_timer_stop(&no_ops);

   // show stats
   fast_timer_show(&no_ops, "-- loop with empty fused-start/stops");
   printf("\n");

   fast_timer_show_details(&timer, NULL);
   printf("  * avg cost of timer fused start + stop: %5.3f nsec\n",
          fast_timer_nsec(&no_ops) / (double)no_op_ct);
   printf("\n");
   printf("\n");




   // measure cost of histogram inserts
   fast_timer_reset(&no_ops);
   log_histo_reset(&hist);

   // NOTE: with 16-bit bins, this will overflow,
   //       but we're just interested in performance.
   fast_timer_start(&no_ops);
   for (i=0; i<no_op_ct; ++i) {
      log_histo_add_interval(&hist, &timer);
   }
   fast_timer_stop(&no_ops);

   // show stats
   fast_timer_show(&no_ops, "-- loop with empty log-histogram inserts");
   printf("\n");

   fast_timer_show_details(&no_ops, NULL);
   printf("  * avg cost of log-histo insert: %5.3f nsec\n",
          fast_timer_nsec(&no_ops) / (double)no_op_ct);
   printf("\n");
   printf("\n");







   // overall timing for this entire test
   fast_timer_stop(&overall);

   // show stats
   fast_timer_show(&overall, "-- overall (including printing)");
   printf("\n");
   fast_timer_show_details(&timer, NULL);
   printf("\n");
}
