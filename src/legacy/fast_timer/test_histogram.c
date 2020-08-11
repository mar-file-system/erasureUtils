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


#include <stdio.h>
#include <stdint.h>
#include <unistd.h>             // sleep()
#include <string.h>
#include <errno.h>

#include "fast_timer.h"


int main(int argc, char* argv[]) {

   int       i;

   LogHisto  hist;
   log_histo_reset(&hist);

   FastTimer demo;
   fast_timer_inits();
   fast_timer_reset(&demo);


   // add some synthetic durations to the histogram.

#  define HISTO(TYPE, CONST)                                            \
   do { uint64_t c = (uint64_t)(CONST);                                 \
      demo.start.v64 = 0;   /* for TYPE = interval */                   \
      demo.stop.v64 = c;    /* for TYPE = interval */                   \
      demo.accum = c;       /* for TYPE = accum */                      \
      int bin = log_histo_add_##TYPE(&hist, &demo);                     \
      printf("adding fake histogram %8s with duration: 0x%016lx  -> bin[%2d]\n", #TYPE, c, bin); \
   } while (0)

   //                0123456701234567
   HISTO(interval, 0x8000000000000000);
   HISTO(interval, 0x4000000000000000);

   HISTO(interval, 0x0000000100000000);
   HISTO(interval, 0x0000000100000001);
   HISTO(interval, 0x00000001ffffffff);
   HISTO(interval, 0x00000000ffffffff);

   HISTO(interval, 0x0000000000000001);
   HISTO(interval, 0x0000000000000000);
   printf("\n");

   HISTO(accum,    0x0000000000010000);
   HISTO(accum,    0x0000000000010101);
   HISTO(accum,    0x0000000000018000);
   HISTO(accum,    0x0000000000011111);
   printf("\n");




   // show histogram bin contents
   printf("histogram bins (most-significant first):\n");
   log_histo_show(&hist, 0, NULL, 0);

   printf("as raw numbers:\n");
   log_histo_show(&hist, 1, NULL, 0);
   printf("\n");

   // show the time-intervals represented by histogram bins
   printf("bin[%2d]:  0x%016lx      = %16.06lf sec\n", 0, 0, 0.f);

   demo.accum = 1;
   for (i=0; i<64; ++i) {
      double sec  = fast_timer_sec(&demo);
      double usec = fast_timer_usec(&demo);
      double nsec = fast_timer_nsec(&demo);

      printf("bin[%2d]:  0x%016lx      < %16.06lf sec", i+1, demo.accum, sec);

      if (usec < 1000.f)
         printf("   %10.06lf usec", usec);

      if (nsec < 1000.f)
         printf("   %10.06lf ns", nsec);

      printf("\n");

      demo.accum <<= 1;
   }
}
