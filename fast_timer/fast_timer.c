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





// see: https://www.ccsl.carleton.ca/~jamuir/rdtscpm1.pdf
// see: https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf

#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "fast_timer.h"




#ifdef __GNUC__
#  define likely(x)      __builtin_expect(!!(x), 1)
#  define unlikely(x)    __builtin_expect(!!(x), 0)
#else
#  define likely(x)      (x)
#  define unlikely(x)    (x)
#endif



// having problems with <cpuid.h> ...
#  define __cpuid(level, a, b, c, d)                          \
   __asm__ volatile("cpuid\n\t"                               \
                    : "=a" (a), "=b" (b), "=c" (c), "=d" (d)  \
                    : "0" (level))

#  define CHAR_OR_DOT(CH)                       \
   (isprint(CH) ? (CH) : '.')

#  define REV(reg)                       \
   printf("|%c%c%c%c",                   \
          CHAR_OR_DOT(reg & 0xff),       \
          CHAR_OR_DOT((reg>>8) & 0xff),  \
          CHAR_OR_DOT((reg>>16) & 0xff), \
          CHAR_OR_DOT((reg>>24) & 0xff))


#   define K   1000.f
#   define M   1000000.f
#   define G   1000000000.f


int show_cpuid() {

   int a, b, c, d;              // eax, ebx, ecx, edx

   int i;
   for (i=0; i<0x17; ++i) {
      __cpuid(i, a, b, c, d);
      printf("cpuid[%02x]: a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x\n", i, a, b, c, d);
   }

   // for levels 0x8000002, 0x8000003, 0x8000004,
   // the results in registers eax, ebx, ecx, edx are characters in (effing) little
   // endian order, forming a string we can parse to find the (nominal) CPU frequency.
   printf("\n");
   for (i=0x80000000; i<0x80000008; ++i) {
      __cpuid(i, a, b, c, d);
      printf("cpuid[%02x]: a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x   ", i, a, b, c, d);
      REV(a); REV(b); REV(c); REV(d);
      printf("|  (reversed w/in each word)\n");
   }

   return  0;
}


static volatile double ticks_per_sec = -1;
       volatile int    invariant_TSC = 0;

// lock for access to reap_list[] elements
pthread_mutex_t init_mtx = PTHREAD_MUTEX_INITIALIZER;


// call this before calling fast_timer_*sec().
//
// Initializes ticks_per_sec.  Returns 0 for success, negative for failure.
//
// TBD: Check cpuid output for info on whether CPU supports consistent
//      clock rate.  This is the modern default, but we're just assuming,
//      for now.

int fast_timer_inits() {

   int a, b, c, d;              // eax, ebx, ecx, edx

   if (likely(ticks_per_sec > 0))
      return 0;                 // already initialized

   // test proc brand-string supported
   __cpuid(0x80000000, a, b, c, d);
   if (! (a & 0x80000000)
       || (a < 0x80000004)) {
      fprintf(stderr, "no proc-brand string!\n");
      return -1;
   }

   // parse funky reversed-order chars
   //
   // NOTE: Our goal is to turn this number into a divisor such that TSC
   //       intervals can always be rendered in common units (e.g. nsec).
   //       The results from cpuid are just telling us the rate at which
   //       TSC increments the clock.  (Alternatively, we could save the
   //       letter used in cpuid info, and show everything in that unit.)
   //      
   __cpuid(0x80000004, a, b, c, d);
   float mult = 1;
   switch (d & 0xff) {
   case 'M': mult = M;   break;
   case 'G': mult = G;   break;
   default:
      fprintf(stderr, "couldn't find multiplier in '%c'\n", d & 0xff);
      return -1;
   }
   //   printf("multiplier: '%c'\n", d & 0xff);


   char str[] = { (char)(c       & 0xff),
                  (char)((c>>8)  & 0xff),
                  (char)((c>>16) & 0xff),
                  (char)((c>>24) & 0xff),
                  0 };
   //   printf("str:    '%s'\n", (char*)str);

   float normed;
   sscanf(str, "%f", &normed);
   //   printf("normed: %f\n", normed);

   // just locking around the updates means we allow a race for
   // hypothetical different threads to do updates with their
   // own values, but they are likely to compute similar
   // values, and any future threads will avoid the problem
   // because fast_timer_inits() will see that ticks_per_sec
   // already has a value.

   pthread_mutex_lock(&init_mtx);

   // --- set the static value, used in fast_timer_sec(), etc
   ticks_per_sec = normed * mult;
   //   printf("freq:   %f\n", ticks_per_sec);

   // --- "invariant TSC" means thread-migration across cores do not make
   //     the TSC invalid.  (Also means the rate
   __cpuid(0x80000007, a, b, c, d);
   invariant_TSC = (d & 0x100) >> 8;

   pthread_mutex_unlock(&init_mtx);


#ifndef ALLOW_VARIABLE_TSC
   if (! invariant_TSC) {
      fprintf(stderr, "This processor doesn't have an 'invariant' TSC.\n");
      exit(-1);                 // see fast_timer_stop()
   }
#endif

   return 0;
}





// convert the value in ft->accum to seconds or nsec

double fast_timer_sec(FastTimer* ft) {
   return ((double)ft->accum / ticks_per_sec);
}
double fast_timer_msec(FastTimer* ft) {
   return ((double)ft->accum / ticks_per_sec) * K;
}
double fast_timer_usec(FastTimer* ft) {
   return ((double)ft->accum / ticks_per_sec) * M;
}
double fast_timer_nsec(FastTimer* ft) {
   return ((double)ft->accum / ticks_per_sec) * G;
}



int fast_timer_show(FastTimer* ft, int simple, const char* str) {
   const char* str1 = ((str) ? str : "");

   if (simple) {
      printf("%s%7.5f sec\n",  str1, fast_timer_sec(ft));
      return 0;
   }
   
   printf("%s\n", str1);
   printf("  start:   %016lx\n", ft->start);
   printf("  stop:    %016lx\n", ft->stop);

   printf("  accum:   %016lx", ft->accum);
   if (ft->migrations)
      printf("  (%d)", ft->migrations);
   printf("\n");

   //   // resolve into nearset units
   //   const char* units[] = { "ns", "us", "ms", NULL };
   //   double      ticks   = fast_timer_nsec(ft);
   //
   //   int i;
   //   for (i=0; (units[i] && ticks > 1000.0); ++i) {
   //      ticks /= 1000.0;
   //   }
   //   printf("  elapsed: %7.5f  %s\n", ticks, (units[i] ? units[i] : "sec"));

   printf("  elapsed: ");
   printf("%7.5f sec, ", fast_timer_sec(ft));
   printf("%7.5f usec, ", fast_timer_usec(ft));
   printf("%7.5f nsec\n", fast_timer_nsec(ft));

   return 0;
}

int fast_timer_show_details(FastTimer* ft, const char* str) {
   if (str)
      printf("%s\n", str);

   printf("  chip:    %d\n", ft->chip);
   printf("  core:    %d\n", ft->core);
   printf("  migr:    %u\n", ft->migrations);
   printf("  ticks/s: %6.2f\n", ticks_per_sec);
   printf("  CPU:     %5.3f GHz\n", ticks_per_sec / G);
   printf("\n");

   return 0;
}





// ---------------------------------------------------------------------------
// log-histogram
// ---------------------------------------------------------------------------

int log_histo_reset(LogHisto* hist) {
   memset(hist, 0, sizeof(LogHisto));
   return 0;
}



// print out the contents of a log-histo.
//
// <pretty> aims for somewhat more human-readability.  Non-pretty could
// be handy for generating datasets for visualization, etc.
//
//
// NOTE: 65 bins.  bin[0] is special, then there are bins for each bit in
//    the 64-bit timer.
//
// NOTE: As noted in fast_timer.c:
//
//    bin[i] represents timer with highest-order bit = 2^(i-1),
//    bin[0] represents timer with all-zeros (or error).
//
//    Thus, the bins are "little endian".
//
//    However, we're printing them out in big-endian order (i.e. bin[64] first).
//    Thus, the display shows bins in order descending by significance.

int log_histo_show(LogHisto* hist, int simple, const char* str) {
   int i;
   const char* str1 = ((str) ? str : "");

   printf(str1);
   if (!simple)
      printf("\n\t");

   for (i=0; i<65; ++i) {

      // spacing and newlines
      if (i && !(i%4))
         printf("  ");
      if ((i && !(i%16)) && (! simple))
         printf("\n\t");

      if ((hist->bin[64 - i]) || simple)
         printf("%2d ", hist->bin[64 - i]);
      else
         printf("-- ");
   }
   printf("\n");

   if (! simple)
      printf("\n");
}
