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


static double ticks_per_sec = -1;
static int    invariant_TSC = 0;

// call this once, from a single-thread, before any threads try to call
// fast_timer_sec().  Initializes ticks_per_sec.  Returns 0 for success,
// negative for failure.

// TBD: Check cpuid output for info on whether CPU supports consistent clock rate.
//      This is the modern default, but we're just assuming, for now.
int fast_timer_inits() {

   int a, b, c, d;              // eax, ebx, ecx, edx

   if (ticks_per_sec > 0)
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

   // --- set the static value, used in fast_timer_sec(), etc
   ticks_per_sec = normed * mult;
   //   printf("freq:   %f\n", ticks_per_sec);



   // --- "invariant TSC" means thread-migration across cores do not make
   //     the TSC invalid.  (Also means the rate
   __cpuid(0x80000007, a, b, c, d);
   invariant_TSC = (d & 0x100) >> 8;

   if (! invariant_TSC) {
      fprintf(stderr, "This processor doesn't have an 'invariant' TSC.\n");
      exit(-1);                 // see fast_timer_stop()
   }


   return 0;
}



// reset a specific timer.

__attribute__((always_inline))
int fast_timer_reset(FastTimer* ft) {
   memset(ft, 0, sizeof(FastTimer));
}

__attribute__((always_inline))
int fast_timer_start(FastTimer* ft) {
   unsigned long int x;
   unsigned a, d, c;

#ifdef MAYBE_TSC_NOT_INVARIANT
   // note current chip/core
   // https://software.intel.com/en-us/forums/intel-open-source-openmp-runtime-library/topic/507598
   //   __asm__ volatile("rdtscp"
   //                    : "=a" (a), "=d" (d), "=c" (c));
   __asm__ volatile("rdtscp"
                    : "=c" (c));

   ft->chip = (c & 0xFFF000)>>12;
   ft->core = c & 0xFFF;
#endif

   asm volatile("CPUID\n"
                "RDTSC\n"
                "mov %%edx, %0\n"
                "mov %%eax, %1\n"
                : "=r" (ft->start.v32[HI]),
                  "=r" (ft->start.v32[LO])
                :: "%rax", "%rbx", "%rcx", "%rdx");

   // printf("strt: %llx = %08lx %08lx\n", ft->start.v64, ft->start.v32[HI], ft->start.v32[LO]);
   return 0;
}


// if chip/core has changed during the interval between start and stop, the
// TSC difference won't be meaningful.  In this case we record a
// "migration" but the elapsed time is not added into the accumulator.

__attribute__((always_inline))
int fast_timer_stop(FastTimer* ft) {
   int a, d, c;

   asm volatile("RDTSCP\n"
                "mov %%edx, %0\n"
                "mov %%eax, %1\n"
                "mov %%ecx, %2\n"
                "CPUID\n"
                :  "=r" (ft->stop.v32[HI]), "=r" (ft->stop.v32[LO]), "=r" (c)
                :: "%rax", "%rbx", "%rcx", "%rdx");

   int chip = (c & 0xFFF000)>>12;
   int core = c & 0xFFF;

   // The current code never defines this.  We assume invariant TSC.
   // Currently, fast_timer_init() will abort, if it discovers we're
   // running on a non-invariant TSC.  This code path has been tested;
   // chip/core migrations are detected, histo ignores them, etc.
   // 
#ifdef MAYBE_TSC_NOT_INVARIANT
   if (unlikely((invariant_TSC == 0)
                && ((chip != ft->chip)
                    || (core != ft->core)))) {

      ++ ft->migrations;
      ft->chip = chip;
      ft->core = core;

      ft->stop.v64 = ft->start.v64; /* so LogHisto sees elapsed == 0 */
      return -1;
   }
#endif

   // printf("stop: %llx = %08lx %08lx\n", stop.v64, stop.v32[HI], stop.v32[LO]);
   ft->accum += ft->stop.v64 - ft->start.v64;
   return 0;
}



// stop previous interval, and begin a new one

__attribute__((always_inline))
int fast_timer_stop_start(FastTimer* ft) {
   int a, d, c;

   asm volatile("RDTSCP\n"
                "mov %%edx, %0\n"
                "mov %%eax, %1\n"
                "mov %%ecx, %2\n"
                "CPUID\n"
                "RDTSCP\n"
                "mov %%edx, %3\n"
                "mov %%eax, %4\n"
                :  "=r" (ft->stop.v32[HI]), "=r" (ft->stop.v32[LO]),
                   "=r" (c),
                   "=r" (d), "=r" (a)
                :: "%rax", "%rbx", "%rcx", "%rdx");

   int chip = (c & 0xFFF000)>>12;
   int core = c & 0xFFF;

   if (unlikely((chip != ft->chip)
                || (core != ft->core))) {

      ++ ft->migrations;
      ft->chip = chip;
      ft->core = core;

      ft->stop.v64 = ft->start.v64; /* so LogHisto sees elapsed == 0 */
      return -1;
   }

   // printf("stop: %llx = %08lx %08lx\n", stop.v64, stop.v32[HI], stop.v32[LO]);
   ft->accum += ft->stop.v64 - ft->start.v64;

   /* start next iteration */
   ft->start.v32[HI] = d;
   ft->start.v32[LO] = a;

   return 0;
}


// convert the value in ft->accum to seconds or nsec

double fast_timer_sec(FastTimer* ft) {
   return ((double)ft->accum / ticks_per_sec);
}
double fast_timer_usec(FastTimer* ft) {
   return ((double)ft->accum / ticks_per_sec) * M;
}
double fast_timer_nsec(FastTimer* ft) {
   return ((double)ft->accum / ticks_per_sec) * G;
}


int fast_timer_show(FastTimer* ft, const char* str) {
   if (str)
      printf("%s\n", str);

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


// Add a tick to the bin matching the timer-accumulator.  Each bin
// represents all values between two adjascent powers of 2.
//
//   bin[0] counts timer values that are exactly zero
//
//          These are special because they may represent the special case
//          where an interval was thrown out, e.g. due to a core
//          migration).
//
//   bin[n] counts timer-values in the range [ 2^(n-1), 2^n )
//
//          The remaining bin-numbers 1 through 64 match the
//          most-significant-bit (1-based) of the timer-values that are
//          counted there.
//
//
// NOTE: In the event of a migration, the FT accumulator is unchanged.
//       Such "zero events" are counted in bin 0
//
// NOTE: We don't change the timer accumulator.  We just look at the duration
//       of the most-recent fast_timer_stop() - faster_timer_start().
//
__attribute__((always_inline))
int log_histo_add_value(LogHisto* hist, uint64_t timer_value) {
   
   int i;

   //   printf(" value:     %016lx\n", timer_value);

#if 0
   // assert all bits below the highest-order asserted bit 
   uint64_t mask  = timer_value;
   int      shift = 1;
   for (i=0; i<6; ++i) {
      mask |= mask >> shift;
      printf(" mask[%d]:   %016lx\n", i, mask);
      shift <<= 1;
   }
   printf(" mask:      %016lx\n", mask);

   // round up to nearest power of 2
   // shift-right so our bin-index will be 0-based
   // do the shift first, so we don't overflow
   // 1-based bit-position is the bin-index
   uint64_t  high_bit = (mask ? ((mask >> 1) +1) : 0);
   printf(" mask>>1:   %016lx\n", (mask >>1));
   printf(" mask>>1)+1 %016lx\n", (mask >>1)+1);
   printf(" high_bit:  %016lx\n", high_bit);
   
   // select histogram bin
   for (i=0; high_bit; ++i) {
      high_bit >>= 1;
   }

   printf(" bin_no:    %d\n", i);
   printf(" bin[%d]:    %hd (before)\n", i, hist->bin[i]);
   hist->bin[i] += 1;
   printf(" bin[%d]:    %hd (after)\n", i, hist->bin[i]);
   printf("\n");

#else
   // (round up to nearest power of 2)
   // find the 1-based bit-position of highest-bit
   // 1-based bit-position is the bin-index
   // select histogram bin
   // TBD: vectorize this, for speed
   uint64_t bit = (uint64_t)1 << 63;
   for (i=64; i; --i) {
      if (timer_value & bit)
         break;
      bit >>= 1;
   }

   //   printf(" bin_no:    %d\n", i);
   //   printf(" bin[%d]:    %hd (before)\n", i, hist->bin[i]);

   hist->bin[i] += 1;

   //   printf(" bin[%d]:    %hd (after)\n", i, hist->bin[i]);
   //   printf("\n");

#endif

   return i;                    /* return bin-number */
}


__attribute__((always_inline))
int log_histo_add_interval(LogHisto* hist, FastTimer* ft) {
   return log_histo_add_value(hist, (ft->stop.v64 - ft->start.v64));
}


__attribute__((always_inline))
int log_histo_add_accum(LogHisto* hist, FastTimer* ft) {
   return log_histo_add_value(hist, ft->accum);
}


// dest += src
// TBD: Drop LogHisto to 64 elements, aligned appropriately, and do this with SIMD intrinsics.
__attribute__((always_inline))
int log_histo_add(LogHisto* dest, LogHisto* src) {
   int i;
   for (i=0; i<65; ++i) {
      dest->bin[i] += src->bin[i];
   }
   return 0;
}



// NOTE: 65 bins.  bin[0] is special, then there are bins for each bit in
//    the 64-bit timer.

int log_histo_show_bins(LogHisto* hist, const char* str) {
   int i;

   if (str)
      printf(str);

   printf("\t");
   for (i=0; i<65; ++i) {
      if (i && !(i%4))
         printf("  ");
      if (i && !(i%16))
         printf("\n\t");

      if (hist->bin[64 - i])
         printf("%2d ", hist->bin[64 - i]);
      else
         printf("-- ");
   }
   printf("\n");
   printf("\n");
}
