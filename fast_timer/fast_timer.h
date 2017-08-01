#ifndef __MARFS_FAST_TIMER_H__
#define __MARFS_FAST_TIMER_H__

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



// NOTE: The TSC ticks at the "nominal" processor frequency (i.e. the
// default freq, not counting changes in the actual processor freq
// resulting from idling or turbo, etc.)  As wikipedia puts it: "TSC ticks
// are counting the passage of time, not the number of CPU clock cycles",
// which is perfect for us.
//
// However, older CPUs allow the TSC to vary, e.g. following clockrate
// changes as the CPU throttles back to control temperature.  On those
// CPUs, the TSC can not be relied on to measure time.  Additionally,
// thread migrations across cores move to an incompatible TSC.  Newer
// models have an "invariant" TSC, which obviate both of these issues.  We
// do not currently define ALLOW_VARIABLE_TSC.
//
// Currently, fast_timer_init() will abort, if it discovers we're running
// on a non-invariant TSC. In that case, ALLOW_VARIABLE_TSC will accomodate
// these issues, at the cost of some efficiency.
//
// Meanwhile, on an invariant TSC, it is apparently safe to assume that all cores
// have sychronized TSCs, unless it's possible that someone has executed a WRMSR
// instruction to change that.



#include <string.h>             // memset()
#include <stdlib.h>

#ifdef __GNUC__
#  define ft_likely(x)      __builtin_expect(!!(x), 1)
#  define ft_unlikely(x)    __builtin_expect(!!(x), 0)
#else
#  define ft_likely(x)      (x)
#  define ft_unlikely(x)    (x)
#endif



// indices for TimerValue.v32[] elements
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define LO  0
#  define HI  1
#else
#  define LO  1
#  define HI  0
#endif


typedef union {
   uint64_t v64;
   uint32_t v32[2];             /* see HI/LO */
} TimerValue;

typedef struct {
   int            chip;         /* CPU chip on which timer was started */
   int            core;         /* CPU core "  "     "     "   "       */
   TimerValue     start;
   TimerValue     stop;
   uint32_t       migrations;   /* n chip/core migrations during timing */
   uint32_t       MHz;          /* nominal CPU freq (see NOTE above) */
   uint64_t       accum;
} FastTimer;


// debugging
int show_cpuid();


extern int invariant_TSC;

// call this once, before any threads try to call fast_timer_sec().
// Returns 0 for success, negative for failure.
int fast_timer_inits();



// You must do this before using a given timer.  Do it again, anytime the
// timer is not running, to reset the accumulator, and the migrations-count

static __attribute__((always_inline)) inline
int fast_timer_reset(FastTimer* ft) {
   memset(ft, 0, sizeof(FastTimer));
}

static __attribute__((always_inline)) inline
int fast_timer_start(FastTimer* ft) {
   unsigned long int x;
   unsigned a, d, c;

#ifdef ALLOW_VARIABLE_TSC
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

static __attribute__((always_inline)) inline
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

   // This code path has been tested; chip/core migrations are detected,
   // loghisto functions ignore them, etc.
   // 
#ifdef ALLOW_VARIABLE_TSC
   if (ft_unlikely((invariant_TSC == 0)
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

static __attribute__((always_inline)) inline
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

   if (ft_unlikely((chip != ft->chip)
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



// convert the TSC ticks in ft->accum to elapsed time
double fast_timer_sec(FastTimer* ft);
double fast_timer_usec(FastTimer* ft);
double fast_timer_nsec(FastTimer* ft);


// print timer stats
int fast_timer_show(FastTimer* ft, const char* str);
int fast_timer_show_details(FastTimer* ft, const char* str);




// ---------------------------------------------------------------------------
// LogHisto
//
// To allow speedy collection of diagnostics, we support maintenance of
// "log-scaled histograms".  The idea is that you take a (64-bit) timer
// value, effeciently round it up to the highest power-of-two, and add 1 to
// the bin corresponding to that bit-position.
//
// Because it may incur some cost to update the bins (vector load/store),
// and many of the low-order bits represent time-scales the might not be
// expected to be relevant, we can reduce the total size ofthe vector of
// bins by shifting out some of the least-significant bits in accumulated
// timer values, and mask off some of the remaining most-significant bits.
// ---------------------------------------------------------------------------

// #ifdef __SSE2__
// #  include <x86intrin.h>
//#endif

// bin[0] holds number of events where timer->accum == 0    [e.g. migration event]
// bin[1] holds number of events where timer->accum <  0x00...01
// bin[2] holds number of events where timer->accum <  0x00...02  (and >= 0x00...01)
// bin[3] holds number of events where timer->accum <  0x00...04  (and >= 0x00...02)
// etc ...

typedef struct {
   // __m128i      bin[6];        // 48 16-bit bins
   uint16_t        bin[65];     // bin[0] special + 64 bins representing timer-bits
} LogHisto;


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
static __attribute__((always_inline)) inline
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


// increment the bin matching the current timer interval
// NOTE: This is (ft->stop - ft->start), not the accumulator.
static __attribute__((always_inline)) inline
int log_histo_add_interval(LogHisto* hist, FastTimer* ft) {
   return log_histo_add_value(hist, (ft->stop.v64 - ft->start.v64));
}



// increment the bin corresponding to ft->accum.
// (e.g. if multiple intervals were required to accumulate the quantity to be binned)
static __attribute__((always_inline)) inline
int log_histo_add_accum(LogHisto* hist, FastTimer* ft) {
   return log_histo_add_value(hist, ft->accum);
}


// accumulate counts from one histo into another.
// dest += src
// TBD: Drop LogHisto to 64 elements, aligned appropriately, and do this with SIMD intrinsics.
static __attribute__((always_inline)) inline
int log_histo_add(LogHisto* dest, LogHisto* src) {
   int i;
   for (i=0; i<65; ++i) {
      dest->bin[i] += src->bin[i];
   }
   return 0;
}



int log_histo_show_bins(LogHisto* hist, const char* str);



#endif
