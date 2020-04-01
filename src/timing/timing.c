
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



int show_handle_stats(ne_handle handle) {

   TimingData* timing = handle->timing_data_ptr; /* shorthand */

   if (! timing->flags)
      printf("No stats\n");

   else {
      int simple = (timing->flags & TF_SIMPLE);

      fast_timer_show(&timing->handle_timer,  simple, "handle:  ", 0);
      fast_timer_show(&timing->erasure, simple, "erasure: ", 0);
      printf("\n");

      int i;
      int N = handle->erasure_state->N;
      int E = handle->erasure_state->E;
      for (i=0; i<N+E; ++i) {
         printf("\n-- block %d\n", i);

         fast_timer_show(&timing->stats[i].thread, simple, "thread:  ", 0);
         fast_timer_show(&timing->stats[i].open,   simple, "open:    ", 0);

         fast_timer_show(&timing->stats[i].read,   simple, "read:    ", 0);
         log_histo_show(&timing->stats[i].read_h,  simple, "read_h:  ", 0);

         fast_timer_show(&timing->stats[i].write,  simple, "write:   ", 0);
         log_histo_show(&timing->stats[i].write_h, simple, "write_h: ", 0);

         fast_timer_show(&timing->stats[i].close,  simple, "close:   ", 0);
         fast_timer_show(&timing->stats[i].rename, simple, "rename:  ", 0);
         fast_timer_show(&timing->stats[i].stat,   simple, "stat:    ", 0);
         fast_timer_show(&timing->stats[i].xattr,  simple, "xattr:   ", 0);

         fast_timer_show(&timing->stats[i].crc,    simple, "CRC:     ", 0);
         log_histo_show(&timing->stats[i].crc_h,   simple, "CRC_h:   ", 0);
      }
   }

   return 0;
}


// it's an error to give us more than one flag at a time
const char* timing_flag_name(TimingFlags flag) {
   switch (flag) {
   case TF_OPEN:    return "open";
   case TF_RW:      return "rd/wr";
   case TF_CLOSE:   return "close";
   case TF_RENAME:  return "rename";
   case TF_STAT:    return "stat";
   case TF_XATTR:   return "xattr";
   case TF_ERASURE: return "erasure";
   case TF_CRC:     return "crc";
   case TF_THREAD:  return "thread";
   case TF_HANDLE:  return "handle";
   case TF_SIMPLE:  return "simple";
   default:         return "UNKNOWN_TIMING_FLAG";
   }
}


// copy active parts of TimingData into a buffer.  This could be used for
// moving data between MPI ranks.  Note that in this case, there is no need
// to translate the data into network-byte-order, as we can assume that
// both hosts have the same host-byte-order.  We can also assume that they
// are both using the same compiled image of TimingData (so no worries
// about relative struct-member alignment, etc).
//
// return amount of data installed, or -1 if we ran out of room in the buffer.
// 
ssize_t export_timing_data(TimingData* const timing, char* buffer, size_t buf_size)
{
   const size_t header_size = (char*)&timing->agg_stats - (char*)timing;
   char*        buf_ptr     = buffer;
   ssize_t      remain      = buf_size;
   int          flag_count  = 0;

#define PUSH(BUF, DATA, SIZE, REMAIN)           \
   do {                                         \
      if ((SIZE) > REMAIN)                      \
         return -1;                             \
      memcpy(BUF, DATA, (SIZE));                \
      BUF    += (SIZE);                         \
      REMAIN -= (SIZE);                         \
   } while (0)

#define PUSH_STAT(BUF, STAT, SIZE, REMAIN)                              \
   for (i=0; i<timing->blk_count; ++i) {                                \
      PUSH(BUF, (char*)&timing->stats[i].STAT, SIZE, REMAIN);           \
   }                                                                    \

   // copy top-level single values
   PUSH(buf_ptr, (char*)timing, header_size, remain);

   TimingFlagsValue mask;
   for (mask=0x1; mask; mask <<= 1) {
      int i;
      switch (timing->flags & mask) {

      case TF_OPEN:
         PUSH_STAT(buf_ptr, open,   sizeof(FastTimer), remain);
         PUSH_STAT(buf_ptr, open_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_RW:
         PUSH_STAT(buf_ptr, read,   sizeof(FastTimer), remain);
         PUSH_STAT(buf_ptr, read_h, sizeof(LogHisto),  remain);
         ++flag_count;

         PUSH_STAT(buf_ptr, write,   sizeof(FastTimer), remain);
         PUSH_STAT(buf_ptr, write_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_CLOSE:
         PUSH_STAT(buf_ptr, close,   sizeof(FastTimer), remain);
         PUSH_STAT(buf_ptr, close_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_RENAME:
         PUSH_STAT(buf_ptr, rename,  sizeof(FastTimer), remain);
         ++flag_count;
         break;

      case TF_STAT:
         PUSH_STAT(buf_ptr, stat,  sizeof(FastTimer), remain);
         ++flag_count;
         break;

      case TF_XATTR:
         PUSH_STAT(buf_ptr, xattr,  sizeof(FastTimer), remain);
         ++flag_count;
         break;

      case TF_CRC:
         PUSH_STAT(buf_ptr, crc,   sizeof(FastTimer), remain);
         PUSH_STAT(buf_ptr, crc_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_THREAD:
         PUSH_STAT(buf_ptr, thread,   sizeof(FastTimer), remain);
         ++flag_count;
         break;


      case TF_ERASURE:        // not per-thread; already moved at top-level
         break;

      case TF_HANDLE:         // not per-thread; already moved at top-level
         break;

      case TF_SIMPLE:         // meta-flag
         break;
      }
   }

#undef PUSH
#undef PUSH_STAT

   return buf_size - remain;
}


// complement of export_timing_data().  Here we would be on the receiving-side
// of MPI transport, installing values into our TimingData struct.
//
// NOTE: for convenience, we keep this identical to export_timing_data(),
// but we just swap source/destination, by using PULL() instead of PUSH().

int import_timing_data(TimingData* timing, char* const buffer, size_t buf_size)
{
   char*   buf_ptr     = buffer;
   ssize_t remain      = buf_size;
   int     flag_count  = 0;
   size_t  header_size = (char*)&timing->agg_stats - (char*)timing;

#define PULL(BUF, DATA, SIZE, REMAIN)           \
   do {                                         \
      if ((SIZE) > REMAIN)                      \
         return -1;                             \
      memcpy(DATA, BUF, (SIZE));                \
      BUF    += (SIZE);                         \
      REMAIN -= (SIZE);                         \
   } while (0)

#define PULL_STAT(BUF, STAT, SIZE, REMAIN)                              \
   for (i=0; i<timing->blk_count; ++i) {                                \
      PULL(BUF, (char*)&timing->stats[i].STAT, SIZE, REMAIN);           \
   }                                                                    \
   
   // restore top-level single values
   PULL(buf_ptr, (char*)timing, header_size, remain);

   TimingFlagsValue mask;
   for (mask=0x1; mask; mask <<= 1) {

      int i;
      switch (timing->flags & mask) {

      case TF_OPEN:
         PULL_STAT(buf_ptr, open,   sizeof(FastTimer), remain);
         PULL_STAT(buf_ptr, open_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_RW:
         PULL_STAT(buf_ptr, read,   sizeof(FastTimer), remain);
         PULL_STAT(buf_ptr, read_h, sizeof(LogHisto),  remain);
         ++flag_count;

         PULL_STAT(buf_ptr, write,   sizeof(FastTimer), remain);
         PULL_STAT(buf_ptr, write_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_CLOSE:
         PULL_STAT(buf_ptr, close,   sizeof(FastTimer), remain);
         PULL_STAT(buf_ptr, close_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_RENAME:
         PULL_STAT(buf_ptr, rename,  sizeof(FastTimer), remain);
         ++flag_count;
         break;

      case TF_STAT:
         PULL_STAT(buf_ptr, stat,  sizeof(FastTimer), remain);
         ++flag_count;
         break;

      case TF_XATTR:
         PULL_STAT(buf_ptr, xattr,  sizeof(FastTimer), remain);
         ++flag_count;
         break;

      case TF_CRC:
         PULL_STAT(buf_ptr, crc,   sizeof(FastTimer), remain);
         PULL_STAT(buf_ptr, crc_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_THREAD:
         PULL_STAT(buf_ptr, thread,   sizeof(FastTimer), remain);
         ++flag_count;
         break;


      case TF_ERASURE:        // not per-thread; already moved at top-level
         break;

      case TF_HANDLE:         // not per-thread; already moved at top-level
         break;

      case TF_SIMPLE:         // meta-flag
         break;
      }
   }

#undef PULL
#undef PULL_STAT

   return 0;
}



#if 0
// TBD ...

// like import_timing_data(), but add the values into what is already in
// place in <timing> This means we add the values from the buffer, directly
// into our timing structure, instead of first building a new timing
// structuere with installed values, and then accumulating all the restored
// elements into some other TimingData.
//
// Among other things, this means that we don't simply pull the "single"
// (per-handle) values at the head of TimingData, because some of those
// need to be accumulated, as well.
ssize_t accumulate_timing_data2(TimingData* timing, char* const buffer, size_t buf_size)
{
   char*   buf_ptr     = buffer;
   ssize_t remain      = buf_size;
   int     flag_count  = 0;
   size_t  header_size = (char*)&timing->agg_stats - (char*)timing;

#define PULL_TIMER(BUF, DATA, SIZE, REMAIN)     \
   do {                                         \
      if ((SIZE) > REMAIN)                      \
         return -1;                             \
      fast_timer_add2(DATA, BUF);               \
      BUF    += (SIZE);                         \
      REMAIN -= (SIZE);                         \
   } while (0)

#define PULL_TIMERS(BUF, STAT, SIZE, REMAIN)                            \
   for (i=0; i<timing->blk_count; ++i) {                                \
      PULL_TIMER(BUF, (char*)&timing->stats[i].STAT, SIZE, REMAIN);     \
   }                                                                    \


#define PULL_HISTO(BUF, DATA, SIZE, REMAIN)     \
   do {                                         \
      if ((SIZE) > REMAIN)                      \
         return -1;                             \
      log_histo_add2(DATA, BUF);                \
      BUF    += (SIZE);                         \
      REMAIN -= (SIZE);                         \
   } while (0)

#define PULL_HISTOS(BUF, STAT, SIZE, REMAIN)                            \
   for (i=0; i<timing->blk_count; ++i) {                                \
      PULL_HISTO(BUF, (char*)&timing->stats[i].STAT, SIZE, REMAIN);     \
   }                                                                    \
   
   // copy top-level single values
   PULL(buf_ptr, (char*)timing, header_size, remain);

   TimingFlagsValue mask;
   for (mask=0x1; mask; mask <<= 1) {

      int i;
      switch (timing->flags & mask) {

      case TF_OPEN:
         PULL_TIMER(buf_ptr, open,   sizeof(FastTimer), remain);
         PULL_HISTO(buf_ptr, open_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_RW:
         PULL_TIMER(buf_ptr, read,   sizeof(FastTimer), remain);
         PULL_HISTO(buf_ptr, read_h, sizeof(LogHisto),  remain);
         ++flag_count;

         PULL_TIMER(buf_ptr, write,   sizeof(FastTimer), remain);
         PULL_HISTO(buf_ptr, write_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_CLOSE:
         PULL_TIMER(buf_ptr, close,   sizeof(FastTimer), remain);
         PULL_HISTO(buf_ptr, close_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_RENAME:
         PULL_TIMER(buf_ptr, rename,  sizeof(FastTimer), remain);
         ++flag_count;
         break;

      case TF_STAT:
         PULL_TIMER(buf_ptr, stat,  sizeof(FastTimer), remain);
         ++flag_count;
         break;

      case TF_XATTR:
         PULL_TIMER(buf_ptr, xattr,  sizeof(FastTimer), remain);
         ++flag_count;
         break;

      case TF_CRC:
         PULL_TIMER(buf_ptr, crc,   sizeof(FastTimer), remain);
         PULL_HISTO(buf_ptr, crc_h, sizeof(LogHisto),  remain);
         ++flag_count;
         break;

      case TF_THREAD:
         PULL_TIMER(buf_ptr, thread,   sizeof(FastTimer), remain);
         ++flag_count;
         break;


      case TF_ERASURE:        // not per-thread; already moved at top-level
         break;

      case TF_HANDLE:         // not per-thread; already moved at top-level
         break;

      case TF_SIMPLE:         // meta-flag
         break;
      }
   }

#undef PULL_TIMER
#undef PULL_HISTO
#undef PULL_STAT

   return flag_count;
}
#endif

// accumulate timings in <src> into <dest>.  Currently, pftool uses this to
// accumulate timing data across copy-operations that occur in one
// reporting interval.  
int accumulate_timing_data(TimingData* dest, TimingData* src)
{
   int i;
   int flag_count = 0;

   if (! dest->flags) {
      dest->flags     |= src->flags;
      dest->blk_count  = src->blk_count;
      dest->pod_id     = src->pod_id;
   }

   // counting the number of accumulation-events allows us to compute averages
   dest->event_count += 1;

#define ADD_TIMERS(DST, SRC, STAT)                                      \
   for (i=0; i<(SRC)->blk_count; ++i) {                                 \
      fast_timer_add(&(DST)->stats[i].STAT, &(SRC)->stats[i].STAT);     \
   }                                                                    \

#define ADD_HISTOS(DST, SRC, STAT)                                      \
   for (i=0; i<(SRC)->blk_count; ++i) {                                 \
      log_histo_add(&(DST)->stats[i].STAT, &(SRC)->stats[i].STAT);      \
   }                                                                    \


   TimingFlagsValue mask;
   for (mask=0x1; mask; mask <<= 1) {

      int i;
      switch (src->flags & mask) {

      case TF_OPEN:
         ADD_TIMERS(dest, src, open);
         ADD_HISTOS(dest, src, open_h);
         ++flag_count;
         break;

      case TF_RW:
         ADD_TIMERS(dest, src, read);
         ADD_HISTOS(dest, src, read_h);
         ++flag_count;

         ADD_TIMERS(dest, src, write);
         ADD_HISTOS(dest, src, write_h);
         ++flag_count;
         break;

      case TF_CLOSE:
         ADD_TIMERS(dest, src, close);
         ADD_HISTOS(dest, src, close_h);
         ++flag_count;
         break;

      case TF_RENAME:
         ADD_TIMERS(dest, src, rename);
         ++flag_count;
         break;

      case TF_STAT:
         ADD_TIMERS(dest, src, stat);
         ++flag_count;
         break;

      case TF_XATTR:
         ADD_TIMERS(dest, src, xattr);
         ++flag_count;
         break;

      case TF_CRC:
         ADD_TIMERS(dest, src, crc);
         ADD_HISTOS(dest, src, crc_h);
         ++flag_count;
         break;

      case TF_THREAD:
         ADD_TIMERS(dest, src, thread);
         ++flag_count;
         break;


      case TF_ERASURE:        // not per-thread
         fast_timer_add(&dest->erasure,   &src->erasure);
         log_histo_add(&dest->erasure_h, &src->erasure_h);
         ++flag_count;
         break;

      case TF_HANDLE:         // not per-thread
         fast_timer_add(&dest->handle_timer, &src->handle_timer);
         ++flag_count;
         break;

      case TF_SIMPLE:         // meta-flag
         ++flag_count;
         break;
      }
   }

#undef ADD_TIMERS
#undef ADD_HISTOS

   return flag_count;
}



// <avg> non-zero means show timer-values as averages (across multiple
// events).  In this case, we still print histograms without averaging, to
// avoid hiding single outlier elements.
//
int print_timing_data(TimingData* timing, const char* hdr, int avg, int use_syslog)
{
   static const size_t HEADER_SIZE = 512;
   char header[HEADER_SIZE];

   header[0] = 0;
   strncat(header, hdr, HEADER_SIZE);
   header[HEADER_SIZE -1] = 0;  // manpage wrong.  strncat() doesn't assure terminal-NULL
   int   do_avg = (avg && (timing->event_count > 1));

   // keep things simple for parsers of our log-output
   const char* avg_str_not = "(tot)"; // i.e. no averaging was done on this value
   const char* avg_str     = (avg ? "(avg)" : avg_str_not);

   size_t header_len = strlen(header);
   size_t remain     = HEADER_SIZE - header_len -1;
   char*  tail       = header + header_len;
   size_t tail_len   = 0;
   char*  tail2      = tail;
   size_t remain2    = 0;

   // number of accumulation-events (e.g. file-closures resulting in
   // TimingData being accumulated).  Divide by this to get averages.
   int event_count = timing->event_count;

   int i;
   int flag_count = 0;

   fast_timer_inits();

   // "erasure_h" is currently the longest timing-stat name
#define MAKE_HEADER(STAT, AVG_STR)                                      \
   snprintf(tail, remain, " evt %2d %-10s %s ", event_count, #STAT, AVG_STR); \
   tail_len = strlen(tail);                                             \
   tail2    = tail + tail_len;                                          \
   remain2  = remain - tail_len;

#define PRINT_TIMERS(TIMING, STAT)                                      \
   MAKE_HEADER(STAT, avg_str);                                          \
   for (i=0; i<(TIMING)->blk_count; ++i) {                              \
      snprintf(tail2, remain2, "blk %2d   ", i);                        \
      if (do_avg) /* side-effect ... */                                 \
         fast_timer_div(&(TIMING)->stats[i].STAT, timing->event_count); \
      fast_timer_show(&(TIMING)->stats[i].STAT, 1, header, use_syslog); \
   }

   // histo elements are printed "%2d", and high-order bin is typically 0,
   // so one-less space in the header lines up better with timer values.
#define PRINT_HISTOS(TIMING, STAT)                                      \
   MAKE_HEADER(STAT, avg_str_not);                                      \
   for (i=0; i<(TIMING)->blk_count; ++i) {                              \
      snprintf(tail2, remain2, "blk %2d  ", i);                         \
      log_histo_show(&(TIMING)->stats[i].STAT, 1, header, use_syslog);  \
   }


   TimingFlagsValue mask;
   for (mask=0x1; mask; mask <<= 1) {

      int i;
      switch (timing->flags & mask) {

      case TF_OPEN:
         PRINT_TIMERS(timing, open);
         PRINT_HISTOS(timing, open_h);
         ++flag_count;
         break;

      case TF_RW:
         PRINT_TIMERS(timing, read);
         PRINT_HISTOS(timing, read_h);
         ++flag_count;

         PRINT_TIMERS(timing, write);
         PRINT_HISTOS(timing, write_h);
         ++flag_count;
         break;

      case TF_CLOSE:
         PRINT_TIMERS(timing, close);
         PRINT_HISTOS(timing, close_h);
         ++flag_count;
         break;

      case TF_RENAME:
         PRINT_TIMERS(timing, rename);
         ++flag_count;
         break;

      case TF_STAT:
         PRINT_TIMERS(timing, stat);
         ++flag_count;
         break;

      case TF_XATTR:
         PRINT_TIMERS(timing, xattr);
         ++flag_count;
         break;

      case TF_CRC:
         PRINT_TIMERS(timing, crc);
         PRINT_HISTOS(timing, crc_h);
         ++flag_count;
         break;

      case TF_THREAD:
         PRINT_TIMERS(timing, thread);
         ++flag_count;
         break;



      case TF_ERASURE:        // not per-thread
         MAKE_HEADER(erasure, avg_str);
         if (do_avg)
            fast_timer_div(&timing->erasure, timing->event_count);
         fast_timer_show(&timing->erasure,  1, header,   use_syslog);

         MAKE_HEADER(erasure_h, avg_str_not);
         log_histo_show(&timing->erasure_h, 1, header, use_syslog);
         ++flag_count;
         break;

      case TF_HANDLE:         // not per-thread
         MAKE_HEADER(handle, avg_str);
         if (do_avg)
            fast_timer_div(&timing->handle_timer, timing->event_count);
         fast_timer_show(&timing->handle_timer, 1, header, use_syslog);
         ++flag_count;
         break;

      case TF_SIMPLE:         // meta-flag
         break;
      }
   }

#undef MAKE_HEADER
#undef PRINT_TIMERS
#undef PRINT_HISTOS

   return flag_count;
}






