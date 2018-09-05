#ifndef __MARFS_COPYRIGHT_H__
#define __MARFS_COPYRIGHT_H__

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

#endif



#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "erasure.h"
// #include "erasure_internals.h"

int crc_status();


#ifdef SOCKETS

// <dest> is the buffer to receive the snprintf'ed path
// <size> is the size of that buffer
// <format> is a path template.  For sockets, on the VLE,
//           it might look like 192.168.0.%d:/zfs/exports/repo10+2/pod1/block%d/my_file
// <block> is the current 0-based block-number (from libne)
// <state> is whatever state was passed into ne_open1()
//
//
// WARNING: When MarFS calls libne on behalf of RMDA-sockets-based repos,
//     it also passes in an snprintf function, plus an argument that
//     contains parts of the parsed MarFS configuration, which are used by
//     that snprintf function to compute the proper values for host-number
//     and block-number in the partially-rehydrated path-template (i.e. it
//     already has scatter-dir and cap-unit filled in), using information
//     from the configuration.
// 
//     Here, we don't have that.  Instead, this is just hardwired to match
//     the latest config on the VLE testbed.  If the testbed changes, and
//     you change your MARFSCONFIGRC to try to fix things ... things still
//     won't be fixed, this hardwired thing will be the thing that's
//     broken.
//
//     see marfs/fuse/src/dal.c
//
int snprintf_for_vle(char*       dest,
                     size_t      size,
                     const char* format,
                     uint32_t    block,
                     void*       state) {

  int pod_offset   = 0;
  int host_offset  = 1 + (block / 2);
  int block_offset = 0;

  return snprintf(dest, size, format,
                  pod_offset + host_offset, // "192.168.0.%d"
                  block_offset + block);    // "block%d"
}
#endif



// Show all the usage options in one place, for easy reference
// An arrow appears next to the one you tried to use.
//
void usage(const char* prog_name, const char* op) {

   PRINTlog("Usage: %s <op> [args ...]\n", prog_name);
   PRINTlog("  <op> and args are like one of the following lines\n");
   PRINTlog("\n");

#define USAGE(CMD, ARGS)                                       \
   PRINTlog("  %2s %-10s %s\n",                                \
           (!strcmp(op, CMD) ? "->" : ""), (CMD), (ARGS))

   USAGE("write",      "input_file  erasure_path N E start_file  [timing_flags] [input_size]");
   USAGE("put",        "input_file  erasure_path N E start_file  [timing_flags] [input_size]");
   USAGE("read",       "output_file erasure_path N E start_file  [timing_flags] [read_size]");
   USAGE("get",        "output_file erasure_path N E start_file  [timing_flags] [read_size]");
   USAGE("rebuild",    "erasure_path             N E start_file  [timing_flags]");
   USAGE("status",     "erasure_path");
   USAGE("delete",     "erasure_path stripe_width");
   USAGE("sizeof",     "erasure_path quorum stripe_width");

   USAGE("crc_status", "");
   USAGE("help",       "");

   PRINTlog("\n");
   PRINTlog("\n");
   PRINTlog("  NOTES:\n");
   PRINTlog("     write/read        use random transfer-size  (<= 1MB)\n");
   PRINTlog("     put/get           like write/read but use fixed (1MB) transfer-size\n");
   PRINTlog("\n");
   PRINTlog("     <timing_flags> can be decimal, or can be hex-value starting with \"0x\"\n");
   PRINTlog("\n");
   PRINTlog("        OPEN    =  0x0001\n");
   PRINTlog("        RW      =  0x0002     /* each individual read/write, in given stream */\n");
   PRINTlog("        CLOSE   =  0x0004     /* cost of close */\n");
   PRINTlog("        RENAME  =  0x0008\n");
   PRINTlog("        STAT    =  0x0010\n");
   PRINTlog("        XATTR   =  0x0020\n");
   PRINTlog("        ERASURE =  0x0040\n");
   PRINTlog("        CRC     =  0x0080\n");
   PRINTlog("        THREAD  =  0x0100     /* from beginning to end  */\n");
   PRINTlog("        HANDLE  =  0x0200     /* from start/stop, all threads, in 1 handle */\n");
   PRINTlog("        SIMPLE  =  0x0400     /* diagnostic output uses terse numeric formats */\n");
   PRINTlog("\n");
   PRINTlog("     <erasure_path> is one of the following\n");
   PRINTlog("\n");
   PRINTlog("       [RDMA] xx.xx.xx.%%d:pppp/local/blah/block%%d/.../fname\n");
   PRINTlog("\n");
   PRINTlog("               ('/local/blah' is some local path on all accessed storage nodes\n");
   PRINTlog("\n");
   PRINTlog("       [MC]   /NFS/blah/block%%d/.../fname\n");
   PRINTlog("\n");
   PRINTlog("               ('/NFS/blah/'  is some NFS path on the client nodes\n");
   PRINTlog("\n");

#undef USAGE
}



int
parse_flags(TimingFlagsValue* flags, const char* str) {
   if (! str)
      *flags = 0;

   else if (!strncmp("0x", str, 2)) {
      errno = 0;
      *flags = (TimingFlagsValue)strtol(str+2, NULL, 16);
      if (errno) {
         PRINTlog("couldn't parse flags from '%s'\n", str);
         return -1;
      }
   }
   else {
      errno = 0;
      *flags = (TimingFlagsValue)strtol(str, NULL, 10);
      if (errno) {
         PRINTlog("couldn't parse flags from '%s'\n", str);
         return -1;
      }
   }

   return 0;
}


uDALType
select_impl(const char* path) {
   return (strchr(path, ':')
           ? UDAL_SOCKETS
           : UDAL_POSIX);
}

SnprintfFunc
select_snprintf(const char* path) {
   return (strchr(path, ':')
           ? snprintf_for_vle      // MC over RDMA-sockets
           : ne_default_snprintf); // MC over NFS
}




int main( int argc, const char* argv[] ) 
{
   void* buff;
   unsigned long long       nread;
   unsigned long long       toread;
   unsigned long long       totdone = 0;
   const unsigned long long M       = (1024 * 1024);

   int start;
   char wr = -1;
   int filefd;
   int N;
   int E;
   int tmp;
   unsigned long long totbytes;
   TimingFlagsValue   timing_flags = 0;
   int                parse_err = 0;
   const char*        size_arg = NULL;
   int                rand_size = 1;

   LOG_INIT();

   if ( argc < 2 ) {
      usage(argv[0], "help");
      return -1;
   }


   if ((    strcmp( argv[1], "write"    ) == 0 )
       || ( strcmp( argv[1], "put" ) == 0 )) {
      if ( argc < 7 ) {
         usage( argv[0], argv[1] ); 
         return -1;
      }
      if ( argc >= 8 )          // optional <timing_flags>
         parse_err = parse_flags(&timing_flags, argv[7]);

      if ( argc >= 9)
         size_arg = argv[8];

      wr = 1;
      if (strcmp( argv[1], "put" ) == 0 )
         rand_size = 0;
   }
   else if ((    strcmp( argv[1], "read" ) == 0 )
            || ( strcmp( argv[1], "get" ) == 0 )) {
      if ( argc < 7 ) {
         usage( argv[0], argv[1] ); 
         return -1;
      }
      if ( argc >= 8 )          // optional <timing_flags>
         parse_err = parse_flags(&timing_flags, argv[7]);

      if ( argc >= 9)
         size_arg = argv[8];

      wr = 0;
      if (strcmp( argv[1], "get" ) == 0 )
         rand_size = 0;
   }
   else if ( strcmp( argv[1], "rebuild" ) == 0 ) {
      if ( argc < 6 ) {
         usage( argv[0], argv[1] ); 
         return -1;
      }
      if ( argc == 7 )          // optional <timing_flags>
         parse_err = parse_flags(&timing_flags, argv[6]);

      wr = 2;
   }

   else if ( strcmp( argv[1], "status" ) == 0 ) {
      if ( argc != 3 ) { 
         usage( argv[0], argv[1] ); 
         return -1;
      }
      wr = 3;
   }

   else if ( strcmp( argv[1], "delete" ) == 0 ) {
      if ( argc != 4 ) {
         usage( argv[0], argv[1] ); 
         return -1;
      }
      N = atoi(argv[3]);
      wr = 4;
   }

   else if ( strcmp( argv[1], "crc-status" ) == 0 ) {
      PRINTout("MAX-N: %d   MAX-E: %d\n", MAXN, MAXE);
      return crc_status();
   }

   else if ( strcmp( argv[1], "sizeof" ) == 0 ) {
      if ( argc != 5 ) {
         usage( argv[0], argv[1] );
         return -1;
      }
      wr = 5;
   }

   else {
      usage( argv[0], "help" );
      return -1;
   }
   
   PRINTdbg("libneTest: command = '%s'\n", argv[1]);



   // --- command-specific extra args
   if ( wr < 2 ) {              // read or write
      N = atoi(argv[4]);
      E = atoi(argv[5]);
      start = atoi(argv[6]);
   }
   else if ( wr < 3 ) {         // i.e. rebuild
      N = atoi(argv[3]);
      E = atoi(argv[4]);
      start = atoi(argv[5]);
   }

   if (parse_err) {
      usage(argv[0], argv[1]);
      return -1;
   }

   if (size_arg)                // optional <input_size> for write
      totbytes = strtoll(size_arg, NULL, 10);
   else
      // totbytes = N * 64 * 1024; // default
#     ifdef INT_CRC
      totbytes = M - sizeof(u32); // default
#     else
      totbytes = M;             // default
#     endif
 
   srand(time(NULL));
   ne_handle handle;

   SktAuth  auth;
   skt_auth_init(SKT_S3_USER, &auth); /* this is safe, whether built with S3_AUTH, or not */



#  define NE_OPEN(PATH, MODE, ...)    ne_open1  (select_snprintf(PATH), NULL, select_impl(PATH), auth, timing_flags, \
                                                 (PATH), (MODE), ##__VA_ARGS__ )

#  define NE_DELETE(PATH, WIDTH)      ne_delete1(select_snprintf(PATH), NULL, select_impl(PATH), auth, timing_flags, \
                                                 (PATH), (WIDTH))

#  define NE_STATUS(PATH)             ne_status1(select_snprintf(PATH), NULL, select_impl(PATH), auth, timing_flags, \
                                                 (PATH))

#  define NE_SIZE(PATH, QUOR, WIDTH)  ne_size1  (select_snprintf(PATH), NULL, select_impl(PATH), auth, timing_flags, \
                                                 (PATH), (QUOR), (WIDTH))



   // -----------------------------------------------------------------
   // write
   // -----------------------------------------------------------------

   if ( wr == 1 ) {

      buff = malloc( sizeof(char) * totbytes );

      PRINTout("libneTest: writing content of file %s to erasure striping (N=%d,E=%d,offset=%d)\n",
               argv[2], N, E, start );

      filefd = open( argv[2], O_RDONLY );
      if ( filefd == -1 ) {
         PRINTlog("libneTest: failed to open file %s\n", argv[2] );
         return -1;
      }

      handle = NE_OPEN( (char *)argv[3], NE_WRONLY, start, N, E );
      if ( handle == NULL ) {
         PRINTlog("libneTest: ne_open failed\n   Errno: %d\n   Message: %s\n", errno, strerror(errno) );
         return -1;
      }

      if (rand_size)
         toread = rand() % (totbytes+1);
      else
         toread = (totbytes < M) ? totbytes : M;

      while ( totbytes != 0 ) {

         // read from input file
         nread = read( filefd, buff, toread );

         // write to erasure stripes
         PRINTdbg("libneTest: preparing to write %llu to erasure files...\n", nread );
         ssize_t nwritten = ne_write( handle, buff, nread );
         if ( nwritten != nread ) {
            PRINTlog("libneTest: unexpected # of bytes (%ld) written by ne_write (expected %ld)\n", nwritten, nread );
            return -1;
         }
         PRINTdbg("libneTest: write successful\n" );

         // without a command-line <input_size> argument, copy from the
         // input-file until we reach EOF
         if (size_arg)
            totbytes -= nread;
         else if (toread != 0  &&  nread == 0)
            totbytes = 0;

         totdone += nread;

         if (rand_size)
            toread = rand() % (totbytes+1);
         else
            toread = (totbytes < M) ? totbytes : M;
      }

      //      // if stat-flags were set, show collected stats
      //      show_handle_stats(handle);

      close(filefd);
      free(buff);

      PRINTout("libneTest: all writes completed\n");
      PRINTout("libneTest: total written = %llu\n", totdone );
   }


   // -----------------------------------------------------------------
   // read
   // -----------------------------------------------------------------

   else if ( wr == 0 ) {

      // if <size_arg> wasn't provided, read the whole thing
      uint64_t           tbd_bytes;         // total data to be moved
      uint64_t           totbytes_per_iter; // buf-size

      PRINTout("libneTest: reading %llu bytes from erasure striping "
               "(N=%d,E=%d,offset=%d) to file %s\n", totbytes, N, E, start, argv[2] );
      buff = malloc( sizeof(char) * totbytes );
      PRINTout("libneTest: allocated buffer of size %llu\n", sizeof(char) * totbytes );

      filefd = open( argv[2], O_WRONLY | O_CREAT, 0644 );
      if ( filefd == -1 ) {
         PRINTlog("libneTest: failed to open file %s\n", argv[2] );
         return -1;
      }

#if 0
      tbd_bytes = totbytes;
      if ((N == 0) || (size_arg ==0)) {

         // detect the size of the file, and then read the whole thing.
         //
         // NOTE: In the case of UDAL_SOCKETS case (with RDMA), NE_NOINFO
         //       will attempt to stat MAXPARTS parts.  The snprintf
         //       function will happily generate IP addrs off the deep-end.
         //       Each of these will be stated through the RDMA UDAL, which
         //       will result in an rsocket() call that has to time-out.
         //       This works, but it's slow.
         
         handle = NE_OPEN( (char *)argv[3], (NE_RDONLY | NE_NOINFO) );
      }
      else
         handle = NE_OPEN( (char *)argv[3], NE_RDONLY, start, N, E );

      if ( handle == NULL ) {
         PRINTlog("libneTest: ne_open failed\n   Errno: %d\n   Message: %s\n", errno, strerror(errno) );
         return -1;
      }

      if (! size_arg)
         tbd_bytes = handle->totsz;

#else
      tbd_bytes = totbytes;
      if ((N == 0) || (size_arg ==0)) {

         // If the size for the read wasn't provided, use ne_stat() to find the
         // actual size of the file, and then read the whole thing.

         TimingFlagsValue temp_timing_flags = timing_flags; /* don't use timing_flags during ... NE_STAT() */
         timing_flags = 0;

         PRINTout("libneTest: stat'ing to get total size.  path = '%s'\n", (char *)argv[2] );

         ne_stat stat = NE_STATUS( (char *)argv[3] );
         if ( stat == NULL ) {
            PRINTlog("libneTest: ne_status failed!\n" );
            return -1;
         }

         PRINTout("after ne_status() -- N: %d  E: %d  bsz: %d  Start-Pos: %d  totsz: %llu\n",
                 stat->N, stat->E, stat->bsz, stat->start, (unsigned long long)stat->totsz );

         timing_flags = temp_timing_flags; /* restore timing_flags for NE_READ() */

         if (! N)
            N = stat->N;

         if (! E)
            E = stat->E;

         if (! start)
            start = stat->start;

         if (! size_arg)
            tbd_bytes = stat->totsz;
      }

      handle = NE_OPEN( (char *)argv[3], NE_RDONLY, start, N, E );
      if ( handle == NULL ) {
         PRINTlog("libneTest: ne_open failed\n   Errno: %d\n   Message: %s\n", errno, strerror(errno) );
         return -1;
      }
      PRINTout("did open()\n");

#endif

      // fill multiple buffers, if needed
      totbytes_per_iter = totbytes;
      while (totdone < tbd_bytes) {

         totbytes = totbytes_per_iter;
         if ((totdone + totbytes) > tbd_bytes)
            totbytes = tbd_bytes - totdone;
         PRINTdbg("libneTest: performing buffer-loop to read %llu bytes, at %llu/%llu\n",
                  totbytes, totdone, tbd_bytes );

         // go through each buffers-worth of data as a series of reads of
         // decreasing size, in order to exercise "corner cases".
         // ("readall" just uses max buffers always)
         if (totbytes && rand_size)
            toread = (rand() % totbytes) + 1;
         else
            toread = (totbytes < M) ? totbytes : M;

         while ( totbytes > 0 ) {

            PRINTdbg("libneTest: preparing to read %llu from erasure files with offset %llu\n", toread, totdone );
            if ( toread > totbytes ) {
               PRINTlog("libneTest: toread (%llu) > totbytes (%llu)\n", toread, totbytes);
               exit(EXIT_FAILURE);
            }

            tmp = ne_read( handle, buff, toread, totdone );
            if ( toread != tmp ) {
               // couldn't this happen without there being an error (?)
               PRINTlog("libneTest: ne_read got %d but expected %llu\n", tmp, toread );
               return -1;
            }

            PRINTdbg("libneTest: ...done.  Writing %llu to output file.\n", toread );
            write( filefd, buff, toread );

            totbytes -= toread;
            totdone  += toread;

            if ( totbytes && rand_size)
               toread = ( rand() % totbytes ) + 1;
            else if ( totbytes )
               toread = (totbytes < M) ? totbytes : M;
         }
      }

      free(buff); 
      close(filefd);

      //      // if stat-flags were set, show collected stats
      //      show_handle_stats(handle);

      PRINTout("libneTest: all reads completed\n");
      PRINTout("libneTest: total read = %llu\n", totdone );
   }


   // -----------------------------------------------------------------
   // rebuild
   // -----------------------------------------------------------------

   else if ( wr == 2 ) {
      PRINTout("libneTest: rebuilding erasure striping (N=%d,E=%d,offset=%d)\n", N, E, start );

      if ( N == 0 ) {
         handle = NE_OPEN( (char *)argv[2], NE_REBUILD | NE_NOINFO );
         if(handle == NULL) {
           perror("ne_open()");
         }
      }
      else {
         handle = NE_OPEN( (char *)argv[2], NE_REBUILD, start, N, E );
      }

      tmp = ne_rebuild( handle );
      if ( tmp < 0 ) {
        PRINTout("rebuild result %d, errno=%d (%s)\n", tmp, errno, strerror(errno));
        PRINTlog("libneTest: rebuild failed!\n" );
         return -1;
      }
      PRINTout("libneTest: rebuild complete\n" );
   }


   // -----------------------------------------------------------------
   // status
   // -----------------------------------------------------------------

   else if ( wr == 3 ) {
      PRINTout("libneTest: retrieving status of erasure striping with path \"%s\"\n", (char *)argv[2] );
      ne_stat stat = NE_STATUS( (char *)argv[2] );
      if ( stat == NULL ) {
         PRINTlog("libneTest: ne_status failed!\n" );
         return -1;
      }

      PRINTout( "N: %d  E: %d  bsz: %d  Start-Pos: %d  totsz: %llu\n",
                stat->N, stat->E, stat->bsz, stat->start, (unsigned long long)stat->totsz );
      PRINTout( "Extended Attribute Errors : ");
      for( tmp = 0; tmp < ( stat->N+stat->E ); tmp++ ){
         PRINTout( "%d ", stat->xattr_status[tmp] );
      }
      PRINTout( "\n" );

      PRINTout( "Data/Erasure Errors :       " );
      int nerr = 0;
      for( tmp = 0; tmp < ( stat->N+stat->E ); tmp++ ){
         if( stat->data_status[tmp] )
            nerr++;
         PRINTout( "%d ", stat->data_status[tmp] );
      }
      PRINTout( "\n" );

      if( nerr > stat->E )
         PRINTlog( "WARNING: the data appears to be unrecoverable!\n" );
      else if ( nerr > 0 )
         PRINTlog( "WARNING: errors were found, be sure to rebuild this object before data loss occurs!\n" );

      /* Encode any file errors into the return status */
      tmp=0;
      for( filefd = 0; filefd < stat->N+stat->E; filefd++ ) {
         if ( stat->data_status[filefd] || stat->xattr_status[filefd] ) {
            tmp += ( 1 << ((filefd + stat->start) % (stat->N+stat->E)) );
         }
      }
      free(stat);

      printf("%d\n",tmp);

      return tmp;
   }


   // -----------------------------------------------------------------
   // size
   // -----------------------------------------------------------------

   else if (wr == 5) {
      PRINTout( "Size of \"%s\" -- %zd\n",
                argv[2],
                NE_SIZE( argv[2], atoi(argv[3]), atoi(argv[4]) ) );
      return 0;
   }


   // -----------------------------------------------------------------
   // delete
   // -----------------------------------------------------------------

   else if ( wr == 4 ) {
      PRINTout("libneTest: deleting striping corresponding to path \"%s\" with width %d...\n", (char*)argv[2], N );
      if ( NE_DELETE( (char*) argv[2], N ) ) {
         PRINTlog("libneTest: deletion attempt indicates a failure for path \"%s\"\n", (char*)argv[2] );
         return -1;
      }
      PRINTout("libneTest: deletion successful\n" );
      return 0;
   }



   tmp = ne_close( handle );
   PRINTout("close rc: %d\n",tmp);
   fflush(stdout);
   fflush(stderr);

   return tmp;

}


int crc_status() {
   #ifdef INT_CRC
   printf("Intermediate-CRCs: Active\n");
   return 0;
   #else
   printf("Intermediate-CRCs: Inactive\n");
   return 1;
   #endif
}


