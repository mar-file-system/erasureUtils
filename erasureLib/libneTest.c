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
// see marfs/fuse/src/dal.c
//
// <dest> is the buffer to receive the snprintf'ed path
// <size> is the size of that buffer
// <format> is a path template.  For sockets, on the VLE,
//           it might look like 192.168.0.%d:/zfs/exports/repo10+2/pod1/block%d/my_file
// <block> is the current block-number (from libne)
// <state> is whatever state was passed into ne_open1()
//
int snprintf_for_vle(char*       dest,
                     size_t      size,
                     const char* format,
                     uint32_t    block,
                     void*       state) {

  int pod_offset = 0;
  int host_offset = 1 + (block / 2);
  int block_offset = 1 + block;
  return snprintf(dest, size, format,
                  pod_offset + host_offset,  // "192.168.0.%d"
                  block_offset);             // "block%d"
}
#endif



// Show all the usage options in one place, for easy reference
// An arrow appears next to the one you tried to use.
//
void usage(const char* prog_name, const char* op) {

#define USAGE(CMD, ARGS)                                       \
   PRINTerr("  %2s %-10s %s\n",                                \
           (!strcmp(op, CMD) ? "->" : ""), (CMD), (ARGS))

   PRINTerr("Usage: %s <op> [args ...]\n", prog_name);
   PRINTerr("  where <op> and args are one of the following\n");
   PRINTerr("\n");

   USAGE("write",      "input_file output_path N E start_file [input_size]");
   USAGE("read",       "output_file erasure_path N E start_file total_bytes");
   USAGE("rebuild",    "erasure_path N E start_file");
   USAGE("status",     "erasure_path");
   USAGE("delete",     "erasure_path stripe_width");
   USAGE("crc_status", "");
   USAGE("help",       "");

   PRINTerr("\n");
}


int main( int argc, const char* argv[] ) 
{
   unsigned long long nread;
   void *buff;
   unsigned long long toread;
   unsigned long long totdone = 0;
   int start;
   char wr;
   int filefd;
   int N;
   int E;
   int tmp;
   unsigned long long totbytes;

   LOG_INIT();

   if ( argc < 2 ) {
      usage(argv[0], "help");
      return -1;
   }

   if ( strncmp( argv[1], "write", strlen(argv[1]) ) == 0 ) {
      if ( argc < 7 ) { 
         usage( argv[0], argv[1] ); 
         return -1;
      }
      wr = 1;
   }
   else if ( strncmp( argv[1], "read", strlen(argv[1]) ) == 0 ) {
      if ( argc < 8 ) { 
         usage( argv[0], argv[1] ); 
         return -1;
      }
      wr = 0;
   }
   else if ( strncmp( argv[1], "rebuild", strlen(argv[1]) ) == 0 ) {
      if ( argc != 6 ) { 
         usage( argv[0], argv[1] ); 
         return -1;
      }
      wr = 2;
   }
   else if ( strncmp( argv[1], "status", strlen(argv[1]) ) == 0 ) {
      if ( argc != 3 ) { 
         usage( argv[0], argv[1] ); 
         return -1;
      }
      wr = 3;
   }
   else if ( strncmp( argv[1], "delete", strlen(argv[1]) ) == 0 ) {
      if ( argc != 4 ) {
         usage( argv[0], argv[1] ); 
         return -1;
      }
      N = atoi(argv[3]);
      wr = 4;
   }
   else if ( strncmp( argv[1], "crc-status", strlen(argv[1]) ) == 0 ) {
      printf("MAX-N: %d   MAX-E: %d\n", MAXN, MAXE);
      return crc_status();
   }
   else {
      usage( argv[0], "help" );
      return -1;
   }
   
   PRINTout("libneTest: command = '%s'\n", argv[2]);


   // --- command-specific extra args
   if ( wr < 2 ) {
      N = atoi(argv[4]);
      E = atoi(argv[5]);
      start = atoi(argv[6]);
   }
   else if ( wr < 3 ) {
      N = atoi(argv[3]);
      E = atoi(argv[4]);
      start = atoi(argv[5]);
   }

   if ( argc == 8 ) {
      totbytes = strtoll(argv[7],NULL,10); 
   }
   else {
      totbytes = N * 64 * 1024;
   }
 
#ifdef SOCKETS
   SktAuth  auth;
   skt_auth_init(SKT_S3_USER, &auth); /* this is safe, whether built with S3_AUTH, or not */

#  define NE_OPEN(PATH, MODE, ...)   ne_open1  (snprintf_for_vle, NULL, auth, (PATH), (MODE), ##__VA_ARGS__ )
#  define NE_STATUS(PATH)            ne_status1(snprintf_for_vle, NULL, auth, (PATH))

#else
#  define NE_OPEN(PATH, MODE, ...)   ne_open((PATH), (MODE), ##__VA_ARGS__ )
#  define NE_STATUS(PATH)            ne_status(PATH)

#endif

   srand(time(NULL));
   ne_handle handle;


   // -----------------------------------------------------------------
   // write
   // -----------------------------------------------------------------

   if ( wr == 1 ) {

      buff = malloc( sizeof(char) * totbytes );

      PRINTout("libneTest: writing content of file %s to erasure striping (N=%d,E=%d,offset=%d)\n",
               argv[2], N, E, start );

      filefd = open( argv[2], O_RDONLY );
      if ( filefd == -1 ) {
         PRINTerr("libneTest: failed to open file %s\n", argv[2] );
         return -1;
      }

      handle = NE_OPEN( (char *)argv[3], NE_WRONLY, start, N, E );
      if ( handle == NULL ) {
         PRINTerr("libneTest: ne_open failed\n   Errno: %d\n   Message: %s\n", errno, strerror(errno) );
         return -1;
      }

      toread = rand() % (totbytes+1);

      while ( totbytes != 0 ) {
         nread = read( filefd, buff, toread );
         PRINTout("libneTest: preparing to write %llu to erasure files...\n", nread );
         if ( nread != ne_write( handle, buff, nread ) ) {
            PRINTerr("libneTest: unexpected # of bytes written by ne_write\n" );
            return -1;
         }
         PRINTout("libneTest: write successful\n" );

         if ( argc == 8 ) {
            totbytes -= nread;
         }
         else if (toread != 0  &&  nread == 0) {
            totbytes = 0;
         }
         totdone += nread;

         toread = rand() % (totbytes+1);
      }

      if ( ne_flush( handle ) != 0 ) {
         PRINTerr("libneTest: flush failed!\n" );
         return -1;
      }

      free(buff);
      close(filefd);
      PRINTout("libneTest: all writes completed\n");
      PRINTout("libneTest: total written = %llu\n", totdone );

   }

   // -----------------------------------------------------------------
   // read
   // -----------------------------------------------------------------

   else if ( wr == 0 ) {
      PRINTout("libneTest: reading %llu bytes from erasure striping "
               "(N=%d,E=%d,offset=%d) to file %s\n", totbytes, N, E, start, argv[2] );

      buff = malloc( sizeof(char) * totbytes );
      PRINTout("libneTest: allocated buffer of size %llu\n", sizeof(char) * totbytes );

      filefd = open( argv[2], O_WRONLY | O_CREAT, 0644 );
      if ( filefd == -1 ) {
         PRINTerr("libneTest: failed to open file %s\n", argv[2] );
         return -1;
      }

      if ( N == 0 ) {
         handle = NE_OPEN( (char *)argv[3], NE_RDONLY | NE_NOINFO );
      }
      else {
         handle = NE_OPEN( (char *)argv[3], NE_RDONLY, start, N, E );
      }

      if ( handle == NULL ) {
         PRINTerr("libneTest: ne_open failed\n   Errno: %d\n   Message: %s\n", errno, strerror(errno) );
         return -1;
      }
      
      toread = (rand() % totbytes) + 1;
      if ( toread > totbytes ) { exit(1000); }
      nread = 0;

      while ( totbytes > 0 ) {
         PRINTout("libneTest: preparing to read %llu from erasure files with offset %llu\n", toread, nread );
         if ( toread > totbytes ) { exit(1000); }

         tmp = ne_read( handle, buff, toread, nread );

         if( toread != tmp ) {
            PRINTerr("libneTest: unexpected # of bytes read by ne_read\n");
            PRINTerr("libneTest:  got %d but expected %llu\n", tmp, toread );
            return -1;
         }

         PRINTout("libneTest: ...done.  Writing %llu to output file.\n", toread );
         write( filefd, buff, toread );

         totbytes -= toread;
         nread += toread;
         totdone += toread;
         if ( totbytes != 0 )
            toread = ( rand() % totbytes ) + 1;
      }

      free(buff); 
      close(filefd);
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
        printf("rebuild result %d, errno=%d (%s)\n", tmp, errno, strerror(errno));
        PRINTerr("libneTest: rebuild failed!\n" );
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
         PRINTerr("libneTest: ne_status failed!\n" );
         return -1;
      }
      printf( "N: %d  E: %d  bsz: %d  Start-Pos: %d  totsz: %llu\nExtended Attribute Errors : ",
              stat->N, stat->E, stat->bsz, stat->start, (unsigned long long)stat->totsz );
      for( tmp = 0; tmp < ( stat->N+stat->E ); tmp++ ){
         printf( "%d ", stat->xattr_status[tmp] );
      }
      printf( "\nData/Erasure Errors : " );
      for( tmp = 0; tmp < ( stat->N+stat->E ); tmp++ ){
         printf( "%d ", stat->data_status[tmp] );
      }
      printf( "\n" );
      free(stat);

      tmp=0;
      /* Encode any file errors into the return status */
      for( filefd = 0; filefd < stat->N+stat->E; filefd++ ) {
         if ( stat->data_status[filefd] || stat->xattr_status[filefd] ) { tmp += ( 1 << ((filefd + stat->start) % (stat->N+stat->E)) ); }
      }

      printf("%d\n",tmp);

      return tmp;
   }


   // -----------------------------------------------------------------
   // delete
   // -----------------------------------------------------------------

   else if ( wr == 4 ) {
      PRINTout("libneTest: deleting striping corresponding to path \"%s\" with width %d...\n", (char*)argv[2], N );
      if ( ne_delete( (char*) argv[2], N ) ) {
         PRINTerr("libneTest: deletion attempt indicates a failure for path \"%s\"\n", (char*)argv[2] );
         return -1;
      }
      PRINTout("libneTest: deletion successful\n" );
      return 0;
   }



   tmp = ne_close( handle );
   fflush(stdout);
   printf("%d\n",tmp);

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


