#include <erasure.h>

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

These erasure utilites make use of the Intel Intelligent Storage Acceleration Library (Intel ISA-L), which can be found at https://github.com/01org/isa-l and is under its own license.

MarFS uses libaws4c for Amazon S3 object communication. The original version
is at https://aws.amazon.com/code/Amazon-S3/2601 and under the LGPL license.
LANL added functionality to the original work. The original work plus
LANL contributions is found at https://github.com/jti-lanl/aws4c.

GNU licenses can be found at http://www.gnu.org/licenses/.
*/

#endif

#include <time.h>

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

   fprintf(stdout, "libTest: Running.  Preparing to parse args...\n");


   if ( argc < 2 ) {
      fprintf( stderr, "libTest: no operation (read/write) was specified!\n");
      return -1;
   }

   if ( strncmp( argv[1], "write", strlen(argv[1]) ) == 0 ) {
      if ( argc < 7 ) { 
         fprintf(stderr,"libTest: insufficient arguments for a write operation\nlibTest:   expected \'%s %s input_file output_path N E start_file [input_size]\'\n", argv[0], argv[1] ); 
         return -1;
      }
      wr = 1;
   }
   else if ( strncmp( argv[1], "read", strlen(argv[1]) ) == 0 ) {
      if ( argc < 8 ) { 
         fprintf(stderr,"libTest: insufficient arguments for a read operation\nlibTest:   expected \'%s %s output_file erasure_path N E start_file total_bytes\'\n", argv[0], argv[1] ); 
         return -1;
      }
      wr = 0;
   }
   else if ( strncmp( argv[1], "rebuild", strlen(argv[1]) ) == 0 ) {
      if ( argc < 6  ||  argc > 6 ) { 
         fprintf(stderr,"libTest: inappropriate arguments for a rebuild operation\nlibTest:   expected \'%s %s erasure_path N E start_file\'\n", argv[0], argv[1] ); 
         return -1;
      }
      wr = 2;
   }
   else if ( strncmp( argv[1], "status", strlen(argv[1]) ) == 0 ) {
      if ( argc < 6  ||  argc > 6 ) { 
         fprintf(stderr,"libTest: inappropriate arguments for a status operation\nlibTest:   expected \'%s %s erasure_path N E start_file\'\n", argv[0], argv[1] ); 
         return -1;
      }
      wr = 3;
   }
   else if ( strncmp( argv[1], "crc-status", strlen(argv[1]) ) == 0 ) {
      return crc_status();
   }
   else {
      fprintf( stderr, "libTest: argument 1 not recognized, expecting \"read\" or \"write\"\n" );
      return -1;
   }
   

   if ( wr < 2 ) {
      N = atoi(argv[4]);
      E = atoi(argv[5]);
      start = atoi(argv[6]);
   }
   else {
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
 
   srand(time(NULL));
   ne_handle handle;

   if ( wr == 1 ) { //write

      buff = malloc( sizeof(char) * totbytes );

      fprintf( stdout, "libTest: writing content of file %s to erasure striping (N=%d,E=%d,offset=%d)\n", argv[2], N, E, start );

      filefd = open( argv[2], O_RDONLY );
      if ( filefd == -1 ) {
         fprintf( stderr, "libTest: failed to open file %s\n", argv[2] );
         return -1;
      }

      handle = ne_open( (char *)argv[3], NE_WRONLY, start, N, E );
      if ( handle == NULL ) {
         fprintf( stderr, "libTest: ne_open failed\n   Errno: %d\n   Message: %s\n", errno, strerror(errno) );
         return -1;
      }

      toread = rand() % (totbytes+1);

      while ( totbytes != 0 ) {
         nread = read( filefd, buff, toread );
         fprintf( stdout, "libTest: preparing to write %llu to erasure files...\n", nread );
         if ( nread != ne_write( handle, buff, nread ) ) {
            fprintf( stderr, "libTest: unexpected # of bytes written by ne_write\n" );
            return -1;
         }
         fprintf( stdout, "libTest: write successful\n" );

         if ( argc == 8 ) {
            totbytes -= nread;
         }
         else if (toread != 0  &&  nread == 0) {
            totbytes = 0;
         }
         totdone += nread;

         toread = rand() % (totbytes+1);
      }

      free(buff);
      close(filefd);
      fprintf( stdout, "libTest: all writes completed\nlibTest: total written = %llu\n", totdone );

   }
   else if ( wr == 0 ) { //read
      fprintf( stdout, "libTest: reading %llu bytes from erasure striping (N=%d,E=%d,offset=%d) to file %s\n", totbytes, N, E, start, argv[2] );

      buff = malloc( sizeof(char) * totbytes );
      fprintf( stdout, "libTest: allocated buffer of size %llu\n", sizeof(char) * totbytes );

      filefd = open( argv[2], O_WRONLY | O_CREAT, 0644 );
      if ( filefd == -1 ) {
         fprintf( stderr, "libTest: failed to open file %s\n", argv[2] );
         return -1;
      }

      handle = ne_open( (char *)argv[3], NE_RDONLY, start, N, E );
      if ( handle == NULL ) {
         fprintf( stderr, "libTest: ne_open failed\n   Errno: %d\n   Message: %s\n", errno, strerror(errno) );
         return -1;
      }
      
      toread = (rand() % totbytes) + 1;
      if ( toread > totbytes ) { exit(1000); }
      nread = 0;

      while ( totbytes > 0 ) {
         fprintf( stdout, "libTest: preparing to read %llu from erasure files with offset %llu\n", toread, nread );
         if ( toread > totbytes ) { exit(1000); }

         tmp = ne_read( handle, buff, toread, nread );

         if( toread != tmp ) {
            fprintf( stderr, "libTest: unexpected # of bytes read by ne_read\nlibTest:  got %d but expected %llu\n", tmp, toread );
            return -1;
         }

         fprintf( stdout, "libTest: ...done.  Writing %llu to output file.\n", toread );
         write( filefd, buff, toread );

         totbytes -= toread;
         nread += toread;
         totdone += toread;
         if ( totbytes != 0 )
            toread = ( rand() % totbytes ) + 1;
      }

      free(buff); 
      close(filefd);
      fprintf( stdout, "libTest: all reads completed\nlibTest: total read = %llu\n", totdone );
   }
   else if ( wr == 2 ) { //rebuild
      fprintf( stdout, "libTest: rebuilding erasure striping (N=%d,E=%d,offset=%d)\n", N, E, start );
      handle = ne_open( (char *)argv[2], NE_REBUILD, start, N, E );
      tmp = ne_rebuild( handle );
      if ( tmp != 0 ) {
         fprintf( stderr, "libTest: rebuild failed!\n" );
         return -1;
      }
      fprintf( stdout, "libTest: rebuild complete\n" );
   }
   else if ( wr == 3 ) { //status
      fprintf( stdout, "libTest: retrieving status of erasure striping (N=%d,E=%d,offset=%d)\n", N, E, start );
      handle = ne_open( (char *)argv[2], NE_REBUILD, start, N, E );
   }

   tmp = ne_close( handle );
   printf("%d\n",tmp);

   return tmp;

}


int crc_status() {
   #ifdef INT_CRC
      return 0;
   #else
      return 1;
   #endif
}


