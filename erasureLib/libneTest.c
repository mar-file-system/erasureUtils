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


int crc_status() {
#ifdef INT_CRC
   printf("Intermediate-CRCs: Active\n");
   return 0;
#else
   printf("Intermediate-CRCs: Inactive\n");
   return 1;
#endif
}



#if (SOCKETS != SKT_none)

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
           (!strncmp(op, CMD, 10) ? "->" : ""), (CMD), (ARGS))

   USAGE("read",       "erasure_path N E start_file [-t timing_flags] [-r] [-s input_size] [-o output_file]");
   USAGE("write",      "erasure_path N E start_file [-t timing_flags] [-r] [-s input_size] [-i input_file]");
   USAGE("verify",     "erasure_path N E start_file [-t timing_flags] [-r] [-s input_size] [-o output_file]");
   USAGE("rebuild",    "erasure_path N E start_file [-t timing_flags]");
   USAGE("delete",     "erasure_path stripe_width   [-t timing_flags] [-f]");
   USAGE("stat",       "erasure_path                [-t timing_flags]");
   USAGE("crc-status", "");
   USAGE("help",       "");

   PRINTlog("\n");
   PRINTlog("\n");
   PRINTlog("  NOTES:\n");
   PRINTlog("     read/write/verify   Use a fixed transfer size (slightly larger than a libne stripe),\n" \
"                            but can use a random transfer-size (<= fixed size) if '-r' is specified.\n");
   PRINTlog("\n");
   PRINTlog("     output_file         If not specified for read, the retrieved data will simply be \n"
"                            discarded.\n");
   PRINTlog("\n");
   PRINTlog("     input_file          If not specified for write, a stream of zeros will be stored to \n"
"                            the erasure stripe up to the given input_size.  Specifiying \n"
"                            neither '-s' nor '-i' for a write operation will result in \n"
"                            an error condition.\n");
   PRINTlog("\n");
   PRINTlog("     <timing_flags>      can be decimal, or can be hex-value starting with \"0x\"\n");
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



int parse_flags(TimingFlagsValue* flags, const char* str) {
   if (! str)
      *flags = 0;
   else {
      errno = 0;
      // strtol() already detects the '0x' prefix for us
      *flags = (TimingFlagsValue)strtol(str, NULL, 0);
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
#if (SOCKETS != SKT_none)
   return (strchr(path, ':')
           ? snprintf_for_vle      // MC over RDMA-sockets
           : ne_default_snprintf); // MC over NFS
#else
   return ne_default_snprintf; // MC over NFS
#endif
}




int main( int argc, const char** argv ) 
{
   void* buff;
   unsigned long long totdone = 0;

   char wr = -1;  // defines the operation being performed ( 0 = read, 1 = write, 2 = rebuild, 3 = verify, 4 = stat, 5 = delete )
   int filefd;
   int N = -1;
   int E = -1;
   int O = -1;
   char* erasure_path = NULL;
   TimingFlagsValue   timing_flags = 0;
   int                parse_err = 0;
   char               size_arg = 0;
   char               rand_size = 0;
   char               force_delete = 0;
   char* output_file = NULL;
   char* input_file  = NULL;

   unsigned long long buff_size = ( BLKSZ + 1 ) * MAXN; //choose a buffer size that can potentially read beyond a stripe boundary
   size_t totbytes = buff_size;

   LOG_INIT();

   char pr_usage = 0;
   int c;
   // parse all position-independent arguments
   while ( (c = getopt( argc, (char* const*)argv, "t:i:o:s:rfh" )) != -1 ) {
      switch (c) {
         char* endptr;
         case 't':
            if ( parse_flags(&timing_flags, optarg) ) {
               PRINTlog( "failed to parse timing flags value: \"%s\"\n", optarg );
               pr_usage = 1;
            }
            break;
         case 'i':
            input_file = optarg;
            break;
         case 'o':
            output_file = optarg;
            break;
         case 's':
            size_arg = 1;
            totbytes = strtoll(optarg, &endptr, 10);
            // afterwards, check for a parse error
            if ( *endptr != '\0' ) {
               PRINTlog( "%s: failed to parse argument for '-s' option: \"%s\"\n", argv[0], optarg );
               usage( argv[0], "help" );
               return -1;
            }
            break;
         case 'r':
            rand_size = 1;
            break;
         case 'f':
            force_delete = 1;
            break;
         case 'h':
            usage( argv[0], "help" );
            return 0;
         case '?':
            pr_usage = 1;
            break;
         default:
            PRINTlog( "failed to parse command line options\n" );
            return -1;
      }
   }

   char* operation = NULL;
   // parse all position/command-dependent arguments
   for ( c = optind; c < argc; c++ ) {
      if ( wr < 0 ) { // if no operation specified, the first arg should define it
         if ( strcmp( argv[c], "read"    ) == 0 )
            wr = 0;
         else if ( strcmp( argv[c], "write"    ) == 0 )
            wr = 1;
         else if ( strcmp( argv[c], "verify"    ) == 0 )
            wr = 2;
         else if ( strcmp( argv[c], "rebuild"    ) == 0 )
            wr = 3;
         else if ( strcmp( argv[c], "delete"    ) == 0 )
            wr = 4;
         else if ( strcmp( argv[c], "stat"    ) == 0 )
            wr = 5;
         else if ( strcmp( argv[c], "crc-status" ) == 0 ) {
            PRINTout( "MAXN: %d     MAXE: %d\n", MAXN, MAXE );
            crc_status();
            return 0;
         }
         else if ( strcmp( argv[c], "help" ) == 0 ) {
            usage( argv[0], argv[c] );
            return 0;
         }
         else {
            PRINTlog( "%s: unrecognized operation argument provided: \"%s\"\n", argv[0], argv[c] );
            usage( argv[0], "help" );
            return -1;
         }
         operation = (char *)argv[c];
      }
      else if ( erasure_path == NULL ) { // all operations require this as the next argument
         erasure_path = (char *)argv[c];
      }
      else if ( (wr < 4)  &&  (O == -1) ) { // loop through here until N/E/O are populated, if this operation needs them
         char val = '\0';
         char* endptr = &val;
         if ( N == -1 ) {
            val = 'N';
            N = strtol( argv[c], &endptr, 10 );
         }
         else if ( E == -1 ) {
            val = 'E';
            E = strtol( argv[c], &endptr, 10 );
         }
         else {
            val = 'O';
            O = strtol( argv[c], &endptr, 10 );
         }
         // afterwards, check for a parse error
         if ( *endptr != '\0' ) {
            PRINTlog( "%s: failed to parse value for %c: \"%s\"\n", argv[0], val, argv[c] );
            usage( argv[0], operation );
            return -1;
         }
      }
      else if ( (wr == 4)  &&  (N == -1) ) { // for delete, store the stripe width to 'N'
         char* endptr;
         N = strtol( argv[c], &endptr, 10 );
         if ( *endptr != '\0' ) {
            PRINTlog( "%s: failed to parse value for stripe-width: \"%s\"\n", argv[0], argv[c] );
            usage( argv[0], operation );
            return -1;
         }
      }
      else {
         PRINTlog( "%s: encountered unrecognized argument: \"%s\"\n", argv[0], argv[c] );
         usage( argv[0], operation );
         return -1;
      }
   }

   // verify that we received all required args
   if ( operation == NULL ) {
      PRINTlog( "%s: no operation specified\n", argv[0] );
      usage( argv[0], "help" );
      return -1;
   }
   if ( erasure_path == NULL  ||  ( (wr != 5) && (N == -1) )  ||  ( (wr < 4) && (O == -1) ) ) {
      PRINTlog( "%s: missing required arguments for operation: \"%s\"\n", argv[0], operation );
      usage( argv[0], operation );
      return -1;
   }

   // warn if improper args were specified for a given op
   if ( ( input_file != NULL )  &&  ( wr != 1 ) ) {
      PRINTlog( "%s: the '-i' flag is not applicable to operation: \"%s\"\n", argv[0], operation );
      usage( argv[0], operation );
      return -1;
   }

   if ( (rand_size)  &&  ( wr > 2 ) ) {
      PRINTlog( "%s: the '-r' flag is not applicable to operation: \"%s\"\n", argv[0], operation );
      usage( argv[0], operation );
      return -1;
   }

   if ( (size_arg)  &&  ( wr > 2 ) ) {
      PRINTlog( "%s: the '-s' flag is not applicable to operation: \"%s\"\n", argv[0], operation );
      usage( argv[0], operation );
      return -1;
   }

   if ( ( output_file != NULL )  &&  ( wr != 0  &&  wr != 2 ) ) {
      PRINTlog( "%s: the '-o' flag is not applicable to operation: \"%s\"\n", argv[0], operation );
      usage( argv[0], operation );
      return -1;
   }

   if ( (wr == 1)  &&  (input_file == NULL)  &&  !(size_arg) ) {
      PRINTlog( "%s: missing required arguments for operation: \"%s\"\n", argv[0], operation );
      PRINTlog( "%s: write operations require one or both of the '-s' and '-i' options\n", argv[0] );
      usage( argv[0], operation );
      return -1;
   }

   // if we've made it all the way here without hitting a hard error, make sure to still print usage from a previous 'soft' error
   if ( pr_usage ) {
      usage( argv[0], operation );
      return -1;
   }
   
   PRINTdbg("libneTest: command = '%s'\n", operation);

#  define NE_OPEN(PATH, MODE, ...)    ne_open1  (select_snprintf(PATH), NULL, select_impl(PATH), auth, \
                                                 timing_flags, NULL,    \
                                                 (PATH), (MODE), ##__VA_ARGS__ )

#  define NE_DELETE(PATH, WIDTH)      ne_delete1(select_snprintf(PATH), NULL, select_impl(PATH), auth, \
                                                 timing_flags, NULL,    \
                                                 (PATH), (WIDTH))

#  define NE_STATUS(PATH)             ne_status1(select_snprintf(PATH), NULL, select_impl(PATH), auth, \
                                                 timing_flags, NULL,    \
                                                 (PATH))

# define NE_STAT_CALL(PATH, E_STRUCT)      ne_stat1(select_snprintf(PATH), NULL, select_impl(PATH), auth, \
                                                 timing_flags, NULL,    \
                                                 (PATH), (E_STRUCT) )

#  define NE_SIZE(PATH, QUOR, WIDTH)  ne_size1  (select_snprintf(PATH), NULL, select_impl(PATH), auth, \
                                                 timing_flags, NULL,    \
                                                 (PATH), (QUOR), (WIDTH))
   ne_handle handle;

   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("%s: failed to initialize default socket-authentication credentials\n", argv[0] );
      return -1;
   }
   int tmp;

   // -----------------------------------------------------------------
   // rebuild
   // -----------------------------------------------------------------

   if ( wr == 3 ) {
      PRINTout("libneTest: rebuilding erasure striping (N=%d,E=%d,offset=%d)\n", N, E, O );

      if ( (tmp = ne_rebuild( erasure_path, NE_REBUILD, O, N, E )) ) {
         PRINTout("rebuild result %d, errno=%d (%s)\n", tmp, errno, strerror(errno));
         PRINTlog("libneTest: rebuild failed!\n" );
         return -1;
      }
      PRINTout("libneTest: rebuild complete\n" );

      PRINTout("rebuild rc: %d\n",tmp);

      return tmp;
   }



   // -----------------------------------------------------------------
   // delete
   // -----------------------------------------------------------------

   if ( wr == 4 ) {
      char response;
      char iter = 0;
      while ( !(force_delete)  &&  response != 'y'  &&  response != 'Y' ) {
         response = '\n';
         PRINTout("libneTest: deleting striping corresponding to path \"%s\" with width %d...\n"
                  "Are you sure you wish to continue? (y/n): ", (char*)argv[2], N );
         fflush( stdout );
         while( response == '\n' )
            response = getchar();
         if ( response == 'n'  ||  response == 'N' )
            return -1;
         PRINTout( "libneTest: input unrecognized\n" );
         iter++; // see if this has happened a lot
         if ( iter > 4 ) {
            PRINTout( "libneTest: terminating due to excessive unrecognized user input\n" );
            return -1;
         }
      }
      if ( NE_DELETE( erasure_path, N ) ) {
         PRINTlog("libneTest: deletion attempt indicates a failure for path \"%s\"\n", (char*)argv[2] );
         return -1;
      }
      PRINTout("libneTest: deletion successful\n" );
      return 0;
   }


   // -----------------------------------------------------------------
   // stat
   // -----------------------------------------------------------------

   if ( wr == 5 ) {
      PRINTout("libneTest: retrieving status of erasure striping with path \"%s\"\n", (char *)argv[2] );
      struct ne_stat_struct stat_struct;
      e_status stat = &stat_struct;
      memset( stat, 0, sizeof( struct ne_stat_struct ) );

      if ( NE_STAT_CALL( erasure_path, stat ) ) {
         PRINTlog("libneTest: ne_status failed!\n" );
         return -1;
      }

      PRINTout( "N: %d  E: %d  bsz: %d  Start-Pos: %d  totsz: %llu\n",
                stat->N, stat->E, stat->bsz, stat->O, (unsigned long long)stat->totsz );
      PRINTout( "Extended Attribute Errors : ");
      for( tmp = 0; tmp < ( stat->N+stat->E ); tmp++ ){
         PRINTout( "%d ", stat->manifest_status[tmp] );
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
         if ( stat->data_status[filefd] || stat->manifest_status[filefd] ) {
            tmp += ( 1 << ((filefd + stat->O) % (stat->N+stat->E)) );
         }
      }
      printf("%d\n",tmp);

      return tmp;
   }


   // -----------------------------------------------------------------
   // read / write / verify
   // -----------------------------------------------------------------

   srand(time(NULL));

   // allocate space for a data buffer and zero out so that we could zero write using it
   buff = memset( malloc( sizeof(char) * buff_size ), 0, buff_size );
   if ( buff == NULL ) {
      PRINTlog( "libneTest: failed to allocate space for a data buffer\n" );
      return -1;
   }

   int std_fd = 0; // no way this FD gets reused, so safe to initialize to this
   if ( output_file != NULL )
      std_fd = open( output_file, O_WRONLY | O_CREAT | O_EXCL, 0600 );
   else if ( input_file != NULL )
      std_fd = open( input_file, O_RDONLY );

   // verify a proper open of our standard file
   if ( std_fd < 0 ) {
      if ( output_file != NULL )
         PRINTlog( "libneTest: failed to open output file \"%s\": %s\n", output_file, strerror(errno) );
      else
         PRINTlog( "libneTest: failed to open input file \"%s\": %s\n", input_file, strerror(errno) );
      free( buff );
      return -1;
   }

   if ( wr == 0 ) // read
      handle = ne_open( erasure_path, NE_RDONLY, O, N, E );
   else if ( wr == 1 ) // write
      handle = ne_open( erasure_path, NE_WRONLY, O, N, E );
   else if ( wr == 2 ) // verify
      handle = ne_open( erasure_path, NE_RDALL, O, N, E );

   // check for a successful open of the handle
   if ( handle == NULL ) {
      PRINTlog( "libneTest: failed to open the requested erasure path for a %s operation\n", operation );
      return -1;
   }

   unsigned long long toread;

   if (rand_size)
      toread = rand() % (buff_size+1);
   else
      toread = buff_size;
   if ( toread > totbytes )
      toread = totbytes;

   off_t bytes_moved = 0;
   while ( toread > 0 ) {

      // READ DATA
      ssize_t nread = toread; // assume success if no read takes place
      if ( (wr == 1)  &&  (std_fd) ) { // if input_file was defined, writes get data from it 
         PRINTdbg("libneTest: reading %llu bytes from \"%s\"\n", toread, input_file );
         nread = read( std_fd, buff, toread );
      }
      else if ( wr != 1 ) { // read/verify get data from the erasure stripe
         PRINTdbg("libneTest: reading %llu bytes from erasure stripe\n", toread );
         nread = ne_read( handle, buff, toread, bytes_moved );
      }

      // check for a read error
      if ( (nread < 0)  ||  ( (size_arg) && (nread < toread) ) ) {
         PRINTlog( "libneTest: expected to read %llu bytes from source but instead received: %zd\n", toread, nread );
         free( buff );
         ne_close( handle );
         if ( std_fd )
            close( std_fd );
         return -1;
      }

      // WRITE DATA
      if ( wr == 1 ) { // for write, just output to the stripe
         PRINTdbg( "libneTest: writing %zd bytes to erasure stripe\n", nread );
         nread = ne_write( handle, buff, nread );
      }
      else if ( std_fd ) { // for read/verify, only write out if given the -o flag
         PRINTdbg( "libneTest: writing %zd bytes to \"%s\"\n", nread, output_file );
         nread = write( std_fd, buff, nread );
      }
 
      // check for a write error
      if ( (nread < 0)  ||  ( (size_arg) && (nread < toread) ) ) {
         PRINTlog( "libneTest: expected to write %llu bytes but instead wrote: %zd\n", toread, nread );
         free( buff );
         ne_close( handle );
         if ( std_fd )
            close( std_fd );
         return -1;
      }

      // increment our counters
      bytes_moved += nread;

      // determine how much to read next time
      if (rand_size)
         toread = rand() % (buff_size+1);
      else
         toread = buff_size;
      if ( (size_arg)  &&  (toread > (totbytes - bytes_moved)) )
         toread = totbytes - bytes_moved;
      // if size wasn't specified, only read until we can't any more
      if ( !(size_arg)  &&  (nread < toread) )
         toread = 0;

   }

   PRINTout( "libneTest: all data movement completed (%llu bytes)\n", bytes_moved );

   if ( std_fd  &&  close( std_fd ) ) {
      if ( wr == 1 )
         PRINTlog( "libneTest: encountered an error when trying to close input file\n" );
      else
         PRINTlog( "libneTest: encountered an error when trying to close output file\n" );
   }
      

   // close the handle and indicate it's close condition
   tmp = ne_close( handle );
   PRINTout("close rc: %d\n",tmp);

   return tmp;
}

