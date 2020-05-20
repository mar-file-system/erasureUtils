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



 

/* ---------------------------------------------------------------------------

This file provides the implementation of multiple operations intended for
use by the MarFS MultiComponent DAL.

These include:   ne_read(), ne_write(), ne_health(), and ne_rebuild().

Additionally, each output file gets an xattr added to it (yes all 12 files
in the case of a 10+2 the xattr looks something like this:

   10 2 64 0 196608 196608 3304199718723886772 1717171

These fields, in order, are:

    N         is nparts
    E         is numerasure
    offset    is the starting position of the stripe in terms of part number
    chunksize is chunksize
    nsz       is the size of the part
    ncompsz   is the size of the part but might get used if we ever compress the parts
    totsz     is the total real data in the N part files.

Since creating erasure requires full stripe writes, the last part of the
file may all be zeros in the parts.  Thus, totsz is the real size of the
data, not counting the trailing zeros.

All the parts and all the erasure stripes should be the same size.  To fill
in the trailing zeros, this program uses truncate - punching a hole in the
N part files for the zeros.

In the case where libne is built to include support for S3-authentication,
and to use the libne sockets extensions (RDMA, etc) instead of files, then
the caller (for example, the MarFS sockets DAL) may acquire
authentication-information at program-initialization-time which we could
not acquire at run-time.  For example, access to authentication-information
may require escalated privileges, whereas fuse and pftool de-escalate
priviledges after start-up.  To support such cases, we must allow a caller
to pass cached credentials through the ne_etc() functions, to the
underlying skt_etc() functions.

--------------------------------------------------------------------------- */

// #include "libne_auto_config.h"   /* HAVE_LIBISAL */

#define DEBUG 1
#define USE_STDOUT 1
#define LOG_PREFIX "metainfo"
#include "logging/logging.h"

#include "io/io.h"
#include "dal/dal.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>



/* ------------------------------   INTERNAL HELPER FUNCTIONS   ------------------------------ */


// Internal helper function
// Estimate the space required for a meta_info string representation
size_t get_minfo_strlen( ) {
   // Note: Binary 3bits == max value of 7, so decimal representation requires at most 1byte per 3bits of the struct 
   //       plus an additional 8bytes for whitespace and the terminating null character.
   return ( ( sizeof( struct meta_info_struct ) * 8 ) / 3 ) + 8;
}



/* ------------------------------   META INFO TRANSLATION   ------------------------------ */


/**
 * Perform a DAL get_meta call and parse the resulting string 
 * into the provided meta_info_struct reference.
 * @param DAL dal : Dal on which to perfrom the get_meta operation
 * @param int block : Block on which this operation is being performed (for logging only)
 * @param meta_info* minfo : meta_info reference to populate with values 
 * @return int : Zero on success, a negative value if a failure occurred, or the number of 
 *               meta values successfully parsed if only portions of the meta info could 
 *               be recovered.
 */
int dal_get_minfo( DAL dal, BLOCK_CTXT handle, meta_info* minfo ) {
   // Allocate space for a string
   size_t strmax = get_minfo_strlen();
   char* str = (char*) malloc( strmax );
   if ( str == NULL ) {
      LOG( LOG_ERR, "failed to allocate space for a meta_info string!\n" );
      return -1;
   }
   // set stand-ins for all values
   minfo->N = 0;
   minfo->E = -1;
   minfo->O = -1;
   minfo->partsz  = -1;
   minfo->versz   = -1;
   minfo->blocksz = -1;
   minfo->crcsum  = -1;
   minfo->totsz   = -1;
   // get the meta info for the given object
   if ( dal->get_meta( handle, str, strmax ) <= 0 ) {
      LOG( LOG_ERR, "failed to retrieve meta value!\n" );
      free( str );
      return -1;
   }

   int status = 8; // initialize to the number of values we expect to parse
   // Parse the string into appropriate meta_info fields
   // declared here so that the compiler can hopefully free up this memory outside of the 'else' block
   char metaN[5];        /* char array to get n parts from the meta string */
   char metaE[5];        /* char array to get erasure parts from the meta string */
   char metaO[5];        /* char array to get erasure offset from the meta string */
   char metapartsz[20];  /* char array to get erasure partsz from the meta string */
   char metaversz[20];   /* char array to get compressed block size from the meta string */
   char metablocksz[20]; /* char array to get complete block size from the meta string */
   char metacrcsum[20];  /* char array to get crc sum from the meta string */
   char metatotsize[20]; /* char array to get object totsz from the meta string */
   
   // only process the meta string if we successfully retreived it
   int ret = sscanf(str,"%4s %4s %4s %19s %19s %19s %19s %19s",
                        metaN,
                        metaE,
                        metaO,
                        metapartsz,
                        metaversz,
                        metablocksz,
                        metacrcsum,
                        metatotsize);
   free( str );
   if ( ret < 1 ) {
      LOG( LOG_ERR, "sscanf failed to parse any values from meta info!\n" );
      return -1;
   }
   if (ret != 8) {
      LOG( LOG_WARNING, "sscanf parsed only %d values from meta info: \"%s\"\n", ret, str);
      status = ret;
   }  
   
   char* endptr;
   // simple macro to save some repeated lines of code
   // this is used to parse all meta values, check for errors, and assign them to their appropriate locations
#define PARSE_VALUE( VAL, STR, GT_VAL, PARSE_FUNC, TYPE ) \
   if ( ret > GT_VAL ) { \
      TYPE tmp_val = (TYPE) PARSE_FUNC ( STR, &(endptr), 10 ); \
      if ( *(endptr) == '\0'  &&  (tmp_val > VAL ) ) { \
         VAL = tmp_val; \
      } \
      else { \
         LOG( LOG_ERR, "failed to parse meta value at position %d: \"%s\"\n", GT_VAL, STR ); \
         status -= 1; \
      } \
   }
   // Parse all values into the meta_info struct
   PARSE_VALUE(       minfo->N,       metaN, 0,  strtol, int )
   PARSE_VALUE(       minfo->E,       metaE, 1,  strtol, int )
   PARSE_VALUE(       minfo->O,       metaO, 2,  strtol, int )
   PARSE_VALUE(  minfo->partsz,  metapartsz, 3,  strtol, ssize_t )
   PARSE_VALUE(   minfo->versz,   metaversz, 4,  strtol, ssize_t )
   PARSE_VALUE( minfo->blocksz, metablocksz, 5,  strtol, ssize_t )
   PARSE_VALUE(  minfo->crcsum,  metacrcsum, 6, strtoll, long long )
   PARSE_VALUE(   minfo->totsz, metatotsize, 7, strtoll, ssize_t )

   return ( status == 8 ) ? 0 : status;
}


/**
 * Convert a meta_info struct to string format and perform a DAL set_meta call
 * @param DAL dal : Dal on which to perfrom the get_meta operation
 * @param BLOCK_CTXT handle : Block on which this operation is being performed
 * @param meta_info* minfo : meta_info reference to populate with values 
 * @return int : Zero on success, or a negative value if an error occurred 
 */
int dal_set_minfo( DAL dal, BLOCK_CTXT handle, meta_info* minfo ) {
   // Allocate space for a string
   size_t strmax = get_minfo_strlen();
   char* str = (char*) malloc( strmax );
   if ( str == NULL ) {
      LOG( LOG_ERR, "failed to allocate space for a meta_info string!\n" );
      return -1;
   }

	// fill the string allocation with meta_info values
   if ( snprintf(str,strmax,"%d %d %d %zu %zu %zu %llu %zu\n",
                  minfo->N, minfo->E, minfo->O,
                  minfo->partsz, minfo->versz,
                  minfo->blocksz, minfo->crcsum,
                  minfo->totsz) < 0 ) {
      LOG( LOG_ERR, "failed to convert meta_info to string format!\n" );
      free( str );
      return -1;
   }

	if ( dal->set_meta( handle, str, strlen( str ) ) ) {
		LOG( LOG_ERR, "failed to set meta value!\n" );
		free( str );
		return -1;
	}

   free( str );
	return 0;
}


