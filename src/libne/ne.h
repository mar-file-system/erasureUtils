#ifndef __NE_H__
#define __NE_H__

#ifdef __cplusplus
extern "C" {
#endif

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


#define INT_CRC
#define META_FILES

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>

#define LOG_PREFIX "libne"
#include "logging/logging.h"

#include <libxml/tree.h>

#ifndef LIBXML_TREE_ENABLED
#error "Included Libxml2 does not support tree functionality!"
#endif


/* MIN_PROTECTION sets the threshold for when writes will fail.  If
   fewer than n+MIN_PROTECTION blocks were written successfully, then
   the write will fail. */
#define MIN_PROTECTION 1

/* MIN_MD_CONSENSUS defines the minimum number of metadata files/xattrs we
   have to look at, which are all in agreement about the values for N and
   E, before ne_status1() will believe that it knows what N+E is.  In the
   case of META_FILES being defined, this avoids doing (MAXN + MAXE) -
   (N+E) failed stats for every ne_status(), ne_read(), etc. (In the case
   of UDAL_SOCKETS, each of those failed "stats" results in an attempt to
   connect to a non-existent server, which must then time out.  */
#define MIN_MD_CONSENSUS  2

#define MAXN 9999
#define MAXE 9999

#define MAXNAME 2048
#define MAXBUF 4096
#define MAXBLKSZ 16777216
#define BLKSZ 1048576
#define HEADSZ 70
#define TEST_SEED 57

#define METALEN 125
#define MAXPARTS (MAXN + MAXE)
#define NO_INVERT_MATRIX -2

#define UNSAFE(HANDLE, NERR) ( (NERR)  &&  (NERR > ((HANDLE)->erasure_state->E - MIN_PROTECTION)) )

typedef uint32_t u32;
typedef uint64_t u64;

typedef enum {
  NE_RDONLY  = 1,         //1  -- read data, only read erasure when necessary for reconstruction
  NE_RDALL,               //2  -- read data and all erasure, regardless of data state
  NE_WRONLY,              //3  -- write data and erasure to new stripe
  NE_WRALL = NE_WRONLY,   //   -- same as above, defined just to avoid confusion
} ne_mode;

#define MAX_QDEPTH      2
#define MAX_RD_QDEPTH   3   /* (unused) */

typedef struct ne_erasure_struct {
   int N;
   int E;
   int O;
   size_t partsz;
   char crcs;
} ne_erasure;

typedef struct ne_state_struct {
   // striping size
   size_t blocksz;
   size_t totsz;

   // striping health
   char* meta_status; // user allocated region, must be at least ( sizeof(char) * max_block ) bytes; ignored if NULL
   char* data_status; // user allocated region, must be at least ( sizeof(char) * max_block ) bytes; ignored if NULL

   // per-part info
   u64* csum;       // user allocated region, must be at least ( sizeof(u64) * max_block ) bytes; ignored if NULL
   size_t* ncompsz; // user allocated region, must be at least ( sizeof(size_t) * max_block ) bytes; ignored if NULL
} ne_state;

// location struct
typdef struct ne_location_struct {
   int pod;
   int cap;
   int scatter;
} ne_location;



/*
 ---  Initialization/Termination functions, to produce and destroy a ne_ctxt  ---
*/

// context struct
typedef struct ne_ctxt_struct* ne_ctxt; // forward decl.

/**
 * Initializes a new ne_ctxt
 * @param xmlNode* dal_root : Root of a libxml2 DAL node describing data access
 * @param ne_location max_loc : ne_location struct containing maximum allowable pod/cap/scatter 
 *                              values for this context
 * @param int max_block : Integer maximum block value ( N + E ) for this context
 * @return ne_ctxt : New ne_ctxt or NULL if an error was encountered
 */
ne_ctxt ne_init( xmlNode* dal_root, ne_location max_loc, int max_block );

/**
 * Destroys an existing ne_ctxt
 * @param ne_ctxt ctxt : Reference to the ne_ctxt to be destroyed
 * @return int : Zero on a success, and -1 on a failure
 */
int ne_term ( ne_ctxt ctxt );



/*
 ---  Per-Object functions, to perform a given op on a specific object  ---
*/

/**
 * Determine the erasure structure of a given object
 * @param ne_ctxt ctxt : The ne_ctxt used to access this data stripe
 * @param const char* objID : ID of the object to stat
 * @param ne_location loc : Location of the object to stat
 * @param ne_erasure* epat : Address of an ne_erasure struct to be populated
 * @param ne_state* state : Address of an ne_state struct to be populated (ignored, if NULL)
 * @return int : Zero if no stripe errors were found, a positive integer bitmask of any repaired 
 *               errors, or a negative value if an unrecoverable failure occurred
 */
int ne_stat( ne_ctxt ctxt, const char* objID, ne_location loc, ne_erasure* epat, ne_state* state );

/**
 * Verify a given erasure striped object and reconstruct any damaged data, if possible
 * @param ne_ctxt ctxt : The ne_ctxt used to access this data stripe
 * @param const char* objID : ID of the object to be rebuilt
 * @param ne_location loc : Location of the object to be rebuilt
 * @param ne_erasure epat : Erasure pattern of the object to be rebuilt
 * @param ne_state* state : Address of an ne_state struct to be populated (ignored, if NULL)
 * @return int : Zero if no stripe errors were found, a positive integer bitmask of any repaired 
 *               errors, or a negative value if an unrecoverable failure occurred
 */
int ne_rebuild( ne_ctxt ctxt, const char* objID, ne_location loc, ne_erasure epat, ne_state* state );

/**
 * Delete a given object
 * @param ne_ctxt ctxt : The ne_ctxt used to access this data stripe
 * @param const char* objID : ID of the object to be rebuilt
 * @param ne_location loc : Location of the object to be rebuilt
 * @return int : Zero on success and -1 on failure
 */
int ne_delete( ne_ctxt ctxt, const char* objID, ne_location loc );



/*
 ---  Stream functions, to write/read a specific object  ---
*/

// handle struct
typedef struct ne_handle_struct* ne_handle; // forward decl.

/**
 * Create a new handle for reading or writing a specific object
 * @param ne_ctxt ctxt : The ne_ctxt used to access this data stripe
 * @param const char* objID : ID of the object to be rebuilt
 * @param ne_location loc : Location of the object to be rebuilt
 * @param ne_erasure epat : Erasure pattern of the object to be rebuilt
 * @param ne_mode mode : Handle mode (NE_RDONLY || NE_RDALL || NE_WRONLY || NE_WRALL)
 * @return ne_handle : Newly created ne_handle, or NULL if an error occured
 */
ne_handle ne_open( ne_ctxt ctxt, const char* objID, ne_location loc, ne_erasure epat, ne_mode mode );

/**
 * Read from a given NE_RDONLY or NE_RDALL handle
 * @param ne_handle handle : The ne_handle reference to read from
 * @param off_t offset : Offset at which to read
 * @param void* buffer : Reference to a buffer to be filled with read data
 * @param size_t bytes : Number of bytes to be read
 * @return ssize_t : The number of bytes successfully read, or -1 on a failure
 */
ssize_t ne_read( ne_handle handle, off_t offset, void* buffer, size_t nbytes );

/**
 * Write to a given NE_WRONLY or NE_WRALL handle
 * @param ne_handle handle : The ne_handle reference to write to
 * @param const void* buffer : Buffer to be written to the handle
 * @param size_t bytes : Number of bytes to be written from the buffer
 * @return ssize_t : The number of bytes successfully written, or -1 on a failure
 */
ssize_t ne_write( ne_handle handle, const void* buffer, size_t nbytes );

/**
 * Close an open ne_handle
 * @param ne_handle handle : The ne_handle reference to close
 * @param ne_state* state : Address of an ne_state struct to be populated (ignored, if NULL)
 * @return int : Zero on success, and -1 on a failure
 */
int ne_close( ne_handle handle, ne_state* state );


#ifdef __cplusplus
}
#endif

#endif

