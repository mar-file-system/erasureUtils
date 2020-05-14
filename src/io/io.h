#ifndef __IO_THREADS_H__
#define __IO_THREADS_H__

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

// THIS INTERFACE RELIES ON THE DAL INTERFACE!
#include "dal/dal.h"
#include <pthread.h>

#define SUPER_BLOCK_CNT 2
#define CRC_BYTES 4 // DO NOT decrease without adjusting CRC gen and block creation code!
#define CRC_SEED 


// forward declaration of DAL references (anything actually using this file will need to include "dal.h" as well!)
// typedef BLOCK_CTXT;
// typedef struct DAL_location_struct DAL_location;
// typedef enum DAL_MODE_enum DAL_MODE;
// typedef struct DAL_struct* DAL;


/* ------------------------------   META INFO   ------------------------------ */


// This struct is intended to allow read threads to pass
// meta-file/xattr info back to the ne_open() function
typedef struct meta_info_struct {
   int N;
   int E;
   int O;
   size_t partsz; 
   size_t versz;
   size_t blocksz; 
   unsigned long long crcsum;
   size_t totsz;
} meta_info;


/**
 * Perform a DAL get_meta call and parse the resulting string 
 * into the provided meta_info_struct reference.
 * @param DAL dal : Dal on which to perfrom the get_meta operation
 * @param int block : Block on which this operation is being performed (for logging only)
 * @param meta_info* minfo : meta_info reference to populate with values 
 * @return int : Zero on success, the number of 
 */
int dal_get_minfo( DAL dal, BLOCK_CTXT handle, meta_info* minfo );



/* ------------------------------   IO QUEUE   ------------------------------ */


typedef struct ioblock_struct {
   size_t data_size;    // amount of usable data contained in this buffer
   off_t  error_start;  // offset in buffer at which data errors begin
   void*  buff;         // buffer for data transfer
} ioblock;


// Queue of IOBlocks for thread communication
typedef struct ioqueue_struct {
   pthread_mutex_t qlock;        // lock for queue manipulation
   pthread_cond_t  avail_block;  // condition for awaiting an available block
   int             head;         // integer indicating location of the next available block
   int             depth;        // current depth of the queue
   ioblock         block_list[SUPER_BLOCK_CNT]; // list of ioblocks

   size_t          fill_threshold;
   size_t          split_threshold;

   size_t          partsz;       // size of each erasure part
   size_t          iosz;         // size of each IO
   int             partcnt;      // number of erasure parts each buffer can hold
   size_t          blocksz;      // size of each ioblock buffer
} ioqueue;



/**
 * Creates a new IOQueue
 * @param size_t iosz : Byte size of each IO to be performed
 * @param size_t partsz : Byte size of each erasure part
 * @return ioqueue* : Reference to the newly created IOQueue
 */
ioqueue* create_ioqueue( size_t iosz, size_t partsz, DAL_MODE mode );

/**
 * Destroys an existing IOQueue
 * @param ioqueue* ioq : Reference to the ioqueue struct to be destroyed
 * @return int : Zero on success and a negative value if an error occurred
 */
int destroy_ioqueue( ioqueue* ioq );

/**
 * Determines if a new ioblock is necessary to store additional data and, if so, reserves it.  Also, as ioblocks are filled, 
 * populates the 'push_block' reference with the ioblock that should be passed for read/write use.
 * @param ioblock** cur_block : Reference to be popluated with an updated ioblock (usable if return value == 0)
 * @param ioblock** push_block : Reference to be populated with a filled ioblock, ready to be passed for read/write use
 * @param ioqueue* ioq : Reference to the ioqueue struct from which ioblocks should be gathered
 * @return int : A positive value if the passed ioblock is full and push_block has been set (cur_block updated and push_block set),
 *               a value of zero if the current ioblock is now safe to fill (cur_block set to new ioblock reference OR unchanged), 
 *               and a negative value if an error was encountered.
 * 
 * NOTE: It is an error to write data of size != both erasure part size and the IO size to an ioblock.
 * 
 * NOTE -- it is possible, in the case of a full ioblock (return value == 1), for the newly reserved ioblock to ALSO be full.
 *         ONLY a return value of zero implies the current ioblock is safe for use!
 */
int reserve_ioblock( ioblock** cur_block, ioblock** push_block, ioqueue* ioq );

/**
 * Retrieve a buffer target reference for writing into the given ioblock
 * @param ioblock* block : Reference to the ioblock to retrieve a target for
 * @return void* : Buffer reference to write to
 */
void* ioblock_write_target( ioblock* block );

/**
 * Retrieve a buffer target reference for reading data from the given ioblock
 * @param ioblock* block : Reference to the ioblock to retrieve a target for
 * @param size_t* bytes : Reference to be populated with the data size of the ioblock
 * @return void* : Buffer reference to read from
 */
void* ioblock_read_target( ioblock* block, size_t* bytes );

/**
 * Update the data_size value of a given ioblock
 * @param ioblock* block : Reference to the ioblock to update
 * @param size_t bytes : Size of data added to the ioblock
 */
void ioblock_update_fill( ioblock* block, size_t bytes );

/**
 * Simply makes an ioblock available for use again by increasing ioqueue depth (works due to single producer & consumer assumption)
 * @param ioqueue* ioq : Reference to the ioqueue struct to have depth increased
 * @param int : Zero on success and a negative value if an error occurred
 */
int release_ioblock( ioqueue* ioq );



/* ------------------------------   THREAD BEHAVIOR   ------------------------------ */

// This struct contains all info read threads should need 
// to access their respective data blocks
typedef struct global_state_struct {
   char*        objID;
   DAL_location location;
   DAL_MODE     dmode;
   DAL          dal; 
   ioqueue*     ioq;
   off_t        offset;
   meta_info    minfo;
   char         meta_error;
   char         data_error;
} global_state;


// Write thread internal state struct
typedef struct thread_state_struct {
   global_state* gstate;
   BLOCK_CTXT   handle;
   ioblock*     iob;
} thread_state;




#ifdef __cplusplus
}
#endif

#endif

