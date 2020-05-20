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

#include "libne_auto_config.h"

#define DEBUG 1
#define USE_STDOUT 1
#define LOG_PREFIX "iothreads"
#include "logging/logging.h"

#include "io/io.h"
#include "thread_queue/thread_queue.h"
#include "dal/dal.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>



/* The following are defined here, so as to hide them from users of the library */
// erasure functions
#ifdef HAVE_LIBISAL
extern uint32_t crc32_ieee(uint32_t seed, uint8_t * buf, uint64_t len);
extern void     ec_encode_data(int len, int srcs, int dests, unsigned char *v,unsigned char **src, unsigned char **dest);
#else
extern uint32_t crc32_ieee_base(uint32_t seed, uint8_t * buf, uint64_t len);
extern void     ec_encode_data_base(int len, int srcs, int dests, unsigned char *v,unsigned char **src, unsigned char **dest);
#endif



/* ------------------------------   THREAD BEHAVIOR FUNCTIONS   ------------------------------ */



/**
 * Initialize the write thread state and create a DAL BLOCK_CTXT
 * @param unsigned int tID : The ID of this thread
 * @param void* global_state : Reference to a gthread_state struct
 * @param void** state : Reference to be populated with this thread's state info
 * @return int : Zero on success and -1 on failure
 */
int write_init( unsigned int tID, void* global_state, void** state ) {
   // sanity check, this code was written to handle only a single thread per-queue
   if ( tID > 0 ) {
      LOG( LOG_ERR, "too many threads in a single queue!\n" );
      return -1;
   }
   // allocate space for a thread state struct
   (*state) = malloc( sizeof( struct thread_state_struct ) );
   thread_state* tstate = (*state);
   if ( tstate == NULL ) {
      LOG( LOG_ERR, "failed to allocate space for a thread state struct!\n" );
      return -1;
   }

   gthread_state* gstate = (gthread_state*) global_state;
   DAL dal = gstate->dal; // shorthand reference
   // set some gstate values
   gstate->offset = 0;
   gstate->data_error = 0;
   gstate->meta_error = 0;
   gstate->minfo.blocksz = 0;
   gstate->minfo.crcsum  = 0;

   // set state fields
   tstate->gstate = gstate;
   tstate->iob    = NULL;
   tstate->handle = dal->open( dal->ctxt, gstate->dmode, gstate->location, gstate->objID );
   if( tstate->handle == NULL ) {
      LOG( LOG_ERR, "failed to open handle for block %d!\n", gstate->location.block );
      gstate->data_error = 1;
      free( tstate );
      return -1;
   }

   return 0;
}


/**
 * Initialize the read thread state and create a DAL BLOCK_CTXT
 * @param unsigned int tID : The ID of this thread
 * @param void* global_state : Reference to a gthread_state struct
 * @param void** state : Reference to be populated with this thread's state info
 * @return int : Zero on success and -1 on failure
 */
int read_init( unsigned int tID, void* global_state, void** state ) {
   // sanity check, this code was written to handle only a single thread per-queue
   if ( tID > 0 ) {
      LOG( LOG_ERR, "too many threads in a single queue!\n" );
      return -1;
   }
   // allocate space for a thread state struct
   (*state) = malloc( sizeof( struct thread_state_struct ) );
   thread_state* tstate = (*state);
   if ( tstate == NULL ) {
      LOG( LOG_ERR, "failed to allocate space for a thread state struct!\n" );
      return -1;
   }

   gthread_state* gstate = (gthread_state*) global_state;
   // set some gstate values
   gstate->offset = 0;
   gstate->data_error = 0;
   gstate->meta_error = 0;

   // set state fields
   DAL dal = gstate->dal; // shorthand reference
   tstate->gstate = gstate;
   tstate->iob    = NULL;

   // open a handle for this block
   tstate->handle = dal->open( dal->ctxt, gstate->dmode, gstate->location, gstate->objID );
   if( tstate->handle == NULL ) {
      LOG( LOG_WARNING, "failed to open handle for block %d!\n", gstate->location.block );
      gstate->data_error=1;
   }

   // populate our minfo struct with obj meta values
   if ( dal_get_minfo( dal, tstate->handle, &gstate->minfo ) != 0 ) {
      gstate->meta_error = 1;
   }

   return 0;
}


/**
 * Consume data buffers, generate CRCs for them, and write blocks out to their targets
 * @param void** state : Thread state reference
 * @param void** work_todo : Reference to the data buffer / work package
 * @return int : Integer return code ( -1 on failure, 0 on success )
 */
int write_consume( void** state, void** work_todo ) {
   // get a reference to the thread state struct
   thread_state* tstate = (thread_state*) (*state);
   // get a reference to the global state for this block
   gthread_state* gstate = (gthread_state*) (tstate->gstate);
   // get a reference to the ioblock we've recieved to work on
   ioblock* iob = (ioblock*) (*work_todo);

   // determine what and how much data we have
   size_t datasz = 0;
   void* datasrc = ioblock_read_target( iob, &datasz );
   if ( datasrc == NULL ) {
      LOG( LOG_ERR, "Recieved a NULL read target from ioblock!\n" );
      gstate->data_error = 1;
      return -1;
   }

   // sanity check that our data size makes sense
   if ( datasz != ( gstate->minfo.versz - CRC_BYTES ) ) {
      LOG( LOG_ERR, "Recieved unexpected data size: %zd\n", datasz );
      gstate->data_error = 1;
      return -1;
   }

   // calculate a CRC for this data and append it to the buffer
   *(uint32_t*)( datasrc + datasz ) = crc32_ieee(CRC_SEED, datasrc, datasz);
   gstate->minfo.crcsum += *( (uint32_t*) (datasrc + datasz) );
   datasz += CRC_BYTES;
   // increment our block size
   gstate->minfo.blocksz += datasz;

   // write data out via the DAL, but only if we have not yet encoutered a write error
   if ( (gstate->data_error == 0)  &&  gstate->dal->put( tstate->handle, datasrc, datasz ) ) {
      LOG( LOG_ERR, "Failed to write %zu bytes to block %d!\n", datasz, gstate->location.block );
      gstate->data_error = 1;
      // don't bother to abort yet, we'll do that on close
   }

   // regardless of success, we need to free up our ioblock
   if ( release_ioblock( gstate->ioq ) ) {
      LOG( LOG_ERR, "Failed to release ioblock!\n" );
      gstate->data_error = 1;
      return -1;
   }

   return 0;
}


/**
 * Read data from our target, verify its CRC, and continue until we have a full buffer to push
 * @param void** state : Thread state reference
 * @param void** work_tofill : Reference to be populated with the produced buffer
 * @return int : Integer return code ( -1 on error, 0 on success, and 2 once all buffers have been read )
 */
int read_produce( void** state, void** work_tofill ) {
   // get a reference to the thread state struct
   thread_state* tstate = (thread_state*) (*state);
   // get a reference to the global state for this block
   gthread_state* gstate = (gthread_state*) (tstate->gstate);

   // check if our offset is beyond the end of the block
   if ( gstate->offset >= gstate->minfo.blocksz ) {
      LOG( LOG_INFO, "Thread has reached end of block %d\n", gstate->location.block );
      return 2;
   }

   // loop until we have filled an ioblock
   ioblock* push_block = NULL;
   int resres = 0;
   while ( 1 ) {
      resres = reserve_ioblock( &(tstate->iob), &push_block, gstate->ioq );
      // check for an error condition
      if ( resres == -1 ) {
         LOG( LOG_ERR, "Failed to reserve an ioblock!\n" );
         return -1;
      }
      // check if our ioblock is full, and ready to be pushed
      if ( resres > 0 ) {
         LOG( LOG_INFO, "Pushing full ioblock to work queue\n" );
         break;
      }
      // otherwise, perform a read and store data to that block
      ssize_t read_data = 0;
      void* store_tgt = ioblock_write_target( tstate->iob );
      if ( (read_data = gstate->dal->get( tstate->handle, store_tgt, gstate->minfo.versz, gstate->offset )) <
            gstate->minfo.versz ) {
         LOG( LOG_ERR, "Expected read return value of %zd for block %d, but recieved: %zd\n", 
               gstate->minfo.versz, gstate->location.block, read_data );
         gstate->data_error = 1;
         return -1;
      }
      // check the crc
      read_data -= CRC_BYTES;
      uint32_t crc = crc32_ieee(CRC_SEED, store_tgt, read_data);
      uint32_t scrc = *((uint32_t*) (store_tgt + read_data));
      if ( crc != scrc ) {
         LOG( LOG_ERR, "Calculated CRC of data (%zu) does not match stored CRC: %zu\n", crc, scrc );
         gstate->data_error = 1;
         return -1;
      }
      // note how much REAL data (no CRC) we've stored to the ioblock
      ioblock_update_fill( tstate->iob, read_data );
      // note our increased offset within the data
      gstate->offset += read_data;
   }

   // populate our workpackage with the filled ioblock
   *work_tofill = push_block;
   return 0;
}


/**
 * No-op function, just to fill out the TQ struct
 */
int write_pause( void** state, void** prev_work ) {
   return 0; // noop, probably permanently
}


/**
 * No-op function, just to fill out the TQ struct
 */
int read_pause( void** state, void** prev_work ) {
   return 0; // noop, probably permanently
}


/**
 * No-op function, just to fill out the TQ struct
 */
int write_resume( void** state, void** prev_work ) {
   return 0; // noop, probably permanently
}


/**
 * Create an IOQueue (if not done already), and destory any work package we already produced (reseek possible)
 * @param void** state : Thread state reference
 * @param void** prev_work : Reference to any previously populated buffer
 * @return int : Integer return code ( -1 on error, 0 on success )
 */
int read_resume( void** state, void** prev_work ) {
   // get a reference to the thread state struct
   thread_state* tstate = (thread_state*) (*state);
   // get a reference to the global state for this block
   gthread_state* gstate = (gthread_state*) (tstate->gstate);

   // check for a NULL ioq and create one if so
   if ( gstate->ioq == NULL ) {
      gstate->ioq = create_ioqueue( gstate->minfo.versz, gstate->minfo.partsz, gstate->dmode );
      if ( gstate->ioq == NULL ) {
         LOG( LOG_ERR, "Failed to create ioqueue!\n" );
         return -1;
      }
   }
   // check for a NON-NULL work package, and release the block if so
   if ( *prev_work != NULL ) {
      // attempt to release our previously filled buffer
      // NOTE -- this only works assuming the master / consumer proc has already 
      //         consumed all other IOBlock work packages
      if ( release_ioblock( gstate->ioq ) ) {
         LOG( LOG_ERR, "Failed to release previous ioblock!\n" );
         return -1;
      }
      // NULL out our IOBlock reference, causing us to immediately generate another
      *prev_work = NULL;
   }
   return 0;
}


/**
 * Write out our meta info and close our target reference
 * @param void** state : Thread state reference
 * @param void** prev_work : Reference to any unused previous buffer
 */
void write_term( void** state, void** prev_work ) {
   // get a reference to the thread state struct
   thread_state* tstate = (thread_state*) (*state);
   // get a reference to the global state for this block
   gthread_state* gstate = (gthread_state*) (tstate->gstate);

   // if we never used an IOBlock reference, we need to release it
   if ( *(prev_work) != NULL  &&  release_ioblock( gstate->ioq ) ) {
      LOG( LOG_ERR, "Failed to release previous IOBlock!\n" );
      gstate->data_error = 1;
      // not much to do besides complain
   }

   // attempt to write out meta info
   if ( dal_set_minfo( gstate->dal, tstate->handle, &(gstate->minfo) ) ) {
      LOG( LOG_ERR, "Failed to set meta value for block %d!\n", gstate->location.block );
      gstate->meta_error = 1;
   }

   // don't leave potentially bad data behind
   // NOTE -- not really a problem of data being corrupt (crcs can catch that)
   //         Rather, completely skipped writes *could* mean our erasure stripes end up 
   //         misaligned, something we can't easily detect.
   if ( gstate->data_error != 0  ||  gstate->dal->close( tstate->handle ) ) {
      LOG( LOG_ERR, "Aborting write of block %d due to previous errors!\n", gstate->location.block );
      if ( gstate->dal->abort( tstate->handle ) ) {
         LOG( LOG_ERR, "Abort of block %d failed!\n", gstate->location.block );
         // not really much to do besides complain
      }
   }

   // just free and NULL our state, there isn't any useful info in there
   free( tstate );
   *state = NULL;
}


/**
 * Close our target reference
 * @param void** state : Thread state reference
 * @param void** prev_work : Reference to any unused previous buffer
 */
void read_term( void** state, void** prev_work ) {
   // get a reference to the thread state struct
   thread_state* tstate = (thread_state*) (*state);
   // get a reference to the global state for this block
   gthread_state* gstate = (gthread_state*) (tstate->gstate);

   // if we never pushed an IOBlock reference, we need to release it
   if ( *(prev_work) != NULL  &&  release_ioblock( gstate->ioq ) ) {
      LOG( LOG_ERR, "Failed to release previous IOBlock!\n" );
      // not much to do besides complain
   }

   // close our DAL handle
   if ( gstate->dal->close( tstate->handle ) ) {
      LOG( LOG_ERR, "Failed to close read handle for block %d!\n", gstate->location.block );
      // can only really complain, nothing else to be done
   }

   // just free and NULL our state, there isn't any useful info in there
   free( tstate );
   *state = NULL;

   // NOTE -- it is up to the master / consumer proc to destroy our IOQueue
}


