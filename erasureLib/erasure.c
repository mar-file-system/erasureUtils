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


#include "erasure.h"
#include "udal.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#if (AXATTR_RES == 2)
#  include <attr/xattr.h>
#else
#  include <sys/xattr.h>
#endif

#include <assert.h>
#include <pthread.h>


static int set_block_xattr(ne_handle handle, int block);



// #defines, macros, external functions, etc, that we don't want exported
// for users of the library some are also used in libneTest.c
//
// #include "erasure_internals.h"

/* The following are defined here, so as to hide them from users of the library */
#ifdef HAVE_LIBISAL
extern uint32_t      crc32_ieee(uint32_t seed, uint8_t * buf, uint64_t len);
extern void          ec_encode_data(int len, int srcs, int dests, unsigned char *v,unsigned char **src, unsigned char **dest);
#else
extern uint32_t      crc32_ieee_base(uint32_t seed, uint8_t * buf, uint64_t len);
extern void          ec_encode_data_base(int len, int srcs, int dests, unsigned char *v,unsigned char **src, unsigned char **dest);
#endif

int ne_set_xattr   ( const char *path, const char *xattrval, size_t len );
int ne_get_xattr   ( const char *path, char *xattrval, size_t len );
int ne_delete_block( const char *path );
int ne_link_block  ( const char *link_path, const char *target );
int xattr_check    ( ne_handle handle, char *path );
static int gf_gen_decode_matrix(unsigned char *encode_matrix,
                                unsigned char *decode_matrix,
                                unsigned char *invert_matrix,
                                unsigned int *decode_index,
                                unsigned char *src_err_list,
                                unsigned char *src_in_err,
                                int nerrs, int nsrcerrs, int k, int m);
//void dump(unsigned char *buf, int len);



// run-time selection of sockets vs file, for uDAL

#define FD_INIT(GFD, HANDLE)                (HANDLE)->impl->fd_init(&(GFD))
#define FD_ERR(GFD)                         (GFD).impl->fd_err(&(GFD))
#define FD_NUM(GFD)                         (GFD).impl->fd_num(&(GFD))

// This is opening a file (not a handle), using the impl in the handle.
// Save the ne_handle into the GFD at open-time, so:
// (a) we don't have to pass handle->auth to impls that don't need it
// (b) write_all() can just take a GFD, and impls can still get auth if they need it
//
// TBD: It's awkward for some of the new functions to create a dummy
//      handle, just so they can OPEN() a GFD.  Better would be to just
//      have OPEN() take impl and auth, and store just those onto the gfd.
//      The only UDAL op that cares is udal_skt_open() which only needs the
//      auth.  [p]HNDLOP() could then just use the impl directly from the
//      gfd.  The handle is never really needed.  Callers of OPEN() that
//      are currently using a "fake" handle just to use OPEN() include
//      ne_size(), and ne_set_attr1().
//
#define OPEN(GFD, AUTH, IMPL, ...)              do { (GFD).auth = (AUTH); \
                                                     (GFD).impl = (IMPL); \
                                                 (IMPL)->open(&(GFD), ## __VA_ARGS__); } while(0)

#define pHNDLOP(OP, GFDp, ...)              (GFDp)->impl->OP((GFDp), ## __VA_ARGS__)
#define HNDLOP(OP, GFD, ...)                (GFD).impl->OP(&(GFD), ## __VA_ARGS__)

#define PATHOP(OP, IMPL, AUTH, PATH, ...)   (IMPL)->OP((AUTH), (PATH), ## __VA_ARGS__)

#define UMASK(GFD, MASK)                    umask(MASK) /* TBD */




/**
 * write(2) may return less than the requested write-size, without there being any errors.
 * Call write() repeatedly until the buffer has been completely written, or an error has occurred.
 *
 * @param GenericFD fd: the file/socket to write to
 * @param void* buffer: buffer to be written
 * @param size_t nbytes: size of the buffer
 *
 * @return ssize_t: the amount written.  negative for errors.
 */

static ssize_t write_all(GenericFD* fd, const void* buffer, size_t nbytes) {
  ssize_t     result = 0;
  size_t      remain = nbytes;
  const char* buf    = buffer;  /* assure ourselves pointer arithmetic is by onezies  */

  while (remain) {
    errno = 0;

    ssize_t count = pHNDLOP(write, fd, buf+result, remain);

    if (count < 0)
      return count;

    //    // this is EAGAIN, even after successful writes
    //    else if (errno)
    //      return -1;

    remain -= count;
    result += count;
  }

  return result;
}


/**
 * read(2) may return less than the requested read-size, without there being any errors.
 * Call read() repeatedly until the buffer has been completely filled, or an error (or EOF) has occurred.
 *
 * @param GenericFD fd: the file/socket to read from
 * @param void* buffer: buffer to be filled
 * @param size_t nbytes: size of the buffer
 *
 * @return ssize_t: the amount read.  negative for errors.
 */

ssize_t read_all(GenericFD* fd, void* buffer, size_t nbytes) {
  ssize_t     result = 0;
  size_t      remain = nbytes;
  char*       buf    = buffer;  /* assure ourselves pointer arithmetic is by onezies  */

  while (remain) {
    errno = 0;

    ssize_t count = pHNDLOP(read, fd, buf+result, remain);

    if (count < 0)
      return count;

    else if (count == 0)
      return result;            /* EOF */

    //    // COMMENTED OUT: see write_all()
    //    else if (errno)
    //      return -1;

    remain -= count;
    result += count;
  }

  return result;
}



void bq_destroy(BufferQueue *bq) {
  // XXX: Should technically check these for errors (ie. still locked)
  pthread_mutex_destroy(&bq->qlock);
  pthread_cond_destroy(&bq->thread_resume);
  pthread_cond_destroy(&bq->master_resume);
}

int bq_init(BufferQueue *bq, int block_number, ne_handle handle) {
//  int i;
//  for(i = 0; i < MAX_QDEPTH; i++) {
//    bq->buffers[i] = buffers[i];
//  }

  bq->block_number = block_number;
  bq->qdepth       = 0;
  bq->head         = 0;
  bq->tail         = 0;
  bq->con_flags    = 0;
  bq->state_flags  = 0;
  bq->buffer_size  = handle->erasure_state->bsz;
  bq->handle       = handle;
  bq->offset       = 0;

  FD_INIT(bq->file, handle);

  if( handle->mode == NE_RDONLY || handle->mode == NE_RDALL || handle->mode == NE_STAT ) {
    // initialize all read threads in a halted state
    bq->con_flags |= BQ_HALT;
    // allocate space for the manifest info
    bq->buffers[0] = malloc( sizeof( struct read_meta_buffer_struct ) );
    if ( bq->buffers[0] == NULL ) {
      return -1;
    }
  }

  if(pthread_mutex_init(&bq->qlock, NULL)) {
    PRINTerr("failed to initialize mutex for qlock\n");
    return -1;
  }
  if(pthread_cond_init(&bq->thread_resume, NULL)) {
    PRINTerr("failed to initialize cv for thread_resume\n");
    // should also destroy the mutex
    pthread_mutex_destroy(&bq->qlock);
    return -1;
  }
  if(pthread_cond_init(&bq->master_resume, NULL)) {
    PRINTerr("failed to initialize cv for master_resume\n");
    pthread_mutex_destroy(&bq->qlock);
    pthread_cond_destroy(&bq->thread_resume);
    return -1;
  }
  if(pthread_cond_init(&bq->resume, NULL)) {
    PRINTerr("failed to initialize cv for resume\n");
    pthread_mutex_destroy(&bq->qlock);
    pthread_cond_destroy(&bq->thread_resume);
    pthread_cond_destroy(&bq->master_resume);
    return -1;
  }

  return 0;
}

void bq_signal(BufferQueue* bq, BQ_Control_Flags sig) {
  pthread_mutex_lock(&bq->qlock);
  PRINTdbg("signalling 0x%x to block %d\n", (uint32_t)sig, bq->block_number);
  bq->con_flags |= sig;
  pthread_cond_signal(&bq->thread_resume);
  pthread_mutex_unlock(&bq->qlock);  
}

void bq_close(BufferQueue *bq) {
  bq_signal(bq, BQ_FINISHED);
}

void bq_abort(BufferQueue *bq) {
  bq_signal(bq, BQ_ABORT);
}


void bq_finish(void* arg) {
  BufferQueue *bq = (BufferQueue *)arg;
  PRINTdbg("exiting thread for block %d, in %s\n", bq->block_number, bq->path);
}


void *bq_writer(void *arg) {
  BufferQueue *bq      = (BufferQueue *)arg;
  ne_handle    handle  = bq->handle;
  TimingData*  timing = handle->timing_data_ptr;
  size_t       written = 0;
  int          error;
  char         aborted = 0; // set to 1 on abort and 2 on pthread lock error

  char* meta_status = &(handle->erasure_state->manifest_status[bq->block_number]);
  char* data_status = &(handle->erasure_state->data_status[bq->block_number]);

#ifdef INT_CRC
  const int write_size = bq->buffer_size + sizeof(u32);
#else
  const int write_size = bq->buffer_size;
#endif

  if (timing->flags & TF_THREAD)
     fast_timer_start(&timing->stats[bq->block_number].thread);
  
  // debugging, assure we see thread entry/exit, even via cancellation
  PRINTdbg("entering write thread for block %d, in %s\n", bq->block_number, bq->path);
  pthread_cleanup_push(bq_finish, bq);

// ---------------------- OPEN DATA FILE ----------------------

  if (timing->flags & TF_OPEN)
     fast_timer_start(&timing->stats[bq->block_number].open);

  // open the file.
  OPEN(bq->file, handle->auth, handle->impl, bq->path, O_WRONLY|O_CREAT, 0666);

  if (timing->flags & TF_OPEN)
  {
     fast_timer_stop(&timing->stats[bq->block_number].open);
     log_histo_add_interval(&timing->stats[bq->block_number].open_h,
                            &timing->stats[bq->block_number].open);
  }

  PRINTdbg("opened file %d\n", bq->block_number);

// ---------------------- INITIALIZE MAIN PROCESS LOOP ----------------------

  // use 'read' to time how long we spend waiting to pull work off our queue
  // I've moved this outside the critical section, partially to spend less time
  // holding the queue lock, and partially because time spent waiting for our 
  // queue lock to be released is indicative of ne_write() copying data around
  if (timing->flags & TF_RW)
     fast_timer_start(&timing->stats[bq->block_number].read);

  if(pthread_mutex_lock(&bq->qlock) != 0) {
    PRINTerr("failed to lock queue lock: %s\n", strerror(error));
    // outside of critical section, but should be fine as flags aren't shared
    *data_status = 1;
    aborted = 2;
  }
  // only set BQ_OPEN after aquiring the queue lock
  // this will allow initialize_queues() to complete and ne_open to reset umask
  bq->state_flags |= BQ_OPEN;
  // this is intended to avoid any oddities from instruction re-ordering
  if(FD_ERR(bq->file)) {
    *data_status = 1;
  }
  pthread_cond_signal(&bq->master_resume);
  // As no work could have been queued yet, we'll give up the lock as soon as we hit the main loop
  
  while( !(aborted) ) { //condition check used only to skip the main loop if we failed to get the lock above


// ---------------------- CHECK FOR SPECIAL CONDITIONS ----------------------

    // the thread should always be holding its queue lock at this point

    // check for any states that require us to wait on the master proc, but allow a FINISHED or ABORT signal to break us out
    while ( ( bq->qdepth == 0  ||  (bq->con_flags & BQ_HALT) )  &&  !((bq->con_flags & BQ_FINISHED) || (bq->con_flags & BQ_ABORT)) ) {
      // note the halted state if we were asked to pause
      if ( bq->con_flags & BQ_HALT ) {
         bq->state_flags |= BQ_HALTED;
         // the master proc could have been waiting for us to halt, so we must signal
         pthread_cond_signal(&bq->master_resume);
         // a reseek is comming, reset our internal/handle values to account for it
         written = 0;
         handle->erasure_state->csum[bq->block_number] = 0;
      }

      // wait on the thread_resume condition
      PRINTdbg("bq_writer[%d]: waiting for signal from ne_write\n", bq->block_number);
      pthread_cond_wait(&bq->thread_resume, &bq->qlock);

      // if we were halted, make sure we immediately indicate that we aren't any more 
      // and reseek our input file.
      if ( bq->state_flags & BQ_HALTED ) {
         PRINTdbg( "thread %d is resuming\n", bq->block_number );
         // let the master proc know that we are no longer halted
         bq->state_flags &= ~(BQ_HALTED);
         if ( (bq->offset == 0)  &&  !(FD_ERR(bq->file)) ) {
            // reseek our input file, if possible
            // Note: technically, it may be possible to unset any data error here.
            // Currently, I don't think there's a benefit to this though.
            if ( bq->offset != HNDLOP(lseek, bq->file, bq->offset, SEEK_SET) ) {
               PRINTerr( "thread %d is entering an unwritable state (seek error)\n", bq->block_number );
               *data_status = 1;
            }
         }
      }
    }

    // check for flags that might tell us to quit
    if(bq->con_flags & BQ_ABORT) {
      PRINTerr("thread %d is aborting\n", bq->block_number);
      // make sure no one thinks we finished properly
      *data_status = 1;
      pthread_mutex_unlock(&bq->qlock);
      // note that we should unlink the destination
      aborted = 1;
      // let the post-loop code cleanup after us
      break;
    }

    if((bq->qdepth == 0) && (bq->con_flags & BQ_FINISHED)) {       // then we are done.
      PRINTdbg("BQ finished\n");
      pthread_mutex_unlock(&bq->qlock);
      break;
    }
    pthread_mutex_unlock(&bq->qlock);

    // stop the 'read' timer once we have work to do
    if (timing->flags & TF_RW) {
       fast_timer_stop(&timing->stats[bq->block_number].read);
       log_histo_add_interval(&timing->stats[bq->block_number].read_h,
                              &timing->stats[bq->block_number].read);
    }


    if( !(*data_status)  &&  !(bq->state_flags & BQ_SKIP) ) {

// ---------------------- WRITE TO THE DATA FILE ----------------------

      if (timing->flags & TF_RW)
         fast_timer_start(&timing->stats[bq->block_number].write);

// removing this since the newer NFS clients are better behaved
/*
      if(written >= SYNC_SIZE) {
         if ( HNDLOP(fsync, bq->file) )
            *data_status = 1;
         written = 0;
      }

      PRINTdbg("Writing block %d\n", bq->block_number);
*/

      *(u32*)( bq->buffers[bq->head] + bq->buffer_size )   = crc32_ieee(TEST_SEED, bq->buffers[bq->head], bq->buffer_size);
      error     = write_all(&bq->file, bq->buffers[bq->head], write_size);
      handle->erasure_state->csum[bq->block_number] += *(u32*)( bq->buffers[bq->head] + bq->buffer_size );

      PRINTdbg("write done for block %d at offset %zd\n", bq->block_number, written);
      if (timing->flags & TF_RW) {
         fast_timer_stop(&timing->stats[bq->block_number].write);
         log_histo_add_interval(&timing->stats[bq->block_number].write_h,
                                &timing->stats[bq->block_number].write);
      }

    }
    else { // there were previous errors. skipping the write
      error = write_size;
    }

    if(error < write_size) {
      *data_status = 1;
    }
    else {
      // track data written to this block
      written += bq->buffer_size;
    }

// ---------------------- CLEAR ENTRY FROM THE BUFFER QUEUE ----------------------

    // use 'read' to time how long it takes us to receive work
    if (timing->flags & TF_RW)
       fast_timer_start(&timing->stats[bq->block_number].read);

    // get the queue lock so that we can adjust the head position
    if((error = pthread_mutex_lock(&bq->qlock)) != 0) {
      PRINTerr("failed to lock queue lock: %s\n", strerror(error));
      // note the error
      *data_status = 1;
      // set the aborted flag, for consistency
      aborted = 2;
      // let the post-loop code cleanup after us
      break;
    }

    // even if there was an error, say we wrote the block and move on.
    // the producer thread is responsible for checking the error flag
    // and killing us if needed.

    bq->head = (bq->head + 1) % MAX_QDEPTH;
    bq->qdepth--;
    PRINTdbg( "completed a work buffer, set queue depth to %d and queue head to %d\n", bq->qdepth, bq->head );

    if ( bq->qdepth == MAX_QDEPTH - 1 )
       pthread_cond_signal(&bq->master_resume);
  }

// ---------------------- END OF MAIN PROCESS LOOP ----------------------

  // should have already relinquished the queue lock before breaking out

  // stop the 'read' timer, which will still be running after any loop breakout
  if (timing->flags & TF_RW) {
    fast_timer_stop(&timing->stats[bq->block_number].read);
    log_histo_add_interval(&timing->stats[bq->block_number].read_h,
                           &timing->stats[bq->block_number].read);
  }

  // for whatever reason, this thread's work is done.  close the file
  if (timing->flags & TF_CLOSE)
     fast_timer_start(&timing->stats[bq->block_number].close);
  int close_rc = HNDLOP(close, bq->file);
  if (timing->flags & TF_CLOSE)
  {
     fast_timer_stop(&timing->stats[bq->block_number].close);
     log_histo_add_interval(&timing->stats[bq->block_number].close_h,
                            &timing->stats[bq->block_number].close);
  }

  // check for special case, where rebuild does not need this block
  if ( bq->state_flags & BQ_SKIP ) {
    PRINTdbg( "thread %d was never used and will terminate early\n", bq->block_number );
    PATHOP(unlink, handle->impl, handle->auth, bq->path); // try to clean up after ourselves.
    if (timing->flags & TF_THREAD)
       fast_timer_stop(&timing->stats[bq->block_number].thread);
    return NULL; // don't bother trying to rename
  }

  // this should catch any errors from close or within the main loop
  if ( close_rc || (*data_status) ) {
    if ( close_rc ) {
       PRINTerr("error closing block %d\n", bq->block_number);
    }
    else {
       PRINTerr("early termination due to error for block %d\n", bq->block_number);
    }

    *data_status = 1;   // ensure the error was noted

    // check if the write has been aborted
    if ( aborted == 1 )
      PATHOP(unlink, handle->impl, handle->auth, bq->path); // try to clean up after ourselves.

    if (timing->flags & TF_THREAD)
       fast_timer_stop(&timing->stats[bq->block_number].thread);

    return NULL; // don't bother trying to rename
  }

// ---------------------- STORE META INFO ----------------------

  // set our part size based on how much we have written
  handle->erasure_state->ncompsz[ bq->block_number ] = written;

  if(set_block_xattr(bq->handle, bq->block_number) != 0) {
    *meta_status = 1;
    // if we failed to set the xattr, don't bother with the rename.
    PRINTerr("error setting xattr for block %d\n", bq->block_number);
    if (timing->flags & TF_THREAD)
       fast_timer_stop(&timing->stats[bq->block_number].thread);
    return NULL;
  }

// ---------------------- RENAME OUTPUT FILES TO FINAL LOCATIONS ----------------------

  // rename
  if (timing->flags & TF_RENAME)
     fast_timer_start(&timing->stats[bq->block_number].rename);

  char block_file_path[MAXNAME];
  //  sprintf( block_file_path, handle->path_fmt,
  //           (bq->block_number+handle->erasure_state->O)%(handle->erasure_state->N+handle->erasure_state->E) );
  handle->snprintf( block_file_path, MAXNAME, handle->path_fmt,
                    (bq->block_number+handle->erasure_state->O)%(handle->erasure_state->N+handle->erasure_state->E), handle->printf_state );

  PRINTdbg("bq_writer: renaming old:  %s\n", bq->path );
  PRINTdbg("                    new:  %s\n", block_file_path );
  if( PATHOP( rename, handle->impl, handle->auth, bq->path, block_file_path ) != 0 ) {
    PRINTerr("bq_writer: rename failed: %s\n", strerror(errno) );
    *data_status = 1;
  }

#ifdef META_FILES
  // rename the META file too
  strncat( bq->path, META_SFX, strlen(META_SFX)+1 );
  strncat( block_file_path, META_SFX, strlen(META_SFX)+1 );

  PRINTdbg("bq_writer: renaming meta old:  %s\n", bq->path );
  PRINTdbg("                         new:  %s\n", block_file_path );
  if ( PATHOP( rename, handle->impl, handle->auth, bq->path, block_file_path ) != 0 ) {
     PRINTerr("bq_writer: rename failed: %s\n", strerror(errno) );
     *meta_status = 1;
  }
#endif

  if (timing->flags & TF_RENAME)
     fast_timer_stop(&timing->stats[bq->block_number].rename);
  if (timing->flags & TF_THREAD)
     fast_timer_stop(&timing->stats[bq->block_number].thread);

  pthread_cleanup_pop(1);
  return NULL;
}



void* bq_reader(void* arg) {
   BufferQueue* bq      = (BufferQueue *)arg;
   ne_handle    handle  = bq->handle;
   TimingData*  timing  = handle->timing_data_ptr;
   int          error   = 0;

   if (timing->flags & TF_THREAD)
      fast_timer_start(&timing->stats[bq->block_number].thread);
  
   // debugging, assure we see thread entry/exit, even via cancellation
   PRINTdbg("entering read thread for block %d, in %s\n", bq->block_number, bq->path);
   pthread_cleanup_push(bq_finish, bq);

// ---------------------- READ META INFO ----------------------

   // we will use the first of our buffers as a container for our manifest values
   read_meta_buffer meta_buf = (read_meta_buffer) bq->buffers[0];
   // initialize all values to indicate errors
   meta_buf->N = 0;
   meta_buf->E = -1;
   meta_buf->O = -1;
   meta_buf->bsz = 0;
   meta_buf->nsz = 0;
   meta_buf->totsz = 0;
   char* meta_status = &(handle->erasure_state->manifest_status[bq->block_number]);
   char* data_status = &(handle->erasure_state->data_status[bq->block_number]);

   // pull the meta info for this thread's block
   char xattrval[XATTRLEN];
   if ( ne_get_xattr1( handle->impl, handle->auth, bq->path, xattrval, XATTRLEN ) < 0 ) {
      PRINTerr( "bq_reader: failed to retrieve meta info for file \"%s\"\n", bq->path );
      *meta_status = 1;
   }
   else {
      // declared here so that the compiler can hopefully free up this memory outside of the 'else' block
      char xattrN[5];            /* char array to get n parts from xattr */
      char xattrE[5];            /* char array to get erasure parts from xattr */
      char xattrO[5];            /* char array to get erasure_offset from xattr */
      char xattrbsz[20];         /* char array to get chunksize from xattr */
      char xattrnsize[20];       /* char array to get total size from xattr */
      char xattrncompsize[20];   /* char array to get ncompsz from xattr */
      char xattrcsum[50];        /* char array to get check-sum from xattr */
      char xattrtotsize[160];    /* char array to get totsz from xattr */

      // only process the xattr if we successfully retreived it
      int ret = sscanf(xattrval,"%4s %4s %4s %19s %19s %19s %49s %159s",
            xattrN,
            xattrE,
            xattrO,
            xattrbsz,
            xattrnsize,
            xattrncompsize,
            xattrcsum,
            xattrtotsize);
      if (ret != 8) {
         PRINTerr( "bq_reader: sscanf parsed only %d values from meta info of block %d: \"%s\"\n", ret, bq->block_number, xattrval);
         *meta_status = 1;
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
            PRINTerr( "bq_reader: failed to parse meta value at position %d for block %d: \"%s\"\n", GT_VAL, bq->block_number, STR ); \
            *meta_status = 1; \
         } \
      }
      // N, E, O, bsz, and nsz are global values, and thus need to go in the meta_buf
      PARSE_VALUE( meta_buf->N, xattrN, 0, strtol, int )
      PARSE_VALUE( meta_buf->E, xattrE, 1, strtol, int )
      PARSE_VALUE( meta_buf->O, xattrO, 2, strtol, int )
      PARSE_VALUE( meta_buf->bsz, xattrbsz, 3, strtoul, unsigned int )
      PARSE_VALUE( meta_buf->nsz, xattrnsize, 4, strtoul, unsigned int )
      // ncompsz and csum are considered 'per-part' info, and thus can just be stored to the handle struct
      PARSE_VALUE( handle->erasure_state->ncompsz[ bq->block_number ], xattrncompsize, 5, strtoul, unsigned int )
      PARSE_VALUE( handle->erasure_state->csum[ bq->block_number ], xattrcsum, 6, strtoull, u64 )
      // totsz is global, so this needs to go into the meta_buf
      PARSE_VALUE( meta_buf->totsz, xattrtotsize, 7, strtoull, u64 )
   }

// ---------------------- OPEN DATA FILE ----------------------

   if (timing->flags & TF_OPEN)
      fast_timer_start(&timing->stats[bq->block_number].open);

   OPEN( bq->file, handle->auth, handle->impl, bq->path, O_RDONLY );

   if (timing->flags & TF_OPEN)
   {
      fast_timer_stop(&timing->stats[bq->block_number].open);
      log_histo_add_interval(&timing->stats[bq->block_number].open_h,
                            &timing->stats[bq->block_number].open);
   }

   PRINTdbg("opened file %d\n", bq->block_number);

// ---------------------- INITIALIZE MAIN PROCESS LOOP ----------------------

   char   aborted = 0;         // set to 1 on pthread_lock error
   char   resetable_error = 0; // set on read error, reset on successful re-seek
   char   permanent_error = 0; // set on failure to open file or global crc mismatch, never cleared

   // use 'write' to time how long we spend waiting to push buffers to our queue
   // I've moved this outside the critical section, partially to spend less time
   // holding the queue lock, and partially because time spent waiting for our 
   // queue lock to be released is indicative of ne_read() copying data around
   if (timing->flags & TF_RW)
      fast_timer_start(&timing->stats[bq->block_number].write);

   // attempt to lock the queue before beginning the main loop
   if((error = pthread_mutex_lock(&bq->qlock)) != 0) {
      PRINTerr("failed to lock queue lock: %s\n", strerror(error));
      // note the error
      *data_status = 1;
      aborted = 1;
   }
   // only set BQ_OPEN after aquiring the queue lock
   // this will allow initialize_queues() to complete and ne_open to reset umask
   bq->state_flags |= BQ_OPEN;
   // this is intended to avoid any oddities from instruction re-ordering
   if(FD_ERR(bq->file)) {
      PRINTerr( "failed to open data file for block %d: \"%s\"\n", bq->block_number, bq->path );
      *data_status = 1;
      permanent_error = 1;
      resetable_error = 1; // while not actually resetable, we need to set this to avoid any read attempts on the bad FD
   }
   // As we should have initialized in a halted state, we'll signal and give up the lock as soon as we hit the main loop

   // local value for the files crcsum
   u64 local_crcsum = 0;
   // flag to indicate if we can trust our local crcsum for the file
   char good_crc = 1;
   // used to indicate read return values
   size_t error = 0;
   // used to calculate the end of the file.  However, we are not yet sure that values needed for determining this are set
   // in the handle.  Therefore, initialize this to zero, then reset once we have been 'resumed' by the master proc below.
   int num_stripes = 0;

   while ( !(aborted) ) { // condition check used just to skip the main loop if we failed to get the queue lock

// ---------------------- CHECK FOR SPECIAL CONDITIONS ----------------------

      // the thread should always be holding its queue lock at this point

      // check for any states that require us to wait on the master proc, but allow a FINISHED or ABORT signal to break us out.
      // Note, it is tempting to wait on 'resetable_error' here; however, we depend upon this thread to set error states for 
      // all buffers and to advance the queue.  Otherwise, ne_read() would be forced to assume that this thread is just really 
      // darn slow.
      while ( ( bq->qdepth == MAX_QDEPTH  ||  (bq->con_flags & BQ_HALT) )  &&  !((bq->con_flags & BQ_FINISHED) || (bq->con_flags & BQ_ABORT)) ) {
         // note the halted state if we were asked to pause
         if ( bq->con_flags & BQ_HALT ) {
            bq->state_flags |= BQ_HALTED;
            // the master proc could have been waiting for us to halt, so we must signal
            pthread_cond_signal(&bq->master_resume);
            good_crc = 0; // a reseek is comming, so assume we can't use our crcsum
         }

         // wait on the thread_resume condition
         PRINTdbg("bq_reader[%d]: waiting for signal from ne_read\n", bq->block_number);
         pthread_cond_wait(&bq->thread_resume, &bq->qlock);

         // if we were halted, we have some housekeeping to take care of
         if ( bq->state_flags & BQ_HALTED ) {
            PRINTdbg( "thread %d is resuming\n", bq->block_number );
            // let the master proc know that we are no longer halted
            bq->state_flags &= ~(BQ_HALTED);
            // reseek our input file, if possible
            if ( !(permanent_error) ) {
               resetable_error = 0; // reseeking, so clear our temporary error state
               if ( bq->offset != HNDLOP(lseek, bq->file, bq->offset, SEEK_SET) ) {
                  PRINTerr( "thread %d is entering an unreadable state (seek error)\n", bq->block_number );
                  *data_status = 1;
                  resetable_error = 1; // do not attempt any reads until we successfully reseek
               }
               else if ( bq->offset == 0 ) {
                  good_crc = 1; // if we're starting from offset zero again, our crcsum is valid
                  local_crcsum = 0;
               }
            }
            // as the handle structs should now be initialized, calculate how large our file is expected to be
            if ( !( bq->con_flags & (BQ_FINISHED | BQ_ABORT) ) )
               num_stripes = (int)( ( handle->erasure_state->totsz - 1 ) / ( bq->buffer_size * (size_t)handle->erasure_state->N ) );
            // technically, this will be number of stripes minus 1, due to int truncation
         }
      }

      // check for flags that might tell us to quit
      if(bq->con_flags & BQ_ABORT) {
         PRINTerr("thread %d is aborting\n", bq->block_number);
         // make sure no one thinks we finished properly
         *data_status = 1;
         pthread_mutex_unlock(&bq->qlock);
         aborted = 1; //probably unnecessary
         // let the post-loop code cleanup after us
         break;
      }

      // if the finished flag is set, we are done, regardless of how full the queue is
      if(bq->con_flags & BQ_FINISHED) {
         PRINTdbg("BQ_reader %d finished\n", bq->block_number);
         pthread_mutex_unlock(&bq->qlock);
         break;
      }
      pthread_mutex_unlock(&bq->qlock);

      // stop the 'write' timer once we have work to do
      if (timing->flags & TF_RW) {
          fast_timer_stop(&timing->stats[bq->block_number].write);
          log_histo_add_interval(&timing->stats[bq->block_number].write_h,
                                 &timing->stats[bq->block_number].write);
      }


// ---------------------- READ FROM DATA FILE ----------------------

      error = 0;

      // only read if we are at a good offset within the file
      if ( !(resetable_error) ) {

         u32 crc_val = 0;

         if (timing->flags & TF_RW)
            fast_timer_start(&timing->stats[bq->block_number].read);

         error     = read_all(&bq->file, bq->buffers[bq->tail], bq->buffer_size + sizeof(u32));

         if (timing->flags & TF_RW) {
            fast_timer_stop(&timing->stats[bq->block_number].read);
            log_histo_add_interval(&timing->stats[bq->block_number].read_h,
                                   &timing->stats[bq->block_number].read);
         }

         if ( error != bq->buffer_size + sizeof(u32) ) {
            PRINTerr( "read error for block %d at offset %zd\n", bq->block_number, bq->offset );
            *data_status = 1;
            resetable_error = 1;
            error = 0;
         }
         else {
            crc_val   = crc32_ieee(TEST_SEED, bq->buffers[bq->tail], bq->buffer_size);
            if ( memcmp( bq->buffers[bq->tail] + bq->buffer_size, &crc_val, sizeof(u32) ) ) {
               PRINTerr( "crc mismatch detected by block %d at offset %zd\n", bq->block_number, bq->offset );
               *data_status = 1;
               // this is why we need this 'error' value to persist outside the loop, to catch transient data errors.
               // No need to set the 'resetable_error' flag, as one bad block won't necessarily affect others.
               // Note that I've also elected not to invalidate our local crcsum here, as it doesn't really matter once 
               // we've already noted the error.
               bq->offset += error; // still increment offset
               error = 0;
            }
            else {
               // leave the crc value sitting in the buffer.  This will be a signal to ne_read() that the buffer is
               // usable.
               local_crcsum += crc_val;
               PRINTdbg("read done for block %d at offset %zd\n", bq->block_number, bq->offset);
            }
         }
      }

      if( error == 0 ) { //paradoxically, meaning there was an error...
         // zero out the crc position to indicate a bad buffer to ne_read()
         *(u32*)(bq->buffers[bq->tail] + bq->buffer_size) = 0;
         // any error means we can't trust our local crcsum any more
         good_crc = 0;
      }
      else {
         bq->offset += error;
      }

      // check if we are at the end of our file
      if ( !(resetable_error)  &&  ( ( bq->offset / ( bq->buffer_size + sizeof(u32) ) ) > num_stripes ) ) {
         PRINTdbg( "thread %d has reached the end of its data file ( offset = %zd )\n", bq->block_number, bq->offset );
         resetable_error = 1; // this should allow us to refuse any further buffers while avoiding a reported error

         // if we're at the end of the file, and both our local crcsum and the global are 'trustworthy', verify them
         if ( good_crc  &&  !(handle->erasure_state->manifest_status[bq->block_number])  &&  
               ( local_crcsum != handle->erasure_state->csum[bq->block_number] ) ) {
            *data_status = 1;
            // if the global doesn't match, something very odd is going on with this block.  Best to avoid reading it 
            // from now on.
            permanent_error = 1; // note: resetable flag already set above
            PRINTerr( "thread %d detected global crc mismatch ( data = %llu, meta = %llu )\n", 
                        bq->block_number, local_crcsum, handle->erasure_state->csum[bq->block_number] );
         }
      }


// ---------------------- ADD ENTRY TO BUFFER QUEUE ----------------------

      // use 'write' to time how long it takes us to receive work
      if (timing->flags & TF_RW)
         fast_timer_start(&timing->stats[bq->block_number].write);

      // get the queue lock so that we can adjust the tail position
      if((error = pthread_mutex_lock(&bq->qlock)) != 0) {
         PRINTerr("failed to lock queue lock: %s\n", strerror(error));
         // note the error
         *data_status = 1;
         // set the aborted flag, for consistency
         aborted = 2;
         // let the post-loop code cleanup after us
         break;
      }

      // even if there was an error, just zero the crc and move on.
      // the master proc is responsible for checking the error flag
      // and killing us if needed.

      bq->tail = (bq->tail + 1) % MAX_QDEPTH;
      bq->qdepth++;
      PRINTdbg( "completed a work buffer, set queue depth to %d and queue tail to %d\n", bq->qdepth, bq->tail );

      // only signal if it is likely that the master has been waiting for a new buffer
      if ( bq->qdepth == 1 )
         pthread_cond_signal(&bq->master_resume);

   }

// ---------------------- END OF MAIN PROCESS LOOP ----------------------

   // should have already relinquished the queue lock before breaking out

   // stop the 'write' timer, which will still be running after any loop breakout
   if (timing->flags & TF_RW) {
      fast_timer_stop(&timing->stats[bq->block_number].write);
      log_histo_add_interval(&timing->stats[bq->block_number].write_h,
                           &timing->stats[bq->block_number].write);
   }

   // for whatever reason, this thread's work is done.  close the file
   if (timing->flags & TF_CLOSE)
      fast_timer_start(&timing->stats[bq->block_number].close);

   int close_rc = HNDLOP(close, bq->file);

   if (timing->flags & TF_CLOSE)
   {
      fast_timer_stop(&timing->stats[bq->block_number].close);
      log_histo_add_interval(&timing->stats[bq->block_number].close_h,
                            &timing->stats[bq->block_number].close);
   }
   // at least note any close error, even though this shouldn't matter for reads
   if ( close_rc ) {
      PRINTerr("error closing block %d\n", bq->block_number);
      *data_status = 1;
   }

   // all done!
   if (timing->flags & TF_THREAD)
      fast_timer_stop(&timing->stats[bq->block_number].thread);

   pthread_cleanup_pop(1);
   return NULL;
}


void terminate_threads( BQ_Control_Flags flag, ne_handle handle, int thread_cnt, int thread_offset ) {
   int i;
   /* wait for the threads */
   for(i = thread_offset; i < (thread_offset + thread_cnt); i++) {
      bq_signal( &handle->blocks[i], flag );
      pthread_join( handle->threads[i], NULL );
      bq_destroy( &handle->blocks[i] );
      PRINTdbg( "thread %d has terminated\n", i );
   }
}


void signal_threads( BQ_Control_Flags flag, ne_handle handle, int thread_cnt, int thread_offset ) {
   int i;
   /* wait for the threads */
   for(i = thread_offset; i < (thread_offset + thread_cnt); i++) {
      bq_signal( &handle->blocks[i], flag );
   }
}


// Used to resume a specific thread.
// Pulled out into a seperate func to allow ne_rebuild1_vl() to call it directly
void bq_resume( off_t offset, BufferQueue* bq ) {
   // TODO: should probably give these funcs a return value and actually do 
   // some error checking for this lock call
   pthread_mutex_lock( &bq->qlock );
   while( !(bq->state_flags & BQ_HALTED) ) {
      PRINTdbg( "master proc waiting on thread %d to signal\n", bq->block_number );
      pthread_cond_wait( &bq->master_resume, &bq->qlock );
   }

   // now that the thread is suspended, clear out the buffer queue
   bq->qdepth = 0;
   // Note: we specifically set queue positions to zero to avoid any oddness with queues potentially
   // being misaligned from one another, which will break erasure.
   bq->head = 0;
   bq->tail = 0;
   // as these buffers are consistently overwritten, we really just need to pretend we read them all

   // special case, if this thread is supposed to be set to skip work
   if ( offset < 0 ) {
      bq->offset = 0;
      bq->state_flags |= BQ_SKIP; // because we hold the lock, we're fine to do this
   }
   else {
      // set the thread to a new offset
      bq->offset = offset;
      // clear any previous instance of the skip flag
      bq->state_flags &= ~(BQ_SKIP);
   }

   // clear the HALT signal
   PRINTdbg("clearing 0x%x signal for block %d\n", (uint32_t)BQ_HALT, bq->block_number);
   bq->con_flags &= ~(BQ_HALT);
   pthread_cond_signal( &bq->thread_resume );
   pthread_mutex_unlock( &bq->qlock );
}


void resume_threads( off_t offset, ne_handle handle, int thread_cnt, int thread_offset ) {
   int i;
   /* wait for the threads */
   for(i = thread_offset; i < (thread_offset + thread_cnt); i++) {
      BufferQueue* bq = &handle->blocks[i];
      bq_resume( offset, bq );
   }
}


/**
 * This helper function is intended to identify the most common sensible values amongst all meta_buffers 
 * for a given number of read threads and return them in a provided read_meta_buffer struct.
 * If two numbers have the same number of instances, preference will be given to the first number ( the 
 * one with a lower block number ).
 * @param BufferQueue blocks[ MAXPARTS ] : Array of buffer queues for all threads
 * @param int num_threads : Number of threads with meta_info ready
 * @param read_meta_buffer ret_buf : Buffer to be populated with return values
 * @return int : Lesser of the counts of matching N/E values
 */
int check_matches( BufferQueue blocks[ MAXPARTS ], int num_threads, read_meta_buffer ret_buf ) {
   int N_match[MAXPARTS]     = { 0 };
   int E_match[MAXPARTS]     = { 0 };
   int O_match[MAXPARTS]     = { 0 };
   int bsz_match[MAXPARTS]   = { 0 };
   int nsz_match[MAXPARTS]   = { 0 };
   int totsz_match[MAXPARTS] = { 0 };

   int i;
   for ( i = 0; i < num_threads; i++ ) {
      int j;
      read_meta_buffer meta_buf = (read_meta_buffer)(blocks[i].buffers[0]);
// this macro is intended to produce counts of matching values at the index of their first appearance
#define COUNT_MATCH_AT_INDEX( VAL, MATCH_LIST, MAX_VAL, MIN_VAL ) \
if ( meta_buf->VAL >= MIN_VAL  &&  meta_buf->VAL <= MAX_VAL ) { \
   for ( j = 0; j < i; j++ ) { \
      if ( ((read_meta_buffer)(blocks[j].buffers[0]))->VAL == meta_buf->VAL ) { \
         break; \
      } \
   } \
   MATCH_LIST[j]++; \
}
      COUNT_MATCH_AT_INDEX( N, N_match, MAXN, 1 )
      COUNT_MATCH_AT_INDEX( E, E_match, MAXE, 0 )
      COUNT_MATCH_AT_INDEX( O, O_match, MAXPARTS - 1, 0 )
      COUNT_MATCH_AT_INDEX( bsz, bsz_match, MAXBLKSZ, 0 )
      COUNT_MATCH_AT_INDEX( nsz, nsz_match, meta_buf->nsz, 0 ) //no maximum
      COUNT_MATCH_AT_INDEX( totsz, totsz_match, meta_buf->totsz, 0 ) //no maximum
   }

   int N_index = 0;
   int E_index = 0;
   int O_index = 0;
   int bsz_index = 0;
   int nsz_index = 0;
   int totsz_index = 0;
   for ( i = 1; i < num_threads; i++ ) {
      if ( N_match[i] > N_match[N_index] )
         N_index = i;
      if ( E_match[i] > E_match[E_index] )
         E_index = i;
      if ( O_match[i] > O_match[O_index] )
         O_index = i;
      if ( bsz_match[i] > bsz_match[bsz_index] )
         bsz_index = i;
      if ( nsz_match[i] > nsz_match[nsz_index] )
         nsz_index = i;
      if ( totsz_match[i] > totsz_match[totsz_index] )
         totsz_index = i;
   }

   // assign appropriate values to our output struct
   // Note: we have to do a sanity check on the match count, to make sure 
   // we don't return an out-of-bounds value.
   if ( N_match[N_index] )
      ret_buf->N = ((read_meta_buffer)(blocks[N_index].buffers[0]))->N;
   else
      ret_buf->N = 0;
   if ( E_match[E_index] )
      ret_buf->E = ((read_meta_buffer)(blocks[E_index].buffers[0]))->E;
   else
      ret_buf->E = -1;
   if ( O_match[O_index] )
      ret_buf->O = ((read_meta_buffer)(blocks[O_index].buffers[0]))->O;
   else
      ret_buf->O = -1;
   if ( bsz_match[bsz_index] )
      ret_buf->bsz = ((read_meta_buffer)(blocks[bsz_index].buffers[0]))->bsz;
   else
      ret_buf->bsz = 0;
   if ( nsz_match[nsz_index] )
      ret_buf->nsz = ((read_meta_buffer)(blocks[nsz_index].buffers[0]))->nsz;
   else
      ret_buf->nsz = 0;
   if ( totsz_match[totsz_index] )
      ret_buf->totsz = ((read_meta_buffer)(blocks[totsz_index].buffers[0]))->totsz;
   else
      ret_buf->totsz = 0;

   return ( N_match[N_index] > E_match[E_index] ) ? E_match[E_index] : N_match[N_index];
}



/**
 * Initialize the buffer queues for the handle and start the threads.
 *
 * @return -1 on failure, 0 on success.
 */
static int initialize_queues(ne_handle handle) {
   int i;
   int num_blocks = handle->erasure_state->N + handle->erasure_state->E;

   struct read_meta_buffer_struct read_meta_state; //needed to determine metadata consensus for reads

   /* open files and initialize BufferQueues */
   for(i = 0; i < num_blocks; i++) {
      int error, file_descriptor;
      char path[MAXNAME];
      BufferQueue *bq = &handle->blocks[i];
      // generate the path
      // sprintf(bq->path, handle->path_fmt, (i + handle->erasure_state->O) % num_blocks);
      handle->snprintf(bq->path, MAXNAME, handle->path_fmt, (i + handle->erasure_state->O) % num_blocks, handle->printf_state);

      if ( handle->mode == NE_REBUILD ) {
         strcat(bq->path, REBUILD_SFX);
         PRINTdbg( "starting up rebuild/write thread for block %d\n", i );
      }
      else if ( handle->mode == NE_WRONLY ) {
         strcat(bq->path, WRITE_SFX);
         PRINTdbg( "starting up write thread for block %d\n", i );
      }
      else {
         PRINTdbg( "starting up read thread for block %d\n", i );
      }
    
      if(bq_init(bq, i, handle) < 0) {
         PRINTerr("bq_init failed for block %d\n", i);
         terminate_threads( BQ_ABORT, handle, i, 0 );
         return -1;
      }
      // note that read threads will be initialized in a halted state

      // start the threads
      if ( handle->mode == NE_WRONLY  ||  handle->mode == NE_REBUILD )
         error = pthread_create(&handle->threads[i], NULL, bq_writer, (void *)bq);
      else
         error = pthread_create(&handle->threads[i], NULL, bq_reader, (void *)bq);
      if(error != 0) {
         PRINTerr("failed to start thread %d\n", i);
         terminate_threads( BQ_ABORT, handle, i, 0 );
         return -1;
      }
   }

   // We finish checking thread status down here in order to give them a bit more time to spin up.
   for(i = 0; i < num_blocks; i++) {

      BufferQueue *bq = &handle->blocks[i];

      PRINTdbg("Checking for error opening block %d\n", i);

      if ( pthread_mutex_lock( &bq->qlock ) ) {
         PRINTerr( "failed to aquire queue lock for thread %d\n", i );
         terminate_threads( BQ_ABORT, handle, i+1, 0 );
         return -1;
      }

      // wait for the queue to be ready.
      while( !( bq->state_flags & BQ_OPEN ) ) // wait for the thread to open its file
         pthread_cond_wait( &bq->master_resume, &bq->qlock );
      pthread_mutex_unlock( &bq->qlock ); // just waiting for open to complete, don't need to hold this longer

   }

   // For reads, find the most common values from amongst all meta information, now that all threads have started.
   // We have to do this here, in case we don't have a bsz value
   if ( handle->mode == NE_RDONLY  ||  handle->mode == NE_RDALL ) {
      int matches = check_matches( handle->blocks, i, &(read_meta_state) );
      // sanity check: if N/E values have changed at this point, the meta info is in a very odd state
      if ( handle->erasure_state->N != read_meta_state.N  ||  handle->erasure_state->E != read_meta_state.E ) {
         PRINTerr( "detected mismatch between provided N/E (%d/%d) and the most common meta values for this stripe (%d/%d)\n", 
                     handle->erasure_state->N, handle->erasure_state->E, read_meta_state.N, read_meta_state.E );
         terminate_threads( BQ_ABORT, handle, num_blocks, 0 );
         return -1;
      }
      handle->erasure_state->O = read_meta_state.O;
      if ( !(handle->erasure_state->bsz) ) // only set bsz if not already specified via NE_SETBSZ mode
         handle->erasure_state->bsz = read_meta_state.bsz;
      handle->erasure_state->nsz = read_meta_state.nsz;
      handle->erasure_state->totsz = read_meta_state.totsz;
      // Note: ncompsz and crcsum are set by the thread itself
      for ( i = 0; i < num_blocks; i++ ) {
         // take this opportunity to mark all mismatched meta values as incorrect
         read_meta_buffer read_buf = (read_meta_buffer)handle->blocks[i].buffers[0];
         if ( read_buf->N != handle->erasure_state->N  ||  read_buf->E != handle->erasure_state->E  ||  read_buf->O != handle->erasure_state->O  ||  
              read_buf->bsz != handle->erasure_state->bsz  ||  read_buf->nsz != handle->erasure_state->nsz  ||  
              read_buf->totsz != handle->erasure_state->totsz )
            handle->erasure_state->manifest_status[i] = 1;
         // free our read_meta_buff structs
         free( read_buf ); 
         // update each thread's buffer size, just in case
         handle->blocks[i].buffer_size = handle->erasure_state->bsz;
      }
   }


   /* allocate buffers */
   for(i = 0; i < MAX_QDEPTH; i++) {

      PRINTdbg( "creating buffer list for queue position %d\n", i );

      int j;
      // note, we always make space for a crc.  For writes, this is only needed if we are including 
      // intermediate-crcs.  For reads, we will use this extra space to indicate any data 
      // integrity errors for each buffer..
      int error = posix_memalign(&handle->buffer_list[i], 64,
                               num_blocks * ( handle->erasure_state->bsz + sizeof( u32 ) ) );
      if(error == -1) {
         // clean up previously allocated buffers and fail.
         // we can't recover from this error.
         for(j = i-1; j >= 0; j--) {
            free(handle->buffer_list[j]);
         }
         PRINTerr("posix_memalign failed for queue %d\n", i);
         return -1;
      }

      //void *buffers[MAX_QDEPTH];
      for(j = 0; j < num_blocks; j++) {
         handle->block_buffs[i][j] = handle->buffer_list[i] + ( j * ( handle->erasure_state->bsz + sizeof( u32 ) ) );
         // assign pointers into the memaligned buffers.
         handle->blocks[j].buffers[i] = handle->block_buffs[i][j];
      }

   }

   // finally, we have to give all necessary read threads the go-ahead to begin
   if( handle->mode == NE_RDONLY ) {
      resume_threads( 0, handle, handle->erasure_state->N, 0 );
   }
   else if ( handle->mode == NE_RDALL ) {
      // for NE_RDALL, we immediately start both data and erasure threads
      resume_threads( 0, handle, handle->erasure_state->N + handle->erasure_state->E, 0 );
      handle->ethreads_running  = handle->erasure_state->E;
   }

   return 0;
}


int bq_enqueue(BufferQueue *bq, const void *buf, size_t size) {
  int ret = 0;

  if((ret = pthread_mutex_lock(&bq->qlock)) != 0) {
    PRINTerr("Failed to lock queue for write\n");
    errno = ret;
    return -1;
  }

  while(bq->qdepth == MAX_QDEPTH)
    pthread_cond_wait(&bq->master_resume, &bq->qlock);

  // NOTE: _Might_ be able to get away with not locking here, since
  // access is controled by the qdepth var, which will not allow a
  // read until we say there is stuff here to be read.
  // 
  // bq->buffers[bq->tail] is a pointer to the beginning of the
  // buffer. bq->buffers[bq->tail] + bq->offset should be a pointer to
  // the inside of the buffer.
  memcpy(bq->buffers[bq->tail]+bq->offset, buf, size);

  if(size+bq->offset < bq->buffer_size) {
    // then this is not a complete block.
    PRINTdbg("saved incomplete buffer for block %d at queue position %d\n", bq->block_number, bq->tail);
    bq->offset += size;
  }
  else {
    bq->offset = 0;
    bq->qdepth++;
    bq->tail = (bq->tail + 1) % MAX_QDEPTH;
    PRINTdbg("queued complete buffer for block %d at queue position %d\n", bq->block_number, bq->tail);
    pthread_cond_signal(&bq->thread_resume);
  }
  pthread_mutex_unlock(&bq->qlock);

  return ret;
}


// unused.  These all devolve to memset(0), which is already done on all
// the BenchStats in a handle, when the handle is initialized
int init_bench_stats(BenchStats* stats) {

   fast_timer_reset(&stats->thread);
   fast_timer_reset(&stats->open);
   log_histo_reset(&stats->open_h);

   fast_timer_reset(&stats->read);
   log_histo_reset(&stats->read_h);

   fast_timer_reset(&stats->write);
   log_histo_reset(&stats->write_h);

   fast_timer_reset(&stats->close);
   log_histo_reset(&stats->open_h);
   fast_timer_reset(&stats->rename);

   fast_timer_reset(&stats->stat);
   fast_timer_reset(&stats->xattr);

   fast_timer_reset(&stats->crc);
   log_histo_reset(&stats->crc_h);

   return 0;
}


// This might work, if you have an NFS Multi-Component implementation,
// and your block-directories are named something like /path/to/block%d/more/path/filename,
// and the name of the block 0 dir is /path/to/block0
//
// This is the default, for MC repos.  We ignore <printf_state>
//
// There's an opportunity for MC repos to handle e.g. non-zero naming, etc, by extending the
// the default marfs configuration for MC repos, something like is done for MC_SOCKETS,
// and passing that in as <stat>, here.

int ne_default_snprintf(char* dest, size_t size, const char* format, u32 block, void* printf_state) {
  return snprintf(dest, size, format, block);
}


ne_handle create_handle( SnprintfFunc fn, void* state,
                           uDALType itype, SktAuth auth,
                           TimingFlagsValue timing_flags, TimingData* timing_data,
                           char *path, ne_mode mode, e_status erasure_state ) {
   // this makes a convenient place to handle a NE_NOINFO case.
   // Just make sure not to infinite loop by calling ne_stat1() after it calls us!
   if ( mode != NE_STAT  &&  !(erasure_state->N) ) {
      PRINTdbg( "using ne_stat1() to determine N/E/O values for handle\n" );
      // need to stash our bsz value, in case NE_SETBSZ was specified
      u32 bsz = erasure_state->bsz; 
      // if we don't have any N/E/O values, let ne_stat() do the work of determining those
      if ( ne_stat1( fn, state, itype, auth, timing_flags, timing_data, path, erasure_state ) )
         return NULL;
      // we now need to stash the values we care about, and clear the rest of this struct; 
      // otherwise, our meta-info/data errors may not take offset into account.
      int N = erasure_state->N;
      int E = erasure_state->E;
      int O = erasure_state->O;
      // completely clear the e_status struct to ensure no extra state is carried over
      memset( erasure_state, 0, sizeof( struct ne_stat_struct ) );
      // then reassign the values we wish to preserve
      erasure_state->N = N;
      erasure_state->E = E;
      erasure_state->O = O;
      // if bsz was not set, this value will be overwritten in initialize_queues()
      erasure_state->bsz = bsz;
   }


   ne_handle handle = malloc( sizeof( struct handle ) );
   if ( handle == NULL )
      return handle;
   memset(handle, 0, sizeof(struct handle));

   /* initialize any non-zero handle members */
   handle->erasure_state = erasure_state;
   handle->buff_offset = 0;
   handle->prev_err_cnt = 0;
   handle->mode = mode;


   handle->snprintf = fn;
   handle->printf_state    = fn;
   handle->auth     = auth;
   handle->impl     = get_impl(itype);

   if (! handle->impl) {
      PRINTerr( "create_handle: couldn't find implementation for itype %d\n", itype );
      free( handle );
      errno = EINVAL;
      return NULL;
   }

   handle->timing_data_ptr = (timing_data ? timing_data : &handle->timing_data);
   TimingData* timing      = handle->timing_data_ptr; // shorthand
   timing->flags           = timing_flags;

   if (timing->flags) {
      fast_timer_inits();

      // // redundant with memset() on handle
      // init_bench_stats(&handle->agg_stats);
   }
   if (timing->flags & TF_HANDLE)
      fast_timer_start(&timing->handle_timer); /* start overall timer for handle */

   char* nfile = malloc( strlen(path) + 1 );
   strncpy( nfile, path, strlen(path) + 1 );
   handle->path_fmt = nfile;

   return handle;
}


/**
 * Internal helper function, intended to parse a list of variadic ne_open() args
 * into the provided erasure_state struct and to strip parsing flags from the 
 * provided ne_mode value.
 * @param va_list ap : Variadic argument list for parsing
 * @param ne_mode mode : Mode value to assist in parsing
 * @param e_status erasure_state : e_status struct pointer to have N/E/O/bsz populated
 * @return ne_mode : Mode argument with parsing flags stripped, or 0 on error
 */
ne_mode parse_va_open_args( va_list ap, ne_mode mode, e_status erasure_state ) {
   // first, ensure there is no garbage data in our e_status struct
   memset( erasure_state, 0, sizeof( struct ne_stat_struct ) );

   // now, use the mode flags to determine how to parse the variadic args
   int counter = 3;
   if ( mode & NE_SETBSZ ) {
      counter++;
      mode -= NE_SETBSZ;
      PRINTdbg( "ne_open: NE_SETBSZ flag detected\n");
   }
   else {
      erasure_state->bsz = BLKSZ;
   }
   if ( mode & NE_NOINFO ) {
      counter -= 3;
      mode -= NE_NOINFO;
      PRINTdbg( "ne_open: NE_NOINFO flag detected\n");
   }

   // Parse variadic arguments
   if ( counter == 1 ) {
      erasure_state->bsz = va_arg( ap, int );
   }
   else if ( counter > 1 ){
      erasure_state->O = va_arg( ap, int );
      erasure_state->N = va_arg( ap, int );
      erasure_state->E = va_arg( ap, int );
      if ( counter == 4 ){
         erasure_state->bsz = va_arg( ap, int );
      }
   }

   if ( mode == NE_WRONLY  &&  counter < 2 ) {
      PRINTerr( "ne_open: recieved an invalid \"NE_NOINFO\" flag for \"NE_WRONLY\" operation\n");
      errno = EINVAL;
      return 0;
   }

#ifdef INT_CRC
   //shrink data size to fit crc within block
   erasure_state->bsz -= sizeof( u32 );
#endif

   if ( counter > 1 ) {
      if ( erasure_state->N < 1  ||  erasure_state->N > MAXN ) {
         PRINTerr( "ne_open: improper N arguement received - %d\n", erasure_state->N);
         errno = EINVAL;
         return 0;
      }
      if ( erasure_state->E < 0  ||  erasure_state->E > MAXE ) {
         PRINTerr( "ne_open: improper E arguement received - %d\n", erasure_state->E);
         errno = EINVAL;
         return 0;
      }
      if ( erasure_state->O < 0  ||  erasure_state->O >= (erasure_state->N+erasure_state->E) ) {
         PRINTerr( "ne_open: improper erasure_offset arguement received - %d\n", erasure_state->O);
         errno = EINVAL;
         return 0;
      }
   }
   if ( erasure_state->bsz < 0  ||  erasure_state->bsz > MAXBLKSZ ) {
      PRINTerr( "ne_open: improper bsz argument received - %d\n", erasure_state->bsz );
      errno = EINVAL;
      return 0;
   }

   // return the mode argument, with NE_NOINFO and NE_SETBSZ flags stipped out
   return mode;
}


/**
 * Opens a new handle for a specific erasure striping
 *
 * ne_open(path, mode, ...)  calls this with fn=ne_default_snprintf, and printf_state=NULL
 *
 * @param SnprintfFunc : function takes block-number and <state> and produces per-block path from template.
 * @param state : optional state to be used by SnprintfFunc (e.g. configuration details)
 * @param itype : uDAL implementation for low-level storage access
 * @param auth : optional credentials (actually AWSContext*) to authenticate socket connections (e.g. RDMA)
 * @param timing_flags : control collection of timing-data across various operations
 * @param timing_data_ptr : optional TimingData not in ne_handle (i.e. to survive ne_close())
 * @param char* path : sprintf format-template for individual files of in each stripe.
 * @param ne_mode mode : Mode in which the file is to be opened.  Either NE_RDONLY, NE_WRONLY, or NE_REBUILD.
 * @param int erasure_offset : Offset of the erasure stripe, defining the name of the first N file
 * @param int N : Data width of the striping
 * @param int E : Erasure width of the striping
 *
 * @return ne_handle : The new handle for the opened erasure striping
 */
int initialize_handle( ne_handle handle )
{
   // assign short names for easy reference (should never be altered)
   const int N = handle->erasure_state->N;
   const int E = handle->erasure_state->E;
   const int erasure_offset = handle->erasure_state->O;
   const u32 bsz = handle->erasure_state->bsz;
   PRINTdbg( "ne_open: using stripe values (N=%d,E=%d,bsz=%d,offset=%d)\n", N,E,bsz,erasure_offset);

   // umask is process-wide, so we have to manipulate it outside of the threads
   mode_t mask = umask(0000);
   if(initialize_queues(handle) < 0) {
     // all destruction/cleanup should be handled in initialize_queues()
     errno = ENOMEM;
     return -1;
   }
   umask(mask);
   int nerr = 0;
   int i;
   // quick loop to count up errors
   for ( i = 0; i < (handle->erasure_state->N + handle->erasure_state->E); i++ ) {
     if ( handle->erasure_state->data_status[i]  ||  handle->erasure_state->manifest_status[i] )
       nerr++;
   }
   if( (handle->mode == NE_WRONLY || handle->mode == NE_REBUILD)  &&  UNSAFE(handle,nerr) ) {
     PRINTerr( "errors have rendered the handle unsafe to continue\n" );
     for(i = 0; i < handle->erasure_state->N + handle->erasure_state->E; i++) {
       bq_abort(&handle->blocks[i]);
       // just detach and let the OS clean up. We don't care about the return any more.
       pthread_detach(handle->threads[i]);
     }
     return -1; //don't hand out a dead handle!
   }

   /* allocate matrices */
   handle->encode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->decode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->invert_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->g_tbls = malloc(MAXPARTS * MAXPARTS * 32);

   return 0;
}


// caller (e.g. MC-sockets DAL) specifies SprintfFunc, stat, and SktAuth
// New: caller also provides flags that control whether stats are collected
//
// <timing_data> can be NULL if caller doesn't want to provide their own
//    TimingData.  (The reason for doing so would be to survive
//    ne_close().)
ne_handle ne_open1( SnprintfFunc fn, void* state,
                    uDALType itype, SktAuth auth,
                    TimingFlagsValue timing_flags, TimingData* timing_data,
                    char *path, ne_mode mode, ... ) {

   e_status erasure_state_tmp = malloc( sizeof( struct ne_stat_struct ) );
   if ( erasure_state_tmp == NULL ) {
      errno = ENOMEM;
      return NULL;
   }

   va_list vl;
   va_start(vl, mode);
   // this function will parse args and zero out our e_status struct
   mode = parse_va_open_args( vl, mode, erasure_state_tmp );
   va_end(vl);

   if ( mode != NE_WRONLY  &&  mode != NE_RDONLY  &&  mode != NE_RDALL ) { //reject improper mode arguments
      PRINTerr( "improper mode argument received - %d\n", mode );
      free( erasure_state_tmp );
      errno = EINVAL;
      return NULL;
   }

   // this will handle allocating a handle and setting values
   ne_handle handle = create_handle( fn, state, itype, auth, timing_flags, timing_data, path, mode, erasure_state_tmp );
   if ( handle == NULL ) {
      free( erasure_state_tmp );
      return handle;
   }

   if( initialize_handle(handle) ) {
      free( handle );
      free( erasure_state_tmp );
      return NULL;
   }
   return handle;
}


// provide defaults for SprintfFunc, printf_state, and SktAuth
// so naive callers can continue to work (in some cases).
ne_handle ne_open( char *path, ne_mode mode, ... ) {
   e_status erasure_state_tmp = malloc( sizeof( struct ne_stat_struct ) );
   if ( erasure_state_tmp == NULL ) {
      errno = ENOMEM;
      return NULL;
   }

   va_list vl;
   va_start(vl, mode);
   // this function will parse args and zero out our e_status struct
   mode = parse_va_open_args( vl, mode, erasure_state_tmp );
   va_end(vl);

   if ( mode != NE_WRONLY  &&  mode != NE_RDONLY  &&  mode != NE_RDALL ) { //reject improper mode arguments
      PRINTerr( "improper mode argument received - %d\n", mode );
      free( erasure_state_tmp );
      errno = EINVAL;
      return NULL;
   }

   // this is safe for builds with/without sockets enabled
   // and with/without socket-authentication enabled
   // However, if you do build with socket-authentication, this will require a read
   // from a file (~/.awsAuth) that should probably only be accessible if ~ is /root.
   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("failed to initialize default socket-authentication credentials\n");
      return NULL;
   }

   // this will handle allocating a handle and setting values
   ne_handle handle = create_handle( ne_default_snprintf, NULL, UDAL_POSIX, auth, 0, NULL, path, mode, erasure_state_tmp );
   if ( handle == NULL ) {
      free( erasure_state_tmp );
      return handle;
   }

   if( initialize_handle(handle) ) {
      free( handle );
      free( erasure_state_tmp );
      return NULL;
   }

   return handle;
}



/**
 * Threaded read of nbytes of data at offset from the erasure striping referenced by the given handle
 * @param ne_handle handle : Open handle referencing the desired erasure striping
 * @param void* buffer : Memory location in which to store the retrieved data
 * @param int nbytes : Integer number of bytes to be read
 * @param off_t offset : Offset within the data at which to begin the read
 * @return int : The number of bytes read or -1 on a failure
 */
ssize_t ne_read( ne_handle handle, void *buffer, size_t nbytes, off_t offset ) {

   PRINTdbg( "called to retrieve %zu bytes at offset %zd\n", nbytes, offset );

// ---------------------- CHECK BOUNDARY AND INVALID CALL CONDITIONS ----------------------

   if ( !(handle) ) {
      PRINTerr( "ne_read received a NULL handle!\n" );
      return -1;
   }

   int N = handle->erasure_state->N;
   int E = handle->erasure_state->E;
   size_t bsz = handle->erasure_state->bsz;
   size_t stripesz = bsz * N;

   if (nbytes > UINT_MAX) {
     PRINTerr( "ne_read: not yet validated for write-sizes above %lu\n", UINT_MAX);
     errno = EFBIG;             /* sort of */
     return -1;
   }

   if ( handle->mode != NE_RDONLY  &&  handle->mode != NE_RDALL ) {
      PRINTerr( "ne_read: handle is in improper mode for reading!\n" );
      errno = EPERM;
      return -1;
   }

   if ( (offset + nbytes) > handle->erasure_state->totsz ) {
      if ( offset >= handle->erasure_state->totsz )
         return 0; //EOF
      nbytes = handle->erasure_state->totsz - offset;
      PRINTdbg("ne_read: read would extend beyond EOF, resizing read request to %zu\n", nbytes);
   }

// ---------------------- SKIP TO APPROPRIATE FILE STRIPE ----------------------

   int cur_stripe = (int)( offset / stripesz ); // I think int truncation actually works out in our favor here

   // if the offset is behind us or so far in front that there is no chance of the work having already been done...
   if ( (handle->buff_offset > ( cur_stripe * stripesz ))  ||  (( handle->buff_offset + ( MAX_QDEPTH * stripesz ) ) < ( cur_stripe * stripesz )) ) {
      PRINTdbg( "new offset of %zd will require threads to reseek\n", offset );
      // we need to halt all threads and trigger a reseek
      signal_threads( BQ_HALT, handle, N+E, 0 );
      resume_threads( (off_t)cur_stripe * ( bsz + sizeof(u32) ), handle, N + handle->ethreads_running, 0 );
   }
   else {
      // we may still be at least a few stripes behind the given offset.  Calculate how many.
      int munch_stripes = (int)(( offset - handle->buff_offset ) / stripesz);
      // if we're at all behind...
      if (munch_stripes) {
         PRINTdbg( "attempting to 'munch' %d buffers off of all queues (%d) to reach offset of %zd\n", munch_stripes, N + handle->ethreads_running, offset );
         // just chuck buffers off of each queue until we hit the right stripe
         int i;
         for( i = 0; i < (N + handle->ethreads_running); i++ ) {
            int thread_munched = 0;

            // since the entire loop is a critical section, just lock around it
            if ( pthread_mutex_lock( &handle->blocks[i].qlock ) ) {
               PRINTerr( "failed to acquire queue lock for thread %d\n", i );
               return -1;
            }
            while ( thread_munched < munch_stripes ) {
               
               while ( handle->blocks[i].qdepth == 0 ) {
                  PRINTdbg( "waiting on thread %d to produce a buffer\n", i );
                  // releasing the lock here will let the thread get some work done
                  pthread_cond_wait( &handle->blocks[i].master_resume, &handle->blocks[i].qlock );
               }

               // remove as many buffers as we can without going beyond the appropriate stripe
               int orig_depth = handle->blocks[i].qdepth;
               handle->blocks[i].qdepth = ( (orig_depth - ( munch_stripes - thread_munched )) < 0 ) ? 0 : (orig_depth - ( munch_stripes - thread_munched ));
               handle->blocks[i].head = ( handle->blocks[i].head + ( orig_depth - handle->blocks[i].qdepth ) ) % MAX_QDEPTH;
               thread_munched += ( orig_depth - handle->blocks[i].qdepth );

               // make sure to signal the thread if we just made room for it to resume work
               if ( orig_depth == MAX_QDEPTH )
                  pthread_cond_signal( &handle->blocks[i].thread_resume );
            }
            pthread_mutex_unlock( &handle->blocks[i].qlock );
         }
         PRINTdbg( "finished pre-read buffer 'munching'\n" );
      }
   }

   // we are now on the proper stripe for all running queues, so update our offset to reflect that
   off_t orig_handle_offset = handle->buff_offset;
   handle->buff_offset = cur_stripe * stripesz;
   offset = offset - handle->buff_offset;

   PRINTdbg( "after reaching the appropriate stripe, read is at offset %zd\n", offset );

// ---------------------- BEGIN MAIN READ LOOP ----------------------

   // time to start actually filling this read request
   size_t bytes_read = 0;
   while( nbytes ) { // while data still remains to be read, loop over each stripe
      unsigned char stripe_in_err[MAXPARTS] = { 0 };
      unsigned char stripe_err_list[MAXPARTS] = { 0 };
      int nstripe_errors = 0;
      int nsrcerr = 0;
      int ethreads_checked = 0;
      size_t to_read_in_stripe = ( nbytes % stripesz ) - offset;
      char read_full_stripe = ( (offset + nbytes) > stripesz ) ? 1 : 0;
      int cur_block = 0;
      int skip_blocks = (int)( offset / bsz ); // determine how many blocks we need to skip over to hit the first requested data
      offset = offset % bsz; // adjust offset to be that within the first requested block

      PRINTdbg( "preparing to read from stripe %d beginning at offset %zd in block %d\n", cur_stripe, offset, skip_blocks );

// ---------------------- VERIFY INTEGRITY OF ALL BLOCKS IN STRIPE ----------------------

      // First, loop through all data buffers in the stripe, looking for errors.
      // Then, starup erasure threads as necessary to deal with errors.
      // Technically, it would theoretically be more efficient to limit this to 
      // only the blocks we expect to need.  However, if we hit any error in those 
      // blocks, we'll suddenly need the whole stripe.  I am hoping the reduced 
      // complexity of just checking them all will be worth what will probably 
      // only be the slightest of performance hits.  Besides, in the expected 
      // use case of reading a file start to finish, we'll eventually need this 
      // entire stripe regardless.
      while ( nstripe_errors > ethreads_checked  ||  cur_block < N ) {
         // check if we can even handle however many errors we've hit so far
         if ( nstripe_errors > E ) {
            PRINTdbg( "stripe %d has too many data errors (%d) to be recovered\n", cur_stripe, nstripe_errors );
            errno=ENODATA;
            return -1;
         }
         int threads_to_start = (nstripe_errors - handle->ethreads_running); // previous check should insure we don't start more than E
         if ( threads_to_start > 0 ) { // ignore possible negative value
            PRINTdbg( "starting up %d erasure threads at offset (%zd) to cope with data errors\n", threads_to_start, (off_t)cur_stripe * bsz );
            resume_threads( (off_t)cur_stripe * ( bsz + sizeof(u32) ), handle, threads_to_start, N + handle->ethreads_running );
            handle->ethreads_running += threads_to_start;
         }
         ethreads_checked = nstripe_errors; //we will be checking as many erasure blocks as there are errors

         // we now need to check each needed block for errors.
         // Note that neglecting to reassign cur_block in this loop allows us to avoid 
         // rechecking threads when the outer while-loop repeats.
         for ( ; cur_block < (N+ethreads_checked); cur_block++ ) {
            if ( pthread_mutex_lock( &handle->blocks[cur_block].qlock ) ) {
               PRINTerr( "failed to acquire queue lock for erasure thread %d\n", cur_block );
               return -1;
            }
            // if necessary, wait for the buffer to be ready
            while ( handle->blocks[cur_block].qdepth == 0 ) {
               PRINTdbg( "waiting on thread %d to produce a buffer\n", cur_block );
               // releasing the lock here will let the thread get some work done
               pthread_cond_wait( &handle->blocks[cur_block].master_resume, &handle->blocks[cur_block].qlock );
            }
            pthread_mutex_unlock( &handle->blocks[cur_block].qlock ); // just wanted the buffer to be ready, don't need to hold this

            // check for errors based on whether the crc position of this buffer was cleaned out
            if ( !(*(u32*)( handle->blocks[cur_block].buffers[ handle->blocks[cur_block].head ] + bsz )) ) {
               // a zero value in the crc position means the buffer is bad
               PRINTdbg( "detected bad buffer for block %d at stripe %d\n", cur_block, cur_stripe );
               stripe_err_list[nstripe_errors] = cur_block;
               nstripe_errors++;
               stripe_in_err[cur_block] = 1;
               // we just need to note the error, nothing to be done about it until we have all buffers ready
            }
         }
         if ( !(ethreads_checked) )
            nsrcerr = nstripe_errors; // stash the number of data blocks in error for later erasure use
         PRINTdbg( "have checked %d blocks in stripe %d for errors\n", cur_block, cur_stripe );
      }

// ---------------------- HALT UNNECESSARY ERASURE THREADS ----------------------

      // if we'er trying to avoid unnecessary reads AND are not re-hitting the same stripe as a previous call...
      if ( handle->mode == NE_RDONLY  &&  handle->buff_offset != orig_handle_offset ) {
         // keep the greater of how many erasure threads we've needed in the last couple of stripes...
         if ( nstripe_errors > handle->prev_err_cnt )
            handle->prev_err_cnt = nstripe_errors;
         // ...and halt all others
         for ( cur_block = (N + nstripe_errors); cur_block < (N + handle->prev_err_cnt); cur_block++ ) {
            bq_signal( &handle->blocks[cur_block], BQ_HALT );
            handle->ethreads_running--;
         }
         // need to reassign, in case the number of errors is decreasing
         handle->prev_err_cnt = nstripe_errors;
      }

// ---------------------- REGENERATE FAULTY BLOCKS FROM ERASURE ----------------------

      // if necessary, engage erasure code to regenerate the missing buffers
      if ( nstripe_errors ) {

         // check if our erasure_state has changed, and invalidate our erasure_structs if so
         for ( cur_block = 0; cur_block < (N + E); cur_block++ ) {
            if ( handle->prev_in_err[ cur_block ] != stripe_in_err[ cur_block ] ) {
               handle->e_ready = 0;
               handle->prev_in_err[ cur_block ] = stripe_in_err[ cur_block ];
            }
         }

         if ( handle->timing_data_ptr->flags & TF_ERASURE )
            fast_timer_start(&handle->timing_data_ptr->erasure);

         if ( !(handle->e_ready) ) {

            // Generate encode matrix encode_matrix
            // The matrix generated by gf_gen_rs_matrix
            // is not always invertable.
            PRINTdbg("initializing erasure structs...\n");
            gf_gen_rs_matrix(handle->encode_matrix, N+E, N);

            // Generate g_tbls from encode matrix encode_matrix
            ec_init_tables(N, E, &(handle->encode_matrix[N * N]), handle->g_tbls);

            int ret_code = gf_gen_decode_matrix( handle->encode_matrix, handle->decode_matrix,
                  handle->invert_matrix, handle->decode_index, stripe_err_list, stripe_in_err,
                  nstripe_errors, nsrcerr, N, N+E);

            if (ret_code != 0) {
               PRINTerr("failure to generate decode matrix, errors may exceed erasure limits\n");
               errno=ENODATA;

               if ( handle->timing_data_ptr->flags & TF_ERASURE ) {
                  fast_timer_stop(&handle->timing_data_ptr->erasure);
                  log_histo_add_interval(&handle->timing_data_ptr->erasure_h,
                                         &handle->timing_data_ptr->erasure);
               }
               return -1;
            }


            PRINTdbg( "init erasure tables nsrcerr = %d e_ready = %d...\n", nsrcerr, handle->e_ready );
            ec_init_tables(N, nstripe_errors, handle->decode_matrix, handle->g_tbls);

            handle->e_ready = 1; //indicate that rebuild structures are initialized
         }

         // as this struct will change depending on the head position of our queues, we must generate here
         unsigned char *recov[ MAXPARTS ];
         for (cur_block = 0; cur_block < N; cur_block++) {
            BufferQueue* bq = &handle->blocks[handle->decode_index[cur_block]];
            recov[cur_block] = bq->buffers[ bq->head ];
         }

         unsigned char* temp_buffs[ nstripe_errors ];
         for ( cur_block = 0; cur_block < nstripe_errors; cur_block++ ) {
            // assign storage locations for the repaired buffers to be on top of the faulty buffers
            BufferQueue* bq = &handle->blocks[stripe_err_list[ cur_block ]];
            temp_buffs[ cur_block ] = bq->buffers[ bq->head ];
            // as we are regenerating over the bad buffer, mark it as usable for future iterations
            *(u32*)( temp_buffs[ cur_block ] + bsz ) = 1;
         }

         PRINTdbg( "performing regeneration from erasure...\n" );

         ec_encode_data(bsz, N, nstripe_errors, handle->g_tbls, recov, &temp_buffs[0]);

         if ( handle->timing_data_ptr->flags & TF_ERASURE ) {
            fast_timer_stop(&handle->timing_data_ptr->erasure);
            log_histo_add_interval(&handle->timing_data_ptr->erasure_h,
                                   &handle->timing_data_ptr->erasure);
         }


      }

// ---------------------- COPY OUT REQUESTED PORTIONS OF THE STRIPE ----------------------

      // finally, copy all requested data into the buffer and clear unneeded queue entries
      for( cur_block = 0; cur_block <  N + handle->ethreads_running; cur_block++ ) {
         BufferQueue* bq = &handle->blocks[cur_block];

         // does this buffer contain requested data?
         if ( cur_block >= skip_blocks  &&  cur_block < N ) {
            // if so, copy it to our output buffer
            size_t to_copy = ( (bsz - offset) > nbytes ) ? nbytes : (bsz - offset);
            // as no one but ne_read should be adjusting the head position, and we have already verified that this buffer is ready, 
            // we can safely copy from it without holding the queue lock
            PRINTdbg( "copying %zd bytes from thread %d's buffer at position %d to the output buff\n", to_copy, cur_block, bq->head );
            memcpy( buffer + bytes_read, bq->buffers[bq->head] + offset, to_copy );
            nbytes -= to_copy;
            bytes_read += to_copy;
            offset = 0; // as we have copied from the first applicable value, this offset is no longer relevant
         }

         // if this write request extends beyond the current stripe, we need to clear out these queue entries
         if ( read_full_stripe ) {
            PRINTdbg( "clearing a buffer from thread %d's queue as our read offset is beyond it\n", cur_block );
            if ( pthread_mutex_lock( &handle->blocks[cur_block].qlock ) ) {
               PRINTerr( "failed to acquire queue lock for thread %d\n", cur_block );
               return -1;
            }
            // wait for a buffer to be produced, if necessary
            while ( handle->blocks[cur_block].qdepth == 0 ) {
               PRINTdbg( "waiting on thread %d to produce a buffer\n", cur_block );
               // releasing the lock here will let the thread get some work done
               pthread_cond_wait( &handle->blocks[cur_block].master_resume, &handle->blocks[cur_block].qlock );
            }

            // just throw away this buffer
            handle->blocks[cur_block].qdepth--;
            handle->blocks[cur_block].head = ( handle->blocks[cur_block].head + 1 ) % MAX_QDEPTH;

            // make sure to signal the thread if we just made room for it to resume work
            if ( handle->blocks[cur_block].qdepth == MAX_QDEPTH - 1 )
               pthread_cond_signal( &handle->blocks[cur_block].thread_resume );
            pthread_mutex_unlock( &handle->blocks[cur_block].qlock );
         }
         else if ( !(nbytes) ) { // early breakout if we are done.  No point looping over all queues
            break;
         }
      }

// ---------------------- END OF MAIN READ LOOP ----------------------

      // set all values to align with the next stripe
      offset = 0;
      cur_stripe++;
      if ( read_full_stripe )
         handle->buff_offset += stripesz;
   }

   return bytes_read;
}



/**
 * Writes nbytes from buffer into the erasure striping specified by the provided handle
 * @param ne_handle handle : Handle for the erasure striping to be written to
 * @param void* buffer : Buffer containing the data to be written
 * @param int nbytes : Number of data bytes to be written from buffer
 * @return int : Number of bytes written or -1 on error
 */
ssize_t ne_write( ne_handle handle, const void *buffer, size_t nbytes )
{
 
   int N;                       /* number of raid parts not including E */ 
   int E;                       /* num erasure stripes */
   unsigned int bsz;                     /* chunksize in k */ 
   int counter;                 /* general counter */
   int ecounter;                /* general counter */
   ssize_t ret_out;             /* Number of bytes returned by read() and write() */
   unsigned long long totsize;  /* used to sum total size of the input file/stream */
   int mtot;                    /* N + numerasure stripes */
   u32 readsize;
   u32 writesize;
   u32 crc;                     /* crc 32 */
   TimingData* timing = handle->timing_data_ptr;

   if (nbytes > UINT_MAX) {
     PRINTerr( "ne_write: not yet validated for write-sizes above %lu\n", UINT_MAX);
     errno = EFBIG;             /* sort of */
     return -1;
   }

   if ( handle->mode != NE_WRONLY  &&  handle->mode != NE_REBUILD ) {
     PRINTerr( "ne_write: handle is in improper mode for writing! %d\n", handle->mode );
     errno = EPERM;
     return -1;
   }

   N = handle->erasure_state->N;
   E = handle->erasure_state->E;
   bsz = handle->erasure_state->bsz;

   mtot=N+E;


   /* loop until the file input or stream input ends */
   totsize = 0;
   while (1) { 

      counter = handle->buff_rem / bsz;
      /* loop over the parts and write the parts, sum and count bytes per part etc. */
      // NOTE: regarding benchmark timers, this routine just hands off work asynchronously to
      // bq_writer threads.  We let each individual thread maintain its own stats.
      while (counter < N) {

         writesize = ( handle->buff_rem % bsz ); // ? amount being written to block (block size - already written).
         readsize = bsz - writesize; // amount being read for block[block_index] from source buffer

         //avoid reading beyond end of buffer
         if ( totsize + readsize > nbytes ) { readsize = nbytes-totsize; }

         if ( readsize < 1 ) {
            PRINTdbg("ne_write: reading of input is now complete\n");
            break;
         }

         // I think we can understand this as follows: the "read offset" is an
         // offset in the generated erasure data, not including the user's data,
         // and the "write offset" is the logical position in the total output,
         // not including the 4-bytes-per-block of CRC data.
         PRINTdbg( "ne_write: reading input for %lu bytes with offset of %llu "
                   "and writing to offset of %lu in handle buffer\n",
                   (unsigned long)readsize, totsize, handle->buff_rem );
         //memcpy ( handle->buffer + handle->buff_rem, buffer+totsize, readsize);
         int queue_result = bq_enqueue(&handle->blocks[counter], buffer+totsize, readsize);
         if(queue_result == -1) {
           // bq_enqueue will set errno.
           return -1;
         }
         
         PRINTdbg( "ne_write:   ...copy complete.\n");

         totsize += readsize;
         writesize = readsize + ( handle->buff_rem % bsz );
         handle->buff_rem += readsize;

         if ( writesize < bsz ) {  //if there is not enough data to write a full block, stash it in the handle buffer
            PRINTdbg("ne_write: reading of input is complete, stashed %lu bytes in handle buffer\n", (unsigned long)readsize);
            break;
         }

         counter++;
      } //end of writes for N

      // If we haven't written a whole stripe, terminate. This happens
      // if there is not enough data to form a complete stripe.
      if ( counter != N ) {
         break;
      }


      /* calculate and write erasure */
      if (timing->flags & TF_ERASURE)
         fast_timer_start(&timing->erasure);

      if ( handle->e_ready == 0 ) {
         PRINTdbg( "ne_write: initializing erasure matricies...\n");
         // Generate encode matrix encode_matrix
         // The matrix generated by gf_gen_rs_matrix]
         // is not always invertable.
         gf_gen_rs_matrix(handle->encode_matrix, mtot, N);
         // Generate g_tbls from encode matrix encode_matrix
         ec_init_tables(N, E, &(handle->encode_matrix[N * N]), handle->g_tbls);

         handle->e_ready = 1;
      }

      // Perform matrix dot_prod for EC encoding
      // using g_tbls from encode matrix encode_matrix
      // Need to lock the two buffers here.
      int i;
      int buffer_index;
      for(i = N; i < handle->erasure_state->N + handle->erasure_state->E; i++) {
        BufferQueue *bq = &handle->blocks[i];
        if(pthread_mutex_lock(&bq->qlock) != 0) {
          PRINTerr("Failed to acquire lock for erasure blocks\n");
          return -1;
        }
        while(bq->qdepth == MAX_QDEPTH) {
          pthread_cond_wait(&bq->master_resume, &bq->qlock);
        }
        if(i == N) {
          buffer_index = bq->tail;
        }
        else {
          assert(buffer_index == bq->tail);
        }
      }
      PRINTdbg( "ne_write: calculating %d erasure from %d data blocks at queue position %d\n", E, N, buffer_index );

      // this makes a good place to increment our global 'part-size'
      handle->erasure_state->nsz += bsz;

      ec_encode_data(bsz, N, E, handle->g_tbls,
                     (unsigned char **)handle->block_buffs[buffer_index],
                     (unsigned char **)&(handle->block_buffs[buffer_index][N]));

      if (timing->flags & TF_ERASURE) {
         fast_timer_stop(&timing->erasure);
         log_histo_add_interval(&timing->erasure_h,
                                &timing->erasure);
      }

      for(i = N; i < handle->erasure_state->N + handle->erasure_state->E; i++) {
        BufferQueue *bq = &handle->blocks[i];
        bq->qdepth++;
        bq->tail = (bq->tail + 1) % MAX_QDEPTH;
        pthread_cond_signal(&bq->thread_resume);
        pthread_mutex_unlock(&bq->qlock);
      }

      //now that we have written out all data, reset buffer
      handle->buff_rem = 0; 
   }
   handle->erasure_state->totsz += totsize; //as it is impossible to write at an offset, the sum of writes will be the total size

   int nerr = 0; //used for reporting excessive errors at the end of the function
   for ( counter = 0; counter < N + E; counter++) {
      if ( handle->erasure_state->manifest_status[counter] || handle->erasure_state->data_status[counter] )
           nerr++;
   }

   // If the errors exceed the minimum protection threshold number of
   // errrors then fail the write.
   if( UNSAFE(handle,nerr) ) {
     PRINTerr("ne_write: errors exceed minimum protection level (%d)\n",
              MIN_PROTECTION);
     errno = EIO;
     return -1;
   }
   else {
     return totsize;
   }
}



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
         printf("-- block %d\n", i);

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

void extract_repo_name(char* path, char* repo, int* pod_id)
{
   char* token;
   char* path_ = strdup(path);
   char* pod = NULL;
   char* repo_name = NULL;
   //walk through path to get information
   token = strtok(path_, "/");
   while (token != NULL)
   {
      if ((pod = strstr(token, "pod")) != NULL)
      {
         //get the pod ID
         *pod_id = atoi(pod+3);
      }
      else if((repo_name = strstr(token, "_repo")) != NULL)
      {
         //got repo name
         char* underscore = strstr(token, "_");
         size_t len = underscore - token;
         memcpy(repo, token, len);
      }
      token = strtok(NULL, "/");
   }

   free(path_); //test
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
   const char* avg_str_not = "-----"; // i.e. no averaging was done on this value
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





/**
 * Closes the erasure striping indicated by the provided handle and flushes
 * the handle buffer, if necessary.
 *
 * @param ne_handle handle : Handle for the striping to be closed
 *
 * @return int : Status code.  Success is indicated by 0, and failure by -1.
 *               A positive value indicates that the operation was
 *               successful, but that errors were encountered in the
 *               stripe.  The Least-Significant Bit of the return code
 *               corresponds to the first of the N data stripe files, while
 *               each subsequent bit corresponds to the next N files and
 *               then the E files.  A 1 in these positions indicates that
 *               an error was encountered while acessing that specific
 *               file.  Note, this code does not account for the offset of
 *               the stripe.  The code will be relative to the file names
 *               only.  (i.e. an error in "<output_path>1<output_path>"
 *               would be encoded in the second bit of the output, a
 *               decimal value of 2)
 */
int ne_close( ne_handle handle ) 
{
   int            counter;
   int            N;
   int            E;
   unsigned int   bsz;
   int            ret = 0;
   //extract_repo_name(handle->path_fmt, handle->repo, handle->pod_id);
   
   PRINTdbg( "entering ne_close()\n" );

   if ( handle == NULL ) {
      PRINTerr( "ne_close: received a NULL handle\n" );
      errno = EINVAL;
      return -1;
   }

   N = handle->erasure_state->N;
   E = handle->erasure_state->E;
   bsz = handle->erasure_state->bsz;

   TimingData* timing = handle->timing_data_ptr; /* shorthand */


   /* flush the handle buffer if necessary */
   if ( ( handle->mode == NE_WRONLY  ||  handle->mode == NE_REBUILD )  &&  handle->buff_rem != 0 ) {
      int tmp;
      unsigned char* zero_buff;
      PRINTdbg( "ne_close: flushing handle buffer...\n" );
      //zero the buffer to the end of the stripe
      tmp = (N*bsz) - handle->buff_rem;
      zero_buff = malloc(sizeof(char) * tmp);
      bzero(zero_buff, tmp );

      if ( tmp != ne_write( handle, zero_buff, tmp ) ) { //make ne_write do all the work
         PRINTerr( "ne_close: failed to flush handle buffer\n" );
         ret = -1;
      }

      handle->erasure_state->totsz -= tmp;
      free( zero_buff );
   }


   // set the umask here to catch all meta files and reset before returning
   mode_t mask = umask(0000);
   /* Close file descriptors and free bufs and set xattrs for written files */
   counter = 0;
   for(counter = 0; counter < N+E; counter++) {
      bq_close(&handle->blocks[counter]);
   }

   int nerr = 0;
   int i;
   /* wait for the threads */
   for(i = 0; i < handle->erasure_state->N + handle->erasure_state->E; i++) {
      pthread_join(handle->threads[i], NULL);
      bq_destroy(&handle->blocks[i]);
      if ( handle->erasure_state->manifest_status[i] || handle->erasure_state->data_status[i] )
         nerr++; //use this opportunity to count how many errors we have
   }

   // all potential meta-file manipulation should be done now (threads have exited)
   // should be safe to reset umask
   umask(mask);

   /* free the buffers */
   for(i = 0; i < MAX_QDEPTH; i++) {
      free(handle->buffer_list[i]);
   }

   if( (UNSAFE(handle,nerr) && handle->mode == NE_WRONLY) ) {
      PRINTdbg( "ne_close: detected unsafe error levels following write operation\n" );
      ret = -1;
   }
   else if ( nerr > handle->erasure_state->E ) { /* for non-writes */
      PRINTdbg( "ne_close: detected excessive errors following a read operation\n" );
      ret = -1;
   }
   if ( ret == 0 ) {
      PRINTdbg( "ne_close: encoding error pattern in return value...\n" );
      /* Encode any file errors into the return status */
      for( counter = 0; counter < N+E; counter++ ) {
         if ( handle->erasure_state->data_status[counter] | handle->erasure_state->manifest_status[counter] ) {
            ret += ( 1 << ((counter + handle->erasure_state->O) % (N+E)) );
         }
      }
   }

   if ( handle->path_fmt != NULL )
      free(handle->path_fmt);

   free(handle->encode_matrix);
   free(handle->decode_matrix);
   free(handle->invert_matrix);
   free(handle->g_tbls);
   
   if (timing->flags & TF_HANDLE)
      fast_timer_stop(&timing->handle_timer); /* overall cost of this op */

   // if we are only serving libne (marfs/pftool would've provided and
   // alternative TimingData, so timing data could survive ne_close()), and
   // we have been requested to collect timing data (e.g. on the libneTest
   // command-line), then dump it to stdout now.
   if (timing->flags
       && (handle->timing_data_ptr == &handle->timing_data)) {
      show_handle_stats(handle);
   }

   free( handle->erasure_state );
   free(handle);
   return ret;
}


/**
 * Determines whether the parent directory of the given file exists
 * @param char* path : Character string to be searched
 * @param int max_length : Maximum length of the character string to be scanned
 * @return int : 0 if the parent directory does exist and -1 if not
 */
int parent_dir_missing(uDALType itype, SktAuth auth, char* path, int max_length ) {
   char*       tmp   = path;
   int         len   = 0;
   int         index = -1;
   const uDAL* impl  = get_impl(itype);

   struct stat status;
   int         res;

   while ( (len < max_length) &&  (*tmp != '\0') ) {
      if( *tmp == '/' )
         index = len;
      len++;
      tmp++;
   }
   
   tmp = path;
   *(tmp + index) = '\0';
   res = PATHOP(stat, impl, auth, tmp, &status );
   PRINTdbg( "parent_dir_missing: stat of \"%s\" returned %d\n", path, res );
   *(tmp + index) = '/';

   return res;
}


/**
 * Deletes the erasure striping of the specified width with the specified path format
 *
 * ne_delete(path, width)  calls this with fn=ne_default_snprintf, and printf_state=NULL
 *
 * @param char* path : Name structure for the files of the desired striping.  This should contain a single "%d" field.
 * @param int width : Total width of the erasure striping (i.e. N+E)
 * @return int : 0 on success and -1 on failure
 */
int ne_delete1( SnprintfFunc snprintf_fn, void* state,
                uDALType itype, SktAuth auth,
                TimingFlagsValue timing_flags, TimingData* timing_data,
                char* path, int width ) {

   char  file[MAXNAME];       /* array name of files */
   char  partial[MAXNAME];
   int   counter;
   int   ret = 0;
   int   parent_missing;

   const uDAL* impl = get_impl(itype);

   // flags control collection of timing stats
   FastTimer  timer;            // we don't have an ne_handle
   if (timing_flags & TF_HANDLE) {
      fast_timer_inits();
      fast_timer_reset(&timer); /* prepare timer for use */
      fast_timer_start(&timer); /* start overall timer */
   }

   for( counter=0; counter<width; counter++ ) {
      parent_missing = -2;
      bzero( file, sizeof(file) );

      snprintf_fn( file,    MAXNAME, path, counter, snprintf_fn );

      snprintf_fn( partial, MAXNAME, path, counter, snprintf_fn );
      strncat( partial, WRITE_SFX, MAXNAME - strlen(partial) );

      // unlink the file or the unfinished file.  If both fail, check
      // whether the parent directory exists.  If not, indicate an error.
      if ( ne_delete_block1(impl, auth, file)
           &&  PATHOP(unlink, impl, auth, partial )
           &&  (parent_missing = parent_dir_missing(itype, auth, file, MAXNAME)) ) {

         ret = -1;
      }
   }

   if (timing_flags & TF_HANDLE) {
      fast_timer_stop(&timer);
      if (timing_data)
         log_histo_add_interval(&timing_data->misc_h, &timer);
      else
         fast_timer_show(&timer, (timing_flags & TF_SIMPLE),  "delete: ", 0);
   }

   return ret;
}

int ne_delete(char* path, int width ) {

   // This is safe for builds with/without sockets and/or socket-authentication enabled.
   // However, if you do build with socket-authentication, this will require a read
   // from a file (~/.awsAuth) that should probably only be accessible if ~ is /root.
   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("failed to initialize default socket-authentication credentials\n");
      return -1;
   }

   return ne_delete1(ne_default_snprintf, NULL, UDAL_POSIX, auth, 0, NULL, path, width);
}



int ne_rebuild1_vl( SnprintfFunc fn, void* state,
                    uDALType itype, SktAuth auth,
                    TimingFlagsValue timing_flags, TimingData* timing_data,
                    char *path, ne_mode mode, va_list ap ) {

// ---------------------- OPEN THE ORIGINAL STRIPE FOR READ ----------------------

   PRINTdbg( "opening handle for read\n" );

   e_status erasure_state_read = malloc( sizeof( struct ne_stat_struct ) );
   if ( erasure_state_read == NULL ) {
      errno = ENOMEM;
      return -1;
   }

   // open the stripe for RDALL to verify all data/erasure blocks and to regenerate as we read
   // this function will parse args and zero out our e_status struct
   ne_mode read_mode = parse_va_open_args( ap, NE_RDALL | ( mode & ( NE_NOINFO | NE_SETBSZ ) ), erasure_state_read );

   if ( !(read_mode) ) { //reject improper mode arguments
      PRINTerr( "improper mode argument received - %d\n", mode );
      free( erasure_state_read );
      errno = EINVAL;
      return -1;
   }

   // this will handle allocating a handle and setting values
   ne_handle read_handle = create_handle( fn, state, itype, auth, timing_flags, timing_data, path, read_mode, erasure_state_read );
   if ( read_handle == NULL ) {
      free( erasure_state_read );
      return -1;
   }

   if( initialize_handle(read_handle) ) {
      free( read_handle );
      free( erasure_state_read );
      return -1;
   }

   // as we didn't parse our own arguments, we now need to pull their values out of the read handle structs.
   // Even if opened with NE_NOINFO, these should be populated by the time ne_open() returns.
   int N = erasure_state_read->N;
   int E = erasure_state_read->E;
   int O = erasure_state_read->O;
   u32 bsz = erasure_state_read->bsz;
   u64 totsz = erasure_state_read->totsz;
   // allocate a buffer for moving data between the two handles
   size_t buff_size = bsz * N;
   void* data_buff = malloc( sizeof(char) * buff_size ); // reading a whole stripe at a time is probably most efficient
   if ( data_buff == NULL ) {
      PRINTerr( "ne_rebuild: failed to allocate space for a stripe buffer\n" );
      ne_close( read_handle );
      errno = ENOMEM;
      return -1;
   }

// ---------------------- OPEN THE SAME STRIPE FOR OUTPUT ----------------------

   PRINTdbg( "opening handle for write\n" );

   e_status erasure_state_write = malloc( sizeof( struct ne_stat_struct ) );
   if ( erasure_state_write == NULL ) {
      errno = ENOMEM;
      ne_close( read_handle );
      return -1;
   }
   // zeroing out this struct is mandatory, as we won't be calling parse_va_open_args() with it
   // who knows what malloc gave us
   memset( erasure_state_write, 0, sizeof( struct ne_stat_struct ) );

   // populate the write handle with values set in the read handle
   erasure_state_write->N = N;
   erasure_state_write->E = E;
   erasure_state_write->O = O;
   erasure_state_write->bsz = bsz;

   // this will handle allocating a handle and setting value (we can pass in NE_REBUILD here to use the proper suffix for writes)
   ne_handle write_handle = create_handle( fn, state, itype, auth, timing_flags, timing_data, path, NE_REBUILD, erasure_state_write );
   if ( write_handle == NULL ) {
      free( erasure_state_write );
      ne_close( read_handle );
      return -1;
   }

   if( initialize_handle(write_handle) ) {
      free( write_handle );
      free( erasure_state_write );
      ne_close( read_handle );
      return -1;
   }

// ---------------------- BEGIN MAIN REBUILD LOOP ----------------------

   // let's create a struct to indicate which blocks we are rebuilding
   char being_rebuilt[ N + E ];
   // keep track of how many times we have re-read the original file
   char iterations = 0;
   // use this as a flag for final completion
   char all_rebuilt = 0;

   // Now, we need to loop over all data, until the entire file has been successfully read and re-written as necessary
   while ( !(all_rebuilt) ) {

      PRINTdbg( "performing iteration %d of the rebuild process\n", iterations );
      // We should only have to read the original a maximum of two times.  Once to detect all data errors, and 
      // a second time to output all regenerated blocks.  Any more than that is suspicious and should be reported.
      if ( iterations > 1 )
         break;

// ---------------------- DEACTIVATE UNNEEDED OUTPUT THREADS ----------------------

      // At this point, we are either just beginning the rebuild process or are restarting it after hitting an additional 
      // error.  Either way, we need to reach into the write handle and explicitly error-out all blocks that aren't being 
      // rebuilt.  This will prevent any data from being written to them until needed.  Setting their error state like 
      // this should also allow us to bypass having the blocks considered 'bad' at close time of write_handle.
      signal_threads( BQ_HALT, write_handle, N+E, 0 ); // halt all write threads
      // explicitly clear fields set by ne_write()
      write_handle->erasure_state->nsz = 0;
      write_handle->erasure_state->totsz = 0;
      write_handle->buff_rem = 0;
      int i;
      for ( i = 0; i < (N + E); i++ ) {
         BufferQueue* bq = &write_handle->blocks[i];
         if ( erasure_state_read->manifest_status[i] || erasure_state_read->data_status[i] ) {
            // if the read handle has this block listed as being in error, we need to actually write out a new copy
            PRINTdbg( "block %d is needed for output, and will be resumed\n", i );
            bq_resume( 0, bq );
            being_rebuilt[i] = 1;
         }
         else {
            PRINTdbg( "block %d is unneeded, and will be skipped\n", i );
            bq_resume( -1, bq ); // otherwise, use a special offset value of -1 to tell the thread to error itself out
            being_rebuilt[i] = 0;
         }
         // Note: For write threads, adjusting this offset is misleading, as it refers to a queue buffer offset rather than 
         // one of a file.  However, as resume_threads() should be clearing out the write queue before removing the HALT flag,
         // this offset needs to be reset to zero regardless.  As we know this should always be zero, we can use a negative 
         // value to overload the meaning.
      }

// ---------------------- REPAIR DAMAGED BLOCKS ----------------------

      off_t bytes_repaired = 0; // keep track of how much of the file has successfully been repaired
      char err_out = 0; // use this flag to indicate a hard failure condition

      // this loop will actually perform the data movement
      while ( bytes_repaired < totsz ) {
         size_t bytes_to_copy = ( ( (buff_size+bytes_repaired) > totsz ) ? ( totsz - bytes_repaired ) : buff_size );
         // read the bytes from the original file
         PRINTdbg( "reading %zd bytes from original file\n", bytes_to_copy );
         if ( ne_read( read_handle, data_buff, bytes_to_copy, bytes_repaired ) != bytes_to_copy ) {
            PRINTerr( "ne_rebuild: failed to read %zd bytes at offset %zd from the original stripe\n", bytes_to_copy, bytes_repaired );
            err_out = 1;
            break;
         }
         // then write it fresh out to the repaired blocks
         PRINTdbg( "writing %zd bytes to the rebulding blocks\n", bytes_to_copy );
         if ( ne_write( write_handle, data_buff, bytes_to_copy ) != bytes_to_copy ) {
            PRINTerr( "ne_rebuild: failed to write %zd bytes at offset %zd to the repaired blocks\n", bytes_to_copy, bytes_repaired );
            err_out = 1;
            break;
         }
         bytes_repaired += bytes_to_copy;
      }
      iterations++; // note that we have read the original again

// ---------------------- CHECK FAILURE/SUCCESS CONDITIONS ----------------------

      // Any read/write errors should cause us to fail.
      if ( err_out )
         break;

      // loop through all blocks in the read handle, checking for new errors
      all_rebuilt = 1;
      for ( i = 0; i < (N + E); i++ ) {
         if ( ( erasure_state_read->manifest_status[i] || erasure_state_read->data_status[i] )  &&  !(being_rebuilt[i]) ) {
            all_rebuilt = 0; // any error which we have not yet rebuilt will require a re-run
            PRINTdbg( "new error in block %d will require a re-read\n", i );
         }
      }

// ---------------------- END MAIN LOOP AND CLEANUP ----------------------

   }

   PRINTdbg( "exited rebuild loop after %d iterations\n", iterations );

   free( data_buff );
   ne_close( read_handle );
   if ( !(all_rebuilt) ) { // error conditions should have left this at zero
      PRINTdbg( "aborting all write threads due to rebuild error\n" );
      // we need to make sure that our 'repaired' blocks are never used
      signal_threads( BQ_ABORT, write_handle, N+E, 0 );
      ne_close( write_handle ); // don't care about the return here
      return -1;
   }

   // finalize our rebuilt blocks
   return ne_close(write_handle); // the error pattern returned by ne_close() should now indicate the state of the stripe
}


int ne_rebuild1( SnprintfFunc fn, void* state,
                 uDALType itype, SktAuth auth,
                 TimingFlagsValue timing_flags, TimingData* timing_data,
                 char* path, ne_mode mode, ... ) {

   int ret; 
   va_list vl;
   va_start(vl, mode);
   ret = ne_rebuild1_vl(fn, state, itype, auth, timing_flags, timing_data, path, mode, vl); 
   va_end(vl);
   return ret; 
}


int ne_rebuild( char *path, ne_mode mode, ... ) {
   int ret;

   // this is safe for builds with/without sockets enabled
   // and with/without socket-authentication enabled
   // However, if you do build with socket-authentication, this will require a read
   // from a file (~/.awsAuth) that should probably only be accessible if ~ is /root.
   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("failed to initialize default socket-authentication credentials\n");
      return -1;
   }

   va_list   vl;
   va_start(vl, mode);
   ret = ne_rebuild1_vl(ne_default_snprintf, NULL, UDAL_POSIX, auth, 0, NULL, path, mode, vl);
   va_end(vl);

   return ret;
}



#ifndef HAVE_LIBISAL
// This replicates the function defined in libisal.  If we define it here,
// and do static linking with libisal, the linker will complain.

void ec_init_tables(int k, int rows, unsigned char *a, unsigned char *g_tbls)
{
        int i, j;

        for (i = 0; i < rows; i++) {
                for (j = 0; j < k; j++) {
                        gf_vect_mul_init(*a++, g_tbls);
                        g_tbls += 32;
                }
        }
}
#endif

// Generate decode matrix from encode matrix
static int gf_gen_decode_matrix(unsigned char *encode_matrix,
                                unsigned char *decode_matrix,
                                unsigned char *invert_matrix,
                                unsigned int *decode_index,
                                unsigned char *src_err_list,
                                unsigned char *src_in_err,
                                int nerrs, int nsrcerrs, int k, int m)
{
        int i, j, p;
        int r;
        unsigned char *backup, *b, s;
        int incr = 0;

        b = malloc(MAXPARTS * MAXPARTS);
        backup = malloc(MAXPARTS * MAXPARTS);

        if (b == NULL || backup == NULL) {
           PRINTerr("gf_gen_decode_matrix: failure of malloc\n");
           free(b);
           free(backup);
           errno = ENOMEM;
           return -1;
        }
        // Construct matrix b by removing error rows
        for (i = 0, r = 0; i < k; i++, r++) {
                while (src_in_err[r])
                        r++;
                for (j = 0; j < k; j++) {
                        b[k * i + j] = encode_matrix[k * r + j];
                        backup[k * i + j] = encode_matrix[k * r + j];
                }
                decode_index[i] = r;
        }
        incr = 0;
        while (gf_invert_matrix(b, invert_matrix, k) < 0) {
                if (nerrs == (m - k)) {
                        free(b);
                        free(backup);
                        PRINTerr("gf_gen_decode_matrix: BAD MATRIX\n");
                        return NO_INVERT_MATRIX;
                }
                incr++;
                memcpy(b, backup, MAXPARTS * MAXPARTS);
                for (i = nsrcerrs; i < nerrs - nsrcerrs; i++) {
                        if (src_err_list[i] == (decode_index[k - 1] + incr)) {
                                // skip the erased parity line
                                incr++;
                                continue;
                        }
                }
                if (decode_index[k - 1] + incr >= m) {
                        free(b);
                        free(backup);
                        PRINTerr("gf_gen_decode_matrix: BAD MATRIX\n");
                        return NO_INVERT_MATRIX;
                }
                decode_index[k - 1] += incr;
                for (j = 0; j < k; j++)
                        b[k * (k - 1) + j] = encode_matrix[k * decode_index[k - 1] + j];

        };

        if (b == NULL || backup == NULL) {
           PRINTerr("gf_gen_decode_matrix: failure of malloc\n");
           free(b);
           free(backup);
           errno = ENOMEM;
           return -1;
        }
        // Construct matrix b by removing error rows
        for (i = 0, r = 0; i < k; i++, r++) {
                while (src_in_err[r])
                        r++;
                for (j = 0; j < k; j++) {
                        b[k * i + j] = encode_matrix[k * r + j];
                        backup[k * i + j] = encode_matrix[k * r + j];
                }
                decode_index[i] = r;
        }
        incr = 0;
        while (gf_invert_matrix(b, invert_matrix, k) < 0) {
                if (nerrs == (m - k)) {
                        free(b);
                        free(backup);
                        PRINTerr("gf_gen_decode_matrix: BAD MATRIX\n");
                        return NO_INVERT_MATRIX;
                }
                incr++;
                memcpy(b, backup, MAXPARTS * MAXPARTS);
                for (i = nsrcerrs; i < nerrs - nsrcerrs; i++) {
                        if (src_err_list[i] == (decode_index[k - 1] + incr)) {
                                // skip the erased parity line
                                incr++;
                                continue;
                        }
                }
                if (decode_index[k - 1] + incr >= m) {
                        free(b);
                        free(backup);
                        PRINTerr("gf_gen_decode_matrix: BAD MATRIX\n");
                        return NO_INVERT_MATRIX;
                }
                decode_index[k - 1] += incr;
                for (j = 0; j < k; j++)
                        b[k * (k - 1) + j] = encode_matrix[k * decode_index[k - 1] + j];

        };

        for (i = 0; i < nsrcerrs; i++) {
                for (j = 0; j < k; j++) {
                        decode_matrix[k * i + j] = invert_matrix[k * src_err_list[i] + j];
                }
        }
        /* src_err_list from encode_matrix * invert of b for parity decoding */
        for (p = nsrcerrs; p < nerrs; p++) {
                for (i = 0; i < k; i++) {
                        s = 0;
                        for (j = 0; j < k; j++)
                                s ^= gf_mul(invert_matrix[j * k + i],
                                            encode_matrix[k * src_err_list[p] + j]);

                        decode_matrix[k * p + i] = s;
                }
        }
        free(b);
        free(backup);
        return 0;
}


/**
 * Performs a rebuild operation on the erasure striping indicated by the given handle, but ignores faulty xattr values.
 * @param ne_handle handle : The handle for the erasure striping to be repaired
 * @return int : Status code.  Success is indicated by 0 and failure by -1
 */
//int ne_noxattr_rebuild(ne_handle handle) {
//   while ( handle->erasure_state->nerr > 0 ) {
//      handle->erasure_state->nerr--;
//      handle->erasure_state->src_in_err[handle->src_err_list[handle->erasure_state->nerr]] = 0;
//      handle->src_err_list[handle->erasure_state->nerr] = 0;
//   }
//   return ne_rebuild( handle ); 
//}


int ne_stat1( SnprintfFunc fn, void* state,
                    uDALType itype, SktAuth auth,
                    TimingFlagsValue timing_flags, TimingData* timing_data,
                    char *path, e_status e_state_struct ) {
   memset( e_state_struct, 0, sizeof( struct ne_stat_struct ) );
   ne_handle handle = create_handle( fn, state, itype, auth, timing_flags, timing_data, path, NE_STAT, e_state_struct );
   if ( handle == NULL )
      return -1;

   int i;
   int consensus = MIN_MD_CONSENSUS;
   int num_blocks = consensus;
   char error = 0; // for indicating an error condition

   struct read_meta_buffer_struct read_meta_state; //needed to determine metadata consensus of read threadss
   int threads_checked = 0; // count of how many threads have already been verified

   // We need to dynamically determine the N, E, O, and bsz values.
   // This requires spinning up threads, one at a time, and checking their meta info for consistency.
   // Thus, we initialize num_blocks to a 'consensus' value and then reset to something more reasonable once 
   // we have a good idea of N/E.

   /* open files and initialize BufferQueues */
   for(i = 0; i < num_blocks; i++) {
      BufferQueue *bq = &handle->blocks[i];
      handle->snprintf(bq->path, MAXNAME, handle->path_fmt, (i + handle->erasure_state->O) % num_blocks, handle->printf_state);

      PRINTdbg( "starting up thread for block %d\n", i );
    
      if(bq_init(bq, i, handle) < 0) {
         PRINTerr("bq_init failed for block %d\n", i);
         error = 1; // to trigger cleanup below
         break;
      }
      // note that read threads will be initialized in a halted state

      if ( pthread_create(&handle->threads[i], NULL, bq_reader, (void *)bq) ) {
         PRINTerr("failed to start thread %d\n", i);
         error = 1; // to trigger cleanup below
         break;
      }

      if ( handle->erasure_state->N == 0 ) {
         PRINTdbg("Checking for error opening block %d\n", i);

         if ( pthread_mutex_lock( &bq->qlock ) ) {
            PRINTerr( "failed to aquire queue lock for thread %d\n", i );
            error = 1; // to trigger cleanup below
            break;
         }

         // wait for the queue to be ready.
         while( !( bq->state_flags & BQ_OPEN ) ) // wait for the thread to open its file
            pthread_cond_wait( &bq->master_resume, &bq->qlock );
         pthread_mutex_unlock( &bq->qlock ); // just waiting for open to complete, don't need to hold this longer

         threads_checked++;

         // if we have all the threads needed for determining N/E
         if ( (i+1) >= consensus ) {

            PRINTdbg( "attempting to determine N/E values after starting %d threads\n", i+1 );

            // find the most common values from amongst all meta information
            int matches = check_matches( handle->blocks, i+1, &(read_meta_state) );

            // special case, if we have still failed to produce sensible N/E values
            if ( matches < 1 ) {
               // if we are still within our bounds, just keep extending the stripe, trying to find *something*
               if ( num_blocks < MAXPARTS )
                  num_blocks++;
               else
                  error = 1; // to trigger cleanup below
               continue;
            }

            // we have N/E values, so use them to determine a new consensus
            consensus = ( read_meta_state.E ) ? ( read_meta_state.E + 1 ) : ( read_meta_state.N );
            PRINTdbg( "set consensus to %d after retrieving new N/E values (have %d matches)\n", consensus, matches );
            // if we have sufficient matches for consensus, assign them to our handle
            if ( matches >= consensus ) {
               PRINTdbg( "setting N/E to %d/%d after reaching consensus of %d\n", read_meta_state.N, read_meta_state.E, matches );
               handle->erasure_state->N = read_meta_state.N;
               handle->erasure_state->E = read_meta_state.E;
            }
            num_blocks = read_meta_state.N + read_meta_state.E;
         }
      }
   }

   int threads_running = i;

   // check for errors on open...
   // We finish checking thread status down here in order to give them a bit more time to spin up.
   for(i = threads_checked; i < num_blocks; i++) {

      BufferQueue *bq = &handle->blocks[i];

      PRINTdbg("Checking for error opening block %d\n", i);

      if ( pthread_mutex_lock( &bq->qlock ) ) {
         PRINTerr( "failed to aquire queue lock for thread %d\n", i );
         error = 1; // to trigger cleanup below
         break;
      }

      // wait for the queue to be ready.
      while( !( bq->state_flags & BQ_OPEN ) ) // wait for the thread to open its file
         pthread_cond_wait( &bq->master_resume, &bq->qlock );
      pthread_mutex_unlock( &bq->qlock ); // just waiting for open to complete, don't need to hold this longer

   }


   // find the most common values from amongst all meta information, now that all threads have started
   // we have to do this here, in case we don't have a bsz value
   int matches = check_matches( handle->blocks, num_blocks, &(read_meta_state) );
   handle->erasure_state->O = read_meta_state.O;
   handle->erasure_state->bsz = read_meta_state.bsz;
   handle->erasure_state->nsz = read_meta_state.nsz;
   handle->erasure_state->totsz = read_meta_state.totsz;
   // Note: ncompsz and crcsum are set by the thread itself
   for ( i = 0; i < num_blocks; i++ ) {
      // take this opportunity to mark all mismatched meta values as incorrect
      read_meta_buffer read_buf = (read_meta_buffer)handle->blocks[i].buffers[0];
      if ( read_buf->N != handle->erasure_state->N  ||  read_buf->E != handle->erasure_state->E  ||  read_buf->O != handle->erasure_state->O  ||  
           read_buf->bsz != handle->erasure_state->bsz  ||  read_buf->nsz != handle->erasure_state->nsz  ||  
           read_buf->totsz != handle->erasure_state->totsz )
         handle->erasure_state->manifest_status[i] = 1;
      // free our read_meta_buff structs
      free( read_buf ); 
   }

   terminate_threads( BQ_FINISHED, handle, threads_running, 0 );
   free( handle->path_fmt );
   free( handle );
   if ( error )
      return -1;
   return 0;

}



int ne_stat( char* path, e_status erasure_status_struct ) {
   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("failed to initialize default socket-authentication credentials\n");
      return -1;
   }

   return ne_stat1( ne_default_snprintf, NULL, UDAL_POSIX, auth, 0, NULL, path, erasure_status_struct );
}



// ---------------------------------------------------------------------------
// per-block functions
//
// These functions operate on a single block-file.  They are called both
// from (a) administrative applications which run on the server-side, and
// (b) from client-side applications (like the MarFS run-time).  With the
// advent of the uDAL, the second case requires wrapping in
// uDAL-implementation-sensitive code.  See comments above
// ne_delete_block() for details.
// ---------------------------------------------------------------------------




int ne_set_xattr1(const uDAL* impl, SktAuth auth,
                  const char *path, const char *xattrval, size_t len) {
   int ret = -1;

   // see comments above OPEN() defn
   GenericFD      fd   = {0};
   struct handle  hndl = {0};
   ne_handle      handle = &hndl;

   handle->impl = impl;
   handle->auth = auth;
   if (! handle->impl) {
      PRINTerr( "ne_set_xattr1: implementation is NULL\n");
      errno = EINVAL;
      return -1;
   }


#ifdef META_FILES
   char meta_file[2048];
   strcpy( meta_file, path );
   strncat( meta_file, META_SFX, strlen(META_SFX) + 1 );

   // cannot set umask here as this is called within threads
   OPEN( fd, handle->auth, handle->impl, meta_file, O_WRONLY | O_CREAT, 0666 );

   if (FD_ERR(fd)) {
      PRINTerr( "ne_close: failed to open file %s\n", meta_file);
      ret = -1;
   }
   else {
      // int val = HNDLOP( write, fd, xattrval, strlen(xattrval) + 1 );
      int val = write_all(&fd, xattrval, strlen(xattrval) + 1 );
      if ( val != strlen(xattrval) + 1 ) {
         PRINTerr( "ne_close: failed to write to file %s\n", meta_file);
         ret = -1;
         HNDLOP(close, fd);
      }
      else {
         ret = HNDLOP(close, fd);
      }
   }

   // PATHOP(chown, handle->impl, handle->auth, meta_file, handle->owner, handle->group);

#else
   // looks like the stuff below might conceivably work with threads.
   // The problem is that fgetxattr/fsetxattr are not yet implemented.
#   error "xattr metadata is not functional with new thread model"

   OPEN( fd, handle->auth, handle->impl, path, O_RDONLY );
   if (FD_ERR(fd)) { 
      PRINTerr("ne_set_xattr: failed to open file %s\n", path);
      ret = -1;
   }
   else {

#   if (AXATTR_SET_FUNC == 5) // XXX: not functional with threads!!!
      ret = HNDLOP(fsetxattr, fd, XATTRKEY, xattrval, strlen(xattrval), 0);
#   else
      ret = HNDLOP(fsetxattr, fd, XATTRKEY, xattrval, strlen(xattrval), 0, 0);
#   endif
   }

   if (HNDLOP(close, fd) < 0) {
      PRINTerr("ne_set_xattr: failed to close file %s\n", path);
      ret = -1;
   }
#endif //META_FILES

   return ret;
}

int ne_set_xattr( const char *path, const char *xattrval, size_t len) {

   // this is safe for builds with/without sockets enabled
   // and with/without socket-authentication enabled
   // However, if you do build with socket-authentication, this will require a read
   // from a file (~/.awsAuth) that should probably only be accessible if ~ is /root.
   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("failed to initialize default socket-authentication credentials\n");
      return -1;
   }

   return ne_set_xattr1(get_impl(UDAL_POSIX), auth, path, xattrval, len);
}



int ne_get_xattr1( const uDAL* impl, SktAuth auth,
                   const char *path, char *xattrval, size_t len) {
   int ret = 0;

   // see comments above OPEN() defn
   GenericFD      fd   = {0};
   struct handle  hndl = {0};
   ne_handle      handle = &hndl;

   handle->impl = impl;
   handle->auth = auth;
   if (! handle->impl) {
      PRINTerr( "ne_get_xattr1: implementation is NULL\n" );
      errno = EINVAL;
      return -1;
   }


#ifdef META_FILES
   char meta_file_path[2048];
   strncpy(meta_file_path, path, 2048);
   strncat(meta_file_path, META_SFX, strlen(META_SFX)+1);

   OPEN( fd, handle->auth, handle->impl, meta_file_path, O_RDONLY );
   if (FD_ERR(fd)) {
      ret = -1;
      PRINTerr("ne_get_xattr: failed to open file %s\n", meta_file_path);
   }
   else {
      // ssize_t size = HNDLOP( read, fd, xattrval, len );
      ssize_t size = read_all(&fd, xattrval, len);
      if ( size < 0 ) {
         PRINTerr("ne_get_xattr: failed to read from file %s\n", meta_file_path);
         ret = -1;
      }
      else if(size == 0) {
         PRINTerr( "ne_get_xattr: read 0 bytes from metadata file %s\n", meta_file_path);
         ret = -1;
      }
      else if (size == len) {
         // This might mean that the read truncated results to fit into our buffer.
         // Caller should give us a buffer that has more-than-enough room.
         PRINTerr( "ne_get_xattr: read %d bytes from metadata file %s\n", size, meta_file_path);
         ret = -1;
      }

      if (HNDLOP(close, fd) < 0) {
         PRINTerr("ne_get_xattr: failed to close file %s\n", meta_file_path);
         ret = -1;
      }
      if (! ret)
         ret = size;
   }

#else
   // looks like the stuff below might conceivably work with threads.
#   error "xattr metadata is not functional with new thread model"

   OPEN( fd, handle->auth, handle->impl, path, O_RDONLY );
   if (FD_ERR(fd)) { 
      PRINTerr("ne_get_xattr: failed to open file %s\n", path);
      ret = -1;
   }
   else {

#   if (AXATTR_GET_FUNC == 4)
      ret = HNDLOP(fgetxattr, fd, XATTRKEY, &xattrval[0], len);
#   else
      ret = HNDLOP(fgetxattr, fd, XATTRKEY, &xattrval[0], len, 0, 0);
#   endif
   }

   if (HNDLOP(close, fd) < 0) {
      PRINTerr("ne_get_xattr: failed to close file %s\n", meta_file_path);
      ret = -1;
   }
#endif

   return ret;
}

int ne_get_xattr( const char *path, char *xattrval, size_t len) {

   // this is safe for builds with/without sockets enabled
   // and with/without socket-authentication enabled
   // However, if you do build with socket-authentication, this will require a read
   // from a file (~/.awsAuth) that should probably only be accessible if ~ is /root.
   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("failed to initialize default socket-authentication credentials\n");
      return -1;
   }

   return ne_get_xattr1(get_impl(UDAL_POSIX), auth, path, xattrval, len);
}

static int set_block_xattr(ne_handle handle, int block) {
  int tmp = 0;
  TimingData* timing = handle->timing_data_ptr;

  char xattrval[1024];
  sprintf(xattrval,"%d %d %d %d %lu %lu %llu %llu",
          handle->erasure_state->N, handle->erasure_state->E, handle->erasure_state->O,
          handle->erasure_state->bsz, handle->erasure_state->nsz,
          handle->erasure_state->ncompsz[block], (unsigned long long)handle->erasure_state->csum[block],
          (unsigned long long)handle->erasure_state->totsz);

  PRINTdbg( "ne_close: setting file %d xattr = \"%s\"\n",
            block, xattrval );

  char block_file_path[2048];
  handle->snprintf(block_file_path, MAXNAME, handle->path_fmt,
                   (block+handle->erasure_state->O)%(handle->erasure_state->N + handle->erasure_state->E),
                   handle->printf_state);

   if ( handle->mode == NE_REBUILD )
      strncat( block_file_path, REBUILD_SFX, strlen(REBUILD_SFX)+1 );
   else if ( handle->mode == NE_WRONLY )
      strncat( block_file_path, WRITE_SFX, strlen(WRITE_SFX)+1 );
   

   if (timing->flags & TF_XATTR)
      fast_timer_start(&timing->stats[block].xattr);

   int rc = ne_set_xattr1(handle->impl, handle->auth, block_file_path, xattrval, strlen(xattrval));

   if (timing->flags & TF_XATTR)
      fast_timer_stop(&timing->stats[block].xattr);

   return rc;
}


// unlink a single block (including the manifest file, if
// META_FILES is defined).  This is called from:
//
// (a) a commented-out function in the mc_ring.c MarFS utility ('ch'
//     branch), where I think it would represent a fully-specified
//     block-file on the server-side.  From the server-side, UDAL_POSIX
//     will always work with such paths.
//
// (b) ne_delete1(), where it refers to a fully-specified block-file, but
//     from the client-side.  Therefore, it may potentially need to go
//     through a MarFS RDMA server, so it must acquire uDAL dressing, to
//     allow selection of the appropriate uDAL implementation.


int ne_delete_block1(const uDAL* impl, SktAuth auth, const char *path) {

   int ret = PATHOP(unlink, impl, auth, path);

#ifdef META_FILES
   if(ret == 0) {
      char meta_path[2048];
      strncpy(meta_path, path, 2048);
      strcat(meta_path, META_SFX);

      ret = PATHOP(unlink, impl, auth, meta_path);
   }
#endif

   return ret;
}

int ne_delete_block(const char *path) {

   // this is safe for builds with/without sockets enabled
   // and with/without socket-authentication enabled
   // However, if you do build with socket-authentication, this will require a read
   // from a file (~/.awsAuth) that should probably only be accessible if ~ is /root.
   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("failed to initialize default socket-authentication credentials\n");
      return -1;
   }

   return ne_delete_block1(get_impl(UDAL_POSIX), auth, path);
}




/**
 * Make a symlink to an existing block.
 */
int ne_link_block1(const uDAL* impl, SktAuth auth,
                   const char *link_path, const char *target) {

   struct stat target_stat;
   int         ret;


#ifdef META_FILES
   char meta_path[2048];
   char meta_path_target[2048];

   strcpy(meta_path, link_path);
   strcat(meta_path, META_SFX);

   strcpy(meta_path_target, target);
   strcat(meta_path_target, META_SFX);
#endif // META_FILES

   // stat the target.
   if (PATHOP(stat, impl, auth, target, &target_stat) == -1) {
      return -1;
   }

   // if it is a symlink, then move it,
   if(S_ISLNK(target_stat.st_mode)) {
      // check that the meta file has a symlink here too, If not then
      // abort without doing anything. If it does, then proceed with
      // making symlinks.
      if(PATHOP(stat, impl, auth, meta_path_target, &target_stat) == -1) {
         return -1;
      }
      if(!S_ISLNK(target_stat.st_mode)) {
         return -1;
      }
      char   tp[2048];
      char   tp_meta[2048];
      size_t link_size;
      if((link_size = PATHOP(readlink, impl, auth, target, tp, 2048)) != -1) {
         tp[link_size] = '\0';
      }
      else {
         return -1;
      }
#ifdef META_FILES
      if((link_size = PATHOP(readlink, impl, auth, meta_path_target, tp_meta, 2048)) != -1) {
         tp_meta[link_size] = '\0';
      }
      else {
         return -1;
      }
#endif

      // make the new links.
      ret = PATHOP(symlink, impl, auth, tp, link_path);
#ifdef META_FILES
      if(ret == 0)
         ret = PATHOP(symlink, impl, auth, tp_meta, meta_path);
#endif

      // remove the old links.
      ret = PATHOP(unlink, impl, auth, target);
#ifdef META_FILES
      if(ret == 0)
         PATHOP(unlink, impl, auth, meta_path_target);
#endif
      return ret;
   }

   // if not, then create the link.
   ret = PATHOP(symlink, impl, auth, target, link_path);
#ifdef META_FILES
   if(ret == 0)
      ret = PATHOP(symlink, impl, auth, meta_path_target, meta_path);
#endif
   return ret;
}


int ne_link_block(const char *link_path, const char *target) {

   // this is safe for builds with/without sockets enabled
   // and with/without socket-authentication enabled
   // However, if you do build with socket-authentication, this will require a read
   // from a file (~/.awsAuth) that should probably only be accessible if ~ is /root.
   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("failed to initialize default socket-authentication credentials\n");
      return -1;
   }

   return ne_link_block1(get_impl(UDAL_POSIX), auth, link_path, target);
}
