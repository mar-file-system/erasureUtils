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

int xattr_check( ne_handle handle, char *path );
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
#define FD_ERR(GFD)                         (GFD).hndl->impl->fd_err(&(GFD))
#define FD_NUM(GFD)                         (GFD).hndl->impl->fd_num(&(GFD))

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
#define OPEN(GFD, HANDLE, ...)              do { (GFD).hndl = (HANDLE); \
                                                 (HANDLE)->impl->open(&(GFD), ## __VA_ARGS__); } while(0)

#define pHNDLOP(OP, GFDp, ...)              (GFDp)->hndl->impl->OP((GFDp), ## __VA_ARGS__)
#define HNDLOP(OP, GFD, ...)                (GFD).hndl->impl->OP(&(GFD), ## __VA_ARGS__)

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



// check for an incomplete write of an object
int incomplete_write( ne_handle handle ) {
   char fname[MAXNAME];
   int i;
   int err_cnt = 0;

   for( i = 0; i < handle->erasure_state->nerr; i++ ) {
      int block = handle->src_err_list[i];
      handle->snprintf( fname, MAXNAME, handle->erasure_state->path_fmt,
                        (handle->erasure_state->start + block) % ( (handle->erasure_state->N) ? (handle->erasure_state->N + handle->erasure_state->E) : MAXPARTS ),
                        handle->printf_state);
      strcat( fname, WRITE_SFX );
      

      if (handle->timing_flags & TF_STAT)
         fast_timer_start(&handle->stats[block].stat);

      // check for a partial data-file
      struct stat st;
      if( stat( fname, &st ) == 0 ) {

         if (handle->timing_flags & TF_STAT)
            fast_timer_stop(&handle->stats[block].stat);

         return 1;
      }

      //check for a partial meta-file
      strcat( fname, META_SFX );
      if( stat( fname, &st ) == 0 ) {

         if (handle->timing_flags & TF_STAT)
            fast_timer_stop(&handle->stats[block].stat);

         return 1;
      }

      err_cnt++;                // ?

      if (handle->timing_flags & TF_STAT)
         fast_timer_stop(&handle->stats[block].stat);
   }

   return 0;
}


void bq_destroy(BufferQueue *bq) {
  // XXX: Should technically check these for errors (ie. still locked)
  pthread_mutex_destroy(&bq->qlock);
  pthread_cond_destroy(&bq->have_work);
  pthread_cond_destroy(&bq->have_space);
}

int bq_init(BufferQueue *bq, int block_number, void **buffers, ne_handle handle) {
  int i;
  for(i = 0; i < MAX_QDEPTH; i++) {
    bq->buffers[i] = buffers[i];
  }

  bq->block_number = block_number;
  bq->qdepth       = 0;
  bq->head         = 0;
  bq->tail         = 0;
  bq->flags        = 0;
  bq->csum         = 0;
  bq->buffer_size  = handle->erasure_state->bsz;
  bq->handle       = handle;
  bq->offset       = 0;

  FD_INIT(bq->file, handle);

  if(pthread_mutex_init(&bq->qlock, NULL)) {
    PRINTerr("failed to initialize mutex for qlock\n");
    return -1;
  }
  if(pthread_cond_init(&bq->have_work, NULL)) {
    PRINTerr("failed to initialize cv for have_work\n");
    // should also destroy the mutex
    pthread_mutex_destroy(&bq->qlock);
    return -1;
  }
  if(pthread_cond_init(&bq->have_space, NULL)) {
    PRINTerr("failed to initialize cv for have_space\n");
    pthread_mutex_destroy(&bq->qlock);
    pthread_cond_destroy(&bq->have_work);
    return -1;
  }

  return 0;
}

void bq_signal(BufferQueue*bq, BufferQueue_Flags sig) {
  pthread_mutex_lock(&bq->qlock);
  PRINTdbg("signalling 0x%x to block %d\n", (uint32_t)sig, bq->block_number);
  bq->flags |= sig;
  pthread_cond_signal(&bq->have_work);
  pthread_mutex_unlock(&bq->qlock);  
}

void bq_close(BufferQueue *bq) {
  bq_signal(bq, BQ_FINISHED);
}

void bq_abort(BufferQueue *bq) {
  bq_signal(bq, BQ_ABORT);
}


void bq_writer_finis(void* arg) {
  BufferQueue *bq = (BufferQueue *)arg;
  PRINTdbg("exiting thread for block %d, in %s\n", bq->block_number, bq->path);
}


void *bq_writer(void *arg) {
  BufferQueue *bq      = (BufferQueue *)arg;
  ne_handle    handle  = bq->handle;
  size_t       written = 0;
  int          error;

#ifdef INT_CRC
  const int write_size = bq->buffer_size + sizeof(u32);
#else
  const int write_size = bq->buffer_size;
#endif

  if (handle->timing_flags & TF_THREAD)
     fast_timer_start(&handle->stats[bq->block_number].thread);
  if (handle->timing_flags & TF_OPEN)
     fast_timer_start(&handle->stats[bq->block_number].open);
  
  // debugging, assure we see thread entry/exit, even via cancellation
  PRINTdbg("entering thread for block %d, in %s\n", bq->block_number, bq->path);
  pthread_cleanup_push(bq_writer_finis, bq);

  // open the file.
  OPEN(bq->file, handle, bq->path, O_WRONLY|O_CREAT, 0666);

  if(pthread_mutex_lock(&bq->qlock) != 0) {
    PRINTerr("failed to lock queue lock: %s\n", strerror(error));
    // this is a FATAL error
    if (handle->timing_flags & TF_THREAD)
       fast_timer_stop(&handle->stats[bq->block_number].thread);
    // set error, so that initialize_queues() will know to mark this block bad
    // outside of critical section, but should be fine as flags aren't shared
    bq->flags |= BQ_ERROR;
    return NULL;
    //exit(-1); // is this the appropriate response??
  }
  if(FD_ERR(bq->file)) {
    bq->flags |= BQ_ERROR;
  }
  else {
    // note the file as having been successfully opened
    // this will allow initialize_queues() to complete and ne_open to reset umask
    bq->flags |= BQ_OPEN;
  }
  pthread_cond_signal(&bq->have_space);
  pthread_mutex_unlock(&bq->qlock);

  PRINTdbg("opened file %d\n", bq->block_number);
  if (handle->timing_flags & TF_OPEN)
  {
     fast_timer_stop(&handle->stats[bq->block_number].open);
     log_histo_add_interval(&handle->stats[bq->block_number].open_h,
                                &handle->stats[bq->block_number].open);
  }
  if (handle->timing_flags & TF_RW)
     fast_timer_start(&handle->stats[bq->block_number].read);

  
  while(1) {

    // wait for FULL condition
    if((error = pthread_mutex_lock(&bq->qlock)) != 0) {
      PRINTerr("failed to lock queue lock: %s\n", strerror(error));
      // This is a FATAL error
      if (handle->timing_flags & TF_THREAD)
         fast_timer_stop(&handle->stats[bq->block_number].thread);
      // note the error, just in case
      bq->flags |= BQ_ERROR;
      return NULL;
    }
    while(bq->qdepth == 0 && !((bq->flags & BQ_FINISHED) || (bq->flags & BQ_ABORT))) {
      PRINTdbg("bq_writer[%d]: waiting for signal from ne_write\n", bq->block_number);
      pthread_cond_wait(&bq->have_work, &bq->qlock);
    }

    if (handle->timing_flags & TF_RW) {
       fast_timer_stop(&handle->stats[bq->block_number].read);
       log_histo_add_interval(&handle->stats[bq->block_number].read_h,
                              &handle->stats[bq->block_number].read);
    }

    // check for flags that might tell us to quit
    if(bq->flags & BQ_ABORT) {
      PRINTerr("aborting buffer queue\n");
      if (handle->timing_flags & TF_CLOSE)
         fast_timer_start(&handle->stats[bq->block_number].close);

      if(HNDLOP(close, bq->file) == 0) {
         PATHOP(unlink, handle->impl, handle->auth, bq->path); // try to clean up after ourselves.
      }
      pthread_mutex_unlock(&bq->qlock);

      if (handle->timing_flags & TF_CLOSE)
      {
         fast_timer_stop(&handle->stats[bq->block_number].close);
         log_histo_add_interval(&handle->stats[bq->block_number].close_h,
                                &handle->stats[bq->block_number].close);
      }
      // though it shouldn't matter, make sure no one thinks we finished properly
      bq->flags |= BQ_ERROR;
      return NULL;
    }

    if((bq->qdepth == 0) && (bq->flags & BQ_FINISHED)) {       // then we are done.
      // // TBD: ?
      // PRINTerr("closing buffer queue\n");
      // HNDLOP(close, bq->file);
      // pthread_mutex_unlock(&bq->qlock);

      PRINTdbg("BQ finished\n");
      break;
    }


    if(!(bq->flags & BQ_ERROR)) {

      if (handle->timing_flags & TF_RW)
         fast_timer_start(&handle->stats[bq->block_number].write);

      pthread_mutex_unlock(&bq->qlock);

// removing this since the newer NFS clients are better behaved
/*
      if(written >= SYNC_SIZE) {
         if ( HNDLOP(fsync, bq->file) )
            bq->flags |= BQ_ERROR;
         written = 0;
      }

      PRINTdbg("Writing block %d\n", bq->block_number);
*/

      *(u32*)( bq->buffers[bq->head] + bq->buffer_size )   = crc32_ieee(TEST_SEED, bq->buffers[bq->head], bq->buffer_size);
      error     = write_all(&bq->file, bq->buffers[bq->head], write_size);
      bq->csum += *(u32*)( bq->buffers[bq->head] + bq->buffer_size );
      pthread_mutex_lock(&bq->qlock);

      PRINTdbg("write done for block %d\n", bq->block_number);
      if (handle->timing_flags & TF_RW) {
         fast_timer_stop(&handle->stats[bq->block_number].write);
         log_histo_add_interval(&handle->stats[bq->block_number].write_h,
                                &handle->stats[bq->block_number].write);
      }

    }
    else { // there were previous errors. skipping the write
      error = write_size;
    }

    if(error < write_size) {
      bq->flags |= BQ_ERROR;
    }
    else {
      written += error;
    }

    // even if there was an error, say we wrote the block and move on.
    // the producer thread is responsible for checking the error flag
    // and killing us if needed.
    if (handle->timing_flags & TF_RW)
       fast_timer_start(&handle->stats[bq->block_number].read);

    bq->head = (bq->head + 1) % MAX_QDEPTH;
    bq->qdepth--;

    pthread_cond_signal(&bq->have_space);
    pthread_mutex_unlock(&bq->qlock);
  }
  pthread_mutex_unlock(&bq->qlock);


  // close the file and terminate if any errors were encountered
  if (handle->timing_flags & TF_CLOSE)
     fast_timer_start(&handle->stats[bq->block_number].close);
  int close_rc = HNDLOP(close, bq->file);
  if (handle->timing_flags & TF_CLOSE)
  {
     fast_timer_stop(&handle->stats[bq->block_number].close);
     log_histo_add_interval(&handle->stats[bq->block_number].close_h,
                                &handle->stats[bq->block_number].close);
  }
  if ( close_rc || (bq->flags & BQ_ERROR) ) {
    bq->flags |= BQ_ERROR;      // ensure the error was noted
    PRINTerr("error closing block %d\n", bq->block_number);
    if (handle->timing_flags & TF_THREAD)
       fast_timer_stop(&handle->stats[bq->block_number].thread);
    return NULL; // don't bother trying to rename
  }

  handle->csum[bq->block_number] = bq->csum;
  if(set_block_xattr(bq->handle, bq->block_number) != 0) {
    bq->flags |= BQ_ERROR;
    // if we failed to set the xattr, don't bother with the rename.
    PRINTerr("error setting xattr for block %d\n", bq->block_number);
    if (handle->timing_flags & TF_THREAD)
       fast_timer_stop(&handle->stats[bq->block_number].thread);
    return NULL;
  }


  // rename
  if (handle->timing_flags & TF_RENAME)
     fast_timer_start(&handle->stats[bq->block_number].rename);

  char block_file_path[MAXNAME];
  //  sprintf( block_file_path, handle->erasure_state->path_fmt,
  //           (bq->block_number+handle->erasure_state->start)%(handle->erasure_state->N+handle->erasure_state->E) );
  handle->snprintf( block_file_path, MAXNAME, handle->erasure_state->path_fmt,
                    (bq->block_number+handle->erasure_state->start)%(handle->erasure_state->N+handle->erasure_state->E), handle->printf_state );

  PRINTdbg("bq_writer: renaming old:  %s\n", bq->path );
  PRINTdbg("                    new:  %s\n", block_file_path );
  if( PATHOP( rename, handle->impl, handle->auth, bq->path, block_file_path ) != 0 ) {
    PRINTerr("bq_writer: rename failed: %s\n", strerror(errno) );
    bq->flags |= BQ_ERROR;
  }

#ifdef META_FILES
  // rename the META file too
  strncat( bq->path, META_SFX, strlen(META_SFX)+1 );
  strncat( block_file_path, META_SFX, strlen(META_SFX)+1 );

  PRINTdbg("bq_writer: renaming meta old:  %s\n", bq->path );
  PRINTdbg("                         new:  %s\n", block_file_path );
  if ( PATHOP( rename, handle->impl, handle->auth, bq->path, block_file_path ) != 0 ) {
     PRINTerr("bq_writer: rename failed: %s\n", strerror(errno) );
     bq->flags |= BQ_ERROR;
  }
#endif

  if (handle->timing_flags & TF_RENAME)
     fast_timer_stop(&handle->stats[bq->block_number].rename);
  if (handle->timing_flags & TF_THREAD)
     fast_timer_stop(&handle->stats[bq->block_number].thread);

  pthread_cleanup_pop(1);
  return NULL;
}

/**
 * Initialize the buffer queues for the handle and start the threads.
 *
 * @return -1 on failure, 0 on success.
 */
static int initialize_queues(ne_handle handle) {
  int i;
  int num_blocks = handle->erasure_state->N + handle->erasure_state->E;

  /* allocate buffers */
  for(i = 0; i < MAX_QDEPTH; i++) {
    int error = posix_memalign(&handle->buffer_list[i], 64,
                               num_blocks * ( handle->erasure_state->bsz + sizeof( u32 ) ) );
    if(error == -1) {
      int j;
      // clean up previously allocated buffers and fail.
      // we can't recover from this error.
      for(j = i-1; j >= 0; j--) {
         free(handle->buffer_list[j]);
      }
      PRINTerr("posix_memalign failed for queue %d\n", i);
      return -1;
    }
  }

  /* open files and initialize BufferQueues */
  for(i = 0; i < num_blocks; i++) {
    int error, file_descriptor;
    char path[MAXNAME];
    BufferQueue *bq = &handle->blocks[i];
    // generate the path
    // sprintf(bq->path, handle->erasure_state->path_fmt, (i + handle->erasure_state->start) % num_blocks);
    handle->snprintf(bq->path, MAXNAME, handle->erasure_state->path_fmt, (i + handle->erasure_state->start) % num_blocks, handle->printf_state);

    strcat(bq->path, WRITE_SFX);

    // assign pointers into the memaligned buffers.
    void *buffers[MAX_QDEPTH];
    int j;
    for(j = 0; j < MAX_QDEPTH; j++) {
      buffers[j] = handle->buffer_list[j] + ( i * ( handle->erasure_state->bsz + sizeof( u32 ) ) );
    }
    
    if(bq_init(bq, i, buffers, handle) < 0) {
      // TODO: handle error.
      PRINTerr("bq_init failed for block %d\n", i);
      return -1;
    }

    // start the threads
    error = pthread_create(&handle->threads[i], NULL, bq_writer, (void *)bq);
    if(error != 0) {
      PRINTerr("failed to start thread %d\n", i);
      return -1;
      // TODO: clean up!!
    }
  }

  /* create the buff_list in the handle. */
  for(i = 0; i < MAX_QDEPTH; i++) {
    int j;
    for(j = 0; j < num_blocks; j++) {
      handle->block_buffs[i][j] = handle->buffer_list[i] + ( j * ( handle->erasure_state->bsz + sizeof( u32 ) ) );
    }
  }

  // check for errors on open...
  for(i = 0; i < num_blocks; i++) {
    PRINTdbg("Checking for error opening block %d\n", i);

    BufferQueue *bq = &handle->blocks[i];
    pthread_mutex_lock(&bq->qlock);

    // wait for the queue to be ready.
    while(!(bq->flags & BQ_OPEN) && !(bq->flags & BQ_ERROR))
      pthread_cond_wait(&bq->have_space, &bq->qlock);

    if(bq->flags & BQ_ERROR) {
      PRINTerr("open failed for block %d\n", i);
      handle->erasure_state->src_in_err[i] = 1;
      handle->src_err_list[handle->erasure_state->nerr] = i;
      handle->erasure_state->nerr++;
    }
    pthread_mutex_unlock(&bq->qlock);
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
    pthread_cond_wait(&bq->have_space, &bq->qlock);

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
    PRINTdbg("saved incomplete buffer for block %d\n", bq->block_number);
    bq->offset += size;
  }
  else {
    bq->offset = 0;
    bq->qdepth++;
    bq->tail = (bq->tail + 1) % MAX_QDEPTH;
    if(bq->flags & BQ_ERROR) {
      ret = 1;
    }
    PRINTdbg("queued complete buffer for block %d\n", bq->block_number);
    pthread_cond_signal(&bq->have_work);
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



/**
 * Opens a new handle for a specific erasure striping
 *
 * ne_open(path, mode, ...)  calls this with fn=ne_default_snprintf, and printf_state=NULL
 *
 * @param SnprintfFunc : function takes block-number and <printf_state> and produces per-block path from template.
 * @param printf_state : optional printf_state to be used by SnprintfFunc (e.g. configuration details)
 * @param cred : optional credentials (actually AWSContext*) to authenticate socket connections (e.g. RDMA)
 * @param char* path : sprintf format-template for individual files of in each stripe.
 * @param ne_mode mode : Mode in which the file is to be opened.  Either NE_RDONLY, NE_WRONLY, or NE_REBUILD.
 * @param int erasure_offset : Offset of the erasure stripe, defining the name of the first N file
 * @param int N : Data width of the striping
 * @param int E : Erasure width of the striping
 *
 * @return ne_handle : The new handle for the opened erasure striping
 */


ne_handle ne_open1_vl( SnprintfFunc fn, void* printf_state,
                       uDALType itype, SktAuth auth, TimingFlagsValue timing_flags,
                       char *path, ne_mode mode, va_list ap )
{
   char file[MAXNAME];       /* array name of files */
   int counter;
   int ret;
   int N = 0;
   int E = 0;
   int erasure_offset = 0;
#ifdef INT_CRC
   int crccount;
#endif
   int bsz = BLKSZ;

   counter = 3;
   if ( mode & NE_SETBSZ ) {
      counter++;
      mode -= NE_SETBSZ;
      PRINTdbg( "ne_open: NE_SETBSZ flag detected\n");
   }
   if ( mode & NE_NOINFO ) {
      counter -= 3;
      mode -= NE_NOINFO;
      PRINTdbg( "ne_open: NE_NOINFO flag detected\n");
   }

   // Parse variadic arguments
   if ( counter == 1 ) {
      bsz = va_arg( ap, int );
   }
   else if ( counter > 1 ){
      erasure_offset = va_arg( ap, int );
      N = va_arg( ap, int );
      E = va_arg( ap, int );
      if ( counter == 4 ){
         bsz = va_arg( ap, int );
      }
   }

   if ( mode == NE_WRONLY  &&  counter < 2 ) {
      PRINTerr( "ne_open: recieved an invalid \"NE_NOINFO\" flag for \"NE_WRONLY\" operation\n");
      errno = EINVAL;
      return NULL;
   }

#ifdef INT_CRC
   //shrink data size to fit crc within block
   bsz -= sizeof( u32 );
#endif

   if ( counter > 1 ) {
      if ( N < 1  ||  N > MAXN ) {
         PRINTerr( "ne_open: improper N arguement received - %d\n", N);
         errno = EINVAL;
         return NULL;
      }
      if ( E < 0  ||  E > MAXE ) {
         PRINTerr( "ne_open: improper E arguement received - %d\n", E);
         errno = EINVAL;
         return NULL;
      }
      if ( erasure_offset < 0  ||  erasure_offset >= N+E ) {
         PRINTerr( "ne_open: improper erasure_offset arguement received - %d\n", erasure_offset);
         errno = EINVAL;
         return NULL;
      }
   }
   if ( bsz < 0  ||  bsz > MAXBLKSZ ) {
      PRINTerr( "ne_open: improper bsz argument received - %d\n", bsz );
      errno = EINVAL;
      return NULL;
   }

   ne_handle handle = malloc( sizeof( struct handle ) );
   memset(handle, 0, sizeof(struct handle));

   handle->erasure_state = malloc( sizeof( struct ne_stat_struct ) );
   memset( handle->erasure_state, 0, sizeof( struct ne_stat_struct ) );

   /* initialize any non-zero handle members */
   handle->erasure_state->N = N;
   handle->erasure_state->E = E;
   handle->erasure_state->bsz = bsz;
   handle->erasure_state->start = erasure_offset;

   if ( counter < 2 ) {
      handle->mode = NE_STAT;
      PRINTdbg( "ne_open: temporarily setting mode to NE_STAT\n");
   }
   else {
      handle->mode = mode;
   }

   handle->snprintf = fn;
   handle->printf_state    = printf_state;
   handle->auth     = auth;
   handle->impl     = get_impl(itype);

   if (! handle->impl) {
      PRINTerr( "ne_open: couldn't find implementation for itype %d\n", itype );
      errno = EINVAL;
      return NULL;
   }

   // flags control collection of timing stats
   handle->timing_flags = timing_flags;
   if (handle->timing_flags) {
      fast_timer_inits();

      // // redundant with memset() on handle
      // init_bench_stats(&handle->agg_stats);
   }
   if (handle->timing_flags & TF_HANDLE)
      fast_timer_start(&handle->handle_timer); /* start overall timer for handle */

   char* nfile = malloc( strlen(path) + 1 );
   strncpy( nfile, path, strlen(path) + 1 );
   handle->erasure_state->path_fmt = nfile;

   if ( mode == NE_REBUILD  ||  mode == NE_RDONLY ) {
      ret = xattr_check(handle, path); // identify total data size of stripe
      if ((ret == 0) && (handle->mode == NE_STAT)) {
         PRINTdbg( "ne_open: resetting mode to %d\n", mode);
         handle->mode = mode;
         while ( handle->erasure_state->nerr > 0 ) {
            handle->erasure_state->nerr--;
            handle->erasure_state->src_in_err[handle->src_err_list[handle->erasure_state->nerr]] = 0;
            handle->src_err_list[handle->erasure_state->nerr] = 0;
         }
         ret = xattr_check(handle,path); //perform the check again, identifying mismatched values
      }
      PRINTdbg("ne_open: Post xattr_check() -- NERR = %d, N = %d, E = %d, Start = %d, TotSz = %llu\n",
               handle->erasure_state->nerr, handle->erasure_state->N, handle->erasure_state->E, handle->erasure_state->start, handle->erasure_state->totsz );

      if ( ret != 0 ) {
         if( incomplete_write( handle ) ) {
            errno = ENOENT;
            return NULL;
         }
         PRINTerr( "ne_open: extended attribute check has failed\n" );
         free( handle->erasure_state );
         free( handle );
         errno = ENODATA;
         return NULL;
      }

   }
   else if ( mode != NE_WRONLY ) { //reject improper mode arguments
      PRINTerr( "improper mode argument received - %d\n", mode );
      errno = EINVAL;
      free( handle->erasure_state );
      free( handle );
      return NULL;
   }

   N = handle->erasure_state->N;
   E = handle->erasure_state->E;
   bsz = handle->erasure_state->bsz;
   erasure_offset = handle->erasure_state->start;
   PRINTdbg( "ne_open: using stripe values (N=%d,E=%d,bsz=%d,offset=%d)\n", N,E,bsz,erasure_offset);

   if(handle->mode == NE_WRONLY) { // first cut: mutlti-threading only for writes.
     // umask is process-wide, so we have to manipulate it outside of the threads
     mode_t mask = umask(0000);
     if(initialize_queues(handle) < 0) {
       // all destruction/cleanup should be handled in initialize_queues()
       free( handle->erasure_state );
       free(handle);
       errno = ENOMEM;
       return NULL;
     }
     umask(mask);
     if( UNSAFE(handle) ) {
       int i;
       for(i = 0; i < handle->erasure_state->N + handle->erasure_state->E; i++) {
         bq_abort(&handle->blocks[i]);
         // just detach and let the OS clean up. We don't care about the return any more.
         pthread_detach(handle->threads[i]);
       }
     }
   }

   else { // for non-writes, initialize the buffers in the old way.

   /* allocate a big buffer for all the N chunks plus a bit extra for reading in crcs */
#ifdef INT_CRC
     crccount = 1;
     if ( E > 0 )
        crccount = E;

     ret = posix_memalign( &(handle->buffer), 64, ((N+E)*bsz) + (sizeof(u32)*crccount) ); //add space for intermediate checksum
     PRINTdbg("ne_open: Allocated handle buffer of size %zd for bsz=%d, N=%d, E=%d\n",
              ((N+E)*bsz) + (sizeof(u32)*crccount), bsz, N, E);
#else
     ret = posix_memalign( &(handle->buffer), 64, ((N+E)*bsz) );
     PRINTdbg("ne_open: Allocated handle buffer of size %zd for bsz=%d, N=%d, E=%d\n",
              (N+E)*bsz, bsz, N, E);
#endif

     if ( ret != 0 ) {
       PRINTerr( "ne_open: failed to allocate handle buffer\n" );
       errno = ENOMEM;
       return NULL;
     }

     /* loop through and open up all the output files and initilize per part info and allocate buffers */
     counter = 0;
     PRINTdbg( "opening file descriptors...\n" );
     mode_t mask = umask(0000);
     while ( counter < N+E ) {

       if (handle->timing_flags & TF_OPEN)
           fast_timer_start(&handle->stats[counter].open);

       bzero( file, MAXNAME );
       u32 blk_i = (counter+erasure_offset)%(N+E); // absolute index of block to be written, within pod
       handle->snprintf(file, MAXNAME, path, blk_i, handle->printf_state);
       
#ifdef INT_CRC
       if ( counter > N ) {
         crccount = counter - N;
         handle->buffs[counter] = handle->buffer + ( counter*bsz ) + ( crccount * sizeof(u32) ); //make space for block and erasure crc
       }
       else {
         handle->buffs[counter] = handle->buffer + ( counter*bsz ); //make space for block
       }
#else
       handle->buffs[counter] = handle->buffer + ( counter*bsz ); //make space for block
#endif


      if( mode == NE_WRONLY ) {
         PRINTdbg( "   opening %s%s for write\n", file, WRITE_SFX );
         OPEN(handle->FDArray[counter], handle,
              strncat( file, WRITE_SFX, strlen(WRITE_SFX)+1 ), O_WRONLY | O_CREAT, 0666 );
      }
//      else if ( mode == NE_REBUILD  &&  handle->erasure_state->src_in_err[counter] == 1 ) {
//         PRINTdbg( "   opening %s%s for write\n", file, REBUILD_SFX );
//         OPEN(handle->FDArray[counter], handle,
//              strncat( file, REBUILD_SFX, strlen(REBUILD_SFX)+1 ), O_WRONLY | O_CREAT, 0666 );
//      }
      else {
         PRINTdbg( "   opening %s for read\n", file );
         OPEN(handle->FDArray[counter], handle, file, O_RDONLY );
      }

      if (handle->timing_flags & TF_OPEN)
      {
         fast_timer_stop(&handle->stats[counter].open);
         log_histo_add_interval(&handle->stats[counter].open_h,
                                &handle->stats[counter].open);
      }
      if ( FD_ERR(handle->FDArray[counter])  &&  handle->erasure_state->src_in_err[counter] == 0 ) {
         PRINTerr( "   failed to open file %s! '%s'\n", file, strerror(errno) );

         handle->src_err_list[handle->erasure_state->nerr] = counter;
         handle->erasure_state->nerr++;
         handle->erasure_state->src_in_err[counter] = 1;
         if ( handle->erasure_state->nerr > E ) { //if errors are unrecoverable, terminate
           errno = ENODATA;
           return NULL;
         }
         if ( mode != NE_REBUILD ) { counter++; }
         
         continue;
       }
      
       counter++;
     }
     umask(mask);
   }

   /* allocate matrices */
   handle->encode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->decode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->invert_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->g_tbls = malloc(MAXPARTS * MAXPARTS * 32);

   return handle;

}

// caller (e.g. MC-sockets DAL) specifies SprintfFunc, stat, and SktAuth
// New: caller also provides flags that control whether stats are collected
ne_handle ne_open1( SnprintfFunc fn, void* printf_state,
                    uDALType itype, SktAuth auth, TimingFlagsValue timing_flags,
                    char *path, ne_mode mode, ... ) {

   ne_handle ret;
   va_list vl;
   va_start(vl, mode);
   ret = ne_open1_vl(fn, printf_state, itype, auth, timing_flags, path, mode, vl);
   va_end(vl);
   return ret;
}


// provide defaults for SprintfFunc, printf_state, and SktAuth
// so naive callers can continue to work (in some cases).
ne_handle ne_open( char *path, ne_mode mode, ... ) {
   ne_handle ret;

   // this is safe for builds with/without sockets enabled
   // and with/without socket-authentication enabled
   // However, if you do build with socket-authentication, this will require a read
   // from a file (~/.awsAuth) that should probably only be accessible if ~ is /root.
   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("failed to initialize default socket-authentication credentials\n");
      return NULL;
   }

   va_list   vl;
   va_start(vl, mode);
   ret = ne_open1_vl(ne_default_snprintf, NULL, UDAL_POSIX, auth, 0, path, mode, vl);
   va_end(vl);

   return ret;
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

/**
 * Reads nbytes of data at offset from the erasure striping referenced by the given handle
 * @param ne_handle handle : Handle referencing the desired erasure striping
 * @param void* buffer : Memory location in which to store the retrieved data
 * @param int nbytes : Integer number of bytes to be read
 * @param off_t offset : Offset within the data at which to begin the read
 * @return int : The number of bytes read or -1 on a failure
 */
ssize_t ne_read( ne_handle handle, void *buffer, size_t nbytes, off_t offset ) 
{
   int mtot = (handle->erasure_state->N)+(handle->erasure_state->E);
   int minNerr = handle->erasure_state->N+1;  // greater than N
   int maxNerr = -1;   // less than N
   int nsrcerr = 0;
   int counter;
   char firststripe;
   char firstchunk;
   char error_in_stripe;
   unsigned char *temp_buffs[ MAXPARTS ];
   int            temp_buffs_alloc = 0;
   int N = handle->erasure_state->N;
   int E = handle->erasure_state->E;
   unsigned int bsz = handle->erasure_state->bsz;
   int nerr = 0;
   unsigned long datasz[ MAXPARTS ] = {0};
   ssize_t ret_in;
   int tmp;
   unsigned int decode_index[ MAXPARTS ];
   u32 llcounter;
   u32 readsize;
   u32 startoffset;
   u32 startpart;
   u32 startstripe;
   u32 tmpoffset;
   u32 tmpchunk;
   u32 endchunk;
#ifdef INT_CRC
   u32 crc;
#endif
   ssize_t out_off;
   off_t seekamt;

   
   if (nbytes > UINT_MAX) {
     PRINTerr( "ne_read: not yet validated for write-sizes above %lu\n", UINT_MAX);
     errno = EFBIG;             /* sort of */
     return -1;
   }

   if ( handle->mode != NE_RDONLY ) {
      PRINTerr( "ne_read: handle is in improper mode for reading!\n" );
      errno = EPERM;
      return -1;
   }

   if ( (offset + nbytes) > handle->erasure_state->totsz ) {
      PRINTdbg("ne_read: read would extend beyond EOF, resizing read request...\n");
      nbytes = handle->erasure_state->totsz - offset;
      if ( nbytes <= 0 ) {
         PRINTerr( "ne_read: offset is beyond filesize\n" );
         // return -1;             /* pread() would just return 0 in this case */
         return 0;             /* EOF */
      }
   }

   llcounter = 0;
   tmpoffset = 0;

   //check stripe cache
   if ( (offset >= handle->buff_offset)
        &&  (offset < (handle->buff_offset + handle->buff_rem)) ) {
      seekamt = offset - handle->buff_offset;
      readsize = ( nbytes > (handle->buff_rem - seekamt) ) ? (handle->buff_rem - seekamt) : nbytes;
      PRINTdbg( "ne_read: filling request for first %lu bytes from cache with offset %zd in buffer...\n",
                (unsigned long) readsize, seekamt );
      memcpy( buffer, handle->buffer + seekamt, readsize );
      llcounter += readsize;
   }

   //if entire request was cached, nothing remains to be done
   if ( llcounter == nbytes )
      return llcounter;


   //determine min/max errors and allocate temporary buffers
   for ( counter = 0; counter < mtot; counter++ ) {
      if ( handle->erasure_state->src_in_err[counter] ) {
         nerr++;
         if ( counter < N ) { 
            nsrcerr++;
            if ( counter > maxNerr ) { maxNerr = counter; }
            if ( counter < minNerr ) { minNerr = counter; }
         }
      }
   }

   if ( handle->erasure_state->nerr != nerr ) {
      PRINTerr( "ne_read: iconsistent internal state : handle->erasure_state->nerr and handle->erasure_state->src_in_err\n" );
      errno = ENOTRECOVERABLE;
      return -1;
   }


   /******** Rebuild While Reading ********/
read:

   startstripe = (offset+llcounter) / (bsz*N);
   startpart = (offset + llcounter - ((off_t)startstripe*bsz*N))/bsz;
   startoffset = offset+llcounter - (startstripe*bsz*N) - (startpart*bsz);

   PRINTdbg("ne_read: read with rebuild from startstripe %d startpart %d and startoffset %d for nbytes %d\n",
           startstripe, startpart, startoffset, nbytes);

   counter = 0;

   endchunk = ((offset+nbytes) - (startstripe*N*bsz) ) / bsz;
   int stop = endchunk;

   if ( endchunk > N ) {
      endchunk = N;
      stop = mtot - 1;
   }     

   /**** set seek positions for initial reading ****/
   //if not reading from corrupted chunks, we can just set these normally
   if (startpart > maxNerr  ||  endchunk < minNerr ) {

      for ( counter = 0; counter <= stop; counter++ ) {

#ifdef INT_CRC
         seekamt = startstripe * ( bsz+sizeof(u32) ); 
         if (counter < startpart) {
            seekamt += ( bsz+sizeof(u32) ); 
         }
#else
         seekamt = (startstripe*bsz);
         if (counter < startpart) {
            seekamt += bsz;
         }
         else if (counter == startpart) {
            seekamt += startoffset; 
         }
#endif

         if (handle->timing_flags & TF_RW)
            fast_timer_start(&handle->stats[counter].read);

         if( handle->erasure_state->src_in_err[counter] == 0 ) {
            if ( counter >= N ) {
#ifdef INT_CRC
               seekamt += ( bsz+sizeof(u32) );
#else
               seekamt += bsz;
#endif

               PRINTdbg("seeking erasure file e%d to %zd, as we will be reading from the next stripe\n",counter-N, seekamt);
            }
            else {
               PRINTdbg("seeking input file %d to %zd, as there is no error in this stripe\n",counter, seekamt);
            }


            tmp = HNDLOP(lseek, handle->FDArray[counter], seekamt, SEEK_SET);

            //if we hit an error here, seek positions are wrong and we must restart
            if ( tmp != seekamt ) {
               if ( counter > maxNerr )  maxNerr = counter;
               if ( counter < minNerr )  minNerr = counter;
               handle->erasure_state->src_in_err[counter] = 1;
               handle->src_err_list[handle->erasure_state->nerr] = counter;
               handle->erasure_state->nerr++;
               nsrcerr++;
               handle->e_ready = 0; //indicate that erasure structs require re-initialization

               if (handle->timing_flags & TF_RW) {
                  fast_timer_stop(&handle->stats[counter].read);
                  log_histo_add_interval(&handle->stats[counter].read_h,
                                         &handle->stats[counter].read);
               }

               goto read; //if another error is encountered, start over
            }
         }

         if (handle->timing_flags & TF_RW) {
            fast_timer_stop(&handle->stats[counter].read);
            log_histo_add_interval(&handle->stats[counter].read_h,
                                   &handle->stats[counter].read);
         }
      }
      //temporary addition to allow for the constant reading of erasure parts
      for ( counter = N; counter < mtot; counter++ ) {
         tmp = 0;
         if ( handle->erasure_state->src_in_err[ counter ] == 0 ) {
#ifdef INT_CRC
            tmp = HNDLOP(lseek, handle->FDArray[counter], (startstripe*( bsz+sizeof(u32) )), SEEK_SET);
#else
            tmp = HNDLOP(lseek, handle->FDArray[counter], (startstripe*bsz), SEEK_SET);
#endif
         }
         //note any errors, no need to restart though
         if ( tmp < 0 ) {
            handle->erasure_state->src_in_err[counter] = 1;
            handle->src_err_list[handle->erasure_state->nerr] = counter;
            handle->erasure_state->nerr++;
            nsrcerr++;
            handle->e_ready = 0; //indicate that erasure structs require re-initialization
         }
      }
      tmpchunk = startpart;
      tmpoffset = startoffset;
      error_in_stripe = 0;
   }


   else {  //if not, we will require the entire stripe for rebuild

      PRINTdbg("startpart = %d, endchunk = %d\n   This stripe contains corrupted blocks...\n", startpart, endchunk);
      while (counter < mtot) {

         if( handle->erasure_state->src_in_err[counter] == 0 ) {

            if (handle->timing_flags & TF_RW)
               fast_timer_start(&handle->stats[counter].read);

#ifdef INT_CRC
            tmp = HNDLOP(lseek, handle->FDArray[counter], (startstripe*( bsz+sizeof(u32) )), SEEK_SET);
#else
            tmp = HNDLOP(lseek, handle->FDArray[counter], (startstripe*bsz), SEEK_SET);
#endif

            //note any errors, no need to restart though
            if ( tmp < 0 ) {
               if ( counter > maxNerr )  maxNerr = counter;
               if ( counter < minNerr )  minNerr = counter;
               handle->erasure_state->src_in_err[counter] = 1;
               handle->src_err_list[handle->erasure_state->nerr] = counter;
               handle->erasure_state->nerr++;
               nsrcerr++;
               handle->e_ready = 0; //indicate that erasure structs require re-initialization
               counter++;

               if (handle->timing_flags & TF_RW) {
                  fast_timer_stop(&handle->stats[counter].read);
                  log_histo_add_interval(&handle->stats[counter].read_h,
                                         &handle->stats[counter].read);
               }
               continue;
            }
#ifdef INT_CRC
            PRINTdbg("seek input file %d to %lu, to read entire stripe\n",counter, (unsigned long)(startstripe*( bsz+sizeof(u32) )));
#else
            PRINTdbg("seek input file %d to %lu, to read entire stripe\n",counter, (unsigned long)(startstripe*bsz));
#endif

            if (handle->timing_flags & TF_RW) {
               fast_timer_stop(&handle->stats[counter].read);
               log_histo_add_interval(&handle->stats[counter].read_h,
                                      &handle->stats[counter].read);
            }
         }

         counter++;
      }

      tmpchunk = 0;
      tmpoffset = 0;
      error_in_stripe = 1;
      //handle->e_ready = 0; //test


      // temp_buffs[] will be needed for regeneration
      for ( counter = 0; counter < mtot; counter++ ) {
         tmp = posix_memalign((void **)&(temp_buffs[counter]),64,bsz);
         if ( tmp != 0 ) {
            PRINTerr( "ne_read: failed to allocate temporary data buffer\n" );
            errno = tmp;
            return -1;
         }
      }
      temp_buffs_alloc = mtot;
   }


   firstchunk = 1;
   firststripe = 1;
   out_off = llcounter;

   /**** output each data stipe, regenerating as necessary ****/
   while ( llcounter < nbytes ) {

      if( handle->erasure_state->nerr > handle->erasure_state->E ) {
         PRINTerr("ne_read: errors exceed erasure limits\n");
         errno=ENODATA;
         return llcounter;
      }

      handle->buff_offset = (offset+llcounter);
      handle->buff_rem = 0;

      for ( counter = 0; counter < N; counter++ ) {
         datasz[counter] = 0;
      }

      endchunk = ((long)(offset+nbytes) - (long)( (offset + llcounter) - ((offset+llcounter)%(N*bsz)) ) ) / bsz;

      PRINTdbg( "ne_read: endchunk unadjusted - %d\n", endchunk );
      if ( endchunk >= N ) {
         endchunk = N - 1;
      }

      PRINTdbg("ne_read: endchunk adjusted - %d\n", endchunk);
      if ( endchunk < minNerr ) {
         PRINTdbg( "ne_read: there is no error in this stripe\n");
         error_in_stripe = 0;
      }

      /**** read data into buffers ****/
      for( counter=tmpchunk; counter < N; counter++ ) {

         if ( llcounter == nbytes  &&  error_in_stripe == 0 ) {
            PRINTdbg( "ne_read: data reads complete\n");
            break;
         }

         if (handle->timing_flags & TF_RW)
            fast_timer_start(&handle->stats[counter].read);

         readsize = bsz-tmpoffset;

         if ( handle->erasure_state->src_in_err[counter] == 1 ) {  //this data chunk is invalid
            PRINTdbg("ne_read: ignoring data for faulty chunk %d\n",counter);
            if ( firstchunk == 0 ) {
               llcounter += readsize;

               if ( llcounter < nbytes ) {
                  datasz[counter] = readsize;
               }
               else {
                  datasz[counter] = nbytes - (llcounter - readsize);
                  llcounter=nbytes;
               }
            }
            else if ( counter == startpart ) {
               llcounter += (( readsize - (startoffset - tmpoffset) < (nbytes - llcounter) )
                             ? readsize - (startoffset - tmpoffset)
                             : (nbytes - llcounter));
               datasz[counter] = llcounter - out_off;
               firstchunk = 0;
            }
            // ensure that the stripe is flagged as having an error.
            error_in_stripe = 1;

            if (handle->timing_flags & TF_RW) {
               fast_timer_stop(&handle->stats[counter].read);
               log_histo_add_interval(&handle->stats[counter].read_h,
                                      &handle->stats[counter].read);
            }
         }

         else {    //this data chunk is valid, store it

            if ( (nbytes-llcounter) < readsize  &&  error_in_stripe == 0 )
               readsize = nbytes-llcounter;

#ifdef INT_CRC
            PRINTdbg("ne_read: read %lu from datafile %d\n", bsz+sizeof(crc), counter);
            // ret_in = HNDLOP(read, handle->FDArray[counter], handle->buffs[counter], bsz+sizeof(crc));
            ret_in = read_all(&handle->FDArray[counter], handle->buffs[counter], bsz+sizeof(crc));
            ret_in -= (sizeof(u32)+tmpoffset);
#else
            PRINTdbg("ne_read: read %d from datafile %d\n", readsize, counter);
            // ret_in = HNDLOP(read, handle->FDArray[counter], handle->buffs[counter], readsize);
            ret_in = read_all(&handle->FDArray[counter], handle->buffs[counter], readsize);
#endif
            if (handle->timing_flags & TF_RW) {
               fast_timer_stop(&handle->stats[counter].read);
               log_histo_add_interval(&handle->stats[counter].read_h,
                                      &handle->stats[counter].read);
            }

            //check for a read error
            if ( ret_in < readsize ) {

               PRINTerr( "ne_read: error encountered while reading data file %d "
                         "(expected %d but received %d)\n",
                         counter, readsize, ret_in);
               if ( counter > maxNerr )  maxNerr = counter;
               if ( counter < minNerr )  minNerr = counter;
               handle->erasure_state->src_in_err[counter] = 1;
               handle->src_err_list[handle->erasure_state->nerr] = counter;
               handle->erasure_state->nerr++;
               nsrcerr++;
               handle->e_ready = 0; //indicate that erasure structs require re-initialization
               ret_in = 0;
               counter--;

               //if this is the first encountered error for the stripe, we must start over
               if ( error_in_stripe == 0 ) {
                  for( tmp = counter; tmp >=0; tmp-- ) {
                     llcounter -= datasz[tmp];
                  }
                  PRINTdbg( "ne_read: restarting stripe read, reset total read to %lu\n", (unsigned long)llcounter);
                  goto read;
               }

               continue;
            }


#ifdef INT_CRC
            else {
               //calculate and verify crc
               if (handle->timing_flags & TF_CRC)
                  fast_timer_start(&handle->stats[counter].crc);

               crc = crc32_ieee( TEST_SEED, handle->buffs[counter], bsz );
               int cmp = memcmp( handle->buffs[counter]+bsz, &crc, sizeof(u32) );

               if (handle->timing_flags & TF_CRC) {
                  fast_timer_stop(&handle->stats[counter].crc);
                  log_histo_add_interval(&handle->stats[counter].crc_h,
                                         &handle->stats[counter].crc);
               }

               if ( cmp != 0 ){
                  PRINTerr( "ne_read: mismatch of int-crc for file %d while reading with rebuild\n", counter);
                  if ( counter > maxNerr )  maxNerr = counter;
                  if ( counter < minNerr )  minNerr = counter;
                  handle->erasure_state->src_in_err[counter] = 1;
                  handle->src_err_list[handle->erasure_state->nerr] = counter;
                  handle->erasure_state->nerr++;
                  nsrcerr++;
                  handle->e_ready = 0; //indicate that erasure structs require re-initialization
                  counter--;
                  ret_in = 0;
                  //if this is the first encountered error for the stripe, we must start over
                  if ( error_in_stripe == 0 ) {
                     for( tmp = counter; tmp >=0; tmp-- ) {
                        llcounter -= datasz[tmp];
                     }
                     PRINTdbg( "ne_read: restarting stripe read, reset total read to %lu\n", (unsigned long)llcounter);
                     goto read;
                  }
                  continue;
               }
            }
#endif

            if ( firstchunk == 0 ) {
               llcounter += ret_in;
               if ( llcounter < nbytes ) {
                  datasz[counter] = ret_in;
               }
               else {
                  datasz[counter] = nbytes - (llcounter - ret_in);
                  llcounter = nbytes;
               }
            }
            else if ( counter == startpart ) {
               llcounter += (ret_in - (startoffset-tmpoffset) < (nbytes-llcounter) ) ? ret_in-(startoffset-tmpoffset) : (nbytes-llcounter);
               datasz[counter] = llcounter - out_off;
               firstchunk = 0;
            }

         }

         tmpoffset = 0;

      } //completion of read from stripe



      //notice, we only need the erasure stripes if we hit an error
      counter = N;
      while ( counter < mtot ) { //&&  error_in_stripe == 1 ) {

#ifdef INT_CRC
         readsize = bsz+sizeof(u32);
#else
         readsize = bsz; //may want to limit later
#endif

         if ( handle->erasure_state->src_in_err[counter] == 0 ) {

            PRINTdbg("ne_read: reading %d from erasure %d\n",readsize,counter);
            if (handle->timing_flags & TF_RW)
               fast_timer_start(&handle->stats[counter].read);

            // ret_in = HNDLOP(read, handle->FDArray[counter], handle->buffs[counter], readsize);
            ret_in = read_all(&handle->FDArray[counter], handle->buffs[counter], readsize);

            if (handle->timing_flags & TF_RW) {
               fast_timer_stop(&handle->stats[counter].read);
               log_histo_add_interval(&handle->stats[counter].read_h,
                                      &handle->stats[counter].read);
            }

            if ( ret_in < readsize ) {
               if ( ret_in < 0 ) {
                  ret_in = 0;
               }

               handle->erasure_state->src_in_err[counter] = 1;
               handle->src_err_list[handle->erasure_state->nerr] = counter;
               handle->erasure_state->nerr++;
               handle->e_ready = 0; //indicate that erasure structs require re-initialization

              // error_in_stripe = 1;
               PRINTerr("ne_read: failed to read all erasure data in file %d\n", counter);
               PRINTerr("ne_read: zeroing data for faulty erasure %d from %lu to %d\n",counter,ret_in,bsz);
               bzero(handle->buffs[counter]+ret_in,bsz-ret_in);

               PRINTdbg("ne_read: zeroing temp_data for faulty erasure %d\n",counter);
               bzero(temp_buffs[counter],bsz);

               PRINTdbg("ne_read: done zeroing %d\n",counter);
            }
#ifdef INT_CRC
            else {
               //calculate and verify crc
               if (handle->timing_flags & TF_CRC)
                  fast_timer_start(&handle->stats[counter].crc);

               crc = crc32_ieee( TEST_SEED, handle->buffs[counter], bsz );
               int cmp = memcmp( handle->buffs[counter]+bsz, &crc, sizeof(u32) );

               if (handle->timing_flags & TF_CRC) {
                  fast_timer_stop(&handle->stats[counter].crc);
                  log_histo_add_interval(&handle->stats[counter].crc_h,
                                         &handle->stats[counter].crc);
               }

               if ( cmp != 0 ){
                  PRINTerr("ne_read: mismatch of int-crc for file %d (erasure)\n", counter);
                  if ( counter > maxNerr )  maxNerr = counter;
                  if ( counter < minNerr )  minNerr = counter;
                  handle->erasure_state->src_in_err[counter] = 1;
                  handle->src_err_list[handle->erasure_state->nerr] = counter;
                  handle->erasure_state->nerr++;
                  nsrcerr++;
                  handle->e_ready = 0; //indicate that erasure structs require re-initialization
                  //error_in_stripe = 1;
               }
            }
#endif
         }
         else {
            PRINTdbg( "ne_read: ignoring data for faulty erasure %d\n", counter );
         }
         counter++;
      }

      /**** regenerate from erasure ****/
      if ( error_in_stripe == 1 ) {

         if (handle->timing_flags & TF_ERASURE)
            fast_timer_start(&handle->erasure_timer);

         /* If necessary, initialize the erasure structures */
         if ( handle->e_ready == 0 ) {
            // Generate encode matrix encode_matrix
            // The matrix generated by gf_gen_rs_matrix
            // is not always invertable.
            PRINTdbg("ne_read: initializing erasure structs...\n");
            gf_gen_rs_matrix(handle->encode_matrix, mtot, N);

            // Generate g_tbls from encode matrix encode_matrix
            ec_init_tables(N, E, &(handle->encode_matrix[N * N]), handle->g_tbls);

            ret_in = gf_gen_decode_matrix( handle->encode_matrix, handle->decode_matrix,
                  handle->invert_matrix, decode_index, handle->src_err_list, handle->erasure_state->src_in_err,
                  handle->erasure_state->nerr, nsrcerr, N, mtot);

            if (ret_in != 0) {
               PRINTerr("ne_read: failure to generate decode matrix, errors may exceed erasure limits\n");
               errno=ENODATA;

               for ( counter = 0; counter < temp_buffs_alloc; counter++ )
                  free(temp_buffs[counter]);

               if (handle->timing_flags & TF_ERASURE) {
                  fast_timer_stop(&handle->erasure_timer);
                  log_histo_add_interval(&handle->erasure_h,
                                         &handle->erasure_timer);
               }
               return -1;
            }

            for (tmp = 0; tmp < N; tmp++) {
               handle->recov[tmp] = handle->buffs[decode_index[tmp]];
            }

            PRINTdbg( "ne_read: init erasure tables nsrcerr = %d e_ready = %d...\n", nsrcerr, handle->e_ready );
            ec_init_tables(N, handle->erasure_state->nerr, handle->decode_matrix, handle->g_tbls);

            handle->e_ready = 1; //indicate that rebuild structures are initialized
         }
         PRINTdbg( "ne_read: performing regeneration from erasure...\n" );

         ec_encode_data(bsz, N, handle->erasure_state->nerr, handle->g_tbls, handle->recov, &temp_buffs[N]);

         if (handle->timing_flags & TF_ERASURE) {
            fast_timer_stop(&handle->erasure_timer);
            log_histo_add_interval(&handle->erasure_h,
                                   &handle->erasure_timer);
         }

      }

      /**** write appropriate data out ****/
      for( counter=startpart, tmp=0; counter <= endchunk; counter++ ) {
         readsize = datasz[counter];

#if DEBUG_NE
         if ( readsize+out_off > llcounter ) {
           fprintf(stderr,"ne_read: out_off + readsize(%lu) > llcounter at counter = %d!\n",(unsigned long)readsize,counter);

           for ( counter = 0; counter < temp_buffs_alloc; counter++ )
              free(temp_buffs[counter]);

           return -1;
         }
#endif

         if (handle->timing_flags & TF_RW)
            fast_timer_start(&handle->stats[counter].write);

         if ( handle->erasure_state->src_in_err[counter] == 0 ) {
            PRINTdbg( "ne_read: performing write of %d from chunk %d data\n", readsize, counter );

#ifdef INT_CRC
            if ( firststripe  &&  counter == startpart )
#else
            if ( firststripe  &&  counter == startpart  &&  error_in_stripe )
#endif
            {
               PRINTdbg( "ne_read:   with offset of %d\n", startoffset );
               memcpy( buffer+out_off, (handle->buffs[counter])+startoffset, readsize );
            }
            else {
               memcpy( buffer+out_off, handle->buffs[counter], readsize );
            }
         }
         else {

            for ( tmp = 0; counter != handle->src_err_list[tmp]; tmp++ ) {
               if ( tmp == handle->erasure_state->nerr ) {
                  PRINTerr( "ne_read: improperly definded erasure structs, failed to locate %d in src_err_list\n", tmp );
                  errno = ENOTRECOVERABLE;

                  for ( counter = 0; counter < temp_buffs_alloc; counter++ )
                     free(temp_buffs[counter]);

                  if (handle->timing_flags & TF_RW) {
                     fast_timer_stop(&handle->stats[counter].write);
                     log_histo_add_interval(&handle->stats[counter].write_h,
                                            &handle->stats[counter].write);
                  }

                  return -1;
               }
            }

            if ( firststripe == 0  ||  counter != startpart ) {
               PRINTdbg( "ne_read: performing write of %d from regenerated chunk %d data, src_err = %d\n",
                            readsize, counter, handle->src_err_list[tmp] );
               memcpy( buffer+out_off, temp_buffs[N+tmp], readsize );
            }
            else {
               PRINTdbg( "ne_read: performing write of %d from regenerated chunk %d data with offset %d, src_err = %d\n",
                            readsize, counter, startoffset, handle->src_err_list[tmp] );
               memcpy( buffer+out_off, (temp_buffs[N+tmp])+startoffset, readsize );
            }

         } //end of src_in_err = true block

         out_off += readsize;

         if (handle->timing_flags & TF_RW) {
            fast_timer_stop(&handle->stats[counter].write);
            log_histo_add_interval(&handle->stats[counter].write_h,
                                   &handle->stats[counter].write);
         }

      } //end of output loop for stipe data

      if ( out_off != llcounter ) {
         PRINTerr( "ne_read: internal mismatch : llcounter (%lu) and out_off (%zd)\n", (unsigned long)llcounter, out_off );
         errno = ENOTRECOVERABLE;

         for ( counter = 0; counter < temp_buffs_alloc; counter++ )
            free(temp_buffs[counter]);

         return -1;
      }

      firststripe=0;
      tmpoffset = 0; tmpchunk = 0; startpart=0;

    }//end of generating loop for each stripe

   if ( error_in_stripe == 1 ) {
      handle->buff_offset -= ( handle->buff_offset % (N*bsz) );
   }

   //copy regenerated blocks and note length of cached stripe
   for ( counter = 0; counter < mtot; counter++ ) {
      if ( error_in_stripe == 1  &&  counter < N ) {
         if ( handle->erasure_state->src_in_err[counter] == 1 ) {
            for ( tmp = 0; counter != handle->src_err_list[tmp]; tmp++ ) {
               if ( tmp == handle->erasure_state->nerr ) {
                  PRINTerr( "ne_read: improperly definded erasure structs, failed to locate %d in src_err_list while caching\n", tmp );
                  mtot=0;
                  tmp=0;
                  handle->buff_rem -= bsz; //just to offset the later addition
                  break;
               }
            }
            PRINTdbg( "ne_read: caching %d from regenerated chunk %d data, src_err = %d\n", bsz, counter, handle->src_err_list[tmp] );
            memcpy( handle->buffs[counter], temp_buffs[N+tmp], bsz );
         }
         handle->buff_rem += bsz;
      }
      else if ( counter < N ) {
         handle->buff_rem += datasz[counter];
      }
   }

   for ( counter = 0; counter < temp_buffs_alloc; counter++ )
      free(temp_buffs[counter]);

   PRINTdbg( "ne_read: cached %lu bytes from stripe at offset %zd\n", handle->buff_rem, handle->buff_offset );

   return llcounter; 
}

void sync_file(ne_handle handle, int block_index) {
#if 0
  char path[MAXNAME];
  int  block_number = ((handle->erasure_state->start + block_index)
                       % (handle->erasure_state->N + handle->erasure_state->E));
  handle->snprintf(path, MAXNAME, handle->erasure_state->path_fmt, block_number, handle->printf_state);
  strcat(path, WRITE_SFX);

  HNDLOP(close, handle->FDArray[block_index]);
  OPEN(handle->FDArray[block_index], handle, path, O_WRONLY);
  if(FD_ERR(handle->FDArray[block_index])) {
    PRINTerr( "failed to reopen file\n");
    handle->erasure_state->src_in_err[block_index] = 1;
    handle->src_err_list[handle->erasure_state->nerr] = block_index;
    handle->erasure_state->nerr++;
    return;
  }

  off_t seek = HNDLOP(lseek, handle->FDArray[block_index],
                      handle->written[block_index],
                      SEEK_SET);
  if(seek < handle->written[block_index]) {
    PRINTerr( "failed to seek reopened file\n");
    handle->erasure_state->src_in_err[block_index] = 1;
    handle->src_err_list[handle->erasure_state->nerr] = block_index;
    handle->erasure_state->nerr++;
    HNDLOP(close, handle->FDArray[block_index]);
    return;
  }

#else
  HNDLOP(fsync, handle->FDArray[block_index]);

#endif
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

   if (nbytes > UINT_MAX) {
     PRINTerr( "ne_write: not yet validated for write-sizes above %lu\n", UINT_MAX);
     errno = EFBIG;             /* sort of */
     return -1;
   }

   if ( handle-> mode != NE_WRONLY  &&  handle->mode != NE_REBUILD ) {
     PRINTerr( "ne_write: handle is in improper mode for writing!\n" );
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
         //if we failed to enqueue work for this block, note that the block is in error
         if(queue_result != 0 && !handle->erasure_state->src_in_err[counter]) {
           handle->erasure_state->src_in_err[counter] = 1;
           handle->src_err_list[handle->erasure_state->nerr] = counter;
           handle->erasure_state->nerr++;
         }
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

#ifdef INT_CRC
         writesize += sizeof(crc);
#endif

         handle->written[counter] += writesize;

#ifdef INT_CRC
         writesize -= sizeof(crc);
#endif

         handle->nsz[counter] += writesize;
         handle->ncompsz[counter] += writesize;
         
         counter++;
      } //end of writes for N

      // If we haven't written a whole stripe, terminate. This happens
      // if there is not enough data to form a complete stripe.
      if ( counter != N ) {
         break;
      }


      /* calculate and write erasure */
      if (handle->timing_flags & TF_ERASURE)
         fast_timer_start(&handle->erasure_timer);

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

      PRINTdbg( "ne_write: calculating %d recovery blocks from %d data blocks\n",E,N);
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
          pthread_cond_wait(&bq->have_space, &bq->qlock);
        }
        if(i == N) {
          buffer_index = bq->tail;
        }
        else {
          assert(buffer_index == bq->tail);
        }
      }

      ec_encode_data(bsz, N, E, handle->g_tbls,
                     (unsigned char **)handle->block_buffs[buffer_index],
                     (unsigned char **)&(handle->block_buffs[buffer_index][N]));

      if (handle->timing_flags & TF_ERASURE) {
         fast_timer_stop(&handle->erasure_timer);
         log_histo_add_interval(&handle->erasure_h,
                                &handle->erasure_timer);
      }

      for(i = N; i < handle->erasure_state->N + handle->erasure_state->E; i++) {
        BufferQueue *bq = &handle->blocks[i];
        bq->qdepth++;
        bq->tail = (bq->tail + 1) % MAX_QDEPTH;
        pthread_cond_signal(&bq->have_work);
        pthread_mutex_unlock(&bq->qlock);
        handle->nsz[i] += bsz;
        handle->ncompsz[i] += bsz;
      }

      //now that we have written out all data, reset buffer
      handle->buff_rem = 0; 
   }
   handle->erasure_state->totsz += totsize; //as it is impossible to write at an offset, the sum of writes will be the total size

   // If the errors exceed the minimum protection threshold number of
   // errrors then fail the write.
   if( UNSAFE(handle) ) {
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

   if (! handle->timing_flags)
      printf("No stats\n");

   else {
      int simple = (handle->timing_flags & TF_SIMPLE);

      fast_timer_show(&handle->handle_timer,  simple, "handle:  ");
      fast_timer_show(&handle->erasure_timer, simple, "erasure: ");
      printf("\n");
         
      int i;
      int N = handle->erasure_state->N;
      int E = handle->erasure_state->E;
      for (i=0; i<N+E; ++i) {
         printf("-- block %d\n", i);

         fast_timer_show(&handle->stats[i].thread, simple, "thread:  ");
         fast_timer_show(&handle->stats[i].open,   simple, "open:    ");

         fast_timer_show(&handle->stats[i].read,   simple, "read:    ");
         log_histo_show(&handle->stats[i].read_h,  simple, "read_h:  ");

         fast_timer_show(&handle->stats[i].write,  simple, "write:   ");
         log_histo_show(&handle->stats[i].write_h, simple, "write_h: ");

         fast_timer_show(&handle->stats[i].close,  simple, "close:   ");
         fast_timer_show(&handle->stats[i].rename, simple, "rename:  ");
         fast_timer_show(&handle->stats[i].stat,   simple, "stat:    ");
         fast_timer_show(&handle->stats[i].xattr,  simple, "xattr:   ");

         fast_timer_show(&handle->stats[i].crc,    simple, "CRC:     ");
         log_histo_show(&handle->stats[i].crc_h,   simple, "CRC_h:   ");
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

void copy_timing_stats(ne_handle handle)
{
   int i, j;
   int total_blk = handle->erasure_state->N + handle->erasure_state->E;
   char* open_cursor = handle->timing_stats;
   //printf("libne open_cursor pointer %p\n", open_cursor);
   char* read_cursor = handle->timing_stats + (3 + sizeof(double) * 65 * (handle->erasure_state->N + handle->erasure_state->E));
   char* write_cursor = handle->timing_stats + 2 * (3 + sizeof(double) * 65 * (handle->erasure_state->N + handle->erasure_state->E));
   char* close_cursor = handle->timing_stats + 3 * (3 + sizeof(double) * 65 * (handle->erasure_state->N + handle->erasure_state->E));

   if(handle->timing_flags & TF_OPEN)
   {
      //put open identifier
      snprintf(open_cursor, 3, "OP");
      //printf("open_cursor after snprintf %s\n", open_cursor);

      open_cursor += 3;
      for(i = 0; i < total_blk; i++)
      {
         double* blk = ((double*)open_cursor) + (65 * i);
         for(j = 64; j; j--)
         {
            blk[j] += handle->stats[i].open_h.bin[j];
            //printf("LIBNE OPEN blk %d j %d value %f\n", i, j, blk[j]);
         }
      }
   }
   else
   {
      snprintf(open_cursor, 3, "--");
   }

   if(handle->timing_flags & TF_RW)
   {
      //first accumulate read
      snprintf(read_cursor, 3, "RD");
      read_cursor += 3;
      for(i = 0; i < total_blk; i++)
      {
         double* blk = ((double*)read_cursor) + (65 * i);
         for(j = 64; j; j--)
         {
            blk[j] += handle->stats[i].read_h.bin[j];
            //printf("LIBNE READ blk %d j %d value %f\n", i, j, blk[j]);
         }
      }

      //then accumulate write
      snprintf(write_cursor, 3, "WR");
      write_cursor += 3;
      for(i = 0; i < total_blk; i++)
      {
         double* blk = ((double*)write_cursor) + (65 * i);
         for(j = 64; j; j--)
         {
            blk[j] += handle->stats[i].write_h.bin[j];
            //printf("LIBNE WRITE blk %d j %d value %f\n", i, j, blk[j]);
         }
      }
   }
   else
   {
      snprintf(read_cursor, 3, "--");
      snprintf(write_cursor, 3, "--");
   }

   if (handle->timing_flags & TF_CLOSE)
   {
      snprintf(close_cursor, 3, "CL");
      close_cursor += 3;
      for(i = 0; i < total_blk; i++)
      {
         double* blk = ((double*)close_cursor) + (65 * i);
         for(j = 64; j; j--)
         {
            blk[j] += handle->stats[i].close_h.bin[j];
         // printf("LIBNE CLOSE blk %d j %d value %f\n", i, j, blk[j]);
         }
      }
   }
   else
   {
      snprintf(close_cursor, 3, "--");
   }
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
   int counter;
   char xattrval[XATTRLEN];
   char file[MAXNAME];       /* array name of files */
   char nfile[MAXNAME];       /* array name of files */
   int N;
   int E;
   unsigned int bsz;
   int ret = 0;
   int tmp;
   unsigned char *zero_buff;
   //extract_repo_name(handle->erasure_state->path_fmt, handle->repo, handle->pod_id);

   time_t curtime;
   time(&curtime);


   if ( handle == NULL ) {
      PRINTerr( "ne_close: received a NULL handle\n" );
      errno = EINVAL;
      return -1;
   }
   N = handle->erasure_state->N;
   E = handle->erasure_state->E;
   bsz = handle->erasure_state->bsz;


   /* flush the handle buffer if necessary */
   if ( handle->mode == NE_WRONLY  &&  handle->buff_rem != 0 ) {
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
   while (counter < N+E) {

      char no_rename = 0;
      if (handle->mode == NE_WRONLY ) {
         bq_close(&handle->blocks[counter]);
      }
      else if (! FD_ERR(handle->FDArray[counter])) {

         // as this operation can only be read or rebuild, we only 
         // really care if close fails for a rebuild output file
         if (HNDLOP(close, handle->FDArray[counter])
             && (handle->erasure_state->src_in_err[counter]  == 1)
             && (handle->mode == NE_REBUILD)) {

            ret = -1;
            no_rename = 1;
            PRINTerr("ne_close: close failed for rebuild output file %d, "
                     "aborting rename for that file\n", counter );
         }

         // insurance, to protect against further use
         FD_INIT(handle->FDArray[counter], handle); // set fd to -1
      }

     if (handle->mode == NE_REBUILD && handle->erasure_state->src_in_err[counter] == 1 ) {

         // if mode is NE_WRONLY this will be handled by the BQ thread.
         if(set_block_xattr(handle, counter) != 0) {
           no_rename = 1;
           ret = -1;
           PRINTerr( "ne_close: failed to set xattr for rebuilt file %d\n", counter );
         }
         handle->snprintf( file, MAXNAME, handle->erasure_state->path_fmt, (counter+handle->erasure_state->start)%(N+E), handle->printf_state );
         strncpy( nfile, file, strlen(file) + 1);

         // save the original file
         if( handle->e_ready == 1  &&  no_rename == 0 ) {
            char timestamp[30];

            strftime( timestamp, 30, ".rebuild_bkp.%m%d%y-%H%M%S", localtime(&curtime) );
            strncat( file, timestamp, 30 );
            
            // perform the rename
            errno = 0;
            PRINTdbg( "ne_close: renaming old: %s\n", nfile );
            PRINTdbg( "                   new: %s\n", file );
            if( PATHOP( rename, handle->impl, handle->auth,  nfile, file )
                && (errno != ENOENT) ) { //if there is no original, this is not an error

               PRINTerr( "ne_close: failed to rename original file '%s' to '%s'\n", nfile, file );
               ret = -1;
               no_rename = 1;
            }
            else if (errno) {
               PRINTdbg( "ne_close: rename failed (not considered an error): %s\n", strerror(errno) );
            }

            strncpy( file, nfile, strlen(nfile) + 1);
         }

         strncat( file, REBUILD_SFX, strlen(REBUILD_SFX) + 1 );

         if ( PATHOP( chown, handle->impl, handle->auth, file, handle->owner, handle->group) ) {
            PRINTerr( "ne_close: failed to chown rebuilt file\n" );
            no_rename = 1;
            ret = -1;
         }

         if ( handle->e_ready == 1  &&  no_rename == 0 ) {

            PRINTdbg( "ne_close: renaming old: %s\n", file );
            PRINTdbg( "                   new: %s\n", nfile );
            if ( PATHOP( rename, handle->impl, handle->auth, file, nfile ) != 0 ) {
               PRINTerr( "ne_close: failed to rename rebuilt file\n" );
               // rebuild should fail even if only one file can't be renamed
               ret = -1;
            }

#ifdef META_FILES
            // corresponding "meta" file ...
            strncat( file,  META_SFX, strlen(META_SFX)+1 );
            strncat( nfile, META_SFX, strlen(META_SFX)+1 );

            PRINTdbg( "ne_close: renaming old: %s\n", file );
            PRINTdbg( "                   new: %s\n", nfile );
            if ( PATHOP( rename, handle->impl, handle->auth, file, nfile ) != 0 ) {
               PRINTerr( "ne_close: failed to rename rebuilt meta file\n" );
               // rebuild should fail even if only one file can't be renamed
               ret = -1;
            }
#endif

         }
         else{
            PRINTerr( "ne_close: cleaning up file %s from failed rebuild\n", file );
            PATHOP( unlink, handle->impl, handle->auth, file );

#ifdef META_FILES
            // corresponding "meta" file ...
            strncat( file, META_SFX, strlen(META_SFX)+1 );
            PRINTerr( "ne_close: cleaning up file %s from failed rebuild\n", file );
            PATHOP( unlink, handle->impl, handle->auth, file );
#endif

         }
      }

      counter++;
   }

   if(handle->mode == NE_WRONLY) {
     int i;
     /* wait for the threads */
     for(i = 0; i < handle->erasure_state->N + handle->erasure_state->E; i++) {
       pthread_join(handle->threads[i], NULL);
       /* add up the errors */
       if((handle->blocks[i].flags & BQ_ERROR) && !handle->erasure_state->src_in_err[i]) {
         handle->erasure_state->src_in_err[i] = 1;
         handle->src_err_list[handle->erasure_state->nerr] = i;
         handle->erasure_state->nerr++;
       }
       bq_destroy(&handle->blocks[i]);
     }

     /* free the buffers */
     for(i = 0; i < MAX_QDEPTH; i++) {
       free(handle->buffer_list[i]);
     }
   }
   else { // still need to do it the old way for non-writes
     free(handle->buffer);
   }

   // all potential meta-file manipulation should be done now (threads have exited)
   // should be safe to reset umask
   umask(mask);

   //if (handle->timing_flags) {
   //   fast_timer_stop(&handle->handle_timer);
   //  show_handle_stats(handle);
   //}

   if( (UNSAFE(handle) && handle->mode == NE_WRONLY) ) {
      PRINTdbg( "ne_close: detected unsafe error levels following write operation\n" );
      ret = -1;
   }
   else if( handle->mode == NE_REBUILD  &&  handle->e_ready == 0 ) {
      PRINTdbg( "ne_close: detected an incomplete/failed rebuild process\n" );
      ret = -1;
   }
   else if ( handle->erasure_state->nerr > handle->erasure_state->E  &&  handle->mode == NE_RDONLY ) { /* for non-writes */
      PRINTdbg( "ne_close: detected excessive errors following a read operation\n" );
      ret = -1;
   }
   if ( ret == 0 ) {
      PRINTdbg( "ne_close: encoding error pattern in return value...\n" );
      /* Encode any file errors into the return status */
      for( counter = 0; counter < N+E; counter++ ) {
         if ( handle->erasure_state->src_in_err[counter] ) {
            ret += ( 1 << ((counter + handle->erasure_state->start) % (N+E)) );
         }
      }
   }

   if ( handle->erasure_state->path_fmt != NULL )
      free(handle->erasure_state->path_fmt);

   free(handle->encode_matrix);
   free(handle->decode_matrix);
   free(handle->invert_matrix);
   free(handle->g_tbls);
   
   if (handle->timing_flags & TF_HANDLE)
      fast_timer_stop(&handle->handle_timer); /* overall cost of this op */

   if (handle->timing_flags)
      copy_timing_stats(handle);

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
int ne_delete1( SnprintfFunc snprintf_fn, void* printf_state,
                uDALType itype, SktAuth auth, TimingFlagsValue timing_flags,
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

      snprintf_fn( file,    MAXNAME, path, counter, printf_state );

      snprintf_fn( partial, MAXNAME, path, counter, printf_state );
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
      fast_timer_show(&timer, (timing_flags & TF_SIMPLE),  "delete: ");
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

   return ne_delete1(ne_default_snprintf, NULL, UDAL_POSIX, auth, 0, path, width);
}



// This is only used from libneTest?  (Maybe this was developed to give
// libneTest an easy way to determine the size of a striped object, so that
// that size could then be provided on a subsequent command-line, to do a
// "read" of the whole file?  If so, you can now just skip providing the
// size on the command-line for a "read", and libneTest will just read the
// whole thing.)
//
// Tweaked: Instead of expecting a template pattern for the path, and then
// adding ".meta", to generate our local template, we expect the caller to
// provide the appropriate template as the path, including ".meta", if they
// want meta.  libneTest will do this.

off_t ne_size1( SnprintfFunc snprintf_fn, void* printf_state,
                uDALType itype, SktAuth auth, TimingFlagsValue timing_flags,
                const char* ptemplate, int quorum, int max_stripe_width ) {

   char file[MAXNAME];
   char xattrval[XATTRLEN];

   if( max_stripe_width < 1 )
      max_stripe_width = MAXPARTS;
   if( quorum < 1 )
      quorum = max_stripe_width;
   if( quorum > max_stripe_width ) {
      PRINTerr( "ne_size: received a quorum value greater than the max_stripe_width\n" );
      errno = EINVAL;
      return -1;
   }

   // see comments above OPEN() defn
   GenericFD      fd   = {0};
   struct handle  hndl = {0};
   ne_handle      handle = &hndl;

   handle->impl = get_impl(itype);
   handle->auth = auth;
   if (! handle->impl) {
      PRINTerr( "ne_size: couldn't find implementation for itype %d\n", itype );
      errno = EINVAL;
      return -1;
   }


   off_t sizes_reported[max_stripe_width];
   int   match     = 0;
   off_t prev_size = -1;
   int   i;

   for( i = 0; i < max_stripe_width  &&  match < quorum; i++ ) {
      snprintf_fn( file, MAXNAME, ptemplate, i, printf_state );

      PRINTdbg("ne_size: opening file %s\n", file);
      OPEN( fd, handle, file, O_RDONLY );
      if ( FD_ERR(fd) ) { 
         PRINTerr("ne_size: failed to open file %s\n", file);
         continue;
      }

#ifdef META_FILES

      int tmp = HNDLOP(read, fd, &xattrval[0], XATTRLEN );
      if ( tmp < 0 ) {
         PRINTerr("ne_size: failed to read from file %s\n", file);
         HNDLOP( close, fd );
         continue;
      }
      else if(tmp == 0) {
         PRINTerr( "ne_size: read 0 bytes from metadata file %s\n", file);
         HNDLOP( close, fd );
         continue;
      }

#else

#  if (AXATTR_GET_FUNC == 4)
      if( HNDLOP(fgetxattr, fd, XATTRKEY, &xattrval[0], XATTRLEN) )
         continue;
#  else
      if( HNDLOP(fgetxattr, fd, XATTRKEY, &xattrval[0], XATTRLEN, 0, 0) )
         continue;
#  endif

#endif //META_FILES

      tmp = HNDLOP( close, fd );
      if ( tmp < 0 ) {
         PRINTerr("ne_size: failed to close file %s\n", file);
         continue;
      }

      PRINTdbg( "ne_size: file %s xattr returned %s\n", file, xattrval );

      sscanf( xattrval, "%*s %*s %*s %*s %*s %*s %*s %zd", &sizes_reported[i] );

      if ( prev_size == -1  ||  sizes_reported[i] == prev_size ) {
         match++;
      }
      else { 
         match = 1;
         int k;
         for( k = 0; k < i; k++ ) {
            if( sizes_reported[k] == sizes_reported[i] )
               match++;
         }
      }

      prev_size = sizes_reported[i];
   }

   if( prev_size == -1 ) {
      errno = ENOENT;
      return -1;
   }
   if( match < quorum ) {
      errno = ENODATA;
      return -1;
   }

   return prev_size;
}

off_t ne_size( const char* path, int quorum, int max_stripe_width ) {

   // This is safe for builds with/without sockets and/or socket-authentication enabled.
   // However, if you do build with socket-authentication, this will require a read
   // from a file (~/.awsAuth) that should probably only be accessible if ~ is /root.
   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("failed to initialize default socket-authentication credentials\n");
      return -1;
   }

   return ne_size1(ne_default_snprintf, NULL, UDAL_POSIX, auth, 0, path, quorum, max_stripe_width);
}



/**
 * Internal helper function intended to access xattrs for the purpose of validating/identifying handle information
 * @param ne_handle handle : The handle for the current erasure striping
 * @param char* path : Name structure for the files of the desired striping.  This should contain a single "%d" field.
 * @return int : Status code, with 0 indicating success and -1 indicating failure
 */
int xattr_check( ne_handle handle, char *path ) 
{
   char file[MAXNAME];       /* array name of files */
#ifdef META_FILES
   char nfile[MAXNAME];       /* array name of files */
#endif
   int counter;
   int bcounter;
   int ret;
   int tmp;
   char xattrval[XATTRLEN];
   char xattrchunks[20];       /* char array to get n parts from xattr */
   char xattrchunksizek[20];   /* char array to get chunksize from xattr */
   char xattrnsize[20];        /* char array to get total size from xattr */
   char xattrerasure[20];      /* char array to get erasure from xattr */
   char xattroffset[20];      /* char array to get erasure_offset from xattr */
   char xattrncompsize[20];    /* general char for xattr manipulation */
   char xattrnsum[50];         /* char array to get xattr sum from xattr */
   char xattrtotsize[160];
   int N = handle->erasure_state->N;
   int E = handle->erasure_state->E;
   int erasure_offset = handle->erasure_state->start;
   unsigned int bsz = handle->erasure_state->bsz;
   unsigned long nsz;
   unsigned long ncompsz;
   char goodfile = 0;
   u64 csum;
   u64 totsz;
#ifdef INT_CRC
   unsigned int blocks;
   u32 crc;
#endif
   int N_list[ MAXPARTS ] = { 0 };
   int E_list[ MAXPARTS ] = { 0 };
   int O_list[ MAXPARTS ] = { -1 };
   unsigned int bsz_list[ MAXPARTS ] = { 0 };
   u64 totsz_list[ MAXPARTS ] = { 0 };
   int N_match[ MAXPARTS ] = { 0 };
   int E_match[ MAXPARTS ] = { 0 };
   int O_match[ MAXPARTS ] = { 0 };
   int bsz_match[ MAXPARTS ] = { 0 };
   int totsz_match[ MAXPARTS ] = { 0 };

   struct stat* partstat = malloc (sizeof(struct stat));
   int lN;
   int lE;
  
   if ( handle->mode == NE_STAT  &&  N == 0 ) {
      N = MAXN;
      E = MAXE;
   }

   lN = N;
   lE = E;

#ifdef META_FILES
   GenericFD MetaFDArray[ MAXPARTS ];
   memset(MetaFDArray, 0, sizeof(MetaFDArray));
#endif

   PRINTdbg( "xattr_check: planned %d iterations\n", lN+lE );

   for ( counter = 0; counter < lN+lE; counter++ ) {
      bzero(file,sizeof(file));
      handle->snprintf( file, MAXNAME, path, (counter+handle->erasure_state->start)%(lN+lE), handle->printf_state );

      if (handle->timing_flags & TF_STAT)
         fast_timer_start(&handle->stats[counter].stat);

      ret = PATHOP(stat, handle->impl, handle->auth, file, partstat);

      if (handle->timing_flags & TF_STAT)
         fast_timer_stop(&handle->stats[counter].stat);


      PRINTdbg( "xattr_check: stat of file %s returns %d\n", file, ret );
      handle->csum[counter]=0; //reset csum to make results clearer
      if ( ret != 0 ) {
         PRINTerr( "xattr_check: file %s: failure of stat\n", file );
         handle->erasure_state->src_in_err[counter] = 1;
         handle->src_err_list[handle->erasure_state->nerr] = counter;
         handle->erasure_state->nerr++;
         continue;
      }
      handle->owner = partstat->st_uid;
      handle->group = partstat->st_gid;
      bzero(xattrval,sizeof(xattrval));


      if (handle->timing_flags & TF_XATTR)
         fast_timer_start(&handle->stats[counter].xattr);

      ret = ne_get_xattr1(handle->impl, handle->auth, file, xattrval, sizeof(xattrval));

      if (handle->timing_flags & TF_XATTR)
         fast_timer_stop(&handle->stats[counter].xattr);

      if (ret < 0) {
         PRINTerr( "xattr_check: failure of xattr retrieval for file %s\n", file);
         handle->erasure_state->src_in_err[counter] = 1;
         handle->src_err_list[handle->erasure_state->nerr] = counter;
         handle->erasure_state->nerr++;
         continue;
      }
      PRINTdbg("xattr_check: file %d (%s) xattr returned \"%s\"\n",counter,file,xattrval);

      ret = sscanf(xattrval,"%s %s %s %s %s %s %s %s",
                   xattrchunks,
                   xattrerasure,
                   xattroffset,
                   xattrchunksizek,
                   xattrnsize,
                   xattrncompsize,
                   xattrnsum,
                   xattrtotsize);
      if (ret != 8) {
         PRINTerr( "xattr_check: sscanf parsed only %d values in MD from '%s'\n", ret, file);
         handle->erasure_state->src_in_err[counter] = 1;
         handle->src_err_list[handle->erasure_state->nerr] = counter;
         handle->erasure_state->nerr++;
         continue;
      }

      N = atoi(xattrchunks);
      E = atoi(xattrerasure);
      erasure_offset = atoi(xattroffset);
      bsz = atoi(xattrchunksizek);
      nsz = strtol(xattrnsize,NULL,0);
      ncompsz = strtol(xattrncompsize,NULL,0);
      csum = strtoll(xattrnsum,NULL,0);
      totsz = strtoll(xattrtotsize,NULL,0);

#ifdef INT_CRC
      blocks = nsz / bsz;
#endif

      if ( handle->mode != NE_STAT ) { // for 'stat' these handle values will be uninitialized

         /* verify xattr */
         if ( N != handle->erasure_state->N ) {
            PRINTerr( "xattr_check: filexattr N = %d did not match handle value  %d\n", N, handle->erasure_state->N); 
            handle->erasure_state->src_in_err[counter] = 1;
            handle->src_err_list[handle->erasure_state->nerr] = counter;
            handle->erasure_state->nerr++;
            continue;
         }
         else if ( E != handle->erasure_state->E ) {
            PRINTerr( "xattr_check: filexattr E = %d did not match handle value  %d\n", E, handle->erasure_state->E); 
            handle->erasure_state->src_in_err[counter] = 1;
            handle->src_err_list[handle->erasure_state->nerr] = counter;
            handle->erasure_state->nerr++;
            continue;
         }
         else if ( bsz != handle->erasure_state->bsz ) {
            PRINTerr( "xattr_check: filexattr bsz = %d did not match handle value  %d\n", bsz, handle->erasure_state->bsz); 
            handle->erasure_state->src_in_err[counter] = 1;
            handle->src_err_list[handle->erasure_state->nerr] = counter;
            handle->erasure_state->nerr++;
            continue;
         }
         else if ( erasure_offset != handle->erasure_state->start ) {
            PRINTerr( "xattr_check: filexattr offset = %d did not match handle value  %d\n", erasure_offset, handle->erasure_state->start); 
            handle->erasure_state->src_in_err[counter] = 1;
            handle->src_err_list[handle->erasure_state->nerr] = counter;
            handle->erasure_state->nerr++;
            continue;
         }

      }

      if
#ifdef INT_CRC
         ( ( nsz + (blocks*sizeof(crc)) ) != partstat->st_size )
#else
         ( nsz != partstat->st_size )
#endif
      {
         PRINTerr( "xattr_check: filexattr nsize = %lu did not match stat value %zd (possible missing internal crcs)\n", nsz, partstat->st_size); 
         handle->erasure_state->src_in_err[counter] = 1;
         handle->src_err_list[handle->erasure_state->nerr] = counter;
         handle->erasure_state->nerr++;
         continue;
      }
      else if ( (nsz % bsz) != 0 ) {
         PRINTerr( "xattr_check: filexattr nsize = %lu is inconsistent with block size %d \n", nsz, bsz); 
         handle->erasure_state->src_in_err[counter] = 1;
         handle->src_err_list[handle->erasure_state->nerr] = counter;
         handle->erasure_state->nerr++;
         continue;
      }
      else if ( (N + E) <= erasure_offset ) {
         PRINTerr( "xattr_check: filexattr offset = %d is inconsistent with stripe width %d\n", erasure_offset, (N+E)); 
         handle->erasure_state->src_in_err[counter] = 1;
         handle->src_err_list[handle->erasure_state->nerr] = counter;
         handle->erasure_state->nerr++;
         continue;
      }
      else if
#ifdef INT_CRC
         ( ( ncompsz + (blocks*sizeof(crc)) ) != partstat->st_size )
#else
         ( ncompsz != partstat->st_size )
#endif
      {
         PRINTerr( "xattr_check: filexattr ncompsize = %lu did not match stat value %zd (possible missing crcs)\n", ncompsz, partstat->st_size); 
         handle->erasure_state->src_in_err[counter] = 1;
         handle->src_err_list[handle->erasure_state->nerr] = counter;
         handle->erasure_state->nerr++;
         continue;
      }
      else if ( ((ncompsz * N) - totsz) >= bsz*N ) {
         PRINTerr( "xattr_check: filexattr total_size = %llu is inconsistent with ncompsz %lu\n", (unsigned long long)totsz, ncompsz); 
         handle->erasure_state->src_in_err[counter] = 1;
         handle->src_err_list[handle->erasure_state->nerr] = counter;
         handle->erasure_state->nerr++;
         continue;
      }
      else {
         PRINTdbg( "setting csum for file %d to %llu\n", counter, (unsigned long long)csum);
         handle->csum[counter] = csum;
         if ( handle->mode == NE_RDONLY ) {

            //only set the file size if it is not already set (i.e. by a call with mode=NE_STAT)
            if( ! handle->erasure_state->totsz )
               handle->erasure_state->totsz = totsz;

            continue; // break;
         }

         // This bundle of spaghetti acts to individually verify each
         // "important" xattr value and count matches amongst all files
         char nc = 1, ec = 1, of = 1, bc = 1, tc = 1;

         //if these values are already initialized, skip setting them
         if ( handle->mode != NE_STAT ) {
            nc = 0; ec = 0; of = 0; bc = 0;
         }

         for ( bcounter = 0;
               (( nc || ec || bc || tc || of )  &&  (bcounter < MAXPARTS));
               bcounter++ ) {

            if ( nc ) {
               if ( N_list[bcounter] == N ) {
                  N_match[bcounter]++;
                  nc = 0;
               }
               else if ( N_list[bcounter] == 0 ) {
                  N_list[bcounter] = N;
                  N_match[bcounter]++;
                  nc = 0;
               }
            }

            if ( ec ) {
               if ( E_list[bcounter] == E ) {
                  E_match[bcounter]++;
                  ec = 0;
               }
               else if ( E_list[bcounter] == 0 ) {
                  E_list[bcounter] = E;
                  E_match[bcounter]++;
                  ec = 0;
               }
            }

            if ( of ) {
               if ( O_list[bcounter] == erasure_offset ) {
                  O_match[bcounter]++;
                  of = 0;
               }
               else if ( O_list[bcounter] == -1 ) {
                  O_list[bcounter] = erasure_offset;
                  O_match[bcounter]++;
                  of = 0;
               }
            }

            if ( bc ) {
               if ( bsz_list[bcounter] == bsz ) {
                  bsz_match[bcounter]++;
                  bc = 0;
               }
               else if ( bsz_list[bcounter] == 0 ) {
                  bsz_list[bcounter] = bsz;
                  bsz_match[bcounter]++;
                  bc = 0;
               }
            }

            if ( tc ) {
               if ( totsz_list[bcounter] == totsz ) {
                  totsz_match[bcounter]++;
                  tc = 0;
               }
               else if ( totsz_list[bcounter] == 0 ) {
                  totsz_list[bcounter] = totsz;
                  totsz_match[bcounter]++;
                  tc = 0;
               }
            }
         } //end of value-check loop



         // After we've found some minimum number of metadata values, which
         // all agree on the values of N+E, let's believe that we only need
         // to stat N+E metadata files.

         if ((   lN == MAXN)
             && (lE == MAXE)
             && ((! MIN_MD_CONSENSUS)
                 || (counter >= (MIN_MD_CONSENSUS -1)))) {

            PRINTdbg( "xattr_check: testing for consensus on iteration %d\n", counter);
            if ((     N_match[0] == 0 )     || ( N_match[0] >= MIN_MD_CONSENSUS)
                && (( E_match[0] == 0 )     || ( E_match[0] >= MIN_MD_CONSENSUS))
                && (( O_match[0] == 0 )     || ( O_match[0] >= MIN_MD_CONSENSUS))
                && (( bsz_match[0] == 0 )   || ( bsz_match[0] >= MIN_MD_CONSENSUS))
                && (( totsz_match[0] == 0 ) || ( totsz_match[0] >= MIN_MD_CONSENSUS))) {

               PRINTdbg( "xattr_check: consensus achieved N=%d, E=%d\n", N, E);
               lN = N;
               lE = E;
            }
         }
             


      } //end of else at end of xattr checks


   } //end of loop over files

   free(partstat);
   ret = 0;

   if ( handle->mode != NE_RDONLY ) { //if the handle is uninitialized, store the necessary info

      //loop through the counts of matching xattr values and identify the most prevalent match
      int maxmatch=0;
      int match=-1;
      for ( bcounter = 0; bcounter < MAXPARTS; bcounter++ ) {
         if ( totsz_match[bcounter] > maxmatch ) {
            maxmatch = totsz_match[bcounter];
            match = bcounter;
         }
         if ( bcounter > 0 && N_match[bcounter] > 0 )
            ret = 1;
      }
      if ( match != -1 )
         handle->erasure_state->totsz = totsz_list[match];
      else {
         PRINTerr( "xattr_check: failed to locate any matching totsz xattr vals!\n" );
         errno = ENODATA;
         return -1;
      }


      if ( handle->mode == NE_STAT ) {

         //loop through the counts of matching xattr values and identify the most prevalent match
         maxmatch=0;
         match=-1;
         for ( bcounter = 0; bcounter < MAXPARTS; bcounter++ ) {
            if ( N_match[bcounter] > maxmatch ) {
               maxmatch = N_match[bcounter];
               match = bcounter;
            }
            if ( bcounter > 0 && N_match[bcounter] > 0 )
               ret = 1;
         }
         if ( match != -1 )
            handle->erasure_state->N = N_list[match];
         else {
            PRINTerr( "xattr_check: failed to locate any matching N xattr vals!\n" );
            errno = ENODATA;
            return -1;
         }


         //loop through the counts of matching xattr values and identify the most prevalent match
         maxmatch=0;
         match=-1;
         for ( bcounter = 0; bcounter < MAXPARTS; bcounter++ ) {
            if ( E_match[bcounter] > maxmatch ) {
               maxmatch = E_match[bcounter];
               match = bcounter;
            }
            if ( bcounter > 0 && N_match[bcounter] > 0 )
               ret = 1;
         }
         if ( match != -1 )
            handle->erasure_state->E = E_list[match];
         else {
            PRINTerr( "xattr_check: failed to locate any matching E xattr vals!\n" );
            errno = ENODATA;
            return -1;
         }


         //loop through the counts of matching xattr values and identify the most prevalent match
         maxmatch=0;
         match=-1;
         for ( bcounter = 0; bcounter < MAXPARTS; bcounter++ ) {
            if ( O_match[bcounter] > maxmatch ) {
               maxmatch = O_match[bcounter];
               match = bcounter;
            }
            if ( bcounter > 0 && N_match[bcounter] > 0 )
               ret = 1;
         }
         if ( match != -1 )
            handle->erasure_state->start = O_list[match];
         else {
            PRINTerr( "xattr_check: failed to locate any matching offset xattr vals!\n" );
            errno = ENODATA;
            return -1;
         }


         //loop through the counts of matching xattr values and identify the most prevalent match
         maxmatch=0;
         match=-1;
         for ( bcounter = 0; bcounter < MAXPARTS; bcounter++ ) {
            if ( bsz_match[bcounter] > maxmatch ) {
               maxmatch = bsz_match[bcounter];
               match = bcounter;
            }
            if ( bcounter > 0 && N_match[bcounter] > 0 )
               ret = 1;
         }
         if ( match != -1 )
            handle->erasure_state->bsz = bsz_list[match];
         else {
            PRINTerr( "xattr_check: failed to locate any matching bsz xattr vals!\n" );
            errno = ENODATA;
            return -1;
         }

      } //end of NE_STAT exclusive checks
   }

   /* If no usable file was located or the number of errors is too great, notify of failure */
   if ( handle->mode != NE_STAT  &&  handle->erasure_state->nerr > handle->erasure_state->E ) {
      errno = ENODATA;
      return -1;
   }

   if ( ret != 0 ) {
      PRINTerr( "xattr_check: mismatched xattr values were detected, but not identified!" );
      return 1;
   }

   return 0;
}

// Rebuild functions begin here
typedef struct rebuild_err_struct {

   // file descriptors for data/erasure parts in which an error was found
   struct GenericFD FDArray[ MAXPARTS ];

   // per-stripe error info
   int           nerr;
   unsigned char src_in_err[ MAXPARTS ];
   unsigned char src_err_list[ MAXPARTS ];

   // per rebuild run error info
   unsigned char per_rebuild_err[ MAXPARTS ];

   // permanent error info
   unsigned char permanent_err[ MAXPARTS ];
} *rebuild_err;


// sets per-stripe error pattern info for an ongoing rebuild
void update_rebuild_err( rebuild_err epat, int block ) {
   if( epat->src_in_err[block] )
     return; //nothing to do

   epat->src_in_err[ block ] = 1;
   //ensure that sources are listed in order
   int i, tmp;
   for ( i = 0; i < epat->nerr; i++ ) {
      if ( epat->src_err_list[i] > block ) { break; }
   }
   while ( i < epat->nerr ) {
      // re-sort the error list.
      tmp = epat->src_err_list[i];
      epat->src_err_list[i] = block;
      block = tmp;
      i++;
   }
   epat->src_err_list[epat->nerr] = block;
   epat->nerr++;
}


// reset per-stripe error info, but keep permanent errors and file descriptors
// returns 0 if erasure structs will require re-initialization and 1 otherwise
int rebuild_err_reset( rebuild_err epat, int stripe_width ) {
   int block, onerr = epat->nerr;
   epat->nerr = 0;
   for( block=0; block < stripe_width; block++ ) {
      epat->src_in_err[ block ] = 0;
      epat->src_err_list[ block ] = 0;
      if( epat->permanent_err[ block ] )
        epat->per_rebuild_err[ block ] = 1;
      //because we have reset nerr and are clearing src_err_list, it is safe to reinsert persistent errors
      if( epat->per_rebuild_err[ block ] )
         update_rebuild_err( epat, block );
   }
   // if nerr is the same before and after, the error pattern hasn't changed
   return ( onerr == epat->nerr ) ? 1 : 0;
}


static int reopen_for_rebuild(ne_handle handle, int block, rebuild_err epat) {
  char file[MAXNAME];

  handle->snprintf(file, MAXNAME, handle->erasure_state->path_fmt,
                   (block+handle->erasure_state->start)%(handle->erasure_state->N+handle->erasure_state->E),
                   handle->printf_state);

  PRINTdbg( "   stashing handle for %s\n", &file[0] );
  epat->FDArray[block] = handle->FDArray[block];
  update_rebuild_err( epat, block );
  //Maybe we could close the file here, if a "permanent error" was detected?

  PRINTdbg( "   opening %s for write\n", file );
  if( handle->mode == NE_STAT ) {
     PRINTdbg( "   setting FD %d to -1\n", block );
     FD_INIT(handle->FDArray[block], handle);
  }
  else {
     PRINTdbg( "   opening %s for write\n", file );
     OPEN(handle->FDArray[block], handle,
          strncat( file, REBUILD_SFX, strlen(REBUILD_SFX)+1 ),
          O_WRONLY | O_CREAT, 0666 );
  }

  // if the error has already been set, just return
  if( handle->erasure_state->src_in_err[block] )
    return 0;

  handle->erasure_state->src_in_err[block] = 1;

  //ensure that sources are listed in order
  int i, tmp;
  for ( i = 0; i < handle->erasure_state->nerr; i++ ) {
    if ( handle->src_err_list[i] > block)
      break;
  }
  while ( i < handle->erasure_state->nerr ) {
    // re-sort the error list.
    tmp = handle->src_err_list[i];
    handle->src_err_list[i] = block;
    block = tmp;
    i++;
  }

  handle->src_err_list[handle->erasure_state->nerr] = block;
  handle->erasure_state->nerr++;
  handle->e_ready = 0; //indicate that erasure structs require re-initialization

  return 0;
}

// Seek to the start of each block file.
// return -1 on fatal error (seek failed that was expected to succeed)
// return 1 on non-fatal error (seek failed, but may still be recoverable).
// return 0 on success.
static int reset_blocks(ne_handle handle, rebuild_err epat) {
  int block_index;
  for(block_index = 0; block_index < handle->erasure_state->N + handle->erasure_state->E; block_index++) {

    //seek all non-errored files and all rebuild output files
    if(handle->mode != NE_STAT || handle->erasure_state->src_in_err[block_index] == 0) {
      PRINTdbg( "ne_rebuild: performing seek to offset 0 for file %d\n",
                block_index);
      if (HNDLOP(lseek, handle->FDArray[block_index], 0, SEEK_SET) == -1) {
        if(handle->erasure_state->src_in_err[block_index]) {
           PRINTerr( "ne_rebuild: failed to seek ouput file %d (critical error)\n", block_index );
          handle->e_ready = 0;
          return -1;
        }
        else {
           PRINTerr( "ne_rebuild: encountered error while seeking data/erasure file %d\n", block_index );
           reopen_for_rebuild(handle, block_index,epat);
           epat->per_rebuild_err[ block_index ] = 1;
          return 1;
        }
      }
      
    }

    if ( handle->erasure_state->src_in_err[block_index]  &&  ! FD_ERR(epat->FDArray[block_index]) ) {
       PRINTdbg( "ne_rebuild: performing seek to offset 0 for in-error file %d\n",
                 block_index);
       // always reattempt a seek of the original, so long as we have a FD
       if ( HNDLOP(lseek, epat->FDArray[block_index], 0, SEEK_SET) == -1 ) {
          PRINTdbg( "ne_rebuild: failed to seek in-error file %d\n", block_index );

          // we skip updating the per-stripe errors here, as that will always be handled later on
          epat->per_rebuild_err[ block_index ] = 1;
      }
    }

  } // for
  return 0;
}

static int fill_buffers(ne_handle handle, u64 *csum, rebuild_err epat) {
  int          block_index;
  u32          crc;
  const int    ERASURE_WIDTH = handle->erasure_state->N + handle->erasure_state->E;
#ifdef INT_CRC
  const size_t BUFFER_SIZE   = handle->erasure_state->bsz + sizeof(crc);
#else
  const size_t BUFFER_SIZE   = handle->erasure_state->bsz;
#endif

  for(block_index = 0; block_index < ERASURE_WIDTH; block_index++) {
    GenericFD* readFD = &handle->FDArray[block_index];
    if ( handle->erasure_state->src_in_err[ block_index ] ) {
      readFD = &epat->FDArray[ block_index ];
      if( epat->src_in_err[ block_index ] == 0  &&  FD_ERR(*readFD) ) {
        epat->permanent_err[ block_index ] = 1;
        epat->per_rebuild_err[ block_index ] = 1;
        update_rebuild_err( epat, block_index );
        PRINTdbg( "ne_rebuild: encountered -1 FD for in-error file %d\n", block_index );
      }
    }
    if (! epat->src_in_err[block_index]) {
      // size_t read_size = HNDLOP(read, readFD, handle->buffs[block_index],
      //                           BUFFER_SIZE);
      ssize_t read_size = read_all(readFD,
                                   handle->buffs[block_index],
                                   BUFFER_SIZE);

      if (read_size < BUFFER_SIZE) {
         PRINTerr( "ne_rebuild: encountered error while reading file %d\n",
                   block_index);

        epat->per_rebuild_err[ block_index ] = 1;
        if ( handle->erasure_state->src_in_err[ block_index ] == 0 ) {
          reopen_for_rebuild(handle, block_index,epat);
          return -1;
        }
        update_rebuild_err( epat, block_index );
        handle->e_ready = 0; // force reinit of erasure structs
        continue; //added here to avoid writing to rebuild file
      }
      crc = crc32_ieee( TEST_SEED, handle->buffs[block_index], handle->erasure_state->bsz);
      csum[block_index] += crc;

#ifdef INT_CRC
      // verify the stored crc
      u32 *buff_crc = (u32*)(handle->buffs[block_index] + (handle->erasure_state->bsz));
      if(*buff_crc != crc) {
        PRINTerr( "ne_rebuild: mismatch of int-crc for file %d\n",
                block_index);
        if ( handle->erasure_state->src_in_err[ block_index ] == 0 ) {
          reopen_for_rebuild(handle, block_index,epat);
          return -1;
        }
        update_rebuild_err( epat, block_index );
        handle->e_ready = 0; // force reinit of erasure structs
        continue; //added here to avoid writing to rebuild file
      }
#endif
      if( handle->erasure_state->src_in_err[ block_index ]  &&  handle->mode != NE_STAT ) {
        // this is ugly, but due to the structure of the handle buffers, we have to write out this good data block/crc before reading another
        size_t written = HNDLOP(write, handle->FDArray[block_index],
                                handle->buffs[block_index], BUFFER_SIZE);
        if( written != BUFFER_SIZE ) {
           PRINTerr( "ne_rebuild: failed to write valid buffer to rebuilt file %d "
                     "(critical error)\n", block_index );
           handle->e_ready = 0;
           epat->nerr = handle->erasure_state->N + handle->erasure_state->E;
           return -1;
        }
        PRINTerr( "ne_rebuild: successfully wrote valid buffer out to rebuilt file %d\n", block_index );

        // update manifest values appropriately
        handle->csum[block_index]      += crc;
        handle->nsz[block_index]       += handle->erasure_state->bsz;
        handle->ncompsz[block_index]   += handle->erasure_state->bsz;
      }
    }
  }
  return 0;
}

static int write_buffers(ne_handle handle, unsigned char *rebuild_buffs[], rebuild_err epat) {
  u32 crc;
  int i;
  int written, total_written = 0;
#ifdef INT_CRC
  const size_t BUFFER_SIZE = handle->erasure_state->bsz + sizeof(crc);
#else
  const size_t BUFFER_SIZE = handle->erasure_state->bsz;
#endif

  for(i = 0; i < epat->nerr; i++) {
    // if we hit an error for this stripe, use the rebuilt buffer to generate a crc
    crc = crc32_ieee(TEST_SEED, rebuild_buffs[handle->erasure_state->N+i], handle->erasure_state->bsz);
#ifdef INT_CRC
    u32 *buf_crc = (u32*)(rebuild_buffs[handle->erasure_state->N+i] + (handle->erasure_state->bsz));
    *buf_crc = crc;
#endif

    if(handle->mode != NE_STAT) {
       // written = HNDLOP(write, handle->FDArray[epat->src_err_list[i]],
       //                  rebuild_buffs[handle->erasure_state->N+i], BUFFER_SIZE);
       written = write_all(&handle->FDArray[epat->src_err_list[i]],
                           rebuild_buffs[handle->erasure_state->N+i], BUFFER_SIZE);

      if(written < BUFFER_SIZE) {
         PRINTerr("failed to write %llu bytes to fd %d\n",
                  BUFFER_SIZE, FD_NUM(handle->FDArray[handle->src_err_list[i]]));
        return -1;
      }
      PRINTdbg("wrote %llu bytes to fd %d\n",
               BUFFER_SIZE, FD_NUM(handle->FDArray[handle->src_err_list[i]]));
    }
    handle->csum[epat->src_err_list[i]]      += crc;
    handle->nsz[epat->src_err_list[i]]       += handle->erasure_state->bsz;
    handle->ncompsz[epat->src_err_list[i]]   += handle->erasure_state->bsz;
    total_written                            += handle->erasure_state->bsz;
  }
  // have to be careful that this return value does not over-inflate the rebuilt total
  return total_written;
}

// free an array of pointers.
static inline void free_buffers(unsigned char *buffs[], int size) {
  int i;
  for(i = 0; i < size; i++) {
    free(buffs[i]);
  }
}

int do_rebuild(ne_handle handle, rebuild_err epat) {
  int            block_index;
  int            nsrcerr       = 0;
  size_t         rebuilt_size  = 0;
  unsigned char *rebuild_buffs[ MAXPARTS ];
  unsigned int   decode_index[ MAXPARTS ];
  u64            csum[ MAXPARTS ];
  u32            crc;

  const int      ERASURE_WIDTH = handle->erasure_state->N + handle->erasure_state->E;
#ifdef INT_CRC
  const size_t   BUFFER_SIZE = handle->erasure_state->bsz + sizeof(crc);
#else
  const size_t   BUFFER_SIZE = handle->erasure_state->bsz;
#endif

  int tmp;
  char alloc_flag = 0;
  if( epat == NULL ) {
     alloc_flag = 1;
     epat = malloc( sizeof( struct rebuild_err_struct ) );
     if ( epat == NULL ) {
        errno = ENOMEM;
        return -1;
     }
     memset(epat, 0, sizeof( struct rebuild_err_struct ));
  }

  for ( block_index = 0; block_index < ERASURE_WIDTH; block_index++ ) {
    tmp = posix_memalign((void **)&(rebuild_buffs[block_index]),
                         64, BUFFER_SIZE);
    if ( tmp != 0 ) {
      PRINTerr("ne_rebuild: failed to allocate temporary data buffer\n" );
      errno = tmp;
      return -1;
    }
    // clean up epat structures
    if( alloc_flag ) {

      // init the in-error FD array to -1 to avoid confusion
      FD_INIT(epat->FDArray[ block_index ], handle);

      // clear all permanent errors
      epat->permanent_err[ block_index ] = 0;
    }

    // rebuild now handles opening all output files
    if( handle->erasure_state->src_in_err[ block_index ] ) {
      epat->FDArray[ block_index ] = handle->FDArray[ block_index ];
      if( handle->mode == NE_STAT ) {
        FD_INIT(handle->FDArray[ block_index ], handle);
      }
      else {
        reopen_for_rebuild( handle, block_index, epat );
      }
    }
  }

  PRINTdbg( "ne_rebuild: initiating rebuild operation...\n" );

  // loop over all the data to complete the rebuild.
  while(rebuilt_size < handle->erasure_state->totsz) {

    // (re)starting the rebuild. reset checksums. reset position in
    // blocks.
    if(rebuilt_size == 0) {
      epat->nerr = 0;
      for(block_index = 0; block_index < ERASURE_WIDTH; block_index++) {
        epat->src_in_err[ block_index ] = 0;
        epat->src_err_list[ block_index ] = 0;
        epat->per_rebuild_err[ block_index ] = 0;

        if( handle->erasure_state->src_in_err[block_index] == 0 ) {
          csum[block_index] = 0;
        }
        else {
          handle->csum[ block_index ] =    0;
          handle->nsz[ block_index ] =     0;
          handle->ncompsz[ block_index ] = 0;
        }
      }

      int reset_result = reset_blocks(handle,epat);
      if(reset_result == -1) {
        handle->e_ready = 0;
        free_buffers(rebuild_buffs, ERASURE_WIDTH);
        return -1; // fail the rebuild. could not seek.
      }
      else if(reset_result == 1) {
        PRINTerr( "ne_rebuild: restarting rebuild due to seek error");
        rebuilt_size = 0; // restart.
        continue;
      }
    }
    // always reset the error pattern for a new stripe, this will
    // update the stripe to reflect only permanent/per-rebuild errors
    nsrcerr = 0;
    tmp = rebuild_err_reset( epat, ERASURE_WIDTH );
    if( handle->e_ready )
      handle->e_ready = tmp;

    // try to read data from the non-corrupted files, verifies
    // checksums while reading.
    if(fill_buffers(handle, csum, epat) != 0) {
      // failed to read something. Fill_buffers took care of
      // reopening the necessary files.
      if ( epat->nerr == (handle->erasure_state->N + handle->erasure_state->E) ) {
         PRINTerr( "ne_rebuild: detected a failure to write to an output file\n" );
         return -1;
      }
      rebuilt_size = 0;
      continue;
    }

    // zero out any errors
    for(block_index = 0; block_index < ERASURE_WIDTH; block_index++) {
      if(epat->src_in_err[block_index]) {
        // Zero buffers for faulty blocks
        PRINTdbg( "ne_rebuild: zeroing data for faulty_file %d\n",
                   block_index);
        if(block_index < handle->erasure_state->N) { nsrcerr++; }
        // We don't actually care about int-crcs at this point,
        // those were verified when read.  The erasure will only
        // take place over the data blocks.
        bzero(handle->buffs[block_index], handle->erasure_state->bsz);
        bzero(rebuild_buffs[block_index], handle->erasure_state->bsz);
      }
    }

    /* Check that errors are still recoverable */
    if( epat->nerr > handle->erasure_state->E ) {
       PRINTerr("ne_rebuild: errors exceed regeneration capacity of erasure\n");
      errno = ENODATA;
      handle->e_ready = 0;
      free_buffers(rebuild_buffs, ERASURE_WIDTH);
      return -1;
    }

    /* Regenerate stripe from erasure */
    /* If necessary, initialize the erasure structures */
    if(handle->e_ready == 0) {
      // Generate encode matrix encode_matrix. The matrix generated by
      // gf_gen_rs_matrix is not always invertable.
      PRINTdbg("ne_rebuild: initializing erasure structs...\n");
      gf_gen_rs_matrix(handle->encode_matrix, handle->erasure_state->N + handle->erasure_state->E,
                       handle->erasure_state->N);

      // Generate g_tbls from encode matrix encode_matrix
      ec_init_tables(handle->erasure_state->N, handle->erasure_state->E,
                     &(handle->encode_matrix[handle->erasure_state->N * handle->erasure_state->N]),
                     handle->g_tbls);

      int decode_result = gf_gen_decode_matrix( handle->encode_matrix,
                                                handle->decode_matrix,
                                                handle->invert_matrix,
                                                decode_index,
                                                epat->src_err_list,
                                                epat->src_in_err,
                                                epat->nerr,
                                                nsrcerr,
                                                handle->erasure_state->N,
                                                handle->erasure_state->N + handle->erasure_state->E);
      if(decode_result != 0) {
        PRINTerr( "ne_rebuild: failure to generate decode matrix\n");
        errno = ENODATA;
        free_buffers(rebuild_buffs, ERASURE_WIDTH);
        return -1;
      }

      int i;
      for(i = 0; i < handle->erasure_state->N; i++) {
        handle->recov[i] = handle->buffs[decode_index[i]];
      }

      PRINTdbg( "ne_rebuild: init erasure tables nsrcerr = %d...\n", nsrcerr);
      ec_init_tables(handle->erasure_state->N, epat->nerr,
                     handle->decode_matrix, handle->g_tbls);
      handle->e_ready = 1; // indicate that rebuild structures are initialized
    }

    PRINTdbg("ne_rebuild: performing regeneration from erasure...\n" );

    ec_encode_data(handle->erasure_state->bsz, handle->erasure_state->N, epat->nerr,
                   handle->g_tbls, handle->recov, &rebuild_buffs[handle->erasure_state->N]);
    size_t size_written;
    if((size_written = write_buffers(handle, rebuild_buffs, epat)) < 0) {
      free_buffers(rebuild_buffs, ERASURE_WIDTH);
      return -1; // fail the rebuild. something went seriously wrong.
    }

    PRINTdbg( "ne_rebuild: stripe regeneration complete\n" );
    rebuilt_size += handle->erasure_state->N * handle->erasure_state->bsz;
  }

  // verify block-level crcs
  int retry = 0;
  for (block_index = 0; block_index < ERASURE_WIDTH; block_index++) {
    if(handle->erasure_state->src_in_err[block_index] == 0
       && handle->csum[block_index] != csum[block_index]) {
      PRINTerr( "ne_rebuild: mismatch of crc sum for file %d, "
                  "handle:%llu data:%llu\n", block_index,
                  (unsigned long long)handle->csum[block_index],
                  (unsigned long long)csum[block_index]);
      reopen_for_rebuild(handle, block_index,epat);
      // if we've hit a block-level crc error, we never want to trust that file again
      epat->permanent_err[ block_index ] = 1;
      epat->per_rebuild_err[ block_index ] = 1;
      update_rebuild_err( epat, block_index ); // update this, just to make the next 'early failure' check work
      retry = 1;
    }
  }

  if(retry && handle->mode != NE_STAT) {
    // protect from an infinite recursion
    if( epat->nerr > handle->erasure_state->E ) {
      PRINTerr( "ne_rebuild: errors exceed regeneration capacity of erasure\n");
      free_buffers(rebuild_buffs, ERASURE_WIDTH);
      errno = ENODATA;
      return -1;
    }
    else {
      int i;
      free_buffers(rebuild_buffs, ERASURE_WIDTH);
      return do_rebuild(handle,epat);
    }
  }

  for ( tmp = 0; tmp < handle->erasure_state->nerr; tmp++ ) {
    int block = handle->src_err_list[ tmp ];
    if( ! FD_ERR(epat->FDArray[ block ]) ) {
       HNDLOP(close, epat->FDArray[ block ]); // we don't really care if this fails
    }
  }
  free( epat );
  free_buffers(rebuild_buffs, ERASURE_WIDTH);
  return 0;
}

/**
 * Performs a rebuild operation on the erasure striping indicated by
 * the given handle.
 *
 * @param ne_handle handle : The handle for the erasure striping to be repaired
 * @return int : Status code.  0 indicates that the object was intact,
 * -1 indicates failure to rebuild, > 0 indicates that the object was
 * degraded and has been rebuilt successfully.
 */
int ne_rebuild( ne_handle handle ) {

   if ( handle == NULL ) {
      PRINTerr( "ne_rebuild: received NULL handle\n" );
      errno = EINVAL;
      return -1;
   }

   if ( handle->mode != NE_REBUILD  &&  handle->mode != NE_STAT ){
      PRINTerr( "ne_rebuild: handle is in improper mode for rebuild operation" );
      errno = EPERM;
      return -1;
   }

   //   init = 0; init should be set to 0 before entering rebuild/retry loop.
   mode_t mask = umask(0000);
   int rebuild_result = do_rebuild(handle,NULL);
   umask(mask);

   return ((rebuild_result) ? -1 : handle->erasure_state->nerr);
}


/**
 * Flushes the handle buffer of the given striping, zero filling the remainder of the stripe data.
 *
 *     Note, at present and paradoxically, this SHOULD NOT be called before
 *     the completion of a series of reads to a file.  Performing a write
 *     after a call to ne_flush WILL result in zero fill remaining within
 *     the erasure striping.
 *
 * @param ne_handle handle : Handle for the erasure striping to be flushed
 * @return int : 0 on success and -1 on failure
 */
int ne_flush( ne_handle handle ) {
   int N;
   int E;
   unsigned int bsz;
   int ret = 0;
   int tmp;
//   int counter;
//   int rem_back;
   off_t pos[ MAXPARTS ];
   unsigned char *zero_buff;

   if ( handle == NULL ) {
      PRINTerr( "ne_flush: received a NULL handle\n" );
      errno = EINVAL;
      return -1;
   }

   if ( handle->mode != NE_WRONLY ) {
      PRINTerr( "ne_flush: handle is in improper mode for writing\n" );
      errno = EINVAL;
   }

   N = handle->erasure_state->N;
   E = handle->erasure_state->E;
   bsz = handle->erasure_state->bsz;

   if ( handle->buff_rem == 0 ) {
      PRINTdbg( "ne_flush: handle buffer is empty, nothing to be done.\n" );
      return ret;
   }

//   rem_back = handle->buff_rem;
//
//   // store the seek positions for each file
//   for ( counter = 0; counter < (handle->erasure_state->N + handle->erasure_state->E); counter++ ) {
//      pos[counter] = HNDLOP(lseek, handle->FDArray[counter], 0, SEEK_CUR);
//      if ( pos[counter] == -1 ) {
//         PRINTerr( "ne_flush: failed to obtain current seek position for file %d\n", counter );
//         return -1;
//      }
//      if ( (rem_back/(handle->erasure_state->bsz)) == counter ) {
//         pos[counter] += rem_back % handle->erasure_state->bsz;
//      }
//      else if ( (rem_back/(handle->erasure_state->bsz)) > counter ) {
//         pos[counter] += handle->erasure_state->bsz;
//      }
//      fprintf(stdout, "    got seek pos for file %d as %zd ( rem = %d )\n", counter, pos[counter], rem_back );//REMOVE
//   }


   PRINTdbg( "ne_flush: flusing handle buffer...\n" );
   //zero the buffer to the end of the stripe
   tmp = (N*bsz) - handle->buff_rem;
   zero_buff = malloc(sizeof(char) * tmp);
   bzero(zero_buff, tmp );

   if ( tmp != ne_write( handle, zero_buff, tmp ) ) { //make ne_write do all the work
      PRINTerr( "ne_flush: failed to flush handle buffer\n" );
      ret = -1;
   }

//   // reset the seek positions for each file
//   for ( counter = 0; counter < (handle->erasure_state->N + handle->erasure_state->E); counter++ ) {
//      if ( HNDLOP(lseek, handle->FDArray[counter], pos[counter], SEEK_SET ) == -1 ) {
//         PRINTerr( "ne_flush: failed to reset seek position for file %d\n", counter );
//         return -1;
//      }
//      fprintf(stdout, "    set seek pos for file %d as %zd\n", counter, pos[counter] ); //REMOVE
//   }
//   handle->buff_rem = rem_back;

   //reset various handle properties
   handle->erasure_state->totsz -= tmp;
   free( zero_buff );

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

//void dump(unsigned char *buf, int len)
//{
//        int i;
//        for (i = 0; i < len;) {
//                printf(" %2x", 0xff & buf[i++]);
//                if (i % 32 == 0)
//                        printf("\n");
//        }
//        printf("\n");
//}

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
int ne_noxattr_rebuild(ne_handle handle) {
   while ( handle->erasure_state->nerr > 0 ) {
      handle->erasure_state->nerr--;
      handle->erasure_state->src_in_err[handle->src_err_list[handle->erasure_state->nerr]] = 0;
      handle->src_err_list[handle->erasure_state->nerr] = 0;
   }
   return ne_rebuild( handle ); 
}


/**
 * Retrieves the health and parameters for the erasure striping
 * indicated by the provided path and offset
 *
 * ne_status(path) calls this with fn=ne_default_snprintf, and printf_state=NULL
 *
 * @param SnprintfFunc fn : function takes block-number and <printf_state> and produces per-block path from template.
 * @param void* printf_state : optional printf_state to be used by SnprintfFunc (e.g. configuration details)
 * @param SktAuth auth : authentication may be required for RDMA uDALTypes
 * @param TimingFlagsValue flags : flags control the collection of statistics.
 * @param uDALType itype : select the underlying file-system implementation (RDMA versus POSIX).
 * @param char* path : sprintf format-template for individual files of in each stripe.
 *
 * @return nestat : Status structure containing the encoded error
 *                  pattern of the stripe (as with ne_close) as well
 *                  as the number of data parts (N), number of erasure
 *                  parts (E), and blocksize (bsz) for the stripe.
 */

ne_stat ne_status1( SnprintfFunc fn, void* printf_state,
                    uDALType itype, SktAuth auth, TimingFlagsValue timing_flags,
                    char *path )
{
   char file[MAXNAME];       /* array name of files */
   int counter;
   int ret;
#ifdef INT_CRC
   int crccount;
   unsigned int bsz = BLKSZ - sizeof( u32 );
#else
   unsigned int bsz = BLKSZ;
#endif

   ne_stat   stat   = malloc( sizeof( struct ne_stat_struct ) );
   ne_handle handle = malloc( sizeof( struct handle ) );
   if ( stat == NULL  ||  handle == NULL ) {
      PRINTerr( "ne_status: failed to allocate stat/handle structures!\n" );
      return NULL;
   }
   memset(handle, 0, sizeof(struct handle));

   handle->erasure_state = malloc( sizeof( struct ne_stat_struct ) );
   memset( handle->erasure_state, 0, sizeof( struct ne_stat_struct ) );

   handle->impl = get_impl(itype);

   // flags control collection of timing stats
   handle->timing_flags = timing_flags;
   if (timing_flags) {
      fast_timer_inits();

      // // redundant with memset() on handle
      // init_bench_stats(&handle->agg_stats);
   }
   if (handle->timing_flags & TF_HANDLE)
      fast_timer_start(&handle->handle_timer); /* start overall timer for handle */


   /* initialize stored info */
   for ( counter=0; counter < MAXPARTS; counter++ ) {
      handle->csum[counter] = 0;
      handle->nsz[counter] = 0;
      handle->ncompsz[counter] = 0;
      handle->erasure_state->src_in_err[counter] = 0;
      handle->src_err_list[counter] = 0;
      stat->data_status[counter] = 0;
      stat->xattr_status[counter] = 0;
   }
   handle->erasure_state->nerr           = 0;
   handle->erasure_state->totsz          = 0;
   handle->erasure_state->N              = 0;
   handle->erasure_state->E              = 0;
   handle->erasure_state->bsz            = 0;
   handle->erasure_state->start = 0;
   handle->mode           = NE_STAT;
   handle->e_ready        = 0;
   handle->buff_offset    = 0;
   handle->buff_rem       = 0;

   handle->snprintf = fn;
   handle->printf_state    = printf_state;
   handle->auth     = auth;

   char* nfile = malloc( strlen(path) + 1 );
   strncpy( nfile, path, strlen(path) + 1 );
   handle->erasure_state->path_fmt = nfile;

   ret = xattr_check(handle, path); // identify total data size of stripe
   if( ret == -1 ) {
      PRINTerr( "ne_status: extended attribute check has failed\n" );
      free( handle->erasure_state );
      free( handle );
      return NULL;
   }
   while ( handle->erasure_state->nerr > 0 ) {
      handle->erasure_state->nerr--;
      handle->erasure_state->src_in_err[handle->src_err_list[handle->erasure_state->nerr]] = 0;
      handle->src_err_list[handle->erasure_state->nerr] = 0;
   }

   // verify the stripe, now that values have been established
   //
   // QUEST: Is this doing anything we didn't already do in the first call?
   //      It is rereading all the MD files.  Seems expensive.
   handle->mode = NE_REBUILD;
   ret = xattr_check(handle, path);
   if ( ret == -1 ) {
      PRINTerr( "ne_status: extended attribute check has failed\n" );
      free( handle->erasure_state );
      free( handle );
      return NULL;
   }
   handle->mode = NE_STAT;

   PRINTdbg( "ne_status: Post xattr_check() -- NERR = %d, N = %d, E = %d, Start = %d, TotSz = %llu\n",
             handle->erasure_state->nerr, handle->erasure_state->N, handle->erasure_state->E, handle->erasure_state->start, handle->erasure_state->totsz );

   stat->N = handle->erasure_state->N;
   stat->E = handle->erasure_state->E;
   stat->bsz = handle->erasure_state->bsz;
   stat->totsz = handle->erasure_state->totsz;
   stat->start = handle->erasure_state->start;

   // store xattr failures to stat struct and reset error data
   for ( counter = 0; counter < ( handle->erasure_state->N + handle->erasure_state->E ); counter++ ) {
      if ( counter < handle->erasure_state->nerr ) {
         stat->xattr_status[handle->src_err_list[counter]] = 1;
         handle->src_err_list[counter] = 0;
      }
      handle->erasure_state->src_in_err[counter] = 0;
   }
   handle->erasure_state->nerr = 0;

   /* allocate a big buffer for all the N chunks plus a bit extra for reading in crcs */
#ifdef INT_CRC
   crccount = 1;
   if ( handle->erasure_state->E > 0 )
      crccount = handle->erasure_state->E;

   // add space for intermediate checksum
   ret = posix_memalign( &(handle->buffer), 64,
                         ((handle->erasure_state->N+handle->erasure_state->E)*bsz) + (sizeof(u32)*crccount) );
   PRINTdbg("ne_stat: Allocated handle buffer of size %zd for bsz=%d, N=%d, E=%d\n",
            ((handle->erasure_state->N+handle->erasure_state->E)*bsz) + (sizeof(u32)*crccount),
            handle->erasure_state->bsz, handle->erasure_state->N, handle->erasure_state->E);
#else
   ret = posix_memalign( &(handle->buffer), 64,
                         ((handle->erasure_state->N+handle->erasure_state->E)*bsz) );
   PRINTdbg("ne_stat: Allocated handle buffer of size %d for bsz=%d, N=%d, E=%d\n",
            (handle->erasure_state->N+handle->erasure_state->E)*bsz, handle->erasure_state->bsz, handle->erasure_state->N, handle->erasure_state->E);
#endif
   if ( ret != 0 ) {
      PRINTerr( "ne_status: failed to allocate handle buffer\n" );
      errno = ret;
      return NULL;
   }

   /* allocate matrices */
   handle->encode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->decode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->invert_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->g_tbls = malloc(MAXPARTS * MAXPARTS * 32);


   /* verify that we can open all the files:
      loop through and open up all the input data-files, initilize per part info, and allocate buffers */
   counter = 0;
   PRINTdbg( "ne_status: opening file descriptors...\n" );
   while ( counter < (handle->erasure_state->N+handle->erasure_state->E) ) {
      bzero( file, MAXNAME );
      handle->snprintf( file, MAXNAME, path, (counter+handle->erasure_state->start)%(handle->erasure_state->N+handle->erasure_state->E), handle->printf_state );

#ifdef INT_CRC
      if ( counter > handle->erasure_state->N ) {
         crccount = counter - handle->erasure_state->N;
         handle->buffs[counter] = handle->buffer + ( counter*bsz ) + ( crccount * sizeof(u32) ); //make space for block and erasure crc
      }
      else {
         handle->buffs[counter] = handle->buffer + ( counter*bsz ); //make space for block
      }
#else
      handle->buffs[counter] = handle->buffer + ( counter*bsz ); //make space for block
#endif

      PRINTdbg( "ne_status:    opening %s for read\n", file );
      OPEN(handle->FDArray[counter], handle, file, O_RDONLY);

      if ( FD_ERR(handle->FDArray[counter])  &&  handle->erasure_state->src_in_err[counter] == 0 ) {
         PRINTerr( "ne_status:    failed to open file %s!\n", file );
         handle->src_err_list[handle->erasure_state->nerr] = counter;
         handle->erasure_state->nerr++;
         handle->erasure_state->src_in_err[counter] = 1;
         counter++;

         continue;
      }

      counter++;
   }

   if ( ne_rebuild( handle ) < 0 ) {
      PRINTerr( "ne_status: rebuild indicates that data is unrecoverable\n" );
   }

   // store data failures to stat struct
   for ( counter = 0; counter < handle->erasure_state->nerr; counter++ ) {
      stat->data_status[handle->src_err_list[counter]] = 1;
   }


   /* Close file descriptors and free bufs */
   PRINTdbg( "ne_status: closing file descriptors...\n" );
   counter = 0;
   while (counter < (handle->erasure_state->N+handle->erasure_state->E) ) {

      if ( handle->erasure_state->src_in_err[counter] == 0  &&  ! FD_ERR(handle->FDArray[counter]) ) {
        HNDLOP(close, handle->FDArray[counter]);
      }

      counter++;
   }

   PRINTdbg( "ne_status: freeing ...\n" );
   free(handle->buffer);
   free(handle->encode_matrix);
   free(handle->decode_matrix);
   free(handle->invert_matrix);
   free(handle->g_tbls);

   if (timing_flags & TF_HANDLE) {
      fast_timer_stop(&handle->handle_timer);
      show_handle_stats(handle);
   }
   free(handle->erasure_state->path_fmt);
   free( handle->erasure_state );
   free(handle);

   PRINTdbg( "ne_status: done.\n" );
   return stat;
}

ne_stat ne_status(char *path) {

   // this is safe for builds with/without sockets and/or socket-authentication enabled
   // However, if you do build with socket-authentication, this will require a read
   // from a file (~/.awsAuth) that should probably only be accessible if ~ is /root.
   SktAuth  auth;
   if (DEFAULT_AUTH_INIT(auth)) {
      PRINTerr("failed to initialize default socket-authentication credentials\n");
      return NULL;
   }

   return ne_status1(ne_default_snprintf, NULL, UDAL_POSIX, auth, 0, path);
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
   OPEN( fd, handle, meta_file, O_WRONLY | O_CREAT, 0666 );

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

   OPEN( fd, handle, path, O_RDONLY );
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

   OPEN( fd, handle, meta_file_path, O_RDONLY );
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

   OPEN( fd, handle, path, O_RDONLY );
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
  char xattrval[1024];
  sprintf(xattrval,"%d %d %d %d %lu %lu %llu %llu",
          handle->erasure_state->N, handle->erasure_state->E, handle->erasure_state->start,
          handle->erasure_state->bsz, handle->nsz[block],
          handle->ncompsz[block], (unsigned long long)handle->csum[block],
          (unsigned long long)handle->erasure_state->totsz);

  PRINTdbg( "ne_close: setting file %d xattr = \"%s\"\n",
            block, xattrval );

  char block_file_path[2048];
  handle->snprintf(block_file_path, MAXNAME, handle->erasure_state->path_fmt,
                   (block+handle->erasure_state->start)%(handle->erasure_state->N + handle->erasure_state->E),
                   handle->printf_state);

   if ( handle->mode == NE_REBUILD )
      strncat( block_file_path, REBUILD_SFX, strlen(REBUILD_SFX)+1 );
   else if ( handle->mode == NE_WRONLY )
      strncat( block_file_path, WRITE_SFX, strlen(WRITE_SFX)+1 );
   

   if (handle->timing_flags & TF_XATTR)
      fast_timer_start(&handle->stats[block].xattr);

   int rc = ne_set_xattr1(handle->impl, handle->auth, block_file_path, xattrval, strlen(xattrval));

   if (handle->timing_flags & TF_XATTR)
      fast_timer_stop(&handle->stats[block].xattr);

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
