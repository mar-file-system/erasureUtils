#include <erasure.h>

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#if (AXATTR_RES == 2)
#  include <attr/xattr.h>
#else
#  include <sys/xattr.h>
#endif
#include <assert.h>
#include <pthread.h>

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
 
/********************************************************/
/*

This file provides the implementation of multiple operations intended for use by the MarFS MultiComponent DAL.

These include:   ne_read(), ne_write(), ne_health(), and ne_rebuild().

Additionally, each output file gets an xattr added to it  (yes all 12 files in the case of a 10+2
the xattr looks like this
n.e.offset.blocksize.nsz.ncompsz.ncrcsum.totsz: 10 2 64 0 196608 196608 3304199718723886772 1717171
N is nparts, E is numerasure, offset is the starting position of the stripe in terms of part number, chunksize is chunksize, nsz is the size of the part, ncompsz is the size of the part but might get used if we ever compress the parts, totsz is the total real data in the N part files.
Since creating erasure requires full stripe writes, the last part of the file may all be zeros in the parts.  This totsz is the real size of the data, not counting the trailing zeros.
All the parts and all the erasure stripes should be the same size.
To fill in the trailing zeros, this program uses truncate - punching a hole in the N part files for the zeros.

*********************************************************/

/* The following are defined here, so as to hide them from users of the library */
#ifdef HAVE_LIBISAL
extern uint32_t crc32_ieee(uint32_t seed, uint8_t * buf, uint64_t len);
extern void ec_encode_data(int len, int srcs, int dests, unsigned char *v,unsigned char **src, unsigned char **dest);
#else
extern uint32_t crc32_ieee_base(uint32_t seed, uint8_t * buf, uint64_t len);
extern void ec_encode_data_base(int len, int srcs, int dests, unsigned char *v,unsigned char **src, unsigned char **dest);
#endif
extern void pq_gen_sse(int, int, void*);  /* assembler routine to use sse to calc p and q */
extern void xor_gen_sse(int, int, void*);  /* assembler routine to use sse to calc p */
extern int pq_check_sse(int, int, void*);  /* assembler routine to use sse to calc p */
extern int xor_check_sse(int, int, void*);  /* assembler routine to use sse to calc p */
extern void gf_gen_rs_matrix(unsigned char *a, int m, int k);
extern void gf_vect_mul_init(unsigned char c, unsigned char *tbl);
extern unsigned char gf_mul(unsigned char a, unsigned char b);
extern int gf_invert_matrix(unsigned char *in_mat, unsigned char *out_mat, const int n);

int xattr_check( ne_handle handle, char *path );
void ec_init_tables(int k, int rows, unsigned char *a, unsigned char *g_tbls);
static int gf_gen_decode_matrix(unsigned char *encode_matrix,
				unsigned char *decode_matrix,
				unsigned char *invert_matrix,
				unsigned int *decode_index,
				unsigned char *src_err_list,
				unsigned char *src_in_err,
				int nerrs, int nsrcerrs, int k, int m);
//void dump(unsigned char *buf, int len);

// check for an incomplete write of an object
int incomplete_write( ne_handle handle ) {
   char fname[MAXNAME];
   int i;
   int err_cnt = 0;

   for( i = 0; i < handle->nerr; i++ ) {
      int block = handle->src_err_list[i];
      snprintf( fname, MAXNAME, handle->path, (handle->erasure_offset + block) % ( (handle->N) ? (handle->N + handle->E) : MAXPARTS ) );
      strcat( fname, WRITE_SFX );
      
      struct stat st;
      // check for a partial data-file
      if( stat( fname, &st ) == 0 ) {
         return 1;
      }
      else {
         //check for a partial meta-file
         strcat( fname, META_SFX );
         if( stat( fname, &st ) == 0 ) return 1;
         err_cnt++;
      }
   }

   return 0;
}

void bq_destroy(BufferQueue *bq) {
  // XXX: Should technically check these for errors (ie. still locked)
  pthread_mutex_destroy(&bq->qlock);
  pthread_cond_destroy(&bq->full);
  pthread_cond_destroy(&bq->empty);
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
  bq->file         = -1;
  bq->buffer_size  = handle->bsz;
  bq->handle       = handle;
  bq->offset       = 0;

  if(pthread_mutex_init(&bq->qlock, NULL)) {
    DBG_FPRINTF(stderr, "failed to initialize mutex for qlock\n");
    return -1;
  }
  if(pthread_cond_init(&bq->full, NULL)) {
    DBG_FPRINTF(stderr, "failed to initialize cv for full\n");
    // should also destroy the mutex
    pthread_mutex_destroy(&bq->qlock);
    return -1;
  }
  if(pthread_cond_init(&bq->empty, NULL)) {
    DBG_FPRINTF(stderr, "failed to initialize cv for empty\n");
    pthread_mutex_destroy(&bq->qlock);
    pthread_cond_destroy(&bq->full);
    return -1;
  }

  return 0;
}

void bq_signal(BufferQueue*bq, BufferQueue_Flags sig) {
  pthread_mutex_lock(&bq->qlock);
  bq->flags |= sig;
  pthread_cond_signal(&bq->full);
  pthread_mutex_unlock(&bq->qlock);  
}

void bq_close(BufferQueue *bq) {
  bq_signal(bq, BQ_FINISHED);
}

void bq_abort(BufferQueue *bq) {
  bq_signal(bq, BQ_ABORT);
}

static int set_block_xattr(ne_handle handle, int block) {
  int tmp = 0;
  char xattrval[1024];
  sprintf(xattrval,"%d %d %d %d %lu %lu %llu %llu",
          handle->N, handle->E, handle->erasure_offset,
          handle->bsz, handle->nsz[block],
          handle->ncompsz[block], (unsigned long long)handle->csum[block],
          (unsigned long long)handle->totsz);
  DBG_FPRINTF( stdout, "ne_close: setting file %d xattr = \"%s\"\n",
               block, xattrval );

#ifdef META_FILES
  char meta_file[2048];
  sprintf( meta_file, handle->path,
           (block+handle->erasure_offset)%(handle->N+handle->E) );
  if ( handle->mode == NE_REBUILD ) {
    strncat( meta_file, REBUILD_SFX, strlen(REBUILD_SFX)+1 );
  }
  else if ( handle->mode == NE_WRONLY ) {
    strncat( meta_file, WRITE_SFX, strlen(WRITE_SFX)+1 );
  }
  strncat( meta_file, META_SFX, strlen(META_SFX) + 1 );
  mode_t mask = umask(0000);
  int fd = open( meta_file, O_WRONLY | O_CREAT, 0666 );
  umask(mask);
  if ( fd < 0 ) { 
    DBG_FPRINTF(stderr, "ne_close: failed to open file %s\n", meta_file);
    tmp = -1;
  }
  else {
    int val = write( fd, xattrval, strlen(xattrval) + 1 );
    if ( val != strlen(xattrval) + 1 ) {
      DBG_FPRINTF(stderr, "ne_close: failed to write to file %s\n",
                  meta_file);
      tmp = -1;
      close( fd );
    }
    else {
      tmp = close( fd );
    }
  }
  chown(meta_file, handle->owner, handle->group);
#else

#warn "xattr metadata is not functional with new thread model"
#if (AXATTR_SET_FUNC == 5) // XXX: not functional with threads!!!
  tmp = fsetxattr(handle->FDArray[counter], XATTRKEY, xattrval,
                  strlen(xattrval), 0);
#else
  tmp = fsetxattr(handle->FDArray[counter], XATTRKEY, xattrval,
                  strlen(xattrval), 0, 0);
#endif

#endif //META_FILES
  return tmp;
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

  // open the file.
  bq->file = open(bq->path, O_WRONLY|O_CREAT, 0666);

  if(pthread_mutex_lock(&bq->qlock) != 0) {
    exit(-1); // XXX: is this the appropriate response??
  }
  if(bq->file == -1) {
    bq->flags |= BQ_ERROR;
  }
  else {
    bq->flags |= BQ_OPEN;
  }
  pthread_cond_signal(&bq->empty);
  pthread_mutex_unlock(&bq->qlock);

  DBG_FPRINTF(stdout, "bq_writer: opened file %d in thread %x\n", bq->block_number, pthread_self());
  
  while(1) {
    if((error = pthread_mutex_lock(&bq->qlock)) != 0) {
      DBG_FPRINTF(stderr, "failed to lock queue lock: %s\n", strerror(error));
      // XXX: This is a FATAL error
      return (void *)-1;
    }

    while(bq->qdepth == 0 && !(bq->flags & BQ_FINISHED) || bq->flags & BQ_ABORT) {
      DBG_FPRINTF(stdout, "bq_writer[%d]: waiting for signal from ne_write\n", bq->block_number);
      pthread_cond_wait(&bq->full, &bq->qlock);
    }

    if(bq->flags & BQ_ABORT) {
      DBG_FPRINTF(stderr, "aborting buffer queue\n");
      if(close(bq->file) == 0) {
        unlink(bq->path); // try to clean up after ourselves.
      }
      pthread_mutex_unlock(&bq->qlock);
      return NULL;
    }
    if(bq->qdepth == 0 && bq->flags & BQ_FINISHED) {       // then we are done.
      break;
    }
    
    if(!(bq->flags & BQ_ERROR)) {
      pthread_mutex_unlock(&bq->qlock);
      if(written >= SYNC_SIZE) {
        fsync(bq->file);
        written = 0;
      }
      DBG_FPRINTF(stdout, "Writing block %d\n", bq->block_number);
      u32 crc   = crc32_ieee(TEST_SEED, bq->buffers[bq->head], bq->buffer_size);
      error     = write(bq->file, bq->buffers[bq->head], bq->buffer_size);
#ifdef INT_CRC
      error    += write(bq->file, &crc, sizeof(u32)); // XXX: super small write... could degrade performance
#endif
      bq->csum += crc;
      pthread_mutex_lock(&bq->qlock);
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
    DBG_FPRINTF(stdout, "write done for block %d\n", bq->block_number);
    // even if there was an error, say we wrote the block and move on.
    // the producer thread is responsible for checking the error flag
    // and killing us if needed.
    bq->head = (bq->head + 1) % MAX_QDEPTH;
    bq->qdepth--;

    pthread_cond_signal(&bq->empty);
    pthread_mutex_unlock(&bq->qlock);
  }

  pthread_mutex_unlock(&bq->qlock);

  // close the file and terminate if any errors were encountered
  if( close(bq->file)  ||  bq->flags & BQ_ERROR ) {
    bq->flags |= BQ_ERROR; // ensure the error was noted
    return NULL; // don't bother trying to rename
  }

  handle->csum[bq->block_number] = bq->csum;
  if(set_block_xattr(bq->handle, bq->block_number) != 0) {
    bq->flags |= BQ_ERROR;
    // if we failed to set the xattr, don't bother with the rename.
    return NULL;
  }
  char block_file_path[2048];
  sprintf( block_file_path, handle->path,
           (bq->block_number+handle->erasure_offset)%(handle->N+handle->E) );
  if( rename( bq->path, block_file_path ) != 0 ) {
    DBG_FPRINTF( stderr, "ne_close: failed to rename written file %s\n", bq->path );
    bq->flags |= BQ_ERROR;
  }
#ifdef META_FILES
  strncat( bq->path, META_SFX, strlen(META_SFX)+1 );
  strncat( block_file_path, META_SFX, strlen(META_SFX)+1 );
  if ( rename( bq->path, block_file_path ) != 0 ) {
    DBG_FPRINTF( stderr, "ne_close: failed to rename written meta file %s\n", bq->path );
    bq->flags |= BQ_ERROR;
  }
#endif
  return NULL;
}

/**
 * Initialize the buffer queues for the handle and start the threads.
 *
 * @return -1 on failure, 0 on success.
 */
static int initialize_queues(ne_handle handle) {
  int i;
  int num_blocks = handle->N + handle->E;

  /* allocate buffers */
  for(i = 0; i < MAX_QDEPTH; i++) {
    int error = posix_memalign(&handle->buffer_list[i], 64,
                               num_blocks * handle->bsz);
    if(error == -1) {
      int j;
      // clean up previously allocated buffers and fail.
      // we can't recover from this error.
      for(j = i-1; j >= 0; j--) { free(handle->buffer_list[j]); }
      return -1;
    }
  }

  /* open files and initialize BufferQueues */
  for(i = 0; i < num_blocks; i++) {
    int error, file_descriptor;
    char path[2048];
    BufferQueue *bq = &handle->blocks[i];
    // generate the path
    sprintf(bq->path, handle->path, (i + handle->erasure_offset) % num_blocks);
    strcat(bq->path, WRITE_SFX);

    // assign pointers into the memaligned buffers.
    void *buffers[MAX_QDEPTH];
    int j;
    for(j = 0; j < MAX_QDEPTH; j++) {
      buffers[j] = handle->buffer_list[j] + i * handle->bsz;
    }
    
    if(bq_init(bq, i, buffers, handle) < 0) {
      // TODO: handle error.
      return -1;
    }

    // start the threads
    error = pthread_create(&handle->threads[i], NULL, bq_writer, (void *)bq);
    if(error != 0) {
      DBG_FPRINTF(stderr, "failed to start thread\n");
      return -1;
      // TODO: clean up!!
    }
  }

  /* create the buff_list in the handle. */
  for(i = 0; i < MAX_QDEPTH; i++) {
    int j;
    for(j = 0; j < num_blocks; j++) {
      handle->block_buffs[i][j] = handle->buffer_list[i] + j * handle->bsz;
    }
  }

  // check for errors on open...
  for(i = 0; i < num_blocks; i++) {
    DBG_FPRINTF(stdout, "Checking for error opening block %d\n", i);
    BufferQueue *bq = &handle->blocks[i];
    pthread_mutex_lock(&bq->qlock);
    // wait for the queue to be ready.
    while(!(bq->flags & BQ_OPEN) && !(bq->flags & BQ_ERROR))
      pthread_cond_wait(&bq->empty, &bq->qlock);
    if(bq->flags & BQ_ERROR) {
      DBG_FPRINTF(stderr, "open failed for block %d", i);
      handle->src_in_err[i] = 1;
      handle->src_err_list[handle->nerr] = i;
      handle->nerr++;
    }
    pthread_mutex_unlock(&bq->qlock);
  }

  return 0;
}

int bq_enqueue(BufferQueue *bq, void *buf, size_t size) {
  int ret = 0;

  if((ret = pthread_mutex_lock(&bq->qlock)) != 0) {
    DBG_FPRINTF(stderr, "Failed to lock queue for write\n");
    errno = ret;
    return -1;
  }

  while(bq->qdepth == MAX_QDEPTH)
    pthread_cond_wait(&bq->empty, &bq->qlock);

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
    DBG_FPRINTF(stdout, "saved incomplete buffer for block %d\n", bq->block_number);
    bq->offset += size;
  }
  else {
    bq->offset = 0;
    bq->qdepth++;
    bq->tail = (bq->tail + 1) % MAX_QDEPTH;
    if(bq->flags & BQ_ERROR) {
      ret = 1;
    }
    DBG_FPRINTF(stdout, "queued complete buffer for block %d\n", bq->block_number);
    pthread_cond_signal(&bq->full);
  }
  pthread_mutex_unlock(&bq->qlock);

  return ret;
}

/**
 * Opens a new handle for a specific erasure striping
 * @param char* path : Name structure for the files of the desired striping.  This should contain a single "%d" field.
 * @param ne_mode mode : Mode in which the file is to be opened.  Either NE_RDONLY, NE_WRONLY, or NE_REBUILD.
 * @param int erasure_offset : Offset of the erasure stripe, defining the name of the first N file
 * @param int N : Data width of the striping
 * @param int E : Erasure width of the striping
 * @return ne_handle : The new handle for the opened erasure striping
 */
ne_handle ne_open( char *path, ne_mode mode, ... )
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
      DBG_FPRINTF( stdout, "ne_open: NE_SETBSZ flag detected\n");
   }
   if ( mode & NE_NOINFO ) {
      counter -= 3;
      mode -= NE_NOINFO;
      DBG_FPRINTF( stdout, "ne_open: NE_NOINFO flag detected\n");
   }

   // Parse variadic arguments
   va_list ap;
   va_start( ap, mode );
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
   va_end( ap );

   if ( mode == NE_WRONLY  &&  counter < 2 ) {
      DBG_FPRINTF( stderr, "ne_open: recieved an invalid \"NE_NOINFO\" flag for \"NE_WRONLY\" operation\n");
      errno = EINVAL;
      return NULL;
   }

#ifdef INT_CRC
   //shrink data size to fit crc within block
   bsz -= sizeof( u32 );
#endif

   ne_handle handle = malloc( sizeof( struct handle ) );

   if ( counter > 1 ) {
      if ( N < 1  ||  N > MAXN ) {
         DBG_FPRINTF( stderr, "ne_open: improper N arguement received - %d\n", N );
         errno = EINVAL;
         return NULL;
      }
      if ( E < 0  ||  E > MAXE ) {
         DBG_FPRINTF( stderr, "ne_open: improper E arguement received - %d\n", E );
         errno = EINVAL;
         return NULL;
      }
      if ( erasure_offset < 0  ||  erasure_offset >= N+E ) {
         DBG_FPRINTF( stderr, "ne_open: improper erasure_offset arguement received - %d\n", erasure_offset );
         errno = EINVAL;
         return NULL;
      }
   }
   if ( bsz < 0  ||  bsz > MAXBLKSZ ) {
      DBG_FPRINTF( stderr, "ne_open: improper bsz arguement received - %d\n", bsz );
      errno = EINVAL;
      return NULL;
   }

   /* initialize stored info */
   handle->nerr = 0;
   handle->totsz = 0;
   handle->N = N;
   handle->E = E;
   handle->bsz = bsz;
   handle->erasure_offset = erasure_offset;
   if ( counter < 2 ) {
      handle->mode = NE_STAT;
      DBG_FPRINTF( stdout, "ne_open: temporarily setting mode to NE_STAT\n");
   }
   else {
      handle->mode = mode;
   }
   handle->e_ready = 0;
   handle->buff_offset = 0;
   handle->buff_rem = 0;

   for ( counter=0; counter < MAXPARTS; counter++ ) {
      handle->csum[counter] = 0;
      handle->nsz[counter] = 0;
      handle->ncompsz[counter] = 0;
      handle->written[counter] = 0;
      handle->src_in_err[counter] = 0;
      handle->src_err_list[counter] = 0;
   }

   char* nfile = malloc( strlen(path) + 1 );
   strncpy( nfile, path, strlen(path) + 1 );
   handle->path = nfile;

   if ( mode == NE_REBUILD  ||  mode == NE_RDONLY ) {
      ret = xattr_check(handle,path); //idenfity total data size of stripe
      if ( ret == 0  &&  handle->mode == NE_STAT ) {
         handle->mode = mode;
         DBG_FPRINTF( stdout, "ne_open: resetting mode to %d\n", mode);
         while ( handle->nerr > 0 ) {
            handle->nerr--;
            handle->src_in_err[handle->src_err_list[handle->nerr]] = 0;
            handle->src_err_list[handle->nerr] = 0;
         }
         ret = xattr_check(handle,path); //perform the check again, identifying mismatched values
      }

      DBG_FPRINTF( stdout, "ne_open: Post xattr_check() -- NERR = %d, N = %d, E = %d, Start = %d, TotSz = %llu\n", handle->nerr, handle->N, handle->E, handle->erasure_offset, handle->totsz );

      if ( ret != 0 ) {
         if( incomplete_write( handle ) ) { errno = ENOENT; return NULL; }
         DBG_FPRINTF( stderr, "ne_open: extended attribute check has failed\n" );
         free( handle );
         errno = ENODATA;
         return NULL;
      }

   }
   else if ( mode != NE_WRONLY ) { //reject improper mode arguments
      DBG_FPRINTF( stderr, "improper mode argument received - %d\n", mode );
      errno = EINVAL;
      free( handle );
      return NULL;
   }

   N = handle->N;
   E = handle->E;
   bsz = handle->bsz;
   erasure_offset = handle->erasure_offset;
   DBG_FPRINTF( stdout, "ne_open: using stripe values (N=%d,E=%d,bsz=%d,offset=%d)\n", N,E,bsz,erasure_offset);

   if(handle->mode == NE_WRONLY) { // first cut: mutlti-threading only for writes.
     if(initialize_queues(handle) < 0) {
       // all destroction/cleanup should be handled in initialize_queues()
       free(handle);
       errno = ENOMEM;
       return NULL;
     }
     if( UNSAFE(handle) ) {
       int i;
       for(i = 0; i < handle->N + handle->E; i++) {
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
     if ( E > 0 ) { crccount = E; }

     ret = posix_memalign( &(handle->buffer), 64, ((N+E)*bsz) + (sizeof(u32)*crccount) ); //add space for intermediate checksum
     DBG_FPRINTF(stdout,"ne_open: Allocated handle buffer of size %zd for bsz=%d, N=%d, E=%d\n", ((N+E)*bsz) + (sizeof(u32)*crccount), bsz, N, E);
#else
     ret = posix_memalign( &(handle->buffer), 64, ((N+E)*bsz) );
     DBG_FPRINTF(stdout,"ne_open: Allocated handle buffer of size %zd for bsz=%d, N=%d, E=%d\n", (N+E)*bsz, bsz, N, E);
#endif
     if ( ret != 0 ) {
       DBG_FPRINTF( stderr, "ne_open: failed to allocate handle buffer\n" );
       errno = ENOMEM;
       return NULL;
     }

        /* loop through and open up all the output files and initilize per part info and allocate buffers */
     counter = 0;
     DBG_FPRINTF( stdout, "opening file descriptors...\n" );
     mode_t mask = umask(0000);
     while ( counter < N+E ) {
       bzero( file, MAXNAME );
       sprintf( file, path, (counter+erasure_offset)%(N+E) );
       
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
         DBG_FPRINTF( stdout, "   opening %s%s for write\n", file, WRITE_SFX );
         handle->FDArray[counter] = open( strncat( file, WRITE_SFX, strlen(WRITE_SFX)+1 ), O_WRONLY | O_CREAT, 0666 );
       }
       else if ( mode == NE_REBUILD  &&  handle->src_in_err[counter] == 1 ) {
         DBG_FPRINTF( stdout, "   opening %s%s for write\n", file, REBUILD_SFX );
         handle->FDArray[counter] = open( strncat( file, REBUILD_SFX, strlen(REBUILD_SFX)+1 ), O_WRONLY | O_CREAT, 0666 );
         
       }
       else {
         DBG_FPRINTF( stdout, "   opening %s for read\n", file );
         handle->FDArray[counter] = open( file, O_RDONLY );
       }
       
       if ( handle->FDArray[counter] == -1  &&  handle->src_in_err[counter] == 0 ) {
         DBG_FPRINTF( stderr, "   failed to open file %s (%s)!!!!\n", file,
                      strerror(errno));
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
         handle->src_in_err[counter] = 1;
         if ( handle->nerr > E ) { //if errors are unrecoverable, terminate
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


/**
 * Reads nbytes of data at offset from the erasure striping referenced by the given handle
 * @param ne_handle handle : Handle referencing the desired erasure striping
 * @param void* buffer : Memory location in which to store the retrieved data
 * @param int nbytes : Integer number of bytes to be read
 * @param off_t offset : Offset within the data at which to begin the read
 * @return int : The number of bytes read or -1 on a failure
 */
int ne_read( ne_handle handle, void *buffer, int nbytes, off_t offset ) 
{
   int mtot = (handle->N)+(handle->E);
   int minNerr = handle->N+1;  // greater than N
   int maxNerr = -1;   // less than N
   int nsrcerr = 0;
   int counter;
   char firststripe;
   char firstchunk;
   char error_in_stripe;
   unsigned char *temp_buffs[ MAXPARTS ];
   int N = handle->N;
   int E = handle->E;
   unsigned int bsz = handle->bsz;
   int nerr = 0;
   unsigned long datasz[ MAXPARTS ] = {0};
   long ret_in;
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

   if ( handle->mode != NE_RDONLY ) {
      DBG_FPRINTF( stderr, "ne_read: handle is in improper mode for reading!\n" );
      errno = EPERM;
      return -1;
   }

   if ( (offset + nbytes) > handle->totsz ) {
      DBG_FPRINTF(stdout,"ne_read: read would extend beyond EOF, resizing read request...\n");
      nbytes = handle->totsz - offset;
      if ( nbytes <= 0 ) {
         DBG_FPRINTF( stderr, "ne_read: offset is beyond filesize\n" );
         return 0;
      }
   }

   llcounter = 0;
   tmpoffset = 0;

   //check stripe cache
   if ( offset >= handle->buff_offset  &&  offset < (handle->buff_offset + handle->buff_rem) ) {
      seekamt = offset - handle->buff_offset;
      readsize = ( nbytes > (handle->buff_rem - seekamt) ) ? (handle->buff_rem - seekamt) : nbytes;
      DBG_FPRINTF( stdout, "ne_read: filling request for first %lu bytes from cache with offset %zd in buffer...\n", (unsigned long) readsize, seekamt );
      memcpy( buffer, handle->buffer + seekamt, readsize );
      llcounter += readsize;
   }

   //if entire request was cached, nothing remains to be done
   if ( llcounter == nbytes ) { return llcounter; }


   //determine min/max errors and allocate temporary buffers
   for ( counter = 0; counter < mtot; counter++ ) {
      tmp = posix_memalign((void **)&(temp_buffs[counter]),64,bsz);
      if ( tmp != 0 ) {
         DBG_FPRINTF( stderr, "ne_read: failed to allocate temporary data buffer\n" );
         errno = tmp;
         return -1;
      }
      if ( handle->src_in_err[counter] ) {
         nerr++;
         if ( counter < N ) { 
            nsrcerr++;
            if ( counter > maxNerr ) { maxNerr = counter; }
            if ( counter < minNerr ) { minNerr = counter; }
         }
      }
   }

   if ( handle->nerr != nerr ) {
      DBG_FPRINTF( stderr, "ne_read: iconsistent internal state : handle->nerr and handle->src_in_err\n" );
      errno = ENOTRECOVERABLE;
      return -1;
   }


   /******** Rebuild While Reading ********/
read:

   startstripe = (offset+llcounter) / (bsz*N);
   startpart = (offset + llcounter - (startstripe*bsz*N))/bsz;
   startoffset = offset+llcounter - (startstripe*bsz*N) - (startpart*bsz);

   DBG_FPRINTF(stdout,"ne_read: read with rebuild from startstripe %d startpart %d and startoffset %d for nbytes %d\n",startstripe,startpart,startoffset,nbytes);

   counter = 0;

   endchunk = ((offset+nbytes) - (startstripe*N*bsz) ) / bsz;
   int stop = endchunk;

   if ( endchunk > N ) {
      endchunk = N;
      stop = mtot - 1;
   }     

   /**** set seek positions for initial reading ****/
   if (startpart > maxNerr  ||  endchunk < minNerr ) {  //if not reading from corrupted chunks, we can just set these normally
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
         if( handle->src_in_err[counter] == 0 ) {
            if ( counter >= N ) {
#ifdef INT_CRC
               seekamt += ( bsz+sizeof(u32) );
#else
               seekamt += bsz;
#endif

               DBG_FPRINTF(stdout,"seeking erasure file e%d to %zd, as we will be reading from the next stripe\n",counter-N, seekamt);
            }
            else {
               DBG_FPRINTF(stdout,"seeking input file %d to %zd, as there is no error in this stripe\n",counter, seekamt);
            }

            tmp = lseek(handle->FDArray[counter],seekamt,SEEK_SET);

            //if we hit an error here, seek positions are wrong and we must restart
            if ( tmp != seekamt ) {
               if ( counter > maxNerr )  maxNerr = counter;
               if ( counter < minNerr )  minNerr = counter;
               handle->src_in_err[counter] = 1;
               handle->src_err_list[handle->nerr] = counter;
               handle->nerr++;
               nsrcerr++;
               handle->e_ready = 0; //indicate that erasure structs require re-initialization
               goto read; //if another error is encountered, start over
            }

         }
      }
      tmpchunk = startpart;
      tmpoffset = startoffset;
      error_in_stripe = 0;
   }
   else {  //if not, we will require the entire stripe for rebuild
      DBG_FPRINTF(stdout,"startpart = %d, endchunk = %d\n   This stipe contains corrupted blocks...\n", startpart, endchunk);
      while (counter < mtot) {
         if( handle->src_in_err[counter] == 0 ) {

#ifdef INT_CRC
            tmp = lseek(handle->FDArray[counter],(startstripe*( bsz+sizeof(u32) )),SEEK_SET);
#else
            tmp = lseek(handle->FDArray[counter],(startstripe*bsz),SEEK_SET);
#endif

            //note any errors, no need to restart though
            if ( tmp < 0 ) {
               if ( counter > maxNerr )  maxNerr = counter;
               if ( counter < minNerr )  minNerr = counter;
               handle->src_in_err[counter] = 1;
               handle->src_err_list[handle->nerr] = counter;
               handle->nerr++;
               nsrcerr++;
               handle->e_ready = 0; //indicate that erasure structs require re-initialization
               counter++;
               continue;
            }
#ifdef INT_CRC
            DBG_FPRINTF(stdout,"seek input file %d to %lu, to read entire stripe\n",counter, (unsigned long)(startstripe*( bsz+sizeof(u32) )));
#else
            DBG_FPRINTF(stdout,"seek input file %d to %lu, to read entire stripe\n",counter, (unsigned long)(startstripe*bsz));
#endif
         }
         counter++;
      }

      tmpchunk = 0;
      tmpoffset = 0;
      error_in_stripe = 1;
      //handle->e_ready = 0; //test
   }

   firstchunk = 1;
   firststripe = 1;
   out_off = llcounter;

   /**** output each data stipe, regenerating as necessary ****/
   while ( llcounter < nbytes ) {

      handle->buff_offset = (offset+llcounter);
      handle->buff_rem = 0;

      for ( counter = 0; counter < N; counter++ ) {
         datasz[counter] = 0;
      }

      endchunk = ((long)(offset+nbytes) - (long)( (offset + llcounter) - ((offset+llcounter)%(N*bsz)) ) ) / bsz;

      DBG_FPRINTF( stdout, "ne_read: endchunk unadjusted - %d\n", endchunk );
      if ( endchunk >= N ) {
         endchunk = N - 1;
      }

      DBG_FPRINTF(stdout,"ne_read: endchunk adjusted - %d\n", endchunk);
      if ( endchunk < minNerr ) {
         DBG_FPRINTF(stdout, "ne_read: there is no error in this stripe\n");
         error_in_stripe = 0;
      }

      /**** read data into buffers ****/
      for( counter=tmpchunk; counter < N; counter++ ) {

         if ( llcounter == nbytes  &&  error_in_stripe == 0 ) {
            DBG_FPRINTF(stdout, "ne_read: data reads complete\n");
            break;
         }

         readsize = bsz-tmpoffset;

         if ( handle->src_in_err[counter] == 1 ) {  //this data chunk is invalid
            DBG_FPRINTF(stdout,"ne_read: ignoring data for faulty chunk %d\n",counter);
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
               llcounter += (readsize - (startoffset-tmpoffset) < (nbytes-llcounter) ) ? readsize-(startoffset-tmpoffset) : (nbytes-llcounter);
               datasz[counter] = llcounter - out_off;
               firstchunk = 0;
            }
            // ensure that the stripe is flagged as having an error.
            error_in_stripe = 1;
         }
         else {    //this data chunk is valid, store it
            if ( (nbytes-llcounter) < readsize  &&  error_in_stripe == 0 ) {
               readsize = nbytes-llcounter;
            }

#ifdef INT_CRC
            DBG_FPRINTF(stdout,"ne_read: read %lu from datafile %d\n", bsz+sizeof(crc), counter);
#else
            DBG_FPRINTF(stdout,"ne_read: read %d from datafile %d\n",readsize,counter);
#endif

#ifdef INT_CRC
            ret_in = read( handle->FDArray[counter], handle->buffs[counter], bsz+sizeof(crc) );
            ret_in -= (sizeof(u32)+tmpoffset);
#else
            ret_in = read( handle->FDArray[counter], handle->buffs[counter], readsize );
#endif

            //check for a read error
            if ( ret_in < readsize ) {

               if ( ret_in < 0  ||  handle->nerr < handle->E ) {
                  DBG_FPRINTF(stderr, "ne_read: error encountered while reading data file %d\n", counter);
                  if ( counter > maxNerr )  maxNerr = counter;
                  if ( counter < minNerr )  minNerr = counter;
                  handle->src_in_err[counter] = 1;
                  handle->src_err_list[handle->nerr] = counter;
                  handle->nerr++;
                  nsrcerr++;
                  handle->e_ready = 0; //indicate that erasure structs require re-initialization
                  ret_in = 0;
                  counter--;
                  //if this is the first encountered error for the stripe, we must start over
                  if ( error_in_stripe == 0 ) {
                     for( tmp = counter; tmp >=0; tmp-- ) {
                        llcounter -= datasz[tmp];
                     }
                     DBG_FPRINTF( stdout, "ne_read: restarting stripe read, reset total read to %lu\n", (unsigned long)llcounter);
                     goto read;
                  }
                  continue;
               }
               else {
                  nbytes = llcounter + ret_in;
                  DBG_FPRINTF(stderr, "ne_read: inputs exhausted, limiting read to %d bytes\n",nbytes);
               }

               DBG_FPRINTF(stderr, "ne_read: failed to read all requested data from file %d\n", counter);
               DBG_FPRINTF(stdout,"ne_read: zeroing missing data for %d from %lu to %d\n",counter,ret_in,bsz);

               bzero(handle->buffs[counter]+ret_in,bsz-ret_in);

            }
#ifdef INT_CRC
            else {
               //calculate and verify crc
               crc = crc32_ieee( TEST_SEED, handle->buffs[counter], bsz );
               if ( memcmp( handle->buffs[counter]+bsz, &crc, sizeof(u32) ) != 0 ){
                  DBG_FPRINTF(stderr, "ne_read: mismatch of int-crc for file %d while reading with rebuild\n", counter);
                  if ( counter > maxNerr )  maxNerr = counter;
                  if ( counter < minNerr )  minNerr = counter;
                  handle->src_in_err[counter] = 1;
                  handle->src_err_list[handle->nerr] = counter;
                  handle->nerr++;
                  nsrcerr++;
                  handle->e_ready = 0; //indicate that erasure structs require re-initialization
                  counter--;
                  ret_in = 0;
                  //if this is the first encountered error for the stripe, we must start over
                  if ( error_in_stripe == 0 ) {
                     for( tmp = counter; tmp >=0; tmp-- ) {
                        llcounter -= datasz[tmp];
                     }
                     DBG_FPRINTF( stdout, "ne_read: restarting stripe read, reset total read to %lu\n", (unsigned long)llcounter);
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
      while ( counter < mtot  &&  error_in_stripe == 1 ) {

#ifdef INT_CRC
         readsize = bsz+sizeof(u32);
#else
         readsize = bsz; //may want to limit later
#endif

         if ( handle->src_in_err[counter] == 0 ) {
            DBG_FPRINTF(stdout,"ne_read: reading %d from erasure %d\n",readsize,counter);
            ret_in = read( handle->FDArray[counter], handle->buffs[counter], readsize );
            if ( ret_in < readsize ) {
               if ( ret_in < 0 ) {
                  ret_in = 0;
               }

               handle->src_in_err[counter] = 1;
               handle->src_err_list[handle->nerr] = counter;
               handle->nerr++;
               handle->e_ready = 0; //indicate that erasure structs require re-initialization
               error_in_stripe = 1;
               DBG_FPRINTF(stderr, "ne_read: failed to read all erasure data in file %d\n", counter);
               DBG_FPRINTF(stdout,"ne_read: zeroing data for faulty erasure %d from %lu to %d\n",counter,ret_in,bsz);
               bzero(handle->buffs[counter]+ret_in,bsz-ret_in);
               DBG_FPRINTF(stdout,"ne_read: zeroing temp_data for faulty erasure %d\n",counter);
               bzero(temp_buffs[counter],bsz);
               DBG_FPRINTF(stdout,"ne_read: done zeroing %d\n",counter);
            }
#ifdef INT_CRC
            else {
               //calculate and verify crc
               crc = crc32_ieee( TEST_SEED, handle->buffs[counter], bsz );
               if ( memcmp( handle->buffs[counter]+bsz, &crc, sizeof(u32) ) != 0 ){
                  DBG_FPRINTF(stderr, "ne_read: mismatch of int-crc for file %d (erasure)\n", counter);
                  if ( counter > maxNerr )  maxNerr = counter;
                  if ( counter < minNerr )  minNerr = counter;
                  handle->src_in_err[counter] = 1;
                  handle->src_err_list[handle->nerr] = counter;
                  handle->nerr++;
                  nsrcerr++;
                  handle->e_ready = 0; //indicate that erasure structs require re-initialization
                  error_in_stripe = 1;
               }
            }
#endif
         }
         else {
            DBG_FPRINTF( stdout, "ne_read: ignoring data for faulty erasure %d\n", counter );
         }
         counter++;
      }

      /**** regenerate from erasure ****/
      if ( error_in_stripe == 1 ) {

         /* If necessary, initialize the erasure structures */
         if ( handle->e_ready == 0 ) {
            // Generate encode matrix encode_matrix
            // The matrix generated by gf_gen_rs_matrix
            // is not always invertable.
            DBG_FPRINTF(stdout,"ne_read: initializing erasure structs...\n");
            gf_gen_rs_matrix(handle->encode_matrix, mtot, N);

            // Generate g_tbls from encode matrix encode_matrix
            ec_init_tables(N, E, &(handle->encode_matrix[N * N]), handle->g_tbls);

            ret_in = gf_gen_decode_matrix( handle->encode_matrix, handle->decode_matrix,
                  handle->invert_matrix, decode_index, handle->src_err_list, handle->src_in_err,
                  handle->nerr, nsrcerr, N, mtot);

            if (ret_in != 0) {
               DBG_FPRINTF(stderr,"ne_read: failure to generate decode matrix, errors may exceed erasure limits\n");
               errno=ENODATA;
               return -1;
            }

            for (tmp = 0; tmp < N; tmp++) {
               handle->recov[tmp] = handle->buffs[decode_index[tmp]];
            }

            DBG_FPRINTF( stdout, "ne_read: init erasure tables nsrcerr = %d e_ready = %d...\n", nsrcerr, handle->e_ready );
            ec_init_tables(N, handle->nerr, handle->decode_matrix, handle->g_tbls);

            handle->e_ready = 1; //indicate that rebuild structures are initialized
         }
         DBG_FPRINTF( stdout, "ne_read: performing regeneration from erasure...\n" );

         ec_encode_data(bsz, N, handle->nerr, handle->g_tbls, handle->recov, &temp_buffs[N]);
      }

      /**** write appropriate data out ****/
      for( counter=startpart, tmp=0; counter <= endchunk; counter++ ) {
         readsize = datasz[counter];

#ifdef DEBUG
         if ( readsize+out_off > llcounter ) {
           fprintf(stderr,"ne_read: out_off + readsize(%lu) > llcounter at counter = %d!!!\n",(unsigned long)readsize,counter);
           return -1;
         }
#endif

         if ( handle->src_in_err[counter] == 0 ) {
            DBG_FPRINTF( stdout, "ne_read: performing write of %d from chunk %d data\n", readsize, counter );

#ifdef INT_CRC
            if ( firststripe  &&  counter == startpart )
#else
            if ( firststripe  &&  counter == startpart  &&  error_in_stripe )
#endif
            {
               DBG_FPRINTF( stdout, "ne_read:   with offset of %d\n", startoffset );
               memcpy( buffer+out_off, (handle->buffs[counter])+startoffset, readsize );
            }
            else {
               memcpy( buffer+out_off, handle->buffs[counter], readsize );
            }
         }
         else {

            for ( tmp = 0; counter != handle->src_err_list[tmp]; tmp++ ) {
               if ( tmp == handle->nerr ) {
                  DBG_FPRINTF( stderr, "ne_read: improperly definded erasure structs, failed to locate %d in src_err_list\n", tmp );
                  errno = ENOTRECOVERABLE;
                  return -1;
               }
            }

            if ( firststripe == 0  ||  counter != startpart ) {
               DBG_FPRINTF( stdout, "ne_read: performing write of %d from regenerated chunk %d data, src_err = %d\n", readsize, counter, handle->src_err_list[tmp] );
               memcpy( buffer+out_off, temp_buffs[N+tmp], readsize );
            }
            else {
               DBG_FPRINTF( stdout, "ne_read: performing write of %d from regenerated chunk %d data with offset %d, src_err = %d\n", readsize, counter, startoffset, handle->src_err_list[tmp] );
               memcpy( buffer+out_off, (temp_buffs[N+tmp])+startoffset, readsize );
            }

         } //end of src_in_err = true block

         out_off += readsize;

      } //end of output loop for stipe data

      if ( out_off != llcounter ) {
         DBG_FPRINTF( stderr, "ne_read: internal mismatch : llcounter (%lu) and out_off (%zd)\n", (unsigned long)llcounter, out_off );
         errno = ENOTRECOVERABLE;
         return -1;
      }

      firststripe=0;
      tmpoffset = 0; tmpchunk = 0; startpart=0;

   } //end of generating loop for each stripe

   if ( error_in_stripe == 1 ) {
      handle->buff_offset -= ( handle->buff_offset % (N*bsz) );
   }

   //copy regenerated blocks and note length of cached stripe
   for ( counter = 0; counter < mtot; counter++ ) {
      if ( error_in_stripe == 1  &&  counter < N ) {
         if ( handle->src_in_err[counter] == 1 ) {
            for ( tmp = 0; counter != handle->src_err_list[tmp]; tmp++ ) {
               if ( tmp == handle->nerr ) {
                  DBG_FPRINTF( stderr, "ne_read: improperly definded erasure structs, failed to locate %d in src_err_list while caching\n", tmp );
                  mtot=0;
                  tmp=0;
                  handle->buff_rem -= bsz; //just to offset the later addition
                  break;
               }
            }
            DBG_FPRINTF( stdout, "ne_read: caching %d from regenerated chunk %d data, src_err = %d\n", bsz, counter, handle->src_err_list[tmp] );
            memcpy( handle->buffs[counter], temp_buffs[N+tmp], bsz );
         }
         handle->buff_rem += bsz;
      }
      else if ( counter < N ) { handle->buff_rem += datasz[counter]; }
      free(temp_buffs[counter]);
   }

   DBG_FPRINTF( stdout, "ne_read: cached %lu bytes from stripe at offset %zd\n", handle->buff_rem, handle->buff_offset );

   return llcounter; 
}

void sync_file(ne_handle handle, int block_index) {
#if 0
  char path[1024];
  int block_number = (handle->erasure_offset + block_index)
    % (handle->N + handle->E);
  sprintf(path, handle->path, block_number);
  strcat(path, WRITE_SFX);
  close(handle->FDArray[block_index]);
  handle->FDArray[block_index] = open(path, O_WRONLY);
  if(handle->FDArray[block_index] == -1) {
    DBG_FPRINTF(stderr, "failed to reopen file\n");
    handle->src_in_err[block_index] = 1;
    handle->src_err_list[handle->nerr] = block_index;
    handle->nerr++;
    return;
  }

  off_t seek = lseek(handle->FDArray[block_index],
                     handle->written[block_index],
                     SEEK_SET);
  if(seek < handle->written[block_index]) {
    DBG_FPRINTF(stderr, "failed to seek reopened file\n");
    handle->src_in_err[block_index] = 1;
    handle->src_err_list[handle->nerr] = block_index;
    handle->nerr++;
    close(handle->FDArray[block_index]);
    return;
  }
#else
  fsync(handle->FDArray[block_index]);
#endif
}


/**
 * Writes nbytes from buffer into the erasure stiping specified by the provided handle
  * @param ne_handle handle : Handle for the erasure striping to be written to
 * @param void* buffer : Buffer containing the data to be written
 * @param int nbytes : Number of data bytes to be written from buffer
 * @return int : Number of bytes written or -1 on error
 */
int ne_write( ne_handle handle, void *buffer, size_t nbytes )
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

   if ( handle-> mode != NE_WRONLY  &&  handle->mode != NE_REBUILD ) {
      DBG_FPRINTF( stderr, "ne_write: handle is in improper mode for writing!\n" );
      errno = EPERM;
      return -1;
   }

   N = handle->N;
   E = handle->E;
   bsz = handle->bsz;

   mtot=N+E;


   /* loop until the file input or stream input ends */
   totsize = 0;
   while (1) { 

      counter = handle->buff_rem / bsz;
      /* loop over the parts and write the parts, sum and count bytes per part etc. */
      while (counter < N) {

        writesize = ( handle->buff_rem % bsz ); // ? The amount of data being written to the block (block size - whatever has already been written).
         readsize = bsz - writesize; // readsize is the amount of data being read for block[block_index] from the source buffer

         //avoid reading beyond end of buffer
         if ( totsize + readsize > nbytes ) { readsize = nbytes-totsize; }

         if ( readsize < 1 ) {
            DBG_FPRINTF(stdout,"ne_write: reading of input is now complete\n");
            break;
         }

         DBG_FPRINTF( stdout, "ne_write: reading input for %lu bytes with offset of %llu\n          and writing to offset of %lu in handle buffer\n", (unsigned long)readsize, totsize, handle->buff_rem );
         
         //memcpy ( handle->buffer + handle->buff_rem, buffer+totsize, readsize);
         int queue_result = bq_enqueue(&handle->blocks[counter], buffer+totsize, readsize);
         if(queue_result == -1) {
           // bq_enqueue will set errno.
           return -1;
         }
         else if(queue_result != 0 && !handle->src_in_err[counter]) {
           handle->src_in_err[counter] = 1;
           handle->src_err_list[handle->nerr] = counter;
           handle->nerr++;
         }
         
         DBG_FPRINTF(stdout, "ne_write:   ...copy complete.\n");
         
         totsize += readsize;
         writesize = readsize + ( handle->buff_rem % bsz );
         handle->buff_rem += readsize;

         if ( writesize < bsz ) {  //if there is not enough data to write a full block, stash it in the handle buffer
            DBG_FPRINTF(stdout,"ne_write: reading of input is complete, stashed %lu bytes in handle buffer\n", (unsigned long)readsize);
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
      if ( handle->e_ready == 0 ) {
         DBG_FPRINTF(stdout, "ne_write: initializing erasure matricies...\n");
         // Generate encode matrix encode_matrix
         // The matrix generated by gf_gen_rs_matrix]
         // is not always invertable.
         gf_gen_rs_matrix(handle->encode_matrix, mtot, N);
         // Generate g_tbls from encode matrix encode_matrix
         ec_init_tables(N, E, &(handle->encode_matrix[N * N]), handle->g_tbls);

         handle->e_ready = 1;
      }

      DBG_FPRINTF(stdout, "ne_write: caculating %d recovery stripes from %d data stripes\n",E,N);
      // Perform matrix dot_prod for EC encoding
      // using g_tbls from encode matrix encode_matrix
      // Need to lock the two buffers here.
      int i;
      int buffer_index;
      for(i = N; i < handle->N + handle->E; i++) {
        BufferQueue *bq = &handle->blocks[i];
        if(pthread_mutex_lock(&bq->qlock) != 0) {
          DBG_FPRINTF(stderr, "Failed to acquire lock for erasure blocks\n");
          return -1;
        }
        while(bq->qdepth == MAX_QDEPTH) {
          pthread_cond_wait(&bq->empty, &bq->qlock);
        }
        if(i == N) {
          buffer_index = bq->tail;
        }
        else {
          assert(buffer_index == bq->tail);
        }
      }
      ec_encode_data(bsz, N, E, handle->g_tbls, (unsigned char **)handle->block_buffs[buffer_index], (unsigned char **)&(handle->block_buffs[buffer_index][N]));

      for(i = N; i < handle->N + handle->E; i++) {
        BufferQueue *bq = &handle->blocks[i];
        bq->qdepth++;
        bq->tail = (bq->tail + 1) % MAX_QDEPTH;
        pthread_cond_signal(&bq->full);
        pthread_mutex_unlock(&bq->qlock);
        handle->nsz[i] += bsz;
        handle->ncompsz[i] += bsz;
      }

      //now that we have written out all data, reset buffer
      handle->buff_rem = 0; 
   }
   handle->totsz += totsize; //as it is impossible to write at an offset, the sum of writes will be the total size

   // If the errors exceed the minimum protection threshold number of
   // errrors then fail the write.
   if( UNSAFE(handle) ) {
     DBG_FPRINTF(stderr,
                 "ne_write: errors exceed minimum protection level (%d)\n",
                 MIN_PROTECTION);
     errno = EIO;
     return -1;
   }
   else {
     return totsize;
   }
}

/**
 * Closes the erasure striping indicated by the provided handle and flushes the handle buffer, if necessary.
 * @param ne_handle handle : Handle for the striping to be closed
 * @return int : Status code.  Success is indicated by 0 and failure by -1.  A positive value indicates that the operation was sucessful, 
 *               but that errors were encountered in the stipe.  The Least-Significant Bit of the return code corresponds to the first of 
 *               the N data stripe files, while each subsequent bit corresponds to the next N files and then the E files.  A 1 in these 
 *               positions indicates that an error was encountered while acessing that specific file.
 *               Note, this code does not account for the offset of the stripe.  The code will be relative to the file names only.
 *               (i.e. an error in "<output_path>1<output_path>" would be encoded in the second bit of the output, a decimal value of 2)
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
#ifdef META_FILES
   int val;
   int fd;
#endif
   unsigned char *zero_buff;


   if ( handle == NULL ) {
      DBG_FPRINTF( stderr, "ne_close: received a NULL handle\n" );
      errno = EINVAL;
      return -1;
   }
   N = handle->N;
   E = handle->E;
   bsz = handle->bsz;


   /* flush the handle buffer if necessary */
   if ( handle->mode == NE_WRONLY  &&  handle->buff_rem != 0 ) {
      DBG_FPRINTF( stdout, "ne_close: flusing handle buffer...\n" );
      //zero the buffer to the end of the stripe
      tmp = (N*bsz) - handle->buff_rem;
      zero_buff = malloc(sizeof(char) * tmp);
      bzero(zero_buff, tmp );

      if ( tmp != ne_write( handle, zero_buff, tmp ) ) { //make ne_write do all the work
         DBG_FPRINTF( stderr, "ne_close: failed to flush handle buffer\n" );
         ret = -1;
      }

      handle->totsz -= tmp;
      free( zero_buff );
   }

   /* Close file descriptors and free bufs and set xattrs for written files */
   counter = 0;
   while (counter < N+E) {

     if (handle->mode == NE_REBUILD && handle->src_in_err[counter] == 1 ) {
         // if mode is NE_WRONLY this will be handled by the BQ thread.
         if(set_block_xattr(handle, counter) != 0) {
           if(handle->src_in_err[counter] == 0) {
             handle->src_in_err[counter] = 1;
             handle->src_err_list[handle->nerr] = counter;
             handle->nerr++;
           }
         }
         sprintf( file, handle->path, (counter+handle->erasure_offset)%(N+E) );
         strncpy( nfile, file, strlen(file) + 1);
         strncat( file, REBUILD_SFX, strlen(REBUILD_SFX) + 1 );

         if ( handle->e_ready == 1 ) {

            chown(file, handle->owner, handle->group);
            if ( rename( file, nfile ) != 0 ) {
               DBG_FPRINTF( stderr, "ne_close: failed to rename rebuilt file\n" );
               // rebuild should fail even if only one file can't be renamed
               ret = -1;
            }

#ifdef META_FILES
            strncat( file, META_SFX, strlen(META_SFX)+1 );
            strncat( nfile, META_SFX, strlen(META_SFX)+1 );
            if ( rename( file, nfile ) != 0 ) {
               DBG_FPRINTF( stderr, "ne_close: failed to rename rebuilt meta file\n" );
               // rebuild should fail even if only one file can't be renamed
               ret = -1;
            }
#endif

         }
         else{

            DBG_FPRINTF( stderr, "ne_close: cleaning up file %s from failed rebuild\n", file );
            unlink( file );
#ifdef META_FILES
            strncat( file, META_SFX, strlen(META_SFX)+1 );
            DBG_FPRINTF( stderr, "ne_close: cleaning up file %s from failed rebuild\n", file );
            unlink( file );
#endif

         }
      }

      if (handle->mode == NE_WRONLY ) {
        bq_close(&handle->blocks[counter]);
      }
      else if(handle->FDArray[counter] != -1) {
         if(close(handle->FDArray[counter]) != 0
            && handle->src_in_err[counter]  == 0) {
            // If the close fails mark the block as errored.
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
         }
      }

      counter++;
   }

   if(handle->mode == NE_WRONLY) {
     int i;
     /* wait for the threads */
     for(i = 0; i < handle->N + handle->E; i++) {
       pthread_join(handle->threads[i], NULL);
       /* add up the errors */
       if((handle->blocks[i].flags & BQ_ERROR) && !handle->src_in_err[i]) {
         handle->src_in_err[i] = 1;
         handle->src_err_list[handle->nerr] = i;
         handle->nerr++;
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

   if( (UNSAFE(handle) && handle->mode == NE_WRONLY) || (handle->nerr > handle->E) /* for non-writes */) {
     ret = -1;
   }

   if ( ret == 0 ) {
      DBG_FPRINTF( stdout, "ne_close: encoding error pattern in return value...\n" );
      /* Encode any file errors into the return status */
      for( counter = 0; counter < N+E; counter++ ) {
         if ( handle->src_in_err[counter] ) { ret += ( 1 << ((counter + handle->erasure_offset) % (N+E)) ); }
      }
   }

   if ( handle->path != NULL ) {
      free(handle->path);
   }

   free(handle->encode_matrix);
   free(handle->decode_matrix);
   free(handle->invert_matrix);
   free(handle->g_tbls);
   free(handle);
   
   return ret;

}


/**
 * Determines whether the parent directory of the given file exists
 * @param char* path : Character string to be searched
 * @param int max_length : Maximum length of the character string to be scanned
 * @return int : 0 if the parent directory does exist and -1 if not
 */
int parent_dir_missing( char* path, int max_length ) {
   char* tmp = path;
   int len = 0;
   int index = -1;
   struct stat status;
   int res;

   while ( len < max_length  &&  *tmp != '\0' ) {
      if( *tmp == '/' ) index = len;
      len++;
      tmp++;
   }
   
   tmp = path;
   *(tmp + index) = '\0';
   res = stat( tmp, &status );
   DBG_FPRINTF( stdout, "parent_dir_missing: stat of \"%s\" returned %d\n", path, res );
   *(tmp + index) = '/';

   return res;
}


/**
 * Deletes the erasure striping of the specified width with the specified path format
 * @param char* path : Name structure for the files of the desired striping.  This should contain a single "%d" field.
 * @param int width : Total width of the erasure striping (i.e. N+E)
 * @return int : 0 on success and -1 on failure
 */
int ne_delete( char* path, int width ) {
   char file[MAXNAME];       /* array name of files */
   char partial[MAXNAME];
   int counter;
   int ret = 0;
   int parent_missing;
   
   for( counter=0; counter<width; counter++ ) {
      parent_missing = -2;
      bzero( file, sizeof(file) );
      sprintf( file, path, counter );
      sprintf( partial, path, counter );
      strncat( partial, WRITE_SFX, MAXNAME );
      // unlink the file or the unfinished file.  If both fail, check if the parent directory exists.  If not, indicate an error.
      if ( ( unlink( file )  &&  unlink( partial ) )  &&  (parent_missing = parent_dir_missing(file, MAXNAME)) ) ret = -1;
#ifdef META_FILES
      strncat( file, META_SFX, MAXNAME );
      strncat( partial, META_SFX, MAXNAME );
      // same as the above, but only stat the parent dir if we haven't already verified that it exists
      if ( unlink( file )  &&  unlink( partial ) ) {
         if( parent_missing == -2 ) parent_missing = parent_dir_missing(file, MAXNAME);
         if( parent_missing ) ret = -1;
      }
#endif
   }

   return ret;
}


off_t ne_size( const char* path, int quorum, int max_stripe_width ) {
   char ptemplate[MAXNAME];
   char file[MAXNAME];
   char xattrval[XATTRLEN];

   if( max_stripe_width < 1 ) max_stripe_width = MAXPARTS;
   if( quorum < 1 ) quorum = max_stripe_width;
   if( quorum > max_stripe_width ) {
      DBG_FPRINTF( stderr, "ne_size: received a quorum value greater than the max_stripe_width\n" );
      errno = EINVAL;
      return -1;
   }

   strncpy( ptemplate, path, MAXNAME );

#ifdef META_FILES
   strncat( ptemplate, META_SFX, strlen(META_SFX)+1 );
#endif

   int match = 0;
   off_t sizes_reported[max_stripe_width];
   off_t prev_size = -1;
   int i;
   for( i = 0; i < max_stripe_width  &&  match < quorum; i++ ) {
      sprintf( file, ptemplate, i );

#ifdef META_FILES

      DBG_FPRINTF(stdout,"ne_size: opening file %s\n", file);
      int meta_fd = open( file, O_RDONLY );
      if ( meta_fd >= 0 ) {
         int tmp = read( meta_fd, &xattrval[0], XATTRLEN );
         if ( tmp < 0 ) {
            DBG_FPRINTF(stderr,"ne_size: failed to read from file %s\n", file);
            continue;
         }
         else if(tmp == 0) {
            DBG_FPRINTF(stderr, "ne_size: read 0 bytes from metadata file %s\n", file);
            continue;
         }
         tmp = close( meta_fd );
         if ( tmp < 0 ) {
            DBG_FPRINTF(stderr,"ne_size: failed to close file %s\n", file);
            continue;
         }
      }
      else {
         DBG_FPRINTF(stderr,"ne_size: failed to open file %s\n", file);
         continue;
      }

#else

#if (AXATTR_GET_FUNC == 4)
      if( getxattr(file,XATTRKEY,&xattrval[0],XATTRLEN) ) continue;
#else
      if( getxattr(file,XATTRKEY,&xattrval[0],XATTRLEN,0,0) ) continue;
#endif

#endif //META_FILES

      DBG_FPRINTF( stdout, "ne_size: file %s xattr returned %s\n", file, xattrval );
      
      sscanf( xattrval, "%*s %*s %*s %*s %*s %*s %*s %zd", &sizes_reported[i] );

      if ( prev_size == -1  ||  sizes_reported[i] == prev_size ) {
         match++;
      }
      else { 
         match = 1;
         int k;
         for( k = 0; k < i; k++ ) {
            if( sizes_reported[k] == sizes_reported[i] ) match++;
         }
      }

      prev_size = sizes_reported[i];
   }

   if( prev_size == -1 ) { errno = ENOENT; return -1; }
   if( match < quorum ) { errno = ENODATA; return -1; }
   return prev_size;
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
   int filefd;
   char xattrval[XATTRLEN];
   char xattrchunks[20];       /* char array to get n parts from xattr */
   char xattrchunksizek[20];   /* char array to get chunksize from xattr */
   char xattrnsize[20];        /* char array to get total size from xattr */
   char xattrerasure[20];      /* char array to get erasure from xattr */
   char xattroffset[20];      /* char array to get erasure_offset from xattr */
   char xattrncompsize[20];    /* general char for xattr manipulation */
   char xattrnsum[50];         /* char array to get xattr sum from xattr */
   char xattrtotsize[160];
   int N = handle->N;
   int E = handle->E;
   int erasure_offset = handle->erasure_offset;
   unsigned int bsz = handle->bsz;
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

   for ( counter = 0; counter < lN+lE; counter++ ) {
      bzero(file,sizeof(file));
      sprintf( file, path, (counter+handle->erasure_offset)%(lN+lE) );
      ret = stat( file, partstat );
      handle->csum[counter]=0; //reset csum to make results clearer
      DBG_FPRINTF( stdout, "xattr_check: stat of file %s returns %d\n", file, ret );
      if ( ret != 0 ) {
         DBG_FPRINTF( stderr, "xattr_check: file %s: failure of stat\n", file );
         handle->src_in_err[counter] = 1;
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
         continue;
      }
      handle->owner = partstat->st_uid;
      handle->group = partstat->st_gid;
      bzero(xattrval,sizeof(xattrval));

#ifdef META_FILES

      sprintf( nfile, handle->path, (counter+handle->erasure_offset)%(N+E) );
      strncat( nfile, META_SFX, strlen(META_SFX)+1 );
      DBG_FPRINTF(stdout,"xattr_check: opening file %s\n",nfile);
      int meta_fd = open( nfile, O_RDONLY );
      if ( meta_fd >= 0 ) {
         tmp = read( meta_fd, &xattrval[0], sizeof(xattrval) );
         if ( tmp < 0 ) {
            DBG_FPRINTF(stderr,"xattr_check: failed to read from file %s\n",nfile);
            ret = tmp;
         }
         else if(tmp == 0) {
           DBG_FPRINTF(stderr, "xattr_check: read 0 bytes from metadata file %s\n", nfile);
           ret = -1;
         }
         tmp = close( meta_fd );
         if ( tmp < 0 ) {
            DBG_FPRINTF(stderr,"xattr_check: failed to close file %s\n",nfile);
            ret = tmp;
         }
      }
      else {
         ret = -1;
         DBG_FPRINTF(stderr,"xattr_check: failed to open file %s\n",nfile);
      }

#else

#if (AXATTR_GET_FUNC == 4)
      ret = getxattr(file,XATTRKEY,&xattrval[0],sizeof(xattrval));
#else
      ret = getxattr(file,XATTRKEY,&xattrval[0],sizeof(xattrval),0,0);
#endif

#endif //META_FILES

      if (ret < 0) {
         DBG_FPRINTF(stderr, "xattr_check: failure of xattr retrieval for file %s\n", file);
         handle->src_in_err[counter] = 1;
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
         continue;
      }
      DBG_FPRINTF(stdout,"xattr_check: file %d (%s) xattr returned \"%s\"\n",counter,file,xattrval);

      sscanf(xattrval,"%s %s %s %s %s %s %s %s",xattrchunks,xattrerasure,xattroffset,xattrchunksizek,xattrnsize,xattrncompsize,xattrnsum,xattrtotsize);
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

      if ( handle->mode != NE_STAT ) { //branch skips checks involving uninitialized handle values (i.e. for stat)

         /* verify xattr */
         if ( N != handle->N ) {
            DBG_FPRINTF (stderr, "xattr_check: filexattr N = %d did not match handle value  %d\n", N, handle->N); 
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }
         else if ( E != handle->E ) {
            DBG_FPRINTF (stderr, "xattr_check: filexattr E = %d did not match handle value  %d\n", E, handle->E); 
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }
         else if ( bsz != handle->bsz ) {
            DBG_FPRINTF (stderr, "xattr_check: filexattr bsz = %d did not match handle value  %d\n", bsz, handle->bsz); 
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }
         else if ( erasure_offset != handle->erasure_offset ) {
            DBG_FPRINTF (stderr, "xattr_check: filexattr offset = %d did not match handle value  %d\n", erasure_offset, handle->erasure_offset); 
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }

      }

#ifdef INT_CRC
      if ( ( nsz + (blocks*sizeof(crc)) ) != partstat->st_size )
#else
      if ( nsz != partstat->st_size )
#endif
      {
         DBG_FPRINTF (stderr, "xattr_check: filexattr nsize = %lu did not match stat value %zd (possible missing internal crcs)\n", nsz, partstat->st_size); 
         handle->src_in_err[counter] = 1;
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
         continue;
      }
      else if ( (nsz % bsz) != 0 ) {
         DBG_FPRINTF (stderr, "xattr_check: filexattr nsize = %lu is inconsistent with block size %d \n", nsz, bsz); 
         handle->src_in_err[counter] = 1;
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
         continue;
      }
      else if ( (N + E) <= erasure_offset ) {
         DBG_FPRINTF (stderr, "xattr_check: filexattr offset = %d is inconsistent with stripe width %d\n", erasure_offset, (N+E)); 
         handle->src_in_err[counter] = 1;
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
         continue;
      }
#ifdef INT_CRC
      else if ( ( ncompsz + (blocks*sizeof(crc)) ) != partstat->st_size )
#else
      else if ( ncompsz != partstat->st_size )
#endif
      {
         DBG_FPRINTF (stderr, "xattr_check: filexattr ncompsize = %lu did not match stat value %zd (possible missing crcs)\n", ncompsz, partstat->st_size); 
         handle->src_in_err[counter] = 1;
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
         continue;
      }
      else if ( ((ncompsz * N) - totsz) >= bsz*N ) {
         DBG_FPRINTF (stderr, "xattr_check: filexattr total_size = %llu is inconsistent with ncompsz %lu\n", (unsigned long long)totsz, ncompsz); 
         handle->src_in_err[counter] = 1;
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
         continue;
      }
      else {
         DBG_FPRINTF( stdout, "setting csum for file %d to %llu\n", counter, (unsigned long long)csum);
         handle->csum[counter] = csum;
         if ( handle->mode == NE_RDONLY ) {
            if( ! handle->totsz ) handle->totsz = totsz; //only set the file size if it is not already set (i.e. by a call with mode=NE_STAT)
            break;
         }

         // This bundle of spaghetti acts to individually verify each "important" xattr value and count matches amongst all files
         char nc = 1, ec = 1, of = 1, bc = 1, tc = 1;
         if ( handle->mode != NE_STAT ) { nc = 0; ec = 0; of = 0; bc = 0; } //if these values are already initialized, skip setting them
         for ( bcounter = 0; ( nc || ec || bc || tc || of )  &&  bcounter < MAXPARTS; bcounter++ ) {
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

      } //end of else at end of xattr checks


   } //end of loop over files

   free(partstat);
   ret = 0;

   if ( handle->mode != NE_RDONLY ) { //if the handle is uninitialized, store the necessary info

      int maxmatch=0;
      int match=-1;
      //loop through the counts of matching xattr values and identify the most prevalent match
      for ( bcounter = 0; bcounter < MAXPARTS; bcounter++ ) {
         if ( totsz_match[bcounter] > maxmatch ) { maxmatch = totsz_match[bcounter]; match = bcounter; }
         if ( bcounter > 0 && N_match[bcounter] > 0 ) { ret = 1; }
      }

      if ( match != -1 ) {
         handle->totsz = totsz_list[match];
      }
      else {
         DBG_FPRINTF( stderr, "xattr_check: failed to locate any matching totsz xattr vals!\n" );
         errno = ENODATA;
         return -1;
      }

      if ( handle->mode == NE_STAT ) {
         maxmatch=0;
         match=-1;
         //loop through the counts of matching xattr values and identify the most prevalent match
         for ( bcounter = 0; bcounter < MAXPARTS; bcounter++ ) {
            if ( N_match[bcounter] > maxmatch ) { maxmatch = N_match[bcounter]; match = bcounter; }
            if ( bcounter > 0 && N_match[bcounter] > 0 ) { ret = 1; }
         }

         if ( match != -1 ) {
            handle->N = N_list[match];
         }
         else {
            DBG_FPRINTF( stderr, "xattr_check: failed to locate any matching N xattr vals!\n" );
            errno = ENODATA;
            return -1;
         }

         maxmatch=0;
         match=-1;
         //loop through the counts of matching xattr values and identify the most prevalent match
         for ( bcounter = 0; bcounter < MAXPARTS; bcounter++ ) {
            if ( E_match[bcounter] > maxmatch ) { maxmatch = E_match[bcounter]; match = bcounter; }
            if ( bcounter > 0 && N_match[bcounter] > 0 ) { ret = 1; }
         }

         if ( match != -1 ) {
            handle->E = E_list[match];
         }
         else {
            DBG_FPRINTF( stderr, "xattr_check: failed to locate any matching E xattr vals!\n" );
            errno = ENODATA;
            return -1;
         }

         maxmatch=0;
         match=-1;
         //loop through the counts of matching xattr values and identify the most prevalent match
         for ( bcounter = 0; bcounter < MAXPARTS; bcounter++ ) {
            if ( O_match[bcounter] > maxmatch ) { maxmatch = O_match[bcounter]; match = bcounter; }
            if ( bcounter > 0 && N_match[bcounter] > 0 ) { ret = 1; }
         }

         if ( match != -1 ) {
            handle->erasure_offset = O_list[match];
         }
         else {
            DBG_FPRINTF( stderr, "xattr_check: failed to locate any matching offset xattr vals!\n" );
            errno = ENODATA;
            return -1;
         }

         maxmatch=0;
         match=-1;
         //loop through the counts of matching xattr values and identify the most prevalent match
         for ( bcounter = 0; bcounter < MAXPARTS; bcounter++ ) {
            if ( bsz_match[bcounter] > maxmatch ) { maxmatch = bsz_match[bcounter]; match = bcounter; }
            if ( bcounter > 0 && N_match[bcounter] > 0 ) { ret = 1; }
         }

         if ( match != -1 ) {
            handle->bsz = bsz_list[match];
         }
         else {
            DBG_FPRINTF( stderr, "xattr_check: failed to locate any matching bsz xattr vals!\n" );
            errno = ENODATA;
            return -1;
         }
      } //end of NE_STAT exclusive checks
   }

   /* If no usable file was located or the number of errors is too great, notify of failure */
   if ( handle->mode != NE_STAT  &&  handle->nerr > handle->E ) {
      errno = ENODATA;
      return -1;
   }

   if ( ret != 0 ) {
      fprintf( stderr, "xattr_check: mismatched xattr values were detected, but not identified!" );
      return 1;
   }

   return 0;
}

static int reopen_for_rebuild(ne_handle handle, int block) {
  char file[MAXNAME];

  handle->src_in_err[block] = 1;

  sprintf( file, handle->path,
           (block+handle->erasure_offset)%(handle->N+handle->E) );

  DBG_FPRINTF( stdout, "   closing %s\n", &file[0] );
  close( handle->FDArray[block] );

  if( handle->mode == NE_STAT ) {
    handle->FDArray[block] = -1;
    DBG_FPRINTF( stdout, "   setting FD %d to -1\n", block );
  }
  else {

    DBG_FPRINTF( stdout, "   opening %s for write\n", file );

    handle->FDArray[block] =
      open( strncat( file, REBUILD_SFX, strlen(REBUILD_SFX)+1 ),
          O_WRONLY | O_CREAT, 0666 );

  }

  //ensure that sources are listed in order
  int i, tmp;
  for ( i = 0; i < handle->nerr; i++ ) {
    if ( handle->src_err_list[i] > block) { break; }
  }
  while ( i < handle->nerr ) {
    // re-sort the error list.
    tmp = handle->src_err_list[i];
    handle->src_err_list[i] = block;
    block = tmp;
    i++;
  }

  handle->src_err_list[handle->nerr] = block;
  handle->nerr++;
  handle->e_ready = 0; //indicate that erasure structs require re-initialization

  return 0;
}

// Seek to the start of each block file.
// return -1 on fatal error (seek failed that was expected to succeed)
// return 1 on non-fatal error (seek failed, but may still be recoverable).
// return 0 on success.
static int reset_blocks(ne_handle handle) {
  int block_index;
  for(block_index = 0; block_index < handle->N + handle->E; block_index++) {

    if(handle->mode != NE_STAT || handle->src_in_err[block_index] == 0) {
      DBG_FPRINTF(stdout,
                  "ne_rebuild: performing seek to offset 0 for file %d\n",
                  block_index);
      if(lseek(handle->FDArray[block_index], 0, SEEK_SET) == -1) {
        if(handle->src_in_err[block_index] == 1) {
          handle->e_ready = 0;
          return -1;
        }
        else {
          DBG_FPRINTF( stderr, "ne_rebuild: encountered error while seeking file %d\n", block_index );
          reopen_for_rebuild(handle, block_index);
          return 1;
        }
      }
    }
  }
  return 0;
}

static int fill_buffers(ne_handle handle, u64 *csum) {
  int          block_index;
  u32          crc;
  const int    ERASURE_WIDTH = handle->N + handle->E;
#ifdef INT_CRC
  const size_t BUFFER_SIZE   = handle->bsz + sizeof(crc);
#else
  const size_t BUFFER_SIZE   = handle->bsz;
#endif

  for(block_index = 0; block_index < ERASURE_WIDTH; block_index++) {
    if(!handle->src_in_err[block_index]) {
      size_t read_size = read(handle->FDArray[block_index],
                              handle->buffs[block_index],
                              BUFFER_SIZE);
      if(read_size < BUFFER_SIZE) {
        DBG_FPRINTF(stderr,
                    "ne_rebuild: encountered error while reading file %d\n",
                    block_index);
        reopen_for_rebuild(handle, block_index);
        return -1;
      }
      crc = crc32_ieee( TEST_SEED, handle->buffs[block_index], handle->bsz);
      csum[block_index] += crc;

#ifdef INT_CRC
      // verify the stored crc
      u32 *buff_crc = (u32*)(handle->buffs[block_index] + (handle->bsz));
      if(*buff_crc != crc) {
        DBG_FPRINTF(stderr, "ne_rebuild: mismatch of int-crc for file %d\n",
                    block_index);
        reopen_for_rebuild(handle, block_index);
        return -1;
      }
#endif
    }
  }
  return 0;
}

static int write_buffers(ne_handle handle, unsigned char *rebuild_buffs[]) {
  u32 crc;
  int i;
  int written, total_written = 0;
#ifdef INT_CRC
  const size_t BUFFER_SIZE = handle->bsz + sizeof(crc);
#else
  const size_t BUFFER_SIZE = handle->bsz;
#endif

  for(i = 0; i < handle->nerr; i++) {
    crc = crc32_ieee(TEST_SEED, rebuild_buffs[handle->N+i], handle->bsz);
    if(handle->mode != NE_STAT) {
#ifdef INT_CRC
      u32 *buf_crc = (u32*)(rebuild_buffs[handle->N+i] + (handle->bsz));
      *buf_crc = crc;
#endif
      written = write(handle->FDArray[handle->src_err_list[i]],
                      rebuild_buffs[handle->N+i], BUFFER_SIZE);
      if(written < BUFFER_SIZE) {
        return -1;
      }
    }
    handle->csum[handle->src_err_list[i]]    += crc;
    handle->nsz[handle->src_err_list[i]]     += handle->bsz;
    handle->ncompsz[handle->src_err_list[i]] += handle->bsz;
    total_written                            += handle->bsz;
  }
  return total_written;
}

// free an array of pointers.
static inline void free_buffers(unsigned char *buffs[], int size) {
  int i;
  for(i = 0; i < size; i++) {
    free(buffs[i]);
  }
}

int do_rebuild(ne_handle handle) {
  int            block_index;
  int            nsrcerr       = 0;
  size_t         rebuilt_size  = 0;
  unsigned char *rebuild_buffs[ MAXPARTS ];
  unsigned int   decode_index[ MAXPARTS ];
  u64            csum[ MAXPARTS ];
  u32            crc;

  const int      ERASURE_WIDTH = handle->N + handle->E;
#ifdef INT_CRC
  const size_t   BUFFER_SIZE = handle->bsz + sizeof(crc);
#else
  const size_t   BUFFER_SIZE = handle->bsz;
#endif

  for ( block_index = 0; block_index < ERASURE_WIDTH; block_index++ ) {
    int tmp;
    tmp = posix_memalign((void **)&(rebuild_buffs[block_index]),
                         64, BUFFER_SIZE);
    if ( tmp != 0 ) {
      DBG_FPRINTF( stderr,
                   "ne_rebuild: failed to allocate temporary data buffer\n" );
      errno = tmp;
      return -1;
    }
  }

  DBG_FPRINTF( stdout, "ne_rebuild: initiating rebuild operation...\n" );

  // loop over all the data to complete the rebuild.
  while(rebuilt_size < handle->totsz) {

    // (re)starting the rebuild. reset checksums. reset position in
    // blocks.
    if(rebuilt_size == 0) {
      nsrcerr = 0;
      for(block_index = 0; block_index < ERASURE_WIDTH; block_index++) {
        if( handle->src_in_err[block_index] == 0 ) {
          csum[block_index] = 0;
        }
        else {
          handle->csum[block_index] = 0;
        }
      }

      int reset_result = reset_blocks(handle);
      if(reset_result == -1) {
        handle->e_ready = 0;
        free_buffers(rebuild_buffs, ERASURE_WIDTH);
        return -1; // fail the rebuild. could not seek.
      }
      else if(reset_result == 1) {
        DBG_FPRINTF(stderr, "ne_rebuild: restarting rebuild due to seek error");
        rebuilt_size = 0; // restart.
        continue;
      }
    }

    for(block_index = 0; block_index < ERASURE_WIDTH; block_index++) {
      if(handle->src_in_err[block_index]) {
        // Zero buffers for faulty blocks
        DBG_FPRINTF(stdout, "ne_rebuild: zeroing data for faulty_file %d\n",
                   block_index);
        if(block_index < handle->N) { nsrcerr++; }
        // XXX: Do these account for INT_CRC????
        bzero(handle->buffs[block_index], handle->bsz);
        bzero(rebuild_buffs[block_index], handle->bsz);
      }
    }

    // try to read data from the non-corrupted files, verifies
    // checksums while reading.
    if(fill_buffers(handle, csum) != 0) {
      // failed to read something. Fill_buffers took care of
      // reopening the necessary files.
      rebuilt_size = 0;
      continue;
    }

    /* Check that errors are still recoverable */
    if(handle->nerr > handle->E) {
      DBG_FPRINTF(stderr, "ne_rebuild: errors exceed regeneration "
                  "capacity of erasure\n");
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
      DBG_FPRINTF(stdout,"ne_rebuild: initializing erasure structs...\n");
      gf_gen_rs_matrix(handle->encode_matrix, handle->N + handle->E,
                       handle->N);

      // Generate g_tbls from encode matrix encode_matrix
      ec_init_tables(handle->N, handle->E,
                     &(handle->encode_matrix[handle->N * handle->N]),
                     handle->g_tbls);

      int decode_result = gf_gen_decode_matrix( handle->encode_matrix,
                                                handle->decode_matrix,
                                                handle->invert_matrix,
                                                decode_index,
                                                handle->src_err_list,
                                                handle->src_in_err,
                                                handle->nerr,
                                                nsrcerr,
                                                handle->N,
                                                handle->N + handle->E);
      if(decode_result != 0) {
        DBG_FPRINTF(stderr, "ne_rebuild: failure to generate decode matrix\n");
        errno = ENODATA;
        free_buffers(rebuild_buffs, ERASURE_WIDTH);
        return -1;
      }

      int i;
      for(i = 0; i < handle->N; i++) {
        handle->recov[i] = handle->buffs[decode_index[i]];
      }

      DBG_FPRINTF(stdout, "ne_rebuild: init erasure tables nsrcerr = %d...\n");
      ec_init_tables(handle->N, handle->nerr,
                     handle->decode_matrix, handle->g_tbls);
      handle->e_ready = 1; // indicate that rebuild structures are initialized
    }

    DBG_FPRINTF( stdout,
                 "ne_rebuild: performing regeneration from erasure...\n" );

    ec_encode_data(handle->bsz, handle->N, handle->nerr,
                   handle->g_tbls, handle->recov, &rebuild_buffs[handle->N]);
    size_t size_written;
    if((size_written = write_buffers(handle, rebuild_buffs)) < 0) {
      free_buffers(rebuild_buffs, ERASURE_WIDTH);
      return -1; // fail the rebuild. something went seriously wrong.
    }

    rebuilt_size += handle->N * handle->bsz;
  }

  // verify block-level crcs
  int retry = 0;
  for (block_index = 0; block_index < ERASURE_WIDTH; block_index++) {
    if(handle->src_in_err[block_index] == 0
       && handle->csum[block_index] != csum[block_index]) {
      DBG_FPRINTF(stderr, "ne_rebuild: mismatch of crc sum for file %d, "
                  "handle:%llu data:%llu\n", block_index,
                  (unsigned long long)handle->csum[block_index],
                  (unsigned long long)csum[block_index]);
      reopen_for_rebuild(handle, block_index);
      retry = 1;
    }
  }

  if(retry && handle->mode != NE_STAT) {
    // protect from an infinite recursion
    if( handle->nerr > handle->E ) {
      DBG_FPRINTF(stderr, "ne_rebuild: errors exceed regeneration "
                   "capacity of erasure\n");
      free_buffers(rebuild_buffs, ERASURE_WIDTH);
      errno = ENODATA;
      return -1;
    }
    else {
      int i;
      free_buffers(rebuild_buffs, ERASURE_WIDTH);
      return do_rebuild(handle);
    }
  }

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
      DBG_FPRINTF( stderr, "ne_rebuild: received NULL handle\n" );
      errno = EINVAL;
      return -1;
   }

   if ( handle->mode != NE_REBUILD  &&  handle->mode != NE_STAT ){
      DBG_FPRINTF( stderr, "ne_rebuild: handle is in improper mode for rebuild operation" );
      errno = EPERM;
      return -1;
   }

   //   init = 0; init should be set to 0 before entering rebuild/retry loop.
   mode_t mask = umask(0000);
   int rebuild_result = do_rebuild(handle);
   umask(mask);

   return (handle->nerr <= handle->E) && (rebuild_result == 0) ?
     handle->nerr : -1;
}


/**
 * Flushes the handle buffer of the given striping, zero filling the remainder of the stripe data.
 *     Note, at present and paradoxically, this SHOULD NOT be called before the completeion of a series of reads to a file.
 *     Performing a write after a call to ne_flush WILL result in zero fill remaining within the erasure striping.
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
      DBG_FPRINTF( stderr, "ne_flush: received a NULL handle\n" );
      errno = EINVAL;
      return -1;
   }

   if ( handle->mode != NE_WRONLY ) {
      DBG_FPRINTF( stderr, "ne_flush: handle is in improper mode for writing\n" );
      errno = EINVAL;
   }

   N = handle->N;
   E = handle->E;
   bsz = handle->bsz;

   if ( handle->buff_rem == 0 ) {
      DBG_FPRINTF( stdout, "ne_flush: handle buffer is empty, nothing to be done.\n" );
      return ret;
   }

//   rem_back = handle->buff_rem;
//
//   // store the seek positions for each file
//   for ( counter = 0; counter < (handle->N + handle->E); counter++ ) {
//      pos[counter] = lseek(handle->FDArray[counter], 0, SEEK_CUR);
//      if ( pos[counter] == -1 ) {
//         DBG_FPRINTF( stderr, "ne_flush: failed to obtain current seek position for file %d\n", counter );
//         return -1;
//      }
//      if ( (rem_back/(handle->bsz)) == counter ) {
//         pos[counter] += rem_back % handle->bsz;
//      }
//      else if ( (rem_back/(handle->bsz)) > counter ) {
//         pos[counter] += handle->bsz;
//      }
//      fprintf( stdout, "    got seek pos for file %d as %zd ( rem = %d )\n", counter, pos[counter], rem_back );//REMOVE
//   }


   DBG_FPRINTF( stdout, "ne_flush: flusing handle buffer...\n" );
   //zero the buffer to the end of the stripe
   tmp = (N*bsz) - handle->buff_rem;
   zero_buff = malloc(sizeof(char) * tmp);
   bzero(zero_buff, tmp );

   if ( tmp != ne_write( handle, zero_buff, tmp ) ) { //make ne_write do all the work
      DBG_FPRINTF( stderr, "ne_flush: failed to flush handle buffer\n" );
      ret = -1;
   }

//   // reset the seek positions for each file
//   for ( counter = 0; counter < (handle->N + handle->E); counter++ ) {
//      if ( lseek( handle->FDArray[counter], pos[counter], SEEK_SET ) == -1 ) {
//         DBG_FPRINTF( stderr, "ne_flush: failed to reset seek position for file %d\n", counter );
//         return -1;
//      }
//      fprintf( stdout, "    set seek pos for file %d as %zd\n", counter, pos[counter] ); //REMOVE
//   }
//   handle->buff_rem = rem_back;

   //reset various handle properties
   handle->totsz -= tmp;
   free( zero_buff );

   return ret;
}


#ifndef HAVE_LIBISAL
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
           DBG_FPRINTF(stderr,"gf_gen_decode_matrix: failure of malloc\n");
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
			DBG_FPRINTF(stderr,"gf_gen_decode_matrix: BAD MATRIX\n");
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
			DBG_FPRINTF(stderr,"gf_gen_decode_matrix: BAD MATRIX\n");
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
   while ( handle->nerr > 0 ) {
      handle->nerr--;
      handle->src_in_err[handle->src_err_list[handle->nerr]] = 0;
      handle->src_err_list[handle->nerr] = 0;
   }
   return ne_rebuild( handle ); 
}


/**
 * Retrieves the health and parameters for the erasure striping indicated by the provided path and offset
 * @param char* path : Name structure for the files of the desired striping.  This should contain a single "%d" field.
 * @return nestat : Status structure containing the encoded error pattern of the stripe (as with ne_close) as well as 
 *                  the number of data parts (N), number of erasure parts (E), and blocksize (bsz) for the stripe.
 */
ne_stat ne_status( char *path )
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

   ne_stat stat = malloc( sizeof( struct ne_stat_struct ) );
   ne_handle handle = malloc( sizeof( struct handle ) );
   if ( stat == NULL  ||  handle == NULL ) {
      DBG_FPRINTF( stderr, "ne_status: failed to allocate stat/handle structures!\n" );
      return NULL;
   }

   /* initialize stored info */
   for ( counter=0; counter < MAXPARTS; counter++ ) {
      handle->csum[counter] = 0;
      handle->nsz[counter] = 0;
      handle->ncompsz[counter] = 0;
      handle->src_in_err[counter] = 0;
      handle->src_err_list[counter] = 0;
      stat->data_status[counter] = 0;
      stat->xattr_status[counter] = 0;
   }
   handle->nerr = 0;
   handle->totsz = 0;
   handle->N = 0;
   handle->E = 0;
   handle->bsz = 0;
   handle->erasure_offset = 0;
   handle->mode = NE_STAT;
   handle->e_ready = 0;
   handle->buff_offset = 0;
   handle->buff_rem = 0;

   char* nfile = malloc( strlen(path) + 1 );
   strncpy( nfile, path, strlen(path) + 1 );
   handle->path = nfile;

   ret = xattr_check(handle,path); //idenfity total data size of stripe
   if( ret == -1 ) {
      DBG_FPRINTF( stderr, "ne_status: extended attribute check has failed\n" );
      free( handle );
      return NULL;
   }
   while ( handle->nerr > 0 ) {
      handle->nerr--;
      handle->src_in_err[handle->src_err_list[handle->nerr]] = 0;
      handle->src_err_list[handle->nerr] = 0;
   }

   handle->mode = NE_REBUILD;
   ret = xattr_check(handle,path); //verify the stripe, now that values have been established
   if ( ret == -1 ) {
      DBG_FPRINTF( stderr, "ne_status: extended attribute check has failed\n" );
      free( handle );
      return NULL;
   }
   handle->mode = NE_STAT;

   DBG_FPRINTF( stdout, "ne_status: Post xattr_check() -- NERR = %d, N = %d, E = %d, Start = %d, TotSz = %llu\n", handle->nerr, handle->N, handle->E, handle->erasure_offset, handle->totsz );

   stat->N = handle->N;
   stat->E = handle->E;
   stat->bsz = handle->bsz;
   stat->totsz = handle->totsz;
   stat->start = handle->erasure_offset;

   // store xattr failures to stat struct and reset error data
   for ( counter = 0; counter < ( handle->N + handle->E ); counter++ ) {
      if ( counter < handle->nerr ) {
         stat->xattr_status[handle->src_err_list[counter]] = 1;
         handle->src_err_list[counter] = 0;
      }
      handle->src_in_err[counter] = 0;
   }
   handle->nerr = 0;

   /* allocate a big buffer for all the N chunks plus a bit extra for reading in crcs */
#ifdef INT_CRC
   crccount = 1;
   if ( handle->E > 0 ) { crccount = handle->E; }

   ret = posix_memalign( &(handle->buffer), 64, ((handle->N+handle->E)*bsz) + (sizeof(u32)*crccount) ); //add space for intermediate checksum
   DBG_FPRINTF(stdout,"ne_stat: Allocated handle buffer of size %zd for bsz=%d, N=%d, E=%d\n", ((handle->N+handle->E)*handle->bsz)+(sizeof(u32)*crccount), handle->bsz, handle->N, handle->E);
#else
   ret = posix_memalign( &(handle->buffer), 64, ((handle->N+handle->E)*bsz) );
   DBG_FPRINTF(stdout,"ne_stat: Allocated handle buffer of size %d for bsz=%d, N=%d, E=%d\n", (handle->N+handle->E)*handle->bsz, handle->bsz, handle->N, handle->E);
#endif
   if ( ret != 0 ) {
      DBG_FPRINTF( stderr, "ne_status: failed to allocate handle buffer\n" );
      errno = ret;
      return NULL;
   }

   /* allocate matrices */
   handle->encode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->decode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->invert_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->g_tbls = malloc(MAXPARTS * MAXPARTS * 32);


   /* loop through and open up all the output files, initilize per part info, and allocate buffers */
   counter = 0;
   DBG_FPRINTF( stdout, "ne_status: opening file descriptors...\n" );
   while ( counter < (handle->N+handle->E) ) {
      bzero( file, MAXNAME );
      sprintf( file, path, (counter+handle->erasure_offset)%(handle->N+handle->E) );

#ifdef INT_CRC
      if ( counter > handle->N ) {
         crccount = counter - handle->N;
         handle->buffs[counter] = handle->buffer + ( counter*bsz ) + ( crccount * sizeof(u32) ); //make space for block and erasure crc
      }
      else {
         handle->buffs[counter] = handle->buffer + ( counter*bsz ); //make space for block
      }
#else
      handle->buffs[counter] = handle->buffer + ( counter*bsz ); //make space for block
#endif

      DBG_FPRINTF( stdout, "ne_status:    opening %s for read\n", file );
      handle->FDArray[counter] = open( file, O_RDONLY );

      if ( handle->FDArray[counter] == -1  &&  handle->src_in_err[counter] == 0 ) {
         DBG_FPRINTF( stderr, "ne_status:    failed to open file %s!!!!\n", file );
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
         handle->src_in_err[counter] = 1;
         counter++;

         continue;
      }

      counter++;
   }

   if ( ne_rebuild( handle ) < 0 ) {
      DBG_FPRINTF( stderr, "ne_status: rebuild indicates that data is unrecoverable\n" );
   }

   // store data failures to stat struct
   for ( counter = 0; counter < handle->nerr; counter++ ) {
      stat->data_status[handle->src_err_list[counter]] = 1;
   }


   /* Close file descriptors and free bufs */
   counter = 0;
   while (counter < (handle->N+handle->E) ) {

      if ( handle->src_in_err[counter] == 0  &&  handle->FDArray[counter] != -1 ) { close(handle->FDArray[counter]); }

      counter++;
   }
   free(handle->buffer);
  
   free(handle->encode_matrix);
   free(handle->decode_matrix);
   free(handle->invert_matrix);
   free(handle->g_tbls);
   free(handle);

   return stat;

}

