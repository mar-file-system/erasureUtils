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
 
/********************************************************/
/*

This file provides the implementation of multiple operations intended for use by the MarFS MultiComponent DAL.

These include:   ne_read(), ne_write(), ne_health(), and ne_rebuild().

Additionally, each output file gets an xattr added to it  (yes all 12 files in the case of a 10+2
the xattr looks like this
n.e.chunksize.nsz.ncompsz.ncrcsum.totsz: 10 2 64 196608 196608 3304199718723886772 1717171
N is nparts, E is numerasure, chunksize is chunksize, nsz is the size of the part, ncompsz is the size of the part but might get used if we ever compress the parts, totsz is the total real data in the N part files.
Since creating erasure requires full stripe writes, the last part of the file may all be zeros in the parts.  This totsz is the real size of the data, not counting the trailing zeros.
All the parts and all the erasure stripes should be the same size.
To fill in the trailing zeros, this program uses truncate - punching a hole in the N part files for the zeros.

*********************************************************/


/* The following are defined here, so as to hide them from users of the library */
int error_check( ne_handle handle, char *path );
void ec_init_tables(int k, int rows, unsigned char *a, unsigned char *g_tbls);
void dump(unsigned char *buf, int len);
static int gf_gen_decode_matrix(unsigned char *encode_matrix,
				unsigned char *decode_matrix,
				unsigned char *invert_matrix,
				unsigned int *decode_index,
				unsigned char *src_err_list,
				unsigned char *src_in_err,
				int nerrs, int nsrcerrs, int k, int m);


/**
 * Opens a new handle for a specific erasure striping
 * @param char* path : Name structure for the files of the desired striping.  This should contain a single "%d" field.
 * @param ne_mode mode : Mode in which the file is to be opened.  Either NE_RDONLY, NE_WRONLY, or NE_REBUILD.
 * @param int erasure_offset : Offset of the erasure stripe, defining the name of the first N file
 * @param int N : Data width of the striping
 * @param int E : Erasure width of the striping
 * @return ne_handle : The new handle for the opened erasure striping
 */
ne_handle ne_open( char *path, ne_mode mode, int erasure_offset, int N, int E )
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

   ne_handle handle = malloc( sizeof( struct handle ) );

   if ( N < 1  ||  N > MAXN ) {
#ifdef DEBUG
      fprintf( stderr, "improper N arguement received - %d\n", N );
#endif
      errno = EINVAL;
      return NULL;
   }
   if ( E < 0  ||  E > MAXE ) {
#ifdef DEBUG
      fprintf( stderr, "improper E arguement received - %d\n", E );
#endif
      errno = EINVAL;
      return NULL;
   }
//   if ( bsz < 0 ) {
//      fprintf( stderr, "improper bsz arguement received - %d\n", bsz );
//      errno = EINVAL;
//      return NULL;
//   }
   if ( erasure_offset < 0  ||  erasure_offset >= N+E ) {
#ifdef DEBUG
      fprintf( stderr, "improper erasure_offset arguement received - %d\n", erasure_offset );
#endif
      errno = EINVAL;
      return NULL;
   }

   /* initialize stored info */
   for ( counter=0; counter < N+E; counter++ ) {
      handle->src_in_err[counter] = 0;
      handle->src_err_list[counter] = 0;
   }
   handle->nerr = 0;
   handle->totsz = 0;
   handle->N = N;
   handle->E = E;
   handle->bsz = bsz;
   handle->erasure_offset = erasure_offset;
   handle->mode = mode;
   handle->e_ready = 0;
   handle->buff_offset = 0;
   handle->buff_rem = 0;

   if ( mode == NE_REBUILD  ||  mode == NE_RDONLY ) {
      ret = error_check(handle,path); //idenfity a preliminary error pattern
      if ( ret != 0 ) {
#ifdef DEBUG
         fprintf( stderr, "ne_open: error_check has failed\n" );
#endif
         free( handle );
         return NULL;
      }
   }
   else if ( mode != NE_WRONLY ) { //reject improper mode arguments
#ifdef DEBUG
      fprintf( stderr, "improper mode argument received - %d\n", mode );
#endif
      errno = EINVAL;
      return NULL;
   }

   /* allocate a big buffer for all the N chunks plus a bit extra for reading in crcs */
#ifdef INT_CRC
   crccount = 1;
   if ( E > 0 ) { crccount = E; }

   posix_memalign( &(handle->buffer), 64, ((N+E)*bsz) + (sizeof(u32)*crccount) ); //add space for intermediate checksum
#else
   posix_memalign( &(handle->buffer), 64, ((N+E)*bsz) );
#endif

#ifdef DEBUG
   fprintf(stdout,"ne_open: Allocated handle buffer of size %d for bsz=%d, N=%d, E=%d\n", (N+E)*bsz, bsz, N, E);
#endif

   /* allocate matrices */
   handle->encode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->decode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->invert_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->g_tbls = malloc(MAXPARTS * MAXPARTS * 32);


   /* loop through and open up all the output files and initilize per part info and allocate buffers */
   counter = 0;
#ifdef DEBUG
   fprintf( stdout, "opening file descriptors...\n" );
#endif
   while ( counter < N+E ) {
      handle->csum[counter] = 0;
      handle->nsz[counter] = 0;
      handle->ncompsz[counter] = 0;
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

      if( mode == NE_WRONLY  ||  (mode == NE_REBUILD  &&  handle->src_in_err[counter] == 1) ) {
#ifdef DEBUG
         fprintf( stdout, "   opening %s for write\n", file );
#endif
         handle->FDArray[counter] = open( file, O_WRONLY | O_CREAT, 0666 );
      }
      else {
#ifdef DEBUG
         fprintf( stdout, "   opening %s for read\n", file );
#endif
         handle->FDArray[counter] = open( file, O_RDONLY );
      }

      if ( handle->FDArray[counter] == -1  &&  handle->src_in_err[counter] == 0 ) {
#ifdef DEBUG
         fprintf( stderr, "   failed to open file %s!!!!\n", file );
#endif
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
         handle->src_in_err[counter] = 1;
         if ( handle->nerr > E ) { //if errors are unrecoverable, terminate
            return NULL;
         }
         continue;
      }

      counter++;
   }

   return handle;

}

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
   unsigned long ret_in;
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
#ifdef DEBUG
      fprintf( stderr, "ne_read: handle is in improper mode for reading!\n" );
#endif
      errno = EPERM;
      return -1;
   }

   if ( (offset + nbytes) > handle->totsz ) {
#ifdef DEBUG
      fprintf(stdout,"ne_read: read would extend beyond EOF, resizing read request...\n");
#endif
      nbytes = handle->totsz - offset;
      if ( nbytes <= 0 ) {
#ifdef DEBUG
         fprintf( stderr, "ne_read: offset is beyond filesize\n" );
#endif
         return 0;
      }
   }

   llcounter = 0;
   tmpoffset = 0;

   //check stripe cache
   if ( offset >= handle->buff_offset  &&  offset < (handle->buff_offset + handle->buff_rem) ) {
      seekamt = offset - handle->buff_offset;
      readsize = ( nbytes > (handle->buff_rem - seekamt) ) ? (handle->buff_rem - seekamt) : nbytes;
#ifdef DEBUG
      fprintf( stdout, "ne_read: filling request for first %lu bytes from cache with offset %zd in buffer...\n", (unsigned long) readsize, seekamt );
#endif
      memcpy( buffer, handle->buffer + seekamt, readsize );
      llcounter += readsize;
   }

   //if entire request was cached, nothing remains to be done
   if ( llcounter == nbytes ) { return llcounter; }


   //determine min/max errors and allocate temporary buffers
   for ( counter = 0; counter < mtot; counter++ ) {
      posix_memalign((void **)&(temp_buffs[counter]),64,bsz);
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
#ifdef DEBUG
      fprintf( stderr, "ne_read: iconsistent internal state : handle->nerr and handle->src_in_err\n" );
#endif
      errno = ENOTRECOVERABLE;
      return -1;
   }


   /******** Rebuild While Reading ********/
rebuild:

   startstripe = (offset+llcounter) / (bsz*N);
   startpart = (offset + llcounter - (startstripe*bsz*N))/bsz;
   startoffset = offset+llcounter - (startstripe*bsz*N) - (startpart*bsz);

#ifdef DEBUG
   fprintf(stdout,"ne_read: read with rebuild from startstripe %d startpart %d and startoffset %d for nbytes %d\n",startstripe,startpart,startoffset,nbytes);
#endif

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

#ifdef DEBUG
               fprintf(stdout,"seeking erasure file e%d to %zd, as we will be reading from the next stripe\n",counter-N, seekamt);
#endif
            }
#ifdef DEBUG
            else {
               fprintf(stdout,"seeking input file %d to %zd, as there is no error in this stripe\n",counter, seekamt);
            }
#endif

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
               goto rebuild; //if another error is encountered, start over
            }

         }
      }
      tmpchunk = startpart;
      tmpoffset = startoffset;
      error_in_stripe = 0;
   }
   else {  //if not, we will require the entire stripe for rebuild
#ifdef DEBUG
      fprintf(stdout,"startpart = %d, endchunk = %d\n   This stipe contains corrupted blocks...\n", startpart, endchunk);
#endif
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
#ifdef DEBUG
#ifdef INT_CRC
            fprintf(stdout,"seek input file %d to %lu, to read entire stripe\n",counter, (unsigned long)(startstripe*( bsz+sizeof(u32) )));
#else
            fprintf(stdout,"seek input file %d to %lu, to read entire stripe\n",counter, (unsigned long)(startstripe*bsz));
#endif
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

#ifdef DEBUG
      fprintf( stdout, "ne_read: endchunk unadjusted - %d\n", endchunk );
#endif
      if ( endchunk >= N ) {
         endchunk = N - 1;
      }

#ifdef DEBUG
      fprintf(stdout,"ne_read: endchunk adjusted - %d\n", endchunk);
#endif
      if ( endchunk < minNerr ) {
#ifdef DEBUG
         printf("ne_read: there is no error in this stripe\n");
#endif
         error_in_stripe = 0;
      }

      /**** read data into buffers ****/
      for( counter=tmpchunk; counter < N; counter++ ) {

         if ( llcounter == nbytes  &&  error_in_stripe == 0 ) {
#ifdef DEBUG
            fprintf(stdout, "ne_read: data reads complete\n");
#endif
            break;
         }

         readsize = bsz-tmpoffset;

         if ( handle->src_in_err[counter] == 1 ) {  //this data chunk is invalid
#ifdef DEBUG
            fprintf(stdout,"ne_read: ignoring data for faulty chunk %d\n",counter);
#endif
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

         }
         else {    //this data chunk is valid, store it
            if ( (nbytes-llcounter) < readsize  &&  error_in_stripe == 0 ) {
               readsize = nbytes-llcounter;
            }

#ifdef DEBUG
#ifdef INT_CRC
            fprintf(stdout,"ne_read: read %lu from datafile %d\n", bsz+sizeof(crc), counter);
#else
            fprintf(stdout,"ne_read: read %d from datafile %d\n",readsize,counter);
#endif
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
#ifdef DEBUG
                  fprintf(stderr, "ne_read: error encountered while reading data file %d\n", counter);
#endif
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
                        llcounter -= datasz[counter];
                     }
#ifdef DEBUG
                     fprintf( stdout, "ne_read: restarting stripe read, reset total read to %lu\n", (unsigned long)llcounter);
#endif
                     goto rebuild;
                  }
                  continue;
               }
               else {
                  nbytes = llcounter + ret_in;
#ifdef DEBUG
                  fprintf(stderr, "ne_read: inputs exhausted, limiting read to %d bytes\n",nbytes);
#endif
               }

#ifdef DEBUG
               fprintf(stderr, "ne_read: failed to read all requested data from file %d\n", counter);
               fprintf(stdout,"ne_read: zeroing missing data for %d from %lu to %d\n",counter,ret_in,bsz);
#endif
               bzero(handle->buffs[counter]+ret_in,bsz-ret_in);

            }
#ifdef INT_CRC
            else {
               //calculate and verify crc
               crc = crc32_ieee( TEST_SEED, handle->buffs[counter], bsz );
               if ( memcmp( handle->buffs[counter]+bsz, &crc, sizeof(u32) ) != 0 ){
#ifdef DEBUG
                  fprintf(stderr, "ne_read: mismatch of int-crc for file %d while reading with rebuild\n", counter);
#endif
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
                        llcounter -= datasz[counter];
                     }
#ifdef DEBUG
                     fprintf( stdout, "ne_read: restarting stripe read, reset total read to %lu\n", (unsigned long)llcounter);
#endif
                     goto rebuild;
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

#ifdef DEBUG
         fprintf(stderr, "ne_read: nbytes = %d, llcounter = %lu, read_size = %d\n", nbytes, (unsigned long)llcounter, readsize);
#endif
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
#ifdef DEBUG
            fprintf(stdout,"ne_read: reading %d from erasure %d\n",readsize,counter);
#endif
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
#ifdef DEBUG
               fprintf(stderr, "ne_read: failed to read all erasure data in file %d\n", counter);
               fprintf(stdout,"ne_read: zeroing data for faulty erasure %d from %lu to %d\n",counter,ret_in,bsz);
#endif
               bzero(handle->buffs[counter]+ret_in,bsz-ret_in);
#ifdef DEBUG
               fprintf(stdout,"ne_read: zeroing temp_data for faulty erasure %d\n",counter);
#endif
               bzero(temp_buffs[counter],bsz);
#ifdef DEBUG
               fprintf(stdout,"ne_read: done zeroing %d\n",counter);
#endif
            }
#ifdef INT_CRC
            else {
               //calculate and verify crc
               crc = crc32_ieee( TEST_SEED, handle->buffs[counter], bsz );
               if ( memcmp( handle->buffs[counter]+bsz, &crc, sizeof(u32) ) != 0 ){
#ifdef DEBUG
                  fprintf(stderr, "ne_read: mismatch of int-crc for file %d (erasure)\n", counter);
#endif
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
#ifdef DEBUG
         else {
            fprintf( stdout, "ne_read: ignoring data for faulty erasure %d\n", counter );
         }
#endif
         counter++;
      }

      /**** regenerate from erasure ****/
      if ( error_in_stripe == 1 ) {

         /* If necessary, initialize the erasure structures */
         if ( handle->e_ready == 0 ) {
            // Generate encode matrix encode_matrix
            // The matrix generated by gf_gen_rs_matrix
            // is not always invertable.
#ifdef DEBUG
            fprintf(stdout,"ne_read: initializing erasure structs...\n");
#endif
            gf_gen_rs_matrix(handle->encode_matrix, mtot, N);

            // Generate g_tbls from encode matrix encode_matrix
            ec_init_tables(N, E, &(handle->encode_matrix[N * N]), handle->g_tbls);

            ret_in = gf_gen_decode_matrix( handle->encode_matrix, handle->decode_matrix,
                  handle->invert_matrix, decode_index, handle->src_err_list, handle->src_in_err,
                  handle->nerr, nsrcerr, N, mtot);

            if (ret_in != 0) {
#ifdef DEBUG
               fprintf(stderr,"ne_read: failure to generate decode matrix, errors may exceed erasure limits\n");
#endif
               errno=ENODATA;
               return -1;
            }

            for (tmp = 0; tmp < N; tmp++) {
               handle->recov[tmp] = handle->buffs[decode_index[tmp]];
            }

#ifdef DEBUG
            fprintf( stdout, "ne_read: init erasure tables nsrcerr = %d e_ready = %d...\n", nsrcerr, handle->e_ready );
#endif
            ec_init_tables(N, handle->nerr, handle->decode_matrix, handle->g_tbls);

            handle->e_ready = 1; //indicate that rebuild structures are initialized
         }
#ifdef DEBUG
         fprintf( stdout, "ne_read: performing regeneration from erasure...\n" );
#endif
         ec_encode_data(bsz, N, handle->nerr, handle->g_tbls, handle->recov, &temp_buffs[N]);
      }

      /**** write appropriate data out ****/
      for( counter=startpart, tmp=0; counter <= endchunk; counter++ ) {
         readsize = datasz[counter];

#ifdef DEBUG
         if ( readsize+out_off > llcounter ) { fprintf(stderr,"ne_read: out_off + readsize(%lu) > llcounter at counter = %d!!!\n",(unsigned long)readsize,counter); return -1; }
#endif

         if ( handle->src_in_err[counter] == 0 ) {
#ifdef DEBUG
            fprintf( stdout, "ne_read: performing write of %d from chunk %d data\n", readsize, counter );
#endif

#ifdef INT_CRC
            if ( firststripe  &&  counter == startpart ) {
#else
            if ( firststripe  &&  counter == startpart  &&  error_in_stripe ) {
#endif
#ifdef DEBUG
               fprintf( stdout, "ne_read:   with offset of %d\n", startoffset );
#endif
               memcpy( buffer+out_off, (handle->buffs[counter])+startoffset, readsize );
            }
            else {
               memcpy( buffer+out_off, handle->buffs[counter], readsize );
            }
         }
         else {

            for ( tmp = 0; counter != handle->src_err_list[tmp]; tmp++ ) {
               if ( tmp == handle->nerr ) {
#ifdef DEBUG 
                  fprintf( stderr, "ne_read: improperly definded erasure structs, failed to locate %d in src_err_list\n", tmp );
#endif
                  errno = ENOTRECOVERABLE;
                  return -1;
               }
            }

            if ( firststripe == 0  ||  counter != startpart ) {
#ifdef DEBUG
               fprintf( stdout, "ne_read: performing write of %d from regenerated chunk %d data, src_err = %d\n", readsize, counter, handle->src_err_list[tmp] );
#endif
               memcpy( buffer+out_off, temp_buffs[N+tmp], readsize );
            }
            else {
#ifdef DEBUG
               fprintf( stdout, "ne_read: performing write of %d from regenerated chunk %d data with offset %d, src_err = %d\n", readsize, counter, startoffset, handle->src_err_list[tmp] );
#endif
               memcpy( buffer+out_off, (temp_buffs[N+tmp])+startoffset, readsize );
            }

         } //end of src_in_err = true block

         out_off += readsize;

      } //end of output loop for stipe data

      if ( out_off != llcounter ) {
#ifdef DEBUG
         fprintf( stderr, "ne_read: internal mismatch : llcounter (%lu) and out_off (%zd)\n", (unsigned long)llcounter, out_off );
#endif
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
#ifdef DEBUG 
                  fprintf( stderr, "ne_read: improperly definded erasure structs, failed to locate %d in src_err_list while caching\n", tmp );
#endif
                  mtot=0;
                  tmp=0;
                  handle->buff_rem -= bsz; //just to offset the later addition
                  break;
               }
            }
#ifdef DEBUG
            fprintf( stdout, "ne_read: caching %d from regenerated chunk %d data, src_err = %d\n", bsz, counter, handle->src_err_list[tmp] );
#endif
            memcpy( handle->buffs[counter], temp_buffs[N+tmp], bsz );
         }
         handle->buff_rem += bsz;
      }
      else if ( counter < N ) { handle->buff_rem += datasz[counter]; }
      free(temp_buffs[counter]);
   }

#ifdef INT_CRC
   fprintf( stderr, "ne_read: cached %lu bytes from stripe at offset %lu\n", handle->buff_rem, handle->buff_offset );
#endif

   return llcounter; 
}


/**
 * Writes nbytes from buffer into the erasure stiping specified by the provided handle
 * @param ne_handle handle : Handle for the erasure striping to be written to
 * @param void* buffer : Buffer containing the data to be written
 * @param int nbytes : Number of data bytes to be written from buffer
 * @return int : Number of bytes written, or -1 on error.
 */
int ne_write( ne_handle handle, void *buffer, int nbytes )
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
#ifdef DEBUG
      fprintf( stderr, "ne_write: handle is in improper mode for writing!\n" );
#endif
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

         writesize = ( handle->buff_rem % bsz );
         readsize = bsz - writesize;

         //avoid reading beyond end of buffer
         if ( totsize + readsize > nbytes ) { readsize = nbytes-totsize; }

         if ( readsize < 1 ) {
#ifdef DEBUG
            fprintf(stdout,"ne_write: reading of input is now complete\n");
#endif
            break;
         }

#ifdef DEBUG
         fprintf( stdout, "ne_write: reading input for %lu bytes with offset of %llu\n          and writing to offset of %lu in handle buffer\n", (unsigned long)readsize, totsize, handle->buff_rem );
#endif
         memcpy ( handle->buffer + handle->buff_rem, buffer+totsize, readsize);
#ifdef DEBUG
         fprintf(stdout, "ne_write:   ...copy complete.\n");
#endif
         totsize += readsize;
         writesize = readsize + ( handle->buff_rem % bsz );
         handle->buff_rem += readsize;

         if ( writesize < bsz ) {  //if there is not enough data to write a full block, stash it in the handle buffer
#ifdef DEBUG
            fprintf(stdout,"ne_write: reading of input is complete, stashed %lu bytes in handle buffer\n", (unsigned long)readsize);
#endif
            break;
         }


         if ( handle->src_in_err[counter] == 0 ) {
            /* this is the crcsum for each part */
            crc = crc32_ieee(TEST_SEED, handle->buffs[counter], bsz);

#ifdef INT_CRC
            // write out per-block-crc
            memcpy( handle->buffs[counter]+writesize, &crc, sizeof(crc) );
            writesize += sizeof(crc);
#endif

            /* if we were compressing we would compress here */
#ifdef DEBUG
            fprintf(stdout,"ne_write: wr %d to file %d\n",writesize,counter);
#endif
            ret_out = write(handle->FDArray[counter],handle->buffs[counter],writesize); 

            if ( ret_out != writesize ) {
#ifdef DEBUG
               fprintf( stderr, "ne_write: write to file %d returned %zd instead of expected %lu\n" , counter, ret_out, (unsigned long)writesize );
#endif
               handle->src_in_err[counter] = 1;
               handle->src_err_list[handle->nerr] = counter;
               handle->nerr++;
            }

#ifdef INT_CRC
            writesize -= sizeof(crc);
#endif

            handle->csum[counter] += crc; 
            handle->nsz[counter] += writesize;
            handle->ncompsz[counter] += writesize;
         }

         counter++;
      } //end of writes for N

      //if we haven't written a whole stripe, terminate
      if ( counter != N ) {
         break;
      }


      /* calculate and write erasure */
      if ( handle->e_ready == 0 ) {
#ifdef DEBUG
         fprintf(stdout, "ne_write: initializing erasure matricies...\n");
#endif
         // Generate encode matrix encode_matrix
         // The matrix generated by gf_gen_rs_matrix
         // is not always invertable.
         gf_gen_rs_matrix(handle->encode_matrix, mtot, N);
         // Generate g_tbls from encode matrix encode_matrix
         ec_init_tables(N, E, &(handle->encode_matrix[N * N]), handle->g_tbls);

         handle->e_ready = 1;
      }

#ifdef DEBUG
      fprintf(stdout, "ne_write: caculating %d recovery stripes from %d data stripes\n",E,N);
#endif
      // Perform matrix dot_prod for EC encoding
      // using g_tbls from encode matrix encode_matrix
      ec_encode_data( bsz, N, E, handle->g_tbls, handle->buffs, &(handle->buffs[N]) );

      ecounter = 0;
      while (ecounter < E) {
         crc = crc32_ieee(TEST_SEED, handle->buffs[counter+ecounter], bsz); 

         writesize = bsz;
#ifdef INT_CRC
         // write out per-block-crc
         memcpy( handle->buffs[counter+ecounter]+writesize, &crc, sizeof(crc) );
         writesize += sizeof(crc);
#endif

         handle->csum[counter+ecounter] += crc; 
         handle->nsz[counter+ecounter] += bsz;
         handle->ncompsz[counter+ecounter] += bsz;
#ifdef DEBUG
         fprintf( stdout, "ne_write: writing out erasure stripe %d\n", ecounter );
#endif
         ret_out = write(handle->FDArray[counter+ecounter],handle->buffs[counter+ecounter],writesize); 

         if ( ret_out != writesize ) {
#ifdef DEBUG
            fprintf( stderr, "ne_write: write to erasure file %d, returned %zd instead of expected %d\n" , ecounter, ret_out, writesize );
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
         }

         ecounter++;
      }

      //now that we have written out all data, reset buffer
      handle->buff_rem = 0; 
   }
   handle->totsz += totsize; //as it is impossible to write at an offset, the sum of writes will be the total size
 
   return totsize;
}


/**
 * Closes the erasure striping indicated by the provided handle and flushes the handle buffer, if necessary.
 * @param ne_handle handle : Handle for the striping to be closed
 * @return int : Status code.  Success is indicated by 0 and failure by -1.  A positive value indicates that the operation was sucessful, 
 *               but that errors were encountered in the stipe.  The Least-Significant Bit of the return code corresponds to the first of 
 *               the N data stripe files, while each subsequent bit corresponds to the next N files and then the E files.  A 1 in these 
 *               positions indicates that an error was encountered while acessing that specific file.
 */
int ne_close( ne_handle handle ) 
{

   int counter;
   char xattrval[strlen(XATTRKEY)+50];
   int N;
   int E;
   unsigned int bsz;
   int ret = 0;
   int tmp;
   unsigned char *zero_buff;


   if ( handle == NULL ) {
#ifdef DEBUG
      fprintf( stderr, "ne_close: received a NULL handle\n" );
#endif
      errno = EINVAL;
      return -1;
   }

   N = handle->N;
   E = handle->E;
   bsz = handle->bsz;


   /* flush the handle buffer if necessary */
   if ( handle->mode == NE_WRONLY  &&  handle->buff_rem != 0 ) {
#ifdef DEBUG
      fprintf( stdout, "ne_close: flusing handle buffer...\n" );
#endif
      //zero the buffer to the end of the stripe
      tmp = (N*bsz) - handle->buff_rem;
      zero_buff = malloc(sizeof(char) * tmp);
      bzero(zero_buff, tmp );

      if ( tmp != ne_write( handle, zero_buff, tmp ) ) { //make ne_write do all the work
#ifdef DEBUG
         fprintf( stderr, "ne_close: failed to flush handle buffer\n" );
#endif
         ret = -1;
      }

      handle->totsz -= tmp;

   }

   /* Close file descriptors and free bufs and set xattrs for written files */
   counter = 0;
   while (counter < N+E) {
      if ( handle->mode == NE_WRONLY  ||  (handle->mode == NE_REBUILD && handle->src_in_err[counter] == 1) ) { 
         bzero(xattrval,sizeof(xattrval));
         sprintf(xattrval,"%d %d %d %lu %lu %zu %zu",N,E,bsz,handle->nsz[counter],handle->ncompsz[counter],handle->csum[counter],handle->totsz);
#ifdef DEBUG
         fprintf( stdout, "ne_close: setting file %d xattr = \"%s\"\n", counter, xattrval );
#endif
         tmp = fsetxattr(handle->FDArray[counter],XATTRKEY, xattrval,strlen(xattrval),0); 
         
         if ( tmp != 0 ) {
#ifdef DEBUG
            fprintf( stderr, "ne_close: failed to set xattr for file %d\n", counter );
#endif
            ret = -1;
         }

      }
      if ( handle->FDArray[counter] != -1 ) { close(handle->FDArray[counter]); }
      counter++;
   }
   free(handle->buffer);
  
   if ( ret == 0 ) {
#ifdef DEBUG
      fprintf( stdout, "ne_close: encoding error pattern in return value...\n" );
#endif
      /* Encode any file errors into the return status */
      for( counter = 0; counter < N+E; counter++ ) {
         if ( handle->src_in_err[counter] ) { ret += ( 1 << ((counter + handle->erasure_offset) % (N+E)) ); }
      }
   }

   free(handle->encode_matrix);
   free(handle->decode_matrix);
   free(handle->invert_matrix);
   free(handle->g_tbls);
   free(handle);
   
   return ret;

}


/**
 * Internal helper function intended to identify file error pattern ahead of ne_read or ne_rebuild operations.
 * @param ne_handle handle : The handle for the current erasure striping
 * @param char* path : Name structure for the files of the desired striping.  This should contain a single "%d" field.
 * @return int : Status code, with 0 indicating success and -1 indicating failure
 */
int error_check( ne_handle handle, char *path ) 
{
   char file[MAXNAME];       /* array name of files */
   int counter;
   int bcounter;
   int ret;
   int ret_in;
   int filefd;
   char xattrval[strlen(XATTRKEY)+50];
   char xattrchunks[20];       /* char array to get n parts from xattr */
   char xattrchunksizek[20];   /* char array to get chunksize from xattr */
   char xattrnsize[20];        /* char array to get total size from xattr */
   char xattrerasure[20];      /* char array to get erasure from xattr */
   char xattrncompsize[20];    /* general char for xattr manipulation */
   char xattrnsum[50];         /* char array to get xattr sum from xattr */
   char xattrtotsize[160];
   int N = handle->N;
   int E = handle->E;
   unsigned int bsz = handle->bsz;
   unsigned long nsz;
   unsigned long ncompsz;
#ifdef INT_CRC
   unsigned int blocks;
   u32 crc;
#endif
   u64 scrc;
   char goodfile = 0;
   u64 totsz;
   struct stat* partstat = malloc (sizeof(struct stat));
   void *buf;

#ifdef INT_CRC
   posix_memalign(&buf,32,bsz+sizeof(crc));
#else
   posix_memalign(&buf,32,bsz);
#endif

   for ( counter = 0; counter < N+E; counter++ ) {
      bzero(file,sizeof(file));
      sprintf( file, path, (counter+handle->erasure_offset)%(N+E) );
      ret = stat( file, partstat );
#ifdef DEBUG
      fprintf( stdout, "error_check: stat of file %s returns %d\n", file, ret );
#endif
      if ( ret != 0 ) {
#ifdef DEBUG
         fprintf( stderr, "error_check: file %s: failure of stat\n", file );
#endif
         handle->src_in_err[counter] = 1;
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
      }
      else if ( handle->mode == NE_REBUILD  ||  goodfile == 0 ) {
         bzero(xattrval,sizeof(xattrval));
         ret = getxattr(file,XATTRKEY,&xattrval[0],sizeof(xattrval));
#ifdef DEBUG
         fprintf(stderr,"error_check: file %s xattr returned %d\n",file,ret);
#endif
         if (ret < 0) {
#ifdef DEBUG
            fprintf(stderr, "error_check: failure of xattr retrieval for file %s\n", file);
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }

         sscanf(xattrval,"%s %s %s %s %s %s %s",xattrchunks,xattrerasure,xattrchunksizek,xattrnsize,xattrncompsize,xattrnsum,xattrtotsize);
         N = atoi(xattrchunks);
         E = atoi(xattrerasure);
         bsz = atoi(xattrchunksizek);
         nsz = strtol(xattrnsize,NULL,0);
         ncompsz = strtol(xattrncompsize,NULL,0);
         totsz = strtoll(xattrtotsize,NULL,0);

#ifdef INT_CRC
         blocks = nsz / bsz;
#endif

         /* verify xattr */
         if ( N != handle->N ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr N = %d did not match handle value  %d \n", N, handle->N); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }
         else if ( E != handle->E ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr E = %d did not match handle value  %d \n", E, handle->E); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }
         else if ( bsz != handle->bsz ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr bsz = %d did not match handle value  %d \n", bsz, handle->bsz); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }
#ifdef INT_CRC
         else if ( ( nsz + (blocks*sizeof(crc)) ) != partstat->st_size ) {
#else
         else if ( nsz != partstat->st_size ) {
#endif
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr nsize = %lu did not match stat value %zu \n", nsz, partstat->st_size); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }
         else if ( (nsz % bsz) != 0 ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr nsize = %lu is inconsistent with block size %d \n", nsz, bsz); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }

#ifdef INT_CRC
         else if ( ( ncompsz + (blocks*sizeof(crc)) ) != partstat->st_size ) {
#else
         else if ( ncompsz != partstat->st_size ) {
#endif
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr ncompsize = %lu did not match stat value %zu \n", ncompsz, partstat->st_size); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }
         else if ( ((ncompsz * N) - totsz) >= bsz*N ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr total_size = %llu is inconsistent with ncompsz %lu\n", (unsigned long long)totsz, ncompsz); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            continue;
         }
         else {
            handle->totsz = totsz;
            goodfile = 1;
         }

         if ( handle->mode == NE_REBUILD ) {
            filefd = open( file, O_RDONLY );
            if ( filefd == -1 ) {
#ifdef DEBUG
               fprintf( stderr, "error_check: failed to open file %s for read\n", file );
#endif
               handle->src_in_err[counter] = 1;
               handle->src_err_list[handle->nerr] = counter;
               handle->nerr++;
               continue;
            }

            ret_in = ncompsz / bsz;
            bcounter=0;
            scrc = 0;

            while ( bcounter < ret_in ) {

#ifdef INT_CRC
               ret = read(filefd,buf,bsz+sizeof(crc));

               if ( ret != bsz+sizeof(crc) ) {
#else
                  ret = read(filefd,buf,bsz);

               if ( ret != bsz ) {
#endif
#ifdef DEBUG
                  fprintf( stderr, "error_check: failure to read full amt for file %s block %d\n", file, bcounter );
#endif
                  handle->src_in_err[counter] = 1;
                  handle->src_err_list[handle->nerr] = counter;
                  handle->nerr++;
                  break;
               }

#ifdef INT_CRC
                  //store and verify intermediate crc
               crc = crc32_ieee( TEST_SEED, buf, bsz );

               if ( memcmp( &crc, buf+bsz, sizeof(crc) ) != 0 ) {
#ifdef DEBUG
                  fprintf( stderr, "error_check: int-crc mismatch for file %s\n", file );
#endif
                  handle->src_in_err[counter] = 1;
                  handle->src_err_list[handle->nerr] = counter;
                  handle->nerr++;
                  break;
               }

               scrc += crc;
#else
               scrc += crc32_ieee( TEST_SEED, buf, bsz );
#endif
               bcounter++;
            } //end of while loop

            if ( scrc != strtoll(xattrnsum,NULL,0)  &&  handle->src_in_err[counter] == 0 ) {
#ifdef DEBUG
               fprintf( stderr, "error_check: crc mismatch for file %s\n", file );
#endif
               handle->src_in_err[counter] = 1;
               handle->src_err_list[handle->nerr] = counter;
               handle->nerr++;
            }

            close(filefd);

         } //end of if-rebuild

      } //end of if-goodfile/rebuild
   } //end of loop over files

   free(partstat);
   free(buf);

   if ( goodfile == 0 ) {
      errno = EUCLEAN;
      return -1;
   }

   /* If no usable file was located or the number of errors is too great, notify of failure */
   if ( handle->nerr > E ) {
      errno = ENODATA;
      return -1;
   }

   return 0;
}


/**
 * Performs a rebuild operation on the erasure striping indicated by the given handle.
 * @param ne_handle handle : The handle for the erasure striping to be repaired
 * @return int : Status code.  Success is indicated by 0 and failure by -1
 */
int ne_rebuild( ne_handle handle ) {
   int counter;
   int ret_in;
   int nsrcerr=0;
   int i;
   unsigned char *temp_buffs[ MAXPARTS ];
   unsigned int decode_index[ MAXPARTS ];
   char init;
   u32 crc;
   u64 totsizetest;

   if ( handle == NULL ) {
#ifdef DEBUG
      fprintf( stderr, "ne_rebuild: received NULL handle\n" );
#endif
      errno = EINVAL;
      return -1;
   }

   if ( handle->mode != NE_REBUILD ){
#ifdef DEBUG
      fprintf( stderr, "ne_rebuild: handle is in improper mode for rebuild operation" );
#endif
      errno = EPERM;
      return -1;
   }

   init = 1;
   totsizetest = 0;
   /* Perform rebuild over all data */
   while (totsizetest < handle->totsz) {  
      ret_in = 0;
      counter = 0;
      while (counter < (handle->N + handle->E)) {
#ifdef INT_CRC
         if ( init == 1 ) { posix_memalign((void **)&(temp_buffs[counter]),64,(handle->bsz)+sizeof(crc)); }
#else
         if ( init == 1 ) { posix_memalign((void **)&(temp_buffs[counter]),64,handle->bsz); }
#endif
         if (handle->src_in_err[counter] == 1) {
#ifdef DEBUG
            if ( init == 1 ) { fprintf( stdout, "ne_rebuild: zeroing data for faulty file %d\n", counter ); }
#endif
            if ( counter < handle->N  &&  init == 1 ) { nsrcerr++; }
            bzero(handle->buffs[counter], handle->bsz); 
            bzero(temp_buffs[counter], handle->bsz); 
         } else {

#ifdef INT_CRC
            ret_in = read(handle->FDArray[counter],handle->buffs[counter],(handle->bsz)+sizeof(crc)); 
            if ( ret_in < (handle->bsz)+sizeof(crc) ) {
#else
            ret_in = read(handle->FDArray[counter],handle->buffs[counter],handle->bsz); 
            if ( ret_in < (handle->bsz) ) {
#endif
#ifdef DEBUG
               fprintf( stderr, "ne_rebuild: encountered error while reading file %d\n", counter );
#endif
               handle->src_err_list[handle->nerr] = counter;
               handle->src_in_err[counter] = 1;
               handle->nerr++;
               handle->e_ready = 0; //indicate that erasure structs require re-initialization
               if ( counter < handle->N ) { nsrcerr++; }
               continue;
            }

#ifdef INT_CRC
            //calculate and verify crc
            crc = crc32_ieee( TEST_SEED, handle->buffs[counter], handle->bsz );
            if ( memcmp( handle->buffs[counter]+(handle->bsz), &crc, sizeof(u32) ) != 0 ){
#ifdef DEBUG
               fprintf(stderr, "ne_rebuild: mismatch of int-crc for file %d (erasure)\n", counter);
#endif
               handle->src_in_err[counter] = 1;
               handle->src_err_list[handle->nerr] = counter;
               handle->nerr++;
               handle->e_ready = 0; //indicate that erasure structs require re-initialization
               if ( counter < handle->N ) { nsrcerr++; }
               continue;
            }
#endif

         }
         counter++;
      }

      /* Check that errors are still recoverable */
      if ( handle->nerr > handle->E ) {
#ifdef DEBUG
         fprintf( stderr, "ne_rebuild: errors exceed regeneration capacity of erasure\n" );
#endif
         errno = ENODATA;
         return -1;
      }

      /* Regenerate stripe from erasure */
      /* If necessary, initialize the erasure structures */
      if ( handle->e_ready == 0 ) {
         // Generate encode matrix encode_matrix
         // The matrix generated by gf_gen_rs_matrix
         // is not always invertable.
#ifdef DEBUG
         fprintf(stdout,"ne_rebuild: initializing erasure structs...\n");
#endif
         gf_gen_rs_matrix(handle->encode_matrix, handle->N + handle->E, handle->N);

         // Generate g_tbls from encode matrix encode_matrix
         ec_init_tables(handle->N, handle->E, &(handle->encode_matrix[handle->N * handle->N]), handle->g_tbls);

         ret_in = gf_gen_decode_matrix( handle->encode_matrix, handle->decode_matrix,
               handle->invert_matrix, decode_index, handle->src_err_list, handle->src_in_err,
               handle->nerr, nsrcerr, handle->N, handle->N + handle->E);

         if (ret_in != 0) {
#ifdef DEBUG
            fprintf(stderr,"ne_rebuild: failure to generate decode matrix\n");
#endif
            errno = ENODATA;
            return -1;
         }

         for (i = 0; i < handle->N; i++) {
            handle->recov[i] = handle->buffs[decode_index[i]];
         }

#ifdef DEBUG
         fprintf( stdout, "ne_rebuild: init erasure tables nsrcerr = %d...\n", nsrcerr );
#endif
         ec_init_tables(handle->N, handle->nerr, handle->decode_matrix, handle->g_tbls);

         handle->e_ready = 1; //indicate that rebuild structures are initialized
      }
#ifdef DEBUG
      if ( init == 1 ) { fprintf( stdout, "ne_rebuild: performing regeneration from erasure...\n" ); }
#endif
      ec_encode_data(handle->bsz, handle->N, handle->nerr, handle->g_tbls, handle->recov, &temp_buffs[handle->N]);


      for (i = 0; i < handle->nerr; i++) {
         crc = crc32_ieee(TEST_SEED, temp_buffs[handle->N+i], handle->bsz);
#ifdef INT_CRC
         memcpy ( temp_buffs[handle->N+i]+(handle->bsz), &crc, sizeof(crc) );
         write(handle->FDArray[handle->src_err_list[i]],temp_buffs[handle->N+i],(handle->bsz)+sizeof(crc));
#else
         write(handle->FDArray[handle->src_err_list[i]],temp_buffs[handle->N+i],handle->bsz);
#endif
         handle->csum[handle->src_err_list[i]] += crc;
         handle->nsz[handle->src_err_list[i]] += handle->bsz;
         handle->ncompsz[handle->src_err_list[i]] += handle->bsz;
      }
      totsizetest += handle->N*handle->bsz;  
      init = 0;
   }

   for ( counter = 0; counter < (handle->N + handle->E); counter++ ) {
      free( temp_buffs[counter] );
   }

   return 0;
}


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

void dump(unsigned char *buf, int len)
{
        int i;
        for (i = 0; i < len;) {
                printf(" %2x", 0xff & buf[i++]);
                if (i % 32 == 0)
                        printf("\n");
        }
        printf("\n");
}

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
#ifdef DEBUG
		fprintf(stderr,"gf_gen_decode_matrix: failure of malloc\n");
#endif
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
#ifdef DEBUG
			fprintf(stderr,"gf_gen_decode_matrix: BAD MATRIX\n");
#endif
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
#ifdef DEBUG
			fprintf(stderr,"gf_gen_decode_matrix: BAD MATRIX\n");
#endif
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

