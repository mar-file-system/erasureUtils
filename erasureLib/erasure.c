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
   int bsz = BLKSZ;
   int ret;

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
   handle->rem_buff = 0;

   if ( mode == NE_REBUILD  ||  mode == NE_RDONLY ) {
      ret = error_check(handle,path); //idenfity a preliminary error pattern
      if ( ret != 0 ) {
#ifdef DEBUG
         fprintf( stderr, "ne_open: error_check has failed\n" );
#endif
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
   posix_memalign( &(handle->buffer), 64, (N+E)*((bsz*1024)) ); //TODO add space for intermediate checksum
#ifdef DEBUG
   fprintf(stdout,"ne_open: Allocated handle buffer of size %d for bsz=%d, N=%d, E=%d\n", (N+E)*((bsz*1024)), bsz, N, E);
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
      handle->buffs[counter] = handle->buffer + ( counter*bsz*1024 ); //make space for block TODO and its associated crc

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
      }

      counter++;
   }

   return handle;

}

int ne_read( ne_handle handle, void *buffer, int nbytes, off_t offset ) 
{
   int mtot = (handle->N)+(handle->E);
   //char file[MAXNAME];
   //char rebuild = 0;
   int minNerr = handle->N+1;  // greater than N
   int maxNerr = -1;   // less than N
   int nsrcerr = 0;
   int counter;
   int skipped_err;
   char firststripe;
   char firstchunk;
   char error_in_stripe;
   //char xattrval[strlen(XATTRKEY)+50];
   unsigned char *temp_buffs[ MAXPARTS ];
   int N = handle->N;
   int E = handle->E;
   int bsz = handle->bsz;
   int nerr = 0;
   unsigned long datasz[ MAXPARTS ] = {0};
   unsigned long ret_in;
   int tmp;
   unsigned int decode_index[ MAXPARTS ];
   //unsigned char* recov[ MAXPARTS ];
   u32 llcounter;
   u32 readsize;
   u32 startoffset;
   u32 startpart;
   u32 startstripe;
   u32 tmpoffset;
   u32 tmpchunk;
   u32 endchunk;
   //u64 csum;
   //u64 totsz;
   ssize_t out_off;
   off_t seekamt;

   if ( handle->mode != NE_RDONLY  &&  handle->mode != NE_REBUILD ) {
#ifdef DEBUG
      fprintf( stderr, "ne_read: handle is in improper mode for reading!\n" );
#endif
      errno = EPERM;
      return -1;
   }

   if ( offset >= handle->totsz ) {
#ifdef DEBUG
      fprintf( stderr, "ne_read: offset is beyond filesize\n" );
#endif
      return 0;
   }

   if ( (offset + nbytes) > handle->totsz ) {
#ifdef DEBUG
      fprintf(stdout,"ne_read: read would extend beyond EOF, resizing read request...\n");
#endif
      nbytes = handle->totsz - offset;
   }

   for ( counter = 0; counter < mtot; counter++ ) {
      posix_memalign((void **)&(temp_buffs[counter]),64,bsz*1024);       
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


   startstripe = offset / (bsz*1024*N);
   startpart = (offset - (startstripe*bsz*1024*N))/(bsz*1024);
   startoffset = offset - (startstripe*bsz*1024*N) - (startpart*bsz*1024);
#ifdef DEBUG
   fprintf(stdout,"ne_read: read from startstripe %d startpart %d and startoffset %d for nbytes %d\n",startstripe,startpart,startoffset,nbytes);
#endif

   /******** Read Without Rebuild ********/  
   counter = 0;
#ifdef DEBUG
   fprintf(stdout,"ne_read: honor read request with len = %d\n",nbytes);
#endif

   /* Set seek positions within each file */
   while ( counter < N  &&  nsrcerr == 0 ) {
      if (counter < startpart) seekamt = ((startstripe+1)*bsz*1024); 
      if (counter == startpart) seekamt = (startstripe*bsz*1024) + startoffset; 
      if (counter > startpart) seekamt = (startstripe*bsz*1024); 
      tmp = lseek(handle->FDArray[counter],seekamt,SEEK_SET);
      if ( tmp < 0 ) {
#ifdef DEBUG
         fprintf( stderr, "ne_read: encountered error seeking file %d\n", counter );
#endif
         if ( counter > maxNerr )  maxNerr = counter;
         if ( counter < minNerr )  minNerr = counter;
         handle->src_in_err[counter] = 1;
         handle->src_err_list[handle->nerr] = counter;
         handle->nerr++;
         nsrcerr++;
         handle->e_ready = 0; //indicate that erasure structs require re-initialization
         break;
      }
#ifdef DEBUG
      fprintf(stdout,"ne_read: seek input file %d %zd\n",counter, seekamt);
#endif
      counter++;
   }
   llcounter = 0;
   tmpoffset = 0;
   char firstpart = 1;
   
   /* Read in nbytes so long as no errors have been encountered */
   while ( llcounter < nbytes  &&  nsrcerr == 0 ) {
      ret_in = 0;
      counter = 0;
      while ( counter < N ) {
         readsize = bsz*1024;
         if (firstpart ) {
            if( counter == startpart) {
               /*if ( counter < startpart ) {
                 datasz[counter] = 0;
                 counter++;
                 continue;
                 }*/
               firstpart = 0;
               readsize = bsz*1024-startoffset;
            }
            else {
               counter++;
               continue;
            }
         } 
         if ((nbytes-tmpoffset) < readsize) readsize = nbytes-tmpoffset;
#ifdef DEBUG
         fprintf(stdout,"ne_read: preparing to read %lu from datafile %d\n",(unsigned long)readsize,counter);
#endif

         /**** read ****/
         tmp = read( handle->FDArray[counter], handle->buffs[counter], readsize );
         if ( tmp < 0 ) {
#ifdef DEBUG
            fprintf(stderr, "ne_read: encoutered error while reading from file %d without rebuild\n", counter);
#endif
            if ( counter > maxNerr )  maxNerr = counter;
            if ( counter < minNerr )  minNerr = counter;
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
            nsrcerr++;
            handle->e_ready = 0; //indicate that erasure structs require re-initialization
            break;
         }
         datasz[counter] = tmp;
         ret_in += tmp;
         tmpoffset += tmp;
         if ( tmp < readsize ) {
            nbytes = llcounter + tmpoffset;
#ifdef DEBUG
            fprintf(stdout, "ne_read: Input exhausted, limiting read size to %d\n", nbytes);
#endif
            break;
         }
         counter++;
      }
      if ( nsrcerr != 0 ) {
         break;
      }

      llcounter = tmpoffset;

      /**** copy to buffer ****/
      counter = 0;
      while ( counter < N ) {
#ifdef DEBUG
         fprintf(stdout,"ne_read: writing %lu to buffer at offset %lu\n",datasz[counter],(llcounter-ret_in));
#endif
         memcpy( buffer+(llcounter-ret_in), handle->buffs[counter], datasz[counter] );
         ret_in -= datasz[counter];
         datasz[counter] = 0;
         //if( counter >= N ) counter = 0;
         counter++;
      }

      if ( ret_in != 0 ) {
#ifdef DEBUG
         fprintf( stderr, "ne_read: mismatch between bytes read and output of %lu\n", ret_in );
#endif
         errno=ENOTRECOVERABLE;
         return -1;
      }

#ifdef DEBUG
      fprintf( stdout, "ne_read: total output = %lu\n", (unsigned long)llcounter );
#endif
   }

   /******** Rebuild While Reading ********/
rebuild:

   if (nsrcerr != 0) { 
#ifdef DEBUG
      fprintf(stdout,"ne_read: honor read request with rebuild\n");
#endif
      startstripe = (offset+llcounter) / (bsz*1024*N);
      startpart = (offset + llcounter - (startstripe*bsz*1024*N))/(bsz*1024);
      startoffset = offset+llcounter - (startstripe*bsz*1024*N) - (startpart*bsz*1024);
#ifdef DEBUG
      fprintf(stdout,"ne_read: read with rebuild from startstripe %d startpart %d and startoffset %d for nbytes %d\n",startstripe,startpart,startoffset,nbytes);
#endif

      counter = 0;

      endchunk = ((offset+nbytes) - (startstripe*N*bsz*1024) ) / (bsz*1024);

      if ( endchunk >= N ) {
         endchunk = mtot - 1;
      }     

      /**** set seek positions for initial reading ****/
      if (startpart > maxNerr  ||  endchunk < minNerr ) {  //if not reading from corrupted chunks, we can just set these normally
         for ( counter = 0; counter <= endchunk; counter++ ) {
            if (counter < startpart) {
               seekamt = (startstripe*bsz*1024) + (bsz*1024); 
            }
            else if (counter == startpart) {
               seekamt = (startstripe*bsz*1024) + startoffset; 
            }
            else { 
               seekamt = (startstripe*bsz*1024); 
            }
            if( handle->src_in_err[counter] == 0 ) {
               if ( counter < N ) {
#ifdef DEBUG
                  fprintf(stdout,"seeking input file %d to %zd, as there is no error in this stripe\n",counter, seekamt);
#endif
               }
               else {
                  seekamt += (bsz*1024);
#ifdef DEBUG
                  fprintf(stdout,"seeking erasure file e%d to %zd, as we will be reading from the next stripe\n",counter-N, seekamt);
#endif
               }
               tmp = lseek(handle->FDArray[counter],seekamt,SEEK_SET);

               //if we hit an error here, seek positions are wrong and we must restart
               if ( tmp < 0 ) {
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
               tmp = lseek(handle->FDArray[counter],(startstripe*bsz*1024),SEEK_SET);
#ifdef DEBUG
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
               fprintf(stdout,"seek input file %d to %lu, to read entire stripe\n",counter, (unsigned long)(startstripe*bsz*1024));
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

         endchunk = ((long)(offset+nbytes+1) - (long)((long)(startstripe*N*bsz*1024) + llcounter) ) / (bsz*1024);
         skipped_err = 0;
         
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
            readsize = bsz*1024-tmpoffset;

            if ( llcounter == nbytes  &&  !error_in_stripe ) {
#ifdef DEBUG
               fprintf(stdout, "ne_read: data reads complete\n");
#endif
               break;
            }

            if ( handle->src_in_err[counter] == 1 ) {  //this data chunk is invalid
#ifdef DEBUG
               fprintf(stdout,"ne_read: zeroing data for faulty chunk %d\n",counter);
#endif
               bzero(handle->buffs[counter],bsz*1024);
#ifdef DEBUG
               fprintf(stdout,"ne_read: zeroing tmp_data for faulty chunk %d\n",counter);
#endif
               bzero(temp_buffs[counter],bsz*1024);

               error_in_stripe = 1;

               if ( firstchunk == 1  &&  counter == startpart ) {
                  llcounter = (readsize - (startoffset-tmpoffset) < nbytes ) ? readsize-(startoffset-tmpoffset) : nbytes;
                  datasz[counter] = llcounter;
                  firstchunk = 0;
               }
               else if ( firstchunk == 0 ) {

                  llcounter += readsize;

                  if ( llcounter < nbytes ) {
                     datasz[counter] = readsize;
                  }
                  else {
                     datasz[counter] = nbytes - (llcounter - readsize);
                     llcounter=nbytes;
                  }
               }
               else {
                  skipped_err++;
               }

            }
            else {    //this data chunk is valid, store it
               if ( (nbytes-llcounter) < readsize  &&  error_in_stripe == 0 ) {
                  readsize = nbytes-llcounter;
               }

#ifdef DEBUG
               fprintf(stdout,"read %d from datafile %d\n",readsize,counter);
#endif
               ret_in = read( handle->FDArray[counter], handle->buffs[counter], readsize );
               //check for a read error
               if ( ret_in < readsize ) {
                  if ( ret_in < 0 ) {
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
                     //if we have skipped some of the stripe, we must start over
                     if ( error_in_stripe == 0 && tmpoffset != 0 ) {
                        for( tmp = counter -1; tmp >=0; tmp-- ) {
                           llcounter -= datasz[counter];
                        }
                        goto rebuild;
                     }
                  }
                  else {
                     nbytes = llcounter + ret_in;
#ifdef DEBUG
                     fprintf(stderr, "ne_read: inputs exhausted, limiting read to %d bytes\n",nbytes);
#endif
                  }

#ifdef DEBUG
                  fprintf(stderr, "ne_read: failed to read all requested data from file %d\n", counter);
                  fprintf(stdout,"ne_read: zeroing missing data for %d from %lu to %d\n",counter,ret_in,bsz*1024);
#endif
                  bzero(handle->buffs[counter]+ret_in,bsz*1024-ret_in);
#ifdef DEBUG
                  fprintf(stdout,"ne_read: zeroing temp_data for data block %d\n",counter);
#endif
                  bzero(temp_buffs[counter],bsz*1024);
                  

               }

               if ( firstchunk  &&  counter == startpart ) {
                  llcounter = (ret_in - (startoffset-tmpoffset) < nbytes ) ? ret_in-(startoffset-tmpoffset) : nbytes;
                  datasz[counter] = llcounter;
                  firstchunk = 0;
               }
               else if ( !firstchunk ) {
                  llcounter += ret_in;
                  if ( llcounter < nbytes ) {
                     datasz[counter] = ret_in;
                  }
                  else {
                     datasz[counter] = nbytes - (llcounter - ret_in);
                     llcounter = nbytes;
                  }
               }

            }

#ifdef DEBUG
            fprintf(stderr, "ne_read: nbytes = %d, llcounter = %lu, read_size = %d\n", nbytes, (unsigned long)llcounter, readsize);
#endif
            tmpoffset = 0;

         } //completion of read from stripe

         //notice, we only need the erasure stripes if we hit an error
         while ( counter < mtot  &&  error_in_stripe == 1 ) {

            readsize = bsz*1024; //may want to limit later

            if( handle->src_in_err[counter] ) {
#ifdef DEBUG
               fprintf(stdout,"ne_read: zeroing data for faulty erasure %d\n",counter);
#endif
               bzero(handle->buffs[counter],bsz*1024);
#ifdef DEBUG
               fprintf(stdout,"ne_read: zeroing temp_data for faulty erasure %d\n",counter);
#endif
               bzero(temp_buffs[counter],bsz*1024);
            }
            else {
#ifdef DEBUG
               fprintf(stdout,"ne_read: reading %d from erasure %d\n",readsize,counter);
#endif
               ret_in = read( handle->FDArray[counter], handle->buffs[counter], readsize );
               if ( ret_in < readsize ) {
                  if ( ret_in < 0 ) {
                     ret_in = 0;
                     if ( counter > maxNerr )  maxNerr = counter;
                     if ( counter < minNerr )  minNerr = counter;
                     handle->src_in_err[counter] = 1;
                     handle->src_err_list[handle->nerr] = counter;
                     handle->nerr++;
                     handle->e_ready = 0; //indicate that erasure structs require re-initialization
                     error_in_stripe = 1;
                  }
                  else if ( ret_in > readsize ) { //this likely will never happen.  Included for completeness though.
#ifdef DEBUG
                     fprintf( stderr, "ne_read: value read from erasure file %d was larger than expected\n", counter );
#endif
                     ret_in = readsize;
                  }
#ifdef DEBUG
                  fprintf(stderr, "ne_read: failed to read erasure data in file %d\n", counter);
                  fprintf(stdout,"ne_read: zeroing data for faulty erasure %d from %lu to %d\n",counter,ret_in,bsz*1024);
#endif
                  bzero(handle->buffs[counter]+ret_in,bsz*1024-ret_in);
#ifdef DEBUG
                  fprintf(stdout,"ne_read: zeroing temp_data for faulty erasure %d\n",counter);
#endif
                  bzero(temp_buffs[counter],bsz*1024);
#ifdef DEBUG
                  fprintf(stdout,"ne_read: done zeroing %d\n",counter);
#endif
               }
            }
            counter++;
         }


         if ( handle->nerr > handle->E ) {
#ifdef DEBUG
            fprintf( stderr, "ne_read: encoutered errors exceed erasure limits\n" );
#endif
            errno = ENODATA;
            break;
         }

         /**** regenerate from erasure ****/
         if ( error_in_stripe == 1 ) {

            /* If necessary, initialize the erasure structures */
            if ( nsrcerr > 0  &&  handle->e_ready == 0 ) {
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
                  fprintf(stderr,"ne_read: failure to generate decode matrix\n");
#endif
                  errno=ENODATA;
                  return -1;
               }

               for (tmp = 0; tmp < N; tmp++) {
                  handle->recov[tmp] = handle->buffs[decode_index[tmp]];
               }

               handle->e_ready = 1; //indicate that rebuild structures are initialized
            }

#ifdef DEBUG
            fprintf( stdout, "ne_read: init erasure tables nsrcerr = %d e_ready = %d...\n", nsrcerr, handle->e_ready );
#endif
            ec_init_tables(N, handle->nerr, handle->decode_matrix, handle->g_tbls);
#ifdef DEBUG
            fprintf( stdout, "ne_read: performing regeneration from erasure...\n" );
#endif
            ec_encode_data(bsz*1024, N, handle->nerr, handle->g_tbls, handle->recov, &temp_buffs[N]);
         }


         /**** write appropriate data out ****/
         for( counter=startpart, tmp=0; counter <= endchunk; counter++ ) {
            readsize = datasz[counter];

#ifdef DEBUG
            if ( readsize > llcounter ) { fprintf(stderr,"ne_read: GROSS ERROR!!!\n"); }
#endif

            if ( handle->src_in_err[counter] == 0 ) {
#ifdef DEBUG
               fprintf( stdout, "Performing write of %d from chunk %d data\n", readsize, counter );
#endif

               if ( firststripe  &&  counter == startpart  &&  error_in_stripe ) {
#ifdef DEBUG
                  fprintf( stdout, "   with offset of %d\n", startoffset );
#endif
                  memcpy( buffer+out_off, (handle->buffs[counter])+startoffset, readsize );
               }
               else {
                  memcpy( buffer+out_off, handle->buffs[counter], readsize );
               }
            }
            else {
#ifdef DEBUG
               fprintf( stdout, "ne_read: performing write of %d from regenerated chunk %d data, src_err = %d\n", readsize, counter, handle->src_err_list[tmp] );
#endif
               if ( firststripe ) {
                  if ( counter == startpart ) {
#ifdef DEBUG
                     fprintf( stdout, "   with offset of %d\n", startoffset );
                     fprintf( stdout, "   Accounting for a skip of %d blocks\n", skipped_err );
#endif
                     memcpy( buffer+out_off, (temp_buffs[N+tmp+skipped_err])+startoffset, readsize );
                  }
                  else {
#ifdef DEBUG
                     fprintf( stdout, "   Accounting for a skip of %d blocks\n", skipped_err );
#endif
                     memcpy( buffer+out_off, temp_buffs[N+tmp+skipped_err], readsize );
                  }
               }
               else {
#ifdef DEBUG
                  fprintf( stdout, "   no errors skipped\n" );
#endif
                  memcpy( buffer+out_off, temp_buffs[N+tmp], readsize );
               }

               tmp++;

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
         out_off = llcounter;
         for ( counter = 0; counter < N; counter++ ) {
            datasz[counter] = 0;
         }
         counter = 0; tmpoffset = 0; tmpchunk = 0; startpart=0;

      } //end of generating loop for each stripe

   } //end of "Read with rebuild" case

   for( counter = 0; counter < N+E; counter++ ) {
      free(temp_buffs[counter]);
   }

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
   int bsz;                     /* chunksize in k */ 
   int counter;                 /* general counter */
   int ecounter;                /* general counter */
   int buflen;                   /* general int */
   ssize_t ret_out;     /* Number of bytes returned by read() and write() */
   unsigned long long totsize;            /* used to sum total size of the input file/stream */
   int mtot;                   /* N + numerasure stripes */
   int loops;                    /* general counter for loops */
   u32 writesize;
   u32 crc;                      /* crc 32 */

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
   loops = 0;
   while (1) { 
#ifdef DEBUG
      fprintf(stdout, "ne_write: iteration %d for write of size %d\n", loops, nbytes);
#endif
      
      /* check for any data remaining within the handle buffer */
      if ( handle->rem_buff != 0 ) {
         writesize = N*bsz*1024 - handle->rem_buff;
         if ( totsize + writesize > nbytes ) { writesize = nbytes-totsize; }
         if ( writesize > 0 ) {
#ifdef DEBUG
            fprintf( stdout, "ne_write: reading input for %lu bytes with offset of %llu\n          and writing to offset of %lu in handle buffer\n", (unsigned long)writesize, totsize, handle->rem_buff );
#endif
            memcpy ( handle->buffer + handle->rem_buff, buffer+totsize, writesize);
#ifdef DEBUG
            fprintf(stdout, "ne_write:   ...copy complete.\n");
#endif
            totsize += writesize;
         }
         else if ( handle->rem_buff < N*bsz*1024 ) {
#ifdef DEBUG
            fprintf(stdout,"ne_write: reading of input is now complete\n");
#endif
            break;
         }
         writesize += handle->rem_buff;
         handle->rem_buff = 0;
      }
      else { //if none there, read all input from the buffer argument
         writesize = N*bsz*1024;
         if ( totsize + writesize > nbytes ) { writesize = nbytes-totsize; }
         if ( writesize < 1 ) {
#ifdef DEBUG
            fprintf(stdout,"ne_write: reading of input is now complete\n");
#endif
            break;
         }
#ifdef DEBUG
         fprintf( stdout, "ne_write: reading input for %lu bytes with offset of %llu\n", (unsigned long)writesize, totsize );
#endif
         memcpy ( handle->buffer, buffer+totsize, writesize);
#ifdef DEBUG
         fprintf(stdout, "ne_write:   ...copy compete.\n");
#endif
         totsize+=writesize;
      }
      if ( writesize < N*bsz*1024 ) {  //if there is not enough data to write a full stripe, stash it in the handle buffer
#ifdef DEBUG
         fprintf(stdout,"ne_write: reading of input is complete, stashing %lu bytes in handle buffer\n", writesize-handle->rem_buff);
#endif
         handle->rem_buff = writesize;
         break;
      }


      counter = 0;
      /* loop over the parts and write the parts, sum and count bytes per part etc. */
      while (counter < N) {

         if ( handle->src_in_err[counter] == 0 ) {
            /* this is the crcsum for each part */
            crc = crc32_ieee(TEST_SEED, handle->buffs[counter], bsz*1024);
            // TODO write out per-block-crc
            /* if we were compressing we would compress here */
            buflen = 1024*bsz;
#ifdef DEBUG
            fprintf(stdout,"ne_write: wr %d to file %d\n",buflen,counter);
#endif
            ret_out = write(handle->FDArray[counter],handle->buffs[counter],buflen); 
            
            if ( ret_out != buflen ) {
#ifdef DEBUG
               fprintf( stderr, "ne_write: write to file %d returned %zd instead of expected %d\n" , counter, ret_out, buflen );
#endif
               handle->src_in_err[counter] = 1;
               handle->src_err_list[handle->nerr] = counter;
               handle->nerr++;
            }

            handle->csum[counter] += crc; 
            handle->nsz[counter] += bsz*1024;
            handle->ncompsz[counter] += buflen;
         }
         counter++;
      }

      /* calculate and write erasure */
      if ( handle->e_ready == 0 ) {
         loops=MAXPARTS;
#ifdef DEBUG
         fprintf(stdout, "ne_write: initializing erasure matricies MAX = %d...\n", loops);
#endif
         // Generate encode matrix encode_matrix
         // The matrix generated by gf_gen_rs_matrix
         // is not always invertable.
         gf_gen_rs_matrix(handle->encode_matrix, mtot, N);
         // Generate g_tbls from encode matrix encode_matrix
         ec_init_tables(N, E, &(handle->encode_matrix[N * N]), handle->g_tbls);

         handle->e_ready = 1;
#ifdef DEBUG
         fprintf(stdout, "                           N=%d, E=%d, mtot=%d, enc_mt=%p, g_tbls=%p\n", N, E, mtot, (void *)handle->encode_matrix, (void *)handle->g_tbls);
#endif
      }

#ifdef DEBUG
      fprintf(stdout, "ne_write: caculating %d recovery stripes from %d data stripes\n",E,N);
#endif
      // Perform matrix dot_prod for EC encoding
      // using g_tbls from encode matrix encode_matrix
      ec_encode_data( bsz*1024, N, E, handle->g_tbls, handle->buffs, &(handle->buffs[N]) );

      ecounter = 0;
      while (ecounter < E) {
         crc = crc32_ieee(TEST_SEED, handle->buffs[counter+ecounter], bsz*1024); 
         handle->csum[counter+ecounter] += crc; 
         handle->nsz[counter+ecounter] += bsz*1024;
         handle->ncompsz[counter+ecounter] += bsz*1024;
#ifdef DEBUG
         fprintf( stdout, "ne_write: writing out erasure stripe %d\n", ecounter );
#endif
         ret_out = write(handle->FDArray[counter+ecounter],handle->buffs[counter+ecounter],bsz*1024); 
         
         if ( ret_out != bsz*1024 ) {
#ifdef DEBUG
            fprintf( stderr, "ne_write: write to erasure file %d, returned %zd instead of expected %d\n" , ecounter, ret_out, bsz*1024 );
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
         }

         ecounter++;
      } 
      counter++;
      loops++;

#ifdef DEBUG
      fprintf( stdout, "ne_write: completed iteration for stripe %d\n", loops );
#endif
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
   int N = handle->N;
   int E = handle->E;
   int bsz = handle->bsz;
   int ret = EXIT_SUCCESS;
   int tmp;

   /* flush the handle buffer if necessary */
   if ( handle->mode == NE_WRONLY  &&  handle->rem_buff ) {
      //zero the buffer to the end of the stripe
      tmp = (N*bsz*1024) - handle->rem_buff;
      bzero(handle->buffer+handle->rem_buff, tmp );
      handle->rem_buff += tmp;

      if ( 0 != ne_write( handle, NULL, 0 ) ) { //make ne_write do all the work
#ifdef DEBUG
         fprintf( stderr, "ne_close: failed to flush handle buffer\n" );
#endif
         ret = -1;
      }

   }

   /* Close file descriptors and free bufs and set xattrs for written files */
   counter = 0;
   while (counter < N+E) {
      if ( handle->mode == NE_WRONLY ) { 
         bzero(xattrval,sizeof(xattrval));
         sprintf(xattrval,"%d %d %d %lu %lu %zu %zu",N,E,bsz,handle->nsz[counter],handle->ncompsz[counter],handle->csum[counter],handle->totsz);
#ifdef DEBUG
         fprintf( stdout, "file %d xattr = \"%s\"\n", counter, xattrval );
#endif
         tmp = fsetxattr(handle->FDArray[counter],XATTRKEY, xattrval,strlen(xattrval),0); 
         
         if ( tmp != EXIT_SUCCESS ) {
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
  
   if ( ret == EXIT_SUCCESS ) { 
      /* Encode any file errors into the return status */
      for( counter = 0; counter < N+E; counter++ ) {
         if ( handle->src_in_err[counter] ) { ret += ( 1 << (counter + handle->erasure_offset) % (N+E) ); }
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
   int bsz = handle->bsz;
   unsigned long nsz;
   unsigned long ncompsz;
   u64 scrc;
   char goodfile = 0;
   u64 totsz;
   struct stat* partstat = malloc (sizeof(struct stat));
   void *buf;

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

         /* verify xattr */
#ifdef DEBUG
         fprintf(stdout,"error_check: total file size is %llu numparts %d erasure %d blocksize %d\n",(unsigned long long)totsz,N,E,bsz);
#endif
         if ( N != handle->N ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr N = %d did not match handle value  %d \n", N, handle->N); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
         }
         else if ( E != handle->E ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr E = %d did not match handle value  %d \n", E, handle->E); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
         }
         else if ( bsz != handle->bsz ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr bsz = %d did not match handle value  %d \n", bsz, handle->bsz); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
         }
         else if ( nsz != partstat->st_size ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr nsize = %lu did not match stat value %zu \n", nsz, partstat->st_size); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
         }
         else if ( (nsz % bsz) != 0 ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr nsize = %lu is inconsistent with block size %d \n", nsz, bsz); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
         }
         else if ( ncompsz != partstat->st_size ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr ncompsize = %lu did not match stat value %zu \n", ncompsz, partstat->st_size); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
         }
         else if ( ((ncompsz * N) - totsz) >= bsz*1024*N ) {
#ifdef DEBUG
            fprintf (stderr, "error_check: filexattr total_size = %llu is inconsistent with ncompsz %lu\n", (unsigned long long)totsz, ncompsz); 
#endif
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
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

            ret_in = ncompsz / (bsz*1024);
            bcounter=0;
            posix_memalign(&buf,32,bsz*1024);
            scrc = 0;

            while ( bcounter < ret_in ) {

               ret = read(filefd,buf,bsz*1024);

               if ( ret != bsz*1024 ) {
#ifdef DEBUG
                  fprintf( stderr, "error_check: failure to read full amt for file %s block %d\n", file, bcounter );
#endif
                  handle->src_in_err[counter] = 1;
                  handle->src_err_list[handle->nerr] = counter;
                  handle->nerr++;
                  break;
               }
               scrc += crc32_ieee( TEST_SEED, buf, bsz*1024 );

               bcounter++;
            }

            if ( scrc != strtoll(xattrnsum,NULL,0) ) {
#ifdef DEBUG
               fprintf( stderr, "error_check: crc mismatch for file %s\n", file );
#endif
               handle->src_in_err[counter] = 1;
               handle->src_err_list[handle->nerr] = counter;
               handle->nerr++;
            }

            free(buf);

         } 

      }
   }

   if ( goodfile == 0 ) {
      errno = EUCLEAN;
      return -1;
   }

   free(partstat);

   /* If no usable file was located or the number of errors is too great, notify of failure */
   if ( handle->nerr > E ) {
      errno = ENODATA;
      return -1;
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

