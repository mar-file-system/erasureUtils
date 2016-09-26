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

void ec_init_tables(int k, int rows, unsigned char *a, unsigned char *g_tbls);
void dump(unsigned char *buf, int len);
static int gf_gen_decode_matrix(unsigned char *encode_matrix,
				unsigned char *decode_matrix,
				unsigned char *invert_matrix,
				unsigned int *decode_index,
				unsigned char *src_err_list,
				unsigned char *src_in_err,
				int nerrs, int nsrcerrs, int k, int m);


ne_handle ne_open( char *path, ne_mode mode, int erasure_offset, int N, int E )
{

   char file[MAXNAME];       /* array name of files */
   int counter;
   int bsz = BLKSZ;

   ne_handle handle = malloc( sizeof( struct handle ) );

   if ( N < 1  ||  N > MAXN ) {
      fprintf( stderr, "improper N arguement received - %d\n", N );
      errno = EINVAL;
      return NULL;
   }
   if ( E < 0  ||  E > MAXE ) {
      fprintf( stderr, "improper E arguement received - %d\n", E );
      errno = EINVAL;
      return NULL;
   }
//   if ( bsz < 0 ) {
//      fprintf( stderr, "improper bsz arguement received - %d\n", bsz );
//      errno = EINVAL;
//      return NULL;
//   }
   if ( erasure_offset < 0  ||  erasure_offset >= N+E ) {
      fprintf( stderr, "improper erasure_offset arguement received - %d\n", erasure_offset );
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
      ; //TODO identify failure pattern
   }
   else if ( mode != NE_WRONLY ) {
      fprintf( stderr, "improper mode argument received - %d\n", mode );
      errno = EINVAL;
      return NULL;
   }

   /* allocate a big buffer for all the N chunks plus a bit extra for reading in crcs */
   posix_memalign( &(handle->buffer), 64, (N+E)*(handle->bsz*1024+sizeof(u32)) );

   /* allocate matrices */
   handle->encode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->decode_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->invert_matrix = malloc(MAXPARTS * MAXPARTS);
   handle->g_tbls = malloc(MAXPARTS * MAXPARTS * 32);


   /* loop through and open up all the output files and initilize per part info and allocate buffers */
   counter = 0;
   fprintf( stderr, "opening file descriptors...\n" );
   while ( counter < N+E ) {
      handle->csum[counter] = 0;
      handle->nsz[counter] = 0;
      handle->ncompsz[counter] = 0;
      bzero( file, MAXNAME );
      sprintf( file, path, (counter+erasure_offset)%(N+E) );
      handle->buffs[counter] = handle->buffer + counter*(bsz*1024 ); //make space for block TODO and its associated crc

      if( mode == NE_WRONLY  ||  (mode == NE_REBUILD && handle->src_in_err[counter]) ) {
         fprintf( stderr, "   opening %s for write\n", file );
         handle->FDArray[counter] = open( file, O_WRONLY | O_CREAT, 0666 );
      }
      else {
         fprintf( stderr, "   opening %s for read\n", file );
         handle->FDArray[counter] = open( file, O_RDONLY );
      }

      if ( handle->FDArray[counter] == -1  &&  handle->src_in_err[counter] == 0 ) {
         fprintf( stderr, "   failed to open file %s!!!!\n", file );
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
   int goodfile = 999;
   int minNerr = handle->N+1;  // greater than N
   int maxNerr = -1;   // less than N
   int nsrcerr = 0;
   int counter;
   //char xattrval[strlen(XATTRKEY)+50];
   int N = handle->N;
   int E = handle->E;
   int bsz = handle->bsz;
   int nerr = 0;
   unsigned long datasz[ MAXN + MAXE ];
   int ret_in;
   int tmp;
   unsigned int decode_index[ MAXN + MAXE ];
   u32 llcounter;
   u32 readsize;
   u32 startoffset;
   u32 startpart;
   u32 startstripe;
   //u64 csum;
   //u64 totsz;
   ssize_t ret_out;
   off_t seekamt;

   if ( handle->mode != NE_RDONLY  &&  handle->mode != NE_REBUILD ) {
      fprintf( stderr, "ne_read: handle is in improper mode for reading!\n" );
      errno = EPERM;
      return -1;
   }


   for ( counter = 0; counter < mtot; counter++ ) {
      if ( handle->src_in_err[counter] ) {
         nerr++;
         if ( counter < N ) { 
            nsrcerr++;
            if ( counter > maxNerr ) { maxNerr = counter; }
            if ( counter < minNerr ) { minNerr = counter; }
         }
      }
      else {
         goodfile = counter;
      }
   }

   if ( handle->nerr != nerr  ||  goodfile == 999 ) {
      fprintf( stderr, "ne_read: iconsistent internal state\n" );
      errno = EBADFD;
      return -1;
   }

   //TODO 'goodfile' xattr check seems redundant here, may be useful in health check though.
//   bzero(file,sizeof(file));
//   sprintf(file,handle->path,goodfile);
//
//   /* go to the a good file depending on missing (there can only be one missing) and get the xattr to tell us how big the file is, num parts, chunk size, etc. */
//   bzero( xattrval, sizeof(xattrval) );
//   getxattr( file, XATTRKEY, &xattrval[0], sizeof(xattrval) );
//   fprintf(stderr,"got xattr %s for %s\n",xattrval,file);
//   sscanf(xattrval,"%d %d %d %d %d %llu %llu",N,E,bsz,nsz,ncompsz,csum,totsz);
//
//   /* edit stuff from xattr */
//   fprintf(stderr,"total file size is %llu numparts %d ncompsize %d erasure %d blocksize %d\n",totsz,N,ncompsz,E,bsz);
//   if ( N != handle->N ) {
//      fprintf (stderr, "ne_read: filexattr N = %d did not match handle value  %d \n", N, handle->N); 
//      errno = EBADFD;
//      return -1;
//   }
//   if ( E != handle->E ) {
//      fprintf (stderr, "ne_read: filexattr E = %d did not match handle value  %d \n", E, handle->E); 
//      errno = EBADFD;
//      return -1;
//   }
//   if ( bsz != handle->bsz ) {
//      fprintf (stderr, "ne_read: filexattr bsz = %d did not match handle value  %d \n", bsz, handle->bsz); 
//      errno = EBADFD;
//      return -1;
//   }
//   if ( nsz != handle->nsz[goodfile] ) {
//      fprintf (stderr, "ne_read: filexattr nsz = %d did not match handle value  %d \n", nsz, handle->nsz); 
//      errno = EBADFD;
//      return -1;
//   }
//   if ( ncompsz != handle->ncompsz[goodfile] ) {
//      fprintf (stderr, "ne_read: filexattr ncompsz = %d did not match handle value  %d \n", ncompsz, handle->ncompsz); 
//      errno = EBADFD;
//      return -1;
//   }
//   if ( csum != handle->csum[goodfile] ) {
//      fprintf (stderr, "ne_read: filexattr E = %llu did not match handle value  %llu \n", csum, handle->csum[goodfile]); 
//      errno = EBADFD;
//      return -1;
//   }
//   if ( totsz != handle->totsz ) {
//      fprintf (stderr, "ne_read: filexattr totsz = %d did not match handle value  %d \n", totsz, handle->totsz); 
//      errno = EBADFD;
//      return -1;
//   }


   if ( nsrcerr > 0  &&  ! handle->e_ready ) {
      // Generate encode matrix encode_matrix
      // The matrix generated by gf_gen_rs_matrix
      // is not always invertable.
      gf_gen_rs_matrix(handle->encode_matrix, mtot, N);

      // Generate g_tbls from encode matrix encode_matrix
      ec_init_tables(N, E, &(handle->encode_matrix[N * N]), handle->g_tbls);

      ret_in = gf_gen_decode_matrix( handle->encode_matrix, handle->decode_matrix,
         handle->invert_matrix, decode_index, handle->src_err_list, handle->src_in_err,
         handle->nerr, nsrcerr, N, mtot);

      if (ret_in != 0) {
         fprintf(stderr,"Fail to gf_gen_decode_matrix\n");
         return -1;
      }

      handle->e_ready = 1; //indicate that rebuild structures are initialized
   }

   /* open input files initialize some per part values, skip opening missing files  erasure if not in rebuild mode1  */
   /*counter = 0;
   while (counter < mtot) {
      bzero(file,MAXNAME);
      if (counter < ntot) {
         sprintf(infile,"%s.%d",argv[1],counter);
      } else {
         sprintf(infile,"%s.e%d",argv[1],counter-ntot);
      }
      if (src_in_err[counter] == 0) {
         input_fd[counter] = open(infile, O_RDONLY);
         if (input_fd[counter] == -1) {
            perror("open of input");
            exit(-9);
         }
         fprintf(stderr,"opening file %s\n",infile);
      } 
      posix_memalign(&buf,64,chunksize*1024);       
      buffs[counter]=buf;
      posix_memalign(&buf,64,chunksize*1024);       
      temp_buffs[counter]=buf;
      sum[counter] = 0;
      nsz[counter] = 0;
      ncompsz[counter] = 0;
      counter++;        
   }*/

   startstripe = offset / (bsz*1024*N);
   startpart = (offset - (startstripe*bsz*1024*N))/(bsz*1024);
   startoffset = offset - (startstripe*bsz*1024*N) - (startpart*bsz*1024);
   fprintf(stderr,"read from startstripe %d startpart %d and startoffset %d for nbytes %d\n",startstripe,startpart,startoffset,nbytes);

   /******** Read Without Rebuild ********/  
   counter = 0;
   fprintf(stderr,"ne_read: honor read request with len = %d\n",nbytes);
   while ( counter < N  &&  nsrcerr == 0 ) {
      if (counter < startpart) seekamt = ((startstripe+1)*bsz*1024); 
      if (counter == startpart) seekamt = (startstripe*bsz*1024) + startoffset; 
      if (counter > startpart) seekamt = (startstripe*bsz*1024); 
      tmp = lseek(handle->FDArray[counter],seekamt,SEEK_SET);
      if ( tmp < 0 ) {
         fprintf( stderr, "ne_read: encountered error seeking file %d\n", counter );
         handle->src_in_err[counter] = 1;
         handle->src_err_list[nerr] = counter;
         nerr++;
         nsrcerr++;
         handle->e_ready = 0; //indicate that erasure structs require re-initialization
         break;
      }
      fprintf(stderr,"ne_read: seek input file %d %zd\n",counter, seekamt);
      counter++;
   }
   llcounter = 0;
   char firstpart = 1;
   counter = startpart;
   
   while ( llcounter < nbytes  &&  nsrcerr == 0 ) {
      ret_in = 0;
      counter = 0;
      while ( counter < N ) {
         readsize = bsz*1024;
         if (firstpart) {
            if ( counter < startpart ) {
               datasz[counter] = 0;
               counter++;
               continue;
            }
            firstpart = 0;
            readsize = bsz*1024-startoffset;
         } 
         if ((nbytes-llcounter) < readsize) readsize = nbytes-llcounter;
         fprintf(stderr,"ne_read: preparing to read %lu from datafile %d\n",(unsigned long)readsize,counter);

         /**** read ****/
         ret_out = read( handle->FDArray[counter], handle->buffs[counter], readsize );
         datasz[counter] = ret_out;
         if ( ret_out < 0 ) {
            fprintf(stderr, "ne_read: encoutered error while reading from file %d without rebuild\n", counter);
            handle->src_in_err[counter] = 1;
            handle->src_err_list[nerr] = counter;
            nerr++;
            nsrcerr++;
            handle->e_ready = 0; //indicate that erasure structs require re-initialization
            break;
         }
         ret_in += ret_out;
         if ( ret_out == 0 ) {
            fprintf(stderr, "ne_read: Input exhausted\n");
            break;
         }
         counter++;
      }
      if ( nsrcerr ) {
         break;
      }

      llcounter = llcounter + ret_in;

      /**** write ****/
      counter = 0;
      while ( counter < N ) {
         buffer = memcpy( buffer, handle->buffs[counter], datasz[counter] );
         fprintf(stderr,"ne_read: wrote out %lu to buffer\n",datasz[counter]);
         ret_in -= datasz[counter];
         if( counter >= N ) counter = 0;
         counter++;
      }

      fprintf( stderr, "ne_read: total output = %lu\n", (unsigned long)llcounter );

   }

   /******** Rebuild While Reading ********/
//   if (nsrcerr != 0) { //TODO refactor end
//      fprintf(stderr,"honor read request with rebuild\n");
//
//
//      counter = 0;
//
//      endchunk = ((offset+nbytes) - (startstripe*N*bsz*1024) ) / (bsz*1024);
//
//      if ( endchunk >= ntot ) {
//         endchunk = mtot - 1;
//      }     
//
//      /**** set seek positions for initial reading ****/
//      if (startpart > maxNerr  ||  endchunk < minNerr ) {  //if not reading from corrupted chunks, we can just set these normally
//         fprintf(stderr,"startpart = %d, endchunk = %d\n   This stipe does not contain any corrupted blocks...\n", startpart, endchunk);
//         for ( counter = 0; counter <= endchunk; counter++ ) {
//            if (counter < startpart) {
//               seekamt = (startstripe*bsz*1024) + (bsz*1024); 
//            }
//            else if (counter == startpart) {
//               seekamt = (startstripe*bsz*1024) + startoffset; 
//            }
//            else { 
//               seekamt = (startstripe*bsz*1024); 
//            }
//            if( src_in_err[counter] == 0 ) {
//               if ( counter < ntot ) {
//                  fprintf(stderr,"seek input file %d to %lld, as there is no error in this stripe\n",counter, seekamt);
//               }
//               else {
//                  seekamt += (bsz*1024);
//                  fprintf(stderr,"seek erasure file e%d to %lld, as we will be reading from the next stripe\n",counter-ntot, seekamt);
//               }
//               lseek(input_fd[counter],seekamt,SEEK_SET);
//            }
//         }
//         tmpchunk = startpart;
//         tmpoffset = startoffset;
//         error_in_stripe = 0;
//      }
//      else {  //if not, we will require the entire stripe for rebuild
//         fprintf(stderr,"startpart = %d, endchunk = %d\n   This stipe contains corrupted blocks...\n", startpart, endchunk);
//         while (counter < mtot) {
//            if( src_in_err[counter] == 0 ) {
//               lseek(input_fd[counter],(startstripe*bsz*1024),SEEK_SET);
//               if (counter < ntot) {
//                  fprintf(stderr,"seek input file %d to %lld, to read entire stripe\n",counter, (startstripe*bsz*1024));
//               }
//               else {
//                  fprintf(stderr,"seek erasure file e%d to %lld, to read entire stripe\n",counter-ntot, (startstripe*bsz*1024));
//               }
//            }
//            counter++;
//         }
//
//         tmpchunk = 0;
//         tmpoffset = 0;
//         error_in_stripe = 1;
//      }
//
//      firstchunk = 1;
//      firststripe = 1;
//
//
//      /**** output each data stipe, regenerating as necessary ****/
//      while ( llcounter < nbytes ) {
//
//         endchunk = ((long)(offset+nbytes+1) - (long)((long)(startstripe*N*bsz*1024) + llcounter) ) / (chunksize*1024);
//         //endchunk--;
//         skipped_err = 0;
//         printf("\nEndchunk unadjusted - %d\n", endchunk);
//         if ( endchunk >= N ) {
//            endchunk = N - 1;
//         }
//         printf("Endchunk adjusted - %d\n\n", endchunk);
//
//         if ( endchunk < minNerr ) {
//            printf("There is no error in this stripe\n");
//            error_in_stripe = 0;
//         }
//
//         /**** read data into buffers ****/
//         for( counter=tmpchunk; counter < N; counter++ ) {
//            readsize = bsz*1024-tmpoffset;
//
//            if ( llcounter == nbytes  &&  !error_in_stripe ) {
//               fprintf(stderr, "Data reads complete\n");
//               break;
//            }
//
//            //exit(0);
//            if ( src_in_err[counter] ) {  //this data chunk is invalid
//               fprintf(stderr,"zeroing data for faulty chunk %d\n",counter);
//               bzero(buffs[counter],bsz*1024);
//               bzero(temp_buffs[counter],bsz*1024);
//
//               error_in_stripe = 1;
//
//               if ( firstchunk  &&  counter == startpart ) {
//                  printf("First desired chunk : invalid\n");
//                  llcounter = (readsize - (startoffset-tmpoffset) < nbytes ) ? readsize-(startoffset-tmpoffset) : nbytes;
//                  datasz[counter] = llcounter;
//                  firstchunk = 0;
//               }
//               else if ( !firstchunk ) {
//
//                  llcounter += readsize;
//
//                  if ( llcounter < nbytes ) {
//                     datasz[counter] = readsize;
//                  }
//                  else {
//                     datasz[counter] = nbytes - (llcounter - readsize);
//                     llcounter=nbytes;
//                  }
//               }
//               else {
//                  skipped_err++;
//               }
//
//               //error_in_stripe = 1;
//            }
//            else {    //this data chunk is valid, store it
//               if ( (nbytes-llcounter) < readsize  &&  error_in_stripe == 0 ) {
//                  readsize = nbytes-llcounter;
//               }
//
//               fprintf(stderr,"read %d from datafile %d\n",readsize,counter);
//               ret_in = read( input_fd[counter], buffs[counter], readsize );
//               /*if ( ret_in < 1 ) {
//                 fprintf(stderr, "N data input exhausted!\n");
//                 break;
//                 }*/
//               /*if( firstchunk ) {
//                 llcounter = llcounter + ret_in - startoffset;
//                 firstchunk = 0;
//                 }
//                 else {
//                 llcounter = llcounter + ret_in;
//                 }*/
//               if ( firstchunk  &&  counter == startpart ) {
//                  printf("First desired chunk : valid\n");
//                  llcounter = (ret_in - (startoffset-tmpoffset) < nbytes ) ? ret_in-(startoffset-tmpoffset) : nbytes;
//                  datasz[counter] = llcounter;
//                  firstchunk = 0;
//               }
//               else if ( !firstchunk ) {
//                  llcounter += ret_in;
//                  if ( llcounter < nbytes ) {
//                     datasz[counter] = ret_in;
//                  }
//                  else {
//                     datasz[counter] = nbytes - (llcounter - ret_in);
//                     llcounter = nbytes;
//                  }
//               }
//
//               //tmpoffset = 0;
//            }
//            printf("nbytes = %lu, llcounter = %lu, ret_in = %d, read_size = %d\n", nbytes, llcounter, ret_in, readsize);
//            tmpoffset = 0;
//         }
//         //notice, we only need the erasure stripes if we hit an error
//         while ( counter < mtot  &&  error_in_stripe == 1 ) {
//
//            readsize = bsz*1024; //may want to limit later
//
//            if( src_in_err[counter] ) {
//               bzero(buffs[counter],bsz*1024);
//               bzero(temp_buffs[counter],bsz*1024);
//            }
//            else {
//               fprintf(stderr,"read %d from erasure %d\n",readsize,counter-N);
//               ret_in = read( input_fd[counter], buffs[counter], readsize );
//               if ( ret_in < readsize ) {
//                  fprintf(stderr, "Failed to read erasure!\n");
//                  break;
//               }
//            }
//            counter++;
//         }
//
//         /**** regenerate from erasure ****/
//         if ( error_in_stripe ) {
//            for (i = 0; i < ntot; i++) {
//               recov[i] = buffs[decode_index[i]];
//            }
//            printf("\nPerforming regeneration from erasure...\n\n");
//            ec_init_tables(ntot, nerr, decode_matrix, g_tbls);
//            ec_encode_data(bsz*1024, ntot, nerr, g_tbls, recov, &temp_buffs[ntot]);
//         }
//
//         ret_out = llcounter;
//
//         //firstchunk = 1;
//         fprintf( stderr, "llcounter = %lu\n", llcounter );
//         fprintf(stderr,"%d %d %d %d %d %d %d %d %d %d %d\n",counter, tmpoffset, tmpchunk, error_in_stripe,startpart, startoffset, firststripe, ntot, mtot, etot, ret_out);
//
//         /**** write appropriate data out ****/
//         for( counter=startpart, i=0; counter <= endchunk; counter++ ) {
//            readsize = datasz[counter];
//
//            fprintf( stderr, "--- firststripe = %d ---\n", firststripe );
//
//            if ( readsize > ret_out ) { printf("GROSS ERROR!!!\n"); }
//
//            ret_out -= readsize;
//
//            if ( src_in_err[counter] == 0 ) {
//               fprintf( stderr, "Performing write of %d from chunk %d data\n", readsize, counter );
//
//               if ( firststripe  &&  counter == startpart  &&  error_in_stripe ) {
//                  //firststripe = 0;
//                  //if ( error_in_stripe ) {
//                  fprintf( stderr, "   with offset of %d\n", startoffset );
//                  readsize -= write( output_fd, (buffs[counter])+startoffset, readsize );
//                  //perror("");
//                  //printf ( "   readsize now %d\n", readsize );
//                  /*}
//                    else {
//                    readsize -= write( output_fd, buffs[counter], readsize );
//                    }*/
//               }
//               else {
//                  readsize -= write( output_fd, buffs[counter], readsize );
//               }
//            }
//            else {
//               fprintf( stderr, "Performing write of %d from regenerated chunk %d data, src_err = %d\n", readsize, counter, src_err_list[i] );
//               printf( " Note, skipped %d errored blocks\n", skipped_err );
//               if ( firststripe ) {
//                  //firststripe = 0;
//                  if ( counter == startpart ) {
//                     fprintf( stderr, "   with offset of %d\n", startoffset );
//                     printf( "   Accounting for a skip of %d blocks\n", skipped_err );
//                     readsize -= write( output_fd, (temp_buffs[N+i+skipped_err])+startoffset, readsize );
//                  }
//                  else {
//                     printf( "   Accounting for a skip of %d blocks\n", skipped_err );
//                     readsize -= write( output_fd, temp_buffs[N+i+skipped_err], readsize );
//                     //readsize -= write( output_fd, temp_buffs[N+i], readsize );
//                  }
//               }
//               else {
//                  fprintf( stderr, "   stupid simple\n", startoffset );
//                  readsize -= write( output_fd, temp_buffs[N+i], readsize );
//               }
//
//               i++;
//
//            } //end of src_in_err = true block
//
//            if( readsize != 0 ) {
//               fprintf( stderr, "lanl_netof: Error: write failed of chunk %d to %s, failed to store %lu\n", counter, outfile, readsize );
//            }
//
//         } //end of output loop for stipe data
//
//         firststripe=0;
//         for ( counter = 0; counter < N; counter++ ) {
//            datasz[counter] = 0;
//         }
//         counter = 0; tmpoffset = 0; tmpchunk = 0; startpart=0;
//
//      } //end of generating loop for each stripe
//
//   } //end of "Read with rebuild" case

   return (EXIT_SUCCESS); 
}


int ne_write( ne_handle handle, void *buffer, int nbytes )
{
 
   int N;                       /* number of raid parts not including E */ 
   int E;                       /* num erasure stripes */
   int bsz;                     /* chunksize in k */ 
   int counter;                 /* general counter */
   int ecounter;                /* general counter */
   int buflen;                   /* general int */
   ssize_t ret_out;     /* Number of bytes returned by read() and write() */
   long long totsize;            /* used to sum total size of the input file/stream */
   int mtot;                   /* N + numerasure stripes */
   int loops;                    /* general counter for loops */
   u32 writesize;
   u32 crc;                      /* crc 32 */

   if ( handle-> mode != NE_WRONLY  &&  handle->mode != NE_REBUILD ) {
      fprintf( stderr, "ne_write: handle is in improper mode for writing!\n" );
      errno = EPERM;
      return -1;
   }

   N = handle->N;
   E = handle->E;
   bsz = handle->bsz;
   handle->totsz = nbytes; //as it is impossible to write at an offset, this will be the total file size
 
   /* verify bounds for N */
   if (N < 2  ||  N > MAXPARTS) {
      return EINVAL;
   }

   /* verify bounds for E */
   if (E < 0  ||  E > MAXE ) {
      return EINVAL;
   }

   /* verify bounds for bsz */
   if (bsz < 1  ||  bsz > MAXBLKSZ ) {
      return EINVAL;
   }

   mtot=N+E;


   /* loop until the file input or stream input ends */
   totsize = 0;
   loops = 0;
   while (1) { 

      /* check for any data remaining within the handle buffer */
      if ( handle->rem_buff ) {
         writesize = N*bsz*1024 - handle->rem_buff;
         if ( totsize + writesize > nbytes ) { writesize = nbytes-totsize; }
         fprintf( stderr, "ne_write: reading input for %lu bytes\n", (unsigned long)writesize );
         handle->buffer = memcpy ( handle->buffer + handle->rem_buff, buffer, writesize);
         if ( writesize < 1 ) {
            printf("ne_write: reading of input is now complete\n");
            break;
         }
         writesize += handle->rem_buff;
      }
      else { //if none there, read all input from the buffer argument
         writesize = N*bsz*1024;
         if ( totsize + writesize > nbytes ) { writesize = nbytes-totsize; }
         fprintf( stderr, "ne_write: reading input for %lu bytes\n", (unsigned long)writesize );
         handle->buffer = memcpy ( handle->buffer, buffer, writesize);
         if ( writesize < 1 ) {
            printf("ne_write: reading of input is now complete\n");
            break;
         }
      }
      if ( writesize < N*bsz*1024 ) {  //if there is not enough data to write a full stripe, stash it in the handle buffer
         printf("ne_write: reading of input is complete, stashing %lu bytes in handle buffer\n", writesize-handle->rem_buff);
         handle->rem_buff = writesize;
         break;
      }

      totsize=totsize+writesize;
      counter = 0;
      /* loop over the parts and write the parts, sum and count bytes per part etc. */
      while (counter < N) {

         if ( handle->src_in_err[counter] == 0 ) {
            /* this is the crcsum for each part */
            crc = crc32_ieee(TEST_SEED, handle->buffs[counter], bsz*1024);
            // TODO write out per-block-crc
            /* if we were compressing we would compress here */
            buflen = 1024*bsz;
            fprintf(stderr,"ne_write: wr %d to file %d\n",buflen,counter);
            ret_out = write(handle->FDArray[counter],handle->buffs[counter],buflen); 
            
            if ( ret_out != buflen ) {
               fprintf( stderr, "ne_write: write to file %d returned %zd instead of expected %d\n" , counter, ret_out, buflen );
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
      if ( ! handle->e_ready ) {
         fprintf(stderr, "ne_write: initializing erasure matricies...\n");
         // Generate encode matrix encode_matrix
         // The matrix generated by gf_gen_rs_matrix
         // is not always invertable.
         gf_gen_rs_matrix(handle->encode_matrix, mtot, N);

         // Generate g_tbls from encode matrix encode_matrix
         ec_init_tables(N, mtot - N, &(handle->encode_matrix[N * N]), handle->g_tbls);
         handle->e_ready = 1;
      }

      fprintf(stderr, "ne_write: caculating %d recovery stripes from %d data stripes\n",E,N);
      // Perform matrix dot_prod for EC encoding
      // using g_tbls from encode matrix encode_matrix
      ec_encode_data( bsz*1024, N, E, handle->g_tbls, handle->buffs, &(handle->buffs[N]) );

      ecounter = 0;
      while (ecounter < E) {
         crc = crc32_ieee(TEST_SEED, handle->buffs[counter+ecounter], bsz*1024); 
         handle->csum[counter+ecounter] += crc; 
         handle->nsz[counter+ecounter] += bsz*1024;
         handle->ncompsz[counter+ecounter] += bsz*1024;
         fprintf( stderr, "ne_write: writing out erasure stripe %d\n", ecounter );
         ret_out = write(handle->FDArray[counter+ecounter],handle->buffs[counter+ecounter],bsz*1024); 
         
         if ( ret_out != bsz*1024 ) {
            fprintf( stderr, "ne_write: write to erasure file %d, returned %zd instead of expected %d\n" , ecounter, ret_out, bsz*1024 );
            handle->src_in_err[counter] = 1;
            handle->src_err_list[handle->nerr] = counter;
            handle->nerr++;
         }

         ecounter++;
      } 
      counter++;
      loops++;

      fprintf( stderr, "ne_write: completed iteration for stripe %d\n", loops );
   }
 
   return (EXIT_SUCCESS);
}

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
      bzero(handle->buffer+handle->rem_buff, (N*bsz*1024) - handle->rem_buff );
      tmp = ne_write( handle, handle->buffer + handle->rem_buff, (N*bsz*1024) - handle->rem_buff ); //make ne_write do all the work
      
      if ( tmp != EXIT_SUCCESS ) {
         fprintf( stderr, "ne_close: failed to flush handle buffer\n" );
         ret = -1;
      }

   }

   /* Close file descriptors and free bufs and set xattrs for written files */
   counter = 0;
   while (counter < N+E) {
      if ( handle->mode == NE_WRONLY ) { 
         bzero(xattrval,sizeof(xattrval));
         sprintf(xattrval,"%d %d %d %lu %lu %zu %zu",N,E,bsz,handle->nsz[counter],handle->ncompsz[counter],handle->csum[counter],handle->totsz);
         fprintf( stderr, "file %d xattr = \"%s\"\n", counter, xattrval );
         tmp = fsetxattr(handle->FDArray[counter],XATTRKEY, xattrval,strlen(xattrval),0); 
         
         if ( tmp != EXIT_SUCCESS ) {
            fprintf( stderr, "ne_close: failed to set xattr for file %d\n", counter );
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
   
   return ret;

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

#define NO_INVERT_MATRIX -2
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
		printf("Test failure! Error with malloc\n");
		free(b);
		free(backup);
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
			printf("BAD MATRIX\n");
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
			printf("BAD MATRIX\n");
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

