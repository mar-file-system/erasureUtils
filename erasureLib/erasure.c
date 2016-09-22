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


ne_handle ne_open( char *path, ne_mode mode, int erasure_offset, int N, int E )
{
   return ne_open( path, mode, erasure_offset, N, E, BLKSZ );
}



ne_handle ne_open( char *path, ne_mode mode, int erasure_offset, int N, int E, int bsz )
{

   char file[MAXNAME];       /* array name of files */
   int counter;

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
   if ( bsz < 0 ) {
      fprintf( stderr, "improper bsz arguement received - %d\n", bsz );
      errno = EINVAL;
      return NULL;
   }
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
   handle->path = path;
   handle->nerr = 0;
   handle->N = N;
   handle->E = E;
   handle->bsz = bsz;
   hanlde->mode = mode;
   handle->rem_buff = 0;

   if ( mode == NE_REBUILD ) {
      ; //TODO health check to identify failure pattern
   }
   else if ( mode != NE_WRONLY  &&  mode != NE_RDONLY ) {
      fprintf( stderr, "improper mode argument received - %d\n", mode );
      errno = EINVAL;
      return NULL;
   }

   /* allocate a big buffer for all the N chunks plus a bit extra for reading in crcs */
   posix_memalign( &(handle->buffer), 64, ((N+E)*(handle->bsz)*1024)+sizeof(u32)  );

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
      handle->buffs[counter] = handle->buffer + ( counter*bsz*1024 );

      if( mode == NE_WRONLY  ||  (mode == NE_REBUILD && handle->src_in_err[counter]) ) {
         fprintf( stderr, "   opening %s for write\n", file );
         handle->FDArray[counter] = open( file, O_WRONLY | O_CREAT, 0666 );
      }
      else {
         fprintf( stderr, "   opening %s for read\n", file );
         handle->FDArray[counter] = open( file, O_RDONLY );
      }

      if (handle->FDArray[counter] == -1) {
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

int ne_read( ne_handle handle, void *buffer, int nbyte, off_t offset ) 
{
   int mtot = (handle->N)+(handle->E);
   int ntot;
   int etot;
   char file[MAXNAME];
   int goodfile = 999;
   int minNerr = strlen(argv[2]); //note, greater than N
   int maxNerr = -1;              //note, less than N
   int nsrcerr = 0;
   int nerr = 0;
   int counter;

   for ( counter = 0; counter < mtot; counter++ ) {
      if ( src_in_err[counter] ) {
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

   bzero(file,sizeof(file));
   sprintf(file,handle->path,goodfile);

   /* go to the a good file depending on missing (there can only be one missing) and get the xattr to tell us how big the file is, num parts, chunk size, etc. */
   getxattr(file,XATTRKEY,&xattrval[0],sizeof(xattrval)); //refactor ends here TODO
   fprintf(stderr,"got xattr %s for %s\n",xattrval,infile);
   bzero(xattrchunks,sizeof(xattrchunks));
   bzero(xattrchunksizek,sizeof(xattrchunksizek));
   bzero(xattrtotsize,sizeof(xattrtotsize));
   bzero(xattrerasure,sizeof(xattrerasure));
   sscanf(xattrval,"%s %s %s %s %s %s %s",xattrchunks,xattrerasure,xattrchunksizek,xattrnsize,xattrncompsize,xattrnsum,xattrtotsize);
   totsize = atoll(xattrtotsize);

   /* edit stuff from xattr */
   ncompsize = atoi (xattrncompsize);
   numchunks = atoi (xattrchunks);
   erasure = atoi ( xattrerasure);
   chunksize = atoi (xattrchunksizek);
   totsize = atoll (xattrtotsize);
   fprintf(stderr,"total file size is %lld numchunks %d ncompsize %d erasure %d chunksize %d\n",totsize,numchunks,ncompsize,erasure,chunksize);
   if (numchunks < 2 ) {
      fprintf (stderr, " filexattr %d , numchunks must be between 2 and %d \n",numchunks,MAXPARTS); 
      return 1;
   }
   if (numchunks > MAXPARTS ) {
      fprintf (stderr," filexattr %d , numchunks must be between 2 and %d \n",numchunks,MAXPARTS); 
      return 1;
   }
   if (chunksize < 1 ) {
      fprintf (stderr," filexattr %d , chunksize must be between 1 and %d (in k)\n",chunksize,MAXBUF); 
      return 1;
   }
   if (chunksize > MAXBUF ) {
      fprintf (stderr," filexattr %d , chunksize must be between 1 and %d (in k)\n",chunksize,MAXBUF); 
      return 1;
   }
   if (missing > numchunks) {
      fprintf (stderr," missing %d , must be from 0 to numchunks %d\n",missing,numchunks); 
      return 1;
   }
   if (erasure < 1) {
      fprintf (stderr," erasure %d , must be from 1 to 4\n",erasure); 
      return 1;
   }
   if (erasure > 4) {
      fprintf (stderr," erasure %d , must be from 1 to 4\n",erasure); 
      return 1;
   }
   if (etot != erasure) {
      fprintf (stderr," erasure %d not equal input %d\n",erasure,etot); 
      return 1;
   }
   if (ntot != numchunks) {
      fprintf (stderr," numchunks %d not equal input %d\n",numchunks,ntot); 
      return 1;
   }
   if (nerr > etot) {
      fprintf (stderr," nerr %d must be less than erasure  %d\n",nerr,etot); 
      return 1;
   }
   if (nerr < 1) {
      fprintf (stderr," nerr %d must be greater than zero \n",nerr); 
      return 1;
   }

   fprintf(stderr,"nerr %d nsrcerr %d ntot %d etot %d goodfile %d mtot %d\n",nerr, nsrcerr, ntot, etot, goodfile,mtot);
   fprintf(stderr,"src_in_err:\n");
   dump(src_in_err,MAXPARTS);
   fprintf(stderr,"src_err_list:\n");
   dump(src_err_list,MAXPARTS);

    offset = atoll(argv[4]);
    if ( offset < 0 ) {
        fprintf (stderr," offset %lld must be >= 0 \n",offset);
        return 1;
    }
    if ( offset >= totsize ) {
        fprintf (stderr," offset %lld must be < totsize %lld \n",offset, totsize);
        return 1;
    }
    length = atoll(argv[5]);
    if ( length < 1 ) {
        fprintf (stderr," length %lld must be > 0\n",length);
        return 1;
    }
    if ((offset+length) > totsize) {
        fprintf (stderr," offset %lld + length %lld must be <= totsize %lld\n",offset, length, totsize);
        return 1;
    }

    strcpy(outfile,argv[6]);
    fprintf(stderr,"attempt produce offset %lld for length %lld from infile parts %s totsize %lld to outfile %s using data pattern %s erasure pattern %s data stripe errors %d total stripe errors %d from %d + %d\n",offset, length, argv[1], totsize, outfile,argv[2],argv[3],nsrcerr,nerr,ntot,etot);

    if (!strncmp(outfile,"-",1)) {
       output_fd = 1;
    } else {
       output_fd = open(outfile, O_WRONLY | O_CREAT, 0644);
        fprintf(stderr,"open output file %s\n",outfile);
        if (output_fd == -1) {
          fprintf(stderr,"open output file %s failed\n",outfile);
          exit(-9);
        }
    }

    if (nsrcerr > 0 ) {
       /* we are in rebuild mode */
       /* build matrix */
       encode_matrix = malloc(MAXPARTS * MAXPARTS);
       decode_matrix = malloc(MAXPARTS * MAXPARTS);
       invert_matrix = malloc(MAXPARTS * MAXPARTS);
       g_tbls = malloc(MAXPARTS * MAXPARTS * 32);

       // Generate encode matrix encode_matrix
       // The matrix generated by gf_gen_rs_matrix
       // is not always invertable.
       gf_gen_rs_matrix(encode_matrix, mtot, ntot);

       // Generate g_tbls from encode matrix encode_matrix
       ec_init_tables(ntot, mtot-ntot, &encode_matrix[ntot * ntot], g_tbls);

       ret_in = gf_gen_decode_matrix(encode_matrix, decode_matrix,
             invert_matrix, decode_index, src_err_list, src_in_err,
                  nerr, nsrcerr, ntot, mtot);

       /*printf( "\n\nDecodeM : nerr = %d, nsrcerr = %d, ntot = %d, mtot = %d\nsrc_in_err:\n", nerr, nsrcerr, ntot, mtot );
       dump(src_in_err,MAXPARTS);
       printf( "src_err_list:\n" );
       dump(src_err_list,MAXPARTS);
       printf("\n\n");*/
       

       if (ret_in != 0) {
           fprintf(stderr,"Fail to gf_gen_decode_matrix\n");
           return -1;
       }
    }

    /* open input files initialize some per part values skip opening missing files and erasure if not in rebuild mode1  */
    counter = 0;
    while (counter < mtot) {
      bzero(infile,MAXNAME);
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
    }

    startstripe = offset / (chunksize*1024*numchunks);
    startchunk = (offset - (startstripe*chunksize*1024*numchunks))/(chunksize*1024);
    startoffset = offset - (startstripe*chunksize*1024*numchunks) - (startchunk*chunksize*1024);
    fprintf(stderr,"read from startstripe %d startchunk %d and startoffset %d for length %lld\n",startstripe,startchunk,startoffset,length);

    /******** Read Without Rebuild ********/  
    if (nsrcerr == 0) {
       counter = 0;
       while (counter < numchunks) {
          if (counter < startchunk) seekamt = (startstripe*chunksize*1024) + (chunksize*1024); 
          if (counter == startchunk) seekamt = (startstripe*chunksize*1024) + startoffset; 
          if (counter > startchunk) seekamt = (startstripe*chunksize*1024); 
          lseek(input_fd[counter],seekamt,SEEK_SET);
          fprintf(stderr,"seek input file %d %lld\n",counter, seekamt);
          counter++;
       }
       fprintf(stderr,"honor read request no rebuild with len = %lld\n",length);
       llcounter = 0;
       firstchunk = 0;
       counter = startchunk;
       while ( llcounter < length ) {
          writesize = chunksize*1024;
          if (firstchunk == 0) {
             firstchunk = 1;
             writesize = chunksize*1024-startoffset;
          } 
          if ((length-llcounter) < writesize) writesize = length-llcounter;
          fprintf(stderr,"would read %d from datafile %d\n",writesize,counter);

          /**** read ****/
          ret_out = read( input_fd[counter], buffs[counter], writesize );
          ret_in += ret_out;
          if ( ret_out < 1 ) {
             fprintf(stderr, "Input exhausted\n");
             break;
          }
          llcounter = llcounter + ret_out;

          /**** write ****/
          if( ret_out != write( output_fd, buffs[counter], ret_out ) ) {
             fprintf(stderr, "lanl_netof: could not output full data amount");
          }
          fprintf(stderr,"would write %d to outfile totwrites %d \n",writesize,llcounter);
          counter++;
          if( counter >= numchunks ) counter = 0;
       } 
    } 

    /******** Rebuild While Reading ********/
    else {
       fprintf(stderr,"honor read request with rebuild\n");

       
       counter = 0;
       
       endchunk = ((offset+length) - (startstripe*numchunks*chunksize*1024) ) / (chunksize*1024);

       if ( endchunk >= ntot ) {
          endchunk = mtot - 1;
       }     
 
       /**** set seek positions for initial reading ****/
       if (startchunk > maxNerr  ||  endchunk < minNerr ) {  //if not reading from corrupted chunks, we can just set these normally
          fprintf(stderr,"startchunk = %d, endchunk = %d\n   This stipe does not contain any corrupted blocks...\n", startchunk, endchunk);
          for ( counter = 0; counter <= endchunk; counter++ ) {
             if (counter < startchunk) {
                seekamt = (startstripe*chunksize*1024) + (chunksize*1024); 
             }
             else if (counter == startchunk) {
                seekamt = (startstripe*chunksize*1024) + startoffset; 
             }
             else { 
                seekamt = (startstripe*chunksize*1024); 
             }
             if( src_in_err[counter] == 0 ) {
                if ( counter < ntot ) {
                   fprintf(stderr,"seek input file %d to %lld, as there is no error in this stripe\n",counter, seekamt);
                }
                else {
                   seekamt += (chunksize*1024);
                   fprintf(stderr,"seek erasure file e%d to %lld, as we will be reading from the next stripe\n",counter-ntot, seekamt);
                }
                lseek(input_fd[counter],seekamt,SEEK_SET);
             }
          }
          tmpchunk = startchunk;
          tmpoffset = startoffset;
          error_in_stripe = 0;
       }
       else {  //if not, we will require the entire stripe for rebuild
          fprintf(stderr,"startchunk = %d, endchunk = %d\n   This stipe contains corrupted blocks...\n", startchunk, endchunk);
          while (counter < mtot) {
             if( src_in_err[counter] == 0 ) {
                lseek(input_fd[counter],(startstripe*chunksize*1024),SEEK_SET);
                if (counter < ntot) {
                   fprintf(stderr,"seek input file %d to %lld, to read entire stripe\n",counter, (startstripe*chunksize*1024));
                }
                else {
                   fprintf(stderr,"seek erasure file e%d to %lld, to read entire stripe\n",counter-ntot, (startstripe*chunksize*1024));
                }
             }
             counter++;
          }

          tmpchunk = 0;
          tmpoffset = 0;
          error_in_stripe = 1;
       }

       llcounter = 0;
       firstchunk = 1;
       firststripe = 1;


       /**** output each data stipe, regenerating as necessary ****/
       while ( llcounter < length ) {

          endchunk = ((long)(offset+length+1) - (long)((long)(startstripe*numchunks*chunksize*1024) + llcounter) ) / (chunksize*1024);
          //endchunk--;
          skipped_err = 0;
          printf("\nEndchunk unadjusted - %d\n", endchunk);
          if ( endchunk >= numchunks ) {
             endchunk = numchunks - 1;
          }
          printf("Endchunk adjusted - %d\n\n", endchunk);

          if ( endchunk < minNerr ) {
             printf("There is no error in this stripe\n");
             error_in_stripe = 0;
          }

          /**** read data into buffers ****/
          for( counter=tmpchunk; counter < numchunks; counter++ ) {
             writesize = chunksize*1024-tmpoffset;

             if ( llcounter == length  &&  !error_in_stripe ) {
                fprintf(stderr, "Data reads complete\n");
                break;
             }
             
             //exit(0);
             if ( src_in_err[counter] ) {  //this data chunk is invalid
                fprintf(stderr,"zeroing data for faulty chunk %d\n",counter);
                bzero(buffs[counter],chunksize*1024);
                bzero(temp_buffs[counter],chunksize*1024);
                
                error_in_stripe = 1;

                if ( firstchunk  &&  counter == startchunk ) {
                   printf("First desired chunk : invalid\n");
                   llcounter = (writesize - (startoffset-tmpoffset) < length ) ? writesize-(startoffset-tmpoffset) : length;
                   nsz[counter] = llcounter;
                   firstchunk = 0;
                }
                else if ( !firstchunk ) {

                   llcounter += writesize;

                   if ( llcounter < length ) {
                      nsz[counter] = writesize;
                   }
                   else {
                      nsz[counter] = length - (llcounter - writesize);
                      llcounter=length;
                   }
                }
                else {
                   skipped_err++;
                }

                //error_in_stripe = 1;
             }
             else {    //this data chunk is valid, store it
                if ( (length-llcounter) < writesize  &&  error_in_stripe == 0 ) {
                   writesize = length-llcounter;
                }

                fprintf(stderr,"read %d from datafile %d\n",writesize,counter);
                ret_in = read( input_fd[counter], buffs[counter], writesize );
                /*if ( ret_in < 1 ) {
                   fprintf(stderr, "N data input exhausted!\n");
                   break;
                }*/
                /*if( firstchunk ) {
                   llcounter = llcounter + ret_in - startoffset;
                   firstchunk = 0;
                }
                else {
                   llcounter = llcounter + ret_in;
                }*/
                if ( firstchunk  &&  counter == startchunk ) {
                   printf("First desired chunk : valid\n");
                   llcounter = (ret_in - (startoffset-tmpoffset) < length ) ? ret_in-(startoffset-tmpoffset) : length;
                   nsz[counter] = llcounter;
                   firstchunk = 0;
                }
                else if ( !firstchunk ) {
                   llcounter += ret_in;
                   if ( llcounter < length ) {
                      nsz[counter] = ret_in;
                   }
                   else {
                      nsz[counter] = length - (llcounter - ret_in);
                      llcounter = length;
                   }
                }

                //tmpoffset = 0;
             }
             printf("length = %lu, llcounter = %lu, ret_in = %d, read_size = %d\n", length, llcounter, ret_in, writesize);
             tmpoffset = 0;
          }
          //notice, we only need the erasure stripes if we hit an error
          while ( counter < mtot  &&  error_in_stripe == 1 ) {

             writesize = chunksize*1024; //may want to limit later

             if( src_in_err[counter] ) {
                bzero(buffs[counter],chunksize*1024);
                bzero(temp_buffs[counter],chunksize*1024);
             }
             else {
                fprintf(stderr,"read %d from erasure %d\n",writesize,counter-numchunks);
                ret_in = read( input_fd[counter], buffs[counter], writesize );
                if ( ret_in < writesize ) {
                   fprintf(stderr, "Failed to read erasure!\n");
                   break;
                }
             }
             counter++;
          }

          /**** regenerate from erasure ****/
          if ( error_in_stripe ) {
             for (i = 0; i < ntot; i++) {
                   recov[i] = buffs[decode_index[i]];
             }
             printf("\nPerforming regeneration from erasure...\n\n");
             ec_init_tables(ntot, nerr, decode_matrix, g_tbls);
             ec_encode_data(chunksize*1024, ntot, nerr, g_tbls, recov, &temp_buffs[ntot]);
          }

          ret_out = llcounter;

          //firstchunk = 1;
          fprintf( stderr, "llcounter = %lu\n", llcounter );
          fprintf(stderr,"%d %d %d %d %d %d %d %d %d %d %d\n",counter, tmpoffset, tmpchunk, error_in_stripe,startchunk, startoffset, firststripe, ntot, mtot, etot, ret_out);

          /**** write appropriate data out ****/
          for( counter=startchunk, i=0; counter <= endchunk; counter++ ) {
             writesize = nsz[counter];

             fprintf( stderr, "--- firststripe = %d ---\n", firststripe );

             if ( writesize > ret_out ) { printf("GROSS ERROR!!!\n"); }

             ret_out -= writesize;

             if ( src_in_err[counter] == 0 ) {
                fprintf( stderr, "Performing write of %d from chunk %d data\n", writesize, counter );

                if ( firststripe  &&  counter == startchunk  &&  error_in_stripe ) {
                   //firststripe = 0;
                   //if ( error_in_stripe ) {
                   fprintf( stderr, "   with offset of %d\n", startoffset );
                   writesize -= write( output_fd, (buffs[counter])+startoffset, writesize );
                      //perror("");
                      //printf ( "   writesize now %d\n", writesize );
                   /*}
                   else {
                      writesize -= write( output_fd, buffs[counter], writesize );
                   }*/
                }
                else {
                   writesize -= write( output_fd, buffs[counter], writesize );
                }
             }
             else {
                fprintf( stderr, "Performing write of %d from regenerated chunk %d data, src_err = %d\n", writesize, counter, src_err_list[i] );
                printf( " Note, skipped %d errored blocks\n", skipped_err );
                if ( firststripe ) {
                   //firststripe = 0;
                   if ( counter == startchunk ) {
                      fprintf( stderr, "   with offset of %d\n", startoffset );
                      printf( "   Accounting for a skip of %d blocks\n", skipped_err );
                      writesize -= write( output_fd, (temp_buffs[numchunks+i+skipped_err])+startoffset, writesize );
                   }
                   else {
                      printf( "   Accounting for a skip of %d blocks\n", skipped_err );
                      writesize -= write( output_fd, temp_buffs[numchunks+i+skipped_err], writesize );
                      //writesize -= write( output_fd, temp_buffs[numchunks+i], writesize );
                   }
                }
                else {
                   fprintf( stderr, "   stupid simple\n", startoffset );
                   writesize -= write( output_fd, temp_buffs[numchunks+i], writesize );
                }

                i++;

             } //end of src_in_err = true block

             if( writesize != 0 ) {
                fprintf( stderr, "lanl_netof: Error: write failed of chunk %d to %s, failed to store %lu\n", counter, outfile, writesize );
             }

          } //end of output loop for stipe data

          firststripe=0;
          for ( counter = 0; counter < numchunks; counter++ ) {
             nsz[counter] = 0;
          }
          counter = 0; tmpoffset = 0; tmpchunk = 0; startchunk=0;

       } //end of generating loop for each stripe

    } //end of "Read with rebuild" case

/******* cut in from rebuildne
    totsizetest = 0;
    while (totsizetest < ncompsize) {  
      ret_in = 0;
      counter = 0;
      while (counter < mtot) {
         if (src_in_err[counter] == 1) {
            bzero(buffs[counter], chunksize*1024); 
            bzero(temp_buffs[counter], chunksize*1024); 
         } else {
            ret_in = read(input_fd[counter],buffs[counter],chunksize*1024); 
         }
         counter++;
      }

      for (i = 0; i < ntot; i++) {
            recov[i] = buffs[decode_index[i]];
      }
      ec_init_tables(ntot, nerr, decode_matrix, g_tbls);
      ec_encode_data(chunksize*1024, ntot, nerr, g_tbls, recov, &temp_buffs[ntot]);

      for (i = 0; i < nerr; i++) {
         write(input_fd[src_err_list[i]],temp_buffs[ntot+i],chunksize*1024);
         crc = 0;
         crc = crc32_ieee(TEST_SEED, temp_buffs[ntot+i], chunksize*1024);
         sum[src_err_list[i]] = sum[src_err_list[i]] + crc;
         nsz[src_err_list[i]] = nsz[src_err_list[i]] + chunksize*1024;
         ncompsz[src_err_list[i]] = ncompsz[src_err_list[i]] + chunksize*1024;
      }
      totsizetest = totsizetest + (chunksize*1024);  
    }
********** cut in from rebuildne */ 

    /* Close file descriptors and free bufs set xattrs on missing */
    counter = 0;
    while (counter < mtot) {
       if (src_in_err[counter] == 0) close(input_fd[counter]); 
       free(buffs[counter]);
       counter++;
    }
    close(output_fd);

    return (EXIT_SUCCESS); 
}


int ne_write( ne_handle handle, void *buffer, int nbyte )
{
 
   int output_fd[MAXN + MAXE];      /* array of file output file descriptors */
   unsigned long sum[MAXN + MAXE];  /* array of sum (for summing each part)  */
   int nsz[MAXN + MAXE];            /* array of for summing up the size of each part */
   int ncompsz[MAXN + MAXE];        /* array of for summing the parts compressed (future)  */
   int N;                       /* number of raid parts not including E */ 
   int E;                       /* num erasure stripes */
   int bsz;                     /* chunksize in k */ 
   int counter;                 /* general counter */
   int ecounter;                /* general counter */
   int buflen;                   /* general int */
   int tbuflen;                  /* general int */
   ssize_t ret_in, tret_in, ret_out;    /* Number of bytes returned by read() and write() */
   char xattrval[200];           /* used to format xattr value */
   long long totsize;            /* used to sum total size of the input file/stream */
   void *buff;                   /* general buf ptr */
   void *tbuff;                  /* general buf ptr */
   unsigned char *buffs[MAXN + MAXE];      /* array of buffs for the parts and p and q */
    void *ebuf;                  /* handy pointer for p buff */
   int numtot;                   /* N + numerasure stripes */
   int loops;                    /* general counter for loops */
   unsigned char *encode_matrix, *decode_matrix, *invert_matrix, *g_tbls;
   u32 crc;                      /* crc 32 */

   N = handle->N;
   E = handle->E;
   bsz = handle->bsz;
 
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

   numtot=N+E;


   /* loop until the file input or stream input ends */
   totsize = 0;
   loops = 0;
   while (1) {  
      ret_in = 0;
      /* read in from the stdin or file read in full n parts * bsz */
      if (!strncmp(argv[1],"-",1)) {
         tret_in = 0;
         tbuff=buff;
         tbuflen=N*bsz*1024;
         while (ret_in <= N*bsz*1024) {
            tret_in = read(input_fd, tbuff, tbuflen);
            if (tret_in < 1) break;
               tbuff = tbuff + tret_in;
               tbuflen = tbuflen - tret_in;
               ret_in = ret_in + tret_in;
               printf("reading stdin  file returned %zd \n",ret_in);
         }
      } else {
         ret_in = read(input_fd,buff,N*bsz*1024);
      } 
      printf("reading input returned total of %zd\n",ret_in);
      if ( ret_in < 1 ) {
         printf("reading of input is now complete\n");
         break;
      }

      totsize=totsize+ret_in;
      counter = 0;
      /* loop over the parts and write the parts, sum and count bytes per part etc. */
      while (counter < N) {
         /* if we were compressing we would compress here */
         ncompsz[counter]=ncompsz[counter]+bsz*1024;
         buflen = (((counter+1) * bsz*1024) - ret_in);
         if (buflen > bsz*1024) {
            buflen = 0;
         }
         //Gransom Edited
         else if (buflen > 0) {
            buflen = (bsz*1024) - buflen;
         }
         else if (buflen <= 0) {
            buflen = bsz*1024;
         }
         if (buflen > 0) {
            //printf("wr %d to %d\n",buflen,counter);
            /* if we were to compress it might be here */
            write(output_fd[counter],buffs[counter],buflen); 
            printf("wr %d to %d\n",buflen,counter);
         }
         /* if the part is not a full write, poke a hole in the file using truncate */
         /* also fill the rest of the buffer with nulls so the pq calc will be correct */
         if (buflen < bsz*1024) {
            //printf("truncating file %d to %d\n",counter, output_size[counter] + (bsz*1024)-buflen);
            printf("truncating file %d to %d\n",counter, (loops+1)*bsz*1024);
            ftruncate(output_fd[counter], ((loops+1)*bsz*1024));
            bzero(buffs[counter]+buflen,(bsz*1024)-buflen);
            printf("zeroing from %d to %d in %d\n",buflen,bsz*1024,counter);
         }
         /* this is the crcsum for each part */
         crc = 0;
         crc = crc32_ieee(TEST_SEED, buffs[counter], bsz*1024); 
         sum[counter] = sum[counter] + crc; 
         nsz[counter]=nsz[counter]+bsz*1024;
         counter++;
      }
      /* calculate and write p and q */
      //printf("\n");
      printf("calc erasure\n");
      // Generate encode matrix encode_matrix
      // The matrix generated by gf_gen_rs_matrix
      // is not always invertable.
      gf_gen_rs_matrix(encode_matrix, numtot, N);

      // Generate g_tbls from encode matrix encode_matrix
      ec_init_tables(N, numtot - N, &encode_matrix[N * N], g_tbls);

      printf("erasure_code_test: caculating %d recovery stripes from %d data stripes\n",numtot-N,N);
      // Perform matrix dot_prod for EC encoding
      // using g_tbls from encode matrix encode_matrix
      ec_encode_data(bsz*1024, N, numtot - N, g_tbls, buffs, &buffs[N]);

      ecounter = 0;
      printf("counter = %d\n",counter);
      while (ecounter < E) {
         crc = 0;
         crc = crc32_ieee(TEST_SEED, buffs[counter+ecounter], bsz*1024); 
         sum[counter+ecounter] = sum[counter+ecounter] + crc; 
         nsz[counter+ecounter]=nsz[counter+ecounter]+bsz*1024;
         ncompsz[counter+ecounter]=ncompsz[counter+ecounter]+bsz*1024;
         write(output_fd[counter+ecounter],buffs[counter+ecounter],bsz*1024); 
         ecounter++;
      } 
      counter++;
      if (ret_in < bsz*1024*N) {
         break;
      }
      loops++;
   }
 
   /* Close file descriptors write xattr for each part and p and q and free buffers */
   if (strncmp(argv[1],"-",1)) close(input_fd);
   counter = 0;
   while (counter < N+E) {
      bzero(xattrval,sizeof(xattrval));
      sprintf(xattrval,"%d %d %d %d %d %lu %lld",N,E,bsz,nsz[counter],ncompsz[counter],sum[counter],totsize);
      fsetxattr(output_fd[counter],XATTRKEY, xattrval,strlen(xattrval),0);
      close(output_fd[counter]);
      counter++;
   }
   free(buff);
   counter = 0;
   while (counter < E) {
      free(buffs[counter+N]);
      counter++;
   }
 
   return (EXIT_SUCCESS);
}

int ne_close( ne_handle handle ) 
{
   
}

