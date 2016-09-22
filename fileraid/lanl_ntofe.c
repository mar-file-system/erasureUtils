#include <lanl_pq_g.h>

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

lanl_ntofe - N to file and E
Syntx  lanl_ntofe inputfileprefix outputfile numerasure

This program reads the input parts, recreates the original file and creats E erasure stripes.   
It uses the Intel ISA-l calculate erasure code and crc routines (which are available in C, SSE, and AVX512.
The output can be a file or can be a "-", which says write to stdout.
Typical syntax:
./lanl_ntofe outtest origfile 2
this reads outest.0 through outest.N, creates orignfile and outtest.e0 and outtest.e1
./lanl_ntofe outtest - 1 > /dev/null
this reads outtest.0 - outtest.N, dumps the orignal file to /dev/null, and creates outtest.e0

This relies upon the xattr stored to each input file, of the form:
n.e.chunksize.nsz.ncompsz.ncrcsum.totsz

N is nparts, E is numerasure, chunksize is chunksize, nsz is the size of the part, ncompsz is the size of the part but might get used if we ever compress the parts, totsz is the total real data in the N part files.
Since creating erasure requires full stripe writes, the last part of the file may all be zeros in the parts.  This totsz is the real size of the data, not counting the trailing zeros.
All the parts and all the erasure stripes should be the same size.
To fill in the trailing zeros, this program uses truncate - punching a hole in the N part files for the zeros.
The ncrcsum field in the xattr is a 64 bit long sum of the crc32s done on each chunksize on the  parts and erasure parts individually, so this is like a checkcrcsum for each of the N parts plus the erasure stripes  awhich will be handy for finding issues in an embarrasingly parallel way.
The nsum is calcluated by the summing crc32s of each chunksize routine which could be accelerated later or included in the erasure calculation someday to speed it up.

to do
fix it so that errors are fprintf stderr and make sure exits are non zero

*/
/*********************************************************/

int main(int argc, char* argv[]) {
 
   int input_fd[MAXPARTS];    /* array of input file descriptors */
   int output_fd[5];         /* output file descriptors */
   unsigned long sum[MAXPARTS];  /* array of sum (for summing each part)  */
   int nsz[MAXPARTS];       /* array of for summing up the size of each part */
   int ncompsz[MAXPARTS];     /* array of for summing the parts compressed (future)  */
   char infile[MAXNAME];     /* array of name of input files */
   int numchunks;         /* n number of raid parts not including p and q */ 
   int chunksize;         /* chunksize in k */ 
   int counter;              /* general counter */
   int ecounter;             /* general counter */
   int buflen;               /* general int */
   int tbuflen;              /* general int */
   ssize_t ret_in, tret_in, ret_out;   /* Number of bytes returned by read() and write() */
   char xattrval[200];         /* used to format xattr value */
   long long totsize;         /* used to sum total size of the input file/stream */
   char inchar[100];            /* in characters */
   void *buff;               /* general buf ptr */
   void *tbuff;              /* general buf ptr */
   unsigned char *buffs[MAXPARTS];     /* array of buffs for the parts and erasure */
   void *ebuf;               /* handy pointer for p buff */
   int inlen;                /* input len */
   int in;                   /* general int */
   int nerr;                 /* number of missing erasures */
   int numtot;               /* numchunks + numerasure stripes */
   int etot;                    /* tot e */
   unsigned long csum;         /* long for summing */
   int loops;               /* general counter for loops */
   unsigned char *encode_matrix, *decode_matrix, *invert_matrix, *g_tbls;
   u32 crc;                 /* crc 32 */
   unsigned char src_in_err[MAXPARTS];    /* stripe error map */
   unsigned char src_err_list[MAXPARTS];  /* stripe error list */
 
   /* print usage */
   if( argc > 4  ||  argc < 3 ){
      printf ("Usage: %s inputfilespref outputfile epattern(i.e. 0.1.0)\n",argv[0]); 
      return 1;
   }

//start cp
   if ( argc == 3 ) {
      inlen = 0;
   }
   else {
      inlen = strlen(argv[3]);
   }
   nerr = 0;
   etot = 0;
   counter = 0;
   //fprintf(stderr,"processing starting erasure input etot %d inlen %d arg %s\n”,etot,inlen,argv[3]);

   //parse through epattern
   while (counter < inlen) {
      bzero(inchar,sizeof(inchar));
      strncpy(inchar, argv[3]+counter,1); 
      in = atoi(inchar);
      if (in < 0) {
          fprintf(stderr,"epattern character must be 0 or 1 %d\n",in);
          exit(-1);
      }
      if (in > 1) {
         fprintf(stderr,"epattern character must be 0 or 1 %d\n",in);
         exit(-1);
      }
      if (in == 1) {
         src_in_err[etot] = 1;
         src_err_list[nerr] = etot;
         nerr++; 
      }
      //fprintf(stderr,"processing erasure input counter %d etot %d\n",counter,etot);
      etot++;
      counter++;
      counter++;
   }
   fprintf(stderr,"nerr %d etot %d\n",nerr, etot);
   fprintf(stderr,"src_in_err:\n");
   dump(src_in_err,MAXPARTS);
   fprintf(stderr,"src_err_list:\n");
   dump(src_err_list,MAXPARTS);
//end cp

   if (etot < 0 || etot > 4 ) {
      printf (" you entered %s , but the number of erasure files must be between 0 and 4\n",argv[3]); 
      return 1;
   }

   /* Create output file descriptor. if stdin set that up*/
   if (!strncmp(argv[2],"-",1)) {
      output_fd[0] = STDOUT_FILENO;
   } else { 
      output_fd[0] = open (argv [2], O_CREAT | O_WRONLY, 0644);
      if (output_fd[0] == -1) {
         perror ("open");
         return 2;
      }
   }
   printf("opened output file %s\n",argv[2]);

   sprintf(infile,"%s.0",argv[1]);
   bzero(xattrval,sizeof(xattrval));
   ret_in = getxattr(infile,XATTRKEY,&xattrval[0],sizeof(xattrval));
   if ( ret_in < 0 ) {
      perror("Could not access the xattr input chunk 0");
      exit(-1);
   }
   //note: I don’t care about the stored erasure, so I just throw it into “loops” and overwrite it later
   sscanf(xattrval, "%d %d %d %d %d %ld %lld", &numchunks, &loops, &chunksize, &nsz[0], &ncompsz[0], &sum[0], &totsize);
   fprintf(stderr,"Successfully identified numchunks = %d, chunksize = %d, totsize = %lld\n", numchunks, chunksize, totsize);

   /* allocate matrix */
   encode_matrix = malloc(MAXPARTS * MAXPARTS);
   decode_matrix = malloc(MAXPARTS * MAXPARTS);
   invert_matrix = malloc(MAXPARTS * MAXPARTS);
   g_tbls = malloc(MAXPARTS * MAXPARTS * 32);

   /* allocate a big buffer for all the chunks and the erasure */
   posix_memalign(&buff,64,numchunks*chunksize*1024);

   /* loop through and open up all the input files and initilize per part info and allocate buffers */
   counter = 0;
   printf("opening files");
   fflush(stdout);
   while ( counter < numchunks+etot ) {
      sum[counter] = 0;
      nsz[counter] = 0;
      ncompsz[counter] = 0;
      bzero(infile,MAXNAME);
      if (counter < numchunks) {
         sprintf(infile,"%s.%d",argv[1],counter);
         buffs[counter] = buff + (counter*chunksize*1024);
         input_fd[counter] = open(infile, O_RDONLY);
         if (input_fd[counter] == -1) {
            perror("Failed to open input file");
            exit(-9);
         }
      } else {
         //though I use 'infile', these files will actually be output
         sprintf(infile,"%s.e%d",argv[1],counter-numchunks);
         posix_memalign(&ebuf,32,chunksize*1024);
         buffs[counter]=ebuf;
         if ( src_in_err[counter-numchunks] == 1 ) {
            output_fd[1+counter-numchunks] = open(infile, O_WRONLY | O_CREAT, 0644);
            if (output_fd[1+counter-numchunks] == -1) {
               perror("Failed to open e output file");
               exit(-9);
            }
         }
      }
      printf(" %s ",infile);
      counter++;
   }
   printf("\n");

   numtot=numchunks+etot;


   /* loop until the file input ends */
   loops = 0;
   ret_in = 0;
   while (ret_in < totsize) {
      tret_in = 0;
      counter = 0;
      /* loop over and read the parts, sum and count bytes per part etc. */
      while (counter < numchunks) {
         tbuff=buffs[counter];
         tbuflen=chunksize*1024;
         tret_in = read(input_fd[counter], tbuff, tbuflen);
         printf("Reading input chunk %d returned total of %zd \n",counter,tret_in);
         if (tret_in < 1) {
            printf("Inputs exhausted\n");
            if (ret_in != totsize ) {
               fprintf(stderr,"lanl_ntofe: failed to locate all chunk data\n");
               exit(-1);
            }
            break;
         }
         //tbuff = tbuff + tret_in;
         //tbuflen = tbuflen - tret_in;
         if (tret_in > (totsize - ret_in)) tret_in = totsize - ret_in;
         ret_in = ret_in + tret_in;

         /* this is the crcsum for each part */
         crc = crc32_ieee(TEST_SEED, tbuff, chunksize*1024);
         sum[counter] = sum[counter] + crc;

         tret_in = write(output_fd[0],tbuff,tret_in);
         printf("wrote %zd to %s\n",tret_in,argv[2]);
         counter++;
      }

      /* calculate and write erasure */
      //printf("\n");
      printf("calc erasure\n");
      // Generate encode matrix encode_matrix
      // The matrix generated by gf_gen_rs_matrix
      // is not always invertable.
      gf_gen_rs_matrix(encode_matrix, numtot, numchunks);

      // Generate g_tbls from encode matrix encode_matrix
      ec_init_tables(numchunks, numtot - numchunks, &encode_matrix[numchunks * numchunks], g_tbls);

      printf("erasure_code_test: calculating %d recovery stripes from %d data stripes, and writing %d erasure stripes out\n",numtot-numchunks,numchunks,nerr);
      // Perform matrix dot_prod for EC encoding
      // using g_tbls from encode matrix encode_matrix
      ec_encode_data(chunksize*1024, numchunks, numtot - numchunks, g_tbls, buffs, &buffs[numchunks]);

      ecounter = 0;
      printf("counter = %d, ret_in = %zd, numchunks = %d, loops = %d\n",counter,ret_in,numchunks,loops);
      while (ecounter < etot) {
         crc = crc32_ieee(TEST_SEED, buffs[counter+ecounter], chunksize*1024); 
         sum[counter+ecounter] = sum[counter+ecounter] + crc; 
         nsz[counter+ecounter]=nsz[counter+ecounter]+chunksize*1024;
         ncompsz[counter+ecounter]=ncompsz[counter+ecounter]+chunksize*1024;
         if (src_in_err[ecounter] == 1) {
            fprintf(stderr, "Outputting to file %s.e%d...", argv[1], ecounter);
            write(output_fd[1+ecounter],buffs[counter+ecounter],chunksize*1024); 
         }
         
         int ret = xor_check(counter+1,chunksize*1024,buffs);
         if (ret != 0) {
            fprintf(stderr, "P does not match xor for iteration %d\n",loops);
         }

         ecounter++;
      } 
      loops++;
   }
 
   /* Close file descriptors, store xattr for erasure and verify stored xattr for N parts, free buffers */
   if (strncmp(argv[2],"-",1)) close(output_fd[0]);
   counter = 0;
   while (counter < numtot) {
      if ( counter >= numchunks  &&  src_in_err[counter-numchunks] == 1 ) { //set xattrs for erasure files
         bzero(xattrval,sizeof(xattrval));
         sprintf(xattrval,"%d %d %d %d %d %lu %lld",numchunks,etot,chunksize,nsz[counter],ncompsz[counter],sum[counter],totsize);
         fsetxattr(output_fd[1+counter-numchunks],XATTRKEY, xattrval,strlen(xattrval),0);
         close(output_fd[1+counter-numchunks]);
      }
      else if (counter < numchunks){  //verify crc and then close input files
         sprintf(infile,"%s.%d",argv[1],counter);
         bzero(xattrval,sizeof(xattrval));
         ret_in = getxattr(infile,XATTRKEY,&xattrval[0],sizeof(xattrval));
         if ( ret_in < 0 ) {
            perror("lanl_ntofe: could not access the xattr of an input chunk");
         }
         //note: I don’t care about the stored erasure, so I just throw it into “loops” and overwrite it later
         sscanf(xattrval, "%d %d %d %d %d %lu", &numchunks, &loops, &chunksize, &nsz[counter], &ncompsz[counter], &csum);
         if ( sum[counter] != csum ) {
            fprintf(stderr, "lanl_ntofe: crc mismatch for %s -- New = %lu Orig = %lu\n",infile, sum[counter], csum);
         }
         close(input_fd[counter]);
      }
      counter++;
   }
   free(buff);
   counter = 0;
   while (counter < etot) {
     free(buffs[counter+numchunks]);
     counter++;
   }
 
   return (EXIT_SUCCESS);
}
