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

lanl_ftone - file to N E
Syntx  lanl_ftonpq inputfile outputfileprefex numparts chunksize_in_k numerasure 

This program reads the input file, stripes that file over numparts (N) in
chunksize of chunksize_in_k and creats E erasure stripes.  It uses the
Intel ISA-l calculate erasure code and crc routines (which are available in
C, SSE, and AVX512.  The input can be a file or can be a - which says read
off of stdin.

Typical syntax:

    ./lanl_ftone inputfile outtest 10 64 2

this reads inputfile and creates outtest.0 - outtest.9 and outtest.e0 and
outtest.e1 it stripes 10 wide and uses 64k as the chunksize and it creates
two erasure stripes

    cat inputfile | ./lanl_ftonpq - outtest 10 64 1

this reads from stdin and creates outtest.0 - outtest.9 and outtest.e0 it
stripes 10 wide and uses 64k as the chunksize and it only creates one
erasure since the last parm is 1

Additionally, each output file gets an xattr added to it (yes all 11 or 12
files in the case of a 10+pq the xattr looks like this

    n.e.chunksize.nsz.ncompsz.ncrcsum.totsz: 10 2 64 196608 196608 3304199718723886772 1717171

N is nparts, E is numerasure, chunksize is chunksize, nsz is the size of
the part, ncompsz is the size of the part but might get used if we ever
compress the parts, totsz is the total real data in the N part files.

Since creating erasure requires full stripe writes, the last part of the
file may all be zeros in the parts.  This totsz is the real size of the
data, not counting the trailing zeros.

All the parts and all the erasure stripes should be the same size.

To fill in the trailing zeros, this program uses truncate - punching a hole
in the N part files for the zeros.

The ncrcsum field in the xattr is a 64 bit long sum of the crc32s done on
each chunksize on the parts and erasure parts individually, so this is like
a checkcrcsum for each of the N parts plus the erasure stripes awhich will
be handy for finding issues in an embarrasingly parallel way.

The nsum is calcluated by the summing crc32s of each chunksize routine
which could be accelerated later or included in the erasure calculation
someday to speed it up.

TO DO:
-- fix it so that errors are fprintf stderr and make sure exits are non zero


*/
/*********************************************************/

int main(int argc, char* argv[]) {
 
    int input_fd;                 /* Input file descriptor */
    int output_fd[MAXPARTS];      /* array of file output file descriptors */
    unsigned long sum[MAXPARTS];  /* array of sum (for summing each part)  */
    int nsz[MAXPARTS];            /* array of for summing up the size of each part */
    int ncompsz[MAXPARTS];        /* array of for summing the parts compressed (future)  */
    char outfile[MAXNAME];        /* array of name of output files */
    int numchunks;                /* n number of raid parts not including p and q */ 
    int chunksize;                /* chunksize in k */ 
    int counter;                  /* general counter */
    int ecounter;                  /* general counter */
    int buflen;                   /* general int */
    int tbuflen;                  /* general int */
    ssize_t ret_in, tret_in, ret_out;    /* Number of bytes returned by read() and write() */
    char xattrval[200];           /* used to format xattr value */
    long long totsize;            /* used to sum total size of the input file/stream */
    void *buff;                   /* general buf ptr */
    void *tbuff;                  /* general buf ptr */
    unsigned char *buffs[MAXPARTS];      /* array of buffs for the parts and p and q */
    unsigned char *buffc[MAXPARTS];      /* array of buffs for the parts and p and q */
    void *ebuf;                   /* handy pointer for p buff */
    int erasure;                  /* num erasure stripes */
    int numtot;                   /* numchunks + numerasure stripes */
    unsigned long csum;           /* long for summing */
    int loops;                    /* general counter for loops */
    unsigned char *encode_matrix, *decode_matrix, *invert_matrix, *g_tbls;
    u32 crc;                      /* crc 32 */
 
    /* print usage */
    if(argc != 6){
        printf ("Usage: %s inputfile outputfilespec numchunks chunksize(k) numerasures (1-4) \n",argv[0]); 
        return 1;
    }
    /* get numchunks from input */
    numchunks = atoi (argv[3]);
    if (numchunks < 2 ) {
        printf (" you entered %d , numchunks must be between 2 and %d \n",numchunks,MAXPARTS); 
        return 1;
    }
    if (numchunks > MAXPARTS ) {
        printf (" you entered %d , numchunks must be between 2 and %d \n",numchunks,MAXPARTS); 
        return 1;
    }
    /* get chunksize from input */
    chunksize = atoi (argv[4]);
    if (chunksize < 1 ) {
        printf (" you entered %d , numchunks must be between 1 and %d (in k)\n",chunksize,MAXBUF); 
        return 1;
    }
    if (chunksize > MAXBUF ) {
        printf (" you entered %d , numchunks must be between 1 and %d (in k)\n",chunksize,MAXBUF); 
        return 1;
    }
    /* get erasure from input */
    erasure = atoi (argv[5]);
    if (erasure < 1 ) {
       printf (" erasure must be greater than zero %d\n",erasure);
       return 1;
    }
    if (erasure > 4 ) {
       printf (" erasure must be less than 5 %d\n",erasure);
       return 1;
    }
    
    /* Create input file descriptor if stdin set that up*/
    if (!strncmp(argv[1],"-",1)) {
       input_fd = 0;
    } else { 
       input_fd = open (argv [1], O_RDONLY);
       if (input_fd == -1) {
            perror ("open");
            return 2;
       }
    }
    numtot=numchunks+erasure;
    printf("opened input file %s %d\n",argv[1],input_fd);

    /* allocate matrix */
        encode_matrix = malloc(MAXPARTS * MAXPARTS);
        decode_matrix = malloc(MAXPARTS * MAXPARTS);
        invert_matrix = malloc(MAXPARTS * MAXPARTS);
        g_tbls = malloc(MAXPARTS * MAXPARTS * 32);

    /* allocate a big buffer for all the N chunks */
    posix_memalign(&buff,64,numchunks*chunksize*1024);

    /* loop through and open up all the output files and initilize per part info and allocate buffers */
    counter = 0;
    printf("opening outfile");
    while (counter < numchunks+erasure) {
       sum[counter] = 0;
       nsz[counter] = 0;
       ncompsz[counter] = 0;
       bzero(outfile,MAXNAME);
       if (counter < numchunks) {
         sprintf(outfile,"%s.%d",argv[2],counter);
         buffs[counter] = buff + (counter*chunksize*1024);
         output_fd[counter] = open(outfile, O_WRONLY | O_CREAT, 0644);
         if (output_fd[counter] == -1) {
            perror("open of output");
            exit(-9);
         }
       } else {
         sprintf(outfile,"%s.e%d",argv[2],counter-numchunks);
         posix_memalign(&ebuf,32,chunksize*1024);
         buffs[counter]=ebuf;
         output_fd[counter] = open(outfile, O_WRONLY | O_CREAT, 0644);
         if (output_fd[counter] == -1) {
            perror("open of e out");
            exit(-9);
         } 
       }
       printf(" %s ",outfile);
       counter++;
    }
    printf("\n");

    /* loop until the file input or stream input ends */
    totsize = 0;
    loops = 0;
    while (1) {  
      ret_in = 0;
      /* read in from the stdin or file read in full n parts * chunksize */
      if (!strncmp(argv[1],"-",1)) {
        tret_in = 0;
        tbuff=buff;
        tbuflen=numchunks*chunksize*1024;
        while (ret_in <= numchunks*chunksize*1024) {
          tret_in = read(input_fd, tbuff, tbuflen);
          if (tret_in < 1) break;
          tbuff = tbuff + tret_in;
          tbuflen = tbuflen - tret_in;
          ret_in = ret_in + tret_in;
          printf("reading stdin  file returned %zd \n",ret_in);
        }
      } else {
        ret_in = read(input_fd,buff,numchunks*chunksize*1024);
      } 
      printf("reading input returned total of %zd\n",ret_in);
      if ( ret_in < 1 ) {
         printf("reading of input is now complete\n");
         break;
      }

      totsize=totsize+ret_in;
      counter = 0;
      /* loop over the parts and write the parts, sum and count bytes per part etc. */
      while (counter < numchunks) {
         /* if we were compressing we would compress here */
         ncompsz[counter]=ncompsz[counter]+chunksize*1024;
         buflen = (((counter+1) * chunksize*1024) - ret_in);
         if (buflen > chunksize*1024) {
            buflen = 0;
         }
         //Gransom Edited
         else if (buflen > 0) {
            buflen = (chunksize*1024) - buflen;
         }
         else if (buflen <= 0) {
            buflen = chunksize*1024;
         }
         if (buflen > 0) {
            //printf("wr %d to %d\n",buflen,counter);
            /* if we were to compress it might be here */
            write(output_fd[counter],buffs[counter],buflen); 
            printf("wr %d to %d\n",buflen,counter);
         }
         /* if the part is not a full write, poke a hole in the file using truncate */
         /* also fill the rest of the buffer with nulls so the pq calc will be correct */
         if (buflen < chunksize*1024) {
            //printf("truncating file %d to %d\n",counter, output_size[counter] + (chunksize*1024)-buflen);
            printf("truncating file %d to %d\n",counter, (loops+1)*chunksize*1024);
            ftruncate(output_fd[counter], ((loops+1)*chunksize*1024));
            bzero(buffs[counter]+buflen,(chunksize*1024)-buflen);
            printf("zeroing from %d to %d in %d\n",buflen,chunksize*1024,counter);
         }
         /* this is the crcsum for each part */
         crc = 0;
#ifdef HAVE_LIBISAL
         crc = crc32_ieee(TEST_SEED, buffs[counter], chunksize*1024); 
#else
         crc = crc32_ieee_base(TEST_SEED, buffs[counter], chunksize*1024); 
#endif
         sum[counter] = sum[counter] + crc; 
         nsz[counter]=nsz[counter]+chunksize*1024;
         counter++;
      }
      /* calculate and write p and q */
      //printf("\n");
      printf("calc erasure\n");
      // Generate encode matrix encode_matrix
      // The matrix generated by gf_gen_rs_matrix
      // is not always invertable.
      gf_gen_rs_matrix(encode_matrix, numtot, numchunks);

      // Generate g_tbls from encode matrix encode_matrix
      ec_init_tables(numchunks, numtot - numchunks, &encode_matrix[numchunks * numchunks], g_tbls);

      printf("erasure_code_test: caculating %d recovery stripes from %d data stripes\n",numtot-numchunks,numchunks);
      // Perform matrix dot_prod for EC encoding
      // using g_tbls from encode matrix encode_matrix
#ifdef HAVE_LIBISAL
      ec_encode_data(chunksize*1024, numchunks, numtot - numchunks, g_tbls, buffs, &buffs[numchunks]);
#else
      ec_encode_data_base(chunksize*1024, numchunks, numtot - numchunks, g_tbls, buffs, &buffs[numchunks]);
#endif
/* testing testing testing 
      ret_out = xor_check_sse(numchunks+1,chunksize*1024,buffs);   
      if (ret_out != 0) {
          fprintf(stderr,"xor check failed e0 raid calc test %zd\n",ret_out);
          exit(-1);
      } else {
          fprintf(stderr,"xor check pased e0 raid calc test %zd\n",ret_out);
      } 
      if (erasure > 1) {
      ret_out = pq_check_sse(numchunks+2,chunksize*1024,buffs);   
        if (ret_out != 0) {
            fprintf(stderr,"pq check failed e0 raid calc test %zd\n",ret_out);
            exit(-1);
        } else {
            fprintf(stderr,"pq check pased e0 raid calc test %zd\n",ret_out);
        } 
      } 
 testing testing testing */

      ecounter = 0;
      printf("counter = %d\n",counter);
      while (ecounter < erasure) {
         crc = 0;
#ifdef HAVE_LIBISAL
         crc = crc32_ieee(TEST_SEED, buffs[counter+ecounter], chunksize*1024); 
#else
         crc = crc32_ieee_base(TEST_SEED, buffs[counter+ecounter], chunksize*1024); 
#endif
         sum[counter+ecounter] = sum[counter+ecounter] + crc; 
         nsz[counter+ecounter]=nsz[counter+ecounter]+chunksize*1024;
         ncompsz[counter+ecounter]=ncompsz[counter+ecounter]+chunksize*1024;
         write(output_fd[counter+ecounter],buffs[counter+ecounter],chunksize*1024); 
         ecounter++;
      } 
      counter++;
      if (ret_in < chunksize*1024*numchunks) {
         break;
      }
      loops++;
    }
 
    /* Close file descriptors write xattr for each part and p and q and free buffers */
    if (strncmp(argv[1],"-",1)) close(input_fd);
    counter = 0;
    while (counter < numchunks+erasure) {
       bzero(xattrval,sizeof(xattrval));
       sprintf(xattrval,"%d %d %d %d %d %lu %lld",numchunks,erasure,chunksize,nsz[counter],ncompsz[counter],sum[counter],totsize);
#if (AXATTR_SET_FUNC == 5)
       fsetxattr(output_fd[counter],XATTRKEY, xattrval,strlen(xattrval),0);
#else
       fsetxattr(output_fd[counter],XATTRKEY, xattrval,strlen(xattrval),0,0);
#endif
       close(output_fd[counter]);
       counter++;
    }
    free(buff);
    counter = 0;
    while (counter < erasure) {
      free(buffs[counter+numchunks]);
      counter++;
    }
 
    return (EXIT_SUCCESS);
}
