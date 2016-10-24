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


/***********************************************************/
/*
lanl_singleHealth  read a single part and verify various attributes
Syntax 
lanl_singleHealth inputfile Nparts chunksizeinK realfilesize numerasure
example:
./lanl_singleHealth outtest.2 10 64 17171717 2
read outtest.2 using 64k chunksize, realfilesize=17171717, and two erasure stripes (P and Q) and test health of that file and its extended attributes.

tests to be performed:
check for missing part
stat and compare to xattrs
calculate sum and check against xattr
calcuate size and compare against xattr

report any errors


The program uses the Intel ISA-L routines for producing p and q in C, SSE, and AVX512.
all N E have xattr n.e.chunksize.nsz.ncompsz.ncrcsum.totsz: 10 2 64 196608 196608 3304199718723886772 1717171
N is nparts, E is nerasure, chunksize is chunksize, nsz is the size of the part, ncompsz is the size of the part but might get used if we ever compress the parts, totsz is the total real data in the N part files. 
the crcsum is produced using the crc32 routine over the chunksize and summing the results accross each file

***************************************************************/
 
int main(int argc, char* argv[]) {
 
   int output_fd;            /* output file descriptor */
   int p_fd;                 /* p file descriptor */
   int q_fd;                 /* q file descriptor */
   int input_fd;   /* array of file output file descriptors */
   int numchunks;            /* n number of raid parts not including p and q */ 
   int chunksize;            /* chunksize in k */ 
   int topcounter;           /* general counter */ 
   int buflen;               /* general int */
   void * buf;               /* general buf ptr */
   ssize_t ret_in, ret_out;  /* Number of bytes returned by read() and write() */
   char xattrval[200];         /* char array to build xattr value */
   char xattrchunks[20];       /* char array to get n parts from xattr */
   char xattrchunksizek[20];   /* char array to get chunksize from xattr */
   char xattrnsize[20];        /* char array to get total size from xattr */
   char xattrerasure[20];      /* char array to get erasure from xattr */
   int nsize;                  /* general int */
   char xattrncompsize[20];    /* general char for xattr manipulation */
   int ncompsize;              /* general int */
   char xattrnsum[50];         /* char array to get xattr sum from xattr */
   int nsum;                   /* general int */
   char xattrtotsize[160];     /* char array to get total size from xattr */
   long long totsize;          /* total size of file */
   long long totsizetest;      /* used to get total size of file */
   int writesize;              /* write size variable */
   int numerasure;             /* number of erasure blocks per stripe */
   int file;                   /* file flag */
   u32 crc;                    /* used for storing chunk crc */
   unsigned long sum;      /* used for per part sum */
   unsigned long xattrsum; /* used for per part sum */
   int nsz;          /* array of parts sizes */
   int ncompsz;      /* array of compressed part size (future) */
   int exists;       /* array of part exists */
   struct stat partstat;   /* array of stat structs */
   int loops;                  /* general counter */ 
   int toploops;               /* general counter */ 

   //implementation not yet compelete
   /*printf("The implementation of this program is not yet complete!\n");
   exit(0);*/


   /* syntax */
   if(argc != 6){
      fprintf (stderr,"Usage: %s inputfile Nparts chunksizeinK realfilesize nerasure(0-4) \n",argv[0]); 
      return 1;
   }

   numchunks = atoi(argv[2]);
   if (numchunks < 2 || numchunks > MAXPARTS-2 ) {
      fprintf (stderr, " numchunks %d , numchunks must be between 2 and %d \n",numchunks,MAXPARTS-2); 
      return 1;
   }
   chunksize = atoi(argv[3]);
   if (chunksize < 1 || chunksize > MAXBUF ) {
      fprintf (stderr," chunksize %d , chunksize must be between 1 and %d (in k)\n",chunksize,MAXBUF); 
      return 1;
   }
   totsize = atoll(argv[4]);
   if (totsize < 0) {
      fprintf (stderr," realfilesize %lld , file must be greater than zero\n",totsize); 
      return 1;
   }
   numerasure = atoi (argv[5]);
   if (numerasure < 0  ||  numerasure > 4 ) {
      fprintf (stderr," numerasure %d , value must be between 0 and 4\n", numerasure); 
      return 1;
   }

   /* Stat the file */
   ret_in = stat(argv[1],&partstat);
   fprintf(stderr,"stat of file %s returns %zd\n",argv[1],ret_in);
   if (ret_in != 0) {
     fprintf(stderr, "file %s: failure of stat\n", argv[1]);
     exit(-1);
   }

   /* Verify xattr */
   bzero(xattrval,sizeof(xattrval));
#if (AXATTR_GET_FUNC == 4)
   ret_in = getxattr(argv[1],XATTRKEY,&xattrval[0],sizeof(xattrval));
#else
   ret_in = getxattr(argv[1],XATTRKEY,&xattrval[0],sizeof(xattrval),0,0);
#endif
   fprintf(stderr,"file %s xattr returned %zd\n",argv[1],ret_in);
   if (ret_in < 0) {
     fprintf(stderr, "file %s: failure of xattr retrieval\n", argv[1]);
     exit(-1);
   }
   bzero(xattrchunks,sizeof(xattrchunks));
   bzero(xattrchunksizek,sizeof(xattrchunksizek));
   bzero(xattrerasure,sizeof(xattrerasure));
   bzero(xattrtotsize,sizeof(xattrtotsize));
   bzero(xattrnsum,sizeof(xattrnsum));
   sscanf(xattrval,"%s %s %s %s %s %s %s",xattrchunks,xattrerasure,xattrchunksizek,xattrnsize,xattrncompsize,xattrnsum,xattrtotsize);
   fprintf(stderr, "file %s: xattr %s\n",argv[1],xattrval);
   if (atoi(xattrchunks) != numchunks) {
     fprintf(stderr, "file %s: numparts mismatch %s %d\n",argv[1],xattrchunks,numchunks);
     exit(-1);
   }
   if (atoi(xattrerasure) != numerasure) {
     fprintf(stderr, "file %s: numerasure mismatch %s %d\n",argv[1],xattrerasure,numerasure);
     exit(-1);
   }
   if (atoi(xattrchunksizek) != chunksize) {
     fprintf(stderr, "file %s: chunksize mismatch %s %d\n",argv[1],xattrchunksizek,chunksize);
     exit(-1);
   }
   if (atoll(xattrtotsize) != totsize) {
     fprintf(stderr, "file %s: totsize mismatch %s %lld\n",argv[1],xattrtotsize,totsize);
     exit(-1);
   }
   if (atoi(xattrnsize) != partstat.st_size) {
     fprintf(stderr, "file %s: stat size  mismatch %s %lld\n",argv[1],xattrnsize,partstat.st_size);
     exit(-1);
   }
   if ((atoi(xattrnsize) % (chunksize*1024)) != 0) {
     fprintf(stderr, "file %s: part size multiple of chunksize  mismatch %s %d\n",argv[1],xattrnsize,chunksize*1024);
     exit(-1);
   }
   if (atoi(xattrncompsize) != partstat.st_size) {
     fprintf(stderr, "file %s: stat compsize  mismatch %s %lld\n",argv[1],xattrncompsize,partstat.st_size);
     exit(-1);
   }
   if ((atoi(xattrncompsize) % (chunksize*1024)) != 0) {
     fprintf(stderr, "file %s: part compsize multiple of chunksize  mismatch %s %d\n",argv[1],xattrncompsize,chunksize*1024);
     exit(-1);
   }
   /* open up the files for read  and allocate a buffer per file */
   input_fd = open(argv[1], O_RDONLY);
   if (input_fd == -1) {
     perror("open of file failed");
     exit(-9);
   }
   /* initialize buf and vals for the part */
   posix_memalign(&buf,32,chunksize*1024);
   sum = 0;
   nsz = 0;
   ncompsz = 0;
   xattrsum =  strtoul(xattrnsum,NULL,0);

   /* loop over the entire file and generate its crcsum */
   topcounter = 0; 
   toploops = atoi(xattrncompsize) / (chunksize*1024);
   while (topcounter < toploops) {  
      ret_in = 0;

      /* read, calc sum and tot */
      ret_in = read(input_fd,buf,chunksize*1024); 
      if (ret_in != chunksize*1024) {
        fprintf(stderr,"unexpectedly small size for file %s, expected %d but only got %lu\n",argv[1],chunksize*1024,ret_in); 
        exit(-1);
      }
      //fprintf(stderr,"reading %zd from %s\n",ret_in,argv[1]);
#ifdef AISAL
      crc = crc32_ieee(TEST_SEED, buf, chunksize*1024);
#else
      crc = crc32_ieee_base(TEST_SEED, buf, chunksize*1024);
#endif
      sum = sum + crc; 
      nsz = nsz + chunksize*1024;
      ncompsz = ncompsz + chunksize*1024;

      topcounter++;
   }

   if (xattrsum != sum) {
     fprintf(stderr,"sum missmatch for file %s xattr sum %lu sum %lu\n",argv[1],xattrsum,sum); 
     exit(-1);
   } else {
     fprintf(stderr,"sum match for file %s xattr sum %lu sum %lu\n",argv[1],xattrsum,sum); 
   }
   close(input_fd);
   free(buf);

   return (EXIT_SUCCESS);
}
