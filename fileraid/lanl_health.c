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
lanl_health  read the N parts, P and optionally Q
Syntax 
lanl_ntofpq inputfileprefix(N parts) Nparts chunksizeinK realfilesize pq(1 p only, 2 p and q)
example:
./lanl_nnpqhealth outtest 10 64 17171717 2
read outtest.0 - outtest.9 parts  using 64k chunksize realfilesize=17171717 and P and Q and test health

tests to be performed
check for missing parts
stat all and compare to xattrs for all
compare xattrs against each other
calculate sum and check against xattr
calcuate size and compare against xattr
calculate P and Q and compare against file P and Q

Other stuff:
jacknife

report any errors


The program uses the Intel ISA-L routines for producing p and q in C, SSE, and AVX512.
all N P q have xattr n.chunksize.nsz.ncompsz.nsum.totsz: 10 64 196608 196608 3304199718723886772 1717171
N is nparts, chunksize is chunksize, nsz is the size of the part, ncompsz is the size of the part but might get used if we ever compress the parts, totsz is the total real data in the N part files. 
the sum is produced using the summer routine which should be done more efficiently while p and q are produced

todo
add p and q and pq jacknifes
move summer to separate .o
combine summer and p and q

***************************************************************/

 
    /*should be made its own .o and/or added to the erasure producing routines for efficiency */
    /* give it an array of bytes a multiple of 8 bytes long and it will return a sum of the */
    /* 8 byte words */
    unsigned long summer(void * sumbuf, int sumbufsize) {
         int sumcounter;
         unsigned long * sump;
         unsigned long tsum;
         tsum = 0;
         sumcounter = 0;
         //printf("in summer\n");
         while (sumcounter < sumbufsize) {
            sump = sumbuf + (sumcounter);
            tsum = tsum + *sump;
            sumcounter=sumcounter+8;
            //printf("summing %d %d %lu\n",counter,sumcounter,*sump);
         }
         return tsum;
    }

int main(int argc, char* argv[]) {
 
    int output_fd;               /* output file descriptor */
    int p_fd;                    /* p file descriptor */
    int q_fd;                    /* q file descriptor */
    int input_fd[MAXPARTS];      /* array of file output file descriptors */
    char infile[MAXNAME];        /* array of name of input files */
    int numchunks;               /* n number of raid parts not including p and q */ 
    int chunksize;               /* chunksize in k */ 
    int counter;                 /* general counter */ 
    int topcounter;              /* general counter */ 
    int buflen;                  /* general int */
    char * buf;                  /* general buf ptr */
    ssize_t ret_in, ret_out;     /* Number of bytes returned by read() and write() */
    char xattrval[200];          /* char array to build xattr value */
    char xattrchunks[20];        /* char array to get n parts from xattr */
    char xattrchunksizek[20];    /* char array to get chunksize from xattr */
    char xattrnsize[20];         /* char array to get total size from xattr */
    int nsize;                   /* general int */
    char xattrncompsize[20];     /* general char for xattr manipulation */
    int ncompsize;               /* general int */
    char xattrnsum[50];          /* char array to get xattr sum from xattr */
    int nsum;                    /* general int */
    char xattrtotsize[160];      /* char array to get total size from xattr */
    long long totsize;           /* total size of file */
    long long totsizetest;       /* used to get total size of file */
    int writesize;               /* write size variable */
    int pq;                      /* pq flag */
    int file;                    /* file flag */
    void * buffs[MAXPARTS+2];    /* array of buffs for parts and p and q */
    unsigned long csum;          /* used for summing */
    unsigned long sum[MAXPARTS]; /* used for per part sum */
    unsigned long xattrsum[MAXPARTS]; /* used for per part sum */
    int nsz[MAXPARTS];           /* array of parts sizes */
    int ncompsz[MAXPARTS];       /* array of compressed part size (future) */
    int exists[MAXPARTS];        /* array of part exists */
    struct stat partstat[MAXPARTS]; /* array of stat structs */
    int loops;                   /* general counter */ 
    int toploops;                /* general counter */ 

    /* syntax */
    if(argc != 6){
        fprintf (stderr,"Usage: %s inputfilespec Nparts chunksizeinK realfilesize pq(1-p only, 2-q only) \n",argv[0]); 
        return 1;
    }

    numchunks = atoi(argv[2]);
    if (numchunks < 2 ) {
        fprintf (stderr, " numchunks %d , numchunks must be between 2 and %d \n",numchunks,MAXPARTS-2); 
        return 1;
    }
    if (numchunks > MAXPARTS ) {
        fprintf (stderr," numchunks %d , numchunks must be between 2 and %d \n",numchunks,MAXPARTS-2); 
        return 1;
    }
    chunksize = atoi(argv[3]);
    if (chunksize < 1 ) {
        fprintf (stderr," chunksize %d , chunksize must be between 1 and %d (in k)\n",chunksize,MAXBUF); 
        return 1;
    }
    if (chunksize > MAXBUF ) {
        fprintf (stderr," chunksize %d , chunksize must be between 1 and %d (in k)\n",chunksize,MAXBUF); 
        return 1;
    }
    totsize = atoll(argv[4]);
    if (totsize < 0) {
        fprintf (stderr," realfilesize %lld , file must be greater than zero\n",totsize); 
        return 1;
    }
    pq = atoi (argv[5]);
    if (pq < 1 ) {
        fprintf (stderr," pq %d , file must be 1 or 2 \n",pq); 
        return 1;
    }
    if (pq > 2 ) {
        fprintf (stderr," pq %d , pq must be 1 or 2  \n",pq); 
        return 1;
    }

    counter = 0;
    if (pq > 1) {
       loops = numchunks+2;
    } else {
       loops = numchunks+1;
    }
    while (counter < loops) {
       bzero(infile,sizeof(infile));
       sprintf(infile,"%s.%d",argv[1],counter);
       if (counter == numchunks) sprintf(infile,"%s.p",argv[1]);
       if (counter == numchunks+1) sprintf(infile,"%s.q",argv[1]);
       ret_in = stat(infile,&partstat[counter]);
       fprintf(stderr,"stat of file %s returns %zd\n",infile,ret_in);
       if (ret_in != 0) {
          exit(-1);
       }
       bzero(xattrval,sizeof(xattrval));
       ret_in = getxattr(infile,XATTRKEY,&xattrval[0],sizeof(xattrval),0,0);
       fprintf(stderr,"file %s xattr %zd\n",infile,ret_in);
       if (ret_in < 0) {
          exit(-1);
       }
       bzero(xattrchunks,sizeof(xattrchunks));
       bzero(xattrchunksizek,sizeof(xattrchunksizek));
       bzero(xattrtotsize,sizeof(xattrtotsize));
       bzero(xattrnsum,sizeof(xattrnsum));
       sscanf(xattrval,"%s %s %s %s %s %s",xattrchunks,xattrchunksizek,xattrnsize,xattrncompsize,xattrnsum,xattrtotsize);
       fprintf(stderr, "file %s: xattr %s\n",infile,xattrval);
       if (atoi(xattrchunks) != numchunks) {
          fprintf(stderr, "file %s: numparts mismatch %s %d\n",infile,xattrchunks,numchunks);
          exit(-1);
       }
       if (atoi(xattrchunksizek) != chunksize) {
          fprintf(stderr, "file %s: chunksize mismatch %s %d\n",infile,xattrchunksizek,chunksize);
          exit(-1);
       }
       if (atoll(xattrtotsize) != totsize) {
          fprintf(stderr, "file %s: totsize mismatch %s %lld\n",infile,xattrtotsize,totsize);
          exit(-1);
       }
       if (atoi(xattrnsize) != partstat[counter].st_size) {
          fprintf(stderr, "file %s: stat size  mismatch %s %lld\n",infile,xattrnsize,partstat[counter].st_size);
          exit(-1);
       }
       if ((atoi(xattrnsize) % (chunksize*1024)) != 0) {
          fprintf(stderr, "file %s: part size multiple of chunksize  mismatch %s %d\n",infile,xattrnsize,chunksize*1024);
          exit(-1);
       }
       if (atoi(xattrncompsize) != partstat[counter].st_size) {
          fprintf(stderr, "file %s: stat compsize  mismatch %s %lld\n",infile,xattrncompsize,partstat[counter].st_size);
          exit(-1);
       }
       if ((atoi(xattrncompsize) % (chunksize*1024)) != 0) {
          fprintf(stderr, "file %s: part compsize multiple of chunksize  mismatch %s %d\n",infile,xattrncompsize,chunksize*1024);
          exit(-1);
       }
       /* open up the files for read  and allocate a buffer per file */
       input_fd[counter] = open(infile, O_RDONLY);
       if (input_fd[counter] == -1) {
          perror("open of file failed");
          exit(-9);
       }
       /* allocate for parts buffs */
       posix_memalign(&buffs[counter],32,chunksize*1024);       
       sum[counter] = 0;
       nsz[counter] = 0;
       ncompsz[counter] = 0;
       xattrsum[counter] =  strtoul(xattrnsum,NULL,0);

       counter++;
    }

    /* loop over full stripe reads of num parts * chunksize, write output file to totalsize */
    /* generate sum and check p and q*/
    topcounter = 0; 
    toploops = atoi(xattrncompsize) / (chunksize*1024);
    if (pq > 1) {
       loops = numchunks+2;
    } else {
       loops = numchunks+1;
    }
    while (topcounter < toploops) {  
      ret_in = 0;
      counter = 0;
      /* loop over parts read, calc sum and tot */
      while (counter < loops) {
         ret_in = read(input_fd[counter],buffs[counter],chunksize*1024); 
         //fprintf(stderr,"reading %zd from infile %d\n",ret_in,counter);
         csum = 0;
         csum = summer(buffs[counter],chunksize*1024);
         sum[counter] = sum[counter] + csum; 
         nsz[counter] = nsz[counter] + chunksize*1024;
         ncompsz[counter] = ncompsz[counter] + chunksize*1024;

         counter++;
      }
      if (pq <  2) {
         ret_out = xor_check_sse(loops,chunksize*1024,buffs);
         if (ret_out != 0) {
            fprintf(stderr,"failed P raid calc test %zd\n",ret_out);
            exit(-1);
         } 
      } else {
         ret_out = pq_check_sse(loops,chunksize*1024,buffs);
         if (ret_out != 0) {
            fprintf(stderr,"failed PQ raid calc test %zd\n",ret_out);
            exit(-1);
         } 
      } 
      topcounter++;
    }
    fprintf(stderr,"passed raid P or PQ test\n");

    counter = 0;
    if (pq > 1) {
       loops = numchunks+2;
    } else {
       loops = numchunks+1;
    }
    while (counter < loops) {
       bzero(infile,sizeof(infile));
       sprintf(infile,"%s.%d",argv[1],counter);
       if (counter == numchunks) sprintf(infile,"%s.p",argv[1]);
       if (counter == numchunks+1) sprintf(infile,"%s.q",argv[1]);
       if (xattrsum[counter] != sum[counter]) {
          fprintf(stderr,"sum missmatch for file %s xattr sum %lu sum %lu\n",infile,xattrsum[counter],sum[counter]); 
          exit(-1);
       } else {
          fprintf(stderr,"sum match for file %s xattr sum %lu sum %lu\n",infile,xattrsum[counter],sum[counter]); 
       }
       close(input_fd[counter]);
       free(buffs[counter]);
       counter++;
    }

    return (EXIT_SUCCESS);
}
