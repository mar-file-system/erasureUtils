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
lanl_rebuild1N_from_e0 read all the N stripes except the missing one which has to be provided by the user and use the XOR e0 to rebuild the missing N stripe 
Syntax 
lanl_rebuild1N_from_e0 inputfileprefix(N parts) missingpart(start numbering with zero) 
example:
./lanl_rebuid1N_from_e0 outtest 3
this will use outtest.0,1,2,4,5,6,7,8,9 and e0 to rebuild outtest.3  (in a 10+e) 
The program uses the Intel ISA-L routines for producing xor in C, SSE, and AVX512.
Additionally,  the missing part file  get an xattr added to it 
the xattr looks like this
n.e.chunksize.nsz.ncompsz.ncrcsum.totsz: 10 2 64 196608 196608 3304199718723886772 1717171
N is nparts, E is num erasure, chunksize is chunksize, nsz is the size of the part, ncompsz is the size of the part but might get used if we ever compress the parts, totsz is the total real data in the N part files. 
the ncrcsum is produced using the crc32 for each chunksize and summing those over the file

todo

*/
/***************************************************************/

 
int main(int argc, char* argv[]) {
 
    int output_fd;               /* output file descriptor */
    int p_fd;                    /* p file descriptor */
    int q_fd;                    /* q file descriptor */
    int input_fd[MAXPARTS];      /* array of file output file descriptors */
    char infile[MAXNAME];        /* array of name of input files */
    int numchunks;               /* n number of raid parts not including p and q */ 
    int chunksize;               /* chunksize in k */ 
    int counter;                 /* general counter */ 
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
    int nsz[MAXPARTS];           /* array of parts sizes */
    int ncompsz[MAXPARTS];       /* array of compressed part size (future) */
    int missing;                 /* missing N part from user */
    int erasure;                 /* num erasure */
    char xattrerasure[8];        /* num erasure */
    u32 crc;                     /* crc 32 */
 
    /* syntax */
    if(argc != 3){
        fprintf (stderr,"Usage: %s inputfilespec missingpart(start numbering with zero) \n",argv[0]); 
        return 1;
    }
    /* edit input */
    missing = atoi (argv[2]);
    if (missing < 0 ) {
        fprintf (stderr," missing %d ,must be 0 to max parts\n",missing); 
        return 1;
    }
    if (pq > MAXPARTS) {
        fprintf (stderr," missing %d ,must be 0 to max parts\n",missing); 
        return 1;
    }

    /* go to the part.0 or part.1 file depending on missing (there can only be one missing) and get the xattr to tell us how big the file is, num parts, chunk size, etc. */
    bzero(infile,sizeof(infile));
    if (missing > 0) sprintf(infile,"%s.0",argv[1]);
    if (missing == 0) sprintf(infile,"%s.1",argv[1]);
#if (AXATTR_GET_FUNC == 4)
    getxattr(infile,XATTRKEY,&xattrval[0],sizeof(xattrval));
#else
    getxattr(infile,XATTRKEY,&xattrval[0],sizeof(xattrval),0,0);
#endif
    fprintf(stderr,"got xattr %s\n",xattrval);
    bzero(xattrchunks,sizeof(xattrchunks));
    bzero(xattrchunksizek,sizeof(xattrchunksizek));
    bzero(xattrtotsize,sizeof(xattrtotsize));
    bzero(xattrerasure,sizeof(xattrerasure));
    sscanf(xattrval,"%s %s %s %s %s %s %s",xattrchunks,xattrerasure,xattrchunksizek,xattrnsize,xattrncompsize,xattrnsum,xattrtotsize);
    totsize = atoll(xattrtotsize);
    fprintf(stderr,"total file size is %lld\n",totsize);

    /* edit stuff from xattr */
    ncompsize = atoi (xattrncompsize);
    numchunks = atoi (xattrchunks);
    erasure = atoi ( xattrerasure);
    if (numchunks < 2 ) {
        fprintf (stderr, " filexattr %d , numchunks must be between 2 and %d \n",numchunks,MAXPARTS); 
        return 1;
    }
    if (numchunks > MAXPARTS ) {
        fprintf (stderr," filexattr %d , numchunks must be between 2 and %d \n",numchunks,MAXPARTS); 
        return 1;
    }
    chunksize = atoi (xattrchunksizek);
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
     
    /* open input files initialize some per part values skip opening missing file  */
    counter = 0;
    while (counter < numchunks) {
       if (counter != missing) {
         bzero(infile,MAXNAME);
         sprintf(infile,"%s.%d",argv[1],counter);
         fprintf(stderr,"opening infile %s\n",infile);
         input_fd[counter] = open(infile, O_RDONLY);
         if (input_fd[counter] == -1) {
            perror("open of input");
            exit(-9);
         }
       }
       /* allocate for parts buffs */
       posix_memalign(&buffs[counter],32,chunksize*1024);       
       sum[counter] = 0;
       nsz[counter] = 0;
       ncompsz[counter] = 0;
       counter++;
    }
    /* allocate for last  buff*/
    posix_memalign(&buffs[counter],32,chunksize*1024);       
    sum[counter] = 0;
    nsz[counter] = 0;
    ncompsz[counter] = 0;

    /* Create missing file descriptor this goes into the last place in the buffer array and file descriptor array but the file is name.missing  */
    /* put the missing one where P should be */
    bzero(infile,MAXNAME);
    sprintf(infile,"%s.%d",argv[1],missing);
    fprintf(stderr,"opening missing %s in fd %d\n",infile,counter);
    input_fd[counter] = open(infile, O_WRONLY | O_CREAT, 0644);
    if (input_fd[counter] == -1) {
       perror("open of missing");
       exit(-9);
    }
    /* open up e0 file an put it in where the missing one should be in the array */
    sprintf(infile,"%s.e0",argv[1]);
    input_fd[missing] = open(infile, O_RDONLY);
    if (input_fd[missing] == -1) {
       perror ("open e0 file");
       return 2;
    }
   fprintf(stderr,"opened e0 %s file in position %d\n",infile,missing);

    totsizetest = 0;
    while (totsizetest < ncompsize*numchunks) {  
      ret_in = 0;
      counter = 0;
      /* loop over parts since we put e0 in where missing should be we just read these up */
      while (counter < numchunks) {
         ret_in = read(input_fd[counter],buffs[counter],chunksize*1024); 
         //fprintf(stderr,"reading %zd from infile %d\n",ret_in,counter);
         /* write appropriate amount to output file based on total size from xattr */
         totsizetest = totsizetest + ret_in;
/*
         if (file ) {
           if (totsizetest <= totsize) {
              writesize = ret_in;
           } else {
              writesize = totsize - (totsizetest - ret_in); 
           }
           if (writesize > 0) {
              //fprintf(stderr,"writing %zd to outfile \n",writesize);
              //write(output_fd,buffs[counter],writesize);
           }
         }
*/
         counter++;
      }
      /* calc e0 which is really the missing stripe sum, total, and write missing files */
      xor_gen_sse(numchunks+1,chunksize*1024,buffs);
      fprintf(stderr,"writing xor %zd to missing file at fd %d \n",chunksize*1024,counter);
      write(input_fd[counter],buffs[counter],chunksize*1024);
      crc = 0;
      crc = crc32_ieee(TEST_SEED, buffs[counter], chunksize*1024);
      sum[counter] = sum[counter] + crc;
      nsz[counter] = nsz[counter] + chunksize*1024;
      ncompsz[counter] = ncompsz[counter] + chunksize*1024;
    }
 
    /* Close file descriptors and free bufs set xattrs on missing */
    counter = 0;
    while (counter < numchunks) {
       close(input_fd[counter]);
       free(buffs[counter]);
       counter++;
    }
    /* close and free the last entry - the missing one) */
    free(buffs[counter]);
    bzero(xattrval,sizeof(xattrval));
    sprintf(xattrval,"%d %d %d %d %d %lu %lld",numchunks,erasure,chunksize,nsz[counter],ncompsz[counter],sum[counter],totsize);
#if (AXATTR_SET_FUNC == 5)
    fsetxattr(input_fd[counter],XATTRKEY, xattrval,strlen(xattrval),0);
#else
    fsetxattr(input_fd[counter],XATTRKEY, xattrval,strlen(xattrval),0,0);
#endif
    close(input_fd[counter]);
    return (EXIT_SUCCESS);
}
