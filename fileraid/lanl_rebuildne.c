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
lanl_rebuildne read all the N stripes and erasure stripes except the missing ones which has to be provided by the user and use the erasrue rebuild the missing stripes 
Syntax 
lanl_rebuildne inputfileprefix npattern(0.0.1.0.0) epattern(1.0) ** 0 for read 1 for rebuild  
example:
./lanl_rebuidne outfile 0.0.1.0.0 1.0     
this is rebuilding the third stripe and the e0 stripe in a 5+2  
The program uses the Intel ISA-L routines for producing xor in C, SSE, and AVX512.
Additionally,  the missing files  get the xattr added to it 
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
    //char * buf;                  /* general buf ptr */
    ssize_t ret_in, ret_out;     /* Number of bytes returned by read() and write() */
    char xattrval[200];          /* char array to build xattr value */
    char xattrchunks[20];        /* char array to get n parts from xattr */
    char xattrchunksizek[20];    /* char array to get chunksize from xattr */
    char xattrnsize[20];         /* char array to get total size from xattr */
    int nsize;                   /* general int */
    int i;                       /* general int */
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
    void * buf;                  /* temp malloc buffer pointer */
    unsigned char * buffs[MAXPARTS];    /* array of buffs for parts and p and q */
    unsigned char * temp_buffs[MAXPARTS];    /* array of buffs for parts and p and q */
    unsigned char * recov[MAXPARTS];    /* array of buffs for parts and p and q */
    unsigned long csum;          /* used for summing */
    unsigned long sum[MAXPARTS]; /* used for per part sum */
    int nsz[MAXPARTS];           /* array of parts sizes */
    int ncompsz[MAXPARTS];       /* array of compressed part size (future) */
    int missing;                 /* missing N part from user */
    int erasure;                 /* num erasure */
    char xattrerasure[8];        /* num erasure */
    u32 crc;                     /* crc 32 */
    int in;                      /* general int */
    char inchar[100];            /* in characters */
    int inlen;                   /* input len */
    int nerr;                    /* num missing stripes*/
    int nsrcerr;                 /* num missing data stripes*/
    int ntot;                    /* tot n */
    int etot;                    /* tot e */
    int mtot;                    /* tot master */
    int goodfile;                /* a good file we can check xattrs against */
    int goodfileset;             /* a good file we can check xattrs against */
    unsigned char src_in_err[MAXPARTS]; /* stripe error map */
    unsigned char src_err_list[MAXPARTS]; /* stripe error list */
    unsigned char *encode_matrix, *decode_matrix, *invert_matrix, *g_tbls;
    unsigned int decode_index[MAXPARTS];
 
    /* syntax */
    if(argc != 4){
        fprintf (stderr,"Usage: %s inputfileprefix npattern(0.0.1.0.0) epattern(1.0) \n",argv[0]); 
        return 1;
    }

    memset(src_in_err, 0, MAXPARTS);
    inlen = strlen(argv[2]);
    nerr = 0;
    ntot = 0;
    nsrcerr = 0;
    mtot=0;
    goodfile=999;
    goodfileset=0;
    counter = 0;
    while (counter < inlen) {
      bzero(inchar,sizeof(inchar));
      strncpy(inchar, argv[2]+counter,1); 
      in = atoi(inchar);
      if (in < 0) {
         printf("npattern character must be 0 or 1 %d\n",in);
         exit(-1);
      }
      if (in > 1) {
         printf("npattern character must be 0 or 1 %d\n",in);
         exit(-1);
      }
      if (in == 1) {
        src_in_err[mtot] = 1;
        src_err_list[nerr] = mtot;
        nsrcerr++;
        nerr++; 
      } else {
        goodfile = mtot;
        //printf("data goodfile %d\n",goodfile);
      }
      //printf("processing input counter %d mtot %d\n",counter,mtot);
      ntot++;
      mtot++;
      counter++;
      counter++;
    } 
    inlen = strlen(argv[3]);
    etot = 0;
    counter = 0;
    //printf("processing starting erasure input mtot %d inlen %d arg %s\n",mtot,inlen,argv[3]);
    while (counter < inlen) {
      bzero(inchar,sizeof(inchar));
      strncpy(inchar, argv[3]+counter,1); 
      in = atoi(inchar);
      if (in < 0) {
         printf("epattern character must be 0 or 1 %d\n",in);
         exit(-1);
      }
      if (in > 1) {
         printf("epattern character must be 0 or 1 %d\n",in);
         exit(-1);
      }
      if (in == 1) {
        src_in_err[mtot] = 1;
        src_err_list[nerr] = mtot;
        nerr++; 
      } else {
        goodfile = mtot;
        //printf("erasure goodfile %d\n",goodfile);
      }
      //printf("processing erasure input counter %d mtot %d\n",counter,mtot);
      etot++;
      mtot++;
      counter++;
      counter++;
    }
    printf("nerr %d nsrcerr %d ntot %d etot %d goodfile %d mtot %d\n",nerr, nsrcerr, ntot, etot, goodfile,mtot);
    printf("src_in_err:\n");
    dump(src_in_err,MAXPARTS);
    printf("src_err_list:\n");
    dump(src_err_list,MAXPARTS);

    bzero(infile,sizeof(infile));
    if (goodfile < ntot) {
      sprintf(infile,"%s.%d",argv[1],goodfile);
    } else {
      sprintf(infile,"%s.e%d",argv[1],goodfile-ntot);
    }

    /* go to the a good file depending on missing (there can only be one missing) and get the xattr to tell us how big the file is, num parts, chunk size, etc. */
    bzero(xattrval,sizeof(xattrval));
#if (AXATTR_GET_FUNC == 4)
    getxattr(infile,XATTRKEY,&xattrval[0],sizeof(xattrval));
#else
    getxattr(infile,XATTRKEY,&xattrval[0],sizeof(xattrval),0,0);
#endif
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
    /*if (missing > numchunks) {
        fprintf (stderr," missing %d , must be from 0 to numchunks %d\n",missing,numchunks); 
        return 1;
    }*/
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
    /* allocate matrix */
    encode_matrix = malloc(MAXPARTS * MAXPARTS);
    decode_matrix = malloc(MAXPARTS * MAXPARTS);
    invert_matrix = malloc(MAXPARTS * MAXPARTS);
    g_tbls = malloc(MAXPARTS * MAXPARTS * 32);

    // Generate encode matrix encode_matrix
    // The matrix generated by gf_gen_rs_matrix
    // is not always invertable.
    gf_gen_rs_matrix(encode_matrix, mtot, ntot);

    // Generate g_tbls from encode matrix encode_matrix
    ec_init_tables(ntot, mtot - ntot, &encode_matrix[ntot * ntot], g_tbls);

    ret_in = gf_gen_decode_matrix(encode_matrix, decode_matrix,
             invert_matrix, decode_index, src_err_list, src_in_err,
                  nerr, nsrcerr, ntot, mtot);
    if (ret_in != 0) {
        printf("Fail to gf_gen_decode_matrix\n");
        return -1;
    }
    printf("erasure_code_test: now we buid an array of buffers that contain the non failed stripes\n");

    /* open input files initialize some per part values skip opening missing file  */
    counter = 0;
    while (counter < mtot) {
      bzero(infile,MAXNAME);
      if (counter < ntot) {
         sprintf(infile,"%s.%d",argv[1],counter);
         fprintf(stderr,"opening data file %s\n",infile);
      } else {
         sprintf(infile,"%s.e%d",argv[1],counter-ntot);
         fprintf(stderr,"opening erasure file %s\n",infile);
      }
      if (src_in_err[counter] == 0) {
         input_fd[counter] = open(infile, O_RDONLY);
         if (input_fd[counter] == -1) {
           perror("open of input");
           exit(-9);
         }
      } else {
        input_fd[counter] = open(infile, O_WRONLY | O_CREAT, 0644);
        fprintf(stderr,"missing file %s\n",infile);
        if (input_fd[counter] == -1) {
          perror("open of missing");
          exit(-9);
        }
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
         }
         counter++;
      }

      for (i = 0; i < ntot; i++) {
            recov[i] = buffs[decode_index[i]];
      }
      ec_init_tables(ntot, nerr, decode_matrix, g_tbls);
#ifdef AISAL
      ec_encode_data(chunksize*1024, ntot, nerr, g_tbls, recov, &temp_buffs[ntot]);
#else
      ec_encode_data_base(chunksize*1024, ntot, nerr, g_tbls, recov, &temp_buffs[ntot]);
#endif

      for (i = 0; i < nerr; i++) {
         write(input_fd[src_err_list[i]],temp_buffs[ntot+i],chunksize*1024);
         crc = 0;
#ifdef AISAL
         crc = crc32_ieee(TEST_SEED, temp_buffs[ntot+i], chunksize*1024);
#else
         crc = crc32_ieee_base(TEST_SEED, temp_buffs[ntot+i], chunksize*1024);
#endif
         sum[src_err_list[i]] = sum[src_err_list[i]] + crc;
         nsz[src_err_list[i]] = nsz[src_err_list[i]] + chunksize*1024;
         ncompsz[src_err_list[i]] = ncompsz[src_err_list[i]] + chunksize*1024;
      }
      totsizetest = totsizetest + (chunksize*1024);  
    }
 
    /* Close file descriptors and free bufs set xattrs on missing */
    counter = 0;
    while (counter < mtot) {
       if (src_in_err[counter] == 1) {
          bzero(xattrval,sizeof(xattrval));
          sprintf(xattrval,"%d %d %d %d %d %lu %lld",numchunks,erasure,chunksize,nsz[counter],ncompsz[counter],sum[counter],totsize);
#if (AXATTR_SET_FUNC == 5)
          fsetxattr(input_fd[counter],XATTRKEY, xattrval,strlen(xattrval),0);
#else
          fsetxattr(input_fd[counter],XATTRKEY, xattrval,strlen(xattrval),0,0);
#endif
          printf("wrote and set xattr for %d\n",counter);
       }
       close(input_fd[counter]);
       free(buffs[counter]);
       counter++;
    }

    return (EXIT_SUCCESS);
}
