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
lanl_netof read all the N stripes and erasure stripes except the missing ones which has to be provided by the user and create a file or part of a file 
Syntax 
lanl_netof inputfileprefix npattern(0.0.1.0.0) epattern(1.0) offset outputfile(name or - for stdout)
pattern usage 0 for read 1 for rebuild  
example:
./lanl_netof outtest 0.0.1.0.0 1.0 4476 900005 outfile
this will provide the read of the file data from the n parts and e erasures starting at any offset and 
either for length or until pipe ends if using stdout pipe
the example reads from outtest.0,1,3,4 and e1  and rebuilds the data from outtest.2 on the fly to honor
the request for file data
The program uses the Intel ISA-L routines for producing xor in C, SSE, and AVX512.
Additionally,  the files have the xattr  
n.e.chunksize.nsz.ncompsz.ncrcsum.totsz: 10 2 64 196608 196608 3304199718723886772 1717171
N is nparts, E is num erasure, chunksize is chunksize, nsz is the size of the part, ncompsz is the size of the part but might get used if we ever compress the parts, totsz is the total real data in the N part files. 
the ncrcsum is produced using the crc32 for each chunksize and summing those over the file

*/
/***************************************************************/


int main(int argc, char* argv[]) {
 
    int output_fd;               /* output file descriptor */
    char outfile[MAXNAME];       /* outfile name */
    long long offset;            /* request offset */
    long long length;            /* request length */ 
    int tmpchunk;                /* chunk var for use in read loop */
    int tmpoffset;               /* offset var for use in read loop */
    int input_fd[MAXPARTS];      /* array of file output file descriptors */
    char infile[MAXNAME];        /* array of name of input files */
    int numchunks;               /* n number of raid parts not including p and q */ 
    int chunksize;               /* chunksize in k */ 
    char firstchunk;             /* general flag */
    int counter;                 /* general counter */ 
    int llcounter;              /* general counter */ 
    int lltotcounter;              /* general counter */ 
    char firststripe;            /* general flag */
    //char * buf;                /* general buf ptr */
    ssize_t ret_in, ret_out;     /* Number of bytes returned by read() and write() */
    char xattrval[200];          /* char array to build xattr value */
    char xattrchunks[20];        /* char array to get n parts from xattr */
    char xattrchunksizek[20];    /* char array to get chunksize from xattr */
    char xattrnsize[20];         /* char array to get total size from xattr */
    int nsize;                   /* general int */
    int i;                       /* general int */
    int maxNerr;                 /* index of last data chunks containing errors */
    int minNerr;                 /* index of first data chunks containing errors */
    char xattrncompsize[20];     /* general char for xattr manipulation */
    int ncompsize;               /* general int */
    char xattrnsum[50];          /* char array to get xattr sum from xattr */
    int nsum;                    /* general int */
    char xattrtotsize[160];      /* char array to get total size from xattr */
    long long totsize;           /* total size of file */
    long long totsizetest;       /* used to get total size of file */
    int writesize;               /* write size variable */
    int skipped_err;             /* counter for skipped error chunks */
    int file;                    /* file flag */
    void * buf;                  /* temp malloc buffer pointer */
    unsigned char * buffs[MAXPARTS];    /* array of buffs for parts and p and q */
    unsigned char * temp_buffs[MAXPARTS];    /* array of buffs for parts and p and q */
    unsigned char * recov[MAXPARTS];    /* array of buffs for parts and p and q */
    unsigned long csum;          /* used for summing */
    unsigned long sum[MAXPARTS]; /* used for per part sum */
    int nsz[MAXPARTS];           /* array of parts sizes */
    int ncompsz[MAXPARTS];       /* array of compressed part size (future) */
    int missing=0;                 /* missing N part from user */
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
    char error_in_stripe;
    int startstripe;
    int startchunk;
    int startoffset;
    int endchunk;
    off_t seekamt;
     
    /* syntax */
    if(argc != 7){
        fprintf (stderr,"Usage: %s inputfileprefix npattern(0.0.1.0.0) epattern(1.0) offset length outputfile(name or -) \n",argv[0]); 
        return 1;
    }

    memset(src_in_err, 0, MAXPARTS);
    inlen = strlen(argv[2]);
    nerr = 0;
    ntot = 0;
    nsrcerr = 0;
    maxNerr = -1;              //note, less than N
    minNerr = strlen(argv[2]); //note, greater than N
    mtot=0;
    goodfile=999;
    goodfileset=0;
    counter = 0;

    //parse through npattern
    while (counter < inlen) {
      bzero(inchar,sizeof(inchar));
      strncpy(inchar, argv[2]+counter,1); 
      in = atoi(inchar);
      if (in < 0) {
         fprintf(stderr,"npattern character must be 0 or 1 %d\n",in);
         exit(-1);
      }
      if (in > 1) {
         fprintf(stderr,"npattern character must be 0 or 1 %d\n",in);
         exit(-1);
      }
      if (in == 1) {
        src_in_err[mtot] = 1;
        src_err_list[nerr] = mtot;
        if (mtot > maxNerr) maxNerr=mtot;
        if (mtot < minNerr) minNerr=mtot;
        nsrcerr++;
        nerr++; 
      } else {
        goodfile = mtot;
        //fprintf(stderr,"data goodfile %d\n",goodfile);
      }
      //fprintf(stderr,"processing input counter %d mtot %d\n",counter,mtot);
      ntot++;
      mtot++;
      counter++;
      counter++;
    } 
    inlen = strlen(argv[3]);
    etot = 0;
    counter = 0;
    //fprintf(stderr,"processing starting erasure input mtot %d inlen %d arg %s\n",mtot,inlen,argv[3]);

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
        src_in_err[mtot] = 1;
        src_err_list[nerr] = mtot;
        nerr++; 
      } else {
        goodfile = mtot;
        //fprintf(stderr,"erasure goodfile %d\n",goodfile);
      }
      //fprintf(stderr,"processing erasure input counter %d mtot %d\n",counter,mtot);
      etot++;
      mtot++;
      counter++;
      counter++;
    }
    fprintf(stderr,"nerr %d nsrcerr %d ntot %d etot %d goodfile %d mtot %d\n",nerr, nsrcerr, ntot, etot, goodfile,mtot);
    fprintf(stderr,"src_in_err:\n");
    dump(src_in_err,MAXPARTS);
    fprintf(stderr,"src_err_list:\n");
    dump(src_err_list,MAXPARTS);

    bzero(infile,sizeof(infile));
    if (goodfile < ntot) {
      sprintf(infile,"%s.%d",argv[1],goodfile);
    } else {
      sprintf(infile,"%s.e%d",argv[1],goodfile-ntot);
    }

    /* go to the a good file depending on missing (there can only be one missing) and get the xattr to tell us how big the file is, num parts, chunk size, etc. */
    getxattr(infile,XATTRKEY,&xattrval[0],sizeof(xattrval));
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

       if ( endchunk > ntot ) {
          endchunk = mtot;
       }     
 
       /**** set seek positions for initial reading ****/
       if (startchunk > maxNerr  ||  endchunk < minNerr ) {  //if not reading from corrupted chunks, we can just set these normally
          fprintf(stderr,"startchunk = %d, endchunk = %d\n   This stipe does not contain any corrupted blocks...\n", startchunk, endchunk);
          for ( counter = 0; counter < endchunk; counter++ ) {
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
