#ifndef __NE_H__
#define __NE_H__

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

#define DEBUG
#define INT_CRC
//#define XATTR_CRC

#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/uio.h>
#if (AXATTR_RES == 1)
#include <sys/xattr.h>
#elif (AXATTR_RES == 2)
#include <attr/xattr.h>
#endif

#define MAXN 15
#define MAXE 5
#define MAXNAME 1024 
#define MAXBUF 4096 
#define MAXBLKSZ 256
#define BLKSZ 65536
#define TEST_SEED 57

#define XATTRKEY "user.n.e.bsz.nsz.ncompsz.ncrcsum.totsz"
#ifdef XATTR_CRC
#define XCRCKEY "crc_list"
#endif
#define MAXPARTS (MAXN + MAXE)
#define NO_INVERT_MATRIX -2

typedef uint32_t u32;
typedef uint64_t u64;
typedef enum {NE_RDONLY,NE_WRONLY,NE_REBUILD} ne_mode;

typedef struct node {
   struct node *next;
   struct node *prev;
   u32 crc;
} *crc_node;

typedef struct handle {
   /* Erasure Info */
   int N;
   int E;
   unsigned int bsz;

   /* Read/Write Info and Structures */
   ne_mode mode;
   u64 totsz;
   void *buffer;
   unsigned char *buffs[ MAXN + MAXE ];
   unsigned long buff_rem;
   off_t buff_offset;
   int FDArray[ MAXN + MAXE ];
#ifdef XATTR_CRC
   crc_node crc_list[ MAXPARTS ];
#endif

   /* Per-part Info */
   u64 csum[ MAXN + MAXE ];
   unsigned long nsz[ MAXN + MAXE ];
   unsigned long ncompsz[ MAXN + MAXE ];

   /* Error Pattern Info */
   int nerr;
   int erasure_offset;
   unsigned char e_ready;
   unsigned char src_in_err[ MAXN + MAXE ];
   unsigned char src_err_list[ MAXN + MAXE ];

   /* Erasure Manipulation Structures */
   unsigned char *encode_matrix;
   unsigned char *decode_matrix;
   unsigned char *invert_matrix;
   unsigned char *g_tbls;
   unsigned char *recov[ MAXPARTS ];
} *ne_handle;

/* Erasure Utility Functions */
ne_handle ne_open( char *path, ne_mode mode, int start_position, int N, int E );
int ne_read( ne_handle handle, void *buffer, int nbytes, off_t offset );
int ne_write( ne_handle handle, void *buffer, int nbytes );
int ne_close( ne_handle handle );
int ne_rebuild( ne_handle handle );

extern void pq_gen_sse(int, int, void*);  /* assembler routine to use sse to calc p and q */
extern void xor_gen_sse(int, int, void*);  /* assembler routine to use sse to calc p */
extern int pq_check_sse(int, int, void*);  /* assembler routine to use sse to calc p */
extern int xor_check_sse(int, int, void*);  /* assembler routine to use sse to calc p */
extern uint32_t crc32_ieee(uint32_t seed, uint8_t * buf, uint64_t len);
extern void gf_gen_rs_matrix(unsigned char *a, int m, int k);
extern void ec_encode_data(int len, int srcs, int dests, unsigned char *v,unsigned char **src, unsigned char **dest);
extern void gf_vect_mul_init(unsigned char c, unsigned char *tbl);
extern unsigned char gf_mul(unsigned char a, unsigned char b);
extern int gf_invert_matrix(unsigned char *in_mat, unsigned char *out_mat, const int n);

#endif
