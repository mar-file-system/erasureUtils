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

These erasure utilites make use of the Intel Intelligent Storage
Acceleration Library (Intel ISA-L), which can be found at
https://github.com/01org/isa-l and is under its own license.

MarFS uses libaws4c for Amazon S3 object communication. The original version
is at https://aws.amazon.com/code/Amazon-S3/2601 and under the LGPL license.
LANL added functionality to the original work. The original work plus
LANL contributions is found at https://github.com/jti-lanl/aws4c.

GNU licenses can be found at http://www.gnu.org/licenses/.
*/

#endif // copyright


#define INT_CRC
#define META_FILES

#include "config.h"
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>


#define NE_LOG_PREFIX "libne"
#ifdef SOCKETS
#  include "skt_common.h"
   typedef SocketHandle  FileDesc;
#else
#  include "ne_logging.h"
   typedef int           FileDesc;
   typedef void*         SktAuth;
#endif





/* MIN_PROTECTION sets the threshold for when writes will fail.  If
   fewer than n+MIN_PROTECTION blocks were written successfully, then
   the write will fail. */
#define MIN_PROTECTION 1
#define MAXN 15
#define MAXE 5
#define MAXNAME 1024 
#define MAXBUF 4096 
#define MAXBLKSZ 16777216
#define BLKSZ 1048576
#define HEADSZ 70
#define TEST_SEED 57
#define SYNC_SIZE (34 * 1024 * 1024) /* number of MB between close/reopen */

#define XATTRKEY "user.n.e.offset.bsz.nsz.ncompsz.ncrcsum.totsz"
#define WRITE_SFX ".partial"
#define REBUILD_SFX ".rebuild"
#define META_SFX ".meta"
#define MAXPARTS (MAXN + MAXE)
#define NO_INVERT_MATRIX -2




/* It's useful to distinguish diagnostics intended for stderr vs stdout.
   Running 'marfs_fuse -f ... > log 2>&1' allows stderr to go to the log,
   but stdout doesn't get there.  So, one could tweak the PRINTout defn
   here, to send stdout-diagnostics to stderr, then rebuild with
   --enable-debug=all, then rebuild marfs_fuse with --enable-logging=stdout
   --enable-debug, run fuse as suggested above, and see integrated
   diagnostics for fuse and libne in the fuse output log. */

#if (DEBUG_NE == 2)
#  include <syslog.h>
#  define PRINTout(...)   SYSLOG(LOG_DEBUG, ##__VA_ARGS__)
#  define PRINTerr(...)   SYSLOG(LOG_ERR,   ##__VA_ARGS__)
#  define LOG_INIT()      openlog(NE_LOG_PREFIX, LOG_CONS|LOG_PID, LOG_USER)

#elif (DEBUG_NE)
// #  define PRINTout(...)   FPRINTF(stdout, ##__VA_ARGS__)
#  define PRINTout(...)   FPRINTF(stderr, ##__VA_ARGS__) /* stderr for 'fuse -f ...' */
#  define PRINTerr(...)   FPRINTF(stderr, ##__VA_ARGS__)
#  define LOG_INIT()

#else
#  define PRINTout(...)
#  define PRINTerr(...)   fprintf(stderr, ##__VA_ARGS__)
#  define LOG_INIT()
#endif


#ifndef HAVE_LIBISAL
#  define crc32_ieee(...)     crc32_ieee_base(__VA_ARGS__)
#  define ec_encode_data(...) ec_encode_data_base(__VA_ARGS__)
#endif

#define UNSAFE(HANDLE) ((HANDLE)->nerr > (HANDLE)->E - MIN_PROTECTION)

typedef uint32_t u32;
typedef uint64_t u64;

typedef enum {
  NE_RDONLY = 0,
  NE_WRONLY,
  NE_REBUILD,
  NE_STAT,
  NE_NOINFO = 4,
  NE_SETBSZ = 8
} ne_mode;

#define MAX_QDEPTH 5

typedef enum {
  BQ_ERROR    = 0x01 << 0,
  BQ_FINISHED = 0x01 << 1,
  BQ_ABORT    = 0x01 << 2,
  BQ_OPEN     = 0x01 << 3,
} BufferQueue_Flags;

struct handle; // forward decl.

typedef struct buffer_queue {
  pthread_mutex_t    qlock;
  void              *buffers[MAX_QDEPTH];
  size_t             offset;             /* amount of partial block that has
                                            been stored in the buffer[tail] */
  u64                csum;               /* checksum for all data written */
  pthread_cond_t     full;               /* cv signals there is a full slot */
  pthread_cond_t     empty;              /* cv signals there is an empty slot */
  int                qdepth;             /* number of elements in the queue */
  int                head;               /* next full position */  
  int                tail;               /* next empty position */
  FileDesc           file;               /* file descriptor */
  char               path[2048];         /* path to the file */
  int                block_number;
  struct handle     *handle;
  BufferQueue_Flags  flags;
  size_t             buffer_size;
} BufferQueue;

typedef struct ne_stat_struct {
   char xattr_status[ MAXPARTS ];
   char data_status[ MAXPARTS ];
   int N;
   int E;
   int start;
   unsigned int bsz;
   u64 totsz;
} *ne_stat;


// One of these for each channel.
// A channel that is opened O_WRONLY still does "reads"
// to fill its buffers.
#include "fast_timer.h"
typedef struct {
   FastTimer   thread;
   FastTimer   open;

   FastTimer   read;
   LogHisto    read_h;

   FastTimer   write;
   LogHisto    write_h;

   FastTimer   close;
   FastTimer   rename;

   FastTimer   crc;
   LogHisto    crc_h;
} BenchStats;


typedef enum {
   SF_OPEN    =  0x0001,
   SF_RW      =  0x0002,    /* each individual read/write, in given stream */
   SF_CLOSE   =  0x0004,    /* cost of close */
   SF_RENAME  =  0x0008,
   SF_CRC     =  0x0010,
   SF_ERASURE =  0x0020,
   SF_THREAD  =  0x0040,    /* from beginning to end  */
   SF_HANDLE  =  0x0080,    /* from start/stop, all threads, in 1 handle */
   // SF_GLOBAL  =  0x0100,    /* cost across all handles */
} StatFlags;

typedef  uint16_t  StatFlagsValue;


// This allows ne_open() and other functions to perform arbitrary
// conversions of a given block-number (in the range [0, N+E-1]), into
// the hostname, block-subdir, etc, for the supplied path.  This is
// mainly needed with --enable-sockets.  It allows the caller to use
// its own configuration-info to control these computations within
// ne_open().

typedef  int (*SnprintfFunc)(char* dest, size_t size, const char* format, u32 block, void* state);

// SnprintfFunc ne_default_snprintf;
int ne_default_snprintf(char* dest, size_t size, const char* format, u32 block, void* state);


typedef struct handle {
   /* Erasure Info */
   int N;
   int E;
   unsigned int bsz;
   char *path;

   /* Read/Write Info and Structures */
   ne_mode mode;
   u64 totsz;
   void *buffer;
   unsigned char *buffs[ MAXPARTS ];
   unsigned long buff_rem;
   off_t buff_offset;
   FileDesc FDArray[ MAXPARTS ];
   SktAuth  auth;               /* pass-through to RDMA/sockets impl */

   /* Threading fields */
   void *buffer_list[MAX_QDEPTH];
   void *block_buffs[MAX_QDEPTH][MAXPARTS];
   pthread_t threads[MAXPARTS];
   BufferQueue blocks[MAXPARTS];

   /* Per-part Info */
   u64 csum[ MAXPARTS ];
   unsigned long nsz[ MAXPARTS ];
   unsigned long ncompsz[ MAXPARTS ];
   off_t written[ MAXPARTS ];

   /* Error Pattern Info */
   int nerr;
   int erasure_offset;
   unsigned char e_ready;
   unsigned char src_in_err[ MAXPARTS ];
   unsigned char src_err_list[ MAXPARTS ];

   /* Erasure Manipulation Structures */
   unsigned char *encode_matrix;
   unsigned char *decode_matrix;
   unsigned char *invert_matrix;
   unsigned char *g_tbls;
   unsigned char *recov[ MAXPARTS ];

   /* Used for rebuilds to restore the original ownership to the rebuilt file. */
   uid_t owner;
   gid_t group;

   /* path-printing technique provided by caller */
   SnprintfFunc   snprintf;
   void*          state;        // caller-data to be provided to <snprintf>

   /* optional timing/benchmarking */
   int            stat_flags;        /* initialized at build-time */
   BenchStats     stats[ MAXPARTS ]; /* ops w/in each thread */
   BenchStats     agg_stats;         /* ops across "threads", O_RDONLY */
   FastTimer      handle_timer;      /* pre-open to post-close, all threads complete */
   FastTimer      erasure_timer;
   LogHisto       erasure_h;

} *ne_handle;


/* Erasure utility-functions taking a raw path argument */
ne_handle ne_open1  ( SnprintfFunc func, void* state, SktAuth auth, StatFlagsValue flags, char *path, ne_mode mode, ... );
int       ne_delete1( SnprintfFunc func, void* state, SktAuth auth, char *path, int width );
ne_stat   ne_status1( SnprintfFunc func, void* state, SktAuth auth, char *path );

// these interfaces provide a default SnprintfFunc, which supports the
// expectations of the default MarFS multi-component implementation
ne_handle ne_open  ( char *path, ne_mode mode, ... );
int       ne_delete( char* path, int width );
ne_stat   ne_status( char* path);


/* Erasure utility-functions taking a <handle> argument */
ssize_t   ne_read ( ne_handle handle, void       *buffer, size_t nbytes, off_t offset );
ssize_t   ne_write( ne_handle handle, const void *buffer, size_t nbytes );
int       ne_close( ne_handle handle );
int       ne_rebuild( ne_handle handle );
int       ne_noxattr_rebuild( ne_handle handle );
int       ne_flush( ne_handle handle );

#endif

