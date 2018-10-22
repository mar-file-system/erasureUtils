#ifndef __NE_H__
#define __NE_H__

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


#define INT_CRC
#define META_FILES

#include "config.h"
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>


#define NE_LOG_PREFIX "libne"
#include "ne_logging.h"

// generated to #define SOCKETS, etc, based on configuration options.
#include "skt_config.h"
#include "udal.h"




/* MIN_PROTECTION sets the threshold for when writes will fail.  If
   fewer than n+MIN_PROTECTION blocks were written successfully, then
   the write will fail. */
#define MIN_PROTECTION 1

/* MIN_MD_CONSENSUS defines the minimum number of metadata files/xattrs we
   have to look at, which are all in agreement about the values for N and
   E, before ne_status1() will believe that it knows what N+E is.  In the
   case of META_FILES being defined, this avoids doing (MAXN + MAXE) -
   (N+E) failed stats for every ne_status(), ne_read(), etc. (In the case
   of UDAL_SOCKETS, each of those failed "stats" results in an attempt to
   connect to a non-existent server, which must then time out.  */
#define MIN_MD_CONSENSUS  6

#define MAXN 15
#define MAXE 5
#define MAXNAME 2048
#define MAXBUF 4096
#define MAXBLKSZ 16777216
#define BLKSZ 1048576
#define HEADSZ 70
#define TEST_SEED 57
#define SYNC_SIZE (34 * 1024 * 1024) /* number of MB between close/reopen */

#define XATTRKEY "user.n.e.offset.bsz.nsz.ncompsz.ncrcsum.totsz"
#define XATTRLEN 125
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
   diagnostics for fuse and libne in the fuse output log.

   I know it seems odd to suppress stderr-output for the non-debugging
   build, but, otherwise, pftool spews many errors at the user, e.g. when
   underlying libne is failing reads.  This may happen, for example, when
   servers are bottlenecked and communications are timing out, or if a
   server fails, etc.  This kind of output is not something the user wants
   to see, even though from libne's perspective it is a genuine error.
   Probably the best solution is to add PRINTlog(), or something, and have
   the code become conscious of output that really is worth showing to the
   user (for example, command-line help from libneTest).
 */


#if (DEBUG_NE == 2)
#  include <syslog.h>
#  define PRINTout(...)   SYSLOG(LOG_INFO,  ##__VA_ARGS__)
#  define PRINTerr(...)   SYSLOG(LOG_ERR,   ##__VA_ARGS__)
#  define PRINTlog(...)   SYSLOG(LOG_ERR,   ##__VA_ARGS__)
#  define PRINTdbg(...)   SYSLOG(LOG_DEBUG, ##__VA_ARGS__)
#  define LOG_INIT()      openlog(NE_LOG_PREFIX, LOG_CONS|LOG_PID, LOG_USER)

#elif (DEBUG_NE)
#  define PRINTout(...)   FPRINTF(stderr, ##__VA_ARGS__) /* stderr for 'fuse -f ...' */
#  define PRINTerr(...)   FPRINTF(stderr, ##__VA_ARGS__)
#  define PRINTlog(...)   FPRINTF(stderr, ##__VA_ARGS__)
#  define PRINTdbg(...)   FPRINTF(stderr, ##__VA_ARGS__)
#  define LOG_INIT()

#else
#  define PRINTout(...)   fprintf(stdout, ##__VA_ARGS__)
#  define PRINTerr(...)   /* fprintf(stderr, ##__VA_ARGS__) */
#  define PRINTlog(...)   fprintf(stdout, ##__VA_ARGS__)
#  define PRINTdbg(...)
#  define LOG_INIT()
#endif


#ifndef HAVE_LIBISAL
#  define crc32_ieee(...)     crc32_ieee_base(__VA_ARGS__)
#  define ec_encode_data(...) ec_encode_data_base(__VA_ARGS__)
#endif

#define UNSAFE(HANDLE) ((HANDLE)->erasure_state->nerr > (HANDLE)->erasure_state->E - MIN_PROTECTION)

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
  pthread_cond_t     have_work;          /* cv signals there is a full slot */
  pthread_cond_t     have_space;         /* cv signals there is an empty slot */
  int                qdepth;             /* number of elements in the queue */
  int                head;               /* next full position */  
  int                tail;               /* next empty position */
  struct GenericFD   file;               /* file descriptor */
  char               path[2048];         /* path to the file */
  int                block_number;
  struct handle     *handle;
  BufferQueue_Flags  flags;
  size_t             buffer_size;
} BufferQueue;

typedef struct ne_stat_struct {
   // erasure structure
   int N;
   int E;
   int O;
   unsigned int bsz;
   char* path_fmt;

   // striping size
   u64 totsz;
   unsigned long nsz;

   // striping health
   char manifest_status[ MAXPARTS ];
   char data_status[ MAXPARTS ];
   char src_in_err[ MAXPARTS ];
   int nerr;

   // per-part info
   u64 csum[ MAXPARTS ];
   unsigned long ncompsz[ MAXPARTS ];
} *e_status;


// One of these for each channel.
// A channel that is opened O_WRONLY still does "reads"
// to fill its buffers.
#include "fast_timer.h"
typedef struct {
   FastTimer   thread;
   FastTimer   open;
   LogHisto    open_h;

   FastTimer   read;
   LogHisto    read_h;

   FastTimer   write;
   LogHisto    write_h;

   FastTimer   close;
   LogHisto    close_h;

   FastTimer   rename;
   FastTimer   stat;
   FastTimer   xattr;

   FastTimer   crc;
   LogHisto    crc_h;
} BenchStats;


// (co-maintain help message in libneTest)
typedef enum {
   TF_OPEN    =  0x0001,
   TF_RW      =  0x0002,    /* each individual read/write, in given stream */
   TF_CLOSE   =  0x0004,    /* cost of close */
   TF_RENAME  =  0x0008,
   TF_STAT    =  0x0010,
   TF_XATTR   =  0x0020,
   TF_ERASURE =  0x0040,
   TF_CRC     =  0x0080,
   TF_THREAD  =  0x0100,    /* from beginning to end  */
   TF_HANDLE  =  0x0200,    /* from start to stop, all threads, in 1 handle */
   TF_SIMPLE  =  0x0400,    /* diagnostic output uses terse numeric formats */

   // TF_GLOBAL  =  0x0800,    /* cost across all handles */
} TimingFlags;

typedef  uint16_t  TimingFlagsValue;


// This allows ne_open() and other functions to perform arbitrary
// conversions of a given block-number (in the range [0, N+E-1]), into
// the hostname, block-subdir, etc, for the supplied path.  This is
// mainly needed with --enable-sockets.  It allows the caller to use
// its own configuration-info to control these computations within
// ne_open().

typedef  int (*SnprintfFunc)(char* dest, size_t size, const char* format, u32 block, void* state);

// SnprintfFunc ne_default_snprintf;
int ne_default_snprintf(char* dest, size_t size, const char* format, u32 block, void* state);


struct FileSysImpl; // fwd-decl  (udal.h)
struct GenericFD;   // fwd-decl  (udal.h)

struct handle {
   /* Erasure Info */
   e_status erasure_state;

   /* Read/Write Info and Structures */
   ne_mode mode;
   void *buffer;
   unsigned char *buffs[ MAXPARTS ];
   unsigned long buff_rem;
   off_t buff_offset;
   GenericFD FDArray[ MAXPARTS ];

   /* Threading fields */
   void *buffer_list[MAX_QDEPTH];
   void *block_buffs[MAX_QDEPTH][MAXPARTS];
   pthread_t threads[MAXPARTS];
   BufferQueue blocks[MAXPARTS];

   /* Per-part Info */
   //u64 csum[ MAXPARTS ];
   //unsigned long nsz[ MAXPARTS ];
   //unsigned long ncompsz[ MAXPARTS ];
   //off_t written[ MAXPARTS ];

   /* Erasure Manipulation Structures */
   unsigned char e_ready;
   unsigned char src_err_list[ MAXPARTS ];
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
   void*          printf_state;        // caller-data to be provided to <snprintf>

   /* pass-through to RDMA/sockets impl */
   SktAuth        auth;

   /* run-time dispatch of sockets versus file implementation */
   const uDAL*    impl;

   /* optional timing/benchmarking */
   TimingFlags    timing_flags;      /* initialized at build-time */
   BenchStats     stats[ MAXPARTS ]; /* ops w/in each thread */
   BenchStats     agg_stats;         /* ops across "threads", O_RDONLY */
   FastTimer      handle_timer;      /* pre-open to post-close, all threads complete */
   FastTimer      erasure_timer;
   LogHisto       erasure_h;

   char*          timing_stats;  /* ptr to block where timing data is to be copied at close */
};
typedef struct handle* ne_handle;



/* Erasure utility-functions taking a raw path argument */

// NOTE: A function named like "foo1()" is the uDAL-sensitive version of
//       the corresponding function "foo()".  Calling foo() will call
//       foo1() supplying the current-default POSIX uDAL, whereas foo1()
//       can be used by uDAL-savvy callers (like the MarFS RDMA DAL) that
//       know which uDAL they want to use.  This allows utilities written
//       for the NFS-based POSIX uDAL to continue to work over NFS in
//       production, while we validate the functioning of the RDMA uDAL.
//
//       Ultimately, this allows repos using both kinds of uDALs to
//       co-exist, and to be accessed with the same libne build.
//       Theoretically (validated on small scale in practice), it is
//       possible to access objects written with either uDAL, using either
//       uDAL.  However, it seems a big step to drop this assumption into
//       production, without first going through a phase in which old repos
//       continue to be accessed with the NFS uDAL, while new experimental
//       work can be done using the RDMA uDAL.

ne_handle ne_open1  ( SnprintfFunc func, void* state,
                      uDALType itype, SktAuth auth, TimingFlagsValue flags,
                      char *path, ne_mode mode, ... );

int       ne_delete1( SnprintfFunc func, void* state,
                      uDALType itype, SktAuth auth, TimingFlagsValue flags, 
                      char *path, int width );

e_status   ne_status1( SnprintfFunc func, void* state,
                      uDALType itype, SktAuth auth, TimingFlagsValue flags,
                      char *path );

off_t     ne_size1  ( SnprintfFunc func, void* state,
                      uDALType itype, SktAuth auth, TimingFlagsValue flags,
                      const char* path, int quorum, int max_stripe_width );


// per-block
int       ne_set_xattr1   ( const uDAL* impl, SktAuth auth,
                            const char *path, const char *xattrval, size_t len );

int       ne_get_xattr1   ( const uDAL* impl, SktAuth auth,
                            const char *path, char *xattrval, size_t len );

int       ne_delete_block1( const uDAL* impl, SktAuth auth,
                            const char *path );

int       ne_link_block1  ( const uDAL* impl, SktAuth auth,
                            const char *link_path, const char *target );


// these interfaces provide a default SnprintfFunc, which supports the
// expectations of the default MarFS NFS-based multi-component implementation
ne_handle ne_open  ( char *path, ne_mode mode, ... );
int       ne_delete( char* path, int width );
e_status   ne_status( char* path);
off_t     ne_size  ( const char* path, int quorum, int max_stripe_width );

int       ne_set_xattr   ( const char *path, const char *xattrval, size_t len );
int       ne_get_xattr   ( const char *path, char *xattrval, size_t len );
int       ne_delete_block( const char *path );
int       ne_link_block  ( const char *link_path, const char *target );




/* Erasure utility-functions taking a <handle> argument */
ssize_t   ne_read ( ne_handle handle, void       *buffer, size_t nbytes, off_t offset );
ssize_t   ne_write( ne_handle handle, const void *buffer, size_t nbytes );
int       ne_close( ne_handle handle );
int       ne_rebuild( ne_handle handle );
int       ne_noxattr_rebuild( ne_handle handle );
int       ne_flush( ne_handle handle );

#endif

