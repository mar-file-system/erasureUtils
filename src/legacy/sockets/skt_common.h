#ifndef SOCKET_COMMON_H
#define SOCKET_COMMON_H

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
MarFS is released under the BSD license.

MarFS was reviewed and released by LANL under Los Alamos Computer Code identifier:
LA-CC-15-039.

MarFS uses libaws4c for Amazon S3 object communication. The original version
is at https://aws.amazon.com/code/Amazon-S3/2601 and under the LGPL license.
LANL added functionality to the original work. The original work plus
LANL contributions is found at https://github.com/jti-lanl/aws4c.

GNU licenses can be found at http://www.gnu.org/licenses/.
*/


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>             // struct sockaddr_un
#include <netinet/in.h>         // struct sockaddr_in
#include <infiniband/ib.h>      // AF_IB
#include <sys/uio.h>            // read(), write()
#include <unistd.h>             // read(), write()
#include <stdlib.h>             // exit()
#include <sys/types.h>
#include <sys/stat.h>

#include "udal_config.h"
#if S3_AUTH
#  include <aws4c.h>
#endif

// we further-refine output-destinations, based on debugging level
#include "ne_logging.h"

#define FAIL_STR   "* fail: "

#if (DEBUG_SOCKETS && USE_SYSLOG)
#  include <syslog.h>
#  define neLOG(FMT,...)  SYSLOG(LOG_INFO,           FMT, ##__VA_ARGS__)
#  define neERR(FMT,...)  SYSLOG(LOG_ERR,   FAIL_STR FMT, ##__VA_ARGS__)
#  define neDBG(FMT,...)  SYSLOG(LOG_DEBUG,          FMT, ##__VA_ARGS__)

#elif (DEBUG_SOCKETS)
#  define neLOG(FMT,...)  FPRINTF(stderr,            FMT, ##__VA_ARGS__)
#  define neERR(FMT,...)  FPRINTF(stderr,   FAIL_STR FMT, ##__VA_ARGS__)
#  define neDBG(FMT,...)  FPRINTF(stderr,            FMT, ##__VA_ARGS__)

#elif (USE_SYSLOG)
#  include <syslog.h>
#  define neLOG(FMT,...)  SYSLOG(LOG_INFO,           FMT, ##__VA_ARGS__)
#  define neERR(FMT,...)
#  define neDBG(FMT,...)

#else
#  define neLOG(FMT,...)  fprintf(stdout,            FMT, ##__VA_ARGS__)
#  define neERR(FMT,...)  /* fprintf(stderr,   FAIL_STR FMT, ##__VA_ARGS__) */
#  define neDBG(FMT,...)
#endif

// always goes to stderr, regardless of DEBUG setting
#define DIAGNOSE(FMT,...)  FPRINTF(stderr,   FAIL_STR FMT, ##__VA_ARGS__)



// Callers can suppress printing of successful tests, by choice of <PRINT>
// All failures go to stderr.
#define _TEST(EXPR, TEST, PRINT, FAIL_PRINT, RETURN)                    \
   do {                                                                 \
      PRINT(#EXPR " " #TEST "  ?\n");                                   \
      if ((EXPR) TEST) {                                                \
         PRINT(#EXPR " " #TEST "\n");                                   \
      }                                                                 \
      else {                                                            \
         FAIL_PRINT(FAIL_STR #EXPR " " #TEST "%s%s\n",                  \
                    (errno ? ": " : ""),                                \
                    (errno ? strerror(errno) : ""));                    \
         RETURN;                                                        \
      }                                                                 \
   } while(0)


// print warning, if expression doesn't have expected value
#define EXPECT(EXPR)        _TEST(EXPR,    , neDBG, neDBG,   /* nothing */)
#define EXPECT_0(EXPR)      _TEST(EXPR, ==0, neDBG, neDBG,   /* nothing */)
#define EXPECT_GT0(EXPR)    _TEST(EXPR,  >0, neDBG, neDBG,   /* nothing */)
//#define EXPECT(EXPR)        _TEST(EXPR,    , neDBG, DIAGNOSE,   /* nothing */)
//#define EXPECT_0(EXPR)      _TEST(EXPR, ==0, neDBG, DIAGNOSE,   /* nothing */)
//#define EXPECT_GT0(EXPR)    _TEST(EXPR,  >0, neDBG, DIAGNOSE,   /* nothing */)

// return -1, if expr doesn't have expected value
#define NEED(EXPR)          _TEST(EXPR,    , neDBG, neDBG,   return -1)
#define NEED_0(EXPR)        _TEST(EXPR, ==0, neDBG, neDBG,   return -1)
#define NEED_GT0(EXPR)      _TEST(EXPR,  >0, neDBG, neDBG,   return -1)


// call cleanup function before exiting, if expr doesn't return expected value
// [put a "jHANDLER" invocation at the top of a function that uses jNEED() macros.]
typedef void(*jHandlerType)(void* arg);
#define jHANDLER(FN, ARG)   jHandlerType j_handler = &(FN); void* j_handler_arg = (ARG)

#define jNEED(EXPR)         _TEST(EXPR,    , neDBG, neDBG,   j_handler(j_handler_arg); return -1)
#define jNEED_0(EXPR)       _TEST(EXPR, ==0, neDBG, neDBG,   j_handler(j_handler_arg); return -1)
#define jNEED_GT0(EXPR)     _TEST(EXPR,  >0, neDBG, neDBG,   j_handler(j_handler_arg); return -1)


// abort(), if expr doesn't have expected value
#define REQUIRE(EXPR)       _TEST(EXPR,    , neDBG, DIAGNOSE,   abort()  )
#define REQUIRE_0(EXPR)     _TEST(EXPR, ==0, neDBG, DIAGNOSE,   abort()  )
#define REQUIRE_GT0(EXPR)   _TEST(EXPR,  >0, neDBG, DIAGNOSE,   abort()  )




#define SOCKET_NAME_PREFIX      "socket_"
#define MAX_SOCKET_NAME_SIZE    (sizeof(SOCKET_NAME_PREFIX) + 10)

#define MAX_SOCKET_CONNS        512  /* server-side */

#define FNAME_SIZE              512 /* incl final null */
#define HOST_SIZE               128 /* incl final null */
#define PORT_STR_SIZE            16 /* incl final null */



// now that we are using riomap(), these must be the same?  [for rsocket builds]
#ifndef SERVER_BUF_SIZE
# define SERVER_BUF_SIZE         (1024 * 1024)
#endif

#ifndef CLIENT_BUF_SIZE
# define CLIENT_BUF_SIZE         (1024 * 1024)
#endif


#define XATTR_NAME_SIZE         128
#define XATTR_VALUE_SIZE        128

#define STAT_DATA_SIZE          (13 * sizeof(size_t)) /* room enough for all 13 members */



// These represent the max delay (in sec), waiting for protocol tokens
// to/from client/server.  If any kind of socket communication is
// happening faster than that, you will not see a timeout.
//
// When debugging, we typically want to be able to step slowly through
// an exchange, without provoking a timeout.  You can accomplish this
// (setting DEBIUG_SOCKETS > 1), by configuring with
// '--enable-debug=gdb'.  Be careful, though: if the problem happens
// only because of a timeout, you'll not see it this way.  Also, note
// that when *not* debugging, DEBUG_SOCKETS is #define'd, but is 0.

// WARNING: if these values are set small (e.g. 30 sec), and there is a
//     small value (e.g. 100) for wait_usec in read/write_raw(), then the
//     computation of the total amount spent in the loops is radically
//     overestimated (i.e. SELECT() appears very innaccurate for such small
//     intervals, and the result is that e.g. clients see the server
//     spontaneously dropping connections, etc, showing as getting EOF from
//     the server.

#if (DEBUG_SOCKETS > 1)
#  define WR_TIMEOUT          10000
#  define RD_TIMEOUT          10000
#else
#  define WR_TIMEOUT             20
#  define RD_TIMEOUT             20
#endif


// timeout period, per poll  (in sec)
//
// rpoll() doesn't detect peer-HUP after rpoll() has already begun waiting.
// We must rpoll() again to see the HUP.  Having this shorter than
// RD_/WR_TIMOUT allows server-side to reclaim dropped connections more
// quickly.
#define POLL_PERIOD           2

// max number of failed polls and/or incomplete-reads/writes, in
// read_raw()/write_raw().  Intended to detect a crazy number of interrupts
// in a short time.  read/write_raw() will exit when this condition, or
// RD/WR_TIMEOUT, is reached, whichever comes first.  When the timeouts are
// long (i.e. when debugging), this should be long.
// #define MAX_POLLS           500
#define MAX_RD_POLLS           (RD_TIMEOUT * 20)
#define MAX_WR_POLLS           (WR_TIMEOUT * 20)


// max seconds server-side date string can lag behind date-string generated
// on client, for S3-authentication.  (Set negative to disable.)
// NOTE: this formulation is intended to allow more lag when debugging.
#define MAX_S3_DATE_LAG          ((WR_TIMEOUT > RD_TIMEOUT) ? WR_TIMEOUT : RD_TIMEOUT)

#define MAX_S3_DATA              1024 + FNAME_SIZE /* authentication data */

#define SKT_S3_USER              "mcadmin"  /* desired token #1 in ~/.awsAuth */


// This allows SocketHandle (which needs a reference to an AWSContext*, iff
// S3_AUTH is defined) to be used in other contexts where S3_AUTH does not
// get defined.  In other words, this typedef is agnostic about S3_AUTH.
typedef void*    SktAuth; // actually, AWSContext*



#ifdef __GNUC__
#  define likely(x)      __builtin_expect(!!(x), 1)
#  define unlikely(x)    __builtin_expect(!!(x), 0)
#else
#  define likely(x)      (x)
#  define unlikely(x)    (x)
#endif


// shorthand, to turn thread-cancelability off/on
// argument must be ENABLE or DISABLE
#define THREAD_CANCEL(ENABLE)                                           \
  do { int prev_cancel_state;                                           \
    pthread_setcancelstate(PTHREAD_CANCEL_##ENABLE, &prev_cancel_state); \
  } while (0)



/* -----------------------------------
 * RDMA sockets
 * ----------------------------------- */
#if (SOCKETS == SKT_rdma)

#  include <rdma/rsocket.h>
/// #  define SKT_FAMILY   AF_INET
typedef struct rdma_addrinfo           SockAddr;

#  define SOCKET(...)           rsocket(__VA_ARGS__)
#  define SETSOCKOPT(...)       rsetsockopt(__VA_ARGS__)
#  define BIND(...)             rbind(__VA_ARGS__)
#  define LISTEN(...)           rlisten(__VA_ARGS__)
#  define ACCEPT(...)           raccept(__VA_ARGS__)
#  define CONNECT(...)          rconnect(__VA_ARGS__)
#  define CLOSE(...)            rclose(__VA_ARGS__)
#  define WRITE(...)            rwrite(__VA_ARGS__)
#  define READ(...)             rread(__VA_ARGS__)
#  define SEND(...)             rsend(__VA_ARGS__)
#  define RECV(...)             rrecv(__VA_ARGS__)
#  define SHUTDOWN(...)         rshutdown(__VA_ARGS__)
#  define SELECT(...)           rselect(__VA_ARGS__)
#  define POLL(...)             rpoll(__VA_ARGS__)

#  define RIOMAP(...)           riomap(__VA_ARGS__)
#  define RIOUNMAP(...)         riounmap(__VA_ARGS__)
#  define RSETSOCKOPT(...)      rsetsockopt(__VA_ARGS__)


// These LOCK/UNLOCKs should be removed, after our patch (5ac0576d51dd) to
// librdmacm is installed.  This is a work-around for unpatched systems.

extern pthread_mutex_t rdma_bug_lock;

#  define LOCK(LOCK)            pthread_mutex_lock(LOCK);
#  define UNLOCK(LOCK)          pthread_mutex_unlock(LOCK);

#  define BUG_LOCK()                               \
   while(1) {                                      \
      THREAD_CANCEL(DISABLE);                      \
      if (! pthread_mutex_trylock(&rdma_bug_lock)) \
         break;                                    \
      THREAD_CANCEL(ENABLE);                       \
      sched_yield();                               \
   }

#  define BUG_UNLOCK()                             \
   pthread_mutex_unlock(&rdma_bug_lock);           \
   THREAD_CANCEL(ENABLE);



/* -----------------------------------
 * IP sockets
 * ----------------------------------- */
#elif (SOCKETS == SKT_ip)

#  define SKT_FAMILY   AF_INET
typedef struct sockaddr_in                   SockAddr;

#  define SOCKET(...)           socket(__VA_ARGS__)
#  define SETSOCKOPT(...)       setsockopt(__VA_ARGS__)
#  define BIND(...)             bind(__VA_ARGS__)
#  define LISTEN(...)           listen(__VA_ARGS__)
#  define ACCEPT(...)           accept(__VA_ARGS__)
#  define CONNECT(...)          connect(__VA_ARGS__)
#  define CLOSE(...)            close(__VA_ARGS__)
#  define WRITE(...)            write(__VA_ARGS__)
#  define READ(...)             read(__VA_ARGS__)
#  define SEND(...)             send(__VA_ARGS__)
#  define RECV(...)             recv(__VA_ARGS__)
#  define SHUTDOWN(...)         shutdown(__VA_ARGS__)
#  define SELECT(...)           select(__VA_ARGS__)
#  define POLL(...)             poll(__VA_ARGS__)

#  define RIOMAP(...)
#  define RIOUNMAP(...)
#  define RSETSOCKOPT(...)

#  define LOCK(LOCK)
#  define UNLOCK(LOCK)

#  define BUG_LOCK()
#  define BUG_UNLOCK(LOCK)


/* -----------------------------------
 * UNIX sockets
 * ----------------------------------- */
#elif (SOCKETS == SKT_unix)

#  define SKT_FAMILY   AF_UNIX
typedef struct sockaddr_un                   SockAddr;

#  define SOCKET(...)           socket(__VA_ARGS__)
#  define SETSOCKOPT(...)       setsockopt(__VA_ARGS__)
#  define BIND(...)             bind(__VA_ARGS__)
#  define LISTEN(...)           listen(__VA_ARGS__)
#  define ACCEPT(...)           accept(__VA_ARGS__)
#  define CONNECT(...)          connect(__VA_ARGS__)
#  define CLOSE(...)            close(__VA_ARGS__)
#  define WRITE(...)            write(__VA_ARGS__)
#  define READ(...)             read(__VA_ARGS__)
#  define SEND(...)             send(__VA_ARGS__)
#  define RECV(...)             recv(__VA_ARGS__)
#  define SHUTDOWN(...)         shutdown(__VA_ARGS__)
#  define SELECT(...)           select(__VA_ARGS__)
#  define POLL(...)             poll(__VA_ARGS__)

#  define RIOMAP(...)
#  define RIOUNMAP(...)
#  define RSETSOCKOPT(...)

#  define LOCK(LOCK)
#  define UNLOCK(LOCK)

#  define BUG_LOCK()
#  define BUG_UNLOCK(LOCK)


#else
#  error "skt_common.h requires SOCKETS to select socket-type.  This should agree with the value used when building libne"
#endif




// Unused, for now
typedef enum {
  PROT_UNIX = 1,
  PROT_IP,
  PROT_IB,
  PROT_IB_RDMA,                 // default
} ProtoType;

typedef struct {
  ProtoType    prot;  // unused, for now
  char         host[HOST_SIZE];
  uint16_t     port;
  char         port_str[PORT_STR_SIZE];
  char         fname[FNAME_SIZE];
} PathSpec;


typedef enum {
  HNDL_FNAME       = 0x0001,
  HNDL_CONNECTED   = 0x0002,
  HNDL_RIOMAPPED   = 0x0004,

  HNDL_IS_SOCKET   = 0x0010,    // read/write-buffer also work on files
  HNDL_RIOWRITE    = 0x0020,
  HNDL_DOUBLE      = 0x0040,    // double-buffering (currently unused)

  HNDL_GET         = 0x0100,
  HNDL_PUT         = 0x0200,
  HNDL_OP_INIT     = 0x0400,
  // HNDL_CLOSED      = 0x0800,

  HNDL_SEEK_SET    = 0x1000,    // skt_write() found SEEK (see SocketHandle.seek_pos)
  HNDL_PEER_EOF    = 0x2000,    // skt_write() found ACK 0
  HNDL_SENT_DATA0  = 0x4000,    // skt_write() sent DATA0 (see copy_file_to_socket())
  HNDL_FSYNC       = 0x8000,    // skt_read() found FSYNC

  // currently unused for other purposes
  HNDL_DBG1        = 0x0008,
  HNDL_DBG2        = 0x0080,
  HNDL_DBG3        = 0x0800,
} SHFlags;


typedef enum {
   SKT_F_SETAUTH   = 1          // install credentials on opened socket-handle
} SocketFcntlCmd;



// ne_read() now has a queue of read-buffers, like ne_write().  Every call
// to ne_read() with a new buffer provokes a new RIO unmap/map, via
// skt_read() -> read_init() -> riomap_reader().  It seems that maybe the
// unmapping is not working, or something, because after 255 of these
// remaps, the sending of RIOMAP_OFFSET to the peer simply doesn't get
// through.  The peer is polling but nothing arrives.
//
// In order to handle a large number of remappings across what is actually
// a limited number of buffers, we will try the following.  Allow, an array
// of known appings to exist, and only unmap one of those (the oldest) when
// we have used them all up.  In the case described above, there are just
// MAX_QDEPTH buffers being provided over and over.
typedef struct {
   off_t              rio_offset;  // reader sends mapping to writer, for riowrite()
   char*              rio_buf;     // reader saves riomapp'ed address, for riounmap()
   size_t             rio_size;    // reader saves riomapp'ed size, for riounmap()
} RiomapSpec;

// For now, MAX_QDEPTH (in erasure.h) should always be the same as this.
// TBD: Fix things so we can just incude erasure, and define them equivalent
#define MAX_RIOMAPS   2   /* should be >= MAX_QDEPTH, from erasure.h ? */

// per-connection state
typedef struct {
   PathSpec           path_spec;   // host,port,path parsed from URL
   int                open_flags;  // skt_open()
   mode_t             open_mode;   // skt_open()
   int                peer_fd;     // fd for comms with socket-peer
   RiomapSpec         riomap_spec[MAX_RIOMAPS];
   int                riomap_pos;  // riomap_spec[] index for next mapping
   int                riomap_count;
   volatile size_t    stream_pos;  // ignore redundant skt_seek(), support reaper
   ssize_t            seek_pos;    // ignore, unless HNDL_SEEK_ABS
   SHFlags            flags;
   SktAuth            aws_ctx;     // S3_AUTH credentials (e.g. cached by DAL at init-time)
} SocketHandle;




// "commands" for pseudo-packet
// just a sequence of ints
//
// *** NOTE: Co-maintain _command_str[], in skt_common.c
typedef enum {
  CMD_GET   = 1,                // ignore <size>
  CMD_PUT,
  CMD_DEL,
  CMD_STAT,
  CMD_FSYNC,
  CMD_SEEK_SET,                 // <size> has position to seek to
  CMD_SET_XATTR,                // <size> is split into <name_len>, <value_len>
  CMD_GET_XATTR,                // ditto
  CMD_CHOWN,
  CMD_RENAME,
  CMD_UNLINK,

  CMD_TEST,                     // iff built with --enable-test-api

  CMD_S3_AUTH,                  // client submits S3 signature, etc
  CMD_RIO_OFFSET,               // reader sends riomapped offset (for riowrite)
  CMD_DATA,                     // amount of data sent (via riowrite)
  CMD_ACK,                      // got data (ready for riowrite), <size> has read-size
  CMD_RETURN,                   // command received (<size> has ack'ed cmd)
  CMD_NOP,                      // graceful server-thread exit (see skt_close())

  CMD_NULL,                     // THIS IS ALWAYS LAST
} SocketCommand;
typedef uint32_t  SocketCommandType; // standardized for network transmission

const char* command_str(SocketCommand cmd);



// sequence of OR'able bits.
typedef enum {
  PKT_EOF =   0x01,
  PKT_ERR =   0x02,
} PacketFlags;

// These are blobs of control-data on the socket-stream, and allow OOB commands.
// The buf can be reliably transmitted in a single send.
// The sent buf contains a uint64_t, followed by a uint32_t, and they
// are received such that the 64-bit int is aligned to a 64-bit boundary.
typedef struct {
  uint8_t            flags;
   union {
      uint64_t       big[2];
      uint32_t       small[4];  // 4th value is ignored (see HDR_BUFSIZE)
   } buf;                       // (transmitted as a unit)
} PseudoPacketHeader;

#define HDR_SIZE(HDR)   (HDR)->buf.big[0]
#define HDR_CMD(HDR)    (HDR)->buf.small[2]
#define HDR_BUF(HDR)    &(HDR)->buf
#define HDR_BUFSIZE     (sizeof(uint64_t) + sizeof(uint32_t))



typedef struct {
  uint32_t    command;
  char        fname[FNAME_SIZE];
  uint32_t    mode;
} OpenPacketHeader;




// --- network-byte-order conversions

// These have to be macros, because sizeof(VAR) varies with VAR
#define _SEND_VALUE(NEED_MACRO, BUF, VAR)                               \
   do {                                                                 \
      NEED_MACRO( hton_generic((BUF), (char*)&(VAR), sizeof(VAR)) == 0 ); \
      (BUF)    += sizeof(VAR);                                          \
   } while (0)

#define _SEND_VALUE_SAFE(NEED_MACRO, BUF, VAR, REMAIN)                  \
   do {                                                                 \
      NEED_MACRO( (sizeof(VAR) <= (REMAIN)) );                          \
      _SEND_VALUE(NEED_MACRO, BUF, VAR);                                \
      (REMAIN) -= sizeof(VAR);                                          \
   } while (0)


#define  SEND_VALUE(BUF, VAR)                _SEND_VALUE( NEED, BUF, VAR)
#define jSEND_VALUE(BUF, VAR)                _SEND_VALUE(jNEED, BUF, VAR)

#define  SEND_VALUE_SAFE(BUF, VAR, REMAIN)   _SEND_VALUE_SAFE(NEED, BUF, VAR, REMAIN)




// // These need char**, and size_t*, so we can side-effect caller's variables
// inline void _send_string(char** dest, char* src, size_t len) {
//    strncpy(*dest, src, len);
//    (*dest)[len] = 0;
//    *dest += len +1;
// }
// inline int _send_string_safe(char** dest, char* src, size_t len, size_t* remain) {
//    SEND_VALUE_SAFE(*dest, len, *remain); // send the length
//    NEED( len <= (REMAIN) );
//    _send_string(dest, src, len);
//    *remain -= len +1;
//    return 0;
// }
// 
// #define  SEND_STRING_SAFE(BUF, STR, REMAIN)                           \
//    NEED0( _send_string_safe(&(BUF), (STR), strlen(STR), &(BUF_REMAIN)) )

// send size too, because we have to compute it anyhow, and
// it saves server having to do it again to do its own checking.
#define  SEND_STRING_SAFE(BUF, STR, LEN, REMAIN)          \
   do {                                                   \
      NEED( (LEN) < (REMAIN));                            \
      strncpy((BUF), (STR), (LEN));                       \
      (BUF)[LEN] = 0;                                     \
      (BUF)      += (LEN) +1;                             \
      (REMAIN)   -= (LEN) +1;                             \
   } while(0)






#define _RECV_VALUE(NEED_MACRO, VAR, BUF)                            \
   do {                                                              \
      NEED_MACRO( ntoh_generic((char*)&(VAR), (BUF), sizeof(VAR)) == 0 ); \
      (BUF)+=sizeof(VAR);                                            \
   } while (0)

#define  RECV_VALUE(VAR, BUF) _RECV_VALUE( NEED, VAR, BUF) 
#define jRECV_VALUE(VAR, BUF) _RECV_VALUE(jNEED, VAR, BUF) 



#define _RECV_VALUE_SAFE(NEED_MACRO, VAR, BUF, REMAIN)                  \
   do {                                                                 \
      NEED_MACRO( (sizeof(VAR) <= (REMAIN)) );                          \
      _RECV_VALUE(NEED_MACRO, VAR, BUF);                                \
      (REMAIN) -= sizeof(VAR);                                          \
   } while (0)

#define  RECV_VALUE_SAFE(VAR, BUF, REMAIN)   _RECV_VALUE_SAFE(NEED, VAR, BUF, REMAIN)







uint64_t hton64(uint64_t ll);
uint64_t ntoh64(uint64_t ll);

int hton_generic(char* dst, char* src, size_t src_size);
int ntoh_generic(char* dst, char* src, size_t src_size);



// --- low-level tools
int      read_raw(int fd, char* buf, size_t size, int peek_p);
int      write_raw(int fd, char* buf, size_t size);

int      write_pseudo_packet(int fd, SocketCommand command, size_t size, void* buff);
int      read_pseudo_packet_header(int fd, PseudoPacketHeader* hdr, int peek);

int      read_init (SocketHandle* handle, SocketCommand cmd, char* buf, size_t size);
int      write_init(SocketHandle* handle, SocketCommand cmd);

ssize_t  read_buffer (int fd, char*       buf, size_t size, int is_socket);
int      write_buffer(int fd, const char* buf, size_t size, int is_socket, off_t offset);

ssize_t  copy_file_to_socket(int fd, SocketHandle* handle, char* buf, size_t size);
ssize_t  copy_socket_to_file(SocketHandle* handle, int fd, char* buf, size_t size);

void     shut_down_handle(SocketHandle* handle);
void     jshut_down_handle(void* handle);
void     jskt_close(void* handle);


// --- build-agnostic functions for initializing S3-credentials
//     (i.e. these can always be safely called, regardless of S3_AUTH)
//
int  skt_auth_init(const char* user,  SktAuth* auth);      // typically once per program
int  skt_auth_install(SocketHandle* handle, SktAuth auth); // after skt_open()
void skt_auth_free(SktAuth auth);                          // no future calls to skt_auth_install()


// --- For now, we'll use a open/read/write/close model, because that
//     will fit most easily into libne.

int           skt_open     (SocketHandle* handle, const char* fname, int flags, ...);

ssize_t       skt_write    (SocketHandle* handle, const void* buf, size_t count);
ssize_t       skt_write_all(SocketHandle* handle, const void* buf, size_t count);

ssize_t       skt_read     (SocketHandle* handle,       void* buf, size_t count);
ssize_t       skt_read_all (SocketHandle* handle,       void* buf, size_t count);

off_t         skt_lseek    (SocketHandle* handle, off_t offset, int whence);
int           skt_fsetxattr(SocketHandle* handle, const char* name, const void* value, size_t size, int flags);
int           skt_fsync    (SocketHandle* handle);  // no-op, for now
int           skt_close    (SocketHandle* handle);  // also does fsync()


// --- install an AWSContext with awsKey into a SocketHandle (after
//     skt_open(), but before any data or comms have been sent), to support
//     S3-based authentication.
int           skt_fcntl(SocketHandle* handle, SocketFcntlCmd cmd, ...);

// --- these all create ad hoc SocketHandles, so there is an aws_ctx in
//     case we are built with authentication enabled.  Arg is ignored in
//     builds with authentication disabled.  We use void*, so erasureLib/*
//     doesn't have to know about AWSContext.
int           skt_unlink(const void* aws_ctx, const char* service_path);
int           skt_chown (const void* aws_ctx, const char* service_path, uid_t uid, gid_t gid);
int           skt_rename(const void* aws_ctx, const char* service_path, const char* new_fname);
int           skt_stat  (const void* aws_ctx, const char* service_path, struct stat* st);

// libne uses fsetxattr() [taking fd] for sets, but getxattr() [taking path] for gets
int           skt_getxattr(const void* aws_auth, const char* service_path, const char* name, void* value, size_t size);





#endif
