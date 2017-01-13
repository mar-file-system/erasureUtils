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
#include <infiniband/ib.h>	// AF_IB
#include <sys/uio.h>            // read(), write()
#include <unistd.h>             // read(), write()
#include <stdlib.h>             // exit()




// use 'make ... DEBUG=1' to enable the DBG() statements

#ifdef DEBUG
#  define DBG(...)   fprintf(stderr, ##__VA_ARGS__)
#else
#  define DBG(...)
#endif




#define _TEST(EXPR, TEST, PRINT, RETURN)			 \
  do {								 \
    PRINT(#EXPR "\n");						 \
    if (! ((EXPR) TEST)) {					 \
      fprintf(stderr, "%s:%d test failed: '%s': %s\n",		 \
	      __FILE__, __LINE__, #EXPR, strerror(errno));	 \
      RETURN;							 \
    }								 \
  } while(0)


// fail if expression is false
#define TRY(EXPR)           _TEST(EXPR,    , printf,          )
#define TEST(EXPR)          _TEST(EXPR,    , DBG,    return -1)
#define REQUIRE(EXPR)       _TEST(EXPR,    , DBG,    abort()  )

// fail if expression is non-zero
#define TRY_0(EXPR)         _TEST(EXPR, ==0, printf,          )
#define TEST_0(EXPR)        _TEST(EXPR, ==0, DBG,    return -1)
#define REQUIRE_0(EXPR)     _TEST(EXPR, ==0, DBG,    abort()  )

// fail if expression is <= 0
#define TRY_GT0(EXPR)       _TEST(EXPR,  >0, printf,          )
#define TEST_GT0(EXPR)      _TEST(EXPR,  >0, DBG,    return -1)
#define REQUIRE_GT0(EXPR)   _TEST(EXPR,  >0, DBG,    abort()  )




#define SOCKET_NAME_PREFIX      "socket_"
#define MAX_SOCKET_NAME_SIZE    (sizeof(SOCKET_NAME_PREFIX) + 10)

#define MAX_SOCKET              9

#define MAX_SOCKET_CONNS        256

#define FNAME_SIZE              128 /* incl final null */
#define HOST_SIZE               128 /* incl final null */
#define PORT_STR_SIZE            16 /* incl final null */

// now that we are using riomap(), these must be the same?  [for rsocket builds]
#define CLIENT_BUF_SIZE         (1024 * 1024)
#define SERVER_BUF_SIZE         (1024 * 1024)

#define XATTR_NAME_SIZE         128
#define XATTR_VALUE_SIZE        128


/* -----------------------------------
 * UNIX sockets
 * ----------------------------------- */
#ifdef UNIX_SOCKETS
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

#  define RIOMAP(...)
#  define RIOUNMAP(...)
#  define RSETSOCKOPT(...)


/* -----------------------------------
 * RDMA sockets
 * ----------------------------------- */
#elif (defined RDMA_SOCKETS)
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

#  define RIOMAP(...)           riomap(__VA_ARGS__)
#  define RIOUNMAP(...)         riounmap(__VA_ARGS__)
#  define RSETSOCKOPT(...)      rsetsockopt(__VA_ARGS__)



/* -----------------------------------
 * IP sockets (default)
 * ----------------------------------- */
#else
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

#  define RIOMAP(...)
#  define RIOUNMAP(...)
#  define RSETSOCKOPT(...)


#endif


// Unused, for now
typedef enum {
  PROT_UNIX = 1,
  PROT_IP,
  PROT_IB,
  PROT_IB_RDMA,			// default
} ProtoType;

typedef struct {
  ProtoType    prot;  // unused, for now
  char         host[HOST_SIZE];
  uint16_t     port;
  char         port_str[PORT_STR_SIZE];
  char         fname[FNAME_SIZE];
} PathSpec;


typedef enum {
  HNDL_FNAME     = 0x01,
  HNDL_SERVER_FD = 0x02,
  HNDL_RIOMAPPED = 0x04,

  HNDL_IS_SOCKET = 0x10,       // read/write-buffer also work on files
  HNDL_RIOWRITE  = 0x20,
  HNDL_DOUBLE    = 0x40,	// double-buffering

  HNDL_GET       = 0x0100,
  HNDL_PUT       = 0x0200,
  HNDL_OP_INIT   = 0x0400,
  HNDL_CLOSED    = 0x0800,
} SHFlags;



typedef struct {
  PathSpec     path_spec;
  int          open_flags;
  mode_t       open_mode;
  int          fd;
  off_t        rio_offset;
  size_t       pos;		// TBD: stream-position, to ignore redundant skt_seek()
  uint16_t     flags;		// SHFlags
} SocketHandle;


// "commands" for pseudo-packet
// just a sequence of ints
//
// NOTE: Co-maintain _command_str[], in common.c
typedef enum {
  CMD_GET   = 1,		// ignore <length>
  CMD_PUT,
  CMD_DEL,
  CMD_DATA,			// 
  CMD_ACK,			// data received (ready for riowrite)
  CMD_STAT,
  CMD_RIO_OFFSET,
  CMD_SEEK_ABS,			// <length> has position to seek to
  CMD_SEEK_FWD,
  CMD_SEEK_BACK,
  CMD_SET_XATTR,		// <length> is split into <name_len>, <value_len>
  CMD_GET_XATTR,		// ditto

  CMD_NULL,			// THIS IS ALWAYS LAST
} SocketCommand;
typedef uint32_t  SocketCommandType; // standardized for network transmission

const char* command_str(SocketCommand cmd);



// sequence of OR'able bits.
typedef enum {
  PKT_EOF =   0x01,
  PKT_ERR =   0x02,
} PacketFlags;

// These demarcate blobs of data on the socket-stream, and allow OOB commands.
typedef struct {
  uint8_t            flags;
  SocketCommandType  command;	// SocketCommand
  //  union {
  //    uint64_t  big;
  //    uint32_t  small[2];
  //  } length;
  uint64_t           length;
  // void*              buff;
} PseudoPacketHeader;

typedef struct {
  uint32_t    command;
  char        fname[FNAME_SIZE];
  uint32_t    mode;
} OpenPacketHeader;


// For now, we'll use a open/read/write/close model, because that
// will fit most easily into libne.

int           skt_open (SocketHandle* handle, const char* fname, int flags, mode_t mode);
ssize_t       skt_write(SocketHandle* handle, const void* buf, size_t count);
ssize_t       skt_read (SocketHandle* handle,       void* buf, size_t count);
off_t         skt_seek (SocketHandle* handle, off_t offset, int whence);
int           skt_close(SocketHandle* handle);

int write_pseudo_packet(int fd, SocketCommand command, size_t length, void* buff);
int read_pseudo_packet_header(int fd, PseudoPacketHeader* pkt);
int read_fname(int fd, char* fname, size_t length);


ssize_t read_buffer (int fd, char*       buf, size_t size, int is_socket);
int     write_buffer(int fd, const char* buf, size_t size, int is_socket, off_t offset);





#endif
