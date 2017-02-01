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



#include <stdio.h>
#include <limits.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>

#include "skt_common.h"





// This is used for abnormal exits on client or server.
// (e.g., server-thread exits or is cancelled)
//
void
shut_down_handle(SocketHandle* handle) {

#if UNIX_SOCKETS
  if (handle->flags & HNDL_FNAME) {
    DBG("shut_down_handle: unlinking '%s'\n", handle->fname);
    unlink(handle->fname);
  }
#endif


  if (handle->flags & HNDL_CONNECTED) {
    // Without doing our own riounmap, we get a segfault in the
    // CLOSE() below, when rclose() calls riounmap() itself.
    //
    // It's okay if handle->rio_buf only has local scope, in server_put(),
    // we're just unmapping the address here, not using it.
    //
    if (handle->flags & HNDL_RIOMAPPED) {
      DBG("shut_down_handle(%d): riounmap'ing\n", handle->peer_fd);
      RIOUNMAP(handle->peer_fd, handle->rio_buf, handle->rio_size);
      handle->flags &= ~HNDL_RIOMAPPED;
    }

    DBG("shut_down_handle(%d): shutdown\n", handle->peer_fd);
    SHUTDOWN(handle->peer_fd, SHUT_RDWR);

    DBG("shut_down_handle(%d): close\n", handle->peer_fd);
    CLOSE(handle->peer_fd);
    handle->flags &= ~HNDL_CONNECTED;
  }

  DBG("shut_down_handle(%d): done\n", handle->peer_fd);
}



// Issue repeated reads until we've gotten <size> bytes, or error, or
// EOF.  Return negative for error.  Otherwise, return the total
// number of bytes that could be read.  If return-value is positive,
// but less than <size>, there must've been an EOF.

ssize_t read_buffer(int fd, char* buf, size_t size, int is_socket) {
  DBG("read_buffer(%d, 0x%llx, %lld, %d)\n", fd, buf, size, is_socket);


#ifdef USE_RIOWRITE
  // If we would be reading from an rsocket where the writer is using
  // riowrite(), then we won't see anything in the fd; RDMA is
  // transparently moving data directly into our buffer.  In that
  // case, the writer will send us a DATA pseudo-packet, to indicate
  // when the RDMA is complete.

  if (is_socket) {
    PseudoPacketHeader header;
    NEED_0( read_pseudo_packet_header(fd, &header) );
    if (header.command != CMD_DATA) {
      fprintf(stderr, "unexpected pseudo-packet: %s\n", command_str(header.command));
      return -1;
    }
    else if (header.flags & PKT_EOF)
      return 0;

    return header.size;
  }
#endif

  char*   read_ptr    = buf;
  size_t  read_total  = 0;
  size_t  read_remain = size;
  int     eof         = 0;

  while (read_remain && !eof) {

    ssize_t read_count;
    if (is_socket)
      read_count = READ(fd, read_ptr, read_remain);
    else
      read_count = read(fd, read_ptr, read_remain);

    DBG("read_count(1): %lld\n", read_count);

    if (read_count < 0) {
      DBG("read error: %s\n", strerror(errno));
      return read_count;
    }
    else if (read_count == 0) {
      eof = 1;
      DBG("read EOF\n");
    }

    read_total  += read_count;
    read_ptr    += read_count;
    read_remain -= read_count;
  }
  DBG("read_total: %lld\n", read_total);

  // // wouldn't want to do this with large reads ...
  // DBG("contents: %s\n", read_buf);

  return read_total;
}




// write bytes until <size>, or error.
// Return 0 for success, negative for error.
//
// WARNING: Do not use this to jam arbitrary amounts of data into a
//    socket that might use RIOWRITE.  write_buffer() can be used to
//    assure that the reader's request-amount is fully written, but
//    not to assure that the writer's buffer is fully written.  See
//    skt_write() for better understanding.
//
// NOTE: If <size>==0, the server will treat it as EOF.
//
int write_buffer(int fd, const char* buf, size_t size, int is_socket, off_t offset) {
  DBG("write_buffer(%d, 0x%llx, %lld, %d, 0x%llx)\n", fd, buf, size, is_socket, offset);

  const char*  write_ptr     = buf;
  size_t       write_remain  = size;
  size_t       write_total   = 0;
  while (write_remain) {

    ssize_t write_count;
    if (is_socket) {
#ifdef USE_RIOWRITE
      write_count = riowrite(fd, write_ptr, write_remain, offset + write_total, 0);
#else
      write_count = WRITE(fd, write_ptr, write_remain);
#endif
    }
    else
      write_count = write(fd, write_ptr, write_remain);

    DBG("write_count: %lld\n", write_count);
    if (write_count < 0) {
      fprintf(stderr, "write of %llu bytes failed, after writing %llu: %s\n",
              write_remain, write_total, strerror(errno));
      return -1;
    }
    write_total   += write_count;
    write_ptr     += write_count;
    write_remain  -= write_count;

#if 0
    if (errno == ENOSPC)
      DBG("buffer is full.  ignoring.\n");
    else if (errno == EPIPE) {
      DBG("client disconnected?\n");
      return -1;
      break;
    }
    else if (errno) {
      perror("write failed\n");
      return -1;
      break;
    }
#endif
  }
  DBG("write_total: %lld\n", write_total);


#ifdef USE_RIOWRITE
  if (is_socket) {
    NEED_0( write_pseudo_packet(fd, CMD_DATA, size, NULL) );
  }
#endif

  return 0;
}







// for small socket-reads that don't use RDMA
ssize_t read_raw(int fd, char* buf, size_t size) {
  DBG("read_raw(%d, 0x%llx, %lld)\n", fd, buf, size);
  return RECV(fd, buf, size, MSG_WAITALL);
}
  
// for small socket-writes that don't use RDMA
int write_raw(int fd, char* buf, size_t size) {
  DBG("write_raw(%d, 0x%llx, %lld)\n", fd, buf, size);

  ssize_t write_count = WRITE(fd, buf, size);
  if (write_count != size) {
    fprintf(stderr, "failed to write %lld bytes\n", size);
    return -1;
  }
  return 0;
}





// [lifted from marfs_common.c, with name changes to avoid link-time conflicts
// when both impls are present.]
//
// htonll() / ntohll() are not provided in our environment.  <endian.h> or
// <byteswap.h> make things easier, but these are non-standard.  Also, we're
// compiled with -Wall, so we avoid pointer-aliasing that makes gcc whine.
//
// TBD: Find the appropriate #ifdefs to make these definitions go away on
//     systems that already provide them.


// see http://esr.ibiblio.org/?p=5095
#define IS_LITTLE_ENDIAN (*(uint16_t *)"\0\xff" >= 0x100)

uint64_t hton64(uint64_t ll) {
  if (IS_LITTLE_ENDIAN) {
    uint64_t result;
    char* sptr = ((char*)&ll) +7; // gcc doesn't mind char* aliases
    char* dptr = (char*)&result; // gcc doesn't mind char* aliases
    int i;
    for (i=0; i<8; ++i)
      *dptr++ = *sptr--;
    return result;
  }
  else
    return ll;
}

uint64_t ntoh64(uint64_t ll) {
  if (IS_LITTLE_ENDIAN) {
    uint64_t result;
    char* sptr = ((char*)&ll) +7; // gcc doesn't mind char* aliases
    char* dptr = (char*)&result; // gcc doesn't mind char* aliases
    int i;
    for (i=0; i<8; ++i)
      *dptr++ = *sptr--;
    return result;
  }
  else
    return ll;
}

// TO STRING
// perform a conversion (e.g. htons()), while moving data of type TYPE from
// SOURCE (variable) to DEST (string).  DEST is updated to a point just
// after the copied data.
#define COPY_OUT(DEST, SOURCE, TYPE, CONVERSION_FN)  \
  {  TYPE temp = CONVERSION_FN (SOURCE);            \
  memcpy(DEST, (char*)&temp, sizeof(TYPE));      \
  DEST += sizeof(TYPE);                          \
  }

// FROM STRING
// perform a conversion (e.g. ntohs()), while moving data of type TYPE from
// SOURCE (string) to DEST (variable).  SOURCE is updated to a point just
// after the used data.
#define COPY_IN(DEST, SOURCE, TYPE, CONVERSION_FN)  \
  {  TYPE temp;                                    \
  memcpy((char*)&temp, SOURCE, sizeof(TYPE));   \
  DEST = CONVERSION_FN( temp );                 \
  SOURCE += sizeof(TYPE);                       \
  }


// *** co-maintain SocketCommand, in skt_common.h
const char* _command_str[] = {
  "unknown_command",
  "GET",
  "PUT",
  "DEL",
  "DATA",
  "ACK",
  "STAT",
  "RIO_OFFSET",
  "SEEK_ABS",
  "SEEK_FWD",
  "SEEK_BACK",
  "SET_XATTR",
  "GET_XATTR",
  "CHOWN",
  "RENAME",
  "NULL"
};
const char* command_str(SocketCommand command) {
  if (command > CMD_NULL)
    command = 0;
  return _command_str[command];
}


// for now, this is only used by client
int write_pseudo_packet(int fd, SocketCommand command, size_t size, void* buf) {
  ssize_t write_count;

  // --- write <command>
  DBG("-> command: %s\n", command_str(command));
  uint32_t cmd = htonl(command);
  NEED_0( write_raw(fd, (char*)&cmd, sizeof(cmd)) );

  // --- write <size>
  DBG("-> size:  %llu\n", size);
  uint64_t sz = hton64(size);
  NEED_0( write_raw(fd, (char*)&sz, sizeof(sz)) );

  // --- maybe write <buf>
  if (buf) {
    DBG("-> buf:     0x%08x\n", (size_t)buf);
    NEED_0( write_raw(fd, (char*)buf, size) );
  }

  return 0;
}

// for now, this is only used by server
int read_pseudo_packet_header(int fd, PseudoPacketHeader* hdr) {
  ssize_t read_count;
  memset(hdr, 0, sizeof(PseudoPacketHeader));

  // --- read <command>
  uint32_t cmd;
  read_count = read_raw(fd, (char*)&cmd, sizeof(cmd));
  if (! read_count) {
    hdr->flags |= PKT_EOF;
    DBG("EOF\n");
    return -1;
  }
  else if (read_count != sizeof(cmd)) {
    DBG("read err %lld\n", read_count);
    hdr->flags |= PKT_ERR;
    return -1;
  }
  hdr->command = ntohl(cmd);
  DBG("<- command: %s\n", command_str(hdr->command));


  // --- read <size>
  uint64_t sz;
  read_count = read_raw(fd, (char*)&sz, sizeof(sz));
  if (! read_count) {
    hdr->flags |= (PKT_EOF & PKT_ERR);
    DBG("EOF\n");
    return -1;
  }
  else if (read_count != sizeof(sz)) {
    DBG("read err %lld\n", read_count);
    hdr->flags |= PKT_ERR;
    return -1;
  }
  hdr->size = ntoh64(sz);
  DBG("<- size:  %llu\n", hdr->size);

  return 0;
}





// paths to the server can be specified as  host:port/path/to/file
// eventually, we'll allow   prot://host:port/path/to/file
//
// <service_path>   unparsed server-spec
// <spec>           parsed components of <service_path>
//
// Shoulda just used sscanf.  Chris got me thinking about maximizing
// parsing efficiency, but that was a different context.
//
int parse_service_path(PathSpec* spec, const char* service_path) {

  // --- parse <host>
  const char*  ptr    = service_path;
  size_t       length = strcspn(ptr, ":");

  if (! ptr[length]) {
    fprintf(stderr, "couldn't find port in '%s'\n", ptr);
    return -1;
  }
  else if (length >= HOST_SIZE) {
    fprintf(stderr, "host token-length (plus NULL) %u exceeds max %u in '%s'\n",
            length +1, HOST_SIZE, service_path);
    return -1;
  }
  else if (! strcmp(ptr + length, "://")) {
    fprintf(stderr, "protocol-specs not yet supported, for '%s'\n",
            service_path);
    return -1;
  }
  strncpy(spec->host, ptr, length);
  spec->host[length] = 0;


  // --- parse <port> (string)
  ptr += length +1;             // skip over ':'
  length = strcspn(ptr, "/");

  if (! ptr[length]) {
    fprintf(stderr, "couldn't find file-path in '%s'\n", ptr);
    return -1;
  }
  else if (length >= PORT_STR_SIZE) {
    fprintf(stderr, "port-token length (plus NULL) %u exceeds max %u in '%s'\n",
            length +1, PORT_STR_SIZE, service_path);
    return -1;
  }
  strncpy(spec->port_str, ptr, length);
  spec->port_str[length] = 0;

  // --- parse <port> (value)
  errno = 0;
  unsigned long  port = strtoul(ptr, NULL, 10);
  if (errno) {
    fprintf(stderr, "couldn't read port from '%s': %s", ptr, strerror(errno));
    return -1;
  }
  if (port >> 16) {
    fprintf(stderr, "port %lu is greater than %u\n", port, ((uint32_t)1 << 16) -1);
    return -1;
  }
  spec->port = port;


  // --- parse file-path
  ptr += length;                // don't skip over '/'
  length = strlen(ptr);
  if (! length) {
    fprintf(stderr, "couldn't find file-component in '%s'\n", service_path);
    return -1;
  }
  else if (length >= FNAME_SIZE) {
    fprintf(stderr, "file-token length (plus NULL) %u exceeds max %u in '%s'\n",
            length +1, FNAME_SIZE, ptr);
    return -1;
  }
  strncpy(spec->fname, ptr, length);
  spec->fname[length] = 0;

  return 0;
}



// client-side PUT, or server-side GET
//
// <fd> should already be opened for read (unless SKIP_FILE_READS)
// 
// <handle> should already be opened for writing (e.g. with skt_open() in client,
//      or fake_open() on server.
//
ssize_t copy_file_to_socket(int fd, SocketHandle* handle, char* buf, size_t size) {

#ifdef SKIP_FILE_READS
  // This allows cutting out the performance cost of doing file reads
  size_t iters = SKIP_FILE_READS; // we will write (SKIP_FILE_READ * <size>) bytes

  // initialize once, to allow diagnosis of results?
  memset(buf, 1, size);
#endif

  size_t bytes_moved = 0;       /* total */
  int    eof         = 0;
  int    err         = 0;

  while (!eof && !err) {

    // --- read from file (unless file-reads are suppressed)
#ifdef SKIP_FILE_READS
    // don't waste time reading.  Just send a raw buffer.
    ssize_t read_count  = size;

    if (unlikely(iters-- <= 0)) {
      DBG("fake EOF\n");
      eof = 1;
      read_count  = 0;
      break;
    }
    DBG("%d: fake read: %lld\n", iters, read_count);

#else
    // read data up to <size>, or EOF
    ssize_t read_count = read_buffer(fd, buf, size, 0);
    DBG("read_count: %lld\n", read_count);
    NEED( read_count >= 0 );

    if (read_count == 0) {
      DBG("read EOF\n");
      eof = 1;
      break;
    }
#endif

    // --- copy all of buffer to socket
    //    Do not use write_buffer(handle->peer_fd, ... )
    size_t remain = read_count;
    size_t copied = 0;
    while (remain) {
      ssize_t write_count = skt_write(handle, buf+copied, remain);
      NEED( write_count >= 0 ); // spin forever if server's FS is wedged?
      remain -= write_count;
      copied += write_count;
    }

    // entire read-buffer was moved
    bytes_moved += read_count;
  }
  DBG("copy-loop done  (%llu bytes).\n", bytes_moved);


  return bytes_moved;
}





// client-side GET, or server-side PUT
//
// <fd> should already be opened for writing (unless SKIP_FILE_WRITES)
// 
// <handle> should already be opened for writing (e.g. with skt_open() in client,
//      or fake_open() on server.
//
ssize_t copy_socket_to_file(SocketHandle* handle, int fd, char* buf, size_t size) {

  size_t bytes_moved = 0;       /* total */
  int    eof         = 0;
  int    err         = 0;

  while (!eof && !err) {

    // --- read from socket, up to <size>, or EOF
    ssize_t read_count = skt_read(handle, buf, size);
    DBG("read_count: %lld\n", read_count);
    NEED( read_count >= 0 );

    if (read_count == 0) {
      DBG("read EOF\n");
      eof = 1;
      break;
    }


    // --- copy all of buffer to file (unless file-writes are suppressed)
#ifdef SKIP_FILE_WRITES
    // don't waste time writing to file
    DBG("fake write: %lld\n", read_count);
#else
    // copy all of buffer to file
    NEED_0( write_buffer(fd, buf, read_count, 0, 0) );
    DBG("copied out\n");
#endif


    bytes_moved += read_count;
  }
  DBG("copy-loop done  (%llu bytes).\n", bytes_moved);

  return bytes_moved;
}













// ---------------------------------------------------------------------------
// client interface
// ---------------------------------------------------------------------------


#define NO_IMPL()                                               \
  fprintf(stderr, "%s not implemented\n", __FUNCTION__);        \
  abort()





// .................................................................
// OPEN
//
// Return -1 for failures, to match behavior of open(2).
// Like open(2), we allow an optional <mode> argument:
//
//   open(SocketHandle* handle, const char* svc_path, int flags)
//   open(SocketHandle* handle, const char* svc_path, int flags, mode_t mode)
//
// <mode> is used iff <flags> includes O_CREAT
//
// NOTE: The server_thread, dispatched as a result of skt_open(), will
//     not actually presume what operation is being performed, until
//     the respective skt_read() or skt_write() call.  Conveniently,
//     that means we can also use this connection to perform other
//     operations (e.g. SETXATTR, CHOWN, etc).  In these cases, the
//     open flags are ignored.
//
// TBD: Set errcode "appropriately".
// ...........................................................................

int  skt_open (SocketHandle* handle, const char* service_path, int flags, ...) {
  DBG("skt_open(0x%llx, '%s', %x, ...)\n", (size_t)handle, service_path, flags);

  if (handle->flags && (! (handle->flags & HNDL_CLOSED))) {
    fprintf(stderr, "attempt to open handle that is not closed\n");
    return -1;
  }
  memset(handle, 0, sizeof(SocketHandle));

  mode_t mode = 0;
  if (flags & O_CREAT) {
   va_list ap;
   va_start( ap, flags );
   mode = va_arg( ap, int );    /* compiler can't handle "mode_t"? */
   va_end( ap );
  }

  // shorthand
  PathSpec* spec = &handle->path_spec;
  NEED_0( parse_service_path(spec, service_path) );

  handle->open_flags = flags;
  handle->open_mode  = mode;

  // RD/WR with RDMA would require riomaps on both ends, or else
  // two different channels, each with a single riomap.
  if (flags & (O_RDWR)) {
    errno = ENOTSUP;            // TBD?
    return -1;
  }
  else if (flags & O_WRONLY)
    handle->flags |= HNDL_PUT;
  else
    handle->flags |= HNDL_GET;



#ifdef UNIX_SOCKETS
  SockAddr          s_addr;
  struct sockaddr*  s_addr_ptr = (struct sockaddr*)&s_addr;
  socklen_t         s_addr_len = sizeof(SockAddr);

  // initialize the sockaddr structs
  memset(&s_addr, 0, s_addr_len);

  //  (void)unlink(socket_name);
  strcpy(s_addr.sun_path, socket_name);
  s_addr.sun_family = AF_UNIX;


#elif (defined RDMA_SOCKETS)
  struct rdma_addrinfo  hints;
  struct rdma_addrinfo* res;

  memset(&hints, 0, sizeof(hints));
  //  hints.ai_port_space = RDMA_PS_TCP;
  hints.ai_port_space = RDMA_PS_IB;
  //  hints.ai_qp_type = IBV_QPT_RC; // amounts to SOCK_STREAM

  int rc = rdma_getaddrinfo((char*)spec->host, (char*)spec->port_str, &hints, &res);
  if (rc) {
    fprintf(stderr, "rdma_getaddrinfo(%s) failed: %s\n", spec->host, strerror(errno));
    return -1;
  }

  struct sockaddr*  s_addr_ptr = (struct sockaddr*)res->ai_dst_addr;
  socklen_t         s_addr_len = res->ai_dst_len;
# define  SKT_FAMILY  res->ai_family


#else  // IP sockets
  SockAddr          s_addr;
  struct sockaddr*  s_addr_ptr = (struct sockaddr*)&s_addr;
  socklen_t         s_addr_len = sizeof(SockAddr);

  // initialize the sockaddr structs
  memset(&s_addr, 0, s_addr_len);

  struct hostent* server = gethostbyname(spec->host);
  if (! server) {
    fprintf(stderr, "gethostbyname(%s) failed: %s\n", spec->host, strerror(errno));
    return -1;
  }

  s_addr.sin_family      = AF_INET;
  s_addr.sin_port        = htons(spec->port);
  memcpy((char *)&s_addr.sin_addr.s_addr,
         (char *)server->h_addr, 
         server->h_length);
#endif


  // open socket to server
  NEED_GT0( handle->peer_fd = SOCKET(SKT_FAMILY, SOCK_STREAM, 0) );

  //  // don't do this on the PUT-client?
  //  int disable = 0;
  //  NEED_0( RSETSOCKOPT(handle->peer_fd, SOL_RDMA, RDMA_INLINE, &disable, sizeof(disable)) );

  if (handle->flags & HNDL_PUT) {
    unsigned mapsize = 1; // max number of riomap'ed buffers (on this fd ?)
    NEED_0( RSETSOCKOPT(handle->peer_fd, SOL_RDMA, RDMA_IOMAPSIZE, &mapsize, sizeof(mapsize)) );
  }

  NEED_0( CONNECT(handle->peer_fd, s_addr_ptr, s_addr_len) );
  handle->flags |= HNDL_CONNECTED;
  DBG("skt_open: connected '%s'\n", spec->fname);


  return 0;
}




// ...........................................................................
// PUT
//
// When writing to a socket with RDMA, we can't write more than the
// size of the reader's buffer.  So, we've extended the
// command-protocol slightly: when the reader sends an ACK saying the
// buffer is available, the value associated with the ACk tells us the
// reader's buffer-size.  If <size> is bigger than that, we truncate
// to reader's size.
//
// Libne formerly threw errors if writes returned less-than-expected
// values.  We could force multiple writes here, to guarantee that
// everything gets written, but a better approach seems to be to let
// skt_write() act somewhat like write(), and have libne wrap its
// writes in retries, until the full amount has been written.
//
// OBSOLETE: We allow a sequence of "writes" on an open socket, but
//     because of the client-server interactions needed for RDMA
//     sockets, each write is an all-or-nothing thing.  We write all
//     of your buffer to the server, or we fail.  For compatibility
//     with write(2), we return an ssize_t, but it will always either
//     match the size of your buffer, or be negative.
//
// For RDMA+IB, we communicate with the server to receive the
// memory-mapped offset for server-side buffer we will write into.
//
// NOTE: The server understands DATA 0 to mean EOF.  We will send that
//     in skt_close().  Therefore, if someone calls skt_write() with
//     <size> 0, we'll treat it as a no-op.
//
// ...........................................................................


// On the first call to skt_write(), the writer exchanges some
// initialization-info with the peer.  If we are using riowrite(),
// we need the peer's riomapped buffer-offset.
//
// In the case of writing on behalf of a client-PUT, this also
// involves sending the PUT-request.  In the case of server-GET, it
// does not.
//
int write_init(SocketHandle* handle) {

  // --- first time through, initialize comms with server
  if (! (handle->flags & HNDL_OP_INIT)) {

    if (! (handle->flags & HNDL_SERVER_SIDE)) {
      PathSpec* spec = &handle->path_spec;
      NEED_0( write_pseudo_packet(handle->peer_fd, CMD_PUT, strlen(spec->fname)+1, spec->fname) );
    }

#if USE_RIOWRITE
    // server sends us the offset she got from riomap()
    PseudoPacketHeader header;
    NEED_0( read_pseudo_packet_header(handle->peer_fd, &header) );
    if (header.command != CMD_RIO_OFFSET) {
      fprintf(stderr, "expected RIO_OFFSET pseudo-packet, not %s\n", command_str(header.command));
      return -1;
    }
    handle->rio_offset = header.size;
    DBG("got riomap offset from peer: 0x%llx\n", header.size);
#endif  

    handle->flags |= HNDL_OP_INIT;
  }

  return 0;
}



ssize_t skt_write(SocketHandle* handle, const void* buf, size_t size) {

  DBG("skt_write(%d, %llx, %llu)\n", handle->peer_fd, (size_t)buf, size);
  if (! size)
    return 0;                   // see NOTE

  // perform deferred initial protocol exchanges, if needed
  NEED_0( write_init(handle) );


#ifdef USE_RIOWRITE
  // We're about to overwrite the destination buffer via RDMA.
  // Don't call write_buffer() until the other-end reports that it
  // is finished with the buffer.
  PseudoPacketHeader header;
  NEED_0( read_pseudo_packet_header(handle->peer_fd, &header) );

  if (header.command != CMD_ACK) {
    fprintf(stderr, "expected an ACK, but got %s\n", command_str(header.command));
    return -1;
  }

  // Reader's ACK now also includes the size of the reader's
  // read-buffer.  For RDMA, don't write more than this amount.
  if (size > header.size) {
    size = header.size;
  }

#endif

  // write_buffer() is okay here, because we know how much the peer can handle
  NEED_0( write_buffer(handle->peer_fd, buf, size, 1, handle->rio_offset) );
  handle->stream_pos += size;  /* tracking for skt_lseek() */

  return size;
}



// ...........................................................................
// READ
//
// ...........................................................................


// On the first call to skt_read(), the reader exchanges some
// initialization-info with the peer.  The peer is the one doing the
// writing, so, for riowrite, we need to send her our riomap offset
// (which also implies that she she has already called
// setsockopt(RDMA_IOMAPSIZE).)
//
// In the case of reading on behalf of a client-GET, this also
// involves sending the initial GET-request to the server.  In the
// case of server-PUT, it does not.
//
int read_init(SocketHandle* handle, char* buf, size_t size) {

  if (! (handle->flags & HNDL_OP_INIT)) {

    if (! (handle->flags & HNDL_SERVER_SIDE)) {
      PathSpec* spec = &handle->path_spec;
      NEED_0( write_pseudo_packet(handle->peer_fd, CMD_GET, strlen(spec->fname)+1, spec->fname) );
    }

#if USE_RIOWRITE
    // send peer the offset we get from riomap()
    // She'll need this for riowrite(), in write_buffer()

    //  unsigned mapsize = 1; // max number of riomap'ed buffers
    //  NEED_0( RSETSOCKOPT(handle->peer_fd, SOL_RDMA, RDMA_IOMAPSIZE, &mapsize, sizeof(mapsize)) );

    DBG("riomap(%d, 0x%llu, ...)\n", handle->peer_fd, (size_t)buf);
    handle->rio_offset = RIOMAP(handle->peer_fd, buf, size, PROT_WRITE, 0, -1);
    if (handle->rio_offset == (off_t)-1) {
      fprintf(stderr, "riomap failed: %s\n", strerror(errno));
      return -1;
    }
    DBG("riomap offset: %llu\n", handle->rio_offset);
    handle->rio_buf  = buf;     // to allow the riounmap in shut_down_thread()
    handle->rio_size = size;    // to allow the riounmap in shut_down_thread()
    handle->flags |= HNDL_RIOMAPPED;

    NEED_0( write_pseudo_packet(handle->peer_fd, CMD_RIO_OFFSET, handle->rio_offset, NULL) );
#endif

    handle->flags |= HNDL_OP_INIT;
  }

  return 0;
}


// WARNING: If USE_RIOWRITE is defined, you must always call this
//    function with the same buffer, because we will initially use it
//    to riomap the destination offset for RDMA, and all subsequent
//    RDMA writes from the peer will go there.

ssize_t skt_read(SocketHandle* handle, void* buf, size_t size) {

  ssize_t   read_count = 0;

  // perform deferred initial protocol, if needed
  NEED_0( read_init(handle, buf, size) );


#ifdef USE_RIOWRITE
  // tell peer we are done with buffer, so she can begin overwriting
  // with her next riowrite().  We also indicate the maximum amount we
  // can recv.
  NEED_0( write_pseudo_packet(handle->peer_fd, CMD_ACK, size, NULL) );


  // wait for peer to finish riowrite()
  PseudoPacketHeader header;
  NEED_0( read_pseudo_packet_header(handle->peer_fd, &header) );

  if (header.command != CMD_DATA) {
    fprintf(stderr, "expected an DATA, but got %s\n", command_str(header.command));
    return -1;
  }

  // writer's DATA might conceivably be less than <size>
  read_count = header.size;

#else
  read_count = read_buffer(handle->peer_fd, buf, size, 1);

#endif

  handle->stream_pos += read_count;  /* tracking for skt_lseek() */
  return read_count;
}


// ...........................................................................
// SEEK
//
// libne uses lseek().  It appears that under normal circumstances all
// those seeks might be redundant with the current position.  We
// detect that by tracking the current position in the stream.
// In that case, we can trivially return success.  Otherwise, for now,
// we report an error.
//
// TBD: Add seeking to the repertoire of commands that the server
//      supports.
// ...........................................................................

off_t skt_lseek(SocketHandle* handle, off_t offset, int whence) {

  if ((whence == SEEK_SET) && (offset == handle->stream_pos)) {
    return handle->stream_pos;
  }
  if ((whence == SEEK_CUR) && (offset == 0)) {
    return handle->stream_pos;
  }

  fprintf(stderr, "lseek(%llu, %d) from %llu -- non-zero head motion not yet supported\n",
          offset, handle->stream_pos, whence);
  errno = EINVAL;
  return (off_t)-1;
}


// ...........................................................................
// FSETXATTR
//
// libne uses this in some cases, but maybe we can get away with not
// supporting it, for now.
// ...........................................................................

int skt_fsetxattr(SocketHandle* handle, const char* service_path, const void* value, size_t size, int flags) {
  NO_IMPL();  
}




// ...........................................................................
// CLOSE
//
// Finalize comms with server.  Server will fsync().
// ...........................................................................

int skt_close(SocketHandle* handle) {

  if (handle->flags & HNDL_OP_INIT) {
    handle->flags &= ~HNDL_OP_INIT;

    if (handle->flags & HNDL_PUT) {
      // we were writing to this socket

#ifdef USE_RIOWRITE
      // let the other end know that there's no more data
      NEED_0( write_pseudo_packet(handle->peer_fd, CMD_DATA, 0, NULL) );
#endif

      // wait for the other end to fsync
      //
      // NOTE: If we did a previous skt_write(), then the first
      //       pseudo-packet we read will be the ACK for that write,
      //       rather than the ACK for the DATA 0 we just wrote.  Skip
      //       over the former to get to the latter.
      PseudoPacketHeader hdr;
      EXPECT_0( read_pseudo_packet_header(handle->peer_fd, &hdr) );
      EXPECT(   (hdr.command == CMD_ACK) );

      if ((hdr.command == CMD_ACK) && hdr.size) {
        EXPECT_0( read_pseudo_packet_header(handle->peer_fd, &hdr) );
        EXPECT(   (hdr.command == CMD_ACK) );
      }
    }
    else {
      // we were reading from this socket

#ifdef USE_RIOWRITE
      // We got the DATA 0 indicating EOF.  Send an ACK 0, as a sign off.
      NEED_0( write_pseudo_packet(handle->peer_fd, CMD_ACK, 0, NULL) );
#endif
    }
  }


  // This is redundant with what would be done by the thread-cleanup
  // handlers (in the server), or in the shut_down() call (in the
  // client app), but regular applications (e.g. libne) won't have a
  // shut-down handler.
  shut_down_handle(handle);

  return 0;
}






// ===========================================================================
// file-based ops
//
// The client-server setup currently creates/destroys socket
// connections at open/close time, respectively.  For file-based ops,
// like chown, etc, this is bound to add a fair amount of overhead, if
// the only thing we really want to do with the socket is send a
// pseudo-packet saying chown this file, etc.  But that's what we're
// doing, for now.
//
// TBD: For the needs of libne, we could potentially "cheat" a little,
//     and allow a socket that was opened for GET/PUT to be
//     "pre-closed", or something, which would leave the socket in
//     place, so we could send chown/chmod ops.  However, that gets a
//     little ugly to do in an implementation-agnostic way, because
//     the file-based version (i.e. as opposed to using this sockets
//     library) will close first, then chown.
//
// ===========================================================================



// ...........................................................................
// UNLINK
// ...........................................................................

int skt_unlink(const char* service_path) {
  NO_IMPL();
}


// ...........................................................................
// CHOWN
// ...........................................................................

int  skt_chown (const char* service_path, uid_t uid, gid_t gid) {

  SocketHandle       handle = {0};
  PseudoPacketHeader hdr = {0};

  // This does NOT actually open() the server-side file
  NEED_0( skt_open(&handle, service_path, (O_WRONLY|O_CREAT)) );


  // command pseudo-packet header
  PathSpec* spec = &handle.path_spec;
  NEED_0( write_pseudo_packet(handle.peer_fd, CMD_CHOWN, strlen(spec->fname)+1, spec->fname) );

  // write UID
  uint64_t uid_buf = hton64(uid);
  NEED_0( write_raw(handle.peer_fd, (char*)&uid_buf, sizeof(uid_buf)) );

  // write GID
  uint64_t gid_buf = hton64(gid);
  NEED_0( write_raw(handle.peer_fd, (char*)&gid_buf, sizeof(gid_buf)) );


  // read ACK, including return-code from the remote lchown().
  NEED_0( read_pseudo_packet_header(handle.peer_fd, &hdr) );
  NEED(   (hdr.command == CMD_ACK_CMD) );
  int rc =   (int)hdr.size;

  // close()
  NEED_0( skt_close(&handle) );

  return rc;
}



// ...........................................................................
// RENAME
// ...........................................................................


int  skt_rename (const char* service_path, const char* new_fname) {

  SocketHandle       handle = {0};
  PseudoPacketHeader hdr = {0};

  // This does NOT actually open() the server-side file
  NEED_0( skt_open(&handle, service_path, (O_WRONLY|O_CREAT)) );


  // send command pseudo-packet
  PathSpec* spec = &handle.path_spec;
  NEED_0( write_pseudo_packet(handle.peer_fd, CMD_RENAME, strlen(spec->fname)+1, spec->fname) );

  // send new-fname
  //  NEED_0( write_pseudo_packet(handle.peer_fd, CMD_RENAME_VAL, strlen(new_fname)+1, new_fname) );
  size_t len     = strlen(new_fname) +1;
  size_t len_buf = hton64(len);
  NEED_0( write_raw(handle.peer_fd, (char*)&len_buf,   sizeof(len_buf)) );
  NEED_0( write_raw(handle.peer_fd, (char*)&new_fname, len) );


  // read ACK, including return-code from the remote rename().
  NEED_0( read_pseudo_packet_header(handle.peer_fd, &hdr) );
  NEED(   (hdr.command == CMD_ACK_CMD) );
  int rc =   (int)hdr.size;

  // close()
  NEED_0( skt_close(&handle) );

  return rc;
}


// ...........................................................................
// STAT
// ...........................................................................

int skt_stat(const char* service_path, struct stat* st) {
  NO_IMPL();
}


// ...........................................................................
// GETXATTR
// ...........................................................................

int skt_getxattr(const char* service_path, const char* name, void* value, size_t size) {
  NO_IMPL();
}

