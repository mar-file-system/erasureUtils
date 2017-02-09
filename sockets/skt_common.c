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
    int dbg;                    // check return values

    // Without doing our own riounmap, we get a segfault in the
    // CLOSE() below, when rclose() calls riounmap() itself.
    //
    // It's okay if handle->rio_buf only has local scope, in server_put(),
    // we're just unmapping the address here, not using it.
    //
    if (handle->flags & HNDL_RIOMAPPED) {
      DBG("shut_down_handle(%d): riounmap'ing\n", handle->peer_fd);
      dbg = RIOUNMAP(handle->peer_fd, handle->rio_buf, handle->rio_size);
      DBG("shut_down_handle(%d): unmap = %d\n", handle->peer_fd, dbg);
      handle->flags &= ~HNDL_RIOMAPPED;
    }

    DBG("shut_down_handle(%d): shutdown\n", handle->peer_fd);
    dbg = SHUTDOWN(handle->peer_fd, SHUT_RDWR);
    DBG("shut_down_handle(%d): shutdown = %d\n", handle->peer_fd, dbg);

    DBG("shut_down_handle(%d): close\n", handle->peer_fd);
    dbg = CLOSE(handle->peer_fd);
    DBG("shut_down_handle(%d): close = %d\n", handle->peer_fd, dbg);

    handle->flags &= ~HNDL_CONNECTED;
  }

  DBG("shut_down_handle(%d): done\n", handle->peer_fd);
}

void jshut_down_handle(void* handle) {
  shut_down_handle((SocketHandle*)handle);
}
void jskt_close(void* handle) {
  skt_close((SocketHandle*)handle);
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
  // when the RDMA is complete.  (And we already told the writer how
  // big our buffer is, so the DATA packet won't indicate a size
  // bigger than that.)  If we get an actual EOF on the socket, that's
  // an error; the server should send DATA 0, to indicate an EOF on
  // file-data.

  if (is_socket) {
    PseudoPacketHeader header;
    NEED_0( read_pseudo_packet_header(fd, &header) );
    if (header.command != CMD_DATA) {
      fprintf(stderr, "unexpected pseudo-packet: %s\n", command_str(header.command));
      return -1;
    }

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
//
// TBD: As load grow on the server, this might want to do something
//     like write_buffer() does.

int read_raw(int fd, char* buf, size_t size) {
  DBG("read_raw(%d, 0x%llx, %lld)\n", fd, buf, size);

  ssize_t read_count = RECV(fd, buf, size, MSG_WAITALL);
  if (! read_count)
    DBG("EOF\n");
  if (read_count != size) {
    fprintf(stderr, "failed to read %lld bytes\n", size);
    return -1;
  }
  return 0;
}
  
// for small socket-writes that don't use RDMA
//
// TBD: As load grow on the server, this might want to do something
//     like write_buffer() does.

int write_raw(int fd, char* buf, size_t size) {
  DBG("write_raw(%d, 0x%llx, %lld)\n", fd, buf, size);

  // ssize_t write_count = WRITE(fd, buf, size);
  ssize_t write_count = SEND(fd, buf, size, 0); // TBD: flags?
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



int hton_generic(char* dst, char* src, size_t src_size) {
  switch(src_size) {
  case 8:  *((uint64_t*)dst) = hton64(*((uint64_t*)src)); break;
  case 4:  *((uint32_t*)dst) = htonl (*((uint32_t*)src)); break;
  case 2:  *((uint16_t*)dst) = htons (*((uint16_t*)src)); break;
  case 1:  *dst = *src; break;

  default:  return -1;
  }
  return 0;
}

int ntoh_generic(char* dst, char* src, size_t src_size) {
  switch(src_size) {
  case 8:   *((uint64_t*)dst) = ntoh64(*((uint64_t*)src)); break;
  case 4:   *((uint32_t*)dst) = ntohl (*((uint32_t*)src)); break;
  case 2:   *((uint16_t*)dst) = ntohs (*((uint16_t*)src)); break;
  case 1:   *dst = *src; break;

  default:  return -1;
  }
  return 0;
}






// *** co-maintain SocketCommand, in skt_common.h
const char* _command_str[] = {
  "unknown_command",

  "GET",
  "PUT",
  "DEL",
  "STAT",
  "SEEK_ABS",
  "SEEK_FWD",
  "SEEK_BACK",
  "SET_XATTR",
  "GET_XATTR",
  "CHOWN",
  "RENAME",

  "RIO_OFFSET",
  "DATA",
  "ACK",
  "ACK_CMD",

  "NULL"
};
const char* command_str(SocketCommand command) {
  if (command > CMD_NULL)
    command = 0;
  return _command_str[command];
}


// for now, this is only used by client
// NOTE: We take care of network-byte-order conversions
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
    if (size <= FNAME_SIZE)
      DBG("-> buf:     0x%08x ='%s'\n", (size_t)buf, buf);
    else
      DBG("-> buf:     0x%08x\n", (size_t)buf);

    NEED_0( write_raw(fd, (char*)buf, size) );
  }

  return 0;
}

// for now, this is only used by server
// NOTE: We take care of network-byte-order conversions
int read_pseudo_packet_header(int fd, PseudoPacketHeader* hdr) {
  ssize_t read_count;
  memset(hdr, 0, sizeof(PseudoPacketHeader));

  // --- read <command>
  uint32_t cmd;
  NEED_0( read_raw(fd, (char*)&cmd, sizeof(cmd)) );
  hdr->command = ntohl(cmd);
  DBG("<- command: %s\n", command_str(hdr->command));


  // --- read <size>
  uint64_t sz;
  NEED_0( read_raw(fd, (char*)&sz, sizeof(sz)) );
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
// NOTE: If O_CREAT flag is present, you *must* provide a mode arg.
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
  DBG("skt_open(0x%llx (flags: 0x%x), '%s', %x, ...)\n", (size_t)handle, handle->flags, service_path, flags);

  if (handle->flags && (! (handle->flags & HNDL_CLOSED))) {
    fprintf(stderr, "attempt to open handle that is not closed\n");
    return -1;
  }
  memset(handle, 0, sizeof(SocketHandle));
  handle->peer_fd = -1;         // libne checks the fd for succes

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
  hints.ai_port_space = RDMA_PS_TCP;
  //  hints.ai_port_space = RDMA_PS_IB;
  //  hints.ai_qp_type = IBV_QPT_RC; // amounts to SOCK_STREAM

  // NEW:
  // hints.ai_flags |= RAI_FAMILY;
  // hints.ai_family = AF_INET;

  int rc = rdma_getaddrinfo((char*)spec->host, (char*)spec->port_str, &hints, &res);
  if (rc) {
    fprintf(stderr, "rdma_getaddrinfo(%s) failed: %s\n", spec->host, strerror(errno));
    return -1;
  }

  struct sockaddr*  s_addr_ptr = (struct sockaddr*)res->ai_dst_addr;
  socklen_t         s_addr_len = res->ai_dst_len;
# define  SKT_FAMILY  res->ai_family

  // debugging
  NEED( s_addr_ptr->sa_family == AF_INET );
  struct sockaddr_in* sin_ptr = (struct sockaddr_in*)s_addr_ptr;
# include <arpa/inet.h>
  char dotted[INET_ADDRSTRLEN];
  NEED_GT0( inet_ntop(AF_INET, &sin_ptr->sin_addr, dotted, INET_ADDRSTRLEN) );
  DBG("rdma_getaddrinfo: %s:%d\n", dotted, ntohs(sin_ptr->sin_port));


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


  // don't assign positive value to handle->peer_fd, as long as one of
  // the NEED() macros might still return failure.  libne is going to
  // look at handle->peer_fd to see whether the open succeeded.
  int fd;

  // open socket to server
  NEED_GT0( fd = SOCKET(SKT_FAMILY, SOCK_STREAM, 0) );
  DBG("fd = %d\n", fd);

  //  // don't do this on the PUT-client?
  //  int disable = 0;
  //  NEED_0( RSETSOCKOPT( fd, SOL_RDMA, RDMA_INLINE, &disable, sizeof(disable)) );

  if (handle->flags & HNDL_PUT) {
    unsigned mapsize = 1; // max number of riomap'ed buffers (on this fd ?)
    NEED_0( RSETSOCKOPT( fd, SOL_RDMA, RDMA_IOMAPSIZE, &mapsize, sizeof(mapsize)) );
  }

  NEED_0( CONNECT(fd, s_addr_ptr, s_addr_len) );
  DBG("skt_open: connected [%d] '%s'\n", fd, spec->fname);

  handle->peer_fd = fd;         // now peer_fd can be assigned
  handle->flags |= HNDL_CONNECTED;
  return fd;
}




// ...........................................................................
// WRITE
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



// This does non-RDMA-related init tasks (including sending the
// command to the server, unless the command is CMD_NULL), on a handle
// that has already been through skt_open().  This is used by both
// write_init() and read_init(), but can also be used by other
// routines that want a handle, but don't want the overhead of setting
// up for RDMA (riowrite).  For exmaple, skt_rename() needs a handle,
// but only needs it to exchange a couple of tokens.
//
// In other words, if you want to use skt_read/skt_write, instead of
// read_raw/write_raw, but for some reason you don't want to use RDMA.
// You could initialize with this.
//
// NOTE: You don't need this, just to allow shut_down_handle() to do
//     all its necessary cleanup, For example, if you just want to
//     send some tokens with read_raw/write_raw, you don't need this.
//     However, it's a convenient way to send the initial command to
//     the server, and won't hurt you, unless you really did want to
//     use RDMA.

int basic_init(SocketHandle* handle, SocketCommand cmd) {
  DBG("basic_init(0x%llx, %s)\n", (size_t)handle, command_str(cmd));

  if (! (handle->flags & HNDL_OP_INIT)) {

    // Inits are only performed once.  If one of the NEED() calls
    // fail, here, or in read/write_init, don't let anyone come back
    // on and try again, with comms in some unknown state.
    handle->flags |= HNDL_OP_INIT;

    if (cmd != CMD_NULL) {
      PathSpec* spec = &handle->path_spec;
      NEED_0( write_pseudo_packet(handle->peer_fd, cmd, strlen(spec->fname)+1, spec->fname) );
    }
  }
  return 0;
}


// On the first call to skt_write(), the writer exchanges some
// initialization-info with the peer.  If we are using riowrite(),
// we need the peer's riomapped buffer-offset.
//
// In the case of writing on behalf of a client-PUT, this also
// involves sending the PUT-request.  In the case of server-GET, it
// does not.
//
// The reason for breaking this out is that a client that is using
// skt_write() might not want PUT to be the initial command sent to
// the server.  Using write_init() explicitly, they can force sending
// some other initial command, and then use skt_write() and
// skt_close() normally.
//
int write_init(SocketHandle* handle, SocketCommand cmd) {

  // --- first time through, initialize comms with server
  if (! (handle->flags & HNDL_OP_INIT)) {

    // inits common to read/write, allows simpler inits for non-RDMA tasks
    NEED_0( basic_init(handle, cmd) );


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

  }

  return 0;
}



ssize_t skt_write(SocketHandle* handle, const void* buf, size_t size) {
  DBG("skt_write(%d(flags: 0x%x), %llx, %llu)\n", handle->peer_fd, handle->flags, (size_t)buf, size);

  if (! size)
    return 0;                   // see NOTE

  // perform deferred initial protocol exchanges, if needed
  NEED_0( write_init(handle, CMD_PUT) );


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



ssize_t skt_write_all(SocketHandle* handle, const void* buffer, size_t size) {

  ssize_t     result = 0;
  size_t      remain = size;
  const char* buf    = buffer;

  while (remain) {
    errno = 0;

    ssize_t count = skt_write(handle, (const uint8_t*)buf+result, remain);

    if (count < 0)
      return count;

    else if (errno)
      return -1;

    remain -= count;
    result += count;
  }

  return result;
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
// The reason for breaking this out is that a client that is using
// skt_read() might not want GET to be the initial command sent to the
// server.  Using read_init() explicitly, they can force sending some
// other initial command, and then use skt_read() and skt_close()
// normally.
//
// Any operations on behalf of the client that want a connection
// featuring RDMA comms can call read_init() with the specific
// SocketCommand they want to send to the serever.  (e.g. RENAME
// doesn't need RDMA, because it's just exchanging a couple of tokens,
// so it can just use basic_init().)

int read_init(SocketHandle* handle, SocketCommand cmd, char* buf, size_t size) {

  if (! (handle->flags & HNDL_OP_INIT)) {

    // inits common to read/write, allows simpler inits for non-RDMA tasks
    NEED_0( basic_init(handle, cmd) );


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

  }

  return 0;
}


// WARNING: If USE_RIOWRITE is defined, you must always call this
//    function with the same buffer, because we will initially use it
//    to riomap the destination offset for RDMA, and all subsequent
//    RDMA writes from the peer will go there.

ssize_t skt_read(SocketHandle* handle, void* buf, size_t size) {
  DBG("skt_read(%d(flags: 0x%x), %llx, %llu)\n", handle->peer_fd, handle->flags, (size_t)buf, size);

  ssize_t   read_count = 0;

  // perform deferred initial protocol, if needed
  NEED_0( read_init(handle, CMD_GET, buf, size) );


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


ssize_t skt_read_all(SocketHandle* handle, void* buffer, size_t size) {

  ssize_t  result = 0;
  size_t   remain = size;
  char*    buf    = buffer;

  while (remain) {
    errno = 0;

    ssize_t count = skt_read(handle, buf+result, remain);

    if (count < 0)
      return count;

    else if (count == 0)
      return result;            /* EOF */

    //    else if (errno)
    //      return -1;

    remain -= count;
    result += count;
  }

  return result;
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
  DBG("skt_read(%d(flags: 0x%x), %llx, %d)\n", handle->peer_fd, handle->flags, offset, whence);

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

  // jNEED() macros will run this before exiting
  jHANDLER( jshut_down_handle, handle );

  if (handle->flags & HNDL_OP_INIT) {
    handle->flags &= ~HNDL_OP_INIT;

    if (handle->flags & HNDL_PUT) {
      // we were writing to this socket

#ifdef USE_RIOWRITE
      // let the other end know that there's no more data
      jNEED_0( write_pseudo_packet(handle->peer_fd, CMD_DATA, 0, NULL) );
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
      jNEED_0( write_pseudo_packet(handle->peer_fd, CMD_ACK, 0, NULL) );
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
  NEED_GT0( skt_open(&handle, service_path, O_WRONLY) );

  // jNEED() macros will run this before exiting
  jHANDLER( jshut_down_handle, &handle );

  // command pseudo-packet header
  PathSpec* spec = &handle.path_spec;
  jNEED_0( write_pseudo_packet(handle.peer_fd, CMD_CHOWN, strlen(spec->fname)+1, spec->fname) );

  // write UID
  uint64_t uid_buf = hton64(uid);
  jNEED_0( write_raw(handle.peer_fd, (char*)&uid_buf, sizeof(uid_buf)) );

  // write GID
  uint64_t gid_buf = hton64(gid);
  jNEED_0( write_raw(handle.peer_fd, (char*)&gid_buf, sizeof(gid_buf)) );


  // read ACK, including return-code from the remote lchown().
  jNEED_0( read_pseudo_packet_header(handle.peer_fd, &hdr) );
  jNEED(   (hdr.command == CMD_ACK_CMD) );
  int rc =   (int)hdr.size;

  // close()
  jNEED_0( skt_close(&handle) );

  return rc;
}



// ...........................................................................
// RENAME
// ...........................................................................


// NOTE: As on the server-side, we forgo establishing an "open"
//     handle, which would allow e.g. skt_write() of the new fname,
//     instead of write_raw().  It would also add an extra layer of
//     protocol, plus the overhead of riomapping/unmapping, just for
//     that one thing.  Instead, we'll just resort to write_raw(), and
//     our cleanup devolves to shut_down_handle().

int skt_rename (const char* service_path, const char* new_path) {
  DBG("skt_rename from: %s\n", service_path);
  DBG("skt_rename to:   %s\n", new_path);

  // if libne is calling, both paths are service_paths.
  // Strip off the host:port portion of the new_path
  const char* new_fname = new_path;
  PathSpec    new_spec;
  if (! parse_service_path(&new_spec, new_path) ) {
    new_fname = new_spec.fname;
    DBG("skt_rename to2:  %s\n", new_fname);
  }

  SocketHandle       handle = {0};
  PseudoPacketHeader hdr = {0};

  // This does NOT actually open() the server-side file
  NEED_GT0( skt_open(&handle, service_path, O_WRONLY) );

#if 0
  // jNEED() macros will run this before exiting
  jHANDLER( jskt_close, &handle );

  // perform deferred initial protocol exchanges, and send fname
  NEED_0( write_init(&handle, CMD_RENAME) );

#else
  // jNEED() macros will run this before exiting
  jHANDLER( jshut_down_handle, &handle );

  // perform deferred initial protocol exchanges, and send fname
  jNEED_0( basic_init(&handle, CMD_RENAME) );
#endif

  // send new-fname
  size_t len     = strlen(new_fname) +1;
  size_t len_buf = hton64(len);
  jNEED_0( write_raw(handle.peer_fd, (char*)&len_buf,   sizeof(len_buf)) );
  jNEED_0( write_raw(handle.peer_fd, (char*)new_fname, len) );

  // read ACK, including return-code from the remote rename().
  jNEED_0( read_pseudo_packet_header(handle.peer_fd, &hdr) );
  jNEED(   (hdr.command == CMD_ACK_CMD) );
  int rc =   (int)hdr.size;

#if 0
  // close()
  NEED_0( skt_close(&handle) );
#else
  // close()
  shut_down_handle(&handle);
#endif

  return rc;
}


// ...........................................................................
// STAT
//
// We are just exchanging a small blob of stat info, but we use RDMA
// to do it, to try to minimize the CPU load on the server.  This also
// makes it easier to send a series of network-byte-order values of
// different sizes.
//
// TBD: Server just translates successive struct members to
//    network-byte-order (appropriately to their size) and sends them
//    contiguously.  We're assuming that STAT_DATA_STRUCT size being
//    the same on client and server means that all the fields also
//    have the same size.  It might be better for the server to
//    include some info that would allow us to validate that we agree
//    on the size of the elements.
//
// TBD: It would be even smarter for client to open send an endian
//    argument, and maybe the server could just RDMA the struct
//    contents straight to us without the need for translations to
//    network-byte-order.
//
// ...........................................................................

int skt_stat(const char* service_path, struct stat* st) {
  SocketHandle   handle = {0};
  char           buf[STAT_DATA_SIZE]   __attribute__ (( aligned(64) ));
  char*          ptr = buf;

  // server sends us remote return-code with special meaning:
  //   (1) if lstat() failed:    negative errcode
  //   (2) if lstat() succeeded: sizeof(struct stat), for crude validation
  ssize_t rc;

  // This does NOT actually open() the server-side file
  NEED_GT0( skt_open(&handle, service_path, (O_RDONLY)) );

#if 0
  // jNEED() macros will run this before exiting
  jHANDLER( jskt_close, &handle );

  // send STAT plus fname, and prepare for reading via skt_read()
  jNEED_0( read_init(&handle, CMD_STAT, ptr, STAT_DATA_SIZE) );
#else
  // jNEED() macros will run this before exiting
  jHANDLER( jshut_down_handle, &handle );

  // send STAT plus fname, and prepare for reading via read_raw()
  jNEED_0( basic_init(&handle, CMD_STAT) );
#endif

  // rc is sent as a pseudo-packet
  PseudoPacketHeader hdr;
  jNEED_0( read_pseudo_packet_header(handle.peer_fd, &hdr) );
  jNEED(   (hdr.command == CMD_ACK_CMD) );
  rc = hdr.size;
  if (rc < 0) {

    // case (1): remote lstat failed.
    errno = -rc;
    DBG("stat failed: %s\n", strerror(errno));
    return -1;
  }

  // case (2): remote lstat succeeded.

  // (a) First value is sizeof(struct stat) on the server, for crude validation
  jNEED( rc == sizeof(*st) );

  // (b) fill in the struct.  quick-and-dirty approach.
#if 0
  ssize_t read_size = skt_read_all(&handle, ptr, STAT_DATA_SIZE);
  jNEED( read_size == STAT_DATA_SIZE );
#else
  jNEED_0( read_raw(handle.peer_fd, ptr, STAT_DATA_SIZE) );
#endif

  jRECV_VALUE(st->st_dev, ptr);     /* ID of device containing file */
  jRECV_VALUE(st->st_ino, ptr);     /* inode number */
  jRECV_VALUE(st->st_mode, ptr);    /* protection */
  jRECV_VALUE(st->st_nlink, ptr);   /* number of hard links */
  jRECV_VALUE(st->st_uid, ptr);     /* user ID of owner */
  jRECV_VALUE(st->st_gid, ptr);     /* group ID of owner */
  jRECV_VALUE(st->st_rdev, ptr);    /* device ID (if special file) */
  jRECV_VALUE(st->st_size, ptr);    /* total size, in bytes */
  jRECV_VALUE(st->st_blksize, ptr); /* blocksize for file system I/O */
  jRECV_VALUE(st->st_blocks, ptr);  /* number of 512B blocks allocated */
  jRECV_VALUE(st->st_atime, ptr);   /* time of last access */
  jRECV_VALUE(st->st_mtime, ptr);   /* time of last modification */
  jRECV_VALUE(st->st_ctime, ptr);   /* time of last status change */

#if 0
  // close RDMA stream
  jNEED_0( skt_close(&handle) );
#else
  // close
  shut_down_handle(&handle);
#endif

  return 0;
}


// ...........................................................................
// GETXATTR
// ...........................................................................

int skt_getxattr(const char* service_path, const char* name, void* value, size_t size) {
  NO_IMPL();
}

