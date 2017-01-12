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
#include <errno.h>
#include <string.h>

#include "common.h"




// Issue repeated reads until we've gotten <size> bytes, or error, or
// EOF.  Return negative for error.  Otherwise, return the total
// number of bytes that could be read.  If return-value is positive,
// but less than <size>, there must've been an EOF.

ssize_t read_buffer(int fd, char* buf, size_t size, int is_socket) {
  DBG("read_buffer(%d, 0x%llx, %lld, %d)\n", fd, buf, size, is_socket);

#ifdef USE_RIOWRITE
  // If we would be reading from an rsocket where the writer is using
  // riowrite(), we won't see anything in the fd; it's just doing RDMA
  // directly into our buffer.  Writer will write one extra byte,
  // beyond the end (which we will have allocated), and will have set
  // it to zero before the transfer.  After the transfer, this will be
  // set to 1.
  //
  // TBD? buffers are all aligned to 64-byte boundaries anyhow.  If
  // size was always a multiple of size_t, the the overflow could be a
  // size_t, which would let the writer communicate that less than the
  // expected size was written.  This may be unnecessary, because we
  // have pseudo-packet headers that could always be used to
  // pre-arrange the amount of data to be transmitted.  So, a single
  // byte would work fine.

  ///   if (is_socket) {
  ///     char* overflow = buf + size;
  /// 
  ///     while (! *overflow)
  ///       sched_yield();
  /// 
  ///     uint8_t code = (uint8_t)*overflow;
  ///     DBG("overflow-code = %d\n", (int)code);
  ///     if (code == (uint8_t)-1)
  ///       return -1;
  /// 
  ///     // reset for next read/write
  ///     *overflow = 0;
  /// 
  ///     return size;
  ///   }

  if (is_socket) {
    PseudoPacketHeader header;
    CHECK_0( read_pseudo_packet_header(fd, &header) );
    if (header.flags & PKT_EOF)
      return 0;
    else if (header.command != CMD_DATA) {
      fprintf(stderr, "unexpected pseudo-packet: %s\n", command_str(header.command));
      return -1;
    }
    return header.length;
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
// WARNING: in the case of USE_RIOWRITE to a socket, we actually write
//     size +1 bytes, so read_buffer() on the other end can detect
//     completion..
int write_buffer(int fd, char* buf, size_t size, int is_socket, off_t offset) {
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
      printf("buffer is full.  ignoring.\n");
    else if (errno == EPIPE) {
      printf("client disconnected?\n");
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
  //  // reader can't tell that the previous riowrite has completed until
  //  // it sees this byte change
  //  if (is_socket) {
  //    uint8_t one = 1;
  //    if (riowrite(fd, (char*)&one, 1, offset+size, 0)) {
  //      perror("riowrite overflow failed");
  //      return -1;
  //    }
  //  }

  if (is_socket) {
    CHECK_0( write_pseudo_packet(fd, CMD_DATA, size, NULL) );
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





// [from marfs_common.c]
// htonll() / ntohll() are not provided in our environment.  <endian.h> or
// <byteswap.h> make things easier, but these are non-standard.  Also, we're
// compiled with -Wall, so we avoid pointer-aliasing that makes gcc whine.
//
// TBD: Find the appropriate #ifdefs to make these definitions go away on
//     systems that already provide them.


// see http://esr.ibiblio.org/?p=5095
#define IS_LITTLE_ENDIAN (*(uint16_t *)"\0\xff" >= 0x100)

uint64_t htonll(uint64_t ll) {
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
uint64_t ntohll(uint64_t ll) {
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


// co-maintain SocketCommand, in common.h
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
  "NULL"
};
const char* command_str(SocketCommand command) {
  if (command > CMD_NULL)
    command = 0;
  return _command_str[command];
}


// for now, this is only used by client
int write_pseudo_packet(int fd, SocketCommand command, size_t length, void* buf) {
  ssize_t write_count;

  // --- write <command>
  DBG("-> command: %s\n", command_str(command));
  uint32_t cmd = htonl(command);
  CHECK_0( write_raw(fd, (char*)&cmd, sizeof(cmd)) );

  // --- write <length>
  DBG("-> length:  %llu\n", length);
  uint64_t len = htonll(length);
  CHECK_0( write_raw(fd, (char*)&len, sizeof(len)) );

  // --- maybe write <buf>
  if (buf) {
    DBG("-> buf:     0x%08x\n", (size_t)buf);
    CHECK_0( write_raw(fd, (char*)buf, length) );
  }

  return 0;
}

// for now, this is only used by server
int read_pseudo_packet_header(int fd, PseudoPacketHeader* hdr) {
  ssize_t read_count;

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
    return -1;
  }
  hdr->command = ntohl(cmd);
  DBG("<- command: %s\n", command_str(hdr->command));


  // --- read <length>
  uint64_t len;
  read_count = read_raw(fd, (char*)&len, sizeof(len));
  if (! read_count) {
    hdr->flags |= (PKT_EOF & PKT_ERR);
    DBG("EOF\n");
    return -1;
  }
  else if (read_count != sizeof(len)) {
    DBG("read err %lld\n", read_count);
    return -1;
  }
  hdr->length = ntohll(len);
  DBG("<- length:  %llu\n", hdr->length);

  return 0;
}


// --- read <fname>
//     name must include terminal NULL.
int read_fname(int fd, char* fname, size_t length) {

  size_t fname_size = length;
  if (fname_size > FNAME_SIZE) {
    fprintf(stderr, "fname-length %llu exceeds maximum %u\n", fname_size, FNAME_SIZE);
    return -1;
  }
  // ssize_t read_count = read(client_fd, &fname, FNAME_SIZE);
  // ssize_t read_count = read_buffer(fd, fname, fname_size, 1);
  ssize_t read_count = read_raw(fd, fname, fname_size);
  if (read_count != fname_size) {
    fprintf(stderr, "failed to read fname (%lld)\n", read_count);
    return -1;
  }
  else if (!fname[0] || fname[fname_size -1]) {
    fprintf(stderr, "bad fname\n");
    return -1;
  }
  DBG("fname: %s\n", fname);

  return 0;
}




#define NO_IMPL()						\
  fprintf(stderr, "%s not implemented\n", __FUNCTION__);	\
  abort()

SocketHandle  skt_open (const char* fname, int flags, mode_t mode) {
  NO_IMPL();
}

ssize_t       skt_write(SocketHandle* handle, const void* buf, size_t count) {
  NO_IMPL();
}

ssize_t       skt_read (SocketHandle* handle,       void* buf, size_t count) {
  NO_IMPL();
}

off_t         skt_seek (SocketHandle* handle, off_t offset, int whence) {
  NO_IMPL();
}

int           skt_close(SocketHandle* handle) {
  NO_IMPL();
}
