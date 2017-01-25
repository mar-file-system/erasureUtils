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



// This is like socket_server.c, but we now have multiple servers.
//
// CLIENT: The goal for the client is to maintain connections with as many
// servers as are in service at a time, reading from whichever ones produce
// output, in a timely manner.  The client is currently in C++ only because
// it uses some STL to manage info about which servers are connected, etc.
//
// SERVER: The goal for the server is to produce continuous output at a
// rate similar to that of our application, and to be robust if the client
// fails to read, drops a connection, or lets the buffer fill up.  We want
// the server to remain in C.


#include <stdio.h>
#include <errno.h>
#include <stdlib.h>             // strtol()
#include <unistd.h>             // usleep()
#include <string.h>             // strcpy()
#include <signal.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pthread.h>

#include "skt_common.h"



// These are now only used in main_flags
#define  MAIN_BIND         0x0001
#define  MAIN_SOCKET_FD    0x0002

// These are now only used in ThreadContext.flags
#define  CTX_PRE_THREAD   0x0010 /* client_fd has been opened */
#define  CTX_THREAD_EXIT  0x0020
#define  CTX_THREAD_ERR   0x0040

#define  CTX_RIOMAPPED    0x0100
#define  CTX_FILE_OPEN    0x0200
#define  CTX_EOF          0x0400


static unsigned char  main_flags = 0;

static char server_name[MAX_SOCKET_NAME_SIZE +1];

static int  socket_fd;               // listen() to this
// static int  client_fd;               // read/write to this
// static int  file_fd;                  // writing client data to file




// all the state needed to make server-threads thread-safe.
//
// NOTE: The point of ThreadContext.buf, is to store a pointer to the
//     buffer that is provided to riomap(), in server_put(), so that
//     we can riounmap it, in shut_down_thread().  Currently, we are
//     just allocating this on the stack in server_put(), which means
//     that it is out of scope in shut_down_thread().  Apparently,
//     this is fine.  All that riounmap really cares about is the
//     address of the buffer that was mapped.
//
//     If we really cared about ThreadContext.buf pointing to
//     something that is still valid in shut_down_thread(), and wanted
//     to avoid the overhead and possible leaking of dynamic alloc, we
//     could make it a member of the ThreadContext, as is commented
//     out, here.  That works, but means our ThreadContexts always
//     take up that much more space, even if they are just going to be
//     handling a CMD_CHOWN, or something.
//   
typedef struct {
  volatile int        flags;	 // lockless: see ServerConnection 
  int                 err_no;	 // TBD
  PseudoPacketHeader  hdr;	 // read/write "pseudo-packets" to/from socket
  int                 client_fd; // socket
  int                 file_fd;	 // server-side file

  char*               buf;	 // (currently static)
  /// char                buf[SERVER_BUF_SIZE]  __attribute__ (( aligned(64) ));
  
  off_t               offset;	 // server-side riomap'ped offset for PUT
  char                fname[FNAME_SIZE];
} ThreadContext;


// our record of an existing connection
// NOTE: We avoid the need for locking by taking some care: main only
//    sets ctx.flags when they are zero.  Threads reset to zero on
//    exit.
typedef struct ServerConnection {
  pthread_t      thr;
  ThreadContext  ctx;
} SConn;

SConn conn_list[MAX_SOCKET_CONNS];

// // access to conn_list[] elements
// pthread_mutex_t conn_lock;





// clean-up for a given thread.
// Threads only handle the client_fd, and file_fd.
// The listening socket is shut-down by main.
void
shut_down_thread(void* arg) {
  ThreadContext* ctx = (ThreadContext*)arg;

  // maybe close the local file
  if (ctx->flags & CTX_FILE_OPEN) {

#ifndef SKIP_FILE_WRITES
    if (ctx->hdr.command == CMD_PUT)
      EXPECT_0( close(ctx->file_fd) );
#endif

#ifndef SKIP_FILE_READS
    if (ctx->hdr.command == CMD_GET)
      EXPECT_0( close(ctx->file_fd) );
#endif

  }

  if (ctx->flags & CTX_PRE_THREAD) {
    DBG("shut_down_thread: closing client_fd %d\n", ctx->client_fd);

    // Without doing our own riounmap, we get a segfault in the
    // CLOSE() below, when rclose() calls riounmap() itself.
    //
    // It's okay if ctx->buf only has local scope, in server_put(),
    // we're just unmapping the address here, not using it.
    //
    if (ctx->flags & CTX_RIOMAPPED) {
      DBG("shut_down_thread(%d): riounmap'ing\n", ctx->client_fd);
      RIOUNMAP(ctx->client_fd, ctx->buf, SERVER_BUF_SIZE);
    }

    DBG("shut_down_thread(%d): shutdown\n", ctx->client_fd);
    SHUTDOWN(ctx->client_fd, SHUT_RDWR);

    DBG("shut_down_thread(%d): close\n", ctx->client_fd);
    CLOSE(ctx->client_fd);

    DBG("shut_down_thread(%d): done\n", ctx->client_fd);
  }

  ctx->flags |= CTX_THREAD_EXIT;
}


// main uses this for surprise exits
void
shut_down() {

  // shutdown all threads
  int i;
  for (i=0; i<MAX_SOCKET_CONNS; ++i) {
    if ((conn_list[i].ctx.flags & (CTX_PRE_THREAD | CTX_THREAD_EXIT))
	== CTX_PRE_THREAD) {
      DBG("shut_down: cancelling conn %d ...", i);
      pthread_cancel(conn_list[i].thr);
      pthread_join(conn_list[i].thr, NULL);
      DBG("done.\n");
    }
  }

  // close up shop
  if (main_flags & MAIN_BIND) {
    DBG("shut_down: unlinking '%s'\n", server_name);
    (void)unlink(server_name);
  }
  if (main_flags & MAIN_SOCKET_FD) {
    DBG("shut_down: closing socket_fd %d\n", socket_fd);
    CLOSE(socket_fd);
  }
}


// for main()
static void
sig_handler(int sig) {
  fprintf(stderr, "sig_handler exiting on signal %d\n", sig);
  shut_down();
  exit(0);
}










// ctx->hdr.command will be CMD_GET or CMD_PUT.
//
// For PUT, client is sending us data to go into a file
// For GET, we're reading from file and shipping to client.
//
// Return 0 for success, non-zero for fail.
//
int server_put(ThreadContext* ctx) {

  // shorthand
  int                  cmd       = ctx->hdr.command;
  int                  client_fd = ctx->client_fd;
  PseudoPacketHeader*  hdr       = &ctx->hdr;
  char*                fname     = ctx->fname;
  int                  o_flags   = ((cmd == CMD_PUT)
				    ? (O_WRONLY|O_CREAT|O_TRUNC)
				    : (O_RDONLY));

  int                  src_fd;
  int                  src_is_socket;
  int                  dst_fd;
  int                  dst_is_socket;

  ///  char*  buf = ctx->buf;
  char                 buf[SERVER_BUF_SIZE]  __attribute__ (( aligned(64) ));
  
#if USE_RIOWRITE
  // --- send client the offset we got from riomap()
  //     She'll need this for riowrite(), in write_buffer()

  //  unsigned mapsize = 1; // max number of riomap'ed buffers
  //  NEED_0( RSETSOCKOPT(client_fd, SOL_RDMA, RDMA_IOMAPSIZE, &mapsize, sizeof(mapsize)) );

  ctx->offset = RIOMAP(client_fd, buf, SERVER_BUF_SIZE, PROT_WRITE, 0, -1);
  if (ctx->offset == (off_t)-1) {
    fprintf(stderr, "riomap failed: %s\n", strerror(errno));
    return -1;
  }
  DBG("riomap offset: %llu\n", ctx->offset);
  ctx->buf = buf;	// to allow the riounmap in shut_down_thread()
  ctx->flags |= CTX_RIOMAPPED;

  NEED_0( write_pseudo_packet(client_fd, CMD_RIO_OFFSET, ctx->offset, NULL) );
  NEED_0( write_pseudo_packet(client_fd, CMD_ACK, 0, NULL) );

#endif


  // --- PUT: read from socket, write to file
  //
  // In the case of USE_RIOWRITE, data is sent (by client for PUT, by
  // server for GET) via RDMA.  This means the reader has no awareness
  // of when the write has been completed.  So we use the socket to
  // send a series of DATA pseudo-packets, each with a length
  // indicating the amount of data transferred via RDMA.  A final DATA
  // 0 is sent to indicate EOF.
  //
  // This "packetization" of the data could allow out-of-band comms
  // (e.g.  we could return a set of ACKs, with checksums, on demand,
  // to allow the client to validate the stream, without requiring
  // that we do that for clients that don't want it.).
  //
  while (likely(! (ctx->flags & CTX_EOF))) {

    // --- first pass: open local file, if needed
    if (unlikely(! (ctx->flags & CTX_FILE_OPEN))) {

#ifndef SKIP_FILE_WRITES
      // open local file for writing
      ctx->file_fd = open(fname, o_flags);
      if (ctx->file_fd < 0) {
	fprintf(stderr, "couldn't open '%s' for command '%s': %s\n",
		fname, command_str(cmd), strerror(errno));
	ctx->flags |= CTX_THREAD_ERR;
	return -1;
      }
      printf("opened file '%s'\n", fname);
#endif
      ctx->flags |= CTX_FILE_OPEN;
    }


    // --- read data up to SERVER_BUF_SIZE, or EOF, from client
    ssize_t read_total = read_buffer(client_fd, buf, SERVER_BUF_SIZE, 1);
    if (read_total < 0) {
      ctx->flags |= CTX_THREAD_ERR;
      break;
    }
    else if (read_total == 0)
      ctx->flags |= CTX_EOF;


#ifndef SKIP_FILE_WRITES
    // --- write buffer to file
    if (read_total && write_buffer(ctx->file_fd, buf, read_total, 0, ctx->offset)) {
      ctx->flags |= CTX_THREAD_ERR;
      break;
    }
#endif

#ifdef USE_RIOWRITE
    // tell client we are done with buffer, so she can begin
    // overwriting with her next riowrite()
    if( write_pseudo_packet(client_fd, CMD_ACK, read_total, NULL) ) {
      ctx->flags |= CTX_THREAD_ERR;
      break;
    }
#endif

  }
  DBG("copy-loop done.\n");



#ifndef SKIP_FILE_WRITES
  // finished.  maybe close the local file we opened.
  if (ctx->flags & CTX_FILE_OPEN) {
    fsync(ctx->file_fd);	// for consistent sustained ZFS throughput
    DBG("-- fsync'ed %d\n", ctx->file_fd);
    close(ctx->file_fd);
    DBG("-- closed   %d\n", ctx->file_fd);
    ctx->flags &= ~CTX_FILE_OPEN;
  }
#endif


  return 0;
}









// UNDER CONSTRUCTION ...
// Assimilating GET-specific boilerplate from the generic version

int server_get(ThreadContext* ctx) {

  // shorthand
  int                  cmd       = ctx->hdr.command;
  int                  client_fd = ctx->client_fd;
  PseudoPacketHeader*  hdr       = &ctx->hdr;
  char*                fname     = ctx->fname;
  int                  o_flags   = O_RDONLY;

  int                  src_fd;
  int                  src_is_socket;
  int                  dst_fd;
  int                  dst_is_socket;

  char                 buf[SERVER_BUF_SIZE]  __attribute__ (( aligned(64) ));

  
#if USE_RIOWRITE
  // --- client sends us the offset she got from riomap()
  //     we'll need this for riowrite(), in write_buffer()
  PseudoPacketHeader header = {0};
  NEED_0( read_pseudo_packet_header(client_fd, &header) );
  if (header.command != CMD_RIO_OFFSET) {
    fprintf(stderr, "expected RIO_OFFSET pseudo-packet, not %s\n", command_str(header.command));
    return -1;
  }
  ctx->offset = header.length;
  DBG("got riomap offset from client: 0x%llx\n", header.length);
#endif


  // --- GET: read from file, write to socket
  //
  // In the case of USE_RIOWRITE, data is sent (by client for PUT, by
  // server for GET) via RDMA.  This means the reader has no awareness
  // of when the write has been completed.  So we use the socket to
  // send a series of DATA pseudo-packets, each with a length
  // indicating the amount of data transferred via RDMA.  A final DATA
  // 0 is sent to indicate EOF.
  //
  // This "packetization" of the data could allow out-of-band comms
  // (e.g.  we could return a set of ACKs, with checksums, on demand,
  // to allow the client to validate the stream, without requiring
  // that we do that for clients that don't want it.).
  //
  while (likely(! (ctx->flags & CTX_EOF))) {

    // --- open local file, if needed
    if (unlikely(! (ctx->flags & CTX_FILE_OPEN))) {

#ifndef SKIP_FILE_READS
      // open local file for reading
      ctx->file_fd = open(fname, o_flags);
      if (ctx->file_fd < 0) {
	fprintf(stderr, "couldn't open '%s' for command '%s': %s\n",
		fname, command_str(cmd), strerror(errno));
	ctx->flags |= CTX_THREAD_ERR;
	return -1;
      }
      printf("opened file '%s'\n", fname);
#endif
      ctx->flags |= CTX_FILE_OPEN;
    }

    // --- read data up to SERVER_BUF_SIZE, or EOF, from <source>
#ifdef SKIP_FILE_READS
    // TBD: Keep some state in the handle, to limit the number of fake
    //      reads we do before faking an EOF.  As it stands, this will
    //      succeed forever.
    ssize_t read_total = SERVER_BUF_SIZE;
#else
    ssize_t read_total = read_buffer(ctx->file_fd, buf, SERVER_BUF_SIZE, 0);
    if (read_total < 0) {
      ctx->flags |= CTX_THREAD_ERR;
      break;
    }
    else if (read_total < SERVER_BUF_SIZE)
      ctx->flags |= CTX_EOF;
#endif

    // --- write buffer to <dest>
    if (write_buffer(client_fd, buf, read_total, 1, ctx->offset)) {
      ctx->flags |= CTX_THREAD_ERR;
      break;
    }

#ifdef USE_RIOWRITE
    // tell client we are done with buffer, which will be overwrriten
    // by the next riowrite()
    if ( write_pseudo_packet(src_fd, CMD_ACK, 0, NULL) ) {
      ctx->flags |= CTX_THREAD_ERR;
      break;
    }
#endif

  }
  DBG("copy-loop done.\n");


#ifndef SKIP_FILE_READS
  // maybe close the local file we opened
  if (ctx->flags & CTX_FILE_OPEN) {
    fsync(ctx->file_fd);	// for consistent sustained ZFS throughput
    DBG("-- fsync'ed %d\n", ctx->file_fd);
    close(ctx->file_fd);
    DBG("-- closed   %d\n", ctx->file_fd);
    ctx->flags &= ~CTX_FILE_OPEN;
  }
#endif

  return 0;
}








// THIS GENERIC PUT/GET WAS GETTING TOO UGLY.
// KEEPING IT AROUND UNTIL server_put() AND server_get() ARE WORKING

int server_put_or_get(ThreadContext* ctx) {

  // shorthand
  int                  cmd       = ctx->hdr.command;
  int                  client_fd = ctx->client_fd;
  PseudoPacketHeader*  hdr       = &ctx->hdr;
  char*                fname     = ctx->fname;
  int                  o_flags   = ((cmd == CMD_PUT)
				    ? (O_WRONLY|O_CREAT|O_TRUNC)
				    : (O_RDONLY));

  int                  src_fd;
  int                  src_is_socket;
  int                  dst_fd;
  int                  dst_is_socket;

  char                 buf[SERVER_BUF_SIZE]  __attribute__ (( aligned(64) ));

  
#if USE_RIOWRITE
  if (cmd == CMD_PUT) {

    // --- send client the offset we got from riomap()
    //     She'll need this for riowrite(), in write_buffer()

    //  unsigned mapsize = 1; // max number of riomap'ed buffers
    //  NEED_0( RSETSOCKOPT(client_fd, SOL_RDMA, RDMA_IOMAPSIZE, &mapsize, sizeof(mapsize)) );

    ctx->offset = RIOMAP(client_fd, buf, SERVER_BUF_SIZE, PROT_WRITE, 0, -1);
    if (ctx->offset == (off_t)-1) {
      fprintf(stderr, "riomap failed: %s\n", strerror(errno));
      return -1;
    }
    DBG("riomap offset: %llu\n", ctx->offset);

    NEED_0( write_pseudo_packet(client_fd, CMD_RIO_OFFSET, ctx->offset, NULL) );
    NEED_0( write_pseudo_packet(client_fd, CMD_ACK, 0, NULL) );

    ctx->buf = buf;	// to allow the riounmap in shut_down_thread()
    ctx->flags |= CTX_RIOMAPPED;
  }
  else {

    // --- client sends us the offset she got from riomap()
    //     we'll need this for riowrite(), in write_buffer()
    PseudoPacketHeader header = {0};
    NEED_0( read_pseudo_packet_header(client_fd, &header) );
    if (header.command != CMD_RIO_OFFSET) {
      fprintf(stderr, "expected RIO_OFFSET pseudo-packet, not %s\n", command_str(header.command));
      return -1;
    }
    ctx->offset = header.length;
    DBG("got riomap offset from server: 0x%llx\n", header.length);
  }
#endif


  // --- PUT: read from socket, write to file
  //     GET: read from file,   write to socket
  //
  // In the case of USE_RIOWRITE, data is sent (by client for PUT, by
  // server for GET) via RDMA.  This means the reader has no awareness
  // of when the write has been completed.  So we use the socket to
  // send a series of DATA pseudo-packets, each with a length
  // indicating the amount of data transferred via RDMA.  A final DATA
  // 0 is sent to indicate EOF.
  //
  // This "packetization" of the data could allow out-of-band comms
  // (e.g.  we could return a set of ACKs, with checksums, on demand,
  // to allow the client to validate the stream, without requiring
  // that we do that for clients that don't want it.).
  //
  while (likely(! (ctx->flags & CTX_EOF))) {

#ifdef SKIP_FILE_WRITES
    // short-circuit writing to file.
    // NOTE: We also don't set CTX_FILE_OPEN, so shut_down_thread()
    //       will skip trying to close it
    if (cmd == CMD_PUT) {	// PUT: client_fd -> file_fd
      src_fd        = client_fd;
      src_is_socket = 1;
    }
    else
#endif

    // --- open local file, if needed
    if (unlikely(! (ctx->flags & CTX_FILE_OPEN))) {

      // open with appropriate flags
      ctx->file_fd = open(fname, o_flags);
      if (ctx->file_fd < 0) {
	fprintf(stderr, "couldn't open '%s' for command '%s': %s\n",
		fname, command_str(cmd), strerror(errno));
	ctx->flags |= CTX_THREAD_ERR;
	return -1;
      }
      ctx->flags |= CTX_FILE_OPEN;
      printf("opened file '%s'\n", fname);

      // prepare to copy data for GET/PUT
      if (cmd == CMD_PUT) {	// PUT: client_fd -> file_fd
	src_fd        = client_fd;
	src_is_socket = 1;

	dst_fd        = ctx->file_fd;
	dst_is_socket = 0;
      }
      else {			// GET: file_fd -> client_fd
	src_fd        = ctx->file_fd;
	src_is_socket = 0;

	dst_fd        = client_fd;
	dst_is_socket = 1;
      }
    }

    // --- read data up to SERVER_BUF_SIZE, or EOF, from <source>
    ssize_t read_total = read_buffer(src_fd, buf, SERVER_BUF_SIZE, src_is_socket);
    if (read_total < 0) {
      ctx->flags |= CTX_THREAD_ERR;
      break;
    }
    else if (read_total < SERVER_BUF_SIZE)
      ctx->flags |= CTX_EOF;


#ifndef SKIP_FILE_WRITES
    // --- write buffer to <dest>
    if (write_buffer(dst_fd, buf, read_total, dst_is_socket, ctx->offset)) {
      ctx->flags |= CTX_THREAD_ERR;
      break;
    }
#endif

#ifdef USE_RIOWRITE
    // tell client we are done with buffer, which will be overwrriten
    // by the next riowrite()
    if (src_is_socket)
      NEED_0( write_pseudo_packet(src_fd, CMD_ACK, 0, NULL) );
#endif

  }
  DBG("copy-loop done.\n");


  // maybe close the local file we opened
  if (ctx->flags & CTX_FILE_OPEN) {
    fsync(ctx->file_fd);	// for consistent sustained ZFS throughput
    DBG("-- fsync'ed %d\n", ctx->file_fd);
    close(ctx->file_fd);
    DBG("-- closed   %d\n", ctx->file_fd);
    ctx->flags &= ~CTX_FILE_OPEN;
  }


  return 0;
}



int server_del(ThreadContext* ctx) {
  if (unlink(ctx->fname)) {
    fprintf(stderr, "couldn't unlink '%s'\n", ctx->fname);
    ctx->flags |= CTX_THREAD_ERR;
    return -1;
  }
  return 0;
}



int server_chown(ThreadContext* ctx) {

  int                client_fd = ctx->client_fd;
  PseudoPacketHeader header = {0};

  // read UID
  uint64_t uid_buf;
  NEED_0( read_raw(client_fd, (char*)&uid_buf, sizeof(uid_buf)) );
  uid_t uid = ntoh64(uid_buf);

  // read GID
  uint64_t gid_buf;
  NEED_0( read_raw(client_fd, (char*)&gid_buf, sizeof(gid_buf)) );
  gid_t gid = ntoh64(gid_buf);

  // perform op
  int rc = lchown(ctx->fname, uid, gid);

  // send ACK with return-code
  NEED_0( write_pseudo_packet(client_fd, CMD_ACK_CMD, rc, NULL) );

  return rc;
}


int server_rename(ThreadContext* ctx) {

  int                client_fd = ctx->client_fd;
  PseudoPacketHeader header = {0};

  // read destination-fname length (incl terminal NULL)
  uint64_t len;
  NEED_0( read_raw(client_fd, (char*)&len, sizeof(len)) );
  len = ntoh64(len);
  NEED( len <= FNAME_SIZE );

  // read fname
  char fname[FNAME_SIZE];
  NEED_0( read_raw(client_fd, (char*)&fname, len) );
  NEED( fname[len-1] == 0 );    // caller sent terminal-NULL?

  // perform op
  int rc = rename(ctx->fname, fname);

  // send ACK with return-code
  NEED_0( write_pseudo_packet(client_fd, CMD_ACK_CMD, rc, NULL) );

  return rc;
}



// TBD: do the stat, translate fields to net-byte-order, ship to client.
//      We will want write_stat()/read_stat() functions in skt_common.
int server_stat(ThreadContext* ctx) {
  fprintf(stderr, "server_stat('%s' not implemented\n", ctx->fname);
  ctx->flags |= CTX_THREAD_ERR;
  return -1;
}









// NOTE: To make our lockless interaction with the ThreadContext work, We
//     need to do the following: (a) before exiting, reset
//     <ctx>->flags.  At that point, assume that all contents of the
//     referenced <ctx> may immediately be overwritten.

void* server_thread(void* arg) {
  ThreadContext* ctx = (ThreadContext*)arg;

  // cleanup fd's etc, if we pthread_exit(), or get cancelled
  // NOTE: This isn't actually a function, but rather a butt-ugly macro
  //       ending in '{', where the coresponding pthread_cleanup_pop()
  //       macro supplies the closing '}'
  pthread_cleanup_push(shut_down_thread, arg);

  // shorthand
  int                  client_fd = ctx->client_fd;
  PseudoPacketHeader*  hdr       = &ctx->hdr;
  char*                fname     = ctx->fname;

  // read initial header (incl client command)
  if (read_pseudo_packet_header(client_fd, hdr)) {
    DBG("failed to read pseudo-packet header\n");
    pthread_exit(ctx);
  }

  // maybe read fname
  switch (hdr->command) {
  case CMD_PUT:
  case CMD_GET:
  case CMD_DEL:
  case CMD_STAT:
  case CMD_CHOWN:
  case CMD_RENAME:
    read_fname(client_fd, fname, hdr->length);
  };

  // always print command and arg for log
  printf("server_thread (fd=%d): %s %s\n", client_fd, command_str(hdr->command), fname);

  // perform command
  switch (hdr->command) {
  case CMD_PUT:    server_put(ctx);     break;
  case CMD_GET:    server_get(ctx);     break;
  case CMD_DEL:    server_del(ctx);     break;
  case CMD_STAT:   server_stat(ctx);    break;
  case CMD_CHOWN:  server_chown(ctx);   break;
  case CMD_RENAME: server_rename(ctx);  break;

  default:
    fprintf(stderr, "unsupported op: '%s'\n", command_str(hdr->command));
    ctx->flags |= CTX_THREAD_ERR;
  }


  // cleanup, and release context for use by another thread
  pthread_cleanup_pop(1);
}




// TBD: There should be a separate reaper-thread that periodically
//      cleans up terminated threads (e.g. take over our branch that
//      looks for CTX_THREAD_EXIT), instead of us doing it inline
//      while someone is waiting for service.
//

int find_available_conn() {
  int i;
  for (i=0; i<MAX_SOCKET_CONNS; ++i) {

    if (! conn_list[i].ctx.flags) {
      memset(&conn_list[i].ctx, 0, sizeof(conn_list[i].ctx));
      return i;
    }

    else if (conn_list[i].ctx.flags & CTX_THREAD_EXIT) {
      // TBD: handle threads that return failure?
      pthread_join(conn_list[i].thr, NULL);
      conn_list[i].ctx.flags = 0;
      memset(&conn_list[i].ctx, 0, sizeof(conn_list[i].ctx));
      return i;
    }
  }

  return -1;
}


// create a new thread to handle interactions through this fd.
// TBD: re-use threads from a pool.
int push_thread(int client_fd) {
  int  i = find_available_conn(); // does cleanup, and wipe to zeros
  if (i < 0)
    return -1;

  conn_list[i].ctx.client_fd = client_fd;
  conn_list[i].ctx.flags |= CTX_PRE_THREAD;

  DBG("connection[%d] <- fd=%d\n", i, client_fd);
  NEED_0( pthread_create(&conn_list[i].thr, NULL, server_thread, &conn_list[i].ctx) );

  return 0;
}



int
main(int argc, char* argv[]) {

  // cmd-line gives us our server-number, which determines our socket-name
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <port>\n", argv[0]);
    exit(1);
  }

  char*  port_str = argv[1];
  errno = 0;
  int    port     = strtol(argv[1], NULL, 10);
  if (errno) {
    char errmsg[128];
    sprintf("couldn't read integer from '%s'", argv[1]);
    perror(errmsg);
    abort();
  }

  // for UNIX sockets, this is an fname.  for INET this is just for diagnostics
  sprintf(server_name, "%s_%02d", SOCKET_NAME_PREFIX, port);


  // be sure to close the connection, if we are terminated by a signal
  struct sigaction sig_act;
  sig_act.sa_handler = sig_handler;
  sigaction(SIGTERM, &sig_act, NULL);
  sigaction(SIGINT,  &sig_act, NULL);
  sigaction(SIGPIPE, &sig_act, NULL);
  sigaction(SIGABRT, &sig_act, NULL);


  // --- initialize the sockaddr struct
#ifdef UNIX_SOCKETS
  struct sockaddr_un  s_addr;
  struct sockaddr_un* s_addr_ptr = &s_addr;
  socklen_t           s_addr_len = sizeof(struct sockaddr_un);
  
  socklen_t           c_addr_size;
  struct sockaddr_un  c_addr;

  memset(&s_addr, 0, s_addr_len);
  (void)unlink(server_name);
  strcpy(s_addr.sun_path, server_name);
  s_addr.sun_family = AF_UNIX;


#elif (defined RDMA_SOCKETS)
  struct rdma_addrinfo  hints;
  struct rdma_addrinfo* res;

  memset(&hints, 0, sizeof(hints));
  //  hints.ai_port_space = RDMA_PS_TCP;
  hints.ai_port_space = RDMA_PS_IB;
  hints.ai_flags      = RAI_PASSIVE;

  // testing:
  hints.ai_flags |= RAI_FAMILY;
  //  hints.ai_family = AF_IB;

  int rc = rdma_getaddrinfo(NULL, (char*)port_str, &hints, &res);
  if (rc) {
    fprintf(stderr, "rdma_getaddrinfo() failed: %s\n", strerror(errno));
    exit(1);
  }

  struct sockaddr*  s_addr_ptr = (struct sockaddr*)res->ai_src_addr; /* src for server */
  socklen_t         s_addr_len = res->ai_src_len;
# define  SKT_FAMILY  res->ai_family


#else // IP sockets
  socklen_t           c_addr_size;
  struct sockaddr_in  c_addr;

  struct sockaddr_in  s_addr;
  struct sockaddr_in* s_addr_ptr = &s_addr;
  socklen_t           s_addr_len = sizeof(struct sockaddr_in);
  
  memset(&s_addr, 0, s_addr_len);
  s_addr.sin_family      = AF_INET;
  s_addr.sin_addr.s_addr = INADDR_ANY;
  s_addr.sin_port        = htons(port);
#endif


 // --- open socket as server, and wait for a client
  REQUIRE_GT0( socket_fd = SOCKET(SKT_FAMILY, SOCK_STREAM, 0) );


  // --- When a server dies or exits, it leaves a connection in
  //     TIME_WAIT state, which is eventually cleaned up.  Meanwhile,
  //     trying to restart the server tells you that the "socket is
  //     already in use".  This setting allows the restart to just
  //     work.
  int enable = 1;
  REQUIRE_0( SETSOCKOPT(socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) );

  // int disable = 0;
  // REQUIRE_0( RSETSOCKOPT(socket_fd, SOL_RDMA, RDMA_INLINE, &disable, sizeof(disable)) );

  // you'd think we should do this on client_fd after the accept(), but that fails, and this succeeds
  unsigned mapsize = MAX_SOCKET_CONNS; // max number of riomap'ed buffers
  REQUIRE_0( RSETSOCKOPT(socket_fd, SOL_RDMA, RDMA_IOMAPSIZE, &mapsize, sizeof(mapsize)) );



  REQUIRE_0( BIND(socket_fd, (struct sockaddr*)s_addr_ptr, s_addr_len) );
  main_flags |= MAIN_BIND;

  REQUIRE_0( LISTEN(socket_fd, SOMAXCONN) );
  main_flags |= MAIN_SOCKET_FD;
  printf("%s listening\n", server_name);


  // receive connections and spin off threads to handle them
  while (1) {

    int client_fd;
    ///  REQUIRE_GT0( client_fd = ACCEPT(socket_fd, (struct sockaddr*)&c_addr, &c_addr_size) );
    REQUIRE_GT0( client_fd = ACCEPT(socket_fd, NULL, 0) );
    DBG("main: connected fd=%d\n", client_fd);

    if (push_thread(client_fd)) {
      fprintf(stderr, "main: couldn't allocate thread, dropping fd=%d\n", client_fd);
      SHUTDOWN(client_fd, SHUT_RDWR);
      CLOSE(client_fd);
    }
  }

  shut_down();
  return 0;
}
