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
#include <stdint.h>
#include <signal.h>
#include <stdlib.h>             // strtol()
#include <limits.h>             // PATH_MAX
#include <unistd.h>             // usleep(), fork()
#include <string.h>             // strcpy()
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef USE_PROCS
#  include <pthread.h>
#endif

#include "skt_common.h"



// These are now only used in main_flags
#define  MAIN_BIND         0x0001
#define  MAIN_SOCKET_FD    0x0002

// These are now only used in ThreadContext.flags
#define  CTX_PRE_THREAD   0x0010 /* client_fd has been opened */
#define  CTX_THREAD_EXIT  0x0020
#define  CTX_THREAD_ERR   0x0040

// #define  CTX_RIOMAPPED    0x0100 /* now done in ThreadContext.handle.flags */
// #define  CTX_FILE_OPEN    0x0200 /* now we just look at ctx->file_fd */
#define  CTX_EOF          0x0400


static unsigned char  main_flags = 0;

static char server_name[MAX_SOCKET_NAME_SIZE +1];

static int  socket_fd;               // main listens to this


// command-line '-d' provides restricted dir-tree where files may be affected
const char*   dir_root = NULL;
size_t        dir_root_len;

// command-line '-r' [option] says whether to run a reaper-thread
int           reap = 0;



// all the state needed to make server-threads thread-safe.
//
// NOTE: The point of Handle.rio_buf, is to store a pointer to the
//     buffer that is provided to riomap(), in server_put(), so that
//     we can riounmap it, in shut_down_thread().  Currently, we are
//     just allocating this on the stack in server_put(), which means
//     that it is out of scope in shut_down_thread().  Apparently,
//     this is fine.  All that riounmap really cares about is the
//     *address* of the buffer that was mapped.
//
typedef struct {
  volatile int        flags;     // lockless: see ServerConnection 
  int                 err_no;    // TBD
  PseudoPacketHeader  hdr;       // read/write "pseudo-packets" to/from socket
  int                 pos;       // index in conn_list[], for diagnostics

  SocketHandle        handle;    // socket to peer

  int                 file_fd;   // local file for GET/PUT  
  char                fname[FNAME_SIZE];
} ThreadContext;

#define IS_ACTIVE(CTX)  (  ((CTX)->flags & (CTX_PRE_THREAD | CTX_THREAD_EXIT))  == CTX_PRE_THREAD  )



// --- our record of existing connections
//
// NOTE: We avoid the need for locking by taking some care: main only
//    sets ctx.flags when they are zero.  Threads set a different flag
//    on exit.  When main sees this flag set, it can join and reset.
typedef struct ServerConnection {
#ifdef USE_PROCS
  int            pid;
#else
  pthread_t      thr;
#endif
  ThreadContext  ctx;
} SConn;

SConn  conn_list[MAX_SOCKET_CONNS];

// // lock for access to conn_list[] elements (not needed)
// pthread_mutex_t conn_lock;


// --- The reaper-thread tracks handle->stream_pos for all connections
//     in conn_list[].  If the thread doesn't move within the given
//     timeout-period, the reaper will cancel it.

ssize_t         reap_list[MAX_SOCKET_CONNS]; // stream_pos, or -1

const size_t    reap_timeout_sec = 10;

// lock for access to reap_list[] elements
pthread_mutex_t reap_mtx = PTHREAD_MUTEX_INITIALIZER;

pthread_t       reap_thr;



// clean-up for a given thread.
// Only ever called from the cleanup handler of an active thread.
//
// We only deal with the client_fd, and file_fd.
// The listening socket is shut-down by main.
//
// Printing <pos> allows easy correlation of reaper-activity with
// corresponding thread-shutdowns.

void
shut_down_thread(void* arg) {
  ThreadContext* ctx = (ThreadContext*)arg;
  DBG("pos: %d, peer_fd: %d, file_fd: %d\n", ctx->pos, ctx->handle.peer_fd, ctx->file_fd);

  // maybe close the local file
  if (ctx->file_fd > 0) {

#ifndef SKIP_FILE_WRITES
    if (ctx->hdr.command == CMD_PUT) {
      EXPECT_0( fsync(ctx->file_fd) );	// for consistent sustained ZFS throughput
      EXPECT_0( close(ctx->file_fd) );
    }
#endif

#ifndef SKIP_FILE_READS
    if (ctx->hdr.command == CMD_GET)
      EXPECT_0( close(ctx->file_fd) );
#endif

    ctx->file_fd = 0;
  }

  if (ctx->flags & CTX_PRE_THREAD) {
    SocketHandle*  handle = &ctx->handle; // shorthand

    DBG("closing client_fd %d\n", handle->peer_fd);
    shut_down_handle(handle);
  }

  ctx->flags |= CTX_THREAD_EXIT;
}



// main uses this for surprise exits
void
shut_down_server() {

  // shutdown reaper
  DBG("stopping reaper\n");
  pthread_cancel(reap_thr);
  pthread_join(reap_thr, NULL);
  // pthread_mutex_destroy(&reap_mtx);
  DBG("done.\n");

  // shutdown all connection-handling threads
  int i;
  for (i=0; i<MAX_SOCKET_CONNS; ++i) {
    if (IS_ACTIVE(&conn_list[i].ctx)) {
      DBG("cancelling conn %d ...", i);
      pthread_cancel(conn_list[i].thr);
      pthread_join(conn_list[i].thr, NULL);
      DBG("done.\n");
    }
  }

  // close up shop
  if (main_flags & MAIN_BIND) {
    DBG("unlinking '%s'\n", server_name);
    (void)unlink(server_name);
  }
  if (main_flags & MAIN_SOCKET_FD) {
    DBG("closing socket_fd %d\n", socket_fd);
    CLOSE(socket_fd);
  }
}


// for main()
static void
sig_handler(int sig) {
  ERR("sig_handler exiting on signal %d\n", sig);
  shut_down_server();
  exit(0);
}





// --- read <fname> from peer (client)
//
// <fname_length> is the size they told us it would be.
// <max_size> is the space available in <fname>.  It must be big enough
//     to hold the canonicalized version of the fname.
//
// name must include terminal-NULL (which must be part of <fname_size>)
//
// NOTE: We require the fully-canonicalized path to be a proper
//     sub-path of <dir_root> (i.e. the direcotry-tree indicated on
//     the command-line, when the server was started.
// 
int read_fname(int peer_fd, char* fname, size_t fname_size, size_t max_size) {

  if (fname_size > max_size) {
    ERR("fname-length %llu exceeds maximum %u\n", fname_size, max_size);
    return -1;
  }

  // read fname from the peer
  NEED_0( read_raw(peer_fd, fname, fname_size) );
  if (!fname[0] || fname[fname_size -1]) {
    ERR("bad fname\n");
    return -1;
  }
  DBG("fname: %s\n", fname);


  // validate canonicalized name, using "<dir>" from server command-line.
  //
  // realpath() thinks we want to know whether the path exists,
  // ignoring possible cases where the canonicalized path could be
  // produced regardless of whether it exists or not.
  //
  // Let's try a simpler question: does the fully-canonicalized
  // parent-directory exist?  [Instead of copying the entire path in
  // order to safely extract the parent-dir with basename(), let's try
  // a low-impact alternative.]
  char   canon[PATH_MAX+1];
  size_t canon_len = 0;

  char*  last_slash = strrchr(fname, '/');
  if (last_slash) {
    *last_slash = 0;
    char* path = realpath(fname, canon); // canonicalize the parent-dir?
    if (!path)
      ERR("realpath(%s) failed (parent-directory): %s\n", fname, strerror(errno));
    
    *last_slash = '/';               // restore original fname
    if (!path)
      return -1;

    // canonicalized parent-dir exists.  create fully-canonicalized
    // path by appending the possibly-non-existent fname.
    canon_len = strlen(canon);
    size_t last_slash_len = strlen(last_slash);
    if ((canon_len + last_slash_len +1) > PATH_MAX) {
      ERR("hand-built realpath (%s%s) would be too big\n", canon, last_slash);
      return -1;
    }
    strcat(canon, last_slash);
    canon_len += last_slash_len;
  }
  else if (strrchr(dir_root, '/')) {
    ERR("path %s has no '/', so obvisouly it can't be under '%s'\n", fname, dir_root);
    return -1;
  }
  else {
    ERR("Neither path '%s' nor dir_root '%s' have slashes.  "
        "Let's hope you know what you're doing\n",
        fname, dir_root);
    strncpy(canon, fname, PATH_MAX);
    canon[PATH_MAX] = 0;
    canon_len = strlen(canon);
  }


  // make sure canonicalized path is under <dir_root>.
  if (strncmp(canon, dir_root, dir_root_len)
      || (canon[dir_root_len] != '/')) {

    ERR("illegal path: '%s'  (canonicalized path: '%s' does not begin with '%s')\n",
        fname, canon, dir_root);
    return -1;
  }

  NEED( (canon_len <= max_size) );
  strcpy(fname, canon);
 
  return 0;
}





// We want to use skt_read() and skt_write(), so that our GET/PUT
// impls can just use the symmetrical opposite of what client uses.
// (This will assure protocols are consistent.)  That suggests we
// would use a SocketHandle, like clients do.  Unlike clients, we
// don't "open" with a path to a server, but we can still initialize a
// SocketHandle, so that e.g. skt_read()/skt_write() can be used
// normally.
//
// The CMD_NULL command causes read_init()/write_init(),
// to suppress sending GET/PUT to the peer.
//
// NOTE: We assume this is the SocketHandle inside a ThreadContext,
//     which gets zero'ed before a thread is spun up, so we don't
//     bother wiping it clean.
//
// NOTE: This shouldn't be called "fake".  It's a real "open", on the
//     server side, that initializes protocol with the other end to
//     allow skt_read()/skt_write(), and setting up so that
//     skt_close() will do the shut-down hand-shake, as well.
//
//     If all you want to do is read_raw() or write_raw(), you don't
//     need this.  Instead, (I think) you can just call basic_init()
//     on your handle, and shut_down_handle() at "close" time.
//
int fake_open(SocketHandle* handle, int flags, char* buf, size_t size) {
  DBG("fake_open(0x%llx, 0x%x, 0x%llx, %lld)\n", (size_t)handle, flags, (size_t)buf, size);

  // RD/WR with RDMA would require riomaps on both ends, or else
  // two different channels, each with a single riomap.
  if (flags & (O_RDWR)) {
    errno = ENOTSUP;		// TBD?
    return -1;
  }

  handle->flags |= HNDL_CONNECTED;
  if (flags & O_WRONLY) {
    handle->flags |= HNDL_PUT;
    NEED_0( write_init(handle, CMD_NULL) ); // don't send PUT

#if 0
    // Early experiments seemed to show that the server-side can't set
    // RDMA_IOMAPSIZE on the fd we get from raccept(), but must
    // instead do it on the socket fd we get from rsocket(), which
    // then applies to all the raccpet() sockets.
    //
    // if it turns out we do need this, then instead of having it
    // here, move it from skt_open() to write_init(), and everybody
    // (client and server) can get at it there.
    unsigned mapsize = 1; // max number of riomap'ed buffers (on this fd ?)
    NEED_0( RSETSOCKOPT(handle->peer_fd, SOL_RDMA, RDMA_IOMAPSIZE, &mapsize, sizeof(mapsize)) );
#endif
  }
  else {
    handle->flags |= HNDL_GET;
    NEED_0( read_init(handle, CMD_NULL, buf, size) ); // don't send GET
  }

  return 0;
}


// This is like fake_open(), but we know that we are ONLY going to be
// exchanging pseudo-packet-headers with the client, and are NEVER
// going to call skt_read() or skt_write() to exchange data.
// Therefore, we can bypass the cost of doing a riomap on either end,
// while still assuring that the protocol is cleaned up by skt_close()
// on both ends.

// NOTE: To implement API operations that are synchronous (from the
//    client's perspective), the client-side should skt_open(WR), and
//    server-side fake_open_basic(RD).  For async operations,
//    skt_open(RD)/fake_open_basic(WR).

int fake_open_basic(SocketHandle* handle, int flags) {
  DBG("fake_open_basic(0x%llx, 0x%x, 0x%llx, %lld)\n", (size_t)handle, flags);

  // this isn't even meaningful for the tokens-only exchanges we will
  // be doing.  It would apply to data.  We can always exchange
  // control-info in both directions.
  if (flags & (O_RDWR)) {
    errno = ENOTSUP;
    return -1;
  }

  handle->flags |= HNDL_CONNECTED;
  if (flags & O_WRONLY)
    handle->flags |= HNDL_PUT;
  else
    handle->flags |= HNDL_GET;

  NEED_0( basic_init(handle, CMD_NULL) ); // don't send GET/PUT

  return 0;
}




// PUT (server-side) -- READ from the socket
//
// client is calling skt_open/skt_write/skt_close, sending us data to
// go into a file.  We are calling fake_open/skt_read/
// shut_down_thread.
//
// Return 0 for success, non-zero for fail.

int server_put(ThreadContext* ctx) {

  SocketHandle*        handle    = &ctx->handle;
  char*                fname     = ctx->fname;

  char                 buf[SERVER_BUF_SIZE]  __attribute__ (( aligned(64) ));
  

  // open socket for reading (client writes, we read)
  fake_open(handle, O_RDONLY, buf, SERVER_BUF_SIZE);

  // open local file for writing (unless file-writes are suppressed)
#ifndef SKIP_FILE_WRITES
  ctx->file_fd = open(fname, (O_WRONLY | O_CREAT | O_TRUNC), 0660);
  if (ctx->file_fd < 0) {
    ERR("couldn't open '%s' for writing: %s\n",
        fname, strerror(errno));
    return -1;
  }
  DBG("opened file '%s'\n", fname);
#endif



  // --- PUT: server reads from socket, writes to file
  ssize_t bytes_moved = copy_socket_to_file(handle, ctx->file_fd, buf, SERVER_BUF_SIZE);
  NEED( bytes_moved >= 0 );



  // close socket
  EXPECT_0( skt_close(handle) );
  return 0;
}








// GET (server-side) -- WRITE to the socket
//
// Basically a mirror image of PUT, and similar to
// skt_open/write/close().  We set the IOMAPSIZE sockopt, client does
// the riomap and sends us the offset, then we read from our file and
// call riowrite() to RDMA buffers over to her mapped buffer, sending
// "DATA n" pseudo-packets after each one.  We always wait for an "ACK
// n" response before continuing.

int server_get(ThreadContext* ctx) {

  SocketHandle*        handle    = &ctx->handle;
  char*                fname     = ctx->fname;

  char                 buf[SERVER_BUF_SIZE]  __attribute__ (( aligned(64) ));


  // open socket for writing (we write, client reads)
  fake_open(handle, O_WRONLY, buf, SERVER_BUF_SIZE);

  // open local file for reading (unless file-reads are suppressed)
#ifndef SKIP_FILE_WRITES
  ctx->file_fd = open(fname, (O_RDONLY));
  if (ctx->file_fd < 0) {
    ERR("couldn't open '%s' for reading: %s\n",
        fname, strerror(errno));
    return -1;
  }
  DBG("opened file '%s'\n", fname);
#endif



  // --- GET: server reads from file, writes to socket
  ssize_t bytes_moved = copy_file_to_socket(ctx->file_fd, handle, buf, SERVER_BUF_SIZE);
  NEED( bytes_moved >= 0 );


  // close socket
  EXPECT_0( skt_close(handle) );
  return 0;
}





int server_del(ThreadContext* ctx) {
  if (unlink(ctx->fname)) {
    ERR("couldn't unlink '%s'\n", ctx->fname);
    ctx->flags |= CTX_THREAD_ERR;
    return -1;
  }
  return 0;
}



int server_chown(ThreadContext* ctx) {

  SocketHandle*      handle    = &ctx->handle;
  char*              fname     = ctx->fname;
  int                client_fd = handle->peer_fd;
  PseudoPacketHeader header = {0};

  // we only use the control-channel
  NEED_0( fake_open_basic(handle, O_RDONLY) );

  // read UID
  uint64_t uid_buf;
  NEED_0( read_raw(client_fd, (char*)&uid_buf, sizeof(uid_buf)) );
  uid_t uid = ntoh64(uid_buf);

  // read GID
  uint64_t gid_buf;
  NEED_0( read_raw(client_fd, (char*)&gid_buf, sizeof(gid_buf)) );
  gid_t gid = ntoh64(gid_buf);

  // perform op
  int rc = lchown(fname, uid, gid);
  DBG("result: %d %s\n", rc, (rc ? strerror(errno) : ""));

  // send ACK with return-code
  NEED_0( write_pseudo_packet(client_fd, CMD_RETURN, rc, NULL) );

  // skt_chown() will call skt_close(), so send an ACK 0, like
  // we were closing a normal handle.
  NEED_0( write_pseudo_packet(client_fd, CMD_ACK, 0, NULL) );

  // close transaction with client
  NEED_0( skt_close(handle) );
 
  return rc;
}


int server_rename(ThreadContext* ctx) {

  SocketHandle*      handle    = &ctx->handle;
  char*              fname     = ctx->fname;
  int                client_fd = handle->peer_fd;
  PseudoPacketHeader header = {0};


  // we only use the control-channel
  NEED_0( fake_open_basic(handle, O_RDONLY) );

  // read new-fname length (incl terminal NULL)
  uint64_t len;
  NEED_0( read_raw(client_fd, (char*)&len, sizeof(len)) );
  len = ntoh64(len);
  NEED( len <= FNAME_SIZE );

  // read new-fname
  char new_fname[FNAME_SIZE];
  NEED_0( read_fname(client_fd, new_fname, len, FNAME_SIZE) );


  // perform op
  int rc = rename(fname, new_fname);
  DBG("result: %d %s\n", rc, (rc ? strerror(errno) : ""));

  // send ACK with return-code
  NEED_0( write_pseudo_packet(client_fd, CMD_RETURN, rc, NULL) );

  // skt_chown() will call skt_close(), so send an ACK 0, like
  // we were closing a normal handle.
  NEED_0( write_pseudo_packet(client_fd, CMD_ACK, 0, NULL) );

  // finish transaction with client
  NEED_0( skt_close(handle) );

  return rc;
}



// Do the stat, translate fields to net-byte-order, ship to client.
// We're actually doing this over RDMA to try to keep the CPU load down.
//
// client reads (read_raw) results from the stream.  The first value
// is returned as a pseudo-packet with the key CMD_RETURN, and the
// value an ssize_t, to be interpreted differently in the following
// two cases:
//
// (1) if lstat fails
//    (a) the ssize_t is the negative errno (as an ssize_t)
//    (b) there ain't no (b).
//
// (2) if lstat succeeds
//    (a) the ssize_t is positive sizeof(struct stat) on the server
//    (b) 13 values as contiguous network-byte-order binary values,
//        each the same size as the actual value in the stat struct.
//
// Return:
//   We return 0 unless one of the NEED macros failed.
//   Failure of the call to stat() is not a failure for this function.
//
// TBD: We're using the same approach and rationale for not "opening"
//     RDMA as was used for server_rename().  However, it might make
//     more sense, here, to go ahead and open a channel to allow
//     sending teh stat info via RDMA.  Question, when there are a ton
//     of stats going on, will it be better to avoid the overhead of
//     spinning up RDMA channels, or better to avoid burdening the CPU
//     with all these sends.
//
//     Another option is to just RDMA our local stat struct, along
//     with a key that indicates our endian-ness.  If the client
//     happens to have the same endian-ness, we can both avoid the
//     cost of the network-byte-order computations, and local
//     data-movement.
//
// TBD: The jHANDLER/jNEED/jSEND_VALUE stuff is now overkill.  Threads
//     now always clean-up their handles via shut_down_thread() ->
//     shut_down_handle().

int server_stat(ThreadContext* ctx) {

  SocketHandle*      handle    = &ctx->handle;
  char*              fname     = ctx->fname;
  struct stat        st;

  DBG("stat %s\n", fname);


#if 1
  // open socket for writing (we write, client reads)
  //  fake_open(handle, O_WRONLY, buf, STAT_DATA_SIZE);
  fake_open_basic(handle, O_RDONLY);

  // jNEED() failures run this before exiting
  jHANDLER(jskt_close, handle);

#else
  // jNEED() failures run this before exiting
  jHANDLER(jshut_down_handle, handle);
#endif

  // stat local file
  // Failure doesn't mean the server-routine failed
  if (lstat(fname, &st)) {
    // case (1), stat failed
    DBG("stat failed: %s\n", strerror(errno));

    // (a) send ACK with return-code == negative errno
    NEED_0( write_pseudo_packet(handle->peer_fd, CMD_RETURN, -errno, NULL) );
  }
  else {
    // case (2), stat succeeded
    DBG("stat OK\n");

    // (a) send ACK with return-code == sizeof(struct stat), for crude validation
    jNEED_0( write_pseudo_packet(handle->peer_fd, CMD_RETURN, sizeof(struct stat), NULL) );


    // (b) "send" individual field values into the buffer
    char   buffer[STAT_DATA_SIZE];
    char*  buf = buffer;
  
    jSEND_VALUE(buf, st.st_dev);     /* ID of device containing file */
    jSEND_VALUE(buf, st.st_ino);     /* inode number */
    jSEND_VALUE(buf, st.st_mode);    /* protection */
    jSEND_VALUE(buf, st.st_nlink);   /* number of hard links */
    jSEND_VALUE(buf, st.st_uid);     /* user ID of owner */
    jSEND_VALUE(buf, st.st_gid);     /* group ID of owner */
    jSEND_VALUE(buf, st.st_rdev);    /* device ID (if special file) */
    jSEND_VALUE(buf, st.st_size);    /* total size, in bytes */
    jSEND_VALUE(buf, st.st_blksize); /* blocksize for file system I/O */
    jSEND_VALUE(buf, st.st_blocks);  /* number of 512B blocks allocated */
    jSEND_VALUE(buf, st.st_atime);   /* time of last access */
    jSEND_VALUE(buf, st.st_mtime);   /* time of last modification */
    jSEND_VALUE(buf, st.st_ctime);   /* time of last status change */

    // send the whole buffer in one shot, so client can just read it all
#if 0
    ssize_t write_count = skt_write_all(handle, buffer, STAT_DATA_SIZE);
    jNEED( write_count == STAT_DATA_SIZE );
#else
    jNEED_0( write_raw(handle->peer_fd, buffer, STAT_DATA_SIZE) );
#endif

  }  

#if 1
  // close
  EXPECT_0( skt_close(handle) );
#else
  // close
  shut_down_handle(handle);
#endif

  return 0;
}









// ...........................................................................
// server_thread
//
// This is the thread that gets spun up to handle any new connection.
// Figure out what the client wants (by reading a pseudo-packet), then
// dispatch the function to handle that task.
//
// NOTE: To make our lockless interaction with the ThreadContext work, We
//     need to do the following: (a) before exiting, reset
//     <ctx>->flags.  At that point, assume that all contents of the
//     referenced <ctx> may immediately be overwritten.
// ...........................................................................

void* server_thread(void* arg) {
  ThreadContext* ctx = (ThreadContext*)arg;

  // cleanup fd's etc, if we pthread_exit(), or get cancelled.
  // NOTE: This isn't actually a function, but rather a butt-ugly
  //     macro ending in '{', where the corresponding
  //     pthread_cleanup_pop() macro (below) supplies the closing '}'.

  pthread_cleanup_push(shut_down_thread, arg);

  // shorthand
  SocketHandle*        handle    = &ctx->handle;
  int                  client_fd = handle->peer_fd;
  PseudoPacketHeader*  hdr       = &ctx->hdr;
  char*                fname     = ctx->fname;

  int rc = 0;

  // read client command
  if (read_pseudo_packet_header(client_fd, hdr)) {
    DBG("failed to read pseudo-packet header\n");
    pthread_exit(ctx);
  }
  DBG("\n");
  DBG("server thread: %s\n", command_str(hdr->command));

  // maybe read fname, if command implies one
  switch (hdr->command) {
  case CMD_PUT:
  case CMD_GET:
  case CMD_DEL:
  case CMD_STAT:
  case CMD_CHOWN:
  case CMD_RENAME:
    rc = read_fname(client_fd, fname, hdr->size, FNAME_SIZE);
  };

  if (! rc) {
    // always print command and arg for log
    printf("server_thread (fd=%d): %s %s\n", client_fd, command_str(hdr->command), fname);

    // perform command
    switch (hdr->command) {
    case CMD_PUT:    rc = server_put(ctx);     break;
    case CMD_GET:    rc = server_get(ctx);     break;
    case CMD_DEL:    rc = server_del(ctx);     break;
    case CMD_STAT:   rc = server_stat(ctx);    break;
    case CMD_CHOWN:  rc = server_chown(ctx);   break;
    case CMD_RENAME: rc = server_rename(ctx);  break;

    default:
      ERR("unsupported op: '%s'\n", command_str(hdr->command));
      rc = -1;
    }
  }

  if (rc)
    ctx->flags |= CTX_THREAD_ERR;

  // cleanup, and release context for use by another thread
  pthread_cleanup_pop(1);
}



// periodically sweep the existing threads, and terminate any of them
// that haven't moved data within the timeout-period.  We only do the
// pthread_cancel, not the join.  That's because we run periodically,
// but find_available_conn() runs as needed.  If we were to do the
// join, we'd have to add more locking around accesses to the
// context-flags, in find_available_conn().  As is, the thread
// clean-up handlers will set the CTX_THREAD_EXIT flag, and
// find_available_conn() will see that.

void* reap_thread(void* arg) {

  while (1) {

    sleep(reap_timeout_sec);
    // ERR("reaper: awake\n");

    pthread_mutex_lock(&reap_mtx);

    // compare current handle.stream_pos with last-seen value, for all connections
    int i;
    for (i=0; i<MAX_SOCKET_CONNS; ++i) {

      if (IS_ACTIVE(&conn_list[i].ctx)) {
        size_t current_pos = conn_list[i].ctx.handle.stream_pos;

        // --- already reaped.  Hasn't exited yet?  find_available_conn() hasn't used it?
        if (reap_list[i] == -2)
          continue;

        // --- first sighting of this connection?  Note current pos
        else if (reap_list[i] < 0) {
          // ERR("reaper [%3d]: first sighting\n", i);
          reap_list[i] = current_pos;
        }

        // --- if nothing has moved, kill the thread (and the connection)
        else if (reap_list[i] == current_pos) {
          ERR("reaper [%3d]: reaping  (peer_fd: %d, file_fd: %d)\n",
              i, conn_list[i].ctx.handle.peer_fd, conn_list[i].ctx.file_fd);
          reap_list[i] = -2;
          pthread_cancel(conn_list[i].thr); // cleanup sets CTX_THREAD_EXIT
        }

        // --- if data has moved, track the current position
        else
          reap_list[i] = current_pos;
      }

      else
        reap_list[i] = -1;
    }

    pthread_mutex_unlock(&reap_mtx);
  }

  return NULL;
}


// Return an index in conn_list[], which push_thread() can use to hold
// a new thread.  Or, return -1 for failure.
//
// We use <pos> to pick up the search from wherever we left off after
// the previous call.
//
// NOTE: There is a separate reaper-thread that periodically cleans up
//      terminated threads.  When it calls pthread_cancel(), thread
//      cleanup-handlers should eventually set CTX_THREAD_EXIT in the
//      corresponding ThreadContext flags.  At that point, we can
//      reuse that context.
//
int find_available_conn(int client_fd) {
  static int pos=MAX_SOCKET_CONNS;
  int        result = -1;
  int        i;

  pthread_mutex_lock(&reap_mtx);
  for (i=0; i<MAX_SOCKET_CONNS; ++i) {

    ++ pos;
    if (pos >= MAX_SOCKET_CONNS)
      pos = 0;

    if (! conn_list[pos].ctx.flags) {
      // unused slot
      result = pos;
      break;
    }

    else if (conn_list[pos].ctx.flags & CTX_THREAD_EXIT) {
      // thread exited, or was cancelled
      // TBD: handle threads that return failure?
      pthread_join(conn_list[pos].thr, NULL);
      result = pos;
      break;
    }
  }


  if (result >= 0) {
    DBG("connection[%d] <- fd=%d\n", i, client_fd);
    memset(&conn_list[pos].ctx, 0, sizeof(conn_list[pos].ctx));

    conn_list[pos].ctx.pos             = pos;   // for diagnostics
    conn_list[pos].ctx.handle.peer_fd  = client_fd;
    conn_list[pos].ctx.handle.flags   |= HNDL_CONNECTED;
    conn_list[pos].ctx.flags          |= CTX_PRE_THREAD;

    reap_list[pos] = -1;
  }

  pthread_mutex_unlock(&reap_mtx);
  return result;
}


// create a new thread to handle interactions through this fd.
//
// NOTE: We are lock-free by virutue of the fact that we only write
//     CTX_PRE_THREAD before spin-up, and thread sets CTX_THREAD_EXIT
//     on exit.
//
// TBD: re-use threads from a pool.
int push_thread(int client_fd) {
  int  i = find_available_conn(client_fd); // does cleanup, and wipe to zeros
  if (i < 0)
    return -1;

  NEED_0( pthread_create(&conn_list[i].thr, NULL, server_thread, &conn_list[i].ctx) );
  return 0;
}



void usage(const char* progname) {
  ERR("Usage: %s -p <port> -d <dir> [ -r ]\n", progname);
  ERR("  -p <port>   port on which the server should listen\n");
  ERR("  -d <dir>    server will allow clients to write arbitrary files under <dir>\n");
  ERR("                (but nowhere else)\n");
  ERR("  -r          use a 'reap' thread, to clean up stuck threads\n");
  exit(1);
}

int
main(int argc, char* argv[]) {

  const char* port_str = NULL;
  int         port = 0;

  int         reap = 0;

  int         c;
  while ( (c = getopt(argc, argv, "p:d:rh")) != -1) {
    switch (c) {
    case 'p':      port_str = optarg;    break;
    case 'd':      dir_root = optarg;    break;
    case 'r':      reap     = 1;         break;

    case 'h':
    default:
      usage(argv[0]);
      return -1;
    }
  }


  // validation of args
  if (! port_str)
    usage(argv[0]);
  if (! dir_root)
    usage(argv[0]);

  dir_root_len = strlen(dir_root);

  // parse <port>
  errno = 0;
  port = strtol(port_str, NULL, 10);
  if (errno) {
    char errmsg[128];
    sprintf("couldn't read integer from '%s'", port_str);
    perror(errmsg);
    abort();
  }




  // for UNIX sockets, this is an fname.  for INET this is just for diagnostics
  sprintf(server_name, "%s_%02d", SOCKET_NAME_PREFIX, port);


  // be sure to clean-up all threads, etc, if we are terminated by a signal
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
  hints.ai_port_space = RDMA_PS_TCP;
  //  hints.ai_port_space = RDMA_PS_IB;
  hints.ai_flags      = RAI_PASSIVE;

  // testing:
  //  hints.ai_flags |= RAI_FAMILY;
  //  hints.ai_family = AF_IB;

  int rc = rdma_getaddrinfo(NULL, (char*)port_str, &hints, &res);
  if (rc) {
    ERR("rdma_getaddrinfo() failed: %s\n", strerror(errno));
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
  // [see fake_open()]
  //   unsigned mapsize = MAX_SOCKET_CONNS; // max number of riomap'ed buffers
  unsigned mapsize = 1; // max number of riomap'ed buffers (for this fd?)
  REQUIRE_0( RSETSOCKOPT(socket_fd, SOL_RDMA, RDMA_IOMAPSIZE, &mapsize, sizeof(mapsize)) );



  REQUIRE_0( BIND(socket_fd, (struct sockaddr*)s_addr_ptr, s_addr_len) );
  main_flags |= MAIN_BIND;

  REQUIRE_0( LISTEN(socket_fd, SOMAXCONN) );
  main_flags |= MAIN_SOCKET_FD;
  printf("%s listening\n", server_name);


  // spin up reaper-thread to clean-up dead-beat connections
  int i;
  for (i=0; i<MAX_SOCKET_CONNS; ++i) {
    reap_list[i] = -1;
  }
  // REQUIRE_0( pthread_mutex_init(&reap_mtx, NULL) );

  if (reap)
    REQUIRE_0( pthread_create(&reap_thr, NULL, reap_thread, NULL) );

  

  // receive connections and spin off threads to handle them
  while (1) {

    ///  int client_fd = ACCEPT(socket_fd, (struct sockaddr*)&c_addr, &c_addr_size);
    int client_fd = ACCEPT(socket_fd, NULL, 0);
    if (client_fd < 0) {
      perror("failed accept()");
      continue;
    }

    DBG("main: connected fd=%d\n", client_fd);
    if (push_thread(client_fd)) {
      ERR("main: couldn't allocate thread, dropping fd=%d\n", client_fd);
      SHUTDOWN(client_fd, SHUT_RDWR);
      CLOSE(client_fd);
    }
  }

  shut_down_server();
  return 0;
}
