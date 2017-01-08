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

#include "socket_common.h"

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)


// These are now only used in main_flags
#define  _FLAG_BIND         0x0001
#define  _FLAG_SOCKET_FD    0x0002
// #define  _FLAG_CLIENT_FD    0x0004 /* now redundant with _FLAG_PRE_THREAD */
#define  _FLAG_PRE_THREAD   0x0010

// These are now only used in ThreadContext.flags
#define  _FLAG_THREAD_EXIT  0x0040
#define  _FLAG_THREAD_ERR   0x0080

#define  _FLAG_FILE_OPEN    0x0100
#define  _FLAG_EOF          0x0200


static unsigned char  main_flags = 0;


static char socket_name[MAX_SOCKET_NAME_SIZE +1];
static int  socket_fd;               // listen() to this
static int  client_fd;               // read/write to this
// static int  file_fd;                  // writing client data to file


// called from SKT_CHECK, to print diagnostics
static void socket_check_info(const char* expr) {
  printf("server %s:  running '%s'\n", socket_name, expr);
}



// all the state needed to make server-threads thread-safe.
typedef struct {
  volatile int        flags;	 // lockless: see ServerConnection 
  int                 err_no;	 // TBD
  PseudoPacketHeader  hdr;	 // read/write "pseudo-packets" to/from socket
  int                 client_fd; // socket
  int                 file_fd;	 // server-side file
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

#define MAX_SOCKET_CONNS  128

SConn conn_list[MAX_SOCKET_CONNS];

// // access to conn_list[] elements
// pthread_mutex_t conn_lock;



// clean-up for a given thread.
// Threads only handle the client_fd, and file_fd.
// The listening socket is shut-down by main.
void shut_down_thread(void* arg) {
  ThreadContext* ctx = (ThreadContext*)arg;

  // maybe close the local file
  if (ctx->flags & _FLAG_FILE_OPEN) {
     SKT_CHECK( close(ctx->file_fd) );
  }

  if (ctx->flags & _FLAG_PRE_THREAD) {
    fprintf(stderr, "shut_down_thread: closing client_fd %d\n", client_fd);
    SHUTDOWN(ctx->client_fd, SHUT_RDWR);
    CLOSE(ctx->client_fd);
  }

  ctx->flags |= _FLAG_THREAD_EXIT;
}


// main uses this for surprise exits
void
shut_down() {
  // shutdown all threads
  int i;
  for (i=0; i<MAX_SOCKET_CONNS; ++i) {
    if ((conn_list[i].ctx.flags & (_FLAG_PRE_THREAD | _FLAG_THREAD_EXIT))
	== _FLAG_PRE_THREAD) {
      fprintf(stderr, "shut_down: cancelling conn %d ...", i);
      pthread_cancel(conn_list[i].thr);
      pthread_join(conn_list[i].thr, NULL);
      fprintf(stderr, "done.\n");
    }
  }

  // close up shop
  if (main_flags & _FLAG_BIND) {
    fprintf(stderr, "shut_down: unlinking '%s'\n", socket_name);
    (void)unlink(socket_name);
  }
  if (main_flags & _FLAG_SOCKET_FD) {
    fprintf(stderr, "shut_down: closing socket_fd %d\n", socket_fd);
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










// ctx->hdr.command will be SKT_GET or SKT_PUT.
//
// For PUT, client is sending us data to go into a file
// For GET, we're reading from file and shipping to client.
//
// Return 0 for success, non-zero for fail.
//
int socket_get_or_put(ThreadContext* ctx) {
  char                 read_buf[SERVER_BUF_SIZE]  __attribute__ (( aligned(64) ));

  // shorthand
  int                  cmd       = ctx->hdr.command;
  int                  client_fd = ctx->client_fd;
  PseudoPacketHeader*  hdr       = &ctx->hdr;
  char*                fname     = ctx->fname;
  int                  o_flags   = ((cmd == SKT_PUT)
				    ? (O_WRONLY|O_CREAT|O_TRUNC)
				    : (O_RDONLY));
  int                  src_fd;
  int                  src_is_socket;
  int                  dst_fd;
  int                  dst_is_socket;


  // --- read from socket, write to file
  // TBD: Client should eventually send data as a series of DATA
  //     pseudo-packets, each with a length followed by that much
  //     data.  We'd then read SERVER_BUF_SIZE chunks out of that,
  //     for writing into the file.  This "packetization" of the
  //     data would allow out-of-band comms from the client (e.g.
  //     we could return a demand-driven set of ACKs, with
  //     checksums, to allow the client to validate the stream with
  //     out us having to require it).
  while (likely(! (ctx->flags & _FLAG_EOF))) {

    // --- open local file, if needed
    if (unlikely(! (ctx->flags & _FLAG_FILE_OPEN))) {

      // open with appropriate flags
      ctx->file_fd = open(fname, o_flags);
      if (ctx->file_fd < 0) {
	fprintf(stderr, "couldn't open '%s' for command '%s': %s\n",
		fname, command_str(cmd), strerror(errno));
	ctx->flags |= _FLAG_THREAD_ERR;
	return -1;
      }
      ctx->flags |= _FLAG_FILE_OPEN;
      DBG("opened file '%s'\n", fname);

      // prepare to copy data for GET/PUT
      if (cmd == SKT_PUT) {	// PUT: client_fd -> file_fd
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
    ssize_t read_total = read_buffer(src_fd, read_buf, SERVER_BUF_SIZE, src_is_socket);
    if (read_total < 0) {
      ctx->flags |= _FLAG_THREAD_ERR;
      break;
    }
    else if (read_total < SERVER_BUF_SIZE)
      ctx->flags |= _FLAG_EOF;


    // --- write buffer to <dest>
    if (write_buffer(dst_fd, read_buf, read_total, dst_is_socket)) {
      ctx->flags |= _FLAG_THREAD_ERR;
      break;
    }
  }
  DBG("copy-loop done.\n");


  // maybe close the local file we opened
  if (ctx->flags & _FLAG_FILE_OPEN) {
    close(ctx->file_fd);
    ctx->flags &= ~_FLAG_FILE_OPEN;
  }


#if 0
  // --- send an ACK to client, so they can close their socket
  static const uint32_t ack = 1;
  write_count = WRITE(client_fd, &ack, sizeof(uint32_t));
  DBG("write_count(ACK): %lld\n", write_count);
  if ((write_count < 0) || (write_count != 4)) {
    DBG("ACK failed\n");
    ctx->flags |= _FLAG_THREAD_ERR;
  }
#endif

  return 0;
}


int socket_del(ThreadContext* ctx) {
  if (unlink(ctx->fname)) {
    fprintf(stderr, "couldn't unlink '%s'\n", ctx->fname);
    ctx->flags |= _FLAG_THREAD_ERR;
    return -1;
  }
  return 0;
}


// TBD: do the stat, translate fields to net-byte-order, ship to client.
//      We will want write_stat()/read_stat() functions in socket_common.
int socket_stat(ThreadContext* ctx) {
  fprintf(stderr, "socket_stat('%s' not implemented\n", ctx->fname);
  ctx->flags |= _FLAG_THREAD_ERR;
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
  read_pseudo_packet_header(client_fd, hdr);

  // maybe read fname
  switch (hdr->command) {
  case SKT_PUT:
  case SKT_GET:
  case SKT_DEL:
  case SKT_STAT:
    read_fname(client_fd, fname, hdr->length);
  };

  printf("server_thread (fd=%d): %s %s\n", client_fd, command_str(hdr->command), fname);

  // perform command
  switch (hdr->command) {
  case SKT_PUT:   socket_get_or_put(ctx);   break;
  case SKT_GET:   socket_get_or_put(ctx);   break;
  case SKT_DEL:   socket_del(ctx);          break;
  case SKT_STAT:  socket_stat(ctx);         break;

  default:
    fprintf(stderr, "unsupported op: '%s'\n", command_str(hdr->command));
    ctx->flags |= _FLAG_THREAD_ERR;
  }

  shut_down_thread(ctx);
  ctx->flags = 0;		// context is free for new thread

  pthread_cleanup_pop(0);
}




// TBD: There should be a separate reaper-thread that periodically
//      cleans up terminated threads (e.g. the branch that looks for
//      _FLAG_THREAD_EXIT), instead of us doing it inline while
//      someone is waiting for service.
//

int find_available_conn() {
  int i;
  for (i=0; i<MAX_SOCKET_CONNS; ++i) {

    if (! conn_list[i].ctx.flags)
      return i;

    else if (conn_list[i].ctx.flags & _FLAG_THREAD_EXIT) {
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
  int  i = find_available_conn();
  if (i < 0)
    return -1;

  conn_list[i].ctx.client_fd = client_fd;
  conn_list[i].ctx.flags |= _FLAG_PRE_THREAD;

  printf("connection[%d] handles fd=%d\n", i, client_fd);
  CHECK_0( pthread_create(&conn_list[i].thr, NULL, server_thread, &conn_list[i].ctx) );

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

  // be sure to close the connection, if we are terminated by a signal
  struct sigaction sig_act;
  sig_act.sa_handler = sig_handler;
  sigaction(SIGTERM, &sig_act, NULL);
  sigaction(SIGINT,  &sig_act, NULL);
  sigaction(SIGPIPE, &sig_act, NULL);
  sigaction(SIGABRT, &sig_act, NULL);


  // for UNIX sockets, this is an fname.  for INET this is just for diagnostics
  sprintf(socket_name, "%s_%02d", SOCKET_NAME_PREFIX, port);


  // --- initialize the sockaddr struct
#ifdef UNIX_SOCKETS
  struct sockaddr_un  s_addr;
  struct sockaddr_un* s_addr_ptr = &s_addr;
  socklen_t           s_addr_len = sizeof(struct sockaddr_un);
  
  socklen_t           c_addr_size;
  struct sockaddr_un  c_addr;

  memset(&s_addr, 0, s_addr_len);
  (void)unlink(socket_name);
  strcpy(s_addr.sun_path, socket_name);
  s_addr.sun_family = AF_UNIX;


#elif (defined RDMA_SOCKETS)
  struct rdma_addrinfo  hints;
  struct rdma_addrinfo* res;

  memset(&hints, 0, sizeof(hints));
  //  hints.ai_port_space = RDMA_PS_TCP;
  hints.ai_port_space = RDMA_PS_IB;
  hints.ai_flags      = RAI_PASSIVE;
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
  SKT_CHECK( socket_fd = SOCKET(SKT_FAMILY, SOCK_STREAM, 0) );


  // --- When a server dies or exits, it leaves a connection in
  //     TIME_WAIT state, which is eventually cleaned up.  Meanwhile,
  //     trying to restart the server tells you that the "socket is
  //     already in use".  This setting allows the restart to just
  //     work.
  int enable = 1;
  SKT_CHECK( SETSOCKOPT(socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) );

  SKT_CHECK( BIND(socket_fd, (struct sockaddr*)s_addr_ptr, s_addr_len) );
  main_flags |= _FLAG_BIND;

  SKT_CHECK( LISTEN(socket_fd, SOMAXCONN) );
  main_flags |= _FLAG_SOCKET_FD;


  // receive connections and spin off threads to handle them
  while (1) {

    ///  SKT_CHECK( client_fd = ACCEPT(socket_fd, (struct sockaddr*)&c_addr, &c_addr_size) );
    SKT_CHECK( client_fd = ACCEPT(socket_fd, NULL, 0) );
    printf("server %s: connected %s\n", socket_name);

    if (push_thread(client_fd)) {
      fprintf(stderr, "couldn't allocate thread, dropping this connection\n");
      SHUTDOWN(client_fd, SHUT_RDWR);
      CLOSE(client_fd);
    }
  }

  shut_down();
  return 0;
}
