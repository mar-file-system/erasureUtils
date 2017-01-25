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


#include <stdio.h>              // sprintf()
#include <stdint.h>
#include <unistd.h>             // getopt()
#include <fcntl.h>
#include <netdb.h>
#include <time.h>
#include <string.h>             // strcpy()
#include <errno.h>

#include "skt_common.h"


static SocketHandle handle = {0};



void
shut_down() {

#if UNIX_SOCKETS
  if (handle.flags & HNDL_FNAME) {
    fprintf(stderr, "shut_down: unlinking '%s'\n", handle.fname);
    (void)unlink(handle.fname);
  }
#endif

  if (handle.flags & HNDL_SERVER_FD) {
    fprintf(stderr, "shut_down: closing socket_fd %d\n", handle.fd);
    SHUTDOWN(handle.fd, SHUT_RDWR);
    CLOSE(handle.fd);
  }
}


static void
sig_handler(int sig) {
  fprintf(stderr, "sig_handler exiting on signal %d\n", sig);
  shut_down();
  exit(0);
}



// ---------------------------------------------------------------------------
// PUT
// ---------------------------------------------------------------------------
// return number of bytes moved, or -1 for error.
ssize_t client_put(const char* path) {

  char read_buf[CLIENT_BUF_SIZE] __attribute__ (( aligned(64) )); /* copy stdin to socket */

  // --- TBD: authentication handshake
  REQUIRE_0( skt_open(&handle, path, (O_WRONLY|O_CREAT), 0660) );

  
#ifdef SKIP_FILE_READS
  // This allows cutting out the performance cost of doing reads on
  // the client side.

  size_t iters = SKIP_FILE_READS; // we will write (<this> * CLIENT_BUF_SIZE) bytes

  static int needs_init = 1;
  if (unlikely(needs_init)) {
    memset(read_buf, 1, CLIENT_BUF_SIZE);
    needs_init = 0;
  }
#endif


  size_t bytes_moved = 0;	/* total */
  int    eof         = 0;
  int    err         = 0;
  while (!eof && !err) {


#ifdef SKIP_FILE_READS
    // --- don't waste time reading.  Just send a raw buffer.
    ssize_t read_count  = CLIENT_BUF_SIZE;

    if (unlikely(iters-- <= 0)) {
      DBG("fake EOF\n");
      eof = 1;
      read_count  = 0;
      break;
    }
    DBG("%d: fake read: %lld\n", iters, read_count);

#else
    // --- read data up to CLIENT_BUF_SIZE or EOF
    ssize_t read_count = read_buffer(STDIN_FILENO, read_buf, CLIENT_BUF_SIZE, 0);
    if (read_count < 0) {
      fprintf(stderr, "read error: %s\n", strerror(errno));
      abort();
    }
    else if (read_count == 0) {
      DBG("read EOF\n");
      eof = 1;
      break;
    }
    DBG("read_count: %llu\n", read_count);
#endif


    // --- write buffer to socket
    REQUIRE_GT0( skt_write(&handle, read_buf, read_count) );
    bytes_moved += read_count;
  }
  DBG("copy-loop done  (%llu bytes).\n", bytes_moved);


  // --- close
  REQUIRE_0( skt_close(&handle) );

  return bytes_moved;
}



// ---------------------------------------------------------------------------
// GET
// ---------------------------------------------------------------------------

// return number of bytes moved, or -1 for error.
ssize_t client_get(const char* path) {

  char read_buf[CLIENT_BUF_SIZE] __attribute__ (( aligned(64) )); /* copy socket to stdout */

  // --- TBD: authentication handshake
  REQUIRE_0( skt_open(&handle, path, (O_RDONLY)) );

  
  size_t bytes_moved = 0;	/* total */
  int    eof         = 0;
  int    err         = 0;
  while (!eof && !err) {

    // --- read from socket, up to CLIENT_BUF_SIZE or EOF
    ssize_t read_count = skt_read(&handle, read_buf, CLIENT_BUF_SIZE);
    if (read_count < 0) {
      fprintf(stderr, "read error: %s\n", strerror(errno));
      abort();
    }
    else if (read_count == 0) {
      DBG("read EOF\n");
      eof = 1;
      break;
    }
    DBG("read_count: %llu\n", read_count);


#ifdef SKIP_FILE_WRITES
    // --- don't waste time writing to stdout
    DBG("%d: fake write: %lld\n", iters, read_count);

#else
    // --- write buffer to stdout
    ssize_t write_count = write_buffer(STDOUT_FILENO, read_buf, read_count, 0, 0);
    if (write_count < 0) {
      fprintf(stderr, "read error: %s\n", strerror(errno));
      abort();
    }
    DBG("write_count: %llu\n", write_count);
#endif


    bytes_moved += read_count;
  }
  DBG("copy-loop done  (%llu bytes).\n", bytes_moved);


  // --- close
  REQUIRE_0( skt_close(&handle) );

  return bytes_moved;
}




// ---------------------------------------------------------------------------
// This client is just an application to test writing to one file.
// The command-line gives host, port, destination-fname,
// and the program reads from stdin and writes to a socket that puts data to
// our server.  The server then dumps incoming data to the file.
//
// TBD:
//
//  -- initial authentication protocol.  Custom call-and-response, or
//     is there some built-in support.  Could use our liwabws4c to
//     generate an encrypted S3 header.
//
//     Initial header needs at least:
//       op
//       fname
//       block-size    (each block then starts with magic number or something)
//       UID, GID
//       reserved space?
//
// -- add command-line args for everything needed in initial header
//
// -- abstract away the ad-hoc message-headers.  Let client/server use
//    header generating/parsing functions, which could be implemented
//    in skt_common.c
//
// ---------------------------------------------------------------------------


typedef enum {
  OP_ERR = 0,
  OP_PUT,
  OP_GET,
} ClientOp;


int usage(const char* prog) {
  fprintf(stderr, "Usage: %s  <operation>  <host>:<port>/<fname>\n", prog);
  fprintf(stderr, "where <operation> is one of:\n");
  fprintf(stderr, "  -p     (PUT) read from stdin, write to remote file\n");
  fprintf(stderr, "  -g     (GET) read from remote file, write to stdout\n");
}

int
main(int argc, char* argv[]) {

  if (argc != 3) {
    usage(argv[0]);
    return -1;
  }

  // --- start timer
  struct timespec start;
  if (clock_gettime(CLOCK_REALTIME, &start)) {
    fprintf(stderr, "failed to get START timer '%s'\n", strerror(errno));
    return -1;                // errno is set
  }

  // --- parse args
  SocketCommand cmd       = CMD_NULL;
  char*         file_spec = NULL;
  int     c;
  while ( (c = getopt(argc, argv, "g:p:h")) != -1) {
    switch (c) {
    case 'p':      cmd = CMD_PUT;  file_spec=optarg;    break;
    case 'g':      cmd = CMD_GET;  file_spec=optarg;    break;

    case 'h':
    default:
      usage(argv[0]);
      return -1;
    }
  }

  // --- perform op
  ssize_t bytes_moved = 0;
  switch (cmd) {
  case CMD_PUT:   bytes_moved = client_put(file_spec); break;
  case CMD_GET:   bytes_moved = client_get(file_spec); break;
  default:
    fprintf(stderr, "unsupported command: %s\n", command_str(cmd));
    return -1;
  }

  if (bytes_moved < 0) {
    perror("error");
    return -1;
  }

  // --- compute bandwidth
  struct timespec end;
  if (clock_gettime(CLOCK_REALTIME, &end)) {
    fprintf(stderr, "failed to get END timer '%s'\n", strerror(errno));
    return -1;                // errno is set
  }
  size_t nsec = (end.tv_sec - start.tv_sec) * 1000UL * 1000 * 1000;
  nsec += (end.tv_nsec - start.tv_nsec);

  printf("start: %lu.%llu\n", start.tv_sec, start.tv_nsec);
  printf("end:   %lu.%llu\n", end.tv_sec,   end.tv_nsec);
  printf("nsec:  %llu\n", nsec);
  printf("bytes: %llu\n", bytes_moved);

  printf("%5.2f MB/s\n", ((double)bytes_moved / nsec) * 1000.0);


  // --- clean up
  shut_down();
  return 0;
}
