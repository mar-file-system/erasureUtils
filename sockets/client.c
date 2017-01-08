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
#include <string.h>             // strcpy()
#include <errno.h>
#include <stdint.h>
#include <netdb.h>
#include <time.h>

#include "socket_common.h"

#define  _FLAG_FNAME       0x01
#define  _FLAG_SERVER_FD   0x02

static unsigned char  flags = 0;

static char socket_name[MAX_SOCKET_NAME_SIZE +1];
static int  server_fd;               // listen() to this

// called from SKT_CHECK, to print diagnostics
static void socket_check_info(const char* expr) {
  printf("client:  running '%s'\n", expr);
}



void
shut_down() {

#if UNIX_SOCKETS
  if (flags & _FLAG_FNAME) {
    fprintf(stderr, "shut_down: unlinking '%s'\n", socket_name);
    (void)unlink(socket_name);
  }
#endif

  if (flags & _FLAG_SERVER_FD) {
    fprintf(stderr, "shut_down: closing socket_fd %d\n", server_fd);
    SHUTDOWN(server_fd, SHUT_RDWR);
    CLOSE(server_fd);
  }
}


static void
sig_handler(int sig) {
  fprintf(stderr, "sig_handler exiting on signal %d\n", sig);
  shut_down();
  exit(0);
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
//    in socket_common.c
//
// ---------------------------------------------------------------------------



int
main(int argc, char* argv[]) {

  if (argc != 4) {
     fprintf(stderr, "Usage: %s <host> <port> <fname>\n", argv[0]);
     fprintf(stderr, "For now, we are just reading from stdin, and writing to remote file\n", argv[0]);
     exit(1);
  }

  const char* host     = argv[1];
  const char* port_str = argv[2];
  const char* fname    = argv[3];

  // parse <port>
  errno = 0;
  int port = strtol(argv[2], NULL, 10);
  if (errno) {
    char errmsg[128];
    sprintf("couldn't read integer from '%s'", argv[2]);
    perror(errmsg);
    exit(1);
  }

  // for UNIX socket, this is fname, for INET this is just for diagnostics
  sprintf(socket_name, "%s_%02d", SOCKET_NAME_PREFIX, port);


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
  int rc = rdma_getaddrinfo((char*)host, (char*)port_str, &hints, &res);
  if (rc) {
    fprintf(stderr, "rdma_getaddrinfo(%s) failed: %s\n", host, strerror(errno));
    exit(1);
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

  struct hostent* server = gethostbyname(host);
  if (! server) {
    fprintf(stderr, "gethostbyname(%s) failed: %s\n", host, strerror(errno));
    exit(1);
  }

  s_addr.sin_family      = AF_INET;
  s_addr.sin_port        = htons(port);
  memcpy((char *)&s_addr.sin_addr.s_addr,
	 (char *)server->h_addr, 
	 server->h_length);
#endif


  // open socket to server
  /// SKT_CHECK( server_fd = SOCKET(PF_INET, SOCK_STREAM, 0) );
  SKT_CHECK( server_fd = SOCKET(SKT_FAMILY, SOCK_STREAM, 0) );

  
  SKT_CHECK( CONNECT(server_fd, s_addr_ptr, s_addr_len) );
  flags |= _FLAG_SERVER_FD;

  printf("server %s: connected\n", socket_name);

  // interact with server.  Server reads custom header, then data.
  // For now, the header is just:
  ssize_t       read_count = 0;
  ssize_t       write_count = 0;
  unsigned int  err = 0;



  // interact with server.
  unsigned int  op;             /* 0=GET from zfile, 1=PUT, else quit connection */
  char          zfname[FNAME_SIZE];
  char          read_buf[CLIENT_BUF_SIZE]; /* copy stdin to socket */

  size_t zfname_size = strlen(zfname);
  if (zfname_size >= FNAME_SIZE) {
    fprintf(stderr, "filename size %llu is greater than %u\n", zfname_size, FNAME_SIZE);
    exit(1);
  }
  strcpy(zfname, fname);
  

  // -- TBD: authentication handshake


  // -- TBD: abstract into standard-header write/read functions
  // send: <op> <zfname>
  // where:
  //   unsigned int <op>     = {GET | PUT}
  //   char[FNAME_SIZE] <zfname> = path in mounted ZFS
  //              e.g. [on 10.10.0.2]  /mnt/repo10+2/pod1/block3/scatterN/foo
  //              e.g. [on 10.10.0.2]  /mnt/repo10+2/pod1/block4/scatterN/foo

#if 0
  op = OP_PUT; // for now

  // write <op>
  write_count = WRITE(server_fd, &op, sizeof(op));
  if (write_count != sizeof(op)) {
    fprintf(stderr, "failed to write op (%lld)\n", write_count);
    exit(1);
  }
  else if (op != OP_PUT) {
    fprintf(stderr, "only supporting PUT, for now (%u)\n", op);
    exit(1);
  }
  printf("op:     %u\n", op);

  // write <zfname>
  write_count = WRITE(server_fd, &zfname, FNAME_SIZE);
  if (write_count != FNAME_SIZE) {
    fprintf(stderr, "failed to write zfname (%lld)\n", write_count);
    exit(1);
  }
  else if (!zfname[0] || zfname[FNAME_SIZE -1]) {
    fprintf(stderr, "bad zfname\n");
    exit(1);
  }
  printf("zfname: %s\n", zfname);

#else
  SocketHandle handle = { .fd    = server_fd,
			  .flags = 0,
			  .pos   = 0 };

  CHECK_0( write_pseudo_packet(&handle, SKT_PUT, strlen(zfname) +1, zfname) );
#endif



#define SKIP_READS 1
#ifdef SKIP_READS
  // int iters = 2048;
  int iters = (10 * 1024); // we will write (<this> * CLIENT_BUF_SIZE) bytes
#endif


  struct timespec start;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &start)) {
    fprintf(stderr, "failed to get START timer '%s'\n", strerror(errno));
    return -1;                // errno is set
  }

  size_t bytes_moved = 0;	/* total */
  int    eof         = 0;
  while (!eof && !err) {


#ifdef SKIP_READS
    // don't waste time reading.  Just send a raw buffer.
    size_t read_total  = CLIENT_BUF_SIZE;

    if (iters-- == 0) {
      eof = 1;
      read_total  = 0;
      break;
    }
    DBG("%d: fake read: %lld\n", iters, read_total);

#else
    // --- read data up to CLIENT_BUF_SIZE or EOF
    char*  read_ptr    = &read_buf[0];
    size_t read_total  = 0;
    size_t read_remain = CLIENT_BUF_SIZE;
    while (read_remain && !eof && !err) {

      read_count = read(STDIN_FILENO, read_ptr, read_remain);
      DBG("read_count(1): %lld\n", read_count);

      if (read_count < 0) {
	DBG("read error: %s\n", strerror(errno));
	exit(1);
      }
      else if (read_count == 0) {
	eof = 1;
	DBG("read EOF\n");
      }

      read_total  += read_count;
      read_ptr    += read_count;
      read_remain -= read_count;
    }
    DBG("read_total: %llu\n", read_total);
#endif



    // --- write buffer to socket
    char*   write_ptr    = &read_buf[0];
    size_t  write_remain = read_total;
    size_t  write_total  = 0;	/* per iteration */
    while (write_remain && !err) {

      write_count = WRITE(server_fd, write_ptr, write_remain);
      DBG("write_count: %lld\n", write_count);
      if (write_count < 0) {
	fprintf(stderr, "write of %llu bytes failed, after writing %llu: %s\n",
		write_remain, write_total, strerror(errno));
	exit(0);
      }
      write_total  += write_count;
      write_ptr    += write_count;
      write_remain -= write_count;

#if 0
      if (errno == ENOSPC)
	printf("buffer is full.  ignoring.\n");
      else if (errno == EPIPE) {
	printf("client disconnected?\n");
	err = 1;
	break;
      }
      else if (errno) {
	perror("write failed\n");
	err = 1;
	break;
      }
#endif
    }
    DBG("write_total: %llu\n", write_total);
    bytes_moved += write_total;

  }
  DBG("copy-loop done  (%llu bytes).\n", bytes_moved);


  // compute bandwidth
  struct timespec end;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &end)) {
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



#if 0
  // --- wait for ACK
  if (eof && !err) {
    DBG("waiting for ACK ...\n", read_count);
    uint32_t ack;
    read_count = READ(server_fd, &ack, sizeof(uint32_t));
    DBG("read_count(2): %lld\n", read_count);
    if ((read_count < 0) || (ack != 1))
      DBG("ACK fail\n");
    else
      DBG("ACK succeess\n");
  }
#endif
  

  shut_down();
  return 0;
}
