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

#include "socket_common.h"




#define  _FLAG_FNAME       0x01
#define  _FLAG_SOCKET_FD   0x02
#define  _FLAG_CLIENT_FD   0x04
#define  _FLAG_ZFILE_OPEN  0x08

static unsigned char  flags = 0;


static char socket_name[MAX_SOCKET_NAME_SIZE +1];
static int  socket_fd;               // listen() to this
static int  client_fd;               // read/write to this
static int  zfs_fd;                  // writing client datsa to file

// called from SKT_CHECK, to print diagnostics
static void socket_check_info(const char* expr) {
  printf("server %s:  running '%s'\n", socket_name, expr);
}



void
shut_down() {
  if (flags & _FLAG_FNAME) {
    fprintf(stderr, "shut_down: unlinking '%s'\n", socket_name);
    (void)unlink(socket_name);
  }

  // maybe close the local file we wrote
  if (flags & _FLAG_ZFILE_OPEN) {
     SKT_CHECK( close(zfs_fd) );
  }

  if (flags & _FLAG_SOCKET_FD) {
    fprintf(stderr, "shut_down: closing socket_fd %d\n", socket_fd);
    CLOSE(socket_fd);
  }

  if (flags & _FLAG_CLIENT_FD) {
    fprintf(stderr, "shut_down: closing client_fd %d\n", client_fd);
    CLOSE(client_fd);
  }
}


static void
sig_handler(int sig) {
  fprintf(stderr, "sig_handler exiting on signal %d\n", sig);
  shut_down();
  exit(0);
}






















int
main(int argc, char* argv[]) {

  int  port;

  // be sure to close the connection, if we are terminated by a signal
  struct sigaction sig_act;
  sig_act.sa_handler = sig_handler;
  sigaction(SIGTERM, &sig_act, NULL);
  sigaction(SIGINT,  &sig_act, NULL);
  sigaction(SIGPIPE, &sig_act, NULL);
  sigaction(SIGABRT, &sig_act, NULL);


  // cmd-line gives us our server-number, which determines our socket-name
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <port>\n", argv[0]);
    exit(1);
  }
  errno = 0;
  port = strtol(argv[1], NULL, 10);
  if (errno) {
    char errmsg[128];
    sprintf("couldn't read integer from '%s'", argv[1]);
    perror(errmsg);
    abort();
  }

  // for UNIX sockets, this is an fname.  for INET this is just for diagnostics
  sprintf(socket_name, "%s_%02d", SOCKET_NAME_PREFIX, port);


  // --- initialize the sockaddr struct
#ifdef UNIX_SOCKETS
# define ADDR_SIZE  sizeof(struct sockaddr_un)
  socklen_t           c_addr_size;
  struct sockaddr_un  c_addr;
  struct sockaddr_un  s_addr;

  memset(&s_addr, 0, ADDR_SIZE);
  (void)unlink(socket_name);
  strcpy(s_addr.sun_path, socket_name);
  s_addr.sun_family = AF_UNIX;

#else
# define ADDR_SIZE  sizeof(struct sockaddr_in)
  socklen_t           c_addr_size;
  struct sockaddr_in  c_addr;
  struct sockaddr_in  s_addr;

  memset(&s_addr, 0, ADDR_SIZE);
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

  SKT_CHECK( BIND(socket_fd, (struct sockaddr*)&s_addr, ADDR_SIZE) );
  flags |= _FLAG_FNAME;

  SKT_CHECK( LISTEN(socket_fd, SOMAXCONN) );
  flags |= _FLAG_SOCKET_FD;



  SKT_CHECK( client_fd = ACCEPT(socket_fd, (struct sockaddr*)&c_addr, &c_addr_size) );
  flags |= _FLAG_CLIENT_FD;
  printf("server %s: connected\n", socket_name);

  // interact with client.  Client can write a non-zero int at us, to get us to quit.
  ssize_t       read_count = 0;
  ssize_t       write_count = 0;
  unsigned int  client_code = 0;
  unsigned int  eof = 0;
  unsigned int  err = 0;

#if 0
  if (select(...))
    ///    read_count = read(client_fd, &client_code, sizeof(client_code));
    read_count = recv(client_fd, &client_code, sizeof(client_code), 0);
#endif


  // interact with client.
  unsigned int  op;             /* 0=GET from zfile, 1=PUT, else quit connection */
  char          zfname[ZFNAME_SIZE];
  char          read_buf[SERVER_BUF_SIZE];

  while ((err == 0) && ((read_count == 0) || (client_code == 0))) {
     // printf("read_count %ld, client_code %d\n", read_count, client_code);

     // recv: <op> <zfname>
     // where:
     //   <op>     = {GET | PUT}
     //   <sfname> = path in mounted ZFS
     //              e.g. [on 10.10.0.2]  /mnt/repo10+2/pod1/block3/scatterN/foo
     //              e.g. [on 10.10.0.2]  /mnt/repo10+2/pod1/block4/scatterN/foo

     // read <op>
     ///     read_count = read(client_fd, &op, sizeof(op));
     read_count = recv(client_fd, &op, sizeof(op), 0);
     if (read_count != sizeof(op)) {
        fprintf(stderr, "failed to read op (%lld)\n", read_count);
	abort();
     }
     else if (op != OP_PUT) {
        fprintf(stderr, "only supporting PUT, for now (%u)\n", op);
	abort();
     }
     printf("op:     %u\n", op);

     // read <zfname>
     /// read_count = read(client_fd, &zfname, ZFNAME_SIZE);
     read_count = recv(client_fd, &zfname, ZFNAME_SIZE, 0);
     if (read_count != ZFNAME_SIZE) {
        fprintf(stderr, "failed to read zfname (%lld)\n", read_count);
	abort();
     }
     else if (!zfname[0] || zfname[ZFNAME_SIZE -1]) {
        fprintf(stderr, "bad zfname\n");
	abort();
     }
     printf("zfname: %s\n", zfname);



     //     // testing.  Make sure we've got the fname correctly, before
     //     // moving on to opening for write.
     //     printf("quitting early\n");
     //     abort();


     // --- open destination, if needed
     if (! (flags & _FLAG_ZFILE_OPEN)) {
       zfs_fd = open(zfname, (O_WRONLY|O_CREAT|O_TRUNC));
       if (zfs_fd < 0) {
	 fprintf(stderr, "couldn't open '%s': %s\n", zfname, strerror(errno));
	 abort();
       }
       DBG("opened '%s'\n", zfname);
       flags |= _FLAG_ZFILE_OPEN;
     }


     // --- read from socket, write to file
     while (!eof && !err) {


       // --- read data up to SERVER_BUF_SIZE, or EOF
       char*  read_ptr    = &read_buf[0];
       size_t read_total  = 0;
       size_t read_remain = SERVER_BUF_SIZE;
       while (read_remain && !eof && !err) {

	 /// read_count = read(client_fd, read_ptr, read_remain);
	 read_count = recv(client_fd, read_ptr, read_remain, 0);
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
       DBG("read_total: %lld\n", read_total);

       // // wouldn't want to do this with large reads ...
       // DBG("contents: %s\n", read_buf);



       // --- write buffer to file
       char*  write_ptr     = &read_buf[0];
       size_t write_remain  = read_total;
       size_t write_total   = 0;
       while (write_remain && !err) {

	 write_count = write(zfs_fd, write_ptr, write_remain);
	 DBG("write_count: %lld\n", write_count);
	 if (write_count < 0) {
	   fprintf(stderr, "write of %llu bytes failed, after writing %llu: %s\n",
		   write_remain, write_total, strerror(errno));
	   abort();
	 }
	 write_total   += write_count;
	 write_ptr     += write_count;
	 write_remain  -= write_count;

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
       DBG("write_total: %lld\n", write_total);

     }
     DBG("copy-loop done.\n");


     // maybe close the local file we wrote
     if (flags & _FLAG_ZFILE_OPEN) {
        SKT_CHECK( close(zfs_fd) );
        flags &= ~_FLAG_ZFILE_OPEN;
     }


#if 0
     // --- send an ACK to client, so they can close their socket
     static const uint32_t ack = 1;
     write_count = write(client_fd, &ack, sizeof(uint32_t));
     DBG("write_count(ACK): %lld\n", write_count);
     if ((write_count < 0) || (write_count != 4)) {
       DBG("ACK failed\n");
       err = 1;
     }
#endif


#  if 0
     if (select(...))
       ///        read_count = read(client_fd, &client_code, sizeof(client_code));
        read_count = recv(client_fd, &client_code, sizeof(client_code));
     else
        read_count = 0;
#  endif
  }





  if (client_code)
    printf("server %s: received %d from client\n", socket_name, client_code);

  printf("server %s: quitting ...\n", socket_name);
  

  shut_down();
  return 0;
}
