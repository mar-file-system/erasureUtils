#ifndef SOCKET_COMMON_H
#define SOCKET_COMMON_H


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>             // struct sockaddr_un
#include <netinet/in.h>         // struct sockaddr_in
#include <sys/uio.h>            // read(), write()
#include <unistd.h>             // read(), write()
#include <stdlib.h>             // exit()




// #define DEBUG

#ifdef DEBUG
#  define DBG(...)   fprintf(stderr, ##__VA_ARGS__)
#else
#  define DBG(...)
#endif




#define SKT_CHECK(EXPR)                                          \
  socket_check_info(#EXPR);                                      \
  if ((EXPR) == -1) {                                            \
    perror("expression failed: '" #EXPR "'\n");                  \
    exit(1);                                                     \
  }


#define SKT_TRY(EXPR)      ((EXPR) != -1)




#define SOCKET_NAME_PREFIX    "socket_"
#define MAX_SOCKET_NAME_SIZE  (sizeof(SOCKET_NAME_PREFIX) + 10)

#define MAX_SOCKET            9


#define ZFNAME_SIZE      128 /* incl final null */


// #define CLIENT_BUF_SIZE         (1024 * 1024)
// #define SERVER_BUF_SIZE         (1024 * 1024 * 10)

// #define CLIENT_BUF_SIZE         (512 * 1024)
// #define SERVER_BUF_SIZE         (512 * 1024)

#define CLIENT_BUF_SIZE         (1024 * 1024)
#define SERVER_BUF_SIZE         (1024 * 1024)



typedef enum {
   OP_GET = 0,
   OP_PUT = 1,
   OP_DEL = 2,
} StreamOp;



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
#  define RECV(...)             recv(__VA_ARGS__)


/* -----------------------------------
 * RDMA sockets
 * ----------------------------------- */
#elif (defined RDMA_SOCKETS)
#  include <rdma/rsocket.h>
#  define SKT_FAMILY   AF_INET
typedef struct sockaddr_in                   SockAddr;

#  define SOCKET(...)           rsocket(__VA_ARGS__)
#  define SETSOCKOPT(...)       rsetsockopt(__VA_ARGS__)
#  define BIND(...)             rbind(__VA_ARGS__)
#  define LISTEN(...)           rlisten(__VA_ARGS__)
#  define ACCEPT(...)           raccept(__VA_ARGS__)
#  define CONNECT(...)          rconnect(__VA_ARGS__)
#  define CLOSE(...)            rclose(__VA_ARGS__)
#  define WRITE(...)            rwrite(__VA_ARGS__)
#  define RECV(...)             rrecv(__VA_ARGS__)


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
#  define RECV(...)             recv(__VA_ARGS__)


#endif





ssize_t read_buffer (int fd, char* buf, size_t size);
int     write_buffer(int fd, char* buf, size_t size);



#endif
