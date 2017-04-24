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
#include <sys/syscall.h>        // syscalls in test3_thr

#include "skt_common.h"


static SocketHandle handle = {0};



// makes it easy to find test output in the cluttered output of a debugging build.
// Also makes it easy to disable all local logging, e.g. when running strace.
//
#ifdef DEBUG_SOCKETS
#  define cLOG(FMT,...)  LOG("--- " FMT, ##__VA_ARGS__)
#else
#  define cLOG(FMT,...)
#endif


void
shut_down() {
  DBG("shut_down: closing socket_fd %d\n", handle.peer_fd);
  shut_down_handle(&handle);
}



static void
sig_handler(int sig) {
  cLOG("sig_handler exiting on signal %d\n", sig);
  shut_down();
  exit(0);
}




// ---------------------------------------------------------------------------
// operations dispatched from main
// ---------------------------------------------------------------------------

// read from file and copy to socket
// return number of bytes moved, or -1 for error.

ssize_t client_put(const char* path) {

  char buf[CLIENT_BUF_SIZE] __attribute__ (( aligned(64) )); /* copy stdin to socket */

  // --- TBD: authentication handshake
  NEED_GT0( skt_open(&handle, path, (O_WRONLY|O_CREAT), 0660) );

  ssize_t bytes_moved = copy_file_to_socket(STDIN_FILENO, &handle, buf, CLIENT_BUF_SIZE);

  // --- close
  NEED_0( skt_close(&handle) );

  return bytes_moved;
}


// read from socket and copy to stdout
// return number of bytes moved, or -1 for error.

ssize_t client_get(const char* path) {

  char buf[CLIENT_BUF_SIZE] __attribute__ (( aligned(64) )); /* copy socket to stdout */

  // --- TBD: authentication handshake
  NEED_GT0( skt_open(&handle, path, (O_RDONLY)) );

  ssize_t bytes_moved = copy_socket_to_file(&handle, STDOUT_FILENO, buf, CLIENT_BUF_SIZE);

  // --- close
  NEED_0( skt_close(&handle) );

  return bytes_moved;
}



int client_rename(const char* path) {

  char  new_fname[FNAME_SIZE];
  snprintf(new_fname, FNAME_SIZE, path);
  strncat(new_fname, ".renamed", FNAME_SIZE - strlen(path));

  NEED_0( skt_rename(path, new_fname) );

  return 0;
}


int client_chown(const char* path) {

  NEED_0( skt_chown(path, 99, 99) );

  return 0;
}


// open a handle for reading, but don't read anything.  Server-side
// reaper thread should terminate the connection.  Does that leak a
// file-descriptor on the server?  This will test that.  do 'lsof |
// grep socket_fs | wc -l' before and after.
int client_reap_read(const char* path) {

  char buf[CLIENT_BUF_SIZE] __attribute__ (( aligned(64) )); /* copy socket to stdout */

  // --- TBD: authentication handshake
  NEED_GT0( skt_open(&handle, path, (O_RDONLY)) );

  // some server-side work is deferred until we actually read.
  printf("reading\n");
  NEED_GT0( skt_read(&handle, buf, 1) );

  // server-side reaper runs every 10 sec
  // needs to run twice with out seeing us move data.
  printf("sleeping for 25 sec ...\n");
  sleep(25);

  // this should fail, because reaper killed the connection
  printf("reading\n");
  ssize_t bytes_moved = skt_read(&handle, buf, 1);

  // --- close
  NEED_0( skt_close(&handle) );

  return bytes_moved;
}








ssize_t client_stat(const char* path) {

  struct stat st;

  int rc = skt_stat(path, &st);
  if (rc < 0) {
    perror("stat failed");
    return 0;                   /* "bytes-moved" */
  }

  printf("st.st_dev:     %llu\n", st.st_dev);     /* ID of device containing file */
  printf("st.st_ino:     %llu\n", st.st_ino);     /* inode number */
  printf("st.st_mode:    %llu\n", st.st_mode);    /* protection */
  printf("st.st_nlink:   %llu\n", st.st_nlink);   /* number of hard links */
  printf("st.st_uid:     %llu\n", st.st_uid);     /* user ID of owner */
  printf("st.st_gid:     %llu\n", st.st_gid);     /* group ID of owner */
  printf("st.st_rdev:    %llu\n", st.st_rdev);    /* device ID (if special file) */
  printf("st.st_size:    %llu\n", st.st_size);    /* total size, in bytes */
  printf("st.st_blksize: %llu\n", st.st_blksize); /* blocksize for file system I/O */
  printf("st.st_blocks:  %llu\n", st.st_blocks);  /* number of 512B blocks allocated */
  printf("st.st_atime:   %llu\n", st.st_atime);   /* time of last access */
  printf("st.st_mtime:   %llu\n", st.st_mtime);   /* time of last modification */
  printf("st.st_ctime:   %llu\n", st.st_ctime);   /* time of last status change */

  return STAT_DATA_SIZE;
}



// Problem opening 2 sockets?
int client_test1(const char* path) {

  SocketHandle handle2;
  char* path2 = malloc(strlen(path) + 5);
  NEED(path2);
  strcpy(path2, path);
  strcat(path2, ".2");

  // buffer to write
  const char* buf = "This is a test\n";
  size_t      buf_len = strlen(buf);

  // open
  NEED_GT0( skt_open(&handle,  path,  (O_WRONLY|O_CREAT), 0660) );
  NEED_GT0( skt_open(&handle2, path2, (O_WRONLY|O_CREAT), 0660) );

  // write
  ssize_t bytes_moved  = skt_write(&handle,  buf, buf_len);
  ssize_t bytes_moved2 = skt_write(&handle2, buf, buf_len);


  // close
  NEED_0( skt_close(&handle) );
  NEED_0( skt_close(&handle2) );

  return 0;
}


// Problem opening >2 sockets?
//
// This is looking a lot like what is going on in libne, but libne
// fails to open the second round of files.  (The rconnect() in
// skt_open() fails.)  But here it works.

int client_test1b(const char* path) {

  typedef struct {
    SocketHandle  handle;
    char*         path;
  } State;

# define N  12
  State state[N];
  int   i;
  for (i=0; i<N; ++i) {
    memset(&state[i], 0, sizeof(State));
    state[i].path = malloc(strlen(path) + 32); // extra room for suffix
    NEED(state[i].path);
    sprintf(state[i].path, "%s.%d", path, i);
    printf("path[%d] : %s\n", i, state[i].path);

    NEED_GT0( skt_open(&state[i].handle, state[i].path, (O_WRONLY|O_CREAT), 0660) );
    printf("           opened\n");
  }
  printf("\n");

  // buffer to write
  const char* buf = "This is a test\n";
  size_t      buf_len = strlen(buf);

  ssize_t bytes_moved = 0;
  ssize_t write_count;
  for (i=0; i<N; ++i) {
    printf("path[%d] : writing\n", i);
    write_count = skt_write(&state[i].handle,  buf, buf_len);
    NEED( write_count == buf_len );
    bytes_moved += write_count;
  }
  printf("\n");


  // close
  for (i=0; i<N; ++i) {
    printf("path[%d] : closing\n", i);
    NEED_0( skt_close(&state[i].handle) );
  }



  // -- TWO: open again, with new names
  typedef  SocketHandle  FileDesc;
#   define OPEN(      FDESC, ...)                 skt_open(&(FDESC), ## __VA_ARGS__)
#   define MAXNAME 1024 

  for (i=0; i<N; ++i) {
    FileDesc  fd;
    char file[MAXNAME];

    memset(&fd, 0, sizeof(FileDesc));
    snprintf(file, MAXNAME-1, "%s.TWO%d", path, i);
    printf("file [%d] : %s\n", i, file);

    NEED_GT0( OPEN(fd, file, (O_WRONLY|O_CREAT), 0660) );
    printf("           opened\n");

    printf("file [%d] : writing\n", i);
    write_count = skt_write(&fd, buf, buf_len);
    NEED( write_count == buf_len );
    bytes_moved += write_count;

    printf("file [%d] : closing\n", i);
    NEED_0( skt_close(&fd) );
  }

#undef MAXNAME
#undef OPEN


# undef N
  return bytes_moved;
}



// This is just like test1b(), but instead of opening all paths
// against a single server, we're opening them against a series of
// servers.
//
// <path> should be something like "192.168.0.%d:xxx/some/zfs/path/block%d/sockets/fname"

int client_test1c(const char* path) {

  typedef struct {
    SocketHandle  handle;
    char*         path;
  } State;

# define N  12
  State state[N];
  int   i;
  for (i=0; i<N; ++i) {
    memset(&state[i], 0, sizeof(State));
    state[i].path = malloc(strlen(path) + 32); // extra room for suffix
    NEED(state[i].path);

    //    sprintf(state[i].path, "%s.%d", path, i);
    int octet = 1 + (i / 2); // 1,1,2,2,3,3 ...
    int block = 1 + i;
    sprintf(state[i].path, path, octet, block);

    printf("path[%d] : %s\n", i, state[i].path);
    fflush(stdout);
    NEED_GT0( skt_open(&state[i].handle, state[i].path, (O_WRONLY|O_CREAT), 0660) );
    printf("           opened\n");
  }
  printf("\n");

  // buffer to write
#if 0
  const char* buf = "This is a test\n";
  size_t      buf_len = strlen(buf);
#else
# define M 1024*1024
  char    storage[M] __attribute__ (( aligned(64) ));;
  char*   buf = storage;
  size_t  buf_len = M;
  memset(buf, 1, M);
#endif

  ssize_t bytes_moved = 0;
  ssize_t write_count;
  for (i=0; i<N; ++i) {
    printf("path[%d] : writing\n", i);
    write_count = skt_write(&state[i].handle,  buf, buf_len);
    NEED( write_count == buf_len );
    bytes_moved += write_count;
  }
  printf("\n");


  // close
  for (i=0; i<N; ++i) {
    printf("path[%d] : closing\n", i);
    NEED_0( skt_close(&state[i].handle) );
  }



  // -- TWO: open again, with new names
    typedef  SocketHandle  FileDesc;
#   define OPEN(      FDESC, ...)                 skt_open(&(FDESC), ## __VA_ARGS__)
#   define MAXNAME 1024 

  for (i=0; i<N; ++i) {
    FileDesc  fd;
    char file[MAXNAME];

    memset(&fd, 0, sizeof(FileDesc));

    // snprintf(file, MAXNAME-1, "%s.TWO%d", path, i);
    int octet = 1 + (i / 2); // 1,1,2,2,3,3 ...
    int block = 1 + i;
    sprintf(file, path, octet, block);
    strcat(file, ".TWO");

    printf("file [%d] : %s\n", i, file);
    fflush(stdout);
    NEED_GT0( OPEN(fd, file, (O_WRONLY|O_CREAT), 0660) );
    printf("           opened\n");

    printf("file [%d] : writing\n", i);
    write_count = skt_write(&fd, buf, buf_len);
    NEED( write_count == buf_len );
    bytes_moved += write_count;

    printf("file [%d] : closing\n", i);
    NEED_0( skt_close(&fd) );
  }

#undef MAXNAME
#undef OPEN


# undef N
  return bytes_moved;
}




// Attempting to recreate a problem encounterd by libne when writing
// to MC_SOCKETS via fuse.  write 1 file of size 1MB, then another
// with a small amount of text, then rename the second one.  The
// "connect" inside the skt_open(), in skt_rename() fails, in that
// case.  Works fine here.  Jamming a bunch of calls to this test in a
// tight loop also succeeds.
//
// UPDATE: client_test2b is just client_test2 with do_seteuid non-zero.
//
// RESULT: test2    works
//         test2b   fails
//

int client_test2(const char* path, int do_seteuid) {

  // buffer to write
# define MiB  (1024 * 1024)
  char     buf[MiB] __attribute__ (( aligned(64) )); /* copy stdin to socket */
  memset(buf, 1, MiB);
  size_t   buf_len = MiB;

  // open, put, close
  ssize_t bytes_moved;
  NEED_GT0( skt_open(&handle,  path,  (O_WRONLY|O_CREAT), 0660) );
  bytes_moved = skt_write(&handle, buf, buf_len);
  NEED( bytes_moved == buf_len );
  NEED_0( skt_close(&handle) );

  // seteuid() causes failure in IB device
  if (do_seteuid)
     NEED_0( seteuid(geteuid()) );

  // create the second file. (name is "<orig>.meta2")
  SocketHandle handle2 = {0};
  char* path2 = malloc(strlen(path) + 32);
  NEED(path2);
  strcpy(path2, path);
  strcat(path2, ".2.meta");

  // write a small amount
  const char* buf2 = "This is a lot less than a MB\n";
  size_t      buf2_len = strlen(buf2);

  NEED_GT0( skt_open(&handle2,  path2,  (O_WRONLY|O_CREAT), 0660) );
  ssize_t bytes_moved2 = skt_write(&handle2, buf2, buf2_len);
  NEED( bytes_moved2 == buf2_len );
  NEED_0( skt_close(&handle2) );

  // rename to "<orig>.2"
  char* path2b = malloc(strlen(path2) + 32);
  NEED(path2b);
  strcpy(path2b, path);
  strcat(path2b, ".2");

  NEED_0( skt_rename(path2, path2b) );

  return bytes_moved + bytes_moved2;
}





// ...........................................................................
// client_test3
//
// Q: what about open/write/close for two different files, from different threads?
// A: works fine.
// ...........................................................................

#include <pthread.h>

enum {
   TC_OPEN         = 0x01,
   TC_OPEN2        = 0x02,
   TC_WRITE        = 0x04,
   TC_CLOSE        = 0x08,
   TC_SETEUID      = 0x10,
   TC_SETEUID_SYS  = 0x20,
   TC_DONE         = 0x40,
};

const char* flag_name(int flag) {
   switch (flag) {
   case TC_OPEN:        return "OPEN";
   case TC_OPEN2:       return "OPEN2";
   case TC_WRITE:       return "WRITE";
   case TC_CLOSE:       return "CLOSE";
   case TC_SETEUID:     return "SETEUID";
   case TC_SETEUID_SYS: return "SETEUID_SYS";
   case TC_DONE:        return "DONE";
   default:             return "UNKNOWN";
   }
}

#define MAX_SEQ   16

typedef struct {
   int                 flags;
   int                 thr_no;
   const char*         path;
   SocketHandle        handle;
   pthread_barrier_t*  barrier;
   int                 sequence[MAX_SEQ]; // only used >= test3c
} ThreadContext;


#define thrNEED(EXPR)          _TEST(EXPR,    , DBG,    return (void*)-1)
#define thrNEED_0(EXPR)        _TEST(EXPR, ==0, DBG,    return (void*)-1)
#define thrNEED_GT0(EXPR)      _TEST(EXPR,  >0, DBG,    return (void*)-1)



// this is the thread-function spawned by client_test3.
void* client_test3_thr(void* arg) {
   ThreadContext* ctx    = (ThreadContext*)arg;

   ssize_t        bytes_moved;

   // SocketHandle   handle_impl = {0};
   // SocketHandle*  handle = &handle_impl;
   SocketHandle*  handle = &ctx->handle;

   char           thr_path[1024];

# define          BUFSIZE  (64)
  char            buf[BUFSIZE] __attribute__ (( aligned(64) )); /* copy stdin to socket */
  memset(buf, ctx->thr_no +1, BUFSIZE);


  // --- open
  //     NOTE: write-mode differs from libne
  //     changing to 0666 doesn't seem to affect success
  if (ctx->flags & TC_OPEN) {
     sprintf(thr_path, "%s.%d", ctx->path, ctx->thr_no);
     cLOG("thr%d: opening %s\n", ctx->thr_no, thr_path);
     // thrNEED_GT0( skt_open(handle,  thr_path,  (O_WRONLY|O_CREAT), 0660) );
     thrNEED_GT0( skt_open(handle,  thr_path,  (O_WRONLY|O_CREAT), 0666) );
  }


  // --- wait for other thread(s) to open their handle, as well.
  cLOG("thr%d: waiting on barrier 0\n", ctx->thr_no);
  pthread_barrier_wait(ctx->barrier);


  // -- pop/push EUID
  //    NOTE: calling seteuid() affects all threads,
  //          but the syscall does not.
  if (ctx->flags & TC_SETEUID) {
     uid_t old_euid;
     int rc;

     cLOG("thr%d: GETTING euid\n", ctx->thr_no);
     old_euid = geteuid();
     cLOG("thr%d: euid = %d\n", ctx->thr_no, old_euid);

     cLOG("thr%d: SETTING euid\n", ctx->thr_no);
     rc = seteuid(old_euid);
     cLOG("thr%d: euid = %d (rc=%d)\n", ctx->thr_no, old_euid, rc);
  }
  else if (ctx->flags & TC_SETEUID_SYS) {
     uid_t old_ruid;
     uid_t old_euid;
     uid_t old_suid;
     int   rc;

     cLOG("thr%d: GETTING euid\n", ctx->thr_no);
     rc = syscall(SYS_getresuid, &old_ruid, &old_euid, &old_suid);
     cLOG("thr%d: euid = %d (rc=%d)\n", ctx->thr_no, old_euid, rc);

     cLOG("thr%d: SETTING euid\n", ctx->thr_no);
     rc = syscall(SYS_setresuid, -1, old_euid, -1);
     cLOG("thr%d: euid = %d (rc=%d)\n", ctx->thr_no, old_euid, rc);
  }


  // --- wait for other thread(s) to open their handle, as well.
  cLOG("thr%d: waiting on barrier 1\n", ctx->thr_no);
  pthread_barrier_wait(ctx->barrier);


  // --- open a different file
  if (ctx->flags & TC_OPEN2) {
     static int  vers = 0;
     sprintf(thr_path, "%s.%d.meta.v%d", ctx->path, ctx->thr_no, vers++);
     cLOG("thr%d: opening %s\n", ctx->thr_no, thr_path);
     SocketHandle fd = {0};
     // thrNEED_GT0( skt_open(&fd,  thr_path,  (O_WRONLY|O_CREAT), 0660) );
     thrNEED_GT0( skt_open(&fd,  thr_path,  (O_WRONLY|O_CREAT), 0666) );
  }

  // --- put
  if (ctx->flags & TC_WRITE) {
     cLOG("thr%d: writing %llu bytes\n", ctx->thr_no, (size_t)BUFSIZE);
     bytes_moved = skt_write(handle, buf, BUFSIZE);
     cLOG("thr%d: wrote   %lld bytes\n", ctx->thr_no, bytes_moved);
     thrNEED( bytes_moved == BUFSIZE );
  }

  // --- close
  if (ctx->flags & TC_CLOSE) {
     cLOG("thr%d: closing\n", ctx->thr_no);
     thrNEED_0( skt_close(handle) );
  }

  cLOG("thr%d: done\n", ctx->thr_no);
  return NULL;
}

// Still chasing the fuse bug.  Try two opens from different threads.
// This does open, write, close all in the same thread-invocation.
int client_test3(const char* path) {

   pthread_barrier_t barrier;
   pthread_t         thr[2];

   ThreadContext     ctx0 = { .flags   = (TC_OPEN|TC_WRITE|TC_CLOSE),
                              .thr_no  = 0,
                              .path    = path,
                              .handle  = {0},
                              .barrier = &barrier };

   ThreadContext     ctx1 = { .flags   = (TC_OPEN|TC_WRITE|TC_CLOSE),
                              .thr_no  = 1,
                              .path    = path,
                              .handle  = {0},
                              .barrier = &barrier };

   pthread_barrier_init(&barrier, NULL, 2);

   // launch two threads to do everything
   cLOG("launching thr0\n");
   pthread_create(&thr[0], NULL, client_test3_thr, &ctx0);
   cLOG("launching thr1\n");
   pthread_create(&thr[1], NULL, client_test3_thr, &ctx1);

   // wait for threads to complete
   cLOG("waiting for thr0\n");
   void* rc0;
   pthread_join(thr[0], &rc0);

   cLOG("waiting for thr1\n");
   void* rc1;
   pthread_join(thr[1], &rc1);
}



// Still chasing the fuse bug.  Try two opens from different threads.  This
// does open and open2 all in the same thread-invocation.  One of the
// threads does a seteuid(geteuid()) before either thread tries the second
// open.
//
// FOUND IT.  Thanks to Garrett for his own bug-reproducer, using seteuid in
//     an RDMA + MPI application.  Turns out that we can work around this in
//     fuse, using the following observation:
//
//     The syscall version of setresuid() only affects the local thread.
//     Other threads continue to be able to open new rsocket connections,
//     etc.  Thus, if fuse will launch threads from inside fuse-open (after
//     the setresuid syscall) which survive for the lifetime of the
//     connection, and are responsible for any new opens and closes related
//     to the file-handle, then it should work.
//
//     The new threads support in libne that Will wrote, does exactly that
//     (for writes).  We'll need a similar thing for fuse reads.
//
int client_test3b(const char* path) {

   pthread_barrier_t barrier;
   pthread_t         thr[2];

   ThreadContext     ctx0 = { // .flags   = (TC_OPEN|TC_SETEUID|TC_OPEN2),
                              .flags   = (TC_OPEN|TC_SETEUID_SYS|TC_OPEN2),
                              .thr_no  = 0,
                              .path    = path,
                              .handle  = {0},
                              .barrier = &barrier };

   ThreadContext     ctx1 = { .flags   = (TC_OPEN|TC_OPEN2),
                              .thr_no  = 1,
                              .path    = path,
                              .handle  = {0},
                              .barrier = &barrier };

   pthread_barrier_init(&barrier, NULL, 2);

   // launch two threads to do everything
   cLOG("launching thr0\n");
   pthread_create(&thr[0], NULL, client_test3_thr, &ctx0);
   cLOG("launching thr1\n");
   pthread_create(&thr[1], NULL, client_test3_thr, &ctx1);

   // wait for threads to complete
   cLOG("waiting for thr0\n");
   void* rc0;
   pthread_join(thr[0], &rc0);

   cLOG("waiting for thr1\n");
   void* rc1;
   pthread_join(thr[1], &rc1);
}


// ...........................................................................
// client_test3c
//
// like client_test3, with two threads each writing to different remote
// files, but now we do the individual open, write, close operations in
// different threads.
//
// RESULT: This works fine.  Multiple threads calling skt_open() works,
//          even when they already have another per-thread socket-handle
//          opened.  It works whether they have done some writing to the
//          previously-opened handle, or not.  Works as root or a regular
//          user.
// ...........................................................................

int client_test3c(const char* path) {

   static const int  N_THR = 2;

   int               i;
   pthread_barrier_t barrier;

   pthread_t         thr[N_THR];
   ThreadContext     ctx[N_THR];

   pthread_barrier_init(&barrier, NULL, N_THR);

   for (i=0; i<N_THR; ++i) {
      ThreadContext ctx1 = { .flags   = 0,
                             .thr_no  = i,
                             .path    = path,
                             .handle  = {0},
                             .barrier = &barrier };
      ctx[i] = ctx1;
   }


#if 1
   // *** WORKS FINE

   int sequence[] = {
      TC_OPEN,
      TC_WRITE,
      TC_OPEN2,
      TC_CLOSE,
      TC_DONE
   };
#elif 0
   // *** WORKS FINE

   int sequence[] = {
      TC_OPEN,
      TC_WRITE,
      TC_CLOSE,
      TC_OPEN2, // do 2nd open after closing first handle
      TC_DONE
   };
#elif 0
   // *** THIS WORKS, after adding initializations ("fd = {0}") to the
   //     OPEN2 case in client_test3_thr.

   int sequence[] = {
      TC_OPEN,
      TC_WRITE,
      TC_OPEN2,
      TC_OPEN2, // do 3rd open, using same stack-alloc'ed fd
      TC_OPEN2, // do 4th open
      TC_DONE
   };
#endif

   // Do open, write, close, in separate thread-invocations
   int* flag_ptr = sequence;
   while (*flag_ptr != TC_DONE) {

      // cLOG("\n\nTHREAD-FLAGS = 0x%x\n", *flag_ptr);
      cLOG("\n\nTHREAD-FLAGS = %s\n", flag_name(*flag_ptr));

      for (i=0; i<N_THR; ++i) {
         ctx[i].flags = *flag_ptr;
      }

      for (i=0; i<N_THR; ++i) {
         cLOG("launching thr %d\n", i);
         pthread_create(&thr[i], NULL, client_test3_thr, &ctx[i]);
      }

      // wait for threads to complete
      for (i=0; i<N_THR; ++i) {
         cLOG("waiting for thr %d\n", i);
         void* rc;
         pthread_join(thr[i], &rc);
         if (rc) {
            ERR("thr %d returned non-zero\n", i);
            return -1;
         }
      }

      // --- prepare to invoke the next operation in sequence[], when threads run again
      ++ flag_ptr;
   }

   cLOG("\n\nDONE\n");
}




// Like test3b, but now we want to know whether just doing a seteuid in the
// main program, taints all subsequent threads that use IB.
//
// RESULT:  Sure enough, the first two threads succeed, and the third fails.
//          Third fails even if master used system-call.

int client_test3d(const char* path) {

   pthread_barrier_t barrier;
   pthread_t         thr0;
   void*             rc0;

   const size_t      MAX_PATH = 1024;
   char              path0[MAX_PATH];
   int               path_no = 0;

   ThreadContext     ctx0 = { .flags   = (TC_OPEN|TC_WRITE|TC_CLOSE),
                              .thr_no  = 0,
                              .path    = path0,
                              .handle  = {0},
                              .barrier = &barrier };

   pthread_barrier_init(&barrier, NULL, 1);


   // --- (1) open/wr/close
   snprintf(path0, MAX_PATH, "%s.%d", path, path_no++);
   cLOG("launching thr0, path = %s\n", path0);
   pthread_create(&thr0, NULL, client_test3_thr, &ctx0);

   cLOG("waiting for thr0\n");
   pthread_join(thr0, &rc0);



   // --- (2) open/wr/close
   memset(&ctx0.handle, 0, sizeof(ctx0.handle)); /* need to do this? */
   snprintf(path0, MAX_PATH, "%s.%d", path, path_no++);
   cLOG("launching thr0, path = %s\n", path0);
   pthread_create(&thr0, NULL, client_test3_thr, &ctx0);

   cLOG("waiting for thr0\n");
   pthread_join(thr0, &rc0);



   // --- screw up all future IB activity?
#if 0
   //    (a) straight fn-call
   
   cLOG("calling seteuid()\n");
   seteuid(geteuid());

#else
   //    (b) system-call

   uid_t old_ruid;
   uid_t old_euid;
   uid_t old_suid;
   int   rc;

   cLOG("GETTING euid\n");
   rc = syscall(SYS_getresuid, &old_ruid, &old_euid, &old_suid);
   cLOG("euid = %d (rc=%d)\n", old_euid, rc);

   cLOG("SETTING euid\n");
   rc = syscall(SYS_setresuid, -1, old_euid, -1);
   cLOG("euid = %d (rc=%d)\n", old_euid, rc);
#endif


   // --- (3) open/wr/close
   memset(&ctx0.handle, 0, sizeof(ctx0.handle)); /* need to do this? */
   snprintf(path0, MAX_PATH, "%s.%d", path, path_no++);
   cLOG("launching thr0, path = %s\n", path0);
   pthread_create(&thr0, NULL, client_test3_thr, &ctx0);

   cLOG("waiting for thr0\n");
   pthread_join(thr0, &rc0);
}




// ...........................................................................
// Similar to test3b, but see whether the seteuid taints a thread that was
// spun up before seteuid is called.  Also, check whether the calling
// process is affected.
//
// RESULT:
//
//   (a) using the seteuid SYSCALL limits the damage to the local thread.
//       Other threads are not affected.
//       Even the calling process is not affected.
//
//   (b) using seteuid() affects all threads in the process,
//       including other threads that are running,
//       as well as the calling process.
//       skt_open() will fail in all of them, after the seteuid().
//
// ...........................................................................

int client_test3e(const char* path) {

   static const int  N_THR = 2;

   int               i;
   pthread_barrier_t barrier;

   pthread_t         thr[N_THR];
   ThreadContext*    ctx[N_THR];

   ThreadContext     ctx0 = { .flags   = (TC_SETEUID_SYS|TC_OPEN2),  // (a)
                              // .flags   = (TC_SETEUID|TC_OPEN2),   // (b)
                              .thr_no  = 0,
                              .path    = path,
                              .handle  = {0},
                              .barrier = &barrier };

   ThreadContext     ctx1 = { .flags   = (TC_OPEN|TC_OPEN2),
                              .thr_no  = 1,
                              .path    = path,
                              .handle  = {0},
                              .barrier = &barrier };

   ctx[0] = &ctx0;
   ctx[1] = &ctx1;

   pthread_barrier_init(&barrier, NULL, 2);


   // --- launch threads
   for (i=0; i<N_THR; ++i) {
      cLOG("launching thr %d\n", i);
      pthread_create(&thr[i], NULL, client_test3_thr, ctx[i]);
   }


   // --- wait for threads to complete
   for (i=0; i<N_THR; ++i) {
      cLOG("waiting for thr %d\n", i);
      void* rc0;
      pthread_join(thr[i], &rc0);
      cLOG("thr%d returned %lld\n", i, (ssize_t)rc0);
   }


   // --- how about the parent process?
   const size_t      MAX_PATH = 1024;
   char              path0[MAX_PATH];
   int               path_no = 0;
   SocketHandle      handle = {0};

   cLOG("opening %s\n", path);
   NEED_GT0( skt_open(&handle, path, (O_WRONLY|O_CREAT), 0666) );



   cLOG("done\n");
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
  fprintf(stderr, "Usage: %s  <operation>  <file_spec>\n", prog);
  fprintf(stderr, "where:\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "<operation> is one of:\n");
  fprintf(stderr, "  -p             PUT -- read from stdin, write to remote file\n");
  fprintf(stderr, "  -g             GET -- read from remote file, write to stdout\n");
  fprintf(stderr, "  -s             stat the remote file\n");
  fprintf(stderr, "  -r             rename to original + '.renamed'\n");
  fprintf(stderr, "  -o             chown to 99:99\n");
  fprintf(stderr, "  -R             hold read-handle open, so reaper-thread will kill connection\n");
  fprintf(stderr, "  -t <test_no>   perform various unit-tests {1,1b,1c,2,3,3b}\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "<flie_spec> is <host>:<port>/<fname>\n");
}

int
main(int argc, char* argv[]) {

  if (argc < 3) {
    usage(argv[0]);
    return -1;
  }

#if (DEBUG_SOCKETS == syslog)
  // POSIX basename() may alter arg
  char* last_slash = strrchr(argv[0], '/');
  char* progname = (last_slash ? last_slash+1 : argv[0]);
  openlog(progname, LOG_CONS|LOG_PID, LOG_USER);
#endif


  // --- parse args
  char    cmd;
  char*   test_no = NULL;
  char*   file_spec = NULL;
  int     c;
  while ( (c = getopt(argc, argv, "t:gpsroRh")) != -1) {
    switch (c) {
    case 't':      cmd = 't';  test_no=optarg;    break;

    case 'p':      cmd = 'p';  break;
    case 'g':      cmd = 'g';  break;
    case 's':      cmd = 's';  break;
    case 'r':      cmd = 'r';  break;
    case 'o':      cmd = 'o';  break;
    case 'R':      cmd = 'R';  break;

    case 'h':
    default:
      usage(argv[0]);
      return -1;
    }
  }

  // I thought getopt() was supposed to strip out the argv elements
  // that it pulled out.  Apparently not.
  file_spec=argv[2];
  if (cmd == 't')
    file_spec=argv[3];


  // --- start timer
  struct timespec start;
  if (clock_gettime(CLOCK_REALTIME, &start)) {
    ERR("failed to get START timer '%s'\n", strerror(errno));
    return -1;                // errno is set
  }

  // --- perform op
  ssize_t bytes_moved = 0;
  switch (cmd) {
  case 'p':   bytes_moved = client_put(file_spec); break;
  case 'g':   bytes_moved = client_get(file_spec); break;
  case 's':   bytes_moved = client_stat(file_spec); break;
  case 'r':   bytes_moved = client_rename(file_spec); break;
  case 'o':   bytes_moved = client_chown(file_spec); break;
  case 'R':   bytes_moved = client_reap_read(file_spec); break;

  case 't': {
    size_t  test_no_len = strlen(test_no);
#   define MATCH(TEST_NO,STR)  ((test_no_len == strlen(STR)) && !strcmp((TEST_NO), (STR)))
    if (     MATCH(test_no, "1"))
      bytes_moved = client_test1(file_spec);
    else if (MATCH(test_no, "1b"))
      bytes_moved = client_test1b(file_spec);
    else if (MATCH(test_no, "1c"))
      bytes_moved = client_test1c(file_spec);
    else if (MATCH(test_no, "2"))
       bytes_moved = client_test2(file_spec, 0);
    else if (MATCH(test_no, "2b"))
       bytes_moved = client_test2(file_spec, 1);
    else if (MATCH(test_no, "3"))
      bytes_moved = client_test3(file_spec);
    else if (MATCH(test_no, "3b"))
      bytes_moved = client_test3b(file_spec);
    else if (MATCH(test_no, "3c"))
      bytes_moved = client_test3c(file_spec);
    //    else if (MATCH(test_no, "3d"))
    //       bytes_moved = client_test3d(file_spec);
    else if (MATCH(test_no, "3e"))
      bytes_moved = client_test3e(file_spec);
    else {
      ERR("unknown test: %s\n", test_no);
      return -1;
    }
#   undef MATCH
  }
    break;
      
  default:
    ERR("unsupported command: %s\n", command_str(cmd));
    return -1;
  }

  if (bytes_moved < 0) {
    perror("error");
    return -1;
  }

  // --- compute bandwidth
  struct timespec end;
  if (clock_gettime(CLOCK_REALTIME, &end)) {
    ERR("failed to get END timer '%s'\n", strerror(errno));
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
