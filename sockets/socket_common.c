#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

#include "socket_common.h"


// Issue repeated reads until we've gotten <size> bytes, or error, or
// EOF.  Return negative for error.  Otherwise, return the total
// number of bytes that could be read.  If return-value is positive,
// but less than <size>, there must've been an EOF.

ssize_t read_buffer(int fd, char* buf, size_t size) {
  DBG("read_buffer(%d, 0x%llx, %lld\n", fd, buf, size);
  if (size > SSIZE_MAX) {
    fprintf(stderr, "<size> %llu exceeds maximum signed return value\n",
	    size, SSIZE_MAX);
    return -1;
  }

  char*   read_ptr    = buf;
  size_t  read_total  = 0;
  size_t  read_remain = size;
  int     eof         = 0;

  while (read_remain && !eof) {

    /// ssize_t read_count = read(fd, read_ptr, read_remain);
    ssize_t read_count = recv(fd, read_ptr, read_remain, 0);
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
int write_buffer(int fd, char* buf, size_t size) {
  DBG("write_buffer(%d, 0x%llx, %lld\n", fd, buf, size);

  char*  write_ptr     = buf;
  size_t write_remain  = size;
  size_t write_total   = 0;
  while (write_remain) {

    ssize_t write_count = write(fd, write_ptr, write_remain);
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

  return 0;
}
