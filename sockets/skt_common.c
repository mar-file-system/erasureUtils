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
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>

#define  NE_LOG_PREFIX   "libne_sockets"
#include "ne_logging.h"

#include "skt_common.h"
#include "fast_timer.h"


// ...........................................................................
//
// NOTE: librdmacm has a race-condition.  A patch is pending
//       (5ac0576d51dd).
//
// DETAILS: If rs_free() releases the fd before calling rs_remove(), a
//       second thread in rsocket() may acquire the same fd and store its
//       own rs in the corresponding index-element.  When the first thread
//       then gets around to calling rs_remove() it ends up removing the rs
//       of the second thread, and storing a NULL there.
//
//       Several functions still do not check for NULL after retrieving an
//       rs from the index for an open rsocket.  Thus, the second thread
//       would get a segfault in any of the following functions: rrecv,
//       rrecvfrom, rsend, rsendto, rsendv, riomap, riounmap, riowrite.
// 
// WORK_AROUND: Until the patch is integrated, we add per-process locking
//       around rsocket() and rclose().  This locking becomes unnecessary,
//       as soon as the patch is integrated into the library.
//
// ...........................................................................

// // use the "fastlock" defined in librdmacm
// #define DEFINE_ATOMICS 1
// #include <rdma/rdma_cma.h>
// static fastlock_t  lock;
//
// called once, before anything else
// void skt_lock_init() {
//    fastlock_init(&lock);
// }


// static sem_t  sem;
pthread_mutex_t rdma_bug_lock = PTHREAD_MUTEX_INITIALIZER;








// This is used for abnormal exits on client or server.
// (e.g., server-thread exits or is cancelled)
//
void
shut_down_handle(SocketHandle* handle) {
    int dbg;                    // check return values

#if (SOCKETS == SKT_unix)
  if (handle->flags & HNDL_FNAME) {
    neDBG("unlinking '%s'\n", handle->fname);
    unlink(handle->fname);
    handle->flags &= ~HNDL_FNAME;
  }
#endif

  if (handle->flags & HNDL_CONNECTED) {

    // rclose() -> rshutdown() -> read() can hang for ~30 sec.  If we are
    // wrapped in BUG_LOCK(), this can cause large numbers of
    // server-threads to be stuck waiting to release their fd,
    // one-at-a-time, preventing allocation of new threads, making the
    // server unresponsive.
    //
    // UNFORTUNTATELY: rsetsockopt() silently ignores SND/RCVTIMEO options.
    struct timeval tv;
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    SETSOCKOPT(handle->peer_fd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
    SETSOCKOPT(handle->peer_fd, SOL_SOCKET, SO_SNDTIMEO, (const void*)&tv, sizeof(tv));

#if 1
    // NOTE: As of librdmacm-1.0.21 (installed in our TOSS-2 RHEL6.9
    //       machines) rclose() calls rshutdown(), if needed.
    //       
    // Commented out because rshutdown() sometimes deadlocks.
    // The stacktrace isn't identical to the one reported here:
    //    https://github.com/ofiwg/librdmacm/issues/1
    //
    // But I'm currently using the latest version of librdmacm.
    // Instead, we have:
    //    sem_wait () at ../nptl/sysdeps/unix/sysv/linux/x86_64/sem_wait.S:86
    //    0x00002b9eb5674847 in fastlock_acquire (rs=0x25db730, nonblock=0, test=0x2b9eb5670870 <rs_conn_all_sends_done>) at src/cma.h:131
    //    rs_process_cq (rs=0x25db730, nonblock=0, test=0x2b9eb5670870 <rs_conn_all_sends_done>) at src/rsocket.c:2022
    //    0x00002b9eb5674acc in rshutdown (socket=<value optimized out>, how=<value optimized out>) at src/rsocket.c:3242
    //    0x00000000004078f8 in shut_down_handle (handle=0x60f608) at skt_common.c:101
    //    0x000000000040422e in shut_down_thread (arg=0x60f5e8) at marfs_objd.c:207
    //    0x00000000004046da in server_thread (arg=0x60f5e8) at marfs_objd.c:748
    //    0x00002b9eb5452aa1 in start_thread (arg=0x2b9eb718a700) at pthread_create.c:301
    //    0x00002b9eb596593d in clone () at ../sysdeps/unix/sysv/linux/x86_64/clone.S:115
    //
    // UPDATE 2018-02-20:
    //
    // I'd bet that the deadlocking mentioned above was happening before we
    // patched rdma-core.  If so, then rshutdown() should "just work", in
    // implementations that include rdma-core after ~2017-09.  Meanwhile,
    // for running on RHEL6 we use BUG_LOCK() to implement a work-around,
    // which imposes locking around opens and closes.  I don't think we're
    // seeing deadlocks in rshutdown(), but rclose() -> rshutdown() ->
    // read() does take ~30 seconds to figure out that a killed peer is
    // never going to respond.  Therefore, it seems like doing the
    // rshutdown() outside BUG_LOCK/UNLOCK could avoid holding that lock
    // all that time.  Trying it now ...

    neDBG("peer_fd %3d: shutdown\n", handle->peer_fd);
    dbg = SHUTDOWN(handle->peer_fd, SHUT_RDWR);
    if (dbg)
       handle->flags |= HNDL_DBG3;
    neDBG("peer_fd %3d: shutdown = %d\n", handle->peer_fd, dbg);
#endif
  }

  if (handle->peer_fd > 0) {
#if 1
    // NOTE: As of librdmacm-1.0.21 (installed in our TOSS-2 RHEL6.9
    //       machines), rclose() calls rs_free() -> rs_free_iomappings() ->
    //       riounmap().
    //
    // Without doing our own riounmap, we get a segfault in the
    // CLOSE() below, when rclose() calls riounmap() itself.
    //
    // It's okay if handle->rio_buf only has local scope, in server_put(),
    // we're just unmapping the address here, not using it.
    //
    if (handle->flags & HNDL_RIOMAPPED) {
      neDBG("peer_fd %3d: riounmap'ing\n", handle->peer_fd);
      dbg = RIOUNMAP(handle->peer_fd, handle->rio_buf, handle->rio_size);
      if (dbg)
         handle->flags |= HNDL_DBG3;
      neDBG("peer_fd %3d: unmap = %d\n", handle->peer_fd, dbg);
      handle->flags &= ~HNDL_RIOMAPPED;
    }
#endif

    neDBG("peer_fd %3d: close\n", handle->peer_fd);
    BUG_LOCK();
    dbg = CLOSE(handle->peer_fd);
    BUG_UNLOCK();
    if (dbg)
       handle->flags |= HNDL_DBG3;
    neDBG("peer_fd %3d: close = %d\n", handle->peer_fd, dbg);

    handle->flags &= ~HNDL_CONNECTED;
  }

  handle->flags = 0;
  neDBG("peer_fd %3d: done\n", handle->peer_fd);
  handle->peer_fd = -1;
}

void jshut_down_handle(void* handle) {
  shut_down_handle((SocketHandle*)handle);
}
void jskt_close(void* handle) {
  skt_close((SocketHandle*)handle);
}



// Issue repeated reads until we've gotten <size> bytes, or error, or
// EOF.  Return negative for error.  Otherwise, return the total
// number of bytes that could be read.  If return-value is positive,
// but less than <size>, there must've been an EOF.

ssize_t read_buffer(int fd, char* buf, size_t size, int is_socket) {
  neDBG("read_buffer(%d, 0x%llx, %lld, %d)\n", fd, buf, size, is_socket);


#ifdef USE_RIOWRITE
  // If we would be reading from an rsocket where the writer is using
  // riowrite(), then we won't see anything in the fd; RDMA is
  // transparently moving data directly into our buffer.  In that
  // case, the writer will send us a DATA pseudo-packet, to indicate
  // when the RDMA is complete.  (And we already told the writer how
  // big our buffer is, so the DATA packet won't indicate a size
  // bigger than that.)  If we get an actual EOF on the socket, that's
  // an error; the server should send DATA 0, to indicate an EOF on
  // file-data.

  if (is_socket) {
    PseudoPacketHeader header;
    NEED_0( read_pseudo_packet_header(fd, &header, 0) );
    if (HDR_CMD(&header) != CMD_DATA) {
       neERR("unexpected pseudo-packet: %s\n", command_str(HDR_CMD(&header)));
      return -1;
    }

    return HDR_SIZE(&header);
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

    neDBG("read_count(1): %lld\n", read_count);

    if (read_count < 0) {
      neDBG("read error: %s\n", strerror(errno));
      return read_count;
    }
    else if (read_count == 0) {
      eof = 1;
      neDBG("read EOF\n");
    }

    read_total  += read_count;
    read_ptr    += read_count;
    read_remain -= read_count;
  }
  neDBG("read_total: %lld\n", read_total);

  // // wouldn't want to do this with large reads ...
  // neDBG("contents: %s\n", read_buf);

  return read_total;
}




// write bytes until <size>, or error.
// Return 0 for success, negative for error.
//
// WARNING: Do not use this to jam arbitrary amounts of data into a
//    socket that might use RIOWRITE.  write_buffer() can be used to
//    assure that the reader's request-amount is fully written, but
//    not to assure that the writer's buffer is fully written.  See
//    skt_write() for better understanding.
//
// NOTE: If <size>==0, the server will treat it as EOF.
//
// NOTE: In order to reliably weave remote-fsync into the protocol,
//    skt_fsync() just sets a flag in the handle.  The next call to skt_write()
//    
//    copy_file_to_socket()

int write_buffer(int fd, const char* buf, size_t size, int is_socket, off_t offset) {
  neDBG("write_buffer(%d, 0x%llx, %lld, skt:%d, off:0x%llx)\n", fd, buf, size, is_socket, offset);

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

    neDBG("write_count: %lld\n", write_count);
    if (write_count < 0) {
      neERR("write of %llu bytes failed, after writing %llu: %s\n",
          write_remain, write_total, strerror(errno));
      return -1;
    }
    write_total   += write_count;
    write_ptr     += write_count;
    write_remain  -= write_count;

#if 0
    if (errno == ENOSPC)
      neDBG("buffer is full.  ignoring.\n");
    else if (errno == EPIPE) {
      neDBG("client disconnected?\n");
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
  neDBG("write_total: %lld\n", write_total);


#ifdef USE_RIOWRITE
  if (is_socket) {
     NEED_0( write_pseudo_packet(fd, CMD_DATA, size, NULL) );
  }
#endif

  return 0;
}







// for small socket-reads that don't use RDMA
//
// BACKGROUND: We previously used blocking requests, but they continue to
//     hang, after a client is killed.  The reaper-task was added to come
//     along and cancel threads in that situation, but rsockets seems
//     vulnerable to deadlocking in shutdown/close, when we use a
//     reaper-thread to clean-up stalled blocking I/O.  Presumably, the
//     issue has to do with state that is left in the rsocket handles when
//     the reaper-task kills a task that is blocked on I/O.  The result is
//     that file-descriptors are lost, even when the reaper is cleaning up
//     stalled/cancelled descriptors.
//
// We use non-blocking I/O. When a client is killed, server-threads will
// eventually time-out (currently 30 sec), at which point the thread will
// shutdown its own handle.  This seems to work smoothly, without
// deadlocks.  No noticable performance cost, compared with blocking I/O.
//
// However, it seems (as of RHEL 6.6) that rselect() has a race-condition.
// It does not detect the case where a message arrived before rselect() was
// entered.  We make an ugly kludge to accommmodate this by breaking our
// timeout into many small wait periods (currently 1 sec), and trying the
// recv() in between.  Presumably, we will sometimes enter the rselect()
// before the message arrives, making this approach somewhat better than
// just iterative sleep() and recv().
//
// In the test case that was deadlocking due to the race-condition in
// rselect(), the new approach succeeds 349 times on iteration 0, 459 times
// on iteration 1, and 2 times on iteration 2.  This doesn't say how much
// time is spent in rselect().  According to the select(2) manpage, Linux
// modifies the tv struct to show remaining time, after select returns.
// However, this must not apply to rselect(), because tv is always 1.0,
// whether rselect() returns 1 or 0.
//
// UPDATE: See the comments about the test-case, above.  The rselect() is
//     apparently never actually returning.  Instead, we're effectively
//     just iterating with a 1 second sleep.  Therefore, I'm pulling it
//     back out, reverting to MSG_WAITALL, for now (see "#if 0").  This
//     revives the possibility that client/server threads may hang forever
//     in the event of an undetected peer-failure, but allows
//     non-disastrous read-performance, in the meantime.
//
// UPDATE: We switched to rpoll() because we were running out of fds (max
//     size for FD_SET is 1024), and, anyhow, rpoll() should be more
//     efficient.  Tests show that rpoll() works correctly in the places we
//     were worried about for rselect(): (a) a message is sent before
//     rpoll() is invoked by teh receiver, or (b) a message is sent when
//     rpoll() is waiting for a timeout.
//
// TBD: As loads grow on the server, this might want to do something
//     like write_buffer() does, to handle incomplete writes.  [DONE.]

int read_raw(int fd, char* buf, size_t size, int peek_p) {
   neDBG("read_raw(%d, 0x%llx, %lld, %d)\n", fd, buf, size, peek_p);

   int        rc = 0;

   const int  wait_millis_tot = (RD_TIMEOUT * 1000L);
   int        period_millis   = (POLL_PERIOD * 1000L);
   int        wait_millis     = period_millis;
   if (unlikely(period_millis > wait_millis_tot))
      wait_millis = wait_millis_tot;

   FastTimer  timer           = {0};
   char*      buf1            = buf;
   size_t     size1           = size;

   fast_timer_start(&timer);

   int       i;
   for (i=0; 1; ++i) {    //   formerly: i<MAX_RD_POLLS

      // --- wait for the fd to have data
      //     (see comment about race-condition)
      //     Actually, we just get HUP, not RDHUP, if other end hung up

      int           interrupted = 0;
      int           timed_out   = 0;
      ssize_t       read_count  = 0;
      struct pollfd pfd         = { .fd      = fd,
                                    .events  = (POLLIN | POLLRDHUP),
                                    //         implicit: POLLERR|POLLHUP|POLLNVAL
                                    .revents = 0 };

      neDBG("entering RD poll with timeout = %d ms [iter: %d]\n", wait_millis, i);
      rc = POLL(&pfd, 1, wait_millis);
      neDBG("poll returned %d (revents: 0x%02x) [iter: %d]\n", rc, pfd.revents, i);

      if (rc < 0) {
         if (errno == EINTR)
            interrupted = 1;
         else {
            neERR("poll failed: %s [iter: %d]\n", strerror(errno), i);
            errno = EIO;
            return -1;
         }
      }
      else if (rc == 0) {
         timed_out = 1;
      }
      else if (! (pfd.revents & POLLIN)) { // see POLLOUT in write_raw()
         neERR("poll got err-flags 0x%x [iter: %d]\n", pfd.revents, i);
         errno = EIO;
         return -1;
      }



      if (unlikely(interrupted))
        neDBG("interrupted.  Will try again [iter: %d]\n", i);

      else if (unlikely(timed_out))
        neDBG("timed-out.  Will try again [iter: %d]\n", i);

      else {

        // --- do the read
        //     NOTE: HUP also shows POLLIN.  RECV() then returns 0.
        neDBG("recv(%d, 0x%lx, %ld, 0x%02x) [iter: %d]\n",
              fd, (size_t)buf1, size1, (peek_p ? MSG_PEEK : MSG_DONTWAIT), i);
        read_count = RECV(fd, buf1, size1, (peek_p ? MSG_PEEK : MSG_DONTWAIT));


        // --- analyze read-results
        if (likely(read_count == size1)) {
          neDBG("read OK [iter: %d]\n", i);
          return 0;
        }
        else if (! read_count) {
          neERR("read EOF [iter: %d]\n", i);
          return -1;     // you called read_raw() because you expected something
        }
        else if (read_count > 0) {
          neERR("read %lld instead of %lld bytes [iter: %d]\n",
           read_count, size1, i);

          // got part of our expected read.  Iterate to get the rest.
          buf1  += read_count;
          size1 -= read_count;
        }
        else if ((errno != EAGAIN)
            && (errno != EWOULDBLOCK)) {
          neERR("read failed [iter: %d]: %s\n", i, strerror(errno));
          return -1;
        }
      }


      // --- compute remaining timeout for retry
      fast_timer_stop(&timer);
      fast_timer_inits();       // first call computes ticks_per_sec

      neDBG("total wait, so far: %7.4f ms [iter: %d]\n", fast_timer_msec(&timer), i);

      int remain_millis = wait_millis_tot - fast_timer_msec(&timer);
      if (unlikely(remain_millis <= 0))
         break;                 // timed out
      else if (unlikely(remain_millis < period_millis))
         wait_millis = remain_millis; // last ~period
      else
         wait_millis = period_millis;

      neDBG("accumulated time = %d sec\n", (int)fast_timer_sec(&timer));
      fast_timer_start(&timer);
   }

   neERR("timeout after %d sec\n", RD_TIMEOUT);
   errno = EIO;
   return -1;
}


// for small socket-writes that don't use RDMA
//
// See notes at read_raw().  It's much more rare that rselect() would
// fail for write_raw().  I thought I saw an indication that it may
// have been happening, but the test I'm looking at shows 0/7946 calls that
// had to iterate in write_raw().
//
// TBD: As loads grow on the server, this might want to do something
//     like write_buffer() does.  [DONE.]


int write_raw(int fd, char* buf, size_t size) {
   neDBG("write_raw(%d, 0x%llx, %lld)\n", fd, buf, size);

   int        rc = 0;

   const int  wait_millis_tot = (WR_TIMEOUT * 1000L);
   int        period_millis   = (POLL_PERIOD * 1000L);
   int        wait_millis     = period_millis;
   if (unlikely(period_millis > wait_millis_tot))
      wait_millis = wait_millis_tot;

   FastTimer  timer           = {0};
   char*      buf1            = buf;
   size_t     size1           = size;

   fast_timer_start(&timer);

   int       i;
   for (i=0; 1; ++i) {    //   formerly: i<MAX_WR_POLLS

      // --- wait for the fd to have data
      //     (see comment about race-condition)

      int           interrupted = 0;
      int           timed_out   = 0;
      ssize_t       write_count = 0;
      struct pollfd pfd         = { .fd      = fd,
                                    .events  = (POLLOUT),
                                    //         implicit: POLLERR|POLLHUP|POLLNVAL
                                    .revents = 0 };

      neDBG("entering WR poll with timeout = %d ms [iter: %d]\n", wait_millis, i);
      rc = POLL(&pfd, 1, wait_millis);
      neDBG("poll returned %d (revents: 0x%02x) [iter: %d]\n", rc, pfd.revents, i);

      if (rc < 0) {
         if (errno == EINTR)
            interrupted = 1;
         else {
            neERR("poll failed: %s [iter: %d]\n", strerror(errno), i);
            errno = EIO;
            return -1;
         }
      }
      else if (rc == 0) {
         timed_out = 1;
      }
      else if (! (pfd.revents & POLLOUT)) { // I saw POLLHUP + POLLOUT ?
         neERR("poll got err-flags 0x%x [iter: %d]\n", pfd.revents, i);
         errno = EIO;
         return -1;
      }



      if (unlikely(interrupted))
         neDBG("interrupted.  Will try again [iter: %d]\n", i);

      else if (unlikely(timed_out))
        neDBG("timed-out.  Will try again [iter: %d]\n", i);

      else {

        // --- do the write
        neDBG("send(%d, 0x%lx, %ld, 0x%02x) [iter: %d]\n",
              fd, (size_t)buf1, size1, MSG_DONTWAIT, i);
        write_count = SEND(fd, buf1, size1, MSG_DONTWAIT);


        // --- analyze write-results
        if (likely(write_count == size1)) {
          neDBG("write OK [iter: %d]\n", i);
          return 0;
        }
        else if (! write_count) {
          // apparently, this can happen (e.g. if destination is overworked)
          neDBG("wrote 0, technically not an error [iter: %d]\n", i);
        }
        else if (write_count > 0) {
          neERR("wrote %lld instead of %lld bytes [iter: %d]\n",
           write_count, size1, i);

          // got part of our expected read.  Iterate to get the rest.
          buf1  += write_count;
          size1 -= write_count;
        }
        else if ((errno != EAGAIN)
            && (errno != EWOULDBLOCK)) {
          neERR("write failed [iter: %d]: %s\n", i, strerror(errno));
          return -1;
        }
      }


      // --- compute remaining timeout for retry
      fast_timer_stop(&timer);
      fast_timer_inits();       // first call computes ticks_per_sec

      neDBG("total wait, so far: %7.4f ms [iter: %d]\n", fast_timer_msec(&timer), i);

      int remain_millis = wait_millis_tot - fast_timer_msec(&timer);
      if (unlikely(remain_millis <= 0))
         break;                 // timed out
      else if (unlikely(remain_millis < period_millis))
         wait_millis = remain_millis; // last ~period
      else
         wait_millis = period_millis;

      neDBG("accumulated time = %d sec\n", (int)fast_timer_sec(&timer));
      fast_timer_start(&timer);
   }

   neERR("timeout after %d sec\n", WR_TIMEOUT);
   errno = EIO;
   return -1;
}



// [lifted from marfs_common.c, with name changes to avoid link-time conflicts
// when both impls are present.]
//
// htonll() / ntohll() are not provided in our environment.  <endian.h> or
// <byteswap.h> make things easier, but these are non-standard.  Also, we're
// compiled with -Wall, so we avoid pointer-aliasing that makes gcc whine.
//
// TBD: Find the appropriate #ifdefs to make these definitions go away on
//     systems that already provide them.


// // see http://esr.ibiblio.org/?p=5095
// #define IS_LITTLE_ENDIAN (*(uint16_t *)"\0\xff" >= 0x100)
// 

uint64_t hton64(uint64_t ll) {
   // if (IS_LITTLE_ENDIAN) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint64_t result;
    char* sptr = ((char*)&ll) +7; // gcc doesn't mind char* aliases
    char* dptr = (char*)&result; // gcc doesn't mind char* aliases
    int i;
    for (i=0; i<8; ++i)
      *dptr++ = *sptr--;
    return result;
    //  }
    //  else
#else
    return ll;
#endif
}

uint64_t ntoh64(uint64_t ll) {
   //  if (IS_LITTLE_ENDIAN) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint64_t result;
    char* sptr = ((char*)&ll) +7; // gcc doesn't mind char* aliases
    char* dptr = (char*)&result; // gcc doesn't mind char* aliases
    int i;
    for (i=0; i<8; ++i)
      *dptr++ = *sptr--;
    return result;
    //  }
    //  else
#else
    return ll;
#endif
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



int hton_generic(char* dst, char* src, size_t src_size) {
  switch(src_size) {
  case 8:  *((uint64_t*)dst) = hton64(*((uint64_t*)src)); break;
  case 4:  *((uint32_t*)dst) = htonl (*((uint32_t*)src)); break;
  case 2:  *((uint16_t*)dst) = htons (*((uint16_t*)src)); break;
  case 1:  *dst = *src; break;

  default:  return -1;
  }
  return 0;
}

int ntoh_generic(char* dst, char* src, size_t src_size) {
  switch(src_size) {
  case 8:   *((uint64_t*)dst) = ntoh64(*((uint64_t*)src)); break;
  case 4:   *((uint32_t*)dst) = ntohl (*((uint32_t*)src)); break;
  case 2:   *((uint16_t*)dst) = ntohs (*((uint16_t*)src)); break;
  case 1:   *dst = *src; break;

  default:  return -1;
  }
  return 0;
}






// *** co-maintain SocketCommand, in skt_common.h
const char* _command_str[] = {
  "unknown_command",

  "GET",
  "PUT",
  "DEL",
  "STAT",
  "FSYNC",
  "SEEK_SET",
  "SET_XATTR",
  "GET_XATTR",
  "CHOWN",
  "RENAME",
  "UNLINK",

  "TEST",

  "S3_AUTH",
  "RIO_OFFSET",
  "DATA",
  "ACK",
  "RETURN",
  "NOP",

  "NULL"
};
const char* command_str(SocketCommand command) {
  if (command > CMD_NULL)
    command = 0;
  return _command_str[command];
}


// NOTE: We take care of network-byte-order conversions
int write_pseudo_packet(int fd, SocketCommand command, size_t size, void* buf) {
  ssize_t write_count;

  //  REQUIRE_0( rs_check(fd) ); // DEBUGGING (custom rsocket.h helper)

  // --- fill in buffer, for single send()
  PseudoPacketHeader  hdr;

  // --- install <command>
  neDBG("-> command: %s\n", command_str(command));
  HDR_CMD(&hdr) = htonl(command);

  // --- install <size>
  neDBG("-> size:    %lld\n", size);
  HDR_SIZE(&hdr) = hton64(size);

  // --- send header as single unit
  NEED_0( write_raw(fd, (char*)HDR_BUF(&hdr), HDR_BUFSIZE) );

  // --- maybe write <buf>
  if (buf) {
    if (size <= FNAME_SIZE)
      neDBG("-> buf:     0x%08x ='%s'\n", (size_t)buf, buf);
    else
      neDBG("-> buf:     0x%08x\n", (size_t)buf);

    NEED_0( write_raw(fd, (char*)buf, size) );
  }

  return 0;
}

// NOTE: We take care of network-byte-order conversions
int read_pseudo_packet_header(int fd, PseudoPacketHeader* hdr, int peek) {
  static const char*  peek_indicator = " *";
  ssize_t read_count;
  memset(hdr, 0, sizeof(PseudoPacketHeader));

  //  REQUIRE_0( rs_check(fd) ); // DEBUGGING (custom rsocket.h helper)

  // --- read header in one go
  NEED_0( read_raw(fd, (char*)HDR_BUF(hdr), HDR_BUFSIZE, peek) );

  // --- extract <command>
  HDR_CMD(hdr) = ntohl(HDR_CMD(hdr));
  neDBG("<- command: %s %c\n", command_str(HDR_CMD(hdr)), peek_indicator[(peek != 0)]);

  // --- extract <size>
  HDR_SIZE(hdr) = ntoh64(HDR_SIZE(hdr));
  neDBG("<- size:    %lld %c\n", HDR_SIZE(hdr), peek_indicator[(peek != 0)]);

  return 0;
}





// paths to the server can be specified as  host:port/path/to/file
// eventually, we'll allow   prot://host:port/path/to/file
//
// <service_path>   unparsed server-spec
// <spec>           parsed components of <service_path>
//
// Shoulda just used sscanf.  Chris got me thinking about maximizing
// parsing efficiency, but that was a different context.
//
int parse_service_path(PathSpec* spec, const char* service_path) {

  // --- parse <host>
  const char*  ptr    = service_path;
  size_t       length = strcspn(ptr, ":");

  if (! ptr[length]) {
    neERR("couldn't find port in '%s'\n", ptr);
    return -1;
  }
  else if (length >= HOST_SIZE) {
    neERR("host token-length (plus NULL) %u exceeds max %u in '%s'\n",
        length +1, HOST_SIZE, service_path);
    return -1;
  }
  else if (! strcmp(ptr + length, "://")) {
    neERR("protocol-specs not yet supported, for '%s'\n",
        service_path);
    return -1;
  }
  strncpy(spec->host, ptr, length);
  spec->host[length] = 0;


  // --- parse <port> (string)
  ptr += length +1;             // skip over ':'
  length = strcspn(ptr, "/");

  if (! ptr[length]) {
    neERR("couldn't find file-path in '%s'\n", ptr);
    return -1;
  }
  else if (length >= PORT_STR_SIZE) {
    neERR("port-token length (plus NULL) %u exceeds max %u in '%s'\n",
        length +1, PORT_STR_SIZE, service_path);
    return -1;
  }
  strncpy(spec->port_str, ptr, length);
  spec->port_str[length] = 0;

  // --- parse <port> (value)
  errno = 0;
  unsigned long  port = strtoul(ptr, NULL, 10);
  if (errno) {
    neERR("couldn't read port from '%s': %s", ptr, strerror(errno));
    return -1;
  }
  if (port >> 16) {
    neERR("port %lu is greater than %u\n", port, ((uint32_t)1 << 16) -1);
    return -1;
  }
  spec->port = port;


  // --- parse file-path
  ptr += length;                // don't skip over '/'
  length = strlen(ptr);
  if (! length) {
    neERR("couldn't find file-component in '%s'\n", service_path);
    return -1;
  }
  else if (length >= FNAME_SIZE) {
    neERR("file-token length (plus NULL) %u exceeds max %u in '%s'\n",
        length +1, FNAME_SIZE, ptr);
    return -1;
  }
  strncpy(spec->fname, ptr, length);
  spec->fname[length] = 0;

  return 0;
}



// client-side of PUT / server-side of GET
//
// <fd> should already be opened for read (unless SKIP_FILE_READS)
// 
// <handle> should already be opened for writing (e.g. with skt_open() in client,
//      or fake_open() on server.
//
// To accomodate libne() calling skt_lseek(), we implement support for
// seeks as an optional CMD_SEEK_SET pseudo-header, sent by the reader
// before the ACK.
//
// UPDATE: libne actually calls seek quite frequently, typically seeking
//    backwards by 1M.  We could keep previous buffers and just return
//    them, in this common case.  Instead, we're picking a more-generic
//    solution.  We peek for the SEEK.  If it's found, then do the seek
//    before reading from file (or use pread()).  If, instead, the
//    control-channel just has the ACK (in which the client is requesting a
//    continuation of sequential reads in the GET-stream), then do that.
//
// NOTE: if the client calls lseek() after we have detected EOF on the
//    input-file, we need to detect that and resume reading.  We can't exit
//    this function until we're sure that that won't happen.  skt_write()
//    has smarts to handle surprises from the peer, so we use that to send
//    the final DATA 0 to the peer, assuring that they don't interrupt with
//    a SEEK, etc.  This means we've done part of the work of skt_close(),
//    so we set a flag in the handle, so that skt_close() will know.
//   

ssize_t copy_file_to_socket(int fd, SocketHandle* handle, char* buf, size_t size) {

#ifdef SKIP_FILE_READS
  // This allows cutting out the performance cost of doing file reads
  // for raw bandwidth tests.
  size_t iters = SKIP_FILE_READS; // we will write (SKIP_FILE_READ * <size>) bytes

  // initialize once, to allow diagnosis of results?
  memset(buf, 1, size);
#endif



  int     file_eof     = 0;     // EOF reading file
  int     peer_eof     = 0;     // EOF writing peer
  int     err          = 0;

  size_t  read_pos     = 0;     // file reads
  ssize_t read_count   = 0;

  int     do_file_read = 1;
  size_t  remain       = size;
  size_t  copied       = 0;

  size_t  bytes_moved  = 0;     // total


  while (!peer_eof && !err) {

     do_file_read = 1;

     // --- peek at the next pseudo-packet, to see if it's a SEEK
     PseudoPacketHeader header;
     NEED_0( read_pseudo_packet_header(handle->peer_fd, &header, 1) );

     // process SEEKs now, so that we only read data from the file that is
     // actually wanted by the socket peer.
     while (HDR_CMD(&header) == CMD_SEEK_SET) {

        // remove peeked SEEK packet-header
        NEED_0( read_pseudo_packet_header(handle->peer_fd, &header, 0) );

        neDBG("got SEEK %lld\n", HDR_SIZE(&header));
        handle->seek_pos = HDR_SIZE(&header);


        // maybe the seek is a no-op?
        if (handle->seek_pos == handle->stream_pos) {
           neDBG("already at seek-pos.  Ignoring\n");

           // peer gets the return-code from lseek()
           NEED_0( write_pseudo_packet(handle->peer_fd, CMD_RETURN, handle->stream_pos, NULL) );
           do_file_read = 1;
        }

        // maybe the seek is within the buffer we read previously?
        else if ((handle->seek_pos >= read_pos)
                 && (handle->seek_pos < handle->stream_pos)) {

              copied = handle->seek_pos   - read_pos;
              remain = handle->stream_pos - handle->seek_pos;

              handle->stream_pos = handle->seek_pos;
              neDBG("seek_pos is in existing buffer, at local offset %lld (length %lld)\n",
                    copied, remain);

              // peer gets the return-code from lseek()
              NEED_0( write_pseudo_packet(handle->peer_fd, CMD_RETURN, handle->stream_pos, NULL) );
              do_file_read = 0;
        }
        else {
           // Do the seek.
           //
           // TBD: File-reading (further down), could just pread() from
           //     this position, saving the need for a separate seek, but
           //     then we'd have to take care to return appropriately for
           //     the seek(), analyzing the results of the pread().  For
           //     now, we'll just do the seek explicitly.

           off_t rc = lseek(fd, handle->seek_pos, SEEK_SET);
           
           // peer gets the return-code from lseek()
           NEED_0( write_pseudo_packet(handle->peer_fd, CMD_RETURN, rc, NULL) );

           NEED( rc != (off_t)-1 );
           handle->stream_pos = rc;
           do_file_read = 1;
        }

        // peek again
        NEED_0( read_pseudo_packet_header(handle->peer_fd, &header, 1) );
     }


    // --- read from file
    //     got a non-SEEK pseudo-packet
    //     (read-after-seek might be re-using buffer from previous read)
    if (do_file_read) {

#ifdef SKIP_FILE_READS
       // File-reads suppressed.  Don't bother reading.  Just send a raw buffer.
       if (unlikely(iters-- <= 0)) {
          neDBG("fake EOF\n");
          file_eof = 1;
          read_count  = 0;
          break;
       }
       neDBG("%d: fake read: %lld\n", iters, read_count);

       read_count = size;
       remain     = read_count;
       copied     = 0;

#else
       // read file data up to <size>, or EOF
       read_pos   = handle->stream_pos;
       read_count = read_buffer(fd, buf, size, 0);
       neDBG("read_pos:   %lld\n", read_pos);
       neDBG("read_count: %lld\n", read_count);
       NEED( read_count >= 0 );

       // #   ifdef DEBUG_SOCKETS
       //        // DEBUGGING: chasing readback problems.
       //        if (read_count > 0) {
       //           char  dbg_buf[128];
       //           char* dbg_bufp = dbg_buf;
       //           int   i;
       //           for (i=0; i<32; ++i) {
       //              
       //              if (i && !(i%4))
       //                 *(dbg_bufp++) = ' ';
       //              
       //              int j;
       //              for (j=0; j<2; ++j) {
       //                 uint8_t nybble = (buf[i] >> ((1-j)*4)) & 0x0f;
       //                 if (nybble < 10)
       //                    *(dbg_bufp++) = nybble | '0';
       //                 else
       //                    *(dbg_bufp++) = ((nybble - 10) | ((uint8_t)'a' -1)) +1; /* 'a' = 0x61 */
       //              }
       //              *(dbg_bufp++) = ',';
       //           }
       //           *(dbg_bufp++) = 0;
       //           neDBG("pos: %llu, dbg_buf=%s\n", read_pos, dbg_buf);
       //        }
       // #   endif

       if (read_count == 0) {
          neDBG("read EOF\n");

          // We want to send a DATA 0, to tell the peer that we are done.  But
          // peer may still seek back into the stream.  We can now use
          // skt_write() to probe for, and handle, any SEEKs, RIO_OFFSETS, or
          // ACK 0 that might be sent from the peer, after we have reached EOF
          // on our input-file.  We'll do that in the write section, below.
          file_eof = 1;
       }

       remain = read_count;
       copied = 0;
#endif
    }


    // --- copy file-data out on socket
    //
    // NOTE: Do not use write_buffer(fd, ... )
    //
    // NOTE: We are copying a continuous stream from the file to the
    //    socket.  We only discover seeks from the client when skt_write()
    //    waits for an ACK, and gets a SEEK, instead.  skt_write() then
    //    returns an "error" to us, with the socket-handle marked
    //    HNDL_SEEK.  We must then drop the write of this buffer we read
    //    (ahead) in the file, do our seek in the fd associated with the
    //    file, and start the new stream from there.
    //
    // TBD: if someone were to seek back into the buffer we've got right
    //    here, we could just reuse the buffer.  A bug in ne_read() does
    //    seek like that, but we can probably just wait until that gets
    //    fixed.

    while (remain || file_eof) {
      ssize_t write_count = skt_write(handle, buf+copied, remain);

      if (unlikely(write_count < 0)) {

        if (handle->flags & HNDL_SEEK_SET) {

           // Apparently, this may still happen, despite the read-ahead for
           // SEEKs at the top of the outer loop.

           neDBG("write 'failed' due to SEEK.  from %lld to %lld\n",
                 handle->stream_pos, handle->seek_pos);
           handle->flags &= ~(HNDL_SEEK_SET);

           // maybe the seek is within the buffer we just read?
           if ((handle->seek_pos >= read_pos)
               && (handle->seek_pos < handle->stream_pos)) {

              copied = handle->seek_pos - read_pos;
              remain = read_count - handle->seek_pos;

              handle->stream_pos = handle->seek_pos;
              neDBG("seek_pos is in existing buffer, at local offset %lld (length %lld)\n",
                    copied, remain);

              // peer gets the return-code from lseek()
              NEED_0( write_pseudo_packet(handle->peer_fd, CMD_RETURN, handle->stream_pos, NULL) );
              continue;
           }

           off_t rc = lseek(fd, handle->seek_pos, SEEK_SET);
           neDBG("lseek returned: %lld\n", (ssize_t)rc);
           if (file_eof && (rc != (off_t)-1) && (rc != handle->stream_pos)) {
              neDBG("SEEK after EOF, ready for more reading at %lld\n",
                    handle->seek_pos);
              file_eof = 0;     // more file-reading to do
           }
           handle->stream_pos = handle->seek_pos;

           // peer gets the return-code from lseek()
           NEED_0( write_pseudo_packet(handle->peer_fd, CMD_RETURN, rc, NULL) );
           NEED( rc != (off_t)-1 );
           read_count = 0;      // don't increment bytes_moved
           break;
        }
        else if (handle->flags & HNDL_PEER_EOF) {
           neDBG("write failed due to peer EOF\n");
           peer_eof = 1;
           read_count = 0;      // don't increment bytes_moved
           break;
        }

        neERR("write failed: moved: %llu, read_ct: %lld, remain: %llu, flags: 0x%04x\n",
              bytes_moved, read_count, remain, handle->flags);
        return -1;
      }

      remain -= write_count;
      copied += write_count;
    }


    // entire read-buffer was moved
    bytes_moved += read_count;
  }
  neDBG("copy-loop done  (moved: %llu, stream_pos: %llu).\n", bytes_moved, handle->stream_pos);


  return bytes_moved;
}




// client-side of GET, or server-side of PUT
//
// <fd> should already be opened for writing (unless SKIP_FILE_WRITES)
// 
// <handle> should already be opened for writing (e.g. with skt_open() in client,
//      or fake_open() on server.
//
ssize_t copy_socket_to_file(SocketHandle* handle, int fd, char* buf, size_t size) {

  size_t bytes_moved = 0;       /* total */
  int    eof         = 0;
  int    err         = 0;

  while (!eof && !err) {

    // --- read from socket, up to <size>, or EOF
    //
    // NOTE: We are processing a continuous incoming stream.  We only
    //    discover requests from the client to fsync the destination file
    //    when skt_read() goes to read from the socket and waits for the
    //    DATA token, but gets an FSYNC, instead.  skt_read() then returns
    //    an "error" to us, with the socket-handle marked FSYNC.  We then
    //    do the fsync, and pick up where we left off.
    //    
    ssize_t read_count = skt_read(handle, buf, size);
    neDBG("read_count: %lld\n", read_count);

    // NEED( read_count >= 0 );
    if (unlikely(read_count < 0)) {

      if (handle->flags & HNDL_FSYNC) {
        neDBG("read failed due to FSYNC\n");
        handle->flags &= ~(HNDL_FSYNC);
        ssize_t rc = fsync(fd);

        // peer gets the return-code from fsync()
        NEED_0( write_pseudo_packet(handle->peer_fd, CMD_RETURN, rc, NULL) );
        NEED_0( rc );
        continue;
      }

      neERR("read failed: moved: %llu\n", bytes_moved);
      return -1;
    }

    if (unlikely(read_count == 0)) {
      neDBG("read EOF\n");
      eof = 1;
      break;
    }


    // --- copy all of buffer to file (unless file-writes are suppressed)
#ifdef SKIP_FILE_WRITES
    // don't waste time writing to file
    neDBG("fake write: %lld\n", read_count);
#else
    // copy all of buffer to file
    NEED_0( write_buffer(fd, buf, read_count, 0, 0) );
    neDBG("copied out\n");
#endif


    bytes_moved += read_count;
  }
  neDBG("copy-loop done  (moved: %llu, stream_pos: %llu).\n", bytes_moved, handle->stream_pos);

  return bytes_moved;
}








#if S3_AUTH

// --- send S3 authentication request
//
// See server_s3_authenticat().  That function expects something like the
// header-fields in an S3 authentication header.  These currently include
// the following:
//
//     date_size       // sizeof(time_t) is not standardized
//     date            // current time (within RD/WR_TIMEOUT of now)
//     op              // the GET/PUT/STAT/etc op being secured
//     filename        // (plus null) possibly a libne "path template"
//     user_name       // (plus null) assoc w/ passwd for hash.  (~/.awsAuth token 2).
//     signature       // (plus null) see GetStringToSign() in libaws4c.
//
// numerical values are expected to be in network-byte-order
// string fields are expected to include the terminal null.
//
// Because the client-side will typically be running de-escalated (in
// pftool or fuse), but credentials are protected in ~/.awsAuth, we need a
// way for the client-side to cache credentials at start-up.  We currently
// do that in the MC-sockets DAL init.  This can then pass-them through
// ne_fcntl() to skt_fcntl(), to install them on a handle that has been
// opened, but not yet written/read.  This has the effect of triggering a
// call to client_s3_authenticate(), when basic_init() is called the first
// time.  As a result, the initial interaction with the server on this
// connection will perform an authentication.

int client_s3_authenticate_internal(SocketHandle* handle, int command) {
   char        s3_data[MAX_S3_DATA];
   char*       ptr        = s3_data;
   size_t      ptr_remain = MAX_S3_DATA;
   char*       ptr_prev   = ptr; // DEBUGGING

   size_t      str_len;

   // generate, convert, and install individual fields
   int32_t        date_size = sizeof(time_t);
   time_t         now = time(NULL);
   uint32_t       op = command;
   AWSContext*    aws_ctx = handle->aws_ctx;
   const char*    user_name = (aws_ctx ? aws_ctx->awsKeyID : SKT_S3_USER);


   // --- DATE  (no guarantee for cross-platform size of time_t)
   char    now_str[32];           // max 26
   NEED_GT0( ctime_r(&now, now_str) );
   neDBG("  date [now]: %s", now_str); // includes newline

   SEND_VALUE_SAFE(ptr, date_size, ptr_remain);
   // neDBG("-- length:  %lld\n", (size_t)ptr - (size_t)ptr_prev);  ptr_prev=ptr;

   SEND_VALUE_SAFE(ptr, now, ptr_remain);
   // neDBG("-- length:  %lld\n", (size_t)ptr - (size_t)ptr_prev);  ptr_prev=ptr;


   // --- OP
   neDBG("  op:         %s\n", command_str(op));
   SEND_VALUE_SAFE(ptr, op, ptr_remain);
   // neDBG("-- length:  %lld\n", (size_t)ptr - (size_t)ptr_prev);  ptr_prev=ptr;


   // --- PATH
   PathSpec* spec = &handle->path_spec;
   str_len        = strlen(spec->fname);

   neDBG("  path_len:   %lld\n", str_len);
   SEND_VALUE_SAFE(ptr, str_len, ptr_remain);
   // neDBG("-- length:  %lld\n", (size_t)ptr - (size_t)ptr_prev);  ptr_prev=ptr;

   neDBG("  path:       %s\n", spec->fname);
   SEND_STRING_SAFE(ptr, spec->fname, str_len, ptr_remain);
   // neDBG("-- length:  %lld\n", (size_t)ptr - (size_t)ptr_prev);  ptr_prev=ptr;


   // --- USER_NAME
   str_len        = strlen(user_name);

   neDBG("  user_len:   %lld\n", str_len);
   SEND_VALUE_SAFE(ptr, str_len, ptr_remain);
   // neDBG("-- length:  %lld\n", (size_t)ptr - (size_t)ptr_prev);  ptr_prev=ptr;

   neDBG("  user_name:  %s\n", user_name);
   SEND_STRING_SAFE(ptr, user_name, str_len, ptr_remain);
   // neDBG("-- length:  %lld\n", (size_t)ptr - (size_t)ptr_prev);  ptr_prev=ptr;
   // neDBG("pass:       %s\n", aws_ctx->awsKey);

   // --- SIGNATURE
   char     resource[1024];        // matches use in aws4c.c
   DateConv date_conv = { .time = &now };

   char* cl_signature = GetStringToSign(resource,
                                        sizeof(resource),
                                        &date_conv,
                                        (char* const)command_str(op),
                                        NULL,
                                        spec->fname,
                                        aws_ctx);
   NEED( cl_signature );
   neDBG("  res  [cl]:  %s\n", resource);
   neDBG("  date [cl]:  %s\n", (char*)date_conv.chars);
   neDBG("  sign [cl]:  %s\n", cl_signature);

   str_len = strlen(cl_signature);

   neDBG("  sign_len:   %lld\n", str_len);
   SEND_VALUE_SAFE(ptr, str_len, ptr_remain);
   // neDBG("-- length:  %lld\n", (size_t)ptr - (size_t)ptr_prev);  ptr_prev=ptr;

   neDBG("  sign:       %s\n", cl_signature);
   SEND_STRING_SAFE(ptr, cl_signature, str_len, ptr_remain);
   // neDBG("-- length:  %lld\n", (size_t)ptr - (size_t)ptr_prev);  ptr_prev=ptr;




   // --- send to server
   size_t data_size = (ptr - s3_data);
   neDBG("data_sz:    %lld\n", data_size);
   NEED_0( write_pseudo_packet(handle->peer_fd, CMD_S3_AUTH, data_size, s3_data) );

   // --- get reply
   PseudoPacketHeader header;
   NEED_0( read_pseudo_packet_header(handle->peer_fd, &header, 0) );
   if (HDR_CMD(&header) != CMD_RETURN) {
      neERR("expected RETURN pseudo-packet, not %s\n", command_str(HDR_CMD(&header)));
      return -1;
   }
   NEED_0(HDR_SIZE(&header));

   return 0;
}



// In normal operation, the DAL should call skt_fcntl() on the handle
// (after skt_open(), but before doing any operation that moves data) in
// order to install the credentials cached by the DAL at start-up.
// However, it's possible you are running the test_client, and you need to
// try to read from ~/.awsAuth to find the credential at run-time.  We'll
// try that.
//
// NOTE: Because the DAL credentials are never freed (and used only once
//     per handle), in the case where we allocated a temporary credential
//     (based on ~/.awwsAuth), we free that again, before returning.
//     Either way, we pull the credential back out of the handle, because
//     it has served its purpose.
//
int client_s3_authenticate(SocketHandle* handle, int command) {

   int needs_free = 0;
   if (! handle->aws_ctx) {
      neLOG("WARNING: handle->AWSContext hasn't been initialized with skt_fcntl().\n");
      neLOG("Trying to read info for user '%s' from ~/.awsAuth ...\n", SKT_S3_USER);
      NEED( handle->aws_ctx = aws_context_new() );

      if (aws_read_config_r((char* const)SKT_S3_USER, handle->aws_ctx)) {
         // probably missing a line in ~/.awsAuth
         neERR("aws_read_config for user '%s' failed\n", SKT_S3_USER);
         aws_context_free_r(handle->aws_ctx);
         handle->aws_ctx = NULL;
         return -1;
      }

      neLOG("Read from ~/.awsAuth succeeded\n");
      needs_free = 1;
   }

   int retval = client_s3_authenticate_internal(handle, command);

#if DEBUG_SOCKETS
   AWSContext*    aws_ctx = handle->aws_ctx;
   const char*    user_name = (aws_ctx ? aws_ctx->awsKeyID : SKT_S3_USER);
   PathSpec*      spec = &handle->path_spec;

   neDBG("-- AUTHENTICATION: %s for user=%s %s %s\n",
         (retval ? "FAIL" : "OK"),
         user_name,
         command_str(command),
         spec->fname);
#endif

   if (needs_free)
      aws_context_free_r(handle->aws_ctx);

   handle->aws_ctx = NULL;
   return retval;
}


#endif






// ---------------------------------------------------------------------------
// client interface
// ---------------------------------------------------------------------------


#define NO_IMPL()                                                 \
  neERR("%s not implemented\n", __FUNCTION__);                    \
  abort()





// .................................................................
// OPEN
//
// Return -1 for failures, to match behavior of open(2).
// Like open(2), we allow an optional <mode> argument:
//
//   open(SocketHandle* handle, const char* svc_path, int flags)
//   open(SocketHandle* handle, const char* svc_path, int flags, mode_t mode)
//
// <mode> is used iff <flags> includes O_CREAT
//
// NOTE: If O_CREAT flag is present, you *must* provide a mode arg.
//
// NOTE: The server_thread, dispatched as a result of skt_open(), will
//     not actually presume what operation is being performed, until
//     the respective skt_read() or skt_write() call.  Conveniently,
//     that means we can also use this connection to perform other
//     operations (e.g. SETXATTR, CHOWN, etc).  In these cases, the
//     open flags are ignored.
//
// NOTE: if ne_write() -> bq_writer (thread) is calling, in the case where
//     our call to SOCKET() succeeds, but our CONNECT() fails, we must
//     return a handle with peer_fd = -1, or ne_write will presume success.
//     Therefore, we're using a jump-handler to call shut_down_handle() on
//     the way out, for such premature exits, and having shut_down_handle()
//     set peer_fd = -1.
//
// TBD: Set errcode "appropriately".
// ...........................................................................

int  skt_open (SocketHandle* handle, const char* service_path, int flags, ...) {
  neDBG("skt_open(0x%llx (flags: 0x%x), '%s', %x, ...)\n", (size_t)handle, handle->flags, service_path, flags);

  if (handle->flags && (handle->flags & HNDL_CONNECTED)) {
    neERR("attempt to open handle that is not closed\n");
    handle->flags |= HNDL_DBG2;
    return -1;
  }
  memset(handle, 0, sizeof(SocketHandle));
  handle->peer_fd = -1;         // libne checks the fd for succes

  mode_t mode = 0;
  if (flags & O_CREAT) {
   va_list ap;
   va_start( ap, flags );
   mode = va_arg( ap, int );    /* compiler can't handle "mode_t"? */
   va_end( ap );
  }

  // shorthand
  PathSpec* spec = &handle->path_spec;
  NEED_0( parse_service_path(spec, service_path) );

  handle->open_flags = flags;
  handle->open_mode  = mode;

  // O_RDWR with RDMA would require riomaps on both ends, or else
  // two different channels, each with a single riomap.
  if (flags & (O_RDWR)) {
    errno = ENOTSUP;            // TBD?
    return -1;
  }
  else if (flags & O_WRONLY)
    handle->flags |= HNDL_PUT;
  else
    handle->flags |= HNDL_GET;



#if (SOCKETS == SKT_unix)
  SockAddr          s_addr;
  struct sockaddr*  s_addr_ptr = (struct sockaddr*)&s_addr;
  socklen_t         s_addr_len = sizeof(SockAddr);

  // initialize the sockaddr structs
  memset(&s_addr, 0, s_addr_len);

  //  (void)unlink(socket_name);
  strcpy(s_addr.sun_path, socket_name);
  s_addr.sun_family = AF_UNIX;


#elif (SOCKETS == SKT_rdma)
  struct rdma_addrinfo  hints;
  struct rdma_addrinfo* res;

  memset(&hints, 0, sizeof(hints));
  hints.ai_port_space = RDMA_PS_TCP;
  //  hints.ai_port_space = RDMA_PS_IB;
  //  hints.ai_qp_type = IBV_QPT_RC; // amounts to SOCK_STREAM

  // NEW:
  // hints.ai_flags |= RAI_FAMILY;
  // hints.ai_family = AF_INET;

  int rc = rdma_getaddrinfo((char*)spec->host, (char*)spec->port_str, &hints, &res);
  if (rc) {
    neERR("rdma_getaddrinfo(%s) failed: %s\n", spec->host, strerror(errno));
    return -1;
  }

  struct sockaddr*  s_addr_ptr = (struct sockaddr*)res->ai_dst_addr;
  socklen_t         s_addr_len = res->ai_dst_len;
# define  SKT_FAMILY  res->ai_family

  // debugging
  NEED( s_addr_ptr->sa_family == AF_INET );
  struct sockaddr_in* sin_ptr = (struct sockaddr_in*)s_addr_ptr;
# include <arpa/inet.h>
  char dotted[INET_ADDRSTRLEN];
  NEED_GT0( inet_ntop(AF_INET, &sin_ptr->sin_addr, dotted, INET_ADDRSTRLEN) );
  neDBG("rdma_getaddrinfo: %s:%d\n", dotted, ntohs(sin_ptr->sin_port));


#else  // IP sockets
  SockAddr          s_addr;
  struct sockaddr*  s_addr_ptr = (struct sockaddr*)&s_addr;
  socklen_t         s_addr_len = sizeof(SockAddr);

  // initialize the sockaddr structs
  memset(&s_addr, 0, s_addr_len);

  struct hostent* server = gethostbyname(spec->host);
  if (! server) {
    neERR("gethostbyname(%s) failed: %s\n", spec->host, strerror(errno));
    return -1;
  }

  s_addr.sin_family      = AF_INET;
  s_addr.sin_port        = htons(spec->port);
  memcpy((char *)&s_addr.sin_addr.s_addr,
         (char *)server->h_addr, 
         server->h_length);
#endif


  // don't assign positive value to handle->peer_fd, as long as one of
  // the NEED() macros might still return failure.  libne is going to
  // look at handle->peer_fd to see whether the open succeeded.
  int fd;

  // open socket to server
  BUG_LOCK();
  fd = SOCKET(SKT_FAMILY, SOCK_STREAM, 0);
  BUG_UNLOCK();
  NEED_GT0(fd);
  neDBG("fd = %d\n", fd);
  //  REQUIRE_0( rs_check(fd) ); // DEBUGGING (custom rsocket.h helper)


  // jNEED() macros will run this before exiting
  jHANDLER( jshut_down_handle, handle );

  handle->peer_fd = fd;

  //  // don't do this on the PUT-client?
  //  int disable = 0;
  //  jNEED_0( RSETSOCKOPT( fd, SOL_RDMA, RDMA_INLINE, &disable, sizeof(disable)) );

  if (handle->flags & HNDL_PUT) {
    unsigned mapsize = 1; // max number of riomap'ed buffers (on this fd ?)
    jNEED_0( RSETSOCKOPT( fd, SOL_RDMA, RDMA_IOMAPSIZE, &mapsize, sizeof(mapsize)) );
  }
  //  REQUIRE_0( rs_check(fd) ); // DEBUGGING (custom rsocket.h helper)

  jNEED_0( CONNECT(fd, s_addr_ptr, s_addr_len) );
  neDBG("skt_open: connected [%d] '%s'\n", fd, spec->fname);
  //  REQUIRE_0( rs_check(fd) ); // DEBUGGING (custom rsocket.h helper)

  handle->flags |= HNDL_CONNECTED;
  return fd;
}




// ...........................................................................
// WRITE
//
// When writing to a socket with RDMA, we can't write more than the
// size of the reader's buffer.  So, we've extended the
// command-protocol slightly: when the reader sends an ACK saying the
// buffer is available, the value associated with the ACk tells us the
// reader's buffer-size.  If <size> is bigger than that, we truncate
// to reader's size.
//
// Libne formerly threw errors if writes returned less-than-expected
// values.  We could force multiple writes here, to guarantee that
// everything gets written, but a better approach seems to be to let
// skt_write() act somewhat like write(), and have libne wrap its
// writes in retries, until the full amount has been written.
//
// OBSOLETE: We allow a sequence of "writes" on an open socket, but
//     because of the client-server interactions needed for RDMA
//     sockets, each write is an all-or-nothing thing.  We write all
//     of your buffer to the server, or we fail.  For compatibility
//     with write(2), we return an ssize_t, but it will always either
//     match the size of your buffer, or be negative.
//
// For RDMA+IB, we communicate with the server to receive the
// memory-mapped offset for server-side buffer we will write into.
//
// NOTE: The peer understands DATA 0 to mean EOF, in the sense that this is
//     our last communication on the connection.  We will send that in
//     skt_close().  Therefore, if someone calls skt_write() with <size> 0,
//     we'll treat it as a no-op.
//
//     UPDATE: When it is trying to be sure that the client is not seeking
//     back into the file for more reading, copy_file_to_socket()
//     [supporting the server-side of GET] would have to duplicate much of
//     our handling of potential SEEK and RIO_OFFSET pseudo-packets sent
//     from the peer.  (But the problem would be harder, because it
//     couldn't just punt to a recursive call, like we do.)  Therefore, we
//     now actually allow a caller to send us size 0, in which case, we
//     *do* send the DATA 0, and also mark the handle, so that skt_close()
//     won't try it again.
//
// ...........................................................................


// We can't assume that client_s3_authenticate() can access ~/.awsAuth at run-time,
// because we may have de-escalated by now (e.g. if caller is fuse/pftool).
// Therefore, we provide a way for the DAL to install a previously-cached
// AWSContext, which has awsKey initialized.

int skt_fcntl(SocketHandle* handle, SocketFcntlCmd cmd, ...) {

   switch (cmd) {

   case SKT_F_SETAUTH: {

      va_list ap;
      va_start( ap, cmd );

      // We expect the arg to be void*, so that ne_open1(), ne_delete1(),
      // etc, can remain blissfully ignorant of AWSContext.
      AWSContext* aws_ctx = (AWSContext*)va_arg( ap, void* );

      va_end( ap );


#if S3_AUTH

      handle->aws_ctx = aws_ctx;
      return 0;

#else
      // If libne was built without authentication (allowed, because
      // someone might not want to have to link with libaws4c), but the
      // client program (fuse/pftool) assumes we are authenticating, then
      // that client should have detected this situation when it tried to
      // initialize its SktAuth (e.g. in DAL.config), calling
      // skt_auth_init().  So, by the time someone gets here, we can assume
      // that they are "approved" to be running without authentication, in
      // which case their call to skt_auth_init() must've returned NULL, so
      // our <aws_ctx> will be NULL.  [So, testing for non-NULL is
      // useless?]

      if (aws_ctx) {
         neERR("attempt to install S3 auth info, but not built with S3_AUTH\n");
         errno = EPERM;
         return -1;
      }
      return 0;

#endif
   }

   default:
      neERR("unknown cmd: %d\n", cmd);
      errno = ENOTSUP;
      return -1;
   }
}



// allow erasureLib/* to always call something for initialization of
// credentials at the top-level, without having to know about building
// with/without S3_AUTH.
//
// NOTE: SktAuth is already a ptr.  We're getting a ptr to caller's ptr.

int  skt_auth_init(const char* user, SktAuth* auth) {

#if S3_AUTH
   const char*  aws_user = user;  // token 1 in ~/.awsAuth
   AWSContext*  aws_ctx  = aws_context_new();
   int          retval   = 0;

   if (! aws_ctx) {
      neERR("Couldn't allocate an AWSContext\n");
      errno = ENOMEM;
      retval = -1;
   }
   else {
      if (! aws_user)
         aws_user = SKT_S3_USER;

      if (aws_read_config_r((char* const)user, aws_ctx)) {
         // probably missing a line in ~/.awsAuth
         neERR("aws_read_config failed, for user '%s'\n", user);
         aws_context_free_r(aws_ctx);
         aws_ctx = NULL;
         retval = -1;
      }
   }

   *auth = aws_ctx;
   return retval;

#else
   // QUESTION: should this fail?  We allow building libne without auth, so
   //     that generic libne users are not required to link with libaws4c.
   //     But if we do build libne without auth, then link to marfs (which
   //     now assumes that sockets are authenticated), shouldn't marfs get
   //     a runtime error here, so that we can't miss that mistake?
   //
   // ANSWER: Apps that link with libne (and expect authentication based on
   //     the SktAuth we are initializing) should test the SktAuth after
   //     return, to assure it is non-null, as well as testing the return
   //     code to assure it is zero.  Apps that are allowed to use sockets
   //     without authentication should just test the return-code.

   *auth = NULL;
   return 0;
#endif
}


// This always works correctly, whether built for S3_AUTH or not, as long
// as you called skt_auth_init() previously.
//
int skt_auth_install(SocketHandle* handle, void* aws_ctx) {
   return skt_fcntl(handle, SKT_F_SETAUTH, aws_ctx);
}


void skt_auth_free(SktAuth auth) {
   if (auth)
      aws_context_free_r((AWSContext*)auth);
}


// This does non-RDMA-related init tasks (including sending the
// command to the server, unless the command is CMD_NULL), on a handle
// that has already been through skt_open().  This is used by both
// write_init() and read_init(), but can also be used by other
// routines that want a handle, but don't want the overhead of setting
// up for RDMA (riowrite).  For exmaple, skt_rename() needs a handle,
// but only needs it to exchange a couple of tokens.
//
// In other words, if you (writer of internals) want to use
// skt_read/skt_write, instead of read_raw/write_raw, but for some
// reason you don't want to initialize for RDMA.  You could initialize
// with this.
//
// NOTE: You don't need this, just to allow shut_down_handle() to do
//     all its necessary cleanup.  For example, if you just want to
//     send some tokens with read_raw/write_raw, you don't need this.
//     However, it's a convenient way to send the initial command to
//     the server, and won't hurt you, unless you really did want to
//     use RDMA.
//
// NOTE: server-side always calls with cmd==CMD_NULL.  Thus,
//     in the case of S3_AUTH, we can be sure we are acting on behalf
//     of the client, when cmd is non-NULL.

int basic_init(SocketHandle* handle, SocketCommand cmd) {
  neDBG("basic_init(0x%llx, %s)\n", (size_t)handle, command_str(cmd));

  if (! (handle->flags & HNDL_OP_INIT)) {

    // Inits are only performed once.  If one of the NEED() calls
    // fail, here, or in read/write_init, don't let anyone come back
    // on and try again, with comms in some unknown state.
    handle->flags |= HNDL_OP_INIT;

    if (cmd != CMD_NULL) {
#if S3_AUTH
      NEED_0( client_s3_authenticate(handle, cmd) );
#else
      PathSpec* spec = &handle->path_spec;
      NEED_0( write_pseudo_packet(handle->peer_fd, cmd, strlen(spec->fname)+1, spec->fname) );
#endif
    }
  }
  return 0;
}


// On the first call to skt_write(), the writer exchanges some
// initialization-info with the peer.  If we are using riowrite(),
// we need the peer's riomapped buffer-offset.
//
// In the case of writing on behalf of a client-PUT, this also
// involves sending the PUT-request.  In the case of server-GET, it
// does not.
//
// The reason for breaking this out is that a client that is using
// skt_write() might not want PUT to be the initial command sent to
// the server.  Using write_init() explicitly, they can force sending
// some other initial command, and then use skt_write() and
// skt_close() normally.
//
int write_init(SocketHandle* handle, SocketCommand cmd) {

  // --- first time through, initialize comms with server
  if (! (handle->flags & HNDL_OP_INIT)) {

     // inits common to read/write, allows simpler inits for non-RDMA tasks
     NEED_0( basic_init(handle, cmd) );


#if USE_RIOWRITE
    // server sends us the offset she got from riomap()
    PseudoPacketHeader header;
    NEED_0( read_pseudo_packet_header(handle->peer_fd, &header, 0) );
    if (HDR_CMD(&header) != CMD_RIO_OFFSET) {
       neERR("expected RIO_OFFSET pseudo-packet, not %s\n", command_str(HDR_CMD(&header)));
      return -1;
    }
    handle->rio_offset = HDR_SIZE(&header);
    neDBG("got riomap offset from peer: 0x%llx\n", HDR_SIZE(&header));
#endif

  }

  return 0;
}



ssize_t skt_write(SocketHandle* handle, const void* buf, size_t size) {
  neDBG("skt_write(%d(flags: 0x%x), %llx, %llu)\n", handle->peer_fd, handle->flags, (size_t)buf, size);

  ///  // COMMENTED OUT.  See UPDATE under "WRITE"
  ///  if (! size)
  ///    return 0;                   // see NOTE under "WRITE"

  // perform deferred initial protocol exchanges, if needed
  NEED_0( write_init(handle, CMD_PUT) );


#ifdef USE_RIOWRITE
  // We're about to overwrite the destination buffer via RDMA.
  // Don't call write_buffer() until the other-end reports that it
  // is finished with the buffer.
  PseudoPacketHeader header;
  NEED_0( read_pseudo_packet_header(handle->peer_fd, &header, 0) );

  if (unlikely (HDR_CMD(&header) != CMD_ACK)) {

    // (This is analogous to the FSYNC-handling inside skt_read().)
    // SEEK here means client is calling skt_lseek(), and skt_write()
    // is called from copy_file_to_socket(), supporting a GET on the
    // server-side.  Therefore, the <fd> that the seek is intended for
    // is for the file, not this handle.  We don't have access to that
    // fd, which is why we have to throw an error back to
    // copy_file_to_socket().

     if (HDR_CMD(&header) == CMD_SEEK_SET) {
      handle->flags |= HNDL_SEEK_SET;
      handle->seek_pos = HDR_SIZE(&header);
      neDBG("got SEEK %lld\n", HDR_SIZE(&header));
      return -1;
    }
     else if (HDR_CMD(&header) == CMD_RIO_OFFSET) {
       neDBG("got RIO_OFFSET: 0x%llx\n", HDR_SIZE(&header));
       handle->rio_offset = HDR_SIZE(&header);
      return skt_write(handle, buf, size); // try again to read ACK ...
    }
    else {
       neERR("expected ACK, but got %s\n", command_str(HDR_CMD(&header)));
      return -1;
    }
  }
  int64_t ack_size = HDR_SIZE(&header);

  // if reader shut-down nicely, and closed before reading everything,
  // their last message to us will be an ACK 0.  If we are serving
  // write_buffer(), it could pay attention to this and stop writing.
  // But no.
  if (! ack_size) {
     handle->flags |= HNDL_PEER_EOF;
     return -1;
  }

  // Reader's ACK includes the size of the reader's read-buffer.
  // For RDMA, don't write more than this amount.
  if (size > ack_size)
    size = ack_size;

#endif


  // write_buffer() is okay here, because we know how much the peer can handle
  NEED_0( write_buffer(handle->peer_fd, buf, size, 1, handle->rio_offset) );
  handle->stream_pos += size;  /* tracking for skt_lseek() */

  // copy_file_to_socket() now uses skt_write() to handle complications
  // (SEEK or RIO_OFFSET) while trying to "close" the stream, so as to
  // potentially remain open to ongoing service if the peer happens to seek
  // back into the stream after copy_file_to_socket() has reached EOF on
  // the input file.  If we've gotten this far, then we did send the
  // closing DATA 0, on behalf of cfts().  Set a flag, so skt_close() wont
  // try the same thing.
  if (! size)
     handle->flags |= HNDL_SENT_DATA0;

  return size;
}



ssize_t skt_write_all(SocketHandle* handle, const void* buffer, size_t size) {

  ssize_t     result = 0;
  size_t      remain = size;
  const char* buf    = buffer;

  while (remain) {
    errno = 0;

    ssize_t count = skt_write(handle, (const uint8_t*)buf+result, remain);

    if (count < 0)
      return count;

    else if (errno)
      return -1;

    remain -= count;
    result += count;
  }

  return result;
}





// ...........................................................................
// READ
//
// ...........................................................................


// We now allow the reader to change the size of the buffer that is
// registered with the writer.  This is only expected at explicit
// places in the protocol.  The issue is that skt_lseek() is now
// allowed to call read_init(), in order to deal with the case where a
// caller is seeking to a non-zero offset on a handle that has never
// been an argument to skt_read().  This means the "GET <fname_size>
// <fname>" pseudo-packet has never been sent to the server (by
// read_init() in skt_read()), so the server has not yet spun up a
// thread to run copy_file_to_socket().  But that was formerly the
// only place in the protocol where riomapping info was exchanged.
// skt_lseek() can't fake that, because it doesn't know the size of
// buffer that will be given to skt_read(), and skt_lseek() can't
// return fake-success, because maybe the seek will fail.
//
// So, we now allow skt_read() to *change* the riomapping, if it gets a
// buffer that differs from the previous one, recorded in the handle.  This
// allows skt_read() to adjust dynamically to different buffer sizes, and
// allows skt_lseek() to fake it by invoking a server-side GET thread on
// its own, providing an inital mapping, which can subsequently be
// renegotiated by skt_read().
//
// We only support monotonically increasing the mapping size.
//
// NEW: The mapping defines where in memory RDMA transfers are going to go.
// So, if the caller provides a new buffer, we must also change the
// riomapping.

int riomap_reader(SocketHandle* handle, void* buf, size_t size) {

#if USE_RIOWRITE

  // drop the old mapping, if the new read has a bigger read-buffer,
  // or if caller has provided a new destination
  if (likely (handle->flags & HNDL_RIOMAPPED)) {

     if (likely ((size <= handle->rio_size)
                 && (buf == handle->rio_buf)))
      return 0;

    THREAD_CANCEL(DISABLE);
    neDBG("peer_fd %3d: Dropping old riomaping\n", handle->peer_fd);
    int dbg = RIOUNMAP(handle->peer_fd, handle->rio_buf, handle->rio_size);
    neDBG("peer_fd %3d: unmap = %d\n", handle->peer_fd, dbg);
    if (dbg) {
       neERR("unmap failed: %s\n", strerror(errno));
       THREAD_CANCEL(ENABLE);
       return -1;
    }
    handle->flags &= ~HNDL_RIOMAPPED;
    THREAD_CANCEL(ENABLE);
  }


  // send peer the offset we get from riomap()
  // She'll need this for riowrite(), in write_buffer()

  //  unsigned mapsize = 1; // max number of riomap'ed buffers
  //  NEED_0( RSETSOCKOPT(handle->peer_fd, SOL_RDMA, RDMA_IOMAPSIZE, &mapsize, sizeof(mapsize)) );

  THREAD_CANCEL(DISABLE);

  neDBG("riomap(%d, 0x%llx, ...)\n", handle->peer_fd, (size_t)buf);
  handle->rio_offset = RIOMAP(handle->peer_fd, buf, size, PROT_WRITE, 0, -1);
  if (handle->rio_offset == (off_t)-1) {
    neERR("riomap failed: %s\n", strerror(errno));
    THREAD_CANCEL(ENABLE);
    return -1;
  }
  neDBG("riomap offset: 0x%llx\n", handle->rio_offset);
  neDBG("riomap size:   %llu\n", size);

  handle->rio_buf  = buf;     // to allow the riounmap in shut_down_thread()
  handle->rio_size = size;    // to allow the riounmap in shut_down_thread()
  handle->flags |= HNDL_RIOMAPPED;
  THREAD_CANCEL(ENABLE);

  NEED_0( write_pseudo_packet(handle->peer_fd, CMD_RIO_OFFSET, handle->rio_offset, NULL) );
#endif

  return 0;
}



// On the first call to skt_read(), the reader exchanges some
// initialization-info with the peer.  The peer is the one doing the
// writing, so, for riowrite, we need to send her our riomap offset
// (which also implies that she has already called
// setsockopt(RDMA_IOMAPSIZE).)
//
// In the case of reading on behalf of a client-GET, this also
// involves sending the initial GET-request to the server.  In the
// case of server-PUT, it does not.
//
// The reason for breaking this out is that a client that is using
// skt_read() might not want GET to be the initial command sent to the
// server.  Using read_init() explicitly, they can force sending some
// other initial command, and then use skt_read() and skt_close()
// normally.
//
// Any operations on behalf of the client that want a connection
// featuring RDMA comms can call read_init() with the specific
// SocketCommand they want to send to the serever.  (e.g. RENAME
// doesn't need RDMA, because it's just exchanging a couple of tokens,
// so it can just use basic_init().)

int read_init(SocketHandle* handle, SocketCommand cmd, char* buf, size_t size) {

  if (! (handle->flags & HNDL_OP_INIT)) {

    // inits common to read/write, allows simpler inits for non-RDMA tasks
    NEED_0( basic_init(handle, cmd) );
  }

  // maybe adjust size of riomapped buffer
  NEED_0( riomap_reader(handle, buf, size) );

  return 0;
}


// WARNING: If USE_RIOWRITE is defined, you must always call this
//    function with the same buffer, because we will initially use it
//    to riomap the destination offset for RDMA, and all subsequent
//    RDMA writes from the peer will go there.

ssize_t skt_read(SocketHandle* handle, void* buf, size_t size) {
  neDBG("skt_read(%d(flags: 0x%x), %llx, %llu)\n", handle->peer_fd, handle->flags, (size_t)buf, size);

  ssize_t   read_count = 0;

  // perform deferred initial protocol, if needed
  NEED_0( read_init(handle, CMD_GET, buf, size) );


#ifdef USE_RIOWRITE
  // tell peer we are done with buffer, so she can begin overwriting
  // with her next riowrite().  We also indicate the maximum amount we
  // can recv.
  NEED_0( write_pseudo_packet(handle->peer_fd, CMD_ACK, size, NULL) );


  // wait for peer to finish riowrite()
  // NOTE: we may optionally receive an FSYNC, before the DATA
  PseudoPacketHeader header;
  NEED_0( read_pseudo_packet_header(handle->peer_fd, &header, 0) );

  if (unlikely(HDR_CMD(&header) != CMD_DATA)) {

    // (This is analogous to the SEEK-handling inside skt_write().)
    // FSYNC here means client is calling skt_fsync(), and skt_read()
    // is called from copy_socket_to_file(), supporting a PUT on the
    // server-side.  Therefore, the fd that the fsync is intended for
    // is for the file, not this handle.  We don't have access to that
    // fd, which is why we have to throw an error back to
    // copy_socket_to_file().

     if (HDR_CMD(&header) == CMD_FSYNC) {
      handle->flags |= HNDL_FSYNC;
      neDBG("got FSYNC\n");
      return -1;
    }

     neERR("expected DATA, but got %s\n", command_str(HDR_CMD(&header)));
    return -1;
  }

  // writer's DATA might conceivably be less than <size>
  read_count = HDR_SIZE(&header);

#else
  read_count = read_buffer(handle->peer_fd, buf, size, 1);

#endif

  handle->stream_pos += read_count;  /* tracking for skt_lseek() */
  return read_count;
}


ssize_t skt_read_all(SocketHandle* handle, void* buffer, size_t size) {

  ssize_t  result = 0;
  size_t   remain = size;
  char*    buf    = buffer;

  while (remain) {
    errno = 0;

    ssize_t count = skt_read(handle, buf+result, remain);

    if (count < 0)
      return count;

    else if (count == 0)
      return result;            /* EOF */

    //    else if (errno)
    //      return -1;

    remain -= count;
    result += count;
  }

  return result;
}


// ...........................................................................
// SEEK
//
// libne uses lseek().  It appears that under normal circumstances all
// those seeks might be redundant with the current position.  We
// detect that by tracking the current position in the stream.
// In that case, we can trivially return success.  Otherwise, for now,
// we report an error.
//
// TBD: Add seeking to the repertoire of commands that the server
//      supports.
// ...........................................................................

off_t skt_lseek(SocketHandle* handle, off_t offset, int whence) {
  neDBG("skt_lseek(%d (flags: 0x%x), 0x%llx, %d)\n", handle->peer_fd, handle->flags, offset, whence);

  if ((whence == SEEK_SET) && (offset == handle->stream_pos)) {
     neDBG("seek to 0x%llx is a no-op\n", offset);
    return handle->stream_pos;
  }
  else if ((whence == SEEK_CUR) && (offset == 0)) {
     neDBG("seek to 0x%llx is a no-op\n", offset);
    return handle->stream_pos;
  }
  else if (unlikely ((whence != SEEK_SET)
                     && (whence != SEEK_CUR)
                     && (whence != SEEK_END))) {
    neERR("lseek(%llu, %d) from %llu -- unknown <whence>\n",
        offset, handle->stream_pos, whence);
    errno = EINVAL;
    return (off_t)-1;
  }
  else if (unlikely (handle->flags & HNDL_PUT)) {
    neERR("lseek(%llu, %d) from %llu -- non-zero head motion on a PUT is not supported\n",
        offset, handle->stream_pos, whence);
    errno = EINVAL;
    return (off_t)-1;
  }
  else if (unlikely (! (handle->flags & HNDL_GET))) {
    neERR("lseek(%llu, %d) from %llu -- filehandle is not open\n",
        offset, handle->stream_pos, whence);
    errno = EINVAL;
    return (off_t)-1;
  }


  // We translate SEEK_CUR into SEEK_SET, using the current stream-pos.
  // Adjust the stream-pos now, so that multiple seeks will work.

  ssize_t seek_pos = -1;
  if (whence == SEEK_END) {
    // we don't keep track of file-size, so we can't easily do this, for now.
    // leave stream_pos where it is; this is just a failed seek.
    // leave seek_pos where it is; this is just a failed seek.

    // seek_pos = <file_size> + offset;
    neERR("lseek(... SEEK_END) not supported\n");
    errno = EINVAL;
    return (off_t)-1;
  }    
  else if (whence == SEEK_SET) {
    seek_pos           = offset;
    handle->stream_pos = offset;   // after the seek
  }
  else if (whence == SEEK_CUR) {
    seek_pos           = handle->stream_pos + offset;
    handle->stream_pos = seek_pos; // after the seek
  }
  neDBG("resolved seek pos: 0x%llx\n", seek_pos);


  // fit the SEEK into the GET protocol.
  //
  // The server is in copy_file_to_socket(), and its next call to
  // skt_write() is waiting for client-side skt_read() to send ACK
  // <bufsize>.  skt_write() is prepared to recv a SEEK_SET <offset>
  // instead.  All we need to do is send that.

  // PROBLEM: Actually, there's a complication.  It's possible the client
  // has not yet called skt_read() for the first time, on this handle, and
  // is also seeking to a non-zero offset.  In that case, the GET would not
  // yet have been sent to the server (by read_init() in skt_read()), in
  // which case the server will not yet have spun out a GET-thread to run
  // copy_file_to_socket().
  //
  // SOLUTION: We could just call read_init() here, but read_init() also
  // sets up the riomapp'ed buffer, receiving the size of the read-buffer
  // from skt_read(), which we don't have.  Therefore, our options are (1),
  // defer the seek, and have skt_read() send it at read-time, or (2) call
  // read_init() here, with some made-up size for riomapping, and allow
  // skt_read() to change the size of the riomapping, as needed in the
  // future.  (2) sounds useful, but requires re-factoring read_init(), but
  // (1) requires skt_lseek() to return a result before we're sure what it
  // should be.  Going with (2).

  // perform deferred initial protocol, if needed
  char  dummy[FNAME_SIZE];
  NEED_0( read_init(handle, CMD_GET, dummy, FNAME_SIZE) );

  NEED_0( write_pseudo_packet(handle->peer_fd, CMD_SEEK_SET, seek_pos, NULL) );


  // wait for peer to respond
  PseudoPacketHeader header;
  NEED_0( read_pseudo_packet_header(handle->peer_fd, &header, 0) );
  if (unlikely(HDR_CMD(&header) != CMD_RETURN)) {
     neERR("expected RETURN, but got %s\n", command_str(HDR_CMD(&header)));
    return -1;
  }
  else if (HDR_SIZE(&header) == (off_t)-1) {
    neERR("lseek RETURN was -1\n");
    return -1;
  }


  return HDR_SIZE(&header);
}


// ...........................................................................
// FSETXATTR
//
// libne uses this in some cases, but maybe we can get away with not
// supporting it, for now.
// ...........................................................................

int skt_fsetxattr(SocketHandle* handle, const char* service_path, const void* value, size_t size, int flags) {
  NO_IMPL();  
}


// ...........................................................................
// FSYNC
//
// libne now periodically performs an fsync().  We are interacting with the
// skt_read() calls, in a server that is looping in copy_socket_to_file().
// Therefore, we must join in the protocol in the way that skt_write()
// write would do.  After skt_read() gets our FSYNC, it will perform the op
// and send us a CMD_ACK, so we can be synchronous.
//
// NOTE: Maybe the libne calls to fsync() are really only useful to
//     MC-over-NFS, and we should just ignore them?  Suppressing the
//     fsyncs seems to improve performance by ~15%.  (Server-side
//     still does an fsync on close.)
//
// ...........................................................................

int skt_fsync(SocketHandle* handle) {

#if 1
  // ignore fsync()
  return 0;

#else
  if (! (handle->flags & HNDL_PUT)) {
    neERR("skt_fsync: handle not open for writing\n");
    errno = EBADF;
    return -1;
  }

  PseudoPacketHeader header;
  NEED_0( read_pseudo_packet_header(handle->peer_fd, &header, 0) );

  // this ACK was intended for skt_write()
  if (unlikely(HDR_CMD(&header) != CMD_ACK)) {
     neERR("expected ACK, but got %s\n", command_str(HDR_CMD(&header)));
    return -1;
  }

  NEED_0( write_pseudo_packet(handle->peer_fd, CMD_FSYNC, 1, NULL) );

  // wait for peer to finish the fsync
  NEED_0( read_pseudo_packet_header(handle->peer_fd, &header, 0) );
  if (unlikely(HDR_CMD(&header) != CMD_RETURN)) {
     neERR("expected RETURN, but got %s\n", command_str(HDR_CMD(&header)));
    return -1;
  }
  else if (HDR_SIZE(&header)) {
     neERR("fsync RETURN was %lld\n", HDR_SIZE(&header));
    return -1;
  }

  return 0;
#endif
}


// ...........................................................................
// CLOSE
//
// Finalize comms with server.  Server will fsync().
// ...........................................................................

int skt_close(SocketHandle* handle) {

   neDBG("skt_close(0x%llx)\n", (size_t)handle);

   // jNEED() macros will run this before exiting
   jHANDLER( jshut_down_handle, handle );

   if (handle->flags & HNDL_OP_INIT) {

      // Reset this now.  If we only get part-way through, don't try again.
      handle->flags &= ~HNDL_OP_INIT;

      if (handle->flags & HNDL_PUT) {
         // we were writing to this socket

         // maybe skt_write() already found ACK 0?
         // If so, trying to send DATA 0 will fail.
         // That will just put failures into the log, so skip it.
         if (handle->flags & HNDL_PEER_EOF)
            neDBG("peer EOF previously detected.  Skipping DATA 0\n");

         else {

#ifdef USE_RIOWRITE
            // let the other end know that there's no more data
            if (! (handle->flags & HNDL_SENT_DATA0))
               jNEED_0( write_pseudo_packet(handle->peer_fd, CMD_DATA, 0, NULL) );
#endif

            // wait for the other end to fsync
            //
            // NOTE: If we did a previous skt_write(), then the first
            //       pseudo-packet we read will be the ACK for that write,
            //       rather than the ACK for the DATA 0 we just wrote.  Skip
            //       over the former to get to the latter.
            PseudoPacketHeader hdr = {0};
            EXPECT_0( read_pseudo_packet_header(handle->peer_fd, &hdr, 0) );
            EXPECT(   (HDR_CMD(&hdr) == CMD_ACK) );
            if (HDR_CMD(&hdr) != CMD_ACK)
                handle->flags |= HNDL_DBG1;

            if ((HDR_CMD(&hdr) == CMD_ACK) && HDR_SIZE(&hdr)) {
               EXPECT_0( read_pseudo_packet_header(handle->peer_fd, &hdr, 0) );
               EXPECT(   (HDR_CMD(&hdr) == CMD_ACK) );
               if (HDR_CMD(&hdr) != CMD_ACK)
                  handle->flags |= HNDL_DBG1;
            }
         }
      }
      else if (! (handle->flags & HNDL_GET)) {
         abort();
      }
      else {
         // we were reading from this socket

#ifdef USE_RIOWRITE
         // We got the DATA 0 indicating EOF.  Send an ACK 0, as a sign off.
         // NOTE: the peer may already have hung up.  Not a problem.

         // jNEED_0( write_pseudo_packet(handle->peer_fd, CMD_ACK, 0, NULL) );
         write_pseudo_packet(handle->peer_fd, CMD_ACK, 0, NULL);

#endif
      }
   }

   // When reading small files, some libne threads close their SocketHandle
   // without ever reading.  But those SocketHandles were minimally open,
   // meaning a server-side thread was spun up to listen to them.  The
   // result is that when the client-side shuts down, the server-side
   // thread gets an EOF.  This is harmless, but it results in "fail"
   // messages written from the server into the log, which can be
   // distracting or alarming.  Therefore, we're trying adding this little
   // sign-off, which will allow the server threads to close gracefully.
   // I'm not sure whether this can create trouble for client-side reads,
   // in the event of some server-side crash, e.g. during a GET.  The
   // client-side doesn't expect NOP.
   else if (handle->flags & HNDL_CONNECTED) {
      // server spun up a listener-thread.  Let it exit gracefully
      jNEED_0( write_pseudo_packet(handle->peer_fd, CMD_NOP, 0, NULL) );
   }


   // This is (harmlessly) redundant with what would be done by the
   // thread-cleanup handlers (in the server), or in the shut_down()
   // call (in the client app), but regular applications (e.g. libne)
   // won't have a shut-down handler.
   shut_down_handle(handle);

   return 0;
}






// ===========================================================================
// file-based ops
//
// The client-server setup currently creates/destroys socket
// connections at open/close time, respectively.  For file-based ops,
// like chown, etc, this is bound to add a fair amount of overhead, if
// the only thing we really want to do with the socket is send a
// pseudo-packet saying chown this file, etc.  But that's what we're
// doing, for now.
//
// TBD: For the needs of libne, we could potentially "cheat" a little, and
//     allow a socket that was opened for GET/PUT to be "pre-closed", or
//     something, which would leave the socket that had been used for
//     writing the data in place, so we could send chown/chmod ops on it.
//     However, that gets a little ugly to do in an implementation-agnostic
//     way, because the file-based version (i.e. as opposed to using this
//     sockets library) will close first, then chown.
//
//
// client/server:  [See FILE_OPS_USE_FULL_OPEN]
//
//     We forego establishing a "fully open" handle (with write_init()),
//     which would allow us to send the new fname with skt_write(), instead
//     of write_raw().  It would also add an extra the overhead of
//     riomapping/unmapping, plus an extra phase of protocol, just for that
//     one thing.  Instead, we'll just resort to write_raw(), and our
//     cleanup devolves to shut_down_handle().
//
//     Using "full" open (i.e. with write_init(), rather than basic_init())
//     doesn't work at the moment.  We want to avoid it anyhow (as the only
//     thing it adds is that the read-side does riomapping of buffers).  It
//     was thought maybe this was why we were seeing a segfault in
//     rclose().
//
//     With full opens, we could chose to have client use skt_write() and
//     server use skt_read() [or vice-versa, if we init with write_init(),
//     etc], instead of using write_raw() / read_raw(), etc.
//
//
//     We could just ignore the nice closing protocol.  After we've done
//     the op, neither side needs to care about the other.  Both sides
//     could just shut_down_handle(), I think.  But mutually closing seems
//     more solid.  Doing it that way, for now, but we don't require a
//     successful close, in order to declare the op successful.
//
//     If one side closes and the other just shuts-down, the closer will be
//     stuck waiting for the other side to read her DATA 0, or to send an
//     ACK, but will eventually time-out.  (See WR_TIMEOUT / RD_TIMEOUT.)
//
// ===========================================================================


// NOTE: Adding full opens requires that the server-side also be doing
//  "full" opens, (i.e. with fake_open(), rather than fake_open_basic()).

#define FILE_OPS_USE_FULL_OPEN 1




// ...........................................................................
// UNLINK
// ...........................................................................

// see comments re "file-based ops"

int skt_unlink(const void* aws_ctx, const char* service_path) {
  //  NO_IMPL();

  SocketHandle       handle = {0};
  PseudoPacketHeader hdr = {0};

  // This does NOT actually open() the server-side file
  NEED_GT0( skt_open(&handle, service_path, O_WRONLY) );

  // jNEED() macros will run this before exiting
  jHANDLER( jskt_close, &handle );

  // install authentication info that will be used in basic_init()
  jNEED_0( skt_fcntl(&handle, SKT_F_SETAUTH, aws_ctx) );

  // send UNLINK with pathname
#if FILE_OPS_USE_FULL_OPEN
  jNEED_0( write_init(&handle, CMD_UNLINK) );
#else
  jNEED_0( basic_init(&handle, CMD_UNLINK) );
#endif

  // read RETURN, providing return-code from the remote rename().
  jNEED_0( read_pseudo_packet_header(handle.peer_fd, &hdr, 0) );
  jNEED(   (HDR_CMD(&hdr) == CMD_RETURN) );
  int rc =   (int)HDR_SIZE(&hdr);

  // close()
  // NEED_0( skt_close(&handle) );
  skt_close(&handle);

  return rc;
}




// ...........................................................................
// CHOWN
// ...........................................................................

// see comments re "file-based ops"

// int  skt_chown (const void* aws_ctx, const char* service_path, uid_t uid, gid_t gid) {
// 
//   SocketHandle       handle = {0};
//   PseudoPacketHeader hdr = {0};
// 
//   // This does NOT actually open() the server-side file
//   NEED_GT0( skt_open(&handle, service_path, O_WRONLY) );
// 
//   // jNEED() macros will run this before exiting
//   jHANDLER( jskt_close, &handle );
// 
//   // install authentication info that will be used in basic_init()
//   jNEED_0( skt_fcntl(&handle, SKT_F_SETAUTH, aws_ctx) );
// 
//   // send CHOWN with pathname
// #if FILE_OPS_USE_FULL_OPEN
//   jNEED_0( write_init(&handle, CMD_CHOWN) );
// #else
//   jNEED_0( basic_init(&handle, CMD_CHOWN) );
// #endif
// 
//   // write UID
//   uint64_t uid_buf = hton64(uid);
//   jNEED_0( write_raw(handle.peer_fd, (char*)&uid_buf, sizeof(uid_buf)) );
// 
//   // write GID
//   uint64_t gid_buf = hton64(gid);
//   jNEED_0( write_raw(handle.peer_fd, (char*)&gid_buf, sizeof(gid_buf)) );
// 
// 
//   // read RETURN, providing return-code from the remote lchown().
//   jNEED_0( read_pseudo_packet_header(handle.peer_fd, &hdr, 0) );
//   jNEED(   (HDR_CMD(&hdr) == CMD_RETURN) );
//   int rc =   (int)HDR_SIZE(&hdr);
// 
//   // close()
//   // jNEED_0( skt_close(&handle) );
//   skt_close(&handle);
// 
//   return rc;
// }


int  skt_chown (const void* aws_ctx, const char* service_path, uid_t uid, gid_t gid) {

  SocketHandle       handle = {0};
  PseudoPacketHeader hdr = {0};

  // This does NOT actually open() the server-side file
  NEED_GT0( skt_open(&handle, service_path, O_WRONLY) );

  // jNEED() macros will run this before exiting
  jHANDLER( jskt_close, &handle );

  // install authentication info that will be used in basic_init()
  jNEED_0( skt_fcntl(&handle, SKT_F_SETAUTH, aws_ctx) );

  // send CHOWN with pathname
#if FILE_OPS_USE_FULL_OPEN
  jNEED_0( write_init(&handle, CMD_CHOWN) );
#else
  jNEED_0( basic_init(&handle, CMD_CHOWN) );
#endif

  // write UID
  uint64_t uid_buf = hton64(uid);
  //  jNEED_0( write_raw(handle.peer_fd, (char*)&uid_buf, sizeof(uid_buf)) );
  jNEED( skt_write(&handle, (char*)&uid_buf, sizeof(uid_buf)) == sizeof(uid_buf) );

  // write GID
  uint64_t gid_buf = hton64(gid);
  jNEED_0( write_raw(handle.peer_fd, (char*)&gid_buf, sizeof(gid_buf)) );


  // read RETURN, providing return-code from the remote lchown().
  jNEED_0( read_pseudo_packet_header(handle.peer_fd, &hdr, 0) );
  jNEED(   (HDR_CMD(&hdr) == CMD_RETURN) );
  int rc =   (int)HDR_SIZE(&hdr);

  // close()
  // jNEED_0( skt_close(&handle) );
  skt_close(&handle);

  return rc;
}



// ...........................................................................
// RENAME
// ...........................................................................

// see comments re "file-based ops"

// int skt_rename (const void* aws_ctx, const char* service_path, const char* new_path) {
//   neDBG("skt_rename from: %s\n", service_path);
//   neDBG("skt_rename to:   %s\n", new_path);
// 
//   // if libne is calling, both paths are service_paths.
//   // Strip off the host:port portion of the new_path
//   const char* new_fname = new_path;
//   PathSpec    new_spec;
//   if (! parse_service_path(&new_spec, new_path) ) {
//     new_fname = new_spec.fname;
//     neDBG("skt_rename to2:  %s\n", new_fname);
//   }
// 
//   SocketHandle       handle = {0};
//   PseudoPacketHeader hdr = {0};
// 
//   // This does NOT actually open() the server-side file
//   NEED_GT0( skt_open(&handle, service_path, O_WRONLY) );
// 
//   // jNEED() macros will run this before exiting
//   jHANDLER( jskt_close, &handle );
// 
//   // install authentication info that will be used in basic_init()
//   jNEED_0( skt_fcntl(&handle, SKT_F_SETAUTH, aws_ctx) );
//   
//   // send RENAME with orig-path
// #if FILE_OPS_USE_FULL_OPEN
//   jNEED_0( write_init(&handle, CMD_RENAME) );
// #else
//   jNEED_0( basic_init(&handle, CMD_RENAME) );
// #endif
// 
//   // send new-fname
//   size_t len     = strlen(new_fname) +1;
//   size_t len_buf = hton64(len);
//   jNEED_0( write_raw(handle.peer_fd, (char*)&len_buf,  sizeof(len_buf)) );
//   jNEED_0( write_raw(handle.peer_fd, (char*)new_fname, len) );
// 
//   // read RETURN, providing return-code from the remote rename().
//   jNEED_0( read_pseudo_packet_header(handle.peer_fd, &hdr, 0) );
//   jNEED(   (HDR_CMD(&hdr) == CMD_RETURN) );
//   int rc =   (int)HDR_SIZE(&hdr);
// 
//   // close()
//   // NEED_0( skt_close(&handle) );
//   skt_close(&handle);
// 
//   return rc;
// }

int skt_rename (const void* aws_ctx, const char* service_path, const char* new_path) {
  neDBG("skt_rename from: %s\n", service_path);
  neDBG("skt_rename to:   %s\n", new_path);

  // if libne is calling, both paths are service_paths.
  // Strip off the host:port portion of the new_path
  const char* new_fname = new_path;
  PathSpec    new_spec;
  if (! parse_service_path(&new_spec, new_path) ) {
    new_fname = new_spec.fname;
    neDBG("skt_rename to2:  %s\n", new_fname);
  }

  SocketHandle       handle = {0};
  PseudoPacketHeader hdr = {0};

  // This does NOT actually open() the server-side file
  NEED_GT0( skt_open(&handle, service_path, O_WRONLY) );

  //  REQUIRE_0( rs_check(handle.peer_fd) ); // DEBUGGING (custom rsocket.h helper)

  // jNEED() macros will run this before exiting
  jHANDLER( jskt_close, &handle );

  //  REQUIRE_0( rs_check(handle.peer_fd) ); // DEBUGGING (custom rsocket.h helper)

  // install authentication info that will be used in basic_init()
  jNEED_0( skt_fcntl(&handle, SKT_F_SETAUTH, aws_ctx) );
  
  //  REQUIRE_0( rs_check(handle.peer_fd) ); // DEBUGGING (custom rsocket.h helper)

  // send RENAME with orig-path
#if FILE_OPS_USE_FULL_OPEN
  jNEED_0( write_init(&handle, CMD_RENAME) );
#else
  jNEED_0( basic_init(&handle, CMD_RENAME) );
#endif

  // send new-fname
  size_t len     = strlen(new_fname) +1;
  size_t len_buf = hton64(len);
  neDBG("sending len = %ld (net-byte-order: 0x%lx)\n", len, len_buf);
  // jNEED_0( write_raw(handle.peer_fd, (char*)&len_buf,  sizeof(len_buf)) );
  jNEED( skt_write(&handle, (char*)&len_buf,  sizeof(len_buf)) == sizeof(len_buf) );

  jNEED_0( write_raw(handle.peer_fd, (char*)new_fname, len) );

  // read RETURN, providing return-code from the remote rename().
  jNEED_0( read_pseudo_packet_header(handle.peer_fd, &hdr, 0) );
  jNEED(   (HDR_CMD(&hdr) == CMD_RETURN) );
  int rc =   (int)HDR_SIZE(&hdr);

  // close()
  // NEED_0( skt_close(&handle) );
  skt_close(&handle);

  return rc;
}


// ...........................................................................
// STAT
//
// We are just exchanging a small blob of stat info, but we use RDMA
// to do it, to try to minimize the CPU load on the server.  This also
// makes it easier to send a series of network-byte-order values of
// different sizes.
//
// TBD: Server just translates successive struct members to
//    network-byte-order (appropriately to their size) and sends them
//    contiguously.  We're assuming that STAT_DATA_STRUCT size being the
//    same on client and server means that all the fields also have the
//    same size.  It might be better for the server to include some info
//    that would allow us to validate that we agree on the size of the
//    elements.
//
// TBD: It would be even smarter for client to send an endian argument, and
//    maybe the server could just RDMA the struct contents straight to us
//    without the need for translations to network-byte-order.
//
// ...........................................................................

// see comments re "file-based ops"

int skt_stat(const void* aws_ctx, const char* service_path, struct stat* st) {
  SocketHandle   handle = {0};
  char           buf[STAT_DATA_SIZE]   __attribute__ (( aligned(64) ));
  char*          ptr = buf;

  // server sends us remote return-code with special meaning:
  //   (1) if lstat() failed:    negative errcode
  //   (2) if lstat() succeeded: sizeof(struct stat), for crude validation
  ssize_t rc;

  // This does NOT actually open() the server-side file
  NEED_GT0( skt_open(&handle, service_path, (O_RDONLY)) );

  // jNEED() macros will run this before exiting
  jHANDLER( jskt_close, &handle );

  // install authentication info that will be used in basic_init()
  jNEED_0( skt_fcntl(&handle, SKT_F_SETAUTH, aws_ctx) );

  // send STAT plus fname, and prepare for reading via skt_read()
#if FILE_OPS_USE_FULL_OPEN
  jNEED_0( read_init(&handle, CMD_STAT, ptr, STAT_DATA_SIZE) );
#else
  jNEED_0( basic_init(&handle, CMD_STAT) );
#endif

  // rc is sent as a pseudo-packet
  PseudoPacketHeader hdr;
  jNEED_0( read_pseudo_packet_header(handle.peer_fd, &hdr, 0) );
  jNEED(   (HDR_CMD(&hdr) == CMD_RETURN) );
  rc = HDR_SIZE(&hdr);
  if (rc < 0) {

    // case (1): remote lstat failed.
    errno = -rc;
    neDBG("stat failed: %s\n", strerror(errno));
    return -1;
  }

  // case (2): remote lstat succeeded.

  // (a) First value is sizeof(struct stat) on the server, for crude validation
  jNEED( rc == sizeof(*st) );

  // (b) fill in the struct.  quick-and-dirty approach.
#if 0
  ssize_t read_size = skt_read_all(&handle, ptr, STAT_DATA_SIZE);
  jNEED( read_size == STAT_DATA_SIZE );
#else
  jNEED_0( read_raw(handle.peer_fd, ptr, STAT_DATA_SIZE, 0) );
#endif

  jRECV_VALUE(st->st_dev, ptr);     /* ID of device containing file */
  jRECV_VALUE(st->st_ino, ptr);     /* inode number */
  jRECV_VALUE(st->st_mode, ptr);    /* protection */
  jRECV_VALUE(st->st_nlink, ptr);   /* number of hard links */
  jRECV_VALUE(st->st_uid, ptr);     /* user ID of owner */
  jRECV_VALUE(st->st_gid, ptr);     /* group ID of owner */
  jRECV_VALUE(st->st_rdev, ptr);    /* device ID (if special file) */
  jRECV_VALUE(st->st_size, ptr);    /* total size, in bytes */
  jRECV_VALUE(st->st_blksize, ptr); /* blocksize for file system I/O */
  jRECV_VALUE(st->st_blocks, ptr);  /* number of 512B blocks allocated */
  jRECV_VALUE(st->st_atime, ptr);   /* time of last access */
  jRECV_VALUE(st->st_mtime, ptr);   /* time of last modification */
  jRECV_VALUE(st->st_ctime, ptr);   /* time of last status change */

  // close
  // jNEED_0( skt_close(&handle) );
  skt_close(&handle);

  return 0;
}


// ...........................................................................
// GETXATTR
// ...........................................................................

// see comments re "file-based ops"

int skt_getxattr(const void* aws_ctx, const char* service_path, const char* name, void* value, size_t size) {
  NO_IMPL();
}

