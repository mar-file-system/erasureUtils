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
Although these files reside in a seperate repository, they fall under the MarFS copyright and license.

MarFS is released under the BSD license.

MarFS was reviewed and released by LANL under Los Alamos Computer Code identifier:
LA-CC-15-039.

These erasure utilites make use of the Intel Intelligent Storage Acceleration Library (Intel ISA-L), which can be found at https://github.com/01org/isa-l and is under its own license.

MarFS uses libaws4c for Amazon S3 object communication. The original version
is at https://aws.amazon.com/code/Amazon-S3/2601 and under the LGPL license.
LANL added functionality to the original work. The original work plus
LANL contributions is found at https://github.com/jti-lanl/aws4c.

GNU licenses can be found at http://www.gnu.org/licenses/.
*/





#include <stdio.h>              /* rename() */
#include <stdarg.h>
#include <errno.h>

#include "erasure.h"
//#include "udal.h"




// ---------------------------------------------------------------------------
// POSIX
//
// NOTE: We avoid naming conflicts with MarFS MDAL implementations.
// ---------------------------------------------------------------------------



#define FD(GFD)   (GFD)->fds.fd


int     udal_posix_fd_init(GenericFD* gfd) { FD(gfd) = -1; }

int     udal_posix_fd_err(GenericFD* gfd) { return (FD(gfd) < 0); }

int     udal_posix_fd_num(GenericFD* gfd) { return FD(gfd); }


int     udal_posix_auth_init(const char* user, SktAuth* auth) { return 0; }

int     udal_posix_auth_install(GenericFD* gfd, SktAuth* auth) { return 0; }

int     udal_posix_open(GenericFD* gfd, const char* path, int flags, ...) {
   if (flags & O_CREAT) {
      va_list va;
      va_start(va, flags);
      mode_t mode = va_arg(va, int);
      va_end(va);

      FD(gfd) = open(path, flags, mode);
   }
   else
      FD(gfd) = open(path, flags);

   return FD(gfd);
}


ssize_t udal_posix_write(GenericFD* gfd, const void* buf, size_t count) {
   return write(FD(gfd), buf, count);
}

ssize_t udal_posix_read(GenericFD* gfd, void* buf, size_t count) {
   return read(FD(gfd), buf, count);
}

int     udal_posix_close(GenericFD* gfd) {
   return close(FD(gfd));
}


#if (AXATTR_SET_FUNC == 5) // XXX: not functional with threads!!!
int     udal_posix_fsetxattr(GenericFD* gfd, const char* name, const void* value, size_t size, int flags) {
   return fsetxattr(FD(gfd), name, value, size, flags);
}

#else
int     udal_posix_fsetxattr(GenericFD* gfd, const char *name, const void *value, size_t size, u_int32_t position, int options) {
   return fsetxattr(FD(gfd), name, value, size, position, options);
}
#endif


// #if (AXATTR_GET_FUNC == 4)
// ssize_t udal_posix_fgetxattr(GenericFD* gfd, const char* name, void* value, size_t size) {
//    return fgetxattr(FD(gfd), name, value, size);
// }
// 
// #else
// ssize_t udal_posix_fgetxattr(GenericFD* gfd, const char *name, void *value, size_t size, u_int32_t position, int options) {
//    return fgetxattr(FD(gfd), name, value, size, position, options);
// }
// #endif


int     udal_posix_fsync(GenericFD* gfd) {
   return fsync(FD(gfd));
}

off_t   udal_posix_lseek(GenericFD* gfd, off_t offset, int whence) {
   return lseek(FD(gfd), offset, whence);
}




// PATHOP
int     udal_posix_chown(SktAuth* auth, const char* path, uid_t owner, gid_t group) {
   return chown(path, owner, group);
}
int     udal_posix_unlink(SktAuth* auth, const char* path) {
   return unlink(path);
}
int     udal_posix_rename(SktAuth* auth, const char* oldpath, const char* newpath) {
   return rename(oldpath, newpath);
}
int     udal_posix_stat(SktAuth* auth, const char* path, struct stat* buff) {
   return stat(path, buff);
}
ssize_t udal_posix_readlink(SktAuth* auth, const char* path, char* buff, size_t bufsize) {
   return readlink(path, buff, bufsize);
}
int     udal_posix_symlink(SktAuth* auth, const char* oldpath, const char* newpath) {
   return symlink(oldpath, newpath);
}





static const uDAL posix_impl = {
   .itype        = UDAL_POSIX,

   .fd_init      = &udal_posix_fd_init,
   .fd_err       = &udal_posix_fd_err,
   .fd_num       = &udal_posix_fd_num,

   .auth_init    = &udal_posix_auth_init,
   .auth_install = &udal_posix_auth_install,

   .open         = &udal_posix_open,
   .write        = &udal_posix_write,
   .read         = &udal_posix_read,
   .close        = &udal_posix_close,
   .fsetxattr    = &udal_posix_fsetxattr,
   // .fgetxattr    = &udal_posix_fgetxattr,
   .fsync        = &udal_posix_fsync,
   .lseek        = &udal_posix_lseek,

   // path-ops
   .chown        = &udal_posix_chown,
   .unlink       = &udal_posix_unlink,
   .rename       = &udal_posix_rename,
   .stat         = &udal_posix_stat,

   .readlink     = &udal_posix_readlink,
   .symlink      = &udal_posix_symlink,
};


const uDAL* udal_impl_posix = &posix_impl;




#undef FD




// ---------------------------------------------------------------------------
// SOCKETS
//
// NOTE: We avoid naming conflicts with librdma_sockets implementations.
// ---------------------------------------------------------------------------



#if (SOCKETS == SKT_none)
   // unused function makes it easy for external builds (e.g. marfs)
   // to determine how we were built
   int udal_non_socket_build() {}


#else

#  define SKT(GFD)   (&(GFD)->fds.skt)






int udal_skt_fd_init(GenericFD* gfd) {
   memset(SKT(gfd), 0, sizeof(SocketHandle));
   SKT(gfd)->peer_fd = -1;
   return 0;
}

int udal_skt_fd_err(GenericFD* gfd)  {
   return ((SKT(gfd)->peer_fd < 0)
           || (! SKT(gfd)->flags & HNDL_CONNECTED)
           || (  SKT(gfd)->flags & HNDL_DBG2)); /* temporary: skt_open() given an open handle */
}

int udal_skt_fd_num(GenericFD* gfd)  { return SKT(gfd)->peer_fd; }



int udal_skt_auth_init(const char* user, SktAuth* auth) {
   return skt_auth_init(user, auth);
}
int udal_skt_auth_install(GenericFD* gfd, SktAuth* auth) {
   return skt_auth_install(SKT(gfd), auth);
}



int udal_skt_open(GenericFD* gfd, const char* path, int flags, ...) {

   SocketHandle* skt = SKT(gfd);

   // open
   int rc;
   if (flags & O_CREAT) {
      va_list va;
      va_start(va, flags);
      mode_t mode = va_arg(va, int);
      va_end(va);

      rc = skt_open(skt, path, flags, mode);
   }
   else
      rc = skt_open(skt, path, flags);

   if (rc > 0) {
      // install SktAuth (which was stored on our ne_handle) onto the skt_handle
      SktAuth auth = gfd->hndl->auth;
      if (skt_fcntl(skt, SKT_F_SETAUTH, auth))
         return -1;             /* should skt_fcntl() failure be okay? */
   }

   return rc;
}


ssize_t udal_skt_write(GenericFD* gfd, const void* buf, size_t count) {
   return skt_write(SKT(gfd), buf, count);
}

ssize_t udal_skt_read(GenericFD* gfd, void* buf, size_t count) {
   return skt_read(SKT(gfd), buf, count);
}

int     udal_skt_close(GenericFD* gfd) {
   return skt_close(SKT(gfd));
}


#  if (AXATTR_SET_FUNC == 5) // XXX: not functional with threads!!!
int     udal_skt_fsetxattr(GenericFD* gfd, const char* name, const void* value, size_t size, int flags) {
   return skt_fsetxattr(SKT(gfd), name, value, size, flags);
}

#  else
int     udal_skt_fsetxattr(GenericFD* gfd, const char *name, const void *value, size_t size, u_int32_t position, int options) {
   return skt_fsetxattr(SKT(gfd), name, value, size, position, options);
}
#  endif


// #if (AXATTR_GET_FUNC == 4)
// ssize_t udal_skt_fgetxattr(GenericFD* gfd, const char* name, void* value, size_t size) {
//    return skt_fgetxattr(SKT(gfd), name, value, size);
// }
// 
// #else
// ssize_t udal_skt_fgetxattr(GenericFD* gfd, const char *name, void *value, size_t size, u_int32_t position, int options) {
//    return skt_fgetxattr(SKT(gfd), name, value, size, position, options);
// }
// #endif


int     udal_skt_fsync(GenericFD* gfd) {
   return skt_fsync(SKT(gfd));
}

off_t   udal_skt_lseek(GenericFD* gfd, off_t offset, int whence) {
   return skt_lseek(SKT(gfd), offset, whence);
}




// PATHOP
int     udal_skt_chown(SktAuth* auth, const char* path, uid_t owner, gid_t group) {
   return skt_chown(auth, path, owner, group);
}

int     udal_skt_unlink(SktAuth* auth, const char* path) {
   return skt_unlink(auth, path);
}

int     udal_skt_rename(SktAuth* auth, const char* oldpath, const char* newpath) {
   return skt_rename(auth, oldpath, newpath);
}

int     udal_skt_stat(SktAuth* auth, const char* path, struct stat* buff) {
   return skt_stat(auth, path, buff);
}
ssize_t udal_skt_readlink(SktAuth* auth, const char* path, char* buff, size_t bufsize) {
   errno = ENOTSUP;
   return -1;
}
int     udal_skt_symlink(SktAuth* auth, const char* old, const char* newpath) {
   errno = ENOTSUP;
   return -1;
}





static const uDAL sockets_impl = {
   .itype        = UDAL_SOCKETS,

   .fd_init      = &udal_skt_fd_init,
   .fd_err       = &udal_skt_fd_err,
   .fd_num       = &udal_skt_fd_num,

   .auth_init    = &udal_skt_auth_init,
   .auth_install = &udal_skt_auth_install,

   .open         = &udal_skt_open,
   .write        = &udal_skt_write,
   .read         = &udal_skt_read,
   .close        = &udal_skt_close,
   .fsetxattr    = &udal_skt_fsetxattr,
   // .fgetxattr    = &udal_skt_fgetxattr,
   .fsync        = &udal_skt_fsync,
   .lseek        = &udal_skt_lseek,

   // path-ops
   .chown        = &udal_skt_chown,
   .unlink       = &udal_skt_unlink,
   .rename       = &udal_skt_rename,
   .stat         = &udal_skt_stat,

   .readlink     = &udal_skt_readlink,
   .symlink      = &udal_skt_symlink,
};


const uDAL*  udal_impl_sockets = &sockets_impl;


#endif // SOCKETS


// ---------------------------------------------------------------------------
// generic
// ---------------------------------------------------------------------------

const uDAL*
get_impl(uDALType itype) {

   if (itype == UDAL_POSIX)
      return udal_impl_posix;
#if (SOCKETS != SKT_none)
   else if (itype == UDAL_SOCKETS)
      return udal_impl_sockets;
#endif
   else {
      PRINTerr( "ne_open: invalid uDAL arg - %d\n", itype);
      errno = EINVAL;
      return NULL;
   }
}
