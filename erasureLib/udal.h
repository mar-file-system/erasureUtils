#ifndef __FILE_SYS_IMPL_H__
#define __FILE_SYS_IMPL_H__

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



#ifndef __NE_H__
#   error "do not include this file directly.  Include erasure.h, instead."
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


// forward-decls
typedef struct uDALImpl uDAL;

// generated to #define SOCKETS, etc, based on configuration options.
#include "udal_config.h"

#if (SOCKETS != SKT_none)
#  include "skt_common.h"
#  define DEFAULT_AUTH_INIT(AUTH)             skt_auth_init(SKT_S3_USER, &(AUTH))
#  define AUTH_INSTALL(FD, AUTH)              skt_auth_install((FD), (AUTH))

#else
   typedef void*    SktAuth;      // always NULL
   typedef int      SocketHandle; // unused
#  define DEFAULT_AUTH_INIT(AUTH)             (AUTH) = NULL
#  define AUTH_INSTALL(FD, AUTH)              0
#endif




// ne_handle stores these, which can be used by any uDAL implementation
typedef struct GenericFD {
   //struct handle*    hndl;      // pointer back to ne_handle
   SktAuth           auth;
   const uDAL*       impl;
   union {
      int            fd;
      SocketHandle   skt;
   }              fds;
} GenericFD;


// // Generic extractor function, redefined by each uDAL implementation.  This is called to
// // transform a GenericFD into the thing needed by a uDAL function.
// typedef void* (*FDExtractor)(GenericFD* gfd);
// 
// // these will be cast to FDExtractor, for storage in uDAL
// static inline int           extract_fd_posix(GenericFD* gfd)   { return gfd->fds.fd; }
// static inline SocketHandle* extract_fd_sockets(GenericFD* gfd) { return &gfd->fds.skt; }


// micro Data Abstraction Layer (uDAL)
//
// This abstraction allows callers to select the file-system implementation
// (RDMA-sockets or POSIX) at open-time, on a per-file-handle basis.  This
// means both the MC and RDMA MarFS DALs can be accessed with the same code.
// Previously, we were doing a build-time configuration of libne, which
// supported only one type of access.
//
// TBD: Perhaps this should just be defined within the MarFS DAL, and
//     passed in to libne?  Probably.  (The uDAL might also be a natural
//     place to keep the snprintf() function, config-state for snprintf,
//     SktAuth pointer, etc).  Meanwhile, realize that this is distinct
//     from the DAL, because we are defining how the individual block-files
//     are accessed, whereas the DAL depends on libne to perform a
//     transparent layer of erasure-coding.  Also, we're setting libne up
//     to be deeply dependent on the uDAL, so it makes some sense that it
//     would be defined and ... implemented, in libne.


typedef int     (*udal_fd_init)(GenericFD* gfd);  // assign obviously-illegitimate value (e.g. -1)
typedef int     (*udal_fd_err) (GenericFD* gfd);  // GFD state is "error" ?
typedef int     (*udal_fd_num) (GenericFD* gfd);  // GFD "number" for diagnostics (e.g. fd value)

typedef int     (*udal_auth_init)(const char* user, SktAuth* auth); // init <auth> for <user>
typedef int     (*udal_auth_install)(GenericFD* gfd, SktAuth* auth);

typedef int     (*udal_open)(GenericFD* gfd, const char* path, int flags, ...);

typedef ssize_t (*udal_write)(GenericFD* gfd, const void *buf, size_t count);
typedef ssize_t (*udal_read) (GenericFD* gfd, void *buf, size_t count);
typedef int     (*udal_close)(GenericFD* gfd);

#if (AXATTR_SET_FUNC == 5) // XXX: not functional with threads!!!
typedef int     (*udal_fsetxattr) (GenericFD* gfd, const char *name, const void *value, size_t size, int flags);
#else
typedef int     (*udal_fsetxattr) (GenericFD* gfd, const char *name, const void *value, size_t size, u_int32_t position, int options);
#endif

// #if (AXATTR_GET_FUNC == 4)
// typedef ssize_t (*udal_fgetxattr) (GenericFD* gfd, const char *name, void *value, size_t size);
// #else
// typedef ssize_t (*udal_fgetxattr) (GenericFD* gfd, const char *name, void *value, size_t size, u_int32_t position, int options);
// #endif

typedef int     (*udal_fsync) (GenericFD* gfd);
typedef off_t   (*udal_lseek) (GenericFD* gfd, off_t offset, int whence);



   // PATHOP
typedef int     (*udal_chown)   (SktAuth* auth, const char *path, uid_t owner, gid_t group);
typedef int     (*udal_unlink)  (SktAuth* auth, const char* path);
typedef int     (*udal_rename)  (SktAuth* auth, const char* oldpath, const char* newpath);
typedef int     (*udal_stat)    (SktAuth* auth, const char* path, struct stat* buff);

typedef ssize_t (*udal_readlink)(SktAuth* auth, const char* path, char* buff, size_t bufsize);
typedef int     (*udal_symlink) (SktAuth* auth, const char* oldpath, const char* newpath);





// select uDAL implementation
typedef enum {
   UDAL_POSIX = 1,               // POSX-type uDAL
   UDAL_SOCKETS
} uDALType;




// FileDescriptors in ne_handle will be either SocketHandle* or int.
// Different uDAL implementations will choose how to extract their own FD.
struct uDALImpl {
   //   FDExtractor   fd_extractor;  // extract fd to be passed to uDAL functions
   uDALType          itype;     /* allows reverse of get_impl() */

   udal_fd_init      fd_init;
   udal_fd_err       fd_err;
   udal_fd_num       fd_num;

   udal_open         open;
   udal_write        write;
   udal_read         read;
   udal_close        close;
   udal_fsetxattr    fsetxattr;
   // udal_fgetxattr    fgetxattr;
   udal_fsync        fsync;
   udal_lseek        lseek;

   udal_chown        chown;
   udal_unlink       unlink;
   udal_rename       rename;
   udal_stat         stat;
   udal_readlink     readlink;
   udal_symlink      symlink;

   udal_auth_init    auth_init;
   udal_auth_install auth_install;
   
};


extern const uDAL*  udal_posix;
extern const uDAL*  udal_sockets;



const uDAL*  get_impl(uDALType itype);


// int default_auth_init(SktAuth* auth) {
//    *(auth) = NULL
//    return 0;
// }



#endif
