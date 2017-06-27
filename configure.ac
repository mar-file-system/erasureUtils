#Copyright (c) 2015, Los Alamos National Security, LLC
#All rights reserved.
#
#Copyright 2015.  Los Alamos National Security, LLC. This software was produced
#under U.S. Government contract DE-AC52-06NA25396 for Los Alamos National
#Laboratory (LANL), which is operated by Los Alamos National Security, LLC for
#the U.S. Department of Energy. The U.S. Government has rights to use, reproduce,
#and distribute this software.  NEITHER THE GOVERNMENT NOR LOS ALAMOS NATIONAL
#SECURITY, LLC MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY
#FOR THE USE OF THIS SOFTWARE.  If software is modified to produce derivative
#works, such modified software should be clearly marked, so as not to confuse it
#with the version available from LANL.
# 
#Additionally, redistribution and use in source and binary forms, with or without
#modification, are permitted provided that the following conditions are met:
#1. Redistributions of source code must retain the above copyright notice, this
#list of conditions and the following disclaimer.
#
#2. Redistributions in binary form must reproduce the above copyright notice,
#this list of conditions and the following disclaimer in the documentation
#and/or other materials provided with the distribution.
#3. Neither the name of Los Alamos National Security, LLC, Los Alamos National
#Laboratory, LANL, the U.S. Government, nor the names of its contributors may be
#used to endorse or promote products derived from this software without specific
#prior written permission.
#
#THIS SOFTWARE IS PROVIDED BY LOS ALAMOS NATIONAL SECURITY, LLC AND CONTRIBUTORS
#"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#ARE DISCLAIMED. IN NO EVENT SHALL LOS ALAMOS NATIONAL SECURITY, LLC OR
#CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
#OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#-----
#NOTE:
#-----
#Although these files reside in a seperate repository, they fall under the MarFS copyright and license.
#
#MarFS is released under the BSD license.
#
#MarFS was reviewed and released by LANL under Los Alamos Computer Code identifier:
#LA-CC-15-039.
#
#These erasure utilites make use of the Intel Intelligent Storage Acceleration Library (Intel ISA-L), which can be found at https://github.com/01org/isa-l and is under its own license.
#
#MarFS uses libaws4c for Amazon S3 object communication. The original version
#is at https://aws.amazon.com/code/Amazon-S3/2601 and under the LGPL license.
#LANL added functionality to the original work. The original work plus
#LANL contributions is found at https://github.com/jti-lanl/aws4c.
#
#GNU licenses can be found at http://www.gnu.org/licenses/.
#
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([erasureUtils], [1.0], [gransom@lanl.gov])
AC_CONFIG_SRCDIR([COPYRIGHT.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

# # suppress compile/link details, if the option is available
# m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])


# default to empty flags, instead of "-g -O2"
: ${CFLAGS=""}
AC_PROG_CC

AC_PROG_RANLIB

# # ignored without 'libtoolize'
# AM_PROG_AR
# AC_PROG_LIBTOOL


# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h])
AXATTR_CHECK

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_SSIZE_T
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([bzero ftruncate memset strerror strtol strtoul])

# AC_FUNC_MALLOC runs into "undefined reference to 'rpl_malloc'"
### AC_FUNC_MALLOC
AC_CHECK_FUNCS([malloc])

AXATTR_GET_FUNC_CHECK
AXATTR_SET_FUNC_CHECK




AC_CHECK_LIB([pthread], [pthread_create])

# sockets subdir doesn't actually need this
AC_CHECK_LIB([isal],    [crc32_ieee],
    [],
    [AC_CHECK_LIB([isal], [crc32_ieee_base],
       [echo
        echo "WARNING:  Could not properly link 'crc32_ieee' from isa-l, defaulting to '_base' implementation"
        echo "          IN THIS STATE, THESE UTILITES MAY NOT FUNCTION AND WILL ALMOST CERTAINLY HAVE VERY POOR PERFORMANCE"
        echo], 
       [AC_MSG_ERROR(["Could not locate Intel's Intelligent Storage Acceleration Library (isa-l) on this system!  Please verify that the proper version of the library (v2.16.0 or higher) is installed."])])])




# optional build uses RDMA-sockets
# The server must be deployed on remote hosts (after building) to support this mode.
AC_ARG_ENABLE([sockets],
              AS_HELP_STRING([--enable-sockets],
                             [One of {rdma,ip,unix}.  File operations go to a server, via sockets.]),
              [case "${enableval}" in
                 rdma) enable_sockets=rdma ;;
                 # ip)   enable_sockets=ip ;;    # TBD
                 # unix) enable_sockets=unix ;;  # TBD
                 no)   enable_sockets=no ;;
                 *)    AC_MSG_FAILURE([enable-sockets={rdma,ip,unix}. Currently, only rdma is supported]) ;;
               esac],
              [enable_sockets=no])

AM_CONDITIONAL([ANY_SOCKETS],   [test "$enable_sockets" != no ])
AM_CONDITIONAL([RDMA_SOCKETS],  [test "$enable_sockets"  = rdma])

AM_COND_IF([ANY_SOCKETS],
           [AC_CHECK_LIB([pthread], [pthread_create])
            AC_CHECK_LIB([rt], [aio_cancel]) ])

AM_COND_IF([RDMA_SOCKETS],
           [AC_CHECK_LIB([rdmacm], [rdma_getaddrinfo]) ])




# whether an S3 authentication header is required/provided by client-functions to socket servers
# libaws4c is used to generate authentication-headers for RDMA socket server
AC_ARG_ENABLE([auth],
               AS_HELP_STRING([--disable-auth],
                              [Don't require RDMA client/server to use authentication.  (Avoid link with aws4c, curl, etc)]),
               [enable_auth=${enableval}],
               [enable_auth=yes])

AM_CONDITIONAL([AUTH_SOCKETS],  [test "$enable_sockets" != no && test x"$enable_auth" != xno])
AM_COND_IF([AUTH_SOCKETS],
           [AC_CHECK_LIB([crypto],      [MD5_Init])
            AC_CHECK_LIB([xml2],        [xmlReadMemory])
            AC_CHECK_LIB([curl],        [curl_easy_cleanup])
            AC_CHECK_LIB([aws4c],       [GetStringToSign])
            AC_CHECK_LIB([aws4c_extra], [get_object_list]) ])





# whether to disable file I/O used in the sockets sub-library.  For
# example, if disabled, neither GET nor PUT via test_client do any
# file-reads or file-writes.
AC_ARG_ENABLE([file-io],
               AS_HELP_STRING([--disable-file-io],
                              [Suppress file I/O for GET/PUT through RDMA client/server.  (For throughput tests)]),
               [enable_file_io=${enableval}],
               [enable_file_io=yes])

AM_CONDITIONAL([SUPPRESS_FILE_IO],  [test "$enable_file_io" != yes])




# option enables collection of stats
# (This value goes right into the code.  e.g. --enable-stats=0x30)
# For now, this is the only way to set stat flags, so stat-gathering will be
# useless overhead if you don't add the GLOBAL flag.  Later, it may be possible
# set flags on a per-handle basis.
AC_ARG_ENABLE([stats],
              AS_HELP_STRING([--enable-stats],
                             [bitmask: 0x80=HNDL, 0x40=THR, 0x20=ERAS, 0x10=CRC, 8=REN, 4=CLOSE, 2=RW, 1=OPEN]),
              [enable_stats=${enableval}],
              [enable_stats=0])

AC_SUBST([enable_stats], [${enable_stats}])





# Allow turning on debugging flags
AC_ARG_ENABLE([debug],
               AS_HELP_STRING([--enable-debug],
                              [Turn on internal debugging.  One of {ne,sockets,all,no}]),
               [case "${enableval}" in
                  ne)        enable_debug=ne ;;
                  sockets)   enable_debug=sockets ;;
                  all)       enable_debug=all ;;
                  allft)     enable_debug=allft ;;
                  *)    AC_MSG_FAILURE([enable-debug={ne,sockets,all,allft,no}.]) ;;
                esac],
               [enable_debug=no])

AM_CONDITIONAL([DEBUG_NE],      [test "$enable_debug" = ne      || test "$enable_debug" = all ])
AM_CONDITIONAL([DEBUG_SOCKETS], [test "$enable_debug" = sockets || test "$enable_debug" = all ])
AM_CONDITIONAL([DEBUG_FT],      [test "$enable_debug" = allft ])



# debugging-output should go to syslog, instead of stdout/stderr?
AC_ARG_ENABLE([syslog],
               AS_HELP_STRING([--enable-syslog],
                              [Send debugging output to syslog, instead of stdout/stderr]),
              [enable_syslog=$enableval],
              [enable_syslog=no])

AM_CONDITIONAL([USE_SYSLOG], [test "x$enable_syslog" != xno])




# We depend on a number of environment variables
AC_ARG_VAR(AWS4C, [The location of the aws4c installation])
AC_ARG_VAR(LIBAWS4C, [The location of the aws4c library installation (probably the same as AWS4C)])

# Customization of server-side buffer-size
AC_ARG_VAR([S_BUFSIZE],
           [If RDMA sockets are enabled, this is the size of buffers used for server-side
            transfers between sockets and files (default is 1MB)])
AM_CONDITIONAL([HAVE_S_BUFSIZE], [test x"$S_BUFSIZE" != x])


# Customization of client-side buffer-size for get/put.
AC_ARG_VAR([C_BUFSIZE],
           [size of client-side buffer, used for client_get()/client_put() only.
            All other functions take client-side buffer and buffer-size as arguments.  (default is 1MB)])
AM_CONDITIONAL([HAVE_C_BUFSIZE], [test x"$C_BUFSIZE" != x])





AC_CONFIG_FILES([Makefile
                 fast_timer/Makefile
                 sockets/Makefile
                 fileraid/Makefile
                 erasureLib/Makefile])
AC_OUTPUT
