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
AC_PROG_RANLIB

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([isal], [crc32_ieee], [],
   [AC_CHECK_LIB([isal], [crc32_ieee_base],
      [echo
       echo "WARNING:  Could not properly link 'crc32_ieee' from isa-l, defaulting to '_base' implementation"
       echo "          IN THIS STATE, THESE UTILITES MAY NOT FUNCTION AND WILL ALMOST CERTAINLY HAVE VERY POOR PERFORMANCE"
       echo], 
         [AC_MSG_ERROR(["Could not locate Intel's Intelligent Storage Acceleration Library (isa-l) on this system!  Please verify that the proper version of the library (v2.16.0 or higher) is installed."])])])

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



# optional build uses RDMA-sockets
# The server must be deployed on remote hosts (after building) to support this mode.
AC_ARG_ENABLE([sockets],
               AS_HELP_STRING([--enable-sockets],
                              [One of {rdma,ip,unix}.  File operations go to a server, via sockets.]),
              [case "${enableval}" in
                 rdma) enable_sockets=rdma ;;
                 no)   enable_sockets=no ;;
                 *)    AC_MSG_FAILURE([enable-sockets={rdma,ip,unix}. Currently, only rdma is supported]) ;;
                esac],
               [enable_sockets=no])

AM_CONDITIONAL([ANY_SOCKETS],   [test "$enable_sockets" != no ])
AM_CONDITIONAL([RDMA_SOCKETS],  [test "$enable_sockets"  = rdma])

       

# Allow turning on debugging flags
AC_ARG_ENABLE([debug],
               AS_HELP_STRING([--enable-debug],
                              [Turn on internal debugging.  One of {ne,sockets,all,no}]),
               [case "${enableval}" in
                  ne)        enable_debug=ne ;;
                  sockets)   enable_debug=sockets ;;
                  all)       enable_debug=all ;;
                  *)    AC_MSG_FAILURE([enable-debug={ne,sockets,all,no}.]) ;;
                esac],
               [enable_debug=no])

AM_CONDITIONAL([DEBUG_NE],      [test "$enable_debug" = ne      || test "$enable_debug" = all ])
AM_CONDITIONAL([DEBUG_SOCKETS], [test "$enable_debug" = sockets || test "$enable_debug" = all ])



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
                 sockets/Makefile
                 fileraid/Makefile
                 erasureLib/Makefile])
AC_OUTPUT
