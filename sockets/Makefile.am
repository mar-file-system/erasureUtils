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
#These erasure utilites make use of the Intel Intelligent Storage
#Acceleration Library (Intel ISA-L), which can be found at
#https://github.com/01org/isa-l and is under its own license.
#
#MarFS uses libaws4c for Amazon S3 object communication. The original version
#is at https://aws.amazon.com/code/Amazon-S3/2601 and under the LGPL license.
#LANL added functionality to the original work. The original work plus
#LANL contributions is found at https://github.com/jti-lanl/aws4c.
#
#GNU licenses can be found at http://www.gnu.org/licenses/.


AM_CPPFLAGS =
AM_LDFLAGS =

#AM_LDFLAGS += -lrt
#AM_LDFLAGS += -static


# number says how many buffers to fake reading from file, to send to server
# for PUT (or to fake writing to file, for client for GET), in order to
# measure raw throughput on the socket transport (e.g. RDMA).  Each buffer
# is CLIENT_BUF_SIZE (default 1MB).
if SUPPRESS_FILE_IO
  # DEFS += -DSKIP_FILE_READS=1024
  # DEFS += -DSKIP_FILE_READS=1048576
  # DEFS += -DSKIP_FILE_READS=10240
  DEFS += -DSKIP_FILE_READS=40960
  DEFS += -DSKIP_FILE_WRITES
endif


# at build-time, we want the versions in the source-tree
AM_CPPFLAGS += -I${top_srcdir}/erasureLib
AM_CPPFLAGS += -I${top_srcdir}/fast_timer



# NOTE: skt_config.h is now generated with values for SOCKETS / USE_RIOWRITE
#   These settings affect the sizes of structures in some of our .h files,
#   which might be used by external systems, so we need to assure that these
#   structures look the same, even for users that don't use our makefile.

if ANY_SOCKETS
  # # -D_GNU_SOURCE provides POLLRDHUP among the flags for poll()/rpoll()
  # DEFS        += -DSOCKETS -DUSE_RIOWRITE -D_GNU_SOURCE
  DEFS        += -D_GNU_SOURCE
endif

if AUTH_SOCKETS
   AM_CPPFLAGS += -I$(AWS4C)
endif


if USE_SYSLOG
   DEBUG_SOCKETS_VALUE=2
else
   DEBUG_SOCKETS_VALUE=1
endif

# These don't affect .h files, so we can do this from the makefile
if DEBUG_SOCKETS
  AM_CFLAGS    = -g -O0
  DEFS        += -DDEBUG_SOCKETS=$(DEBUG_SOCKETS_VALUE)
  AM_CPPFLAGS += -fstack-protector-all -fstack-check
else
  AM_CFLAGS    = -g -O3
  DEFS        += -DDEBUG_SOCKETS=0
endif


if TEST_API
  DEFS        += -DTEST_API
endif


if GPROF
  AM_CFLAGS  += -pg
  AM_LDFLAGS += -pg
endif


if HAVE_S_BUFSIZE
   DEFS        += -DSERVER_BUF_SIZE=$(S_BUFSIZE)
endif

if HAVE_C_BUFSIZE
   DEFS        += -CLIENT_BUF_SIZE=$(C_BUFSIZE)
endif





include_HEADERS = skt_config.h skt_common.h

lib_LIBRARIES = librdma_sockets.a
librdma_sockets_a_SOURCES = skt_common.c skt_common.h
if AUTH_SOCKETS
   librdma_sockets_a_SOURCES += auth.c
endif




bin_PROGRAMS = test_client marfs_objd


marfs_objd_SOURCES = marfs_objd.c
marfs_objd_LDADD  = librdma_sockets.a
marfs_objd_LDADD += ../fast_timer/libft.a

#
# # Various failed attempts to get autoconf to prefer static linking of
# # libisal, if possible.  (Some of these assume libtool is selected in the
# # configure.ac.)  Otherwise, we have to deploy libisal to all the storage
# # servers, so they can run marfs_objd.  However, it seems autotools
# # is violently opposed to allowing that sort of control.  Better
# # approach: realize that we don't even need libisal.  Take that out of
# # the top-level configure.ac, and let erasureLib/Makefile.am add it in
# # locally.
# 
# marfs_objd_LDFLAGS = -lpthread $(AM_LDFLAGS)
# marfs_objd_LDFLAGS = -lpthread -static
# marfs_objd_LDFLAGS = -all-static -lisal
# marfs_objd_LDFLAGS = "-Wl,-Bstatic -lisal -Wl,-Bdynamic"



test_client_SOURCES = test_client.c
test_client_LDADD  = librdma_sockets.a
test_client_LDADD += ../fast_timer/libft.a
