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

# Allow automake to figure out what "+=" means
SOCKET_DEFS =

# This is the pitiful approach required to avoid "already defined" warnings
# from automake, if you were to try to re-assign SOCKET_DEFS to the thing
# you wanted based on two different conditions
if RDMA_SOCKETS
  SOCKET_DEFS += -DSOCKETS=RDMA
  SOCKET_CPPFLAGS = -I${top_srcdir}/sockets
  SOCKET_LIBS = ../sockets/librdma_sockets.a
  SOCKET_LD = -lrdmacm
else
if ANY_SOCKETS
  SOCKET_DEFS += -DSOCKETS
  SOCKET_CPPFLAGS = -I${top_srcdir}/sockets
endif
endif


if USE_SYSLOG
   DEBUG_NE_VALUE=2
else
   DEBUG_NE_VALUE=1
endif


if DEBUG_NE
  AM_CFLAGS = -g -O1
  SOCKET_DEFS += -DDEBUG_NE=$(DEBUG_NE_VALUE)  -fstack-protector-all -fstack-check
else
  AM_CFLAGS = -g -O3
  SOCKET_DEFS += -DDEBUG_NE=0
endif


# erasure.h includes "skt_common.h".  Programs in this dir are built
# before 'make install' will have put ../sockets/skt_common.h into the
# install directory.  So the following allows these executables to be
# built.
AM_CPPFLAGS = $(SOCKET_CPPFLAGS) $(SOCKET_DEFS)



include_HEADERS = erasure.h ne_logging.h


lib_LIBRARIES = libne.a
libne_a_SOURCES = erasure.c erasure.h
libne_a_LIBADD = $(SOCKET_LIBS)


bin_PROGRAMS = libneTest
libneTest_SOURCES = libneTest.c
libneTest_LDADD = libne.a $(SOCKET_LIBS)
# libneTest_LDFLAGS = -lisal $(SOCKET_LD)


check_PROGRAMS = test_read_offset

test_read_offset_SOURCES = test_read_offset.c
test_read_offset_LDADD = libne.a
test_read_offset_LDFLAGS = -lisal


TESTS=erasureTest test_read_offset

