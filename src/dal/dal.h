
#ifndef DAL_H_INCLUDE
#define DAL_H_INCLUDE


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

These erasure utilites make use of the Intel Intelligent Storage
Acceleration Library (Intel ISA-L), which can be found at
https://github.com/01org/isa-l and is under its own license.

MarFS uses libaws4c for Amazon S3 object communication. The original version
is at https://aws.amazon.com/code/Amazon-S3/2601 and under the LGPL license.
LANL added functionality to the original work. The original work plus
LANL contributions is found at https://github.com/jti-lanl/aws4c.

GNU licenses can be found at http://www.gnu.org/licenses/.
*/




#include <libxml/tree.h>
#include <string.h>

#ifndef LIBXML_TREE_ENABLED
#error "Included Libxml2 does not support tree functionality!"
#endif


typedef struct DAL_location_struct {
   int pod;      //
   int cap;
   int block;
   int scatter;
} DAL_location;

// just to provide some type safety (don't want to pass the wrong void*)
typedef void* DAL_CTXT;
typedef void* BLOCK_CTXT;
typedef enum {
   READ = 0,
   WRITE = 1,
   REBUILD = 2
} DAL_MODE;

typedef struct DAL_struct {
   // Name -- Used to identify and configure the DAL
   const char*    name;

   // DAL Internal Context -- passed to each DAL function
   DAL_CTXT       ctxt;

   // DAL Functions -- 
   int (*dal_verify) ( DAL_CTXT ctxt, char fix );
      // Description:
      //  Ensure that the DAL is properly configured, functional, and secure.  Log any problems encountered.
      //  If the 'fix' argument is non-zero, attempt to correct such problems.
      //  Note - the specifics of this implementaiton will depend GREATLY on the nature of the DAL.
      // Return Values:
      //  Zero on success, Non-zero if unresolved problems were found
   int (*dal_migrate) ( DAL_CTXT ctxt, const char* objID, DAL_location src, DAL_location dest, char offline );
      // Description:
      //  Relocate an object referenced by 'objID' & 'src' to new location 'dest'.
      //  If the 'offline' argument is zero, this relocation will be performed such that the object can 
      //  still be referenced at the original 'src' location during and after completion of this process.
      //  If the 'offline' argument is non-zero, this relocation will be performed such that the original 
      //  'src' location is invalidated and any additial resources associated with that reference are 
      //  recovered.
      //  Note - this function should always fail if asked to alter only the 'block' value of an object location.
      //  (Intended to avoid overwriting existing object parts)
      // Return Values:
      //  Zero on success, Non-zero if the operation could not be completed
   int (*dal_del) ( DAL_CTXT ctxt, DAL_location location, const char* objID );
      // Description:
      // Return Values:
      //  Zero on success, Non-zero if the operation could not be completed
   int (*dal_cleanup) ( struct DAL_struct* dal );
      // Description:
      // Return Values:
      //  Zero on success, Non-zero if the operation could not be completed
   BLOCK_CTXT (*dal_open) ( DAL_CTXT ctxt, DAL_MODE mode, DAL_location location, const char* objID );
      // Description:
      // Return Values:
      //  Non-NULL on success, NULL if the operation could not be completed
   int (*dal_set_meta) ( BLOCK_CTXT ctxt, const char* meta_buf, size_t size);
      // Description:
      // Return Values:
      //  Zero on success, Non-zero if the operation could not be completed
   ssize_t (*dal_get_meta) ( BLOCK_CTXT ctxt, char* meta_buf, size_t size);
      // Description:
      // Return Values:
      //  Zero on success, Non-zero if the operation could not be completed
   int (*dal_put) ( BLOCK_CTXT ctxt, const void* buf, size_t size );
      // Description:
      // Return Values:
      //  Zero on success, Non-zero if the operation could not be completed
   ssize_t (*dal_get) ( BLOCK_CTXT ctxt, void* buf, size_t size, off_t offset );
      // Description:
      // Return Values:
      //  Zero on success, Non-zero if the operation could not be completed
   int (*dal_abort) ( BLOCK_CTXT ctxt );
      // Description:
      // Return Values:
      //  Zero on success, Non-zero if the operation could not be completed
   int (*dal_close) ( BLOCK_CTXT ctxt );
      // Description:
      // Return Values:
      //  Zero on success, Non-zero if the operation could not be completed
} *DAL;


// Forward decls of specific DAL initializations
DAL posix_dal_init( xmlNode* dal_conf_root, DAL_location max_loc );


// Function to provide specific DAL initialization calls based on name
DAL init_dal_by_name( const char* name, xmlNode* dal_conf_root, DAL_location max_loc ) {
   if (  strncmp( name, "posix", 6 ) == 0 ) {
      return posix_dal_init( dal_conf_root, max_loc );
   }
   // if no DAL found, return NULL
   return NULL;
}



#endif

