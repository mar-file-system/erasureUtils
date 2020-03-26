
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

#include <fcntl.h>
#include <errno.h>

#define DEBUG 1
#define USE_STDOUT 1
#define LOG_PREFIX "posix_dal"
#include "logging/logging.h"
#include "dal.h"



//   -------------    POSIX DEFINITIONS    -------------

// NOTE -- make sure to adjust SFX_PADDING if changing any SFX strings!
#define SFX_PADDING 13  // number of extra chars required to fit any suffix combo
#define WRITE_SFX ".partial"   // 8 characters
#define REBUILD_SFX ".rebuild" // 8 characters
#define META_SFX ".meta"       // 5 characters (in ADDITION to other suffixes!)



//   -------------    POSIX CONTEXT    -------------

typedef struct posix_block_context_struct {
   int         fd; // File Descriptor (if open)
   char* filepath; // File Path (if open)
   int    filelen; // Length of filepath string
   off_t   offset; // Current file offset (only relevant when reading)
   DAL_MODE  mode; // Mode in which this block was opened
} *POSIX_BLOCK_CTXT;

typedef struct posix_dal_context_struct {
   char*         dirtmp; // Template string for generating directory paths
   int           tmplen; // Length of the dirtmp string
   DAL_location max_loc; // Maximum pod/cap/block/scatter values
   int           dirpad; // Number of chars by which dirtmp may expand via substitutions
} *POSIX_DAL_CTXT;
   


//   -------------    POSIX INTERNAL FUNCTIONS    -------------

int check_loc_limits( DAL_location loc, const DAL_location* max_loc ) {
   // simple check of limits to ensure we don't overrun allocated strings
   if ( loc.pod > max_loc->pod ) {
      LOG( LOG_ERR, "pod value of %d exceeds limit of %d\n", loc.pod, max_loc->pod );
      return -1;
   }
   if ( loc.cap > max_loc->cap ) {
      LOG( LOG_ERR, "cap value of %d exceeds limit of %d\n", loc.cap, max_loc->cap );
      return -1;
   }
   if ( loc.block > max_loc->block ) {
      LOG( LOG_ERR, "block value of %d exceeds limit of %d\n", loc.block, max_loc->block );
      return -1;
   }
   if ( loc.scatter > max_loc->scatter ) {
      LOG( LOG_ERR, "scatter value of %d exceeds limit of %d\n", loc.scatter, max_loc->scatter );
      return -1;
   }
   return 0;
}



int num_digits( int value ) {
   if ( value < 0 ) { return -1; } // negative values not permitted
   if ( value < 10 ) { return 1; }
   if ( value < 100 ) { return 2; }
   if ( value < 1000 ) { return 3; }
   if ( value < 10000 ) { return 4; }
   if ( value < 100000 ) { return 5; }
   // only support values up to 5 digits long
   return -1;
}



int expand_dir_template( POSIX_DAL_CTXT dctxt, POSIX_BLOCK_CTXT bctxt, DAL_location loc, const char* objID ) {
   // check that our DAL_location is within bounds
   if ( check_loc_limits( loc, &(dctxt->max_loc) ) != 0 ) {
      errno = EDOM;
      return -1;
   }

   // allocate string to hold the dirpath
   // NOTE -- allocation size is an estimate, based on the above pod/block/cap/scat limits
   bctxt->filepath = malloc( sizeof(char) * ( dctxt->tmplen + dctxt->dirpad + strlen(objID) + SFX_PADDING + 1 ) );

   // parse through the directory template string, populating filepath as we go
   const char* parse = dctxt->dirtmp;
   char* fill = bctxt->filepath;
   char escp = 0;
   while ( *parse != '\0' ) {

      switch ( *parse ) {

         case '\\': // check for escape character '\'
            if ( escp ) { // only add literal '\' if already escaped
               *fill = *parse;
               fill++;
               escp = 0;
            }
            else { escp = 1; } // escape the next character
            break;
         
         case '{': // check for start of a substitution
            if ( escp ) { // only add literal '{' if escaped
               *fill = '{';
               fill++;
               escp = 0;
            }
            else {
               parse++;
               int fillval = 0;
               if ( *parse == 'p' ) {
                  fillval = loc.pod;
               }
               else if ( *parse == 'b' ) {
                  fillval = loc.block;
               }
               else if ( *parse == 'c' ) {
                  fillval = loc.cap;
               }
               else if ( *parse == 's' ) {
                  fillval = loc.scatter;
               }
               else {
                  LOG( LOG_WARNING, "dir_template contains an unescaped '{' followed by '%c', rather than an expected 'p'/'b'/'c'/'s'\n", *parse );
                  *fill = '{';
                  fill++;
                  continue;
               }
               // ensure the '}' (end of substitution character) follows
               if ( *(parse+1) != '}' ) {
                  LOG( LOG_WARNING, "dir_template contains an '{%c' substitution sequence with no closing '}' character\n", *parse );
                  *fill = '{';
                  fill++;
                  continue;
               }
               // print the numeric value into the fill string
               fillval = snprintf( fill, 5, "%d", fillval );
               if ( fillval <= 0 ) {
                  // if snprintf failed for some reason, we can't recover
                  LOG( LOG_ERR, "snprintf failed when attempting dir_template substitution!\n" );
                  free( bctxt->filepath );
                  bctxt->filepath = NULL;
                  return -1;
               }
               fill += fillval; // update fill pointer to refernce the new end of the string
               parse++; // skip over the '}' character that we have already verified
            }
            break;

         default:
            if ( escp ) {
               LOG( LOG_WARNING, "invalid '\\%c' escape encountered in the dir_template string\n", *parse );
               escp = 0;
            }
            *fill = *parse;
            fill++;
            break;
      }

      parse++;
   }
   // parse through the given objID, populating filepath as we go
   parse = objID;
   while ( *parse != '\0' ) {
      
      switch ( *parse ) {

         // posix won't allow '/' in filenames; replace with '#'
         case '/':
            *fill = '#';
            fill++;
            break;
         
         default:
            *fill = *parse;
            fill++;
            break;
      }

      parse++;
   }
   // ensure we null terminate the string
   *fill = '\0';
   // user pointer arithmetic to determine length of path
   bctxt->filelen = fill - bctxt->filepath;
   return 0;
}



int block_delete( POSIX_BLOCK_CTXT bctxt ) {
   // append the meta suffix and check for success
   char* res = strncat( bctxt->filepath + bctxt->filelen, META_SFX, SFX_PADDING );
   if ( res != ( bctxt->filepath + bctxt->filelen ) ) {
      LOG( LOG_ERR, "failed to append meta suffix \"%s\" to file path \"%s\"!\n", META_SFX, bctxt->filepath );
      errno = EBADF;
      return -1;
   }

   int metalen = strlen( META_SFX );

   // append the write suffix and check for success
   res = strncat( bctxt->filepath + bctxt->filelen + metalen, WRITE_SFX, SFX_PADDING - metalen );
   if ( res != ( bctxt->filepath + bctxt->filelen + metalen ) ) {
      LOG( LOG_ERR, "failed to append write suffix \"%s\" to file path \"%s\"!\n", WRITE_SFX, bctxt->filepath );
      errno = EBADF;
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1;
   }

   // unlink any in-progress meta file (only failure with ENOENT is acceptable)
   if ( unlink( bctxt->filepath ) != 0  &&  errno != ENOENT ) {
      LOG( LOG_ERR, "failed to unlink \"%s\" (%s)\n", bctxt->filepath, strerror(errno) );
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1;
   }

   // trim the write suffix off
   *(bctxt->filepath + bctxt->filelen + metalen) = '\0';

   // unlink any meta file (only failure with ENOENT is acceptable)
   if ( unlink( bctxt->filepath ) != 0  &&  errno != ENOENT ) {
      LOG( LOG_ERR, "failed to unlink \"%s\" (%s)\n", bctxt->filepath, strerror(errno) );
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1; 
   }

   // trim the meta suffix off and attach a write suffix in its place
   *(bctxt->filepath + bctxt->filelen) = '\0';
   res = strncat( bctxt->filepath + bctxt->filelen, WRITE_SFX, SFX_PADDING - metalen );
   if ( res != ( bctxt->filepath + bctxt->filelen ) ) {
      LOG( LOG_ERR, "failed to append write suffix \"%s\" to file path \"%s\"!\n", WRITE_SFX, bctxt->filepath );
      errno = EBADF;
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1;
   }

   // unlink any in-progress data file (only failure with ENOENT is acceptable)
   if ( unlink( bctxt->filepath ) != 0  &&  errno != ENOENT ) {
      LOG( LOG_ERR, "failed to unlink \"%s\" (%s)\n", bctxt->filepath, strerror(errno) );
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1; 
   }

   *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains

   // unlink any data file (only failure with ENOENT is acceptable)
   if ( unlink( bctxt->filepath ) != 0  &&  errno != ENOENT ) {
      LOG( LOG_ERR, "failed to unlink \"%s\" (%s)\n", bctxt->filepath, strerror(errno) );
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1;
   }

   return 0;
}



//   -------------    POSIX IMPLEMENTATION    -------------

int posix_verify ( DAL_CTXT ctxt, char fix ) {
   errno = ENOSYS;
   return -1; // TODO -- actually write this
}



int posix_migrate ( DAL_CTXT ctxt, const char* objID, DAL_location src, DAL_location dest, char offline ) {
   errno = ENOSYS;
   return -1; // TODO -- actually write this
}



int posix_del (  DAL_CTXT ctxt, DAL_location location, const char* objID ) {
   POSIX_DAL_CTXT dctxt = (POSIX_DAL_CTXT) ctxt; // should have been passed a posix context

   // allocate space for a new BLOCK context
   POSIX_BLOCK_CTXT bctxt = malloc( sizeof( struct posix_block_context_struct ) );
   if ( bctxt == NULL ) { return -1; } // malloc will set errno

   // popultate the full file path for this object
   if ( expand_dir_template( dctxt, bctxt, location, objID ) != 0 ) { free( bctxt ); return -1; }

   int res = block_delete( bctxt );

   free( bctxt->filepath );
   free( bctxt );
   return res;
}



int posix_cleanup ( DAL dal ) {
   POSIX_DAL_CTXT dctxt = (POSIX_DAL_CTXT) dal->ctxt; // should have been passed a posix context

   // free DAL context state
   free( dctxt->dirtmp );
   free( dctxt );
   // free the DAL struct and its associated state
   free( dal );
   return 0;
}



BLOCK_CTXT posix_open ( DAL_CTXT ctxt, DAL_MODE mode, DAL_location location, const char* objID ) {
   POSIX_DAL_CTXT dctxt = (POSIX_DAL_CTXT) ctxt; // should have been passed a posix context

   // allocate space for a new BLOCK context
   POSIX_BLOCK_CTXT bctxt = malloc( sizeof( struct posix_block_context_struct ) );
   if ( bctxt == NULL ) { return NULL; } // malloc will set errno

   // popultate the full file path for this object
   if ( expand_dir_template( dctxt, bctxt, location, objID ) != 0 ) { free( bctxt ); return NULL; }

   // populate other BLOCK context fields
   bctxt->offset = 0;
   bctxt->mode = mode;
   
   int oflags = O_WRONLY | O_CREAT | O_TRUNC;
   if ( mode == READ ) {
      oflags = O_RDONLY;
   }
   else {
      char* res = NULL;
      // append the proper suffix
      if ( mode == WRITE ) {
         res = strncat( bctxt->filepath + bctxt->filelen, WRITE_SFX, SFX_PADDING );
      }
      else if ( mode == REBUILD ) {
         res = strncat( bctxt->filepath + bctxt->filelen, REBUILD_SFX, SFX_PADDING );
      } // NOTE -- invalid mode will leave res == NULL
      // check for success appending the suffix
      if ( res != ( bctxt->filepath + bctxt->filelen ) ) {
         LOG( LOG_ERR, "failed to append suffix to file path!\n" );
         errno = EBADF;
         free( bctxt->filepath );
         free( bctxt );
         return NULL;
      }
   }
   // open the file and check for success
   bctxt->fd = open( bctxt->filepath, oflags, S_IRWXU | S_IRWXG | S_IRWXO ); // mode arg should be harmlessly ignored if reading
   if ( bctxt->fd < 0 ) {
      LOG( LOG_ERR, "failed to open file: \"%s\" (%s)\n", bctxt->filepath, strerror(errno) );
      free( bctxt->filepath );
      free( bctxt );
      return NULL;
   }
   // remove any suffix in the simplest possible manner
   *(bctxt->filepath + bctxt->filelen) = '\0';
   // finally, return a reference to our BLOCK context
   return bctxt;
}



int posix_set_meta ( BLOCK_CTXT ctxt, const char* meta_buf, size_t size ) {
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT) ctxt; // should have been passed a posix context

   // append the meta suffix and check for success
   char* res = strncat( bctxt->filepath + bctxt->filelen, META_SFX, SFX_PADDING );
   if ( res != ( bctxt->filepath + bctxt->filelen ) ) {
      LOG( LOG_ERR, "failed to append meta suffix \"%s\" to file path!\n", META_SFX );
      errno = EBADF;
      return -1;
   }

   int metalen = strlen( META_SFX );

   // append the write suffix and check for success
   res = strncat( bctxt->filepath + bctxt->filelen + metalen, WRITE_SFX, SFX_PADDING - metalen );
   if ( res != ( bctxt->filepath + bctxt->filelen + metalen ) ) {
      LOG( LOG_ERR, "failed to append write suffix \"%s\" to file path!\n", WRITE_SFX );
      errno = EBADF;
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1;
   }

   // duplicate the path and check for success
   char* meta_path = strdup( bctxt->filepath );
   if ( meta_path == NULL ) {
      LOG( LOG_ERR, "failed to allocate space for a new string! (%s)\n", strerror(errno) );
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1;
   }

   // open the meta sidecar file and check for success
   int mfd = open( meta_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO );
   if ( mfd < 0 ) {
      LOG( LOG_ERR, "failed to open meta file \"%s\" for write (%s)\n", meta_path, strerror(errno) );
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      free( meta_path );
      return -1;
   }

   // write the provided buffer out to the sidecar file
   if ( write( mfd, meta_buf, size ) != size ) {
      LOG( LOG_ERR, "failed to write buffer to meta file: \"%s\" (%s)\n", meta_path, strerror(errno) );
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      free( meta_path );
      return -1;
   }

   // close the file
   if ( close( mfd ) != 0 ) {
      LOG( LOG_ERR, "failed to properly close meta file: \"%s\" (%s)\n", meta_path, strerror(errno) );
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      free( meta_path );
      return -1;
   }

   // strip only the write suffix from the name
   *(bctxt->filepath + bctxt->filelen + metalen) = '\0';

   // rename the file
   if ( rename( meta_path, bctxt->filepath ) != 0 ) {
      LOG( LOG_ERR, "failed to rename meta file \"%s\" to \"%s\" (%s)\n", meta_path, bctxt->filepath, strerror(errno) );
      free(meta_path);
      return -1;
   }

   *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
   free( meta_path );
   return 0;
}



ssize_t posix_get_meta ( BLOCK_CTXT ctxt, char* meta_buf, size_t size ) {
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT) ctxt; // should have been passed a posix context

   // append the meta suffix and check for success
   char* res = strncat( bctxt->filepath + bctxt->filelen, META_SFX, SFX_PADDING );
   if ( res != ( bctxt->filepath + bctxt->filelen ) ) {
      LOG( LOG_ERR, "failed to append meta suffix \"%s\" to file path!\n", META_SFX );
      errno = EBADF;
      return -1;
   }

   // open the meta sidecar file and check for success
   int mfd = open( bctxt->filepath, O_RDONLY );
   if ( mfd < 0 ) {
      LOG( LOG_ERR, "failed to open meta file \"%s\" for read (%s)\n", bctxt->filepath, strerror(errno) );
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1;  
   }

   ssize_t result = read( mfd, meta_buf, size );

   // close the meta file and check for success
   if ( close( mfd ) != 0 ) {
      // failing this isn't actually all that relevant, probably still want to warn though
      LOG( LOG_WARNING, "failed to close meta file \"%s\" (%s)\n", bctxt->filepath, strerror(errno) );
   }
   *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains

   return result;
}



int posix_put ( BLOCK_CTXT ctxt, const void* buf, size_t size ) {
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT) ctxt; // should have been passed a posix context
   
   // just a write to our pre-opened FD
   if ( write( bctxt->fd, buf, size ) != size ) {
      LOG( LOG_ERR, "write to \"%s\" failed (%s)\n", bctxt->filepath, strerror(errno) );
      return -1;
   }

   return 0;
}



ssize_t posix_get ( BLOCK_CTXT ctxt, void* buf, size_t size, off_t offset ) {
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT) ctxt; // should have been passed a posix context

   // check if we need to seek
   if ( offset != bctxt->offset ) {
      offset = lseek( bctxt->fd, offset, SEEK_SET );
      // make sure our new offset makes sense
      if ( offset < 0 ) {
         LOG( LOG_ERR, "failed to seek to offset %zd of file \"%s\" (%s)\n", offset, bctxt->filepath, strerror(errno) );
         return -1;
      }
   }

   // just a read from our pre-opened FD
   ssize_t res = read( bctxt->fd, buf, size );

   // adjust our offset value
   if ( res > 0 ) { bctxt->offset += res; }

   return res;
}



int posix_abort ( BLOCK_CTXT ctxt ) {
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT) ctxt; // should have been passed a posix context

   // close the file descriptor, note but bypass failure
   if ( close( bctxt->fd ) != 0 ) {
      LOG( LOG_WARNING, "failed to close data file \"%s\" during abort (%s)\n", bctxt->filepath, strerror(errno) );
   }

   // free state
   free( bctxt->filepath );
   free( bctxt );
   return 0;
}



int posix_close ( BLOCK_CTXT ctxt ) {
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT) ctxt; // should have been passed a posix context

   // attempt to close and check for success
   if ( close( bctxt->fd ) != 0 ) {
      LOG( LOG_ERR, "failed to close data file \"%s\" (%s)\n", bctxt->filepath, strerror(errno) );
      return -1;
   }

   if ( bctxt->mode == WRITE  ||  bctxt->mode == REBUILD ) {
      char* res = NULL;
      if ( bctxt->mode == WRITE ) {
         // append the write suffix
         res = strncat( bctxt->filepath + bctxt->filelen, WRITE_SFX, SFX_PADDING );
      }
      else {
         // append the rebuild suffix
         res = strncat( bctxt->filepath + bctxt->filelen, REBUILD_SFX, SFX_PADDING );
      }
      // check for success
      if ( res != ( bctxt->filepath + bctxt->filelen ) ) {
         LOG( LOG_ERR, "failed to append write suffix \"%s\" to file path!\n", WRITE_SFX );
         errno = EBADF;
         *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
         return -1;
      }

      // duplicate the path and check for success
      char* write_path = strdup( bctxt->filepath );
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains

      // attempt to rename and check for success
      if ( rename( write_path, bctxt->filepath ) != 0 ) {
         LOG( LOG_ERR, "failed to rename file \"%s\" to \"%s\" (%s)\n", write_path, bctxt->filepath, strerror(errno) );
         free(write_path);
         return -1;
      }
      free(write_path);
   }

   // free state
   free( bctxt->filepath );
   free( bctxt );
   return 0;
}



//   -------------    POSIX INITIALIZATION    -------------

DAL posix_dal_init( xmlNode* root, DAL_location max_loc ) {
   // first, calculate the number of digits required for pod/cap/block/scatter
   int d_pod = num_digits( max_loc.pod );
   if ( d_pod < 1 ) {
      errno = EDOM;
      LOG( LOG_ERR, "detected an inappropriate value for maximum pod: %d\n", max_loc.pod );
      return NULL;
   }
   int d_cap = num_digits( max_loc.cap );
   if ( d_cap < 1 ) {
      errno = EDOM;
      LOG( LOG_ERR, "detected an inappropriate value for maximum cap: %d\n", max_loc.cap );
      return NULL;
   }
   int d_block = num_digits( max_loc.block );
   if ( d_block < 1 ) {
      errno = EDOM;
      LOG( LOG_ERR, "detected an inappropriate value for maximum block: %d\n", max_loc.block );
      return NULL;
   }
   int d_scatter = num_digits( max_loc.scatter );
   if ( d_scatter < 1 ) {
      errno = EDOM;
      LOG( LOG_ERR, "detected an inappropriate value for maximum scatter: %d\n", max_loc.scatter );
      return NULL;
   }

   // make sure we start on a 'dir_template' node
   if ( root->type == XML_ELEMENT_NODE  &&  strncmp( (char*)root->name, "dir_template", 13 ) == 0 ) {

      // make sure that node contains a text element within it
      if ( root->children != NULL  &&  root->children->type == XML_TEXT_NODE ) {

         // allocate space for our context struct
         POSIX_DAL_CTXT dctxt = malloc( sizeof( struct posix_dal_context_struct ) );
         if ( dctxt == NULL ) { return NULL; } // malloc will set errno

         // copy the dir template into the context struct
         dctxt->dirtmp = strdup( (char*)root->children->content );
         if ( dctxt->dirtmp == NULL ) { free(dctxt); return NULL; } // strdup will set errno

         // initialize all other context fields
         dctxt->tmplen = strlen( dctxt->dirtmp );
         dctxt->max_loc = max_loc;
         dctxt->dirpad = 0;

         // calculate a real value for dirpad based on number of p/c/b/s substitutions
         char* parse = dctxt->dirtmp;
         while ( *parse != '\0' ) {
            if ( *parse == '{' ) {
               // possible substituion, but of what type?
               int increase = 0;
               switch ( *(parse+1) ) {
                  case 'p':
                     increase = d_pod;
                     break;

                  case 'c':
                     increase = d_cap;
                     break;

                  case 'b':
                     increase = d_block;
                     break;

                  case 's':
                     increase = d_scatter;
                     break;
               }
               // if this looks like a valid substitution, check for a final '}'
               if ( increase > 0  &&  *(parse+2) == '}' ) { // NOTE -- we know *(parse+1) != '\0'
                  dctxt->dirpad += increase - 3; // add increase, adjusting for chars used in substitution
               }
            }
            parse++; // next char
         }

         // allocate and populate a new DAL structure
         DAL pdal = malloc( sizeof( struct DAL_struct ) );
         if ( pdal == NULL ) {
            LOG( LOG_ERR, "failed to allocate space for a DAL_struct\n" );
            free(dctxt);
            return NULL;
         } // malloc will set errno
         pdal->name = "posix";
         pdal->ctxt = (DAL_CTXT) dctxt;
         pdal->pread_size = 1048576;
         pdal->pwrite_size = 1048576;
         pdal->verify = posix_verify;
         pdal->migrate = posix_migrate;
         pdal->open = posix_open;
         pdal->set_meta = posix_set_meta;
         pdal->get_meta = posix_get_meta;
         pdal->put = posix_put;
         pdal->get = posix_get;
         pdal->abort = posix_abort;
         pdal->close = posix_close;
         pdal->del = posix_del;
         pdal->cleanup = posix_cleanup;
         return pdal;
      }
      else { LOG( LOG_ERR, "the \"dir_template\" node is expected to contain a template string\n" ); }
   }
   else { LOG( LOG_ERR, "root node of config is expected to be \"dir_template\"\n" ); }
   errno = EINVAL;
   return NULL; // failure of any condition check fails the function
}



