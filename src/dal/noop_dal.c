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

#include "erasureUtils_auto_config.h"
#ifdef DEBUG_DAL
#define DEBUG DEBUG_DAL
#elif (defined DEBUG_ALL)
#define DEBUG DEBUG_ALL
#endif
#define LOG_PREFIX "noop_dal"
#include "logging/logging.h"

#include "dal.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>

//   -------------    NO-OP DEFINITIONS    -------------

#define IO_SIZE 1048576 // Preferred I/O Size

//   -------------    NO-OP CONTEXT    -------------

typedef struct noop_dal_context_struct
{
   int   numblocks;  // Number of blocks for which we have cached info
   char**   c_meta;  // Cached metadata buffer(s) for future read ops
   size_t* metalen;  // Length of each cached metadata buffer
   void**   c_data;  // Cached data buffer(s) for future read ops
   size_t* datalen;  // Length of each cached data buffer
   size_t* maxdata;  // Total ( theoretical ) size of each cached data block
                     // NOTE -- Data content beyond the 'datalen' value will
                     //         be generated via repeated reuse of the cached
                     //         buffer.  As in, 'datalen' sized buffers,
                     //         repeated up to 'maxdata' total data size.
} * NOOP_DAL_CTXT;

typedef struct noop_block_context_struct
{
   NOOP_DAL_CTXT dctxt; // Global DAL context
   DAL_MODE       mode; // Mode of this block ctxt
   int           block; // Block number which this corresponds to
} * NOOP_BLOCK_CTXT;

//   -------------    NO-OP INTERNAL FUNCTIONS    -------------


//   -------------    NO-OP IMPLEMENTATION    -------------

int noop_verify(DAL_CTXT ctxt, char fix)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL dal context!\n");
      return -1;
   }
   // do nothing and assume success
   return 0;
}

int noop_migrate(DAL_CTXT ctxt, const char *objID, DAL_location src, DAL_location dest, char offline)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL dal context!\n");
      return -1;
   }
   // do nothing and assume success
   return 0;
}

int noop_del(DAL_CTXT ctxt, DAL_location location, const char *objID)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL dal context!\n");
      return -1;
   }
   // do nothing and assume success
   return 0;
}

int noop_stat(DAL_CTXT ctxt, DAL_location location, const char *objID)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL dal context!\n");
      return -1;
   }
   // do nothing and assume success
   return 0;
}

int noop_cleanup(DAL dal)
{
   if (dal == NULL)
   {
      LOG(LOG_ERR, "received a NULL dal!\n");
      return -1;
   }
   NOOP_DAL_CTXT dctxt = (NOOP_DAL_CTXT)dal->ctxt; // Should have been passed a DAL context
   // Free DAL and its context state
   int curblock;
   if ( dctxt->c_meta ) {
      // free all meta buffers
      for ( curblock = 0; curblock < dctxt->numblocks; curblock++ ) {
         if ( dctxt->c_meta[curblock] ) { free( dctxt->c_meta[curblock] ); }
      }
      free( dctxt->c_meta );
   }
   if ( dctxt->metalen ) { free( dctxt->metalen ); }
   if ( dctxt->c_data ) {
      // free all data buffers
      for ( curblock = 0; curblock < dctxt->numblocks; curblock++ ) {
         if ( dctxt->c_data[curblock] ) { free( dctxt->c_data[curblock] ); }
      }
      free( dctxt->c_data );
   }
   if ( dctxt->datalen ) { free( dctxt->datalen ); }
   if ( dctxt->maxdata ) { free( dctxt->maxdata ); }
   free(dctxt);
   free(dal);
   return 0;
}

BLOCK_CTXT noop_open(DAL_CTXT ctxt, DAL_MODE mode, DAL_location location, const char *objID)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL dal context!\n");
      return NULL;
   }
   NOOP_DAL_CTXT dctxt = (NOOP_DAL_CTXT)ctxt; // Should have been passed a DAL context
   // attempting to read from a non-cached block is an error
   if ( location.block >= dctxt->numblocks  &&
        ( mode == DAL_READ  ||  mode == DAL_METAREAD ) ) {
      LOG( LOG_ERR, "attempted to read from nonexistent block %d ( max cached = %d )\n", location.block, dctxt->numblocks );
      errno = ENOENT;
      return NULL;
   }
   NOOP_BLOCK_CTXT bctxt = malloc(sizeof(struct noop_block_context_struct));
   if (bctxt == NULL)
   {
      LOG( LOG_ERR, "failed to allocate a new block ctxt\n" );
      return NULL;
   }
   // populate values and global ctxt reference
   bctxt->dctxt = dctxt;
   bctxt->mode = mode;
   bctxt->block = location.block; // pod, cap, scat are all irrelevant for this DAL
   return bctxt;
}

int noop_set_meta(BLOCK_CTXT ctxt, const char *meta_buf, size_t size)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      errno = EINVAL;
      return -1;
   }
   NOOP_BLOCK_CTXT bctxt = (NOOP_BLOCK_CTXT)ctxt; // Should have been passed a block context
   // validate mode
   if ( bctxt->mode != DAL_WRITE  &&  bctxt->mode != DAL_REBUILD ) {
      LOG( LOG_ERR, "received block handle has inappropriate mode\n" );
      errno = EINVAL;
      return -1;
   }
   // do nothing and assume success
   return 0;
}

ssize_t noop_get_meta(BLOCK_CTXT ctxt, char *meta_buf, size_t size)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      return -1;
   }
   NOOP_BLOCK_CTXT bctxt = (NOOP_BLOCK_CTXT)ctxt; // Should have been passed a block context
   // validate mode
   if ( bctxt->mode != DAL_READ  &&  bctxt->mode != DAL_METAREAD ) {
      LOG( LOG_ERR, "received block handle has inappropriate mode\n" );
      errno = EINVAL;
      return -1;
   }
   // Return cached metadata, if present
   if (bctxt->dctxt->c_meta  &&  bctxt->dctxt->c_meta[bctxt->block]  &&  bctxt->dctxt->metalen[bctxt->block])
   {
      size_t maxcopy = ( size > bctxt->dctxt->metalen[bctxt->block] ) ? bctxt->dctxt->metalen[bctxt->block] : size;
      memcpy(meta_buf, bctxt->dctxt->c_meta[bctxt->block], maxcopy);
      return bctxt->dctxt->metalen[bctxt->block]; // always return the maximum, so the caller knows if it is missing info
   }
   // no cached metadata exists ( not necessarily a total failure )
   return 0;
}

int noop_put(BLOCK_CTXT ctxt, const void *buf, size_t size)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      return -1;
   }
   NOOP_BLOCK_CTXT bctxt = (NOOP_BLOCK_CTXT)ctxt; // Should have been passed a block context
   // validate mode
   if ( bctxt->mode != DAL_WRITE  &&  bctxt->mode != DAL_REBUILD ) {
      LOG( LOG_ERR, "received block handle has inappropriate mode\n" );
      errno = EINVAL;
      return -1;
   }
   // do nothing and assume success
   return 0;
}

ssize_t noop_get(BLOCK_CTXT ctxt, void *buf, size_t size, off_t offset)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      return -1;
   }
   NOOP_BLOCK_CTXT bctxt = (NOOP_BLOCK_CTXT)ctxt; // Should have been passed a block context
   // validate mode
   if ( bctxt->mode != DAL_READ  &&  bctxt->mode != DAL_METAREAD ) {
      LOG( LOG_ERR, "received block handle has inappropriate mode\n" );
      errno = EINVAL;
      return -1;
   }
   // validate offset
   if ( offset > bctxt->dctxt->maxdata[bctxt->block] ) {
      LOG( LOG_ERR, "offset %zd is beyond EOF at %zu\n", offset, bctxt->dctxt->maxdata[bctxt->block] );
      errno = EINVAL;
      return -1;
   }
   // Return cached data, if present
   if (bctxt->dctxt->c_data  &&  bctxt->dctxt->c_data[bctxt->block]  &&  bctxt->dctxt->datalen[bctxt->block])
   {
      size_t maxcopy = ( size > (bctxt->dctxt->maxdata[bctxt->block] - offset) ) ? (bctxt->dctxt->datalen[bctxt->block] - offset) : size;
      size_t copied = 0;
      while ( copied < maxcopy ) {
         // calculate the offset and size to pull from our buffer
         off_t suboffset = offset % bctxt->dctxt->datalen[bctxt->block]; // get an offset in terms of this buffer iteration
         size_t copysize = maxcopy - copied; // start with the total remaining bytes
         if ( copysize > bctxt->dctxt->datalen[bctxt->block] ) // reduce to our buffer size, at most
            copysize = bctxt->dctxt->datalen[bctxt->block];
         copysize -= suboffset; // exclude our starting offset
         memcpy(buf + copied, bctxt->dctxt->c_data[bctxt->block] + suboffset, copysize);
         // increment our offset and copied count to include the newly copied data
         copied += copysize;
         offset += copysize;
      }
      return maxcopy; // return however many bytes were provided
   }
   // no cached datadata exists ( not necessarily a total failure )
   return 0;
}

int noop_abort(BLOCK_CTXT ctxt)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      return -1;
   }
   NOOP_BLOCK_CTXT bctxt = (NOOP_BLOCK_CTXT)ctxt; // Should have been passed a block context
   // Free block context
   free(bctxt);
   return 0;
}

int noop_close(BLOCK_CTXT ctxt)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      return -1;
   }
   NOOP_BLOCK_CTXT bctxt = (NOOP_BLOCK_CTXT)ctxt; // Should have been passed a block context
   // Free block context
   free(bctxt);
   return 0;
}

//   -------------    NO-OP INITIALIZATION    -------------

DAL noop_dal_init(xmlNode *root, DAL_location max_loc)
{
   // allocate space for our context struct ( initialized to zero vals, by calloc )
   NOOP_DAL_CTXT dctxt = calloc( 1, sizeof(struct noop_dal_context_struct) );
   if (dctxt == NULL)
   {
      LOG( LOG_ERR, "failed to allocate a new DAL ctxt\n" );
      return NULL;
   }

   // allocate and populate a new DAL structure
   DAL ndal = malloc(sizeof(struct DAL_struct));
   if (ndal == NULL)
   {
      LOG(LOG_ERR, "failed to allocate space for a DAL_struct\n");
      free(dctxt);
      return NULL;
   }
   ndal->name = "noop";
   ndal->ctxt = (DAL_CTXT)dctxt;
   ndal->io_size = IO_SIZE;
   ndal->verify = noop_verify;
   ndal->migrate = noop_migrate;
   ndal->open = noop_open;
   ndal->set_meta = noop_set_meta;
   ndal->get_meta = noop_get_meta;
   ndal->put = noop_put;
   ndal->get = noop_get;
   ndal->abort = noop_abort;
   ndal->close = noop_close;
   ndal->del = noop_del;
   ndal->stat = noop_stat;
   ndal->cleanup = noop_cleanup;

   // loop over XML elements, checking for a read-chache source
   const char* sourceobj = NULL;
   DAL_location sourceloc = {
      .pod = -1,
      .block = -1,
      .cap = -1,
      .scatter = -1
   };
   DAL sourcedal = NULL;
   while ( root != NULL ) {
      if ( root->type == XML_ELEMENT_NODE  &&  strncmp( (char*)root->name, "DAL", 4 ) == 0 ) {
         // check for duplicate
         if ( sourcedal ) {
            LOG( LOG_ERR, "detected duplicate source DAL definitions\n" );
            break;
         }
         // try to initialize our source DAL
         sourcedal = init_dal( root, max_loc );
         if ( sourcedal == NULL ) {
            LOG( LOG_ERR, "failed to intialize source DAL\n" );
            break;
         }
      }
      else if ( root->type == XML_ELEMENT_NODE  &&  strncmp( (char*)root->name, "obj", 4 ) == 0 ) {
         // check for duplicate
         if ( sourceobj ) {
            LOG( LOG_ERR, "detected duplicate 'obj' definition\n" );
            break;
         }
         if ( root->children  &&  root->children->type == XML_TEXT_NODE ) {
            // store a ref to this string
            sourceobj = (const char*)root->children->content;
         }
      }
      else if ( root->type == XML_ELEMENT_NODE  &&  strncmp( (char*)root->name, "pod", 4 ) == 0 ) {
         // check for duplicate
         if ( sourceloc.pod >= 0 ) {
            LOG( LOG_ERR, "detected duplicate 'pod' definition\n" );
            break;
         }
         if ( root->children  &&  root->children->type == XML_TEXT_NODE  &&  root->children->content ) {
            // parse this text as a decimal number
            char* endptr = NULL;
            long int parseval = strtol( (char*)root->children->content, &endptr, 10 );
            // check for parse failure
            if ( endptr  &&  ( *endptr != '\0'  ||  *((char*)root->children->content) == '\0' ) ) {
               LOG( LOG_ERR, "failed to parse 'pod' value: \"%s\"\n", (char*)root->children->content );
               break;
            }
            // check for type overflow
            if ( parseval > INT_MAX ) {
               LOG( LOG_ERR, "'pod' value exceeds type bounds: %ld\n", parseval );
               break;
            }
            sourceloc.pod = (int)parseval;
         }
      }
      else if ( root->type == XML_ELEMENT_NODE  &&  strncmp( (char*)root->name, "cap", 4 ) == 0 ) {
         // check for duplicate
         if ( sourceloc.cap >= 0 ) {
            LOG( LOG_ERR, "detected duplicate 'cap' definition\n" );
            break;
         }
         if ( root->children  &&  root->children->type == XML_TEXT_NODE  &&  root->children->content ) {
            // parse this text as a decimal number
            char* endptr = NULL;
            long int parseval = strtol( (char*)root->children->content, &endptr, 10 );
            // check for parse failure
            if ( endptr  &&  ( *endptr != '\0'  ||  *((char*)root->children->content) == '\0' ) ) {
               LOG( LOG_ERR, "failed to parse 'cap' value: \"%s\"\n", (char*)root->children->content );
               break;
            }
            // check for type overflow
            if ( parseval > INT_MAX ) {
               LOG( LOG_ERR, "'cap' value exceeds type bounds: %ld\n", parseval );
               break;
            }
            sourceloc.cap = (int)parseval;
         }
      }
      else if ( root->type == XML_ELEMENT_NODE  &&  strncmp( (char*)root->name, "scat", 5 ) == 0 ) {
         // check for duplicate
         if ( sourceloc.scatter >= 0 ) {
            LOG( LOG_ERR, "detected duplicate 'scat' definition\n" );
            break;
         }
         if ( root->children  &&  root->children->type == XML_TEXT_NODE  &&  root->children->content ) {
            // parse this text as a decimal number
            char* endptr = NULL;
            long int parseval = strtol( (char*)root->children->content, &endptr, 10 );
            // check for parse failure
            if ( endptr  &&  ( *endptr != '\0'  ||  *((char*)root->children->content) == '\0' ) ) {
               LOG( LOG_ERR, "failed to parse 'scat' value: \"%s\"\n", (char*)root->children->content );
               break;
            }
            // check for type overflow
            if ( parseval > INT_MAX ) {
               LOG( LOG_ERR, "'scat' value exceeds type bounds: %ld\n", parseval );
               break;
            }
            sourceloc.scatter = (int)parseval;
         }
      }
      else if ( root->type == XML_ELEMENT_NODE  &&  strncmp( (char*)root->name, "width", 6 ) == 0 ) {
         // check for duplicate
         if ( sourceloc.block >= 0 ) {
            LOG( LOG_ERR, "detected duplicate 'width' definition\n" );
            break;
         }
         if ( root->children  &&  root->children->type == XML_TEXT_NODE  &&  root->children->content ) {
            // parse this text as a decimal number
            char* endptr = NULL;
            long int parseval = strtol( (char*)root->children->content, &endptr, 10 );
            // check for parse failure
            if ( endptr  &&  ( *endptr != '\0'  ||  *((char*)root->children->content) == '\0' ) ) {
               LOG( LOG_ERR, "failed to parse 'width' value: \"%s\"\n", (char*)root->children->content );
               break;
            }
            // check for type overflow
            if ( parseval > INT_MAX ) {
               LOG( LOG_ERR, "'width' value exceeds type bounds: %ld\n", parseval );
               break;
            }
            sourceloc.block = (int)parseval;
         }
      }
      else if ( root->type != XML_TEXT_NODE ) {
         LOG( LOG_ERR, "encountered unrecognized config element: \"%s\"\n", (char*)root->name );
         break;
      }
      // progress to the next element
      root = root->next;
   }
   // check for fatal error
   if ( root ) {
      if ( sourcedal ) { sourcedal->cleanup( sourcedal ); }
      noop_cleanup(ndal);
      return NULL;
   }
   // validate and ingest any cache source
   if ( sourcedal  ||  sourceobj  ||  sourceloc.pod >= 0  ||  sourceloc.block >= 0  ||  sourceloc.cap >= 0  ||  sourceloc.scatter >= 0 ) {
      // we're no in do-or-die mode for source caching
      // we have some values -- ensure we have all of them
      char fatalerror = 0;
      if ( sourcedal == NULL ) {
         LOG( LOG_ERR, "missing source cache 'DAL' definition\n" );
         fatalerror = 1;
      }
      if ( sourceobj == NULL ) {
         LOG( LOG_ERR, "missing source cache 'obj' definition\n" );
         fatalerror = 1;
      }
      if ( sourceloc.pod < 0 ) {
         LOG( LOG_ERR, "missing source cache 'pod' definition\n" );
         fatalerror = 1;
      }
      if ( sourceloc.cap < 0 ) {
         LOG( LOG_ERR, "missing source cache 'cap' definition\n" );
         fatalerror = 1;
      }
      if ( sourceloc.scatter < 0 ) {
         LOG( LOG_ERR, "missing source cache 'scat' definition\n" );
         fatalerror = 1;
      }
      if ( sourceloc.block < 0 ) {
         LOG( LOG_ERR, "missing source cache 'width' definition\n" );
         fatalerror = 1;
      }
      if ( fatalerror ) {
         if ( sourcedal ) { sourcedal->cleanup( sourcedal ); }
         noop_cleanup(ndal);
         return NULL;
      }

      // update our dal iosize to match that of the source dal
      ndal->io_size = sourcedal->io_size;

      // allocate all cache list elements
      dctxt->numblocks = sourceloc.block;
      dctxt->c_meta =  calloc( dctxt->numblocks, sizeof(char*) );
      dctxt->metalen = calloc( dctxt->numblocks, sizeof(size_t) );
      dctxt->c_data =  calloc( dctxt->numblocks, sizeof(void*) );
      dctxt->datalen = calloc( dctxt->numblocks, sizeof(size_t) );
      dctxt->maxdata = calloc( dctxt->numblocks, sizeof(size_t) );
      if ( dctxt->c_meta == NULL  ||  dctxt->metalen == NULL  ||  dctxt->c_data == NULL  ||  dctxt->datalen == NULL  ||  dctxt->maxdata == NULL ) {
         LOG( LOG_ERR, "failed to allocate all cache elements\n" );
         sourcedal->cleanup( sourcedal );
         noop_cleanup(ndal);
         return NULL;
      }

      // iterate over all blocks and populate all cached info
      for ( sourceloc.block = 0; sourceloc.block < dctxt->numblocks; sourceloc.block++ ) {
         // open a block ctxt
         BLOCK_CTXT sourceblock = sourcedal->open( sourcedal->ctxt, DAL_READ, sourceloc, sourceobj );
         if ( sourceblock == NULL ) {
            // doesn't necessarily have to be a failure ( we could consider this a block with no data / no meta info )
            // However, that seems likely to create confusion.  We'll just abort instead.
            LOG( LOG_ERR, "failed to open cache source block %d\n", sourceloc.block );
            break;
         }
         // populate meta info
         ssize_t metalen = sourcedal->get_meta( sourceblock, NULL, 0 );
         if ( metalen < 0 ) {
            LOG( LOG_ERR, "failed to identify meta length of block %d\n", sourceloc.block );
            sourcedal->close( sourceblock );
            break;
         }
         dctxt->metalen[sourceloc.block] = (size_t)metalen;
         dctxt->c_meta[sourceloc.block] = calloc( metalen, sizeof(char) );
         if ( dctxt->c_meta[sourceloc.block] == NULL ) {
            LOG( LOG_ERR, "failed to allocate meta buffer for cache source block %d of length %zd\n", sourceloc.block, metalen );
            sourcedal->close( sourceblock );
            break;
         }
         if ( sourcedal->get_meta( sourceblock, dctxt->c_meta[sourceloc.block], dctxt->metalen[sourceloc.block] ) != metalen ) {
            LOG( LOG_ERR, "inconsistent length of meta buffer for cache source block %d\n", sourceloc.block );
            sourcedal->close( sourceblock );
            break;
         }
         // populate data info
         dctxt->c_data[sourceloc.block] = malloc( sourcedal->io_size );
         void* cmp_data = malloc( sourcedal->io_size );
         if ( dctxt->c_data[sourceloc.block] == NULL  ||  cmp_data == NULL ) {
            LOG( LOG_ERR, "failed to allocate data cache buffers for source block %d\n", sourceloc.block );
            if ( dctxt->c_data[sourceloc.block] ) { free( dctxt->c_data[sourceloc.block] ); }
            if ( cmp_data ) { free( cmp_data ); }
            sourcedal->close( sourceblock );
            break;
         }
         dctxt->datalen[sourceloc.block] = sourcedal->io_size;
         ssize_t getres = sourcedal->get( sourceblock, dctxt->c_data[sourceloc.block], sourcedal->io_size, 0 );
         while ( getres > 0 ) {
            dctxt->maxdata[sourceloc.block] += getres; // add the most recent 'get' to our max data value
            getres = sourcedal->get( sourceblock, cmp_data, sourcedal->io_size, dctxt->maxdata[sourceloc.block] );
            if ( getres > 0 ) {
               // compare this new buffer against our original
               if ( memcmp( cmp_data, dctxt->c_data[sourceloc.block], getres ) ) {
                  LOG( LOG_ERR, "detected cached data buffer mismatch for block %d in buffer spanning bytes %zu to %zu\n",
                                sourceloc.block, dctxt->maxdata[sourceloc.block], dctxt->maxdata[sourceloc.block] + getres );
                  free( cmp_data );
                  sourcedal->close( sourceblock );
                  sourcedal->cleanup( sourcedal );
                  noop_cleanup(ndal);
                  return NULL;
               }
            }
         }
         free( cmp_data ); // no longer needed
         // close our handle
         if ( sourcedal->close( sourceblock ) ) {
            LOG( LOG_ERR, "close error on cache source block %d\n", sourceloc.block );
            break;
         }
         if ( getres < 0 ) {
            LOG( LOG_ERR, "read error from cache source block %d after %zu bytes read\n", sourceloc.block, dctxt->maxdata[sourceloc.block] );
            break;
         }
      }
      sourcedal->cleanup( sourcedal ); // no longer needed
      // check for error
      if ( sourceloc.block != dctxt->numblocks ) {
         noop_cleanup(ndal);
         return NULL;
      }
   }
   // NOTE -- no source cache defs is valid ( all reads will fail )
   //         only 'some', but not all source defs will result in init() error

   return ndal;
}
