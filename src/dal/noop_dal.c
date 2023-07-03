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
#include "general_include/crcs.c"

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
   meta_info   minfo;  // meta info values to be returned to the caller
   void*      c_data;  // cached data buffer, representing each 'complete' I/O
   void* c_data_tail;  // cached data buffer, representing a trailing 'partial' I/O ( if any )
   size_t  tail_size;  // size of the c_data_tail buffer
} * NOOP_DAL_CTXT;

typedef struct noop_block_context_struct
{
   NOOP_DAL_CTXT dctxt; // Global DAL context
   DAL_MODE       mode; // Mode of this block ctxt
} * NOOP_BLOCK_CTXT;

//   -------------    NO-OP INTERNAL FUNCTIONS    -------------


/**
 * (INTERNAL HELPER FUNC)
 * Parse the content of an xmlNode to populate an int value
 * @param int* target : Reference to the value to populate
 * @param xmlNode* node : Node to be parsed
 * @return int : Zero on success, -1 on error
 */
int parse_int_node( int* target, xmlNode* node ) {
   // check for an included value
   if ( node->children != NULL  &&
        node->children->type == XML_TEXT_NODE  &&
        node->children->content != NULL ) {
      char* valuestr = (char*)node->children->content;
      char* endptr = NULL;
      unsigned long long parsevalue = strtoull( valuestr, &(endptr), 10 );
      // check for any trailing unit specification
      if ( *endptr != '\0' ) {
         LOG( LOG_ERR, "encountered unrecognized trailing character in \"%s\" value: \"%c\"", (char*)node->name, *endptr );
         return -1;
      }
      if ( parsevalue >= INT_MAX ) {  // check for possible overflow
         LOG( LOG_ERR, "specified \"%s\" value is too large to store: \"%s\"\n", (char*)node->name, valuestr );
         return -1;
      }
      // actually store the value
      *target = parsevalue;
      return 0;
   }
   LOG( LOG_ERR, "failed to identify a value string within the \"%s\" definition\n", (char*)node->name );
   return -1;
}

/**
 * (INTERNAL HELPER FUNC)
 * Parse the content of an xmlNode to populate a size value
 * @param size_t* target : Reference to the value to populate
 * @param xmlNode* node : Node to be parsed
 * @return int : Zero on success, -1 on error
 */
int parse_size_node( ssize_t* target, xmlNode* node ) {
   // check for unexpected node format
   if ( node->children == NULL  ||  node->children->type != XML_TEXT_NODE ) {
      LOG( LOG_ERR, "unexpected format of size node: \"%s\"\n", (char*)node->name );
      return -1;
   }
   // check for an included value
   if ( node->children->content != NULL ) {
      char* valuestr = (char*)node->children->content;
      size_t unitmult = 1;
      char* endptr = NULL;
      unsigned long long parsevalue = strtoull( valuestr, &(endptr), 10 );
      // check for any trailing unit specification
      if ( *endptr != '\0' ) {
         if ( *endptr == 'K' ) { unitmult = 1024ULL; }
         else if ( *endptr == 'M' ) { unitmult = 1048576ULL; }
         else if ( *endptr == 'G' ) { unitmult = 1073741824ULL; }
         else if ( *endptr == 'T' ) { unitmult = 1099511627776ULL; }
         else if ( *endptr == 'P' ) { unitmult = 1125899906842624ULL; }
         else {
            LOG( LOG_ERR, "encountered unrecognized character in \"%s\" value: \"%c\"", (char*)node->name, *endptr );
            return -1;
         }
         // check for unacceptable trailing characters
         endptr++;
         if ( *endptr != '\0' ) {
            LOG( LOG_ERR, "encountered unrecognized trailing character in \"%s\" value: \"%c\"", (char*)node->name, *endptr );
            return -1;
         }
      }
      if ( (parsevalue * unitmult) >= SSIZE_MAX ) {  // check for possible overflow
         LOG( LOG_ERR, "specified \"%s\" value is too large to store: \"%s\"\n", (char*)node->name, valuestr );
         return -1;
      }
      // actually store the value
      LOG( LOG_INFO, "detected value of %llu with unit of %zu for \"%s\" node\n", parsevalue, unitmult, (char*)node->name );
      *target = (parsevalue * unitmult);
      return 0;
   }
   // allow empty string to indicate zero value
   *target = 0;
   return 0;
}


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
   if ( dctxt->c_data ) { free( dctxt->c_data ); }
   if ( dctxt->c_data_tail ) { free( dctxt->c_data_tail ); }
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
   NOOP_BLOCK_CTXT bctxt = malloc(sizeof(struct noop_block_context_struct));
   if (bctxt == NULL)
   {
      LOG( LOG_ERR, "failed to allocate a new block ctxt\n" );
      return NULL;
   }
   // populate values and global ctxt reference
   bctxt->dctxt = dctxt;
   bctxt->mode = mode;
   return bctxt;
}

int noop_set_meta(BLOCK_CTXT ctxt, const meta_info* source)
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

int noop_get_meta(BLOCK_CTXT ctxt, meta_info* dest )
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
   // Return cached metadata
   memcpy(dest, &(bctxt->dctxt->minfo), sizeof(struct meta_info_struct));
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
   // Return cached data, if present
   if (bctxt->dctxt->c_data  &&  bctxt->dctxt->c_data[bctxt->block]  &&  bctxt->dctxt->datalen[bctxt->block])
   {
      // validate offset
      if ( offset > bctxt->dctxt->minfo.blocksz ) {
         LOG( LOG_ERR, "offset %zd is beyond EOF at %zu\n", offset, bctxt->dctxt->minfo.blocksz );
         errno = EINVAL;
         return -1;
      }

      // copy from our primary data buff first
      size_t maxcopy = ( size > (bctxt->dctxt->minfo.blocksz - offset) ) ? (bctxt->dctxt->minfo.blocksz - offset) : size;
      size_t copied = 0;
      while ( copied < maxcopy  &&  offset < (bctxt->dctxt->minfo.blocksz - bctxt->dctxt->tail_size) ) {
         // calculate the offset and size to pull from our buffer
         off_t suboffset = offset % bctxt->dctxt->minfo.versz; // get an offset in terms of this buffer iteration
         size_t copysize = maxcopy - copied; // start with the total remaining bytes
         if ( copysize > bctxt->dctxt->minfo.versz ) // reduce to our buffer size, at most
            copysize = bctxt->dctxt->minfo.versz;
         copysize -= suboffset; // exclude our starting offset
         memcpy(buf + copied, bctxt->dctxt->c_data + suboffset, copysize);
         // increment our offset and copied count to include the newly copied data
         copied += copysize;
         offset += copysize;
      }
      // fill any remaining from our tail buffer
      if ( copied < maxcopy ) {
         off_t suboffset = offset % bctxt->dctxt->minfo.versz; // get an offset in terms of this buffer iteration
         size_t copysize = maxcopy - copied; // start with the total remaining bytes
         if ( copysize > bctxt->dctxt->tail_size ) // reduce to our buffer size, at most
            copysize = bctxt->dctxt->tail_size;
         copysize -= suboffset; // exclude our starting offset
         memcpy(buf + copied, bctxt->dctxt->c_data_tail + suboffset, copysize);
         copied += copysize;
      }
      return copied; // return however many bytes were provided
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
   // initialize values to indicate absence
   dctxt.minfo.N = -1;
   dctxt.minfo.E = -1;
   // initialize versz to match io size
   dctxt.minfo.versz = IO_SIZE;

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
   while ( root != NULL ) {
      // validate + parse this node
      if ( root->type != XML_ELEMENT_NODE ) {
         // skip comment nodes
         if ( root->type == XML_COMMENT_NODE ) { continue; }
         // skip text nodes ( could occur if we are passed an empty DAL tag body )
         if ( root->type == XML_TEXT_NODE ) { continue; }
         LOG( LOG_ERR, "encountered unknown node within a NoOp DAL definition\n" );
         break;
      }
      if ( strncmp( (char*)root->name, "N", 2 ) == 0 ) {
         if( parse_int_node( &(dctxt.minfo.N), root ) ) {
            LOG( LOG_ERR, "failed to parse 'N' value\n" );
            break;
         }
      }
      else if ( strncmp( (char*)root->name, "E", 2 ) == 0 ) {
         if( parse_int_node( &(dctxt.minfo.E), root ) ) {
            LOG( LOG_ERR, "failed to parse 'E' value\n" );
            break;
         }
      }
      else if ( strncmp( (char*)root->name, "PSZ", 4 ) == 0 ) {
         if( parse_size_node( &(dctxt.minfo.partsz), root ) ) {
            LOG( LOG_ERR, "failed to parse 'PSZ' value\n" );
            break;
         }
      }
      else if ( strncmp( (char*)root->name, "max_size", 9 ) == 0 ) {
         if( parse_size_node( &(dctxt.minfo.totsz), root ) ) {
            LOG( LOG_ERR, "failed to parse 'max_size' value\n" );
            break;
         }
      }
      else {
         LOG( LOG_ERR, "encountered an unrecognized \"%s\" node within a NoOp DAL definition\n", (char*)subnode->name );
         break;
      }
      // progress to the next element
      root = root->next;
   }
   // check for fatal error
   if ( root ) {
      noop_cleanup(ndal);
      return NULL;
   }
   // validate and ingest any cache source
   if ( dctxt.minfo.N != -1  ||  dctxt.minfo.E != -1  ||  dctxt.minfo.partsz > 0  ||  dctxt.minfo.totsz > 0 ) {
      // we're no in do-or-die mode for source caching
      // we have some values -- ensure we have all of them
      char fatalerror = 0;
      if ( dctxt.minfo.N == -1 ) {
         LOG( LOG_ERR, "missing source cache 'N' definition\n" );
         fatalerror = 1;
      }
      if ( dctxt.minfo.E == -1 ) {
         LOG( LOG_ERR, "missing source cache 'E' definition\n" );
         fatalerror = 1;
      }
      if ( dctxt.minfo.partsz <= 0 ) {
         LOG( LOG_ERR, "missing source cache 'PSZ' definition\n" );
         fatalerror = 1;
      }
      if ( dctxt.minfo.totsz <= 0 ) {
         LOG( LOG_ERR, "missing source cache 'max_size' definition\n" );
         fatalerror = 1;
      }
      if ( fatalerror ) {
         noop_cleanup(ndal);
         return NULL;
      }

      // allocate and populate our primary data buffer
      dctxt->c_data =  calloc( 1, dctxt->versz );
      if ( dctxt->c_data == NULL ) {
         LOG( LOG_ERR, "failed to allocate cached data buffer\n" );
         noop_cleanup(ndal);
         return NULL;
      }
      size_t datasize = dctxt->versz - sizeof(uint32_t);
      uint32_t crcval = crc32_ieee_base(CRC_SEED, dctxt->c_data, datasize);
      *(uint32_t*)( dctxt->c_data + datasize ) = crcval;

      // calculate our blocksize
      size_t totalwritten = dctxt->minfo.totsz; // note the total volume of data to be contained in this object
      totalwritten += totalwritten % (dctxt->minfo.partsz * dctxt->minfo.N); // account for erasure stripe alignment
      size_t iocnt = totalwritten / (datasize * dctxt->minfo.N); // calculate the number of buffers required to store this info
      dctxt->minfo.blocksz = iocnt * dctxt->minfo.versz; // record blocksz based on number of complete I/O buffers
      uint32_t tail_crcval = 0;
      if ( totalwritten % (datasize * dctxt->minfo.N) ) { // account for misalignment
         // populate our 'tail' data buffer info
         size_t remainder = totalwritten % (datasize * dctxt->minfo.N);
         if ( remainder % dctxt->minfo.N ) { // sanity check
            LOG( LOG_ERR, "Remainder value of %zu is not cleanly divisible by N=%d ( tell 'gransom' that he doesn't understand math )\n",
                          remainder, dctxt->minfo.N );
            noop_cleanup(ndal);
            return NULL;
         }
         remainder /= dctxt->minfo.N;
         dctxt->tail_size = remainder + sizeof(uint32_t);
         dctxt->minfo.blocksz += dctxt->tail_size;
         dctxt->c_data_tail = calloc( 1, dctxt->tail_size );
         if ( dctxt->c_data_tail == NULL ) {
            LOG( LOG_ERR, "Failed to allocate c_data_tail buffer\n" );
            noop_cleanup(ndal);
            return NULL;
         }
         tail_crcval = crc32_ieee_base(CRC_SEED, dctxt->c_data_tail, remainder);
         *(uint32_t*)( dctxt->c_data_tail + remainder ) = tail_crcval;
      }

      // calculate our crcsum
      size_t ioindex = 0;
      for ( ; ioindex < iocnt; ioindex++ ) {
         dctxt->minfo.crcsum += crcval;
      }
      dctxt->minfo.crcsum += tail_crcval;
   }
   // NOTE -- no source cache defs is valid ( all reads will fail )
   //         only 'some', but not all source defs will result in init() error

   return ndal;
}
