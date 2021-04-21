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
#if defined(DEBUG_ALL) || defined(DEBUG_DAL)
#define DEBUG 1
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
  char *c_objID; // Cached object ID for future read ops
  char *c_meta;  // Cached metadata string for future read ops
  void *c_data;  // Cached data buffer for future read ops
} * NOOP_DAL_CTXT;

typedef struct noop_block_context_struct
{
  NOOP_DAL_CTXT dctxt; // Global DAL context
  int n_puts;          // Flag determining behavior on write ops
} * NOOP_BLOCK_CTXT;

//   -------------    NO-OP INTERNAL FUNCTIONS    -------------

/** (INTERNAL HELPER FUNCTION)
 * Calculate the number of decimal digits required to represent a given value
 * @param int value : Integer value to be represented in decimal
 * @return int : Number of decimal digits required, or -1 on a bounds error
 */
static int num_digits(int value)
{
  if (value < 0)
  {
    return -1;
  } // negative values not permitted
  if (value < 10)
  {
    return 1;
  }
  if (value < 100)
  {
    return 2;
  }
  if (value < 1000)
  {
    return 3;
  }
  if (value < 10000)
  {
    return 4;
  }
  if (value < 100000)
  {
    return 5;
  }
  // only support values up to 5 digits long
  return -1;
}

//   -------------    NO-OP IMPLEMENTATION    -------------

int noop_verify(DAL_CTXT ctxt, char fix)
{
  if (ctxt == NULL)
  {
    LOG(LOG_ERR, "received a NULL dal context!\n");
    return -1;
  }

  // Do nothing
  return 0;
}

int noop_migrate(DAL_CTXT ctxt, const char *objID, DAL_location src, DAL_location dest, char offline)
{
  if (ctxt == NULL)
  {
    LOG(LOG_ERR, "received a NULL dal context!\n");
    return -1;
  }

  // Do nothing
  return 0;
}

int noop_del(DAL_CTXT ctxt, DAL_location location, const char *objID)
{
  if (ctxt == NULL)
  {
    LOG(LOG_ERR, "received a NULL dal context!\n");
    return -1;
  }

  // Do nothing
  return 0;
}

int noop_stat(DAL_CTXT ctxt, DAL_location location, const char *objID)
{
  if (ctxt == NULL)
  {
    LOG(LOG_ERR, "received a NULL dal context!\n");
    return -1;
  }

  // Do nothing
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
  free(dctxt->c_objID);
  free(dctxt->c_meta);
  free(dctxt->c_data);
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

  // Allocate space for a new block context
  NOOP_BLOCK_CTXT bctxt = malloc(sizeof(struct noop_block_context_struct));
  if (bctxt == NULL)
  {
    return NULL;
  }

  bctxt->dctxt = dctxt;
  bctxt->n_puts = -1;

  // Clear our caches if we are about to write a new block (we will be adding
  // new data to them)
  if ((mode == DAL_WRITE || mode == DAL_REBUILD) && location.block == 0)
  {
    bctxt->n_puts = 0;
    if (dctxt->c_objID)
    {
      free(dctxt->c_objID);
    }
    if (dctxt->c_meta)
    {
      free(dctxt->c_meta);
    }
    if (dctxt->c_data)
    {
      free(dctxt->c_data);
    }
    dctxt->c_objID = strdup(objID);
  }
  // Invalidate the caches if they do not match the object we are about to read
  else if (dctxt->c_objID && strcmp(dctxt->c_objID, objID))
  {
    if (dctxt->c_objID)
    {
      free(dctxt->c_objID);
    }
    if (dctxt->c_meta)
    {
      free(dctxt->c_meta);
    }
    if (dctxt->c_data)
    {
      free(dctxt->c_data);
    }
  }

  return bctxt;
}

int noop_set_meta(BLOCK_CTXT ctxt, const char *meta_buf, size_t size)
{
  if (ctxt == NULL)
  {
    LOG(LOG_ERR, "received a NULL block context!\n");
    return -1;
  }

  NOOP_BLOCK_CTXT bctxt = (NOOP_BLOCK_CTXT)ctxt; // Should have been passed a block context

  // Cache metadata
  if (bctxt->n_puts >= 0)
  {
    bctxt->dctxt->c_meta = malloc(size);
    if (!bctxt->dctxt->c_meta)
    {
      return -1;
    }
    memcpy(bctxt->dctxt->c_meta, meta_buf, size);
  }

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

  // Return cached metadata
  if (bctxt->dctxt->c_meta)
  {
    int len = size < strlen(bctxt->dctxt->c_meta) + 1 ? size : strlen(bctxt->dctxt->c_meta) + 1;
    memcpy(meta_buf, bctxt->dctxt->c_meta, len);
    return len;
  }

  return -1;
}

int noop_put(BLOCK_CTXT ctxt, const void *buf, size_t size)
{
  if (ctxt == NULL)
  {
    LOG(LOG_ERR, "received a NULL block context!\n");
    return -1;
  }

  NOOP_BLOCK_CTXT bctxt = (NOOP_BLOCK_CTXT)ctxt; // Should have been passed a block context

  // Cache data
  if (bctxt->n_puts == 0)
  {
    bctxt->n_puts++;
    bctxt->dctxt->c_data = malloc(size);
    if (!bctxt->dctxt->c_data)
    {
      return -1;
    }
    memcpy(bctxt->dctxt->c_data, buf, size);
  }

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

  // Return cached data
  if (bctxt->dctxt->c_data)
  {
    memcpy(buf, bctxt->dctxt->c_data, size);
    return size;
  }

  return 0;
}

int noop_abort(BLOCK_CTXT ctxt)
{
  if (ctxt == NULL)
  {
    LOG(LOG_ERR, "received a NULL block context!\n");
    return -1;
  }

  // Free block context
  free(ctxt);
  return 0;
}

int noop_close(BLOCK_CTXT ctxt)
{
  if (ctxt == NULL)
  {
    LOG(LOG_ERR, "received a NULL block context!\n");
    return -1;
  }

  // Free block context
  free(ctxt);
  return 0;
}

//   -------------    NO-OP INITIALIZATION    -------------

DAL noop_dal_init(xmlNode *root, DAL_location max_loc)
{
  // first, calculate the number of digits required for pod/cap/block/scatter
  int d_pod = num_digits(max_loc.pod);
  if (d_pod < 1)
  {
    errno = EDOM;
    LOG(LOG_ERR, "detected an inappropriate value for maximum pod: %d\n", max_loc.pod);
    return NULL;
  }
  int d_cap = num_digits(max_loc.cap);
  if (d_cap < 1)
  {
    errno = EDOM;
    LOG(LOG_ERR, "detected an inappropriate value for maximum cap: %d\n", max_loc.cap);
    return NULL;
  }
  int d_block = num_digits(max_loc.block);
  if (d_block < 1)
  {
    errno = EDOM;
    LOG(LOG_ERR, "detected an inappropriate value for maximum block: %d\n", max_loc.block);
    return NULL;
  }
  int d_scatter = num_digits(max_loc.scatter);
  if (d_scatter < 1)
  {
    errno = EDOM;
    LOG(LOG_ERR, "detected an inappropriate value for maximum scatter: %d\n", max_loc.scatter);
    return NULL;
  }

  // allocate space for our context struct
  NOOP_DAL_CTXT dctxt = malloc(sizeof(struct noop_dal_context_struct));
  if (dctxt == NULL)
  {
    return NULL;
  }

  dctxt->c_objID = NULL;
  dctxt->c_meta = NULL;
  dctxt->c_data = NULL;

  // allocate and populate a new DAL structure
  DAL ndal = malloc(sizeof(struct DAL_struct));
  if (ndal == NULL)
  {
    LOG(LOG_ERR, "failed to allocate space for a DAL_struct\n");
    free(dctxt);
    return NULL;
  }
  ndal->name = "no-op";
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
  return ndal;
}
