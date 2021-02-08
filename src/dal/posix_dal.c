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
#define LOG_PREFIX "posix_dal"
#include "logging/logging.h"

#include "dal.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

//   -------------    POSIX DEFINITIONS    -------------

// NOTE -- make sure to adjust SFX_PADDING if changing any SFX strings!
#define SFX_PADDING 14         // number of extra chars required to fit any suffix combo
#define WRITE_SFX ".partial"   // 8 characters
#define REBUILD_SFX ".rebuild" // 8 characters
#define META_SFX ".meta"       // 5 characters (in ADDITION to other suffixes!)

#define IO_SIZE 1048576 // Preferred I/O Size

//   -------------    POSIX CONTEXT    -------------

typedef struct posix_block_context_struct
{
   int fd;         // File Descriptor (if open)
   int mfd;        // Meta File Descriptor (if open)
   int sfd;        // Secure Root File Descriptor (if open)
   char *filepath; // File Path (if open)
   int filelen;    // Length of filepath string
   off_t offset;   // Current file offset (only relevant when reading)
   DAL_MODE mode;  // Mode in which this block was opened
} * POSIX_BLOCK_CTXT;

typedef struct posix_dal_context_struct
{
   char *dirtmp;         // Template string for generating directory paths
   int tmplen;           // Length of the dirtmp string
   DAL_location max_loc; // Maximum pod/cap/block/scatter values
   int dirpad;           // Number of chars by which dirtmp may expand via substitutions
   int sec_root;         // Handle of secure root directory
} * POSIX_DAL_CTXT;

//   -------------    POSIX INTERNAL FUNCTIONS    -------------

/** (INTERNAL HELPER FUNCTION)
 * Simple check of limits to ensure we don't overrun allocated strings
 * @param DAL_location loc : Location to be checked
 * @param DAL_location* max_loc : Reference to the maximum acceptable location value
 * @return int : Zero if the location is acceptable, -1 otherwise
 */
int check_loc_limits(DAL_location loc, const DAL_location *max_loc)
{
   //
   if (loc.pod > max_loc->pod)
   {
      LOG(LOG_ERR, "pod value of %d exceeds limit of %d\n", loc.pod, max_loc->pod);
      return -1;
   }
   if (loc.cap > max_loc->cap)
   {
      LOG(LOG_ERR, "cap value of %d exceeds limit of %d\n", loc.cap, max_loc->cap);
      return -1;
   }
   if (loc.block > max_loc->block)
   {
      LOG(LOG_ERR, "block value of %d exceeds limit of %d\n", loc.block, max_loc->block);
      return -1;
   }
   if (loc.scatter > max_loc->scatter)
   {
      LOG(LOG_ERR, "scatter value of %d exceeds limit of %d\n", loc.scatter, max_loc->scatter);
      return -1;
   }
   return 0;
}

/** (INTERNAL HELPER FUNCTION)
 * Calculate the number of decimal digits required to represent a given value
 * @param int value : Integer value to be represented in decimal
 * @return int : Number of decimal digits required, or -1 on a bounds error
 */
int num_digits(int value)
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

/** (INTERNAL HELPER FUNCTION)
 * Perform necessary string substitutions/calculations to populate all values in a new POSIX_BLOCK_CTXT
 * @param POSIX_DAL_CTXT dctxt : Context reference of the current POSIX DAL
 * @param POSIX_BLOCK_CTXT bctxt : Block context to be populated
 * @param DAL_location loc : Location of the object to be referenced by bctxt
 * @param const char* objID : Object ID to be referenced by bctxt
 * @return int : Zero on success, -1 on failure
 */
int expand_dir_template(POSIX_DAL_CTXT dctxt, POSIX_BLOCK_CTXT bctxt, DAL_location loc, const char *objID)
{
   // check that our DAL_location is within bounds
   if (check_loc_limits(loc, &(dctxt->max_loc)) != 0)
   {
      errno = EDOM;
      return -1;
   }

   //
   bctxt->sfd = dctxt->sec_root;

   // allocate string to hold the dirpath
   // NOTE -- allocation size is an estimate, based on the above pod/block/cap/scat limits
   bctxt->filepath = malloc(sizeof(char) * (dctxt->tmplen + dctxt->dirpad + strlen(objID) + SFX_PADDING + 1));

   // parse through the directory template string, populating filepath as we go
   const char *parse = dctxt->dirtmp;
   char *fill = bctxt->filepath;
   char escp = 0;
   while (*parse != '\0')
   {

      switch (*parse)
      {

      case '\\': // check for escape character '\'
         if (escp)
         { // only add literal '\' if already escaped
            *fill = *parse;
            fill++;
            escp = 0;
         }
         else
         {
            escp = 1;
         } // escape the next character
         break;

      case '{': // check for start of a substitution
         if (escp)
         { // only add literal '{' if escaped
            *fill = '{';
            fill++;
            escp = 0;
         }
         else
         {
            parse++;
            int fillval = 0;
            if (*parse == 'p')
            {
               fillval = loc.pod;
            }
            else if (*parse == 'b')
            {
               fillval = loc.block;
            }
            else if (*parse == 'c')
            {
               fillval = loc.cap;
            }
            else if (*parse == 's')
            {
               fillval = loc.scatter;
            }
            else
            {
               LOG(LOG_WARNING, "dir_template contains an unescaped '{' followed by '%c', rather than an expected 'p'/'b'/'c'/'s'\n", *parse);
               *fill = '{';
               fill++;
               continue;
            }
            // ensure the '}' (end of substitution character) follows
            if (*(parse + 1) != '}')
            {
               LOG(LOG_WARNING, "dir_template contains an '{%c' substitution sequence with no closing '}' character\n", *parse);
               *fill = '{';
               fill++;
               continue;
            }
            // print the numeric value into the fill string
            fillval = snprintf(fill, 5, "%d", fillval);
            if (fillval <= 0)
            {
               // if snprintf failed for some reason, we can't recover
               LOG(LOG_ERR, "snprintf failed when attempting dir_template substitution!\n");
               free(bctxt->filepath);
               bctxt->filepath = NULL;
               return -1;
            }
            fill += fillval; // update fill pointer to refernce the new end of the string
            parse++;         // skip over the '}' character that we have already verified
         }
         break;

      default:
         if (escp)
         {
            LOG(LOG_WARNING, "invalid '\\%c' escape encountered in the dir_template string\n", *parse);
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
   while (*parse != '\0')
   {

      switch (*parse)
      {

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
   // use pointer arithmetic to determine length of path
   bctxt->filelen = fill - bctxt->filepath;
   return 0;
}

/** (INTERNAL HELPER FUNCTION)
 * Delete various components of a given object, identified by it's block context.
 * @param POSIX_BLOCK_CTXT bctxt : Context of the object to be deleted
 * @param char components : Identifies which components of the object to delete
 *                          0 - working data/meta files only
 *                          1 - ALL data/meta files
 * @return int : Zero on success, -1 on failure
 */
int block_delete(POSIX_BLOCK_CTXT bctxt, char components)
{
   char *working_suffix = WRITE_SFX;
   if (bctxt->mode == DAL_REBUILD)
   {
      working_suffix = REBUILD_SFX;
   }
   // append the meta suffix and check for success
   char *res = strncat(bctxt->filepath + bctxt->filelen, META_SFX, SFX_PADDING);
   if (res != (bctxt->filepath + bctxt->filelen))
   {
      LOG(LOG_ERR, "failed to append meta suffix \"%s\" to file path \"%s\"!\n", META_SFX, bctxt->filepath);
      errno = EBADF;
      return -1;
   }

   int metalen = strlen(META_SFX);

   // append the working suffix and check for success
   res = strncat(bctxt->filepath + bctxt->filelen + metalen, working_suffix, SFX_PADDING - metalen);
   if (res != (bctxt->filepath + bctxt->filelen + metalen))
   {
      LOG(LOG_ERR, "failed to append working suffix \"%s\" to file path \"%s\"!\n", working_suffix, bctxt->filepath);
      errno = EBADF;
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1;
   }

   // unlink any in-progress meta file (only failure with ENOENT is acceptable)
   if (unlinkat(bctxt->sfd, bctxt->filepath, 0) != 0 && errno != ENOENT)
   {
      LOG(LOG_ERR, "failed to unlink \"%s\" (%s)\n", bctxt->filepath, strerror(errno));
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1;
   }

   // trim the working suffix off
   *(bctxt->filepath + bctxt->filelen + metalen) = '\0';

   if (components)
   {
      // unlink any meta file (only failure with ENOENT is acceptable)
      if (unlinkat(bctxt->sfd, bctxt->filepath, 0) != 0 && errno != ENOENT)
      {
         LOG(LOG_ERR, "failed to unlink \"%s\" (%s)\n", bctxt->filepath, strerror(errno));
         *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
         return -1;
      }
   }

   // trim the meta suffix off and attach a working suffix in its place
   *(bctxt->filepath + bctxt->filelen) = '\0';
   res = strncat(bctxt->filepath + bctxt->filelen, working_suffix, SFX_PADDING - metalen);
   if (res != (bctxt->filepath + bctxt->filelen))
   {
      LOG(LOG_ERR, "failed to append working suffix \"%s\" to file path \"%s\"!\n", working_suffix, bctxt->filepath);
      errno = EBADF;
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1;
   }

   // unlink any in-progress data file (only failure with ENOENT is acceptable)
   if (unlinkat(bctxt->sfd, bctxt->filepath, 0) != 0 && errno != ENOENT)
   {
      LOG(LOG_ERR, "failed to unlink \"%s\" (%s)\n", bctxt->filepath, strerror(errno));
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
      return -1;
   }

   *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains

   if (components)
   {
      // unlink any data file (only failure with ENOENT is acceptable, as this implies a non-existent file)
      if (unlinkat(bctxt->sfd, bctxt->filepath, 0) != 0 && errno != ENOENT)
      {
         LOG(LOG_ERR, "failed to unlink \"%s\" (%s)\n", bctxt->filepath, strerror(errno));
         *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
         return -1;
      }
   }

   return 0;
}

/** (INTERNAL HELPER FUNCTION)
 * Forms a path to a source location relative to a destination location.
 * @param char* oldpath : Path to our source location (relative to a source root)
 * @param char* newpath : Path to our destination location (relative to the same source root as oldpath)
 * @return char* : Path to oldpath's location relative to newpath's location. NULL on failure
 */
char *convert_relative(char *oldpath, char *newpath)
{
   // check that both paths exist
   if (oldpath == NULL || newpath == NULL)
   {
      return NULL;
   }

   // parse through our destination path, counting the number of directories
   int nBack = 0;
   if (*newpath == '.' && *(newpath + 1) == '/')
   {
      newpath += 2;
   }
   while (*newpath != '\0')
   {
      if (*newpath == '/' && *(newpath + 1) != '/')
      {
         nBack++;
      }
      newpath++;
   }

   // allocate space for our return string
   char *result = malloc(sizeof(char) * (3 * nBack + strlen(oldpath) + 1));
   if (result == NULL)
   {
      return NULL;
   }
   *result = '\0';

   // form path that traverses from destination location to secure root
   for (int i = 0; i < nBack; i++)
   {
      if (strcat(result, "../") != result)
      {
         LOG(LOG_ERR, "failed to append \"../\" to source path!\n");
         errno = EBADF;
         free(result);
         return NULL;
      }
      result += 3;
   }

   // append source location to path
   if (strcat(result, oldpath) != result)
   {
      LOG(LOG_ERR, "failed to append \"../\" to source path!\n");
      errno = EBADF;
      free(result);
      return NULL;
   }

   return result - 3 * nBack;
}

// forward-declarations to allow these functions to be used in manual_migrate
int posix_del(DAL_CTXT ctxt, DAL_location location, const char *objID);

BLOCK_CTXT posix_open(DAL_CTXT ctxt, DAL_MODE mode, DAL_location location, const char *objID);

int posix_set_meta(BLOCK_CTXT ctxt, const char *meta_buf, size_t size);

ssize_t posix_get_meta(BLOCK_CTXT ctxt, char *meta_buf, size_t size);

int posix_put(BLOCK_CTXT ctxt, const void *buf, size_t size);

ssize_t posix_get(BLOCK_CTXT ctxt, void *buf, size_t size, off_t offset);

int posix_abort(BLOCK_CTXT ctxt);

int posix_close(BLOCK_CTXT ctxt);

/** (INTERNAL HELPER FUNCTION)
 * Attempt to manually migrate an object from one location to another using put/get/set_meta/get_meta dal functions..
 * @param POSIX_DAL_CTXT dctxt : Context reference of the current POSIX DAL
 * @param const char* objID : Object ID reference of object to be migraded
 * @param DAL_location src : Source location of the object to be migrated
 * @param DAL_location dest : Destination location of the object to be migrated
 * @param const char* objID : Object ID to be referenced by bctxt
 * @return int : Zero on success, -1 on failure
 */
int manual_migrate(POSIX_DAL_CTXT dctxt, const char *objID, DAL_location src, DAL_location dest)
{
   // allocate buffers to transfer between locations
   void *data_buf = malloc(IO_SIZE);
   if (data_buf == NULL)
   {
      return -1;
   }
   char *meta_buf = malloc(IO_SIZE);
   if (meta_buf == NULL)
   {
      free(data_buf);
      return -1;
   }

   // open both locations
   POSIX_BLOCK_CTXT src_ctxt = (POSIX_BLOCK_CTXT)posix_open((DAL_CTXT)dctxt, DAL_READ, src, objID);
   if (src_ctxt == NULL)
   {
      free(data_buf);
      free(meta_buf);
      return -1;
   }
   POSIX_BLOCK_CTXT dest_ctxt = (POSIX_BLOCK_CTXT)posix_open((DAL_CTXT)dctxt, DAL_WRITE, dest, objID);
   if (dest_ctxt == NULL)
   {
      posix_abort((BLOCK_CTXT)src_ctxt);
      free(data_buf);
      free(meta_buf);
      return -1;
   }

   // move data file from source location to destination location
   ssize_t res;
   int off = 0;
   do
   {
      res = posix_get((BLOCK_CTXT)src_ctxt, data_buf, IO_SIZE, off);
      if (res < 0)
      {
         posix_abort((BLOCK_CTXT)src_ctxt);
         posix_abort((BLOCK_CTXT)dest_ctxt);
         free(data_buf);
         free(meta_buf);
         return -1;
      }
      off = src_ctxt->offset;
      if (posix_put((BLOCK_CTXT)dest_ctxt, data_buf, res))
      {
         posix_abort((BLOCK_CTXT)src_ctxt);
         posix_abort((BLOCK_CTXT)dest_ctxt);
         free(data_buf);
         free(meta_buf);
         return -1;
      }
   } while (res > 0);

   // move meta file from source location to destination location
   res = posix_get_meta((BLOCK_CTXT)src_ctxt, meta_buf, IO_SIZE);
   if (res < 0)
   {
      posix_abort((BLOCK_CTXT)src_ctxt);
      posix_abort((BLOCK_CTXT)dest_ctxt);
      free(data_buf);
      free(meta_buf);
      return -1;
   }
   if (posix_set_meta((BLOCK_CTXT)dest_ctxt, meta_buf, res))
   {
      posix_abort((BLOCK_CTXT)src_ctxt);
      posix_abort((BLOCK_CTXT)dest_ctxt);
      free(data_buf);
      free(meta_buf);
      return -1;
   }

   free(data_buf);
   free(meta_buf);

   // close both locations
   if (posix_close((BLOCK_CTXT)src_ctxt))
   {
      posix_abort((BLOCK_CTXT)dest_ctxt);
      return -1;
   }
   if (posix_close((BLOCK_CTXT)dest_ctxt))
   {
      return -1;
   }

   // delete old file
   if (posix_del((DAL_CTXT)dctxt, src, objID))
   {
      return 1;
   }

   return 0;
}

//   -------------    POSIX IMPLEMENTATION    -------------

int posix_verify(DAL_CTXT ctxt, char fix)
{
   errno = ENOSYS;
   return -1; // TODO -- actually write this
}

int posix_migrate(DAL_CTXT ctxt, const char *objID, DAL_location src, DAL_location dest, char offline)
{
   // fail if only the block is different
   if (src.pod == dest.pod && src.cap == dest.cap && src.scatter == dest.scatter)
   {
      LOG(LOG_ERR, "received identical locations!\n");
      return -1;
   }

   POSIX_DAL_CTXT dctxt = (POSIX_DAL_CTXT)ctxt; // should have been passed a posix context

   POSIX_BLOCK_CTXT srcctxt = malloc(sizeof(struct posix_block_context_struct));
   if (srcctxt == NULL)
   {
      return -1; // malloc will set errno
   }
   POSIX_BLOCK_CTXT destctxt = malloc(sizeof(struct posix_block_context_struct));
   if (destctxt == NULL)
   {
      free(srcctxt);
      return -1; // malloc will set errno
   }

   // popultate the full file path for this object
   if (expand_dir_template(dctxt, srcctxt, src, objID))
   {
      free(srcctxt);
      free(destctxt);
      return -1;
   }
   if (expand_dir_template(dctxt, destctxt, dest, objID))
   {
      free(srcctxt);
      free(destctxt);
      return -1;
   }

   // permanently move object from old location to new location (link to dest loc and unlink src loc)
   if (offline)
   {
      // append the meta suffix to the source and check for success
      char *res = strncat(srcctxt->filepath + srcctxt->filelen, META_SFX, SFX_PADDING);
      if (res != (srcctxt->filepath + srcctxt->filelen))
      {
         LOG(LOG_ERR, "failed to append meta suffix \"%s\" to source file path!\n", META_SFX);
         errno = EBADF;
         free(srcctxt);
         free(destctxt);
         return -1;
      }

      // duplicate the source meta path and check for success
      char *src_meta_path = strdup(srcctxt->filepath);
      if (src_meta_path == NULL)
      {
         LOG(LOG_ERR, "failed to allocate space for a new source meta string! (%s)\n", strerror(errno));
         *(srcctxt->filepath + srcctxt->filelen) = '\0'; // make sure no suffix remains
         free(srcctxt);
         free(destctxt);
         return -1;
      }
      *(srcctxt->filepath + srcctxt->filelen) = '\0'; // make sure no suffix remains

      // append the meta suffix to the destination and check for success
      res = strncat(destctxt->filepath + destctxt->filelen, META_SFX, SFX_PADDING);
      if (res != (destctxt->filepath + destctxt->filelen))
      {
         LOG(LOG_ERR, "failed to append meta suffix \"%s\" to destination file path!\n", META_SFX);
         errno = EBADF;
         free(srcctxt);
         free(destctxt);
         free(src_meta_path);
         return -1;
      }

      // duplicate the destination meta path and check for success
      char *dest_meta_path = strdup(destctxt->filepath);
      if (dest_meta_path == NULL)
      {
         LOG(LOG_ERR, "failed to allocate space for a new destination meta string! (%s)\n", strerror(errno));
         *(destctxt->filepath + destctxt->filelen) = '\0'; // make sure no suffix remains
         free(srcctxt);
         free(destctxt);
         free(src_meta_path);
         return -1;
      }
      *(destctxt->filepath + destctxt->filelen) = '\0'; // make sure no suffix remains

      // attempt to link data and check for success
      if (linkat(dctxt->sec_root, srcctxt->filepath, dctxt->sec_root, destctxt->filepath, 0))
      {
         LOG(LOG_ERR, "failed to link data file \"%s\" to \"%s\" (%s)\n", srcctxt->filepath, destctxt->filepath, strerror(errno));
         free(srcctxt);
         free(destctxt);
         free(src_meta_path);
         free(dest_meta_path);
         return manual_migrate(dctxt, objID, src, dest);
      }

      int ret = 0;
      // attempt to link meta and check for success
      if (linkat(dctxt->sec_root, src_meta_path, dctxt->sec_root, dest_meta_path, 0))
      {
         LOG(LOG_ERR, "failed to link meta file \"%s\" to \"%s\" (%s)\n", src_meta_path, dest_meta_path, strerror(errno));
         if (unlinkat(dctxt->sec_root, destctxt->filepath, 0))
         {
            ret = -2;
         }
         else
         {
            ret = manual_migrate(dctxt, objID, src, dest);
         }
         free(srcctxt);
         free(destctxt);
         free(src_meta_path);
         free(dest_meta_path);
         return ret;
      }

      // attempt to unlink data and check for success
      if (unlinkat(dctxt->sec_root, srcctxt->filepath, 0))
      {
         LOG(LOG_ERR, "failed to unlink source data file \"%s\" (%s)\n", srcctxt->filepath, strerror(errno));
         ret = 1;
      }

      // attempt to unlink meta and check for success
      if (unlinkat(dctxt->sec_root, src_meta_path, 0))
      {
         LOG(LOG_ERR, "failed to unlink source meta file \"%s\" to (%s)\n", src_meta_path, strerror(errno));
         ret = 1;
      }

      free(src_meta_path);
      free(dest_meta_path);
      free(srcctxt);
      free(destctxt);
      return ret;
   }
   // allow object to be accessed from both locations (symlink dest loc to src loc)
   else
   {
      char *oldpath = convert_relative(srcctxt->filepath, destctxt->filepath);
      if (oldpath == NULL)
      {
         LOG(LOG_ERR, "failed to create relative data path for symlink\n");
         free(srcctxt);
         free(destctxt);
         return -1;
      }

      // attempt to symlink data and check for success
      if (symlinkat(oldpath, dctxt->sec_root, destctxt->filepath))
      {
         LOG(LOG_ERR, "failed to create data symlink\n");
         free(srcctxt);
         free(destctxt);
         free(oldpath);
         return -1;
      }

      // append the meta suffix and check for success
      char *res = strncat(srcctxt->filepath + srcctxt->filelen, META_SFX, SFX_PADDING);
      if (res != (srcctxt->filepath + srcctxt->filelen))
      {
         LOG(LOG_ERR, "failed to append meta suffix \"%s\" to source file path!\n", META_SFX);
         errno = EBADF;
         free(srcctxt);
         free(destctxt);
         free(oldpath);
         return -1;
      }
      res = strncat(destctxt->filepath + destctxt->filelen, META_SFX, SFX_PADDING);
      if (res != (destctxt->filepath + destctxt->filelen))
      {
         LOG(LOG_ERR, "failed to append meta suffix \"%s\" to destination file path!\n", META_SFX);
         errno = EBADF;
         *(srcctxt->filepath + srcctxt->filelen) = '\0'; // make sure no suffix remains
         free(srcctxt);
         free(destctxt);
         free(oldpath);
         return -1;
      }

      oldpath = convert_relative(srcctxt->filepath, destctxt->filepath);
      if (oldpath == NULL)
      {
         LOG(LOG_ERR, "failed to create relative meta path for symlink\n");
         free(srcctxt);
         free(destctxt);
         return -1;
      }

      // attempt to symlink meta and check for success
      if (symlinkat(oldpath, dctxt->sec_root, destctxt->filepath))
      {
         LOG(LOG_ERR, "failed to create meta symlink\n");
         *(srcctxt->filepath + srcctxt->filelen) = '\0';   // make sure no suffix remains
         *(destctxt->filepath + destctxt->filelen) = '\0'; // make sure no suffix remains
         free(srcctxt);
         free(destctxt);
         free(oldpath);
         return -1;
      }

      *(srcctxt->filepath + srcctxt->filelen) = '\0';   // make sure no suffix remains
      *(destctxt->filepath + destctxt->filelen) = '\0'; // make sure no suffix remains
      free(oldpath);
   }

   free(srcctxt);
   free(destctxt);
   return 0;
}

int posix_del(DAL_CTXT ctxt, DAL_location location, const char *objID)
{
   POSIX_DAL_CTXT dctxt = (POSIX_DAL_CTXT)ctxt; // should have been passed a posix context

   // allocate space for a new BLOCK context
   POSIX_BLOCK_CTXT bctxt = malloc(sizeof(struct posix_block_context_struct));
   if (bctxt == NULL)
   {
      return -1;
   } // malloc will set errno

   // popultate the full file path for this object
   if (expand_dir_template(dctxt, bctxt, location, objID) != 0)
   {
      free(bctxt);
      return -1;
   }

   int res = block_delete(bctxt, 1);

   free(bctxt->filepath);
   free(bctxt);
   return res;
}

int posix_stat(DAL_CTXT ctxt, DAL_location location, const char *objID)
{
   POSIX_DAL_CTXT dctxt = (POSIX_DAL_CTXT)ctxt; // should have been passed a posix context

   // allocate space for a new BLOCK context
   POSIX_BLOCK_CTXT bctxt = malloc(sizeof(struct posix_block_context_struct));
   if (bctxt == NULL)
   {
      return -1;
   } // malloc will set errno

   // popultate the full file path for this object
   if (expand_dir_template(dctxt, bctxt, location, objID) != 0)
   {
      free(bctxt);
      return -1;
   }

   // perform a stat() call, and just check the return code
   struct stat sstr;
   int res = fstatat(dctxt->sec_root, bctxt->filepath, &sstr, 0);

   free(bctxt->filepath);
   free(bctxt);
   return res;
}

int posix_cleanup(DAL dal)
{
   POSIX_DAL_CTXT dctxt = (POSIX_DAL_CTXT)dal->ctxt; // should have been passed a posix context

   // free DAL context state
   close(dctxt->sec_root);
   free(dctxt->dirtmp);
   free(dctxt);
   // free the DAL struct and its associated state
   free(dal);
   return 0;
}

BLOCK_CTXT posix_open(DAL_CTXT ctxt, DAL_MODE mode, DAL_location location, const char *objID)
{
   POSIX_DAL_CTXT dctxt = (POSIX_DAL_CTXT)ctxt; // should have been passed a posix context

   // allocate space for a new BLOCK context
   POSIX_BLOCK_CTXT bctxt = malloc(sizeof(struct posix_block_context_struct));
   if (bctxt == NULL)
   {
      return NULL;
   } // malloc will set errno

   // popultate the full file path for this object
   if (expand_dir_template(dctxt, bctxt, location, objID) != 0)
   {
      free(bctxt);
      return NULL;
   }

   // populate other BLOCK context fields
   bctxt->offset = 0;
   bctxt->mode = mode;

   char *res = NULL;

   // append the meta suffix and check for success
   res = strncat(bctxt->filepath + bctxt->filelen, META_SFX, SFX_PADDING);
   if (res != (bctxt->filepath + bctxt->filelen))
   {
      LOG(LOG_ERR, "failed to append meta suffix \"%s\" to file path!\n", META_SFX);
      errno = EBADF;
      free(bctxt->filepath);
      free(bctxt);
      return NULL;
   }

   int metalen = strlen(META_SFX);

   int oflags = O_WRONLY | O_CREAT | O_TRUNC;
   if (mode == DAL_READ)
   {
      LOG(LOG_INFO, "Open for READ\n");
      oflags = O_RDONLY;
   }
   else if (mode == DAL_METAREAD)
   {
      LOG(LOG_INFO, "Open for METAREAD\n");
      oflags = O_RDONLY;
      bctxt->fd = -1;
   }
   else
   {
      // append the proper suffix and check for success
      if (mode == DAL_WRITE)
      {
         res = strncat(bctxt->filepath + bctxt->filelen + metalen, WRITE_SFX, SFX_PADDING - metalen);
      }
      else if (mode == DAL_REBUILD)
      {
         res = strncat(bctxt->filepath + bctxt->filelen + metalen, REBUILD_SFX, SFX_PADDING - metalen);
      }
      if (res != (bctxt->filepath + bctxt->filelen + metalen))
      {
         LOG(LOG_ERR, "failed to append suffix to meta path!\n");
         errno = EBADF;
         free(bctxt->filepath);
         free(bctxt);
         return NULL;
      }
   }

   // open the meta file and check for success
   bctxt->mfd = openat(dctxt->sec_root, bctxt->filepath, oflags, S_IRWXU | S_IRWXG | S_IRWXO); // mode arg should be harmlessly ignored if reading
   if (bctxt->mfd < 0)
   {
      LOG(LOG_ERR, "failed to open meta file: \"%s\" (%s)\n", bctxt->filepath, strerror(errno));
      if (mode == DAL_METAREAD)
      {
         free(bctxt->filepath);
         free(bctxt);
         return NULL;
      }
   }
   // remove any suffix in the simplest possible manner
   *(bctxt->filepath + bctxt->filelen) = '\0';

   if (mode == DAL_WRITE || mode == DAL_REBUILD)
   {
      // append the proper suffix
      if (mode == DAL_WRITE)
      {
         LOG(LOG_INFO, "Open for WRITE\n");
         res = strncat(bctxt->filepath + bctxt->filelen, WRITE_SFX, SFX_PADDING);
      }
      else if (mode == DAL_REBUILD)
      {
         LOG(LOG_INFO, "Open for REBUILD\n");
         res = strncat(bctxt->filepath + bctxt->filelen, REBUILD_SFX, SFX_PADDING);
      } // NOTE -- invalid mode will leave res == NULL
      // check for success appending the suffix
      if (res != (bctxt->filepath + bctxt->filelen))
      {
         LOG(LOG_ERR, "failed to append suffix to file path!\n");
         errno = EBADF;
         free(bctxt->filepath);
         free(bctxt);
         return NULL;
      }
   }

   if (mode != DAL_METAREAD)
   {
      // open the file and check for success
      bctxt->fd = openat(dctxt->sec_root, bctxt->filepath, oflags, S_IRWXU | S_IRWXG | S_IRWXO); // mode arg should be harmlessly ignored if reading
      if (bctxt->fd < 0)
      {
         LOG(LOG_ERR, "failed to open file: \"%s\" (%s)\n", bctxt->filepath, strerror(errno));
         free(bctxt->filepath);
         free(bctxt);
         return NULL;
      }
   }
   // remove any suffix in the simplest possible manner
   *(bctxt->filepath + bctxt->filelen) = '\0';

   // finally, return a reference to our BLOCK context
   return bctxt;
}

int posix_set_meta(BLOCK_CTXT ctxt, const char *meta_buf, size_t size)
{

   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      return -1;
   }
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT)ctxt; // should have been passed a posix context

   // write the provided buffer out to the sidecar file
   if (write(bctxt->mfd, meta_buf, size) != size)
   {
      LOG(LOG_ERR, "failed to write buffer to meta file: \"%s\" (%s)\n", bctxt->filepath, strerror(errno));
      return -1;
   }

   return 0;
}

ssize_t posix_get_meta(BLOCK_CTXT ctxt, char *meta_buf, size_t size)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      return -1;
   }
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT)ctxt; // should have been passed a posix context

   ssize_t result = read(bctxt->mfd, meta_buf, size);

   return result;
}

int posix_put(BLOCK_CTXT ctxt, const void *buf, size_t size)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      return -1;
   }
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT)ctxt; // should have been passed a posix context

   // just a write to our pre-opened FD
   if (write(bctxt->fd, buf, size) != size)
   {
      LOG(LOG_ERR, "write to \"%s\" failed (%s)\n", bctxt->filepath, strerror(errno));
      return -1;
   }

   return 0;
}

ssize_t posix_get(BLOCK_CTXT ctxt, void *buf, size_t size, off_t offset)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      return -1;
   }
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT)ctxt; // should have been passed a posix context

   // abort, unless we're reading
   if (bctxt->mode != DAL_READ)
   {
      LOG(LOG_ERR, "Can only perform get ops on a DAL_READ block handle!\n");
      return -1;
   }

   // check if we need to seek
   if (offset != bctxt->offset)
   {
      LOG(LOG_INFO, "Performing seek to new offset of %zd\n", offset);
      bctxt->offset = lseek(bctxt->fd, offset, SEEK_SET);
      // make sure our new offset makes sense
      if (bctxt->offset != offset)
      {
         LOG(LOG_ERR, "failed to seek to offset %zd of file \"%s\" (%s)\n", offset, bctxt->filepath, strerror(errno));
         return -1;
      }
   }

   // just a read from our pre-opened FD
   ssize_t res = read(bctxt->fd, buf, size);

   // adjust our offset value
   if (res > 0)
   {
      bctxt->offset += res;
   }

   return res;
}

int posix_abort(BLOCK_CTXT ctxt)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      return -1;
   }
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT)ctxt; // should have been passed a posix context

   int retval = 0;
   // close the file descriptor, note but bypass failure
   if (close(bctxt->fd) != 0)
   {
      LOG(LOG_WARNING, "failed to close data file \"%s\" during abort (%s)\n", bctxt->filepath, strerror(errno));
   }
   if (close(bctxt->mfd) != 0)
   {
      LOG(LOG_WARNING, "failed to close meta file \"%s\" during abort (%s)\n", bctxt->filepath, strerror(errno));
   }
   if (block_delete(bctxt, 0))
   {
      LOG(LOG_ERR, "failed to delete data file \"%s\" during abort (%s)\n", bctxt->filepath, strerror(errno));
      retval = 1;
   }

   // free state
   free(bctxt->filepath);
   free(bctxt);
   return retval;
}

int posix_close(BLOCK_CTXT ctxt)
{
   if (ctxt == NULL)
   {
      LOG(LOG_ERR, "received a NULL block context!\n");
      return -1;
   }
   POSIX_BLOCK_CTXT bctxt = (POSIX_BLOCK_CTXT)ctxt; // should have been passed a posix context

   // if this is not a meta-only reference, attempt to close our FD and check for success
   if ((bctxt->mode != DAL_METAREAD) && (close(bctxt->fd) != 0))
   {
      LOG(LOG_ERR, "failed to close data file \"%s\" (%s)\n", bctxt->filepath, strerror(errno));
      return -1;
   }

   // attempt to close our meta FD and check for success
   if (close(bctxt->mfd))
   {
      LOG(LOG_ERR, "failed to close meta file \"%s\" (%s)\n", bctxt->filepath, strerror(errno));
      return -1;
   }

   char *res = NULL;
   if (bctxt->mode == DAL_WRITE || bctxt->mode == DAL_REBUILD)
   {
      if (bctxt->mode == DAL_WRITE)
      {
         // append the write suffix
         res = strncat(bctxt->filepath + bctxt->filelen, WRITE_SFX, SFX_PADDING);
      }
      else
      {
         // append the rebuild suffix
         res = strncat(bctxt->filepath + bctxt->filelen, REBUILD_SFX, SFX_PADDING);
      }
      // check for success
      if (res != (bctxt->filepath + bctxt->filelen))
      {
         LOG(LOG_ERR, "failed to append write suffix \"%s\" to file path!\n", WRITE_SFX);
         errno = EBADF;
         *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
         return -1;
      }

      // duplicate the path and check for success
      char *write_path = strdup(bctxt->filepath);
      *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains

      // attempt to rename and check for success
      if (renameat(bctxt->sfd, write_path, bctxt->sfd, bctxt->filepath) != 0)
      {
         LOG(LOG_ERR, "failed to rename data file \"%s\" to \"%s\" (%s)\n", write_path, bctxt->filepath, strerror(errno));
         free(write_path);
         return -1;
      }
      free(write_path);

      // append the meta suffix and check for success
      res = strncat(bctxt->filepath + bctxt->filelen, META_SFX, SFX_PADDING);
      if (res != (bctxt->filepath + bctxt->filelen))
      {
         LOG(LOG_ERR, "failed to append meta suffix \"%s\" to file path!\n", META_SFX);
         errno = EBADF;
         return -1;
      }

      int metalen = strlen(META_SFX);

      // append the proper suffix and check for success
      if (bctxt->mode == DAL_WRITE)
      {
         res = strncat(bctxt->filepath + bctxt->filelen + metalen, WRITE_SFX, SFX_PADDING - metalen);
      }
      if (bctxt->mode == DAL_REBUILD)
      {
         res = strncat(bctxt->filepath + bctxt->filelen + metalen, REBUILD_SFX, SFX_PADDING - metalen);
      }
      if (res != (bctxt->filepath + bctxt->filelen + metalen))
      {
         LOG(LOG_ERR, "failed to append write suffix \"%s\" to file path!\n", WRITE_SFX);
         errno = EBADF;
         *(bctxt->filepath + bctxt->filelen) = '\0'; // make sure no suffix remains
         return -1;
      }

      // duplicate the path and check for success
      char *meta_path = strdup(bctxt->filepath);
      *(bctxt->filepath + bctxt->filelen + metalen) = '\0'; // make sure no suffix remains

      // attempt to rename and check for success
      if (renameat(bctxt->sfd, meta_path, bctxt->sfd, bctxt->filepath) != 0)
      {
         LOG(LOG_ERR, "failed to rename meta file \"%s\" to \"%s\" (%s)\n", meta_path, bctxt->filepath, strerror(errno));
         free(meta_path);
         return -1;
      }
      free(meta_path);
   }

   // free state
   free(bctxt->filepath);
   free(bctxt);
   return 0;
}

//   -------------    POSIX INITIALIZATION    -------------

DAL posix_dal_init(xmlNode *root, DAL_location max_loc)
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

   // make sure we start on a 'dir_template' node
   if (root->type == XML_ELEMENT_NODE && strncmp((char *)root->name, "dir_template", 13) == 0)
   {

      // make sure that node contains a text element within it
      if (root->children != NULL && root->children->type == XML_TEXT_NODE)
      {

         // allocate space for our context struct
         POSIX_DAL_CTXT dctxt = malloc(sizeof(struct posix_dal_context_struct));
         if (dctxt == NULL)
         {
            return NULL;
         } // malloc will set errno

         // copy the dir template into the context struct
         dctxt->dirtmp = strdup((char *)root->children->content);
         if (dctxt->dirtmp == NULL)
         {
            free(dctxt);
            return NULL;
         } // strdup will set errno

         // initialize all other context fields
         dctxt->tmplen = strlen(dctxt->dirtmp);
         dctxt->max_loc = max_loc;
         dctxt->dirpad = 0;

         // calculate a real value for dirpad based on number of p/c/b/s substitutions
         char *parse = dctxt->dirtmp;
         while (*parse != '\0')
         {
            if (*parse == '{')
            {
               // possible substituion, but of what type?
               int increase = 0;
               switch (*(parse + 1))
               {
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
               if (increase > 0 && *(parse + 2) == '}')
               {                                 // NOTE -- we know *(parse+1) != '\0'
                  dctxt->dirpad += increase - 3; // add increase, adjusting for chars used in substitution
               }
            }
            parse++; // next char
         }

         // find the secure root node. Fail if there is none
         while (root->type != XML_ELEMENT_NODE || strncmp((char *)root->name, "sec_root", 9) != 0)
         {
            root = root->next;
            if (root == NULL)
            {
               LOG(LOG_ERR, "failed to find \"secure root\" node\n");
               free(dctxt);
               errno = EINVAL;
               return NULL;
            }
         }

         // make sure that node contains a text element within it and update secure root handle
         dctxt->sec_root = -1;
         errno = EINVAL;

         if (root->children == NULL)
         {
            dctxt->sec_root = AT_FDCWD;
         }
         else if (root->children->type == XML_TEXT_NODE)
         {
            dctxt->sec_root = open((char *)root->children->content, O_DIRECTORY);
         }

         // make sure the secure root handle is valid
         if (dctxt->sec_root == -1)
         {
            LOG(LOG_ERR, "failed to open secure root handle\n");
            free(dctxt);
            return NULL;
         }

         // allocate and populate a new DAL structure
         DAL pdal = malloc(sizeof(struct DAL_struct));
         if (pdal == NULL)
         {
            LOG(LOG_ERR, "failed to allocate space for a DAL_struct\n");
            free(dctxt);
            return NULL;
         } // malloc will set errno
         pdal->name = "posix";
         pdal->ctxt = (DAL_CTXT)dctxt;
         pdal->io_size = IO_SIZE;
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
         pdal->stat = posix_stat;
         pdal->cleanup = posix_cleanup;
         return pdal;
      }
      else
      {
         LOG(LOG_ERR, "the \"dir_template\" node is expected to contain a template string\n");
      }
   }
   else
   {
      LOG(LOG_ERR, "root node of config is expected to be \"dir_template\"\n");
   }
   errno = EINVAL;
   return NULL; // failure of any condition check fails the function
}
