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
#if defined(DEBUG_ALL)  ||  defined(DEBUG_DAL)
   #define DEBUG 1
#endif
#define LOG_PREFIX "fuzzing_dal"
#include "logging/logging.h"

#include "dal.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

typedef struct fuzzing_dal_context_struct {
	DAL	posix_dal; 	// Underlying posix dal
	int	verify; 	// fuzzing behavior of each function. -1 means always
	int	migrate; 	// fails. A positive number means always fails for
	int 	del; 		// the block that corresponds to the number. 0 means 
	int	stat; 		// do not fuzz operation.
	int	cleanup;
	int	open;
	int	set_meta;
	int	get_meta;
	int	put;
	int	get;
	int	abort;
	int	close;
} *FUZZING_DAL_CTXT;

typedef struct fuzzing_block_context_struct {
	FUZZING_DAL_CTXT global_ctxt; // Global context
	DAL_location loc; // Location of block
	BLOCK_CTXT bctxt; // Block context to be passed to underlying dal 
} *FUZZING_BLOCK_CTXT;

//   -------------    POSIX IMPLEMENTATION    -------------

int fuzzing_verify ( DAL_CTXT ctxt, char fix ) {
	FUZZING_DAL_CTXT dctxt = (FUZZING_DAL_CTXT) ctxt;

	if ( dctxt->verify != 0 ) {
		return -2;
	}

	return dctxt->posix_dal->verify( dctxt->posix_dal->ctxt, fix ); 
}


int fuzzing_migrate ( DAL_CTXT ctxt, const char* objID, DAL_location src, DAL_location dest, char offline ) {
	FUZZING_DAL_CTXT dctxt = (FUZZING_DAL_CTXT) ctxt;

	if ( dctxt->migrate < 0 || dctxt->migrate == src.block || dctxt->migrate == dest.block ) {
		return -1;
	}

	return dctxt->posix_dal->migrate( dctxt->posix_dal->ctxt, objID, src, dest, offline ); 
}



int fuzzing_del (  DAL_CTXT ctxt, DAL_location location, const char* objID ) {
	FUZZING_DAL_CTXT dctxt = (FUZZING_DAL_CTXT) ctxt;

	if ( dctxt->del < 0 || dctxt->del == location.block ) {
		return -2;
	}

	return dctxt->posix_dal->del( dctxt->posix_dal->ctxt, location, objID ); 
}



int fuzzing_stat ( DAL_CTXT ctxt, DAL_location location, const char* objID ) {
	FUZZING_DAL_CTXT dctxt = (FUZZING_DAL_CTXT) ctxt;

	if ( dctxt->stat < 0 || dctxt->stat == location.block ) {
		return -2;
	}

	return dctxt->posix_dal->stat( dctxt->posix_dal->ctxt, location, objID ); 
}



int fuzzing_cleanup ( DAL dal ) {
	FUZZING_DAL_CTXT dctxt = (FUZZING_DAL_CTXT) dal->ctxt;

	if ( dctxt->cleanup != 0 ) {
		return -2;
	}

	int res = dctxt->posix_dal->cleanup( dctxt->posix_dal ); 
	if ( res ) {
		return res;
	}

	free( dctxt );

	free( dal );
	return 0;
}



BLOCK_CTXT fuzzing_open ( DAL_CTXT ctxt, DAL_MODE mode, DAL_location location, const char* objID ) {
	FUZZING_DAL_CTXT dctxt = (FUZZING_DAL_CTXT) ctxt;

	if ( dctxt->open < 0 || dctxt->open == location.block ) {
		return NULL;
	}

	FUZZING_BLOCK_CTXT bctxt = malloc( sizeof( struct fuzzing_block_context_struct ) );
	if ( bctxt == NULL ) {
		return NULL;
	}

	bctxt->global_ctxt = dctxt;
	if ( memcpy( &(bctxt->loc), &location, sizeof( struct DAL_location_struct ) ) != &(bctxt->loc) ) {
		free( bctxt );
		return NULL;
	}
	bctxt->bctxt = dctxt->posix_dal->open( dctxt->posix_dal->ctxt, mode, location, objID ); 
	if ( bctxt->bctxt == NULL ) {
		free( bctxt );
		return NULL;
	}

	return bctxt;
}



int fuzzing_set_meta ( BLOCK_CTXT ctxt, const char* meta_buf, size_t size ) {
	FUZZING_BLOCK_CTXT bctxt = (FUZZING_BLOCK_CTXT) ctxt;

	if ( bctxt->global_ctxt->set_meta < 0 || bctxt->global_ctxt->set_meta == bctxt->loc.block ) {
		return -2;
	}

	return bctxt->global_ctxt->posix_dal->set_meta( bctxt->bctxt, meta_buf, size ); 
}



ssize_t fuzzing_get_meta ( BLOCK_CTXT ctxt, char* meta_buf, size_t size ) {
	FUZZING_BLOCK_CTXT bctxt = (FUZZING_BLOCK_CTXT) ctxt;

	if ( bctxt->global_ctxt->get_meta < 0 || bctxt->global_ctxt->get_meta == bctxt->loc.block ) {
		return -2;
	}

	return bctxt->global_ctxt->posix_dal->get_meta( bctxt->bctxt, meta_buf, size ); 
}



int fuzzing_put ( BLOCK_CTXT ctxt, const void* buf, size_t size ) {
	FUZZING_BLOCK_CTXT bctxt = (FUZZING_BLOCK_CTXT) ctxt;

	if ( bctxt->global_ctxt->put < 0 || bctxt->global_ctxt->put == bctxt->loc.block ) {
		return -2;
	}

	return bctxt->global_ctxt->posix_dal->put( bctxt->bctxt, buf, size ); 
}



ssize_t fuzzing_get ( BLOCK_CTXT ctxt, void* buf, size_t size, off_t offset ) {
	FUZZING_BLOCK_CTXT bctxt = (FUZZING_BLOCK_CTXT) ctxt;

	if ( bctxt->global_ctxt->get < 0 || bctxt->global_ctxt->get == bctxt->loc.block ) {
		return -2;
	}

	return bctxt->global_ctxt->posix_dal->get( bctxt->bctxt, buf, size, offset ); 
}



int fuzzing_abort ( BLOCK_CTXT ctxt ) {
	FUZZING_BLOCK_CTXT bctxt = (FUZZING_BLOCK_CTXT) ctxt;
	
	if ( bctxt->global_ctxt->abort < 0 || bctxt->global_ctxt->abort == bctxt->loc.block ) {
		return -2;
	}

	int res = bctxt->global_ctxt->posix_dal->abort( bctxt->bctxt );
	if ( res ) {
		return res;
	}
	
	free( bctxt );
	return 0;
}



int fuzzing_close ( BLOCK_CTXT ctxt ) {
	FUZZING_BLOCK_CTXT bctxt = (FUZZING_BLOCK_CTXT) ctxt;
	
	if ( bctxt->global_ctxt->close < 0 || bctxt->global_ctxt->close == bctxt->loc.block ) {
		return -2;
	}

	int res = bctxt->global_ctxt->posix_dal->close( bctxt->bctxt );
	if ( res ) {
		return res;
	}
	
	free( bctxt );	
	return 0;
}



//   -------------    POSIX INITIALIZATION    -------------

DAL fuzzing_dal_init( xmlNode* root, DAL_location max_loc ) {
	// allocate space for our context struct
	FUZZING_DAL_CTXT dctxt = malloc( sizeof( struct fuzzing_dal_context_struct ) );
	if ( dctxt == NULL ) {
		return NULL;
	}
	
	// initialize underlying posix dal
	dctxt->posix_dal = posix_dal_init( root, max_loc );
	if( dctxt->posix_dal == NULL ) {
		free( dctxt );
		return NULL;
	}
	dctxt->verify = 0;
	dctxt->migrate = 0;
	dctxt->del = 0;
	dctxt->stat = 0;
	dctxt->cleanup = 0;
	dctxt->open = 0;
	dctxt->set_meta = 0;
	dctxt->get_meta = 0;
	dctxt->put = 0;
	dctxt->get = 0;
	dctxt->abort = 0;
	dctxt->close = 0;

	if ( root->type != XML_ELEMENT_NODE || strncmp( (char*)root->name, "dir_template", 13 ) != 0 ) {
		free( dctxt );
		return NULL;
	}
		
	// find the fuzzing data. Fail if there is none
	while( root->type != XML_ELEMENT_NODE || strncmp( (char*)root->name, "fuzzing", 8 ) != 0 ) {
		root = root->next;
		if ( root == NULL ) {
			free( dctxt );
			return NULL;
		}
	}
	
	// parse fuzzing data to context struct
	xmlNode* child = root->children;
	while ( child != NULL ) {
		if ( child->children == NULL || child->children->type != XML_TEXT_NODE ) {
			LOG( LOG_ERR, "the \"%s\" node is expected to contain a fuzzing state\n", (char*)child->name );
		}
		else if ( strncmp( (char*)child->name, "verify", 7 ) == 0 ) {
			dctxt->verify = atoi( (char*)child->children->content );
		}
		else if ( strncmp( (char*)child->name, "migrate", 8 ) == 0 ) {
			dctxt->migrate = atoi( (char*)child->children->content );
		}
		else if ( strncmp( (char*)child->name, "del", 4 ) == 0 ) {
			dctxt->del = atoi( (char*)child->children->content );
		}
		else if ( strncmp( (char*)child->name, "stat", 5 ) == 0 ) {
			dctxt->stat = atoi( (char*)child->children->content );
		}
		else if ( strncmp( (char*)child->name, "cleanup", 8 ) == 0 ) {
			dctxt->cleanup = atoi( (char*)child->children->content );
		}
		else if ( strncmp( (char*)child->name, "open", 5 ) == 0 ) {
			dctxt->open = atoi( (char*)child->children->content );
		}
		else if ( strncmp( (char*)child->name, "set_meta", 9 ) == 0 ) {
			dctxt->set_meta = atoi( (char*)child->children->content );
		}
		else if ( strncmp( (char*)child->name, "get_meta", 9 ) == 0 ) {
			dctxt->get_meta = atoi( (char*)child->children->content );
		}
		else if ( strncmp( (char*)child->name, "put", 4 ) == 0 ) {
			dctxt->put = atoi( (char*)child->children->content );
		}
		else if ( strncmp( (char*)child->name, "get", 4 ) == 0 ) {
			dctxt->get = atoi( (char*)child->children->content );
		}
		else if ( strncmp( (char*)child->name, "abort", 6 ) == 0 ) {
			dctxt->abort = atoi( (char*)child->children->content );
		}
		else if ( strncmp( (char*)child->name, "close", 6 ) == 0 ) {
			dctxt->close = atoi( (char*)child->children->content );
		}
		else if ( ( strncmp( (char*)child->name, "init", 5 ) != 0 ) || ( atoi( (char*)child->children->content ) != 0 ) ) {
			free( dctxt );
			return NULL;
		}
		child = child->next;
	}
	// allocate and populate a new DAL structure
	DAL fdal = malloc( sizeof( struct DAL_struct ) );
	if( fdal == NULL ) {
		LOG( LOG_ERR, "failed to allocate space for a DAL_struct\n" );
		free( dctxt );
		return NULL;
	}
	fdal->name = "fuzzing";
	fdal->ctxt = (DAL_CTXT) dctxt;
	fdal->io_size = dctxt->posix_dal->io_size;
	fdal->verify = fuzzing_verify;
	fdal->migrate = fuzzing_migrate;
	fdal->open = fuzzing_open;
	fdal->set_meta = fuzzing_set_meta;
	fdal->get_meta = fuzzing_get_meta;
	fdal->put = fuzzing_put;
	fdal->get = fuzzing_get;
	fdal->abort = fuzzing_abort;
	fdal->close = fuzzing_close;
	fdal->del = fuzzing_del;
	fdal->stat = fuzzing_stat;
	fdal->cleanup = fuzzing_cleanup;
	return fdal;
  
}



