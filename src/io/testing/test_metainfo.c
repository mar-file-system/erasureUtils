
#define DEBUG 1
#define USE_STDOUT 1
#include "io/io.h"
#include "dal/dal.h"
#include <unistd.h>
#include <stdio.h>


int main( int argc, char** argv ) {
   // create a meta info struct
   meta_info minfo_ref;
   minfo_ref.N = 10;
   minfo_ref.E = 2;
   minfo_ref.O = 5;
   minfo_ref.partsz = 4096;
   minfo_ref.versz = 1048580;
   minfo_ref.blocksz = 104858000;
   minfo_ref.crcsum = 123456789;
   minfo_ref.totsz = 1048576000;

   meta_info minfo_fill;

   xmlDoc *doc = NULL;
   xmlNode *root_element = NULL;


   /*
   * this initialize the library and check potential ABI mismatches
   * between the version it was compiled for and the actual shared
   * library used.
   */
   LIBXML_TEST_VERSION

   /*parse the file and get the DOM */
   doc = xmlReadFile("./testing/config.xml", NULL, XML_PARSE_NOBLANKS);

   if (doc == NULL) {
     printf("error: could not parse file %s\n", "./dal/testing/config.xml");
     return -1;
   }

   /*Get the root element node */
   root_element = xmlDocGetRootElement(doc);

   // Initialize a posix dal instance
   DAL_location maxloc = { .pod = 1, .block = 1, .cap = 1, .scatter = 1 };
   DAL dal = init_dal( root_element, maxloc );

   /* Free the xml Doc */
   xmlFreeDoc(doc);
   /*
   *Free the global variables that may
   *have been allocated by the parser.
   */
   xmlCleanupParser();

   // check that initialization succeeded
   if ( dal == NULL ) {
      printf( "error: failed to initialize DAL: %s\n", strerror(errno) );
      return -1;
   }

   // get a block context on which to set meta info
   BLOCK_CTXT block = dal->open( dal->ctxt, DAL_WRITE, maxloc, "" );
   if ( block == NULL ) { printf( "error: failed to open block context for write: %s\n", strerror(errno) ); return -1; }

   // attempt to set meta info from our ref struct
   if ( dal_set_minfo( dal, block, &(minfo_ref) ) ) {
      printf( "error: failed to set meta info on block: %s\n", strerror(errno) );
      return -1;
   }

   // close the empty block ref
   if ( dal->close( block ) ) { printf( "error: failed to close block write context: %s\n", strerror(errno) ); return -1; }

   // get a block context on which to get meta info
   block = dal->open( dal->ctxt, DAL_READ, maxloc, "" );
   if ( block == NULL ) { printf( "error: failed to open block context for write: %s\n", strerror(errno) ); return -1; }

   // attempt to retrieve meta info into our fill struct
   if ( dal_get_minfo( dal, block, &(minfo_fill) ) ) {
      printf( "error: failed to get meta info on block: %s\n", strerror(errno) );
      return -1;
   }

   // close the empty block ref
   if ( dal->close( block ) ) { printf( "error: failed to close block read context: %s\n", strerror(errno) ); return -1; }

   // Delete the block we created
   if ( dal->del( dal->ctxt, maxloc, "" ) ) { printf( "warning: del failed!\n" ); }

   // Free the DAL
   if ( dal->cleanup( dal ) ) { printf( "error: failed to cleanup DAL\n" ); return -1; }

   // Finally, compare our structs
   int retval=0;
   if ( minfo_ref.N != minfo_fill.N ) {
      printf( "error: set (%d) and retrieved (%d) meta info 'N' values do not match!\n", minfo_ref.N, minfo_fill.N );
      retval=-1;
   }
   if ( minfo_ref.E != minfo_fill.E ) {
      printf( "error: set (%d) and retrieved (%d) meta info 'E' values do not match!\n", minfo_ref.E, minfo_fill.E );
      retval=-1;
   }
   if ( minfo_ref.O != minfo_fill.O ) {
      printf( "error: set (%d) and retrieved (%d) meta info 'O' values do not match!\n", minfo_ref.O, minfo_fill.O );
      retval=-1;
   }
   if ( minfo_ref.partsz != minfo_fill.partsz ) {
      printf( "error: set (%zd) and retrieved (%zd) meta info 'partsz' values do not match!\n", minfo_ref.partsz, minfo_fill.partsz );
      retval=-1;
   }
   if ( minfo_ref.versz != minfo_fill.versz ) {
      printf( "error: set (%zd) and retrieved (%zd) meta info 'versz' values do not match!\n", minfo_ref.versz, minfo_fill.versz );
      retval=-1;
   }
   if ( minfo_ref.blocksz != minfo_fill.blocksz ) {
      printf( "error: set (%zd) and retrieved (%zd) meta info 'blocksz' values do not match!\n", minfo_ref.blocksz, minfo_fill.blocksz );
      retval=-1;
   }
   if ( minfo_ref.crcsum != minfo_fill.crcsum ) {
      printf( "error: set (%lld) and retrieved (%lld) meta info 'crcsum' values do not match!\n", minfo_ref.crcsum, minfo_fill.crcsum );
      retval=-1;
   }
   if ( minfo_ref.totsz != minfo_fill.totsz ) {
      printf( "error: set (%zd) and retrieved (%zd) meta info 'totsz' values do not match!\n", minfo_ref.totsz, minfo_fill.totsz );
      retval=-1;
   }

   return retval;
}


