
#include "dal.h"
#include <unistd.h>
#include <stdio.h>

int main( int argc, char** argv ) {
   

   xmlDoc *doc = NULL;
   xmlNode *root_element = NULL;

   if (argc != 2) {
     errno=EINVAL;
     printf( "error: missing required argument: <filename>\n" );
     return -1;
   }

   /*
   * this initialize the library and check potential ABI mismatches
   * between the version it was compiled for and the actual shared
   * library used.
   */
   LIBXML_TEST_VERSION

     /*parse the file and get the DOM */
   doc = xmlReadFile(argv[1], NULL, XML_PARSE_NOBLANKS);

   if (doc == NULL) {
     printf("error: could not parse file %s\n", argv[1]);
     return -1;
   }

   /*Get the root element node */
   root_element = xmlDocGetRootElement(doc);

   // Initialize a posix dal instance
   DAL_location maxloc = { .pod = 1, .block = 1, .cap = 1, .scatter = 1 };
   DAL dal = init_dal_by_name( "posix", root_element->children, maxloc );
   if ( dal == NULL ) { printf( "error: failed to initialize DAL: %s\n", strerror(errno) ); return -1; }

   // Open, write to, and set meta info for a specific block
   void* writebuffer = calloc( 10, 1024 );
   if ( writebuffer == NULL ) { printf( "error: failed to allocate write buffer\n" ); return -1; }
   BLOCK_CTXT block = dal->open( dal->ctxt, WRITE, maxloc, "" );
   if ( block == NULL ) { printf( "error: failed to open block context for write: %s\n", strerror(errno) ); return -1; }
   if ( dal->put( block, writebuffer, (10*1024) ) ) {
      printf( "warning: put did not return expected value\n" );
   }
   char* meta_val = "this is a meta value!\n";
   if ( dal->set_meta( block, meta_val, 22 ) ) {
      printf( "warning: set_meta did not return expected value\n" );
   }
   if ( dal->close( block ) ) { printf( "error: failed to close block write context: %s\n", strerror(errno) ); return -1; }

   // Open the same block for read and verify all values
   void* readbuffer = malloc( sizeof(char) * 10 * 1024 );
   if ( readbuffer == NULL ) { printf( "error: failed to allocate read buffer\n" ); return -1; }
   block = dal->open( dal->ctxt, READ, maxloc, "" );
   if ( block == NULL ) { printf( "error: failed to open block context for read: %s\n", strerror(errno) ); return -1; }
   if ( dal->get( block, readbuffer, (10*1024), 0 ) != (10*1024) ) {
      printf( "warning: get did not return expected value\n" );
   }
   if ( memcmp( writebuffer, readbuffer, (10*1024) ) ) { printf( "warning: retrieved data does not match written!\n" ); }
   if ( dal->get_meta( block, readbuffer, (10*1024) ) != 22 ) {
      printf( "warning: get_meta returned an unexpected value\n" );
   }
   if ( strncmp( meta_val, readbuffer, 22 ) ) { printf( "warning: retrieved meta value does not match written!\n" ); }
   if ( dal->close( block ) ) { printf( "error: failed to close block read context: %s\n", strerror(errno) ); return -1; }

   // Delete the block we created
   if ( dal->del( dal->ctxt, maxloc, "" ) ) { printf( "warning: del failed!\n" ); }

   // Free the DAL
   if ( dal->cleanup( dal ) ) { printf( "error: failed to cleanup DAL\n" ); return -1; }

   /*free the document */
   xmlFreeDoc(doc);
   free( writebuffer );
   free( readbuffer );

   /*
   *Free the global variables that may
   *have been allocated by the parser.
   */
   xmlCleanupParser();

   return 0;

}


