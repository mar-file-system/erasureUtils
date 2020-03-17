

#define LOG_PREFIX "dal"
#include "logging/logging.h"
#include "dal.h"

#include <ctype.h>


// Function to provide specific DAL initialization calls based on name
DAL init_dal_by_name( const char* name, xmlNode* dal_conf_root, DAL_location max_loc ) {
   // don't want this to be case sensitive, so we'll need to duplicate and modify the name
   char* dname = strdup( name );
   if ( dname == NULL ) {
      LOG( LOG_ERR, "failed to allocate memory for a DAL name string\n" );
      return NULL;
   }
   // convert all chars to lowercase
   char* parse = dname;
   for( ; *parse != '\0'; parse++ ) { *parse = tolower( *parse ); }

   // name comparison for each DAL type
   if (  strncmp( dname, "posix", 6 ) == 0 ) {
      free( dname );
      return posix_dal_init( dal_conf_root, max_loc );
   }

   // if no DAL found, return NULL
   free( dname );
   errno = ENODEV;
   return NULL;
}



