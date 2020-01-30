

#include "dal.h"


// Function to provide specific DAL initialization calls based on name
DAL init_dal_by_name( const char* name, xmlNode* dal_conf_root, DAL_location max_loc ) {
   if (  strncmp( name, "posix", 6 ) == 0 ) {
      return posix_dal_init( dal_conf_root, max_loc );
   }
   // if no DAL found, return NULL
   errno = ENODEV;
   return NULL;
}



