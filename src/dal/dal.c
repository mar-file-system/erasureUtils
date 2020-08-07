
//#define DEBUG 1
//#define USE_STDOUT 1
#define LOG_PREFIX "dal"
#include "logging/logging.h"
#include "dal.h"

#include <ctype.h>


// Function to provide specific DAL initialization calls based on name
DAL init_dal( xmlNode* dal_conf_root, DAL_location max_loc ) {
   // make sure we start on a 'DAL' node
   if ( dal_conf_root->type != XML_ELEMENT_NODE  ||  strncmp( (char*)dal_conf_root->name, "DAL", 4 ) != 0 ) {
      LOG( LOG_ERR, "root xml node is not an element of type \"DAL\"!\n" );
      errno = EINVAL;
      return NULL;
   }

   // make sure we have a valid 'type' attribute
   xmlAttr* type = dal_conf_root->properties;
   xmlNode* typetxt = NULL;
   for ( ; type; type = type->next ) {
      if ( typetxt == NULL  &&  type->type == XML_ATTRIBUTE_NODE  &&  strncmp( (char*)type->name, "type", 5 ) == 0 ) {
         typetxt = type->children;
      }
      else {
         LOG( LOG_WARNING, "encountered unrecognized or redundant DAL attribute: \"%s\"\n", (char*)type->name );
      }
   }
   if ( typetxt == NULL ) {
      LOG( LOG_ERR, "failed to find a 'type' attribute for the given DAL node!\n" );
      errno = EINVAL;
      return NULL;
   }

   // make sure we have a text value for the 'type' attribute
   if ( typetxt->type != XML_TEXT_NODE  ||  typetxt->content == NULL ) {
      LOG( LOG_ERR, "DAL type attribute does not have a text value!\n" );
      errno = EINVAL;
      return NULL;
   }

   // name comparison for each DAL type
   if (  strncasecmp( (char*)typetxt->content, "posix", 6 ) == 0 ) {
      return posix_dal_init( dal_conf_root->children, max_loc );
   }

   // if no DAL found, return NULL
   LOG( LOG_ERR, "failed to identify a DAL of type: \"%s\"\n", typetxt->content );
   errno = ENODEV;
   return NULL;
}



