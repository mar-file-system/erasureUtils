#include <string.h>
#include <aws4c.h>


// @param user    the "user" as known to the object-server.  (2nd field in ~/.awsAuth)
//
// @param pass    the "password" as known to the object-server.  (3rd field in ~/.awsAuth)
//
// @param method  CMD_PUT, etc, for the request
//
// @param obj_id  This is going to be the fname argument to the server.
//                Using just obj-ID (i.e. leaving out the host, and the
//                path down to the object) allows the same signature for
//                all components of a stripe.

char* create_auth_signature(AWSContext* const ctx, // auth_info
                            char* const       method,
                            char* const       obj_id) {

  char         resource [1024];
  DateConv     date_conv = { .time = NULL };

  //  AWSContext ctx = {0};
  //  aws_set_key_r  (auth_info->awsKeyID, &ctx); /* "user" */
  //  aws_set_keyid_r(auth_info->awsKey, &ctx);   /* "pass" */

  char* sign = GetStringToSign(resource, sizeof(resource),
                               &date_conv, method, NULL, obj_id, ctx);
}



