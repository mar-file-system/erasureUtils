#include <string.h>
#include <aws4c.h>


// @param user    the "user" as known to the server.  (2nd field in ~/.awsAuth)
//
// @param pass    the "password" as known to the server.  (3rd field in ~/.awsAuth)
//
// @param method  CMD_PUT, etc, for the request
//
// @param obj_id  This is going to be the fname argument to the server.
//                Using just obj-ID (i.e. leaving out the host, and the
//                path down to the object) allows the same signature for
//                all components of a stripe.

char* create_auth_signature(char* const user,
                            char* const pass,
                            char* const method,
                            char* const obj_id) {
  char  resource [1024];
  char* date = NULL;

  AWSContext ctx;
  memset(&ctx, 0, sizeof(ctx));
  aws_set_key_r  (user, &ctx);
  aws_set_keyid_r(pass, &ctx);

  char* sign = GetStringToSign(resource, sizeof(resource),
                               &date, method, NULL, obj_id, &ctx);
}



