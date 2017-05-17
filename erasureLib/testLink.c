#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "erasure.h"

#define PATH_TEMPLATE "testLink_file.%d"

int main(int argc, char **argv) {
   ne_handle h = ne_open(PATH_TEMPLATE, NE_WRONLY, 10,10,2);
   assert(h != NULL);

   srandom(getpid());

   int i;
   char *buf = malloc(10 * 1024 * 1024);
   for(i = 0; i < 10; i++) {
      int j;
      for(j = 0; j < 10 * 1024 * 1024; j++) {
         buf[i] = random();
      }
      assert(ne_write(h, buf, 10 * 1024 * 1024) == 10 * 1024 * 1024);
   }

   ne_close(h);

   for(i = 0; i < 12; i++) {
      char path[512];
      char link_path[512];
      sprintf(path, PATH_TEMPLATE, i);
      strcpy(link_path, path);
      strcat(link_path, "new");
      assert(ne_link_block(link_path, path) == 0);
   }

   char new_path[512];
   strcpy(new_path, PATH_TEMPLATE);
   strcat(new_path, "new");

   h = ne_open(new_path, NE_RDONLY, 10,10,2);
   assert(h != NULL);
   ne_close(h);

   system("rm testLink_file.*");
}
