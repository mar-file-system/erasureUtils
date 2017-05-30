#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "erasure.h"

#define M  1048576

int main(int argc, char **argv) {
   if(argc < 2) {
      printf("Usage: %s <path template>", argv[0]);
      return 0;
   }
   int start = 0;
   ne_handle h = ne_open(argv[1], NE_WRONLY, start, 10, 2);

   srandom(getpid());
   
   /* make a bunch of data */
   char *data = malloc(M * 40);
   int i;
   for(i = 0; i < 40*M; i++) {
      data[i] = random();
   }
   assert(ne_write(h, data, M*40) == M*40);

   assert(ne_close(h) == 0);

   char dead_file[256];
   sprintf(dead_file, argv[1], 0);
   assert(unlink(dead_file) == 0);

   h = ne_open(argv[1], NE_RDONLY, start, 10, 2);
   assert(h);
   char *read_buff = malloc(10*M);
   off_t offset = 10*M - 4096;
   size_t readsize = 2*M;
   //assert(ne_read(h, read_buff, offset, 0) == offset);
   assert(ne_read(h, read_buff, readsize, offset) == readsize); // begin a read at a non-zero offset into the missing block
   for(i = 0; i < readsize; i++) {
      if(data[offset+i] != read_buff[i]) {
         printf("mismatch at i=%d, offset+i=%d\n", i, offset+i);
         assert(0);
      }
   }

   return 0;
}
