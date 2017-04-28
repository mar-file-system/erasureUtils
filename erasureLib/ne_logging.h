#ifndef LIBNE_LOGGING_H
#define LIBNE_LOGGING_H

// LOG_PREFIX is prepended to all output.  Allows grepping in syslogs.
// Define your own, before including file, if you want to distinguish logging
// from a different place.
//
#ifndef NE_LOG_PREFIX
#  define NE_LOG_PREFIX  "libne"
#endif



#define IMAX(A, B) (((A) > (B)) ? (A) : (B))

#define NE_FPRINTF(FN, FD, FMT,...)                                     \
   do {                                                                 \
      const int prefix_size=16;                                         \
      const int file_blob_size=24;                                      \
      const int file_pad_size = IMAX(1, file_blob_size - strlen(__FILE__)); \
      const int fn_blob_size=20;                                        \
      FN(FD, "%-*.*s  %08x  %s:%-6d%*.*s  %-*.*s |  " FMT,              \
         prefix_size, prefix_size, NE_LOG_PREFIX,                       \
         (unsigned int)pthread_self(),                                  \
         __FILE__, __LINE__, file_pad_size, file_pad_size, " ",         \
         fn_blob_size, fn_blob_size, __FUNCTION__, ##__VA_ARGS__);      \
   } while(0)



// caller should take care of calling openlog(LOG_PREFIX, ...), before
// invoking SYSLOG().
//
#define FPRINTF(FD, FMT,...)   NE_FPRINTF(fprintf, FD,   FMT, ##__VA_ARGS__)
#define SYSLOG(PRIO, FMT,...)  NE_FPRINTF(syslog,  PRIO, FMT, ##__VA_ARGS__)




#endif
