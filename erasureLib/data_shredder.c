#include <stdio.h>
//#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <erasure.h>

#define PRINTERR(...)   fprintf( stderr, "data_shredder: "__VA_ARGS__)
#define PRINTOUT(...)   fprintf( stdout, "data_shredder: "__VA_ARGS__)

int main( int argc, char** argv ) {
   unsigned char distrib = 0;
   char* pathpat = NULL;
   unsigned long long shred_range[2] = {0};
   unsigned long bsz = BLKSZ;
   int N = 10;
   int E = 2;
   
   int opt;
   int status = 0;
   char* endptr;
   unsigned long input;

   // parse arguments
   while( (opt = getopt( argc, argv, "d:o:b:n:e:" )) != -1 ) {
      switch( opt ) {
         case 'd':
            if( distrib != 0 ) {
               PRINTERR( "received duplicate '-d' argument, only the last argument will be honored\n" );
               distrib == 0;
            }
            // looking for shotgun or diagonals
            if( strncmp( optarg, "shotgun", 78 ) == 0 ) {
               distrib = 1;
            }
            else if( strncmp( optarg, "diagonal", 8 ) == 0 ) {
               char* tmp = optarg+8;
               if( strncmp( tmp, "_up", 4 ) == 0 ) {
                  distrib = 2;
               }
               else if( strncmp( tmp, "_down", 6 ) == 0 ) {
                  distrib = 3;
               }
            }
            // warn if the distribution was not recognized
            if( distrib == 0 ) {
               PRINTERR( "received unrecognized error distribution arg: \"%s\"\n", optarg );
            }
            break;
         case 'o':
            // get the start offset for the corruption pattern
            errno = 0;
            shred_range[0] = strtoull( optarg, &(endptr), 10 );
            if( *endptr != ':' ) {
               PRINTERR( "expected a '<low_offset>:<high_offset>' argument following the '-o' option"
                     " but encountered unexpected char: \"%c\"\n", *endptr );
               return -1;
            }
            if( errno != 0 ) {
               PRINTERR( "failed to properly parse offset range \"%s\": expected '<low_offset>:<high_offset>'\n", 
                     optarg );
               return -1;
            }
            // now get the end offset
            char* secstr = endptr + 1;
            if( strncmp( secstr, "end", 4 ) == 0 ) { 
               // handle special value of "end" as max offset
               shred_range[1] = ULLONG_MAX;
            }
            else {
               // parse the remaining string to get the max offset
               shred_range[1] = strtoull( secstr, &(endptr), 10 );
               if( *endptr != '\0' ) {
                  PRINTERR( "expected a '<low_offset>:<high_offset>' argument following the '-o' option"
                        " but encountered unexpected char: \"%c\"\n", *endptr );
                  return -1;
               }
               if( errno != 0 ) {
                  PRINTERR( "failed to properly parse offset range \"%s\": expected '<low_offset>:<high_offset>'\n", 
                        optarg );
                  return -1;
               }
            }
            break;
         case 'b':
            errno = 0;
            bsz = strtoul( optarg, &(endptr), 10 );
            if( *endptr != '\0' ) {
               PRINTERR( "expected an unsigned numeric argument following the '-b' option"
                     " but encountered unexpected char: \"%c\"\n", *endptr );
               return -1;
            }  
            if( errno != 0 ) {
               PRINTERR( "failed to properly parse block-size \"%s\"\n",
                     optarg );
               return -1;
            }
            if( bsz > MAXBLKSZ ) {
               PRINTERR( "input value for block-size exceeds the limits defined in libne: %lu\n", bsz );
               return -1;
            }
            break;
         case 'n':
            errno = 0;
            input = strtoul( optarg, &(endptr), 10 );
            if( *endptr != '\0' ) {
               PRINTERR( "expected an unsigned numeric argument following the '-n' option"
                         " but encountered unexpected char: \"%c\"\n", *endptr );
               return -1;
            }
            if( errno != 0 ) {
               PRINTERR( "failed to properly parse n value \"%s\"\n",
                          optarg );
               return -1;
            }
            if( input > MAXN ) {
               PRINTERR( "input value for N exceeds the limits defined in libne: MAXN = %d\n", MAXN );
               return -1;
            }
            N = (int) input;
            break;
         case 'e':
            errno = 0;
            input = strtoul( optarg, &(endptr), 10 );
            if( *endptr != '\0' ) {
               PRINTERR( "expected an unsigned numeric argument following the '-e' option"
                         " but encountered unexpected char: \"%c\"\n", *endptr );
               return -1;
            }
            if( errno != 0 ) {
               PRINTERR( "failed to properly parse e value \"%s\"\n",
                          optarg );
               return -1;
            }
            if( input > MAXE ) {
               PRINTERR( "input value for E exceeds the limits defined in libne: MAXE = %d\n", MAXE );
               return -1;
            }
            E = (int) input;
            break;
         case '?':
            PRINTERR( "encountered unexpected argument: '-%c' (ignoring)\n", optopt );
            break;
         default:
            PRINTERR( "encountered unexpected error\n" );
            return -1;
      }
   }

   // parse any remaining args
   int index;
   for( index = optind; index < argc; index++ ) {
      if( pathpat == NULL ) {
         int strln = strlen( argv[index] );
         pathpat = malloc( sizeof(char) * ( strln + 1 ) );
         if( pathpat == NULL ) {
            PRINTERR( "failed to allocate memory for erasure path string\n" );
            return -1;
         }
         if( strncpy( pathpat, argv[index], strln ) == NULL ) {
            PRINTERR( "failed to copy pattern string into buffer\n" );
            return -1;
         }
      }
      else {
         PRINTERR( "received unexpected argument: \"%s\" (ignoring)\n", argv[index] );
      }
   }


   PRINTOUT( "using path = %s, n = %d, e = %d, bsz = %lu, distrib = %d, low_off = %llu, high_off = %llu\n", 
              pathpat,N,E,bsz,distrib,shred_range[0],shred_range[1]);

}

