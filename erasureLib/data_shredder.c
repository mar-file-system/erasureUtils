#include <stdio.h>
//#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <limits.h>
#include <erasure.h>

#define PRINTERR(...)   fprintf( stderr, "data_shredder: "__VA_ARGS__)
#define PRINTOUT(...)   fprintf( stdout, "data_shredder: "__VA_ARGS__)


// helper function to print this programs usage info
void print_usage() {
   printf( "This program is inteneded to exercise the libne rebuild functionality by \n"
           "  inserting data corruption into an existing erasure stripe.  This should be used \n"
           "  with EXTREME CAUTION, as it has the potential to render data permanently \n"
           "  unrecoverable if errors were already present.\n"
           "  As a safety measure, backups of the original files are created (by appending a \n"
           "  '.shrd_backup.<TS>' suffix) before the corruption is inserted.  Note, however, \n"
           "  that these backup files will not have any xattrs/manifest info attached.\n"
           "  To reiterate, NEVER RUN THIS PROGRAM AGAINST USER DATA!\n" );
   printf( "usage:  data_shredder -d <corruption_distribution> -o <start_offset>:<end_offset> \n"
           "                      [-b <libne_block-size>] [-n <N>] [-e <E>] [-f] \n"
           "                      <erasure_path_fmt>\n" );
   printf( "  <erasure_path_fmt>   The format string for the erasure stripe to be corrupted, \n"
           "                        including a '\%d' character to be replaced by each block-\n"
           "                        file index\n" );
   printf( "        -d   Specifies the pattern in which data corruption should be inserted\n"
           "               Options = shotgun (random distribution), diagonal_up (adjacent \n"
           "               corruption along a stripe, shifted to higher index block-files in \n"
           "               later stripes), diagonal_down (adjacent corruption along a stripe, \n"
           "               shifted to lower index block-files in later stripes)\n" );
   printf( "        -o   Specifies the offsets within each block-file which should have their \n"
           "               content corrupted (offsets will be shifted to the nearest block \n"
           "               boundry\n" );
   printf( "        -b   Explicitly specifies the libne block size (overrides erasure.h value)\n" );
   printf( "        -n   Explicitly specifies the libne stripe data-width (overrides the \n"
           "               erasure.h value)\n" );
   printf( "        -e   Explicitly specifies the libne stripe erasure-width (overrides the \n"
           "               erasure.h value)\n" );
   printf( "        -f   Forces the corruption operation to take place without prompting the \n"
           "               user for confirmation beforehand\n" );
}


// helper function to copy a given file to a new location
off_t copy_file_by_name( const char* original, const char* destination ) {
   char buffer[4096];
   size_t bytes_read;
   size_t bytes_written;
   off_t total_written = 0;
   char fail = 0;

   // open both the input and output files
   int fd_orig = open( original, O_RDONLY );
   if( fd_orig < 0 ) {
      PRINTERR( "failed to open file \"%s\" for read\n", original );
      return 0;
   }
   mode_t mask = umask(0000);
   int fd_dest = open( destination, O_WRONLY | O_CREAT | O_EXCL, 0666 );
   umask( mask );
   if( fd_dest < 0 ) {
      PRINTERR( "failed to open file \"%s\" for write\n", destination );
      close( fd_orig );
      return 0;
   }

   while( fail == 0  &&  (bytes_read = read( fd_orig, buffer, sizeof(buffer) )) > 0 ) {
      bytes_written = write( fd_dest, buffer, sizeof(buffer) );
      
      if( bytes_written != bytes_read ) {
         PRINTERR( "failed to write to output file \"%s\"\n", destination );
         bytes_read = 0;
         fail = 1;
      }
      total_written += bytes_written;
   }

   if( close( fd_orig ) ) {
      PRINTERR( "failed to properly close input file \"%s\"\n", original );
   }
   if( close( fd_dest ) ) {
      PRINTERR( "failed to properly close output file \"%s\"\n", destination );
      fail = 1;
   }

   if( bytes_read != 0 ) {
      PRINTERR( "failed to read input file \"%s\"\n", original );
      fail = 1;
   }

   if( fail )
      return 0;

   return total_written;
}


int main( int argc, char** argv ) {
   unsigned char distrib = 0;
   char offsetP = 0;
   char* pathpat = NULL;
   unsigned long long shred_range[2] = {0};
   unsigned long bsz = BLKSZ;
   int N = 10;
   int E = 2;
   
   int opt;
   int status = 0;
   char fflag = 0;
   char* endptr;
   unsigned long input;

   // parse arguments
   while( (opt = getopt( argc, argv, "d:o:b:n:e:fh" )) != -1 ) {
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
            if( offsetP )
               PRINTERR( "received multiple '-o' arguements: only the last valid argument will be used\n" );
            offsetP = 0;
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
               shred_range[1] = 0;
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
               // the end offset must be non-zero for us to do anything
               if( shred_range[1] < 1 ) {
                  PRINTERR( "received an invalid shred range: ending offset < 1 implies nothing to be done\n" );
                  return -1;
               }
            }
            offsetP = 1;
            break;
         case 'b':
            // parse and set the new bsz
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
            // parse and set the new N
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
            // check for a bounds violation
            if( input > MAXN  ||  input < 1 ) {
               PRINTERR( "input value for N exceeds the limits defined in libne: MAXN = %d\n", MAXN );
               return -1;
            }
            N = (int) input;
            break;
         case 'e':
            // parse and set the new E
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
            // check for a bounds violation
            if( input > MAXE ) {
               PRINTERR( "input value for E exceeds the limits defined in libne: MAXE = %d\n", MAXE );
               return -1;
            }
            E = (int) input;
            break;
         case 'f':
            fflag = 1;
            break;
         case 'h':
            print_usage();
            return 0;
         case '?':
            PRINTERR( "encountered unexpected argument: '-%c' (ignoring)\n", optopt );
            break;
         default:
            PRINTERR( "encountered unexpected error while parsing arguments\n" );
            print_usage();
            return -1;
      }
   }

   // parse any remaining args
   int index;
   char usage = 0;
   unsigned int strln;
   for( index = optind; index < argc; index++ ) {
      // only set pathpat if it has not already been set
      if( pathpat == NULL ) {
         strln = strlen( argv[index] );
         pathpat = malloc( sizeof(char) * ( strln + 1 ) );
         if( pathpat == NULL ) {
            PRINTERR( "failed to allocate memory for erasure path string\n" );
            return -1;
         }
         if( strncpy( pathpat, argv[index], strln+1 ) == NULL ) {
            PRINTERR( "failed to copy pattern string into buffer\n" );
            return -1;
         }
      }
      else {
         // any additional args are in error
         PRINTERR( "received unexpected argument: \"%s\" (ignoring)\n", argv[index] );
      }
   }

   // check for required args
   if( pathpat == NULL ) {
      PRINTERR( "missing required argument: <erasure_path_fmt>\n" );
      return -1;
   }
   if( !offsetP ) {
      PRINTERR( "a valid offset range must be specified via the '-o' option\n" );
      return -1;
   } 
   if( distrib == 0 ) {
      PRINTERR( "a valid corruption distribution pattern must be specified via '-d'\n" );
      return -1;
   }
   if( E == 0 ) {
      PRINTERR( "E==0 for this erasure stripe implies nothing to be done\n" );
      return -1;
   }

   // align the starting and ending offsets to the block-size
   shred_range[0] -= (shred_range[0] % bsz);
   shred_range[1] += (bsz - (shred_range[1] % bsz));

   // print info for this run
   PRINTOUT( "using path = %s, n = %d, e = %d, bsz = %lu, distrib = %d, low_off = %llu, high_off = %llu, force = %d\n", 
              pathpat,N,E,bsz,distrib,shred_range[0],shred_range[1],fflag);

   // allocate space for both the pattern string and extra for all possible indexes
   char* bfile = malloc( sizeof(char) * ( strln + log10( MAXPARTS ) ) );
   if( bfile == NULL ) {
      PRINTERR( "failed to allocate space for the name of each block-file\n" );
      return -1;
   }

   int stripewidth = N+E;                      // the total data/erasure stripe width
   char backup_array[ MAXPARTS ] = {0};        // indicates whether a given block-file has been backed-up yet
   unsigned long stripecnt = 0;                // the total number of stripes currently processed
   unsigned long long coff = shred_range[0];   // the current offset being dealt with in all block-files
    
   free( pathpat );
   free( bfile );
   return 0;

}

