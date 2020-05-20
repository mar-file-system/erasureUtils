
#include "thread_queue/thread_queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define NUM_CONS 5
#define NUM_PROD 2
#define QDEPTH  100
#define TOT_WRK 15
#define HLT_AT  -1
#define ABT_AT  -1
#define SLP_PER_CONS 2
#define SLP_PER_PROD 1

typedef struct global_state_struct {
   pthread_mutex_t lock;
   int pkgcnt;
}* GlobalState;

typedef struct thread_state_struct {
	unsigned int tID;
	GlobalState gstate;
	int wkcnt;
}* ThreadState;

typedef struct work_package_struct {
	int pkgnum;
}* WorkPkg;


int my_thread_init( unsigned int tID, void* global_state, void** state ) {
	*state = malloc( sizeof( struct thread_state_struct ) );
	if ( *state == NULL ) { return -1; }
	ThreadState tstate = ((ThreadState) *state);

	tstate->tID = tID;
	tstate->gstate = (GlobalState) global_state;
	tstate->wkcnt = 0;
	return 0;
}


int my_consumer( void** state, void** work ) {
	WorkPkg wpkg = ((WorkPkg) *work);
	ThreadState tstate = ((ThreadState) *state);

	tstate->wkcnt++;
	fprintf( stdout, "Thread %u received work package %d ( wkcnt = %d)\n", tstate->tID, wpkg->pkgnum, tstate->wkcnt );
	int num = wpkg->pkgnum;
	free( wpkg );
   usleep( rand() % ( SLP_PER_CONS * 1000000 ) );
	// pause the queue, if necessary
	if ( num == HLT_AT ) { fprintf( stdout, "Thread %u is pausing the queue!\n", tstate->tID ); return 2; }
	// issue an abort, if necessary
	else if (  num == ABT_AT ) { fprintf( stdout, "Thread %u is aborting the queue!\n", tstate->tID ); return -1; }
	return 0;
}


int my_producer( void** state, void** work ) {
	ThreadState tstate = ((ThreadState) *state);

   WorkPkg wpkg = malloc( sizeof( struct work_package_struct ) );
   if ( wpkg == NULL ) {
      fprintf( stdout, "Thread %u failed to allocate space for a new work package!\n", tstate->tID );
      return -1;
   }
   if ( pthread_mutex_lock( &(tstate->gstate->lock) ) ) {
      fprintf( stdout, "Thread %u failed to acquire global state lock\n", tstate->tID );
      free( wpkg );
      return -1;
   }
   wpkg->pkgnum = tstate->gstate->pkgcnt;
   tstate->gstate->pkgcnt++;
   pthread_mutex_unlock( &(tstate->gstate->lock) );
   tstate->wkcnt++;
   usleep( rand() % ( SLP_PER_PROD * 1000000 ) );
   fprintf( stdout, "Thread %u created work package %d ( wkcnt = %d )\n", tstate->tID, wpkg->pkgnum, tstate->wkcnt );
   *work = (void*) wpkg;
   if ( wpkg->pkgnum > TOT_WRK ) { return 1; }
   return 0;
}


int my_pause( void** state, void** prev_work ) {
   return 0;
}


int my_resume( void** state, void** prev_work ) {
   return 0;
}


void my_thread_term( void** state, void** prev_work ) {
   WorkPkg wpkg = ((WorkPkg) *prev_work);
	ThreadState tstate = ((ThreadState) *state);
   if ( wpkg != NULL ) {
      fprintf( stdout, "Thread %u is freeing unused work package %d\n", tstate->tID, wpkg->pkgnum );
      free( wpkg );
      *prev_work = NULL;
   }
	return;
}



int main( int argc, char** argv ) {
   srand( time(NULL) );
	struct global_state_struct gstruct;
   if ( pthread_mutex_init( &(gstruct.lock), NULL ) ) { return -1; }
   gstruct.pkgcnt = 0;

	TQ_Init_Opts tqopts;
   tqopts.log_prefix = "MyTQ";
   tqopts.init_flags = TQ_HALT;
	tqopts.global_state = (void*) &gstruct;
	tqopts.num_threads = NUM_PROD + NUM_CONS;
   tqopts.num_prod_threads = NUM_PROD;
	tqopts.max_qdepth = QDEPTH;
	tqopts.thread_init_func = my_thread_init;
	tqopts.thread_consumer_func = my_consumer;
   tqopts.thread_producer_func = my_producer;
   tqopts.thread_pause_func = my_pause;
   tqopts.thread_resume_func = my_resume;
	tqopts.thread_term_func = my_thread_term;

	printf( "Initializing ThreadQueue...\n" );
	ThreadQueue tq = tq_init( &tqopts );
	if ( tq == NULL ) { printf( "tq_init() failed!  Terminating...\n" ); return -1; }

   printf( "checking if queue is finished...\n" );
   TQ_Control_Flags flags = 0;
   while ( !(flags & TQ_FINISHED)  &&  !(flags & TQ_ABORT) ) {
      if ( tq_wait_for_flags( tq, 0, &flags ) ) {
         printf( "unexpected return from tq_wait_for_flags()!\n" );
      }
      if ( flags & TQ_HALT ) {
         printf( "queue has halted!  Waiting for all threads to pause...\n" );
         if ( tq_wait_for_pause( tq ) ) {
            printf( "unexpected return from tq_wait_for_pause!\n" );
         }
         printf( "...sleeping for 5 seconds (should see no activity)...\n" );
         sleep( 5 );
         printf( "...resuming queue...\n" );
         if ( tq_unset_flags( tq, TQ_HALT ) ) {
            printf( "unexpected return from tq_unset_flags!\n" );
         }
      }
   }
   if ( flags & TQ_FINISHED ) {
      printf( "queue is finished!\n" );
   }
   else if ( flags & TQ_ABORT ) {
      printf( "queue has aborted!\n" );
   }

	int tnum = 0;
	int tres = 0;
	ThreadState tstate = NULL;
	while ( (tres = tq_next_thread_status( tq, (void**)&tstate )) > 0 ) {
		if ( tstate != NULL ) {
			printf( "State for thread %d = { tID=%d, wkcnt=%d }\n", tnum, tstate->tID, tstate->wkcnt );
			free( tstate );
			tnum++;
		}
		else {
			printf( "Received NULL status for thread %d\n", tnum );
		}
	}
	if ( tres != 0 ) { printf( "Failure of tq_next_thread_status()!\n" ); }

   printf( "Global state: %d\n", gstruct.pkgcnt );

	printf( "Finally, closing thread queue...\n" );
   int cres = tq_close(tq);
   if ( cres > 0 ) {
      printf( "Elements still remain on ABORTED queue!  Using tq_dequeue() to retrieve...\n" );
      WorkPkg wpkg = NULL;
      while ( tq_dequeue( tq, TQ_ABORT, (void**) &wpkg ) > 0 ) {
         printf( "Received work package %d from aborted queue\n", wpkg->pkgnum );
         free( wpkg );
      }
      cres = tq_close(tq);
   }

   if ( cres ) {
      printf( "Received unexpected return from tq_close() %d\n", cres );
   }
      
	printf( "Done\n" );
	return 0;
}

