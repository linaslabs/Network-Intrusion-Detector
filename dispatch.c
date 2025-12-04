#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "analysis.h"
#include "queue.h"

#define NUMTHREADS 10

// Compacting the dispatch parameters in one structure for easier use
typedef struct {
    struct pcap_pkthdr header;
    unsigned char *packet;
    int verbose;
} AnalysisJob; 

struct queue *work_queue;
pthread_t threads[NUMTHREADS];

pthread_mutex_t queue_mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond=PTHREAD_COND_INITIALIZER;

int loop = 1;

// Terminate function called when SIGINT signal is received and the process shuts down
void terminate(){
  // Lock queue to prevent race conditions, wake up all threads and unlock queue so they finish
  pthread_mutex_lock(&queue_mutex);
  loop = 0;
  pthread_cond_broadcast(&queue_cond);
  pthread_mutex_unlock(&queue_mutex);

  // Wait for the workers to finish (main thread joins with workers)
  for (int i = 0; i < NUMTHREADS; i++) {
        pthread_join(threads[i], NULL);
  }

  destroy_queue(work_queue);
  printf("Threads finished. Processes terminating... \n");
}

// Function that defines the work a thread is assigned to do
void *work(void *arg){
  // Loop and wait until queue is free to take a new job
  while (loop || !isempty(work_queue)){

    pthread_mutex_lock(&queue_mutex);

    // Loop whilst queue is empty and loop variable is "true"
    while (isempty(work_queue) && loop == 1){
      // Unlocks queue mutex, sleeps and locks when it wakes
      pthread_cond_wait(&queue_cond, &queue_mutex);
    }

    if (!isempty(work_queue)){
      // Take the next job from the queue and unlock the mutex
      AnalysisJob *job = (AnalysisJob *)dequeue(work_queue);
      pthread_mutex_unlock(&queue_mutex);

      // Run the analysis function with the data extracted
      analyse(&job->header, job->packet, job->verbose);
      free(job->packet);
      free(job);
    } else {
      pthread_mutex_unlock(&queue_mutex);
    }
    
  }

  // If loop is false, terminate
	printf("Terminating Worker...\n");
	return NULL;
}

// Function to initialise the threadpool
void create_thp(){
  // Create the queue and threads
  work_queue = create_queue();
  int i;
  for(i=0;i<NUMTHREADS;i++){
		pthread_create(&threads[i],NULL,work,NULL);
	}
}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {

  // Allocating memory for the job and populating its structure
  AnalysisJob *job = malloc(sizeof(AnalysisJob));
  job->header = *header;
  job->verbose = verbose;

  // Allocating new memory for storing the raw packet since pointer is replaced by next packet
  job->packet = malloc(header->caplen);
  
  // Copying the raw data from the packet to the allocated memory
  memcpy(job->packet, packet, header->caplen);

  // lock queue, enqueue packet, signal a worker to wake up, then unlock the queue
  pthread_mutex_lock(&queue_mutex);
	enqueue(work_queue,job);
  // This allows waking up one thread instead of broadcasting to all
	pthread_cond_signal(&queue_cond);
	pthread_mutex_unlock(&queue_mutex);

}
