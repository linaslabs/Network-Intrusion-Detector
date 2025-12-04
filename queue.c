#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

struct queue *create_queue(void){
  struct queue *q=(struct queue *)malloc(sizeof(struct queue));
  q->head=NULL;
  q->tail=NULL;
  return(q);
}

// Removes all elements in the queue
void destroy_queue(struct queue *q){
  while(!isempty(q)){
    dequeue(q);
  }
  free(q);
}

int isempty(struct queue *q){
  return(q->head==NULL);
}

// Adds a new item to the queue, takes in a generic pointer
void enqueue(struct queue *q, void *item){
  struct node *new_node=(struct node *)malloc(sizeof(struct node));
  new_node->item=item;
  new_node->next=NULL;
  
  if(isempty(q)){
    q->head=new_node;
    q->tail=new_node;
  }
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}

// Removes head from queue if it exists, returns the item dequeued (acts like pop)
void *dequeue(struct queue *q){
  struct node *head_node;

  // Intermediary item pointer to store head item and return it after removal
  void *item = NULL;

  if(isempty(q)){
    printf("Error: attempt to dequeue from an empty queue");
    return NULL;
  }
  else{
    head_node = q->head;

    // Store head item before removing it
    item = head_node->item;
    
    q->head = q->head->next;
    if(q->head == NULL)
      q->tail = NULL;
    
    free(head_node); 
    
    // Return head item to the worker
    return item;
  }
}