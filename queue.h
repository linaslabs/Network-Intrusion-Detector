#ifndef QUEUE_H
#define QUEUE_H

// A node will now consist of a pointer (to the packet/analysis job) rather than just the item
struct node {
    void *item;
    struct node *next;
};

struct queue {
    struct node *head;
    struct node *tail;
};

struct queue *create_queue(void);
void destroy_queue(struct queue *q);
int isempty(struct queue *q);

// Enqueue will take in a generic pointer
void enqueue(struct queue *q, void *item);

// Dequeue returns a generic pointer
void *dequeue(struct queue *q);

#endif