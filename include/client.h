#ifndef CLIENT_H
#define CLIENT_H

#include <stddef.h> 
#include <time.h> 

struct Server;

// This struct holds the state for one client
typedef struct Client {
    int fd;
    
    // The dynamically-growing buffer for partial reads
    char* read_buffer;
    size_t read_buffer_len;
    size_t read_buffer_capacity;
    
    // Dynamically growing write-buffer for partial writes 
    char* write_buffer;
    size_t write_buffer_len;      // Total bytes we need to send
    size_t write_buffer_sent;     // How many bytes we've already sent
    size_t write_buffer_capacity;

    /* Used in the linked list for the timer wheel for inactivity in server.c */
    time_t last_active_time;
    struct Client* next;
    struct Client* prev;
    
} Client;

#define MAX_CLIENTS 1024
#define MAX_CLIENT_BUFFER_SIZE (1024 * 1024) /* 1 megabyte of data allowed maximum */

extern Client* g_clients[MAX_CLIENTS];

// Return codes for client_read_data
typedef enum {
    READ_OK,
    READ_DISCONNECTED,
    READ_ERROR,
    READ_AGAIN // For non-blocking, means "no more data right now"
} ClientReadResult;


// Creates a new client for a file descriptor
// and adds them to the g_clients list.
Client* client_create(int fd);

// Frees a client and removes them from the list.
void client_free(Client* client);

// Finds a client by their file descriptor.
Client* client_get(int fd);

// Read data from the socket into the buffer
ClientReadResult client_read_data(Client* client);

// Queues a msg response in the client's buffer 
int queue_client_response(Client* client, const char* msg);

#endif // CLIENT_H