#include <stdlib.h>
#include <unistd.h> 
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "client.h"

// Define the global clients list (initialized to NULL)
Client* g_clients[MAX_CLIENTS] = {0};

#define INITIAL_READ_BUFFER_CAPACITY 1024

Client* client_create(int fd) {
    if (fd < 0 || fd >= MAX_CLIENTS) {
        return NULL; // Invalid FD
    }

    // Allocate the struct
    Client* client = malloc(sizeof(Client));
    if (client == NULL) {
        return NULL;
    }

    // Allocate the initial read buffer
    client->read_buffer = malloc(INITIAL_READ_BUFFER_CAPACITY);
    if (client->read_buffer == NULL) {
        free(client);
        return NULL;
    }
    
    client->fd = fd;
    client->read_buffer_len = 0;
    client->read_buffer_capacity = INITIAL_READ_BUFFER_CAPACITY;

    client->last_active_time = 0; // Will be set by server.c
    client->next = NULL;
    client->prev = NULL;
    
    g_clients[fd] = client; // Store it in our list of clients
    
    return client;
}

void client_free(Client* client) {
    if (client == NULL) return;

    // Free the buffer first
    if (client->read_buffer) {
        free(client->read_buffer);
    }
    
    // Close the file descriptor
    close(client->fd);
    
    // Mark the slot in our array as free
    g_clients[client->fd] = NULL;
    
    // Free the struct itself
    free(client);
}

Client* client_get(int fd) {
    if (fd < 0 || fd >= MAX_CLIENTS) {
        return NULL;
    }
    return g_clients[fd];
}


/**
 * Reads data from the socket into the buffer.
 * This function *must* be called in a loop because we use Edge-Triggered
 * epoll. It will read until the socket buffer is empty (EAGAIN).
 */
ClientReadResult client_read_data(Client* client) {
    
    while(1) {
        if (client->read_buffer_len == client->read_buffer_capacity) {

            if (client->read_buffer_capacity >= MAX_CLIENT_BUFFER_SIZE) {
                // This client is a spammer.
                printf("(Client %d) ERROR: Buffer limit exceeded (%zu bytes)\n",
                       client->fd, client->read_buffer_capacity);
                // Send an error, then disconnect them.
                const char* err = "(error) ERR command too large\n";
                write(client->fd, err, strlen(err));
                return READ_ERROR; // This will trigger a disconnect
            }            
            
            size_t new_capacity = client->read_buffer_capacity * 2;
            
            if (new_capacity < client->read_buffer_capacity + 1) {
                new_capacity = client->read_buffer_capacity + 1;
            }

            char* new_buffer = realloc(client->read_buffer, new_capacity);
            if (new_buffer == NULL) {
                perror("realloc failed");
                return READ_ERROR;
            }
            
            client->read_buffer = new_buffer;
            client->read_buffer_capacity = new_capacity;
            
            printf("(Client %d) Grew buffer to %zu bytes\n", client->fd, new_capacity);
        }

        // Calculate where to read and how much space is left
        char* buffer_start = client->read_buffer + client->read_buffer_len;
        size_t space_left = client->read_buffer_capacity - client->read_buffer_len;

        // Read from the socket
        ssize_t bytes_read = read(client->fd, buffer_start, space_left);

        if (bytes_read == 0) {
            // Client hung up
            return READ_DISCONNECTED;
        }

        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Not an error.
                // We've drained the socket
                return READ_OK;
            }
            // A real error
            perror("read() failed");
            return READ_ERROR;
        }

        // We read some data.
        client->read_buffer_len += bytes_read;
        
    }
}