#include <stdlib.h>
#include <unistd.h> 
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "client.h"
#include "io_backend.h" // Added for backend abstraction

// Define the global clients list (initialized to NULL)
Client* g_clients[MAX_CLIENTS] = {0};

#define INITIAL_READ_BUFFER_CAPACITY 1024 // 1024 characters
#define INITIAL_WRITE_BUFFER_CAPACITY 1024 // 1024 characters

Client* client_create(int fd) {
    if (fd < 0 || fd >= MAX_CLIENTS) {
        return NULL;
    }

    Client* client = malloc(sizeof(Client));
    if (client == NULL) goto fail;

    client->read_buffer = malloc(INITIAL_READ_BUFFER_CAPACITY);
    if (client->read_buffer == NULL) goto fail_read_buf;
    client->read_buffer_len = 0;
    client->read_buffer_capacity = INITIAL_READ_BUFFER_CAPACITY;
    
    client->write_buffer = malloc(INITIAL_WRITE_BUFFER_CAPACITY);
    if (client->write_buffer == NULL) goto fail_write_buf;
    client->write_buffer_len = 0;
    client->write_buffer_sent = 0;
    client->write_buffer_capacity = INITIAL_WRITE_BUFFER_CAPACITY;

    client->fd = fd;
    client->last_active_time = 0; // Will be set by server.c
    client->next = NULL;
    client->prev = NULL;
    
    g_clients[fd] = client; // Store it in our list of clients
    return client;

fail_write_buf:
    free(client->read_buffer);
fail_read_buf:
    free(client);
fail:
    return NULL;
}

void client_free(Client* client) {
    if (client == NULL) return;

    // Free the buffer first
    if (client->read_buffer) {
        free(client->read_buffer);
    }

    if (client->write_buffer) {
        free(client->write_buffer);
    }
    
    // Close the file descriptor via backend
    g_backend->socket_close(client->fd);
    
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
                
                // Write via backend
                g_backend->write(client->fd, err, strlen(err));
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

        // Read from the socket via backend
        ssize_t bytes_read = g_backend->read(client->fd, buffer_start, space_left);

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

/**
 * Queues a response to be sent to the client.
 */
int queue_client_response(Client* client, const char* msg) {
    if (client == NULL || msg == NULL) return -1;

    size_t msg_len = strlen(msg);
    if (msg_len == 0) return 0; // Nothing to send

    size_t new_total_len = client->write_buffer_len + msg_len;

    if (new_total_len > client->write_buffer_capacity) {
        size_t new_capacity = client->write_buffer_capacity;

        // Keep doubling until it's big enough
        while (new_total_len > new_capacity) {
            new_capacity *= 2;
        }
        
        // Check against our max buffer size
        if (new_capacity > MAX_CLIENT_BUFFER_SIZE) {
             new_capacity = MAX_CLIENT_BUFFER_SIZE;
        }
        
        if (new_total_len > new_capacity) {
             printf("(Client %d) ERROR: Write buffer limit exceeded\n", client->fd);
             return -1; // OOM
        }

        char* new_buffer = realloc(client->write_buffer, new_capacity);
        if (new_buffer == NULL) {
            perror("realloc write_buffer");
            return -1; 
        }
        client->write_buffer = new_buffer;
        client->write_buffer_capacity = new_capacity;
    }

    memcpy(client->write_buffer + client->write_buffer_len, msg, msg_len);

    client->write_buffer_len = new_total_len;

    return 0; // Success
}